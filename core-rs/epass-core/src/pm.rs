//! Pass manager and policy.
//!
//! Passes are declared statically in [`REGISTRY`]: a phase, ordering
//! constraints, defaults, and whether loaders may control them. The order is
//! one topological sort of the registry (phase first, then constraints, ties
//! by registration order); it never depends on the input program or on
//! options. Per-program options only filter it.
//!
//! An administrator policy (in the kernel: a sysfs/sysctl string) takes
//! precedence over a loader's popt:
//!
//! | admin   | loader silent  | loader `name(args)` | loader `!name` |
//! |---------|----------------|---------------------|----------------|
//! | forced  | on, admin args | Denied              | Denied         |
//! | denied  | off            | Denied              | off            |
//! | allowed | default        | on, loader args     | off            |

use crate::ctx::Ctx;
use crate::error::{Error, ErrorKind, Result};
use crate::facts::Facts;
use crate::ir::verify::verify;
use crate::ir::Function;
use crate::mem::{FVec, Heap};

/// Pass phases, run in this order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    Canonicalize,
    Optimize,
    /// Enforcement passes; nothing loader-controllable runs after them.
    Instrument,
    /// Mandatory lowering before codegen; never loader-controllable.
    Finalize,
}

/// Global options for one compilation (from gopt and policy).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    /// Return value of a lowered `throw`.
    pub throw_ret: i32,
    /// Validate after every pass (always on in debug builds).
    pub verify_each: bool,
    pub allow_ecall: bool,
    /// Target byte order (affects folding of `bswap.le`/`bswap.be`).
    pub big_endian: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            throw_ret: 0,
            verify_each: cfg!(debug_assertions),
            allow_ecall: false,
            big_endian: false,
        }
    }
}

/// Everything a pass may consult besides the function.
pub struct PassCx<'a, 'h> {
    pub ctx: &'a Ctx<'h>,
    pub facts: &'a dyn Facts,
    pub opts: &'a Options,
}

impl core::fmt::Debug for PassCx<'_, '_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PassCx").field("opts", self.opts).finish()
    }
}

pub type RunFn = for<'a, 'h> fn(&mut Function<'h>, &PassCx<'a, 'h>, Option<&str>) -> Result<()>;
pub type CheckFn = fn(Option<&str>) -> Result<()>;

/// A pass descriptor.
pub struct PassInfo {
    pub name: &'static str,
    pub phase: Phase,
    /// Passes (same phase) this one must run after / before, when enabled.
    pub after: &'static [&'static str],
    pub before: &'static [&'static str],
    pub default_on: bool,
    /// Whether loaders may enable, disable or configure it.
    pub user_controllable: bool,
    /// Always runs (Finalize lowering); policy may only set its arguments.
    pub mandatory: bool,
    /// Validate arguments when the pipeline is built.
    pub check_args: CheckFn,
    pub run: RunFn,
}

impl core::fmt::Debug for PassInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PassInfo")
            .field("name", &self.name)
            .field("phase", &self.phase)
            .finish()
    }
}

/// Accept no arguments.
pub fn no_args(arg: Option<&str>) -> Result<()> {
    match arg {
        None => Ok(()),
        Some(s) if s.trim().is_empty() => Ok(()),
        Some(_) => Err(Error::invalid_input("pass takes no arguments")),
    }
}

/// The built-in passes, in registration order.
pub static REGISTRY: &[PassInfo] = &[
    crate::passes::dump_ir::INFO,
    crate::passes::const_prop::INFO,
    crate::passes::phi::INFO,
    crate::passes::zext_elim::INFO,
    crate::passes::dce::INFO,
    crate::passes::lower_throw::INFO,
];

pub fn find(name: &str) -> Option<&'static PassInfo> {
    REGISTRY.iter().find(|p| p.name == name)
}

/// Topological order of the registry. Errors on unknown names, constraints
/// that contradict phases, and cycles (a registry bug; checked by tests).
pub fn registry_order<'h>(heap: &'h Heap<'h>) -> Result<FVec<'h, usize>> {
    let n = REGISTRY.len();
    let idx = |name: &str| -> Result<usize> {
        REGISTRY
            .iter()
            .position(|p| p.name == name)
            .ok_or(Error::internal("pass constraint names an unknown pass"))
    };
    // edges[a] = passes that must come after a
    let mut indeg: FVec<'_, u32> = FVec::new(heap);
    indeg.resize(n, 0)?;
    let mut edges: FVec<'_, (usize, usize)> = FVec::new(heap);
    for (i, p) in REGISTRY.iter().enumerate() {
        for &a in p.after {
            edges.push((idx(a)?, i))?;
        }
        for &b in p.before {
            edges.push((i, idx(b)?))?;
        }
    }
    for &(a, b) in edges.iter() {
        let (pa, pb) = (
            REGISTRY.get(a).ok_or(Error::internal("pass"))?.phase,
            REGISTRY.get(b).ok_or(Error::internal("pass"))?.phase,
        );
        if pa > pb {
            return Err(Error::internal("pass constraint contradicts phase order"));
        }
        if let Some(d) = indeg.get_mut(b) {
            *d += 1;
        }
    }
    let mut out: FVec<'_, usize> = FVec::with_capacity(heap, n)?;
    let mut done: FVec<'_, bool> = FVec::new(heap);
    done.resize(n, false)?;
    for _ in 0..n {
        // Lowest (phase, registration index) among ready passes.
        let mut pick: Option<usize> = None;
        for i in 0..n {
            if *done.get(i).unwrap_or(&true) || *indeg.get(i).unwrap_or(&1) != 0 {
                continue;
            }
            let better = match pick {
                None => true,
                Some(j) => {
                    let (pi, pj) = (
                        REGISTRY.get(i).map(|p| p.phase),
                        REGISTRY.get(j).map(|p| p.phase),
                    );
                    pi < pj
                }
            };
            if better {
                pick = Some(i);
            }
        }
        let i = pick.ok_or(Error::internal("pass ordering cycle"))?;
        // Phase order: nothing from a later phase may run before an
        // earlier-phase pass that is still waiting.
        out.push(i)?;
        if let Some(d) = done.get_mut(i) {
            *d = true;
        }
        for &(a, b) in edges.iter() {
            if a == i {
                if let Some(d) = indeg.get_mut(b) {
                    *d = d.saturating_sub(1);
                }
            }
        }
    }
    // The pick rule prefers earlier phases, but a constraint chain could
    // still interleave phases; reject that.
    let mut last = Phase::Canonicalize;
    for &i in out.iter() {
        let ph = REGISTRY.get(i).ok_or(Error::internal("pass"))?.phase;
        if ph < last {
            return Err(Error::internal("pass order interleaves phases"));
        }
        last = ph;
    }
    Ok(out)
}

// ------------------------------------------------------------------ parsing

/// Split at top-level commas (outside parentheses).
fn split_items<'s>(heap: &'s Heap<'s>, s: &'s str) -> Result<FVec<'s, &'s str>> {
    let mut out = FVec::new(heap);
    let mut depth = 0i32;
    let mut start = 0usize;
    for (i, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth < 0 {
                    return Err(Error::invalid_input("unbalanced ')' in options"));
                }
            }
            ',' if depth == 0 => {
                let it = s.get(start..i).unwrap_or("").trim();
                if !it.is_empty() {
                    out.push(it)?;
                }
                start = i + 1;
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err(Error::invalid_input("unbalanced '(' in options"));
    }
    let it = s.get(start..).unwrap_or("").trim();
    if !it.is_empty() {
        out.push(it)?;
    }
    Ok(out)
}

/// `name` or `name(args)`.
fn name_args(item: &str) -> Result<(&str, Option<&str>)> {
    match item.find('(') {
        None => Ok((item.trim(), None)),
        Some(p) => {
            let name = item.get(..p).unwrap_or("").trim();
            let rest = item.get(p + 1..).unwrap_or("");
            let args = rest
                .strip_suffix(')')
                .ok_or(Error::invalid_input("pass arguments must end with ')'"))?;
            Ok((name, Some(args)))
        }
    }
}

/// Maximum accepted option-string length (kernel input).
pub const MAX_OPTION_LEN: usize = 4096;

/// Global ePass mode set by the administrator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// ePass never runs.
    Off,
    /// ePass runs when the loader asks (or a pass is forced).
    OptIn,
    /// ePass runs on every program.
    Always,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule<'a> {
    Forced(Option<&'a str>),
    Denied,
    Allowed(Option<&'a str>),
}

/// Administrator policy.
#[derive(Debug)]
pub struct Policy<'a> {
    pub mode: Mode,
    pub allow_user_popt: bool,
    pub allow_ir: bool,
    pub allow_ecall: bool,
    rules: FVec<'a, (&'static str, Rule<'a>)>,
}

impl<'a> Policy<'a> {
    /// The permissive userspace default: opt-in, everything allowed.
    pub fn permissive(heap: &'a Heap<'a>) -> Policy<'a> {
        Policy {
            mode: Mode::OptIn,
            allow_user_popt: true,
            allow_ir: true,
            allow_ecall: false,
            rules: FVec::new(heap),
        }
    }

    /// Parse a policy string, e.g.
    /// `mode=always,user_popt=1,ir=0,+msan,-const_prop,dump_ir`.
    pub fn parse(s: &'a str, heap: &'a Heap<'a>) -> Result<Policy<'a>> {
        if s.len() > MAX_OPTION_LEN {
            return Err(Error::limit("policy string too long"));
        }
        let mut p = Policy::permissive(heap);
        for item in split_items(heap, s)?.iter() {
            let item = *item;
            if let Some((k, v)) = item.split_once('=') {
                let flag = || match v.trim() {
                    "0" => Ok(false),
                    "1" => Ok(true),
                    _ => Err(Error::invalid_input("policy flag must be 0 or 1")),
                };
                match k.trim() {
                    "mode" => {
                        p.mode = match v.trim() {
                            "off" => Mode::Off,
                            "optin" => Mode::OptIn,
                            "always" => Mode::Always,
                            _ => return Err(Error::invalid_input("bad policy mode")),
                        }
                    }
                    "user_popt" => p.allow_user_popt = flag()?,
                    "ir" => p.allow_ir = flag()?,
                    "ecall" => p.allow_ecall = flag()?,
                    _ => return Err(Error::invalid_input("unknown policy key")),
                }
                continue;
            }
            let (rule_of, rest) = match item.strip_prefix('+') {
                Some(r) => (0u8, r),
                None => match item.strip_prefix('-') {
                    Some(r) => (1, r),
                    None => (2, item),
                },
            };
            let (name, args) = name_args(rest)?;
            let info = find(name).ok_or(Error::invalid_input("policy names an unknown pass"))?;
            if p.rules.iter().any(|(n, _)| *n == info.name) {
                return Err(Error::invalid_input("pass named twice in policy"));
            }
            let rule = match rule_of {
                0 => Rule::Forced(args),
                1 if info.mandatory => {
                    return Err(Error::invalid_input("mandatory passes cannot be denied"));
                }
                1 if args.is_some() => {
                    return Err(Error::invalid_input("a denied pass takes no arguments"));
                }
                1 => Rule::Denied,
                _ => Rule::Allowed(args),
            };
            p.rules.push((info.name, rule))?;
        }
        Ok(p)
    }

    pub fn rule(&self, name: &str) -> Rule<'a> {
        self.rules
            .iter()
            .find(|(n, _)| *n == name)
            .map_or(Rule::Allowed(None), |(_, r)| *r)
    }

    pub fn has_forced(&self) -> bool {
        self.rules.iter().any(|(_, r)| matches!(r, Rule::Forced(_)))
    }

    /// Whether ePass should process a program at all.
    pub fn should_run(&self, loader_requested: bool) -> bool {
        match self.mode {
            Mode::Off => false,
            Mode::Always => true,
            Mode::OptIn => loader_requested || self.has_forced(),
        }
    }
}

/// What the host does when compilation fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// Load the original bytecode (fail open); the error goes to the log.
    LoadOriginal,
    /// Reject the load (fail closed).
    Reject,
}

/// One enabled pass with its arguments.
#[derive(Clone, Copy, Debug)]
pub struct Step<'a> {
    pub info: &'static PassInfo,
    pub args: Option<&'a str>,
}

/// The effective, ordered list of passes for one program.
#[derive(Debug)]
pub struct Pipeline<'a> {
    pub steps: FVec<'a, Step<'a>>,
    /// Some pass runs because the policy forces it.
    pub enforced: bool,
}

impl<'a> Pipeline<'a> {
    /// Combine the policy with a loader's popt (see the module table).
    pub fn build(policy: &Policy<'a>, popt: &'a str, heap: &'a Heap<'a>) -> Result<Pipeline<'a>> {
        if popt.len() > MAX_OPTION_LEN {
            return Err(Error::limit("popt too long"));
        }
        // Loader requests by pass name: Some(Some(args)) enable, Some(None)
        // disable (the args field of a `!name` request is never used).
        let mut req: FVec<'a, (&'static str, bool, Option<&'a str>)> = FVec::new(heap);
        let items = split_items(heap, popt)?;
        if !items.is_empty() && !policy.allow_user_popt {
            return Err(Error::new(ErrorKind::Denied, "policy forbids loader pass options"));
        }
        for it in items.iter() {
            let (enable, rest) = match it.strip_prefix('!') {
                Some(r) => (false, r),
                None => (true, *it),
            };
            let (name, args) = name_args(rest)?;
            let info = find(name).ok_or(Error::invalid_input("unknown pass"))?;
            if !enable && args.is_some() {
                return Err(Error::invalid_input("a disabled pass takes no arguments"));
            }
            if !info.user_controllable || info.mandatory {
                return Err(Error::new(ErrorKind::Denied, "pass is not loader-controllable"));
            }
            if req.iter().any(|(n, _, _)| *n == info.name) {
                return Err(Error::invalid_input("pass named twice in popt"));
            }
            req.push((info.name, enable, args))?;
        }
        let order = registry_order(heap)?;
        let mut steps = FVec::new(heap);
        let mut enforced = false;
        for &k in order.iter() {
            let info = REGISTRY.get(k).ok_or(Error::internal("pass"))?;
            let user = req.iter().find(|(n, _, _)| *n == info.name).copied();
            let rule = policy.rule(info.name);
            let on: Option<Option<&'a str>> = match (rule, user) {
                (Rule::Forced(_), Some(_)) => {
                    return Err(Error::new(ErrorKind::Denied, "pass is forced by policy"));
                }
                (Rule::Forced(a), None) => {
                    enforced = true;
                    Some(a)
                }
                (Rule::Denied, Some((_, true, _))) => {
                    return Err(Error::new(ErrorKind::Denied, "pass is denied by policy"));
                }
                (Rule::Denied, _) => None,
                (Rule::Allowed(_), Some((_, true, a))) => Some(a),
                (Rule::Allowed(_), Some((_, false, _))) => None,
                (Rule::Allowed(a), None) => {
                    if info.default_on || info.mandatory {
                        Some(a)
                    } else {
                        None
                    }
                }
            };
            let on = if info.mandatory { Some(on.unwrap_or(None)) } else { on };
            if let Some(args) = on {
                (info.check_args)(args)?;
                steps.push(Step { info, args })?;
            }
        }
        Ok(Pipeline { steps, enforced })
    }

    /// What to do if compiling with this pipeline fails.
    pub fn on_failure(&self, input_is_ir: bool) -> Disposition {
        if input_is_ir || self.enforced {
            Disposition::Reject
        } else {
            Disposition::LoadOriginal
        }
    }

    /// Run every step; validate between passes when requested, and always at
    /// the end.
    pub fn run<'h>(&self, f: &mut Function<'h>, cx: &PassCx<'_, 'h>) -> Result<()> {
        for s in self.steps.iter() {
            crate::ctx_log!(cx.ctx, crate::Level::Debug, "pass {}\n", s.info.name);
            (s.info.run)(f, cx, s.args)?;
            if cx.opts.verify_each {
                verify(f, cx.ctx, cx.opts.allow_ecall)?;
            }
        }
        verify(f, cx.ctx, cx.opts.allow_ecall)
    }

    pub fn names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.steps.iter().map(|s| s.info.name)
    }
}
