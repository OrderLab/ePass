//! One-call compilation shared by the C ABI, `epasstool` and the kernel
//! glue: global options, the ISA target, policy decisions, and the
//! original-to-new instruction offset map.
//!
//! [`run`] returns what the loader should do: load the compiled program,
//! load the original bytecode (ePass skipped or failed open), or reject the
//! load (`Err`, fail closed).

use crate::bpf::{alu, class, jmp, mode, BpfInsn};
use crate::cg::{self, CgOptions};
use crate::ctx::Ctx;
use crate::error::{Error, ErrorKind, Result};
use crate::facts::{Facts, Isa};
use crate::ir::Function;
use crate::log::Level;
use crate::mem::FVec;
use crate::pm::{Disposition, Options, PassCx, Pipeline, Policy, MAX_OPTION_LEN};

/// Global options (gopt): `key[=value]` items separated by commas.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gopt {
    /// `verbose=0..3`: error, warn, info, debug.
    pub level: Level,
    /// `isa=v1..v4`: code generation target (default: see [`target_isa`]).
    pub isa: Option<Isa>,
    /// `ra_colors=4..10`: registers given to the allocator (testing).
    pub ra_colors: u8,
    /// `throw_ret=N`: return value of a lowered `throw`.
    pub throw_ret: i32,
    /// `check` / `nocheck`: run the post-allocation checker.
    pub check: bool,
    /// `verify_each`: validate the IR after every pass.
    pub verify_each: bool,
    /// `endian=little|big`: target byte order (default: the host's).
    pub big_endian: bool,
}

impl Default for Gopt {
    fn default() -> Self {
        Gopt {
            level: Level::Warn,
            isa: None,
            ra_colors: 10,
            throw_ret: 0,
            check: cfg!(debug_assertions),
            verify_each: cfg!(debug_assertions),
            big_endian: cfg!(target_endian = "big"),
        }
    }
}

impl Gopt {
    pub fn parse(s: &str) -> Result<Gopt> {
        if s.len() > MAX_OPTION_LEN {
            return Err(Error::limit("gopt too long"));
        }
        let mut g = Gopt::default();
        for item in s.split(',').map(str::trim).filter(|t| !t.is_empty()) {
            let (key, val) = match item.split_once('=') {
                Some((k, v)) => (k.trim(), Some(v.trim())),
                None => (item, None),
            };
            let num = |lo: i64, hi: i64| -> Result<i64> {
                let v = val.ok_or(Error::invalid_input("gopt option needs a value"))?;
                let n = parse_int(v).ok_or(Error::invalid_input("gopt value is not a number"))?;
                if n < lo || n > hi {
                    return Err(Error::invalid_input("gopt value out of range"));
                }
                Ok(n)
            };
            let flag = || match val {
                None => Ok(()),
                Some(_) => Err(Error::invalid_input("gopt flag takes no value")),
            };
            match key {
                "verbose" => {
                    g.level = match num(0, i64::MAX)? {
                        0 => Level::Error,
                        1 => Level::Warn,
                        2 => Level::Info,
                        _ => Level::Debug,
                    }
                }
                "isa" => {
                    g.isa = Some(match val {
                        Some("v1") => Isa::V1,
                        Some("v2") => Isa::V2,
                        Some("v3") => Isa::V3,
                        Some("v4") => Isa::V4,
                        _ => return Err(Error::invalid_input("isa must be v1, v2, v3 or v4")),
                    })
                }
                "ra_colors" => g.ra_colors = num(4, 10)? as u8,
                "throw_ret" => g.throw_ret = num(i32::MIN as i64, i32::MAX as i64)? as i32,
                "check" => {
                    flag()?;
                    g.check = true;
                }
                "nocheck" => {
                    flag()?;
                    g.check = false;
                }
                "verify_each" => {
                    flag()?;
                    g.verify_each = true;
                }
                "endian" => {
                    g.big_endian = match val {
                        Some("little") => false,
                        Some("big") => true,
                        _ => return Err(Error::invalid_input("endian must be little or big")),
                    }
                }
                _ => return Err(Error::invalid_input("unknown gopt option")),
            }
        }
        Ok(g)
    }
}

/// Decimal or `0x` hexadecimal, optionally negative.
fn parse_int(s: &str) -> Option<i64> {
    let (neg, digits) = match s.strip_prefix('-') {
        Some(d) => (true, d),
        None => (false, s),
    };
    let v = match digits.strip_prefix("0x") {
        Some(h) => i64::from_str_radix(h, 16).ok()?,
        None => digits.parse::<i64>().ok()?,
    };
    Some(if neg { -v } else { v })
}

/// The lowest ISA level covering every instruction of `prog`.
pub fn isa_of(prog: &[BpfInsn]) -> Isa {
    let mut isa = Isa::V1;
    for i in prog {
        let op = i.op();
        let need = match i.class() {
            class::ALU | class::ALU64 if (op == alu::DIV || op == alu::MOD) && i.off == 1 => Isa::V4,
            class::ALU | class::ALU64 if op == alu::MOV && i.off != 0 => Isa::V4,
            class::ALU64 if op == alu::END => Isa::V4,
            class::LDX if i.mode() == mode::MEMSX => Isa::V4,
            class::JMP32 if op == jmp::JA => Isa::V4,
            class::JMP32 => Isa::V3,
            class::JMP if matches!(op, jmp::JLT | jmp::JLE | jmp::JSLT | jmp::JSLE) => Isa::V2,
            _ => Isa::V1,
        };
        isa = isa.max(need);
    }
    isa
}

/// Code generation target: the gopt choice, else the input's own level
/// (bytecode) or the platform's (IR), never above the platform's.
pub fn target_isa(gopt: &Gopt, facts: &dyn Facts, input: &Input<'_>) -> Isa {
    let want = match (gopt.isa, input) {
        (Some(i), _) => i,
        (None, Input::Bytecode(p)) => isa_of(p),
        (None, Input::Ir(_)) => facts.isa(),
    };
    want.min(facts.isa())
}

/// What ePass compiles.
#[derive(Clone, Copy, Debug)]
pub enum Input<'a> {
    Bytecode(&'a [BpfInsn]),
    /// A binary IR blob ([`crate::bin`]).
    Ir(&'a [u8]),
}

/// One compilation request.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    pub input: Input<'a>,
    pub gopt: Gopt,
    /// Loader pass options (popt).
    pub popt: &'a str,
    /// The loader asked for ePass (relevant in `mode=optin`).
    pub requested: bool,
}

/// A compiled program.
#[derive(Debug)]
pub struct Output<'h> {
    pub insns: FVec<'h, BpfInsn>,
    /// For bytecode input, `offsets[i]` is the output index that original
    /// instruction slot `i` maps to (removed instructions map to the next
    /// surviving one), and `offsets[n]` is the output length. Not monotonic
    /// in general: block layout may reorder code. Empty for IR input.
    pub offsets: FVec<'h, u32>,
}

/// What the loader should do.
#[derive(Debug)]
pub enum Outcome<'h> {
    Compiled(Output<'h>),
    /// Load the original bytecode: ePass did not run (`None`) or failed
    /// open (the error, also written to the log).
    LoadOriginal(Option<Error>),
}

/// Run ePass on one program under `policy`. `Err` means reject the load.
pub fn run<'h>(ctx: &Ctx<'h>, facts: &dyn Facts, policy: &Policy<'_>, req: &Request<'_>) -> Result<Outcome<'h>> {
    let is_ir = matches!(req.input, Input::Ir(_));
    if is_ir && !policy.allow_ir {
        return Err(log_err(ctx, Error::new(ErrorKind::Denied, "policy forbids IR input")));
    }
    if !policy.should_run(req.requested) {
        if is_ir {
            return Err(log_err(ctx, Error::new(ErrorKind::Denied, "ePass is disabled by policy")));
        }
        return Ok(Outcome::LoadOriginal(None));
    }
    // Option and policy conflicts always reject: the loader asked for
    // something it cannot have.
    let pipeline = Pipeline::build(policy, req.popt, ctx.heap).map_err(|e| log_err(ctx, e))?;
    match compile(ctx, facts, policy, &pipeline, req) {
        Ok(out) => Ok(Outcome::Compiled(out)),
        Err(e) => {
            let e = log_err(ctx, e);
            if e.kind == ErrorKind::Interrupted {
                return Err(e);
            }
            match pipeline.on_failure(is_ir) {
                Disposition::LoadOriginal => {
                    crate::ctx_log!(ctx, Level::Warn, "epass: loading the original program\n");
                    Ok(Outcome::LoadOriginal(Some(e)))
                }
                Disposition::Reject => Err(e),
            }
        }
    }
}

fn log_err(ctx: &Ctx<'_>, e: Error) -> Error {
    crate::ctx_log!(ctx, Level::Error, "epass: {}\n", e);
    e
}

/// Lift or decode, run the pipeline, generate code.
pub fn compile<'h>(
    ctx: &Ctx<'h>,
    facts: &dyn Facts,
    policy: &Policy<'_>,
    pipeline: &Pipeline<'_>,
    req: &Request<'_>,
) -> Result<Output<'h>> {
    let g = &req.gopt;
    let mut f = load(ctx, facts, req.input)?;
    let opts = Options {
        throw_ret: g.throw_ret,
        verify_each: g.verify_each,
        allow_ecall: policy.allow_ecall,
        big_endian: g.big_endian,
    };
    pipeline.run(&mut f, &PassCx { ctx, facts, opts: &opts })?;
    let co = CgOptions {
        isa: target_isa(g, facts, &req.input),
        big_endian: g.big_endian,
        ra_colors: g.ra_colors,
        check: g.check,
    };
    let enc = cg::compile(&mut f, ctx, &co)?;
    let offsets = match req.input {
        Input::Bytecode(p) => dense_offsets(ctx, p.len(), enc.insns.len(), enc.offsets.as_slice())?,
        Input::Ir(_) => FVec::new(ctx.heap),
    };
    crate::ctx_log!(
        ctx,
        Level::Info,
        "epass: {} -> {} instructions (isa v{})\n",
        match req.input {
            Input::Bytecode(p) => p.len(),
            Input::Ir(_) => 0,
        },
        enc.insns.len(),
        co.isa as u8
    );
    Ok(Output { insns: enc.insns, offsets })
}

/// The input as a validated function.
pub fn load<'h>(ctx: &Ctx<'h>, facts: &dyn Facts, input: Input<'_>) -> Result<Function<'h>> {
    match input {
        Input::Bytecode(p) => crate::lift::lift(p, facts, ctx),
        Input::Ir(blob) => crate::bin::decode(blob, ctx.heap, ctx),
    }
}

/// Expand codegen's sparse `(origin, first emitted)` pairs into one entry
/// per input slot plus the end.
pub fn dense_offsets<'h>(ctx: &Ctx<'h>, n_in: usize, n_out: usize, pairs: &[(u32, u32)]) -> Result<FVec<'h, u32>> {
    const NONE: u32 = u32::MAX;
    let mut map = FVec::with_capacity(ctx.heap, n_in + 1)?;
    map.resize(n_in + 1, NONE)?;
    for &(o, e) in pairs {
        if let Some(slot) = map.as_mut_slice().get_mut(o as usize) {
            if *slot == NONE {
                *slot = e;
            }
        }
    }
    let end = u32::try_from(n_out).map_err(|_| Error::limit("output too long"))?;
    let s = map.as_mut_slice();
    if let Some(last) = s.last_mut() {
        *last = end;
    }
    // The program entry stays the entry, whatever prologue codegen added.
    if let Some(first) = s.first_mut() {
        *first = 0;
    }
    let mut next = end;
    for v in s.iter_mut().rev() {
        if *v == NONE {
            *v = next;
        }
        next = *v;
    }
    Ok(map)
}
