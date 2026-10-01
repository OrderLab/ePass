//! The `.epir` v2 text parser (userspace debugging format; feature `text`).
//!
//! Grammar, one item per line (`;` starts a comment):
//!
//! ```text
//! func main {
//!   slot $0 size=8 align=8 ptr
//! bb0:
//!   %0 = add.64 %arg1, 8
//!   %1 = load.s16 [%0-2]
//!   %2 = phi [%0, bb1], [%1, bb2]
//!   condbr.32.sgt %1, -1, bb1, bb2
//! }
//! ```
//!
//! Instruction names (`%N`) and block labels (`bbN`) are arbitrary numbers;
//! the first label is the entry block. Phi inputs may refer forward; every
//! other operand must already be defined.

use super::func::At;
use super::{
    BinOp, BlockId, BuiltinKind, Callee, Cond, FrameSlot, FuncId, Function, InsnId, Op,
    OpaqueInsn, Size, SlotId, SwapKind, SymKind, Value, Width,
};
use crate::error::{Error, Result};
use crate::mem::{FVec, Heap, IdxVec};
use crate::Ctx;

const NONE: u32 = u32::MAX;

struct Parser<'a, 'h> {
    f: Function<'h>,
    /// name -> InsnId (NONE if undefined)
    names: IdxVec<'h, InsnId, u32>,
    /// label -> BlockId (NONE if undefined)
    labels: IdxVec<'h, BlockId, u32>,
    fixups: FVec<'h, (InsnId, usize, u32)>,
    line: u32,
    _text: &'a str,
}

fn err(msg: &'static str, line: u32) -> Error {
    Error::invalid_input(msg).at(line)
}

fn strip_comment(l: &str) -> &str {
    match l.find(';') {
        Some(p) => l.get(..p).unwrap_or(""),
        None => l,
    }
}

fn parse_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x") {
        return u64::from_str_radix(h, 16).ok();
    }
    if let Some(d) = s.strip_prefix('-') {
        let v: u64 = d.parse().ok()?;
        if v > (1u64 << 63) {
            return None;
        }
        return Some(0u64.wrapping_sub(v));
    }
    s.parse().ok()
}

fn parse_i64(s: &str) -> Option<i64> {
    parse_u64(s).map(|v| v as i64)
}

/// Split `s` at top-level commas (outside brackets and parentheses).
fn split_top<'s>(heap: &'s Heap<'s>, s: &'s str) -> Result<FVec<'s, &'s str>> {
    let mut out = FVec::new(heap);
    let mut depth = 0i32;
    let mut start = 0usize;
    for (i, c) in s.char_indices() {
        match c {
            '[' | '(' => depth += 1,
            ']' | ')' => depth -= 1,
            ',' if depth == 0 => {
                out.push(s.get(start..i).unwrap_or("").trim())?;
                start = i + 1;
            }
            _ => {}
        }
    }
    let last = s.get(start..).unwrap_or("").trim();
    if !last.is_empty() || !out.is_empty() {
        out.push(last)?;
    }
    Ok(out)
}

fn width(s: &str) -> Option<Width> {
    match s {
        "32" => Some(Width::W32),
        "64" => Some(Width::W64),
        _ => None,
    }
}

fn mem_size(s: &str) -> Option<(Size, bool)> {
    Some(match s {
        "u8" => (Size::B1, false),
        "u16" => (Size::B2, false),
        "u32" => (Size::B4, false),
        "u64" => (Size::B8, false),
        "s8" => (Size::B1, true),
        "s16" => (Size::B2, true),
        "s32" => (Size::B4, true),
        _ => return None,
    })
}

fn parse_name_num(s: &str, prefix: &str) -> Option<u32> {
    s.strip_prefix(prefix)?.parse().ok()
}

impl<'a, 'h> Parser<'a, 'h> {
    fn label(&self, s: &str) -> Result<BlockId> {
        let n = parse_name_num(s.trim(), "bb").ok_or(err("bad block label", self.line))?;
        match self.labels.get(BlockId(n)) {
            Some(&b) if b != NONE => Ok(BlockId(b)),
            _ => Err(err("unknown block label", self.line)),
        }
    }

    fn name_lookup(&self, n: u32) -> Option<InsnId> {
        match self.names.get(InsnId(n)) {
            Some(&i) if i != NONE => Some(InsnId(i)),
            _ => None,
        }
    }

    /// Parse a value; `forward` records an unresolved `%N` as a fixup.
    fn value(&mut self, s: &str, forward: Option<(InsnId, usize)>) -> Result<Value> {
        let s = s.trim();
        if let Some(rest) = s.strip_prefix("%arg") {
            let k: u8 = rest.parse().map_err(|_| err("bad %argN", self.line))?;
            return Ok(Value::Param(k));
        }
        if s == "%fp" {
            return Ok(Value::FramePtr);
        }
        if s == "undef" {
            return Ok(Value::Undef);
        }
        if s == "builtin.bb_insn_cnt" {
            return Ok(Value::Builtin(BuiltinKind::BbInsnCount));
        }
        if s == "builtin.bb_insn_critical_cnt" {
            return Ok(Value::Builtin(BuiltinKind::BbInsnCriticalCount));
        }
        if let Some(n) = parse_name_num(s, "%") {
            if let Some(i) = self.name_lookup(n) {
                return Ok(Value::Insn(i));
            }
            return match forward {
                Some((user, k)) => {
                    self.fixups.push((user, k, n))?;
                    Ok(Value::Undef)
                }
                None => Err(err("use of undefined value", self.line)),
            };
        }
        parse_u64(s)
            .map(Value::Const)
            .ok_or(err("bad value", self.line))
    }

    /// `[base+off]` / `[base-off]`.
    fn addr(&mut self, s: &str) -> Result<(Value, i16)> {
        let inner = s
            .trim()
            .strip_prefix('[')
            .and_then(|x| x.strip_suffix(']'))
            .ok_or(err("bad address", self.line))?;
        let split = inner
            .rfind(['+', '-'])
            .filter(|&p| p > 0)
            .ok_or(err("address needs an offset", self.line))?;
        let base = self.value(inner.get(..split).unwrap_or(""), None)?;
        let off = parse_i64(inner.get(split..).unwrap_or("").trim_start_matches('+'))
            .and_then(|o| i16::try_from(o).ok())
            .ok_or(err("bad address offset", self.line))?;
        Ok((base, off))
    }

    fn slot(&self, s: &str) -> Result<(SlotId, i32)> {
        let s = s.trim().strip_prefix('$').ok_or(err("bad slot", self.line))?;
        let split = s.find(['+', '-']);
        let (num, off) = match split {
            Some(p) => (
                s.get(..p).unwrap_or(""),
                parse_i64(s.get(p..).unwrap_or("").trim_start_matches('+'))
                    .and_then(|o| i32::try_from(o).ok())
                    .ok_or(err("bad slot offset", self.line))?,
            ),
            None => (s, 0),
        };
        let n: u32 = num.parse().map_err(|_| err("bad slot", self.line))?;
        Ok((SlotId(n), off))
    }

    fn define(&mut self, name: Option<u32>, id: InsnId) -> Result<()> {
        let Some(n) = name else { return Ok(()) };
        if !self.f.insn(id)?.op.has_result() {
            return Err(err("instruction has no result to name", self.line));
        }
        let slot = self
            .names
            .get_mut(InsnId(n))
            .ok_or(err("value name out of range", self.line))?;
        if *slot != NONE {
            return Err(err("value defined twice", self.line));
        }
        *slot = id.0;
        Ok(())
    }

    fn insn(&mut self, block: BlockId, text: &str) -> Result<()> {
        let heap = self.f.heap();
        let (name, body) = match text.split_once('=') {
            Some((lhs, rhs)) if lhs.trim().starts_with('%') && !lhs.contains('[') => {
                let n = parse_name_num(lhs.trim(), "%").ok_or(err("bad value name", self.line))?;
                (Some(n), rhs.trim())
            }
            _ => (None, text.trim()),
        };
        let (mn, rest) = match body.find([' ', '(']) {
            Some(p) => (body.get(..p).unwrap_or(""), body.get(p..).unwrap_or("").trim()),
            None => (body, ""),
        };
        let mut parts = mn.split('.');
        let head = parts.next().unwrap_or("");
        let a1 = parts.next();
        let a2 = parts.next();
        let at = At::End(block);

        // Phis: inputs may refer forward.
        if head == "phi" {
            let id = self.f.insert_phi(block, &[])?;
            self.define(name, id)?;
            let items = split_top(heap, rest)?;
            for (k, it) in items.iter().enumerate() {
                let inner = it
                    .strip_prefix('[')
                    .and_then(|x| x.strip_suffix(']'))
                    .ok_or(err("bad phi input", self.line))?;
                let (v, b) = inner.rsplit_once(',').ok_or(err("bad phi input", self.line))?;
                let b = self.label(b)?;
                let v = self.value(v, Some((id, k)))?;
                self.f.add_phi_input(id, v, b)?;
            }
            return Ok(());
        }

        let mut args: FVec<'h, Value> = FVec::new(heap);
        let op = match head {
            "neg" => {
                args.push(self.value(rest, None)?)?;
                Op::Neg {
                    w: a1.and_then(width).ok_or(err("bad width", self.line))?,
                }
            }
            "zext" | "sext" => {
                args.push(self.value(rest, None)?)?;
                let from: u8 = a1
                    .and_then(|s| s.parse().ok())
                    .ok_or(err("bad extension", self.line))?;
                Op::Ext {
                    from,
                    signed: head == "sext",
                    w: a2.and_then(width).ok_or(err("bad width", self.line))?,
                }
            }
            "bswap" => {
                args.push(self.value(rest, None)?)?;
                let kind = match a1 {
                    Some("le") => SwapKind::ToLe,
                    Some("be") => SwapKind::ToBe,
                    Some("swap") => SwapKind::Swap,
                    _ => return Err(err("bad bswap kind", self.line)),
                };
                let bits: u8 = a2
                    .and_then(|s| s.parse().ok())
                    .ok_or(err("bad bswap width", self.line))?;
                Op::Bswap { bits, kind }
            }
            "load" => {
                let (size, signed) = a1.and_then(mem_size).ok_or(err("bad load size", self.line))?;
                let (base, off) = self.addr(rest)?;
                args.push(base)?;
                Op::Load { size, signed, off }
            }
            "store" => {
                let (size, signed) = a1.and_then(mem_size).ok_or(err("bad store size", self.line))?;
                if signed {
                    return Err(err("stores are unsigned", self.line));
                }
                let items = split_top(heap, rest)?;
                if items.len() != 2 {
                    return Err(err("store needs address and value", self.line));
                }
                let (base, off) = self.addr(items.first().copied().unwrap_or(""))?;
                args.push(base)?;
                args.push(self.value(items.get(1).copied().unwrap_or(""), None)?)?;
                Op::Store { size, off }
            }
            "ldsym" => {
                let kind = match a1 {
                    Some("map_fd") => SymKind::MapFd,
                    Some("map_value_fd") => SymKind::MapValueFd,
                    Some("btf_id") => SymKind::BtfId,
                    Some("func") => SymKind::Func,
                    Some("map_idx") => SymKind::MapIdx,
                    Some("map_value_idx") => SymKind::MapValueIdx,
                    _ => return Err(err("bad ldsym kind", self.line)),
                };
                let imm = parse_u64(rest).ok_or(err("bad immediate", self.line))?;
                Op::LdSym { kind, imm }
            }
            "slotaddr" => {
                let (slot, off) = self.slot(rest)?;
                Op::SlotAddr { slot, off }
            }
            "slotload" => {
                let (slot, _) = self.slot(rest)?;
                Op::SlotLoad { slot }
            }
            "slotstore" => {
                let items = split_top(heap, rest)?;
                let (slot, _) = self.slot(items.first().copied().unwrap_or(""))?;
                args.push(self.value(items.get(1).copied().unwrap_or(""), None)?)?;
                Op::SlotStore { slot }
            }
            "call" => {
                let unknown_arity = a1 == Some("unknown");
                let (target, list) = rest.split_once('(').ok_or(err("bad call", self.line))?;
                let list = list.strip_suffix(')').ok_or(err("bad call", self.line))?;
                let target = target.trim();
                let callee = if let Some(id) = target.strip_prefix("helper#") {
                    Callee::Helper(parse_i64(id).and_then(|v| i32::try_from(v).ok()).ok_or(err("bad helper id", self.line))?)
                } else if let Some(k) = target.strip_prefix("kfunc#") {
                    let (id, fd) = k.split_once(':').ok_or(err("bad kfunc", self.line))?;
                    Callee::Kfunc {
                        btf_id: parse_i64(id).and_then(|v| i32::try_from(v).ok()).ok_or(err("bad kfunc id", self.line))?,
                        fd_idx: parse_i64(fd).and_then(|v| i16::try_from(v).ok()).ok_or(err("bad kfunc fd", self.line))?,
                    }
                } else if let Some(l) = target.strip_prefix("local#") {
                    Callee::Local(FuncId(l.parse().map_err(|_| err("bad local id", self.line))?))
                } else {
                    return Err(err("bad call target", self.line));
                };
                for it in split_top(heap, list)?.iter() {
                    args.push(self.value(it, None)?)?;
                }
                Op::Call {
                    callee,
                    unknown_arity,
                }
            }
            "opaque" => {
                let (raw, list) = rest.split_once('(').ok_or(err("bad opaque", self.line))?;
                let list = list.strip_suffix(')').ok_or(err("bad opaque", self.line))?;
                let raw = parse_u64(raw).ok_or(err("bad opaque encoding", self.line))?;
                let sig: OpaqueInsn = super::verify::opaque_signature(raw)
                    .ok_or(err("instruction cannot be opaque", self.line))?;
                for it in split_top(heap, list)?.iter() {
                    args.push(self.value(it, None)?)?;
                }
                Op::Opaque(sig)
            }
            "br" => Op::Br {
                target: self.label(rest)?,
            },
            "condbr" => {
                let w = a1.and_then(width).ok_or(err("bad width", self.line))?;
                let cond = Cond::ALL
                    .iter()
                    .copied()
                    .find(|c| Some(c.name()) == a2)
                    .ok_or(err("bad condition", self.line))?;
                let items = split_top(heap, rest)?;
                if items.len() != 4 {
                    return Err(err("condbr needs a, b, true, false", self.line));
                }
                args.push(self.value(items.first().copied().unwrap_or(""), None)?)?;
                args.push(self.value(items.get(1).copied().unwrap_or(""), None)?)?;
                let t = self.label(items.get(2).copied().unwrap_or(""))?;
                let fb = self.label(items.get(3).copied().unwrap_or(""))?;
                Op::CondBr { cond, w, t, f: fb }
            }
            "ret" => {
                args.push(self.value(rest, None)?)?;
                Op::Ret
            }
            "throw" => Op::Throw,
            "poison" => Op::Poison {
                imm: parse_i64(rest)
                    .and_then(|v| i32::try_from(v).ok())
                    .ok_or(err("bad poison id", self.line))?,
            },
            _ if head.starts_with("ecall#") => {
                let id = parse_i64(head.trim_start_matches("ecall#"))
                    .and_then(|v| i32::try_from(v).ok())
                    .ok_or(err("bad ecall id", self.line))?;
                let list = rest
                    .strip_prefix('(')
                    .and_then(|x| x.strip_suffix(')'))
                    .ok_or(err("bad ecall", self.line))?;
                for it in split_top(heap, list)?.iter() {
                    args.push(self.value(it, None)?)?;
                }
                Op::Ecall { id }
            }
            _ => {
                let op = BinOp::ALL
                    .iter()
                    .copied()
                    .find(|o| o.name() == head)
                    .ok_or(err("unknown instruction", self.line))?;
                let w = a1.and_then(width).ok_or(err("bad width", self.line))?;
                let items = split_top(heap, rest)?;
                if items.len() != 2 {
                    return Err(err("binary op needs two operands", self.line));
                }
                args.push(self.value(items.first().copied().unwrap_or(""), None)?)?;
                args.push(self.value(items.get(1).copied().unwrap_or(""), None)?)?;
                Op::Bin { op, w }
            }
        };
        let id = self
            .f
            .insert(at, op, args.as_slice())
            .map_err(|e| if e.pos.is_none() { e.at(self.line) } else { e })?;
        self.f.set_origin(id, None)?;
        self.define(name, id)?;
        Ok(())
    }
}

/// Parse `.epir` text into a function. The result is not yet validated; run
/// [`super::verify::verify`] on it.
pub fn parse<'h>(text: &str, heap: &'h Heap<'h>, ctx: &Ctx<'h>) -> Result<Function<'h>> {
    let bound = text.len().saturating_add(1);
    let mut p = Parser {
        f: Function::new(heap)?,
        names: IdxVec::filled(heap, bound, NONE)?,
        labels: IdxVec::filled(heap, bound, NONE)?,
        fixups: FVec::new(heap),
        line: 0,
        _text: text,
    };
    // Pass 1: labels and slots.
    let mut first = true;
    for (ln, raw) in text.lines().enumerate() {
        ctx.tick()?;
        let l = strip_comment(raw).trim();
        if let Some(lab) = l.strip_suffix(':') {
            let n = parse_name_num(lab, "bb").ok_or(err("bad block label", ln as u32 + 1))?;
            let b = if first { p.f.entry() } else { p.f.add_block()? };
            first = false;
            let slot = p
                .labels
                .get_mut(BlockId(n))
                .ok_or(err("label out of range", ln as u32 + 1))?;
            if *slot != NONE {
                return Err(err("block defined twice", ln as u32 + 1));
            }
            *slot = b.0;
        } else if let Some(rest) = l.strip_prefix("slot ") {
            let mut it = rest.split_whitespace();
            let id = it
                .next()
                .and_then(|s| s.strip_prefix('$'))
                .and_then(|s| s.parse::<u32>().ok())
                .ok_or(err("bad slot", ln as u32 + 1))?;
            let mut size = 0u32;
            let mut align = 8u32;
            let mut ptr = false;
            for kv in it {
                if kv == "ptr" {
                    ptr = true;
                } else if let Some(v) = kv.strip_prefix("size=") {
                    size = v.parse().map_err(|_| err("bad slot size", ln as u32 + 1))?;
                } else if let Some(v) = kv.strip_prefix("align=") {
                    align = v.parse().map_err(|_| err("bad slot align", ln as u32 + 1))?;
                } else {
                    return Err(err("bad slot attribute", ln as u32 + 1));
                }
            }
            let got = p.f.add_slot(FrameSlot {
                size,
                align,
                may_hold_ptr: ptr,
            })?;
            if got.0 != id {
                return Err(err("slots must be numbered in order", ln as u32 + 1));
            }
        }
    }
    if first {
        return Err(Error::invalid_input("no blocks"));
    }
    // Pass 2: instructions.
    let mut cur: Option<BlockId> = None;
    for (ln, raw) in text.lines().enumerate() {
        ctx.tick()?;
        p.line = ln as u32 + 1;
        let l = strip_comment(raw).trim();
        if l.is_empty() || l.starts_with("func ") || l == "}" || l.starts_with("slot ") {
            continue;
        }
        if let Some(lab) = l.strip_suffix(':') {
            cur = Some(p.label(lab)?);
            continue;
        }
        let b = cur.ok_or(err("instruction outside a block", p.line))?;
        p.insn(b, l)?;
    }
    // Resolve forward phi references.
    for k in 0..p.fixups.len() {
        let (phi, idx, n) = *p.fixups.get(k).ok_or(Error::internal("fixup"))?;
        let id = p
            .name_lookup(n)
            .ok_or(Error::invalid_input("phi input names an undefined value"))?;
        p.f.set_operand(phi, idx, Value::Insn(id))?;
    }
    Ok(p.f)
}
