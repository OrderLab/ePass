//! The binary IR blob: the stable format the kernel accepts from userspace.
//!
//! Layout (all little-endian, all records fixed-size):
//!
//! ```text
//! header   32 B  magic "EPIR", version u16, flags u16, n_funcs u32,
//!                total_len u32, 16 reserved bytes (zero)
//! function 32 B  n_blocks, n_insns, n_opnds, n_slots, entry (u32 each),
//!                12 reserved bytes (zero)
//! slots     8 B each   size u32, align u16, flags u16 (bit 0: may hold ptr)
//! blocks    8 B each   first_insn u32, n_insns u32 (a partition of insns)
//! insns    32 B each   op u8, a u8, b u8, c u8, x u32, y u32,
//!                      opnd_first u32, opnd_count u32, origin u32, imm u64
//! opnds    16 B each   kind u8, 3 pad, block u32, payload u64
//! ```
//!
//! The decoder is a security boundary: it checks every count against the
//! limits and the blob length with checked arithmetic before reading, checks
//! every index before using it, never recurses, and returns an error for any
//! malformed input. The decoded function must still pass
//! [`crate::ir::verify::verify`].

use crate::ctx::Ctx;
use crate::error::{Error, Result};
use crate::ir::func::At;
use crate::ir::{
    BinOp, BlockId, BuiltinKind, Callee, Cond, FrameSlot, FuncId, Function, InsnId, Op, Size,
    SlotId, SwapKind, SymKind, Value, Width,
};
use crate::mem::{FVec, Heap, Idx, IdxVec};

pub const MAGIC: [u8; 4] = *b"EPIR";
pub const VERSION: u16 = 1;

const HDR: usize = 32;
const FHDR: usize = 32;
const SLOT: usize = 8;
const BLOCK: usize = 8;
const INSN: usize = 32;
const OPND: usize = 16;
const NO_BLOCK: u32 = u32::MAX;
const NO_ORIGIN: u32 = u32::MAX;
/// Upper bound on frame slots (512 bytes of stack, at least 1 byte each).
const MAX_SLOTS: u32 = 512;

/// Byte sink for the encoder.
pub trait Sink {
    fn put(&mut self, bytes: &[u8]) -> Result<()>;
}

impl Sink for FVec<'_, u8> {
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        self.extend_from_slice(bytes)
    }
}

// ----------------------------------------------------------------- opcodes

mod opc {
    pub const BIN: u8 = 1;
    pub const NEG: u8 = 2;
    pub const EXT: u8 = 3;
    pub const BSWAP: u8 = 4;
    pub const LOAD: u8 = 5;
    pub const STORE: u8 = 6;
    pub const LDSYM: u8 = 7;
    pub const SLOTADDR: u8 = 8;
    pub const SLOTLOAD: u8 = 9;
    pub const SLOTSTORE: u8 = 10;
    pub const CALL: u8 = 11;
    pub const ECALL: u8 = 12;
    pub const OPAQUE: u8 = 13;
    pub const PHI: u8 = 14;
    pub const BR: u8 = 15;
    pub const CONDBR: u8 = 16;
    pub const RET: u8 = 17;
    pub const THROW: u8 = 18;
    pub const POISON: u8 = 19;
}

mod vk {
    pub const INSN: u8 = 0;
    pub const CONST: u8 = 1;
    pub const PARAM: u8 = 2;
    pub const FP: u8 = 3;
    pub const UNDEF: u8 = 4;
    pub const BUILTIN: u8 = 5;
}

#[derive(Clone, Copy, Default)]
struct Rec {
    op: u8,
    a: u8,
    b: u8,
    c: u8,
    x: u32,
    y: u32,
    imm: u64,
}

fn width_code(w: Width) -> u8 {
    match w {
        Width::W32 => 0,
        Width::W64 => 1,
    }
}

fn code_width(c: u8) -> Result<Width> {
    match c {
        0 => Ok(Width::W32),
        1 => Ok(Width::W64),
        _ => Err(Error::invalid_ir("blob: bad width")),
    }
}

fn index_of<T: PartialEq + Copy>(all: &[T], v: T) -> u8 {
    all.iter().position(|&x| x == v).map_or(u8::MAX, |p| p as u8)
}

fn encode_op(op: Op) -> Rec {
    let mut r = Rec::default();
    match op {
        Op::Bin { op, w } => {
            r.op = opc::BIN;
            r.a = index_of(&BinOp::ALL, op);
            r.b = width_code(w);
        }
        Op::Neg { w } => {
            r.op = opc::NEG;
            r.b = width_code(w);
        }
        Op::Ext { from, signed, w } => {
            r.op = opc::EXT;
            r.a = from;
            r.b = width_code(w);
            r.c = signed as u8;
        }
        Op::Bswap { bits, kind } => {
            r.op = opc::BSWAP;
            r.a = bits;
            r.c = match kind {
                SwapKind::ToLe => 0,
                SwapKind::ToBe => 1,
                SwapKind::Swap => 2,
            };
        }
        Op::Load { size, signed, off } => {
            r.op = opc::LOAD;
            r.a = size.bytes() as u8;
            r.c = signed as u8;
            r.x = off as i32 as u32;
        }
        Op::Store { size, off } => {
            r.op = opc::STORE;
            r.a = size.bytes() as u8;
            r.x = off as i32 as u32;
        }
        Op::LdSym { kind, imm } => {
            r.op = opc::LDSYM;
            r.a = kind.src_reg();
            r.imm = imm;
        }
        Op::SlotAddr { slot, off } => {
            r.op = opc::SLOTADDR;
            r.x = slot.to_u32();
            r.y = off as u32;
        }
        Op::SlotLoad { slot } => {
            r.op = opc::SLOTLOAD;
            r.x = slot.to_u32();
        }
        Op::SlotStore { slot } => {
            r.op = opc::SLOTSTORE;
            r.x = slot.to_u32();
        }
        Op::Call {
            callee,
            unknown_arity,
        } => {
            r.op = opc::CALL;
            r.c = unknown_arity as u8;
            match callee {
                Callee::Helper(id) => {
                    r.a = 0;
                    r.x = id as u32;
                }
                Callee::Kfunc { btf_id, fd_idx } => {
                    r.a = 1;
                    r.x = btf_id as u32;
                    r.y = fd_idx as i32 as u32;
                }
                Callee::Local(f) => {
                    r.a = 2;
                    r.x = f.to_u32();
                }
            }
        }
        Op::Ecall { id } => {
            r.op = opc::ECALL;
            r.x = id as u32;
        }
        Op::Opaque(o) => {
            r.op = opc::OPAQUE;
            r.imm = o.raw;
        }
        Op::Phi => r.op = opc::PHI,
        Op::Br { target } => {
            r.op = opc::BR;
            r.x = target.to_u32();
        }
        Op::CondBr { cond, w, t, f } => {
            r.op = opc::CONDBR;
            r.a = index_of(&Cond::ALL, cond);
            r.b = width_code(w);
            r.x = t.to_u32();
            r.y = f.to_u32();
        }
        Op::Ret => r.op = opc::RET,
        Op::Throw => r.op = opc::THROW,
        Op::Poison { imm } => {
            r.op = opc::POISON;
            r.x = imm as u32;
        }
    }
    r
}

/// Decode an op; block and slot fields are raw record indices mapped by the
/// caller through `blocks`.
fn decode_op(r: &Rec, blocks: &IdxVec<'_, BlockId, BlockId>, n_slots: u32) -> Result<Op> {
    let block = |i: u32| -> Result<BlockId> {
        blocks
            .get(BlockId(i))
            .copied()
            .ok_or(Error::invalid_ir("blob: block index out of range"))
    };
    let slot = |i: u32| -> Result<SlotId> {
        if i < n_slots {
            Ok(SlotId(i))
        } else {
            Err(Error::invalid_ir("blob: slot index out of range"))
        }
    };
    let flag = |v: u8| -> Result<bool> {
        match v {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::invalid_ir("blob: bad flag")),
        }
    };
    let size = |v: u8| Size::from_bytes(v as u32).ok_or(Error::invalid_ir("blob: bad size"));
    let off16 = |v: u32| i16::try_from(v as i32).map_err(|_| Error::invalid_ir("blob: bad offset"));
    Ok(match r.op {
        opc::BIN => Op::Bin {
            op: *BinOp::ALL
                .get(r.a as usize)
                .ok_or(Error::invalid_ir("blob: bad binop"))?,
            w: code_width(r.b)?,
        },
        opc::NEG => Op::Neg { w: code_width(r.b)? },
        opc::EXT => Op::Ext {
            from: r.a,
            signed: flag(r.c)?,
            w: code_width(r.b)?,
        },
        opc::BSWAP => Op::Bswap {
            bits: r.a,
            kind: match r.c {
                0 => SwapKind::ToLe,
                1 => SwapKind::ToBe,
                2 => SwapKind::Swap,
                _ => return Err(Error::invalid_ir("blob: bad swap kind")),
            },
        },
        opc::LOAD => Op::Load {
            size: size(r.a)?,
            signed: flag(r.c)?,
            off: off16(r.x)?,
        },
        opc::STORE => Op::Store {
            size: size(r.a)?,
            off: off16(r.x)?,
        },
        opc::LDSYM => Op::LdSym {
            kind: SymKind::from_src_reg(r.a).ok_or(Error::invalid_ir("blob: bad sym kind"))?,
            imm: r.imm,
        },
        opc::SLOTADDR => Op::SlotAddr {
            slot: slot(r.x)?,
            off: r.y as i32,
        },
        opc::SLOTLOAD => Op::SlotLoad { slot: slot(r.x)? },
        opc::SLOTSTORE => Op::SlotStore { slot: slot(r.x)? },
        opc::CALL => Op::Call {
            callee: match r.a {
                0 => Callee::Helper(r.x as i32),
                1 => Callee::Kfunc {
                    btf_id: r.x as i32,
                    fd_idx: off16(r.y)?,
                },
                2 => Callee::Local(FuncId(r.x)),
                _ => return Err(Error::invalid_ir("blob: bad callee")),
            },
            unknown_arity: flag(r.c)?,
        },
        opc::ECALL => Op::Ecall { id: r.x as i32 },
        opc::OPAQUE => Op::Opaque(
            crate::ir::verify::opaque_signature(r.imm)
                .ok_or(Error::invalid_ir("blob: bad opaque instruction"))?,
        ),
        opc::PHI => Op::Phi,
        opc::BR => Op::Br { target: block(r.x)? },
        opc::CONDBR => Op::CondBr {
            cond: *Cond::ALL
                .get(r.a as usize)
                .ok_or(Error::invalid_ir("blob: bad condition"))?,
            w: code_width(r.b)?,
            t: block(r.x)?,
            f: block(r.y)?,
        },
        opc::RET => Op::Ret,
        opc::THROW => Op::Throw,
        opc::POISON => Op::Poison { imm: r.x as i32 },
        _ => return Err(Error::invalid_ir("blob: unknown opcode")),
    })
}

// ----------------------------------------------------------------- encoder

fn put_u16(s: &mut dyn Sink, v: u16) -> Result<()> {
    s.put(&v.to_le_bytes())
}
fn put_u32(s: &mut dyn Sink, v: u32) -> Result<()> {
    s.put(&v.to_le_bytes())
}
fn put_u64(s: &mut dyn Sink, v: u64) -> Result<()> {
    s.put(&v.to_le_bytes())
}

fn count_u32(n: usize) -> Result<u32> {
    u32::try_from(n).map_err(|_| Error::limit("blob too large"))
}

/// Encode a single-function module.
pub fn encode(f: &Function<'_>, out: &mut dyn Sink) -> Result<()> {
    let heap = f.heap();
    // Dense numbering: entry block first, then creation order.
    let mut border: FVec<'_, BlockId> = FVec::new(heap);
    border.push(f.entry())?;
    for b in f.blocks() {
        if b != f.entry() {
            border.push(b)?;
        }
    }
    let mut bidx: IdxVec<'_, BlockId, u32> = IdxVec::filled(heap, f.block_id_bound(), NO_BLOCK)?;
    for (k, &b) in border.iter().enumerate() {
        *bidx.at_mut(b)? = count_u32(k)?;
    }
    let mut iidx: IdxVec<'_, InsnId, u32> = IdxVec::filled(heap, f.insn_id_bound(), u32::MAX)?;
    let mut n_insns = 0usize;
    let mut n_opnds = 0usize;
    for &b in border.iter() {
        for i in f.iter_block(b) {
            *iidx.at_mut(i)? = count_u32(n_insns)?;
            n_insns += 1;
            n_opnds += f.operand_count(i)?;
        }
    }
    let n_slots = f.slot_count();
    let total = HDR
        + FHDR
        + SLOT * n_slots
        + BLOCK * border.len()
        + INSN * n_insns
        + OPND * n_opnds;

    out.put(&MAGIC)?;
    put_u16(out, VERSION)?;
    put_u16(out, 0)?;
    put_u32(out, 1)?;
    put_u32(out, count_u32(total)?)?;
    out.put(&[0u8; 16])?;

    put_u32(out, count_u32(border.len())?)?;
    put_u32(out, count_u32(n_insns)?)?;
    put_u32(out, count_u32(n_opnds)?)?;
    put_u32(out, count_u32(n_slots)?)?;
    put_u32(out, 0)?; // entry is block 0 by construction
    out.put(&[0u8; 12])?;

    for (_, s) in f.slots() {
        put_u32(out, s.size)?;
        put_u16(out, u16::try_from(s.align).map_err(|_| Error::invalid_ir("slot align"))?)?;
        put_u16(out, s.may_hold_ptr as u16)?;
    }
    let mut first = 0u32;
    for &b in border.iter() {
        let n = count_u32(f.iter_block(b).count())?;
        put_u32(out, first)?;
        put_u32(out, n)?;
        first += n;
    }
    let mut ofirst = 0u32;
    for &b in border.iter() {
        for i in f.iter_block(b) {
            let d = f.insn(i)?;
            let mut r = encode_op(d.op);
            // Map block references to dense indices.
            match d.op {
                Op::Br { target } => r.x = *bidx.at(target)?,
                Op::CondBr { t, f: fb, .. } => {
                    r.x = *bidx.at(t)?;
                    r.y = *bidx.at(fb)?;
                }
                _ => {}
            }
            let n = count_u32(f.operand_count(i)?)?;
            out.put(&[r.op, r.a, r.b, r.c])?;
            put_u32(out, r.x)?;
            put_u32(out, r.y)?;
            put_u32(out, ofirst)?;
            put_u32(out, n)?;
            put_u32(out, d.origin.unwrap_or(NO_ORIGIN))?;
            put_u64(out, r.imm)?;
            ofirst += n;
        }
    }
    for &b in border.iter() {
        for i in f.iter_block(b) {
            for o in f.operand_ids(i)? {
                let op = f.opnd(o)?;
                let (kind, payload) = match op.value {
                    Value::Insn(d) => (vk::INSN, *iidx.at(d)? as u64),
                    Value::Const(c) => (vk::CONST, c),
                    Value::Param(k) => (vk::PARAM, k as u64),
                    Value::FramePtr => (vk::FP, 0),
                    Value::Undef => (vk::UNDEF, 0),
                    Value::Builtin(k) => (
                        vk::BUILTIN,
                        match k {
                            BuiltinKind::BbInsnCount => 0,
                            BuiltinKind::BbInsnCriticalCount => 1,
                        },
                    ),
                };
                let blk = match op.block {
                    Some(bb) => *bidx.at(bb)?,
                    None => NO_BLOCK,
                };
                out.put(&[kind, 0, 0, 0])?;
                put_u32(out, blk)?;
                put_u64(out, payload)?;
            }
        }
    }
    Ok(())
}

// ----------------------------------------------------------------- decoder

struct Reader<'b> {
    data: &'b [u8],
}

impl Reader<'_> {
    fn bytes<const N: usize>(&self, at: usize) -> Result<[u8; N]> {
        let end = at.checked_add(N).ok_or(Error::invalid_ir("blob: offset overflow"))?;
        let s = self
            .data
            .get(at..end)
            .ok_or(Error::invalid_ir("blob: truncated"))?;
        let mut out = [0u8; N];
        out.copy_from_slice(s);
        Ok(out)
    }
    fn u8(&self, at: usize) -> Result<u8> {
        Ok(self.bytes::<1>(at)?[0])
    }
    fn u16(&self, at: usize) -> Result<u16> {
        Ok(u16::from_le_bytes(self.bytes(at)?))
    }
    fn u32(&self, at: usize) -> Result<u32> {
        Ok(u32::from_le_bytes(self.bytes(at)?))
    }
    fn u64(&self, at: usize) -> Result<u64> {
        Ok(u64::from_le_bytes(self.bytes(at)?))
    }
}

/// Keep resource errors (OOM, limits, interrupts) as they are; anything else
/// from the IR builder means the blob is malformed.
fn malformed(e: Error, msg: &'static str, idx: u32) -> Error {
    use crate::error::ErrorKind::*;
    match e.kind {
        OutOfMemory | Limit | Interrupted => e,
        _ => Error::invalid_ir(msg).at(idx),
    }
}

fn mul_add(acc: usize, n: u32, size: usize) -> Result<usize> {
    (n as usize)
        .checked_mul(size)
        .and_then(|b| acc.checked_add(b))
        .ok_or(Error::invalid_ir("blob: size overflow"))
}

/// Decode a blob into a function. The result still needs validation.
pub fn decode<'h>(data: &[u8], heap: &'h Heap<'h>, ctx: &Ctx<'h>) -> Result<Function<'h>> {
    let r = Reader { data };
    if r.bytes::<4>(0)? != MAGIC {
        return Err(Error::invalid_ir("blob: bad magic"));
    }
    if r.u16(4)? != VERSION {
        return Err(Error::invalid_ir("blob: unsupported version"));
    }
    if r.u16(6)? != 0 {
        return Err(Error::invalid_ir("blob: unknown flags"));
    }
    if r.u32(8)? != 1 {
        return Err(Error::unsupported("blob: exactly one function is supported"));
    }
    if r.u32(12)? as usize != data.len() {
        return Err(Error::invalid_ir("blob: length mismatch"));
    }
    if r.bytes::<16>(16)? != [0u8; 16] {
        return Err(Error::invalid_ir("blob: reserved header bytes"));
    }
    let n_blocks = r.u32(HDR)?;
    let n_insns = r.u32(HDR + 4)?;
    let n_opnds = r.u32(HDR + 8)?;
    let n_slots = r.u32(HDR + 12)?;
    let entry = r.u32(HDR + 16)?;
    if r.bytes::<12>(HDR + 20)? != [0u8; 12] {
        return Err(Error::invalid_ir("blob: reserved function bytes"));
    }
    let max = ctx.limits.max_insns;
    if n_insns > max || n_blocks > n_insns || n_blocks == 0 {
        return Err(Error::limit("blob: instruction/block count"));
    }
    if n_opnds > max.saturating_mul(8) || n_slots > MAX_SLOTS {
        return Err(Error::limit("blob: operand/slot count"));
    }
    if entry != 0 {
        return Err(Error::invalid_ir("blob: entry must be block 0"));
    }
    let slots_at = HDR + FHDR;
    let blocks_at = mul_add(slots_at, n_slots, SLOT)?;
    let insns_at = mul_add(blocks_at, n_blocks, BLOCK)?;
    let opnds_at = mul_add(insns_at, n_insns, INSN)?;
    let end = mul_add(opnds_at, n_opnds, OPND)?;
    if end != data.len() {
        return Err(Error::invalid_ir("blob: section sizes do not match length"));
    }

    let mut f = Function::new(heap)?;
    // Blocks: record 0 is the entry.
    let mut blocks: IdxVec<'h, BlockId, BlockId> = IdxVec::new(heap);
    blocks.push(f.entry())?;
    for _ in 1..n_blocks {
        let b = f.add_block()?;
        blocks.push(b)?;
    }
    for k in 0..n_slots {
        ctx.tick()?;
        let at = slots_at + k as usize * SLOT;
        let flags = r.u16(at + 6)?;
        if flags > 1 {
            return Err(Error::invalid_ir("blob: bad slot flags"));
        }
        f.add_slot(FrameSlot {
            size: r.u32(at)?,
            align: r.u16(at + 4)? as u32,
            may_hold_ptr: flags == 1,
        })?;
    }

    // Instructions: create with placeholder operands, block by block.
    let mut ids: IdxVec<'h, InsnId, InsnId> = IdxVec::new(heap);
    let mut next_insn = 0u32;
    let mut next_opnd = 0u32;
    let mut placeholder: FVec<'h, Value> = FVec::new(heap);
    for bk in 0..n_blocks {
        let at = blocks_at + bk as usize * BLOCK;
        let first = r.u32(at)?;
        let count = r.u32(at + 4)?;
        if first != next_insn || count == 0 {
            return Err(Error::invalid_ir("blob: blocks must partition instructions"));
        }
        let block = *blocks.at(BlockId(bk))?;
        // 0: phis allowed, 1: body, 2: terminator seen.
        let mut phase = 0u8;
        for k in 0..count {
            ctx.tick()?;
            let idx = first
                .checked_add(k)
                .filter(|&i| i < n_insns)
                .ok_or(Error::invalid_ir("blob: instruction index out of range"))?;
            let at = insns_at + idx as usize * INSN;
            let rec = Rec {
                op: r.u8(at)?,
                a: r.u8(at + 1)?,
                b: r.u8(at + 2)?,
                c: r.u8(at + 3)?,
                x: r.u32(at + 4)?,
                y: r.u32(at + 8)?,
                imm: r.u64(at + 24)?,
            };
            let ofirst = r.u32(at + 12)?;
            let ocount = r.u32(at + 16)?;
            let origin = r.u32(at + 20)?;
            if ofirst != next_opnd {
                return Err(Error::invalid_ir("blob: operands must be contiguous"));
            }
            next_opnd = ofirst
                .checked_add(ocount)
                .filter(|&e| e <= n_opnds)
                .ok_or(Error::invalid_ir("blob: operand range out of bounds"))?;
            let op = decode_op(&rec, &blocks, n_slots)?;
            phase = match (phase, matches!(op, Op::Phi), op.is_terminator()) {
                (2, _, _) => return Err(Error::invalid_ir("blob: instruction after terminator").at(idx)),
                (0, true, _) => 0,
                (_, true, _) => return Err(Error::invalid_ir("blob: phi after non-phi").at(idx)),
                (_, false, true) => 2,
                (_, false, false) => 1,
            };
            let id = if matches!(op, Op::Phi) {
                let phi = f.insert_phi(block, &[])?;
                for j in 0..ocount {
                    let oat = opnds_at + (ofirst + j) as usize * OPND;
                    let ib = r.u32(oat + 4)?;
                    let inb = *blocks
                        .get(BlockId(ib))
                        .ok_or(Error::invalid_ir("blob: phi block out of range"))?;
                    f.add_phi_input(phi, Value::Undef, inb)?;
                }
                phi
            } else {
                if ocount > 5 {
                    return Err(Error::invalid_ir("blob: too many operands"));
                }
                placeholder.clear();
                for _ in 0..ocount {
                    placeholder.push(Value::Undef)?;
                }
                let at = if op.is_terminator() {
                    At::End(block)
                } else {
                    At::BeforeTerminator(block)
                };
                f.insert(at, op, placeholder.as_slice())
                    .map_err(|e| malformed(e, "blob: bad instruction placement", idx))?
            };
            f.set_origin(id, if origin == NO_ORIGIN { None } else { Some(origin) })?;
            ids.push(id)?;
            next_insn = idx + 1;
        }
    }
    if next_insn != n_insns || next_opnd != n_opnds {
        return Err(Error::invalid_ir("blob: unused records"));
    }

    // Operand values.
    for idx in 0..n_insns {
        let id = *ids.at(InsnId(idx))?;
        let at = insns_at + idx as usize * INSN;
        let ofirst = r.u32(at + 12)?;
        let ocount = r.u32(at + 16)?;
        let is_phi = matches!(f.op(id)?, Op::Phi);
        for j in 0..ocount {
            ctx.tick()?;
            let oat = opnds_at + (ofirst + j) as usize * OPND;
            let kind = r.u8(oat)?;
            if r.bytes::<3>(oat + 1)? != [0u8; 3] {
                return Err(Error::invalid_ir("blob: operand padding"));
            }
            let blk = r.u32(oat + 4)?;
            if !is_phi && blk != NO_BLOCK {
                return Err(Error::invalid_ir("blob: block on a non-phi operand"));
            }
            let payload = r.u64(oat + 8)?;
            let v = match kind {
                vk::INSN => {
                    let d = u32::try_from(payload)
                        .ok()
                        .filter(|&d| d < n_insns)
                        .ok_or(Error::invalid_ir("blob: operand names no instruction"))?;
                    Value::Insn(*ids.at(InsnId(d))?)
                }
                vk::CONST => Value::Const(payload),
                vk::PARAM => Value::Param(
                    u8::try_from(payload).map_err(|_| Error::invalid_ir("blob: bad param"))?,
                ),
                vk::FP => Value::FramePtr,
                vk::UNDEF => Value::Undef,
                vk::BUILTIN => Value::Builtin(match payload {
                    0 => BuiltinKind::BbInsnCount,
                    1 => BuiltinKind::BbInsnCriticalCount,
                    _ => return Err(Error::invalid_ir("blob: bad builtin")),
                }),
                _ => return Err(Error::invalid_ir("blob: bad operand kind")),
            };
            f.set_operand(id, j as usize, v)
                .map_err(|e| malformed(e, "blob: bad operand", idx))?;
        }
    }
    Ok(f)
}
