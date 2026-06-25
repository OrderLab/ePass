//! The lifter: translates raw eBPF bytecode into SSA-form IR.
//!
//! Pipeline (mirrors the C `bpf_ir.c`):
//! 1. Discover basic blocks by scanning for jump targets and fallthroughs.
//! 2. Build the SSA form on the fly using Braun et al.'s algorithm
//!    ("Simple and Efficient Construction of SSA Form").
//! 3. Translate each eBPF opcode into one or more IR instructions.
//! 4. Compute CFG successors, the reachable-block chain layout, and end blocks.

use std::collections::HashMap;

use crate::bytecode::{self as bc, BpfInsn};
use crate::env::{Env, Timer};
use crate::error::Result;
use crate::helpers::helper_arg_num;
use crate::ir::insn::{BinOp, Cond, EndKind, InsnKind};
use crate::ir::value::{AddrValue, AluOp, ConstKind, LoadImmExtra, PhiValue, RawPos, RawPosKind, VrType};
use crate::ir::{BbId, Function, InsnId, InsertPos, Value};
use crate::{internal, invalid, unsupported};

/// A pre-IR (raw) instruction, with 64-bit immediates already joined.
#[derive(Debug, Clone, Copy)]
struct PreInsn {
    insn: BpfInsn,
    imm64: i64,
    /// Position in the original bytecode.
    pos: usize,
}

/// A pre-IR basic block, identified by the bytecode position of its entrance.
struct PreBlock {
    start: usize,
    end: usize, // exclusive
    insns: Vec<PreInsn>,
    pred_positions: Vec<usize>,
    /// The corresponding real IR block.
    ir_bb: BbId,
    sealed: bool,
    filled: bool,
    /// Incomplete phi nodes awaiting sealing, keyed by register.
    incomplete_phis: [Option<InsnId>; bc::MAX_BPF_REG],
}

/// SSA construction state.
struct Ssa<'e> {
    #[allow(dead_code)]
    env: &'e mut Env,
    func: Function,
    blocks: Vec<PreBlock>,
    /// `entrance position -> pre-block index`.
    by_entrance: HashMap<usize, usize>,
    entry_idx: usize,
    /// `current_def[reg][block_idx] = value`.
    current_def: Vec<HashMap<usize, Value>>,
    /// Total bytecode length (for fallthrough successor detection).
    total_len: usize,
}

/// Returns true if a raw instruction ends a basic block (any jump except call).
fn is_breakpoint(insn: &BpfInsn) -> bool {
    let code = insn.code;
    let class = bc::class_of(code);
    if class == bc::class::JMP || class == bc::class::JMP32 {
        bc::op_of(code) != bc::op::CALL
    } else {
        false
    }
}

fn is_cond_jump_op(op: u8) -> bool {
    matches!(
        op,
        bc::op::JEQ
            | bc::op::JGT
            | bc::op::JGE
            | bc::op::JSET
            | bc::op::JNE
            | bc::op::JSGT
            | bc::op::JSGE
            | bc::op::JLT
            | bc::op::JLE
            | bc::op::JSLT
            | bc::op::JSLE
    )
}

/// Discover basic-block entrances and build pre-blocks with predecessor links.
fn discover_blocks(env: &mut Env, insns: &mut [BpfInsn]) -> Result<(Vec<(usize, Vec<usize>)>,)> {
    // Normalize `pc+0` conditional jumps into NOPs (ja +0), as the C lifter does.
    for i in 0..insns.len() {
        let code = insns[i].code;
        let class = bc::class_of(code);
        if (class == bc::class::JMP || class == bc::class::JMP32)
            && is_cond_jump_op(bc::op_of(code))
            && insns[i].off == 0
        {
            insns[i] = BpfInsn::new(bc::class::JMP | bc::op::JA, 0, 0, 0, 0);
        }
    }

    // entrance position -> list of predecessor (source) positions
    let mut entrances: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut order: Vec<usize> = Vec::new();
    let ensure = |entrances: &mut HashMap<usize, Vec<usize>>,
                      order: &mut Vec<usize>,
                      pos: usize| {
        if !entrances.contains_key(&pos) {
            entrances.insert(pos, Vec::new());
            order.push(pos);
        }
    };

    let len = insns.len();
    for i in 0..len {
        let code = insns[i].code;
        let class = bc::class_of(code);
        if class != bc::class::JMP && class != bc::class::JMP32 {
            continue;
        }
        let op = bc::op_of(code);
        if op == bc::op::JA {
            if class != bc::class::JMP {
                return Err(unsupported!("BPF_JA only allows JMP class (no JMP32 JA)"));
            }
            let target = (i as i64 + insns[i].off as i64 + 1) as usize;
            ensure(&mut entrances, &mut order, target);
            entrances.get_mut(&target).unwrap().push(i);
        } else if is_cond_jump_op(op) {
            let target = (i as i64 + insns[i].off as i64 + 1) as usize;
            let fallthrough = i + 1;
            ensure(&mut entrances, &mut order, target);
            entrances.get_mut(&target).unwrap().push(i);
            ensure(&mut entrances, &mut order, fallthrough);
            entrances.get_mut(&fallthrough).unwrap().push(i);
        } else if op == bc::op::EXIT {
            if i + 1 < len {
                ensure(&mut entrances, &mut order, i + 1);
            }
        }
    }
    // Entry block at 0 (no predecessors).
    ensure(&mut entrances, &mut order, 0);

    let _ = env;
    order.sort_unstable();

    // Add fallthrough predecessors: for every entrance `e > 0`, if the previous
    // instruction `e-1` does not itself terminate a block (not a breakpoint),
    // then control falls through from `e-1` into `e`. We record `e-1` as a
    // predecessor source position; `block_of_pos` later maps it to its block.
    for &e in &order {
        if e == 0 {
            continue;
        }
        let prev = e - 1;
        if !is_breakpoint(&insns[prev]) {
            let preds = entrances.get_mut(&e).unwrap();
            if !preds.contains(&prev) {
                preds.push(prev);
            }
        }
    }

    let result: Vec<(usize, Vec<usize>)> = order
        .into_iter()
        .map(|pos| (pos, entrances.remove(&pos).unwrap()))
        .collect();
    Ok((result,))
}

impl<'e> Ssa<'e> {
    /// Given a bytecode position, find the pre-block that contains it.
    fn block_of_pos(&self, pos: usize) -> Option<usize> {
        // blocks are sorted by start; find the last block whose start <= pos
        // and whose range contains pos.
        let mut found = None;
        for (idx, b) in self.blocks.iter().enumerate() {
            if b.start <= pos {
                found = Some(idx);
            } else {
                break;
            }
        }
        let idx = found?;
        if pos < self.blocks[idx].end {
            Some(idx)
        } else {
            None
        }
    }

    fn write_var(&mut self, reg: u8, block: usize, val: Value) {
        self.current_def[reg as usize].insert(block, val);
    }

    fn is_var_defined(&self, reg: u8, block: usize) -> bool {
        self.current_def[reg as usize].contains_key(&block)
    }

    fn read_var(&mut self, reg: u8, block: usize) -> Result<Value> {
        if reg == bc::BPF_REG_10 {
            return Ok(Value::Insn(self.func.sp));
        }
        if let Some(&v) = self.current_def[reg as usize].get(&block) {
            return Ok(v);
        }
        if block == self.entry_idx {
            // Entry block defines r1..r5 from function arguments.
            if reg >= bc::BPF_REG_1 && (reg as usize) <= bc::MAX_FUNC_ARG {
                return Ok(Value::Insn(self.func.args[(reg - 1) as usize]));
            }
            return Err(invalid!(
                "read of undefined r{reg} in entry block (invalid program)"
            ));
        }
        self.read_var_recursive(reg, block)
    }

    fn read_var_recursive(&mut self, reg: u8, block: usize) -> Result<Value> {
        let (sealed, single_pred) = {
            let b = &self.blocks[block];
            (b.sealed, if b.pred_positions.len() == 1 { Some(b.pred_positions[0]) } else { None })
        };
        let val;
        if !sealed {
            // Incomplete CFG: place an empty phi to be completed at seal time.
            let ir_bb = self.blocks[block].ir_bb;
            let phi = self.func.create_insn(ir_bb, InsnKind::Phi, InsertPos::Front);
            self.blocks[block].incomplete_phis[reg as usize] = Some(phi);
            val = Value::Insn(phi);
        } else if let Some(pred_pos) = single_pred {
            let pred_block = self
                .block_of_pos(pred_pos)
                .ok_or_else(|| internal!("predecessor block not found for pos {pred_pos}"))?;
            val = self.read_var(reg, pred_block)?;
        } else {
            let ir_bb = self.blocks[block].ir_bb;
            let phi = self.func.create_insn(ir_bb, InsnKind::Phi, InsertPos::Front);
            let v = Value::Insn(phi);
            self.write_var(reg, block, v);
            self.add_phi_operands(reg, phi, block)?;
            val = v;
        }
        self.write_var(reg, block, val);
        Ok(val)
    }

    fn add_phi_operands(&mut self, reg: u8, phi: InsnId, block: usize) -> Result<()> {
        // Map predecessor source positions to their owning blocks, deduplicating
        // so each predecessor block contributes exactly one phi entry.
        let pred_positions = self.blocks[block].pred_positions.clone();
        let mut pred_blocks: Vec<usize> = Vec::new();
        for pred_pos in pred_positions {
            let pb = self
                .block_of_pos(pred_pos)
                .ok_or_else(|| internal!("phi predecessor block not found for pos {pred_pos}"))?;
            if !pred_blocks.contains(&pb) {
                pred_blocks.push(pb);
            }
        }
        for pred_block in pred_blocks {
            let value = self.read_var(reg, pred_block)?;
            let pred_bb = self.blocks[pred_block].ir_bb;
            self.func.insn_mut(phi).phi.push(PhiValue { value, bb: pred_bb });
            self.func.add_use(value, phi);
        }
        Ok(())
    }

    /// Seal a block: complete any incomplete phis now that its predecessors
    /// are all filled.
    fn seal_block(&mut self, block: usize) -> Result<()> {
        for reg in 0..bc::MAX_BPF_REG {
            if let Some(phi) = self.blocks[block].incomplete_phis[reg] {
                self.blocks[block].incomplete_phis[reg] = None;
                self.add_phi_operands(reg as u8, phi, block)?;
            }
        }
        self.blocks[block].sealed = true;
        Ok(())
    }

    /// Build a constant or register source value for an instruction operand.
    fn src_value(&mut self, block: usize, p: &PreInsn) -> Result<Value> {
        let code = p.insn.code;
        if bc::src_of(code) == bc::src::K {
            Ok(Value::Const {
                v: p.insn.imm as i64,
                ty: AluOp::Alu32,
                kind: ConstKind::Plain,
                builtin: crate::ir::value::BuiltinConst::None,
            })
        } else {
            self.read_var(p.insn.src_reg, block)
        }
    }

    fn alu_class(code: u8) -> AluOp {
        if bc::class_of(code) == bc::class::ALU {
            AluOp::Alu32
        } else {
            AluOp::Alu64
        }
    }

    /// Build `dst = dst <op> src` and record the new SSA def for `dst_reg`.
    fn emit_bin(&mut self, block: usize, p: &PreInsn, op: BinOp) -> Result<()> {
        let alu = Self::alu_class(p.insn.code);
        let lhs = self.read_var(p.insn.dst_reg, block)?;
        let rhs = self.src_value(block, p)?;
        let ir_bb = self.blocks[block].ir_bb;
        let id = self.func.create_insn(ir_bb, InsnKind::Bin { op }, InsertPos::Back);
        {
            let insn = self.func.insn_mut(id);
            insn.alu_op = alu;
            insn.values.push(lhs);
            insn.values.push(rhs);
            insn.raw_pos = RawPos::at(p.pos, RawPosKind::Insn);
        }
        self.func.add_use(lhs, id);
        self.func.add_use(rhs, id);
        self.write_var(p.insn.dst_reg, block, Value::Insn(id));
        Ok(())
    }

    fn emit_unary(&mut self, block: usize, p: &PreInsn, kind: InsnKind) -> Result<()> {
        let alu = Self::alu_class(p.insn.code);
        let operand = self.read_var(p.insn.dst_reg, block)?;
        let ir_bb = self.blocks[block].ir_bb;
        let id = self.func.create_insn(ir_bb, kind, InsertPos::Back);
        {
            let insn = self.func.insn_mut(id);
            insn.alu_op = alu;
            insn.values.push(operand);
            insn.raw_pos = RawPos::at(p.pos, RawPosKind::Insn);
        }
        self.func.add_use(operand, id);
        self.write_var(p.insn.dst_reg, block, Value::Insn(id));
        Ok(())
    }

    fn emit_cond_jmp(&mut self, block: usize, p: &PreInsn, cond: Cond) -> Result<()> {
        let alu = if bc::class_of(p.insn.code) == bc::class::JMP {
            AluOp::Alu64
        } else {
            AluOp::Alu32
        };
        let lhs = self.read_var(p.insn.dst_reg, block)?;
        let rhs = self.src_value(block, p)?;
        let fallthrough = self.ir_bb_at_pos(p.pos + 1)?;
        let target = self.ir_bb_at_pos((p.pos as i64 + p.insn.off as i64 + 1) as usize)?;
        let ir_bb = self.blocks[block].ir_bb;
        let id = self.func.create_insn(ir_bb, InsnKind::CondJmp { cond }, InsertPos::Back);
        {
            let insn = self.func.insn_mut(id);
            insn.alu_op = alu;
            insn.values.push(lhs);
            insn.values.push(rhs);
            insn.bb1 = Some(fallthrough);
            insn.bb2 = Some(target);
            insn.raw_pos = RawPos::at(p.pos, RawPosKind::Insn);
        }
        self.func.add_use(lhs, id);
        self.func.add_use(rhs, id);
        Ok(())
    }

    fn ir_bb_at_pos(&self, pos: usize) -> Result<BbId> {
        let idx = *self
            .by_entrance
            .get(&pos)
            .ok_or_else(|| internal!("no basic block starts at pos {pos}"))?;
        Ok(self.blocks[idx].ir_bb)
    }

    /// Translate every instruction in a pre-block into IR, recursing into succs.
    fn fill_block(&mut self, block: usize) -> Result<()> {
        if self.blocks[block].sealed && self.blocks[block].filled {
            return Ok(());
        }
        // Seal if all predecessors are filled.
        let all_preds_filled = {
            let pred_positions = self.blocks[block].pred_positions.clone();
            pred_positions.iter().all(|&pp| {
                self.block_of_pos(pp)
                    .map(|pb| self.blocks[pb].filled)
                    .unwrap_or(true)
            })
        };
        if all_preds_filled && !self.blocks[block].sealed {
            self.seal_block(block)?;
        }
        if self.blocks[block].filled {
            return Ok(());
        }

        let pre_insns = self.blocks[block].insns.clone();
        for p in &pre_insns {
            self.translate(block, p)?;
        }
        self.blocks[block].filled = true;

        // Recurse into successors (by CFG positions).
        let succ_positions = self.successor_positions(block);
        for sp in succ_positions {
            if let Some(sb) = self.by_entrance.get(&sp).copied() {
                self.fill_block(sb)?;
            }
        }
        Ok(())
    }

    /// The bytecode positions of a pre-block's CFG successors.
    fn successor_positions(&self, block: usize) -> Vec<usize> {
        let b = &self.blocks[block];
        let last = b.insns.last();
        let mut succs = Vec::new();
        if let Some(p) = last {
            let code = p.insn.code;
            let class = bc::class_of(code);
            if class == bc::class::JMP || class == bc::class::JMP32 {
                let op = bc::op_of(code);
                if op == bc::op::JA {
                    succs.push((p.pos as i64 + p.insn.off as i64 + 1) as usize);
                    return succs;
                } else if is_cond_jump_op(op) {
                    succs.push(p.pos + 1);
                    succs.push((p.pos as i64 + p.insn.off as i64 + 1) as usize);
                    return succs;
                } else if op == bc::op::EXIT {
                    return succs; // no successors
                }
            }
        }
        // Fallthrough to the next block.
        if b.end < self.total_len {
            succs.push(b.end);
        }
        succs
    }

    fn translate(&mut self, block: usize, p: &PreInsn) -> Result<()> {
        let code = p.insn.code;
        let class = bc::class_of(code);
        match class {
            bc::class::ALU | bc::class::ALU64 => self.translate_alu(block, p),
            bc::class::LD if bc::mode_of(code) == bc::mode::IMM && bc::size_of(code) == bc::size::DW => {
                self.translate_ld_imm64(block, p)
            }
            bc::class::LDX if bc::mode_of(code) == bc::mode::MEM || bc::mode_of(code) == bc::mode::MEMSX => {
                self.translate_load(block, p)
            }
            bc::class::ST if bc::mode_of(code) == bc::mode::MEM => self.translate_store_imm(block, p),
            bc::class::STX if bc::mode_of(code) == bc::mode::MEM => self.translate_store_reg(block, p),
            bc::class::JMP | bc::class::JMP32 => self.translate_jmp(block, p),
            _ => Err(unsupported!(
                "instruction class 0x{:02x} at pos {} not supported",
                class,
                p.pos
            )),
        }
    }

    fn translate_alu(&mut self, block: usize, p: &PreInsn) -> Result<()> {
        let code = p.insn.code;
        let op = bc::op_of(code);
        let alu = Self::alu_class(code);
        if p.insn.off != 0 && op != bc::op::END {
            return Err(invalid!("ALU instruction with nonzero offset at pos {}", p.pos));
        }
        match op {
            bc::op::ADD => self.emit_bin(block, p, BinOp::Add),
            bc::op::SUB => self.emit_bin(block, p, BinOp::Sub),
            bc::op::MUL => self.emit_bin(block, p, BinOp::Mul),
            bc::op::DIV => self.emit_bin(block, p, BinOp::Div),
            bc::op::OR => self.emit_bin(block, p, BinOp::Or),
            bc::op::AND => self.emit_bin(block, p, BinOp::And),
            bc::op::LSH => self.emit_bin(block, p, BinOp::Lsh),
            bc::op::RSH => self.emit_bin(block, p, BinOp::Rsh),
            bc::op::ARSH => self.emit_bin(block, p, BinOp::Arsh),
            bc::op::MOD => self.emit_bin(block, p, BinOp::Mod),
            bc::op::XOR => self.emit_bin(block, p, BinOp::Xor),
            bc::op::MOV => {
                // MOV does not create an instruction; it just rebinds the SSA value.
                let mut v = self.src_value(block, p)?;
                if bc::src_of(code) == bc::src::K {
                    if let Value::Const { ty, .. } = &mut v {
                        *ty = AluOp::Alu32;
                    }
                }
                let _ = alu;
                self.write_var(p.insn.dst_reg, block, v);
                Ok(())
            }
            bc::op::NEG => {
                if bc::src_of(code) != bc::src::K {
                    return Err(invalid!("neg with src != K at pos {}", p.pos));
                }
                self.emit_unary(block, p, InsnKind::Neg)
            }
            bc::op::END => {
                if alu == AluOp::Alu64 {
                    return Err(unsupported!("BPF_END is not supported in 64-bit mode"));
                }
                let kind = match bc::src_of(code) {
                    bc::end::TO_BE => EndKind::ToBe,
                    bc::end::TO_LE => EndKind::ToLe,
                    _ => return Err(unsupported!("unknown BPF_END subcode at pos {}", p.pos)),
                };
                self.emit_unary(
                    block,
                    p,
                    InsnKind::End {
                        kind,
                        swap_width: p.insn.imm as u32,
                    },
                )
            }
            _ => Err(unsupported!("unknown ALU op 0x{:02x} at pos {}", op, p.pos)),
        }
    }

    fn translate_ld_imm64(&mut self, block: usize, p: &PreInsn) -> Result<()> {
        let extra = LoadImmExtra::from_src_reg(p.insn.src_reg)
            .ok_or_else(|| unsupported!("unsupported LD_IMM64 src_reg {}", p.insn.src_reg))?;
        let ir_bb = self.blocks[block].ir_bb;
        let id = self.func.create_insn(
            ir_bb,
            InsnKind::LoadImmExtra {
                extra,
                imm64: p.imm64,
            },
            InsertPos::Back,
        );
        self.func.insn_mut(id).raw_pos = RawPos::at(p.pos, RawPosKind::Insn);
        self.write_var(p.insn.dst_reg, block, Value::Insn(id));
        Ok(())
    }

    fn translate_load(&mut self, block: usize, p: &PreInsn) -> Result<()> {
        // dst = *(size *)(src + off)
        let vr_type = VrType::from_bpf_size(bc::size_of(p.insn.code))
            .ok_or_else(|| invalid!("bad load size at pos {}", p.pos))?;
        let base = self.read_var(p.insn.src_reg, block)?;
        let offset_kind = if p.insn.src_reg == bc::BPF_REG_10 {
            ConstKind::RawOff
        } else {
            ConstKind::Plain
        };
        let mut addr = AddrValue::new(base, p.insn.off);
        addr.offset_kind = offset_kind;
        let ir_bb = self.blocks[block].ir_bb;
        let id = self.func.create_insn(ir_bb, InsnKind::LoadRaw { vr_type, addr }, InsertPos::Back);
        self.func.insn_mut(id).raw_pos = RawPos::at(p.pos, RawPosKind::Insn);
        self.func.add_use(base, id);
        self.write_var(p.insn.dst_reg, block, Value::Insn(id));
        Ok(())
    }

    fn translate_store_imm(&mut self, block: usize, p: &PreInsn) -> Result<()> {
        // *(size *)(dst + off) = imm
        let vr_type = VrType::from_bpf_size(bc::size_of(p.insn.code))
            .ok_or_else(|| invalid!("bad store size at pos {}", p.pos))?;
        let base = self.read_var(p.insn.dst_reg, block)?;
        let offset_kind = if p.insn.dst_reg == bc::BPF_REG_10 {
            ConstKind::RawOff
        } else {
            ConstKind::Plain
        };
        let mut addr = AddrValue::new(base, p.insn.off);
        addr.offset_kind = offset_kind;
        let ir_bb = self.blocks[block].ir_bb;
        let id = self.func.create_insn(ir_bb, InsnKind::StoreRaw { vr_type, addr }, InsertPos::Back);
        let imm = Value::const32(p.insn.imm);
        {
            let insn = self.func.insn_mut(id);
            insn.values.push(imm);
            insn.raw_pos = RawPos::at(p.pos, RawPosKind::Insn);
        }
        self.func.add_use(base, id);
        Ok(())
    }

    fn translate_store_reg(&mut self, block: usize, p: &PreInsn) -> Result<()> {
        // *(size *)(dst + off) = src
        let vr_type = VrType::from_bpf_size(bc::size_of(p.insn.code))
            .ok_or_else(|| invalid!("bad store size at pos {}", p.pos))?;
        let base = self.read_var(p.insn.dst_reg, block)?;
        let src = self.read_var(p.insn.src_reg, block)?;
        let offset_kind = if p.insn.dst_reg == bc::BPF_REG_10 {
            ConstKind::RawOff
        } else {
            ConstKind::Plain
        };
        let mut addr = AddrValue::new(base, p.insn.off);
        addr.offset_kind = offset_kind;
        let ir_bb = self.blocks[block].ir_bb;
        let id = self.func.create_insn(ir_bb, InsnKind::StoreRaw { vr_type, addr }, InsertPos::Back);
        {
            let insn = self.func.insn_mut(id);
            insn.values.push(src);
            insn.raw_pos = RawPos::at(p.pos, RawPosKind::Insn);
        }
        self.func.add_use(base, id);
        self.func.add_use(src, id);
        Ok(())
    }

    fn translate_jmp(&mut self, block: usize, p: &PreInsn) -> Result<()> {
        let op = bc::op_of(p.insn.code);
        match op {
            bc::op::JA => {
                let target = self.ir_bb_at_pos((p.pos as i64 + p.insn.off as i64 + 1) as usize)?;
                let ir_bb = self.blocks[block].ir_bb;
                let id = self.func.create_insn(ir_bb, InsnKind::Ja, InsertPos::Back);
                let insn = self.func.insn_mut(id);
                insn.bb1 = Some(target);
                insn.raw_pos = RawPos::at(p.pos, RawPosKind::Insn);
                Ok(())
            }
            bc::op::EXIT => {
                let r0 = self.read_var(bc::BPF_REG_0, block)?;
                let ir_bb = self.blocks[block].ir_bb;
                let id = self.func.create_insn(ir_bb, InsnKind::Ret, InsertPos::Back);
                {
                    let insn = self.func.insn_mut(id);
                    insn.values.push(r0);
                    insn.raw_pos = RawPos::at(p.pos, RawPosKind::Insn);
                }
                self.func.add_use(r0, id);
                Ok(())
            }
            bc::op::JEQ => self.emit_cond_jmp(block, p, Cond::Eq),
            bc::op::JNE => self.emit_cond_jmp(block, p, Cond::Ne),
            bc::op::JGT => self.emit_cond_jmp(block, p, Cond::Gt),
            bc::op::JGE => self.emit_cond_jmp(block, p, Cond::Ge),
            bc::op::JLT => self.emit_cond_jmp(block, p, Cond::Lt),
            bc::op::JLE => self.emit_cond_jmp(block, p, Cond::Le),
            bc::op::JSGT => self.emit_cond_jmp(block, p, Cond::Sgt),
            bc::op::JSGE => self.emit_cond_jmp(block, p, Cond::Sge),
            bc::op::JSLT => self.emit_cond_jmp(block, p, Cond::Slt),
            bc::op::JSLE => self.emit_cond_jmp(block, p, Cond::Sle),
            bc::op::CALL => self.translate_call(block, p),
            _ => Err(unsupported!("unknown jmp op 0x{:02x} at pos {}", op, p.pos)),
        }
    }

    fn translate_call(&mut self, block: usize, p: &PreInsn) -> Result<()> {
        let src = p.insn.src_reg;
        if src == 1 {
            return Err(unsupported!("BPF-local (pc+offset) calls not supported"));
        }
        if src == 2 {
            return Err(unsupported!("platform-specific helper calls not supported"));
        }

        let is_ecall = src == bc::EPASS_CALL;
        let kind = if is_ecall { InsnKind::Ecall } else { InsnKind::Call { fid: p.insn.imm } };
        let ir_bb = self.blocks[block].ir_bb;
        let id = self.func.create_insn(ir_bb, kind, InsertPos::Back);
        self.func.insn_mut(id).raw_pos = RawPos::at(p.pos, RawPosKind::Insn);

        let argc: usize = if is_ecall {
            if p.insn.imm < 0 {
                return Err(unsupported!("unknown ecall function {} at pos {}", p.insn.imm, p.pos));
            }
            p.insn.dst_reg as usize
        } else {
            match helper_arg_num(p.insn.imm) {
                Some(-1) => {
                    // trace_printk: variable length; infer from defined registers.
                    let mut n = 2usize;
                    let mut j = 2u8;
                    while (j as usize) < bc::MAX_FUNC_ARG {
                        if self.is_var_defined(j + bc::BPF_REG_1, block) {
                            n = (j + bc::BPF_REG_1) as usize;
                            j += 1;
                        } else {
                            break;
                        }
                    }
                    n
                }
                Some(n) => n as usize,
                None => {
                    return Err(unsupported!(
                        "unsupported helper function {} at pos {}",
                        p.insn.imm,
                        p.pos
                    ));
                }
            }
        };

        if argc > bc::MAX_FUNC_ARG {
            return Err(invalid!("too many call arguments ({argc}) at pos {}", p.pos));
        }

        for j in 0..argc {
            let arg = self.read_var(bc::BPF_REG_1 + j as u8, block)?;
            self.func.insn_mut(id).values.push(arg);
            self.func.add_use(arg, id);
        }
        self.write_var(bc::BPF_REG_0, block, Value::Insn(id));
        Ok(())
    }
}

/// Lift an eBPF program to SSA IR.
pub fn lift(env: &mut Env) -> Result<Function> {
    let timer = Timer::start();
    let mut insns = std::mem::take(&mut env.insns);
    let total_len = insns.len();

    let (entrances,) = discover_blocks(env, &mut insns)?;

    // Build the function and one IR block per entrance.
    let mut func = Function::new();
    // The entry pre-block reuses the function's entry IR block; others are new.
    let mut blocks: Vec<PreBlock> = Vec::with_capacity(entrances.len());
    let mut by_entrance: HashMap<usize, usize> = HashMap::new();
    let entrance_starts: Vec<usize> = entrances.iter().map(|(p, _)| *p).collect();

    for (idx, (start, pred_positions)) in entrances.iter().enumerate() {
        // End is the next entrance, or end-of-program; trimmed at a breakpoint.
        let mut end = entrance_starts
            .get(idx + 1)
            .copied()
            .unwrap_or(total_len);
        for pos in *start..end {
            if is_breakpoint_or_exit(&insns[pos]) {
                end = pos + 1;
                break;
            }
        }
        let ir_bb = if *start == 0 { func.entry } else { func.create_bb() };
        by_entrance.insert(*start, idx);

        // Collect pre-insns, joining LD_IMM64 pairs.
        let mut pre_insns = Vec::new();
        let mut pos = *start;
        while pos < end {
            let insn = insns[pos];
            let mut imm64 = (insn.imm as u32) as i64;
            let cur_pos = pos;
            if pos + 1 < end && insns[pos + 1].is_imm64_continuation() {
                imm64 = bc::join_imm64(insn.imm, insns[pos + 1].imm);
                pos += 1;
            }
            pre_insns.push(PreInsn {
                insn,
                imm64,
                pos: cur_pos,
            });
            pos += 1;
        }

        blocks.push(PreBlock {
            start: *start,
            end,
            insns: pre_insns,
            pred_positions: pred_positions.clone(),
            ir_bb,
            sealed: false,
            filled: false,
            incomplete_phis: [None; bc::MAX_BPF_REG],
        });
    }

    // Set up IR-level pred/succ edges between blocks (positions -> blocks).
    // (Filled after translation; SSA construction uses pred_positions directly.)

    let entry_idx = *by_entrance.get(&0).expect("entry block at pos 0");

    let mut ssa = Ssa {
        env,
        func,
        blocks,
        by_entrance,
        entry_idx,
        current_def: vec![HashMap::new(); bc::MAX_BPF_REG],
        total_len,
    };

    ssa.fill_block(entry_idx)?;

    // Seal any blocks still open (e.g. loop headers whose back-edge predecessor
    // was filled after the header). All blocks are filled by now. Completing a
    // phi may create new incomplete phis in still-open predecessors, so we drain
    // to a fixpoint: mark every block sealed, then complete every phi that still
    // has no operands.
    for block in 0..ssa.blocks.len() {
        ssa.blocks[block].sealed = true;
    }
    loop {
        // Find a recorded-but-empty incomplete phi anywhere and complete it.
        let mut pending: Option<(usize, u8, InsnId)> = None;
        'outer: for block in 0..ssa.blocks.len() {
            for reg in 0..bc::MAX_BPF_REG {
                if let Some(phi) = ssa.blocks[block].incomplete_phis[reg] {
                    if ssa.func.insn(phi).phi.is_empty() {
                        pending = Some((block, reg as u8, phi));
                        break 'outer;
                    }
                }
            }
        }
        match pending {
            Some((block, reg, phi)) => {
                ssa.blocks[block].incomplete_phis[reg as usize] = None;
                ssa.add_phi_operands(reg, phi, block)?;
            }
            None => break,
        }
    }

    // Establish IR CFG edges from pre-block successor positions.
    for block in 0..ssa.blocks.len() {
        let from = ssa.blocks[block].ir_bb;
        for sp in ssa.successor_positions(block) {
            if let Some(&sb) = ssa.by_entrance.get(&sp) {
                let to = ssa.blocks[sb].ir_bb;
                ssa.func.connect(from, to);
            }
        }
    }

    let mut func = ssa.func;
    drop(ssa.blocks);

    crate::cfg::finalize(env, &mut func)?;

    env.insns = insns; // restore (the original program is kept until compile writes back)
    env.lift_time_ns += timer.elapsed_ns();
    Ok(func)
}

fn is_breakpoint_or_exit(insn: &BpfInsn) -> bool {
    is_breakpoint(insn)
}
