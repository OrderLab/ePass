//! Human-friendly IR pretty-printer for debugging.
//!
//! Produces an LLVM-like textual form with stable virtual-register numbering,
//! labeled basic blocks, and explicit predecessor/successor annotations. This
//! is intentionally richer than the C printer to make debugging passes easier.

use std::collections::HashMap;
use std::fmt::Write;

use super::insn::{BinOp, Cond, EndKind, InsnKind};
use super::value::{AddrValue, AluOp, BuiltinConst, ConstKind, LoadImmExtra, Value, VrPos, VrType};
use super::{BbId, Function, InsnId};

/// Assigns stable, dense display ids to instructions and blocks.
struct Tags {
    insn_ids: HashMap<InsnId, usize>,
    bb_ids: HashMap<BbId, usize>,
}

impl Tags {
    fn build(func: &Function) -> Self {
        let mut insn_ids = HashMap::new();
        let mut bb_ids = HashMap::new();
        let mut vr = 0usize;
        let order: &[BbId] = if func.reachable_bbs.is_empty() {
            &func.all_bbs
        } else {
            &func.reachable_bbs
        };
        for (bidx, &bb) in order.iter().enumerate() {
            bb_ids.insert(bb, bidx);
            for &id in &func.bb(bb).insns {
                if !func.insn(id).is_void() {
                    insn_ids.insert(id, vr);
                    vr += 1;
                }
            }
        }
        Tags { insn_ids, bb_ids }
    }

    fn vr(&self, id: InsnId) -> String {
        match self.insn_ids.get(&id) {
            Some(n) => format!("%{n}"),
            None => format!("%?{}", id.0),
        }
    }

    fn bb(&self, id: BbId) -> String {
        match self.bb_ids.get(&id) {
            Some(n) => format!("bb{n}"),
            None => format!("bb?{}", id.0),
        }
    }
}

fn alu_suffix(op: AluOp) -> &'static str {
    match op {
        AluOp::Alu32 => "32",
        AluOp::Alu64 => "64",
        AluOp::Unknown => "?",
    }
}

fn binop_name(op: BinOp) -> &'static str {
    match op {
        BinOp::Add => "add",
        BinOp::Sub => "sub",
        BinOp::Mul => "mul",
        BinOp::Div => "div",
        BinOp::Or => "or",
        BinOp::And => "and",
        BinOp::Lsh => "lsh",
        BinOp::Arsh => "arsh",
        BinOp::Rsh => "rsh",
        BinOp::Mod => "mod",
        BinOp::Xor => "xor",
    }
}

fn cond_name(c: Cond) -> &'static str {
    match c {
        Cond::Eq => "jeq",
        Cond::Ne => "jne",
        Cond::Gt => "jgt",
        Cond::Ge => "jge",
        Cond::Lt => "jlt",
        Cond::Le => "jle",
        Cond::Sgt => "jsgt",
        Cond::Sge => "jsge",
        Cond::Slt => "jslt",
        Cond::Sle => "jsle",
    }
}

fn vr_type_name(t: VrType) -> &'static str {
    match t {
        VrType::B8 => "u8",
        VrType::B16 => "u16",
        VrType::B32 => "u32",
        VrType::B64 => "u64",
        VrType::Unknown => "u?",
    }
}

fn fmt_vrpos(pos: VrPos) -> String {
    if !pos.allocated {
        "<unalloc>".to_string()
    } else if pos.spilled != 0 {
        format!("sp{:+}", pos.spilled)
    } else {
        format!("R{}", pos.alloc_reg)
    }
}

fn fmt_value(func: &Function, tags: &Tags, v: Value) -> String {
    match v {
        Value::Const {
            v,
            ty,
            kind,
            builtin,
        } => {
            if builtin != BuiltinConst::None {
                return match builtin {
                    BuiltinConst::BbInsnCnt => "<bb_insn_cnt>".to_string(),
                    BuiltinConst::BbInsnCriticalCnt => "<bb_insn_critical_cnt>".to_string(),
                    BuiltinConst::None => unreachable!(),
                };
            }
            let suffix = match kind {
                ConstKind::Plain => "",
                ConstKind::RawOff => "+sp",
                ConstKind::RawOffRev => "-sp",
            };
            let _ = ty;
            format!("{v}{suffix}")
        }
        Value::Insn(id) => {
            // Pseudo-instructions render as their register/arg name.
            match func.try_insn(id).map(|i| &i.kind) {
                Some(InsnKind::Reg { reg_id }) => format!("R{reg_id}"),
                Some(InsnKind::FunctionArg { arg_id }) => format!("arg{arg_id}"),
                _ => tags.vr(id),
            }
        }
        Value::VrPos(p) | Value::FlattenDst(p) => fmt_vrpos(p),
        Value::Undef => "undef".to_string(),
    }
}

fn fmt_addr(func: &Function, tags: &Tags, a: &AddrValue) -> String {
    let base = fmt_value(func, tags, a.value);
    let off_sp = match a.offset_kind {
        ConstKind::Plain => "",
        ConstKind::RawOff => "+sp",
        ConstKind::RawOffRev => "-sp",
    };
    format!("[{base}{:+}{off_sp}]", a.offset)
}

fn extra_name(e: LoadImmExtra) -> &'static str {
    match e {
        LoadImmExtra::Imm64 => "imm64",
        LoadImmExtra::MapByFd => "map_by_fd",
        LoadImmExtra::MapValFd => "map_val_fd",
        LoadImmExtra::VarAddr => "var_addr",
        LoadImmExtra::CodeAddr => "code_addr",
        LoadImmExtra::MapByIdx => "map_by_idx",
        LoadImmExtra::MapValIdx => "map_val_idx",
    }
}

fn fmt_insn(func: &Function, tags: &Tags, id: InsnId) -> String {
    let insn = func.insn(id);
    let dst = if insn.is_void() {
        String::new()
    } else {
        format!("{} = ", tags.vr(id))
    };
    let vals: Vec<String> = insn
        .values
        .iter()
        .map(|&v| fmt_value(func, tags, v))
        .collect();

    let body = match &insn.kind {
        InsnKind::Alloc { vr_type } => format!("alloc {}", vr_type_name(*vr_type)),
        InsnKind::AllocArray { vr_type, num } => {
            format!("allocarray {} x {}", vr_type_name(*vr_type), num)
        }
        InsnKind::GetElemPtr => format!("getelemptr {}, {}", vals[0], vals[1]),
        InsnKind::Store => format!("store {}, {}", vals[0], vals[1]),
        InsnKind::Load => format!("load {}", vals[0]),
        InsnKind::LoadImmExtra { extra, imm64 } => {
            format!("loadimm.{} {}", extra_name(*extra), imm64)
        }
        InsnKind::StoreRaw { vr_type, addr } => {
            format!(
                "storeraw.{} {}, {}",
                vr_type_name(*vr_type),
                fmt_addr(func, tags, addr),
                vals.first().cloned().unwrap_or_default()
            )
        }
        InsnKind::LoadRaw { vr_type, addr } => {
            format!("loadraw.{} {}", vr_type_name(*vr_type), fmt_addr(func, tags, addr))
        }
        InsnKind::Neg => format!("neg{} {}", alu_suffix(insn.alu_op), vals[0]),
        InsnKind::End { kind, swap_width } => {
            let dir = match kind {
                EndKind::ToLe => "le",
                EndKind::ToBe => "be",
            };
            format!("end.{dir}{swap_width} {}", vals[0])
        }
        InsnKind::Bin { op } => {
            format!("{}{} {}, {}", binop_name(*op), alu_suffix(insn.alu_op), vals[0], vals[1])
        }
        InsnKind::Call { fid } => {
            format!("call #{} ({})", fid, vals.join(", "))
        }
        InsnKind::Ret => format!("ret {}", vals.first().cloned().unwrap_or_default()),
        InsnKind::Throw => "throw".to_string(),
        InsnKind::Ja => format!("ja {}", tags.bb(insn.bb1.unwrap())),
        InsnKind::CondJmp { cond } => format!(
            "{}{} {}, {} -> {} else {}",
            cond_name(*cond),
            alu_suffix(insn.alu_op),
            vals[0],
            vals[1],
            tags.bb(insn.bb2.unwrap()),
            tags.bb(insn.bb1.unwrap()),
        ),
        InsnKind::Phi => {
            let entries: Vec<String> = insn
                .phi
                .iter()
                .map(|p| format!("[{}, {}]", fmt_value(func, tags, p.value), tags.bb(p.bb)))
                .collect();
            format!("phi {}", entries.join(", "))
        }
        InsnKind::Assign => format!("assign {}", vals[0]),
        InsnKind::Reg { reg_id } => format!("reg R{reg_id}"),
        InsnKind::FunctionArg { arg_id } => format!("funcarg {arg_id}"),
        InsnKind::Ecall => format!("ecall ({})", vals.join(", ")),
    };

    format!("{dst}{body}")
}

/// Render a whole function to a debug string.
pub fn print_function(func: &Function) -> String {
    let tags = Tags::build(func);
    let mut out = String::new();
    let order: &[BbId] = if func.reachable_bbs.is_empty() {
        &func.all_bbs
    } else {
        &func.reachable_bbs
    };
    for &bb in order {
        let block = func.bb(bb);
        let preds: Vec<String> = block.preds.iter().map(|&p| tags.bb(p)).collect();
        let succs: Vec<String> = block.succs.iter().map(|&s| tags.bb(s)).collect();
        let _ = writeln!(
            out,
            "{}:  ; preds = [{}]  succs = [{}]",
            tags.bb(bb),
            preds.join(", "),
            succs.join(", ")
        );
        for &id in &block.insns {
            let _ = writeln!(out, "    {}", fmt_insn(func, &tags, id));
        }
        out.push('\n');
    }
    out
}
