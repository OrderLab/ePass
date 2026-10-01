//! eBPF disassembly in the kernel verifier's syntax.

use std::fmt::Write as _;

use epass_core::bpf::{alu, class, jmp, mode, size, BpfInsn};

fn sz(s: u8) -> &'static str {
    match s {
        size::W => "u32",
        size::H => "u16",
        size::B => "u8",
        _ => "u64",
    }
}

fn ssz(s: u8) -> &'static str {
    match s {
        size::W => "s32",
        size::H => "s16",
        size::B => "s8",
        _ => "s64",
    }
}

fn mem(base: u8, off: i16) -> String {
    if off < 0 {
        format!("r{base} {off}")
    } else {
        format!("r{base} +{off}")
    }
}

fn alu_op(op: u8) -> &'static str {
    match op {
        alu::ADD => "+=",
        alu::SUB => "-=",
        alu::MUL => "*=",
        alu::DIV => "/=",
        alu::OR => "|=",
        alu::AND => "&=",
        alu::LSH => "<<=",
        alu::RSH => ">>=",
        alu::MOD => "%=",
        alu::XOR => "^=",
        alu::ARSH => "s>>=",
        _ => "?=",
    }
}

fn jmp_op(op: u8) -> &'static str {
    match op {
        jmp::JEQ => "==",
        jmp::JGT => ">",
        jmp::JGE => ">=",
        jmp::JSET => "&",
        jmp::JNE => "!=",
        jmp::JSGT => "s>",
        jmp::JSGE => "s>=",
        jmp::JLT => "<",
        jmp::JLE => "<=",
        jmp::JSLT => "s<",
        jmp::JSLE => "s<=",
        _ => "?",
    }
}

fn target(pc: usize, off: i64) -> String {
    let t = pc as i64 + 1 + off;
    if off < 0 {
        format!("pc{off} <{t}>")
    } else {
        format!("pc+{off} <{t}>")
    }
}

/// One instruction (`next` is the following slot, for `ld_imm64`).
pub fn insn(pc: usize, i: BpfInsn, next: Option<BpfInsn>) -> String {
    let (d, s, off, imm) = (i.dst, i.src, i.off, i.imm);
    match i.class() {
        class::ALU | class::ALU64 => {
            let r = if i.class() == class::ALU64 { "r" } else { "w" };
            let src = if i.uses_reg() { format!("{r}{s}") } else { format!("{imm}") };
            match i.op() {
                alu::NEG => format!("{r}{d} = -{r}{d}"),
                alu::MOV if off != 0 && i.uses_reg() => format!("{r}{d} = (s{off}){r}{s}"),
                alu::MOV => format!("{r}{d} = {src}"),
                alu::END => {
                    let kind = match (i.class(), i.uses_reg()) {
                        (class::ALU64, _) => "bswap",
                        (_, true) => "be",
                        _ => "le",
                    };
                    format!("r{d} = {kind}{imm} r{d}")
                }
                op @ (alu::DIV | alu::MOD) if off == 1 => {
                    format!("{r}{d} s{} {src}", alu_op(op))
                }
                op => format!("{r}{d} {} {src}", alu_op(op)),
            }
        }
        class::LDX => {
            let t = if i.mode() == mode::MEMSX { ssz(i.size()) } else { sz(i.size()) };
            format!("r{d} = *({t} *)({})", mem(s, off))
        }
        class::ST => format!("*({} *)({}) = {imm}", sz(i.size()), mem(d, off)),
        class::STX if i.mode() == mode::ATOMIC => {
            let w = if i.size() == size::DW { "64" } else { "32" };
            let p = format!("({} *)({})", sz(i.size()), mem(d, off));
            let fetch = imm & 1 != 0;
            let name = match imm & !1 {
                0x00 => "add",
                0x40 => "or",
                0x50 => "and",
                0xa0 => "xor",
                0xe0 => "xchg",
                0xf0 => "cmpxchg",
                0x100 => "load_acquire",
                0x110 => "store_release",
                _ => "?",
            };
            match (name, fetch) {
                ("cmpxchg", _) => format!("r0 = atomic{w}_cmpxchg({p}, r0, r{s})"),
                ("xchg", _) => format!("r{s} = atomic{w}_xchg({p}, r{s})"),
                (_, true) => format!("r{s} = atomic{w}_fetch_{name}({p}, r{s})"),
                (_, false) => format!("lock *{p} {}= r{s}", match name {
                    "add" => "+",
                    "or" => "|",
                    "and" => "&",
                    "xor" => "^",
                    _ => "?",
                }),
            }
        }
        class::STX => format!("*({} *)({}) = r{s}", sz(i.size()), mem(d, off)),
        class::LD if i.mode() == mode::IMM && i.size() == size::DW => {
            let hi = next.map_or(0, |n| n.imm as u32 as u64);
            let v = (hi << 32) | imm as u32 as u64;
            match s {
                0 => format!("r{d} = {v:#x} ll"),
                1 => format!("r{d} = map[fd:{imm}]"),
                2 => format!("r{d} = map[fd:{imm}]+{hi}"),
                3 => format!("r{d} = btf_id {imm}"),
                4 => format!("r{d} = func {}", target(pc, imm as i64)),
                5 => format!("r{d} = map[idx:{imm}]"),
                6 => format!("r{d} = map[idx:{imm}]+{hi}"),
                _ => format!("r{d} = ld_imm64 src={s} {v:#x}"),
            }
        }
        class::LD if i.mode() == mode::ABS => format!("r0 = *({} *)skb[{imm}]", sz(i.size())),
        class::LD if i.mode() == mode::IND => format!("r0 = *({} *)skb[r{s} + {imm}]", sz(i.size())),
        class::JMP | class::JMP32 => {
            let r = if i.class() == class::JMP { "r" } else { "w" };
            match i.op() {
                jmp::JA if i.class() == class::JMP32 => format!("gotol {}", target(pc, imm as i64)),
                jmp::JA => format!("goto {}", target(pc, off as i64)),
                jmp::CALL => match s {
                    1 => format!("call {}", target(pc, imm as i64)),
                    2 => format!("call kfunc {imm}"),
                    _ => format!("call {imm}"),
                },
                jmp::EXIT => "exit".to_string(),
                jmp::JCOND => format!("may_goto {}", target(pc, off as i64)),
                op => {
                    let rhs = if i.uses_reg() { format!("{r}{s}") } else { format!("{imm:#x}") };
                    format!("if {r}{d} {} {rhs} goto {}", jmp_op(op), target(pc, off as i64))
                }
            }
        }
        _ => format!("(unknown code {:#04x})", i.code),
    }
}

/// A whole program, one numbered line per instruction slot.
pub fn program(p: &[BpfInsn]) -> String {
    let mut out = String::new();
    let mut k = 0;
    while let Some(&i) = p.get(k) {
        let wide = i.class() == class::LD && i.mode() == mode::IMM && i.size() == size::DW;
        let _ = writeln!(out, "{k:5}: {}", insn(k, i, p.get(k + 1).copied()));
        k += if wide { 2 } else { 1 };
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(raw: &[u64]) -> String {
        let p: Vec<BpfInsn> = raw.iter().map(|&r| BpfInsn::from_u64(r)).collect();
        program(&p)
    }

    #[test]
    fn verifier_syntax() {
        use epass_core::bpf::BpfInsn as I;
        let p = [
            I::new(0x79, 2, 1, 8, 0),
            I::new(0xb7, 3, 0, 0, -1),
            I::new(0x0c, 3, 2, 0, 0),
            I::new(0x7b, 10, 3, -8, 0),
            I::new(0x25, 2, 0, 2, 100),
            I::new(0x18, 1, 1, 0, 5),
            I::new(0, 0, 0, 0, 0),
            I::new(0x85, 0, 0, 0, 1),
            I::new(0x95, 0, 0, 0, 0),
        ];
        let raw: Vec<u64> = p.iter().map(|i| i.to_u64()).collect();
        let s = d(&raw);
        let want = "    0: r2 = *(u64 *)(r1 +8)\n    1: r3 = -1\n    2: w3 += w2\n    3: *(u64 *)(r10 -8) = r3\n    4: if r2 > 0x64 goto pc+2 <7>\n    5: r1 = map[fd:5]\n    7: call 1\n    8: exit\n";
        assert_eq!(s, want);
    }
}
