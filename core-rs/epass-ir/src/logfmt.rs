//! The "dump" text format: one decimal `u64` per line, each the packed encoding
//! of a single [`BpfInsn`]. This is the machine-diffable format used by the C
//! tool's `readlog` input and `-F log` output, and is our primary validation
//! channel against the reference implementation.

use crate::bytecode::BpfInsn;

/// Parse a dump-format string into a list of instructions.
///
/// Parsing stops at the first blank line (matching the C `readlog` behavior).
/// Lines that are not parseable as `u64` are skipped.
pub fn parse_dump(text: &str) -> Vec<BpfInsn> {
    let mut insns = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        match trimmed.parse::<u64>() {
            Ok(raw) => insns.push(BpfInsn::from_u64(raw)),
            Err(_) => continue,
        }
    }
    insns
}

/// Serialize instructions to dump format (one decimal `u64` per line).
pub fn to_dump(insns: &[BpfInsn]) -> String {
    let mut out = String::new();
    for insn in insns {
        out.push_str(&insn.to_u64().to_string());
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_dump() {
        let insns = vec![
            BpfInsn::from_u64(135), // r0 = 0 (mov)
            BpfInsn::from_u64(149), // exit
        ];
        let text = to_dump(&insns);
        assert_eq!(parse_dump(&text), insns);
    }

    #[test]
    fn stops_at_blank_line() {
        let text = "135\n149\n\n999\n";
        assert_eq!(parse_dump(text).len(), 2);
    }
}
