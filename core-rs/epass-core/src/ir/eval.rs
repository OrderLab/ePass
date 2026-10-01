//! Exact evaluation of IR operations on constants (RFC 9669 semantics).
//! Used by constant folding and by codegen's legalization.

use super::{BinOp, Cond, SwapKind, Width};

fn low(v: u64, w: Width) -> u64 {
    match w {
        Width::W32 => v & 0xffff_ffff,
        Width::W64 => v,
    }
}

fn sx(v: u64, w: Width) -> i64 {
    match w {
        Width::W32 => v as u32 as i32 as i64,
        Width::W64 => v as i64,
    }
}

/// `a op b` at width `w`; the 32-bit result is zero-extended.
pub fn bin(op: BinOp, w: Width, a: u64, b: u64) -> u64 {
    let (a, b) = (low(a, w), low(b, w));
    let mask = (w.bits() - 1) as u64;
    let (sa, sb) = (sx(a, w), sx(b, w));
    let r = match op {
        BinOp::Add => a.wrapping_add(b),
        BinOp::Sub => a.wrapping_sub(b),
        BinOp::Mul => a.wrapping_mul(b),
        BinOp::UDiv => a.checked_div(b).unwrap_or(0),
        BinOp::UMod => a.checked_rem(b).unwrap_or(a),
        // Division by zero yields 0 (sdiv) or the dividend (smod); MIN / -1
        // wraps. `checked_*` keeps every division visibly guarded, so the
        // object has no panic path.
        BinOp::SDiv => match w {
            Width::W32 => match (sa as i32).checked_div(sb as i32) {
                Some(q) => q as i64 as u64,
                None if sb as i32 == 0 => 0,
                None => (sa as i32).wrapping_neg() as i64 as u64,
            },
            Width::W64 => match sa.checked_div(sb) {
                Some(q) => q as u64,
                None if sb == 0 => 0,
                None => sa.wrapping_neg() as u64,
            },
        },
        BinOp::SMod => match w {
            Width::W32 => match (sa as i32).checked_rem(sb as i32) {
                Some(r) => r as i64 as u64,
                None if sb as i32 == 0 => a,
                None => 0,
            },
            Width::W64 => match sa.checked_rem(sb) {
                Some(r) => r as u64,
                None if sb == 0 => a,
                None => 0,
            },
        },
        BinOp::And => a & b,
        BinOp::Or => a | b,
        BinOp::Xor => a ^ b,
        BinOp::Shl => a.wrapping_shl((b & mask) as u32),
        BinOp::LShr => a.wrapping_shr((b & mask) as u32),
        BinOp::AShr => sa.wrapping_shr((b & mask) as u32) as u64,
    };
    low(r, w)
}

pub fn neg(w: Width, a: u64) -> u64 {
    low(sx(low(a, w), w).wrapping_neg() as u64, w)
}

/// Extend the low `from` bits (zero or sign), truncate to `w`.
pub fn ext(from: u8, signed: bool, w: Width, a: u64) -> u64 {
    let from = u32::from(from).clamp(1, 64);
    let v = if from >= 64 {
        a
    } else if signed {
        let s = 64 - from;
        (((a << s) as i64) >> s) as u64
    } else {
        a & ((1u64 << from) - 1)
    };
    low(v, w)
}

/// Byte swap of the low `bits` bits. `ToLe`/`ToBe` depend on the target's
/// endianness: on a little-endian target `ToLe` only truncates.
pub fn bswap(bits: u8, kind: SwapKind, big_endian: bool, a: u64) -> u64 {
    let swap = match kind {
        SwapKind::Swap => true,
        SwapKind::ToLe => big_endian,
        SwapKind::ToBe => !big_endian,
    };
    match (bits, swap) {
        (16, false) => a & 0xffff,
        (32, false) => a & 0xffff_ffff,
        (16, true) => (a as u16).swap_bytes() as u64,
        (32, true) => (a as u32).swap_bytes() as u64,
        (_, false) => a,
        (_, true) => a.swap_bytes(),
    }
}

/// Evaluate a branch condition at width `w`.
pub fn cond(c: Cond, w: Width, a: u64, b: u64) -> bool {
    let (a, b) = (low(a, w), low(b, w));
    let (sa, sb) = (sx(a, w), sx(b, w));
    match c {
        Cond::Eq => a == b,
        Cond::Ne => a != b,
        Cond::Ugt => a > b,
        Cond::Uge => a >= b,
        Cond::Ult => a < b,
        Cond::Ule => a <= b,
        Cond::Sgt => sa > sb,
        Cond::Sge => sa >= sb,
        Cond::Slt => sa < sb,
        Cond::Sle => sa <= sb,
        Cond::Set => a & b != 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc9669_edge_cases() {
        use BinOp::*;
        use Width::*;
        assert_eq!(bin(UDiv, W64, 7, 0), 0);
        assert_eq!(bin(UMod, W64, 7, 0), 7);
        assert_eq!(bin(UMod, W32, 0x1_0000_0007, 0), 7);
        assert_eq!(bin(SDiv, W64, 1 << 63, u64::MAX), 1 << 63);
        assert_eq!(bin(SDiv, W32, 0x8000_0000, 0xffff_ffff), 0x8000_0000);
        assert_eq!(bin(SMod, W64, (-7i64) as u64, 2), (-1i64) as u64);
        assert_eq!(bin(Shl, W64, 1, 65), 2);
        assert_eq!(bin(Shl, W32, 1, 33), 2);
        assert_eq!(bin(AShr, W32, 0xffff_fff8, 1), 0xffff_fffc);
        assert_eq!(bin(Add, W32, 0x7fff_ffff, 0x7fff_ffff), 0xffff_fffe);
        assert_eq!(bin(Add, W64, 0x7fff_ffff, 0x7fff_ffff), 0xffff_fffe);
        assert_eq!(neg(W32, 1), 0xffff_ffff);
        assert_eq!(ext(8, true, W64, 0xff), u64::MAX);
        assert_eq!(ext(8, true, W32, 0xff), 0xffff_ffff);
        assert_eq!(ext(32, false, W64, u64::MAX), 0xffff_ffff);
        assert_eq!(bswap(16, SwapKind::ToBe, false, 0x1234), 0x3412);
        assert_eq!(bswap(16, SwapKind::ToLe, false, 0x1_1234), 0x1234);
        assert!(cond(Cond::Set, W64, 6, 4));
        assert!(cond(Cond::Sgt, W32, 1, 0xffff_ffff));
        assert!(!cond(Cond::Ugt, W32, 1, 0xffff_ffff));
    }
}
