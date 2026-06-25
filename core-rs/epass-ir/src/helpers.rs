//! Static eBPF helper-function argument-count table.
//!
//! Indexed by helper id. A value of `-1` means "variable / special-cased"
//! (currently only `trace_printk`, id 6). This is data ported verbatim from the
//! C implementation and should track the kernel's helper list.

/// Number of arguments each helper takes, indexed by helper id.
/// `i8::MIN` is used for "unknown / unsupported" gaps.
pub const HELPER_ARG_NUM: &[i8] = &[
    /* 0 unused */ i8::MIN,
    2, 4, 2, 3, 0, -1, 0, 0, 5, 5, // 1-10
    5, 3, 3, 0, 0, 2, 1, 3, 1, 4, // 11-20
    4, 2, 2, 1, 5, 4, 3, 5, 3, 3, // 21-30
    3, 2, 3, 1, 0, 3, 2, 3, 2, 2, // 31-40
    1, 0, 3, 2, 3, 1, 1, 2, 5, 4, // 41-50
    3, 4, 4, 2, 4, 3, 5, 2, 2, 4, // 51-60
    2, 2, 4, 3, 2, 5, 4, 5, 4, 4, // 61-70
    4, 4, 4, 4, 3, 4, 1, 4, 1, 0, // 71-80
    2, 4, 2, 5, 5, 1, 3, 2, 2, 4, // 81-90
    4, 3, 1, 1, 1, 1, 1, 1, 5, 5, // 91-100
    4, 3, 3, 3, 4, 4, 5, 2, 1, 5, // 101-110
    5, 3, 3, 3, 3, 2, 1, 0, 4, 4, // 111-120
    5, 1, 1, 3, 0, 5, 3, 1, 2, 4, // 121-130
    3, 2, 2, 2, 2, 1, 1, 1, 1, 1, // 131-140
    4, 4, 4, 3, 5, 2, 3, 3, 5, 4, // 141-150
    1, 4, 2, 1, 2, 5, 2, 0, 2, 0, // 151-160
    3, 1, 5, 4, 5, 3, 4, 1, 3, 3, // 161-170
    3, 1, 1, 1, 1, 3, 4, 1, 4, 5, // 171-180
    4, 3, 3, 2, 1, 0, 1, 1, 4, 4, // 181-190
    5, 3, 3, 2, 3, 1, 4, 4, 2, 2, // 191-200
    5, 5, 3, 3, 3, 2, 2, 0, 4, 5, // 201-210
    2, // 211
];

/// Look up a helper's argument count.
///
/// Returns `Some(n)` for fixed-arity helpers, `Some(-1)` for the variadic
/// `trace_printk`, and `None` for unknown / unsupported ids.
pub fn helper_arg_num(id: i32) -> Option<i8> {
    if id < 0 || id as usize >= HELPER_ARG_NUM.len() {
        return None;
    }
    let n = HELPER_ARG_NUM[id as usize];
    if n == i8::MIN {
        None
    } else {
        Some(n)
    }
}
