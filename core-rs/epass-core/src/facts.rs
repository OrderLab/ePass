//! Program facts supplied by the host: call signatures and the ISA level.
//!
//! In the kernel these come from the verifier's helper prototypes and BTF;
//! in userspace from the built-in helper table (and, for ELF input, from
//! libbpf). The core never hard-codes kernel knowledge beyond the default
//! helper table below.

/// eBPF ISA level (LLVM `-mcpu=vN`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Isa {
    /// Base ISA.
    V1 = 1,
    /// Adds JLT/JLE/JSLT/JSLE.
    V2 = 2,
    /// Adds JMP32 and ALU32 conventions.
    V3 = 3,
    /// Adds sdiv/smod, movsx, MEMSX, bswap, gotol.
    V4 = 4,
}

/// What a call returns, as far as value-class analysis cares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetClass {
    Scalar,
    /// A map value pointer or NULL (e.g. `bpf_map_lookup_elem`).
    MapValueOrNull,
    /// A memory pointer or NULL (e.g. `bpf_ringbuf_reserve`).
    MemOrNull,
    /// A pointer of unknown kind.
    Ptr,
}

/// A call signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sig {
    /// Number of argument registers read (r1..).
    pub nargs: u8,
    /// Arguments at or after this index may be undefined (variadic tails,
    /// e.g. `bpf_trace_printk`).
    pub optional_from: u8,
    pub ret: RetClass,
}

impl Sig {
    pub const fn fixed(nargs: u8) -> Sig {
        Sig {
            nargs,
            optional_from: nargs,
            ret: RetClass::Scalar,
        }
    }
}

/// Host-provided facts.
pub trait Facts {
    /// Signature of helper `id`, or `None` if unknown.
    fn helper(&self, id: i32) -> Option<Sig> {
        default_helper(id)
    }
    /// Signature of a kfunc, or `None` if unknown.
    fn kfunc(&self, _btf_id: i32, _fd_idx: i16) -> Option<Sig> {
        None
    }
    /// Whether calls with unknown signatures may be passed through with all
    /// five argument registers (userspace only; the kernel always knows).
    fn allow_unknown_calls(&self) -> bool {
        false
    }
    /// Highest ISA level the output may use.
    fn isa(&self) -> Isa {
        Isa::V4
    }
}

/// Default facts: the built-in helper table, a configurable ISA level and
/// unknown-call policy.
#[derive(Clone, Copy, Debug)]
pub struct DefaultFacts {
    pub isa: Isa,
    pub allow_unknown_calls: bool,
}

impl Default for DefaultFacts {
    fn default() -> Self {
        DefaultFacts {
            isa: Isa::V4,
            allow_unknown_calls: true,
        }
    }
}

impl Facts for DefaultFacts {
    fn allow_unknown_calls(&self) -> bool {
        self.allow_unknown_calls
    }
    fn isa(&self) -> Isa {
        self.isa
    }
}

/// Argument counts of helpers 1..=211 (the helper list is frozen upstream).
/// `-1` marks `bpf_trace_printk` (2 fixed + 3 optional arguments); `-2` an
/// unused id.
const HELPER_ARGS: [i8; 212] = [
    -2, // 0 unused
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

/// Helpers returning pointers that value-class analysis distinguishes.
fn helper_ret(id: i32) -> RetClass {
    match id {
        1 => RetClass::MapValueOrNull,                      // map_lookup_elem
        131 => RetClass::MemOrNull,                          // ringbuf_reserve
        70 | 102 | 103 | 156 | 157 | 158 => RetClass::Ptr,   // sock/task/... ptrs
        _ => RetClass::Scalar,
    }
}

/// The built-in helper table.
pub fn default_helper(id: i32) -> Option<Sig> {
    let n = *HELPER_ARGS.get(usize::try_from(id).ok()?)?;
    match n {
        -2 => None,
        -1 => Some(Sig {
            nargs: 5,
            optional_from: 2,
            ret: RetClass::Scalar,
        }),
        n => Some(Sig {
            nargs: n as u8,
            optional_from: n as u8,
            ret: helper_ret(id),
        }),
    }
}
