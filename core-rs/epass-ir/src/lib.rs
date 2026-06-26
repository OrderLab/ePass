//! ePass: an SSA-based intermediate representation and compiler framework for
//! eBPF programs.
//!
//! The pipeline mirrors the original C implementation:
//!
//! ```text
//! eBPF bytecode --lift--> SSA IR --run passes--> IR --compile--> eBPF bytecode
//! ```
//!
//! This crate is userspace-only and has no dependency on libbpf or the kernel.

pub mod bytecode;
pub mod cfg;
pub mod cg;
pub mod check;
pub mod env;
pub mod error;
pub mod ffi;
pub mod helpers;
pub mod ir;
pub mod lift;
pub mod logfmt;
pub mod opts;
pub mod pass;
pub mod passes;
pub mod pipeline;

pub use bytecode::BpfInsn;
pub use env::{Env, LogLevel};
pub use error::{Error, Result};
pub use ir::{BbId, BasicBlock, Function, Insn, InsnId, InsnKind, IrBuilder, InsertPoint, Value};
pub use ir::text::{dump_function as dump_ir, load_function_from_file as load_ir_file, load_function_from_str as load_ir_str, DumpOptions};
pub use lift::lift;
pub use opts::{Opts, PrintMode};
pub use pass::{Pass, PassManager};
pub use pipeline::{autorun, run_passes_only};

/// Render a function to its debug textual form.
pub fn print_ir(func: &Function) -> String {
    ir::print::print_function(func)
}

/// Build the default pass pipeline with no pass options.
pub fn default_passes() -> PassManager {
    passes_from_popt("").expect("builtin default pass pipeline is valid")
}

/// Build the builtin pass pipeline from a pass-option string.
///
/// `popt` enables/disables/configures passes, but pass order is decided by each
/// pass's `register_pass` implementation. Examples:
/// - `dump_ir(/tmp/a.epir)` enables the optional IR dump pass;
/// - `!const_prop` disables constant propagation;
/// - `!phi` is rejected because `phi` is not disableable.
pub fn passes_from_popt(popt: &str) -> Result<PassManager> {
    PassManager::from_passes(
        vec![
            Box::new(passes::dump_ir::pass()),
            Box::new(passes::const_prop::pass()),
            Box::new(passes::phi::pass()),
            Box::new(passes::optimization::pass()),
        ],
        popt,
    )
}

/// Backward-compatible alias for callers using the old name.
pub fn default_passes_with_popt(popt: &str) -> PassManager {
    passes_from_popt(popt).expect("pass options produced an invalid builtin pipeline")
}
