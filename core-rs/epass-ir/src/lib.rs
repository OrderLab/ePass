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
pub use ir::{BbId, BasicBlock, Function, Insn, InsnId, InsnKind, Value};
pub use lift::lift;
pub use opts::{Opts, PrintMode};
pub use pass::{Pass, PassManager};
pub use pipeline::{autorun, run_passes_only};

/// Render a function to its debug textual form.
pub fn print_ir(func: &Function) -> String {
    ir::print::print_function(func)
}

/// Build the default pass pipeline (matching the C userspace tool defaults).
pub fn default_passes() -> PassManager {
    let mut pm = PassManager::new();
    pm.pre.push(Box::new(passes::phi::pass()));
    pm
}
