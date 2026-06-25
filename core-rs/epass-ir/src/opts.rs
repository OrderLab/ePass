//! Pipeline options for the userspace ePass library.

/// How the BPF program should be rendered when printing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PrintMode {
    /// Disassembled, human-readable BPF.
    #[default]
    Bpf,
    /// Per-field detail table.
    Detail,
    /// Both disassembly and detail.
    BpfDetail,
    /// One packed `u64` per instruction (the machine-diffable "dump" format).
    Dump,
}

/// Options controlling lifting, transformation, and code generation.
#[derive(Debug, Clone)]
pub struct Opts {
    /// Only print the program; perform no transformation.
    pub print_only: bool,
    /// Verbosity level (0 = quiet, higher = more log detail).
    pub verbose: i32,
    /// Emit the interference graph in Graphviz DOT format.
    pub dotgraph: bool,
    /// Skip the IR validity checker after each pass.
    pub disable_prog_check: bool,
    /// Disable register coalescing in code generation.
    pub disable_coalesce: bool,
    /// How to render printed programs.
    pub print_mode: PrintMode,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            print_only: false,
            verbose: 1,
            dotgraph: false,
            disable_prog_check: false,
            disable_coalesce: false,
            print_mode: PrintMode::Bpf,
        }
    }
}
