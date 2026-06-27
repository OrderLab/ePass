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
    /// Load initial IR from a text `.epir` file instead of lifting bytecode.
    pub load_ir: Option<String>,
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
            load_ir: None,
        }
    }
}

impl Opts {
    /// Apply a comma-separated global-option string (`key` or `key=value`),
    /// e.g. `"verbose=2,disable_coalesce"`. Unknown keys return an error string.
    pub fn apply_gopt(&mut self, gopt: &str) -> Result<(), String> {
        for tok in gopt.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let (key, val) = match tok.split_once('=') {
                Some((k, v)) => (k, Some(v)),
                None => (tok, None),
            };
            match key {
                "verbose" => {
                    self.verbose = val
                        .and_then(|v| v.parse::<i32>().ok())
                        .ok_or_else(|| "verbose requires an integer".to_string())?;
                }
                "disable_coalesce" => self.disable_coalesce = true,
                "print_bpf" => self.print_mode = PrintMode::Bpf,
                "print_dump" => self.print_mode = PrintMode::Dump,
                "print_detail" => self.print_mode = PrintMode::Detail,
                "print_bpf_detail" => self.print_mode = PrintMode::BpfDetail,
                "no_prog_check" => self.disable_prog_check = true,
                "printonly" => self.print_only = true,
                "dotgraph" => self.dotgraph = true,
                "load_ir" => {
                    self.load_ir = Some(
                        val.ok_or_else(|| "load_ir requires a path".to_string())?.to_string(),
                    );
                }
                other => return Err(format!("unknown global option '{other}'")),
            }
        }
        Ok(())
    }
}
