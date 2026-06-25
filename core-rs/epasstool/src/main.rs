//! ePass userspace CLI.
//!
//! Commands:
//!   read   — lift, transform, and compile a program, then write it back
//!   print  — print a program without transforming it
//!
//! Inputs may be ELF object files (parsed via libbpf) or dump-format text files
//! (one packed `u64` per line). Options mirror the original C tool.

mod cli;
mod elf;
mod run;

use std::process::ExitCode;

fn main() -> ExitCode {
    let opts = match cli::parse(std::env::args().skip(1)) {
        Ok(o) => o,
        Err(cli::CliError::Usage) => {
            cli::print_usage();
            return ExitCode::from(2);
        }
        Err(cli::CliError::Message(m)) => {
            eprintln!("error: {m}");
            return ExitCode::from(2);
        }
    };

    match run::run(opts) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
