//! ePass userspace CLI over `epass-core`.

mod cli;
mod elf;
mod run;

use std::process::ExitCode;

fn main() -> ExitCode {
    let opts = match cli::parse(std::env::args().skip(1)) {
        Ok(o) => o,
        Err(m) => {
            eprintln!("epasstool: {m}\n\n{}", cli::USAGE);
            return ExitCode::from(2);
        }
    };
    match run::run(&opts) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("epasstool: {e}");
            ExitCode::FAILURE
        }
    }
}
