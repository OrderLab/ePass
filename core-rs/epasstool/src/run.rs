//! Command dispatch: read/print on ELF or dump-format inputs.

use std::fs;
use std::io::Read;

use epass_ir::{autorun, default_passes, logfmt, run_passes_only, BpfInsn, Env, LogLevel, PrintMode};

use crate::cli::{Mode, OutputFormat, UserOpts};
use crate::elf;

type Error = Box<dyn std::error::Error>;

/// Detect whether a file begins with the ELF magic.
fn is_elf(path: &str) -> bool {
    let mut buf = [0u8; 4];
    if let Ok(mut f) = fs::File::open(path) {
        if f.read_exact(&mut buf).is_ok() {
            return buf == [0x7f, b'E', b'L', b'F'];
        }
    }
    false
}

pub fn run(uo: UserOpts) -> Result<(), Error> {
    if is_elf(&uo.prog) {
        elf::run_elf(&uo)
    } else {
        run_logfile(&uo)
    }
}

/// Read a dump-format text file and process it.
fn run_logfile(uo: &UserOpts) -> Result<(), Error> {
    let text = fs::read_to_string(&uo.prog)?;
    let prog = logfmt::parse_dump(&text);
    let out = process(uo, prog)?;
    if let Some(path) = &uo.prog_out {
        write_output(uo, path, &out)?;
    }
    Ok(())
}

/// Run the pipeline (or just print) on one program, returning the result.
pub fn process(uo: &UserOpts, prog: Vec<BpfInsn>) -> Result<Vec<BpfInsn>, Error> {
    let mut env = Env::new(uo.opts.clone(), prog.clone());

    match uo.mode {
        Mode::Print => {
            print_program(&mut env, &prog);
            flush_log(&env);
            Ok(prog)
        }
        Mode::Read => {
            let passes = default_passes();
            let result = if uo.no_compile {
                run_passes_only(&mut env, &passes).map(|_| prog.clone())
            } else {
                autorun(&mut env, &passes).map(|_| env.insns.clone())
            };
            flush_log(&env);
            Ok(result?)
        }
    }
}

fn print_program(env: &mut Env, prog: &[BpfInsn]) {
    match env.opts.print_mode {
        PrintMode::Dump => {
            for insn in prog {
                env.log(LogLevel::Error, format_args!("{}\n", insn.to_u64()));
            }
        }
        _ => {
            for (i, insn) in prog.iter().enumerate() {
                env.log(
                    LogLevel::Error,
                    format_args!(
                        "[{i}] code={:#04x} dst=r{} src=r{} off={} imm={}\n",
                        insn.code, insn.dst_reg, insn.src_reg, insn.off, insn.imm
                    ),
                );
            }
        }
    }
}

pub(crate) fn write_output(uo: &UserOpts, path: &str, out: &[BpfInsn]) -> Result<(), Error> {
    match uo.output_format {
        OutputFormat::Log => fs::write(path, logfmt::to_dump(out))?,
        OutputFormat::Sec => {
            let mut bytes = Vec::with_capacity(out.len() * 8);
            for insn in out {
                bytes.extend_from_slice(&insn.to_u64().to_le_bytes());
            }
            fs::write(path, bytes)?;
        }
    }
    Ok(())
}

fn flush_log(env: &Env) {
    let log = env.log_buffer();
    if !log.is_empty() {
        print!("{log}");
    }
}
