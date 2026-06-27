//! Command-line parsing, mirroring the original C tool's interface.

use epass_ir::Opts;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Read,
    Print,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Raw section bytes.
    Sec,
    /// Dump format (one `u64` per line).
    Log,
}

#[derive(Debug, Clone)]
pub struct UserOpts {
    pub mode: Mode,
    pub prog: String,
    pub prog_out: Option<String>,
    pub output_format: OutputFormat,
    pub section: Option<String>,
    pub no_compile: bool,
    pub gopt: String,
    pub popt: String,
    pub opts: Opts,
}

pub enum CliError {
    Usage,
    Message(String),
}

pub fn print_usage() {
    eprintln!(
        "Usage: epasstool <command> [options] <file>\n\n\
Commands:\n\
\x20 read   Read (lift, transform and compile) the specified file\n\
\x20 print  Print the specified file\n\n\
Options:\n\
\x20 --pass-only, -P    Skip compilation\n\
\x20 --gopt <arg>       Specify a global option (comma-separated)\n\
\x20 --popt <arg>       Specify a pass option\n\
\x20 --sec, -s <arg>    Specify the ELF section/program name\n\
\x20 -F <arg>           Output format: sec | log (default)\n\
\x20 -o <arg>           Write the modified program to a file\n\n\
Global options (--gopt):\n\
\x20 verbose=<n>        Set verbosity level\n\
\x20 disable_coalesce   Disable register coalescing\n\
\x20 print_bpf          Print disassembled BPF (default)\n\
\x20 print_dump         Print packed u64 dump\n\
\x20 print_detail       Print detailed per-field view\n\
\x20 no_prog_check      Disable the IR validity checker\n"
    );
}

pub fn parse<I: Iterator<Item = String>>(mut args: I) -> Result<UserOpts, CliError> {
    let cmd = args.next().ok_or(CliError::Usage)?;
    let mode = match cmd.as_str() {
        "read" => Mode::Read,
        "print" => Mode::Print,
        _ => return Err(CliError::Usage),
    };

    let mut uo = UserOpts {
        mode,
        prog: String::new(),
        prog_out: None,
        output_format: OutputFormat::Log,
        section: None,
        no_compile: false,
        gopt: String::new(),
        popt: String::new(),
        opts: Opts::default(),
    };

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--pass-only" | "-P" if mode == Mode::Read => uo.no_compile = true,
            "--gopt" => uo.gopt = args.next().ok_or(CliError::Usage)?,
            "--popt" => uo.popt = args.next().ok_or(CliError::Usage)?,
            "--sec" | "-s" => uo.section = Some(args.next().ok_or(CliError::Usage)?),
            "-o" if mode == Mode::Read => uo.prog_out = Some(args.next().ok_or(CliError::Usage)?),
            "-F" if mode == Mode::Read => {
                let f = args.next().ok_or(CliError::Usage)?;
                uo.output_format = match f.as_str() {
                    "sec" => OutputFormat::Sec,
                    "log" => OutputFormat::Log,
                    _ => return Err(CliError::Usage),
                };
            }
            other if !other.starts_with('-') => {
                if uo.prog.is_empty() {
                    uo.prog = other.to_string();
                } else {
                    return Err(CliError::Usage);
                }
            }
            _ => return Err(CliError::Usage),
        }
    }

    if uo.prog.is_empty() {
        return Err(CliError::Usage);
    }

    let gopt = uo.gopt.clone();
    uo.opts.apply_gopt(&gopt).map_err(CliError::Message)?;
    Ok(uo)
}
