//! Command-line parsing.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Lift, run passes, compile.
    Read,
    /// Print a program (bytecode or IR) without transforming it.
    Print,
    /// Lift bytecode to IR.
    Lift,
    /// Convert IR between `.epir` text and the binary blob.
    Convert,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// One decimal `u64` per instruction (`log` is an alias).
    Dump,
    /// Raw little-endian instruction bytes (`sec` is an alias).
    Raw,
    /// Disassembly.
    Asm,
    /// `.epir` IR text.
    Epir,
    /// Binary IR blob.
    Blob,
}

impl Format {
    fn parse(s: &str) -> Option<Format> {
        Some(match s {
            "dump" | "log" => Format::Dump,
            "raw" | "sec" => Format::Raw,
            "asm" => Format::Asm,
            "epir" => Format::Epir,
            "blob" => Format::Blob,
            _ => return None,
        })
    }

    /// The format implied by an output file name.
    pub fn of_path(p: &str) -> Option<Format> {
        let ext = std::path::Path::new(p).extension()?.to_str()?;
        Some(match ext {
            "epir" => Format::Epir,
            "blob" | "epb" => Format::Blob,
            "bin" | "raw" => Format::Raw,
            "s" | "asm" => Format::Asm,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Opts {
    pub cmd: Command,
    pub file: String,
    pub out: Option<String>,
    pub format: Option<Format>,
    pub section: Option<String>,
    pub pass_only: bool,
    pub gopt: String,
    pub popt: String,
    pub policy: String,
    pub quiet: bool,
}

pub const USAGE: &str = "\
Usage: epasstool <command> [options] <file>

Commands:
  read      lift, run passes and compile; write or print the result
  print     print a program (bytecode as assembly, IR as .epir)
  lift      lift bytecode to IR
  convert   convert IR between .epir text and binary blob

Inputs: ELF objects, dump files (one u64 per line), .epir text, IR blobs.

Options:
  --gopt <s>         global options, e.g. verbose=2,isa=v3,ra_colors=6
  --popt <s>         pass options, e.g. const_prop,!zext_elim,dump_ir
  --policy <s>       administrator policy (default: permissive)
  -P, --pass-only    read: run passes but do not compile; output IR
  -s, --sec <name>   ELF program to process (default: all)
  -F <fmt>           output format: dump (alias log), raw (alias sec), asm,
                     epir, blob (default: from -o's extension, else dump for
                     bytecode and epir for IR)
  -o <file>          write the output to a file instead of stdout
  -q                 do not print the compilation log

Global options (--gopt):
  verbose=0..3  isa=v1..v4  ra_colors=4..10  throw_ret=N  check  nocheck
  verify_each  endian=little|big
";

pub fn parse<I: Iterator<Item = String>>(mut args: I) -> Result<Opts, String> {
    let cmd = match args.next().as_deref() {
        Some("read") => Command::Read,
        Some("print") => Command::Print,
        Some("lift") => Command::Lift,
        Some("convert") => Command::Convert,
        Some(c) => return Err(format!("unknown command '{c}'")),
        None => return Err("missing command".into()),
    };
    let mut o = Opts {
        cmd,
        file: String::new(),
        out: None,
        format: None,
        section: None,
        pass_only: false,
        gopt: String::new(),
        popt: String::new(),
        policy: String::new(),
        quiet: false,
    };
    let need = |a: Option<String>, flag: &str| a.ok_or_else(|| format!("{flag} needs an argument"));
    while let Some(a) = args.next() {
        match a.as_str() {
            "--gopt" => o.gopt = need(args.next(), "--gopt")?,
            "--popt" => o.popt = need(args.next(), "--popt")?,
            "--policy" => o.policy = need(args.next(), "--policy")?,
            "-P" | "--pass-only" => o.pass_only = true,
            "-s" | "--sec" => o.section = Some(need(args.next(), "-s")?),
            "-o" => o.out = Some(need(args.next(), "-o")?),
            "-q" => o.quiet = true,
            "-F" => {
                let f = need(args.next(), "-F")?;
                o.format = Some(Format::parse(&f).ok_or_else(|| format!("unknown format '{f}'"))?);
            }
            s if !s.starts_with('-') && o.file.is_empty() => o.file = s.to_string(),
            s => return Err(format!("unexpected argument '{s}'")),
        }
    }
    if o.file.is_empty() {
        return Err("missing input file".into());
    }
    Ok(o)
}
