//! Command dispatch.

use std::io::Write as _;

use epass_core::bpf::BpfInsn;
use epass_core::driver::{self, Gopt, Input, Outcome, Request};
use epass_core::facts::DefaultFacts;
use epass_core::ir::Function;
use epass_core::mem::FVec;
use epass_core::pm::{Options, PassCx, Pipeline, Policy};
use epass_core::{bin, Ctx, Heap, Limits};
use epass_std::{disasm, StdHost};

use crate::cli::{Command, Format, Opts};
use crate::elf;

/// One input program.
pub enum Prog {
    Bytecode(Vec<BpfInsn>),
    Blob(Vec<u8>),
    Text(String),
}

/// Read the input file: ELF (all programs or `-s`), IR blob, dump, or
/// `.epir` text.
pub fn load(o: &Opts) -> Result<Vec<(String, Prog)>, String> {
    let bytes = std::fs::read(&o.file).map_err(|e| format!("{}: {e}", o.file))?;
    if bytes.starts_with(b"\x7fELF") {
        return Ok(elf::programs(&o.file, o.section.as_deref())?
            .into_iter()
            .map(|(n, p)| (n, Prog::Bytecode(p)))
            .collect());
    }
    let name = std::path::Path::new(&o.file)
        .file_stem()
        .map_or_else(String::new, |s| s.to_string_lossy().into_owned());
    if bytes.starts_with(&bin::MAGIC) {
        return Ok(vec![(name, Prog::Blob(bytes))]);
    }
    let text = String::from_utf8(bytes).map_err(|_| format!("{}: not ELF, IR or text", o.file))?;
    let first = text.lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with(';'));
    if first.is_some_and(|l| l.parse::<u64>().is_ok()) {
        // Dump format: stops at the first blank line.
        let mut p = Vec::new();
        for line in text.lines().map(str::trim) {
            if line.is_empty() {
                break;
            }
            let raw = line.parse::<u64>().map_err(|_| format!("{}: bad dump line '{line}'", o.file))?;
            p.push(BpfInsn::from_u64(raw));
        }
        return Ok(vec![(name, Prog::Bytecode(p))]);
    }
    Ok(vec![(name, Prog::Text(text))])
}

pub fn run(o: &Opts) -> Result<(), String> {
    let progs = load(o)?;
    if o.out.is_some() && progs.len() > 1 {
        return Err(format!("{} programs in '{}': select one with -s", progs.len(), o.file));
    }
    for (name, p) in progs {
        process(o, &name, p)?;
    }
    Ok(())
}

enum Content<'a, 'h> {
    Bytecode(&'a [BpfInsn]),
    Ir(&'a Function<'h>),
}

fn process(o: &Opts, name: &str, p: Prog) -> Result<(), String> {
    let host = StdHost::new();
    let heap = Heap::new(&host, Limits::USERSPACE.max_bytes);
    let gopt = Gopt::parse(&o.gopt).map_err(|e| format!("--gopt: {e}"))?;
    let ctx = Ctx::new(&heap, Limits::USERSPACE, gopt.level).map_err(|e| e.to_string())?;
    let facts = DefaultFacts::default();
    let policy = if o.policy.is_empty() {
        Policy::permissive(&heap)
    } else {
        Policy::parse(&o.policy, &heap).map_err(|e| format!("--policy: {e}"))?
    };
    let r = (|| -> Result<(), String> {
        let ir_of = |p: &Prog| -> Result<Function<'_>, String> {
            match p {
                Prog::Bytecode(b) => epass_core::lift::lift(b, &facts, &ctx).map_err(|e| format!("lift: {e}")),
                Prog::Blob(b) => bin::decode(b, &heap, &ctx).map_err(|e| format!("IR: {e}")),
                Prog::Text(t) => {
                    let f = epass_core::ir::parse::parse(t, &heap, &ctx).map_err(|e| format!("IR: {e}"))?;
                    epass_core::ir::verify::verify(&f, &ctx, policy.allow_ecall).map_err(|e| format!("IR: {e}"))?;
                    Ok(f)
                }
            }
        };
        match o.cmd {
            Command::Print => match &p {
                Prog::Bytecode(b) => emit(o, Format::Asm, Content::Bytecode(b)),
                _ => emit(o, Format::Epir, Content::Ir(&ir_of(&p)?)),
            },
            Command::Lift => match &p {
                Prog::Bytecode(_) => emit(o, Format::Epir, Content::Ir(&ir_of(&p)?)),
                _ => Err("lift takes bytecode; use convert for IR".into()),
            },
            Command::Convert => match &p {
                Prog::Bytecode(_) => Err("convert takes IR; use lift for bytecode".into()),
                Prog::Blob(_) => emit(o, Format::Epir, Content::Ir(&ir_of(&p)?)),
                Prog::Text(_) => emit(o, Format::Blob, Content::Ir(&ir_of(&p)?)),
            },
            Command::Read if o.pass_only => {
                let mut f = ir_of(&p)?;
                let pl = Pipeline::build(&policy, &o.popt, &heap).map_err(|e| format!("--popt: {e}"))?;
                let opts = Options {
                    throw_ret: gopt.throw_ret,
                    verify_each: gopt.verify_each,
                    allow_ecall: policy.allow_ecall,
                    big_endian: gopt.big_endian,
                };
                pl.run(&mut f, &PassCx { ctx: &ctx, facts: &facts, opts: &opts }).map_err(|e| format!("passes: {e}"))?;
                emit(o, Format::Epir, Content::Ir(&f))
            }
            Command::Read => {
                let mut blob = FVec::new(&heap);
                let (input, n_in) = match &p {
                    Prog::Bytecode(b) => (Input::Bytecode(b), b.len().to_string()),
                    Prog::Blob(b) => (Input::Ir(b), "IR".to_string()),
                    Prog::Text(_) => {
                        bin::encode(&ir_of(&p)?, &mut blob).map_err(|e| e.to_string())?;
                        (Input::Ir(blob.as_slice()), "IR".to_string())
                    }
                };
                let req = Request { input, gopt, popt: &o.popt, requested: true };
                match driver::run(&ctx, &facts, &policy, &req) {
                    Ok(Outcome::Compiled(out)) => {
                        if !o.quiet {
                            eprintln!("{name}: {n_in} -> {} instructions", out.insns.len());
                        }
                        emit(o, Format::Dump, Content::Bytecode(out.insns.as_slice()))
                    }
                    Ok(Outcome::LoadOriginal(None)) => Err("ePass did not run (policy)".into()),
                    Ok(Outcome::LoadOriginal(Some(e))) | Err(e) => Err(e.to_string()),
                }
            }
        }
    })();
    if !o.quiet {
        let log = ctx.log.borrow();
        let (a, b) = log.parts();
        let mut err = std::io::stderr().lock();
        let _ = err.write_all(a);
        let _ = err.write_all(b);
    }
    r.map_err(|e| if name.is_empty() { e } else { format!("{name}: {e}") })
}

fn emit(o: &Opts, default: Format, c: Content<'_, '_>) -> Result<(), String> {
    let fmt = o.format.or_else(|| o.out.as_deref().and_then(Format::of_path)).unwrap_or(default);
    let bytes: Vec<u8> = match (&c, fmt) {
        (Content::Bytecode(p), Format::Dump) => p.iter().map(|i| format!("{}\n", i.to_u64())).collect::<String>().into_bytes(),
        (Content::Bytecode(p), Format::Raw) => p.iter().flat_map(|i| i.to_u64().to_le_bytes()).collect(),
        (Content::Bytecode(p), Format::Asm) => disasm::program(p).into_bytes(),
        (Content::Ir(f), Format::Epir) => {
            let mut s = String::new();
            epass_core::ir::print::print(&mut s, f).map_err(|e| e.to_string())?;
            s.into_bytes()
        }
        (Content::Ir(f), Format::Blob) => {
            let mut v = FVec::new(f.heap());
            bin::encode(f, &mut v).map_err(|e| e.to_string())?;
            v.as_slice().to_vec()
        }
        (Content::Bytecode(_), _) => return Err(format!("{fmt:?} is an IR format; the output is bytecode")),
        (Content::Ir(_), _) => return Err(format!("{fmt:?} is a bytecode format; the output is IR")),
    };
    match &o.out {
        Some(path) => std::fs::write(path, bytes).map_err(|e| format!("{path}: {e}")),
        None => std::io::stdout().lock().write_all(&bytes).map_err(|e| e.to_string()),
    }
}
