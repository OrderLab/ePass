//! Dev helper: read a dump-format file (u64 per line), run autorun, print the
//! resulting dump to stdout. Used to cross-check against the C `epass` tool.

use std::io::Read;

use epass_ir::{autorun, default_passes, logfmt, Env, Opts};

fn main() {
    let path = std::env::args().nth(1).expect("usage: roundtrip <dump-file>");
    let mut text = String::new();
    std::fs::File::open(&path)
        .expect("open")
        .read_to_string(&mut text)
        .expect("read");
    let prog = logfmt::parse_dump(&text);
    let mut opts = Opts::default();
    opts.verbose = std::env::var("V").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    let mut env = Env::new(opts, prog);
    let passes = default_passes();
    match autorun(&mut env, &passes) {
        Ok(()) => {
            if env.opts.verbose > 0 {
                eprint!("{}", env.log_buffer());
            }
            print!("{}", logfmt::to_dump(&env.insns))
        }
        Err(e) => {
            if env.opts.verbose > 0 {
                eprint!("{}", env.log_buffer());
            }
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}
