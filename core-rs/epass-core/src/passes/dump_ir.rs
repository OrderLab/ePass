//! `dump_ir`: print the IR into the compilation log (Info level).

use core::fmt::Write;

use crate::error::Result;
use crate::ir::print::print;
use crate::ir::Function;
use crate::log::Level;
use crate::pm::{no_args, PassCx, PassInfo, Phase};

pub const INFO: PassInfo = PassInfo {
    name: "dump_ir",
    phase: Phase::Canonicalize,
    after: &[],
    before: &[],
    default_on: false,
    user_controllable: true,
    mandatory: false,
    check_args: no_args,
    run,
};

struct LogWriter<'a, 'b, 'h>(&'a PassCx<'b, 'h>);

impl Write for LogWriter<'_, '_, '_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        if let Ok(mut l) = self.0.ctx.log.try_borrow_mut() {
            l.write_str(Level::Info, s);
        }
        Ok(())
    }
}

fn run<'h>(f: &mut Function<'h>, cx: &PassCx<'_, 'h>, _args: Option<&str>) -> Result<()> {
    if !cx.ctx.log_enabled(Level::Info) {
        return Ok(());
    }
    let mut w = LogWriter(cx);
    print(&mut w, f)
}
