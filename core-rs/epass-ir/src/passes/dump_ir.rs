//! Optional IR dump pass.
//!
//! Enabled with pass option `dump_ir(<path>)` or `dump_ir(path=<path>)`.
//! The pass orders itself first, so it dumps the IR immediately after lift (or
//! immediately after `load_ir`) before other passes mutate it.

use crate::env::Env;
use crate::error::{Error, Result};
use crate::ir::Function;
use crate::pass::Pass;
use crate::invalid;

#[derive(Default)]
pub struct DumpIrPass {
    path: Option<String>,
}

impl Pass for DumpIrPass {
    fn name(&self) -> &str {
        "dump_ir"
    }

    fn enabled_by_default(&self) -> bool {
        false
    }

    fn allow_disable(&self) -> bool {
        true
    }

    fn init(&mut self, arg: Option<&str>) -> Result<()> {
        let arg = arg.ok_or_else(|| invalid!("dump_ir requires a path: use dump_ir(/tmp/file.epir)"))?;
        let path = arg.strip_prefix("path=").unwrap_or(arg).trim();
        if path.is_empty() {
            return Err(invalid!("dump_ir path is empty"));
        }
        self.path = Some(path.to_string());
        Ok(())
    }

    fn register_pass(&self, mut order: Vec<String>) -> Result<Vec<String>> {
        let name = self.name();
        order.retain(|p| p != name);
        order.insert(0, name.to_string());
        Ok(order)
    }

    fn run(&self, env: &mut Env, func: &mut Function) -> Result<()> {
        let Some(path) = self.path.as_ref() else {
            return Ok(());
        };
        crate::ir::text::dump_function_to_file(func, path).map_err(|e| match e {
            Error::Internal(msg) => Error::Internal(format!("dump_ir failed for '{path}': {msg}")),
            other => other,
        })?;
        crate::log_info!(env, "ePass: dumped IR to {}\n", path);
        Ok(())
    }
}

pub fn pass() -> impl Pass {
    DumpIrPass::default()
}
