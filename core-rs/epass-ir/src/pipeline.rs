//! The end-to-end driver: lift, run passes, and compile, mirroring the C
//! `bpf_ir_autorun`.

use crate::cg;
use crate::env::Env;
use crate::error::Result;
use crate::lift;
use crate::pass::PassManager;
use crate::{log_debug, log_info};

fn initial_function(env: &mut Env) -> Result<crate::ir::Function> {
    if let Some(path) = env.opts.load_ir.clone() {
        let mut func = crate::ir::text::load_function_from_file(path)?;
        crate::pass::postprocess(env, &mut func)?;
        Ok(func)
    } else {
        lift::lift(env)
    }
}

/// Lift, run the given passes, and compile the program in `env.insns`,
/// writing the rewritten bytecode back into `env.insns`.
pub fn autorun(env: &mut Env, passes: &PassManager) -> Result<()> {
    let len = env.insns.len();

    if env.opts.print_only {
        return Ok(());
    }

    let mut func = initial_function(env)?;
    log_debug!(env, "{}", crate::ir::print::print_function(&func));

    passes.run(env, &mut func)?;
    cg::compile(env, &mut func)?;

    log_info!(
        env,
        "ePass: {} -> {} instructions\n",
        len,
        env.insns.len()
    );
    Ok(())
}

/// Lift and run passes but skip code generation (the `--pass-only` path).
pub fn run_passes_only(env: &mut Env, passes: &PassManager) -> Result<()> {
    let mut func = initial_function(env)?;
    passes.run(env, &mut func)?;
    Ok(())
}
