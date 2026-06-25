//! The pipeline environment: carries options, the instruction buffer, a log
//! sink, and timing statistics through every stage.

use std::fmt::Write as _;
use std::time::Instant;

use crate::bytecode::BpfInsn;
use crate::opts::Opts;

/// Log severity levels, matching the C `PRINT_LOG_*` macros.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Error = 0,
    Warning = 1,
    Debug = 2,
    Info = 3,
}

/// Mutable state threaded through lifting, passes, and code generation.
pub struct Env {
    pub opts: Opts,
    /// The working instruction buffer (input on entry, rewritten on output).
    pub insns: Vec<BpfInsn>,
    /// Accumulated, human-readable log text.
    log: String,

    pub lift_time_ns: u128,
    pub run_time_ns: u128,
    pub cg_time_ns: u128,

    /// Verifier error code, if ePass is invoked alongside the verifier (-1 = none).
    pub verifier_err: i32,
}

impl Env {
    pub fn new(opts: Opts, insns: Vec<BpfInsn>) -> Self {
        Self {
            opts,
            insns,
            log: String::new(),
            lift_time_ns: 0,
            run_time_ns: 0,
            cg_time_ns: 0,
            verifier_err: -1,
        }
    }

    /// Append a log message if it is at or below the configured verbosity.
    ///
    /// `verbose` is a "level" where higher prints more; a message is kept when
    /// its severity is important enough (`Error`=0) or verbosity is high enough.
    pub fn log(&mut self, level: LogLevel, args: std::fmt::Arguments<'_>) {
        // Errors and warnings are always recorded; debug/info gated by verbosity.
        let keep = match level {
            LogLevel::Error | LogLevel::Warning => true,
            LogLevel::Info => self.opts.verbose >= 1,
            LogLevel::Debug => self.opts.verbose >= 2,
        };
        if keep {
            let _ = self.log.write_fmt(args);
        }
    }

    pub fn log_str(&mut self, level: LogLevel, msg: &str) {
        self.log(level, format_args!("{msg}"));
    }

    /// Borrow the accumulated log text.
    pub fn log_buffer(&self) -> &str {
        &self.log
    }

    /// Take ownership of the log, clearing the internal buffer.
    pub fn take_log(&mut self) -> String {
        std::mem::take(&mut self.log)
    }

    pub fn total_time_ns(&self) -> u128 {
        self.lift_time_ns + self.run_time_ns + self.cg_time_ns
    }
}

/// Convenience macros for logging into an [`Env`].
#[macro_export]
macro_rules! log_error {
    ($env:expr, $($arg:tt)*) => { $env.log($crate::env::LogLevel::Error, format_args!($($arg)*)) };
}
#[macro_export]
macro_rules! log_warn {
    ($env:expr, $($arg:tt)*) => { $env.log($crate::env::LogLevel::Warning, format_args!($($arg)*)) };
}
#[macro_export]
macro_rules! log_info {
    ($env:expr, $($arg:tt)*) => { $env.log($crate::env::LogLevel::Info, format_args!($($arg)*)) };
}
#[macro_export]
macro_rules! log_debug {
    ($env:expr, $($arg:tt)*) => { $env.log($crate::env::LogLevel::Debug, format_args!($($arg)*)) };
}

/// A simple scoped timer; call [`Timer::elapsed_ns`] to read the duration.
pub struct Timer(Instant);

impl Timer {
    pub fn start() -> Self {
        Timer(Instant::now())
    }
    pub fn elapsed_ns(&self) -> u128 {
        self.0.elapsed().as_nanos()
    }
}
