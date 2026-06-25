//! Error types for the ePass IR pipeline.

use thiserror::Error;

/// Errors produced while lifting, transforming, or compiling an eBPF program.
///
/// The C implementation collapses everything into a single `env->err` integer
/// (mostly `-ENOSYS` / `-ENOMEM` / `-EINVAL`) plus a free-form log string. Here
/// we keep a richer, typed enum while still being able to surface a numeric
/// errno-like code for the CLI return path via [`Error::errno`].
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Error {
    /// The program uses a feature ePass does not support yet.
    #[error("unsupported: {0}")]
    Unsupported(String),

    /// The input program is malformed / not a valid eBPF program.
    #[error("invalid program: {0}")]
    InvalidProgram(String),

    /// An internal invariant was violated (a bug in ePass).
    #[error("internal error: {0}")]
    Internal(String),

    /// Register allocation could not find a valid assignment.
    #[error("register allocation failed: {0}")]
    RegAlloc(String),

    /// The program exceeds a configured limit.
    #[error("limit exceeded: {0}")]
    LimitExceeded(String),
}

impl Error {
    /// Map to a negative errno, matching the conventions used by the C tool.
    pub fn errno(&self) -> i32 {
        match self {
            Error::Unsupported(_) | Error::Internal(_) | Error::RegAlloc(_) => -38, // -ENOSYS
            Error::InvalidProgram(_) | Error::LimitExceeded(_) => -22,              // -EINVAL
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Build an [`Error::Unsupported`].
#[macro_export]
macro_rules! unsupported {
    ($($arg:tt)*) => { $crate::error::Error::Unsupported(format!($($arg)*)) };
}

/// Build an [`Error::InvalidProgram`].
#[macro_export]
macro_rules! invalid {
    ($($arg:tt)*) => { $crate::error::Error::InvalidProgram(format!($($arg)*)) };
}

/// Build an [`Error::Internal`].
#[macro_export]
macro_rules! internal {
    ($($arg:tt)*) => { $crate::error::Error::Internal(format!($($arg)*)) };
}
