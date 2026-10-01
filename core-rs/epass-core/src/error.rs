//! Error values.
//!
//! Errors are small `Copy` values: a kind, a static message, and an optional
//! position (an instruction index in the input, or an IR id, depending on the
//! producer). Anything longer is written to the [`crate::log::Log`] at the
//! failure site. No error path allocates.

use core::fmt;

/// Error classes. Each maps to one negative errno for the C ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// An allocation failed.
    OutOfMemory,
    /// A configured limit (instructions, bytes, time) was exceeded.
    Limit,
    /// The host asked the compilation to stop (a fatal signal in the kernel).
    Interrupted,
    /// The input uses a feature ePass does not support yet.
    Unsupported,
    /// The input program or option string is malformed.
    InvalidInput,
    /// Submitted or pass-produced IR failed validation.
    InvalidIr,
    /// Register allocation could not complete.
    RegAlloc,
    /// ePass needed stack slots and none were available.
    NoStack,
    /// The policy forbids the request.
    Denied,
    /// An internal invariant was violated (a bug in ePass).
    Internal,
}

impl ErrorKind {
    /// The negative errno reported through the C ABI.
    pub const fn errno(self) -> i32 {
        match self {
            ErrorKind::OutOfMemory => -12,        // ENOMEM
            ErrorKind::Limit => -7,               // E2BIG
            ErrorKind::Interrupted => -4,         // EINTR
            ErrorKind::Unsupported => -95,        // EOPNOTSUPP
            ErrorKind::InvalidInput => -22,       // EINVAL
            ErrorKind::InvalidIr => -22,          // EINVAL
            ErrorKind::RegAlloc => -28,           // ENOSPC
            ErrorKind::NoStack => -28,            // ENOSPC
            ErrorKind::Denied => -1,              // EPERM
            ErrorKind::Internal => -14,           // EFAULT
        }
    }

    /// Short lowercase name used in messages.
    pub const fn name(self) -> &'static str {
        match self {
            ErrorKind::OutOfMemory => "out of memory",
            ErrorKind::Limit => "limit exceeded",
            ErrorKind::Interrupted => "interrupted",
            ErrorKind::Unsupported => "unsupported",
            ErrorKind::InvalidInput => "invalid input",
            ErrorKind::InvalidIr => "invalid IR",
            ErrorKind::RegAlloc => "register allocation failed",
            ErrorKind::NoStack => "no stack space",
            ErrorKind::Denied => "denied by policy",
            ErrorKind::Internal => "internal error",
        }
    }
}

/// An ePass error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    pub msg: &'static str,
    /// Where the error was detected, when meaningful.
    pub pos: Option<u32>,
}

impl Error {
    pub const fn new(kind: ErrorKind, msg: &'static str) -> Self {
        Error { kind, msg, pos: None }
    }

    /// Attach a position.
    pub const fn at(self, pos: u32) -> Self {
        Error {
            kind: self.kind,
            msg: self.msg,
            pos: Some(pos),
        }
    }

    pub const fn oom() -> Self {
        Error::new(ErrorKind::OutOfMemory, "allocation failed")
    }
    pub const fn limit(msg: &'static str) -> Self {
        Error::new(ErrorKind::Limit, msg)
    }
    pub const fn interrupted() -> Self {
        Error::new(ErrorKind::Interrupted, "interrupted by host")
    }
    pub const fn unsupported(msg: &'static str) -> Self {
        Error::new(ErrorKind::Unsupported, msg)
    }
    pub const fn invalid_input(msg: &'static str) -> Self {
        Error::new(ErrorKind::InvalidInput, msg)
    }
    pub const fn invalid_ir(msg: &'static str) -> Self {
        Error::new(ErrorKind::InvalidIr, msg)
    }
    pub const fn internal(msg: &'static str) -> Self {
        Error::new(ErrorKind::Internal, msg)
    }

    pub const fn errno(&self) -> i32 {
        self.kind.errno()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.pos {
            Some(p) => write!(f, "{}: {} (at {})", self.kind.name(), self.msg, p),
            None => write!(f, "{}: {}", self.kind.name(), self.msg),
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;
