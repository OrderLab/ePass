//! ePass v2 core.
//!
//! An SSA compiler for eBPF programs that runs unchanged in userspace and in
//! the Linux kernel. The crate is `no_std`, has no dependencies, and never
//! panics or recurses in proportion to its input: every allocation is
//! fallible, every lookup is checked, and every graph walk uses an explicit
//! worklist. The only platform contact is the [`mem::Host`] trait.
//!
//! See `design.md` at the repository root.

#![no_std]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )
)]

#[cfg(test)]
extern crate std;

pub mod ctx;
pub mod error;
pub mod log;
pub mod mem;

pub use ctx::{Budget, Ctx, Limits};
pub use error::{Error, ErrorKind, Result};
pub use log::{Level, Log};
pub use mem::{Heap, Host};
