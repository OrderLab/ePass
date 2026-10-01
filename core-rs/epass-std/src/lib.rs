//! Userspace host for `epass-core`.
//!
//! [`StdHost`] backs the core's [`Host`] trait with the system allocator and
//! adds test hooks: fail the n-th allocation, interrupt at the n-th yield,
//! and count live allocations so tests can check for leaks.

pub mod disasm;

use std::alloc::{self, Layout};
use std::cell::Cell;
use std::ptr::NonNull;
use std::time::Instant;

use epass_core::mem::{Host, Interrupted};
use epass_core::Level;

/// System-allocator host with fault injection.
#[derive(Debug)]
pub struct StdHost {
    start: Instant,
    allocs: Cell<u64>,
    live: Cell<i64>,
    fail_alloc_at: Cell<Option<u64>>,
    yields: Cell<u64>,
    interrupt_at_yield: Cell<Option<u64>>,
    /// Echo `Host::log` lines to stderr.
    pub echo: bool,
}

impl Default for StdHost {
    fn default() -> Self {
        StdHost {
            start: Instant::now(),
            allocs: Cell::new(0),
            live: Cell::new(0),
            fail_alloc_at: Cell::new(None),
            yields: Cell::new(0),
            interrupt_at_yield: Cell::new(None),
            echo: false,
        }
    }
}

impl StdHost {
    pub fn new() -> Self {
        Self::default()
    }

    /// Make the `n`-th allocation (1-based, counted from now) fail.
    pub fn fail_allocation_at(&self, n: u64) {
        self.fail_alloc_at.set(Some(self.allocs.get() + n));
    }

    /// Report an interrupt at the `n`-th yield check (1-based, from now).
    pub fn interrupt_at_yield(&self, n: u64) {
        self.interrupt_at_yield.set(Some(self.yields.get() + n));
    }

    /// Allocations attempted so far.
    pub fn allocations(&self) -> u64 {
        self.allocs.get()
    }

    /// Allocations not yet freed.
    pub fn live_allocations(&self) -> i64 {
        self.live.get()
    }
}

impl Host for StdHost {
    fn alloc(&self, layout: Layout) -> Option<NonNull<u8>> {
        let n = self.allocs.get() + 1;
        self.allocs.set(n);
        if self.fail_alloc_at.get() == Some(n) {
            return None;
        }
        // SAFETY: epass-core never requests zero-sized layouts.
        let p = NonNull::new(unsafe { alloc::alloc(layout) })?;
        self.live.set(self.live.get() + 1);
        Some(p)
    }

    unsafe fn free(&self, ptr: NonNull<u8>, layout: Layout) {
        self.live.set(self.live.get() - 1);
        // SAFETY: caller guarantees ptr/layout came from `alloc`.
        unsafe { alloc::dealloc(ptr.as_ptr(), layout) }
    }

    fn log(&self, level: Level, msg: &str) {
        if self.echo {
            eprintln!("[epass {:?}] {}", level, msg);
        }
    }

    fn now_ns(&self) -> u64 {
        self.start.elapsed().as_nanos() as u64
    }

    fn should_yield(&self) -> Result<(), Interrupted> {
        let n = self.yields.get() + 1;
        self.yields.set(n);
        if self.interrupt_at_yield.get() == Some(n) {
            return Err(Interrupted);
        }
        Ok(())
    }
}
