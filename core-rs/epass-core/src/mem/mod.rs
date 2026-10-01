//! Memory: the host boundary and the fallible containers built on it.
//!
//! This is the only module that uses `unsafe`. Everything above it sees safe,
//! fallible containers whose lifetime is tied to one [`Heap`], and a `Heap`
//! lives exactly as long as one compilation.
//!
//! Allocation sizes. Large, id-indexed data (instructions, operands, side
//! tables) uses [`ChunkVec`]/[`IdxVec`], whose chunks are at most
//! [`CHUNK_BYTES`]. Short lists use [`FVec`], a contiguous vector. It is
//! normally small, but can grow up to [`MAX_CONTIG_BYTES`] for rare inputs
//! such as a block with tens of thousands of predecessors. The kernel host
//! therefore backs `alloc` with kvmalloc.

#![allow(unsafe_code)]

mod bitset;
mod chunk;
mod fvec;
mod idx;

pub use bitset::{BitSet, SparseSet};
pub use chunk::ChunkVec;
pub use fvec::FVec;
pub use idx::{Arena, Idx, IdxVec};

use core::alloc::Layout;
use core::cell::Cell;
use core::fmt;
use core::ptr::NonNull;

use crate::error::{Error, Result};
use crate::log::Level;

/// Target size of one chunk of a [`ChunkVec`].
pub const CHUNK_BYTES: usize = 64 * 1024;

/// Largest single contiguous allocation any container makes.
pub const MAX_CONTIG_BYTES: usize = 16 * 1024 * 1024;

/// Returned by [`Host::should_yield`] when the compilation must stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interrupted;

/// The platform: memory, logging, time and cooperative scheduling.
///
/// The userspace implementation lives in `epass-std`; the kernel
/// implementation lives in the kernel overlay (kmalloc/kvmalloc, printk,
/// `cond_resched`, `fatal_signal_pending`).
pub trait Host {
    /// Allocate `layout.size()` bytes aligned to `layout.align()`.
    /// `layout.size()` is never zero. Returning `None` means out of memory.
    fn alloc(&self, layout: Layout) -> Option<NonNull<u8>>;

    /// Release memory returned by [`Host::alloc`].
    ///
    /// # Safety
    /// `ptr` must have been returned by `alloc` on this host with the same
    /// `layout`, and must not be used afterwards.
    unsafe fn free(&self, ptr: NonNull<u8>, layout: Layout);

    /// Emit a diagnostic line immediately (optional; the compilation log is
    /// separate and always kept).
    fn log(&self, _level: Level, _msg: &str) {}

    /// Monotonic time in nanoseconds, or 0 if unavailable.
    fn now_ns(&self) -> u64 {
        0
    }

    /// Called periodically from long-running loops. The kernel host calls
    /// `cond_resched()` here and reports a pending fatal signal.
    fn should_yield(&self) -> core::result::Result<(), Interrupted> {
        Ok(())
    }
}

/// Per-compilation allocator: routes to the host and enforces a byte budget.
pub struct Heap<'h> {
    host: &'h dyn Host,
    used: Cell<usize>,
    peak: Cell<usize>,
    max_bytes: usize,
}

impl fmt::Debug for Heap<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Heap")
            .field("used", &self.used.get())
            .field("peak", &self.peak.get())
            .field("max_bytes", &self.max_bytes)
            .finish()
    }
}

impl<'h> Heap<'h> {
    pub fn new(host: &'h dyn Host, max_bytes: usize) -> Self {
        Heap {
            host,
            used: Cell::new(0),
            peak: Cell::new(0),
            max_bytes,
        }
    }

    pub fn host(&self) -> &'h dyn Host {
        self.host
    }

    /// Bytes currently allocated through this heap.
    pub fn used(&self) -> usize {
        self.used.get()
    }

    /// Highest value of [`Heap::used`] so far.
    pub fn peak(&self) -> usize {
        self.peak.get()
    }

    /// Allocate raw memory for `layout` (size must be non-zero).
    pub(crate) fn alloc(&self, layout: Layout) -> Result<NonNull<u8>> {
        if layout.size() == 0 {
            return Err(Error::internal("zero-sized allocation"));
        }
        if layout.size() > MAX_CONTIG_BYTES {
            return Err(Error::limit("contiguous allocation too large"));
        }
        let new_used = self
            .used
            .get()
            .checked_add(layout.size())
            .ok_or(Error::limit("heap byte limit"))?;
        if new_used > self.max_bytes {
            return Err(Error::limit("heap byte limit"));
        }
        let ptr = self.host.alloc(layout).ok_or(Error::oom())?;
        self.used.set(new_used);
        if new_used > self.peak.get() {
            self.peak.set(new_used);
        }
        Ok(ptr)
    }

    /// Free memory from [`Heap::alloc`].
    ///
    /// # Safety
    /// `ptr` and `layout` must come from a successful `alloc` on this heap.
    pub(crate) unsafe fn free(&self, ptr: NonNull<u8>, layout: Layout) {
        self.used.set(self.used.get().saturating_sub(layout.size()));
        // SAFETY: forwarded caller contract.
        unsafe { self.host.free(ptr, layout) }
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! A std-backed host for unit tests in this crate.
    use super::*;
    use std::alloc;

    #[derive(Debug, Default)]
    pub struct TestHost {
        pub allocs: Cell<u64>,
        pub live: Cell<i64>,
        pub fail_at: Cell<Option<u64>>,
    }

    impl Host for TestHost {
        fn alloc(&self, layout: Layout) -> Option<NonNull<u8>> {
            let n = self.allocs.get() + 1;
            self.allocs.set(n);
            if self.fail_at.get() == Some(n) {
                return None;
            }
            self.live.set(self.live.get() + 1);
            // SAFETY: layout has non-zero size (checked by Heap).
            NonNull::new(unsafe { alloc::alloc(layout) })
        }
        unsafe fn free(&self, ptr: NonNull<u8>, layout: Layout) {
            self.live.set(self.live.get() - 1);
            // SAFETY: caller contract.
            unsafe { alloc::dealloc(ptr.as_ptr(), layout) }
        }
    }
}
