//! Per-compilation context: heap, log, limits and the cooperative budget.

use core::cell::{Cell, RefCell};
use core::fmt;

use crate::error::{Error, Result};
use crate::log::{Level, Log};
use crate::mem::Heap;

/// Resource limits for one compilation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Maximum input instructions (bytecode slots or IR instructions).
    pub max_insns: u32,
    /// Maximum bytes allocated through the heap.
    pub max_bytes: usize,
    /// Wall-clock limit in nanoseconds (0 = none).
    pub time_ns: u64,
    /// Compilation log capacity in bytes.
    pub log_bytes: usize,
    /// How many budget ticks pass between host yield checks.
    pub yield_every: u32,
}

impl Limits {
    /// Defaults for userspace tools.
    pub const USERSPACE: Limits = Limits {
        max_insns: 1_000_000,
        max_bytes: u32::MAX as usize,
        time_ns: 0,
        log_bytes: 1 << 20,
        yield_every: 4096,
    };

    /// Defaults for in-kernel runs (policy may override).
    pub const KERNEL: Limits = Limits {
        max_insns: 65_536,
        max_bytes: 64 << 20,
        time_ns: 10_000_000_000,
        log_bytes: 64 << 10,
        yield_every: 1024,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Limits::USERSPACE
    }
}

/// Cooperative work budget. Long-running loops call [`Budget::tick`]; every
/// `yield_every` ticks the host gets a chance to reschedule or interrupt, and
/// the time limit is checked.
pub struct Budget {
    left: Cell<u32>,
    every: u32,
    deadline_ns: u64,
    ticks: Cell<u64>,
}

impl fmt::Debug for Budget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Budget")
            .field("ticks", &self.ticks.get())
            .field("deadline_ns", &self.deadline_ns)
            .finish()
    }
}

impl Budget {
    fn new(every: u32, deadline_ns: u64) -> Self {
        let every = every.max(1);
        Budget {
            left: Cell::new(every),
            every,
            deadline_ns,
            ticks: Cell::new(0),
        }
    }

    pub fn ticks(&self) -> u64 {
        self.ticks.get()
    }
}

/// Everything a compilation stage needs besides the IR itself.
pub struct Ctx<'h> {
    pub heap: &'h Heap<'h>,
    /// The compilation log. Use [`Ctx::log`] to write; borrows never panic.
    pub log: RefCell<Log<'h>>,
    pub limits: Limits,
    budget: Budget,
}

impl fmt::Debug for Ctx<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ctx")
            .field("heap", self.heap)
            .field("limits", &self.limits)
            .field("budget", &self.budget)
            .finish()
    }
}

impl<'h> Ctx<'h> {
    pub fn new(heap: &'h Heap<'h>, limits: Limits, level: Level) -> Result<Self> {
        let log = Log::new(heap, limits.log_bytes, level)?;
        let deadline = if limits.time_ns == 0 {
            0
        } else {
            heap.host().now_ns().saturating_add(limits.time_ns)
        };
        Ok(Ctx {
            heap,
            log: RefCell::new(log),
            limits,
            budget: Budget::new(limits.yield_every, deadline),
        })
    }

    /// Account one unit of work; periodically yields to the host.
    #[inline]
    pub fn tick(&self) -> Result<()> {
        let b = &self.budget;
        b.ticks.set(b.ticks.get().wrapping_add(1));
        let left = b.left.get().saturating_sub(1);
        if left != 0 {
            b.left.set(left);
            return Ok(());
        }
        b.left.set(b.every);
        self.heap
            .host()
            .should_yield()
            .map_err(|_| Error::interrupted())?;
        if b.deadline_ns != 0 && self.heap.host().now_ns() > b.deadline_ns {
            return Err(Error::limit("compilation time limit"));
        }
        Ok(())
    }

    pub fn budget(&self) -> &Budget {
        &self.budget
    }

    /// Append a formatted message to the log (dropped if the log is busy).
    pub fn log(&self, level: Level, args: fmt::Arguments<'_>) {
        if let Ok(mut l) = self.log.try_borrow_mut() {
            l.write_fmt(level, args);
        }
    }

    pub fn log_enabled(&self, level: Level) -> bool {
        self.log.try_borrow().is_ok_and(|l| l.enabled(level))
    }
}

/// `ctx_log!(ctx, Level::Info, "fmt {}", x)`: append to the context log.
#[macro_export]
macro_rules! ctx_log {
    ($ctx:expr, $level:expr, $($arg:tt)*) => {
        $ctx.log($level, ::core::format_args!($($arg)*))
    };
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;
    use crate::mem::{test_support::TestHost, Host, Interrupted};
    use core::alloc::Layout;
    use core::ptr::NonNull;

    struct InterruptingHost {
        inner: TestHost,
        calls: Cell<u32>,
    }

    impl Host for InterruptingHost {
        fn alloc(&self, layout: Layout) -> Option<NonNull<u8>> {
            self.inner.alloc(layout)
        }
        unsafe fn free(&self, ptr: NonNull<u8>, layout: Layout) {
            // SAFETY: forwarded.
            unsafe { self.inner.free(ptr, layout) }
        }
        fn should_yield(&self) -> core::result::Result<(), Interrupted> {
            self.calls.set(self.calls.get() + 1);
            if self.calls.get() >= 3 {
                Err(Interrupted)
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn tick_yields_periodically_and_propagates_interrupt() {
        let host = InterruptingHost {
            inner: TestHost::default(),
            calls: Cell::new(0),
        };
        let heap = Heap::new(&host, 1 << 22);
        let limits = Limits {
            yield_every: 10,
            ..Limits::USERSPACE
        };
        let ctx = Ctx::new(&heap, limits, Level::Info).unwrap();
        let mut n = 0;
        let err = loop {
            n += 1;
            if let Err(e) = ctx.tick() {
                break e;
            }
        };
        assert_eq!(err.kind, crate::ErrorKind::Interrupted);
        assert_eq!(n, 30);
        assert_eq!(host.calls.get(), 3);
    }
}
