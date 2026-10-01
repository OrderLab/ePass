//! The compilation log: a fixed-size byte ring that keeps the most recent
//! output. It is allocated once, never grows, and formatting into it never
//! allocates. The host copies it out (in the kernel: into the loader's
//! verifier `log_buf`).

use core::fmt;

use crate::error::Result;
use crate::mem::{FVec, Heap};

/// Message severity. Messages above the log's level are discarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
}

pub struct Log<'h> {
    buf: FVec<'h, u8>,
    /// Next write position in `buf`.
    head: usize,
    /// True once the ring has wrapped (older bytes were overwritten).
    wrapped: bool,
    level: Level,
}

impl fmt::Debug for Log<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Log")
            .field("capacity", &self.buf.len())
            .field("wrapped", &self.wrapped)
            .field("level", &self.level)
            .finish()
    }
}

impl<'h> Log<'h> {
    /// A log holding the last `capacity` bytes (0 disables logging).
    pub fn new(heap: &'h Heap<'h>, capacity: usize, level: Level) -> Result<Self> {
        let mut buf = FVec::with_capacity(heap, capacity)?;
        buf.resize(capacity, 0)?;
        Ok(Log {
            buf,
            head: 0,
            wrapped: false,
            level,
        })
    }

    pub fn level(&self) -> Level {
        self.level
    }

    pub fn enabled(&self, level: Level) -> bool {
        level <= self.level && !self.buf.is_empty()
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        let cap = self.buf.len();
        if cap == 0 {
            return;
        }
        // Only the last `cap` bytes can survive.
        let bytes = match bytes.len().checked_sub(cap) {
            Some(skip) if skip > 0 => {
                self.wrapped = true;
                bytes.get(skip..).unwrap_or(&[])
            }
            _ => bytes,
        };
        for &b in bytes {
            if let Some(slot) = self.buf.get_mut(self.head) {
                *slot = b;
            }
            self.head += 1;
            if self.head == cap {
                self.head = 0;
                self.wrapped = true;
            }
        }
    }

    /// Append a formatted message at `level`.
    pub fn write_fmt(&mut self, level: Level, args: fmt::Arguments<'_>) {
        if !self.enabled(level) {
            return;
        }
        let mut w = Writer(self);
        let _ = fmt::write(&mut w, args);
    }

    /// Append a string at `level`.
    pub fn write_str(&mut self, level: Level, s: &str) {
        if self.enabled(level) {
            self.write_bytes(s.as_bytes());
        }
    }

    /// The log contents in order, as up to two slices.
    pub fn parts(&self) -> (&[u8], &[u8]) {
        let (older, newer) = if self.wrapped {
            (
                self.buf.get(self.head..).unwrap_or(&[]),
                self.buf.get(..self.head).unwrap_or(&[]),
            )
        } else {
            (self.buf.get(..self.head).unwrap_or(&[]), &[][..])
        };
        (older, newer)
    }

    /// Whether older output was dropped.
    pub fn truncated(&self) -> bool {
        self.wrapped
    }

    /// Copy the contents into `dst`, NUL-terminated if there is room.
    /// Returns the number of bytes copied (excluding the NUL).
    pub fn copy_out(&self, dst: &mut [u8]) -> usize {
        let (a, b) = self.parts();
        let mut n = 0usize;
        for &byte in a.iter().chain(b.iter()) {
            if n + 1 >= dst.len() {
                break;
            }
            if let Some(d) = dst.get_mut(n) {
                *d = byte;
            }
            n += 1;
        }
        if let Some(d) = dst.get_mut(n) {
            *d = 0;
        }
        n
    }
}

struct Writer<'a, 'h>(&'a mut Log<'h>);

impl fmt::Write for Writer<'_, '_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0.write_bytes(s.as_bytes());
        Ok(())
    }
}

/// `ep_log!(log, Level::Info, "fmt {}", x)`: append to a [`Log`].
#[macro_export]
macro_rules! ep_log {
    ($log:expr, $level:expr, $($arg:tt)*) => {
        $log.write_fmt($level, ::core::format_args!($($arg)*))
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::test_support::TestHost;
    use std::string::String;

    fn contents(log: &Log<'_>) -> String {
        let (a, b) = log.parts();
        let mut s = String::from_utf8_lossy(a).into_owned();
        s.push_str(&String::from_utf8_lossy(b));
        s
    }

    #[test]
    fn keeps_the_tail_when_full() {
        let host = TestHost::default();
        let heap = Heap::new(&host, 1 << 20);
        let mut log = Log::new(&heap, 16, Level::Info).unwrap();
        ep_log!(log, Level::Info, "hello {}\n", 1);
        assert_eq!(contents(&log), "hello 1\n");
        ep_log!(log, Level::Debug, "dropped\n");
        assert_eq!(contents(&log), "hello 1\n");
        ep_log!(log, Level::Info, "0123456789abcdef-tail");
        assert!(log.truncated());
        assert_eq!(contents(&log), "56789abcdef-tail");
        let mut out = [0u8; 8];
        assert_eq!(log.copy_out(&mut out), 7);
        assert_eq!(&out, b"56789ab\0");
    }

    #[test]
    fn zero_capacity_is_silent() {
        let host = TestHost::default();
        let heap = Heap::new(&host, 1 << 20);
        let mut log = Log::new(&heap, 0, Level::Debug).unwrap();
        ep_log!(log, Level::Error, "x");
        assert_eq!(contents(&log), "");
    }
}
