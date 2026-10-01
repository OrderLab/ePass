//! `ChunkVec`: a fallible vector stored in fixed-size chunks.
//!
//! Elements never move once pushed, and no allocation exceeds
//! [`CHUNK_BYTES`] (plus the small chunk directory), so very large arrays
//! stay kmalloc-friendly.

use core::alloc::Layout;
use core::fmt;
use core::marker::PhantomData;
use core::mem;
use core::ptr::NonNull;

use super::{FVec, Heap, CHUNK_BYTES};
use crate::error::{Error, Result};

pub struct ChunkVec<'h, T> {
    chunks: FVec<'h, NonNull<T>>,
    len: usize,
    _owns: PhantomData<T>,
}

impl<'h, T> ChunkVec<'h, T> {
    /// log2 of the per-chunk element count.
    const SHIFT: u32 = {
        let s = mem::size_of::<T>();
        #[allow(clippy::panic)]
        if s == 0 || s > CHUNK_BYTES {
            panic!("ChunkVec element size must be in 1..=CHUNK_BYTES");
        }
        let per = CHUNK_BYTES / s;
        // Largest power of two <= per.
        usize::BITS - 1 - per.leading_zeros()
    };
    const PER_CHUNK: usize = 1 << Self::SHIFT;
    const MASK: usize = Self::PER_CHUNK - 1;

    pub fn new(heap: &'h Heap<'h>) -> Self {
        let _ = Self::SHIFT;
        ChunkVec {
            chunks: FVec::new(heap),
            len: 0,
            _owns: PhantomData,
        }
    }

    pub fn heap(&self) -> &'h Heap<'h> {
        self.chunks.heap()
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn chunk_layout() -> Result<Layout> {
        Layout::array::<T>(Self::PER_CHUNK).map_err(|_| Error::internal("chunk layout"))
    }

    fn slot(&self, index: usize) -> Option<*mut T> {
        if index >= self.len {
            return None;
        }
        let chunk = *self.chunks.get(index >> Self::SHIFT)?;
        // SAFETY: the offset is < PER_CHUNK, inside the chunk allocation.
        Some(unsafe { chunk.as_ptr().add(index & Self::MASK) })
    }

    /// Append an element and return its index.
    pub fn push(&mut self, value: T) -> Result<usize> {
        let index = self.len;
        if index & Self::MASK == 0 && (index >> Self::SHIFT) == self.chunks.len() {
            let layout = Self::chunk_layout()?;
            let p = self.chunks.heap().alloc(layout)?.cast::<T>();
            if let Err(e) = self.chunks.push(p) {
                // SAFETY: just allocated with this layout.
                unsafe { self.chunks.heap().free(p.cast(), layout) };
                return Err(e);
            }
        }
        let chunk = *self
            .chunks
            .get(index >> Self::SHIFT)
            .ok_or(Error::internal("ChunkVec missing chunk"))?;
        // SAFETY: the slot is inside an allocated chunk and uninitialized.
        unsafe { chunk.as_ptr().add(index & Self::MASK).write(value) };
        self.len += 1;
        Ok(index)
    }

    pub fn get(&self, index: usize) -> Option<&T> {
        // SAFETY: slot() only returns initialized slots.
        self.slot(index).map(|p| unsafe { &*p })
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        // SAFETY: as above; &mut self guarantees exclusivity.
        self.slot(index).map(|p| unsafe { &mut *p })
    }

    /// Mutable access to two distinct elements at once.
    pub fn get2_mut(&mut self, a: usize, b: usize) -> Option<(&mut T, &mut T)> {
        if a == b {
            return None;
        }
        let pa = self.slot(a)?;
        let pb = self.slot(b)?;
        // SAFETY: distinct initialized slots never alias.
        Some(unsafe { (&mut *pa, &mut *pb) })
    }

    pub fn last(&self) -> Option<&T> {
        self.len.checked_sub(1).and_then(|i| self.get(i))
    }

    pub fn pop(&mut self) -> Option<T> {
        let index = self.len.checked_sub(1)?;
        let p = self.slot(index)?;
        self.len = index;
        // SAFETY: slot was initialized and is now logically removed.
        Some(unsafe { p.read() })
    }

    /// Drop elements beyond `len` (chunks are kept for reuse).
    pub fn truncate(&mut self, len: usize) {
        while self.len > len {
            drop(self.pop());
        }
    }

    pub fn clear(&mut self) {
        self.truncate(0);
    }

    /// Build a vector of `len` copies of `value`.
    pub fn filled(heap: &'h Heap<'h>, len: usize, value: T) -> Result<Self>
    where
        T: Clone,
    {
        let mut v = ChunkVec::new(heap);
        for _ in 0..len {
            v.push(value.clone())?;
        }
        Ok(v)
    }

    pub fn iter(&self) -> Iter<'_, 'h, T> {
        Iter { v: self, next: 0 }
    }
}

impl<T> Drop for ChunkVec<'_, T> {
    fn drop(&mut self) {
        self.clear();
        if let Ok(layout) = Self::chunk_layout() {
            let heap = self.chunks.heap();
            for &p in self.chunks.iter() {
                // SAFETY: each chunk was allocated with `layout`; all its
                // elements were dropped by clear().
                unsafe { heap.free(p.cast(), layout) };
            }
        }
    }
}

impl<T> fmt::Debug for ChunkVec<'_, T>
where
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

#[derive(Debug)]
pub struct Iter<'a, 'h, T> {
    v: &'a ChunkVec<'h, T>,
    next: usize,
}

impl<'a, T> Iterator for Iter<'a, '_, T> {
    type Item = &'a T;
    fn next(&mut self) -> Option<&'a T> {
        let item = self.v.get(self.next)?;
        self.next += 1;
        Some(item)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.v.len().saturating_sub(self.next);
        (n, Some(n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::test_support::TestHost;

    #[test]
    fn many_elements_across_chunks() {
        let host = TestHost::default();
        let heap = Heap::new(&host, 1 << 26);
        let mut v = ChunkVec::new(&heap);
        let n: u64 = if cfg!(miri) { 20_000 } else { 200_000 };
        for i in 0..n {
            assert_eq!(v.push(i).unwrap(), i as usize);
        }
        assert_eq!(v.len(), n as usize);
        let mid = n as usize / 2 + 3;
        assert_eq!(*v.get(mid).unwrap(), mid as u64);
        assert!(v.get(n as usize).is_none());
        *v.get_mut(7).unwrap() = 70;
        let (a, b) = v.get2_mut(1, 2).unwrap();
        core::mem::swap(a, b);
        assert_eq!(*v.get(1).unwrap(), 2);
        assert_eq!(v.iter().count(), n as usize);
        assert_eq!(v.pop(), Some(n - 1));
        drop(v);
        assert_eq!(host.live.get(), 0);
    }

    #[test]
    fn chunk_size_is_bounded() {
        const _: () = assert!(ChunkVec::<u64>::PER_CHUNK * 8 <= CHUNK_BYTES);
        const _: () = assert!(ChunkVec::<[u8; 24]>::PER_CHUNK * 24 <= CHUNK_BYTES);
    }

    #[test]
    fn failure_at_every_allocation_is_clean() {
        let (fails, n) = if cfg!(miri) { (8, 40_000u32) } else { (40, 100_000u32) };
        for k in 1..fails {
            let host = TestHost::default();
            host.fail_at.set(Some(k));
            {
                let heap = Heap::new(&host, 1 << 26);
                let mut v = ChunkVec::new(&heap);
                for i in 0..n {
                    if v.push(i).is_err() {
                        break;
                    }
                }
            }
            assert_eq!(host.live.get(), 0, "leak with failure at {k}");
        }
    }
}
