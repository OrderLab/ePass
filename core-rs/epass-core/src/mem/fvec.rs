//! `FVec`: a fallible, contiguous, heap-bound vector.

use core::alloc::Layout;
use core::fmt;
use core::marker::PhantomData;
use core::mem::{self, MaybeUninit};
use core::ops::{Deref, DerefMut};
use core::ptr::{self, NonNull};

use super::{Heap, MAX_CONTIG_BYTES};
use crate::error::{Error, Result};

/// A growable contiguous vector whose every allocation can fail.
///
/// Element types must not be zero-sized.
pub struct FVec<'h, T> {
    heap: &'h Heap<'h>,
    ptr: NonNull<T>,
    len: usize,
    cap: usize,
    _owns: PhantomData<T>,
}

impl<'h, T> FVec<'h, T> {
    const ELEM: usize = {
        let s = mem::size_of::<T>();
        #[allow(clippy::panic)]
        if s == 0 {
            panic!("FVec does not support zero-sized types");
        }
        s
    };

    /// Maximum element count for this element type.
    pub const MAX_LEN: usize = MAX_CONTIG_BYTES / Self::ELEM;

    pub fn new(heap: &'h Heap<'h>) -> Self {
        let _ = Self::ELEM;
        FVec {
            heap,
            ptr: NonNull::dangling(),
            len: 0,
            cap: 0,
            _owns: PhantomData,
        }
    }

    pub fn with_capacity(heap: &'h Heap<'h>, cap: usize) -> Result<Self> {
        let mut v = FVec::new(heap);
        v.reserve_exact(cap)?;
        Ok(v)
    }

    pub fn heap(&self) -> &'h Heap<'h> {
        self.heap
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn capacity(&self) -> usize {
        self.cap
    }

    fn layout(cap: usize) -> Result<Layout> {
        Layout::array::<T>(cap).map_err(|_| Error::limit("FVec layout overflow"))
    }

    /// Ensure capacity for at least `additional` more elements (exactly).
    pub fn reserve_exact(&mut self, additional: usize) -> Result<()> {
        let need = self
            .len
            .checked_add(additional)
            .ok_or(Error::limit("FVec length overflow"))?;
        if need <= self.cap {
            return Ok(());
        }
        self.grow_to(need)
    }

    /// Ensure capacity for at least one more element, growing geometrically.
    fn reserve_one(&mut self) -> Result<()> {
        if self.len < self.cap {
            return Ok(());
        }
        let doubled = self.cap.saturating_mul(2).max(4);
        let target = doubled.min(Self::MAX_LEN);
        if target <= self.len {
            return Err(Error::limit("FVec exceeds maximum length"));
        }
        self.grow_to(target)
    }

    fn grow_to(&mut self, new_cap: usize) -> Result<()> {
        if new_cap > Self::MAX_LEN {
            return Err(Error::limit("FVec exceeds maximum length"));
        }
        let new_layout = Self::layout(new_cap)?;
        let new_ptr = self.heap.alloc(new_layout)?.cast::<T>();
        if self.cap != 0 {
            // SAFETY: both regions are valid for `len` elements, distinct
            // allocations, and the old one is freed right after the move.
            unsafe {
                ptr::copy_nonoverlapping(self.ptr.as_ptr(), new_ptr.as_ptr(), self.len);
                let old = Self::layout(self.cap)?;
                self.heap.free(self.ptr.cast(), old);
            }
        }
        self.ptr = new_ptr;
        self.cap = new_cap;
        Ok(())
    }

    /// Append an element. On failure the element is dropped.
    pub fn push(&mut self, value: T) -> Result<()> {
        self.reserve_one()?;
        // SAFETY: `len < cap` after reserve_one; slot is uninitialized.
        unsafe { self.ptr.as_ptr().add(self.len).write(value) };
        self.len += 1;
        Ok(())
    }

    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        // SAFETY: slot `len` was initialized and is now logically removed.
        Some(unsafe { self.ptr.as_ptr().add(self.len).read() })
    }

    /// Insert at `index`, shifting later elements right.
    pub fn insert(&mut self, index: usize, value: T) -> Result<()> {
        if index > self.len {
            return Err(Error::internal("FVec::insert out of range"));
        }
        self.reserve_one()?;
        // SAFETY: capacity for len+1; the shifted range is initialized.
        unsafe {
            let p = self.ptr.as_ptr().add(index);
            ptr::copy(p, p.add(1), self.len - index);
            p.write(value);
        }
        self.len += 1;
        Ok(())
    }

    /// Remove at `index`, shifting later elements left.
    pub fn remove(&mut self, index: usize) -> Option<T> {
        if index >= self.len {
            return None;
        }
        // SAFETY: index < len; tail is moved down over the read slot.
        unsafe {
            let p = self.ptr.as_ptr().add(index);
            let v = p.read();
            ptr::copy(p.add(1), p, self.len - index - 1);
            self.len -= 1;
            Some(v)
        }
    }

    /// Remove at `index` by swapping in the last element (O(1)).
    pub fn swap_remove(&mut self, index: usize) -> Option<T> {
        if index >= self.len {
            return None;
        }
        let last = self.len - 1;
        self.as_mut_slice().swap(index, last);
        self.pop()
    }

    pub fn truncate(&mut self, len: usize) {
        while self.len > len {
            drop(self.pop());
        }
    }

    pub fn clear(&mut self) {
        self.truncate(0);
    }

    /// Keep only elements for which `keep` returns true (order preserved).
    pub fn retain(&mut self, mut keep: impl FnMut(&T) -> bool) {
        let mut write = 0usize;
        for read in 0..self.len {
            // SAFETY: read < len; each element is moved at most once, and
            // dropped exactly once if rejected.
            unsafe {
                let src = self.ptr.as_ptr().add(read);
                if keep(&*src) {
                    if read != write {
                        ptr::copy_nonoverlapping(src, self.ptr.as_ptr().add(write), 1);
                    }
                    write += 1;
                } else {
                    ptr::drop_in_place(src);
                }
            }
        }
        self.len = write;
    }

    pub fn as_slice(&self) -> &[T] {
        // SAFETY: ptr is valid (or dangling with len 0) for len elements.
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [T] {
        // SAFETY: as above, and we hold &mut self.
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    /// Resize to `len` elements, filling new slots with `value`.
    pub fn resize(&mut self, len: usize, value: T) -> Result<()>
    where
        T: Clone,
    {
        if len <= self.len {
            self.truncate(len);
            return Ok(());
        }
        self.reserve_exact(len - self.len)?;
        while self.len < len {
            self.push(value.clone())?;
        }
        Ok(())
    }

    /// Append copies of all elements of `other`.
    pub fn extend_from_slice(&mut self, other: &[T]) -> Result<()>
    where
        T: Copy,
    {
        self.reserve_exact(other.len())?;
        for v in other {
            self.push(*v)?;
        }
        Ok(())
    }

    /// Fallible clone (element types must be `Copy`).
    pub fn try_clone(&self) -> Result<FVec<'h, T>>
    where
        T: Copy,
    {
        let mut out = FVec::with_capacity(self.heap, self.len)?;
        out.extend_from_slice(self.as_slice())?;
        Ok(out)
    }

    /// Push `value` unless it is already present. Returns true if pushed.
    pub fn push_unique(&mut self, value: T) -> Result<bool>
    where
        T: PartialEq,
    {
        if self.as_slice().contains(&value) {
            return Ok(false);
        }
        self.push(value)?;
        Ok(true)
    }

    /// Leak-free conversion to uninit spare capacity (used by readers that
    /// fill a buffer in place).
    pub fn spare_capacity_mut(&mut self) -> &mut [MaybeUninit<T>] {
        // SAFETY: the region [len, cap) is allocated and uninitialized.
        unsafe {
            core::slice::from_raw_parts_mut(
                self.ptr.as_ptr().add(self.len).cast::<MaybeUninit<T>>(),
                self.cap - self.len,
            )
        }
    }
}

impl<T> Drop for FVec<'_, T> {
    fn drop(&mut self) {
        self.clear();
        if self.cap != 0 {
            if let Ok(layout) = Layout::array::<T>(self.cap) {
                // SAFETY: allocated by this heap with this layout.
                unsafe { self.heap.free(self.ptr.cast(), layout) };
            }
        }
    }
}

impl<T> Deref for FVec<'_, T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        self.as_slice()
    }
}

impl<T> DerefMut for FVec<'_, T> {
    fn deref_mut(&mut self) -> &mut [T] {
        self.as_mut_slice()
    }
}

impl<T: fmt::Debug> fmt::Debug for FVec<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.as_slice()).finish()
    }
}

impl<'a, T> IntoIterator for &'a FVec<'_, T> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::test_support::TestHost;

    #[test]
    fn push_pop_insert_remove() {
        let host = TestHost::default();
        let heap = Heap::new(&host, 1 << 20);
        let mut v = FVec::new(&heap);
        for i in 0..100u32 {
            v.push(i).unwrap();
        }
        assert_eq!(v.len(), 100);
        v.insert(0, 1000).unwrap();
        assert_eq!(v[0], 1000);
        assert_eq!(v.remove(0), Some(1000));
        assert_eq!(v.swap_remove(0), Some(0));
        assert_eq!(v[0], 99);
        v.retain(|x| x % 2 == 0);
        assert!(v.iter().all(|x| x % 2 == 0));
        let c = v.try_clone().unwrap();
        assert_eq!(c.as_slice(), v.as_slice());
        drop(c);
        drop(v);
        assert_eq!(host.live.get(), 0);
        assert_eq!(heap.used(), 0);
    }

    #[test]
    fn byte_limit_is_enforced() {
        let host = TestHost::default();
        let heap = Heap::new(&host, 64);
        let mut v = FVec::new(&heap);
        let mut err = None;
        for i in 0..1000u64 {
            if let Err(e) = v.push(i) {
                err = Some(e);
                break;
            }
        }
        assert_eq!(err.map(|e| e.kind), Some(crate::error::ErrorKind::Limit));
    }

    #[test]
    fn allocation_failure_is_reported_and_leak_free() {
        for k in 1..6 {
            let host = TestHost::default();
            host.fail_at.set(Some(k));
            {
                let heap = Heap::new(&host, 1 << 20);
                let mut v = FVec::new(&heap);
                let mut failed = false;
                for i in 0..200u32 {
                    if v.push(i).is_err() {
                        failed = true;
                        break;
                    }
                }
                assert!(failed);
            }
            assert_eq!(host.live.get(), 0);
        }
    }

    #[test]
    fn drops_elements() {
        use std::rc::Rc;
        let host = TestHost::default();
        let heap = Heap::new(&host, 1 << 20);
        let rc = Rc::new(());
        {
            let mut v = FVec::new(&heap);
            for _ in 0..10 {
                v.push(rc.clone()).unwrap();
            }
            v.retain(|_| false);
            v.push(rc.clone()).unwrap();
        }
        assert_eq!(Rc::strong_count(&rc), 1);
    }
}
