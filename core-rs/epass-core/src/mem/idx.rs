//! Typed ids, id-indexed side tables, and tombstoning arenas.

use core::fmt;
use core::marker::PhantomData;

use super::{ChunkVec, Heap};
use crate::error::{Error, Result};

/// A dense `u32` id.
pub trait Idx: Copy + Eq + Ord + fmt::Debug {
    fn from_u32(i: u32) -> Self;
    fn to_u32(self) -> u32;
    fn index(self) -> usize {
        self.to_u32() as usize
    }
}

/// Define a `u32` newtype id implementing [`Idx`].
#[macro_export]
macro_rules! define_idx {
    ($(#[$m:meta])* $vis:vis struct $name:ident;) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
        $vis struct $name(pub u32);
        impl $crate::mem::Idx for $name {
            #[inline]
            fn from_u32(i: u32) -> Self { $name(i) }
            #[inline]
            fn to_u32(self) -> u32 { self.0 }
        }
    };
}

fn id_of<I: Idx>(index: usize) -> Result<I> {
    u32::try_from(index)
        .map(I::from_u32)
        .map_err(|_| Error::limit("id space exhausted"))
}

/// A dense side table keyed by id.
pub struct IdxVec<'h, I: Idx, T> {
    data: ChunkVec<'h, T>,
    _id: PhantomData<I>,
}

impl<'h, I: Idx, T> IdxVec<'h, I, T> {
    pub fn new(heap: &'h Heap<'h>) -> Self {
        IdxVec {
            data: ChunkVec::new(heap),
            _id: PhantomData,
        }
    }

    /// A table with `len` entries, all equal to `value`.
    pub fn filled(heap: &'h Heap<'h>, len: usize, value: T) -> Result<Self>
    where
        T: Clone,
    {
        Ok(IdxVec {
            data: ChunkVec::filled(heap, len, value)?,
            _id: PhantomData,
        })
    }

    pub fn heap(&self) -> &'h Heap<'h> {
        self.data.heap()
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn push(&mut self, value: T) -> Result<I> {
        let next = id_of::<I>(self.data.len())?;
        self.data.push(value)?;
        Ok(next)
    }

    /// Grow with `value` until `id` is a valid index.
    pub fn ensure(&mut self, id: I, value: T) -> Result<()>
    where
        T: Clone,
    {
        while self.data.len() <= id.index() {
            self.data.push(value.clone())?;
        }
        Ok(())
    }

    pub fn get(&self, id: I) -> Option<&T> {
        self.data.get(id.index())
    }

    pub fn get_mut(&mut self, id: I) -> Option<&mut T> {
        self.data.get_mut(id.index())
    }

    /// Checked access that reports an internal error instead of panicking.
    pub fn at(&self, id: I) -> Result<&T> {
        self.get(id).ok_or(Error::internal("id out of range"))
    }

    pub fn at_mut(&mut self, id: I) -> Result<&mut T> {
        self.get_mut(id).ok_or(Error::internal("id out of range"))
    }

    pub fn get2_mut(&mut self, a: I, b: I) -> Option<(&mut T, &mut T)> {
        self.data.get2_mut(a.index(), b.index())
    }

    pub fn iter(&self) -> impl Iterator<Item = (I, &T)> + '_ {
        self.data
            .iter()
            .enumerate()
            .map(|(i, v)| (I::from_u32(i as u32), v))
    }

    pub fn ids(&self) -> impl Iterator<Item = I> {
        (0..self.data.len() as u32).map(I::from_u32)
    }

    pub fn clear(&mut self) {
        self.data.clear();
    }
}

impl<I: Idx, T: fmt::Debug> fmt::Debug for IdxVec<'_, I, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

/// An id-indexed store whose entries can be removed (tombstoned). Ids are
/// never reused, so stale ids are detected rather than aliased.
pub struct Arena<'h, I: Idx, T> {
    slots: IdxVec<'h, I, Option<T>>,
    live: usize,
}

impl<'h, I: Idx, T> Arena<'h, I, T> {
    pub fn new(heap: &'h Heap<'h>) -> Self {
        Arena {
            slots: IdxVec::new(heap),
            live: 0,
        }
    }

    pub fn heap(&self) -> &'h Heap<'h> {
        self.slots.heap()
    }

    /// Number of ids ever allocated (live or removed).
    pub fn capacity_ids(&self) -> usize {
        self.slots.len()
    }

    /// Number of live entries.
    pub fn live(&self) -> usize {
        self.live
    }

    pub fn alloc(&mut self, value: T) -> Result<I> {
        let id = self.slots.push(Some(value))?;
        self.live += 1;
        Ok(id)
    }

    pub fn get(&self, id: I) -> Option<&T> {
        self.slots.get(id).and_then(Option::as_ref)
    }

    pub fn get_mut(&mut self, id: I) -> Option<&mut T> {
        self.slots.get_mut(id).and_then(Option::as_mut)
    }

    pub fn at(&self, id: I) -> Result<&T> {
        self.get(id).ok_or(Error::internal("dead or unknown id"))
    }

    pub fn at_mut(&mut self, id: I) -> Result<&mut T> {
        self.get_mut(id).ok_or(Error::internal("dead or unknown id"))
    }

    pub fn get2_mut(&mut self, a: I, b: I) -> Option<(&mut T, &mut T)> {
        match self.slots.get2_mut(a, b)? {
            (Some(x), Some(y)) => Some((x, y)),
            _ => None,
        }
    }

    pub fn is_live(&self, id: I) -> bool {
        self.get(id).is_some()
    }

    /// Tombstone `id`, returning its value.
    pub fn remove(&mut self, id: I) -> Option<T> {
        let v = self.slots.get_mut(id)?.take();
        if v.is_some() {
            self.live -= 1;
        }
        v
    }

    /// Live entries in id order.
    pub fn iter(&self) -> impl Iterator<Item = (I, &T)> + '_ {
        self.slots
            .iter()
            .filter_map(|(i, v)| v.as_ref().map(|v| (i, v)))
    }
}

impl<I: Idx, T: fmt::Debug> fmt::Debug for Arena<'_, I, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::test_support::TestHost;

    crate::define_idx! {
        struct TestId;
    }

    #[test]
    fn arena_tombstones_and_ids_are_stable() {
        let host = TestHost::default();
        let heap = Heap::new(&host, 1 << 20);
        let mut a: Arena<TestId, u64> = Arena::new(&heap);
        let x = a.alloc(1).unwrap();
        let y = a.alloc(2).unwrap();
        assert_eq!(a.remove(x), Some(1));
        assert!(!a.is_live(x));
        assert!(a.at(x).is_err());
        let z = a.alloc(3).unwrap();
        assert_ne!(z, x);
        assert_eq!(a.live(), 2);
        assert_eq!(a.iter().map(|(_, v)| *v).collect::<std::vec::Vec<_>>(), [2, 3]);
        *a.at_mut(y).unwrap() = 20;
        assert_eq!(*a.at(y).unwrap(), 20);
    }

    #[test]
    fn idxvec_ensure_and_checked_access() {
        let host = TestHost::default();
        let heap = Heap::new(&host, 1 << 20);
        let mut t: IdxVec<TestId, u8> = IdxVec::new(&heap);
        t.ensure(TestId(9), 0).unwrap();
        assert_eq!(t.len(), 10);
        assert!(t.at(TestId(10)).is_err());
        *t.at_mut(TestId(3)).unwrap() = 7;
        assert_eq!(t.get(TestId(3)), Some(&7));
    }
}
