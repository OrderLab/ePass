//! Bit sets and sparse sets over dense `u32` universes.

use core::fmt;

use super::{ChunkVec, Heap};
use crate::error::{Error, Result};

/// A fixed-universe bit set.
pub struct BitSet<'h> {
    words: ChunkVec<'h, u64>,
    bits: usize,
}

impl<'h> BitSet<'h> {
    pub fn new(heap: &'h Heap<'h>, bits: usize) -> Result<Self> {
        let words = bits.div_ceil(64);
        Ok(BitSet {
            words: ChunkVec::filled(heap, words, 0)?,
            bits,
        })
    }

    pub fn universe(&self) -> usize {
        self.bits
    }

    fn word_mut(&mut self, i: usize) -> Result<(&mut u64, u64)> {
        if i >= self.bits {
            return Err(Error::internal("bit index out of range"));
        }
        let w = self
            .words
            .get_mut(i / 64)
            .ok_or(Error::internal("bit word"))?;
        Ok((w, 1u64 << (i % 64)))
    }

    /// Set bit `i`; returns true if it was newly set.
    pub fn insert(&mut self, i: usize) -> Result<bool> {
        let (w, m) = self.word_mut(i)?;
        let was = *w & m != 0;
        *w |= m;
        Ok(!was)
    }

    pub fn remove(&mut self, i: usize) -> Result<bool> {
        let (w, m) = self.word_mut(i)?;
        let was = *w & m != 0;
        *w &= !m;
        Ok(was)
    }

    pub fn contains(&self, i: usize) -> bool {
        i < self.bits
            && self
                .words
                .get(i / 64)
                .is_some_and(|w| w & (1u64 << (i % 64)) != 0)
    }

    pub fn clear(&mut self) {
        let n = self.words.len();
        for i in 0..n {
            if let Some(w) = self.words.get_mut(i) {
                *w = 0;
            }
        }
    }

    /// `self |= other`; returns true if anything changed.
    pub fn union_with(&mut self, other: &BitSet<'_>) -> Result<bool> {
        if other.bits != self.bits {
            return Err(Error::internal("bitset universe mismatch"));
        }
        let mut changed = false;
        for i in 0..self.words.len() {
            let o = *other.words.get(i).ok_or(Error::internal("bit word"))?;
            let w = self.words.get_mut(i).ok_or(Error::internal("bit word"))?;
            let n = *w | o;
            changed |= n != *w;
            *w = n;
        }
        Ok(changed)
    }

    /// `self &= other`; returns true if anything changed.
    pub fn intersect_with(&mut self, other: &BitSet<'_>) -> Result<bool> {
        if other.bits != self.bits {
            return Err(Error::internal("bitset universe mismatch"));
        }
        let mut changed = false;
        for i in 0..self.words.len() {
            let o = *other.words.get(i).ok_or(Error::internal("bit word"))?;
            let w = self.words.get_mut(i).ok_or(Error::internal("bit word"))?;
            let n = *w & o;
            changed |= n != *w;
            *w = n;
        }
        Ok(changed)
    }

    pub fn copy_from(&mut self, other: &BitSet<'_>) -> Result<()> {
        if other.bits != self.bits {
            return Err(Error::internal("bitset universe mismatch"));
        }
        for i in 0..self.words.len() {
            let o = *other.words.get(i).ok_or(Error::internal("bit word"))?;
            *self.words.get_mut(i).ok_or(Error::internal("bit word"))? = o;
        }
        Ok(())
    }

    pub fn count(&self) -> usize {
        self.words.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// Indices of set bits, ascending.
    pub fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        self.words.iter().enumerate().flat_map(|(wi, &w)| {
            let mut w = w;
            core::iter::from_fn(move || {
                if w == 0 {
                    return None;
                }
                let b = w.trailing_zeros() as usize;
                w &= w - 1;
                Some(wi * 64 + b)
            })
        })
    }
}

impl fmt::Debug for BitSet<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

/// A set over `0..universe` with O(1) insert, remove, membership and clear.
pub struct SparseSet<'h> {
    sparse: ChunkVec<'h, u32>,
    dense: ChunkVec<'h, u32>,
}

impl<'h> SparseSet<'h> {
    pub fn new(heap: &'h Heap<'h>, universe: usize) -> Result<Self> {
        if u32::try_from(universe).is_err() {
            return Err(Error::limit("sparse set universe"));
        }
        Ok(SparseSet {
            sparse: ChunkVec::filled(heap, universe, 0)?,
            dense: ChunkVec::new(heap),
        })
    }

    pub fn len(&self) -> usize {
        self.dense.len()
    }

    pub fn is_empty(&self) -> bool {
        self.dense.is_empty()
    }

    pub fn contains(&self, v: u32) -> bool {
        match self.sparse.get(v as usize) {
            Some(&slot) => self.dense.get(slot as usize) == Some(&v),
            None => false,
        }
    }

    /// Returns true if newly inserted.
    pub fn insert(&mut self, v: u32) -> Result<bool> {
        if self.contains(v) {
            return Ok(false);
        }
        let slot = self.dense.len() as u32;
        *self
            .sparse
            .get_mut(v as usize)
            .ok_or(Error::internal("sparse set value out of range"))? = slot;
        self.dense.push(v)?;
        Ok(true)
    }

    /// Returns true if it was present.
    pub fn remove(&mut self, v: u32) -> bool {
        if !self.contains(v) {
            return false;
        }
        let Some(&slot) = self.sparse.get(v as usize) else {
            return false;
        };
        let Some(last) = self.dense.pop() else {
            return false;
        };
        if last != v {
            if let Some(d) = self.dense.get_mut(slot as usize) {
                *d = last;
            }
            if let Some(s) = self.sparse.get_mut(last as usize) {
                *s = slot;
            }
        }
        true
    }

    pub fn clear(&mut self) {
        self.dense.clear();
    }

    /// Members in insertion order (disturbed by removals).
    pub fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        self.dense.iter().copied()
    }
}

impl fmt::Debug for SparseSet<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::test_support::TestHost;

    #[test]
    fn bitset_ops() {
        let host = TestHost::default();
        let heap = Heap::new(&host, 1 << 22);
        let mut a = BitSet::new(&heap, 1000).unwrap();
        let mut b = BitSet::new(&heap, 1000).unwrap();
        assert!(a.insert(3).unwrap());
        assert!(!a.insert(3).unwrap());
        a.insert(999).unwrap();
        b.insert(3).unwrap();
        b.insert(64).unwrap();
        assert!(a.insert(1000).is_err());
        assert!(a.union_with(&b).unwrap());
        assert_eq!(a.iter().collect::<std::vec::Vec<_>>(), [3, 64, 999]);
        assert!(a.intersect_with(&b).unwrap());
        assert_eq!(a.iter().collect::<std::vec::Vec<_>>(), [3, 64]);
        assert_eq!(a.count(), 2);
        assert!(a.remove(3).unwrap());
        assert!(!a.contains(3));
    }

    #[test]
    fn sparse_set_ops() {
        let host = TestHost::default();
        let heap = Heap::new(&host, 1 << 22);
        let mut s = SparseSet::new(&heap, 100).unwrap();
        assert!(s.insert(5).unwrap());
        assert!(s.insert(7).unwrap());
        assert!(!s.insert(5).unwrap());
        assert!(s.remove(5));
        assert!(!s.contains(5));
        assert!(s.contains(7));
        assert!(s.insert(100).is_err());
        s.clear();
        assert!(s.is_empty());
        assert!(!s.contains(7));
    }
}
