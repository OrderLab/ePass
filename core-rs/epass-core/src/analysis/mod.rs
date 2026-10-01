//! Analyses. Each is a side table computed on demand; none is stored in the
//! IR, so passes never have to keep them up to date.

pub mod dom;
pub mod facts;

pub use dom::{Cfg, DomTree};
pub use facts::{frame_extent, Class, ClassFact, Classes, Extent, Provenance, StackFact, UpperZero};
