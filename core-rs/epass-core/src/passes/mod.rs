//! Built-in passes. Each module exports an `INFO` descriptor for the
//! registry in [`crate::pm`].

pub mod const_prop;
pub mod dce;
pub mod dump_ir;
pub mod lower_throw;
pub mod phi;
pub mod zext_elim;
