//! The data layer's bytes: the names it publishes under and the TLV records
//! its Data packets carry (`docs/specs/heap.md`, §2 and §3).
//!
//! Under construction: the shapes are in [`types`]; the codec, the names and
//! the digests land with the module's tests.

mod types;
pub(crate) use types::*;
