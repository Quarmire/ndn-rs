//! The data layer's bytes: the names it publishes under and the TLV records
//! its Data packets carry (`docs/specs/heap.md`, §2 and §3).
//!
//! The shapes of an entry are [`types`]; [`names`] are the packets' names and
//! the keyword router, [`digest`] the two digests, [`pieces`] the shape of a
//! large value's pieces, [`codec`] the entry, grant, seal-key and manifest
//! records, [`tlv`] the TLV-TYPE registry (0x0600–0x063F, odd critical, even
//! skippable).

mod codec;
mod digest;
mod names;
mod pieces;
mod prim;
pub(crate) mod tlv;
mod types;

pub(crate) use codec::*;
pub(crate) use digest::*;
pub(crate) use names::*;
pub(crate) use pieces::*;
pub(crate) use prim::{WireError, each, once, read_name};
pub(crate) use types::*;

#[cfg(test)]
mod codec_tests;
#[cfg(test)]
mod names_tests;
