//! The data layer's bytes: the names it publishes under and the TLV records
//! its Data packets carry (`docs/specs/heap.md`, §2 and §3).
//!
//! Under construction: the shapes are in [`types`], the names, digests,
//! pieces and the TLV registry are in; the entry codec lands with its tests.

mod digest;
mod names;
mod pieces;
mod prim;
pub(crate) mod tlv;
mod types;

#[cfg(feature = "wip-wire")]
mod codec;

pub(crate) use digest::*;
pub(crate) use names::*;
pub(crate) use pieces::*;
pub(crate) use prim::WireError;
pub(crate) use types::*;

#[cfg(feature = "wip-wire")]
pub(crate) use codec::*;

#[cfg(test)]
mod names_tests;
#[cfg(all(test, feature = "wip-wire"))]
mod codec_tests;
