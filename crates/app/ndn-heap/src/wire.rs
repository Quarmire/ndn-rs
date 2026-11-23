//! The data layer's bytes: the names it publishes under and the TLV records
//! its Data packets carry (`docs/specs/heap.md`, §2 and §3).
//!
//! Under construction: the shapes are in [`types`]; the codec, the names and
//! the digests land with the module's tests.

mod types;
pub(crate) use types::*;

#[cfg(feature = "wip-wire")]
mod prim;
#[cfg(feature = "wip-wire")]
pub(crate) mod tlv;
#[cfg(feature = "wip-wire")]
mod names;
#[cfg(feature = "wip-wire")]
mod digest;
#[cfg(feature = "wip-wire")]
mod pieces;
#[cfg(feature = "wip-wire")]
mod codec;
#[cfg(feature = "wip-wire")]
pub(crate) use {codec::*, digest::*, names::*, pieces::*, prim::WireError};

#[cfg(all(test, feature = "wip-wire"))]
mod names_tests;
#[cfg(all(test, feature = "wip-wire"))]
mod codec_tests;
