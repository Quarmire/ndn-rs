//! The data layer: one hash-chained log per (writer, space), membership as
//! an operation fold in which removal wins, epoch keys delivered by a grant
//! pull, the entry a sync notice names fetched directly, one newest-wins
//! register, and durability by sequence reservation. The normative text,
//! wire format included, is `ndn-rs/docs/specs/heap.md`.
//!
//! Under construction (Stage 3 of the re-founding): modules land one at a
//! time behind a `wip-<module>` feature; the public API is exported when the
//! last of them has.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]
// Until the API module wires everything together, items are used only by
// their own tests. Removed when the stage ends.
#![allow(dead_code, unused_imports)]

mod rt;
mod wire;

mod error;
#[cfg(feature = "wip-face-up")]
mod face_up;
#[cfg(feature = "wip-fetch")]
mod fetch;
mod fold;
mod heard;
#[cfg(feature = "wip-log")]
mod log;
#[cfg(feature = "wip-node")]
mod node;
mod pieces;
mod register;
mod reserve;
#[cfg(feature = "wip-revocation")]
mod revocation;
mod seal;
#[cfg(feature = "wip-serve")]
mod serve;
#[cfg(feature = "wip-signal")]
mod signal;
#[cfg(feature = "wip-space")]
mod space;
mod store;
#[cfg(feature = "wip-sync")]
mod sync;
#[cfg(test)]
mod test_kit;
mod trust;
