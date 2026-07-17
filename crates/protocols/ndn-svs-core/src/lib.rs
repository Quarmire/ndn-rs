//! no_std **State Vector Sync core** — the pure logic under ndn-sync's SVS.
//!
//! A state vector is a `NodeID → (boot, seq)` map plus a handful of integer
//! rules (advance, boot-aware merge, gap detection, security clamps) and the
//! SVS v3 wire codec. None of that needs an executor, a lock, or an allocator
//! beyond `alloc`: the collection is an [`alloc::collections::BTreeMap`] and
//! every method is synchronous. That is exactly what a constrained device needs
//! to compute and advance its own state vector.
//!
//! ndn-sync historically fused this logic to std/tokio (a `std::HashMap` behind
//! a `tokio::sync::RwLock`, `async` methods that only awaited the lock). This
//! crate is the extracted core; ndn-sync re-wraps [`SvsCore`] in a
//! `tokio::sync::RwLock` to recover its async API byte-for-byte, and re-wraps
//! the codec's [`SvsLocal`](../ndn_sync/svs_local/struct.SvsLocal.html) around
//! [`NeighborSeqState`] to keep its std lock. Same logic, two bindings.
//!
//! ## Layout
//! * [`tlv`] — NDN NonNegativeInteger + byte-cursor TLV helpers (the shared
//!   codec primitives every SVS dialect walks).
//! * [`codec`] — SVS v3 wire codec: [`StateEntry`], [`encode_svs_data`],
//!   [`decode_svs_data`], the [`SvsLocalError`] type, and the pure
//!   [`NeighborSeqState`] transition used by the self-only local variant.
//! * [`core`] — [`SvsCore`], the synchronous state-vector node: `advance`,
//!   the boot-aware `merge` / `merge_deferred`, `ack`, `snapshot`.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(missing_docs)]

extern crate alloc;

pub mod tlv;

pub mod codec;

pub mod core;

pub use codec::{
    NeighborAdvance, NeighborSeqState, NeighborSnapshot, StateEntry, SvsLocalError,
    decode_svs_data, encode_svs_data,
};
pub use core::{MAX_GAP_SPAN, MAX_TRACKED_PRODUCERS, StateVectorEntry, SvsCore};
