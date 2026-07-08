//! NDN dataset synchronisation: SVS (State Vector Sync) and PSync
//! (IBF-based).
//!
//! SVS is layered after ndn-svs's `SVSyncCore` → `SVSync` split, keeping
//! the transport-agnostic `mpsc<Bytes>` boundary throughout (so the same
//! protocol code runs natively, in the browser, and in a simulator):
//!
//! * **Layer 0 — notification core** ([`svs_sync`]): multicasts the state
//!   vector in a Sync Interest whose name and codec are chosen by the
//!   [`dialect`] ([`WireDialect::V2`] = ndn-svs `<group>/v=2`,
//!   [`WireDialect::V3`] = ndnd `<group>/v=3` with boot timestamps),
//!   merges received vectors with a boot-aware comparison, and runs the
//!   two-state suppression FSM (steady periodic ⇄ reply-to-stale). Sync
//!   Interests are authenticated through the [`security`]
//!   [`SyncSigner`]/[`SyncValidator`] traits (HMAC group key or `Insecure`).
//! * **Layer 1 — data plane** ([`svsync`]): adds a [`DataStore`],
//!   canonical [`svs_data_name`] naming, [`SvSync::publish_data`]
//!   (name→sign→store→advance), an Interest responder for the node's own
//!   data prefix, and a windowed [`SvSync::fetch_range`] pipeline.
//!
//! Pure data structures live in [`svs`] / [`psync`] / [`svs_local`] (the
//! SVS v3 boot-timestamp dialect); shared TLV/NNI codec in `tlv`.
//!
//! [`WireDialect::V2`]: dialect::WireDialect::V2
//! [`WireDialect::V3`]: dialect::WireDialect::V3
//! [`SyncSigner`]: security::SyncSigner
//! [`SyncValidator`]: security::SyncValidator
//! [`DataStore`]: svsync::DataStore
//! [`svs_data_name`]: svsync::svs_data_name
//! [`SvSync::publish_data`]: svsync::SvSync::publish_data
//! [`SvSync::fetch_range`]: svsync::SvSync::fetch_range

#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(missing_docs)]

/// MurmurHash3_x86_32 — the hash family used by PSync's IBF.
pub mod murmur3;

/// Runtime-portable spawn/sleep/Instant for the driver loops (native + wasm32).
mod rt;

/// Shared TLV / NonNegativeInteger codec for the SVS dialects.
mod tlv;

/// Shared segmented transfer (chunk/finalize + windowed fetch) for SVS
/// and PSync.
pub mod transfer;

/// SVS wire-dialect selector (v2 / v3) + unified state-vector codec.
pub mod dialect;

/// Sync-Interest authentication: signer/validator traits + HMAC.
pub mod security;

/// SVS-PS mapping provider: seq→name table, query, and piggyback codec.
pub mod mapping;

pub mod protocol;

pub mod svs;

/// SVS v3 self-only variant for the ndn-dv Advertisement Broadcast
/// pattern (`~/Documents/Dev/ndnd/dv/SPEC.md` §4): self-only outgoing
/// state vector, per-neighbor seq tracking, advance detection.
pub mod svs_local;

pub mod svs_sync;

/// Layer 1 — `SvSync` data plane (DataStore + publish/fetch/serve) on
/// top of the [`svs_sync`] notification core.
pub mod svsync;

/// Layer 2 — `SvsPubSub`: named publications + prefix subscriptions with
/// mapping-based name resolution, on top of [`svsync`].
pub mod pubsub;

/// Persistent [`svsync::DataStore`] over `ndn-storage`'s synchronous
/// `SyncBackend` (fjall / redb / in-memory). Feature `persistent-store`.
#[cfg(feature = "persistent-store")]
#[cfg_attr(docsrs, doc(cfg(feature = "persistent-store")))]
pub mod store;

pub mod psync;

pub mod psync_sync;

/// Bloom filter wire-compatible with `PSync/detail/bloom-filter.cpp`,
/// for Partial Sync subscription sets.
pub mod psync_bloom;

/// PSync Partial Sync: asymmetric `PartialProducer` + Bloom-filter
/// subscription consumer.
pub mod psync_partial;

pub use dialect::WireDialect;
pub use mapping::{MappingList, MappingProvider};
pub use protocol::{SyncError, SyncHandle, SyncUpdate};
pub use psync_bloom::{BloomError, BloomFilter};
pub use psync_partial::{
    PSyncPartialConfig, join_psync_partial_consumer, join_psync_partial_producer,
};
pub use psync_sync::{PSyncConfig, PSyncInbound, join_psync_group};
pub use pubsub::{Publication, SvsPubSub};
pub use security::{HmacKey, Insecure, Rejected, SyncSigner, SyncValidator};
pub use svs_local::{
    NeighborAdvance, NeighborSnapshot, StateEntry, SvsLocal, SvsLocalError, decode_svs_data,
    encode_svs_data,
};
pub use svs_sync::{RetryPolicy, SvsConfig, fetch_with_retry, join_svs_group};
pub use svsync::{
    DataStore, IngestValidator, MemoryStore, PublisherSigner, SvSync, SvSyncConfig, svs_data_name,
};
#[cfg(feature = "persistent-store")]
pub use store::BackendStore;
