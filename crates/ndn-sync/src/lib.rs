//! NDN dataset synchronisation: SVS (State Vector Sync) and PSync
//! (IBF-based).
//!
//! SVS is layered after ndn-svs's `SVSyncCore` → `SVSync` split, keeping
//! the transport-agnostic `mpsc<Bytes>` boundary throughout (so the same
//! protocol code runs natively, in the browser, and in a simulator):
//!
//! * **Layer 0 — notification core** ([`svs_sync`]): multicasts the state
//!   vector in a Sync Interest named `<group>/v=2` (ndn-svs wire-compatible),
//!   merges received vectors, and runs the two-state suppression FSM
//!   (steady periodic ⇄ reply-to-stale). Sync Interests are authenticated
//!   through the [`security`] [`SyncSigner`]/[`SyncValidator`] traits
//!   (HMAC group key or `Insecure`).
//! * **Layer 1 — data plane** ([`svsync`]): adds a [`DataStore`],
//!   canonical [`svs_data_name`] naming, [`SvSync::publish_data`]
//!   (name→sign→store→advance), an Interest responder for the node's own
//!   data prefix, and a windowed [`SvSync::fetch_range`] pipeline.
//!
//! Pure data structures live in [`svs`] / [`psync`] / [`svs_local`] (the
//! SVS v3 boot-timestamp dialect); shared TLV/NNI codec in `tlv`.
//!
//! [`SyncSigner`]: security::SyncSigner
//! [`SyncValidator`]: security::SyncValidator
//! [`DataStore`]: svsync::DataStore
//! [`svs_data_name`]: svsync::svs_data_name
//! [`SvSync::publish_data`]: svsync::SvSync::publish_data
//! [`SvSync::fetch_range`]: svsync::SvSync::fetch_range

#![allow(missing_docs)]

/// MurmurHash3_x86_32 — the hash family used by PSync's IBF.
pub mod murmur3;

/// Runtime-portable spawn/sleep/Instant for the driver loops (native + wasm32).
mod rt;

/// Shared TLV / NonNegativeInteger codec for the SVS dialects.
mod tlv;

/// Sync-Interest authentication: signer/validator traits + HMAC.
pub mod security;

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

pub mod psync;

pub mod psync_sync;

pub use protocol::{SyncError, SyncHandle, SyncUpdate};
pub use security::{HmacKey, Insecure, Rejected, SyncSigner, SyncValidator};
pub use psync_sync::{PSyncConfig, PSyncInbound, join_psync_group};
pub use svs_local::{
    NeighborAdvance, NeighborSnapshot, StateEntry, SvsLocal, SvsLocalError, decode_svs_data,
    encode_svs_data,
};
pub use svs_sync::{RetryPolicy, SvsConfig, fetch_with_retry, join_svs_group};
pub use svsync::{DataStore, MemoryStore, SvSync, SvSyncConfig, svs_data_name};
