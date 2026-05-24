//! NDN dataset synchronisation: SVS (State Vector Sync) and PSync
//! (IBF-based). Pure data structures in [`svs`] / [`psync`] /
//! [`svs_local`]; network protocols in [`svs_sync`] / [`psync_sync`].

#![allow(missing_docs)]

/// MurmurHash3_x86_32 — the hash family used by PSync's IBF.
pub mod murmur3;

/// Runtime-portable spawn/sleep/Instant for the driver loops (native + wasm32).
mod rt;

pub mod protocol;

pub mod svs;

/// SVS v3 self-only variant for the ndn-dv Advertisement Broadcast
/// pattern (`~/Documents/Dev/ndnd/dv/SPEC.md` §4): self-only outgoing
/// state vector, per-neighbor seq tracking, advance detection.
pub mod svs_local;

pub mod svs_sync;

pub mod psync;

pub mod psync_sync;

pub use protocol::{SyncError, SyncHandle, SyncUpdate};
pub use psync_sync::{PSyncConfig, PSyncInbound, join_psync_group};
pub use svs_local::{
    NeighborAdvance, NeighborSnapshot, StateEntry, SvsLocal, SvsLocalError, decode_svs_data,
    encode_svs_data,
};
pub use svs_sync::{RetryPolicy, SvsConfig, fetch_with_retry, join_svs_group};
