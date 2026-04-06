//! # ndn-store -- Forwarding tables and content storage
//!
//! Implements the core forwarding-plane data structures: FIB, PIT, Content
//! Store, and strategy table. All tables are designed for concurrent access
//! (using `DashMap` or sharding) on the packet-processing hot path.
//!
//! ## Key types
//!
//! - [`NameTrie`] -- generic name-prefix trie used by FIB and strategy table.
//! - [`Fib`] / [`FibEntry`] -- Forwarding Information Base (longest-prefix match).
//! - [`Pit`] / [`PitEntry`] -- Pending Interest Table with in/out records.
//! - [`ContentStore`] trait -- pluggable cache interface.
//! - [`LruCs`] -- single-threaded LRU content store.
//! - [`ShardedCs`] -- sharded wrapper for concurrent CS access.
//! - [`FjallCs`] -- persistent on-disk content store (requires `fjall` feature).
//! - [`NullCs`] -- no-op store for testing or cache-less operation.
//! - [`ObservableCs`] -- decorator that emits [`CsEvent`]s on insert/evict.
//! - [`StrategyTable`] -- prefix-to-strategy mapping.
//! - [`CsAdmissionPolicy`] -- trait controlling which Data packets are cached.
//!
//! ## Feature flags
//!
//! - **`fjall`** -- enables [`FjallCs`], the persistent content store backend.

#![allow(missing_docs)]

pub mod content_store;
pub mod fib;
#[cfg(any(feature = "fjall", test))]
pub mod fjall_cs;
pub mod lru_cs;
pub mod observable_cs;
pub mod pit;
pub mod sharded_cs;
pub mod strategy_table;
pub mod trie;

pub use content_store::{
    AdmitAllPolicy, ContentStore, CsAdmissionPolicy, CsCapacity, CsEntry, CsMeta, CsStats,
    DefaultAdmissionPolicy, ErasedContentStore, InsertResult, NullCs,
};
pub use fib::{Fib, FibEntry, FibNexthop};
#[cfg(any(feature = "fjall", test))]
pub use fjall_cs::FjallCs;
pub use lru_cs::LruCs;
pub use observable_cs::{CsEvent, CsObserver, ObservableCs};
pub use pit::{InRecord, OutRecord, Pit, PitEntry, PitToken};
pub use sharded_cs::ShardedCs;
pub use strategy_table::StrategyTable;
pub use trie::NameTrie;
