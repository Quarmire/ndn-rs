//! Forwarding tables and content storage: FIB, PIT, Content Store, strategy
//! table. All tables are designed for concurrent access on the
//! packet-processing hot path.
//!
//! Key types: [`NameTrie`], [`Fib`], [`Pit`], [`ContentStore`] trait,
//! [`LruCs`], [`ShardedCs`], [`FjallCs`] (`fjall` feature), `SqliteCs`
//! (`sqlite-cs` feature — the Android persistent backend), [`NullCs`],
//! [`ObservableCs`], [`StrategyTable`], [`CsAdmissionPolicy`].

#![allow(missing_docs)]

pub mod content_store;
// Shared key/value codec for the disk-backed stores (fjall + sqlite).
#[cfg(any(feature = "fjall", feature = "sqlite-cs", test))]
pub(crate) mod cs_keycodec;
pub mod dead_nonce_list;
pub mod fib;
#[cfg(any(feature = "fjall", test))]
pub mod fjall_cs;
pub mod lru_cs;
pub mod observable_cs;
pub mod pit;
pub mod sharded_cs;
#[cfg(feature = "sqlite-cs")]
pub mod sqlite_cs;
pub mod strategy_table;
pub mod trie;

pub use content_store::{
    AdmitAllPolicy, ContentStore, CsAdmissionPolicy, CsCapacity, CsEntry, CsMeta, CsStats,
    DefaultAdmissionPolicy, ErasedContentStore, InsertResult, NullCs,
};
pub use dead_nonce_list::{DEFAULT_DEAD_NONCE_LIFETIME, DeadNonceList, NonceFingerprint};
pub use fib::{Fib, FibEntry, FibNexthop};
#[cfg(any(feature = "fjall", test))]
pub use fjall_cs::FjallCs;
pub use lru_cs::LruCs;
pub use observable_cs::{CsEvent, CsObserver, ObservableCs};
pub use pit::{
    InRecord, NameHashes, OutRecord, PersistentState, Pit, PitEntry, PitKeyDiscriminator, PitToken,
};
pub use sharded_cs::ShardedCs;
#[cfg(feature = "sqlite-cs")]
pub use sqlite_cs::SqliteCs;
pub use strategy_table::StrategyTable;
pub use trie::NameTrie;
