//! Layer: spec — canonical, runtime-agnostic forwarding rules.
//!
//! `ndn-fwd-core` is the **sans-IO seed** of the forwarder: the forwarding
//! *rules* with no I/O, no async, no allocator, and no opinion about how the
//! tables are stored. The native [`ndn-engine`] (async, `tokio`, `DashMap`)
//! and the bare-metal [`ndn-embedded`] forwarder (sync, `heapless`) keep their
//! own table containers but call into the rules here, so a rule lives exactly
//! once instead of being re-implemented — and drifting — on each side.
//!
//! This first slice holds the two genuinely-shared, container-independent
//! decisions:
//!
//! - [`lpm`] — the FIB longest-prefix-match *selection* rule. The native trie
//!   and the constrained linear table are different containers; both are
//!   pinned to this one selection rule (longest wins, length-guarded).
//! - [`freshness`] — the Content Store freshness predicate, in both the
//!   absolute-deadline form the native CS uses and the wrapping relative-period
//!   form the constrained CS uses, so the comparison (and its wrap correctness)
//!   is defined once.
//!
//! Deliberately **not** here: anything that does I/O, anything async, and any
//! `tracing` spans — instrumentation belongs in the adopting I/O layer, not in
//! these pure functions. The forwarding *pipeline* state machine
//! (`ingest(...) -> actions`) is the intended next tenant; see
//! `.claude/notes/embedded-ndn-modular-build-2026-05-22.md` § 2.

#![no_std]
#![forbid(unsafe_code)]

pub mod conformance;
pub mod freshness;
pub mod lpm;
pub mod pipeline;
pub mod store;
pub mod strategy;
