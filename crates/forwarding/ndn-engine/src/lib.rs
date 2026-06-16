//! # ndn-engine — Forwarder engine and pipeline wiring
//!
//! Assembles the full NDN forwarding plane from pipeline stages, faces,
//! and tables.
//!
//! - [`EngineBuilder`] / [`EngineConfig`] — configure faces, strategies,
//!   and content-store backends before starting the engine.
//! - [`ForwarderEngine`] — owns the FIB, PIT, CS, face table, and the
//!   Tokio task set that drives packet processing.
//! - [`ComposedStrategy`] / [`ContextEnricher`] — adapt and compose
//!   strategy implementations with cross-layer enrichment.
//! - [`ShutdownHandle`] — cooperative shutdown of all engine tasks.

#![allow(missing_docs)]

// `EngineBuilder` pulls `SecurityProfile` / `TrustSchema` / `CertCache` from
// `ndn-security`, which doesn't build for wasm32 (ring + libsqlite3-sys).
// `WasmEngineBuilder` is the wasm-side analog with `ValidationStage` stubbed
// permissively.
#[cfg(not(target_arch = "wasm32"))]
pub mod builder;
pub mod compose;
pub mod discovery_context;
pub mod dispatcher;
pub mod engine;
pub mod enricher;
pub mod expiry;
pub mod fib;
#[cfg(not(target_arch = "wasm32"))]
pub mod installable;
pub mod observability;
pub mod pipeline;
pub mod rate_limit_hook;
pub mod reflexive;
pub mod replay_guard_config;
pub mod readvertise;
pub mod rib;
pub mod routing;
#[cfg(not(target_arch = "wasm32"))]
pub mod signals_driver;
pub mod stages;
pub mod unsolicited;
#[cfg(target_arch = "wasm32")]
pub mod wasm_builder;

#[cfg(not(target_arch = "wasm32"))]
pub use builder::{EngineBuilder, EngineConfig};
pub use compose::ComposedStrategy;
pub use discovery_context::EngineDiscoveryContext;
pub use dispatcher::DataPlane;
pub use engine::{FaceCounters, FaceState, ForwarderEngine, ShutdownHandle};
// Cross-layer signal access for callers of `ForwarderEngine::signals()` /
// `EngineBuilder::signals()` — the traits needed to read/write the store.
pub use ndn_strategy::{LinkSignals, SignalStore, SignalView, SignalsTable};
pub use ndn_runtime::{Runtime, Spawn};
pub use enricher::ContextEnricher;
pub use fib::{Fib, FibEntry, FibNexthop};
#[cfg(not(target_arch = "wasm32"))]
pub use installable::{InstallableProtocol, PostBuildQueue};
pub use replay_guard_config::ReplayGuardConfig;
pub use readvertise::{ReadvertiseDestination, ReadvertisedPrefixes, should_readvertise};
pub use rib::{Rib, RibRoute};
pub use routing::{
    ConfigError, ConfigUpdate, LsdbEntry, NeighborInfo, RoutingHandle, RoutingManager,
    RoutingProtocol, RoutingProtocolStatus,
};
#[cfg(target_arch = "wasm32")]
pub use wasm_builder::{WasmEngineBuilder, WasmEngineConfig};

pub use pipeline::{
    Action, AnyMap, DecodedPacket, DropReason, ForwardingAction, NackReason, PacketContext,
    PipelineStage,
};
pub use rate_limit_hook::{Decision, PacketKind, RateLimitHook, SharedRateLimitHook};
pub use reflexive::{ReflexiveConfig, ReflexiveStatus, ReflexiveTable};
pub use unsolicited::UnsolicitedDataPolicy;
