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

#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(missing_docs)]

// `EngineBuilder` pulls `SecurityProfile` / `TrustSchema` / `CertCache` from
// `ndn-security`, which doesn't build for wasm32 (ring + libsqlite3-sys).
// `WasmEngineBuilder` is the wasm-side analog with `ValidationStage` stubbed
// permissively.
pub mod activity;
#[cfg(not(target_arch = "wasm32"))]
pub mod builder;
pub mod compose;
pub mod discovery_context;
pub mod dispatcher;
pub mod egress;
pub mod engine;
pub mod enricher;
pub mod expiry;
pub mod fib;
#[cfg(not(target_arch = "wasm32"))]
pub mod installable;
pub mod observability;
pub mod path_control;
pub mod pipeline;
pub mod rate_limit_hook;
pub mod readvertise;
pub mod reflexive;
pub mod replay_guard_config;
pub mod rib;
pub mod routing;
#[cfg(not(target_arch = "wasm32"))]
pub mod signals_driver;
pub mod stages;
pub mod traceroute;
pub mod unsolicited;
#[cfg(target_arch = "wasm32")]
pub mod wasm_builder;

pub use activity::NameActivityObserver;
#[cfg(not(target_arch = "wasm32"))]
pub use builder::{EngineBuilder, EngineConfig};
pub use compose::ComposedStrategy;
pub use discovery_context::EngineDiscoveryContext;
pub use dispatcher::DataPlane;
pub use egress::{
    DeficitRoundRobinScheduler, EgressClassifier, EgressScheduler, EgressSchedulerFactory,
    PrefixClassifier, PriorityScheduler, TrafficClass,
};
pub use engine::{FaceCounters, FaceState, ForwarderEngine, ShutdownHandle};
pub use traceroute::TracerouteResponder;
// Cross-layer signal access for callers of `ForwarderEngine::signals()` /
// `EngineBuilder::signals()` — the traits needed to read/write the store.
pub use enricher::ContextEnricher;
pub use fib::{Fib, FibEntry, FibNexthop};
#[cfg(not(target_arch = "wasm32"))]
pub use installable::{InstallableProtocol, PostBuildQueue};
pub use ndn_runtime::{Runtime, Spawn};
pub use ndn_strategy::{LinkSignals, SignalStore, SignalView, SignalsTable};
pub use path_control::{
    PathAuthorizer, PathControlHandler, PathControlObserver, ValidatorAuthorizer,
};
pub use readvertise::{ReadvertiseDestination, ReadvertisedPrefixes, should_readvertise};
pub use replay_guard_config::ReplayGuardConfig;
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
