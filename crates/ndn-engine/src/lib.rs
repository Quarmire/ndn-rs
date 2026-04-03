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

pub mod builder;
pub mod compose;
pub mod dispatcher;
pub mod engine;
pub mod enricher;
pub mod expiry;
pub mod fib;
pub mod stages;

pub use builder::{EngineBuilder, EngineConfig};
pub use compose::ComposedStrategy;
pub use engine::{ForwarderEngine, ShutdownHandle};
pub use enricher::ContextEnricher;
pub use fib::{Fib, FibEntry, FibNexthop};
