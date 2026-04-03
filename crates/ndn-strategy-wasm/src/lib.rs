//! # ndn-strategy-wasm — Hot-loadable WASM strategies
//!
//! Runs user-supplied forwarding strategies as WebAssembly modules via
//! [`wasmtime`]. Each [`WasmStrategy`] instance loads a `.wasm` binary,
//! exposes a host ABI for FIB/measurements queries, and executes the
//! guest `select_nexthops` entry point inside a fuel-limited sandbox.
//!
//! This allows deploying new strategies at runtime without recompiling
//! or restarting the forwarder.

mod host;
mod wasm_strategy;

pub use wasm_strategy::WasmStrategy;
