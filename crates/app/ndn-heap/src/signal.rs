//! The signal gate for ndn-surface (spec §11).
//!
//! Under construction: the module lands behind its `wip-signal` feature.

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "signal_tests.rs"]
mod tests;
