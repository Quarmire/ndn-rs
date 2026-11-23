//! The validator bridge and the adoption of persons per space (spec §9).
//!
//! Under construction: the module lands behind its `wip-trust` feature.

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "trust_tests.rs"]
mod tests;
