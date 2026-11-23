//! Revocation cuts and suspicion (spec §9).
//!
//! Under construction: the module lands behind its `wip-revocation` feature.

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "revocation_tests.rs"]
mod tests;
