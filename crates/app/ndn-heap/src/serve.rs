//! Serving entries, held copies, seal keys and grants (spec §7).
//!
//! Under construction: the module lands behind its `wip-serve` feature.

use std::sync::Arc;

use ndn_packet::Data;

#[cfg(test)]
#[path = "serve_tests.rs"]
mod tests;
