//! `targets` is the canonical tracing-target taxonomy every call site in
//! the workspace uses (also exposed via `ndn-fwd --modules`).
//!
//! `fan_out` is the hook the PIT-satisfy path calls to emit one span per
//! aggregated consumer trace_id, keeping ndn-engine free of an
//! observability-crate dependency.
pub mod fan_out;
#[cfg_attr(not(feature = "experimental-instrument"), doc(hidden))]
pub mod targets;
