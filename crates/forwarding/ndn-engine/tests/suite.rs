//! Single consolidated integration-test binary (P1 compile-cost work).
//!
//! `autotests = false` in Cargo.toml routes every `tests/*.rs` file through
//! this one `[[test]]` target, so the crate links ONE test binary instead of
//! seventeen. The per-topic files stay in place as modules; add a new
//! `#[path]` line here when adding a test file.
//!
//! Feature gating is unchanged: `partitioned_parity` and
//! `partition_throughput` carry `#![cfg(feature = "partitioned-fwd")]` inner
//! attributes, which empty those modules unless the feature is on.

#[path = "broadcast_data_parity.rs"]
mod broadcast_data_parity;
#[path = "congestion_feedback.rs"]
mod congestion_feedback;
#[path = "egress_scheduler.rs"]
mod egress_scheduler;
#[path = "face_factory.rs"]
mod face_factory;
#[path = "fib_shadow_diagnostic.rs"]
mod fib_shadow_diagnostic;
#[path = "forwarding_conformance.rs"]
mod forwarding_conformance;
#[path = "forwarding_hint.rs"]
mod forwarding_hint;
#[path = "incoming_face_id_local_fields.rs"]
mod incoming_face_id_local_fields;
#[path = "local_data_validation.rs"]
mod local_data_validation;
#[path = "nack_counters.rs"]
mod nack_counters;
#[path = "next_hop_face_id_local_fields.rs"]
mod next_hop_face_id_local_fields;
#[path = "partition_throughput.rs"]
mod partition_throughput;
#[path = "partitioned_parity.rs"]
mod partitioned_parity;
#[path = "path_control.rs"]
mod path_control;
#[path = "pit_fan_out_witness.rs"]
mod pit_fan_out_witness;
#[path = "self_learning.rs"]
mod self_learning;
#[path = "traceroute_responder.rs"]
mod traceroute_responder;
