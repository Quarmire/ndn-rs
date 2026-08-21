//! Single consolidated integration-test binary (P1 compile-cost work).
//!
//! `autotests = false` in Cargo.toml routes every `tests/*.rs` file through
//! this one `[[test]]` target, so the crate links ONE test binary instead of
//! thirteen. The per-topic files stay in place as modules; add a new
//! `#[path]` line here when adding a test file.
//!
//! Platform gating is unchanged: `ipc_seam` carries a `#![cfg(unix)]` inner
//! attribute, which empties that module on non-unix targets.

#[path = "cs_erase.rs"]
mod cs_erase;
#[path = "extra_modules.rs"]
mod extra_modules;
#[path = "face_lifecycle_sink_publishes.rs"]
mod face_lifecycle_sink_publishes;
#[path = "face_notification_semantic_events.rs"]
mod face_notification_semantic_events;
#[path = "faces_create_idempotent.rs"]
mod faces_create_idempotent;
#[path = "faces_update_tier2.rs"]
mod faces_update_tier2;
#[path = "ipc_seam.rs"]
mod ipc_seam;
#[path = "ndnsd_adapter.rs"]
mod ndnsd_adapter;
#[path = "notifications.rs"]
mod notifications;
#[path = "security_safebag_import.rs"]
mod security_safebag_import;
#[path = "security_v1_verbs.rs"]
mod security_v1_verbs;
#[path = "status_bridge.rs"]
mod status_bridge;
#[path = "web_wire_e2e.rs"]
mod web_wire_e2e;
