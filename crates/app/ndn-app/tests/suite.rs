//! Single consolidated integration-test binary (P1 compile-cost work).
//!
//! `autotests = false` in Cargo.toml routes every `tests/*.rs` file through
//! this one `[[test]]` target, so the crate links ONE test binary instead of
//! eleven. The per-topic files stay in place as modules; add a new
//! `#[path]` line here when adding a test file.
//!
//! The three `#[ignore]`d throughput measurements in `local_throughput` are
//! unchanged — run them explicitly:
//!   cargo test -p ndn-app --release --test suite -- --ignored local_throughput --nocapture

#[path = "demux.rs"]
mod demux;
#[path = "detached_engine.rs"]
mod detached_engine;
#[path = "embedded.rs"]
mod embedded;
#[path = "local_throughput.rs"]
mod local_throughput;
#[path = "node.rs"]
mod node;
#[path = "rdr_manifest.rs"]
mod rdr_manifest;
#[path = "rdr_round_trip.rs"]
mod rdr_round_trip;
#[path = "rdr_verified.rs"]
mod rdr_verified;
#[path = "reflexive.rs"]
mod reflexive;
#[path = "secure_fetch.rs"]
mod secure_fetch;
#[path = "serve_latest.rs"]
mod serve_latest;
