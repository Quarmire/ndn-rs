//! ndn-bench — the Capstan bench, finally scheduled (ndf-the-gauntlet: "the
//! harness itself ships as a living conformance surface").
//!
//! Library face of the tool crate: the script front-end, the compiler, the
//! lints, the doc-card renderer, the vector runner, and the freeze. The
//! binary in `main.rs` is a thin CLI over these.

pub mod compile;
pub mod doccard;
pub mod freeze;
pub mod lint;
pub mod script;
pub mod vectors;
