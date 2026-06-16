//! In-network computation for NDN.
//!
//! A synthetic [`ComputeFace`] routes Interests to functions registered in a
//! [`ComputeRegistry`] and injects the resulting Data back into the forwarder
//! pipeline, where it caches in the Content Store and aggregates in the PIT
//! like any other Data.
//!
//! The crate is layered:
//!
//! - **Tier 0** — implement [`ComputeHandler`] (`&Interest -> Data`) for full
//!   control, and register it with [`ComputeService::register`].
//! - **Tier 1** — register a typed Rust closure with
//!   [`ComputeService::function`] / [`ComputeService::opaque_function`] and call
//!   it from a consumer with [`ComputeClient`]; arguments and results are framed
//!   for you via [`codec`].
//!
//! Determinism is explicit. A [transparent](ComputeService::function) function's
//! result is fully determined by the invocation name, so it caches and identical
//! concurrent calls coalesce. An [opaque](ComputeService::opaque_function)
//! function's client adds an unpredictable nonce name component so results never
//! alias — required because the engine strips the
//! `ParametersSha256DigestComponent` and cannot use it as a multiplexing key.
//!
//! See `docs/notes/compute-design-2026-05-21.md` (design) and
//! `docs/notes/compute-wire-spec-2026-05-21.md` (cross-implementation wire spec).

pub mod client;
pub mod codec;
pub mod compute_face;
pub mod executor;
pub mod registry;
#[cfg(feature = "sealed-params")]
pub mod sealed;
pub mod service;
pub mod thunk;
#[cfg(feature = "wasm-exec")]
pub mod wasm_exec;

pub use client::{ComputeClient, ComputeClientError};
pub use codec::{ArgComponent, ComputeArgs, ComputeValue};
pub use compute_face::ComputeFace;
pub use executor::ComputeExecutor;
pub use registry::{ComputeError, ComputeHandler, ComputeRegistry};
#[cfg(feature = "sealed-params")]
pub use sealed::{NodeKeypair, SealError, seal};
pub use service::{ComputeContext, ComputeService, Determinism};
pub use thunk::Thunk;
#[cfg(feature = "wasm-exec")]
pub use wasm_exec::WasmExecutor;
