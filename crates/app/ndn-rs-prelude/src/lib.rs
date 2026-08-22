//! `ndn` — umbrella prelude for application authors.
//!
//! Curated re-exports of the application-author API surface. Depend on
//! this crate to fetch a Data by name or serve one and treat the
//! forwarder as opaque. Protocol authors reach into `ndn-engine`,
//! `ndn-strategy`, `ndn-face` directly.
//!
//! The crates.io package is `ndn-rs-prelude` but the library is named
//! `ndn`, so user code writes `use ndn::Node;`.
//!
//! For most apps the one type to learn is [`Node`]: a single
//! handle that exposes every pattern — `fetch` / `serve` / `object` / `publish`
//! / `subscribe` / `query` — over one forwarder connection. The per-pattern
//! types (`Consumer`, `Producer`, …) remain available as building blocks.
//!
//! Beyond the flagship types, the application-facing sub-crates are
//! re-exported wholesale as modules — [`packet`], [`security`], and (native
//! only) [`app`], [`engine`], [`strategy`], [`transport`], [`face_local`] —
//! so `use ndn::engine::pipeline::ForwardingAction;` works without adding
//! `ndn-engine` to your `Cargo.toml`. One dependency covers the front door
//! *and* the reach-in surface.
//!
//! ```no_run
//! use ndn::prelude::*;
//! use ndn::Node;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let node = Node::connect("/run/nfd/nfd.sock").await?;
//! // Decide trust once with `verifying`; then `fetch` returns `SafeData` —
//! // proof the signature checked out. (Bare `node.fetch` is unverified.)
//! let keychain = KeyChain::ephemeral("/example")?;
//! let safe = node.verifying(keychain.validator()).fetch("/example/data").await?;
//! # let _ = safe; Ok(()) }
//! ```
//!
//! On `wasm32-unknown-unknown` only the packet and security surface is
//! re-exported; `Consumer` / `Producer` / `KeyChain` and the connection
//! types are native-only because `ndn-app` pulls the full Tokio runtime.
//! Wasm callers build their engine via `ndn_engine::WasmEngineBuilder`.

#![cfg_attr(docsrs, feature(doc_cfg))]

// ── Module re-exports ───────────────────────────────────────────────────
// The application-facing sub-crate surfaces under one roof, so an app (and
// the in-tree examples) needs only this one dependency: `ndn::packet::…`,
// `ndn::engine::…`, `ndn::strategy::…`. The wasm-safe modules are
// unconditional; the engine / strategy / transport / face stack is
// native-only here (wasm callers keep building their engine via
// `ndn_engine::WasmEngineBuilder` directly, as before).
pub use ndn_packet as packet;
pub use ndn_security as security;

#[cfg(not(target_arch = "wasm32"))]
pub use ndn_app as app;
#[cfg(not(target_arch = "wasm32"))]
pub use ndn_engine as engine;
#[cfg(not(target_arch = "wasm32"))]
pub use ndn_face_local as face_local;
#[cfg(not(target_arch = "wasm32"))]
pub use ndn_strategy as strategy;
#[cfg(not(target_arch = "wasm32"))]
pub use ndn_transport as transport;

// ── Flagship types at the top level ─────────────────────────────────────
pub use ndn_packet::encode::{DataBuilder, InterestBuilder};
pub use ndn_packet::{Data, Interest, NackReason, Name, NameComponent};

pub use ndn_security::{
    AcceptAllPolicy, HierarchicalPolicy, InsecureTrust, LvsTrust, SafeData, SignWith, Signer,
    SignerSelection, SigningInfo, StaticTrust, TrustPolicy, Unverified, ValidationPolicy,
    Validator,
};

#[cfg(not(target_arch = "wasm32"))]
pub use ndn_app::{
    AppError, Connection, Consumer, InProcConnection, IpcConnection, KeyChain, Node, ObjectFetch,
    Producer, Query, Queryable, Responder, Sample, Subscriber, SubscriberConfig, VerifiedConsumer,
};

// The in-process engine front door: build a forwarder inside the app
// (`EngineBuilder`), then mint app faces / a `Node` from it via
// `ndn::app::EngineAppExt`.
#[cfg(not(target_arch = "wasm32"))]
pub use ndn_app::EngineAppExt;
#[cfg(not(target_arch = "wasm32"))]
pub use ndn_engine::{EngineBuilder, EngineConfig};
#[cfg(not(target_arch = "wasm32"))]
pub use ndn_transport::FaceId;

pub mod prelude {
    pub use crate::{Data, DataBuilder, Interest, InterestBuilder, Name};
    // The safe-fetch types, so `verifying(...).fetch()` and `SafeData` are in
    // reach without a separate `use ndn_security::...`.
    pub use crate::{SafeData, Unverified, Validator};

    #[cfg(not(target_arch = "wasm32"))]
    pub use crate::{
        AppError, Consumer, KeyChain, Node, Producer, Query, Queryable, Subscriber,
        VerifiedConsumer,
    };
}
