//! `ndn` — umbrella prelude for application authors.
//!
//! Curated re-exports of the application-author API surface. Depend on
//! this crate to fetch a Data by name or serve one and treat the
//! forwarder as opaque. Protocol authors reach into `ndn-engine`,
//! `ndn-strategy`, `ndn-face-native` directly.
//!
//! The crates.io package is `ndn-rs-prelude` but the library is named
//! `ndn`, so user code writes `use ndn::Consumer;`.
//!
//! ```no_run
//! use ndn::prelude::*;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let keychain = KeyChain::ephemeral("/example")?;
//! // Decide trust once with `verifying`; then `fetch` returns `SafeData` —
//! // proof the signature checked out. (Bare `Consumer::fetch` is unverified.)
//! let mut consumer = Consumer::connect("/run/nfd/nfd.sock").await?.verifying(keychain.validator());
//! let safe = consumer.fetch("/example/data").await?;
//! # Ok(()) }
//! ```
//!
//! On `wasm32-unknown-unknown` only the packet and security surface is
//! re-exported; `Consumer` / `Producer` / `KeyChain` and the connection
//! types are native-only because `ndn-app` pulls the full Tokio runtime.
//! Wasm callers build their engine via `ndn_engine::WasmEngineBuilder`.

#![cfg_attr(docsrs, feature(doc_cfg))]

pub use ndn_packet::encode::{DataBuilder, InterestBuilder};
pub use ndn_packet::{Data, Interest, NackReason, Name, NameComponent};

pub use ndn_security::{
    AcceptAllPolicy, HierarchicalPolicy, InsecureTrust, LvsTrust, SafeData, SignerSelection,
    SigningInfo, StaticTrust, TrustPolicy, Unverified, ValidationPolicy, Validator,
};

#[cfg(not(target_arch = "wasm32"))]
pub use ndn_app::{
    AppError, Connection, Consumer, InProcConnection, IpcConnection, KeyChain, Node, Producer,
    Query, Queryable, Responder, Sample, Subscriber, SubscriberConfig, VerifiedConsumer,
};

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
