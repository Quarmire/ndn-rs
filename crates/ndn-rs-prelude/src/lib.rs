//! `ndn` — umbrella prelude for application authors.
//!
//! Curated re-exports of the application-author API surface. Depend on
//! this crate to fetch a Data by name or serve one and treat the
//! forwarder as opaque. Protocol authors reach into `ndn-engine`,
//! `ndn-strategy`, `ndn-faces` directly.
//!
//! The crates.io package is `ndn-rs-prelude` but the library is named
//! `ndn`, so user code writes `use ndn::Consumer;`.
//!
//! ```no_run
//! use ndn::prelude::*;
//! use ndn::IpcConnection;
//!
//! # async fn run() -> Result<(), ndn::AppError> {
//! let conn = IpcConnection::connect("/run/nfd/nfd.sock").await?;
//! let mut consumer = Consumer::new(conn);
//! let data = consumer.fetch("/example/data").await?;
//! # Ok(()) }
//! ```
//!
//! On `wasm32-unknown-unknown` only the packet and security surface is
//! re-exported; `Consumer` / `Producer` / `KeyChain` and the connection
//! types are native-only because `ndn-app` pulls the full Tokio runtime.
//! Wasm callers build their engine via `ndn_engine::WasmEngineBuilder`.

#![cfg_attr(docsrs, feature(doc_cfg))]

pub use ndn_packet::encode::{DataBuilder, InterestBuilder};
pub use ndn_packet::{Data, Interest, Name, NameComponent, NackReason};

pub use ndn_security::{
    AcceptAllPolicy, HierarchicalPolicy, InsecureTrust, LvsTrust, SignerSelection, SigningInfo,
    StaticTrust, TrustPolicy, ValidationPolicy,
};

#[cfg(not(target_arch = "wasm32"))]
pub use ndn_app::{
    AppError, Connection, Consumer, InProcConnection, IpcConnection, KeyChain, Producer, Query,
    Queryable, Responder, Sample, Subscriber, SubscriberConfig,
};

pub mod prelude {
    pub use crate::{Data, DataBuilder, Interest, InterestBuilder, Name};

    #[cfg(not(target_arch = "wasm32"))]
    pub use crate::{AppError, Consumer, KeyChain, Producer, Query, Queryable, Subscriber};
}
