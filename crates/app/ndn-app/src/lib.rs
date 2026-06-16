//! High-level NDN application API: [`Consumer`], [`Producer`],
//! [`KeyChain`], and the RDR helpers `Consumer::fetch_object` /
//! `Producer::publish_object` for whole-object name-versioned transfer.
//!
//! Connect to an external `ndn-fwd` via [`Consumer::connect`] /
//! [`Producer::connect`] over a Unix socket, or embed via
//! `InProcFace` + [`EngineBuilder`] and use
//! `Consumer::from_handle` / `Producer::from_handle`.

#![allow(missing_docs)]

pub mod app_face;
pub mod connection;
pub mod consumer;
// Client-side connection demux (serve + fetch concurrently over one connection).
pub mod demux;
pub mod engine_ext;
pub mod error;
pub mod object_stream;
pub mod producer;
pub mod publisher;
pub mod queryable;
pub mod rdr;
pub mod reflexive;
pub mod responder;
pub mod rt;
pub mod security;
pub mod subscriber;

#[cfg(all(feature = "blocking", not(target_arch = "wasm32")))]
pub mod blocking;

pub use app_face::OutboundRequest;
pub use connection::{Connection, InProcConnection, LpInfo};
// IpcConnection talks to an external `ndn-fwd` over a Unix socket (ndn-ipc).
#[cfg(not(target_arch = "wasm32"))]
pub use connection::IpcConnection;
pub use demux::{DemuxConnection, ServeGuard};
pub use consumer::{
    CongestionStrategy, Consumer, DEFAULT_INTEREST_LIFETIME, DEFAULT_TIMEOUT, SubscribeOptions,
    Subscription, VerifiedConsumer,
};
pub use engine_ext::EngineAppExt;
pub use error::AppError;
pub use object_stream::serve_object_stream;
pub use producer::{Producer, Router};
pub use publisher::{Publisher, PublisherConfig};
pub use queryable::{Query, Queryable};
pub use reflexive::random_reflexive_name;
pub use responder::Responder;
pub use security::KeyChain;
pub use subscriber::{Sample, Subscriber, SubscriberConfig};

pub use ndn_engine::{ForwarderEngine, ShutdownHandle};
// The native engine builder is std/tokio-multithread; the browser uses the
// single-threaded WasmEngineBuilder. Both yield a `ForwarderEngine` that the
// EngineAppExt registration surface drives identically.
#[cfg(not(target_arch = "wasm32"))]
pub use ndn_engine::EngineBuilder;
#[cfg(target_arch = "wasm32")]
pub use ndn_engine::{WasmEngineBuilder, WasmEngineConfig};

pub mod prelude {
    pub use crate::{
        AppError, Consumer, KeyChain, Producer, Publisher, Query, Queryable, Subscriber,
    };
    pub use ndn_packet::encode::{DataBuilder, InterestBuilder};
    pub use ndn_packet::{Data, Interest, Name, name};
}
