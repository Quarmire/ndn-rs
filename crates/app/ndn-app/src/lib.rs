//! High-level NDN application API: `Consumer`, `Producer`,
//! [`KeyChain`], and the RDR helpers `Consumer::fetch_object` /
//! `Producer::publish_object` for whole-object name-versioned transfer.
//!
//! Connect to an external `ndn-fwd` via [`Consumer::connect`] /
//! [`Producer::connect`] over a Unix socket, or embed via
//! `InProcFace` + [`EngineBuilder`] and use
//! `Consumer::from_handle` / `Producer::from_handle`.
//!
//! # Serving a name
//!
//! To **answer Interests for a prefix**, reach for the high-level serve API —
//! not a raw face recv/send loop. Registering a prefix, decoding each Interest,
//! matching it, signing the reply, and pushing wire bytes back is exactly what
//! these types already do:
//!
//! - [`Producer`] — register a prefix and serve `Data`. [`Producer::serve`]
//!   runs the accept loop and hands each Interest to your handler with a
//!   [`Responder`]; the handler calls [`Responder::respond`] /
//!   [`Responder::respond_bytes`] (with the producer's [`KeyChain`] signer) or
//!   [`Responder::nack`]. For whole-object, name-versioned transfer use
//!   [`Producer::publish_object`] (RDR: segmentation, versioning, and a
//!   metadata/manifest packet, fetched by [`Consumer::fetch_object`]).
//! - [`Responder`] — the single-use reply builder passed to each handler; reply
//!   or nack exactly once (dropping it silently discards the Interest).
//! - [`Publisher`] — a long-lived, push-style producer for streaming / repeated
//!   publication under one prefix.
//! - [`serve_object_stream`] — serve an append-only object stream (sequential
//!   segments) that consumers follow live.
//! - [`Node`] — the unified entry point when an app both serves and fetches over
//!   one connection: `node.serve` / `node.serve_object` wrap the above with
//!   NDN-native verbs. Most apps start here; drop to [`Producer`] for explicit
//!   signed serving or a custom accept loop.
//!
//! Prefer these over hand-rolling the low-level [`app_face`] recv/send loop:
//! that layer exists for transports and bespoke framing, not for everyday name
//! serving, and re-implementing the decode/match/sign/reply cycle on top of it
//! is how the same bugs get reinvented.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(missing_docs)]

pub mod app_face;
pub mod connection;
pub mod consumer;
// Client-side connection demux (serve + fetch concurrently over one connection).
pub mod demux;
pub mod engine_ext;
pub mod error;
pub mod object;
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
#[cfg_attr(docsrs, doc(cfg(feature = "blocking")))]
pub mod blocking;

pub use app_face::OutboundRequest;
pub use connection::{Connection, InProcConnection, LpInfo};
// IpcConnection talks to an external `ndn-fwd` over a Unix socket (ndn-ipc).
#[cfg(not(target_arch = "wasm32"))]
pub use connection::IpcConnection;
pub use consumer::{
    CongestionStrategy, Consumer, DEFAULT_INTEREST_LIFETIME, DEFAULT_TIMEOUT, SubscribeOptions,
    Subscription, VerifiedConsumer,
};
pub use demux::{DemuxConnection, ServeGuard};
pub use engine_ext::EngineAppExt;
pub use error::AppError;
pub use object::ObjectFetch;
pub use object_stream::serve_object_stream;
pub use producer::{Aggregation, Producer, PublishOptions, Router};
pub use publisher::{Publisher, PublisherConfig};
pub use queryable::{Query, Queryable};
pub use reflexive::random_reflexive_name;
pub mod node;
pub use node::{ConnectionProvider, Node, ObjectServeGuard};
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
