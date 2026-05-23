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
#[cfg(not(target_arch = "wasm32"))]
pub mod engine_ext;
pub mod error;
pub mod producer;
pub mod queryable;
pub mod rdr;
pub mod reflexive;
pub mod responder;
pub mod security;
pub mod subscriber;

#[cfg(feature = "blocking")]
pub mod blocking;

pub use app_face::OutboundRequest;
pub use connection::{Connection, InProcConnection, IpcConnection, LpInfo};
pub use consumer::{
    Consumer, DEFAULT_INTEREST_LIFETIME, DEFAULT_TIMEOUT, SubscribeOptions, Subscription,
};
#[cfg(not(target_arch = "wasm32"))]
pub use engine_ext::EngineAppExt;
pub use error::AppError;
pub use producer::Producer;
pub use queryable::{Query, Queryable};
pub use reflexive::random_reflexive_name;
pub use responder::Responder;
pub use security::KeyChain;
pub use subscriber::{Sample, Subscriber, SubscriberConfig};

pub use ndn_engine::{EngineBuilder, ForwarderEngine, ShutdownHandle};

pub mod prelude {
    pub use crate::{AppError, Consumer, KeyChain, Producer, Query, Queryable, Subscriber};
    pub use ndn_packet::encode::{DataBuilder, InterestBuilder};
    pub use ndn_packet::{Data, Interest, Name, name};
}
