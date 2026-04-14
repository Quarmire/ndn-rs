//! # ndn-app — NDN Application API
//!
//! High-level [`Consumer`] and [`Producer`] abstractions for Named Data
//! Networking, plus [`KeyChain`] for identity management and signing.
//!
//! ## Connection modes
//!
//! **External forwarder** — connect to a running `ndn-fwd` via Unix socket:
//!
//! ```rust,no_run
//! # use ndn_app::Consumer;
//! # async fn example() -> Result<(), ndn_app::AppError> {
//! let mut consumer = Consumer::connect("/run/nfd/nfd.sock").await?;
//! let data = consumer.fetch("/example/data").await?;
//! # Ok(())
//! # }
//! ```
//!
//! **Embedded engine** — run the forwarder in-process (ideal for mobile/Android):
//!
//! ```rust,no_run
//! # use ndn_app::{Consumer, Producer, EngineBuilder};
//! # use ndn_engine::EngineConfig;
//! # use ndn_faces::local::InProcFace;
//! # use ndn_packet::Name;
//! # use ndn_packet::encode::DataBuilder;
//! # use ndn_transport::FaceId;
//! # async fn example() -> anyhow::Result<()> {
//! // Create in-process face pairs
//! let (consumer_face, consumer_handle) = InProcFace::new(FaceId(1), 64);
//! let (producer_face, producer_handle) = InProcFace::new(FaceId(2), 64);
//!
//! // Build engine with both faces
//! let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
//!     .face(consumer_face)
//!     .face(producer_face)
//!     .build()
//!     .await?;
//!
//! // Route Interests for /app → producer face
//! let prefix: Name = "/app".parse()?;
//! engine.fib().add_nexthop(&prefix, FaceId(2), 0);
//!
//! // Use Consumer/Producer via handles
//! let mut consumer = Consumer::from_handle(consumer_handle);
//! let mut producer = Producer::from_handle(producer_handle, prefix);
//! # Ok(())
//! # }
//! ```

#![allow(missing_docs)]

pub mod app_face;
pub mod connection;
pub mod consumer;
pub mod error;
pub mod producer;
pub mod queryable;
pub mod responder;
pub mod security;
pub mod subscriber;

#[cfg(feature = "blocking")]
pub mod blocking;

pub use app_face::OutboundRequest;
pub use connection::NdnConnection;
pub use consumer::{Consumer, DEFAULT_INTEREST_LIFETIME, DEFAULT_TIMEOUT};
pub use error::AppError;
pub use producer::Producer;
pub use queryable::{Query, Queryable};
pub use responder::Responder;
pub use security::KeyChain;
pub use subscriber::{Sample, Subscriber, SubscriberConfig};

/// Re-export the engine builder for convenience.
pub use ndn_engine::{EngineBuilder, ForwarderEngine, ShutdownHandle};

/// Prelude for ergonomic imports.
pub mod prelude {
    pub use crate::{AppError, Consumer, KeyChain, Producer, Query, Queryable, Subscriber};
    pub use ndn_packet::encode::{DataBuilder, InterestBuilder};
    pub use ndn_packet::{Data, Interest, Name, name};
}
