//! # ndn-app — NDN Application API
//!
//! High-level [`Consumer`] and [`Producer`] abstractions for Named Data
//! Networking, plus [`KeyChain`] for identity management and signing.
//!
//! ## Connection modes
//!
//! **External router** — connect to a running `ndn-router` via Unix socket:
//!
//! ```rust,no_run
//! # use ndn_app::Consumer;
//! # async fn example() -> Result<(), ndn_app::AppError> {
//! let mut consumer = Consumer::connect("/tmp/ndn-faces.sock").await?;
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
//! # use ndn_face_local::AppFace;
//! # use ndn_packet::Name;
//! # use ndn_packet::encode::DataBuilder;
//! # use ndn_transport::FaceId;
//! # async fn example() -> anyhow::Result<()> {
//! // Create in-process face pairs
//! let (consumer_face, consumer_handle) = AppFace::new(FaceId(1), 64);
//! let (producer_face, producer_handle) = AppFace::new(FaceId(2), 64);
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

pub mod app_face;
pub mod error;
pub mod connection;
pub mod consumer;
pub mod producer;
pub mod security;

#[cfg(feature = "blocking")]
pub mod blocking;

pub use app_face::{AppFace, OutboundRequest};
pub use error::AppError;
pub use connection::NdnConnection;
pub use consumer::Consumer;
pub use producer::Producer;
pub use security::KeyChain;

/// Re-export the engine builder for convenience.
pub use ndn_engine::{EngineBuilder, ForwarderEngine, ShutdownHandle};

/// Prelude for ergonomic imports.
pub mod prelude {
    pub use ndn_packet::{Name, Interest, Data, name};
    pub use ndn_packet::encode::{InterestBuilder, DataBuilder};
    pub use crate::{Consumer, Producer, KeyChain, AppError};
}
