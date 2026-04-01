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
