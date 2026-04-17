//! Blocking (synchronous) wrappers for `Consumer` and `Producer`.
//!
//! Each wrapper creates an internal single-threaded tokio runtime, following
//! the same pattern as `reqwest::blocking`. Users do not need `#[tokio::main]`
//! or any async runtime to use these types.
//!
//! Gated behind the `blocking` feature flag.

use std::path::Path;

use bytes::Bytes;
use tokio::runtime::Runtime;

use ndn_packet::{Data, Name};
use ndn_security::{SafeData, Validator};

use crate::AppError;

/// Blocking NDN consumer.
pub struct BlockingConsumer {
    rt: Runtime,
    inner: super::Consumer,
}

impl BlockingConsumer {
    pub fn connect(socket: impl AsRef<Path>) -> Result<Self, AppError> {
        let rt = Runtime::new().map_err(|e| AppError::Protocol(e.to_string()))?;
        let inner = rt.block_on(super::Consumer::connect(socket))?;
        Ok(Self { rt, inner })
    }

    pub fn fetch(&mut self, name: impl Into<Name>) -> Result<Data, AppError> {
        self.rt.block_on(self.inner.fetch(name))
    }

    pub fn get(&mut self, name: impl Into<Name>) -> Result<Bytes, AppError> {
        self.rt.block_on(self.inner.get(name))
    }

    pub fn fetch_verified(
        &mut self,
        name: impl Into<Name>,
        validator: &Validator,
    ) -> Result<SafeData, AppError> {
        self.rt.block_on(self.inner.fetch_verified(name, validator))
    }
}

/// Blocking NDN producer.
pub struct BlockingProducer {
    rt: Runtime,
    inner: super::Producer,
}

impl BlockingProducer {
    pub fn connect(socket: impl AsRef<Path>, prefix: impl Into<Name>) -> Result<Self, AppError> {
        let rt = Runtime::new().map_err(|e| AppError::Protocol(e.to_string()))?;
        let inner = rt.block_on(super::Producer::connect(socket, prefix))?;
        Ok(Self { rt, inner })
    }

    /// Run the producer loop with a sync handler (blocking).
    ///
    /// The handler receives each Interest and returns `Some(wire_data)` to
    /// respond or `None` to silently drop. For Nack replies, use
    /// [`Producer::serve`](crate::Producer::serve) with the async `Responder` API.
    pub fn serve<F>(&mut self, handler: F) -> Result<(), AppError>
    where
        F: Fn(ndn_packet::Interest) -> Option<Bytes> + Send + Sync + 'static,
    {
        self.rt
            .block_on(self.inner.serve(move |interest, responder| {
                let result = handler(interest);
                async move {
                    if let Some(wire) = result {
                        responder.respond_bytes(wire).await.ok();
                    }
                }
            }))
    }
}
