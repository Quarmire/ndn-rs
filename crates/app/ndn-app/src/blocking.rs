//! Blocking [`Consumer`](super::Consumer) / [`Producer`](super::Producer)
//! wrappers with private Tokio runtimes; mirrors the
//! `reqwest::blocking` shape. Gated by the `blocking` feature.

use std::path::Path;

use bytes::Bytes;
use tokio::runtime::Runtime;

use ndn_packet::{Data, Name};
use ndn_security::{SafeData, Validator};

use crate::AppError;

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

    /// Handler returns `Some(wire_data)` or `None`. For Nack replies
    /// use the async [`Producer::serve`](crate::Producer::serve) +
    /// [`Responder`](crate::Responder) instead.
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
