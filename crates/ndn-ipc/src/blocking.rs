//! Blocking wrapper around [`ForwarderClient`] with a private Tokio
//! runtime — for C FFI, Python bindings, and other non-async callers.

use std::path::Path;

use bytes::Bytes;
use tokio::runtime::Runtime;

use ndn_packet::Name;

use crate::forwarder_client::{ForwarderClient, ForwarderError};

pub struct BlockingForwarderClient {
    rt: Runtime,
    inner: ForwarderClient,
}

impl BlockingForwarderClient {
    /// Attempts SHM data plane, falls back to the Unix socket.
    pub fn connect(face_socket: impl AsRef<Path>) -> Result<Self, ForwarderError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(ForwarderError::Io)?;
        let inner = rt.block_on(ForwarderClient::connect(face_socket))?;
        Ok(Self { rt, inner })
    }

    pub fn connect_unix_only(face_socket: impl AsRef<Path>) -> Result<Self, ForwarderError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(ForwarderError::Io)?;
        let inner = rt.block_on(ForwarderClient::connect_unix_only(face_socket))?;
        Ok(Self { rt, inner })
    }

    pub fn send(&self, pkt: Bytes) -> Result<(), ForwarderError> {
        self.rt.block_on(self.inner.send(pkt))
    }

    pub fn recv(&self) -> Option<Bytes> {
        self.rt.block_on(self.inner.recv())
    }

    pub fn register_prefix(&self, prefix: &Name) -> Result<(), ForwarderError> {
        self.rt.block_on(self.inner.register_prefix(prefix))
    }

    pub fn unregister_prefix(&self, prefix: &Name) -> Result<(), ForwarderError> {
        self.rt.block_on(self.inner.unregister_prefix(prefix))
    }

    pub fn is_shm(&self) -> bool {
        self.inner.is_shm()
    }

    pub fn is_dead(&self) -> bool {
        self.inner.is_dead()
    }

    pub fn close(self) {
        let Self { rt, inner } = self;
        rt.block_on(inner.close());
    }
}
