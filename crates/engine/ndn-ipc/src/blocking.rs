//! Synchronous (blocking) wrapper for [`ForwarderClient`].
//!
//! Useful for non-async contexts such as C FFI or Python bindings where
//! spawning a Tokio runtime manually is more ergonomic than using `async/await`.
//!
//! # Example
//!
//! ```rust,no_run
//! use ndn_ipc::BlockingForwarderClient;
//! use ndn_packet::Name;
//!
//! let mut client = BlockingForwarderClient::connect("/run/nfd/nfd.sock").unwrap();
//! let prefix: Name = "/example".parse().unwrap();
//! client.register_prefix(&prefix).unwrap();
//!
//! // Send a raw NDN packet.
//! client.send(bytes::Bytes::from_static(b"\x05\x01\x00")).unwrap();
//!
//! // Receive a raw NDN packet.
//! if let Some(pkt) = client.recv() {
//!     println!("received {} bytes", pkt.len());
//! }
//! ```

use std::path::Path;

use bytes::Bytes;
use tokio::runtime::Runtime;

use ndn_packet::Name;

use crate::forwarder_client::{ForwarderClient, ForwarderError};

/// Synchronous (blocking) client for communicating with a running `ndn-fwd`.
///
/// Wraps [`ForwarderClient`] with a private Tokio runtime so callers do not
/// need to manage an async runtime. All methods block the calling thread.
pub struct BlockingForwarderClient {
    rt: Runtime,
    inner: ForwarderClient,
}

impl BlockingForwarderClient {
    /// Connect to the forwarder's face socket (blocking).
    ///
    /// Automatically attempts SHM data plane; falls back to Unix socket.
    ///
    /// # Errors
    ///
    /// Returns [`ForwarderError`] if the socket is unreachable or the
    /// connection handshake fails.
    pub fn connect(face_socket: impl AsRef<Path>) -> Result<Self, ForwarderError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(ForwarderError::Io)?;
        let inner = rt.block_on(ForwarderClient::connect(face_socket))?;
        Ok(Self { rt, inner })
    }

    /// Connect using only the Unix socket for data (no SHM attempt).
    pub fn connect_unix_only(face_socket: impl AsRef<Path>) -> Result<Self, ForwarderError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(ForwarderError::Io)?;
        let inner = rt.block_on(ForwarderClient::connect_unix_only(face_socket))?;
        Ok(Self { rt, inner })
    }

    /// Send a raw NDN packet (blocking).
    pub fn send(&self, pkt: Bytes) -> Result<(), ForwarderError> {
        self.rt.block_on(self.inner.send(pkt))
    }

    /// Receive a raw NDN packet (blocking).
    ///
    /// Returns `None` if the forwarder connection is closed.
    pub fn recv(&self) -> Option<Bytes> {
        self.rt.block_on(self.inner.recv())
    }

    /// Register a prefix with the forwarder (blocking).
    pub fn register_prefix(&self, prefix: &Name) -> Result<(), ForwarderError> {
        self.rt.block_on(self.inner.register_prefix(prefix))
    }

    /// Unregister a prefix from the forwarder (blocking).
    pub fn unregister_prefix(&self, prefix: &Name) -> Result<(), ForwarderError> {
        self.rt.block_on(self.inner.unregister_prefix(prefix))
    }

    /// Whether this client is using SHM for data transport.
    pub fn is_shm(&self) -> bool {
        self.inner.is_shm()
    }

    /// Whether the forwarder connection has been lost.
    pub fn is_dead(&self) -> bool {
        self.inner.is_dead()
    }

    /// Gracefully tear down the client (blocking).
    pub fn close(self) {
        let Self { rt, inner } = self;
        rt.block_on(inner.close());
    }
}
