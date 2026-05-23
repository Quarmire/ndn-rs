//! Transport-agnostic packet pipe used by [`Consumer`] and
//! [`Producer`]. [`InProcConnection`] talks to an embedded engine
//! through an [`InProcHandle`]; [`IpcConnection`] talks to an external
//! `ndn-fwd` over Unix socket via [`ForwarderClient`].

use async_trait::async_trait;
use bytes::Bytes;

use ndn_face_native::local::InProcHandle;
use ndn_ipc::ForwarderClient;
use ndn_packet::Name;

use crate::AppError;

/// `&self` everywhere so `Arc<dyn Connection>` can be shared across
/// concurrent send- and receive-half tasks.
#[async_trait]
pub trait Connection: Send + Sync {
    /// Pre-encoded NDN wire packet (Interest, Data, or LpPacket).
    async fn send(&self, wire: Bytes) -> Result<(), AppError>;

    /// `None` when the channel is closed.
    async fn recv(&self) -> Option<Bytes>;

    /// External connections turn this into `/localhost/nfd/rib/register`;
    /// embedded connections no-op (the embedder writes the engine FIB
    /// directly).
    async fn register_prefix(&self, prefix: &Name) -> Result<(), AppError>;
}

pub struct IpcConnection {
    client: ForwarderClient,
}

impl IpcConnection {
    pub fn new(client: ForwarderClient) -> Self {
        Self { client }
    }

    pub fn client(&self) -> &ForwarderClient {
        &self.client
    }
}

#[async_trait]
impl Connection for IpcConnection {
    async fn send(&self, wire: Bytes) -> Result<(), AppError> {
        self.client.send(wire).await.map_err(AppError::Connection)
    }

    async fn recv(&self) -> Option<Bytes> {
        self.client.recv().await
    }

    async fn register_prefix(&self, prefix: &Name) -> Result<(), AppError> {
        self.client
            .register_prefix(prefix)
            .await
            .map_err(AppError::Connection)
    }
}

/// App owns one end of an [`InProcHandle`] pair; the engine owns the
/// matching `InProcFace`. Same Tokio (or wasm-bindgen-futures) runtime.
pub struct InProcConnection {
    handle: InProcHandle,
}

impl InProcConnection {
    pub fn new(handle: InProcHandle) -> Self {
        Self { handle }
    }

    pub fn handle(&self) -> &InProcHandle {
        &self.handle
    }
}

#[async_trait]
impl Connection for InProcConnection {
    async fn send(&self, wire: Bytes) -> Result<(), AppError> {
        self.handle.send(wire).await.map_err(|_| AppError::Closed)
    }

    async fn recv(&self) -> Option<Bytes> {
        self.handle.recv().await
    }

    async fn register_prefix(&self, _prefix: &Name) -> Result<(), AppError> {
        Ok(())
    }
}
