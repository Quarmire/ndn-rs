use bytes::Bytes;

use ndn_faces::local::InProcHandle;
use ndn_ipc::ForwarderClient;
use ndn_packet::Name;

use crate::AppError;

/// Unified NDN connection — either an embedded engine face or an external forwarder.
///
/// Both [`send`](Self::send) and [`recv`](Self::recv) take `&self`, so an
/// `Arc<NdnConnection>` can be shared across tasks for concurrent send/recv.
pub enum NdnConnection {
    /// In-process connection via [`InProcHandle`] (embedded engine).
    Embedded(InProcHandle),
    /// External connection via [`ForwarderClient`] (Unix socket + optional SHM).
    External(ForwarderClient),
}

impl NdnConnection {
    /// Send a packet.
    pub async fn send(&self, pkt: Bytes) -> Result<(), AppError> {
        match self {
            NdnConnection::Embedded(h) => h.send(pkt).await.map_err(|_| AppError::Closed),
            NdnConnection::External(c) => c.send(pkt).await.map_err(AppError::Connection),
        }
    }

    /// Receive a packet. Returns `None` if the channel is closed.
    pub async fn recv(&self) -> Option<Bytes> {
        match self {
            NdnConnection::Embedded(h) => h.recv().await,
            NdnConnection::External(c) => c.recv().await,
        }
    }

    /// Register a prefix (only meaningful for External connections;
    /// embedded faces use engine FIB directly).
    pub async fn register_prefix(&self, prefix: &Name) -> Result<(), AppError> {
        match self {
            NdnConnection::Embedded(_) => Ok(()), // no-op for embedded
            NdnConnection::External(c) => c
                .register_prefix(prefix)
                .await
                .map_err(AppError::Connection),
        }
    }
}
