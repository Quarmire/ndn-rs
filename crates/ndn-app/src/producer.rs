use std::future::Future;
use std::path::Path;

use bytes::Bytes;

use ndn_face_local::AppHandle;
use ndn_ipc::RouterClient;
use ndn_packet::{Interest, Name};

use crate::AppError;
use crate::connection::NdnConnection;

/// High-level NDN producer — serves Data in response to Interests.
pub struct Producer {
    conn: NdnConnection,
    prefix: Name,
}

impl Producer {
    /// Connect to an external router and register a prefix.
    pub async fn connect(
        socket: impl AsRef<Path>,
        prefix: impl Into<Name>,
    ) -> Result<Self, AppError> {
        let prefix = prefix.into();
        let client = RouterClient::connect(socket)
            .await
            .map_err(|e| AppError::Engine(e.into()))?;
        client
            .register_prefix(&prefix)
            .await
            .map_err(|e| AppError::Engine(e.into()))?;
        Ok(Self {
            conn: NdnConnection::External(client),
            prefix,
        })
    }

    /// Create from an in-process AppHandle (embedded engine).
    pub fn from_handle(handle: AppHandle, prefix: Name) -> Self {
        Self {
            conn: NdnConnection::Embedded(handle),
            prefix,
        }
    }

    /// Run the producer loop with an async handler.
    ///
    /// The handler receives each Interest and returns `Some(wire_data)` to
    /// respond or `None` to silently drop.
    pub async fn serve<F, Fut>(&mut self, handler: F) -> Result<(), AppError>
    where
        F: Fn(Interest) -> Fut + Send + Sync,
        Fut: Future<Output = Option<Bytes>> + Send,
    {
        loop {
            let raw = match self.conn.recv().await {
                Some(b) => b,
                None => break,
            };

            let interest = match Interest::decode(raw) {
                Ok(i) => i,
                Err(_) => continue,
            };

            if let Some(data) = handler(interest).await {
                self.conn.send(data).await?;
            }
        }
        Ok(())
    }

    /// The registered prefix.
    pub fn prefix(&self) -> &Name {
        &self.prefix
    }
}
