//! Queryable — register a prefix and respond to incoming queries (Interests).
//!
//! Like [`Producer`](crate::Producer) but returns a stream of [`Query`] objects
//! that the application responds to explicitly, matching Zenoh's queryable pattern.
//!
//! # Example
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), ndn_app::AppError> {
//! use ndn_app::Queryable;
//! use ndn_packet::encode::DataBuilder;
//!
//! let mut q = Queryable::connect("/tmp/ndn-faces.sock", "/sensors/temp").await?;
//!
//! q.serve(|interest| async move {
//!     let data = DataBuilder::new((*interest.name).clone(), b"22.5").build();
//!     Some(data)
//! }).await?;
//! # Ok(())
//! # }
//! ```

use std::path::Path;

use bytes::Bytes;

use ndn_face_local::AppHandle;
use ndn_ipc::RouterClient;
use ndn_packet::{Interest, Name};

use crate::AppError;
use crate::connection::NdnConnection;

/// A queryable endpoint — receives Interests and lets the application reply.
pub struct Queryable {
    conn:   NdnConnection,
    prefix: Name,
}

impl Queryable {
    /// Connect to an external router and register a prefix.
    pub async fn connect(
        socket: impl AsRef<Path>,
        prefix: impl Into<Name>,
    ) -> Result<Self, AppError> {
        let prefix = prefix.into();
        let client = RouterClient::connect(socket).await
            .map_err(|e| AppError::Engine(e.into()))?;
        client.register_prefix(&prefix).await
            .map_err(|e| AppError::Engine(e.into()))?;
        Ok(Self { conn: NdnConnection::External(client), prefix })
    }

    /// Create from an in-process AppHandle (embedded engine).
    pub fn from_handle(handle: AppHandle, prefix: Name) -> Self {
        Self { conn: NdnConnection::Embedded(handle), prefix }
    }

    /// The registered prefix.
    pub fn prefix(&self) -> &Name {
        &self.prefix
    }

    /// Run a query handler loop.
    ///
    /// The handler receives each Interest and returns `Some(wire_data)` to
    /// respond or `None` to silently drop.
    pub async fn serve<F, Fut>(&mut self, handler: F) -> Result<(), AppError>
    where
        F: Fn(Interest) -> Fut + Send + Sync,
        Fut: std::future::Future<Output = Option<Bytes>> + Send,
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
}
