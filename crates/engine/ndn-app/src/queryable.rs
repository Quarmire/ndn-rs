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
//! let mut q = Queryable::connect("/run/nfd/nfd.sock", "/sensors/temp").await?;
//!
//! while let Some(query) = q.recv().await {
//!     let data = DataBuilder::new((*query.interest.name).clone(), b"22.5").build();
//!     query.reply(data).await.ok();
//! }
//! # Ok(())
//! # }
//! ```

use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;

use ndn_faces::local::InProcHandle;
use ndn_ipc::ForwarderClient;
use ndn_packet::{Interest, Name};

use crate::AppError;
use crate::connection::NdnConnection;

/// A query received by a [`Queryable`] — the application replies via [`Query::reply`].
pub struct Query {
    /// The incoming Interest.
    pub interest: Interest,
    /// Sender for the reply Data.
    conn: Arc<NdnConnection>,
}

impl Query {
    pub async fn reply(&self, data: Bytes) -> Result<(), AppError> {
        self.conn.send(data).await
    }
}

/// A queryable endpoint — receives Interests and lets the application reply.
pub struct Queryable {
    conn: Arc<NdnConnection>,
    prefix: Name,
}

impl Queryable {
    pub async fn connect(
        socket: impl AsRef<Path>,
        prefix: impl Into<Name>,
    ) -> Result<Self, AppError> {
        let prefix = prefix.into();
        let client = ForwarderClient::connect(socket)
            .await
            .map_err(AppError::Connection)?;
        client
            .register_prefix(&prefix)
            .await
            .map_err(AppError::Connection)?;
        Ok(Self {
            conn: Arc::new(NdnConnection::External(client)),
            prefix,
        })
    }

    /// Create from an in-process InProcHandle (embedded engine).
    pub fn from_handle(handle: InProcHandle, prefix: Name) -> Self {
        Self {
            conn: Arc::new(NdnConnection::Embedded(handle)),
            prefix,
        }
    }

    pub fn prefix(&self) -> &Name {
        &self.prefix
    }

    /// Receive the next query. Returns `None` when the connection closes.
    ///
    /// Each returned [`Query`] carries a sender so the application can reply
    /// asynchronously — even from a different task.
    pub async fn recv(&self) -> Option<Query> {
        loop {
            let raw = self.conn.recv().await?;
            let interest = match Interest::decode(raw) {
                Ok(i) => i,
                Err(_) => continue,
            };
            return Some(Query {
                interest,
                conn: Arc::clone(&self.conn),
            });
        }
    }

    /// Run a query handler loop.
    ///
    /// The handler receives each Interest and returns `Some(wire_data)` to
    /// respond or `None` to silently drop.
    pub async fn serve<F, Fut>(&self, handler: F) -> Result<(), AppError>
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
