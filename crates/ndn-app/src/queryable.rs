//! Register a prefix and answer incoming Interests explicitly via a
//! stream of [`Query`] objects (Zenoh-shaped). [`Producer`](crate::Producer)
//! is the closure-style equivalent.

use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;

use ndn_faces::local::InProcHandle;
use ndn_ipc::ForwarderClient;
use ndn_packet::{Interest, Name};

use crate::AppError;
use crate::connection::{Connection, InProcConnection, IpcConnection};

pub struct Query {
    pub interest: Interest,
    conn: Arc<dyn Connection>,
}

impl Query {
    pub async fn reply(&self, data: Bytes) -> Result<(), AppError> {
        self.conn.send(data).await
    }
}

pub struct Queryable {
    conn: Arc<dyn Connection>,
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
            conn: Arc::new(IpcConnection::new(client)),
            prefix,
        })
    }

    /// In-process handle for an embedded engine.
    pub fn from_handle(handle: InProcHandle, prefix: Name) -> Self {
        Self {
            conn: Arc::new(InProcConnection::new(handle)),
            prefix,
        }
    }

    pub fn prefix(&self) -> &Name {
        &self.prefix
    }

    /// `None` when the connection closes. The returned [`Query`]
    /// carries its own sender so replies can come from another task.
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

    /// Handler returns `Some(wire_data)` to respond or `None` to drop.
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
