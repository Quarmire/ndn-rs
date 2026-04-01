use std::path::Path;
use std::time::Duration;

use bytes::Bytes;

use ndn_face_local::AppHandle;
use ndn_ipc::RouterClient;
use ndn_packet::{Data, Name};
use ndn_packet::encode::encode_interest;
use ndn_security::{SafeData, Validator, ValidationResult};

use crate::AppError;
use crate::connection::NdnConnection;

/// High-level NDN consumer — fetches Data by name.
pub struct Consumer {
    conn: NdnConnection,
}

impl Consumer {
    /// Connect to an external router via its face socket.
    pub async fn connect(socket: impl AsRef<Path>) -> Result<Self, AppError> {
        let client = RouterClient::connect(socket).await
            .map_err(|e| AppError::Engine(e.into()))?;
        Ok(Self { conn: NdnConnection::External(client) })
    }

    /// Create from an in-process AppHandle (embedded engine).
    pub fn from_handle(handle: AppHandle) -> Self {
        Self { conn: NdnConnection::Embedded(handle) }
    }

    /// Express an Interest by name and return the decoded Data.
    pub async fn fetch(&mut self, name: impl Into<Name>) -> Result<Data, AppError> {
        let name = name.into();
        let wire = encode_interest(&name, None);
        self.fetch_wire(wire).await
    }

    /// Express a pre-encoded Interest and return the decoded Data.
    pub async fn fetch_wire(&mut self, wire: Bytes) -> Result<Data, AppError> {
        self.conn.send(wire).await?;

        let data_bytes = tokio::time::timeout(
            Duration::from_secs(4),
            self.conn.recv(),
        )
        .await
        .map_err(|_| AppError::Timeout)?
        .ok_or_else(|| AppError::Engine(anyhow::anyhow!("connection closed")))?;

        Data::decode(data_bytes)
            .map_err(|e| AppError::Engine(e.into()))
    }

    /// Fetch and verify against a `Validator`. Returns `SafeData` on success.
    pub async fn fetch_verified(
        &mut self,
        name: impl Into<Name>,
        validator: &Validator,
    ) -> Result<SafeData, AppError> {
        let data = self.fetch(name).await?;
        match validator.validate(&data).await {
            ValidationResult::Valid(safe) => Ok(safe),
            ValidationResult::Invalid(e) => Err(AppError::Engine(e.into())),
            ValidationResult::Pending => Err(AppError::Engine(
                anyhow::anyhow!("certificate chain not resolved"),
            )),
        }
    }

    /// Convenience: fetch content as raw bytes.
    pub async fn get(&mut self, name: impl Into<Name>) -> Result<Bytes, AppError> {
        let data = self.fetch(name).await?;
        data.content()
            .map(|b| Bytes::copy_from_slice(b))
            .ok_or_else(|| AppError::Engine(anyhow::anyhow!("Data has no content")))
    }
}
