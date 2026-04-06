use std::path::Path;
use std::time::Duration;

use bytes::Bytes;

use ndn_face_local::AppHandle;
use ndn_ipc::RouterClient;
use ndn_packet::encode::InterestBuilder;
use ndn_packet::lp::{LpPacket, is_lp_packet};
use ndn_packet::{Data, Name};
use ndn_security::{SafeData, ValidationResult, Validator};

use crate::AppError;
use crate::connection::NdnConnection;

/// Default Interest lifetime: 4 seconds.
pub const DEFAULT_INTEREST_LIFETIME: Duration = Duration::from_millis(4000);

/// Default local timeout for waiting on a response.
///
/// This is the local safety-net timeout independent of the Interest lifetime
/// sent on the wire. Set slightly longer than the default Interest lifetime
/// to account for forwarding and processing delays.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(4500);

/// High-level NDN consumer — fetches Data by name.
pub struct Consumer {
    conn: NdnConnection,
}

impl Consumer {
    /// Connect to an external router via its face socket.
    pub async fn connect(socket: impl AsRef<Path>) -> Result<Self, AppError> {
        let client = RouterClient::connect(socket)
            .await
            .map_err(|e| AppError::Engine(e.into()))?;
        Ok(Self {
            conn: NdnConnection::External(client),
        })
    }

    /// Create from an in-process AppHandle (embedded engine).
    pub fn from_handle(handle: AppHandle) -> Self {
        Self {
            conn: NdnConnection::Embedded(handle),
        }
    }

    /// Express an Interest by name and return the decoded Data.
    ///
    /// Uses [`DEFAULT_INTEREST_LIFETIME`] for the wire Interest and
    /// [`DEFAULT_TIMEOUT`] for the local wait. For control over these,
    /// use [`fetch_wire`](Self::fetch_wire) with an [`InterestBuilder`].
    pub async fn fetch(&mut self, name: impl Into<Name>) -> Result<Data, AppError> {
        let wire = InterestBuilder::new(name)
            .lifetime(DEFAULT_INTEREST_LIFETIME)
            .build();
        self.fetch_wire(wire, DEFAULT_TIMEOUT).await
    }

    /// Express a pre-encoded Interest and return the decoded Data.
    ///
    /// `timeout` is the local wait duration — set this to at least the
    /// Interest lifetime encoded in `wire` to avoid timing out before the
    /// forwarder does.
    ///
    /// Returns [`AppError::Nacked`] if the forwarder responds with a Nack
    /// (e.g. no route to the name prefix).
    pub async fn fetch_wire(&mut self, wire: Bytes, timeout: Duration) -> Result<Data, AppError> {
        self.conn.send(wire).await?;

        let reply = tokio::time::timeout(timeout, self.conn.recv())
            .await
            .map_err(|_| AppError::Timeout)?
            .ok_or_else(|| AppError::Engine(anyhow::anyhow!("connection closed")))?;

        // Check for Nack (LpPacket with Nack header).
        if is_lp_packet(&reply)
            && let Ok(lp) = LpPacket::decode(reply.clone())
        {
            if let Some(reason) = lp.nack {
                return Err(AppError::Nacked { reason });
            }
            // LpPacket without Nack — decode the fragment as Data.
            if let Some(fragment) = lp.fragment {
                return Data::decode(fragment).map_err(|e| AppError::Engine(e.into()));
            }
        }

        Data::decode(reply).map_err(|e| AppError::Engine(e.into()))
    }

    /// Fetch and verify against a `Validator`. Returns `SafeData` on success.
    pub async fn fetch_verified(
        &mut self,
        name: impl Into<Name>,
        validator: &Validator,
    ) -> Result<SafeData, AppError> {
        let data = self.fetch(name).await?;
        match validator.validate(&data).await {
            ValidationResult::Valid(safe) => Ok(*safe),
            ValidationResult::Invalid(e) => Err(AppError::Engine(e.into())),
            ValidationResult::Pending => Err(AppError::Engine(anyhow::anyhow!(
                "certificate chain not resolved"
            ))),
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
