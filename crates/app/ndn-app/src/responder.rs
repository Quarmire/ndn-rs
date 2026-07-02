//! Reply builder passed to [`Producer::serve`](crate::Producer::serve)
//! handlers.

use std::sync::Arc;

use bytes::Bytes;

use ndn_packet::encode::DataBuilder;
use ndn_packet::lp::encode_lp_nack;
use ndn_packet::{NackReason, Name};
use ndn_security::{SignWith, Signer};

use crate::AppError;
use crate::connection::Connection;

/// Single-use: call exactly one of [`Self::respond`],
/// [`Self::respond_bytes`], or [`Self::nack`]. Dropping silently
/// discards the Interest.
pub struct Responder {
    conn: Arc<dyn Connection>,
    /// Needed to encode a valid Nack reply (NDNLPv2 §5.2).
    interest_wire: Bytes,
    /// Set when the `Producer`(crate::Producer) was configured with
    /// [`with_signer`](crate::Producer::with_signer); makes [`respond`](Self::respond)
    /// sign instead of emitting a bare digest.
    signer: Option<Arc<dyn Signer>>,
}

impl Responder {
    pub(crate) fn new(
        conn: Arc<dyn Connection>,
        interest_wire: Bytes,
        signer: Option<Arc<dyn Signer>>,
    ) -> Self {
        Self {
            conn,
            interest_wire,
            signer,
        }
    }

    pub async fn respond_bytes(self, wire: Bytes) -> Result<(), AppError> {
        self.conn.send(wire).await
    }

    /// Build and send a `Data` for `name` + `content`. If the producer was
    /// configured with a signer, the reply is **signed** with the producer's
    /// identity; otherwise it carries a `DigestSha256` (integrity, not
    /// authorship). For full control over the wire (custom signing, pre-built
    /// packets) use [`respond_bytes`](Self::respond_bytes).
    pub async fn respond(self, name: Name, content: impl Into<Bytes>) -> Result<(), AppError> {
        let content = content.into();
        let builder = DataBuilder::new(name, &content);
        let wire = match &self.signer {
            Some(signer) => builder
                .sign_with_sync(&**signer)
                .map_err(|e| AppError::Protocol(e.to_string()))?,
            None => builder.build(),
        };
        self.conn.send(wire).await
    }

    pub async fn nack(self, reason: NackReason) -> Result<(), AppError> {
        let nack_wire = encode_lp_nack(reason, &self.interest_wire);
        self.conn.send(nack_wire).await
    }
}
