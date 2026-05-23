//! Reply builder passed to [`Producer::serve`](crate::Producer::serve)
//! handlers.

use std::sync::Arc;

use bytes::Bytes;

use ndn_packet::lp::encode_lp_nack;
use ndn_packet::{NackReason, Name};

use crate::AppError;
use crate::connection::Connection;

/// Single-use: call exactly one of [`Self::respond`],
/// [`Self::respond_bytes`], or [`Self::nack`]. Dropping silently
/// discards the Interest.
pub struct Responder {
    conn: Arc<dyn Connection>,
    /// Needed to encode a valid Nack reply (NDNLPv2 §5.2).
    interest_wire: Bytes,
}

impl Responder {
    pub(crate) fn new(conn: Arc<dyn Connection>, interest_wire: Bytes) -> Self {
        Self {
            conn,
            interest_wire,
        }
    }

    pub async fn respond_bytes(self, wire: Bytes) -> Result<(), AppError> {
        self.conn.send(wire).await
    }

    pub async fn respond(self, name: Name, content: impl Into<Bytes>) -> Result<(), AppError> {
        let data = ndn_packet::encode::DataBuilder::new(name, &content.into()).build();
        self.conn.send(data).await
    }

    pub async fn nack(self, reason: NackReason) -> Result<(), AppError> {
        let nack_wire = encode_lp_nack(reason, &self.interest_wire);
        self.conn.send(nack_wire).await
    }
}
