//! [`Responder`] — reply builder passed to producer handlers.

use std::sync::Arc;

use bytes::Bytes;

use ndn_packet::lp::encode_lp_nack;
use ndn_packet::{Name, NackReason};

use crate::AppError;
use crate::connection::NdnConnection;

/// Reply builder passed to producer handlers in [`Producer::serve`].
///
/// A `Responder` is a single-use object: call exactly one of [`respond`],
/// [`respond_bytes`], or [`nack`] to send a reply.  Dropping without calling
/// a reply method silently discards the Interest.
///
/// # Example
///
/// ```rust,no_run
/// # async fn example(mut producer: ndn_app::Producer) -> Result<(), ndn_app::AppError> {
/// use ndn_packet::encode::DataBuilder;
///
/// producer.serve(|interest, responder| async move {
///     let data = DataBuilder::new((*interest.name).clone(), b"hello").build();
///     responder.respond_bytes(data).await.ok();
/// }).await
/// # }
/// ```
pub struct Responder {
    conn: Arc<NdnConnection>,
    /// Original Interest wire bytes, needed to encode a valid Nack reply.
    interest_wire: Bytes,
}

impl Responder {
    pub(crate) fn new(conn: Arc<NdnConnection>, interest_wire: Bytes) -> Self {
        Self { conn, interest_wire }
    }

    /// Send a raw pre-encoded Data wire packet as the reply.
    pub async fn respond_bytes(self, wire: Bytes) -> Result<(), AppError> {
        self.conn.send(wire).await
    }

    /// Build and send a Data packet with the given name and content.
    pub async fn respond(self, name: Name, content: impl Into<Bytes>) -> Result<(), AppError> {
        let data = ndn_packet::encode::DataBuilder::new(name, &content.into()).build();
        self.conn.send(data).await
    }

    /// Send a Nack reply for the Interest.
    ///
    /// The Nack is encoded as an NDNLPv2 LpPacket containing the original
    /// Interest wire as the Fragment field, per NDNLPv2 §5.2.
    pub async fn nack(self, reason: NackReason) -> Result<(), AppError> {
        let nack_wire = encode_lp_nack(reason, &self.interest_wire);
        self.conn.send(nack_wire).await
    }
}
