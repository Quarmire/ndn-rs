//! Transport-agnostic packet pipe used by [`Consumer`] and
//! [`Producer`]. [`InProcConnection`] talks to an embedded engine
//! through an [`InProcHandle`]; [`IpcConnection`] talks to an external
//! `ndn-fwd` over Unix socket via [`ForwarderClient`].

use async_trait::async_trait;
use bytes::Bytes;

// `InProcHandle` is the same type on both targets — `ndn-face-native` simply
// re-exports it from `ndn-face-local`. The wasm path imports it directly so it
// doesn't pull `ndn-face-native`'s OS-socket transports.
#[cfg(target_arch = "wasm32")]
use ndn_face_local::InProcHandle;
#[cfg(not(target_arch = "wasm32"))]
use ndn_face_native::local::InProcHandle;
#[cfg(not(target_arch = "wasm32"))]
use ndn_ipc::ForwarderClient;
use ndn_packet::Name;
use ndn_packet::lp::{LpPacket, is_lp_packet};
use ndn_transport::FaceId;

use crate::AppError;

/// Per-packet NDNLPv2 local fields surfaced to the application — the
/// `getTag<lp::IncomingFaceIdTag>()` equivalent. `incoming_face_id` is the
/// face the packet arrived on at the forwarder (for an embedded in-process
/// app it comes from the source tag-bag); `congestion_mark` is the LP
/// CongestionMark, if any. Both `None` unless the forwarder attached them
/// (which requires the face to have LocalFields enabled).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LpInfo {
    pub incoming_face_id: Option<FaceId>,
    pub congestion_mark: Option<u64>,
}

/// Extract LP local fields from a (possibly LP-framed) wire packet.
pub(crate) fn lp_info_from_wire(wire: &Bytes) -> LpInfo {
    if !is_lp_packet(wire) {
        return LpInfo::default();
    }
    match LpPacket::decode(wire.clone()) {
        Ok(lp) => LpInfo {
            incoming_face_id: lp.incoming_face_id.map(FaceId),
            congestion_mark: lp.congestion_mark,
        },
        Err(_) => LpInfo::default(),
    }
}

/// `&self` everywhere so `Arc<dyn Connection>` can be shared across
/// concurrent send- and receive-half tasks.
#[async_trait]
pub trait Connection: Send + Sync {
    /// Pre-encoded NDN wire packet (Interest, Data, or LpPacket).
    async fn send(&self, wire: Bytes) -> Result<(), AppError>;

    /// `None` when the channel is closed.
    async fn recv(&self) -> Option<Bytes>;

    /// Like [`recv`](Self::recv) but also surfaces the packet's NDNLPv2 local
    /// fields ([`LpInfo`]). Default decodes any LP frame on the wire; the
    /// in-process connection additionally fills `incoming_face_id` from the
    /// source tag-bag.
    async fn recv_with_meta(&self) -> Option<(Bytes, LpInfo)> {
        self.recv().await.map(|wire| {
            let lp = lp_info_from_wire(&wire);
            (wire, lp)
        })
    }

    /// External connections turn this into `/localhost/nfd/rib/register`;
    /// embedded connections no-op (the embedder writes the engine FIB
    /// directly).
    async fn register_prefix(&self, prefix: &Name) -> Result<(), AppError>;
}

/// Talks to an external `ndn-fwd` over a Unix socket via [`ForwarderClient`].
/// Native-only — the browser reaches its engine through [`InProcConnection`].
#[cfg(not(target_arch = "wasm32"))]
pub struct IpcConnection {
    client: ForwarderClient,
}

#[cfg(not(target_arch = "wasm32"))]
impl IpcConnection {
    pub fn new(client: ForwarderClient) -> Self {
        Self { client }
    }

    pub fn client(&self) -> &ForwarderClient {
        &self.client
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl Connection for IpcConnection {
    async fn send(&self, wire: Bytes) -> Result<(), AppError> {
        self.client.send(wire).await.map_err(AppError::Connection)
    }

    async fn recv(&self) -> Option<Bytes> {
        self.client.recv().await
    }

    async fn register_prefix(&self, prefix: &Name) -> Result<(), AppError> {
        self.client
            .register_prefix(prefix)
            .await
            .map_err(AppError::Connection)
    }
}

/// App owns one end of an [`InProcHandle`] pair; the engine owns the
/// matching `InProcFace`. Same Tokio (or wasm-bindgen-futures) runtime.
pub struct InProcConnection {
    handle: InProcHandle,
}

impl InProcConnection {
    pub fn new(handle: InProcHandle) -> Self {
        Self { handle }
    }

    pub fn handle(&self) -> &InProcHandle {
        &self.handle
    }
}

#[async_trait]
impl Connection for InProcConnection {
    async fn send(&self, wire: Bytes) -> Result<(), AppError> {
        self.handle.send(wire).await.map_err(|_| AppError::Closed)
    }

    async fn recv(&self) -> Option<Bytes> {
        self.handle.recv().await
    }

    async fn recv_with_meta(&self) -> Option<(Bytes, LpInfo)> {
        let tagged = self.handle.recv_tagged().await?;
        let mut lp = lp_info_from_wire(&tagged.wire);
        // In-process delivery carries the ingress face in the tag-bag (the
        // NFD IncomingFaceIdTag equivalent), not on the bare wire.
        if lp.incoming_face_id.is_none() {
            lp.incoming_face_id = tagged.source_face;
        }
        Some((tagged.wire, lp))
    }

    async fn register_prefix(&self, _prefix: &Name) -> Result<(), AppError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_face_native::local::InProcFace;
    use ndn_packet::encode::DataBuilder;
    use ndn_transport::Transport;

    /// An embedded app reads `incoming_face_id` from the in-process source
    /// tag-bag (the NFD IncomingFaceIdTag equivalent), surfaced via `LpInfo`.
    #[tokio::test]
    async fn in_proc_recv_with_meta_surfaces_source_as_incoming_face_id() {
        let (face, handle) = InProcFace::new(FaceId(7), 4);
        // Engine side delivers a Data tagged with the face it arrived on.
        let data = DataBuilder::new("/m/d", b"x").sign_digest_sha256();
        face.send_bytes_with_source(data, FaceId(42)).await.unwrap();

        let conn = InProcConnection::new(handle);
        let (_wire, lp) = conn.recv_with_meta().await.expect("recv");
        assert_eq!(
            lp.incoming_face_id,
            Some(FaceId(42)),
            "incoming_face_id must reflect the ingress face from the tag-bag"
        );
    }
}
