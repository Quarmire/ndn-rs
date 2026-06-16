//! BLE face using the NDNts `@ndn/web-bluetooth-transport` GATT **profile**
//! (the service + characteristic UUIDs below). It shares those UUIDs with
//! browsers (Web Bluetooth) and `esp8266ndn`'s `BleServerTransport`, so device
//! discovery and connect interoperate.
//!
//! | Role | Detail |
//! |------|--------|
//! | GATT role | Server (forwarder is peripheral) |
//! | Service UUID | `099577e3-0788-412a-8824-395084d97391` |
//! | CS (client→server) | `cc5abb89-a541-46d8-a351-2f95a6a81f49` (Write Without Response) |
//! | SC (server→client) | `972f9527-0d83-4261-b95d-b1b2fc73bde4` (Notify) |
//!
//! ## Profile vs. framing — two different things
//!
//! The GATT *profile* (UUIDs) is shared, but the *framing* over the
//! characteristics is not universal. There are two framings on this profile:
//!
//! - **NDNLPv2** — what ndn-rs uses (`BleFace`, [`BleCentralFace`], and
//!   the `ndn-face-webble` browser central). Each ATT write carries one
//!   `LpPacket`; reassembly happens in the pipeline's `ReassemblyBuffer`, the
//!   same code path as UDP/Ethernet.
//! - **NDNts 1-byte header** — what stock NDNts `@ndn/web-bluetooth-transport`
//!   and `esp8266ndn` use (first fragment `0x80 | seq`, continuations
//!   `seq & 0x7F`, unfragmented packets have no header). See
//!   `ndn_boltffi::codec::ndnts_frame`.
//!
//! These are **not** wire-compatible with each other despite the shared UUIDs:
//! an ndn-rs face talks to other ndn-rs faces (and NDNLPv2 clients such as the
//! boltffi mobile apps in NDNLPv2 mode), but reaching a stock NDNts/esp8266ndn
//! peer requires emitting the 1-byte framing, which the native faces do not do
//! today. The default 23-byte ATT MTU is too small for either; modern stacks
//! negotiate >=185 automatically.
//!
//! Backends: Linux via `bluer` (BlueZ), macOS via `objc2`
//! (`CBPeripheralManager`).

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

mod central;
pub use central::BleCentralFace;

mod framing;
pub use framing::{BleFraming, NdntsReassembler};

// Peripheral (GATT server) is Linux/macOS only; the central role below also
// builds on Windows via btleplug.
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::sync::Arc;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use bytes::Bytes;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use ndn_transport::{FaceError, FaceId, FaceKind, Transport};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use tokio::sync::{Mutex, mpsc};

#[cfg(target_os = "linux")]
use linux::BleServer;
#[cfg(target_os = "macos")]
use macos::BleServer;

// Must match NDNts and esp8266ndn exactly (see module-level docs).
pub const BLE_SERVICE_UUID: &str = "099577e3-0788-412a-8824-395084d97391";
pub const BLE_CS_CHAR_UUID: &str = "cc5abb89-a541-46d8-a351-2f95a6a81f49";
pub const BLE_SC_CHAR_UUID: &str = "972f9527-0d83-4261-b95d-b1b2fc73bde4";
/// ndn-rs **extension** characteristic (read-only): its presence tells a
/// connecting central this peer speaks NDNLPv2; its value is a
/// [`BleFraming::capability_byte`]. Stock NDNts/esp8266ndn peers don't expose
/// it, so its absence means NDNts. Namespaced under the service UUID prefix.
pub const BLE_FRAMING_CHAR_UUID: &str = "099577e3-0788-412a-8824-395084d97392";

pub(super) const CHAN_DEPTH: usize = 64;

/// Identifies one connected central within a peripheral's GATT server:
/// the BlueZ device address (Linux) or the `CBCentral.identifier` (macOS).
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) type CentralKey = String;

/// Outbound packet tagged with the central it is destined for. The backend's
/// single TX pump fans these out to the right central.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) struct TxItem {
    pub key: CentralKey,
    pub pkt: Bytes,
}

/// A newly connected central, handed to [`BleListener::accept`] which stamps a
/// [`FaceId`] and builds the per-central [`BleFace`]. The backend keeps the
/// matching inbound sender and TX-pump endpoint alive in its registry.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) struct PendingCentral {
    pub key: CentralKey,
    pub peer_uri: String,
    /// Inbound packets from this central (backend → face).
    pub in_rx: mpsc::UnboundedReceiver<Bytes>,
    /// Outbound endpoint into the backend's keyed TX pump (face → backend).
    pub tx: mpsc::UnboundedSender<TxItem>,
}

#[derive(Debug, thiserror::Error)]
pub enum BleError {
    #[cfg(target_os = "linux")]
    #[error("BlueZ error: {0}")]
    Bluer(#[from] bluer::Error),
    #[error("no Bluetooth adapter available")]
    NoAdapter,
    #[cfg(target_os = "macos")]
    #[error("BLE already bound; only one BleFace per process is supported on macOS")]
    AlreadyBound,
    /// No peripheral matched the requested name/address (central).
    #[error("peripheral not found: {0}")]
    NotFound(String),
    /// Backend error while operating as a central (btleplug / bluer GATT client).
    #[error("BLE central: {0}")]
    Central(String),
    /// The peripheral listener's GATT server shut down; no more centrals.
    #[error("BLE listener closed")]
    ListenerClosed,
}

/// One NDN face over Bluetooth LE, representing a **single connected central**
/// of the local GATT server (peripheral). Created by [`BleListener::accept`],
/// not directly. Linux/macOS only — for the central (client) role, including
/// Windows, use [`BleCentralFace`].
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub struct BleFace {
    id: FaceId,
    local_uri: String,
    remote_uri: String,
    key: CentralKey,
    rx: Mutex<mpsc::UnboundedReceiver<Bytes>>,
    tx: mpsc::UnboundedSender<TxItem>,
    /// Keeps the shared GATT server alive while any per-central face lives.
    _server: Arc<BleServer>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Transport for BleFace {
    fn id(&self) -> FaceId {
        self.id
    }

    fn kind(&self) -> FaceKind {
        FaceKind::Bluetooth
    }

    fn local_uri(&self) -> Option<String> {
        Some(self.local_uri.clone())
    }

    fn remote_uri(&self) -> Option<String> {
        Some(self.remote_uri.clone())
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        self.rx.lock().await.recv().await.ok_or(FaceError::Closed)
    }

    async fn send_bytes(&self, pkt: Bytes) -> Result<(), FaceError> {
        self.tx
            .send(TxItem {
                key: self.key.clone(),
                pkt,
            })
            .map_err(|_| FaceError::Closed)
    }
}

/// GATT-server (peripheral) **listener**: binds the local adapter, advertises
/// the NDN service, and yields one [`BleFace`] per connected central via
/// [`accept`](BleListener::accept) — the NFD-style listener/channel model the
/// forwarder drives in an accept loop.
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use ndn_face::l2::BleListener;
/// use ndn_transport::FaceId;
///
/// let mut listener = BleListener::bind(None, None).await?; // advertises immediately
/// loop {
///     let face = listener.accept(FaceId(0)).await?; // one face per central
///     // engine.add_face(face, …);
/// }
/// # }
/// ```
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub struct BleListener {
    server: Arc<BleServer>,
    new_central_rx: mpsc::UnboundedReceiver<PendingCentral>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl BleListener {
    /// Bind an adapter and begin advertising the NDN service. `adapter` selects
    /// the BlueZ adapter by name on Linux (`None` = default; ignored on macOS);
    /// `local_name` overrides the advertised name (`None` = default `ndn-rs`).
    pub async fn bind(adapter: Option<&str>, local_name: Option<&str>) -> Result<Self, BleError> {
        #[cfg(target_os = "linux")]
        let (server, new_central_rx) = linux::bind(adapter, local_name).await?;
        #[cfg(target_os = "macos")]
        let (server, new_central_rx) = macos::bind(adapter, local_name).await?;
        Ok(Self {
            server,
            new_central_rx,
        })
    }

    /// Await the next central to connect and return it as a face stamped with
    /// `id`. Resolves once per connecting central; returns
    /// [`BleError::ListenerClosed`] if the server has shut down.
    pub async fn accept(&mut self, id: FaceId) -> Result<BleFace, BleError> {
        let pending = self
            .new_central_rx
            .recv()
            .await
            .ok_or(BleError::ListenerClosed)?;
        Ok(BleFace {
            id,
            local_uri: format!("ble://{}", self.server.local_addr()),
            remote_uri: pending.peer_uri,
            key: pending.key,
            rx: Mutex::new(pending.in_rx),
            tx: pending.tx,
            _server: Arc::clone(&self.server),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Verbatim from NDNts / esp8266ndn upstream; failure means we're off-wire.
    #[test]
    fn gatt_uuids_match_ndnts_and_esp8266ndn() {
        assert_eq!(BLE_SERVICE_UUID, "099577e3-0788-412a-8824-395084d97391");
        assert_eq!(BLE_CS_CHAR_UUID, "cc5abb89-a541-46d8-a351-2f95a6a81f49");
        assert_eq!(BLE_SC_CHAR_UUID, "972f9527-0d83-4261-b95d-b1b2fc73bde4");
    }

    #[test]
    fn oversized_packet_roundtrips_via_ndnlpv2() {
        use ndn_packet::fragment::{ReassemblyBuffer, fragment_packet};
        use ndn_packet::lp::LpPacket;

        // NDNts negotiates 517 on Android, 185+ on iOS; pick a conservative
        // value that still forces fragmentation for typical Data packets.
        let ble_mtu: usize = 185 - 3;

        let original: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        let original_bytes = Bytes::copy_from_slice(&original);

        let fragments = fragment_packet(&original_bytes, ble_mtu, 7);
        assert!(
            fragments.len() > 1,
            "test precondition: packet must be fragmented"
        );
        for (i, f) in fragments.iter().enumerate() {
            assert!(
                f.len() <= ble_mtu,
                "fragment {i} is {} bytes, exceeds BLE MTU {}",
                f.len(),
                ble_mtu
            );
        }

        let mut buf = ReassemblyBuffer::default();
        let mut result: Option<Bytes> = None;
        for frag_bytes in &fragments {
            let lp = LpPacket::decode(frag_bytes.clone()).expect("decode LpPacket");
            assert!(lp.is_fragmented());
            let base_seq = lp.sequence.unwrap() - lp.frag_index.unwrap();
            result = buf.process(
                0,
                base_seq,
                lp.frag_index.unwrap(),
                lp.frag_count.unwrap(),
                lp.fragment.unwrap(),
            );
        }

        let reassembled = result.expect("all fragments delivered");
        assert_eq!(reassembled.as_ref(), &original[..]);
    }

    #[test]
    fn small_packet_single_lp_envelope() {
        use ndn_packet::lp::{LpPacket, encode_lp_packet};

        let payload: Vec<u8> = (0..50).map(|i| i as u8).collect();
        let wire = encode_lp_packet(&payload);
        let lp = LpPacket::decode(wire).expect("decode small LpPacket");
        assert!(!lp.is_fragmented(), "small packet should not be fragmented");
        assert_eq!(lp.fragment.as_deref(), Some(&payload[..]));
    }
}
