//! BLE face implementing the NDNts `@ndn/web-bluetooth-transport` protocol.
//!
//! # Protocol specification
//!
//! This face implements the same BLE GATT profile as the NDNts
//! `@ndn/web-bluetooth-transport` package and the ESP32 `esp8266ndn`
//! `BleServerTransport`, making it interoperable with web browsers (via the
//! Web Bluetooth API) and ESP32/Arduino devices.
//!
//! ## GATT profile
//!
//! UUIDs and direction assignments match NDNts
//! [`@ndn/web-bluetooth-transport`](https://github.com/yoursunny/NDNts/blob/main/pkg/web-bluetooth-transport/src/web-bluetooth-transport.ts)
//! and esp8266ndn
//! [`ble-uuid.hpp`](https://github.com/yoursunny/esp8266ndn/blob/main/src/transport/ble-uuid.hpp)
//! exactly.
//!
//! | Role | Detail |
//! |------|--------|
//! | GATT role | **Server** (forwarder acts as peripheral) |
//! | Service UUID | `099577e3-0788-412a-8824-395084d97391` |
//! | CS characteristic (client → server = client → forwarder) | `cc5abb89-a541-46d8-a351-2f95a6a81f49` (Write Without Response) |
//! | SC characteristic (server → client = forwarder → client) | `972f9527-0d83-4261-b95d-b1b2fc73bde4` (Notify) |
//!
//! ## Framing
//!
//! The NDN-BLE protocol itself does not define a fragmentation scheme — as
//! stated in the NDNts README, "it can be used with existing NDN fragmentation
//! schemes such as NDNLPv2." ndn-rs therefore uses NDNLPv2 fragmentation at
//! the Face layer (the same code path used by UDP, multicast, and Ethernet
//! faces). Each BLE ATT write carries exactly one LpPacket, which is either
//! a whole Interest/Data wrapped in an LpPacket envelope or one fragment of
//! a multi-fragment LpPacket.
//!
//! Reassembly is handled by the pipeline's `TlvDecodeStage` via its per-face
//! `ReassemblyBuffer`, so this module has no local fragment state.
//!
//! The BLE ATT MTU must be negotiated high enough to fit at least the NDNLPv2
//! fragment overhead (~50 bytes plus ATT/HCI headers); the default 23-byte
//! MTU is **not** usable. Modern BLE stacks (Web Bluetooth, BlueZ ≥5.48,
//! CoreBluetooth on iOS/macOS, NimBLE on ESP32) negotiate 185+ bytes
//! automatically.
//!
//! ## Platform support
//!
//! | Platform | Backend |
//! |----------|---------|
//! | Linux | BlueZ via `bluer` (D-Bus) |
//! | macOS | CoreBluetooth via `objc2` (`CBPeripheralManager`) |
//!
//! # References
//!
//! - NDNts source: `pkg/web-bluetooth-transport` in yoursunny/NDNts
//! - ESP32 source: `esp8266ndn` library `BleServerTransport`

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

use std::sync::Arc;

use bytes::Bytes;
use ndn_transport::{Face, FaceError, FaceId, FaceKind};
use tokio::sync::{Mutex, mpsc};

#[cfg(target_os = "linux")]
use linux::BleServer;
#[cfg(target_os = "macos")]
use macos::BleServer;

// Must match NDNts and esp8266ndn exactly (see module-level docs).

pub const BLE_SERVICE_UUID: &str = "099577e3-0788-412a-8824-395084d97391";
/// CS (client -> server) — Write Without Response.
pub const BLE_CS_CHAR_UUID: &str = "cc5abb89-a541-46d8-a351-2f95a6a81f49";
/// SC (server -> client) — Notify.
pub const BLE_SC_CHAR_UUID: &str = "972f9527-0d83-4261-b95d-b1b2fc73bde4";

pub(super) const CHAN_DEPTH: usize = 64;

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
}


/// NDN face over Bluetooth LE using the NDNts `@ndn/web-bluetooth-transport`
/// GATT profile.
///
/// Interoperable with:
/// - Web browsers via the Web Bluetooth API + NDNts
/// - ESP32 devices running `esp8266ndn` `BleServerTransport`
///
/// # Usage
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use ndn_faces::l2::BleFace;
/// use ndn_transport::FaceId;
///
/// let face = BleFace::bind(FaceId::new(10)).await?;
/// # Ok(())
/// # }
/// ```
pub struct BleFace {
    id: FaceId,
    local_uri: String,
    /// Incoming NDN packets from the platform RX path.
    rx: Mutex<mpsc::UnboundedReceiver<Bytes>>,
    /// Outgoing NDN packets sent to the platform TX task.
    tx: mpsc::Sender<Bytes>,
    /// Keeps the GATT server and advertisement alive for `self`'s lifetime.
    _server: Arc<BleServer>,
}

impl BleFace {
    /// Bind a BLE GATT server on the system's default Bluetooth adapter and
    /// return a ready-to-use [`BleFace`].
    ///
    /// On Linux this uses BlueZ via the `bluer` crate.
    /// On macOS this uses `CBPeripheralManager` via CoreBluetooth.
    pub async fn bind(id: FaceId) -> Result<Self, BleError> {
        #[cfg(target_os = "linux")]
        return linux::bind(id).await;
        #[cfg(target_os = "macos")]
        return macos::bind(id).await;
    }
}

impl Face for BleFace {
    fn id(&self) -> FaceId {
        self.id
    }

    fn kind(&self) -> FaceKind {
        FaceKind::Bluetooth
    }

    fn local_uri(&self) -> Option<String> {
        Some(self.local_uri.clone())
    }

    async fn recv(&self) -> Result<Bytes, FaceError> {
        self.rx.lock().await.recv().await.ok_or(FaceError::Closed)
    }

    async fn send(&self, pkt: Bytes) -> Result<(), FaceError> {
        self.tx.send(pkt).await.map_err(|_| FaceError::Closed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression guard for NDNts / esp8266ndn UUID interoperability.
    ///
    /// These values are copied verbatim from the upstream sources referenced
    /// in the module docs. If this test ever fails, ndn-rs is on the wrong
    /// side of the wire.
    #[test]
    fn gatt_uuids_match_ndnts_and_esp8266ndn() {
        assert_eq!(BLE_SERVICE_UUID, "099577e3-0788-412a-8824-395084d97391");
        // NDNts CS = client→server (write-without-response)
        assert_eq!(BLE_CS_CHAR_UUID, "cc5abb89-a541-46d8-a351-2f95a6a81f49");
        // NDNts SC = server→client (notify)
        assert_eq!(BLE_SC_CHAR_UUID, "972f9527-0d83-4261-b95d-b1b2fc73bde4");
    }

    /// End-to-end wire-format regression for the BLE face's interop contract.
    ///
    /// The BLE face performs no local framing — outgoing packets take the
    /// same path as other network faces (`encode_lp_packet` for small,
    /// `fragment_packet` for oversized), and incoming BLE writes are handed
    /// up raw to the pipeline's `TlvDecodeStage` which reassembles via
    /// `ReassemblyBuffer`. This test exercises that exact path.
    #[test]
    fn oversized_packet_roundtrips_via_ndnlpv2() {
        use ndn_packet::fragment::{ReassemblyBuffer, fragment_packet};
        use ndn_packet::lp::LpPacket;

        // Representative "realistic" BLE ATT MTU after negotiation. NDNts over
        // Web Bluetooth on Android negotiates 517; on iOS, 185+. We pick a
        // conservative value that still requires fragmentation for typical
        // NDN Data packets.
        let ble_mtu: usize = 185 - 3; // minus ATT overhead

        // A ~4 KB NDN Data-ish packet. Must exceed ble_mtu so that
        // fragmentation is exercised (not just the encode_lp_packet branch).
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

        // Simulate the RX side: each "BLE write" is one LpPacket fragment,
        // handed to the decode/reassembly path.
        let mut buf = ReassemblyBuffer::default();
        let mut result: Option<Bytes> = None;
        for frag_bytes in &fragments {
            let lp = LpPacket::decode(frag_bytes.clone()).expect("decode LpPacket");
            assert!(lp.is_fragmented());
            let base_seq = lp.sequence.unwrap() - lp.frag_index.unwrap();
            result = buf.process(
                base_seq,
                lp.frag_index.unwrap(),
                lp.frag_count.unwrap(),
                lp.fragment.unwrap(),
            );
        }

        let reassembled = result.expect("all fragments delivered");
        assert_eq!(
            reassembled.as_ref(),
            &original[..],
            "reassembled bytes must equal the original packet"
        );
    }

    /// A packet that fits inside one LpPacket envelope must NOT get
    /// fragmented — the BLE face sends it as a single ATT write. Round-trip
    /// through `encode_lp_packet` + `LpPacket::decode`.
    #[test]
    fn small_packet_single_lp_envelope() {
        use ndn_packet::lp::{LpPacket, encode_lp_packet};

        // 50-byte payload — comfortably fits in a single LpPacket at any
        // negotiated BLE MTU.
        let payload: Vec<u8> = (0..50).map(|i| i as u8).collect();
        let wire = encode_lp_packet(&payload);
        let lp = LpPacket::decode(wire).expect("decode small LpPacket");
        assert!(!lp.is_fragmented(), "small packet should not be fragmented");
        assert_eq!(lp.fragment.as_deref(), Some(&payload[..]));
    }
}
