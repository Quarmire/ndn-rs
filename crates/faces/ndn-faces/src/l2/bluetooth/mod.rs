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
//! | Role | Detail |
//! |------|--------|
//! | GATT role | **Server** (forwarder acts as peripheral) |
//! | Service UUID | `099577e3-0788-412a-8824-395084d97391` |
//! | TX characteristic (forwarder → client) | `cc5abb89-a541-46d8-a351-2d95a8a1a374` (Notify) |
//! | RX characteristic (client → forwarder) | `972f9527-0d83-4261-b95d-b7b2a9e5007b` (Write Without Response) |
//!
//! ## Framing
//!
//! Raw NDN TLV packets are sent without LP framing (matching NDNts expectations).
//! If the packet exceeds the negotiated ATT payload size (`att_mtu − 3` bytes),
//! it is fragmented using the NDNts BLE fragmentation scheme:
//!
//! - Small packets that fit in one BLE payload: sent as-is (no header byte).
//! - Fragmented packets: each fragment prefixed with a 1-byte header.
//!   - `0x80 | (seq & 0x7F)` — first fragment; seq is an incrementing counter.
//!   - `seq & 0x7F` — continuation fragment; seq increments per fragment.
//!
//! Reassembly: the receiver buffers fragments until the accumulated bytes form
//! a complete NDN TLV packet (detected by parsing the top-level TLV length).
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
//! - NDNts source: `packages/web-bluetooth-transport`
//! - ESP32 source: `esp8266ndn` library `BleServerTransport`

pub mod framing;
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

// ── GATT UUIDs ────────────────────────────────────────────────────────────────

/// Primary GATT service UUID for the NDN BLE transport.
pub const BLE_SERVICE_UUID: &str = "099577e3-0788-412a-8824-395084d97391";

/// TX characteristic UUID — forwarder notifies client of outgoing NDN packets.
pub const BLE_TX_CHAR_UUID: &str = "cc5abb89-a541-46d8-a351-2d95a8a1a374";

/// RX characteristic UUID — client writes incoming NDN packets to the forwarder.
pub const BLE_RX_CHAR_UUID: &str = "972f9527-0d83-4261-b95d-b7b2a9e5007b";

// ── Constants ─────────────────────────────────────────────────────────────────

/// Depth of the internal TX packet channel (pipeline → BLE notify task).
pub(super) const CHAN_DEPTH: usize = 64;

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors that can occur when binding a [`BleFace`].
#[derive(Debug, thiserror::Error)]
pub enum BleError {
    /// BlueZ D-Bus or GATT error from the `bluer` crate (Linux only).
    #[cfg(target_os = "linux")]
    #[error("BlueZ error: {0}")]
    Bluer(#[from] bluer::Error),
    /// No Bluetooth adapter was found on this system.
    #[error("no Bluetooth adapter available")]
    NoAdapter,
    /// BLE face is already bound (macOS: only one per process is supported).
    #[cfg(target_os = "macos")]
    #[error("BLE already bound; only one BleFace per process is supported on macOS")]
    AlreadyBound,
}

// ── BleFace ───────────────────────────────────────────────────────────────────

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

    /// Enqueue a packet for BLE transmission.
    ///
    /// Applies back-pressure: awaits if the TX queue is full (64 slots).
    /// Returns [`FaceError::Closed`] if the background TX task has exited.
    async fn send(&self, pkt: Bytes) -> Result<(), FaceError> {
        self.tx.send(pkt).await.map_err(|_| FaceError::Closed)
    }
}
