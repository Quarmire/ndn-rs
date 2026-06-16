//! BLE GATT *central* face: dials an NDN-BLE peripheral and exchanges
//! Interest/Data over the same NDNts `web-bluetooth-transport` GATT profile the
//! peripheral ([`super::BleFace`]) serves.
//!
//! | Backend | Platform |
//! |---------|----------|
//! | `bluer` (BlueZ) | Linux |
//! | `btleplug` (CoreBluetooth / WinRT) | macOS, Windows |
//!
//! Framing is chosen at connect: the backend reads the peripheral's optional
//! [`BLE_FRAMING_CHAR_UUID`](super::BLE_FRAMING_CHAR_UUID) capability
//! characteristic — present ⇒ [`BleFraming::Ndnlpv2`], absent ⇒
//! [`BleFraming::Ndnts`] (a stock NDNts/esp8266ndn peer) — unless overridden.
//! TX is framed and RX reassembled per the chosen framing.

use bytes::Bytes;
use ndn_transport::{FaceError, FaceId, FaceKind, Transport};
use tokio::sync::{Mutex, mpsc};

use super::{BleError, BleFraming};

#[cfg(target_os = "linux")]
mod bluer_backend;
#[cfg(any(target_os = "macos", target_os = "windows"))]
mod btleplug_backend;

/// Several OS BLE stacks (and Web Bluetooth) don't expose the negotiated ATT
/// MTU, so the central fragments writes at a conservative payload size that
/// fits the >=185-byte MTU modern stacks negotiate. The peripheral reassembles
/// regardless of fragment size.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
const BLE_WRITE_MTU: usize = 244;

/// NDN face that connects to a peripheral as a GATT central.
///
/// Construct with [`BleCentralFace::connect`].
pub struct BleCentralFace {
    id: FaceId,
    remote_uri: String,
    rx: Mutex<mpsc::UnboundedReceiver<Bytes>>,
    tx: mpsc::Sender<Bytes>,
}

impl BleCentralFace {
    /// Connect to the peripheral identified by `target` — a BLE device name or
    /// address. An empty `target` matches the first peripheral advertising the
    /// NDN service UUID. `framing` forces a wire framing (`None` auto-selects
    /// via the capability characteristic); `adapter` selects the local adapter
    /// by name (`None` = default).
    pub async fn connect(
        id: FaceId,
        target: &str,
        framing: Option<BleFraming>,
        adapter: Option<&str>,
    ) -> Result<Self, BleError> {
        #[cfg(target_os = "linux")]
        {
            bluer_backend::connect(id, target, framing, adapter).await
        }
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            btleplug_backend::connect(id, target, framing, adapter).await
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            let _ = (id, target, framing, adapter);
            Err(BleError::NoAdapter)
        }
    }
}

impl Transport for BleCentralFace {
    fn id(&self) -> FaceId {
        self.id
    }

    fn kind(&self) -> FaceKind {
        FaceKind::Bluetooth
    }

    fn remote_uri(&self) -> Option<String> {
        Some(self.remote_uri.clone())
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        self.rx.lock().await.recv().await.ok_or(FaceError::Closed)
    }

    async fn send_bytes(&self, pkt: Bytes) -> Result<(), FaceError> {
        self.tx.send(pkt).await.map_err(|_| FaceError::Closed)
    }
}
