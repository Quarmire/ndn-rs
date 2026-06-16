//! Linux BLE central via `bluer` (BlueZ D-Bus).
//!
//! NOTE: this backend is gated to `target_os = "linux"`, so it is not
//! compiled on the macOS/Windows dev hosts — verify against the pinned `bluer`
//! 0.17 API on a Linux build.

use std::time::Duration;

use bluer::gatt::WriteOp;
use bluer::gatt::remote::CharacteristicWriteRequest;
use bluer::{AdapterEvent, Session};
use bytes::Bytes;
use futures::StreamExt;
use tokio::sync::{Mutex, mpsc};
use tokio::time::timeout;
use tracing::{debug, warn};

use ndn_transport::FaceId;

use super::super::{
    BLE_CS_CHAR_UUID, BLE_FRAMING_CHAR_UUID, BLE_SC_CHAR_UUID, BLE_SERVICE_UUID, BleError,
    BleFraming, CHAN_DEPTH, NdntsReassembler,
};
use super::{BLE_WRITE_MTU, BleCentralFace};

pub async fn connect(
    id: FaceId,
    target: &str,
    framing_override: Option<BleFraming>,
    adapter_sel: Option<&str>,
) -> Result<BleCentralFace, BleError> {
    let svc_uuid: bluer::Uuid = BLE_SERVICE_UUID.parse().expect("valid service UUID");
    let cs_uuid: bluer::Uuid = BLE_CS_CHAR_UUID.parse().expect("valid CS UUID");
    let sc_uuid: bluer::Uuid = BLE_SC_CHAR_UUID.parse().expect("valid SC UUID");
    let framing_uuid: bluer::Uuid = BLE_FRAMING_CHAR_UUID.parse().expect("valid framing UUID");

    let session = Session::new().await?;
    let adapter = match adapter_sel {
        Some(name) => session.adapter(name)?,
        None => session.default_adapter().await?,
    };
    adapter.set_powered(true).await?;

    // Scan until a device matching `target` (name or address), advertising the
    // NDN service, shows up — or ~10s elapses.
    // `discover_devices()` is `!Unpin`; box-pin so `.next()` is valid.
    let mut events = Box::pin(adapter.discover_devices().await?);
    let device = timeout(Duration::from_secs(10), async {
        while let Some(evt) = events.next().await {
            let AdapterEvent::DeviceAdded(addr) = evt else {
                continue;
            };
            let Ok(dev) = adapter.device(addr) else {
                continue;
            };
            let name = dev.name().await.ok().flatten().unwrap_or_default();
            let uuids = dev.uuids().await.ok().flatten().unwrap_or_default();
            let addr_str = addr.to_string();
            let target_match = target.is_empty()
                || name.eq_ignore_ascii_case(target)
                || addr_str.eq_ignore_ascii_case(target);
            if target_match && uuids.contains(&svc_uuid) {
                return Some(dev);
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
    .ok_or_else(|| BleError::NotFound(target.to_string()))?;

    device.connect().await?;

    // Locate CS/SC (and optional framing) characteristics inside the service.
    let mut cs_char = None;
    let mut sc_char = None;
    let mut framing_char = None;
    for service in device.services().await? {
        if service.uuid().await? != svc_uuid {
            continue;
        }
        for ch in service.characteristics().await? {
            let u = ch.uuid().await?;
            if u == cs_uuid {
                cs_char = Some(ch);
            } else if u == sc_uuid {
                sc_char = Some(ch);
            } else if u == framing_uuid {
                framing_char = Some(ch);
            }
        }
    }
    let cs_char = cs_char.ok_or_else(|| BleError::Central("CS characteristic not found".into()))?;
    let sc_char = sc_char.ok_or_else(|| BleError::Central("SC characteristic not found".into()))?;

    // Pick framing: override, else the capability characteristic (present ⇒
    // NDNLPv2; absent ⇒ stock NDNts peer).
    let framing = match framing_override {
        Some(f) => f,
        None => match framing_char {
            Some(ch) => ch
                .read()
                .await
                .ok()
                .and_then(|v| v.first().copied())
                .map(BleFraming::from_capability_byte)
                .unwrap_or(BleFraming::Ndnlpv2),
            None => BleFraming::Ndnts,
        },
    };
    debug!(target: "face.ble-central", ?framing, "selected BLE framing");

    // `bluer`'s notify stream is `!Unpin`; box-pin it so `.next()` is valid
    // inside the `select!` and the (Unpin) handle moves into the spawned task.
    let mut notify = Box::pin(sc_char.notify().await?);

    let name = device.name().await.ok().flatten();
    let addr = device.address();
    let remote_uri = format!("ble://{}", name.unwrap_or_else(|| addr.to_string()));

    let (tx_app, mut rx_out) = mpsc::channel::<Bytes>(CHAN_DEPTH);
    let (tx_in, rx_in) = mpsc::unbounded_channel::<Bytes>();

    tokio::spawn(async move {
        let mut seq: u64 = 0;
        let mut reasm = NdntsReassembler::new();
        loop {
            tokio::select! {
                outgoing = rx_out.recv() => {
                    let Some(pkt) = outgoing else { break };
                    for frag in framing.frame(&pkt, BLE_WRITE_MTU, &mut seq) {
                        let req = CharacteristicWriteRequest {
                            op_type: WriteOp::Command,
                            ..Default::default()
                        };
                        if let Err(e) = cs_char.write_ext(&frag, &req).await {
                            warn!(target: "face.ble-central", error = %e, "CS write failed; closing");
                            let _ = device.disconnect().await;
                            return;
                        }
                    }
                }
                note = notify.next() => {
                    match note {
                        Some(value) => {
                            let deliver = match framing {
                                BleFraming::Ndnlpv2 => Some(Bytes::from(value)),
                                BleFraming::Ndnts => reasm.feed(&value),
                            };
                            if let Some(pkt) = deliver
                                && tx_in.send(pkt).is_err()
                            {
                                break;
                            }
                        }
                        None => {
                            debug!(target: "face.ble-central", "notify stream ended");
                            break;
                        }
                    }
                }
            }
        }
        let _ = device.disconnect().await;
    });

    Ok(BleCentralFace {
        id,
        remote_uri,
        rx: Mutex::new(rx_in),
        tx: tx_app,
    })
}
