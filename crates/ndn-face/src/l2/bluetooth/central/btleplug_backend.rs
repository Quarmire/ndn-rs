//! macOS / Windows BLE central via `btleplug` (CoreBluetooth / WinRT).

use std::time::Duration;

use btleplug::api::{Central, Manager as _, Peripheral as _, ScanFilter, WriteType};
use btleplug::platform::Manager;
use bytes::Bytes;
use futures::StreamExt;
use tokio::sync::{Mutex, mpsc};
use tokio::time::sleep;
use tracing::{debug, warn};
use uuid::Uuid;

use ndn_transport::FaceId;

use super::super::{
    BLE_CS_CHAR_UUID, BLE_FRAMING_CHAR_UUID, BLE_SC_CHAR_UUID, BLE_SERVICE_UUID, BleError,
    BleFraming, CHAN_DEPTH, NdntsReassembler,
};
use super::{BLE_WRITE_MTU, BleCentralFace};

fn err<E: std::fmt::Display>(e: E) -> BleError {
    BleError::Central(e.to_string())
}

pub async fn connect(
    id: FaceId,
    target: &str,
    framing_override: Option<BleFraming>,
    adapter_sel: Option<&str>,
) -> Result<BleCentralFace, BleError> {
    let service_uuid = Uuid::parse_str(BLE_SERVICE_UUID).expect("valid service UUID");
    let cs_uuid = Uuid::parse_str(BLE_CS_CHAR_UUID).expect("valid CS UUID");
    let sc_uuid = Uuid::parse_str(BLE_SC_CHAR_UUID).expect("valid SC UUID");
    let framing_uuid = Uuid::parse_str(BLE_FRAMING_CHAR_UUID).expect("valid framing UUID");

    let manager = Manager::new().await.map_err(err)?;
    let adapters = manager.adapters().await.map_err(err)?;
    // Select by adapter_info substring when requested, else the first adapter.
    let adapter = match adapter_sel {
        Some(want) => {
            let mut chosen = None;
            for a in adapters {
                if a.adapter_info().await.is_ok_and(|i| i.contains(want)) {
                    chosen = Some(a);
                    break;
                }
            }
            chosen.ok_or(BleError::NoAdapter)?
        }
        None => adapters.into_iter().next().ok_or(BleError::NoAdapter)?,
    };

    adapter
        .start_scan(ScanFilter {
            services: vec![service_uuid],
        })
        .await
        .map_err(err)?;

    // Poll discovered peripherals for ~10s for one matching `target`.
    let peripheral = {
        let mut found = None;
        'outer: for _ in 0..50 {
            for p in adapter.peripherals().await.map_err(err)? {
                let props = p.properties().await.ok().flatten();
                let name = props
                    .as_ref()
                    .and_then(|pr| pr.local_name.clone())
                    .unwrap_or_default();
                let addr = p.address().to_string();
                let matches = target.is_empty()
                    || name.eq_ignore_ascii_case(target)
                    || addr.eq_ignore_ascii_case(target);
                if matches {
                    found = Some(p);
                    break 'outer;
                }
            }
            sleep(Duration::from_millis(200)).await;
        }
        found.ok_or_else(|| BleError::NotFound(target.to_string()))?
    };
    let _ = adapter.stop_scan().await;

    peripheral.connect().await.map_err(err)?;
    peripheral.discover_services().await.map_err(err)?;

    let chars = peripheral.characteristics();
    let cs_char = chars
        .iter()
        .find(|c| c.uuid == cs_uuid)
        .cloned()
        .ok_or_else(|| BleError::Central("CS characteristic not found".into()))?;
    let sc_char = chars
        .iter()
        .find(|c| c.uuid == sc_uuid)
        .cloned()
        .ok_or_else(|| BleError::Central("SC characteristic not found".into()))?;

    // Pick framing: explicit override, else read the capability characteristic
    // (present ⇒ NDNLPv2; absent ⇒ stock NDNts peer).
    let framing = match framing_override {
        Some(f) => f,
        None => match chars.iter().find(|c| c.uuid == framing_uuid).cloned() {
            Some(cap_char) => peripheral
                .read(&cap_char)
                .await
                .ok()
                .and_then(|v| v.first().copied())
                .map(BleFraming::from_capability_byte)
                .unwrap_or(BleFraming::Ndnlpv2),
            None => BleFraming::Ndnts,
        },
    };
    debug!(target: "face.ble-central", ?framing, "selected BLE framing");

    peripheral.subscribe(&sc_char).await.map_err(err)?;
    let mut notifications = peripheral.notifications().await.map_err(err)?;

    let name = peripheral
        .properties()
        .await
        .ok()
        .flatten()
        .and_then(|p| p.local_name)
        .unwrap_or_else(|| peripheral.address().to_string());
    let remote_uri = format!("ble://{name}");

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
                        if let Err(e) =
                            peripheral.write(&cs_char, &frag, WriteType::WithoutResponse).await
                        {
                            warn!(target: "face.ble-central", error = %e, "CS write failed; closing");
                            let _ = peripheral.disconnect().await;
                            return;
                        }
                    }
                }
                note = notifications.next() => {
                    match note {
                        Some(n) if n.uuid == sc_uuid => {
                            // NDNLPv2 passes raw (pipeline reassembles); NDNts is
                            // reassembled here into complete packets.
                            let deliver = match framing {
                                BleFraming::Ndnlpv2 => Some(Bytes::from(n.value)),
                                BleFraming::Ndnts => reasm.feed(&n.value),
                            };
                            if let Some(pkt) = deliver
                                && tx_in.send(pkt).is_err()
                            {
                                break;
                            }
                        }
                        Some(_) => {}
                        None => {
                            debug!(target: "face.ble-central", "notification stream ended");
                            break;
                        }
                    }
                }
            }
        }
        let _ = peripheral.disconnect().await;
    });

    Ok(BleCentralFace {
        id,
        remote_uri,
        rx: Mutex::new(rx_in),
        tx: tx_app,
    })
}
