//! Linux BLE GATT server via `bluer` (BlueZ D-Bus), per-central faces.
//!
//! NOTE: gated to `target_os = "linux"`, so it does not compile on the
//! macOS/Windows dev hosts — verify against `bluer` 0.17 on a Linux build.
//!
//! Per-central de-multiplexing: `bluer` exposes the peer device address on the
//! write request (`CharacteristicWriteIoRequest::device_address`), the read
//! socket (`CharacteristicReader::device_address`) and the notify socket
//! (`CharacteristicWriter::device_address`). We key a registry by `Address`,
//! emit one [`PendingCentral`] per new address, and route reads/writes per
//! central.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use bluer::{
    Address, Session,
    adv::{Advertisement, Type as AdvType},
    gatt::{
        CharacteristicReader, CharacteristicWriter,
        local::{
            Application, Characteristic, CharacteristicControlEvent, CharacteristicNotify,
            CharacteristicNotifyMethod, CharacteristicRead, CharacteristicWrite,
            CharacteristicWriteMethod, Service, characteristic_control,
        },
    },
};
use bytes::Bytes;
use futures::StreamExt;
use ndn_packet::fragment::FRAG_OVERHEAD;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Mutex, mpsc},
};
use tracing::{debug, info, warn};

use super::{
    BLE_CS_CHAR_UUID, BLE_FRAMING_CHAR_UUID, BLE_SC_CHAR_UUID, BLE_SERVICE_UUID, BleError,
    BleFraming, NdntsReassembler, PendingCentral, TxItem,
};

/// ATT protocol overhead per write/notify (1-byte opcode + 2-byte handle).
const ATT_OVERHEAD: usize = 3;

// SC = server→client (notify): forwarder TX. CS = client→server (write): forwarder RX.

pub struct BleServer {
    _app: bluer::gatt::local::ApplicationHandle,
    _adv: bluer::adv::AdvertisementHandle,
    local_addr: String,
}

impl BleServer {
    pub fn local_addr(&self) -> &str {
        &self.local_addr
    }
}

/// Per-connected-central state, keyed by `Address`.
struct CentralState {
    /// Inbound packets from this central → the per-central face.
    in_tx: mpsc::UnboundedSender<Bytes>,
    /// Notify socket for this central; `None` until it subscribes.
    writer: Option<CharacteristicWriter>,
    /// Latched from the first inbound write; mirrored on TX.
    framing: Option<BleFraming>,
}

type Registry = Arc<Mutex<HashMap<Address, CentralState>>>;

/// Ensure a registry entry exists for `addr`; on first sight, emit a
/// [`PendingCentral`] to the listener's accept loop.
async fn ensure_central(
    reg: &Registry,
    addr: Address,
    new_central_tx: &mpsc::UnboundedSender<PendingCentral>,
    tx_sender: &mpsc::UnboundedSender<TxItem>,
) {
    let mut reg = reg.lock().await;
    if reg.contains_key(&addr) {
        return;
    }
    let (in_tx, in_rx) = mpsc::unbounded_channel::<Bytes>();
    reg.insert(
        addr,
        CentralState {
            in_tx,
            writer: None,
            framing: None,
        },
    );
    let _ = new_central_tx.send(PendingCentral {
        key: addr.to_string(),
        peer_uri: format!("ble://{addr}"),
        in_rx,
        tx: tx_sender.clone(),
    });
    debug!(target: "face.system", %addr, "BLE/Linux: new central");
}

pub async fn bind(
    adapter: Option<&str>,
    local_name: Option<&str>,
) -> Result<(Arc<BleServer>, mpsc::UnboundedReceiver<PendingCentral>), BleError> {
    let session = Session::new().await?;
    let names = session.adapter_names().await?;
    let adapter_name = match adapter {
        Some(want) => names
            .into_iter()
            .find(|n| n == want)
            .ok_or(BleError::NoAdapter)?,
        None => names.into_iter().next().ok_or(BleError::NoAdapter)?,
    };
    let adapter = session.adapter(&adapter_name)?;
    adapter.set_powered(true).await?;
    let addr = adapter.address().await?;

    info!(target: "face.system", adapter = %adapter_name, %addr, "BLE/Linux: binding NDN GATT server");

    let svc_uuid: bluer::Uuid = BLE_SERVICE_UUID.parse().unwrap();
    let sc_uuid: bluer::Uuid = BLE_SC_CHAR_UUID.parse().unwrap();
    let cs_uuid: bluer::Uuid = BLE_CS_CHAR_UUID.parse().unwrap();
    let framing_uuid: bluer::Uuid = BLE_FRAMING_CHAR_UUID.parse().unwrap();

    let (sc_ctl, sc_handle) = characteristic_control();
    let (cs_ctl, cs_handle) = characteristic_control();

    // Capability characteristic: read-only, returns this peer's framing byte
    // (NDNLPv2). Its mere presence tells a central we speak NDNLPv2.
    let cap_byte = BleFraming::Ndnlpv2.capability_byte();

    let app = Application {
        services: vec![Service {
            uuid: svc_uuid,
            primary: true,
            characteristics: vec![
                Characteristic {
                    uuid: sc_uuid,
                    notify: Some(CharacteristicNotify {
                        notify: true,
                        method: CharacteristicNotifyMethod::Io,
                        ..Default::default()
                    }),
                    control_handle: sc_handle,
                    ..Default::default()
                },
                Characteristic {
                    uuid: cs_uuid,
                    write: Some(CharacteristicWrite {
                        write_without_response: true,
                        method: CharacteristicWriteMethod::Io,
                        ..Default::default()
                    }),
                    control_handle: cs_handle,
                    ..Default::default()
                },
                Characteristic {
                    uuid: framing_uuid,
                    read: Some(CharacteristicRead {
                        read: true,
                        fun: Box::new(move |_req| Box::pin(async move { Ok(vec![cap_byte]) })),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ],
            ..Default::default()
        }],
        ..Default::default()
    };

    let app_handle = adapter.serve_gatt_application(app).await?;
    let adv_name = local_name
        .map(str::to_owned)
        .unwrap_or_else(|| format!("ndn-rs/{adapter_name}"));
    let adv_handle = adapter
        .advertise(Advertisement {
            advertisement_type: AdvType::Peripheral,
            service_uuids: std::iter::once(svc_uuid).collect(),
            discoverable: Some(true),
            local_name: Some(adv_name),
            ..Default::default()
        })
        .await?;

    let server = Arc::new(BleServer {
        _app: app_handle,
        _adv: adv_handle,
        local_addr: addr.to_string(),
    });

    let (new_central_tx, new_central_rx) = mpsc::unbounded_channel::<PendingCentral>();
    let (tx_sender, mut tx_receiver) = mpsc::unbounded_channel::<TxItem>();
    let registry: Registry = Arc::new(Mutex::new(HashMap::new()));

    // RX: each CS Write event is a per-connection socket; read frames into the
    // originating central's inbound channel. Each ATT write carries one
    // LpPacket (whole or fragment); reassembly happens in the pipeline.
    tokio::spawn({
        let reg = Arc::clone(&registry);
        let new_central_tx = new_central_tx.clone();
        let tx_sender = tx_sender.clone();
        async move {
            futures::pin_mut!(cs_ctl);
            while let Some(evt) = cs_ctl.next().await {
                let CharacteristicControlEvent::Write(req) = evt else {
                    continue;
                };
                let addr = req.device_address();
                let mut reader: CharacteristicReader = match req.accept() {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(target: "face.system", %addr, %e, "BLE/Linux: RX accept failed");
                        continue;
                    }
                };
                ensure_central(&reg, addr, &new_central_tx, &tx_sender).await;
                let in_tx = {
                    let reg = reg.lock().await;
                    reg.get(&addr).map(|s| s.in_tx.clone())
                };
                let Some(in_tx) = in_tx else { continue };
                let reg = Arc::clone(&reg);
                tokio::spawn(async move {
                    let mtu = reader.mtu();
                    let mut buf = vec![0u8; mtu];
                    let mut framing: Option<BleFraming> = None;
                    let mut reasm = NdntsReassembler::new();
                    loop {
                        match reader.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                let raw = &buf[..n];
                                // Latch framing from the first write; record it
                                // in the registry so the TX pump mirrors it.
                                if framing.is_none() {
                                    let f = BleFraming::detect(raw);
                                    framing = Some(f);
                                    if let Some(s) = reg.lock().await.get_mut(&addr) {
                                        s.framing = Some(f);
                                    }
                                }
                                let deliver = match framing {
                                    Some(BleFraming::Ndnts) => reasm.feed(raw),
                                    _ => Some(Bytes::copy_from_slice(raw)),
                                };
                                if let Some(pkt) = deliver
                                    && in_tx.send(pkt).is_err()
                                {
                                    break;
                                }
                            }
                        }
                    }
                    debug!(target: "face.system", %addr, "BLE/Linux: RX socket closed");
                });
            }
        }
    });

    // Notify subscriptions: stash each central's writer for the TX pump.
    tokio::spawn({
        let reg = Arc::clone(&registry);
        let new_central_tx = new_central_tx.clone();
        let tx_sender = tx_sender.clone();
        async move {
            futures::pin_mut!(sc_ctl);
            while let Some(evt) = sc_ctl.next().await {
                let CharacteristicControlEvent::Notify(writer) = evt else {
                    continue;
                };
                let addr = writer.device_address();
                debug!(target: "face.system", %addr, mtu = writer.mtu(), "BLE/Linux: TX subscriber");
                ensure_central(&reg, addr, &new_central_tx, &tx_sender).await;
                if let Some(state) = reg.lock().await.get_mut(&addr) {
                    state.writer = Some(writer);
                }
            }
        }
    });

    // TX pump: fan keyed packets out to the destination central's writer.
    tokio::spawn({
        let reg = Arc::clone(&registry);
        async move {
            let mut frag_seq: u64 = 0;
            while let Some(item) = tx_receiver.recv().await {
                let Ok(addr) = Address::from_str(&item.key) else {
                    continue;
                };
                let mut reg = reg.lock().await;
                let Some(state) = reg.get_mut(&addr) else {
                    continue;
                };
                let framing = state.framing.unwrap_or_default();
                let Some(writer) = state.writer.as_mut() else {
                    continue; // not subscribed yet
                };
                let ble_mtu = writer.mtu().saturating_sub(ATT_OVERHEAD);
                if ble_mtu <= FRAG_OVERHEAD {
                    warn!(target: "face.system", ble_mtu, "BLE/Linux: ATT MTU too small, dropping");
                    continue;
                }
                let frags: Vec<Bytes> = framing.frame(&item.pkt, ble_mtu, &mut frag_seq);
                let mut failed = false;
                for frag in &frags {
                    if writer.write_all(frag).await.is_err() {
                        failed = true;
                        break;
                    }
                }
                if failed {
                    warn!(target: "face.system", %addr, "BLE/Linux: TX notify failed; dropping central");
                    state.writer = None;
                }
            }
        }
    });

    Ok((server, new_central_rx))
}
