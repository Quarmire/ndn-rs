//! Linux BLE GATT server via `bluer` (BlueZ D-Bus).

use std::sync::Arc;

use bluer::{
    Session,
    adv::{Advertisement, Type as AdvType},
    gatt::{
        CharacteristicWriter,
        local::{
            Application, Characteristic, CharacteristicControlEvent, CharacteristicNotify,
            CharacteristicNotifyMethod, CharacteristicWrite, CharacteristicWriteMethod, Service,
            characteristic_control,
        },
    },
};
use bytes::Bytes;
use futures::StreamExt;
use ndn_packet::fragment::{FRAG_OVERHEAD, fragment_packet};
use ndn_packet::lp::{encode_lp_packet, is_lp_packet};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Mutex, mpsc},
};
use tracing::{debug, info, warn};

use super::{BLE_CS_CHAR_UUID, BLE_SC_CHAR_UUID, BLE_SERVICE_UUID, BleError, BleFace, CHAN_DEPTH};

/// ATT protocol overhead per write/notify (1-byte opcode + 2-byte handle).
const ATT_OVERHEAD: usize = 3;

// ── Server handle (keeps GATT app + advertisement alive) ─────────────────────

pub struct BleServer {
    _app: bluer::gatt::local::ApplicationHandle,
    _adv: bluer::adv::AdvertisementHandle,
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn bind(id: ndn_transport::FaceId) -> Result<BleFace, BleError> {
    let session = Session::new().await?;
    let adapter_names = session.adapter_names().await?;
    let adapter_name = adapter_names
        .into_iter()
        .next()
        .ok_or(BleError::NoAdapter)?;
    let adapter = session.adapter(&adapter_name)?;
    adapter.set_powered(true).await?;
    let addr = adapter.address().await?;

    info!(adapter = %adapter_name, %addr, "BLE/Linux: binding NDN GATT server");

    let svc_uuid: bluer::Uuid = BLE_SERVICE_UUID.parse().unwrap();
    // SC = server → client (notify) — the forwarder sends out on this characteristic.
    let sc_uuid: bluer::Uuid = BLE_SC_CHAR_UUID.parse().unwrap();
    // CS = client → server (write) — the forwarder receives on this characteristic.
    let cs_uuid: bluer::Uuid = BLE_CS_CHAR_UUID.parse().unwrap();

    let (sc_ctl, sc_handle) = characteristic_control();
    let (cs_ctl, cs_handle) = characteristic_control();

    let app = Application {
        services: vec![Service {
            uuid: svc_uuid,
            primary: true,
            characteristics: vec![
                // SC: server → client (Notify) — forwarder TX
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
                // CS: client → server (Write Without Response) — forwarder RX
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
            ],
            ..Default::default()
        }],
        // `Application` carries a private `_non_exhaustive` marker in
        // bluer ≥0.17; `..Default::default()` fills it in.
        ..Default::default()
    };

    let app_handle = adapter.serve_gatt_application(app).await?;
    let adv_handle = adapter
        .advertise(Advertisement {
            advertisement_type: AdvType::Peripheral,
            service_uuids: std::iter::once(svc_uuid).collect(),
            discoverable: Some(true),
            local_name: Some(format!("ndn-rs/{adapter_name}")),
            ..Default::default()
        })
        .await?;

    let server = Arc::new(BleServer {
        _app: app_handle,
        _adv: adv_handle,
    });
    let local_uri = format!("ble://{addr}");

    // RX: unbounded so GCD/background threads can send without blocking.
    let (rx_tx, rx_rx) = mpsc::unbounded_channel::<Bytes>();
    // TX: bounded for back-pressure from the pipeline.
    let (tx_tx, tx_rx) = mpsc::channel::<Bytes>(CHAN_DEPTH);

    // ── RX task: client writes → pipeline ────────────────────────────────────
    //
    // Each BLE write carries exactly one LpPacket (whole or fragment). We
    // hand the raw bytes up to the face recv channel; the pipeline's
    // `TlvDecodeStage` handles NDNLPv2 reassembly via its per-face
    // `ReassemblyBuffer`, identical to UDP and Ethernet faces.
    //
    // In bluer ≥0.17, `CharacteristicControlEvent::Write` carries a
    // `CharacteristicWriteIoRequest` that must be `accept()`-ed to yield
    // the underlying `CharacteristicReader` (which is the AsyncRead).
    tokio::spawn({
        let _server = Arc::clone(&server);
        async move {
            futures::pin_mut!(cs_ctl);
            while let Some(evt) = cs_ctl.next().await {
                let CharacteristicControlEvent::Write(req) = evt else {
                    continue;
                };
                let mut reader = match req.accept() {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(%e, "BLE/Linux: RX accept failed");
                        continue;
                    }
                };
                let mtu = reader.mtu();
                debug!(mtu, "BLE/Linux: RX client connected");
                let mut buf = vec![0u8; mtu];
                loop {
                    match reader.read(&mut buf).await {
                        Ok(0) => {
                            debug!("BLE/Linux: RX client disconnected");
                            break;
                        }
                        Err(e) => {
                            warn!(%e, "BLE/Linux: RX read error");
                            break;
                        }
                        Ok(n) => {
                            let pkt = Bytes::copy_from_slice(&buf[..n]);
                            if rx_tx.send(pkt).is_err() {
                                return; // face dropped
                            }
                        }
                    }
                }
            }
        }
    });

    // ── TX task: pipeline → client notify ─────────────────────────────────────
    //
    // Each packet from the pipeline is either already an LpPacket (from the
    // reliability/fragmentation layer) or a bare Interest/Data. If it's bare
    // and fits, wrap in a single LpPacket envelope; if it's bare and
    // oversized, fragment via NDNLPv2 `fragment_packet`. Each resulting
    // LpPacket is sent as one BLE notify = one ATT write.
    //
    // In bluer ≥0.17, `CharacteristicControlEvent::Notify(n)` carries a
    // `CharacteristicWriter` (the AsyncWrite side), not a
    // `CharacteristicNotifier`.
    tokio::spawn(async move {
        futures::pin_mut!(sc_ctl);
        let mut tx_rx = tx_rx;
        let mut notifier: Option<CharacteristicWriter> = None;
        // Monotonic base sequence for NDNLPv2 fragment groups.
        let mut frag_seq: u64 = 0;

        loop {
            if notifier.is_none() {
                loop {
                    match sc_ctl.next().await {
                        Some(CharacteristicControlEvent::Notify(n)) => {
                            debug!(mtu = n.mtu(), "BLE/Linux: TX subscriber connected");
                            notifier = Some(n);
                            break;
                        }
                        Some(_) => continue,
                        None => return,
                    }
                }
            }

            tokio::select! {
                biased;

                maybe_evt = sc_ctl.next() => match maybe_evt {
                    Some(CharacteristicControlEvent::Notify(n)) => {
                        debug!(mtu = n.mtu(), "BLE/Linux: TX subscriber replaced");
                        notifier = Some(n);
                    }
                    Some(_) => {}
                    None => return,
                },

                maybe_pkt = tx_rx.recv() => {
                    let Some(pkt) = maybe_pkt else { return };
                    let n = notifier.as_mut().unwrap();
                    let ble_mtu = n.mtu().saturating_sub(ATT_OVERHEAD);

                    // NDNLPv2 fragmentation requires at least FRAG_OVERHEAD+1
                    // bytes per fragment. If the negotiated MTU is too small,
                    // we cannot use NDNLPv2 fragmentation — drop and log. This
                    // only happens on unnegotiated 23-byte default MTUs; real
                    // BLE stacks negotiate ≥185.
                    if ble_mtu <= FRAG_OVERHEAD {
                        warn!(
                            ble_mtu,
                            needed = FRAG_OVERHEAD + 1,
                            "BLE/Linux: ATT MTU too small for NDNLPv2 fragmentation, dropping packet"
                        );
                        continue;
                    }

                    let result = if is_lp_packet(&pkt) {
                        // Already framed (e.g. from reliability layer) — pass through.
                        n.write_all(&pkt).await
                    } else if pkt.len() + 4 <= ble_mtu {
                        // Fits in a single LpPacket envelope.
                        let wire = encode_lp_packet(&pkt);
                        n.write_all(&wire).await
                    } else {
                        // Oversized — fragment with NDNLPv2.
                        let seq = frag_seq;
                        frag_seq = frag_seq.wrapping_add(1);
                        let fragments = fragment_packet(&pkt, ble_mtu, seq);
                        let mut r: std::io::Result<()> = Ok(());
                        for frag in &fragments {
                            if let Err(e) = n.write_all(frag).await {
                                r = Err(e);
                                break;
                            }
                        }
                        r
                    };

                    if result.is_err() {
                        warn!("BLE/Linux: TX notify failed, waiting for new subscriber");
                        notifier = None;
                    }
                }
            }
        }
    });

    Ok(BleFace {
        id,
        local_uri,
        rx: Mutex::new(rx_rx),
        tx: tx_tx,
        _server: server,
    })
}
