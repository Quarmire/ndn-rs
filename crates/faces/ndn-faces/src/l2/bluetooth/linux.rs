//! Linux BLE GATT server via `bluer` (BlueZ D-Bus).

use std::sync::Arc;

use bluer::{
    adv::{Advertisement, Type as AdvType},
    gatt::local::{
        Application, Characteristic, CharacteristicControlEvent, CharacteristicNotify,
        CharacteristicNotifyMethod, CharacteristicWrite, CharacteristicWriteMethod, Service,
        characteristic_control,
    },
    Session,
};
use bytes::Bytes;
use futures::StreamExt;
use tokio::{
    io::AsyncReadExt,
    sync::{Mutex, mpsc},
};
use tracing::{debug, info, warn};

use super::{BleError, BleFace, CHAN_DEPTH, BLE_RX_CHAR_UUID, BLE_SERVICE_UUID, BLE_TX_CHAR_UUID};
use super::framing::{Assembler, ATT_OVERHEAD, send_pkt};

// ── Server handle (keeps GATT app + advertisement alive) ─────────────────────

pub struct BleServer {
    _app: bluer::gatt::local::ApplicationHandle,
    _adv: bluer::adv::AdvertisementHandle,
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn bind(id: ndn_transport::FaceId) -> Result<BleFace, BleError> {
    let session = Session::new().await?;
    let adapter_names = session.adapter_names().await?;
    let adapter_name = adapter_names.into_iter().next().ok_or(BleError::NoAdapter)?;
    let adapter = session.adapter(&adapter_name)?;
    adapter.set_powered(true).await?;
    let addr = adapter.address().await?;

    info!(adapter = %adapter_name, %addr, "BLE/Linux: binding NDN GATT server");

    let svc_uuid: bluer::Uuid = BLE_SERVICE_UUID.parse().unwrap();
    let tx_uuid: bluer::Uuid = BLE_TX_CHAR_UUID.parse().unwrap();
    let rx_uuid: bluer::Uuid = BLE_RX_CHAR_UUID.parse().unwrap();

    let (tx_ctl, tx_handle) = characteristic_control();
    let (rx_ctl, rx_handle) = characteristic_control();

    let app = Application {
        services: vec![Service {
            uuid: svc_uuid,
            primary: true,
            characteristics: vec![
                // TX: forwarder → client (Notify)
                Characteristic {
                    uuid: tx_uuid,
                    notify: Some(CharacteristicNotify {
                        notify: true,
                        method: CharacteristicNotifyMethod::Io,
                        ..Default::default()
                    }),
                    control_handle: tx_handle,
                    ..Default::default()
                },
                // RX: client → forwarder (Write Without Response)
                Characteristic {
                    uuid: rx_uuid,
                    write: Some(CharacteristicWrite {
                        write_without_response: true,
                        method: CharacteristicWriteMethod::Io,
                        ..Default::default()
                    }),
                    control_handle: rx_handle,
                    ..Default::default()
                },
            ],
            ..Default::default()
        }],
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
    tokio::spawn({
        let _server = Arc::clone(&server);
        async move {
            futures::pin_mut!(rx_ctl);
            while let Some(evt) = rx_ctl.next().await {
                let CharacteristicControlEvent::Write(mut reader) = evt else {
                    continue;
                };
                let mtu = reader.mtu();
                debug!(mtu, "BLE/Linux: RX client connected");
                let mut asm = Assembler::default();
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
                            let chunk = Bytes::copy_from_slice(&buf[..n]);
                            if let Some(pkt) = asm.push(chunk) {
                                if rx_tx.send(pkt).is_err() {
                                    return; // face dropped
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    // ── TX task: pipeline → client notify ─────────────────────────────────────
    tokio::spawn(async move {
        futures::pin_mut!(tx_ctl);
        let mut tx_rx = tx_rx;
        let mut notifier: Option<bluer::gatt::local::CharacteristicNotifier> = None;

        loop {
            if notifier.is_none() {
                loop {
                    match tx_ctl.next().await {
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

                maybe_evt = tx_ctl.next() => match maybe_evt {
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
                    let max_payload = n.mtu().saturating_sub(ATT_OVERHEAD);
                    if send_pkt(n, &pkt, max_payload).await.is_err() {
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
