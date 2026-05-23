//! Zenoh-shaped pub/sub over NDN sync. `Subscriber` joins a sync
//! group, receives new-data notifications from peers, and optionally
//! auto-fetches.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;

use ndn_ipc::ForwarderClient;
use ndn_packet::encode::encode_interest;
use ndn_packet::{Data, Name};

use crate::AppError;
use crate::connection::{Connection, InProcConnection, IpcConnection};

#[derive(Clone, Debug)]
pub struct Sample {
    pub name: Name,
    /// Node key from the sync group.
    pub publisher: String,
    pub seq: u64,
    /// `None` when `auto_fetch` is off — only the notification arrived.
    pub payload: Option<Bytes>,
}

#[derive(Clone, Debug)]
pub struct SubscriberConfig {
    /// Default `true`.
    pub auto_fetch: bool,
    /// Default 4 s.
    pub fetch_timeout: Duration,
    pub svs: ndn_sync::SvsConfig,
}

impl Default for SubscriberConfig {
    fn default() -> Self {
        Self {
            auto_fetch: true,
            fetch_timeout: Duration::from_secs(4),
            svs: ndn_sync::SvsConfig::default(),
        }
    }
}

pub struct Subscriber {
    sample_rx: mpsc::Receiver<Sample>,
    _cancel: tokio_util::sync::CancellationToken,
}

impl Subscriber {
    /// SVS-based subscription. Registers the group prefix and starts
    /// receiving peer updates.
    pub async fn connect(
        socket: impl AsRef<Path>,
        group_prefix: impl Into<Name>,
    ) -> Result<Self, AppError> {
        Self::connect_with_config(socket, group_prefix, SubscriberConfig::default()).await
    }

    pub async fn connect_with_config(
        socket: impl AsRef<Path>,
        group_prefix: impl Into<Name>,
        config: SubscriberConfig,
    ) -> Result<Self, AppError> {
        let group = group_prefix.into();
        let client = ForwarderClient::connect(socket)
            .await
            .map_err(AppError::Connection)?;
        client
            .register_prefix(&group)
            .await
            .map_err(AppError::Connection)?;

        let local_name = group.clone().append(format!("node-{}", std::process::id()));

        Self::run(
            Arc::new(IpcConnection::new(client)) as Arc<dyn Connection>,
            group,
            local_name,
            config,
        )
    }

    /// PSync variant of [`Self::connect`]; pick this when peers in the
    /// group speak PSync.
    pub async fn connect_psync(
        socket: impl AsRef<Path>,
        group_prefix: impl Into<Name>,
    ) -> Result<Self, AppError> {
        Self::connect_psync_with_config(socket, group_prefix, ndn_sync::PSyncConfig::default())
            .await
    }

    pub async fn connect_psync_with_config(
        socket: impl AsRef<Path>,
        group_prefix: impl Into<Name>,
        psync_config: ndn_sync::PSyncConfig,
    ) -> Result<Self, AppError> {
        let group = group_prefix.into();
        let client = ForwarderClient::connect(socket)
            .await
            .map_err(AppError::Connection)?;
        client
            .register_prefix(&group)
            .await
            .map_err(AppError::Connection)?;

        let local_name = group.clone().append(format!("node-{}", std::process::id()));
        Self::run_psync(
            Arc::new(IpcConnection::new(client)) as Arc<dyn Connection>,
            group,
            local_name,
            psync_config,
        )
    }

    pub fn from_connection(
        conn: Arc<dyn Connection>,
        group: Name,
        local_name: Name,
        config: SubscriberConfig,
    ) -> Result<Self, AppError> {
        Self::run(conn, group, local_name, config)
    }

    /// Convenience wrapper for [`InProcHandle`].
    pub fn from_handle(
        handle: ndn_faces::local::InProcHandle,
        group: Name,
        local_name: Name,
        config: SubscriberConfig,
    ) -> Result<Self, AppError> {
        Self::run(
            Arc::new(InProcConnection::new(handle)),
            group,
            local_name,
            config,
        )
    }

    fn run_psync(
        conn: Arc<dyn Connection>,
        group: Name,
        local_name: Name,
        psync_config: ndn_sync::PSyncConfig,
    ) -> Result<Self, AppError> {
        let _ = local_name;
        let cancel = tokio_util::sync::CancellationToken::new();
        let capacity = psync_config.channel_capacity;
        let (sample_tx, sample_rx) = mpsc::channel(capacity);

        let (net_send_tx, mut net_send_rx) = mpsc::channel::<Bytes>(64);
        let (net_recv_tx, net_recv_rx) = mpsc::channel::<ndn_sync::PSyncInbound>(64);

        let mut sync_handle =
            ndn_sync::join_psync_group(group.clone(), net_send_tx, net_recv_rx, psync_config);

        let conn_send = Arc::clone(&conn);
        let cancel_send = cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_send.cancelled() => break,
                    Some(pkt) = net_send_rx.recv() => { let _ = conn_send.send(pkt).await; }
                }
            }
        });

        let conn_recv = Arc::clone(&conn);
        let cancel_recv = cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_recv.cancelled() => break,
                    pkt = conn_recv.recv() => match pkt {
                        Some(raw) => { if raw.first() == Some(&0x05) { let _ = net_recv_tx.send(raw.into()).await; } }
                        None => break,
                    }
                }
            }
        });

        let conn_fetch = Arc::clone(&conn);
        let task_cancel = cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = task_cancel.cancelled() => break,
                    Some(update) = sync_handle.recv() => {
                        for seq in update.low_seq..=update.high_seq {
                            let data_name = update.name.clone().append_segment(seq);
                            let payload = fetch_data(&conn_fetch, &data_name, Duration::from_secs(4)).await;
                            let sample = Sample {
                                name: data_name,
                                publisher: update.publisher.clone(),
                                seq,
                                payload,
                            };
                            if sample_tx.send(sample).await.is_err() { return; }
                        }
                    }
                }
            }
        });

        Ok(Self {
            sample_rx,
            _cancel: cancel,
        })
    }

    /// Spawns three tasks: send pump (SVS → router), recv pump (router
    /// → SVS Interest demux), update processor (`SyncUpdate` → optional
    /// fetch → `Sample`).
    fn run(
        conn: Arc<dyn Connection>,
        group: Name,
        local_name: Name,
        config: SubscriberConfig,
    ) -> Result<Self, AppError> {
        let cancel = tokio_util::sync::CancellationToken::new();
        let (sample_tx, sample_rx) = mpsc::channel(config.svs.channel_capacity);

        let (net_send_tx, mut net_send_rx) = mpsc::channel::<Bytes>(64);
        let (net_recv_tx, net_recv_rx) = mpsc::channel::<Bytes>(64);

        let mut sync_handle = ndn_sync::join_svs_group(
            group.clone(),
            local_name,
            net_send_tx,
            net_recv_rx,
            config.svs,
        );

        let auto_fetch = config.auto_fetch;
        let fetch_timeout = config.fetch_timeout;

        let conn_send = Arc::clone(&conn);
        let cancel_send = cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_send.cancelled() => break,
                    Some(pkt) = net_send_rx.recv() => {
                        let _ = conn_send.send(pkt).await;
                    }
                }
            }
        });

        // Data (0x06) is consumed by fetch tasks via separate recv;
        // only Interests (0x05) flow to the SVS task here.
        let conn_recv = Arc::clone(&conn);
        let cancel_recv = cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_recv.cancelled() => break,
                    pkt = conn_recv.recv() => match pkt {
                        Some(raw) => {
                            if raw.len() > 2 && raw.starts_with(&[0x05]) {
                                let _ = net_recv_tx.send(raw).await;
                            }
                        }
                        None => break,
                    }
                }
            }
        });

        let conn_fetch = Arc::clone(&conn);
        let task_cancel = cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = task_cancel.cancelled() => break,
                    Some(update) = sync_handle.recv() => {
                        for seq in update.low_seq..=update.high_seq {
                            let data_name = update.name.clone().append_segment(seq);
                            let payload = if auto_fetch {
                                fetch_data(&conn_fetch, &data_name, fetch_timeout).await
                            } else {
                                None
                            };
                            let sample = Sample {
                                name: data_name,
                                publisher: update.publisher.clone(),
                                seq,
                                payload,
                            };
                            if sample_tx.send(sample).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            sample_rx,
            _cancel: cancel,
        })
    }

    /// `None` when the subscription ends.
    pub async fn recv(&mut self) -> Option<Sample> {
        self.sample_rx.recv().await
    }
}

async fn fetch_data(conn: &Arc<dyn Connection>, name: &Name, timeout: Duration) -> Option<Bytes> {
    let wire = encode_interest(name, None);
    conn.send(wire).await.ok()?;
    let reply = tokio::time::timeout(timeout, conn.recv()).await.ok()??;
    let data = Data::decode(reply).ok()?;
    data.content().cloned()
}
