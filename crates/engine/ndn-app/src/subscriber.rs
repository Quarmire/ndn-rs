//! High-level subscription API — Zenoh-inspired pub/sub over NDN sync.
//!
//! `Subscriber` joins a sync group, receives notifications of new data from
//! peers, and optionally auto-fetches the data.
//!
//! # Example
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), ndn_app::AppError> {
//! use ndn_app::Subscriber;
//!
//! let mut sub = Subscriber::connect("/run/nfd/nfd.sock", "/chat/room1").await?;
//!
//! while let Some(sample) = sub.recv().await {
//!     println!("{}: {:?}", sample.name, sample.payload);
//! }
//! # Ok(())
//! # }
//! ```

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;

use ndn_ipc::ForwarderClient;
use ndn_packet::encode::encode_interest;
use ndn_packet::{Data, Name};

use crate::AppError;
use crate::connection::NdnConnection;

/// A received publication from a sync group.
#[derive(Clone, Debug)]
pub struct Sample {
    /// The full name of the published data.
    pub name: Name,
    /// Publisher identifier (node key from the sync group).
    pub publisher: String,
    /// Sequence number of this publication.
    pub seq: u64,
    /// Data payload (fetched automatically if `auto_fetch` is enabled,
    /// otherwise `None` — the subscriber only gets the notification).
    pub payload: Option<Bytes>,
}

/// Configuration for a subscriber.
#[derive(Clone, Debug)]
pub struct SubscriberConfig {
    /// Automatically fetch data for each sync update (default: true).
    pub auto_fetch: bool,
    /// Timeout for auto-fetch Interests (default: 4 seconds).
    pub fetch_timeout: Duration,
    /// SVS sync configuration.
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

/// A subscription to a sync group.
///
/// Receives [`Sample`]s as peers publish new data.
pub struct Subscriber {
    sample_rx: mpsc::Receiver<Sample>,
    _cancel: tokio_util::sync::CancellationToken,
}

impl Subscriber {
    /// Connect to a router and subscribe to a sync group prefix.
    ///
    /// Uses SVS as the sync protocol. The subscriber registers the group
    /// prefix and begins receiving updates from peers.
    pub async fn connect(
        socket: impl AsRef<Path>,
        group_prefix: impl Into<Name>,
    ) -> Result<Self, AppError> {
        Self::connect_with_config(socket, group_prefix, SubscriberConfig::default()).await
    }

    /// Connect with explicit configuration.
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

        // Generate a local node name from PID.
        let local_name = group.clone().append(format!("node-{}", std::process::id()));

        Self::run(NdnConnection::External(client), group, local_name, config)
    }

    /// Connect to a router and subscribe to a sync group using **PSync**.
    ///
    /// Identical to [`connect`](Self::connect) but uses PSync instead of SVS.
    /// Use this when peers in the group also use PSync.
    pub async fn connect_psync(
        socket: impl AsRef<Path>,
        group_prefix: impl Into<Name>,
    ) -> Result<Self, AppError> {
        Self::connect_psync_with_config(socket, group_prefix, ndn_sync::PSyncConfig::default())
            .await
    }

    /// Connect with PSync and explicit configuration.
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
            NdnConnection::External(client),
            group,
            local_name,
            psync_config,
        )
    }

    /// Create from an in-process connection (embedded engine).
    pub fn from_connection(
        conn: NdnConnection,
        group: Name,
        local_name: Name,
        config: SubscriberConfig,
    ) -> Result<Self, AppError> {
        Self::run(conn, group, local_name, config)
    }

    /// Internal: run with PSync protocol.
    fn run_psync(
        conn: NdnConnection,
        group: Name,
        local_name: Name,
        psync_config: ndn_sync::PSyncConfig,
    ) -> Result<Self, AppError> {
        let _ = local_name; // PSync uses group name, not per-node name
        let cancel = tokio_util::sync::CancellationToken::new();
        let capacity = psync_config.channel_capacity;
        let (sample_tx, sample_rx) = mpsc::channel(capacity);

        let (net_send_tx, mut net_send_rx) = mpsc::channel::<Bytes>(64);
        let (net_recv_tx, net_recv_rx) = mpsc::channel::<Bytes>(64);

        let mut sync_handle =
            ndn_sync::join_psync_group(group.clone(), net_send_tx, net_recv_rx, psync_config);

        let conn = Arc::new(conn);

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
                        Some(raw) => { if raw.first() == Some(&0x05) { let _ = net_recv_tx.send(raw).await; } }
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

    /// Spawn the background tasks that drive the subscription:
    ///
    /// 1. **Send pump** — forwards sync Interests from the SVS task to the router.
    /// 2. **Recv pump** — reads packets from the connection and routes Interests
    ///    to the SVS task.
    /// 3. **Update processor** — receives `SyncUpdate`s, optionally auto-fetches
    ///    Data, and emits `Sample`s.
    fn run(
        conn: NdnConnection,
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
        let conn = Arc::new(conn);

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

        // Non-sync packets (Data responses for auto-fetch) are handled by
        // the fetch path, not forwarded here.
        let conn_recv = Arc::clone(&conn);
        let cancel_recv = cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_recv.cancelled() => break,
                    pkt = conn_recv.recv() => match pkt {
                        Some(raw) => {
                            // 0x05 = Interest TLV type; forward to SVS task which
                            // ignores non-sync Interests. Data (0x06) is consumed
                            // by fetch tasks via separate recv calls.
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

    /// Receive the next sample. Returns `None` when the subscription ends.
    pub async fn recv(&mut self) -> Option<Sample> {
        self.sample_rx.recv().await
    }
}

/// Fetch a single Data object by expressing an Interest and waiting for a reply.
///
/// Returns `Some(content)` on success, `None` on timeout, decode failure,
/// or missing content.
async fn fetch_data(conn: &NdnConnection, name: &Name, timeout: Duration) -> Option<Bytes> {
    let wire = encode_interest(name, None);
    conn.send(wire).await.ok()?;
    let reply = tokio::time::timeout(timeout, conn.recv()).await.ok()??;
    let data = Data::decode(reply).ok()?;
    data.content().cloned()
}
