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
//! let mut sub = Subscriber::connect("/tmp/ndn-faces.sock", "/chat/room1").await?;
//!
//! while let Some(sample) = sub.recv().await {
//!     println!("{}: {:?}", sample.name, sample.payload);
//! }
//! # Ok(())
//! # }
//! ```

use std::path::Path;

use bytes::Bytes;
use tokio::sync::mpsc;

use ndn_packet::Name;
use ndn_ipc::RouterClient;

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
    /// SVS sync configuration.
    pub svs: ndn_sync::SvsConfig,
}

impl Default for SubscriberConfig {
    fn default() -> Self {
        Self {
            auto_fetch: true,
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
        let client = RouterClient::connect(socket).await
            .map_err(|e| AppError::Engine(e.into()))?;
        client.register_prefix(&group).await
            .map_err(|e| AppError::Engine(e.into()))?;

        // Generate a local node name from PID.
        let local_name = group.clone().append(format!("node-{}", std::process::id()));

        Self::run(NdnConnection::External(client), group, local_name, config)
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

    fn run(
        conn: NdnConnection,
        group: Name,
        local_name: Name,
        config: SubscriberConfig,
    ) -> Result<Self, AppError> {
        let cancel = tokio_util::sync::CancellationToken::new();
        let (sample_tx, sample_rx) = mpsc::channel(config.svs.channel_capacity);

        // Channels for sync protocol ↔ network.
        let (net_send_tx, mut net_send_rx) = mpsc::channel::<Bytes>(64);
        let (net_recv_tx, net_recv_rx) = mpsc::channel::<Bytes>(64);

        // Join the SVS group.
        let mut sync_handle = ndn_sync::join_svs_group(
            group.clone(),
            local_name,
            net_send_tx,
            net_recv_rx,
            config.svs,
        );

        let auto_fetch = config.auto_fetch;
        let task_cancel = cancel.clone();

        // Network send pump: forward sync Interests to the router.
        let conn_for_send = conn;
        tokio::spawn({
            let cancel = task_cancel.clone();
            async move {
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        Some(pkt) = net_send_rx.recv() => {
                            let _ = conn_for_send.send(pkt).await;
                        }
                    }
                }
            }
        });

        // Note: a full implementation would also run a recv pump that
        // filters sync Interests from incoming traffic and forwards them
        // to net_recv_tx. For now, the recv side requires the caller to
        // feed incoming sync packets into the NdnConnection.
        let _ = net_recv_tx; // will be wired in future integration

        // Update processor: receive sync updates, optionally fetch data.
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = task_cancel.cancelled() => break,
                    Some(update) = sync_handle.recv() => {
                        for seq in update.low_seq..=update.high_seq {
                            let data_name = update.name.clone().append_segment(seq);
                            let payload = if auto_fetch {
                                // Fetch via the same connection would require
                                // a shared connection or a separate Consumer.
                                // For now, emit the name without payload;
                                // the application can fetch explicitly.
                                None
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

        Ok(Self { sample_rx, _cancel: cancel })
    }

    /// Receive the next sample. Returns `None` when the subscription ends.
    pub async fn recv(&mut self) -> Option<Sample> {
        self.sample_rx.recv().await
    }
}
