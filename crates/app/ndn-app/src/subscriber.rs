//! Zenoh-shaped pub/sub over NDN sync. `Subscriber` joins a sync
//! group, receives new-data notifications from peers, and optionally
//! auto-fetches.

#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;

#[cfg(not(target_arch = "wasm32"))]
use ndn_ipc::ForwarderClient;
use ndn_packet::Name;
// Used only by the native-only PSync path's hand-rolled fetch.
#[cfg(not(target_arch = "wasm32"))]
use ndn_packet::Data;
#[cfg(not(target_arch = "wasm32"))]
use ndn_packet::encode::encode_interest;

use crate::AppError;
#[cfg(not(target_arch = "wasm32"))]
use crate::connection::IpcConnection;
use crate::connection::{Connection, InProcConnection};
use crate::rt;

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

/// A sync-group subscriber (SVS pub/sub). Most apps obtain one via
/// [`Node::subscribe`](crate::Node::subscribe) rather than constructing it
/// directly.
pub struct Subscriber {
    sample_rx: mpsc::Receiver<Sample>,
    _cancel: tokio_util::sync::CancellationToken,
}

impl Subscriber {
    /// SVS-based subscription. Registers the group prefix and starts
    /// receiving peer updates. Native-only (Unix-socket IPC); in the browser
    /// use [`from_handle`](Self::from_handle) against an embedded engine.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn connect(
        socket: impl AsRef<Path>,
        group_prefix: impl Into<Name>,
    ) -> Result<Self, AppError> {
        Self::connect_with_config(socket, group_prefix, SubscriberConfig::default()).await
    }

    #[cfg(not(target_arch = "wasm32"))]
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
    /// group speak PSync. Native-only (Unix-socket IPC).
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn connect_psync(
        socket: impl AsRef<Path>,
        group_prefix: impl Into<Name>,
    ) -> Result<Self, AppError> {
        Self::connect_psync_with_config(socket, group_prefix, ndn_sync::PSyncConfig::default())
            .await
    }

    #[cfg(not(target_arch = "wasm32"))]
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

    /// Convenience wrapper for an in-process engine handle.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_handle(
        handle: ndn_face::local::InProcHandle,
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

    /// Convenience wrapper for an in-process engine handle (browser).
    #[cfg(target_arch = "wasm32")]
    pub fn from_handle(
        handle: ndn_face_local::InProcHandle,
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

    // Only reached via the native-only `connect_psync*` IPC ctors today. The
    // driver itself is wasm-safe (rt::spawn); exposing browser PSync just needs
    // a `from_handle_psync` entry point — deferred. SVS is browser-reachable via
    // `from_handle`.
    #[cfg(not(target_arch = "wasm32"))]
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
        rt::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_send.cancelled() => break,
                    Some(pkt) = net_send_rx.recv() => { let _ = conn_send.send(pkt).await; }
                }
            }
        });

        let conn_recv = Arc::clone(&conn);
        let cancel_recv = cancel.clone();
        rt::spawn(async move {
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
        rt::spawn(async move {
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

    /// Runs the subscription on the [`SvSync`](ndn_sync::SvSync) data
    /// plane: the `Connection` is bridged to SvSync's `net_out`/`net_in`
    /// channels, and notifications drive SvSync's *correlated* fetcher
    /// (replies matched to Interests by name) instead of a hand-rolled
    /// "read the next packet". This also removes the previous concurrency
    /// bug of two tasks both calling `conn.recv()` — now exactly one
    /// reader feeds SvSync's demux.
    fn run(
        conn: Arc<dyn Connection>,
        group: Name,
        local_name: Name,
        config: SubscriberConfig,
    ) -> Result<Self, AppError> {
        let cancel = tokio_util::sync::CancellationToken::new();
        let (sample_tx, sample_rx) = mpsc::channel(config.svs.channel_capacity);

        // Retained for canonical `svs_data_name` reporting on each Sample.
        let group_for_sample = group.clone();

        // Bridge channels between the Connection and the SvSync data plane.
        let (net_out_tx, mut net_out_rx) = mpsc::channel::<Bytes>(64);
        let (net_in_tx, net_in_rx) = mpsc::channel::<Bytes>(64);

        let svsync_config = ndn_sync::SvSyncConfig {
            svs: config.svs.clone(),
            fetch_timeout: config.fetch_timeout,
            ..Default::default()
        };
        // A subscriber is a pure consumer — it never serves, so the store
        // stays empty (SvSync's demux serves data-prefix Interests from it).
        let store: Arc<dyn ndn_sync::DataStore> = Arc::new(ndn_sync::MemoryStore::new());
        let mut svsync = ndn_sync::SvSync::join(
            group,
            local_name,
            store,
            net_out_tx,
            net_in_rx,
            svsync_config,
        );
        let mut updates = svsync.take_updates();
        let svsync = Arc::new(svsync);

        let auto_fetch = config.auto_fetch;

        // SvSync → Connection (Sync Interests, fetch Interests).
        let conn_send = Arc::clone(&conn);
        let cancel_send = cancel.clone();
        rt::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_send.cancelled() => break,
                    Some(pkt) = net_out_rx.recv() => {
                        let _ = conn_send.send(pkt).await;
                    }
                }
            }
        });

        // Connection → SvSync. Every inbound packet (Sync Interests *and*
        // Data replies) goes to the single demux, which routes them.
        let conn_recv = Arc::clone(&conn);
        let cancel_recv = cancel.clone();
        rt::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_recv.cancelled() => break,
                    pkt = conn_recv.recv() => match pkt {
                        Some(raw) => {
                            if net_in_tx.send(raw).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
            }
        });

        // Notification → correlated fetch → Sample.
        let svsync_fetch = Arc::clone(&svsync);
        let task_cancel = cancel.clone();
        rt::spawn(async move {
            // Keep the SvSync alive for as long as we're subscribed.
            let _svsync = svsync_fetch;
            loop {
                tokio::select! {
                    _ = task_cancel.cancelled() => break,
                    Some(update) = updates.recv() => {
                        for seq in update.low_seq..=update.high_seq {
                            // Canonical ndn-svs publication name
                            // `<node>/<group>/<seq>` (matches SvSync::publish_data
                            // and ndn-svs `getDataName`), reassembling any
                            // multi-segment object the producer published.
                            let data_name = ndn_sync::svs_data_name(
                                &update.name,
                                &group_for_sample,
                                seq,
                            );
                            let payload = if auto_fetch {
                                _svsync
                                    .fetch_publication(&update.name, seq)
                                    .await
                                    .map(|segs| Bytes::from(segs.concat()))
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

/// Hand-rolled fetch for the PSync path (a separate sync protocol with no
/// SvSync data plane). The SVS path uses SvSync's correlated fetcher
/// instead; see [`Subscriber::run`].
#[cfg(not(target_arch = "wasm32"))]
async fn fetch_data(conn: &Arc<dyn Connection>, name: &Name, timeout: Duration) -> Option<Bytes> {
    let wire = encode_interest(name, None);
    conn.send(wire).await.ok()?;
    let reply = rt::timeout(timeout, conn.recv()).await.ok()??;
    let data = Data::decode(reply).ok()?;
    data.content().cloned()
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use ndn_packet::Interest;
    use ndn_packet::encode::{DataBuilder, InterestBuilder};
    use ndn_sync::{StateEntry, WireDialect};
    use tokio::sync::Mutex;

    /// A `Connection` the test fully controls: it captures what the
    /// Subscriber sends and lets the test inject inbound packets — i.e.
    /// the test plays the network + the producer peer.
    struct TestConn {
        out: mpsc::UnboundedSender<Bytes>,
        inn: Mutex<mpsc::UnboundedReceiver<Bytes>>,
    }

    #[async_trait]
    impl Connection for TestConn {
        async fn send(&self, wire: Bytes) -> Result<(), AppError> {
            self.out.send(wire).map_err(|_| AppError::Closed)
        }
        async fn recv(&self) -> Option<Bytes> {
            self.inn.lock().await.recv().await
        }
        async fn register_prefix(&self, _prefix: &Name) -> Result<(), AppError> {
            Ok(())
        }
    }

    fn peer_sync_interest(group: &Name, publisher: &str, seq: u64) -> Bytes {
        let sv = WireDialect::V2.encode_state_vector(&[StateEntry {
            name: publisher.parse().unwrap(),
            boot: 0,
            seq,
        }]);
        InterestBuilder::new(group.clone().append_version(WireDialect::V2.sync_version()))
            .app_parameters(sv.to_vec())
            .build()
    }

    /// End-to-end: a peer's Sync Interest advertises `/grp/pub#1`; the
    /// Subscriber must emit a fetch Interest for `/grp/pub/seg=1`, and
    /// SvSync's *correlated* fetcher must match the Data we return to that
    /// Interest (not to whatever packet happens to arrive next).
    #[tokio::test]
    async fn subscriber_fetches_via_correlated_data_plane() {
        let group: Name = "/grp".parse().unwrap();
        let local: Name = "/grp/sub".parse().unwrap();
        let publisher = "/grp/pub";

        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Bytes>();
        let (in_tx, in_rx) = mpsc::unbounded_channel::<Bytes>();
        let conn = Arc::new(TestConn {
            out: out_tx,
            inn: Mutex::new(in_rx),
        });

        let config = SubscriberConfig {
            auto_fetch: true,
            fetch_timeout: Duration::from_secs(2),
            svs: ndn_sync::SvsConfig {
                sync_interval: Duration::from_millis(50),
                jitter_ms: 0,
                ..Default::default()
            },
        };
        let mut sub =
            Subscriber::from_connection(conn, group.clone(), local, config).expect("subscriber");

        // Advertise the publisher at seq 1.
        in_tx
            .send(peer_sync_interest(&group, publisher, 1))
            .expect("inject sync");

        // The Subscriber should emit a fetch Interest for the canonical
        // publication name `<node>/<group>/<seq>`; respond with matching Data.
        let want: Name = ndn_sync::svs_data_name(&publisher.parse().unwrap(), &group, 1);
        let respond = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let pkt = out_rx.recv().await.expect("subscriber output");
                if let Ok(i) = Interest::decode(pkt)
                    && *i.name == want
                {
                    let data = DataBuilder::new(want.clone(), b"hello-payload").build();
                    in_tx.send(data).expect("inject data");
                    return;
                }
            }
        })
        .await;
        assert!(respond.is_ok(), "subscriber never sent the fetch Interest");

        let sample = tokio::time::timeout(Duration::from_secs(3), sub.recv())
            .await
            .expect("timed out")
            .expect("sample");
        assert_eq!(sample.name, want);
        assert_eq!(sample.publisher, publisher);
        assert_eq!(sample.seq, 1);
        assert_eq!(sample.payload.as_deref(), Some(&b"hello-payload"[..]));
    }
}
