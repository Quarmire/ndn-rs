//! Zenoh-shaped publish side of NDN sync — the counterpart to
//! [`Subscriber`](crate::Subscriber). A `Publisher` joins a sync group and
//! `put`s payloads that group subscribers auto-fetch.
//!
//! The two halves share one naming convention: `Publisher::put` stores Data
//! at the canonical ndn-svs name `<node>/<group>/<seq>` (via
//! [`SvSync::publish_data`](ndn_sync::SvSync::publish_data)) and advances the
//! state vector; [`Subscriber`](crate::Subscriber) fetches that exact name.
//! So an ndn-rs publisher and subscriber interoperate out of the box (and
//! both interoperate with ndn-svs, which uses the same `getDataName`).

#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;

#[cfg(not(target_arch = "wasm32"))]
use ndn_ipc::ForwarderClient;
use ndn_packet::Name;

use crate::AppError;
#[cfg(not(target_arch = "wasm32"))]
use crate::connection::IpcConnection;
use crate::connection::{Connection, InProcConnection};
use crate::rt;

#[derive(Clone, Debug)]
pub struct PublisherConfig {
    pub svs: ndn_sync::SvsConfig,
    /// FreshnessPeriod stamped on published Data. Default 4 s.
    pub data_freshness: Duration,
}

impl Default for PublisherConfig {
    fn default() -> Self {
        Self {
            svs: ndn_sync::SvsConfig::default(),
            data_freshness: Duration::from_secs(4),
        }
    }
}

/// A sync-group publisher. Holds the [`SvSync`](ndn_sync::SvSync) data plane
/// alive (it serves subscribers' fetch Interests from the local store) and
/// exposes [`put`](Self::put) to publish.
pub struct Publisher {
    svsync: Arc<ndn_sync::SvSync>,
    local_name: Name,
    _cancel: tokio_util::sync::CancellationToken,
}

impl Publisher {
    /// SVS-based publisher over a forwarder Unix socket. Registers the group
    /// prefix (sync) and the node's data prefix (so subscribers' fetch
    /// Interests route back here). Native-only; in the browser use
    /// [`from_handle`](Self::from_handle).
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn connect(
        socket: impl AsRef<Path>,
        group_prefix: impl Into<Name>,
    ) -> Result<Self, AppError> {
        Self::connect_with_config(socket, group_prefix, PublisherConfig::default()).await
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn connect_with_config(
        socket: impl AsRef<Path>,
        group_prefix: impl Into<Name>,
        config: PublisherConfig,
    ) -> Result<Self, AppError> {
        let group = group_prefix.into();
        let client = ForwarderClient::connect(socket)
            .await
            .map_err(AppError::Connection)?;

        let local_name = group.clone().append(format!("node-{}", std::process::id()));
        // Data lives at `<node>/<group>` (svs_data_name minus the seq);
        // register it so subscribers' fetch Interests reach this connection.
        let data_prefix = {
            let mut p = local_name.clone();
            for c in group.components() {
                p = p.append_component(c.clone());
            }
            p
        };
        client
            .register_prefix(&group)
            .await
            .map_err(AppError::Connection)?;
        client
            .register_prefix(&data_prefix)
            .await
            .map_err(AppError::Connection)?;

        Self::run(
            Arc::new(IpcConnection::new(client)) as Arc<dyn Connection>,
            group,
            local_name,
            config,
        )
    }

    /// Build over a caller-supplied [`Connection`] (the embedder owns route
    /// setup). `local_name` is this publisher's node id within `group`.
    pub fn from_connection(
        conn: Arc<dyn Connection>,
        group: Name,
        local_name: Name,
        config: PublisherConfig,
    ) -> Result<Self, AppError> {
        Self::run(conn, group, local_name, config)
    }

    /// Convenience wrapper for an in-process engine handle.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_handle(
        handle: ndn_face::local::InProcHandle,
        group: Name,
        local_name: Name,
        config: PublisherConfig,
    ) -> Result<Self, AppError> {
        Self::run(Arc::new(InProcConnection::new(handle)), group, local_name, config)
    }

    /// Convenience wrapper for an in-process engine handle (browser).
    #[cfg(target_arch = "wasm32")]
    pub fn from_handle(
        handle: ndn_face_local::InProcHandle,
        group: Name,
        local_name: Name,
        config: PublisherConfig,
    ) -> Result<Self, AppError> {
        Self::run(Arc::new(InProcConnection::new(handle)), group, local_name, config)
    }

    fn run(
        conn: Arc<dyn Connection>,
        group: Name,
        local_name: Name,
        config: PublisherConfig,
    ) -> Result<Self, AppError> {
        let cancel = tokio_util::sync::CancellationToken::new();

        let (net_out_tx, mut net_out_rx) = mpsc::channel::<Bytes>(64);
        let (net_in_tx, net_in_rx) = mpsc::channel::<Bytes>(64);

        let svsync_config = ndn_sync::SvSyncConfig {
            svs: config.svs.clone(),
            data_freshness: config.data_freshness,
            ..Default::default()
        };
        // A real store: the SvSync demux serves these Data to subscribers.
        let store: Arc<dyn ndn_sync::DataStore> = Arc::new(ndn_sync::MemoryStore::new());
        let svsync = ndn_sync::SvSync::join(
            group,
            local_name.clone(),
            store,
            net_out_tx,
            net_in_rx,
            svsync_config,
        );
        let svsync = Arc::new(svsync);

        // SvSync → Connection (Sync Interests + Data replies to fetches).
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

        // Connection → SvSync demux (peers' Sync Interests + fetch Interests).
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

        Ok(Self {
            svsync,
            local_name,
            _cancel: cancel,
        })
    }

    /// Publish `payload` as the next sequence number. Stores the signed Data
    /// (served to subscribers) and advances + multicasts the state vector.
    /// Returns the assigned sequence number.
    pub async fn put(&self, payload: impl AsRef<[u8]>) -> Result<u64, AppError> {
        self.svsync
            .publish_data(payload.as_ref())
            .await
            .map_err(|e| AppError::Protocol(e.to_string()))
    }

    /// Publish a large object as one sequence number split across
    /// `<node>/<group>/<seq>/v=0/seg=i` segments (subscribers reassemble via
    /// the windowed fetcher). Returns the assigned sequence number.
    pub async fn put_object(&self, segments: &[Vec<u8>]) -> Result<u64, AppError> {
        self.svsync
            .publish_segments_with_mapping(segments, |_| None)
            .await
            .map_err(|e| AppError::Protocol(e.to_string()))
    }

    /// This publisher's node id within the group.
    pub fn local_name(&self) -> &Name {
        &self.local_name
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::subscriber::{Subscriber, SubscriberConfig};
    use async_trait::async_trait;
    use tokio::sync::Mutex;

    /// A `Connection` that forwards to one queue and reads from another —
    /// cross-wire two of them to model two nodes on a shared link.
    struct LinkConn {
        out: mpsc::UnboundedSender<Bytes>,
        inn: Mutex<mpsc::UnboundedReceiver<Bytes>>,
    }

    #[async_trait]
    impl Connection for LinkConn {
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

    fn fast_svs() -> ndn_sync::SvsConfig {
        ndn_sync::SvsConfig {
            sync_interval: Duration::from_millis(40),
            jitter_ms: 0,
            ..Default::default()
        }
    }

    /// End-to-end: a `Publisher::put` must surface at a `Subscriber::recv`
    /// over a shared link — proving the publish naming matches the auto-fetch
    /// naming (the gap this facade closes).
    #[tokio::test]
    async fn publisher_put_reaches_subscriber() {
        let group: Name = "/demo/room".parse().unwrap();

        // P→S and S→P queues; each node sends on one, receives the other.
        let (p2s_tx, p2s_rx) = mpsc::unbounded_channel::<Bytes>();
        let (s2p_tx, s2p_rx) = mpsc::unbounded_channel::<Bytes>();
        let pub_conn = Arc::new(LinkConn { out: p2s_tx, inn: Mutex::new(s2p_rx) });
        let sub_conn = Arc::new(LinkConn { out: s2p_tx, inn: Mutex::new(p2s_rx) });

        let publisher = Publisher::from_connection(
            pub_conn,
            group.clone(),
            "/demo/room/sensor".parse().unwrap(),
            PublisherConfig { svs: fast_svs(), ..Default::default() },
        )
        .expect("publisher");

        let mut subscriber = Subscriber::from_connection(
            sub_conn,
            group.clone(),
            "/demo/room/screen".parse().unwrap(),
            SubscriberConfig {
                auto_fetch: true,
                fetch_timeout: Duration::from_secs(2),
                svs: fast_svs(),
            },
        )
        .expect("subscriber");

        // Give both sides a sync round to learn each other, then publish.
        tokio::time::sleep(Duration::from_millis(120)).await;
        let seq = publisher.put(b"temp=21.5C").await.expect("put");
        assert_eq!(seq, 1);

        let sample = tokio::time::timeout(Duration::from_secs(6), subscriber.recv())
            .await
            .expect("timed out")
            .expect("sample");
        assert_eq!(sample.publisher, "/demo/room/sensor");
        assert_eq!(sample.seq, 1);
        assert_eq!(sample.payload.as_deref(), Some(&b"temp=21.5C"[..]));
    }

    /// A multi-segment `put_object` reassembles into one payload subscriber-side.
    #[tokio::test]
    async fn publisher_put_object_reassembles() {
        let group: Name = "/demo/files".parse().unwrap();
        let (p2s_tx, p2s_rx) = mpsc::unbounded_channel::<Bytes>();
        let (s2p_tx, s2p_rx) = mpsc::unbounded_channel::<Bytes>();
        let pub_conn = Arc::new(LinkConn { out: p2s_tx, inn: Mutex::new(s2p_rx) });
        let sub_conn = Arc::new(LinkConn { out: s2p_tx, inn: Mutex::new(p2s_rx) });

        let publisher = Publisher::from_connection(
            pub_conn,
            group.clone(),
            "/demo/files/src".parse().unwrap(),
            PublisherConfig { svs: fast_svs(), ..Default::default() },
        )
        .expect("publisher");
        let mut subscriber = Subscriber::from_connection(
            sub_conn,
            group.clone(),
            "/demo/files/sink".parse().unwrap(),
            SubscriberConfig { auto_fetch: true, fetch_timeout: Duration::from_secs(2), svs: fast_svs() },
        )
        .expect("subscriber");

        tokio::time::sleep(Duration::from_millis(120)).await;
        let segs = vec![b"AAAA".to_vec(), b"BBBB".to_vec(), b"CC".to_vec()];
        publisher.put_object(&segs).await.expect("put_object");

        let sample = tokio::time::timeout(Duration::from_secs(6), subscriber.recv())
            .await
            .expect("timed out")
            .expect("sample");
        assert_eq!(sample.payload.as_deref(), Some(&b"AAAABBBBCC"[..]));
    }
}
