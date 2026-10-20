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
//!
//! The Data is signed by [`PublisherConfig::signer`]; without one it carries a
//! `DigestSha256` (integrity only, no publisher), which a validating
//! subscriber refuses.

#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;

#[cfg(not(target_arch = "wasm32"))]
use ndn_ipc::ForwarderClient;
use ndn_packet::Name;

#[cfg(not(target_arch = "wasm32"))]
use crate::connection::IpcConnection;
use crate::connection::{Connection, InProcConnection};
use crate::rt;
use crate::{AppError, DataSigner};

#[derive(Clone)]
pub struct PublisherConfig {
    pub svs: ndn_sync::SvsConfig,
    /// FreshnessPeriod stamped on published Data. Default 4 s.
    pub data_freshness: Duration,
    /// The [`DataStore`](ndn_sync::DataStore) holding this publisher's served history (N-15).
    /// `None` (the default) = a fresh in-memory store per instance — RAM-only, so served
    /// history evaporates on restart and continuity leans on re-announcing the whole history
    /// (O(history) per boot). Inject a persistent store (e.g. `ndn_sync::BackendStore` over
    /// fjall/redb, feature `persistent-store`) and a restarted publisher instead serves its
    /// old publications from disk AND resumes its sequence space (`SvSync::join` recovers the
    /// seq high-water mark from the store — N-13). Share one store across boots; never share
    /// one store between two *concurrently live* publishers with the same node name (their
    /// seq spaces would collide).
    pub store: Option<Arc<dyn ndn_sync::DataStore>>,
    /// Which key signs the published Data. [`DataSigner::ByName`] signs with
    /// the key [`SecurityManager::signer_for`](ndn_security::SecurityManager::signer_for)
    /// picks for the publisher's names (`<node>/<group>/…`) — the key of the
    /// trusted prefix they lie in; constructing the publisher fails with
    /// [`AppError::Signing`] when no key of the device may sign them. `None`
    /// (the default) publishes `DigestSha256` Data: integrity only, no
    /// publisher.
    pub signer: Option<DataSigner>,
}

impl std::fmt::Debug for PublisherConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublisherConfig")
            .field("svs", &self.svs)
            .field("data_freshness", &self.data_freshness)
            .field("store", &self.store.as_ref().map(|_| "injected DataStore"))
            .field("signer", &self.signer)
            .finish()
    }
}

impl Default for PublisherConfig {
    fn default() -> Self {
        Self {
            svs: ndn_sync::SvsConfig::default(),
            data_freshness: Duration::from_secs(4),
            store: None,
            signer: None,
        }
    }
}

/// A sync-group publisher. Holds the [`SvSync`](ndn_sync::SvSync) data plane
/// alive (it serves subscribers' fetch Interests from the local store) and
/// exposes [`put`](Self::put) to publish.
///
/// Most apps obtain one via [`Node::publish`](crate::Node::publish) rather than
/// constructing it directly.
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
        let data_prefix = svs_data_prefix(&local_name, &group);
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
        config: PublisherConfig,
    ) -> Result<Self, AppError> {
        Self::run(
            Arc::new(InProcConnection::new(handle)),
            group,
            local_name,
            config,
        )
    }

    fn run(
        conn: Arc<dyn Connection>,
        group: Name,
        local_name: Name,
        config: PublisherConfig,
    ) -> Result<Self, AppError> {
        // Resolved up front: a publisher whose Data no key may sign fails
        // here, not at its first `put`.
        let signer = match &config.signer {
            Some(signer) => Some(publisher_signer(
                signer.signer_for(&svs_data_prefix(&local_name, &group))?,
            )),
            None => None,
        };
        let cancel = tokio_util::sync::CancellationToken::new();

        let (net_out_tx, mut net_out_rx) = mpsc::channel::<Bytes>(64);
        let (net_in_tx, net_in_rx) = mpsc::channel::<Bytes>(64);

        let svsync_config = ndn_sync::SvSyncConfig {
            svs: config.svs.clone(),
            data_freshness: config.data_freshness,
            ..Default::default()
        };
        // The served-history store: injected (persistent across boots — the N-15 seam) or a
        // fresh in-memory store, the unchanged default. `SvSync::join` recovers the seq
        // high-water mark from whatever store it gets, so a handed-off store also resumes the
        // publisher's sequence space.
        let store: Arc<dyn ndn_sync::DataStore> = config
            .store
            .clone()
            .unwrap_or_else(|| Arc::new(ndn_sync::MemoryStore::new()));
        let mut svsync = ndn_sync::SvSync::join(
            group,
            local_name.clone(),
            store,
            net_out_tx,
            net_in_rx,
            svsync_config,
        );
        if let Some(signer) = signer {
            svsync.set_publisher_signer(signer);
        }
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

    /// Publish `payload` as the next sequence number. Stores the Data —
    /// signed by [`PublisherConfig::signer`], else `DigestSha256` — (served to
    /// subscribers) and advances + multicasts the state vector. Returns the
    /// assigned sequence number.
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

/// Where an SVS publisher's Data lives: `<local_name>/<group>/<seq>/…`
/// ([`ndn_sync::svs_data_name`] minus the seq). Routing fetch Interests to the
/// publisher means registering this prefix.
pub(crate) fn svs_data_prefix(local_name: &Name, group: &Name) -> Name {
    let mut p = local_name.clone();
    for c in group.components() {
        p = p.append_component(c.clone());
    }
    p
}

/// Sign publications with `key`, asynchronously (a remote or enclave-held key
/// signs too).
fn publisher_signer(key: Arc<dyn ndn_security::Signer>) -> ndn_sync::PublisherSigner {
    ndn_sync::PublisherSigner {
        sig_type: key.sig_type(),
        key_locator: key.key_name().clone(),
        sign: Arc::new(move |region| {
            let key = Arc::clone(&key);
            Box::pin(async move { key.sign(&region).await.map_err(|e| e.to_string()) })
        }),
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
        let pub_conn = Arc::new(LinkConn {
            out: p2s_tx,
            inn: Mutex::new(s2p_rx),
        });
        let sub_conn = Arc::new(LinkConn {
            out: s2p_tx,
            inn: Mutex::new(p2s_rx),
        });

        let publisher = Publisher::from_connection(
            pub_conn,
            group.clone(),
            "/demo/room/sensor".parse().unwrap(),
            PublisherConfig {
                svs: fast_svs(),
                ..Default::default()
            },
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
        let pub_conn = Arc::new(LinkConn {
            out: p2s_tx,
            inn: Mutex::new(s2p_rx),
        });
        let sub_conn = Arc::new(LinkConn {
            out: s2p_tx,
            inn: Mutex::new(p2s_rx),
        });

        let publisher = Publisher::from_connection(
            pub_conn,
            group.clone(),
            "/demo/files/src".parse().unwrap(),
            PublisherConfig {
                svs: fast_svs(),
                ..Default::default()
            },
        )
        .expect("publisher");
        let mut subscriber = Subscriber::from_connection(
            sub_conn,
            group.clone(),
            "/demo/files/sink".parse().unwrap(),
            SubscriberConfig {
                auto_fetch: true,
                fetch_timeout: Duration::from_secs(2),
                svs: fast_svs(),
            },
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

    /// N-15 GATE: the store seam. A publisher backed by an INJECTED persistent store
    /// (`BackendStore` — ndn-sync's N-13 bridge; the sync-memory backend stands in for
    /// fjall/redb, same `SyncBackend` path) is dropped — "the process exits" — and a NEW
    /// instance over the SAME store then (a) serves the previous boot's publication to a real
    /// fetch through its own demux (the served history survived the handoff; no store peek),
    /// and (b) resumes the sequence space (`put` → seq 2, not a collision at 1 — the
    /// `SvSync::join` seq recovery riding the seam). Default callers are untouched:
    /// `store: None` keeps the per-instance `MemoryStore`, the path every other test in this
    /// module exercises.
    #[tokio::test]
    async fn injected_store_survives_a_publisher_handoff() {
        let group: Name = "/demo/persist".parse().unwrap();
        let node: Name = "/demo/persist/writer".parse().unwrap();
        let store: Arc<dyn ndn_sync::DataStore> = Arc::new(ndn_sync::BackendStore::memory());

        // Boot 1: publish, then crash — the Publisher drops; only the store survives.
        {
            let (p2s_tx, _p2s_rx) = mpsc::unbounded_channel::<Bytes>();
            let (_s2p_tx, s2p_rx) = mpsc::unbounded_channel::<Bytes>();
            let conn = Arc::new(LinkConn {
                out: p2s_tx,
                inn: Mutex::new(s2p_rx),
            });
            let publisher = Publisher::from_connection(
                conn,
                group.clone(),
                node.clone(),
                PublisherConfig {
                    svs: fast_svs(),
                    store: Some(Arc::clone(&store)),
                    ..Default::default()
                },
            )
            .expect("boot-1 publisher");
            assert_eq!(publisher.put(b"born-in-boot-1").await.expect("put"), 1);
        }

        // Boot 2: a fresh instance over the handed-off store, cross-wired to a consumer.
        let (p2c_tx, p2c_rx) = mpsc::unbounded_channel::<Bytes>();
        let (c2p_tx, c2p_rx) = mpsc::unbounded_channel::<Bytes>();
        let pub_conn = Arc::new(LinkConn {
            out: p2c_tx,
            inn: Mutex::new(c2p_rx),
        });
        let consumer_conn = Arc::new(LinkConn {
            out: c2p_tx,
            inn: Mutex::new(p2c_rx),
        });
        let publisher = Publisher::from_connection(
            pub_conn,
            group.clone(),
            node.clone(),
            PublisherConfig {
                svs: fast_svs(),
                store: Some(Arc::clone(&store)),
                ..Default::default()
            },
        )
        .expect("boot-2 publisher");

        // (a) The boot-1 publication is served by boot 2, from the handed-off store.
        let mut consumer = crate::Consumer::new(consumer_conn);
        let data = consumer
            .fetch(ndn_sync::svs_data_name(&node, &group, 1))
            .await
            .expect("boot-1 publication served across the handoff");
        assert_eq!(
            data.content().map(|c| c.as_ref()),
            Some(&b"born-in-boot-1"[..])
        );

        // (b) The sequence space resumed — no collision with the pre-restart name.
        assert_eq!(publisher.put(b"born-in-boot-2").await.expect("put"), 2);
    }

    /// An idle link: the publisher sends into the void and hears nothing.
    fn idle_conn() -> Arc<LinkConn> {
        let (out, _) = mpsc::unbounded_channel::<Bytes>();
        let (_, inn) = mpsc::unbounded_channel::<Bytes>();
        Arc::new(LinkConn {
            out,
            inn: Mutex::new(inn),
        })
    }

    /// A publisher signing by name signs its publications with the key of the
    /// trusted prefix its names lie in — a real signature over the Data,
    /// under that key's KeyLocator — not a `DigestSha256`.
    #[tokio::test]
    async fn publisher_signs_with_the_key_its_names_select() {
        use ndn_security::{SecurityManager, verifier::VerifyOutcome, verify_by_sig_type};

        let n = |s: &str| -> Name { s.parse().unwrap() };
        let mgr = Arc::new(SecurityManager::new());
        let a_key = n("/a/member/x/KEY/k1");
        mgr.generate_ed25519(a_key.clone()).unwrap();
        mgr.generate_ed25519(n("/c/member/x/KEY/k2")).unwrap();
        let store: Arc<dyn ndn_sync::DataStore> = Arc::new(ndn_sync::MemoryStore::new());
        let (group, local) = (n("/a/room"), n("/a/member/x"));

        let publisher = Publisher::from_connection(
            idle_conn(),
            group.clone(),
            local.clone(),
            PublisherConfig {
                store: Some(Arc::clone(&store)),
                signer: Some(DataSigner::ByName(Arc::clone(&mgr))),
                ..Default::default()
            },
        )
        .expect("publisher");
        let seq = publisher.put(b"hello").await.expect("put");

        let wire = store
            .get(&ndn_sync::svs_data_name(&local, &group, seq))
            .expect("published Data stored");
        let data = ndn_packet::Data::decode(wire).unwrap();
        let sig = data.sig_info().unwrap();
        assert_eq!(sig.sig_type, ndn_packet::SignatureType::SignatureEd25519);
        assert_eq!(*sig.key_locator_name().unwrap(), a_key);
        let public_key = mgr.signer_for(&local).unwrap().public_key().unwrap();
        let outcome = verify_by_sig_type(
            sig.sig_type,
            data.signed_region(),
            data.sig_value(),
            &public_key,
        )
        .await
        .unwrap();
        assert_eq!(outcome, VerifyOutcome::Valid);
    }

    /// A publisher whose names no key of the device may sign is refused when
    /// it is built, rather than publishing unsigned Data.
    #[tokio::test]
    async fn publisher_without_a_key_for_its_names_is_refused() {
        let mgr = Arc::new(ndn_security::SecurityManager::new());
        mgr.generate_ed25519("/a/member/x/KEY/k1".parse().unwrap())
            .unwrap();
        let refused = Publisher::from_connection(
            idle_conn(),
            "/z/room".parse().unwrap(),
            "/z/member/y".parse().unwrap(),
            PublisherConfig {
                signer: Some(DataSigner::ByName(mgr)),
                ..Default::default()
            },
        );
        assert!(matches!(refused, Err(AppError::Signing(_))));
    }
}
