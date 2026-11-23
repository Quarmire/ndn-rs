//! The cluster the API cases run over: devices of one or more persons on ONE
//! `ndn_engine::ForwarderEngine`, each with its own key, validator, store
//! and the two halves of the transport the node takes (a `Node` for
//! Interest/Data and a sync face for the group's Sync Interests).
//!
//! The engine carries the sync group of every person's namespace
//! (`ndn_namespace::sync_group::carry`, the multicast strategy), so a Sync
//! Interest a device sends below `<person>/32=sync` reaches the sync face of
//! every other device that registered that prefix, never back to its own.
//!
//! A device is killed by ending its faces and restarted by minting new ones
//! for the same name, key, validator and store: what a node's restart finds.

use std::sync::Arc;

use bytes::Bytes;
use ndn_app::{AppError, Connection, EngineAppExt, EngineBuilder, Node};
use ndn_engine::ForwarderEngine;
use ndn_foundation_types::Name;
use ndn_security::{SecurityManager, SignedTrustContext, TrustSchema, Validator};
use ndn_sync::{DataStore, MemoryStore};
use tokio_util::sync::CancellationToken;

use crate::test_kit::n;

/// A forwarder that never delivers anything: a single-node case hands the
/// node the packets it would have fetched.
pub(crate) struct Unconnected;

#[async_trait::async_trait]
impl Connection for Unconnected {
    async fn send(&self, _wire: Bytes) -> Result<(), AppError> {
        Ok(())
    }
    async fn recv(&self) -> Option<Bytes> {
        futures::future::pending().await
    }
    async fn register_prefix(&self, _prefix: &Name) -> Result<(), AppError> {
        Ok(())
    }
}

/// One device: what a node is started with, and its faces.
pub(crate) struct DeviceKit {
    /// The device's name, e.g. `/alice/laptop`.
    pub name: Name,
    /// The device's signing key, `<name>/KEY/1`.
    pub key: Name,
    /// The device's keys: an Ed25519 key named [`Self::key`].
    pub keys: Arc<SecurityManager>,
    /// A validator that has adopted the hierarchical trust context of every
    /// namespace of the cluster.
    pub validator: Arc<Validator>,
    /// The device's store: shared by every run of the device.
    pub store: Arc<dyn DataStore>,
    /// The node's face for Interest and Data; moves into the transport.
    pub node: Node,
    /// The node's face for Sync Interests; moves into the transport.
    pub sync: Arc<dyn Connection>,
    /// The engine the faces are on; none for a device on [`Unconnected`].
    engine: Option<ForwarderEngine>,
    /// Ends the faces of the current run.
    cancel: CancellationToken,
}

impl DeviceKit {
    fn on_engine(
        engine: &ForwarderEngine,
        name: &str,
        namespaces: &[Name],
        store: Arc<dyn DataStore>,
        cancel: CancellationToken,
    ) -> Self {
        let (node, sync) = faces_on(engine, &cancel);
        Self::with(
            name,
            namespaces,
            store,
            node,
            sync,
            Some(engine.clone()),
            cancel,
        )
    }

    /// A device on a forwarder that delivers nothing (single-node cases):
    /// `name` in the trust contexts of `namespaces`, over `store`.
    pub(crate) fn solo(name: &str, namespaces: &[&str], store: Arc<dyn DataStore>) -> Self {
        let conn: Arc<dyn Connection> = Arc::new(Unconnected);
        let namespaces: Vec<Name> = namespaces.iter().map(|ns| n(ns)).collect();
        Self::with(
            name,
            &namespaces,
            store,
            Node::from_connection(Arc::clone(&conn)),
            conn,
            None,
            CancellationToken::new(),
        )
    }

    fn with(
        name: &str,
        namespaces: &[Name],
        store: Arc<dyn DataStore>,
        node: Node,
        sync: Arc<dyn Connection>,
        engine: Option<ForwarderEngine>,
        cancel: CancellationToken,
    ) -> Self {
        let name = n(name);
        let key = name.clone().append("KEY").append("1");
        let keys = Arc::new(SecurityManager::new());
        keys.generate_ed25519(key.clone())
            .expect("an Ed25519 key for the device");
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        for ns in namespaces {
            validator
                .adopt_context(Arc::new(SignedTrustContext::hierarchical(ns.clone())))
                .expect("the namespace's trust context is adopted");
        }
        Self {
            name,
            key,
            keys,
            validator,
            store,
            node,
            sync,
            engine,
            cancel,
        }
    }

    /// A fresh pair of faces for this device on its engine, for a run that
    /// needs more than the one in [`Self::node`] and [`Self::sync`] (a node
    /// started a second time over the same store). Ended by [`Self::kill`].
    /// Panics on a device that has no engine.
    pub(crate) fn faces(&self) -> (Node, Arc<dyn Connection>) {
        let engine = self.engine.as_ref().expect("a device on an engine");
        faces_on(engine, &self.cancel)
    }

    /// End every face of the device's current run: the device is off the
    /// network. Its store, key and validator stay.
    pub(crate) fn kill(&self) {
        self.cancel.cancel();
    }

    /// Whether the device's current run has been killed.
    pub(crate) fn is_killed(&self) -> bool {
        self.cancel.is_cancelled()
    }
}

fn faces_on(engine: &ForwarderEngine, cancel: &CancellationToken) -> (Node, Arc<dyn Connection>) {
    (
        engine.app_node(cancel.child_token()),
        engine.app_face(cancel.child_token()),
    )
}

/// Devices of several persons on one engine.
pub(crate) struct Cluster {
    /// The one forwarder every device's faces are on.
    pub engine: ForwarderEngine,
    devices: Vec<DeviceKit>,
}

impl Cluster {
    /// One device per name (`/<person>/<device>`), each over its own
    /// [`MemoryStore`]; the namespaces are the persons' (`/<person>`).
    pub(crate) async fn new(devices: &[&str]) -> Self {
        let stores = devices
            .iter()
            .map(|d| (*d, Arc::new(MemoryStore::new()) as Arc<dyn DataStore>))
            .collect::<Vec<_>>();
        Self::with_stores(&stores).await
    }

    /// One device per `(name, store)`: the store a case passes (a
    /// `CrashStore`, a `Held`) is the device's.
    pub(crate) async fn with_stores(devices: &[(&str, Arc<dyn DataStore>)]) -> Self {
        let (engine, shutdown) = EngineBuilder::new(Default::default())
            .build()
            .await
            .expect("an engine");
        // The engine runs as long as the case's runtime does.
        shutdown.detach();
        let mut namespaces: Vec<Name> = Vec::new();
        for (device, _) in devices {
            let person = Name::from_components(n(device).components()[..1].iter().cloned());
            if !namespaces.contains(&person) {
                namespaces.push(person);
            }
        }
        for ns in &namespaces {
            ndn_namespace::sync_group::carry(&engine, ns);
        }
        let devices = devices
            .iter()
            .map(|(device, store)| {
                DeviceKit::on_engine(
                    &engine,
                    device,
                    &namespaces,
                    Arc::clone(store),
                    CancellationToken::new(),
                )
            })
            .collect();
        Self { engine, devices }
    }

    /// Device `i`, in the order of the names `new` was given.
    pub(crate) fn device(&self, i: usize) -> &DeviceKit {
        &self.devices[i]
    }

    /// Every device.
    pub(crate) fn devices(&self) -> &[DeviceKit] {
        &self.devices
    }

    /// End device `i`'s faces; its store, key and validator stay.
    pub(crate) fn kill(&self, i: usize) {
        self.devices[i].kill();
    }

    /// Device `i` again, as a restarted node finds it: the same name, key,
    /// validator and store, new faces (the old ones are ended first when
    /// they are not).
    pub(crate) fn restart(&mut self, i: usize) -> &DeviceKit {
        let old = &mut self.devices[i];
        old.kill();
        old.cancel = CancellationToken::new();
        let (node, sync) = faces_on(&self.engine, &old.cancel);
        old.node = node;
        old.sync = sync;
        &self.devices[i]
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use bytes::Bytes;
    use ndn_packet::Interest;
    use ndn_sync::{MultiSvs, ProducerVouch, SvsConfig, SyncHandle, SyncUpdate, spawn_multi_svs};
    use tokio::sync::mpsc;

    use super::*;
    use crate::test_kit::n;
    use crate::wire::sync_group_of;

    /// A device's membership of one SVS group, as the node joins one: its
    /// sync face registered for the owner's `<O>/32=sync` only, one driver
    /// over the face, the group's own name below that prefix.
    struct Member {
        _svs: MultiSvs,
        handle: SyncHandle,
    }

    async fn join(dev: &DeviceKit, owner: &Name, group: &Name) -> Member {
        dev.sync
            .register_prefix(&ndn_security::sync_group(owner))
            .await
            .expect("the sync face registers the owner's group prefix");
        let (out_tx, mut out_rx) = mpsc::channel::<Bytes>(256);
        let (in_tx, in_rx) = mpsc::channel::<Bytes>(256);
        let svs = spawn_multi_svs(dev.name.clone(), out_tx, in_rx);
        let sync = Arc::clone(&dev.sync);
        tokio::spawn(async move {
            while let Some(pkt) = out_rx.recv().await {
                if sync.send(pkt).await.is_err() {
                    break;
                }
            }
        });
        let sync = Arc::clone(&dev.sync);
        tokio::spawn(async move {
            while let Some(pkt) = sync.recv().await {
                if Interest::decode(pkt.clone()).is_ok() && in_tx.send(pkt).await.is_err() {
                    break;
                }
            }
        });
        let cfg = SvsConfig {
            local_seq: 0,
            max_producers: 64,
            vouch: Some(ProducerVouch(Arc::new(|_| true))),
            ..SvsConfig::lan()
        };
        let handle = svs
            .join(group.clone(), cfg)
            .await
            .expect("the driver joins the group");
        Member { _svs: svs, handle }
    }

    /// The next notice a member hears, and how long after `since`.
    async fn heard(m: &mut Member, since: Instant) -> (SyncUpdate, Duration) {
        let update = tokio::time::timeout(Duration::from_secs(10), m.handle.recv())
            .await
            .expect("the notice arrived within ten seconds")
            .expect("the group is open");
        (update, since.elapsed())
    }

    /// D5: a space's sync group `<O>/32=sync/s/abc` needs no route and no
    /// strategy of its own: `carry(O)` on the engine and the sync face's
    /// registration of `<O>/32=sync` are enough for a Sync Interest to reach
    /// every other member of the group, and no device outside it.
    #[tokio::test]
    async fn t_sync_prefix() {
        let cluster = Cluster::new(&["/alice/laptop", "/alice/phone", "/bob/laptop"]).await;
        let (laptop, phone, bob) = (cluster.device(0), cluster.device(1), cluster.device(2));
        let alice_group = sync_group_of(&n("/alice/32=data/s/abc")).unwrap();
        let bob_group = sync_group_of(&n("/bob/32=data/s/abc")).unwrap();
        assert_eq!(alice_group, n("/alice/32=sync/s/abc"));

        let mut on_laptop = join(laptop, &n("/alice"), &alice_group).await;
        let mut on_phone = join(phone, &n("/alice"), &alice_group).await;
        let mut on_bob = join(bob, &n("/alice"), &alice_group).await;
        let mut bob_on_bobs = join(bob, &n("/bob"), &bob_group).await;
        let mut laptop_on_bobs = join(laptop, &n("/bob"), &bob_group).await;

        let published = Instant::now();
        on_phone.handle.publish(alice_group.clone()).await.unwrap();
        let (to_laptop, took_laptop) = heard(&mut on_laptop, published).await;
        let (to_bob, took_bob) = heard(&mut on_bob, published).await;
        for update in [&to_laptop, &to_bob] {
            assert_eq!(update.name, phone.name, "the notice names its writer");
            assert_eq!(update.high_seq, 1, "and the counter it published");
        }
        eprintln!("notice latency across one engine: laptop {took_laptop:?}, bob {took_bob:?}");
        // Without `carry` the best-route strategy hands a Sync Interest to
        // one member only and the other hears it on a later period (two
        // seconds here): the notice must come from the one Sync Interest.
        assert!(
            took_laptop.max(took_bob) < Duration::from_millis(500),
            "every member heard the notice at once, not on a later period"
        );

        bob_on_bobs.handle.publish(bob_group.clone()).await.unwrap();
        let (to_laptop, _) = heard(&mut laptop_on_bobs, Instant::now()).await;
        assert_eq!(to_laptop.name, bob.name);
        assert_eq!(to_laptop.high_seq, 1);

        // Bob's counter went to Bob's group only, and not back to Bob.
        for (who, member) in [
            ("the phone", &mut on_phone),
            ("Alice's laptop in Alice's group", &mut on_laptop),
            ("Bob in Alice's group", &mut on_bob),
            ("Bob in his own group", &mut bob_on_bobs),
        ] {
            assert!(
                tokio::time::timeout(Duration::from_millis(300), member.handle.recv())
                    .await
                    .is_err(),
                "{who} hears nothing more"
            );
        }
    }

    /// A killed device's faces are gone from the engine's routes and a
    /// restarted one, on the same store, is reached under the same name:
    /// what a node restarted over its own store finds.
    #[tokio::test]
    async fn a_cluster_device_can_be_killed_and_restarted_on_its_store() {
        let mut cluster = Cluster::new(&["/alice/laptop", "/alice/phone"]).await;
        let (owner, group) = (n("/alice"), n("/alice/32=sync/s/abc"));
        let on_laptop = join(cluster.device(0), &owner, &group).await;
        let before = join(cluster.device(1), &owner, &group).await;
        cluster
            .device(1)
            .store
            .insert(n("/localhost/ndn-heap/x"), Bytes::from_static(b"kept"));

        cluster.kill(1);
        drop(before);
        assert!(cluster.device(1).is_killed());
        let phone = cluster.restart(1);
        assert!(!phone.is_killed());
        assert_eq!(
            phone.store.get(&n("/localhost/ndn-heap/x")),
            Some(Bytes::from_static(b"kept")),
            "the restarted device is on the store it had"
        );
        let mut on_phone = join(phone, &owner, &group).await;

        on_laptop.handle.publish(group.clone()).await.unwrap();
        let (update, _) = heard(&mut on_phone, Instant::now()).await;
        assert_eq!(update.name, n("/alice/laptop"));
    }

    /// Measurement for the spec, not an invariant: how long an Interest
    /// takes from one app face of the engine to another (`cargo test -p
    /// ndn-heap test_kit::cluster::tests::face_to_face -- --ignored
    /// --nocapture`).
    #[tokio::test]
    #[ignore = "a measurement: prints the latency between two app faces"]
    async fn face_to_face_latency() {
        let cluster = Cluster::new(&["/alice/laptop", "/alice/phone"]).await;
        let (from, to) = (&cluster.device(0).sync, &cluster.device(1).sync);
        to.register_prefix(&n("/lat")).await.unwrap();
        let mut took = Vec::new();
        for i in 0..500u32 {
            let wire = ndn_packet::encode::InterestBuilder::new(n(&format!("/lat/{i}"))).build();
            let sent = Instant::now();
            from.send(wire).await.unwrap();
            tokio::time::timeout(Duration::from_secs(5), to.recv())
                .await
                .expect("the Interest crossed the engine")
                .expect("the face is open");
            took.push(sent.elapsed());
        }
        took.sort();
        eprintln!(
            "face to face: min {:?}, median {:?}, p99 {:?}, max {:?}",
            took[0],
            took[took.len() / 2],
            took[took.len() * 99 / 100],
            took[took.len() - 1]
        );
    }
}
