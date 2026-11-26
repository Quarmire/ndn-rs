//! The node over `Unconnected` faces: what survives a restart, what a crash
//! takes and what it never takes, when an entry is served and announced.
//!
//! Devices are real: each has a key certified by its namespace's root, and
//! every device's validator holds every namespace's context and every
//! certificate, so entries one node signs another can be handed
//! (`NodeInner::take`) and judged as a fetch would.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_app::{AppError, Connection};
use ndn_foundation_types::Name;
use ndn_packet::Data;
use ndn_security::{Certificate, SecurityManager, SignedTrustContext, TrustSchema, Validator};
use ndn_sync::{DataStore, MemoryStore};
use proptest::prelude::*;

use super::*;
use crate::error::NextStep;
use crate::log::{Alert, Frontier};
use crate::space::{Changes, MembersChange, PutOptions};
use crate::sync::Taken;
use crate::test_kit::{CrashStore, Engine, Held, Metered, PowerCut, n};
use crate::wire::{Entry, log_name};

/// The network half reaches the node through the toy-host seam in tests
/// (`sync::HostRef`); each method is the node's own.
#[async_trait::async_trait]
impl crate::sync::net_kit::Host for NodeInner {
    fn device(&self) -> &Name {
        NodeInner::device(self)
    }
    async fn take(&self, space: &Name, wire: Bytes, probe: bool) -> Taken {
        NodeInner::take(self, space, wire, probe).await
    }
    fn missing(&self, space: &Name) -> Vec<Want> {
        NodeInner::missing(self, space)
    }
    fn high(&self, space: &Name, device: &Name) -> u64 {
        NodeInner::high(self, space, device)
    }
    fn head(&self, space: &Name) -> u64 {
        NodeInner::head(self, space)
    }
    fn note_own_counter(&self, space: &Name, seen: u64) {
        NodeInner::note_own_counter(self, space, seen);
    }
    fn vouched(&self, space: &Name, device: &Name) -> bool {
        NodeInner::vouched(self, space, device)
    }
    fn standing(&self, space: &Name, device: &Name) -> Option<bool> {
        NodeInner::standing(self, space, device)
    }
    fn served(&self, space: &Name, device: &Name, seq: u64) -> Option<Bytes> {
        NodeInner::served(self, space, device, seq)
    }
    fn served_piece(&self, space: &Name, device: &Name, seq: u64, piece: &Name) -> Option<Bytes> {
        NodeInner::served_piece(self, space, device, seq, piece)
    }
    fn seal_key_packet(&self, name: &Name) -> Option<Bytes> {
        NodeInner::seal_key_packet(self, name)
    }
    fn blobs(&self, space: &Name) -> Vec<Blob> {
        NodeInner::blobs(self, space)
    }
    fn held_piece(&self, space: &Name, name: &Name) -> Option<Bytes> {
        NodeInner::held_piece(self, space, name)
    }
    fn keep_pieces(&self, space: &Name, ops: Vec<StoreOp>) {
        NodeInner::keep_pieces(self, space, ops);
    }
    fn assembled(&self, space: &Name, blob: &Blob) {
        NodeInner::assembled(self, space, blob);
    }
    fn owed_keys(&self, space: &Name) -> Vec<EpochId> {
        NodeInner::owed_keys(self, space)
    }
    fn seal_public(&self) -> [u8; 32] {
        NodeInner::seal_public(self)
    }
    async fn validate_device_packet(&self, space: &Name, data: &Data, device: &Name) -> Judged {
        NodeInner::validate_device_packet(self, space, data, device).await
    }
    async fn validate_asker_packet(
        &self,
        space: &Name,
        data: &Data,
        device: &Name,
        chain: &[Bytes],
    ) -> Judged {
        NodeInner::validate_asker_packet(self, space, data, device, chain).await
    }
    fn signer_chain(&self) -> Vec<Bytes> {
        NodeInner::signer_chain(self)
    }
    fn note_grantee(&self, space: &Name, key: &Name, ask: &GrantAsk) -> Result<(), String> {
        NodeInner::note_grantee(self, space, key, ask)
    }
    fn key_arrived(&self, space: &Name, epoch: &EpochId, name: &Name, content: Bytes) -> bool {
        NodeInner::key_arrived(self, space, epoch, name, content)
    }
    fn generation(&self) -> u64 {
        NodeInner::generation(self)
    }
    fn may_grant(
        &self,
        space: &Name,
        epoch: &EpochId,
        asker: &Name,
        key: Option<&Name>,
    ) -> Result<(), GrantRefusal> {
        NodeInner::may_grant(self, space, epoch, asker, key)
    }
    fn grant_packet(
        &self,
        space: &Name,
        epoch: &EpochId,
        asker: &Name,
        key: &Name,
        to: &[u8; 32],
        name: &Name,
    ) -> Option<Bytes> {
        NodeInner::grant_packet(self, space, epoch, asker, key, to, name)
    }
    async fn missing_certificate(&self, space: &Name, wire: &Bytes) -> Option<Name> {
        NodeInner::missing_certificate(self, space, wire).await
    }
    fn take_certificate(&self, space: &Name, wire: &Bytes, missing: &Name, cert: Bytes) -> bool {
        NodeInner::take_certificate(self, space, wire, missing, cert)
    }
    fn held_certificate(&self, name: &Name) -> Option<Bytes> {
        NodeInner::held_certificate(self, name)
    }
}

// -- The world the cases run in ----------------------------------------------------

/// A forwarder that delivers nothing and counts what the node sent into it.
pub(crate) struct Counting {
    pub(crate) sent: AtomicUsize,
    /// The highest counter any Sync Interest of the test space's group carried.
    pub(crate) carried: AtomicU64,
}

#[async_trait::async_trait]
impl Connection for Counting {
    async fn send(&self, wire: Bytes) -> Result<(), AppError> {
        self.sent.fetch_add(1, Ordering::SeqCst);
        if let Ok(interest) = ndn_packet::Interest::decode(wire)
            && let Some(group) = crate::wire::sync_group_of(&space())
            && let Some(vector) = ndn_sync::svs_sync::sync_interest_state(
                &group,
                &interest,
                ndn_sync::WireDialect::V2,
            )
        {
            for entry in vector {
                self.carried.fetch_max(entry.seq, Ordering::SeqCst);
            }
        }
        Ok(())
    }
    async fn recv(&self) -> Option<Bytes> {
        futures::future::pending().await
    }
    async fn register_prefix(&self, _prefix: &Name) -> Result<(), AppError> {
        Ok(())
    }
}

/// One device: what a node is started with. Its store and keys outlive every
/// run of its node.
pub(crate) struct Dev {
    pub(crate) name: Name,
    pub(crate) keys: Arc<SecurityManager>,
    pub(crate) validator: Arc<Validator>,
    pub(crate) store: Arc<dyn DataStore>,
    trust: Arc<Trust>,
}

/// What a world's validators are made of: each namespace's anchor, and every
/// device's certificate.
struct Trust {
    anchors: Vec<(Name, Certificate)>,
    certs: Vec<Certificate>,
}

impl Trust {
    /// A validator over these anchors and certificates; `layered`: each
    /// namespace's context declares the role layout.
    fn validator(&self, layered: bool) -> Arc<Validator> {
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        for (ns, anchor) in &self.anchors {
            let mut ctx = SignedTrustContext::hierarchical(ns.clone());
            if layered {
                ctx = ctx.schema_authoritative();
                // As the context `ndn-fwd init` makes: every role needs a cut once lapsed.
                for role in ["admin", "member", "guest", "node"] {
                    ctx = ctx.with_data_requires_cut(role);
                }
            }
            assert!(ctx.add_anchor(anchor.clone()));
            validator.adopt_context(Arc::new(ctx)).unwrap();
        }
        for cert in &self.certs {
            validator.cert_cache().insert(cert.clone());
        }
        validator
    }
}

/// The devices of one world: each namespace has a root key; each device's key
/// is certified by it. A device's namespace is the first component of its name.
pub(crate) async fn world(devices: &[&str]) -> Vec<Dev> {
    world_of(devices, |name| {
        Name::from_components(name.components()[..1].iter().cloned())
    })
    .await
}

/// [`world`] with the namespace of each device given by `ns_of`.
pub(crate) async fn world_of(devices: &[&str], ns_of: impl Fn(&Name) -> Name) -> Vec<Dev> {
    world_with(devices, ns_of, |_| 365 * 24 * 3600 * 1000).await
}

/// [`world_of`] with the validity of each device's certificate, in ms, given by `validity`.
pub(crate) async fn world_with(
    devices: &[&str],
    ns_of: impl Fn(&Name) -> Name,
    validity: impl Fn(&Name) -> u64,
) -> Vec<Dev> {
    world_built(devices, ns_of, validity, false).await
}

/// [`world`] where each device's validator holds the anchors and its own certificate only,
/// as a device's does on a network: every other certificate it needs is fetched by name.
pub(crate) async fn world_apart(devices: &[&str]) -> Vec<Dev> {
    world_built(
        devices,
        |name| Name::from_components(name.components()[..1].iter().cloned()),
        |_| 365 * 24 * 3600 * 1000,
        true,
    )
    .await
}

async fn world_built(
    devices: &[&str],
    ns_of: impl Fn(&Name) -> Name,
    validity: impl Fn(&Name) -> u64,
    apart: bool,
) -> Vec<Dev> {
    let mut roots: Vec<(Name, SecurityManager, Name, Certificate)> = Vec::new();
    for d in devices {
        let ns = ns_of(&n(d));
        if roots.iter().any(|(r, ..)| *r == ns) {
            continue;
        }
        let mgr = SecurityManager::new();
        let key = ns.clone().append("KEY").append("root");
        mgr.generate_ed25519(key.clone()).unwrap();
        let pk = mgr.get_signer_sync(&key).unwrap().public_key().unwrap();
        let anchor = mgr.issue_self_signed(&key, pk, u64::MAX).unwrap();
        roots.push((ns, mgr, key, anchor));
    }
    let mut made = Vec::new();
    for d in devices {
        let name = n(d);
        let ns = ns_of(&name);
        let (_, root, root_key, _) = roots.iter().find(|(r, ..)| *r == ns).unwrap();
        let keys = Arc::new(SecurityManager::new());
        let key = keys
            .generate_ed25519(name.clone().append("KEY").append("1"))
            .unwrap();
        let public = keys.get_signer_sync(&key).unwrap().public_key().unwrap();
        let cert = root
            .certify(&key, public, root_key, validity(&name))
            .await
            .unwrap();
        made.push((name, keys, cert));
    }
    let anchors: Vec<(Name, Certificate)> = roots
        .iter()
        .map(|(ns, _, _, anchor)| (ns.clone(), anchor.clone()))
        .collect();
    let everyone = Arc::new(Trust {
        anchors: anchors.clone(),
        certs: made.iter().map(|(_, _, cert)| cert.clone()).collect(),
    });
    made.iter()
        .map(|(name, keys, cert)| {
            let trust = if apart {
                Arc::new(Trust {
                    anchors: anchors.clone(),
                    certs: vec![cert.clone()],
                })
            } else {
                Arc::clone(&everyone)
            };
            Dev {
                name: name.clone(),
                keys: Arc::clone(keys),
                validator: trust.validator(false),
                store: Arc::new(MemoryStore::new()),
                trust,
            }
        })
        .collect()
}

impl Dev {
    /// The same device, keys and store, judging as a namespace that declares the
    /// role layout does (its contexts' schema is authoritative, spec §2.1): only
    /// an `admin` or `member` device is an owner device.
    pub(crate) fn layered(&self) -> Dev {
        Dev {
            name: self.name.clone(),
            keys: Arc::clone(&self.keys),
            validator: self.trust.validator(true),
            store: Arc::clone(&self.store),
            trust: Arc::clone(&self.trust),
        }
    }
}

fn cut(dev: &Dev, image: CrashStore) -> (Dev, Arc<CrashStore>) {
    let store = Arc::new(image);
    (
        Dev {
            name: dev.name.clone(),
            keys: Arc::clone(&dev.keys),
            validator: Arc::clone(&dev.validator),
            store: Arc::clone(&store) as Arc<dyn DataStore>,
            trust: Arc::clone(&dev.trust),
        },
        store,
    )
}

/// One device of `/alice`, alone.
pub(crate) async fn solo() -> Dev {
    world(&["/alice/laptop"]).await.remove(0)
}

/// Small timings: nothing in a single-node case waits for a peer.
pub(crate) fn cfg() -> Config {
    let mut c = Config::new();
    c.settle = Duration::from_millis(50);
    c
}

/// A node of `dev` over the store it holds, on a connection that counts.
pub(crate) async fn boot(dev: &Dev, config: Config) -> (Node, Arc<Counting>) {
    let conn = Arc::new(Counting {
        sent: AtomicUsize::new(0),
        carried: AtomicU64::new(0),
    });
    let face: Arc<dyn Connection> = Arc::clone(&conn) as Arc<dyn Connection>;
    let node = Node::start(
        Transport {
            node: ndn_app::Node::from_connection(Arc::clone(&face)),
            sync: face,
        },
        dev.name.clone(),
        Arc::clone(&dev.keys),
        Arc::clone(&dev.validator),
        Arc::clone(&dev.store),
        config,
    )
    .await
    .expect("the node starts");
    (node, conn)
}

pub(crate) fn space() -> Name {
    n("/alice/32=data/notes")
}

pub(crate) fn bytes(s: &str) -> Bytes {
    Bytes::copy_from_slice(s.as_bytes())
}

pub(crate) fn public() -> Share {
    Share {
        readers: Readers::Anyone,
        writers: vec![],
    }
}

pub(crate) fn private(readers: &[&str]) -> Share {
    Share {
        readers: Readers::Persons(readers.iter().map(|r| n(r)).collect()),
        writers: vec![],
    }
}

pub(crate) fn durable(d: bool) -> PutOptions {
    PutOptions { durable: Some(d) }
}

/// The next change, or the case fails.
pub(crate) async fn next(changes: &mut Changes) -> Change {
    tokio::time::timeout(Duration::from_secs(10), changes.next())
        .await
        .expect("a change within 10 s")
        .expect("the watch is open")
        .expect("no error")
}

/// Changes until `pick` takes one.
pub(crate) async fn until<T>(changes: &mut Changes, pick: impl Fn(&Change) -> Option<T>) -> T {
    loop {
        let change = next(changes).await;
        if let Some(found) = pick(&change) {
            return found;
        }
    }
}

/// The entry a device wrote, read back from its store.
fn entry_of(store: &Arc<dyn DataStore>, device: &Name, seq: u64) -> Entry {
    let wire = store
        .get(&log_name(device, &space(), seq))
        .expect("the entry is stored");
    let data = Data::decode(wire).unwrap();
    Entry::decode(data.content().unwrap()).unwrap()
}

/// Hand `to` every entry `from` holds of its own, in order, as a fetch would.
pub(crate) async fn deliver(from: &Dev, to: &Node) -> usize {
    let mut taken = 0;
    for seq in 1.. {
        let Some(wire) = from.store.get(&log_name(&from.name, &space(), seq)) else {
            break;
        };
        match to.inner.take(&space(), wire, false).await {
            Taken::Decided { .. } => taken += 1,
            Taken::Pending(w) => panic!("entry {seq} of {} is pending: {w}", from.name),
        }
    }
    taken
}

// -- Certificates ------------------------------------------------------------------

/// A node answers for its own certificate whether or not a walk vouched for it (a lone device
/// never walks its own chain), and for no other certificate it merely holds: Bob's is held at
/// Alice's node unverified (as a certificate fetched is, until a walk reaches an anchor
/// through it), and is not hers to serve (spec §7.6).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_serves_its_own_certificate_and_no_other_it_merely_holds() {
    let devs = world_apart(&["/alice/laptop", "/bob/laptop"]).await;
    let key = n("/alice/laptop/KEY/1");
    let bobs_key = n("/bob/laptop/KEY/1");
    let cache = devs[0].validator.cert_cache();
    let own = cache.remove(&key).expect("alice holds her own certificate");
    assert!(
        cache.insert_unverified(own),
        "held, and vouched for by no walk"
    );
    let bobs = devs[1]
        .validator
        .cert_cache()
        .get(&Arc::new(bobs_key.clone()))
        .expect("bob holds his own certificate");
    assert!(cache.insert_unverified(bobs));
    assert!(!cache.holds_vouched(&key) && !cache.holds_vouched(&bobs_key));

    let (alice, _) = boot(&devs[0], cfg()).await;
    let wire = alice
        .inner
        .held_certificate(&key)
        .expect("the node answers for the certificate of its own key");
    let cert = Data::decode(wire).unwrap();
    assert_eq!(
        ndn_security::cert_name::key_name_of(&cert.name),
        key,
        "it is a certificate of that key"
    );
    assert!(
        alice.inner.held_certificate(&bobs_key).is_none(),
        "another device's certificate, held and not vouched for, is not served"
    );
    assert!(
        alice
            .inner
            .held_certificate(&n("/alice/laptop/KEY/2"))
            .is_none(),
        "a key of the device's name that the node does not sign with is not served"
    );
}

// -- Restart -----------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_restores_held_spaces() {
    let dev = solo().await;
    let (node, _) = boot(&dev, cfg()).await;
    let heap = node.create(&space(), private(&["/bob"])).await.unwrap();
    let id = heap
        .put(&n("/a"), bytes("one"), PutOptions::default())
        .await
        .unwrap();
    let members = heap.members();
    node.close().await;

    let (node, _) = boot(&dev, cfg()).await;
    assert_eq!(node.spaces(), vec![space()], "the space is held again");
    let heap = node.space(&space()).expect("the space is open");
    let item = heap
        .kept(&n("/a"))
        .await
        .unwrap()
        .expect("the value is held");
    assert_eq!(item.bytes, bytes("one"));
    assert_eq!(item.id, id);
    assert_eq!(heap.members(), members, "the fold is replayed");
    let again = node.open(&space()).await.unwrap();
    assert_eq!(again.name(), &space());
    assert_eq!(node.spaces().len(), 1, "open is idempotent");
    // The epoch key was kept: the restored node can still seal.
    heap.put(&n("/b"), bytes("two"), PutOptions::default())
        .await
        .unwrap();
    assert_eq!(
        heap.kept(&n("/b")).await.unwrap().unwrap().bytes,
        bytes("two")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_clean_close_leaves_no_hole_and_no_gap_statement() {
    let dev = solo().await;
    let (node, _) = boot(&dev, cfg()).await;
    let heap = node.create(&space(), public()).await.unwrap();
    let last = heap
        .put(&n("/a"), bytes("one"), PutOptions::default())
        .await
        .unwrap();
    node.close().await;

    let (node, _) = boot(&dev, cfg()).await;
    let heap = node.space(&space()).unwrap();
    let mut changes = heap.watch(&Frontier::new()).await.unwrap();
    let next_id = heap
        .put(&n("/a"), bytes("two"), PutOptions::default())
        .await
        .unwrap();
    assert_eq!(next_id.seq, last.seq + 1, "no hole after a clean close");
    let prev = entry_of(&dev.store, &dev.name, next_id.seq).prev.unwrap();
    assert_eq!(prev.seq, None, "no gap statement after a clean close");
    // Nothing but the put and its value came to the watcher.
    loop {
        match next(&mut changes).await {
            Change::Alert(a) => panic!("a clean start raised {a:?}"),
            Change::Put(item) if item.id == next_id => break,
            _ => {}
        }
    }
}

/// `set` on a frontier made by `Frontier::everything` says what it was told: the
/// device is seen up to that seq, the others stay seen to the end.
#[test]
fn a_frontier_set_after_everything_is_what_get_answers() {
    let (bob, carol) = (n("/bob/laptop"), n("/carol/laptop"));
    let mut frontier = Frontier::everything();
    assert_eq!(frontier.get(&bob), u64::MAX);
    frontier.set(bob.clone(), 7);
    assert_eq!(frontier.get(&bob), 7, "the device set is seen up to 7");
    assert_eq!(frontier.get(&carol), u64::MAX, "the others stay seen");
    let mut empty = Frontier::new();
    empty.set(bob.clone(), 7);
    assert_eq!((empty.get(&bob), empty.get(&carol)), (7, 0));
}

/// A watch from `Frontier::everything` lists no head and tells what follows: a members
/// change reaches it, the values held before it began do not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_watch_from_everything_replays_no_head() {
    let dev = solo().await;
    let (node, _) = boot(&dev, cfg()).await;
    let heap = node.create(&space(), public()).await.unwrap();
    heap.put(&n("/a"), bytes("one"), PutOptions::default())
        .await
        .unwrap();
    let mut changes = heap.watch(&Frontier::everything()).await.unwrap();
    let after = heap
        .put(&n("/b"), bytes("two"), PutOptions::default())
        .await
        .unwrap();
    match next(&mut changes).await {
        Change::Put(item) => {
            assert_eq!(item.id, after, "a head held before the watch was replayed")
        }
        other => panic!("the first thing told was {other:?}, not the put after the watch began"),
    }
}

// -- What a crash takes ------------------------------------------------------------

/// A device over a crash store: the store it holds and a way to the image a
/// power cut leaves.
async fn crashing() -> (Dev, Arc<CrashStore>) {
    let mut dev = solo().await;
    let store = Arc::new(CrashStore::new());
    dev.store = Arc::clone(&store) as Arc<dyn DataStore>;
    (dev, store)
}

fn after_cut(dev: &Dev, image: CrashStore) -> Dev {
    cut(dev, image).0
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn d11_with_no_peer_the_hole_is_signed_and_readers_do_not_wait() {
    let (dev, store) = crashing().await;
    let (node, _) = boot(&dev, cfg()).await;
    let heap = node.create(&space(), public()).await.unwrap();
    let kept = heap
        .put(&n("/kept"), bytes("kept"), durable(true))
        .await
        .unwrap();
    let hold = store.hold();
    let lost = heap
        .put(&n("/lost"), bytes("lost"), durable(false))
        .await
        .unwrap();
    assert!(lost.seq > kept.seq);
    let image = store.crash();
    drop(hold);
    drop(node);

    // A long settle: with no peer known, nothing waits for one.
    let mut slow = cfg();
    slow.settle = Duration::from_secs(60);
    let dev = after_cut(&dev, image);
    let (node, _) = boot(&dev, slow).await;
    let heap = node.space(&space()).unwrap();
    assert_eq!(
        heap.kept(&n("/kept")).await.unwrap().unwrap().bytes,
        bytes("kept")
    );
    assert_eq!(
        heap.kept(&n("/lost")).await.unwrap(),
        None,
        "what no flush covered is gone"
    );
    let mut changes = heap.watch(&Frontier::new()).await.unwrap();
    let id = tokio::time::timeout(
        Duration::from_secs(5),
        heap.put(&n("/after"), bytes("after"), PutOptions::default()),
    )
    .await
    .expect("a put does not wait for peers that are not there")
    .unwrap();
    assert!(
        id.seq > lost.seq,
        "the new entry is above every seq an earlier run may have shown ({} vs {})",
        id.seq,
        lost.seq
    );
    let (after, resumed) = until(&mut changes, |c| match c {
        Change::Alert(Alert::GapSigned { after, resumed }) => Some((*after, *resumed)),
        _ => None,
    })
    .await;
    assert_eq!((after, resumed), (kept.seq, id.seq));
    let prev = entry_of(&dev.store, &dev.name, id.seq).prev.unwrap();
    assert_eq!(
        (prev.seq, prev.digest),
        (Some(kept.seq), kept.digest),
        "the first entry names the entry the hole follows"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn d15_a_durable_put_survives_crash() {
    let (dev, store) = crashing().await;
    let (node, _) = boot(&dev, cfg()).await;
    let heap = node.create(&space(), public()).await.unwrap();
    heap.put(&n("/a"), bytes("durable"), durable(true))
        .await
        .unwrap();
    let image = store.crash();
    drop(node);
    let (node, _) = boot(&after_cut(&dev, image), cfg()).await;
    let heap = node.space(&space()).unwrap();
    assert_eq!(
        heap.kept(&n("/a")).await.unwrap().unwrap().bytes,
        bytes("durable")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn d14_a_failed_reservation_flush_refuses_puts_past_r_with_the_disks_reason_and_reads_continue()
 {
    let (dev, store) = crashing().await;
    let mut small = cfg();
    small.reserve_block = 8;
    let (node, _) = boot(&dev, small).await;
    let heap = node.create(&space(), public()).await.unwrap();
    heap.put(&n("/before"), bytes("before"), durable(true))
        .await
        .unwrap();
    let mut changes = heap.watch(&Frontier::new()).await.unwrap();
    store.fail_syncs("the disk is on fire");
    let mut refused = None;
    for i in 0..40 {
        match heap
            .put(&n("/p"), bytes(&format!("{i}")), durable(false))
            .await
        {
            Ok(_) => {}
            Err(e) => {
                refused = Some(e);
                break;
            }
        }
    }
    let refused = refused.expect("puts past R are refused");
    assert!(
        matches!(&refused, HeapError::Local { reason } if reason.contains("the disk is on fire")),
        "the refusal names the disk's reason: {refused:?}"
    );
    assert_eq!(refused.next(), NextStep::FixLocal);
    assert_eq!(
        heap.kept(&n("/before")).await.unwrap().unwrap().bytes,
        bytes("before"),
        "reads continue"
    );
    let why = until(&mut changes, |c| match c {
        Change::Alert(Alert::StoreFailed { why }) => Some(why.clone()),
        _ => None,
    })
    .await;
    assert!(why.contains("the disk is on fire"), "{why}");
    assert!(node.flush().await.is_err(), "the failure is sticky");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn put_visible_at_once_is_served_before_the_flush_returns() {
    let mut dev = solo().await;
    let held = Arc::new(Held::default());
    dev.store = Arc::clone(&held) as Arc<dyn DataStore>;
    let (node, conn) = boot(&dev, cfg()).await;
    let heap = node.create(&space(), public()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let hold = held.hold();
    let id = heap
        .put(&n("/a"), bytes("one"), durable(false))
        .await
        .unwrap();
    assert!(
        dev.store.contains(&log_name(&dev.name, &space(), id.seq)),
        "the entry is stored when put returns"
    );
    assert!(
        node.inner.served(&space(), &dev.name, id.seq).is_some(),
        "it is served while the flush is held"
    );
    let mut announced = false;
    for _ in 0..40 {
        if conn.carried.load(Ordering::SeqCst) >= id.seq {
            announced = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(announced, "it is announced while the flush is held");
    drop(hold);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn d16_a_members_operation_is_not_served_or_announced_before_its_flush() {
    let mut dev = solo().await;
    let held = Arc::new(Held::default());
    dev.store = Arc::clone(&held) as Arc<dyn DataStore>;
    let (node, conn) = boot(&dev, cfg()).await;
    let heap = node.create(&space(), public()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let hold = held.hold();
    let changing = {
        let heap = heap.clone();
        tokio::spawn(async move {
            heap.change(MembersChange {
                add_writers: vec![n("/bob")],
                ..MembersChange::default()
            })
            .await
        })
    };
    // Applied here at once, and stored.
    let mut seq = 0;
    for _ in 0..100 {
        if heap.members().writers.contains(&n("/bob")) {
            seq = node.inner.head(&space());
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(seq > 0, "the change is applied locally");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(dev.store.contains(&log_name(&dev.name, &space(), seq)));
    assert!(
        node.inner.served(&space(), &dev.name, seq).is_none(),
        "a Members entry is not served before its flush returned"
    );
    assert!(
        conn.carried.load(Ordering::SeqCst) < seq,
        "nor announced before its flush returned"
    );
    assert!(!changing.is_finished(), "change returns after the flush");
    drop(hold);
    changing.await.unwrap().unwrap();
    assert!(node.inner.served(&space(), &dev.name, seq).is_some());
    let mut announced = false;
    for _ in 0..40 {
        if conn.carried.load(Ordering::SeqCst) >= seq {
            announced = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(announced, "and announced once it returned");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unbacked_counter_does_not_raise_the_head() {
    let dev = solo().await;
    let (node, _) = boot(&dev, cfg()).await;
    let heap = node.create(&space(), public()).await.unwrap();
    let first = heap
        .put(&n("/a"), bytes("one"), PutOptions::default())
        .await
        .unwrap();
    let mut changes = heap.watch(&Frontier::new()).await.unwrap();
    node.inner.note_own_counter(&space(), first.seq + 40);
    let seen = until(&mut changes, |c| match c {
        Change::Alert(Alert::UnbackedCounter { device, seen }) => Some((device.clone(), *seen)),
        _ => None,
    })
    .await;
    assert_eq!(seen, (dev.name.clone(), first.seq + 40));
    assert_eq!(node.inner.head(&space()), first.seq);
    let next_id = heap
        .put(&n("/a"), bytes("two"), PutOptions::default())
        .await
        .unwrap();
    assert_eq!(next_id.seq, first.seq + 1, "a counter is not an entry");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_first_entry_after_losing_everything_uses_the_zero_digest_form() {
    let mut devs = world(&["/alice/laptop", "/alice/phone"]).await;
    let (phone_store, phone_crash) = {
        let s = Arc::new(CrashStore::new());
        (Arc::clone(&s) as Arc<dyn DataStore>, s)
    };
    devs[1].store = phone_store;
    let (laptop, _) = boot(&devs[0], cfg()).await;
    laptop.create(&space(), public()).await.unwrap();
    let (phone, _) = boot(&devs[1], cfg()).await;
    let heap = phone.open(&space()).await.unwrap();
    deliver(&devs[0], &phone).await;
    phone.flush().await.unwrap();
    // Everything the phone signs after this is lost; the reservation, which
    // was durable before anything was signed, is not.
    let hold = phone_crash.hold();
    heap.put(&n("/a"), bytes("lost"), durable(false))
        .await
        .unwrap();
    let image = phone_crash.crash();
    drop(hold);
    drop(phone);
    // And the phone's own entries are gone with it: only what others wrote
    // and the reservation remain.
    let again = after_cut(&devs[1], image);
    let (phone, _) = boot(&again, cfg()).await;
    let heap = phone.space(&space()).unwrap();
    let id = heap
        .put(&n("/b"), bytes("again"), PutOptions::default())
        .await
        .unwrap();
    assert!(id.seq > 1);
    let prev = entry_of(&again.store, &again.name, id.seq).prev.unwrap();
    assert_eq!(
        (prev.digest, prev.seq),
        ([0; 32], Some(0)),
        "nothing held: the zero digest with PREV_SEQ 0"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(12))]

    /// Whatever a crash takes, no two puts return one seq: a seq a peer may
    /// have seen is never signed again.
    #[test]
    fn no_two_entries_at_one_seq_for_random_crash_points(
        steps in proptest::collection::vec((0u8..4, 0usize..6, any::<bool>()), 1..14)
    ) {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (mut dev, mut store) = crashing().await;
            let (mut node, _) = boot(&dev, cfg()).await;
            let mut heap = node.create(&space(), public()).await.unwrap();
            let mut last = 0u64;
            for (what, keep, flush) in steps {
                match what {
                    0 | 1 => {
                        let id = heap
                            .put(&n("/p"), bytes("v"), durable(flush))
                            .await
                            .unwrap();
                        prop_assert!(
                            id.seq > last,
                            "seq {} was signed after seq {last} was returned",
                            id.seq
                        );
                        last = id.seq;
                    }
                    2 => {
                        // A power cut that kept some of the unflushed writes.
                        let image = store.crash_torn(keep);
                        drop(heap);
                        drop(node);
                        (dev, store) = cut(&dev, image);
                        let (n2, _) = boot(&dev, cfg()).await;
                        node = n2;
                        heap = node.space(&space()).unwrap();
                    }
                    _ => {
                        node.close().await;
                        let (n2, _) = boot(&dev, cfg()).await;
                        node = n2;
                        heap = node.space(&space()).unwrap();
                    }
                }
            }
            Ok::<(), TestCaseError>(())
        })?;
    }
}

// -- kill -9 -------------------------------------------------------------------------

/// What the child of `d13_kill_9_loses_nothing` is told: `<engine>|<dir>`.
const ROLE: &str = "NDN_HEAP_NODE_KILL_CHILD";

/// The child: a node on a [`PowerCut`] store that puts for ever, printing
/// `put <k>` once each put returned.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "the child of the kill case; it runs only when the case starts it"]
async fn node_kill_child() {
    use std::io::Write;
    let Ok(role) = std::env::var(ROLE) else {
        return;
    };
    let (engine, dir) = role.split_once('|').unwrap();
    let store = Arc::new(PowerCut::open(
        Engine::parse(engine),
        std::path::Path::new(dir),
    ));
    let mut dev = kill_dev().await;
    dev.store = store as Arc<dyn DataStore>;
    let (node, _) = boot(&dev, cfg()).await;
    let heap = node.create(&space(), public()).await.unwrap();
    let mut out = std::io::stdout();
    for k in 1u64.. {
        heap.put(
            &n(&format!("/p/{k}")),
            bytes(&k.to_string()),
            durable(false),
        )
        .await
        .unwrap();
        writeln!(out, "put {k}").unwrap();
        out.flush().unwrap();
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

/// The device both processes are: the same name and key (seeded) so the
/// restarted node is the node the child was.
async fn kill_dev() -> Dev {
    solo().await
}

fn d13(engine: Engine) {
    use crate::test_kit::ChildRun;
    let dir = tempfile::tempdir().unwrap();
    let mut child = ChildRun::start(
        "node::tests::node_kill_child",
        ROLE,
        format!("{}|{}", engine.label(), dir.path().display()),
    );
    let mut put = 0;
    while put < 12 {
        let line = child.next_line();
        if let Some(k) = line.strip_prefix("put ").and_then(|k| k.parse().ok()) {
            put = k;
        }
    }
    child.kill();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut dev = kill_dev().await;
        dev.store = match engine {
            Engine::Fjall => Arc::new(
                ndn_sync::store::BackendStore::open_fjall(engine.live(dir.path())).unwrap(),
            ),
            Engine::Redb => {
                Arc::new(ndn_sync::store::BackendStore::open_redb(engine.live(dir.path())).unwrap())
            }
        };
        let (node, _) = boot(&dev, cfg()).await;
        let heap = node.space(&space()).expect("the space is held again");
        for k in 1..=put {
            let item = heap
                .kept(&n(&format!("/p/{k}")))
                .await
                .unwrap()
                .unwrap_or_else(|| {
                    panic!(
                        "on {}, put {k} had returned before kill -9 but the store lacks it",
                        engine.label()
                    )
                });
            assert_eq!(item.bytes, bytes(&k.to_string()));
        }
    });
}

#[test]
fn d13_kill_9_loses_nothing_on_fjall() {
    d13(Engine::Fjall);
}

#[test]
fn d13_kill_9_loses_nothing_on_redb() {
    d13(Engine::Redb);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_revoked_while_the_node_was_off_is_withdrawn_at_start() {
    let devs = world(&["/alice/laptop", "/alice/phone"]).await;
    let (laptop, _) = boot(&devs[0], cfg()).await;
    laptop.create(&space(), public()).await.unwrap();
    let (phone, _) = boot(&devs[1], cfg()).await;
    let theirs = phone.open(&space()).await.unwrap();
    deliver(&devs[0], &phone).await;
    theirs
        .put(&n("/from-phone"), bytes("held"), PutOptions::default())
        .await
        .unwrap();
    deliver(&devs[1], &laptop).await;
    let heap = laptop.space(&space()).unwrap();
    assert!(heap.kept(&n("/from-phone")).await.unwrap().is_some());
    laptop.close().await;

    // While the laptop is off, its keyring adopts a context that revokes the
    // phone's key.
    let phone_key = devs[1].name.clone().append("KEY").append("1");
    let revoking = SignedTrustContext::hierarchical(n("/alice"))
        .with_version(2)
        .with_revocation(phone_key);
    devs[0]
        .validator
        .keyring()
        .adopt_update(Arc::new(revoking))
        .expect("the revoking context is adopted");

    let (laptop, _) = boot(&devs[0], cfg()).await;
    let heap = laptop.space(&space()).unwrap();
    assert_eq!(
        heap.kept(&n("/from-phone")).await.unwrap(),
        None,
        "what a revoked key signed is judged again at start and withdrawn"
    );
}

/// The scan for values in pieces runs after every entry taken: a head it has
/// settled is not read from the store again, or a space of many heads would
/// hold its lock for a store read per head on every entry.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rescan_for_values_in_pieces_reads_no_head_it_has_settled() {
    let mut dev = solo().await;
    let held = Arc::new(Held::default());
    dev.store = Arc::clone(&held) as Arc<dyn DataStore>;
    let (node, _) = boot(&dev, cfg()).await;
    let heap = node.create(&space(), public()).await.unwrap();
    for i in 0..40 {
        heap.put(&n(&format!("/path/{i}")), bytes("v"), durable(false))
            .await
            .unwrap();
    }
    let inner = node.inner.space_of(&space()).unwrap();
    assert!(inner.unassembled().is_empty());
    tokio::time::sleep(Duration::from_millis(200)).await;
    let before = held.gets();
    assert!(inner.unassembled().is_empty());
    assert_eq!(
        held.gets(),
        before,
        "the second scan read the entries of heads the first had settled"
    );
}

/// Opening a space reads the small records it replays and no payload: not the
/// entries it signed, not their pieces. A device with gigabytes of its own
/// blobs must not need them in memory to start (review M5).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn opening_a_space_reads_no_payload_and_no_piece() {
    let mut dev = solo().await;
    let metered = Arc::new(Metered::new(Arc::new(MemoryStore::new())));
    dev.store = Arc::clone(&metered) as Arc<dyn DataStore>;
    let (node, _) = boot(&dev, cfg()).await;
    let heap = node.create(&space(), public()).await.unwrap();
    let payload = 200_000;
    for i in 0..5 {
        let value = Bytes::from(vec![i as u8; payload]);
        heap.put(&n(&format!("/blob/{i}")), value, durable(true))
            .await
            .unwrap();
    }
    node.close().await;

    metered.reset();
    let (node, _) = boot(&dev, cfg()).await;
    let read = metered.octets_read();
    assert!(
        read < payload,
        "the reopen read {read} octets from the store (5 values of {payload} octets are stored in pieces): \
         it must read the records it replays and no entry or piece"
    );
    node.close().await;
}

/// An Interest that arrives while a Members entry is being signed (the entry
/// stored, the lock still held) must not be answered with it before a flush
/// covers it: whether it may be served is decided under the log's lock, where
/// the entry is recorded as held back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_interest_during_signing_cannot_get_a_structural_entry_before_its_flush() {
    let mut dev = solo().await;
    let held = Arc::new(Held::default());
    dev.store = Arc::clone(&held) as Arc<dyn DataStore>;
    let (node, _) = boot(&dev, cfg()).await;
    node.create(&space(), public()).await.unwrap();
    let inner = node.inner.space_of(&space()).unwrap();
    let holding = held.hold();

    let body = crate::wire::MembersBody {
        create: None,
        ops: vec![crate::wire::Op::Add {
            id: [9; 16],
            who: n("/alice/tablet"),
            role: crate::wire::Role::Writer,
            epoch: None,
        }],
    };
    let (asked, routed, seq) = {
        let mut log = inner.log.lock();
        let crate::log::Step::Done(id, fx) = log.sign_members(body, node.inner.now()).unwrap()
        else {
            panic!("the reservation covers the next seq");
        };
        let seq = id.seq;
        let (asking, device) = (Arc::clone(&node.inner), dev.name.clone());
        let (began_tx, began_rx) = std::sync::mpsc::channel();
        let asker = std::thread::spawn(move || {
            began_tx.send(()).unwrap();
            asking.served(&space(), &device, seq)
        });
        began_rx.recv().unwrap();
        // Give the asker the time to take what it can before the lock.
        std::thread::sleep(Duration::from_millis(200));
        let routed = inner.route(&node.inner, &log, fx, true);
        (asker, routed, seq)
    };
    inner.finish(&node.inner, routed);

    assert!(
        asked.join().unwrap().is_none(),
        "a Members entry was served before the flush that covers it"
    );
    drop(holding);
    node.flush().await.unwrap();
    assert!(
        node.inner.served(&space(), &dev.name, seq).is_some(),
        "once the flush covering it returned, it is served"
    );
    node.close().await;
}

// -- The owner rule: only an `admin` or `member` device of the owner holds its powers (§9.9) ---

/// Small timings, and no wait for a peer that never answers on the counting forwarder.
fn quick() -> Config {
    let mut c = cfg();
    c.lifetime = Duration::from_millis(100);
    c
}

/// A space stored under the earlier rule, when every device of the owner's namespace was an
/// owner device, and a guest device had signed a `Members` entry: at start under the role
/// layout it is judged once, the entry leaves the fold, and the rule is recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_guest_devices_members_entry_stored_under_the_old_rule_is_withdrawn_at_start() {
    let devs = world(&["/alice/member/laptop", "/alice/guest/bob"]).await;
    let (laptop, guest) = (&devs[0], &devs[1]);
    let mallory = n("/mallory");

    // The earlier rule: a namespace with no role layout declared.
    let (lnode, _) = boot(laptop, quick()).await;
    let heap = lnode.create(&space(), public()).await.unwrap();
    let (gnode, _) = boot(guest, quick()).await;
    let gheap = gnode.open(&space()).await.unwrap();
    deliver(laptop, &gnode).await;
    gheap
        .change(MembersChange {
            add_writers: vec![mallory.clone()],
            ..MembersChange::default()
        })
        .await
        .expect("a device of a flat namespace is an owner device");
    deliver(guest, &lnode).await;
    assert!(
        heap.members().writers.contains(&mallory),
        "precondition: the earlier rule applied the guest's Members entry"
    );
    lnode.close().await;
    gnode.close().await;
    laptop.store.remove(&Kind::RULE.of(&space()));

    let layered = laptop.layered();
    let (lnode, _) = boot(&layered, quick()).await;
    let heap = lnode.space(&space()).expect("the space is held again");
    assert!(
        !heap.members().writers.contains(&mallory),
        "the guest's Members entry is withdrawn by the one judgement at start"
    );
    assert_eq!(
        layered.store.get(&Kind::RULE.of(&space())).as_deref(),
        Some(&[OWNER_RULE][..]),
        "and the space is recorded as judged by the rule"
    );
    lnode.close().await;
}

/// A sealed space stored under the earlier rule: a guest device of the owner may hold the key
/// in force, so an owner device signs a fresh epoch at start, once, and records the rule.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_owner_device_signs_a_fresh_epoch_for_a_sealed_space_stored_under_the_old_rule() {
    let devs = world(&["/alice/member/laptop"]).await;
    let laptop = &devs[0];
    let (node, _) = boot(laptop, quick()).await;
    let heap = node.create(&space(), private(&["/bob"])).await.unwrap();
    let (before, _) = heap.epoch().expect("an epoch is in force");
    node.close().await;
    laptop.store.remove(&Kind::RULE.of(&space()));

    let layered = laptop.layered();
    let (node, _) = boot(&layered, quick()).await;
    let heap = node.space(&space()).unwrap();
    let rule = || layered.store.get(&Kind::RULE.of(&space()));
    for _ in 0..200 {
        if rule().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(
        rule().as_deref(),
        Some(&[OWNER_RULE][..]),
        "the rule is recorded"
    );
    let (now, complete) = heap.epoch().unwrap();
    assert!(complete);
    assert!(
        now.seq > before.seq,
        "a fresh epoch is in force: {before:?} then {now:?}"
    );
    node.close().await;

    // A restart signs none more.
    let (node, _) = boot(&layered, quick()).await;
    let heap = node.space(&space()).unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(heap.epoch().unwrap().0, now, "no epoch is signed again");
    node.close().await;
}

/// Stage-7 I5: a sealed space stored under rule 1 (before the stage-7 grant rules: guest and
/// node devices of readers were granted keys, and no grantee was tracked) is judged again at
/// start under rule 2: an owner device signs a fresh epoch, once, and records rule 2.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sealed_space_stored_under_rule_one_gets_a_fresh_epoch_at_start() {
    let devs = world(&["/alice/member/laptop"]).await;
    let laptop = &devs[0];
    let (node, _) = boot(laptop, quick()).await;
    let heap = node.create(&space(), private(&["/bob"])).await.unwrap();
    let (before, _) = heap.epoch().expect("an epoch is in force");
    node.close().await;
    // What the store held before rule 2.
    laptop
        .store
        .insert(Kind::RULE.of(&space()), Bytes::from_static(&[1]));

    let layered = laptop.layered();
    let (node, _) = boot(&layered, quick()).await;
    let heap = node.space(&space()).unwrap();
    let rule = || layered.store.get(&Kind::RULE.of(&space()));
    for _ in 0..200 {
        if rule().as_deref() == Some(&[2][..]) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(
        rule().as_deref(),
        Some(&[2][..]),
        "a space stored under rule 1 is not judged again under rule 2"
    );
    let (now, complete) = heap.epoch().unwrap();
    assert!(complete);
    assert!(
        now.seq > before.seq,
        "a fresh epoch is in force: {before:?} then {now:?}"
    );
    node.close().await;
}
