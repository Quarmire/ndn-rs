//! The node over `Unconnected` faces: what survives a restart, what a crash
//! takes and what it never takes, when an entry is served and announced.
//!
//! Devices are real: each has a key certified by its namespace's root, and
//! every device's validator holds every namespace's context and every
//! certificate, so entries one node signs another can be handed
//! (`Host::take`) and judged as a fetch would.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
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
use crate::space::{Changes, PutOptions};
use crate::sync::{Host, Taken};
use crate::test_kit::{CrashStore, Engine, Held, PowerCut, n};
use crate::wire::{Body, Entry, log_name};

// -- The world the cases run in ----------------------------------------------------

/// A forwarder that delivers nothing and counts what the node sent into it.
pub(crate) struct Counting {
    pub(crate) sent: AtomicUsize,
}

#[async_trait::async_trait]
impl Connection for Counting {
    async fn send(&self, _wire: Bytes) -> Result<(), AppError> {
        self.sent.fetch_add(1, Ordering::SeqCst);
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
}

/// The devices of one world: each namespace has a root key; each device's key
/// is certified by it.
pub(crate) async fn world(devices: &[&str]) -> Vec<Dev> {
    let mut roots: Vec<(Name, SecurityManager, Name, Certificate)> = Vec::new();
    for d in devices {
        let ns = Name::from_components(n(d).components()[..1].iter().cloned());
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
        let ns = Name::from_components(name.components()[..1].iter().cloned());
        let (_, root, root_key, _) = roots.iter().find(|(r, ..)| *r == ns).unwrap();
        let keys = Arc::new(SecurityManager::new());
        let key = keys
            .generate_ed25519(name.clone().append("KEY").append("1"))
            .unwrap();
        let public = keys.get_signer_sync(&key).unwrap().public_key().unwrap();
        let cert = root
            .certify(&key, public, root_key, 365 * 24 * 3600 * 1000)
            .await
            .unwrap();
        made.push((name, keys, cert));
    }
    made.iter()
        .map(|(name, keys, _)| {
            let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
            for (ns, _, _, anchor) in &roots {
                let ctx = SignedTrustContext::hierarchical(ns.clone());
                assert!(ctx.add_anchor(anchor.clone()));
                validator.adopt_context(Arc::new(ctx)).unwrap();
            }
            for (_, _, cert) in &made {
                validator.cert_cache().insert(cert.clone());
            }
            Dev {
                name: name.clone(),
                keys: Arc::clone(keys),
                validator,
                store: Arc::new(MemoryStore::new()),
            }
        })
        .collect()
}

fn cut(dev: &Dev, image: CrashStore) -> (Dev, Arc<CrashStore>) {
    let store = Arc::new(image);
    (
        Dev {
            name: dev.name.clone(),
            keys: Arc::clone(&dev.keys),
            validator: Arc::clone(&dev.validator),
            store: Arc::clone(&store) as Arc<dyn DataStore>,
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
        match to.inner.take(&space(), wire).await {
            Taken::Decided { .. } => taken += 1,
            Taken::Pending(w) => panic!("entry {seq} of {} is pending: {w}", from.name),
        }
    }
    taken
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
        .get(&n("/a"))
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
        heap.get(&n("/b")).await.unwrap().unwrap().bytes,
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
        heap.get(&n("/kept")).await.unwrap().unwrap().bytes,
        bytes("kept")
    );
    assert_eq!(
        heap.get(&n("/lost")).await.unwrap(),
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
        heap.get(&n("/a")).await.unwrap().unwrap().bytes,
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
        heap.get(&n("/before")).await.unwrap().unwrap().bytes,
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
    let before = conn.sent.load(Ordering::SeqCst);
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
        if conn.sent.load(Ordering::SeqCst) > before {
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
    let before = conn.sent.load(Ordering::SeqCst);
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
    assert_eq!(
        conn.sent.load(Ordering::SeqCst),
        before,
        "nor announced before its flush returned"
    );
    assert!(!changing.is_finished(), "change returns after the flush");
    drop(hold);
    changing.await.unwrap().unwrap();
    assert!(node.inner.served(&space(), &dev.name, seq).is_some());
    let mut announced = false;
    for _ in 0..40 {
        if conn.sent.load(Ordering::SeqCst) > before {
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
    node.inner.note_counter(&space(), &dev.name, first.seq + 40);
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
                .get(&n(&format!("/p/{k}")))
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
    assert!(heap.get(&n("/from-phone")).await.unwrap().is_some());
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
        heap.get(&n("/from-phone")).await.unwrap(),
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
    assert!(inner.unassembled(&node.inner).is_empty());
    tokio::time::sleep(Duration::from_millis(200)).await;
    let before = held.gets();
    assert!(inner.unassembled(&node.inner).is_empty());
    assert_eq!(
        held.gets(),
        before,
        "the second scan read the entries of heads the first had settled"
    );
}
