//! Nodes over one real forwarder: what a peer sees of a put, and what a
//! restarted device gets back from its peers (spec §4, rules 6 and 7).
//!
//! Every device is certified under its namespace's root, so what one node
//! signs another verifies as it would from the network.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use ndn_app::EngineAppExt;
use ndn_engine::{EngineBuilder, ForwarderEngine};
use ndn_foundation_types::Name;
use ndn_sync::{DataStore, SyncUpdate};
use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

use super::tests::{Dev, bytes, cfg, durable, public, space, until, world};
use super::*;
use crate::log::{Alert, Frontier};
use crate::space::PutOptions;
use crate::test_kit::{CrashStore, n};
use crate::wire::{Entry, log_name};

#[path = "mesh_net_tests.rs"]
mod net;

/// Devices on one forwarder; the sync group of every namespace is carried.
struct Mesh {
    engine: ForwarderEngine,
    devs: Vec<Dev>,
    cancels: Vec<Mutex<CancellationToken>>,
}

async fn mesh(devices: &[&str]) -> Mesh {
    let devs = world(devices).await;
    let (engine, shutdown) = EngineBuilder::new(Default::default())
        .build()
        .await
        .expect("an engine");
    shutdown.detach();
    let mut namespaces: Vec<Name> = Vec::new();
    for d in devices {
        let ns = Name::from_components(n(d).components()[..1].iter().cloned());
        if !namespaces.contains(&ns) {
            namespaces.push(ns);
        }
    }
    for ns in &namespaces {
        ndn_namespace::sync_group::carry(&engine, ns);
    }
    let cancels = devs
        .iter()
        .map(|_| Mutex::new(CancellationToken::new()))
        .collect();
    Mesh {
        engine,
        devs,
        cancels,
    }
}

/// Timings that let a vector cross in milliseconds.
fn fast() -> Config {
    let mut c = cfg();
    c.settle = Duration::from_secs(3);
    c.svs.jitter_ms = 20;
    c.svs.suppression_period = Duration::from_millis(30);
    c.svs.sync_interval = Duration::from_secs(1);
    c
}

impl Mesh {
    async fn boot(&self, i: usize, config: Config) -> Node {
        self.boot_on(i, Arc::clone(&self.devs[i].store), config)
            .await
    }

    /// Device `i` again on new faces, over `store`: the old faces end first.
    async fn boot_on(&self, i: usize, store: Arc<dyn DataStore>, config: Config) -> Node {
        let cancel = {
            let mut held = self.cancels[i].lock();
            held.cancel();
            *held = CancellationToken::new();
            held.clone()
        };
        let dev = &self.devs[i];
        tokio::time::timeout(
            Duration::from_secs(20),
            Node::start(
                Transport {
                    node: self.engine.app_node(cancel.child_token()),
                    sync: self.engine.app_face(cancel.child_token()),
                },
                dev.name.clone(),
                Arc::clone(&dev.keys),
                Arc::clone(&dev.validator),
                store,
                config,
            ),
        )
        .await
        .unwrap_or_else(|_| panic!("{} did not finish starting within 20 s", dev.name))
        .expect("the node starts")
    }

    fn kill(&self, i: usize) {
        self.cancels[i].lock().cancel();
    }
}

/// Poll `f` until it holds, or fail with `what`.
async fn eventually<F: Future<Output = bool>>(what: &str, mut f: impl FnMut() -> F) {
    for _ in 0..300 {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("not within 15 s: {what}");
}

async fn has(heap: &Heap, path: &str, value: &str) -> bool {
    matches!(heap.get(&n(path)).await, Ok(Some(i)) if i.bytes == bytes(value))
}

fn entry_of(store: &Arc<dyn DataStore>, device: &Name, seq: u64) -> Entry {
    let wire = store
        .get(&log_name(device, &space(), seq))
        .expect("the entry is stored");
    let data = ndn_packet::Data::decode(wire).unwrap();
    Entry::decode(data.content().unwrap()).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_put_reaches_a_peers_watcher_through_the_forwarder() {
    let m = mesh(&["/alice/laptop", "/alice/phone"]).await;
    let (laptop, phone) = (m.boot(0, fast()).await, m.boot(1, fast()).await);
    let heap = laptop.create(&space(), public()).await.unwrap();
    let theirs = phone.open(&space()).await.unwrap();
    let mut changes = theirs.watch(&Frontier::new()).await.unwrap();
    eventually("the phone sees the space's creation", || async {
        theirs.ready()
    })
    .await;
    let id = heap
        .put(&n("/a"), bytes("one"), PutOptions::default())
        .await
        .unwrap();
    let item = until(&mut changes, |c| match c {
        Change::Put(item) if item.path == n("/a") => Some(item.clone()),
        _ => None,
    })
    .await;
    assert_eq!((item.bytes, item.id), (bytes("one"), id));
    assert_eq!(item.writer, m.devs[0].name);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn d10_a_crash_between_put_and_flush_with_the_peer_reachable_returns_the_entries_whole() {
    let mut m = mesh(&["/alice/laptop", "/alice/phone"]).await;
    let crash = Arc::new(CrashStore::new());
    m.devs[0].store = Arc::clone(&crash) as Arc<dyn DataStore>;
    let (laptop, phone) = (m.boot(0, fast()).await, m.boot(1, fast()).await);
    let heap = laptop.create(&space(), public()).await.unwrap();
    let theirs = phone.open(&space()).await.unwrap();
    eventually("the phone sees the creation", || async { theirs.ready() }).await;
    // The phone writes; the laptop holds it durably (so it knows a peer).
    theirs
        .put(&n("/b"), bytes("phone"), durable(true))
        .await
        .unwrap();
    eventually("the laptop holds the phone's entry", || async {
        has(&heap, "/b", "phone").await
    })
    .await;
    laptop.flush().await.unwrap();
    // The laptop's put reaches the phone before any flush covers it.
    let hold = crash.hold();
    let lost = heap
        .put(&n("/a"), bytes("unflushed"), durable(false))
        .await
        .unwrap();
    eventually("the phone holds the laptop's entry", || async {
        has(&theirs, "/a", "unflushed").await
    })
    .await;
    let image = crash.crash();
    drop(hold);
    drop(heap);
    drop(laptop);
    m.kill(0);

    // The laptop is back on the disk a power cut left, without the entry.
    let image = Arc::new(image);
    let again = m
        .boot_on(0, Arc::clone(&image) as Arc<dyn DataStore>, fast())
        .await;
    let heap = again.space(&space()).unwrap();
    eventually("the entry comes back whole from the peer", || async {
        has(&heap, "/a", "unflushed").await
    })
    .await;
    // The counter the laptop joined with is an entry's seq, not the end of
    // what it reserved: the phone, which holds all it signed, wants nothing
    // of it.
    eventually("the phone wants nothing of the laptop", || async {
        theirs.ready()
    })
    .await;
    let id = heap
        .put(&n("/c"), bytes("next"), PutOptions::default())
        .await
        .unwrap();
    // The resume point is above everything reserved (spec §4, rule 6), and
    // the gap statement names the entry the peer returned as the one the
    // hole follows.
    assert!(id.seq > lost.seq, "{} vs {}", id.seq, lost.seq);
    let prev = entry_of(&(image as Arc<dyn DataStore>), &m.devs[0].name, id.seq)
        .prev
        .unwrap();
    assert_eq!(
        (prev.seq, prev.digest),
        (Some(lost.seq), lost.digest),
        "the entry the peer held is the adopted head the first entry chains to"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn d9_a_crash_between_put_and_flush_never_re_signs_a_seq_a_peer_saw() {
    let mut m = mesh(&["/alice/laptop", "/alice/phone"]).await;
    let crash = Arc::new(CrashStore::new());
    m.devs[0].store = Arc::clone(&crash) as Arc<dyn DataStore>;
    let (laptop, phone) = (m.boot(0, fast()).await, m.boot(1, fast()).await);
    let heap = laptop.create(&space(), public()).await.unwrap();
    let theirs = phone.open(&space()).await.unwrap();
    eventually("the phone sees the creation", || async { theirs.ready() }).await;
    let hold = crash.hold();
    let seen = heap
        .put(&n("/a"), bytes("seen"), durable(false))
        .await
        .unwrap();
    eventually("the phone holds it", || async {
        has(&theirs, "/a", "seen").await
    })
    .await;
    let image = crash.crash();
    drop(hold);
    drop(heap);
    drop(laptop);
    // The phone is not reachable to the restarted laptop: it is on its own.
    m.kill(1);
    let again = m.boot_on(0, Arc::new(image), fast()).await;
    let heap = again.space(&space()).unwrap();
    let id = heap
        .put(&n("/b"), bytes("after"), PutOptions::default())
        .await
        .unwrap();
    assert!(
        id.seq > seen.seq,
        "the laptop signed seq {} after the phone saw {}",
        id.seq,
        seen.seq
    );
    // The phone, back, holds the same entry it held and the new one beside
    // it: nothing it was shown is contradicted.
    let phone = m.boot_on(1, Arc::clone(&m.devs[1].store), fast()).await;
    let theirs = phone.space(&space()).unwrap();
    let mut changes = theirs.watch(&Frontier::new()).await.unwrap();
    eventually("the phone holds the new entry", || async {
        has(&theirs, "/b", "after").await
    })
    .await;
    assert!(has(&theirs, "/a", "seen").await || theirs.get(&n("/a")).await.unwrap().is_none());
    while let Ok(Some(Ok(change))) =
        tokio::time::timeout(Duration::from_millis(300), changes.next()).await
    {
        assert!(
            !matches!(change, Change::Alert(Alert::Equivocation { .. })),
            "{change:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn d12_a_restored_old_image_with_peers_online_raises_rolledback_and_reuses_nothing() {
    let mut m = mesh(&["/alice/laptop", "/alice/phone"]).await;
    let crash = Arc::new(CrashStore::new());
    m.devs[0].store = Arc::clone(&crash) as Arc<dyn DataStore>;
    let mut small = fast();
    small.reserve_block = 8;
    let (laptop, phone) = (
        m.boot(0, small.clone()).await,
        m.boot(1, small.clone()).await,
    );
    let heap = laptop.create(&space(), public()).await.unwrap();
    let theirs = phone.open(&space()).await.unwrap();
    eventually("the phone sees the creation", || async { theirs.ready() }).await;
    theirs
        .put(&n("/b"), bytes("phone"), durable(true))
        .await
        .unwrap();
    eventually("the laptop holds the phone's entry", || async {
        has(&heap, "/b", "phone").await
    })
    .await;
    laptop.flush().await.unwrap();
    // A backup of the laptop's disk, taken now.
    let old = crash.crash();
    // The laptop goes on, far past what the backup reserved.
    let mut top = 0;
    for i in 0..30 {
        top = heap
            .put(&n("/a"), bytes(&format!("v{i}")), durable(true))
            .await
            .unwrap()
            .seq;
    }
    eventually("the phone holds the newest", || async {
        has(&theirs, "/a", "v29").await
    })
    .await;
    drop(heap);
    drop(laptop);
    m.kill(0);

    // The old image is put back, with the phone online.
    let again = m.boot_on(0, Arc::new(old), fast()).await;
    let heap = again.space(&space()).unwrap();
    eventually(
        "every entry the phone holds of the laptop is held again",
        || async { again.inner.head(&space()) >= top },
    )
    .await;
    // What this device signed before the image was taken is applied here as
    // it is at the phone: both read the same value at /a.
    eventually("the laptop applies its own newest entry", || async {
        has(&heap, "/a", "v29").await
    })
    .await;
    let mut changes = heap.watch(&Frontier::new()).await.unwrap();
    let (reserved, seen) = until(&mut changes, |c| match c {
        Change::Alert(Alert::RolledBack { reserved, seen }) => Some((*reserved, *seen)),
        _ => None,
    })
    .await;
    assert!(seen > reserved, "evidence lies above what was reserved");
    let id = heap
        .put(&n("/z"), bytes("after"), PutOptions::default())
        .await
        .unwrap();
    assert!(
        id.seq > top,
        "nothing the phone holds of the laptop is signed over again ({} vs {top})",
        id.seq
    );
    // The counter the laptop announces is the seq it signed: the phone, which
    // holds up to `top`, asks for the new entry and shows it.
    eventually("the phone sees the laptop's new entry", || async {
        has(&theirs, "/z", "after").await
    })
    .await;
}

/// Sync Interests are unsigned: a counter for a device the log vouches for
/// names an entry the reader may probe, not a range it must walk. The heap
/// stays ready, with nothing wanted (M4).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forged_counter_for_a_vouched_device_leaves_the_heap_ready() {
    let m = mesh(&["/alice/laptop", "/alice/phone"]).await;
    let (laptop, phone) = (m.boot(0, fast()).await, m.boot(1, fast()).await);
    let heap = laptop.create(&space(), public()).await.unwrap();
    let theirs = phone.open(&space()).await.unwrap();
    eventually("the phone sees the creation", || async { theirs.ready() }).await;
    theirs
        .put(&n("/b"), bytes("phone"), durable(true))
        .await
        .unwrap();
    eventually("the laptop holds the phone's entry", || async {
        has(&heap, "/b", "phone").await
    })
    .await;
    heap.inner.group.on_update(SyncUpdate {
        publisher: m.devs[1].name.to_string(),
        name: m.devs[1].name.clone(),
        low_seq: 1,
        high_seq: 1_000_000,
        mapping: None,
        serving_party: None,
    });
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        heap.ready() && heap.inner.log.lock().missing().is_empty(),
        "a counter nothing signed leaves nothing wanted"
    );
}

/// An old image that was closed cleanly looks complete, and the device's
/// peers hold what it signed since. With peers known the device waits for its
/// own counter before its first put, so it signs above what they hold instead
/// of over it (the wait is bounded by `Config::settle`, liveness only).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn d13_a_clean_old_image_restored_with_peers_online_signs_above_what_they_hold() {
    let mut m = mesh(&["/alice/laptop", "/alice/phone"]).await;
    let crash = Arc::new(CrashStore::new());
    m.devs[0].store = Arc::clone(&crash) as Arc<dyn DataStore>;
    let (laptop, phone) = (m.boot(0, fast()).await, m.boot(1, fast()).await);
    let heap = laptop.create(&space(), public()).await.unwrap();
    let theirs = phone.open(&space()).await.unwrap();
    eventually("the phone sees the creation", || async { theirs.ready() }).await;
    theirs
        .put(&n("/b"), bytes("phone"), durable(true))
        .await
        .unwrap();
    eventually("the laptop holds the phone's entry", || async {
        has(&heap, "/b", "phone").await
    })
    .await;
    drop(heap);
    laptop.close().await;
    // A backup taken after a clean close.
    let old = crash.crash();
    // The laptop runs on and signs.
    let laptop = m.boot(0, fast()).await;
    let heap = laptop.space(&space()).unwrap();
    let mut top = 0;
    for i in 0..5 {
        top = heap
            .put(&n("/a"), bytes(&format!("v{i}")), durable(true))
            .await
            .unwrap()
            .seq;
    }
    eventually("the phone holds the newest", || async {
        has(&theirs, "/a", "v4").await
    })
    .await;
    drop(heap);
    laptop.close().await;
    m.kill(0);

    // The old, clean image is put back with the phone online.
    let again = m.boot_on(0, Arc::new(old), fast()).await;
    let heap = again.space(&space()).unwrap();
    let id = heap
        .put(&n("/z"), bytes("after"), PutOptions::default())
        .await
        .unwrap();
    assert!(
        id.seq > top,
        "the first put signed seq {} where the phone holds the laptop's entries up to {top}",
        id.seq
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn follow_stores_and_serves_but_publishes_no_vector_entry_and_reads_nothing_sealed() {
    let m = mesh(&["/alice/laptop", "/bob/phone", "/carol/tablet"]).await;
    let (alice, carrier, carol) = (
        m.boot(0, fast()).await,
        m.boot(1, fast()).await,
        m.boot(2, fast()).await,
    );
    let heap = alice
        .create(
            &space(),
            Share {
                readers: Readers::Persons(vec![n("/carol")]),
                writers: vec![],
            },
        )
        .await
        .unwrap();
    let follower = carrier.follow(&space()).await.unwrap();
    heap.put(&n("/secret"), bytes("for carol"), durable(true))
        .await
        .unwrap();
    // The carrier holds the creation, the epoch and the sealed entry, and no
    // more than they are: it signed nothing.
    eventually("the carrier holds the three entries", || async {
        follower.held() >= 3
    })
    .await;
    assert_eq!(carrier.signatures(), 0, "a carrier signs nothing");
    assert!(
        carrier.space(&space()).is_none(),
        "and has no handle to read by"
    );
    // Carol, who can read, is served by the carrier alone once Alice is off
    // the network.
    m.kill(0);
    let theirs = carol.open(&space()).await.unwrap();
    eventually("carol holds the entries the carrier served", || async {
        theirs.ready() && !theirs.members().writers.is_empty() && carol.held() >= 3
    })
    .await;
    follower.close().await;
}
