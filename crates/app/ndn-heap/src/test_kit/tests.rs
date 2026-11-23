//! The store doubles' own invariants, and the two on-disk engines under a
//! killed process: what `kill -9` and a power cut leave.

use super::*;
use crate::store::Stage;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

fn put(store: &dyn DataStore, name: &str, value: &'static str) {
    store.insert(n(name), Bytes::from_static(value.as_bytes()));
}

fn holds(store: &dyn DataStore, name: &str, value: &'static str) -> bool {
    store.get(&n(name)) == Some(Bytes::from_static(value.as_bytes()))
}

#[test]
fn crash_returns_the_image_at_the_last_returned_sync() {
    let store = CrashStore::new();
    put(&store, "/a", "1");
    store.sync().unwrap();
    put(&store, "/b", "2");
    store.remove(&n("/a"));

    let disk = store.crash();
    assert!(holds(&disk, "/a", "1"), "a synced write survives a crash");
    assert!(
        !disk.contains(&n("/b")),
        "a write after the last sync is lost by a crash"
    );
    assert!(
        holds(&store, "/b", "2") && !store.contains(&n("/a")),
        "the live store is untouched by taking an image"
    );
}

#[test]
fn crash_torn_keeps_a_prefix_of_the_unsynced_writes_and_never_splits_a_batch() {
    let store = CrashStore::new();
    put(&store, "/w1", "1");
    store.apply(vec![
        StoreOp::Insert(n("/b1"), Bytes::from_static(b"1")),
        StoreOp::Insert(n("/b2"), Bytes::from_static(b"2")),
    ]);
    put(&store, "/w3", "3");
    assert_eq!(store.unsynced(), 3, "a batch is one write");

    let seen = |keep: usize| {
        let disk = store.crash_torn(keep);
        ["/w1", "/b1", "/b2", "/w3"]
            .map(|name| disk.contains(&n(name)))
            .to_vec()
    };
    assert_eq!(seen(0), [false, false, false, false]);
    assert_eq!(seen(1), [true, false, false, false]);
    assert_eq!(seen(2), [true, true, true, false]);
    assert_eq!(seen(3), [true, true, true, true]);
    assert_eq!(seen(99), [true, true, true, true]);
}

#[test]
fn a_sync_covers_only_the_writes_that_returned_before_it_started() {
    let store = Arc::new(CrashStore::new());
    put(&*store, "/before", "1");
    let holding = store.hold();
    let sync = {
        let store = Arc::clone(&store);
        std::thread::spawn(move || store.sync())
    };
    while store.syncs_started() == 0 {
        std::thread::sleep(Duration::from_millis(1));
    }
    put(&*store, "/during", "2");
    drop(holding);
    sync.join().unwrap().unwrap();

    let disk = store.crash();
    assert!(disk.contains(&n("/before")));
    assert!(
        !disk.contains(&n("/during")),
        "a write that arrived while a sync was under way is not covered by it"
    );
    store.sync().unwrap();
    assert!(
        store.crash().contains(&n("/during")),
        "the next sync covers it"
    );
}

#[test]
fn a_failing_disk_fails_every_sync_until_it_is_healed_and_keeps_serving_reads() {
    let store = CrashStore::new();
    put(&store, "/a", "1");
    store.fail_syncs("the disk is full");
    let err = store.sync().unwrap_err();
    assert!(err.to_string().contains("the disk is full"), "{err}");
    put(&store, "/b", "2");
    assert!(store.sync().is_err());
    assert!(holds(&store, "/b", "2"), "reads and writes go on");
    assert!(
        !store.crash().contains(&n("/a")),
        "a failed sync made nothing durable"
    );
    store.heal_syncs();
    store.sync().unwrap();
    assert!(store.crash().contains(&n("/b")));
}

#[test]
fn held_blocks_sync_until_released_and_counts_batches() {
    let store = Arc::new(Held::default());
    let holding = store.hold();
    let sync = {
        let store = Arc::clone(&store);
        std::thread::spawn(move || store.sync())
    };
    while store.syncs_started() == 0 {
        std::thread::sleep(Duration::from_millis(1));
    }
    std::thread::sleep(Duration::from_millis(30));
    assert!(!sync.is_finished(), "a held store's sync does not return");
    store.apply(vec![StoreOp::Insert(n("/a"), Bytes::new())]);
    assert_eq!(store.batches(), 1);
    drop(holding);
    sync.join().unwrap().unwrap();
}

// -- The on-disk engines under a killed process ------------------------------

/// What the child of the cases below is told: `<engine>|<dir>`.
const ROLE: &str = "NDN_HEAP_KILL_CHILD";

/// The `k`th batch the child writes: an entry and the head that names it,
/// kept together by the stage as one apply.
fn write_batch(stage: &Stage, k: u64) {
    let _batch = stage.batch();
    stage.insert(n(&format!("/e/{k}")), Bytes::from(k.to_be_bytes().to_vec()));
    stage.insert(n("/head"), Bytes::from(k.to_be_bytes().to_vec()));
}

/// The head a store holds, and whether every entry up to it is there and
/// the one above it is not: a batch is all there or none.
fn head_of(store: &dyn DataStore) -> u64 {
    let head = store
        .get(&n("/head"))
        .map_or(0, |v| u64::from_be_bytes(v[..].try_into().unwrap()));
    for k in 1..=head {
        assert!(
            store.contains(&n(&format!("/e/{k}"))),
            "the head is {head} but entry {k} is missing: a batch was torn"
        );
    }
    assert!(
        !store.contains(&n(&format!("/e/{}", head + 1))),
        "entry {} is stored but its head is not: a batch was torn",
        head + 1
    );
    head
}

/// The child: writes batches on a [`PowerCut`] store for ever. After each
/// apply it prints `applied <k>`; every fifth it flushes first and prints
/// `durable <k>` once the flush returned. A case reads these lines, kills the
/// child when it likes and checks what the disk holds against them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "a child process of the kill cases; it runs only when one starts it"]
async fn power_cut_child() {
    let Ok(role) = std::env::var(ROLE) else {
        return;
    };
    let (engine, dir) = role.split_once('|').unwrap();
    let engine = Engine::parse(engine);
    let store = Arc::new(PowerCut::open(engine, &PathBuf::from(dir)));
    let stage = Stage::new(Arc::clone(&store) as Arc<dyn DataStore>);
    let mut out = std::io::stdout();
    for k in 1u64.. {
        write_batch(&stage, k);
        writeln!(out, "applied {k}").unwrap();
        out.flush().unwrap();
        if k % 5 == 0 {
            let flushing = Arc::clone(&store);
            tokio::task::spawn_blocking(move || flushing.sync())
                .await
                .unwrap()
                .unwrap();
            writeln!(out, "durable {k}").unwrap();
            out.flush().unwrap();
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

/// Run the child on `engine` in `dir` until it has printed `applied
/// <at_least>`; kill it with SIGKILL. The last `applied` and `durable` it
/// printed.
fn run_and_kill(engine: Engine, dir: &std::path::Path, at_least: u64) -> (u64, u64) {
    let mut child = ChildRun::start(
        "test_kit::tests::power_cut_child",
        ROLE,
        format!("{}|{}", engine.label(), dir.display()),
    );
    let (mut applied, mut durable) = (0, 0);
    while applied < at_least {
        let line = child.next_line();
        let mut words = line.split_whitespace();
        match (words.next(), words.next().and_then(|w| w.parse().ok())) {
            (Some("applied"), Some(k)) => applied = k,
            (Some("durable"), Some(k)) => durable = k,
            _ => {}
        }
    }
    child.kill();
    (applied, durable)
}

fn open(engine: Engine, path: &std::path::Path) -> Box<dyn DataStore> {
    match engine {
        Engine::Fjall => Box::new(ndn_sync::store::BackendStore::open_fjall(path).unwrap()),
        Engine::Redb => Box::new(ndn_sync::store::BackendStore::open_redb(path).unwrap()),
    }
}

/// `kill -9` takes the process, not the operating system: whatever a write
/// that returned handed to the engine is on disk when the store is opened
/// again, whole batches only.
fn kill_9_loses_nothing(engine: Engine) {
    let dir = tempfile::tempdir().unwrap();
    let (applied, _) = run_and_kill(engine, dir.path(), 12);
    let reopened = open(engine, &engine.live(dir.path()));
    let head = head_of(&*reopened);
    assert!(
        head >= applied,
        "on {}, {applied} batches had returned before kill -9 but the store holds {head}",
        engine.label()
    );
}

/// A power cut takes what no returned flush covered: the disk is the image
/// taken at the last flush (fjall) or write (redb). Every batch the child saw
/// flushed is there, whole batches only.
fn a_power_cut_keeps_what_a_returned_flush_covered(engine: Engine) {
    let dir = tempfile::tempdir().unwrap();
    let (_, durable) = run_and_kill(engine, dir.path(), 12);
    assert!(durable >= 5, "the child flushed before the cut");
    copy_tree(&dir.path().join("image"), &engine.live(dir.path()));
    let disk = open(engine, &engine.live(dir.path()));
    let head = head_of(&*disk);
    assert!(
        head >= durable,
        "on {}, the child saw a flush of {durable} return, yet the disk holds {head}",
        engine.label()
    );
}

#[test]
fn kill_9_loses_nothing_on_fjall() {
    kill_9_loses_nothing(Engine::Fjall);
}

#[test]
fn kill_9_loses_nothing_on_redb() {
    kill_9_loses_nothing(Engine::Redb);
}

#[test]
fn a_power_cut_keeps_what_a_returned_flush_covered_on_fjall() {
    a_power_cut_keeps_what_a_returned_flush_covered(Engine::Fjall);
}

#[test]
fn a_power_cut_keeps_what_a_returned_flush_covered_on_redb() {
    a_power_cut_keeps_what_a_returned_flush_covered(Engine::Redb);
}
