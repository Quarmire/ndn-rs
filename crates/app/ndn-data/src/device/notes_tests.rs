//! Host notes (spec §19.9): the rules on areas, keys and values, the bound per area, durability
//! across a restart and a power loss, and that a note is never served.

use super::super::durability_tests::laptop;
use super::super::*;
use super::{NOTE_PART_MAX, NOTE_VALUE_MAX, NOTES_PER_AREA_MAX, note_name};
use ndn_sync::{MemoryStore, StoreOp};
use std::sync::atomic::AtomicBool;

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

fn mem() -> Arc<dyn DataStore> {
    Arc::new(MemoryStore::new())
}

/// A store whose disk keeps only what a returned [`DataStore::sync`] made durable: a power loss
/// is [`Lossy::after_power_loss`]. While frozen a flush does not finish.
struct Lossy {
    live: MemoryStore,
    disk: MemoryStore,
    pending: parking_lot::Mutex<Vec<StoreOp>>,
    frozen: AtomicBool,
}

impl Lossy {
    fn new() -> Arc<Lossy> {
        Arc::new(Lossy {
            live: MemoryStore::new(),
            disk: MemoryStore::new(),
            pending: parking_lot::Mutex::new(Vec::new()),
            frozen: AtomicBool::new(false),
        })
    }

    /// What the disk holds after a power loss, as a store that opens on it.
    fn after_power_loss(&self) -> Arc<Lossy> {
        let next = Lossy::new();
        for (name, wire) in self.disk.scan_under(&Name::root(), 0) {
            next.live.insert(name.clone(), wire.clone());
            next.disk.insert(name, wire);
        }
        next
    }

    fn on_disk(&self, name: &Name) -> Option<Bytes> {
        self.disk.get(name)
    }
}

impl DataStore for Lossy {
    fn insert(&self, name: Name, wire: Bytes) {
        self.pending
            .lock()
            .push(StoreOp::Insert(name.clone(), wire.clone()));
        self.live.insert(name, wire);
    }
    fn get(&self, name: &Name) -> Option<Bytes> {
        self.live.get(name)
    }
    fn scan_under(&self, prefix: &Name, limit: usize) -> Vec<(Name, Bytes)> {
        self.live.scan_under(prefix, limit)
    }
    fn remove(&self, name: &Name) {
        self.pending.lock().push(StoreOp::Remove(name.clone()));
        self.live.remove(name);
    }
    fn sync(&self) -> std::io::Result<()> {
        while self.frozen.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(5));
        }
        let ops = std::mem::take(&mut *self.pending.lock());
        self.disk.apply(ops);
        Ok(())
    }
}

fn why(e: DataError) -> String {
    match e {
        DataError::BadRequest { why, .. } => why,
        other => panic!("a refusal of the request was expected, got {other:?}"),
    }
}

#[tokio::test]
async fn a_note_is_kept_listed_replaced_and_removed() {
    let dev = laptop(mem()).await;
    let notes = dev.local_notes("link");
    assert_eq!(notes.get("a").unwrap(), None);
    notes.put("a", b"one").await.unwrap();
    notes.put("b", b"").await.unwrap();
    assert_eq!(notes.get("a").unwrap().as_deref(), Some(&b"one"[..]));
    assert_eq!(notes.get("b").unwrap().as_deref(), Some(&b""[..]));
    notes.put("a", b"two").await.unwrap();
    let listed = notes.list().unwrap();
    assert_eq!(
        listed
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_ref()))
            .collect::<Vec<_>>(),
        vec![("a", &b"two"[..]), ("b", &b""[..])]
    );
    // Another area is another set of notes, and an area is a whole component, not a prefix of
    // characters.
    let other = dev.local_notes("lin");
    assert_eq!(other.get("a").unwrap(), None);
    assert!(other.list().unwrap().is_empty());
    notes.remove("a").await.unwrap();
    notes.remove("never-was").await.unwrap();
    assert_eq!(notes.get("a").unwrap(), None);
    assert_eq!(notes.list().unwrap().len(), 1);
    dev.shutdown();
}

#[tokio::test]
async fn an_area_or_key_that_breaks_a_rule_is_refused_naming_it() {
    let dev = laptop(mem()).await;
    let notes = dev.local_notes("link");
    let long = "k".repeat(NOTE_PART_MAX + 1);
    for (key, rule) in [
        ("", "is empty"),
        ("a/b", "contains a '/'"),
        ("a\nb", "control character"),
        ("a\u{7f}", "control character"),
        (long.as_str(), "octets long"),
    ] {
        let put = why(notes.put(key, b"x").await.unwrap_err());
        assert!(put.contains(rule), "put {key:?}: {put}");
        assert!(put.contains("use 1 to 64 octets"), "put {key:?}: {put}");
        assert!(why(notes.get(key).unwrap_err()).contains(rule));
        assert!(why(notes.remove(key).await.unwrap_err()).contains(rule));
        let bad_area = dev.local_notes(key);
        assert!(why(bad_area.put("k", b"x").await.unwrap_err()).contains(rule));
        assert!(why(bad_area.list().unwrap_err()).contains(rule));
    }
    // Exactly 64 octets is fine; so is a key that is not ASCII.
    let edge = "k".repeat(NOTE_PART_MAX);
    notes.put(&edge, b"x").await.unwrap();
    notes.put("clé", b"x").await.unwrap();
    // A value is at most 4 KiB.
    notes.put("big", &vec![1; NOTE_VALUE_MAX]).await.unwrap();
    let e = why(notes
        .put("big", &vec![1; NOTE_VALUE_MAX + 1])
        .await
        .unwrap_err());
    assert!(e.contains("at most 4096 octets"), "{e}");
    assert_eq!(notes.get("big").unwrap().unwrap().len(), NOTE_VALUE_MAX);
    dev.shutdown();
}

#[tokio::test]
async fn an_area_holds_at_most_a_thousand_and_twenty_four_notes() {
    let store = mem();
    let dev = laptop(Arc::clone(&store)).await;
    let notes = dev.local_notes("link");
    // Filled through the store, as a long-lived host would have: a thousand puts through the
    // barrier would only make this slow.
    for i in 0..NOTES_PER_AREA_MAX {
        store.insert(
            note_name("link", &format!("k{i}")),
            Bytes::from_static(b"x"),
        );
    }
    assert_eq!(notes.list().unwrap().len(), NOTES_PER_AREA_MAX);
    let e = why(notes.put("one-more", b"x").await.unwrap_err());
    assert!(e.contains("1024 notes already"), "{e}");
    assert!(e.contains("remove one"), "{e}");
    assert_eq!(notes.get("one-more").unwrap(), None);
    // Replacing one is no new note, and another area has its own thousand.
    notes.put("k5", b"y").await.unwrap();
    dev.local_notes("other")
        .put("one-more", b"x")
        .await
        .unwrap();
    notes.remove("k5").await.unwrap();
    notes.put("one-more", b"x").await.unwrap();
    assert_eq!(notes.list().unwrap().len(), NOTES_PER_AREA_MAX);
    dev.shutdown();
}

#[tokio::test]
async fn notes_come_back_after_a_restart_on_the_same_store() {
    let store = mem();
    let dev = laptop(Arc::clone(&store)).await;
    dev.local_notes("link").put("a", b"one").await.unwrap();
    dev.local_notes("link").put("gone", b"x").await.unwrap();
    dev.local_notes("link").remove("gone").await.unwrap();
    dev.local_notes("other").put("a", b"two").await.unwrap();
    dev.shutdown();
    drop(dev);
    let again = laptop(store).await;
    assert_eq!(
        again.local_notes("link").get("a").unwrap().as_deref(),
        Some(&b"one"[..])
    );
    assert_eq!(again.local_notes("link").get("gone").unwrap(), None);
    assert_eq!(
        again.local_notes("other").get("a").unwrap().as_deref(),
        Some(&b"two"[..])
    );
    again.shutdown();
}

#[tokio::test]
async fn a_put_that_returned_survives_a_power_loss_and_one_still_waiting_is_not_durable() {
    let store = Lossy::new();
    let dev = laptop(store.clone()).await;
    let notes = dev.local_notes("link");
    notes.put("kept", b"one").await.unwrap();
    notes.put("removed", b"x").await.unwrap();
    notes.remove("removed").await.unwrap();
    // The disk is frozen: a put does not return, and what the disk holds does not have it.
    store.frozen.store(true, Ordering::SeqCst);
    let waiting = {
        let notes = notes.clone();
        tokio::spawn(async move { notes.put("waiting", b"two").await })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !waiting.is_finished(),
        "put returned before the store's barrier passed"
    );
    let name = note_name("link", "waiting");
    assert!(store.on_disk(&name).is_none());
    let lost = store.after_power_loss();
    store.frozen.store(false, Ordering::SeqCst);
    waiting.await.unwrap().unwrap();
    assert!(
        store.on_disk(&name).is_some(),
        "the barrier passed, so the note is on disk"
    );
    dev.shutdown();
    drop(dev);
    // After the power loss: what returned is there, a removal that returned stays, and the
    // device starts on it.
    let again = laptop(lost).await;
    let notes = again.local_notes("link");
    assert_eq!(notes.get("kept").unwrap().as_deref(), Some(&b"one"[..]));
    assert_eq!(notes.get("removed").unwrap(), None);
    assert_eq!(notes.get("waiting").unwrap(), None);
    again.shutdown();
}

#[tokio::test]
async fn a_note_is_never_answered_to_an_interest() {
    let dev = laptop(mem()).await;
    dev.local_notes("link")
        .put("a", b"secret-ish")
        .await
        .unwrap();
    let name = note_name("link", "a");
    assert_eq!(name.to_string(), "/localhost/ndn-data/host/link/a");
    for ask in [
        name.clone(),
        n("/localhost/ndn-data/host/link"),
        n("/localhost"),
    ] {
        for prefix in [false, true] {
            assert!(
                dev.inner.packet_for(&ask, prefix).is_none(),
                "{ask} (prefix {prefix}) was answered"
            );
        }
    }
    // The device's producer is registered under its own name only, so no Interest for a
    // `/localhost` name reaches it.
    assert!(!name.has_prefix(dev.name()));
    dev.shutdown();
}

#[tokio::test]
async fn a_stopped_device_refuses_a_put_saying_so() {
    let dev = laptop(mem()).await;
    let notes = dev.local_notes("link");
    notes.put("a", b"one").await.unwrap();
    dev.shutdown();
    let e = notes.put("a", b"two").await.unwrap_err();
    assert!(
        matches!(&e, DataError::Local { reason } if reason.contains("stopped")),
        "{e:?}"
    );
    drop(dev);
    let e = notes.get("a").unwrap_err();
    assert!(matches!(e, DataError::Local { .. }), "{e:?}");
}
