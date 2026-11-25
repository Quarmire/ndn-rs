//! The network half through whole nodes over one real forwarder (spec §7,
//! §6.5): what a node expresses when something new arrives, how a device that
//! has no key yet gets one, who is refused, what a carrier can learn, and how
//! a large value arrives.
//!
//! A child of `mesh_tests`: it runs on its mesh (PKI devices, one engine).

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_app::{AppError, Connection, EngineAppExt};
use ndn_foundation_types::Name;
use ndn_packet::Interest;
use ndn_packet::encode::DataBuilder;
use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

use super::*;
use crate::error::Refusal;
use crate::log::Outcome;
use crate::node::tests::private;
use crate::seal::{self, GrantRefusal};
use crate::space::MembersChange;
use crate::sync::Taken;
use crate::wire::{Body, Entry as WireEntry, Payload, Prev, PutBody};

/// A face that counts the Interests a node expresses through it.
struct Tap {
    inner: Arc<dyn Connection>,
    asked: Mutex<Vec<Name>>,
}

impl Tap {
    fn names(&self) -> Vec<Name> {
        self.asked.lock().clone()
    }
}

#[async_trait::async_trait]
impl Connection for Tap {
    async fn send(&self, wire: Bytes) -> Result<(), AppError> {
        if let Ok(interest) = Interest::decode(wire.clone()) {
            self.asked.lock().push((*interest.name).clone());
        }
        self.inner.send(wire).await
    }
    async fn recv(&self) -> Option<Bytes> {
        self.inner.recv().await
    }
    async fn register_prefix(&self, prefix: &Name) -> Result<(), AppError> {
        self.inner.register_prefix(prefix).await
    }
}

impl Mesh {
    /// Device `i` again, its Interests counted: the old faces end first.
    async fn boot_tapped(&self, i: usize, config: Config) -> (Node, Arc<Tap>) {
        let cancel = {
            let mut held = self.cancels[i].lock();
            held.cancel();
            *held = CancellationToken::new();
            held.clone()
        };
        let dev = &self.devs[i];
        let tap = Arc::new(Tap {
            inner: self.engine.app_face(cancel.child_token()),
            asked: Mutex::new(Vec::new()),
        });
        let node = tokio::time::timeout(
            Duration::from_secs(20),
            Node::start(
                Transport {
                    node: ndn_app::Node::from_connection(Arc::clone(&tap) as Arc<dyn Connection>),
                    sync: self.engine.app_face(cancel.child_token()),
                },
                dev.name.clone(),
                Arc::clone(&dev.keys),
                Arc::clone(&dev.validator),
                Arc::clone(&dev.store),
                config,
            ),
        )
        .await
        .unwrap_or_else(|_| panic!("{} did not finish starting within 20 s", dev.name))
        .expect("the node starts");
        (node, tap)
    }
}

/// Whether `needle` is in any value of `store`.
fn store_holds(store: &Arc<dyn DataStore>, needle: &[u8]) -> bool {
    store
        .scan_under(&Name::root(), 0)
        .iter()
        .any(|(_, value)| value.windows(needle.len()).any(|w| w == needle))
}

/// A new entry costs the receiving node one Interest, for exactly the entry
/// its notice names: no walk, no summary, no repeat.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_new_entry_reaches_the_watcher_with_one_fetch() {
    let m = mesh(&["/alice/laptop", "/alice/phone"]).await;
    let laptop = m.boot(0, fast()).await;
    let (phone, tap) = m.boot_tapped(1, fast()).await;
    let heap = laptop.create(&space(), public()).await.unwrap();
    let theirs = phone.open(&space()).await.unwrap();
    let mut changes = theirs.watch(&Frontier::new()).await.unwrap();
    eventually("the phone sees the creation", || async { theirs.ready() }).await;
    // The creation is held and nothing is wanted before the put is counted.
    eventually("the phone holds the creation and wants nothing", || async {
        phone.held() == 1 && phone.inner.missing(&space()).is_empty()
    })
    .await;
    let before = tap.names().len();
    let id = heap
        .put(&n("/a"), bytes("one"), PutOptions::default())
        .await
        .unwrap();
    let item = until(&mut changes, |c| match c {
        Change::Put(item) if item.path == n("/a") => Some(item.clone()),
        _ => None,
    })
    .await;
    assert_eq!(item.id, id);
    // Long enough for a repeat, a walk or a summary to show.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        tap.names()[before..].to_vec(),
        vec![log_name(&m.devs[0].name, &space(), id.seq)],
        "one Interest, for the entry the notice named"
    );
}

/// A device that has no key of its own yet, of a person admitted as a reader,
/// gets the epoch key by a grant pull and reads the sealed history (the case
/// an Epoch entry's wrap cannot serve: the entry was signed before the device
/// existed).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_device_of_an_admitted_person_gets_the_key_by_a_grant() {
    let m = mesh(&["/alice/laptop", "/bob/laptop", "/bob/phone"]).await;
    let alice = m.boot(0, fast()).await;
    let heap = alice.create(&space(), private(&["/bob"])).await.unwrap();
    heap.put(&n("/history"), bytes("sealed history"), durable(true))
        .await
        .unwrap();
    let phone = m.boot(2, fast()).await;
    let theirs = phone.open(&space()).await.unwrap();
    eventually(
        "the new device reads the sealed history after the grant pull",
        || async { has(&theirs, "/history", "sealed history").await },
    )
    .await;
    assert!(
        theirs.holds_epoch_key(),
        "a device that read a sealed entry after the grant holds the key of the epoch in force"
    );
    // And what Alice writes next, in the same epoch, it reads at once.
    heap.put(&n("/next"), bytes("later"), PutOptions::default())
        .await
        .unwrap();
    eventually("and the entries after it", || async {
        has(&theirs, "/next", "later").await
    })
    .await;
}

/// A reader who was removed is refused every later grant: the new epoch is a
/// key that did not exist before, and the old one is not given again to a
/// device that asks after the removal. What a device already opened it keeps.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removed_reader_is_refused_every_later_grant() {
    let m = mesh(&["/alice/laptop", "/bob/laptop", "/bob/phone"]).await;
    let alice = m.boot(0, fast()).await;
    let heap = alice.create(&space(), private(&["/bob"])).await.unwrap();
    heap.put(&n("/history"), bytes("sealed history"), durable(true))
        .await
        .unwrap();
    let bob = m.boot(1, fast()).await;
    let bobs = bob.open(&space()).await.unwrap();
    eventually("bob's first device reads", || async {
        has(&bobs, "/history", "sealed history").await
    })
    .await;
    let first = heap.inner.log.lock().fold.epochs();
    heap.change(MembersChange {
        remove: vec![n("/bob")],
        ..MembersChange::default()
    })
    .await
    .unwrap();
    heap.put(&n("/after"), bytes("new epoch"), PutOptions::default())
        .await
        .unwrap();

    // A second device of bob's, started after the removal, is never given a key.
    let phone = m.boot(2, fast()).await;
    let theirs = phone.open(&space()).await.unwrap();
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let asked = theirs.get(&n("/history")).await;
        assert!(
            matches!(asked, Err(HeapError::Sealed { .. }) | Ok(None)),
            "a removed reader's device reads nothing: {asked:?}"
        );
        for epoch in &first {
            assert_eq!(
                alice
                    .inner
                    .may_grant(&space(), epoch, &m.devs[2].name, None)
                    .expect_err("refused"),
                GrantRefusal::NotReaderNow
            );
        }
    }
    assert!(!has(&theirs, "/after", "new epoch").await);
}

/// A reader's device whose key is revoked is refused the grant, though its
/// person is still a reader and the epoch names it: the decision names the
/// key, which the granter knows once the seal key packet is judged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reader_device_with_a_revoked_key_is_refused_every_grant() {
    let m = mesh(&["/alice/laptop", "/bob/phone"]).await;
    let alice = m.boot(0, fast()).await;
    let heap = alice.create(&space(), private(&["/bob"])).await.unwrap();
    let epoch = heap.inner.log.lock().fold.in_force().expect("an epoch");
    let (phone, key) = (
        m.devs[1].name.clone(),
        m.devs[1].name.clone().append("KEY").append("1"),
    );
    assert_eq!(
        alice.inner.may_grant(&space(), &epoch, &phone, Some(&key)),
        Ok(())
    );
    let revoking = ndn_security::SignedTrustContext::hierarchical(n("/bob"))
        .with_version(2)
        .with_revocation(key.clone());
    m.devs[0]
        .validator
        .keyring()
        .adopt_update(Arc::new(revoking))
        .expect("adopted");
    assert_eq!(
        alice.inner.may_grant(&space(), &epoch, &phone, Some(&key)),
        Err(GrantRefusal::AskerKeyRevoked)
    );
}

/// Stage-7 L5: a key this node suspects (reported stolen, or caught equivocating) is granted
/// no key though its person is a reader, until the mark is lifted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reader_device_whose_key_is_suspected_here_is_refused_every_grant() {
    let m = mesh(&["/alice/laptop", "/bob/phone"]).await;
    let alice = m.boot(0, fast()).await;
    let heap = alice.create(&space(), private(&["/bob"])).await.unwrap();
    let epoch = heap.inner.log.lock().fold.in_force().expect("an epoch");
    let (phone, key) = (
        m.devs[1].name.clone(),
        m.devs[1].name.clone().append("KEY").append("1"),
    );
    assert_eq!(
        alice.inner.may_grant(&space(), &epoch, &phone, Some(&key)),
        Ok(())
    );
    alice.suspect(&key, Timestamp(1)).unwrap();
    let refused = alice.inner.may_grant(&space(), &epoch, &phone, Some(&key));
    assert_eq!(
        refused,
        Err(GrantRefusal::AskerKeySuspected),
        "a suspected asker was granted the epoch key"
    );
    assert!(
        refused.unwrap_err().to_string().contains("lifted"),
        "the refusal says what to do"
    );
    assert!(alice.unsuspect(&key));
    assert_eq!(
        alice.inner.may_grant(&space(), &epoch, &phone, Some(&key)),
        Ok(()),
        "granted again once the mark is lifted"
    );
}

/// Two owner devices each remove a different reader at the same time; each
/// repairs the epoch it sees incomplete, and the space ends with one complete
/// epoch on both.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_removals_end_with_one_complete_epoch() {
    let m = mesh(&["/alice/laptop", "/alice/phone"]).await;
    let (laptop, phone) = (m.boot(0, fast()).await, m.boot(1, fast()).await);
    let mine = laptop
        .create(&space(), private(&["/bob", "/carol"]))
        .await
        .unwrap();
    let theirs = phone.open(&space()).await.unwrap();
    eventually("the phone holds a complete fold", || async {
        theirs.ready() && theirs.inner.log.lock().fold.complete()
    })
    .await;
    let remove = |who: &str| MembersChange {
        remove: vec![n(who)],
        ..MembersChange::default()
    };
    let (a, b) = tokio::join!(mine.change(remove("/bob")), theirs.change(remove("/carol")));
    a.unwrap();
    b.unwrap();
    let state = |heap: &Heap| {
        let log = heap.inner.log.lock();
        let fold = &log.fold;
        (fold.complete(), fold.in_force(), fold.readers())
    };
    eventually(
        "both hold one complete epoch for the same readers",
        || async {
            let (x, y) = (state(&mine), state(&theirs));
            x.0 && y.0 && x.1.is_some() && x.1 == y.1 && x.2 == y.2
        },
    )
    .await;
    assert_eq!(
        state(&mine).2,
        Readers::Persons(vec![n("/alice")]),
        "neither removed reader remains"
    );
}

/// A reader added by an Add that names the current epoch reads that epoch's
/// history.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reader_added_by_an_add_reads_the_history_of_that_epoch() {
    let m = mesh(&["/alice/laptop", "/bob/laptop"]).await;
    let alice = m.boot(0, fast()).await;
    let heap = alice.create(&space(), private(&["/carol"])).await.unwrap();
    heap.put(&n("/history"), bytes("written before bob"), durable(true))
        .await
        .unwrap();
    heap.change(MembersChange {
        add_readers: vec![n("/bob")],
        ..MembersChange::default()
    })
    .await
    .unwrap();
    let bob = m.boot(1, fast()).await;
    let theirs = bob.open(&space()).await.unwrap();
    eventually("bob reads what was written before he was added", || async {
        has(&theirs, "/history", "written before bob").await
    })
    .await;
}

/// A reader added by an Add holds the epoch's key like one the epoch names:
/// removed again, they read what was written in that epoch and nothing after,
/// though the epoch's own audience never changed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reader_added_by_an_add_and_removed_reads_nothing_written_after() {
    let m = mesh(&["/alice/laptop", "/bob/laptop"]).await;
    let alice = m.boot(0, fast()).await;
    let heap = alice.create(&space(), private(&[])).await.unwrap();
    heap.put(&n("/history"), bytes("before bob"), durable(true))
        .await
        .unwrap();
    heap.change(MembersChange {
        add_readers: vec![n("/bob")],
        ..MembersChange::default()
    })
    .await
    .unwrap();
    let bob = m.boot(1, fast()).await;
    let theirs = bob.open(&space()).await.unwrap();
    eventually("bob reads what was written before he was added", || async {
        has(&theirs, "/history", "before bob").await
    })
    .await;
    heap.change(MembersChange {
        remove: vec![n("/bob")],
        ..MembersChange::default()
    })
    .await
    .unwrap();
    let id = heap
        .put(&n("/after"), bytes("after bob"), durable(true))
        .await
        .unwrap();
    let Body::Sealed(sealed) = entry_of(&m.devs[0].store, &m.devs[0].name, id.seq).body else {
        panic!("the put is sealed");
    };
    // Whatever bob's device asks for, it is never given the key the put is
    // sealed in.
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(
            theirs
                .inner
                .log
                .lock()
                .keys
                .key(&space(), &sealed.epoch)
                .is_none(),
            "a removed reader holds only the keys it was granted before"
        );
    }
}

/// A carrier holds the entries and cannot learn the path: the path and the
/// value are inside the sealed body. (A public space's are in the clear, so
/// the search can find what it looks for.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_sees_no_path() {
    let m = mesh(&["/alice/laptop", "/carol/tablet"]).await;
    let (alice, carrier) = (m.boot(0, fast()).await, m.boot(1, fast()).await);
    let secret = n("/alice/32=data/private");
    let open = n("/alice/32=data/open");
    let sealed = alice.create(&secret, private(&["/bob"])).await.unwrap();
    let plain = alice.create(&open, public()).await.unwrap();
    let carrying = carrier.follow(&secret).await.unwrap();
    let carrying_open = carrier.follow(&open).await.unwrap();
    sealed
        .put(
            &n("/the-secret-path"),
            bytes("the secret value"),
            durable(true),
        )
        .await
        .unwrap();
    plain
        .put(&n("/the-open-path"), bytes("an open value"), durable(true))
        .await
        .unwrap();
    eventually("the carrier holds both spaces' entries", || async {
        carrying.held() >= 3 && carrying_open.held() >= 2
    })
    .await;
    let store = &m.devs[1].store;
    assert!(
        store_holds(store, b"the-open-path"),
        "a public path is in the clear (the search finds what is there)"
    );
    assert!(
        !store_holds(store, b"the-secret-path") && !store_holds(store, b"the secret value"),
        "a carrier of a sealed space holds neither its paths nor its values"
    );
}

/// A plain entry in a sealed space is refused, whoever signed it, and
/// applies nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unsealed_entry_in_a_sealed_space_is_refused() {
    let m = mesh(&["/alice/laptop", "/alice/phone"]).await;
    let alice = m.boot(0, fast()).await;
    let heap = alice.create(&space(), private(&["/bob"])).await.unwrap();
    // The phone is a writer of the owner's person and signs a plain entry.
    let phone = m.devs[1].name.clone();
    let content = WireEntry {
        prev: None,
        after: Vec::new(),
        body: Body::Put(PutBody {
            path: n("/x"),
            payload: Payload::Inline(bytes("in the clear")),
        }),
    }
    .encode()
    .unwrap();
    let signer = m.devs[1]
        .keys
        .get_signer_sync(&phone.clone().append("KEY").append("1"))
        .unwrap();
    let wire = seal::sign(
        DataBuilder::new(log_name(&phone, &space(), 1), &content),
        &*signer,
    )
    .unwrap();
    let taken = alice.inner.take(&space(), wire, false).await;
    assert!(
        matches!(
            taken,
            Taken::Decided {
                outcome: Outcome::Refused(Refusal::Unsealed),
                ..
            }
        ),
        "{taken:?}"
    );
    assert_eq!(heap.get(&n("/x")).await.unwrap(), None, "nothing applied");
}

/// A device that was away and comes back asks only for what changed while it
/// was gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_returning_device_fetches_only_what_changed() {
    let m = mesh(&["/alice/laptop", "/alice/phone"]).await;
    let laptop = m.boot(0, fast()).await;
    let heap = laptop.create(&space(), public()).await.unwrap();
    let phone = m.boot(1, fast()).await;
    let theirs = phone.open(&space()).await.unwrap();
    for (path, value) in [("/a", "one"), ("/b", "two"), ("/c", "three")] {
        heap.put(&n(path), bytes(value), PutOptions::default())
            .await
            .unwrap();
    }
    // Everything is held, the creation and the three puts, and nothing is
    // wanted: the entry a notice names arrives before the ones below it, so
    // the value of the last put can be read while a hole is still open.
    eventually(
        "the phone holds all four entries and wants none",
        || async {
            has(&theirs, "/c", "three").await
                && phone.held() == 4
                && phone.inner.missing(&space()).is_empty()
        },
    )
    .await;
    phone.close().await;
    let later = heap
        .put(&n("/d"), bytes("while away"), durable(true))
        .await
        .unwrap();

    let (phone, tap) = m.boot_tapped(1, fast()).await;
    let theirs = phone.space(&space()).expect("the space is held again");
    eventually("the phone has what changed", || async {
        has(&theirs, "/d", "while away").await
    })
    .await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        tap.names(),
        vec![log_name(&m.devs[0].name, &space(), later.seq)],
        "one Interest, for the one entry it lacked"
    );
}

/// A value of a mebibyte reaches the peer in pieces, and the watcher is told
/// of the put only when the value is whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_1_mib_payload_reaches_the_peer_in_pieces() {
    let m = mesh(&["/alice/laptop", "/alice/phone"]).await;
    let (laptop, phone) = (m.boot(0, fast()).await, m.boot(1, fast()).await);
    let heap = laptop.create(&space(), public()).await.unwrap();
    let theirs = phone.open(&space()).await.unwrap();
    let mut changes = theirs.watch(&Frontier::new()).await.unwrap();
    eventually("the phone sees the creation", || async { theirs.ready() }).await;
    let payload: Vec<u8> = (0..1u32 << 20)
        .map(|i| (i.wrapping_mul(7) % 251) as u8)
        .collect();
    let id = heap
        .put(
            &n("/big"),
            Bytes::from(payload.clone()),
            PutOptions::default(),
        )
        .await
        .unwrap();
    let item = until(&mut changes, |c| match c {
        Change::Put(item) if item.path == n("/big") => Some(item.clone()),
        _ => None,
    })
    .await;
    assert_eq!(item.id, id);
    assert_eq!(
        &item.bytes[..],
        &payload[..],
        "the watcher's first sight of the put carries the whole value"
    );
    let read = theirs.get(&n("/big")).await.unwrap().expect("held");
    assert_eq!(&read.bytes[..], &payload[..]);
}

/// A value in pieces written into a private space before a device of the owner opens the space is
/// read whole by that device once the epoch key has been granted to it: the entry arrives closed
/// (its payload kind is sealed), the key opens it, and the pieces it declares are then asked for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sealed_value_in_pieces_reaches_a_device_that_opens_the_space_after_the_write() {
    let m = mesh(&["/alice/laptop", "/alice/phone"]).await;
    let (laptop, phone) = (m.boot(0, fast()).await, m.boot(1, fast()).await);
    let heap = laptop.create(&space(), private(&[])).await.unwrap();
    let payload: Vec<u8> = (0..1u32 << 18)
        .map(|i| (i.wrapping_mul(7) % 251) as u8)
        .collect();
    heap.put(
        &n("/big"),
        Bytes::from(payload.clone()),
        PutOptions::default(),
    )
    .await
    .unwrap();
    let theirs = phone.open(&space()).await.unwrap();
    eventually("the phone reads the whole value", || async {
        matches!(
            theirs.get(&n("/big")).await,
            Ok(Some(item)) if item.bytes[..] == payload[..]
        )
    })
    .await;
}

/// A device that opens a space after a key was revoked with a cut reads the entries the cut keeps,
/// though the counter the group shows for the key names an entry above the cut that nobody
/// serves (its writer refuses it, as does every holder): the cut says which seqs of the key's
/// log are wanted, and they are asked for without waiting for the counter's entry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_late_device_reads_what_a_revocation_cut_keeps_below_a_counter_nobody_answers() {
    let m = mesh(&["/alice/laptop", "/alice/phone", "/alice/tablet"]).await;
    let (laptop, phone) = (m.boot(0, fast()).await, m.boot(1, fast()).await);
    let mine = laptop.create(&space(), public()).await.unwrap();
    let theirs = phone.open(&space()).await.unwrap();
    eventually("the phone holds the space", || async { theirs.ready() }).await;
    for (path, value) in [("/a", "one"), ("/b", "two")] {
        theirs
            .put(&n(path), bytes(value), durable(false))
            .await
            .unwrap();
    }
    eventually("the laptop holds the phone's two entries", || async {
        has(&mine, "/a", "one").await && has(&mine, "/b", "two").await
    })
    .await;

    // The laptop vouches for what it holds; the phone writes once more, which the cut leaves out.
    let key = m.devs[1].name.clone().append("KEY").append("1");
    let bound = CutBound {
        held_before: Some(Timestamp(u64::MAX / 2)),
        ..CutBound::default()
    };
    let proposal = laptop.revocation_cut(&key, &bound).unwrap();
    theirs
        .put(&n("/c"), bytes("three"), durable(false))
        .await
        .unwrap();

    // Every node adopts the revocation and holds its cut's manifest.
    let (cut, manifest) = (proposal.cut.clone(), proposal.manifest.clone());
    for dev in &m.devs {
        for packet in &manifest {
            let data = ndn_packet::Data::decode(packet.clone()).unwrap();
            dev.validator.cut_manifests().insert(&data).unwrap();
        }
        let held = dev
            .validator
            .keyring()
            .contexts()
            .into_iter()
            .find(|c| *c.namespace() == n("/alice"))
            .expect("the namespace's context");
        let revoking = ndn_security::SignedTrustContext::hierarchical(n("/alice"))
            .with_version(2)
            .with_revocation(key.clone())
            .with_revocation_cut(cut.clone());
        for anchor in held.anchors().iter() {
            revoking.add_anchor(anchor.value().clone());
        }
        dev.validator
            .keyring()
            .adopt_update(Arc::new(revoking))
            .expect("adopted");
    }
    eventually(
        "the phone's third entry is refused by the laptop",
        || async { matches!(mine.get(&n("/c")).await, Ok(None)) },
    )
    .await;

    // A device of the owner that was never in the group reads what the cut keeps.
    let tablet = m.boot(2, fast()).await;
    let late = tablet.open(&space()).await.unwrap();
    eventually("the tablet reads the entries the cut keeps", || async {
        has(&late, "/a", "one").await && has(&late, "/b", "two").await
    })
    .await;
    assert_eq!(late.get(&n("/c")).await.unwrap(), None);
}

/// Every device of the mesh adopts version `version` of the namespace's context, which revokes
/// `key` with `cut`.
fn adopt_revoking(m: &Mesh, key: &Name, version: u64, cut: &ndn_security::RevocationCut) {
    for dev in &m.devs {
        let held = dev
            .validator
            .keyring()
            .contexts()
            .into_iter()
            .find(|c| *c.namespace() == n("/alice"))
            .expect("the namespace's context");
        let next = ndn_security::SignedTrustContext::hierarchical(n("/alice"))
            .with_version(version)
            .with_revocation(key.clone())
            .with_revocation_cut(cut.clone());
        for anchor in held.anchors().iter() {
            next.add_anchor(anchor.value().clone());
        }
        dev.validator
            .keyring()
            .adopt_update(Arc::new(next))
            .expect("adopted");
    }
}

/// A cut that names a tip, with no manifest, keeps what a device that was never in the group
/// asks for: the tip by its signed-region digest (the counter the group shows names an entry
/// above it that nobody serves), then the chain below it, entry by entry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_late_device_reads_what_a_tip_cut_keeps_below_a_counter_nobody_answers() {
    let m = mesh(&["/alice/laptop", "/alice/phone", "/alice/tablet"]).await;
    let (laptop, phone) = (m.boot(0, fast()).await, m.boot(1, fast()).await);
    let mine = laptop.create(&space(), public()).await.unwrap();
    let theirs = phone.open(&space()).await.unwrap();
    eventually("the phone holds the space", || async { theirs.ready() }).await;
    for (path, value) in [("/a", "one"), ("/b", "two")] {
        theirs
            .put(&n(path), bytes(value), durable(false))
            .await
            .unwrap();
    }
    eventually("the laptop holds the phone's two entries", || async {
        has(&mine, "/a", "one").await && has(&mine, "/b", "two").await
    })
    .await;

    // The laptop vouches for what it holds, as one tip; the phone writes once more, above it.
    let key = m.devs[1].name.clone().append("KEY").append("1");
    let bound = CutBound {
        held_before: Some(Timestamp(u64::MAX / 2)),
        tips: true,
        ..CutBound::default()
    };
    let proposal = laptop.revocation_cut(&key, &bound).unwrap();
    assert!(proposal.manifest.is_empty() && proposal.cut.manifest().is_none());
    assert_eq!(proposal.cut.tips().len(), 1);
    theirs
        .put(&n("/c"), bytes("three"), durable(false))
        .await
        .unwrap();

    adopt_revoking(&m, &key, 2, &proposal.cut);
    eventually(
        "the phone's third entry is refused by the laptop",
        || async { matches!(mine.get(&n("/c")).await, Ok(None)) },
    )
    .await;
    assert_eq!(
        mine.get(&n("/a")).await.unwrap().unwrap().bytes,
        bytes("one")
    );

    // A device of the owner that was never in the group reads what the tip keeps.
    let tablet = m.boot(2, fast()).await;
    let late = tablet.open(&space()).await.unwrap();
    eventually("the tablet reads the entries the tip keeps", || async {
        has(&late, "/a", "one").await && has(&late, "/b", "two").await
    })
    .await;
    assert_eq!(late.get(&n("/c")).await.unwrap(), None);
}

/// A cut that names a tip, adopted after the node took the key's entries, withdraws the ones off
/// the chain of the tip (the rejudge on the context's adoption) and keeps the ancestors; the
/// owner re-admits the one it left out by its name and digest and the node takes it back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tip_cut_adopted_later_withdraws_the_entries_off_the_chain_of_its_tip() {
    let m = mesh(&["/alice/laptop", "/alice/phone"]).await;
    let laptop = m.boot(0, fast()).await;
    let mine = laptop.create(&space(), public()).await.unwrap();
    let phone = m.devs[1].name.clone();
    let key = phone.clone().append("KEY").append("1");
    let signer = m.devs[1].keys.get_signer_sync(&key).unwrap();

    // The phone's chain, signed by hand: 1 <- 2 <- 4 <- 5, and an entry 3 beside it that names 2
    // as 4 does (4 states the gap over 3).
    let signed = |seq: u64, prev: Option<Prev>, path: &str| -> Bytes {
        let content = WireEntry {
            prev,
            after: Vec::new(),
            body: Body::Put(PutBody {
                path: n(path),
                payload: Payload::Inline(bytes(path)),
            }),
        }
        .encode()
        .unwrap();
        seal::sign(
            DataBuilder::new(log_name(&phone, &space(), seq), &content),
            &*signer,
        )
        .unwrap()
    };
    let digest = |wire: &Bytes| crate::wire::signed_digest(wire);
    let e1 = signed(1, None, "/a");
    let e2 = signed(
        2,
        Some(Prev {
            digest: digest(&e1),
            seq: None,
        }),
        "/b",
    );
    let fork = signed(
        3,
        Some(Prev {
            digest: digest(&e2),
            seq: None,
        }),
        "/fork",
    );
    let e4 = signed(
        4,
        Some(Prev {
            digest: digest(&e2),
            seq: Some(2),
        }),
        "/c",
    );
    let e5 = signed(
        5,
        Some(Prev {
            digest: digest(&e4),
            seq: None,
        }),
        "/d",
    );
    for wire in [&e1, &e2, &fork, &e4, &e5] {
        let taken = laptop.inner.take(&space(), wire.clone(), false).await;
        assert!(
            matches!(
                &taken,
                Taken::Decided {
                    outcome: Outcome::Applied,
                    ..
                }
            ),
            "{taken:?}"
        );
    }
    for path in ["/a", "/b", "/fork", "/c", "/d"] {
        assert!(has(&mine, path, path).await, "{path}");
    }

    // The laptop's cut: the tip is seq 5; the fork is off its chain, so it is left out and listed.
    let bound = CutBound {
        held_before: Some(Timestamp(u64::MAX / 2)),
        tips: true,
        ..CutBound::default()
    };
    let proposal = laptop.revocation_cut(&key, &bound).unwrap();
    assert_eq!(proposal.cut.tips().len(), 1);
    assert_eq!(proposal.cut.tips()[0].seq, 5);
    assert_eq!(
        proposal.left_out,
        vec![
            log_name(&phone, &space(), 3)
                .append_implicit_digest(crate::wire::implicit_digest(&fork))
        ]
    );

    adopt_revoking(&m, &key, 2, &proposal.cut);
    eventually("the laptop withdraws the entry off the chain", || async {
        matches!(mine.get(&n("/fork")).await, Ok(None))
    })
    .await;
    for path in ["/a", "/b", "/c", "/d"] {
        assert!(
            has(&mine, path, path).await,
            "{path} is on the chain of the tip"
        );
    }

    // The owner re-admits it by name and digest: the node takes it back, though it is off the chain.
    let mut cut = proposal.cut.clone();
    assert!(cut.readmit(proposal.left_out[0].clone()).unwrap());
    adopt_revoking(&m, &key, 3, &cut);
    eventually("the laptop takes the re-admitted entry back", || async {
        has(&mine, "/fork", "/fork").await
    })
    .await;
}

/// The owner re-admits one entry a revocation cut left out, by its name and digest: every node
/// that refused it takes it back, its writer serves it again, and a device that never got it
/// reads it. Nothing is offered again by anyone: the new context version is the whole news.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_entry_the_owner_readmits_by_name_and_digest_returns_to_every_node() {
    let m = mesh(&["/alice/laptop", "/alice/phone", "/alice/tablet"]).await;
    let (laptop, phone) = (m.boot(0, fast()).await, m.boot(1, fast()).await);
    let mine = laptop.create(&space(), public()).await.unwrap();
    let theirs = phone.open(&space()).await.unwrap();
    eventually("the phone holds the space", || async { theirs.ready() }).await;
    theirs
        .put(&n("/a"), bytes("one"), durable(false))
        .await
        .unwrap();
    eventually("the laptop holds the phone's entry", || async {
        has(&mine, "/a", "one").await
    })
    .await;

    // The cut keeps what the laptop holds; the phone writes once more, which it leaves out.
    let key = m.devs[1].name.clone().append("KEY").append("1");
    let bound = CutBound {
        held_before: Some(Timestamp(u64::MAX / 2)),
        ..CutBound::default()
    };
    let proposal = laptop.revocation_cut(&key, &bound).unwrap();
    theirs
        .put(&n("/c"), bytes("three"), durable(false))
        .await
        .unwrap();
    let adopt = |version: u64, cut: ndn_security::RevocationCut| {
        for dev in &m.devs {
            for packet in &proposal.manifest {
                let data = ndn_packet::Data::decode(packet.clone()).unwrap();
                dev.validator.cut_manifests().insert(&data).unwrap();
            }
            let held = dev
                .validator
                .keyring()
                .contexts()
                .into_iter()
                .find(|c| *c.namespace() == n("/alice"))
                .expect("the namespace's context");
            let next = ndn_security::SignedTrustContext::hierarchical(n("/alice"))
                .with_version(version)
                .with_revocation(key.clone())
                .with_revocation_cut(cut.clone());
            for anchor in held.anchors().iter() {
                next.add_anchor(anchor.value().clone());
            }
            dev.validator
                .keyring()
                .adopt_update(Arc::new(next))
                .expect("adopted");
        }
    };
    adopt(2, proposal.cut.clone());
    eventually("the laptop refuses what the cut leaves out", || async {
        matches!(mine.get(&n("/c")).await, Ok(None))
    })
    .await;
    eventually(
        "the phone lists its own entry as refused by the revocation",
        || async { !phone.refused_by_revocation(&key).is_empty() },
    )
    .await;
    let full = phone.refused_by_revocation(&key).remove(0);

    let mut cut = proposal.cut.clone();
    assert!(cut.readmit(full).unwrap());
    adopt(3, cut);
    eventually("the laptop reads the re-admitted entry", || async {
        has(&mine, "/c", "three").await
    })
    .await;
    eventually("its writer takes it back too", || async {
        has(&theirs, "/c", "three").await
    })
    .await;
    // A device of the owner that never held it asks for the exact packet the cut names.
    let tablet = m.boot(2, fast()).await;
    let late = tablet.open(&space()).await.unwrap();
    eventually("a device that never held it reads it", || async {
        has(&late, "/a", "one").await && has(&late, "/c", "three").await
    })
    .await;
}

/// A thief signs at a lost key's seq 1 and the reader hears the thief first; the honest entry at
/// the same name comes second and is kept as evidence. The owner revokes the key with a cut that
/// keeps neither and re-admits the honest entry by its digest: the reader withdraws the thief's
/// bytes and applies the honest ones it holds as evidence, without asking for them again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_honest_copy_kept_as_evidence_is_applied_when_the_owner_readmits_it() {
    let m = mesh(&["/alice/laptop", "/alice/phone"]).await;
    let laptop = m.boot(0, fast()).await;
    let mine = laptop.create(&space(), public()).await.unwrap();
    let phone = m.devs[1].name.clone();
    let key = phone.clone().append("KEY").append("1");
    let signer = m.devs[1].keys.get_signer_sync(&key).unwrap();
    let signed = |path: &str, value: &str| {
        let content = WireEntry {
            prev: None,
            after: Vec::new(),
            body: Body::Put(PutBody {
                path: n(path),
                payload: Payload::Inline(bytes(value)),
            }),
        }
        .encode()
        .unwrap();
        seal::sign(
            DataBuilder::new(log_name(&phone, &space(), 1), &content),
            &*signer,
        )
        .unwrap()
    };
    let (thief, honest) = (signed("/thief", "stolen"), signed("/honest", "mine"));
    for (wire, outcome) in [(&thief, Outcome::Applied), (&honest, Outcome::Evidence)] {
        let taken = laptop.inner.take(&space(), wire.clone(), false).await;
        assert!(
            matches!(&taken, Taken::Decided { outcome: o, .. } if *o == outcome),
            "{taken:?}"
        );
    }
    assert!(has(&mine, "/thief", "stolen").await);

    // The revocation keeps nothing of the key and names the honest bytes.
    let bound = CutBound {
        held_before: Some(Timestamp(0)),
        ..CutBound::default()
    };
    let proposal = laptop.revocation_cut(&key, &bound).unwrap();
    let adopt = |version: u64, cut: ndn_security::RevocationCut| {
        for dev in &m.devs {
            let held = dev
                .validator
                .keyring()
                .contexts()
                .into_iter()
                .find(|c| *c.namespace() == n("/alice"))
                .expect("the namespace's context");
            let next = ndn_security::SignedTrustContext::hierarchical(n("/alice"))
                .with_version(version)
                .with_revocation(key.clone())
                .with_revocation_cut(cut.clone());
            for anchor in held.anchors().iter() {
                next.add_anchor(anchor.value().clone());
            }
            dev.validator
                .keyring()
                .adopt_update(Arc::new(next))
                .expect("adopted");
        }
    };
    adopt(2, proposal.cut.clone());
    eventually("the reader withdraws the thief's entry", || async {
        matches!(mine.get(&n("/thief")).await, Ok(None))
    })
    .await;
    let named = honest_full(&phone, &honest);
    let mut cut = proposal.cut.clone();
    assert!(cut.readmit(named).unwrap());
    adopt(3, cut);
    eventually("the reader applies the honest entry it held", || async {
        has(&mine, "/honest", "mine").await
    })
    .await;
    assert_eq!(mine.get(&n("/thief")).await.unwrap(), None);
}

/// The name a cut re-admits `wire` by: its entry name with the implicit digest.
fn honest_full(device: &Name, wire: &Bytes) -> Name {
    log_name(device, &space(), 1).append_implicit_digest(crate::wire::implicit_digest(wire))
}

/// A private space has an epoch in force once created, complete for exactly its readers, signed by
/// an owner device; a public space has none.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_private_space_reports_its_epoch_and_a_public_one_none() {
    let m = mesh(&["/alice/laptop"]).await;
    let laptop = m.boot(0, fast()).await;
    let sealed = laptop.create(&space(), private(&["/bob"])).await.unwrap();
    let (epoch, complete) = sealed.epoch().expect("an epoch in force");
    assert_eq!(epoch.creator, m.devs[0].name);
    assert!(complete, "the epoch is for exactly the readers");
    let open = laptop
        .create(&n("/alice/32=data/open"), public())
        .await
        .unwrap();
    assert_eq!(open.epoch(), None, "a public space is never sealed");
}

/// A device that opened a space before its creation reached it lists the owner alone and does not
/// know the members: `members_known` says so until the creation is held.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_follower_knows_no_members_until_the_creation_arrives() {
    let m = mesh(&["/alice/laptop", "/alice/phone"]).await;
    let (laptop, phone) = (m.boot(0, fast()).await, m.boot(1, fast()).await);
    let theirs = phone.open(&space()).await.unwrap();
    assert!(!theirs.members_known(), "nothing was created yet");
    laptop.create(&space(), public()).await.unwrap();
    eventually("the phone sees the creation", || async {
        theirs.members_known()
    })
    .await;
    assert_eq!(theirs.members().readers, Readers::Anyone);
}

/// A face that swallows the next `swallow` Sync Interests its node sends, as a lossy link does.
struct Swallow {
    inner: Arc<dyn Connection>,
    swallow: Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait::async_trait]
impl Connection for Swallow {
    async fn send(&self, wire: Bytes) -> Result<(), AppError> {
        use std::sync::atomic::Ordering;
        if Interest::decode(wire.clone()).is_ok()
            && self
                .swallow
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
        {
            return Ok(());
        }
        self.inner.send(wire).await
    }
    async fn recv(&self) -> Option<Bytes> {
        self.inner.recv().await
    }
    async fn register_prefix(&self, prefix: &Name) -> Result<(), AppError> {
        self.inner.register_prefix(prefix).await
    }
}

/// A notice lost on its way to the only peer costs it a moment, not the group's period (half a
/// minute): the device that announced its newest entry announces it again, after a pause that
/// doubles from a quarter second, until a peer is seen to have taken it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_notice_lost_to_the_only_peer_is_announced_again() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let m = mesh(&["/alice/laptop", "/alice/phone"]).await;
    // The reference timing: a group's period is thirty seconds.
    let slow = || {
        let mut c = cfg();
        c.settle = Duration::from_secs(3);
        c
    };
    let swallow = Arc::new(AtomicUsize::new(0));
    let cancel = CancellationToken::new();
    let dev = &m.devs[0];
    let laptop = Node::start(
        Transport {
            node: m.engine.app_node(cancel.child_token()),
            sync: Arc::new(Swallow {
                inner: m.engine.app_face(cancel.child_token()),
                swallow: Arc::clone(&swallow),
            }),
        },
        dev.name.clone(),
        Arc::clone(&dev.keys),
        Arc::clone(&dev.validator),
        Arc::clone(&dev.store),
        slow(),
    )
    .await
    .expect("the laptop starts");
    let phone = m.boot(1, slow()).await;
    let heap = laptop.create(&space(), public()).await.unwrap();
    let theirs = phone.open(&space()).await.unwrap();
    eventually("the phone sees the creation", || async { theirs.ready() }).await;
    let mut changes = theirs.watch(&Frontier::new()).await.unwrap();
    // The next Sync Interest the laptop sends, the notice of this put, is lost.
    swallow.store(1, Ordering::SeqCst);
    heap.put(&n("/a"), bytes("one"), PutOptions::default())
        .await
        .unwrap();
    let began = tokio::time::Instant::now();
    let item = until(&mut changes, |c| match c {
        Change::Put(item) if item.path == n("/a") => Some(item.clone()),
        _ => None,
    })
    .await;
    assert_eq!(item.bytes, bytes("one"));
    assert_eq!(swallow.load(Ordering::SeqCst), 0, "the notice was lost");
    assert!(
        began.elapsed() < Duration::from_secs(8),
        "the phone heard the put {:?} after it, a group period",
        began.elapsed()
    );
}
