//! Folder records and the write paths under them (spec §5, §6.1, §9, §14):
//! a collection's first own record starts from the record in force over it,
//! a refused write leaves nothing behind, a folder dropping a reader stops
//! sealing for it, folder epochs are erased, and a device not synced with
//! the folder's summaries neither signs a default record nor cuts.

use super::*;
use crate::layer::Share;
use crate::merge::Value;
use ndn_app::AppError;
use ndn_security::TrustSchema;
use ndn_sync::MemoryStore;

/// A forwarder that never delivers anything: the test hands the device the
/// packets it would have fetched.
struct Unconnected;

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

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

fn key(device: &Name) -> Name {
    device.clone().append("KEY").append("1")
}

fn id(device: &Name, seq: u64) -> VersionId {
    VersionId {
        writer: Writer::new(key(device)),
        seq: Seq(seq),
    }
}

fn person(p: &str) -> Audience {
    Audience::Person(n(p))
}

fn share(rule: Rule, writers: &[&str], readers: Vec<Audience>) -> Share {
    Share {
        rule,
        writers: writers.iter().map(|w| n(w)).collect(),
        readers,
    }
}

fn yrs() -> Rule {
    Rule::Merge {
        function: crate::merge::Yrs::new().function().clone(),
    }
}

fn folder() -> Name {
    n("/alice/32=data/docs")
}

fn plan() -> Name {
    n("/alice/32=data/docs/plan")
}

fn notes() -> Name {
    n("/alice/32=data/docs/notes")
}

fn options() -> PutOptions {
    PutOptions {
        type_id: TypeId {
            name: n("/types/note"),
            revision: 1,
        },
        keep: Keep::Forever,
        batch: None,
    }
}

fn reading(t: u64) -> Content {
    Content::new().with("t", Bytes::from(t.to_string()))
}

/// The parts a device is started from, so a test can start it again.
struct Parts {
    device: Name,
    keys: Arc<SecurityManager>,
    validator: Arc<Validator>,
    store: Arc<dyn DataStore>,
}

impl Parts {
    fn new(device: &str, others: &[&str]) -> Parts {
        let device = n(device);
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        for ns in others {
            validator
                .adopt_context(Arc::new(SignedTrustContext::hierarchical(n(ns))))
                .unwrap();
        }
        let keys = Arc::new(SecurityManager::new());
        keys.generate_ed25519(key(&device)).unwrap();
        Parts {
            device,
            keys,
            validator,
            store: Arc::new(MemoryStore::new()),
        }
    }

    async fn start(&self) -> Device {
        let conn: Arc<dyn Connection> = Arc::new(Unconnected);
        Device::start(
            Transport {
                node: Node::from_connection(Arc::clone(&conn)),
                sync: conn,
            },
            self.device.clone(),
            Arc::clone(&self.keys),
            Arc::clone(&self.validator),
            Arc::clone(&self.store),
            Config {
                first_look: Duration::from_millis(50),
                ..Config::new()
            },
        )
        .await
        .unwrap()
    }
}

async fn device(name: &str, others: &[&str]) -> Device {
    Parts::new(name, others).start().await
}

/// Hand `dev` the log entry `seq` of `device` about `c` carrying `record`,
/// signed (unchecked) by the device's key, as if fetched and verified; why
/// it is refused, if it is.
fn hand(dev: &Device, device: &Name, c: &Name, seq: u64, record: Record) -> Option<Refusal> {
    let name = log_name(device, Some(c), seq);
    let k = key(device);
    let packet = DataBuilder::new(name.clone(), &wire::encode_record(&record)).sign_sync(
        ndn_packet::SignatureType::SignatureEd25519,
        Some(&k),
        |_| Bytes::from_static(&[0; 64]),
    );
    let mut st = dev.inner.st.lock();
    dev.inner
        .take(&mut st, name.clone(), packet, Writer::new(k), record, false);
    st.refused.get(&name).cloned()
}

/// Hand `to` the log entry `seq` of `from` about `c`, as `from` signed it.
fn relay(from: &Device, to: &Device, c: &Name, seq: u64) -> Option<Refusal> {
    let name = log_name(from.name(), Some(c), seq);
    let wire = from.inner.store.get(&name).expect("written and stored");
    let content = Data::decode(wire).unwrap().content().unwrap().clone();
    hand(
        to,
        from.name(),
        c,
        seq,
        wire::decode_record(content).unwrap(),
    )
}

/// A version of `c`, sealed in `sealed` (its epoch and key) if given.
fn version(device: &Name, c: &Name, seq: u64, sealed: Option<(&Epoch, &ContentKey)>) -> Record {
    let name = log_name(device, Some(c), seq);
    let fields = Content::new().with("t", format!("{device} {seq}"));
    let (fields, sealed) = match sealed {
        Some((e, k)) => (
            Content::new(),
            Some(SealedBody {
                epoch: e.clone(),
                ciphertext: seal::seal_payload(k, &name, &fields, b""),
            }),
        ),
        None => (fields, None),
    };
    Record::Version(VersionBody {
        collection: c.clone(),
        parents: Parents::new(),
        type_id: TypeId {
            name: n("/types/note"),
            revision: 1,
        },
        seal: Seal { any_of: Vec::new() },
        keep: Keep::Forever,
        dated: Timestamp(1),
        group: None,
        rule: None,
        fields,
        op: Bytes::new(),
        sealed,
        chunks: None,
        block: None,
    })
}

fn prune(c: &Name, device: &Name, seq: u64) -> Record {
    Record::Prune(PruneBody {
        prefix: c.clone(),
        upto: [id(device, seq)].into_iter().collect(),
    })
}

fn own(dev: &Device, c: &Name) -> Members {
    dev.inner.st.lock().colls[c].line.own.clone().unwrap()
}

fn refused(dev: &Device, device: &Name, c: &Name, seq: u64) -> Option<Refusal> {
    dev.inner
        .st
        .lock()
        .refused
        .get(&log_name(device, Some(c), seq))
        .cloned()
}

/// The folder's epoch in force here, and its key.
fn folder_epoch(dev: &Device, f: &Name) -> (Epoch, ContentKey) {
    let st = dev.inner.st.lock();
    let e = st.folders[f]
        .members
        .as_ref()
        .unwrap()
        .epoch
        .clone()
        .unwrap();
    let k = st.keys.key(f, &e).unwrap();
    (e, k)
}

/// `/alice/laptop` owning folder `docs`, written by Alice and Bob, holding
/// Bob's version 1 of `plan`, which inherits the folder's record.
async fn inheriting(readers: Vec<Audience>) -> (Device, Name) {
    let dev = device("/alice/laptop", &["/alice", "/bob"]).await;
    dev.share_folder(&folder(), share(Rule::Log, &["/alice", "/bob"], readers))
        .await
        .unwrap();
    let bob = n("/bob/phone");
    assert_eq!(
        hand(&dev, &bob, &plan(), 1, version(&bob, &plan(), 1, None)),
        None
    );
    assert!(dev.inner.st.lock().colls[&plan()].line.own.is_none());
    (dev, bob)
}

// ---- M2: the first own record under a folder -------------------------------------------------

#[tokio::test]
async fn a_first_own_record_changing_the_rule_starts_after_what_was_applied() {
    let (dev, bob) = inheriting(Vec::new()).await;
    dev.share(&plan(), share(yrs(), &[], Vec::new()))
        .await
        .unwrap();
    let m = own(&dev, &plan());
    assert_eq!((m.revision, m.parent), (Seq(1), None));
    assert!(
        m.since.as_ref().is_some_and(|s| s.contains(&id(&bob, 1))),
        "the history read under the folder's rule stays out of the new rule's state"
    );
    assert_eq!(refused(&dev, &bob, &plan(), 1), None);
    dev.shutdown();
}

#[tokio::test]
async fn a_first_own_record_sealing_under_an_unsealed_folder_keeps_the_history() {
    let (dev, bob) = inheriting(Vec::new()).await;
    dev.share(&plan(), share(Rule::Log, &[], vec![person("/alice")]))
        .await
        .unwrap();
    let m = own(&dev, &plan());
    assert!(m.since.as_ref().is_some_and(|s| s.contains(&id(&bob, 1))));
    assert_eq!(
        refused(&dev, &bob, &plan(), 1),
        None,
        "written before the seal, it stays admitted"
    );
    assert!(
        dev.inner.st.lock().colls[&plan()]
            .versions
            .contains_key(&id(&bob, 1))
    );
    dev.shutdown();
}

#[tokio::test]
async fn a_first_own_record_narrowing_the_writers_cuts_and_keeps_their_past() {
    let (dev, bob) = inheriting(Vec::new()).await;
    dev.share(&plan(), share(Rule::Log, &["/alice"], Vec::new()))
        .await
        .unwrap();
    let m = own(&dev, &plan());
    assert!(m.cuts.iter().any(|k| k.of == n("/bob")), "a removal cut");
    assert_eq!(refused(&dev, &bob, &plan(), 1), None, "its past stays");
    assert!(matches!(
        hand(&dev, &bob, &plan(), 2, version(&bob, &plan(), 2, None)),
        Some(Refusal::OutsideCut(_))
    ));
    dev.shutdown();
}

// ---- M3: a refused write leaves nothing behind ------------------------------------------------

#[tokio::test]
async fn a_refused_edit_leaves_the_merge_state_as_it_was() {
    let dev = device("/alice/laptop", &["/alice"]).await;
    let c = n("/alice/32=data/notebook");
    dev.put(&c, reading(1), options()).await.unwrap();
    let value = |dev: &Device| -> Value {
        dev.inner.st.lock().colls[&c]
            .state
            .as_ref()
            .unwrap()
            .value(&BTreeSet::new())
    };
    let (before, head) = (value(&dev), dev.inner.st.lock().head);
    // Fields and operation together pass the most a version carries.
    let huge = Content::new().with("t", Bytes::from(vec![7u8; 33 << 20]));
    let refused = dev.put(&c, huge, options()).await.unwrap_err();
    assert!(matches!(refused, DataError::TooLarge { .. }), "{refused}");
    assert_eq!(value(&dev), before, "the refused edit is not in the state");
    assert_eq!(dev.inner.st.lock().head, head, "nothing signed");
    dev.shutdown();
}

#[tokio::test]
async fn a_refused_operation_into_a_new_collection_signs_no_members_record() {
    let dev = device("/alice/laptop", &["/alice"]).await;
    let c = n("/alice/32=data/notebook");
    let head = dev.inner.st.lock().head;
    let refused = dev
        .put_op(&c, Bytes::from_static(b"not an update"), options())
        .await
        .unwrap_err();
    assert!(matches!(refused, DataError::BadRequest { .. }), "{refused}");
    {
        let st = dev.inner.st.lock();
        assert_eq!(st.head, head, "nothing signed");
        assert!(st.colls.get(&c).is_none_or(|x| x.line.own.is_none()));
    }
    // The collection is still the app's to create.
    dev.put(&c, reading(1), options()).await.unwrap();
    assert_eq!(own(&dev, &c).revision, Seq(1));
    dev.shutdown();
}

// ---- M5: a folder dropping a reader ------------------------------------------------------------

#[tokio::test]
async fn a_writer_does_not_seal_for_a_reader_the_folder_dropped() {
    let owner = device("/alice/laptop", &["/alice", "/bob", "/carol"]).await;
    let writer = device("/bob/laptop", &["/alice", "/bob", "/carol"]).await;
    let (f, c) = (folder(), plan());
    owner
        .share_folder(
            &f,
            share(
                Rule::Log,
                &["/alice", "/bob"],
                vec![person("/alice"), person("/bob"), person("/carol")],
            ),
        )
        .await
        .unwrap();
    owner
        .share(
            &c,
            share(Rule::Log, &[], vec![person("/bob"), person("/carol")]),
        )
        .await
        .unwrap();
    let (e, k) = {
        let st = owner.inner.st.lock();
        let e = st.colls[&c]
            .members
            .as_ref()
            .unwrap()
            .epoch
            .clone()
            .unwrap();
        let k = st.keys.key(&c, &e).unwrap();
        (e, k)
    };
    let head = owner.inner.st.lock().head;
    for seq in 1..=head {
        let subject = match seq {
            1 => &f,
            _ => &c,
        };
        relay(&owner, &writer, subject, seq);
    }
    assert!(writer.inner.st.lock().take_key(&c, &e, k));
    writer.put(&c, reading(1), options()).await.unwrap();
    // The folder drops Carol; the collection's record moving it to a new
    // epoch has not reached the writer.
    owner
        .share_folder(
            &f,
            share(
                Rule::Log,
                &["/alice", "/bob"],
                vec![person("/alice"), person("/bob")],
            ),
        )
        .await
        .unwrap();
    let folder_record = (head + 1..=owner.inner.st.lock().head)
        .find(|seq| {
            owner
                .inner
                .store
                .get(&log_name(owner.name(), Some(&f), *seq))
                .is_some()
        })
        .unwrap();
    assert_eq!(relay(&owner, &writer, &f, folder_record), None);
    let before = writer.inner.st.lock().head;
    not_ready(writer.put(&c, reading(2), options()).await.unwrap_err());
    assert_eq!(
        writer.inner.st.lock().head,
        before,
        "nothing sealed in the epoch Carol reads"
    );
    owner.shutdown();
    writer.shutdown();
}

// ---- M6: folder epochs are erased --------------------------------------------------------------

#[tokio::test]
async fn a_folder_epoch_key_is_destroyed_only_once_every_writer_left_it_everywhere_under_it() {
    let parts = Parts::new("/alice/laptop", &["/alice", "/bob"]);
    let dev = parts.start().await;
    let f = folder();
    dev.share_folder(
        &f,
        share(
            Rule::Log,
            &["/alice"],
            vec![person("/alice"), person("/bob")],
        ),
    )
    .await
    .unwrap();
    let (first, first_key) = folder_epoch(&dev, &f);
    let (phone, tablet) = (n("/alice/phone"), n("/alice/tablet"));
    let sealed = |e, k| Some((e, k));
    assert_eq!(
        hand(
            &dev,
            &phone,
            &plan(),
            1,
            version(&phone, &plan(), 1, sealed(&first, &first_key))
        ),
        None
    );
    assert_eq!(
        hand(
            &dev,
            &tablet,
            &notes(),
            1,
            version(&tablet, &notes(), 1, sealed(&first, &first_key))
        ),
        None
    );
    // Bob removed: a new folder epoch.
    dev.share_folder(&f, share(Rule::Log, &["/alice"], vec![person("/alice")]))
        .await
        .unwrap();
    let (second, second_key) = folder_epoch(&dev, &f);
    assert_ne!(first, second);
    // The phone moves on and prunes its version of the first epoch; the
    // tablet, which has not heard of the second, prunes its own.
    assert_eq!(
        hand(
            &dev,
            &phone,
            &plan(),
            2,
            version(&phone, &plan(), 2, sealed(&second, &second_key))
        ),
        None
    );
    hand(&dev, &phone, &plan(), 3, prune(&plan(), &phone, 1));
    hand(&dev, &tablet, &notes(), 2, prune(&notes(), &tablet, 1));
    assert!(
        dev.inner.st.lock().keys.key(&f, &first).is_some(),
        "the tablet may still write in the first epoch: its erasure waits"
    );
    // It did, offline, in another collection under the folder: it opens.
    assert_eq!(
        hand(
            &dev,
            &tablet,
            &plan(),
            3,
            version(&tablet, &plan(), 3, sealed(&first, &first_key))
        ),
        None
    );
    assert!(matches!(
        dev.inner
            .st
            .lock()
            .held
            .get(&log_name(&tablet, Some(&plan()), 3)),
        Some(Held::Version(_))
    ));
    // It moves on and prunes that one too: now the epoch goes.
    assert_eq!(
        hand(
            &dev,
            &tablet,
            &notes(),
            4,
            version(&tablet, &notes(), 4, sealed(&second, &second_key))
        ),
        None
    );
    hand(&dev, &tablet, &plan(), 5, prune(&plan(), &tablet, 3));
    assert!(
        dev.inner.st.lock().keys.key(&f, &first).is_none(),
        "every writer left the first epoch and pruned all of it"
    );
    assert!(dev.inner.st.lock().keys.key(&f, &second).is_some());
    // The erasure outlives a restart: the key, granted again, is refused.
    dev.shutdown();
    drop(dev);
    let again = parts.start().await;
    {
        let mut st = again.inner.st.lock();
        assert!(st.folders[&f].erased.contains(&first));
        assert!(!st.take_key(&f, &first, first_key.clone()));
    }
    again.shutdown();
}

#[tokio::test]
async fn a_folder_epoch_is_kept_while_a_collection_under_it_is_not_known() {
    let dev = device("/bob/phone", &["/alice", "/bob"]).await;
    let owner = device("/alice/laptop", &["/alice", "/bob"]).await;
    let f = folder();
    owner
        .share_folder(
            &f,
            share(
                Rule::Log,
                &["/alice", "/bob"],
                vec![person("/alice"), person("/bob")],
            ),
        )
        .await
        .unwrap();
    let (first, first_key) = folder_epoch(&owner, &f);
    // Bob's phone reads only `plan`, not the whole folder.
    assert_eq!(relay(&owner, &dev, &f, 1), None);
    assert!(dev.inner.st.lock().take_key(&f, &first, first_key.clone()));
    owner
        .share_folder(
            &f,
            share(Rule::Log, &["/alice", "/bob"], vec![person("/bob")]),
        )
        .await
        .unwrap();
    let (second, second_key) = folder_epoch(&owner, &f);
    assert_eq!(relay(&owner, &dev, &f, owner.inner.st.lock().head), None);
    assert!(
        dev.inner
            .st
            .lock()
            .take_key(&f, &second, second_key.clone())
    );
    let tablet = n("/alice/tablet");
    let sealed = |e, k| Some((e, k));
    assert_eq!(
        hand(
            &dev,
            &tablet,
            &plan(),
            1,
            version(&tablet, &plan(), 1, sealed(&first, &first_key))
        ),
        None
    );
    assert_eq!(
        hand(
            &dev,
            &tablet,
            &plan(),
            2,
            version(&tablet, &plan(), 2, sealed(&second, &second_key))
        ),
        None
    );
    hand(&dev, &tablet, &plan(), 3, prune(&plan(), &tablet, 1));
    assert!(
        dev.inner.st.lock().keys.key(&f, &first).is_some(),
        "another collection under the folder may hold versions of the epoch"
    );
    dev.shutdown();
    owner.shutdown();
}

#[tokio::test]
async fn pruning_in_the_folder_epoch_in_force_rotates_it_and_erases_its_key() {
    let dev = device("/alice/laptop", &["/alice", "/bob"]).await;
    let f = folder();
    dev.share_folder(
        &f,
        share(
            Rule::Log,
            &["/alice"],
            vec![person("/alice"), person("/bob")],
        ),
    )
    .await
    .unwrap();
    let (first, _) = folder_epoch(&dev, &f);
    let written = dev.put(&plan(), reading(1), options()).await.unwrap();
    dev.prune(&plan(), &[written].into_iter().collect())
        .await
        .unwrap();
    let (second, _) = folder_epoch(&dev, &f);
    assert_ne!(first, second, "the folder moved to a new epoch");
    let st = dev.inner.st.lock();
    assert!(
        st.keys.key(&f, &first).is_none(),
        "the pruned epoch's key is gone"
    );
    assert!(st.folders[&f].erased.contains(&first));
    drop(st);
    dev.shutdown();
}

// ---- M8, L1: a device not synced with the folder above ----------------------------------------

/// Make `dev` know `other`, a device of its namespace whose summary root
/// it verified up to `head`, and walked in full up to `walked` (in an
/// earlier run, say), and not since.
fn knows(dev: &Device, other: &str, head: u64, walked: u64) {
    let ns = dev.inner.ns.clone();
    let mut st = dev.inner.st.lock();
    let peer = st.peers.entry((n(other), ns)).or_default();
    peer.head = head;
    peer.kept = head;
    peer.walked = walked;
}

/// Mark `other`'s summary walked in full.
fn synced(dev: &Device, other: &str) {
    let ns = dev.inner.ns.clone();
    let mut st = dev.inner.st.lock();
    st.peers.entry((n(other), ns)).or_default().root = Some([1; 32]);
}

fn not_ready(r: DataError) {
    assert!(
        matches!(r, DataError::NotReady { ref why, .. } if !why.is_empty()),
        "{r}"
    );
    assert_eq!(r.next(), crate::error::NextStep::RetryLater);
    assert!(r.retry());
}

#[tokio::test]
async fn an_owner_device_not_synced_signs_no_default_record() {
    let dev = device("/alice/laptop", &["/alice"]).await;
    // The phone, never walked here, may hold the folder's record.
    knows(&dev, "/alice/phone", 3, 0);
    let head = dev.inner.st.lock().head;
    not_ready(dev.put(&plan(), reading(1), options()).await.unwrap_err());
    assert_eq!(dev.inner.st.lock().head, head, "no record signed");
    not_ready(
        dev.put_group(vec![(plan(), Edit::Fields(reading(1)))], options())
            .await
            .unwrap_err(),
    );
    assert_eq!(dev.inner.st.lock().head, head, "no record signed");
    // Synced, the collection is created.
    synced(&dev, "/alice/phone");
    dev.put(&plan(), reading(1), options()).await.unwrap();
    assert_eq!(own(&dev, &plan()).revision, Seq(1));
    dev.shutdown();
}

/// `dev` restarted from `parts`, having walked `/alice/phone`'s summary
/// in full up to head 3 in its earlier run while it followed `toward`.
async fn walked_earlier(parts: &Parts, toward: &[Name]) -> Device {
    let dev = parts.start().await;
    let (phone, ns) = (n("/alice/phone"), n("/alice"));
    let toward: BTreeSet<Name> = toward.iter().cloned().collect();
    dev.inner
        .store
        .insert(walked_name(&phone, &ns), encode_walked(3, &toward));
    dev.shutdown();
    drop(dev);
    let dev = parts.start().await;
    {
        let st = dev.inner.st.lock();
        let peer = &st.peers[&(phone, ns)];
        assert_eq!((peer.walked, &peer.toward), (3, &toward));
    }
    dev
}

#[tokio::test]
async fn a_device_walked_in_an_earlier_run_holds_nothing_back_until_it_moves() {
    let parts = Parts::new("/alice/laptop", &["/alice"]);
    // That walk went toward the folder (it followed a collection in it).
    let dev = walked_earlier(&parts, &[plan()]).await;
    // Offline since, at the head walked: nothing held back.
    knows(&dev, "/alice/phone", 3, 3);
    dev.put(&notes(), reading(1), options()).await.unwrap();
    // Heard at a newer head not walked yet: it may hold a folder record.
    knows(&dev, "/alice/phone", 5, 3);
    let head = dev.inner.st.lock().head;
    let later = n("/alice/32=data/docs/later");
    not_ready(dev.put(&later, reading(1), options()).await.unwrap_err());
    assert_eq!(dev.inner.st.lock().head, head, "no record signed");
    dev.shutdown();
}

#[tokio::test]
async fn a_walk_that_never_went_toward_the_folder_does_not_count_for_it() {
    let parts = Parts::new("/alice/laptop", &["/alice"]);
    // That walk followed only the photos: it took no folder record of
    // `docs`, which the phone may have signed.
    let dev = walked_earlier(&parts, &[n("/alice/32=data/photos")]).await;
    knows(&dev, "/alice/phone", 3, 3);
    let head = dev.inner.st.lock().head;
    not_ready(dev.put(&notes(), reading(1), options()).await.unwrap_err());
    assert_eq!(dev.inner.st.lock().head, head, "no record signed");
    // A collection with no folder above it is not held back by it.
    dev.put(&n("/alice/32=data/diary"), reading(1), options())
        .await
        .unwrap();
    dev.shutdown();
}

#[tokio::test]
async fn a_cut_is_signed_over_what_is_held_whoever_stays_away() {
    let dev = device("/alice/laptop", &["/alice", "/bob"]).await;
    let f = folder();
    dev.share_folder(&f, share(Rule::Log, &["/alice", "/bob"], Vec::new()))
        .await
        .unwrap();
    // Bob wrote in two collections under the folder, held here, neither
    // followed by itself; his phone is unreachable and was never walked.
    let bob = n("/bob/phone");
    assert_eq!(
        hand(&dev, &bob, &plan(), 1, version(&bob, &plan(), 1, None)),
        None
    );
    assert_eq!(
        hand(&dev, &bob, &notes(), 2, version(&bob, &notes(), 2, None)),
        None
    );
    knows(&dev, "/bob/phone", 3, 0);
    // Removing him is not held off by his phone staying away.
    dev.share_folder(&f, share(Rule::Log, &["/alice"], Vec::new()))
        .await
        .unwrap();
    // The cut covers what is held, in every collection under the folder.
    for (c, seq) in [(plan(), 1), (notes(), 2)] {
        assert_eq!(refused(&dev, &bob, &c, seq), None, "seq {seq} in {c} stays");
    }
    assert!(matches!(
        hand(&dev, &bob, &plan(), 3, version(&bob, &plan(), 3, None)),
        Some(Refusal::OutsideCut(_))
    ));
    dev.shutdown();
}

// ---- what is owed survives a restart; any prune in a folder's epoch rotates it ---------------

#[tokio::test]
async fn an_epoch_owed_when_the_device_stopped_is_owed_again_after_a_restart() {
    let parts = Parts::new("/alice/laptop", &["/alice", "/bob"]);
    let dev = parts.start().await;
    let (f, c) = (folder(), plan());
    dev.share_folder(
        &f,
        share(
            Rule::Log,
            &["/alice"],
            vec![person("/alice"), person("/bob")],
        ),
    )
    .await
    .unwrap();
    dev.share(
        &c,
        share(Rule::Log, &[], vec![person("/alice"), person("/bob")]),
    )
    .await
    .unwrap();
    let before = own(&dev, &c).epoch.unwrap();
    // The phone drops Bob from the folder; this device stops before it
    // signs the collection's new epoch.
    let first = dev.inner.st.lock().folders[&f].line.own.clone().unwrap();
    let drops = MembersBody {
        readers: vec![person("/alice")],
        revision: 2,
        parent: Some(first.as_parent()),
        ..wire::MembersBody::from(&first)
    };
    assert_eq!(
        hand(&dev, &n("/alice/phone"), &f, 1, Record::Members(drops)),
        None
    );
    dev.shutdown();
    drop(dev);
    let dev = parts.start().await;
    let now = own(&dev, &c).epoch.unwrap();
    assert_ne!(now, before, "the epoch Bob holds the key of is left");
    dev.put(&c, reading(1), options()).await.unwrap();
    dev.shutdown();
}

#[tokio::test]
async fn another_writers_prune_in_the_folder_epoch_in_force_rotates_it() {
    let dev = device("/alice/laptop", &["/alice", "/bob"]).await;
    let f = folder();
    dev.share_folder(
        &f,
        share(
            Rule::Log,
            &["/alice"],
            vec![person("/alice"), person("/bob")],
        ),
    )
    .await
    .unwrap();
    let (first, key) = folder_epoch(&dev, &f);
    let tablet = n("/alice/tablet");
    assert_eq!(
        hand(
            &dev,
            &tablet,
            &plan(),
            1,
            version(&tablet, &plan(), 1, Some((&first, &key)))
        ),
        None
    );
    hand(&dev, &tablet, &plan(), 2, prune(&plan(), &tablet, 1));
    dev.inner.settle().await;
    let (second, _) = folder_epoch(&dev, &f);
    assert_ne!(first, second, "the folder moved to a new epoch");
    dev.shutdown();
}

#[tokio::test]
async fn a_lost_device_marked_suspected_is_not_waited_for() {
    let dev = device("/alice/laptop", &["/alice"]).await;
    // The phone, lost before this device ever walked it.
    knows(&dev, "/alice/phone", 3, 0);
    let refused = dev.put(&plan(), reading(1), options()).await.unwrap_err();
    match &refused {
        DataError::NotReady { why, .. } => {
            assert!(why.contains("/alice/phone"), "names the device: {why}")
        }
        other => panic!("{other}"),
    }
    // The owner marks its key suspected: it is waited for no more.
    dev.inner
        .st
        .lock()
        .suspected
        .insert(n("/alice/phone/KEY/1"), Timestamp(1));
    dev.put(&plan(), reading(1), options()).await.unwrap();
    assert_eq!(own(&dev, &plan()).revision, Seq(1));
    dev.shutdown();
}
