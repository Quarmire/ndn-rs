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
    dev.share_folder(
        &folder(),
        share(Rule::Log, &["/alice", "/bob"], readers).into(),
    )
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
            )
            .into(),
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
            )
            .into(),
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
        )
        .into(),
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
    dev.share_folder(
        &f,
        share(Rule::Log, &["/alice"], vec![person("/alice")]).into(),
    )
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
            )
            .into(),
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
            share(Rule::Log, &["/alice", "/bob"], vec![person("/bob")]).into(),
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
        )
        .into(),
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
    dev.share_folder(&f, share(Rule::Log, &["/alice", "/bob"], Vec::new()).into())
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
    dev.share_folder(&f, share(Rule::Log, &["/alice"], Vec::new()).into())
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
        )
        .into(),
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
        )
        .into(),
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

/// A put into another person's collection with no members record held is
/// refused by signed data only (spec §18.1): while a device of that
/// namespace heard here was not walked toward the collection, its record
/// may still arrive — a lost packet on a faulty network — so the put is
/// `NotReady`; once every one was walked and none listed a record, the key
/// may not write there: `NotAllowed`.
#[tokio::test]
async fn a_put_into_another_namespace_is_refused_only_once_its_devices_were_walked() {
    let dev = device("/bob/laptop", &["/alice", "/bob"]).await;
    // Alice's laptop is heard in her namespace's group, never walked.
    let _ = dev.inner.join(&n("/alice")).await;
    dev.inner
        .st
        .lock()
        .groups
        .get_mut(&n("/alice"))
        .expect("joined")
        .members
        .insert(n("/alice/laptop"));
    not_ready(dev.put(&plan(), reading(1), options()).await.unwrap_err());
    // Walked in full, it listed no record of the plan.
    dev.inner
        .st
        .lock()
        .peers
        .entry((n("/alice/laptop"), n("/alice")))
        .or_default()
        .root = Some([1; 32]);
    let refused = dev.put(&plan(), reading(1), options()).await.unwrap_err();
    assert!(matches!(refused, DataError::NotAllowed { .. }), "{refused}");
    dev.shutdown();
}

/// A put into another person's collection under a record that does not
/// admit the key is refused by signed data only (spec §18.1): while a
/// device of that namespace heard here was not walked toward the
/// collection, the record admitting it — signed by a share or an
/// introduction, and lost on its way — may still arrive, so the put is
/// `NotReady`; once every one was walked, the record in force refuses it.
#[tokio::test]
async fn a_put_under_a_record_not_admitting_the_key_is_refused_only_once_its_devices_were_walked() {
    let alice = device("/alice/laptop", &["/alice"]).await;
    alice
        .share_folder(&folder(), share(Rule::Log, &["/alice"], Vec::new()).into())
        .await
        .unwrap();
    let seq = alice.inner.st.lock().head;
    let dev = device("/bob/laptop", &["/alice", "/bob"]).await;
    let _ = dev.inner.join(&n("/alice")).await;
    dev.inner
        .st
        .lock()
        .groups
        .get_mut(&n("/alice"))
        .expect("joined")
        .members
        .insert(n("/alice/laptop"));
    assert_eq!(relay(&alice, &dev, &folder(), seq), None);
    let refused = dev.put(&plan(), reading(1), options()).await.unwrap_err();
    assert!(
        dev.inner.st.lock().colls[&plan()].members.is_some(),
        "the folder's record governs the plan here"
    );
    not_ready(refused);
    // Walked in full, it listed no record admitting Bob.
    dev.inner
        .st
        .lock()
        .peers
        .entry((n("/alice/laptop"), n("/alice")))
        .or_default()
        .root = Some([1; 32]);
    let refused = dev.put(&plan(), reading(1), options()).await.unwrap_err();
    assert!(matches!(refused, DataError::NotAllowed { .. }), "{refused}");
    alice.shutdown();
    dev.shutdown();
}

// ---- REPLY-13 point 9: a device an offer admitted is not a stranger ---------------------------

/// `dev` hears Alice's laptop in her namespace's group, and has walked its
/// summary in full when `walked`.
async fn hears_alice(dev: &Device, walked: bool) {
    let _ = dev.inner.join(&n("/alice")).await;
    let mut st = dev.inner.st.lock();
    st.groups
        .get_mut(&n("/alice"))
        .expect("joined")
        .members
        .insert(n("/alice/laptop"));
    if walked {
        st.peers
            .entry((n("/alice/laptop"), n("/alice")))
            .or_default()
            .root = Some([1; 32]);
    }
}

/// A device that really is no member is refused `AskOwner`; one an offer's
/// answer admitted, that holds no record admitting it yet — none held, or
/// an older revision — is `NotReady`: the record is on its way, so it puts
/// again or joins again with the same code. Once a record admits it the
/// note is let go, so a later removal is refused as it is for anyone.
#[tokio::test]
async fn a_put_by_a_device_an_offer_admitted_is_not_ready_until_its_record_is_held() {
    let alice = device("/alice/laptop", &["/alice", "/bob"]).await;
    alice
        .share_folder(&folder(), share(Rule::Log, &["/alice"], Vec::new()).into())
        .await
        .unwrap();
    let first = alice.inner.st.lock().head;
    let dev = device("/bob/laptop", &["/alice", "/bob"]).await;
    hears_alice(&dev, false).await;
    // Not walked yet: not ready, whoever it is.
    not_ready(dev.put(&plan(), reading(1), options()).await.unwrap_err());
    // Every device walked, no record held: a stranger is told to ask the owner.
    hears_alice(&dev, true).await;
    let refused = dev.put(&plan(), reading(1), options()).await.unwrap_err();
    assert!(matches!(refused, DataError::NotAllowed { .. }), "{refused}");
    assert_eq!(refused.next(), crate::error::NextStep::AskOwner);
    // Admitted by an offer, the record not held yet.
    assert!(dev.inner.note_joined(&folder()).await);
    let refused = dev.put(&plan(), reading(1), options()).await.unwrap_err();
    assert!(
        refused.to_string().contains("join again"),
        "it says what to do: {refused}"
    );
    not_ready(refused);
    // Held, but the revision before the one that admits it.
    assert_eq!(relay(&alice, &dev, &folder(), first), None);
    let refused = dev.put(&plan(), reading(1), options()).await.unwrap_err();
    not_ready(refused);
    // The revision admitting Bob arrives: written, and the note is let go.
    alice
        .share_folder(
            &folder(),
            share(Rule::Log, &["/alice", "/bob"], Vec::new()).into(),
        )
        .await
        .unwrap();
    let second = alice.inner.st.lock().head;
    assert_eq!(relay(&alice, &dev, &folder(), second), None);
    dev.put(&plan(), reading(1), options()).await.unwrap();
    assert!(
        dev.inner
            .store
            .get(&super::intro::joined_name(&folder()))
            .is_none(),
        "the note of the admission is let go once a record admits the device"
    );
    alice.shutdown();
    dev.shutdown();
}

/// A member the record in force admits that does not hold the epoch's key
/// yet — the grant is on its way — is `NotReady`, saying which key.
#[tokio::test]
async fn a_put_by_a_member_that_lacks_the_epochs_key_is_not_ready_naming_it() {
    let alice = device("/alice/laptop", &["/alice", "/bob"]).await;
    alice
        .share_folder(
            &folder(),
            share(
                Rule::Log,
                &["/alice", "/bob"],
                vec![person("/alice"), person("/bob")],
            )
            .into(),
        )
        .await
        .unwrap();
    let seq = alice.inner.st.lock().head;
    let dev = device("/bob/laptop", &["/alice", "/bob"]).await;
    hears_alice(&dev, true).await;
    assert_eq!(relay(&alice, &dev, &folder(), seq), None);
    let refused = dev.put(&plan(), reading(1), options()).await.unwrap_err();
    assert!(
        matches!(&refused, DataError::NotReady { why, .. } if why.contains("key")),
        "{refused}"
    );
    assert_eq!(refused.next(), crate::error::NextStep::RetryLater);
    alice.shutdown();
    dev.shutdown();
}

/// What `join` waits for (REPLY-13 point 9): the members record that admits
/// the device and, sealed, the epoch's key — within `first_look * 3 +
/// lifetime`, naming what is missing when the bound passes, and returning as
/// soon as both are held.
#[tokio::test(start_paused = true)]
async fn a_join_returns_once_the_record_and_the_key_are_held_within_its_bound() {
    use crate::intro::Role;
    let alice = device("/alice/laptop", &["/alice", "/bob"]).await;
    alice
        .share_folder(
            &folder(),
            share(
                Rule::Log,
                &["/alice", "/bob"],
                vec![person("/alice"), person("/bob")],
            )
            .into(),
        )
        .await
        .unwrap();
    let seq = alice.inner.st.lock().head;
    let dev = device("/bob/laptop", &["/alice", "/bob"]).await;
    hears_alice(&dev, false).await;
    let bound = dev.inner.config.first_look * 3 + dev.inner.config.lifetime;
    let inviter = n("/alice/laptop");
    let wait = |dev: &Device| {
        let inner = Arc::clone(&dev.inner);
        let (folder, inviter) = (folder(), inviter.clone());
        async move {
            let start = rt::Instant::now();
            let out = inner.await_admission(&folder, Role::Writer, &inviter).await;
            (out, start.elapsed())
        }
    };
    // Nothing held: the bound passes, and the record is named.
    let (out, took) = wait(&dev).await;
    let refused = out.unwrap_err();
    assert!(
        matches!(&refused, DataError::NotReady { why, .. } if why.contains("members record")),
        "{refused}"
    );
    assert_eq!(refused.next(), crate::error::NextStep::RetryLater);
    assert!(
        took >= bound && took < bound * 2,
        "{took:?} against {bound:?}"
    );
    // The record held, its key not: the key is named.
    assert_eq!(relay(&alice, &dev, &folder(), seq), None);
    let (out, _) = wait(&dev).await;
    let refused = out.unwrap_err();
    assert!(
        matches!(&refused, DataError::NotReady { why, .. } if why.contains("key")),
        "{refused}"
    );
    // The key arrives while the join waits: it returns at once, well inside its bound.
    let (epoch, content_key) = folder_epoch(&alice, &folder());
    let inner = Arc::clone(&dev.inner);
    let f = folder();
    rt::spawn(async move {
        rt::sleep(Duration::from_millis(300)).await;
        assert!(inner.st.lock().take_key(&f, &epoch, content_key));
        inner.progress.notify_waiters();
    });
    let (out, took) = wait(&dev).await;
    out.unwrap();
    assert!(took < bound, "{took:?} against {bound:?}");
    alice.shutdown();
    dev.shutdown();
}

/// A reader is refused a sealed version by signed data only (spec §15,
/// §18.1): holding only a record of the collection that does not admit it,
/// while a device of that namespace heard here was not walked toward the
/// collection, the newer record admitting it — signed by a share, lost on
/// its way — may still arrive, so `get` answers `NotReady`; once every one
/// was walked, the record in force refuses it as `Sealed`.
#[tokio::test]
async fn a_sealed_version_is_refused_to_a_reader_only_once_its_devices_were_walked() {
    let alice = device("/alice/laptop", &["/alice", "/bob"]).await;
    let only = |readers| share(Rule::Log, &["/alice"], readers);
    alice
        .share(&plan(), only(vec![person("/alice")]))
        .await
        .unwrap();
    let first = alice.inner.st.lock().head;
    alice
        .share(&plan(), only(vec![person("/alice"), person("/bob")]))
        .await
        .unwrap();
    let id = alice.put(&plan(), reading(1), options()).await.unwrap();
    let dev = device("/bob/laptop", &["/alice", "/bob"]).await;
    let _ = dev.inner.join(&n("/alice")).await;
    dev.inner
        .st
        .lock()
        .groups
        .get_mut(&n("/alice"))
        .expect("joined")
        .members
        .insert(n("/alice/laptop"));
    // The record that does not admit Bob, and the version sealed in the
    // epoch of the one that does, which has not arrived.
    assert_eq!(relay(&alice, &dev, &plan(), first), None);
    assert_eq!(relay(&alice, &dev, &plan(), id.seq.0), None);
    let v = log_name(alice.name(), Some(&plan()), id.seq.0);
    not_ready(dev.get(&v).await.unwrap_err());
    // Walked in full, it listed no record admitting Bob.
    dev.inner
        .st
        .lock()
        .peers
        .entry((n("/alice/laptop"), n("/alice")))
        .or_default()
        .root = Some([1; 32]);
    let refused = dev.get(&v).await.unwrap_err();
    assert!(matches!(refused, DataError::Sealed { .. }), "{refused}");
    alice.shutdown();
    dev.shutdown();
}

/// Whether `dev` still holds `other`'s summary of `/alice` as walked in full.
fn still_walked(dev: &Device, other: &Name) -> bool {
    dev.inner.st.lock().peers[&(other.clone(), n("/alice"))]
        .root
        .is_some()
}

/// Reading a collection held inside a folder this device follows costs no
/// walk (spec §15, §18.1): the walks that went toward the folder took it. A
/// collection an outside writer was refused making it follow (spec §15,
/// `Config::writer_collections`) was not taken, and following it by its name
/// walks again.
#[tokio::test]
async fn following_a_collection_inside_a_followed_folder_walks_nothing_again() {
    let dev = device("/bob/laptop", &["/alice", "/bob"]).await;
    let alice = n("/alice/laptop");
    assert!(dev.inner.follow(&folder()).await.unwrap(), "followed anew");
    // Alice's summary walked in full while the folder was followed: it took
    // her version of the plan.
    hand(&dev, &alice, &plan(), 1, version(&alice, &plan(), 1, None));
    assert!(dev.inner.st.lock().colls.contains_key(&plan()));
    dev.inner
        .st
        .lock()
        .peers
        .entry((alice.clone(), n("/alice")))
        .or_default()
        .root = Some([1; 32]);
    assert!(
        !dev.inner.follow(&plan()).await.unwrap(),
        "a collection held inside the followed folder is nothing new"
    );
    assert!(
        still_walked(&dev, &alice),
        "nor is the walk that took it forgotten"
    );
    let other = n("/alice/32=data/docs/other");
    let carol = Writer::new(key(&n("/carol/phone")));
    assert!(!dev.inner.st.lock().track(&other, &carol, 0));
    assert!(
        dev.inner.follow(&other).await.unwrap(),
        "a collection refused to an outside writer is followed anew by its name"
    );
    assert!(!still_walked(&dev, &alice), "and walked again");
    dev.shutdown();
}

/// A device following a folder whole learns of a collection under it from
/// a walk — a writer's node lists a version of it — before any version of
/// it is taken (the first one listed is not to be had yet). `get` of that
/// collection answers its state under the folder's record (spec §6.1),
/// the versions it waits for not in it — not `Unavailable` because no
/// version of it arrived yet to set its record in force.
#[tokio::test]
async fn a_collection_a_walk_listed_under_a_followed_folder_is_read_under_the_folder_record() {
    let dev = device("/bob/phone", &["/alice", "/bob"]).await;
    let owner = device("/alice/laptop", &["/alice", "/bob"]).await;
    let f = folder();
    owner
        .share_folder(&f, share(yrs(), &["/alice", "/bob"], Vec::new()).into())
        .await
        .unwrap();
    assert_eq!(relay(&owner, &dev, &f, 1), None);
    dev.inner.follow(&f).await.unwrap();
    // The laptop's node of `plan` lists its version 7, not taken yet.
    dev.inner
        .st
        .lock()
        .colls
        .entry(plan())
        .or_default()
        .entries
        .entry(Writer::new(key(&n("/alice/laptop"))))
        .or_default()
        .insert(7);
    let got = dev.get(&plan()).await;
    assert!(
        matches!(&got, Ok(Answer { got: Got::State(s), .. }) if s.at.is_empty()),
        "a collection under a followed folder is read under the folder's record: {got:?}"
    );
    dev.shutdown();
    owner.shutdown();
}

/// `dev` hears `other`, a device of its own namespace, in the namespace's
/// sync group. Nothing `dev` can reach answers for it, so a look at what it
/// holds never ends.
async fn hears(dev: &Device, other: &str) {
    let ns = dev.inner.ns.clone();
    let _ = dev.inner.join(&ns).await;
    dev.inner
        .st
        .lock()
        .groups
        .get_mut(&ns)
        .expect("joined")
        .members
        .insert(n(other));
}

/// The virtual time `what` takes to finish.
async fn took<T>(what: impl Future<Output = T>) -> (T, Duration) {
    let began = tokio::time::Instant::now();
    let out = what.await;
    (out, began.elapsed())
}

/// `dev` has walked the summary of `other`, a device of its own namespace it
/// heard, toward `folders`: what it may hold of them is held, and a name
/// followed under them later needs no walk of its own.
fn walked(dev: &Device, other: &str, folders: &[Name]) {
    let mut st = dev.inner.st.lock();
    let peer = st
        .peers
        .entry((n(other), dev.inner.ns.clone()))
        .or_default();
    peer.head = 1;
    peer.walked = 1;
    peer.toward = folders.iter().cloned().collect();
}

/// What a put that never waits on another device may take in virtual time:
/// far under the 50 ms first-look time a wait for the phone costs.
const LOCAL: Duration = Duration::from_millis(5);

/// The laptop holds the record of folder `docs` — written by Alice and
/// Bob — and of a merge folder `ops`, and hears the phone, a device of its
/// namespace whose summary nothing it reaches ever answers. While the phone
/// is not walked toward the folder, a put into a collection new to the
/// laptop answers `NotReady` at once, since the phone may hold a narrower
/// record of the collection's own (spec §15, 2). Once it was walked, a put,
/// a `put_op` and a group of twelve into collections new to it, all under a
/// held folder record, inherit that record and return at once (spec §15, 1):
/// none looks at the phone first, so none costs the first-look time, and
/// none signs a members record of its own.
#[tokio::test(start_paused = true)]
async fn a_new_collection_under_a_held_folder_record_is_put_without_waiting_for_a_device_that_cannot_be_reached()
 {
    let dev = device("/alice/laptop", &["/alice", "/bob"]).await;
    let ops = n("/alice/32=data/ops");
    dev.share_folder(
        &folder(),
        share(Rule::Log, &["/alice", "/bob"], Vec::new()).into(),
    )
    .await
    .unwrap();
    dev.share_folder(&ops, share(yrs(), &["/alice", "/bob"], Vec::new()).into())
        .await
        .unwrap();
    hears(&dev, "/alice/phone").await;

    let items: Vec<(Name, Edit)> = (0..12)
        .map(|i| {
            (
                folder().append(format!("paste{i}")),
                Edit::Fields(reading(i)),
            )
        })
        .collect();
    let (refused, spent) = took(dev.put(&plan(), reading(1), options())).await;
    assert!(
        matches!(refused, Err(DataError::NotReady { .. })) && spent < LOCAL,
        "a put inheriting the folder's record, the phone not walked, answered {refused:?} after \
         {spent:?}, not NotReady at once"
    );
    let (refused, spent) = took(dev.put_group(items.clone(), options())).await;
    assert!(
        matches!(refused, Err(DataError::NotReady { .. })) && spent < LOCAL,
        "a group inheriting the folder's record, the phone not walked, answered {refused:?} \
         after {spent:?}, not NotReady at once"
    );
    walked(&dev, "/alice/phone", &[folder(), ops.clone()]);

    let (first, spent) = took(dev.put(&plan(), reading(1), options())).await;
    first.unwrap();
    assert!(
        spent < LOCAL,
        "the first put into a new collection took {spent:?}"
    );

    let a = ops.clone().append("a");
    let op = crate::merge::Yrs::new()
        .start(&a, &Writer::new(key(dev.name())))
        .edit(&reading(1))
        .unwrap();
    let (second, spent) = took(dev.put_op(&a, op, options())).await;
    second.unwrap();
    assert!(
        spent < LOCAL,
        "a put_op into a new collection took {spent:?}"
    );

    let (group, spent) = took(dev.put_group(items.clone(), options())).await;
    assert_eq!(group.unwrap().len(), 12);
    assert!(
        spent < LOCAL,
        "a group of twelve new collections took {spent:?}"
    );

    // Each is written under the record of its folder: none signed its own.
    let st = dev.inner.st.lock();
    let mut all = vec![plan(), a];
    all.extend(items.into_iter().map(|(c, _)| c));
    for c in &all {
        assert!(
            st.colls[c].line.own.is_none(),
            "{c} signed a record of its own"
        );
    }
    drop(st);
    dev.shutdown();
}

/// `share_folder` creating a folder's first record keeps its one bounded
/// look (spec §15, 5): every device heard is walked, for at most the
/// first-look time — an owner device that signs without looking can narrow
/// a line it hasn't seen. Only that call waits: the put right after it,
/// into a collection new to the laptop, answers at once — `NotReady` while
/// the phone, which that look did not reach, was not walked toward the
/// folder (it may hold a narrower record of the collection), and immediate
/// once it was.
#[tokio::test(start_paused = true)]
async fn share_folder_creating_a_first_record_looks_for_at_most_the_first_look_and_the_next_put_does_not()
 {
    let dev = device("/alice/laptop", &["/alice", "/bob"]).await;
    hears(&dev, "/alice/phone").await;
    let first_look = dev.inner.config.first_look;
    let (shared, spent) = took(dev.share_folder(
        &folder(),
        share(Rule::Log, &["/alice", "/bob"], Vec::new()).into(),
    ))
    .await;
    shared.unwrap();
    assert!(
        spent >= first_look && spent <= first_look + LOCAL,
        "the first record of a folder took {spent:?}: one look, at most {first_look:?}"
    );
    let (refused, spent) = took(dev.put(&plan(), reading(1), options())).await;
    assert!(
        matches!(refused, Err(DataError::NotReady { .. })) && spent < LOCAL,
        "the put right after share_folder, the phone not reached by its look, answered \
         {refused:?} after {spent:?}, not NotReady at once"
    );
    walked(&dev, "/alice/phone", &[folder()]);
    let (put, spent) = took(dev.put(&plan(), reading(1), options())).await;
    put.unwrap();
    assert!(
        spent < LOCAL,
        "the put right after share_folder took {spent:?}"
    );
    dev.shutdown();
}
