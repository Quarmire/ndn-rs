//! The sibling surface ([`crate::host`], spec §12): what `ndn-invite` and
//! `ndn-surface` reach the node by. An extension answers the keyword it
//! registered and no other; the signing a node lends out is bounded by the
//! keywords registered; a join's note turns a refusal into a wait until the
//! space lists the device; one entry is fetched by name and judged as any.
//!
//! A child of `mesh_tests`: the cases that need peers run on its mesh (PKI
//! devices on one forwarder), the others on one device with no peers.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use ndn_app::{AppError, Consumer, EngineAppExt};
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Data, Interest};
use ndn_security::ValidationResult;

use super::*;
use crate::error::{NextStep, Refusal};
use crate::host::{AnswerFuture, Extension, NodeHandle};
use crate::node::tests::{Counting, boot, solo};
use crate::space::MembersChange;
use crate::store::Kind;
use crate::wire::{self, signed_digest};

/// Answers every Interest under its keyword `ping` with a Data it signs
/// through the node, and counts the Interests it was asked.
struct Pinger {
    node: NodeHandle,
    asked: AtomicUsize,
}

impl Extension for Pinger {
    fn keywords(&self) -> &'static [&'static str] {
        &["ping"]
    }

    fn answer<'a>(&'a self, interest: &'a Interest) -> AnswerFuture<'a> {
        Box::pin(async move {
            self.asked.fetch_add(1, Ordering::SeqCst);
            let name = (*interest.name).clone();
            self.node.sign_packet(DataBuilder::new(name, b"pong")).ok()
        })
    }
}

/// An extension that claims `keywords` and answers nothing.
struct Claims(&'static [&'static str]);

impl Extension for Claims {
    fn keywords(&self) -> &'static [&'static str] {
        self.0
    }

    fn answer<'a>(&'a self, _interest: &'a Interest) -> AnswerFuture<'a> {
        Box::pin(async { None })
    }
}

/// What a consumer on `node` gets for `name`, asked once and given two
/// seconds.
async fn ask(node: &Node, name: &str) -> Result<Data, AppError> {
    let mut consumer: Consumer = node.consumer();
    consumer
        .fetch_with(InterestBuilder::new(n(name)).lifetime(Duration::from_secs(2)))
        .await
}

/// Device `i` of the mesh, started with a sync face that carries nothing: it
/// hears no notice of any entry, so what it holds is what it fetched by name.
async fn boot_deaf(m: &Mesh, i: usize) -> Node {
    let cancel = {
        let mut held = m.cancels[i].lock();
        held.cancel();
        *held = CancellationToken::new();
        held.clone()
    };
    let dev = &m.devs[i];
    let mut config = fast();
    config.lifetime = Duration::from_millis(300);
    let deaf = Arc::new(Counting {
        sent: AtomicUsize::new(0),
        carried: AtomicU64::new(0),
    });
    Node::start(
        Transport {
            node: m.engine.app_node(cancel.child_token()),
            sync: deaf,
        },
        dev.name.clone(),
        Arc::clone(&dev.keys),
        Arc::clone(&dev.validator),
        Arc::clone(&dev.store),
        config,
    )
    .await
    .expect("the node starts")
}

/// An Interest under `<D>/32=ping` reaches the extension that registered
/// `ping`, which answers with a packet signed by the device's key; an
/// Interest under a keyword nobody registered, or under a core one, never
/// reaches it and is Nacked; the core keywords still serve.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_extension_answers_its_keyword_only() {
    let m = mesh(&["/alice/laptop", "/alice/phone"]).await;
    let (laptop, phone) = (m.boot(0, fast()).await, m.boot(1, fast()).await);
    let pinger = Arc::new(Pinger {
        node: laptop.handle(),
        asked: AtomicUsize::new(0),
    });
    laptop.extend(pinger.clone()).expect("`ping` is free");

    let pong = ask(&phone, "/alice/laptop/32=ping/hello")
        .await
        .expect("the extension answers its keyword");
    assert_eq!(*pong.name, n("/alice/laptop/32=ping/hello"));
    assert_eq!(pong.content().map(|c| c.as_ref()), Some(&b"pong"[..]));
    let signer = pong.sig_info().and_then(|s| s.key_locator_name());
    assert_eq!(signer.as_deref(), Some(laptop.writer()), "the device's key");
    assert!(
        matches!(
            phone.validator().validate(&pong).await,
            ValidationResult::Valid(_)
        ),
        "a peer verifies it as the device's own packet"
    );
    assert_eq!(pinger.asked.load(Ordering::SeqCst), 1);

    for other in [
        "/alice/laptop/32=pong/hello",
        "/alice/laptop/32=seal/hello",
        "/alice/laptop/32=grant/hello",
        "/alice/laptop/32=held/hello",
        "/alice/laptop/hello",
    ] {
        let refused = ask(&phone, other).await;
        assert!(
            matches!(refused, Err(AppError::Nacked { .. })),
            "{other} is Nacked, not answered: {refused:?}"
        );
    }
    assert_eq!(
        pinger.asked.load(Ordering::SeqCst),
        1,
        "the extension was asked for its own keyword only"
    );

    // The core router serves what it served: an entry reaches a peer.
    let heap = laptop.create(&space(), public()).await.unwrap();
    let theirs = phone.open(&space()).await.unwrap();
    heap.put(&n("/a"), bytes("one"), PutOptions::default())
        .await
        .unwrap();
    eventually("the phone reads the laptop's put", || async {
        has(&theirs, "/a", "one").await
    })
    .await;
    assert_eq!(pinger.asked.load(Ordering::SeqCst), 1);
}

/// What a node signs for its extensions is bounded by what they registered:
/// only a name `<this device>/32=<keyword>/…` of a registered keyword. A core
/// keyword's name, another device's, a name with no keyword or with one not
/// right after the device, and a certificate's name are refused before the
/// key is used.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sign_packet_refuses_a_name_no_extension_owns() {
    let dev = solo().await;
    let (node, _) = boot(&dev, cfg()).await;
    let sign = |name: &str| node.sign_packet(DataBuilder::new(n(name), b"x"));

    let refused = |name: &str| {
        let why = sign(name).expect_err(name);
        assert!(
            matches!(&why, HeapError::BadRequest { .. }),
            "{name}: {why:?}"
        );
        assert_eq!(why.next(), NextStep::FixRequest, "{name}");
    };
    // Nothing is registered: no name is signed.
    refused("/alice/laptop/32=ping/x");
    node.extend(Arc::new(Claims(&["ping"]))).unwrap();
    let before = node.signatures();
    for name in [
        "/alice/laptop/32=ping/x",
        "/alice/laptop/32=ping",
        "/alice/laptop/32=ping/a/b/c",
    ] {
        let wire = sign(name).unwrap_or_else(|e| panic!("{name}: {e}"));
        let data = Data::decode(wire).unwrap();
        assert_eq!(*data.name, n(name));
        let signer = data.sig_info().and_then(|s| s.key_locator_name());
        assert_eq!(signer.as_deref(), Some(node.writer()), "{name}");
    }
    assert_eq!(node.signatures(), before + 3);

    for name in [
        "/alice/laptop/32=pong/x",
        "/alice/laptop/32=pin/x",
        "/alice/laptop/32=ping2/x",
        "/alice/laptop/32=log/alice/32=data/notes/seq=9",
        "/alice/laptop/32=seal/x",
        "/alice/laptop/32=grant/x",
        "/alice/laptop/32=held/x",
        "/alice/laptop/32=sync/x",
        "/alice/phone/32=ping/x",
        "/alice/32=ping/x",
        "/alice/laptop",
        "/alice/laptop/x",
        "/alice/laptop/x/32=ping/y",
        "/alice/laptop/KEY/1",
        "/localhost/ndn-heap/32=ping/x",
        "/32=ping/x",
    ] {
        refused(name);
    }
    assert_eq!(node.signatures(), before + 3, "a refusal signs nothing");
}

/// An extension may not claim a keyword the core serves or one already
/// claimed, nor none, nor a word that is no keyword; a refused one registers
/// nothing, not even its other keywords.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn extend_refuses_a_core_keyword_and_a_duplicate() {
    static CORE: &[&[&str]] = &[
        &["data"],
        &["log"],
        &["seal"],
        &["grant"],
        &["held"],
        &["piece"],
        &["manifest"],
        &["signal"],
        &["run"],
        &["sync"],
    ];
    let dev = solo().await;
    let (node, _) = boot(&dev, cfg()).await;
    let bad = |claim: &'static [&'static str]| {
        let why = node
            .extend(Arc::new(Claims(claim)))
            .expect_err(&format!("{claim:?}"));
        assert!(
            matches!(&why, HeapError::BadRequest { .. }),
            "{claim:?}: {why:?}"
        );
        assert_eq!(why.next(), NextStep::FixRequest);
    };
    for claim in CORE.iter().copied() {
        bad(claim);
    }
    bad(&[]);
    bad(&[""]);
    bad(&["UPPER"]);
    bad(&["a/b"]);
    bad(&["ping", "ping"]);

    node.extend(Arc::new(Claims(&["ping"]))).unwrap();
    bad(&["ping"]);
    // One claim that is refused for a keyword registers none of its words.
    bad(&["fresh", "ping"]);
    bad(&["fresh", "log"]);
    assert!(
        node.sign_packet(DataBuilder::new(n("/alice/laptop/32=fresh/x"), b"x"))
            .is_err(),
        "`fresh` was not registered by a refused claim"
    );
    node.extend(Arc::new(Claims(&["fresh", "ask"]))).unwrap();
    node.sign_packet(DataBuilder::new(n("/alice/laptop/32=fresh/x"), b"x"))
        .unwrap();
    node.sign_packet(DataBuilder::new(n("/alice/laptop/32=ask/x"), b"x"))
        .unwrap();
}

/// A device an offer admitted is told to wait, not to ask the owner, until
/// the space lists it: `NotAllowed` without the note, `NotReady` (retry) with
/// it, a put that goes through once the owner's entry arrives, and the note
/// gone then.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn note_joined_turns_not_allowed_into_not_ready_until_listed() {
    let m = mesh(&["/alice/laptop", "/bob/laptop"]).await;
    let (alice, bob) = (m.boot(0, fast()).await, m.boot(1, fast()).await);
    let heap = alice.create(&space(), public()).await.unwrap();
    let theirs = bob.open(&space()).await.unwrap();
    eventually("bob sees the creation", || async { theirs.members_known() }).await;
    let note = Kind::JOINED.of(&space());

    let path = n("/b");
    let put = || theirs.put(&path, bytes("bob"), PutOptions::default());
    let refused = put().await.expect_err("bob is no member");
    assert!(
        matches!(refused, HeapError::NotAllowed { .. }),
        "{refused:?}"
    );
    assert_eq!(refused.next(), NextStep::AskOwner);

    bob.note_joined(&space());
    assert!(
        bob.store().get(&note).is_some(),
        "the note is in the store, under /localhost/ndn-heap/joined/<space>"
    );
    let waiting = put().await.expect_err("bob is not listed yet");
    assert!(matches!(waiting, HeapError::NotReady { .. }), "{waiting:?}");
    assert!(waiting.retry(), "{waiting:?}");
    assert_eq!(waiting.next(), NextStep::RetryLater);
    assert!(bob.store().get(&note).is_some(), "still not listed: kept");

    heap.change(MembersChange {
        add_writers: vec![n("/bob")],
        add_readers: vec![n("/bob")],
        ..MembersChange::default()
    })
    .await
    .unwrap();
    let mut tries = 0;
    loop {
        match put().await {
            Ok(_) => break,
            Err(e) => assert!(e.retry(), "a wait until listed, never a refusal: {e:?}"),
        }
        tries += 1;
        assert!(tries < 300, "bob's put did not go through within 15 s");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(theirs.members().writers.contains(&n("/bob")));
    assert!(
        bob.store().get(&note).is_none(),
        "the note is cleared once the space lists the device"
    );

    // Noting a join of a space that lists the device keeps nothing.
    bob.note_joined(&space());
    assert!(bob.store().get(&note).is_none());
}

/// The note outlives a restart: a device that stopped between the answer and
/// the record is still told to wait.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_joined_note_survives_a_restart() {
    let m = mesh(&["/alice/laptop", "/bob/laptop"]).await;
    let (alice, bob) = (m.boot(0, fast()).await, m.boot(1, fast()).await);
    alice.create(&space(), public()).await.unwrap();
    let theirs = bob.open(&space()).await.unwrap();
    eventually("bob sees the creation", || async { theirs.members_known() }).await;
    bob.note_joined(&space());
    bob.flush().await.unwrap();
    drop(theirs);
    drop(bob);
    m.kill(1);
    let again = m.boot(1, fast()).await;
    let heap = again.space(&space()).expect("the space is held again");
    eventually("bob sees the creation again", || async {
        heap.members_known()
    })
    .await;
    let waiting = heap
        .put(&n("/b"), bytes("bob"), PutOptions::default())
        .await
        .expect_err("bob is not listed");
    assert!(matches!(waiting, HeapError::NotReady { .. }), "{waiting:?}");
}

/// A device told to wait for the entry that lists it stops waiting when the
/// admission was undone before it ever saw it listed: a removal of its person
/// it did not know of arrives, and no Add of hers stands. Here Bob hears the
/// removal an owner device signed (Alice's phone) before the Add it names (her
/// laptop's), so the fold never lists him; he is then told to ask the owner, not
/// to wait for ever.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_joined_note_ends_when_the_listing_it_waited_for_was_undone() {
    let m = mesh(&["/alice/laptop", "/alice/phone", "/bob/laptop"]).await;
    let (laptop, phone) = (m.boot(0, fast()).await, m.boot(1, fast()).await);
    let heap = laptop.create(&space(), public()).await.unwrap();
    let add = heap
        .change(MembersChange {
            add_writers: vec![n("/bob")],
            ..MembersChange::default()
        })
        .await
        .unwrap();
    let theirs = phone.open(&space()).await.unwrap();
    eventually("the phone holds the listing", || async {
        theirs.members().writers.contains(&n("/bob"))
    })
    .await;
    let removal = theirs
        .change(MembersChange {
            remove: vec![n("/bob")],
            ..MembersChange::default()
        })
        .await
        .unwrap();
    assert_eq!(removal.device, m.devs[1].name);

    let bob = boot_deaf(&m, 2).await;
    let bobs = bob.open(&space()).await.unwrap();
    let creation = wire::log_name(&m.devs[0].name, &space(), 1);
    bob.fetch_entry(&creation).await.expect("the creation");
    bob.note_joined(&space());
    let note = Kind::JOINED.of(&space());
    let path = n("/b");
    let put = || bobs.put(&path, bytes("bob"), PutOptions::default());
    let waiting = put().await.unwrap_err();
    assert!(matches!(waiting, HeapError::NotReady { .. }), "{waiting:?}");

    // The removal first: the Add it names is not held, so it names nobody here.
    let removing = wire::log_name(&m.devs[1].name, &space(), removal.seq);
    assert_eq!(bob.fetch_entry(&removing).await.unwrap(), removal);
    let waiting = put().await.unwrap_err();
    assert!(matches!(waiting, HeapError::NotReady { .. }), "{waiting:?}");
    assert!(bob.store().get(&note).is_some());

    // Then the Add: Bob is removed already, listed at no moment.
    let adding = wire::log_name(&m.devs[0].name, &space(), add.seq);
    assert_eq!(bob.fetch_entry(&adding).await.unwrap(), add);
    let refused = put().await.unwrap_err();
    assert!(
        matches!(refused, HeapError::NotAllowed { .. }),
        "{refused:?}"
    );
    assert_eq!(refused.next(), NextStep::AskOwner);
    assert!(
        bob.store().get(&note).is_none(),
        "the note ended with the wait"
    );
}

/// One entry is fetched by its log name and judged as any entry is: held and
/// applied, its id returned, and nothing else fetched with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fetch_entry_admits_one_entry_by_name() {
    let m = mesh(&["/alice/laptop", "/alice/phone"]).await;
    let laptop = m.boot(0, fast()).await;
    let heap = laptop.create(&space(), public()).await.unwrap();
    let put = heap
        .put(&n("/a"), bytes("one"), durable(true))
        .await
        .unwrap();
    let phone = boot_deaf(&m, 1).await;
    let theirs = phone.open(&space()).await.unwrap();
    assert!(!theirs.members_known(), "the phone hears no notice");

    let not_an_entry = phone.fetch_entry(&n("/alice/laptop")).await.unwrap_err();
    assert!(
        matches!(not_an_entry, HeapError::BadName { .. }),
        "{not_an_entry:?}"
    );
    let other = n("/alice/32=data/other");
    let closed = phone
        .fetch_entry(&wire::log_name(&m.devs[0].name, &other, 1))
        .await
        .unwrap_err();
    assert!(matches!(closed, HeapError::BadRequest { .. }), "{closed:?}");

    let creation = wire::log_name(&m.devs[0].name, &space(), 1);
    let id = phone.fetch_entry(&creation).await.expect("fetched");
    assert_eq!((&id.device, id.seq), (&m.devs[0].name, 1));
    assert_eq!(
        id.digest,
        signed_digest(&m.devs[0].store.get(&creation).unwrap()),
        "the id names the signed bytes"
    );
    assert!(theirs.applied(&id), "admitted by the ordinary judge");
    assert!(theirs.members_known(), "and it was the creation");
    assert_eq!(phone.held(), 1, "nothing else came with it");
    assert!(theirs.get(&n("/a")).await.unwrap().is_none());

    let by_name = wire::log_name(&m.devs[0].name, &space(), put.seq);
    assert_eq!(phone.fetch_entry(&by_name).await.unwrap(), put);
    assert!(has(&theirs, "/a", "one").await);
    assert_eq!(
        phone.fetch_entry(&creation).await.unwrap(),
        id,
        "an entry held already is the same answer"
    );

    let absent = wire::log_name(&m.devs[0].name, &space(), 99);
    let gone = phone.fetch_entry(&absent).await.unwrap_err();
    assert!(matches!(gone, HeapError::Unavailable { .. }), "{gone:?}");
    assert!(gone.retry());
}

/// An entry the judge refuses is refused to the caller too: `fetch_entry` is
/// no way around admission. Bob's entry is signed by a writer the phone does
/// not know of yet (the owner's Members entry that lists him is not held):
/// refused as not a member's and applied nowhere; once the Members entry is
/// fetched, the same name is admitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fetch_entry_does_not_admit_what_the_judge_refuses() {
    let m = mesh(&["/alice/laptop", "/alice/phone", "/bob/laptop"]).await;
    let (laptop, bob) = (m.boot(0, fast()).await, m.boot(2, fast()).await);
    let heap = laptop.create(&space(), public()).await.unwrap();
    let listing = heap
        .change(MembersChange {
            add_writers: vec![n("/bob")],
            ..MembersChange::default()
        })
        .await
        .unwrap();
    let bobs = bob.open(&space()).await.unwrap();
    let mut tries = 0;
    let written = loop {
        match bobs
            .put(&n("/b"), bytes("bob"), PutOptions::default())
            .await
        {
            Ok(id) => break id,
            Err(e) => assert!(e.retry(), "{e:?}"),
        }
        tries += 1;
        assert!(tries < 300, "bob's put did not go through within 15 s");
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    let phone = boot_deaf(&m, 1).await;
    let theirs = phone.open(&space()).await.unwrap();
    let creation = wire::log_name(&m.devs[0].name, &space(), 1);
    phone.fetch_entry(&creation).await.expect("the creation");
    let by_bob = wire::log_name(&m.devs[2].name, &space(), written.seq);
    let refused = phone.fetch_entry(&by_bob).await.unwrap_err();
    assert!(
        matches!(
            &refused,
            HeapError::Refused {
                why: Refusal::NotMember,
                ..
            }
        ),
        "{refused:?}"
    );
    assert!(!theirs.applied(&written), "refused, not applied");

    let members = wire::log_name(&m.devs[0].name, &space(), listing.seq);
    assert_eq!(phone.fetch_entry(&members).await.unwrap(), listing);
    assert_eq!(phone.fetch_entry(&by_bob).await.unwrap(), written);
    assert!(theirs.applied(&written));
}

/// `Heap::removed_by` names the Members entry that removed a person who is
/// not listed, so a host can tell the removed person where to fetch it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removed_by_names_the_members_entry_that_removed_a_person() {
    let m = mesh(&["/alice/laptop", "/bob/laptop"]).await;
    let alice = m.boot(0, fast()).await;
    let heap = alice.create(&space(), public()).await.unwrap();
    assert_eq!(heap.removed_by(&n("/bob")), None, "never listed");
    heap.change(MembersChange {
        add_writers: vec![n("/bob")],
        ..MembersChange::default()
    })
    .await
    .unwrap();
    assert_eq!(heap.removed_by(&n("/bob")), None, "listed");
    let removal = heap
        .change(MembersChange {
            remove: vec![n("/bob")],
            ..MembersChange::default()
        })
        .await
        .unwrap();
    assert_eq!(heap.removed_by(&n("/bob")), Some(removal.clone()));
    assert_eq!(removal.device, m.devs[0].name);
    assert_eq!(
        heap.removed_by(&n("/alice")),
        None,
        "the owner is never removed"
    );
    heap.change(MembersChange {
        add_writers: vec![n("/bob")],
        ..MembersChange::default()
    })
    .await
    .unwrap();
    assert_eq!(heap.removed_by(&n("/bob")), None, "admitted again");
}

/// A node tells its host what it was started with and what time it keeps:
/// the names it judges by, its clock and the person of a device.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_node_lends_its_keys_validator_store_clock_and_persons() {
    let dev = solo().await;
    let (node, _) = boot(&dev, cfg()).await;
    assert!(Arc::ptr_eq(node.keys(), &dev.keys));
    assert!(Arc::ptr_eq(node.validator(), &dev.validator));
    assert!(std::ptr::addr_eq(
        Arc::as_ptr(node.store()),
        Arc::as_ptr(&dev.store)
    ));
    assert_eq!(node.person_of(&n("/alice/phone")), n("/alice"));
    assert_eq!(node.person_of(node.name()), *node.namespace());
    assert_eq!(node.config().lifetime, cfg().lifetime);
    let (before, now) = ((cfg().clock)(), node.now());
    assert!(now >= before && now.0 - before.0 < 5_000, "{before} {now}");
    let recipient = node.recipient();
    assert_eq!(recipient.public().len(), 32);
    let handle = node.handle();
    assert_eq!(handle.name(), node.name());
    assert!(Arc::ptr_eq(handle.keys(), node.keys()));
}
