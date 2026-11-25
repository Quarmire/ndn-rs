//! The channel setup through real nodes over one forwarder (docs/specs/channel.md): who is
//! answered with a session, who with a Nack that costs no signature, who with a signed refusal,
//! what a removal does, what a replay yields, the announce.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_app::{AppError, Connection, EngineAppExt};
use ndn_engine::EngineBuilder;
use ndn_foundation_types::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_packet::{Data, Interest, NackReason};
use tokio_util::sync::CancellationToken;

use super::aead::Aead;
use super::answer::{ChanAnswer, session_data};
use super::channels::Asker;
use super::error::ChanError;
use super::key::ChannelKey;
use super::standing::{Who, gate};
use super::wire::{Announce, Answer, ChanAsk, ChannelMode, RefusalCode, SessionRecord, carrier};
use crate::error::NextStep;
use crate::fold::Readers;
use crate::node::tests::{Dev, cfg, space, world, world_apart};
use crate::node::{Config, Node, Transport};
use crate::rt::Instant;
use crate::space::{Heap, MembersChange, Share};
use crate::test_kit::n;
use crate::wire::{chan_prefix, sync_group_of};

/// Timings that let a vector cross in milliseconds.
fn fast() -> Config {
    let mut c = cfg();
    c.settle = Duration::from_secs(3);
    c.svs.jitter_ms = 20;
    c.svs.suppression_period = Duration::from_millis(30);
    c.svs.sync_interval = Duration::from_secs(1);
    c
}

/// Poll `f` until it holds, or fail with `what`.
async fn eventually(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..300 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("not within 15 s: {what}");
}

/// Devices of a world, started on one engine.
struct Rig {
    nodes: Vec<Node>,
    syncs: Vec<Arc<dyn Connection>>,
    cancel: CancellationToken,
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

async fn rig_of(devs: Vec<Dev>) -> Rig {
    let (engine, shutdown) = EngineBuilder::new(Default::default())
        .build()
        .await
        .expect("an engine");
    shutdown.detach();
    for dev in &devs {
        let ns = Name::from_components(dev.name.components()[..1].iter().cloned());
        ndn_namespace::sync_group::carry(&engine, &ns);
    }
    let cancel = CancellationToken::new();
    let (mut nodes, mut syncs) = (Vec::new(), Vec::new());
    for dev in &devs {
        let sync = engine.app_face(cancel.child_token());
        syncs.push(Arc::clone(&sync));
        nodes.push(
            Node::start(
                Transport {
                    node: engine.app_node(cancel.child_token()),
                    sync,
                },
                dev.name.clone(),
                Arc::clone(&dev.keys),
                Arc::clone(&dev.validator),
                Arc::clone(&dev.store),
                fast(),
            )
            .await
            .expect("the node starts"),
        );
    }
    Rig {
        nodes,
        syncs,
        cancel,
    }
}

async fn rig(devices: &[&str]) -> Rig {
    rig_of(world(devices).await).await
}

/// This node holds the space's creation, lists its person, and (sealed) the epoch in force.
fn ready(node: &Node) -> bool {
    node.inner.space_of(&space()).is_some_and(|held| {
        let log = held.log.lock();
        gate(&log, &node.inner.judge, Who::Listed, "test").is_ok()
            && (!log.sealed() || log.fold.in_force().is_some())
    })
}

/// The space `/alice/32=data/notes` owned by the first device, `share` and `change` applied, open
/// at every other device, each ready.
async fn shared(rig: &Rig, share: Share, change: Option<MembersChange>) -> Heap {
    let heap = rig.nodes[0].create(&space(), share).await.unwrap();
    if let Some(change) = change {
        heap.change(change).await.unwrap();
    }
    for node in &rig.nodes[1..] {
        // A device of a person the space does not list has nothing to open.
        if !node.name().to_string().starts_with("/dave") {
            node.open(&space()).await.unwrap();
        }
    }
    eventually("the nodes hold the record", || {
        rig.nodes
            .iter()
            .filter(|n| n.space(&space()).is_some())
            .all(ready)
    })
    .await;
    heap
}

/// A public space written by `writers`, or, when `readers` are named, a **sealed** one read by
/// them and the writers: a public space lists no reader (everybody reads it), and channels need a
/// listed person.
fn public_with(writers: &[&str], readers: &[&str]) -> (Share, Option<MembersChange>) {
    let list = |names: &[&str]| names.iter().map(|w| n(w)).collect::<Vec<Name>>();
    let readers = if readers.is_empty() {
        Readers::Anyone
    } else {
        let mut all = list(readers);
        all.extend(list(writers));
        all.sort();
        all.dedup();
        Readers::Persons(all)
    };
    (
        Share {
            readers,
            writers: list(writers),
        },
        None,
    )
}

fn ask_of(node: &Node, mode: ChannelMode) -> ChanAsk {
    ChanAsk {
        space: space(),
        prefix: Name::root(),
        mode,
        recipient: node.recipient().public(),
        carriers: vec![carrier::DATAGRAM, carrier::STREAM],
        lifetime: 3600,
        epoch: None,
        since: None,
        chain: node.inner.signer_chain(),
    }
}

/// `node`'s signed ask to `to` and the Interest it decodes to.
fn signed_ask(node: &Node, to: &Node, ask: &ChanAsk) -> (Bytes, Interest) {
    let wire = node
        .sign_interest(&chan_prefix(to.name()), &ask.encode().unwrap())
        .unwrap();
    let interest = Interest::decode(wire.clone()).unwrap();
    (wire, interest)
}

async fn fetch(node: &Node, wire: Bytes) -> Result<Data, AppError> {
    node.consumer()
        .fetch_wire(wire, Duration::from_secs(5))
        .await
}

fn nacked(r: Result<Data, AppError>, reason: NackReason) -> bool {
    matches!(r, Err(AppError::Nacked { reason: Some(r) }) if r == reason)
}

fn record_of(sender: &Name, audience: Option<crate::wire::EpochId>) -> SessionRecord {
    SessionRecord {
        id: 5,
        sender: sender.clone(),
        space: space(),
        mode: ChannelMode::Latest,
        key_epoch: 0,
        key_id: [0; 8],
        wrap: Bytes::new(),
        aead: Aead::preferred(),
        carriers: Vec::new(),
        table: Vec::new(),
        ckpt_ms: 20,
        window: None,
        lifetime: 3600,
        audience_epoch: audience,
        frame_max: 1200,
        seq: 1,
        certs: Vec::new(),
    }
}

/// A session Data of `from`'s key answering `to`'s ask `name`, wrapped to `to`, as a sender that
/// ignored its own judgement would make it.
fn crafted(from: &Node, to: &Node, name: &Name, record: SessionRecord) -> Data {
    let wire = session_data(
        &*from.inner.signer,
        name,
        record,
        &ChannelKey::random(),
        &to.recipient().public(),
    )
    .unwrap();
    Data::decode(wire).unwrap()
}

/// Judge `data` as `node`'s answer to the ask it would send to `sender`.
async fn judge(
    node: &Node,
    sender: &Node,
    name: &Name,
    data: Data,
) -> Result<Arc<super::sessions::RecvSession>, ChanError> {
    node.inner
        .chan_take_answer(
            &space(),
            sender.name(),
            ChannelMode::Latest,
            name,
            data,
            node.inner.judge.generation(),
        )
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_writers_ask_is_answered_with_a_session_for_a_writer_and_a_reader() {
    let rig = rig(&["/alice/laptop", "/bob/phone", "/carol/tablet"]).await;
    let (share, change) = public_with(&["/bob"], &["/carol"]);
    shared(&rig, share, change).await;
    let (alice, bob, carol) = (&rig.nodes[0], &rig.nodes[1], &rig.nodes[2]);

    let for_bob = bob
        .ask_channel(&space(), alice.name())
        .await
        .expect("a writer is answered");
    let for_carol = carol
        .ask_channel(&space(), alice.name())
        .await
        .expect("a reader is answered");
    assert_eq!(
        for_bob.channel, for_carol.channel,
        "one channel per space and mode"
    );
    assert_eq!(for_bob.sender, *alice.name());
    assert_eq!((for_bob.mode, for_bob.key_epoch), (ChannelMode::Latest, 0));
    assert_eq!(for_bob.lifetime, Duration::from_secs(3600));

    // Both hold the one key: the frame key of a channel is the same at both ends.
    let now = Instant::now();
    let held = |node: &Node| {
        node.inner
            .chan
            .sessions
            .get(for_bob.channel)
            .expect("a session")
    };
    let (b, c) = (held(bob), held(carol));
    assert_eq!(
        b.frame_key(0, now).unwrap().expose(),
        c.frame_key(0, now).unwrap().expose()
    );
    assert!(b.is_current() && c.is_current());
    assert_eq!(
        alice
            .inner
            .chan
            .channels
            .receiver_count(&space(), ChannelMode::Latest),
        2
    );
    // Two asks, two signatures verified, two sessions signed; nothing else.
    let stats = &alice.inner.chan.stats;
    assert_eq!((stats.answered.get(), stats.refused.get()), (2, 0));
    assert_eq!(alice.inner.judge.interest_walks(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_strangers_ask_is_nacked_and_costs_no_signature_verification() {
    let rig = rig(&["/alice/laptop", "/bob/phone", "/dave/pc"]).await;
    let (share, change) = public_with(&["/bob"], &[]);
    shared(&rig, share, change).await;
    let (alice, bob, dave) = (&rig.nodes[0], &rig.nodes[1], &rig.nodes[2]);
    let (stats, judge) = (&alice.inner.chan.stats, &alice.inner.judge);
    let signed_before = alice
        .inner
        .signatures
        .load(std::sync::atomic::Ordering::Relaxed);

    // Dave's person is listed nowhere: a well-formed, validly signed ask is Nacked, unjudged.
    let (wire, _) = signed_ask(dave, alice, &ask_of(dave, ChannelMode::Latest));
    assert!(nacked(fetch(dave, wire).await, NackReason::NoRoute));
    assert_eq!(
        (stats.strangers.get(), judge.interest_walks()),
        (1, 0),
        "no signature was checked"
    );
    // An ask over 8 KiB, and one that is no ask, are Nacked before they are read.
    let big = dave
        .sign_interest(&chan_prefix(alice.name()), &vec![7u8; 9000])
        .unwrap();
    assert!(nacked(fetch(dave, big).await, NackReason::NoRoute));
    let junk = dave
        .sign_interest(&chan_prefix(alice.name()), b"not an ask")
        .unwrap();
    assert!(nacked(fetch(dave, junk).await, NackReason::NoRoute));
    assert_eq!((stats.oversize.get(), stats.malformed.get()), (1, 1));
    assert_eq!(judge.interest_walks(), 0);
    assert_eq!(
        alice
            .inner
            .signatures
            .load(std::sync::atomic::Ordering::Relaxed),
        signed_before,
        "alice signed nothing for a stranger"
    );

    // A member's key named by a forger costs exactly one verification, and is Nacked too.
    let dave_signer = Arc::clone(&dave.inner.signer);
    let params = ask_of(bob, ChannelMode::Latest).encode().unwrap();
    let forged = InterestBuilder::new(chan_prefix(alice.name()))
        .must_be_fresh()
        .lifetime(Duration::from_secs(4))
        .app_parameters(params.to_vec())
        .sign_sync(dave_signer.sig_type(), Some(bob.writer()), |region| {
            dave_signer.sign_sync(region).unwrap()
        });
    assert!(nacked(fetch(dave, forged).await, NackReason::NoRoute));
    assert_eq!((stats.unverified.get(), judge.interest_walks()), (1, 1));
    assert_eq!(stats.answered.get(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reader_cannot_be_a_sender_and_a_data_from_one_is_refused() {
    let rig = rig(&["/alice/laptop", "/bob/phone", "/carol/tablet"]).await;
    let (share, change) = public_with(&["/bob"], &["/carol"]);
    shared(&rig, share, change).await;
    let (alice, bob, carol) = (&rig.nodes[0], &rig.nodes[1], &rig.nodes[2]);

    // A reader's device has no channel to give: asked, it Nacks.
    match alice.ask_channel(&space(), carol.name()).await {
        Err(e @ ChanError::NotAnswered { .. }) => assert_eq!(e.next(), NextStep::RetryLater),
        other => panic!("a reader answers nobody: {other:?}"),
    }
    // A Data a reader's key signed as a session is no sender's: refused whatever it holds.
    let (_, interest) = signed_ask(bob, carol, &ask_of(bob, ChannelMode::Latest));
    let name = (*interest.name).clone();
    let data = crafted(carol, bob, &name, record_of(carol.name(), None));
    match judge(bob, carol, &name, data).await {
        Err(e @ ChanError::SenderNotWriter { .. }) => assert_eq!(e.next(), NextStep::FixRequest),
        other => panic!("a reader's Data is refused: {other:?}"),
    }
    assert!(
        bob.inner.chan.sessions.all().is_empty(),
        "nothing was installed"
    );
    // Control: the same record signed by a writer's key is accepted.
    let (_, interest) = signed_ask(bob, alice, &ask_of(bob, ChannelMode::Latest));
    let name = (*interest.name).clone();
    let in_force = bob
        .inner
        .space_of(&space())
        .unwrap()
        .log
        .lock()
        .fold
        .in_force();
    let data = crafted(alice, bob, &name, record_of(alice.name(), in_force));
    judge(bob, alice, &name, data)
        .await
        .expect("a writer's Data is accepted");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_session_key_opens_only_with_the_askers_recipient_key_and_the_data_name() {
    let rig = rig(&["/alice/laptop", "/bob/phone", "/carol/tablet"]).await;
    let (share, change) = public_with(&["/bob"], &["/carol"]);
    shared(&rig, share, change).await;
    let (alice, bob, carol) = (&rig.nodes[0], &rig.nodes[1], &rig.nodes[2]);

    let (_, interest) = signed_ask(bob, alice, &ask_of(bob, ChannelMode::Latest));
    let ChanAnswer::Data(wire) = alice.inner.chan_answer(&interest).await else {
        panic!("a member's ask is answered");
    };
    let data = Data::decode(wire).unwrap();
    assert_eq!(
        *data.name, *interest.name,
        "the session is named as the ask"
    );
    let Ok(Answer::Session(record)) = Answer::decode(data.content().unwrap().clone()) else {
        panic!("a session");
    };
    let open =
        |who: &Node, name: &Name, wrap: &[u8]| super::ask::open_wrap(who.recipient(), wrap, name);
    let key = open(bob, &data.name, &record.wrap).expect("the asker opens it");
    assert_eq!(
        ChannelKey::from_bytes(key).id(),
        record.key_id,
        "and it is the key the session names"
    );
    assert!(
        open(carol, &data.name, &record.wrap).is_err(),
        "another device's recipient key does not"
    );
    let renamed = (*data.name).clone().append("x");
    assert!(
        open(bob, &renamed, &record.wrap).is_err(),
        "nor another name"
    );
    let mut flipped = record.wrap.to_vec();
    flipped[40] ^= 1;
    assert!(
        open(bob, &data.name, &flipped).is_err(),
        "nor a wrap with one octet changed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sealed_space_ask_outside_the_audience_gets_a_signed_refusal_that_says_what_to_do() {
    let rig = rig(&["/alice/laptop", "/bob/phone", "/carol/tablet"]).await;
    let share = Share {
        readers: Readers::Persons(vec![n("/carol")]),
        writers: vec![n("/bob")],
    };
    shared(&rig, share, None).await;
    let (alice, bob, carol) = (&rig.nodes[0], &rig.nodes[1], &rig.nodes[2]);

    // Bob writes and reads nothing of the sealed space: authenticated, listed, not in the audience.
    match bob.ask_channel(&space(), alice.name()).await {
        Err(e @ ChanError::Refused { .. }) => {
            let ChanError::Refused { code, text, .. } = &e else {
                unreachable!()
            };
            assert_eq!(*code, RefusalCode::NotAudience);
            assert!(text.contains("owner"), "it says what to do: {text}");
            assert_eq!(e.next(), NextStep::AskOwner);
        }
        other => panic!("outside the audience: a signed refusal, got {other:?}"),
    }
    assert_eq!(alice.inner.chan.stats.refused.get(), 1);
    assert_eq!(
        alice.inner.chan.channels.count(),
        0,
        "a refused ask made no channel"
    );
    // A reader in the audience is answered, and the session names the epoch it was judged by.
    let info = carol
        .ask_channel(&space(), alice.name())
        .await
        .expect("in the audience");
    let session = carol.inner.chan.sessions.get(info.channel).unwrap();
    let in_force = alice
        .inner
        .space_of(&space())
        .unwrap()
        .log
        .lock()
        .fold
        .in_force();
    assert!(in_force.is_some());
    assert_eq!(session.terms().audience, in_force);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removed_receiver_is_not_answered_and_the_channel_rekeys() {
    let rig = rig(&["/alice/laptop", "/bob/phone", "/carol/tablet"]).await;
    let (share, change) = public_with(&["/bob"], &["/carol"]);
    let heap = shared(&rig, share, change).await;
    let (alice, bob, carol) = (&rig.nodes[0], &rig.nodes[1], &rig.nodes[2]);
    bob.ask_channel(&space(), alice.name()).await.unwrap();
    let first = carol.ask_channel(&space(), alice.name()).await.unwrap();
    assert_eq!(first.key_epoch, 0);
    let table = &alice.inner.chan.channels;
    assert_eq!(table.receiver_count(&space(), ChannelMode::Latest), 2);

    heap.change(MembersChange {
        remove: vec![n("/bob")],
        ..MembersChange::default()
    })
    .await
    .unwrap();
    // The owner holds the removal: the channel re-keys and bob is dropped, in one call.
    eventually("the channel is re-keyed and bob dropped", || {
        table
            .current(&space(), ChannelMode::Latest)
            .is_some_and(|k| k.key_epoch >= 1)
            && table.receiver_count(&space(), ChannelMode::Latest) == 1
    })
    .await;
    // Bob's ask is Nacked: his own node may not even send it by now, so it is signed raw.
    let strangers = alice.inner.chan.stats.strangers.get();
    let (wire, _) = signed_ask(bob, alice, &ask_of(bob, ChannelMode::Latest));
    assert!(nacked(fetch(bob, wire).await, NackReason::NoRoute));
    assert_eq!(alice.inner.chan.stats.strangers.get(), strangers + 1);
    // Carol is given the new key, without a second re-key.
    let again = carol.ask_channel(&space(), alice.name()).await.unwrap();
    let now_epoch = table
        .current(&space(), ChannelMode::Latest)
        .unwrap()
        .key_epoch;
    assert_eq!((again.channel, again.key_epoch), (first.channel, now_epoch));
    assert!(
        now_epoch >= 1
            && now_epoch
                == table
                    .current(&space(), ChannelMode::Latest)
                    .unwrap()
                    .key_epoch
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removed_sender_is_dropped_at_the_generation_move() {
    let rig = rig(&["/alice/laptop", "/bob/phone", "/carol/tablet"]).await;
    let (share, change) = public_with(&["/bob"], &["/carol"]);
    let heap = shared(&rig, share, change).await;
    let (bob, carol) = (&rig.nodes[1], &rig.nodes[2]);
    let info = carol
        .ask_channel(&space(), bob.name())
        .await
        .expect("bob is a writer");
    let session = carol.inner.chan.sessions.get(info.channel).unwrap();
    assert!(
        session.is_current(),
        "judged under the counters as they are"
    );

    heap.change(MembersChange {
        remove: vec![n("/bob")],
        ..MembersChange::default()
    })
    .await
    .unwrap();
    eventually(
        "carol holds the removal: the verdict on bob is stale",
        || !session.is_current(),
    )
    .await;
    // The frame layer, finding it stale, judges the sender again before delivering: it fails.
    match session.recheck(&carol.inner) {
        Err(super::sessions::EndReason::NotMember { why }) => {
            assert!(why.contains("writer"), "{why}");
        }
        other => panic!("a removed sender no longer stands: {other:?}"),
    }
    assert!(
        carol.inner.chan.sessions.get(info.channel).is_none(),
        "the session is dropped"
    );
    assert!(matches!(
        session.ended(),
        Some(super::sessions::EndReason::NotMember { .. })
    ));
    assert!(
        session.frame_key(0, Instant::now()).is_none(),
        "and opens nothing"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoked_senders_session_is_dropped_when_the_trust_generation_moves() {
    let rig = rig(&["/alice/laptop", "/bob/phone", "/carol/tablet"]).await;
    let (share, change) = public_with(&["/bob"], &["/carol"]);
    shared(&rig, share, change).await;
    let (bob, carol) = (&rig.nodes[1], &rig.nodes[2]);
    let info = carol.ask_channel(&space(), bob.name()).await.unwrap();
    let session = carol.inner.chan.sessions.get(info.channel).unwrap();
    assert!(session.is_current());

    // Carol adopts a version of /bob's trust context that revokes bob's key.
    let validator = &carol.inner.judge.validator;
    let held = validator
        .keyring()
        .contexts()
        .into_iter()
        .find(|c| *c.namespace() == n("/bob"))
        .expect("the namespace's context");
    let next = ndn_security::SignedTrustContext::hierarchical(n("/bob"))
        .with_version(2)
        .with_revocation(bob.writer().clone());
    for anchor in held.anchors().iter() {
        next.add_anchor(anchor.value().clone());
    }
    validator
        .keyring()
        .adopt_update(Arc::new(next))
        .expect("adopted");

    assert!(!session.is_current(), "the generation moved");
    assert!(
        session.recheck(&carol.inner).is_err(),
        "bob's key is revoked: he no longer stands"
    );
    assert!(carol.inner.chan.sessions.get(info.channel).is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replayed_ask_yields_a_session_only_the_asker_can_open() {
    let rig = rig(&["/alice/laptop", "/bob/phone", "/carol/tablet"]).await;
    let (share, change) = public_with(&["/bob"], &["/carol"]);
    shared(&rig, share, change).await;
    let (alice, bob, carol) = (&rig.nodes[0], &rig.nodes[1], &rig.nodes[2]);
    let (_, interest) = signed_ask(bob, alice, &ask_of(bob, ChannelMode::Latest));

    assert!(matches!(
        alice.inner.chan_answer(&interest).await,
        ChanAnswer::Data(_)
    ));
    // The same signed Interest again, within what the replay guard remembers: Nacked Duplicate.
    assert!(matches!(
        alice.inner.chan_answer(&interest).await,
        ChanAnswer::Nack(NackReason::Duplicate)
    ));
    assert_eq!(alice.inner.chan.stats.replays.get(), 1);

    // A sender that forgot (restarted) answers it: a session wrapped to bob's recipient key,
    // which only bob opens; the one who replayed it (carol) cannot.
    alice.inner.chan.replay.forget_all();
    let ChanAnswer::Data(wire) = alice.inner.chan_answer(&interest).await else {
        panic!("a replay is answered once the guard forgot it");
    };
    let data = Data::decode(wire).unwrap();
    let Ok(Answer::Session(record)) = Answer::decode(data.content().unwrap().clone()) else {
        panic!("a session")
    };
    assert!(super::ask::open_wrap(bob.recipient(), &record.wrap, &data.name).is_ok());
    assert!(super::ask::open_wrap(carol.recipient(), &record.wrap, &data.name).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stale_epoch_sender_is_refused_with_retry() {
    let rig = rig(&["/alice/laptop", "/bob/phone", "/carol/tablet"]).await;
    let share = Share {
        readers: Readers::Persons(vec![n("/bob"), n("/carol")]),
        writers: vec![n("/bob")],
    };
    let heap = shared(&rig, share, None).await;
    let (alice, bob) = (&rig.nodes[0], &rig.nodes[1]);
    // Removing a reader of a sealed space writes a new epoch: the first one is older now.
    heap.change(MembersChange {
        remove: vec![n("/carol")],
        ..MembersChange::default()
    })
    .await
    .unwrap();
    let epochs = |node: &Node| {
        let held = node.inner.space_of(&space()).unwrap();
        let log = held.log.lock();
        (log.fold.in_force(), log.fold.epochs())
    };
    eventually("bob holds both epochs", || {
        let (in_force, all) = epochs(bob);
        all.len() >= 2 && in_force.is_some()
    })
    .await;
    let (in_force, all) = epochs(bob);
    let in_force = in_force.unwrap();
    let old = all
        .into_iter()
        .find(|e| *e != in_force)
        .expect("an older epoch");

    let (_, interest) = signed_ask(bob, alice, &ask_of(bob, ChannelMode::Latest));
    let name = (*interest.name).clone();
    // A sender still on the older epoch: stale, ask again soon.
    let data = crafted(alice, bob, &name, record_of(alice.name(), Some(old)));
    match judge(bob, alice, &name, data).await {
        Err(e @ ChanError::Refused { .. }) => {
            let ChanError::Refused { code, retry_ms, .. } = &e else {
                unreachable!()
            };
            assert_eq!((*code, *retry_ms), (RefusalCode::StaleEpoch, 1000));
            assert_eq!(e.next(), NextStep::RetryLater);
        }
        other => panic!("a sender on an older epoch is stale: {other:?}"),
    }
    // One on an epoch bob does not hold waits for the record.
    let unknown = crate::wire::EpochId {
        creator: n("/alice/laptop"),
        seq: 9999,
    };
    let data = crafted(alice, bob, &name, record_of(alice.name(), Some(unknown)));
    match judge(bob, alice, &name, data).await {
        Err(ChanError::Refused { code, .. }) => assert_eq!(code, RefusalCode::NotReady),
        other => panic!("a sender on a newer epoch: not ready: {other:?}"),
    }
    assert!(bob.inner.chan.sessions.all().is_empty());
    // Control: the epoch in force is accepted.
    let data = crafted(alice, bob, &name, record_of(alice.name(), Some(in_force)));
    judge(bob, alice, &name, data)
        .await
        .expect("the epoch in force is accepted");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_announce_of_a_stranger_costs_a_lookup_and_no_ask() {
    let rig = rig(&["/alice/laptop", "/bob/phone", "/dave/pc"]).await;
    let (share, change) = public_with(&["/bob"], &[]);
    shared(&rig, share, change).await;
    let (alice, bob, dave) = (&rig.nodes[0], &rig.nodes[1], &rig.nodes[2]);
    let group = sync_group_of(&space()).unwrap();
    let _listening = bob.inner.chan_listen(&space());

    // Dave announces himself as a sender: he is no writer of the space.
    let record = Announce {
        sender: dave.name().clone(),
        modes: vec![ChannelMode::Latest],
    }
    .encode();
    let wire = InterestBuilder::new(chan_prefix(&group))
        .lifetime(Duration::from_secs(1))
        .hop_limit(8)
        .app_parameters(record.to_vec())
        .build();
    rig.syncs[2].send(wire).await.unwrap();
    let stats = &bob.inner.chan.stats;
    eventually("bob heard the announce", || {
        stats.announces_heard.get() >= 1
    })
    .await;
    assert_eq!(
        stats.announce_strangers.get(),
        1,
        "a lookup of his person in the record"
    );
    assert_eq!(
        (stats.announce_asks.get(), stats.asked.get()),
        (0, 0),
        "and no ask"
    );
    assert_eq!(
        dave.inner.chan.stats.asks.get() + alice.inner.chan.stats.asks.get(),
        0
    );
    assert_eq!(
        alice.inner.judge.interest_walks() + dave.inner.judge.interest_walks(),
        0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_writers_announce_makes_a_listening_member_ask_once() {
    let rig = rig(&["/alice/laptop", "/bob/phone", "/carol/tablet"]).await;
    let (share, change) = public_with(&["/bob"], &["/carol"]);
    shared(&rig, share, change).await;
    let (alice, bob, carol) = (&rig.nodes[0], &rig.nodes[1], &rig.nodes[2]);
    let now = Instant::now();
    let judged = (
        alice.inner.judge.generation(),
        alice
            .inner
            .space_of(&space())
            .unwrap()
            .log
            .lock()
            .fold
            .version()
            .load(std::sync::atomic::Ordering::SeqCst),
    );
    alice
        .inner
        .chan
        .channels
        .open(&space(), ChannelMode::Latest, None, judged, now)
        .unwrap();
    // Carol wants live data of the space; bob does not.
    let _listening = carol.inner.chan_listen(&space());
    alice.inner.chan_announce(&space()).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let s = &carol.inner.chan.stats;
    assert!(
        carol
            .inner
            .chan
            .sessions
            .find(&space(), alice.name(), ChannelMode::Latest)
            .is_some(),
        "carol: heard {} strangers {} ignored {} announce_asks {} asked {} installed {}; alice sent {}",
        s.announces_heard.get(),
        s.announce_strangers.get(),
        s.announce_ignored.get(),
        s.announce_asks.get(),
        s.asked.get(),
        s.installed.get(),
        alice.inner.chan.stats.announces_sent.get()
    );
    assert_eq!(carol.inner.chan.stats.announce_asks.get(), 1);
    eventually("bob heard it", || {
        bob.inner.chan.stats.announces_heard.get() >= 1
    })
    .await;
    assert_eq!(
        (
            bob.inner.chan.stats.announce_asks.get(),
            bob.inner.chan.stats.asked.get()
        ),
        (0, 0)
    );
    assert_eq!(
        bob.inner.chan.stats.announce_ignored.get(),
        1,
        "a hint nobody wanted"
    );
    // Heard again at once, it makes no second ask of that device.
    alice.inner.chan_announce(&space()).await;
    eventually("carol heard the second", || {
        carol.inner.chan.stats.announces_heard.get() >= 2
    })
    .await;
    assert_eq!(carol.inner.chan.stats.announce_asks.get(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sender_over_its_receiver_cap_gives_a_signed_refusal_that_says_to_retry() {
    let rig = rig(&["/alice/laptop", "/bob/phone"]).await;
    let (share, change) = public_with(&["/bob"], &[]);
    shared(&rig, share, change).await;
    let (alice, bob) = (&rig.nodes[0], &rig.nodes[1]);
    let judged = (
        alice.inner.judge.generation(),
        alice
            .inner
            .space_of(&space())
            .unwrap()
            .log
            .lock()
            .fold
            .version()
            .load(std::sync::atomic::Ordering::SeqCst),
    );
    let now = Instant::now();
    for i in 0..super::channels::RECEIVERS_PER_CHANNEL {
        let (device, key) = (n(&format!("/p{i}/dev")), n(&format!("/p{i}/dev/KEY/1")));
        let asker = Asker {
            device: &device,
            key: &key,
            wanted: 0,
        };
        alice
            .inner
            .chan
            .channels
            .admit(&space(), ChannelMode::Latest, &asker, None, judged, now)
            .unwrap();
    }
    match bob.ask_channel(&space(), alice.name()).await {
        Err(e @ ChanError::Refused { .. }) => {
            let ChanError::Refused {
                code,
                text,
                retry_ms,
                ..
            } = &e
            else {
                unreachable!()
            };
            assert_eq!(*code, RefusalCode::TooMany);
            assert!(text.contains("256") && *retry_ms > 0, "{text}");
            assert_eq!(e.next(), NextStep::RetryLater);
        }
        other => panic!("over the cap: a signed TooMany, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ask_with_a_chain_the_sender_does_not_hold_is_nacked_not_yet_and_the_node_carries_its_chain()
 {
    let rig = rig_of(world_apart(&["/alice/laptop", "/bob/phone"]).await).await;
    let (share, change) = public_with(&["/bob"], &[]);
    shared(&rig, share, change).await;
    let (alice, bob) = (&rig.nodes[0], &rig.nodes[1]);

    // An ask that carries no certificate: alice holds none of bob's, and fetches nothing.
    let mut bare = ask_of(bob, ChannelMode::Latest);
    bare.chain.clear();
    let (_, interest) = signed_ask(bob, alice, &bare);
    assert!(matches!(
        alice.inner.chan_answer(&interest).await,
        ChanAnswer::Nack(NackReason::NotYet)
    ));
    assert_eq!(alice.inner.chan.stats.pending.get(), 1);
    // The node's own ask carries its chain: the same ask is judged and answered.
    bob.ask_channel(&space(), alice.name())
        .await
        .expect("the chain is carried");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reliable_ask_without_a_stream_is_refused_no_stream() {
    let rig = rig(&["/alice/laptop", "/bob/phone"]).await;
    let (share, change) = public_with(&["/bob"], &[]);
    shared(&rig, share, change).await;
    let (alice, bob) = (&rig.nodes[0], &rig.nodes[1]);
    let mut ask = ask_of(bob, ChannelMode::Reliable);
    ask.carriers = vec![carrier::DATAGRAM];
    let (wire, _) = signed_ask(bob, alice, &ask);
    let data = fetch(bob, wire).await.expect("a signed refusal");
    let Ok(Answer::Refusal(r)) = Answer::decode(data.content().unwrap().clone()) else {
        panic!("a refusal");
    };
    assert_eq!(r.code, RefusalCode::NoStream);
    // With a stream the same mode is answered.
    let info = bob
        .ask_channel_in(&space(), alice.name(), ChannelMode::Reliable)
        .await
        .unwrap();
    assert_eq!(info.mode, ChannelMode::Reliable);
}
