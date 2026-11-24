//! What a node answers (spec §7): its own entries as far as the host lets it,
//! another device's only as `32=held` and only if admitted, pieces with their
//! entry, its seal key, and a grant only to the reader the host says may have
//! it; nothing under `/localhost`.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_app::{Connection, Node, ServeGuard};
use ndn_foundation_types::Name;
use ndn_packet::Data;
use ndn_packet::encode::{DataBuilder, InterestBuilder};

use super::*;
use crate::node::Config;
use crate::seal::GrantRefusal;
use crate::sync::Net;
use crate::sync::net_kit::*;
use crate::test_kit::n;
use crate::wire::{
    EpochId, GrantAsk, PieceKind, encode_seal_key, grant_name, held_name, log_name, piece_name,
    seal_key_name,
};

const ME: &str = "/alice/laptop";
const PHONE: &str = "/alice/phone";
const TABLET: &str = "/alice/tablet";

/// A node that serves `prefix` with the handler under test.
struct Server {
    host: Arc<Toyhost>,
    wire: Arc<Wire>,
    _guard: ServeGuard,
}

async fn serving(prefix: &str) -> Server {
    let host = Toyhost::new(ME);
    let wire = Wire::new();
    let node = Node::from_connection(Arc::clone(&wire) as Arc<dyn Connection>);
    let net = Net::start(
        Arc::clone(&host) as Arc<dyn Host>,
        Config::default(),
        node.connection(),
        Face::new() as Arc<dyn Connection>,
    );
    let guard = node
        .serve(n(prefix), move |interest, responder| {
            answer(Arc::clone(&net), interest, responder)
        })
        .await
        .expect("the prefix is served");
    Server {
        host,
        wire,
        _guard: guard,
    }
}

impl Server {
    /// Ask for `name` and let the answer come: what the device sent.
    async fn ask(&self, name: &Name) -> Option<Data> {
        let before = self.wire.answers();
        self.wire.inject(
            InterestBuilder::new(name.clone())
                .lifetime(Duration::from_secs(2))
                .build(),
        );
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(
            self.wire.answers() <= before + 1,
            "one ask, at most one answer"
        );
        if self.wire.answers() != before + 1 {
            return None;
        }
        self.wire.answer_at(before).filter(|d| *d.name == *name)
    }
}

fn me() -> Name {
    n(ME)
}

/// An entry of this device is served as the host serves it, and not at all
/// when the host does not: the answer is a Nack, never silence.
#[tokio::test(start_paused = true)]
async fn an_own_entry_is_served_as_the_host_allows() {
    let s = serving(ME).await;
    let wire = genuine(ME, 3);
    s.host.st.lock().served.insert((me(), 3), wire.clone());
    let got = s.ask(&log_name(&me(), &space(), 3)).await.expect("served");
    assert_eq!(got.raw(), &wire, "the packet the entry was signed as");
    assert!(
        s.ask(&log_name(&me(), &space(), 4)).await.is_none(),
        "an entry the host does not serve (not held, or held back until durable)"
    );
    assert_eq!(s.wire.answers(), 2, "and the miss was a Nack");
}

/// Another device's entry is served only as `32=held/<its name>`, only when
/// the host holds and admitted it, and the answer is a DigestSha256 wrapper
/// of the packet its writer signed.
#[tokio::test(start_paused = true)]
async fn a_held_copy_is_served_only_if_admitted() {
    let s = serving(ME).await;
    let original = log_name(&n(PHONE), &space(), 7);
    let ask = held_name(&me(), &original);
    assert!(
        s.ask(&ask).await.is_none(),
        "not held, not admitted: a Nack"
    );
    let wire = genuine(PHONE, 7);
    s.host.st.lock().served.insert((n(PHONE), 7), wire.clone());
    let got = s.ask(&ask).await.expect("admitted: served");
    assert_eq!(
        got.content().cloned(),
        Some(wire),
        "the packet its writer signed, unchanged, inside the wrapper"
    );
    assert_ne!(
        &*got.name, &original,
        "answered under the holder's name, not as the writer"
    );
}

/// A certificate the host's validator vouches for is served as a held copy too, under the
/// holder's name and in a DigestSha256 wrapper; one it does not hold is Nacked.
#[tokio::test(start_paused = true)]
async fn a_certificate_is_served_as_a_held_copy_only_if_the_host_holds_it() {
    let s = serving(ME).await;
    let key = n("/alice/phone/KEY/1");
    let ask = held_name(&me(), &key);
    assert!(s.ask(&ask).await.is_none(), "not held: a Nack");
    let cert =
        DataBuilder::new(key.clone().append("ca").append_version(1), b"cert").sign_digest_sha256();
    s.host.st.lock().certs.insert(key.clone(), cert.clone());
    let got = s.ask(&ask).await.expect("held: served");
    assert_eq!(got.content().cloned(), Some(cert), "the packet, unchanged");
    assert_ne!(&*got.name, &key, "answered under the holder's name");
    assert!(
        s.ask(&held_name(&me(), &n("/alice/tablet/KEY/1")))
            .await
            .is_none(),
        "another key's certificate is not held"
    );
}

/// The pieces of a served entry are served with it, directly and as held;
/// the pieces of an entry that is not served are not.
#[tokio::test(start_paused = true)]
async fn pieces_are_served_with_their_entry() {
    let s = serving(ME).await;
    let entry = log_name(&me(), &space(), 3);
    let piece = piece_name(&entry, PieceKind::Chunk(0));
    let packet = DataBuilder::new(piece.clone(), b"a chunk").sign_digest_sha256();
    {
        let mut st = s.host.st.lock();
        st.served.insert((me(), 3), genuine(ME, 3));
        st.pieces.insert(piece.clone(), packet.clone());
    }
    let got = s.ask(&piece).await.expect("a piece of a served entry");
    assert_eq!(got.raw(), &packet);
    let other = piece_name(&log_name(&me(), &space(), 4), PieceKind::Chunk(0));
    assert!(
        s.ask(&other).await.is_none(),
        "a piece of an entry that is not served"
    );

    let relayed = piece_name(&log_name(&n(PHONE), &space(), 7), PieceKind::Chunk(0));
    let held = DataBuilder::new(relayed.clone(), b"phone's chunk").sign_digest_sha256();
    {
        let mut st = s.host.st.lock();
        st.served.insert((n(PHONE), 7), genuine(PHONE, 7));
        st.pieces.insert(relayed.clone(), held.clone());
    }
    let got = s
        .ask(&held_name(&me(), &relayed))
        .await
        .expect("a held piece");
    assert_eq!(got.content().cloned(), Some(held));
}

/// This device's seal key packet is served under its own name only.
#[tokio::test(start_paused = true)]
async fn the_seal_key_packet_is_served_under_its_own_name() {
    let s = serving(ME).await;
    let packet = DataBuilder::new(seal_key_name(&me(), &[7; 32]), &encode_seal_key(&[7; 32]))
        .sign_digest_sha256();
    s.host.st.lock().seal = Some(packet.clone());
    let got = s
        .ask(&seal_key_name(&me(), &[7; 32]))
        .await
        .expect("served");
    assert_eq!(got.raw(), &packet);
    assert!(
        s.ask(&seal_key_name(&me(), &[8; 32])).await.is_none(),
        "a key this device never published"
    );
}

/// Names under `/localhost` are never served, whatever the host holds, and a
/// name of another device's log is not this device's to answer.
#[tokio::test(start_paused = true)]
async fn localhost_and_other_devices_names_are_never_served() {
    let s = serving("/").await;
    {
        let mut st = s.host.st.lock();
        st.served.insert((me(), 3), genuine(ME, 3));
        st.served.insert((n(PHONE), 3), genuine(PHONE, 3));
        st.seal = Some(
            DataBuilder::new(seal_key_name(&me(), &[7; 32]), &encode_seal_key(&[7; 32]))
                .sign_digest_sha256(),
        );
    }
    let local: Name = "/localhost/ndn-heap/seal/alice/laptop".parse().unwrap();
    assert!(s.ask(&local).await.is_none());
    let under = Name::from_components(
        n("/localhost")
            .components()
            .iter()
            .chain(log_name(&me(), &space(), 3).components())
            .cloned(),
    );
    assert!(s.ask(&under).await.is_none(), "{under}");
    assert!(
        s.ask(&log_name(&n(PHONE), &space(), 3)).await.is_none(),
        "the phone's own entries are the phone's to answer"
    );
}

/// A grant Interest for the epoch with creator `me` and seq `seq`, carrying the asker's seal
/// key packet.
fn grant_ask_of(asker: &str, public: [u8; 32], seq: u64) -> (GrantAsk, Name) {
    let ask = GrantAsk::new(
        space(),
        EpochId { creator: me(), seq },
        seal_packet(asker, public),
    )
    .expect("a grant ask");
    let name = grant_name(&me(), &ask);
    (ask, name)
}

fn grant_ask(asker: &str, public: [u8; 32]) -> (GrantAsk, Name) {
    grant_ask_of(asker, public, 2)
}

/// The asker's seal key packet, as its device would serve it.
fn seal_packet(asker: &str, public: [u8; 32]) -> Bytes {
    DataBuilder::new(seal_key_name(&n(asker), &public), &encode_seal_key(&public))
        .sign_digest_sha256()
}

/// A grant is answered only for a reader: when the host refuses the ask, no
/// answer carries a key and nothing is sent on its behalf.
#[tokio::test(start_paused = true)]
async fn a_non_reader_gets_no_answer_and_the_granter_fetches_nothing() {
    let s = serving(ME).await;
    s.host.st.lock().grant_says = vec![Err(GrantRefusal::NotReaderNow)];
    let (_, name) = grant_ask(TABLET, [9; 32]);
    assert!(s.ask(&name).await.is_none());
    assert_eq!(
        s.wire.total(),
        0,
        "no Interest was sent for the asker's seal key or anything else"
    );
    assert!(
        s.host.st.lock().granted_to.is_empty(),
        "and no key was wrapped"
    );
}

/// A grant is one exchange: the ask carries the asker's seal key packet, so the granter fetches
/// nothing for it. An Interest sent back would have to return within the one lifetime the
/// asker's ask lives, and on a lossy path (Data held back a second or more on every link) that
/// nested exchange almost never does: k2, k6 and o2 under `--faulty`.
#[tokio::test(start_paused = true)]
async fn a_grant_ask_is_answered_without_the_granter_fetching_anything() {
    let s = serving(ME).await;
    let (_, name) = grant_ask(TABLET, [9; 32]);
    let got = s.ask(&name).await.expect("the grant is answered");
    assert_eq!(&*got.name, &name, "under the grant's own name");
    assert_eq!(
        s.wire.total(),
        0,
        "no Interest left the granter for the asker's seal key"
    );
    assert_eq!(
        s.host.st.lock().granted_to,
        vec![[9; 32]],
        "the key is wrapped to the seal key in the packet the asker's device signed"
    );
}

/// A new device of an admitted person gets the key, and the seal key the granter verified is
/// kept: another epoch's ask carrying the same packet is not judged again within one generation
/// of the judge.
#[tokio::test(start_paused = true)]
async fn a_new_device_of_an_admitted_person_gets_the_key_by_a_grant() {
    let s = serving(ME).await;
    let (_, name) = grant_ask(TABLET, [9; 32]);
    let got = s.ask(&name).await.expect("the grant is answered");
    assert_eq!(&*got.name, &name, "under the grant's own name");
    let again = s.ask(&name).await.expect("asked again, answered again");
    assert_eq!(again.name, got.name);
    s.host.st.lock().device_packets_valid = false;
    let (_, next) = grant_ask_of(TABLET, [9; 32], 3);
    assert!(
        s.ask(&next).await.is_some(),
        "a seal key verified is kept: the next epoch's ask is not judged again"
    );
}

/// A reader who was removed is refused every later grant, even the one
/// already answered once: the decision is the host's at each ask. A captured ask replayed after
/// the removal gets nothing, and one replayed while the reader reads gets the key wrapped to
/// the asker's seal key, which only the asker opens.
#[tokio::test(start_paused = true)]
async fn a_removed_reader_is_refused_every_later_grant() {
    let s = serving(ME).await;
    let (_, name) = grant_ask(TABLET, [9; 32]);
    s.host.st.lock().grant_says = vec![Ok(()), Err(GrantRefusal::NotReaderNow)];
    assert!(s.ask(&name).await.is_some(), "while a reader");
    assert!(s.ask(&name).await.is_none(), "removed: refused");
    assert!(s.ask(&name).await.is_none(), "and every ask after");
    assert_eq!(
        s.host.st.lock().granted_to,
        vec![[9; 32]],
        "one key wrapped, to the asker's seal key alone"
    );
}

/// A packet that is not the asker's seal key (another key inside, or one the
/// judge refuses) is no reason to wrap a key to it.
#[tokio::test(start_paused = true)]
async fn a_seal_key_that_is_not_the_askers_gets_no_grant() {
    let s = serving(ME).await;
    // Content names another public key than the name does.
    let seal = seal_key_name(&n(TABLET), &[9; 32]);
    let wrong = DataBuilder::new(seal, &encode_seal_key(&[1; 32])).sign_digest_sha256();
    let ask = GrantAsk::new(
        space(),
        EpochId {
            creator: me(),
            seq: 2,
        },
        wrong,
    )
    .expect("a well-formed ask");
    assert!(
        s.ask(&grant_name(&me(), &ask)).await.is_none(),
        "mismatched content"
    );

    let s = serving(ME).await;
    s.host.st.lock().device_packets_valid = false;
    let (_, name) = grant_ask(TABLET, [9; 32]);
    assert!(s.ask(&name).await.is_none(), "the judge refuses the packet");
    assert!(s.host.st.lock().granted_to.is_empty());
}

/// An asker whose key is revoked is granted nothing, though its person reads:
/// the node says no once the key that signed its seal key packet is known.
#[tokio::test(start_paused = true)]
async fn an_asker_with_a_revoked_key_gets_no_grant() {
    let s = serving(ME).await;
    let (_, name) = grant_ask(TABLET, [9; 32]);
    s.host
        .st
        .lock()
        .revoked_keys
        .insert(n(TABLET).append("KEY").append("1"));
    assert!(s.ask(&name).await.is_none(), "the key is revoked");
}

/// What was verified and answered before a revocation is not served after it:
/// the kept seal key and the kept grant are for the generation of the judge
/// they were made in.
#[tokio::test(start_paused = true)]
async fn a_kept_seal_key_and_grant_are_not_served_after_the_judge_moves() {
    let s = serving(ME).await;
    let (_, name) = grant_ask(TABLET, [9; 32]);
    assert!(
        s.ask(&name).await.is_some(),
        "granted while the key is good"
    );
    {
        // The tablet is stolen and its key revoked: the judge moves on and
        // refuses what the key signed.
        let mut st = s.host.st.lock();
        st.generation += 1;
        st.device_packets_valid = false;
    }
    assert!(
        s.ask(&name).await.is_none(),
        "neither the kept grant nor the kept seal key answers for a revoked key"
    );
    let (_, next) = grant_ask_of(TABLET, [9; 32], 3);
    assert!(
        s.ask(&next).await.is_none(),
        "the seal key in the next ask is judged again, not taken from what was kept"
    );
}
