//! A cut is exactly what this node holds verified of a key, read through the
//! `verified/` markers and the entries' key locators; suspicion is the
//! node's mark, ended by the revocation. The logs are real (over the crash
//! store, as `log/tests.rs` builds them) and the judge is the caller's: a
//! case hands the log the `Verified` the judge would have made.

use std::collections::BTreeSet;
use std::sync::Arc;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_packet::Data;
use ndn_packet::encode::DataBuilder;
use ndn_security::confidentiality::RecipientKey;
use ndn_security::{
    CertCache, Certificate, Ed25519Signer, Keyring, RevocationCut, SignedTrustContext, Signer,
    Validator, public_key_digest,
};
use ndn_sync::{DataStore, MemoryStore};

use super::*;
use crate::error::{Cut, NextStep, Refusal, Timestamp};
use crate::log::{Log, Outcome, Params};
use crate::reserve::Flusher;
use crate::seal::{self, Keys};
use crate::store::Stage;
use crate::test_kit::{CrashStore, n};
use crate::trust::{Judge, Verified};
use crate::wire::{
    Body, Entry, MembersBody, Op, Payload, Prev, PutBody, Role, implicit_digest, log_name,
    signed_digest,
};

fn notes() -> Name {
    n("/alice/32=data/notes")
}
fn photos() -> Name {
    n("/alice/32=data/photos")
}
fn diary() -> Name {
    n("/alice/32=data/diary")
}

/// A device and one of its keys.
#[derive(Clone)]
struct Dev {
    name: Name,
    key: Name,
    person: Name,
    signer: Arc<Ed25519Signer>,
}

fn dev(name: &str, person: &str, key_id: &str, seed: u8) -> Dev {
    let key = n(&format!("{name}/KEY/{key_id}"));
    Dev {
        name: n(name),
        key: key.clone(),
        person: n(person),
        signer: Arc::new(Ed25519Signer::from_seed(&[seed; 32], key)),
    }
}

/// Bob's phone and its first key.
fn bob() -> Dev {
    dev("/bob/phone", "/bob", "k1", 3)
}
/// Bob's phone, a second key of it.
fn bob_k2() -> Dev {
    dev("/bob/phone", "/bob", "k2", 5)
}
fn alice() -> Dev {
    dev("/alice/phone", "/alice", "k1", 1)
}
fn carol() -> Dev {
    dev("/carol/phone", "/carol", "k1", 4)
}

fn key_digest(d: &Dev) -> [u8; 32] {
    public_key_digest(&d.signer.public_key_bytes())
}

/// A signed packet.
#[derive(Clone)]
struct Packet {
    dev: Dev,
    name: Name,
    wire: Bytes,
}

impl Packet {
    /// The name the owner of the space re-admits it by: with its implicit
    /// digest.
    fn full(&self) -> Name {
        self.name
            .clone()
            .append_implicit_digest(implicit_digest(&self.wire))
    }
}

/// A device's chain in one space.
struct Chain {
    dev: Dev,
    space: Name,
    last: Option<(u64, [u8; 32])>,
}

impl Chain {
    fn new(dev: Dev, space: Name) -> Chain {
        Chain {
            dev,
            space,
            last: None,
        }
    }

    fn sign(&mut self, seq: u64, content: &[u8]) -> Packet {
        let name = log_name(&self.dev.name, &self.space, seq);
        let wire = seal::sign(DataBuilder::new(name.clone(), content), &*self.dev.signer).unwrap();
        let digest = signed_digest(&wire);
        self.last = Some((seq, digest));
        Packet {
            dev: self.dev.clone(),
            name,
            wire,
        }
    }

    /// An entry at `seq`, chained to the last (a gap is declared when seqs
    /// lie between).
    fn entry_at(&mut self, seq: u64, body: Body) -> Packet {
        let prev = self.last.map(|(from, digest)| Prev {
            digest,
            seq: (from + 1 != seq).then_some(from),
        });
        let entry = Entry {
            prev,
            after: vec![],
            body,
        };
        self.sign(seq, &entry.encode().unwrap())
    }

    fn next(&self) -> u64 {
        self.last.map_or(1, |(seq, _)| seq + 1)
    }

    fn put(&mut self, path: &str, bytes: &str) -> Packet {
        self.put_at(self.next(), path, bytes)
    }

    fn put_at(&mut self, seq: u64, path: &str, bytes: &str) -> Packet {
        self.entry_at(
            seq,
            Body::Put(PutBody {
                path: n(path),
                payload: Payload::Inline(Bytes::from(bytes.to_owned())),
            }),
        )
    }

    /// A packet that verifies and does not decode as an entry.
    fn unreadable(&mut self) -> Packet {
        let seq = self.next();
        self.sign(seq, b"not an entry")
    }
}

/// One space as this node (Carol's) holds it.
fn open(store: &Arc<CrashStore>, space: &Name) -> Log {
    let raw = Arc::clone(store) as Arc<dyn DataStore>;
    let me = carol();
    Log::open(
        Params {
            space: space.clone(),
            device: me.name.clone(),
            person: me.person.clone(),
            signer: Arc::clone(&me.signer) as Arc<dyn Signer>,
            keys: Keys::new(RecipientKey::generate()),
            block: 8,
        },
        Arc::clone(&raw),
        Stage::new(Arc::clone(&raw)),
        Flusher::spawn(raw),
    )
    .unwrap()
}

/// Offer `p` to `log` as the judge would have verified it, first seen at
/// `now`; `digest` overrides the public key digest the judge names.
fn admit_as(log: &mut Log, p: &Packet, digest: Option<[u8; 32]>, now: u64) -> Outcome {
    let data = Data::decode(p.wire.clone()).unwrap();
    let v = Verified {
        key: p.dev.key.clone(),
        device: p.dev.name.clone(),
        person: p.dev.person.clone(),
        key_digest: digest.unwrap_or_else(|| key_digest(&p.dev)),
    };
    log.admit(&p.wire, &data, &v, now).outcome
}

fn applied(log: &mut Log, p: &Packet, now: u64) {
    assert_eq!(admit_as(log, p, None, now), Outcome::Applied);
}

/// Alice creates `space` (public) listing `writers`.
fn found(store: &Arc<CrashStore>, space: &Name, writers: &[&str]) -> Log {
    let mut log = open(store, space);
    let ops = writers
        .iter()
        .zip(1u8..)
        .map(|(who, id)| Op::Add {
            id: [id; 16],
            who: n(who),
            role: Role::Writer,
            epoch: None,
        })
        .collect();
    let creation = Chain::new(alice(), space.clone()).entry_at(
        1,
        Body::Members(MembersBody {
            create: Some(true),
            ops,
        }),
    );
    applied(&mut log, &creation, 0);
    log
}

/// What a cut over Bob's logs of `space` names: the prefix without its seq.
fn prefix(space: &Name) -> Name {
    let entry = log_name(&bob().name, space, 0);
    Name::from_components(entry.components()[..entry.len() - 1].iter().cloned())
}

fn authority() -> CutAuthority {
    CutAuthority {
        namespace: n("/bob"),
        certified: BTreeSet::new(),
    }
}

fn lost_at(t: u64) -> CutBound {
    CutBound {
        held_before: Some(Timestamp(t)),
        ..CutBound::default()
    }
}

fn expected(key: &Dev, seqs: &[(&Name, &[u64])]) -> RevocationCut {
    let mut cut = RevocationCut::new(key.key.clone());
    for (space, seqs) in seqs {
        for seq in *seqs {
            cut.add_seq(&prefix(space), *seq);
        }
    }
    cut
}

fn refusal(r: Result<CutProposal, HeapError>) -> String {
    match r {
        Err(e @ HeapError::BadRequest { .. }) => {
            assert_eq!(e.next(), NextStep::FixRequest, "{e}");
            e.to_string()
        }
        other => panic!("not a refused request: {other:?}"),
    }
}

// -- What a cut keeps ----------------------------------------------------------------

/// Held verified, applied or still sealed, of this key only: a seq only a
/// notice named is not held, an entry another key of the device signed is not
/// the key's, and an entry refused for what it carries is neither kept nor
/// listed.
#[tokio::test]
async fn a_cut_keeps_exactly_what_the_device_holds_verified() {
    let store = Arc::new(CrashStore::new());
    let mut a = found(&store, &notes(), &["/bob"]);
    let mut b = found(&store, &photos(), &["/bob"]);
    let mut c = found(&store, &diary(), &[]);

    let mut in_notes = Chain::new(bob(), notes());
    applied(&mut a, &in_notes.put("/a", "1"), 1_000);
    applied(&mut a, &in_notes.put("/b", "2"), 1_000);
    applied(&mut a, &in_notes.put_at(4, "/c", "4"), 1_000);
    a.note_high(&bob().name, 6);
    // A second key of the same device signed seq 5.
    in_notes.dev = bob_k2();
    let by_k2 = in_notes.put_at(5, "/d", "5");
    applied(&mut a, &by_k2, 1_000);
    applied(&mut b, &Chain::new(bob(), photos()).put("/p", "3"), 1_000);
    // The diary does not list Bob: refused as it arrives, kept as refused.
    let refused = Chain::new(bob(), diary()).put("/x", "5");
    assert_eq!(
        admit_as(&mut c, &refused, None, 1_000),
        Outcome::Refused(Refusal::NotMember)
    );

    let logs = [&a, &b, &c];
    let proposal = propose(&logs, &authority(), &bob().key, &lost_at(2_000)).unwrap();
    let want = expected(&bob(), &[(&notes(), &[1, 2, 4]), (&photos(), &[1])]);
    assert_eq!(proposal.cut.ranges(), want.ranges());
    assert!(proposal.left_out.is_empty(), "{:?}", proposal.left_out);
    assert_eq!(proposal.cut.key_digest(), Some(&key_digest(&bob())));
    assert!(proposal.cut.manifest().is_some() && !proposal.manifest.is_empty());

    // By a certificate name of the key: the same cut.
    let cert_name = bob().key.append("self").append_version(1);
    let by_cert = propose(&logs, &authority(), &cert_name, &lost_at(2_000)).unwrap();
    assert_eq!(by_cert.cut.ranges(), want.ranges());

    // The device's other key: only its own entry.
    let other = propose(&logs, &authority(), &bob_k2().key, &lost_at(2_000)).unwrap();
    assert_eq!(
        other.cut.ranges(),
        expected(&bob_k2(), &[(&notes(), &[5])]).ranges()
    );
    assert_eq!(other.cut.key_digest(), Some(&key_digest(&bob_k2())));

    // No entry and no certificate: no public key to bind.
    let nothing = dev("/bob/tablet", "/bob", "k1", 9);
    assert!(
        refusal(propose(&logs, &authority(), &nothing.key, &lost_at(2_000))).contains("public")
    );
    // Neither bound given: say when the device was lost.
    assert!(
        refusal(propose(
            &logs,
            &authority(),
            &bob().key,
            &CutBound::default()
        ))
        .contains("held_before")
    );
    // Not a key name.
    refusal(propose(
        &logs,
        &authority(),
        &n("/bob/phone"),
        &lost_at(2_000),
    ));
}

/// The bound is this node's own observation: what it first verified at or
/// after the loss, or above the last seq the owner gives, is left out and
/// listed by its full name, however it dates itself.
#[tokio::test]
async fn a_thiefs_entry_first_verified_after_the_loss_is_left_out() {
    let store = Arc::new(CrashStore::new());
    let mut log = found(&store, &notes(), &["/bob"]);
    let mut chain = Chain::new(bob(), notes());
    let first = chain.put("/a", "1");
    let second = chain.put("/b", "2");
    let at_the_loss = chain.put("/c", "3");
    let after = chain.put("/d", "4");
    applied(&mut log, &first, 1_000);
    applied(&mut log, &second, 1_999);
    applied(&mut log, &at_the_loss, 2_000);
    applied(&mut log, &after, 3_000);

    let proposal = propose(&[&log], &authority(), &bob().key, &lost_at(2_000)).unwrap();
    assert_eq!(
        proposal.cut.ranges(),
        expected(&bob(), &[(&notes(), &[1, 2])]).ranges(),
        "strictly before the loss"
    );
    let mut listed = vec![at_the_loss.full(), after.full()];
    listed.sort();
    assert_eq!(proposal.left_out, listed, "listed, to re-admit one by one");

    // Bounded by seq instead: the same cut and the same list.
    let upto = CutBound {
        upto: [(notes(), 2)].into_iter().collect(),
        ..CutBound::default()
    };
    let by_seq = propose(&[&log], &authority(), &bob().key, &upto).unwrap();
    assert_eq!(by_seq.cut.ranges(), proposal.cut.ranges());
    assert_eq!(by_seq.left_out, listed);

    // A space the bound does not name keeps nothing.
    let elsewhere = CutBound {
        upto: [(photos(), 9)].into_iter().collect(),
        ..CutBound::default()
    };
    let none = propose(&[&log], &authority(), &bob().key, &elsewhere);
    assert!(refusal(none).contains("public"), "nothing kept, no digest");
}

/// An entry that verified and does not decode is left out and listed, never
/// kept: the owner may re-admit it by its name and digest.
#[tokio::test]
async fn an_unreadable_entry_is_left_out_and_listed() {
    let store = Arc::new(CrashStore::new());
    let mut log = found(&store, &notes(), &["/bob"]);
    let mut chain = Chain::new(bob(), notes());
    let one = chain.put("/a", "1");
    let garbage = chain.unreadable();
    let three = chain.put("/c", "3");
    applied(&mut log, &one, 1_000);
    assert_eq!(
        admit_as(&mut log, &garbage, None, 1_000),
        Outcome::Unreadable
    );
    applied(&mut log, &three, 1_000);

    let proposal = propose(&[&log], &authority(), &bob().key, &lost_at(2_000)).unwrap();
    assert_eq!(
        proposal.cut.ranges(),
        expected(&bob(), &[(&notes(), &[1, 3])]).ranges()
    );
    assert_eq!(proposal.left_out, vec![garbage.full()]);
}

/// An entry withdrawn because the key's revocation does not accept it is not
/// kept by a later cut, and `refused_by_revocation` lists it, by the key.
#[tokio::test]
async fn what_a_revocation_refused_is_listed_and_not_kept() {
    let store = Arc::new(CrashStore::new());
    let mut log = found(&store, &notes(), &["/bob"]);
    let mut chain = Chain::new(bob(), notes());
    let one = chain.put("/a", "1");
    let two = chain.put("/b", "2");
    applied(&mut log, &one, 1_000);
    applied(&mut log, &two, 1_000);
    let fx = log.withdraw(
        &bob().name,
        2,
        Refusal::OutsideCut(Cut {
            device: bob().name,
            keeps_to: 1,
        }),
    );
    assert!(!fx.changes.is_empty(), "the register moved");

    assert_eq!(refused_by_revocation(&[&log], &bob().key), vec![two.full()]);
    assert!(refused_by_revocation(&[&log], &bob_k2().key).is_empty());
    let proposal = propose(&[&log], &authority(), &bob().key, &lost_at(2_000)).unwrap();
    assert_eq!(
        proposal.cut.ranges(),
        expected(&bob(), &[(&notes(), &[1])]).ranges()
    );
    assert!(proposal.left_out.is_empty());
}

// -- What a cut binds ----------------------------------------------------------------

/// The digest the cut names is the one the marker kept when the entry was
/// verified: nothing is verified again. Here the judge named a digest no
/// signature of these entries has (and the authority holds another), and the
/// cut still carries the marker's: a second verification could not produce it.
#[tokio::test]
async fn the_cut_binds_the_digest_of_the_key_that_verified_each_entry_without_a_second_verification()
 {
    let store = Arc::new(CrashStore::new());
    let mut log = found(&store, &notes(), &["/bob"]);
    let mut chain = Chain::new(bob(), notes());
    let marked = [7u8; 32];
    for (i, path) in ["/a", "/b"].into_iter().enumerate() {
        let p = chain.put(path, "x");
        assert_eq!(
            admit_as(&mut log, &p, Some(marked), 1_000 + i as u64),
            Outcome::Applied
        );
    }
    assert_ne!(marked, key_digest(&bob()));
    let certified = CutAuthority {
        namespace: n("/bob"),
        certified: [[1u8; 32]].into_iter().collect(),
    };
    let proposal = propose(&[&log], &certified, &bob().key, &lost_at(2_000)).unwrap();
    assert_eq!(proposal.cut.key_digest(), Some(&marked));

    // With nothing kept, the one public key the authority holds of the key.
    let nothing = propose(&[&log], &certified, &bob().key, &lost_at(500)).unwrap();
    assert_eq!(nothing.cut.key_digest(), Some(&[1u8; 32]));
    assert!(nothing.manifest.is_empty() && nothing.cut.manifest().is_none());
    assert_eq!(nothing.left_out.len(), 2);
    // Two public keys certified and none verified an entry kept: refused.
    let two = CutAuthority {
        namespace: n("/bob"),
        certified: [[1u8; 32], [2u8; 32]].into_iter().collect(),
    };
    refusal(propose(&[&log], &two, &bob().key, &lost_at(500)));
}

/// Entries kept that were verified under two public keys leave a cut unable
/// to say which wrote the honest work: refused, with what to do. Entries the
/// bound leaves out do not count.
#[tokio::test]
async fn a_cut_refuses_when_the_kept_entries_were_verified_under_more_than_two_keys() {
    let store = Arc::new(CrashStore::new());
    let mut log = found(&store, &notes(), &["/bob"]);
    let mut chain = Chain::new(bob(), notes());
    applied(&mut log, &chain.put("/a", "1"), 1_000);
    let under_other = chain.put("/b", "2");
    assert_eq!(
        admit_as(&mut log, &under_other, Some([9; 32]), 3_000),
        Outcome::Applied
    );

    let why = refusal(propose(&[&log], &authority(), &bob().key, &lost_at(4_000)));
    assert!(why.contains("two different public keys"), "{why}");
    // The second one first verified after the loss: not kept, so one key.
    let ok = propose(&[&log], &authority(), &bob().key, &lost_at(2_000)).unwrap();
    assert_eq!(ok.cut.key_digest(), Some(&key_digest(&bob())));
    assert_eq!(ok.left_out, vec![under_other.full()]);
}

/// The names a cut lists are log names `<D>/32=log/<S>`: `ndn-cert` accepts
/// them as they are (the root's checks), the cut file carries the bound with
/// a space as its collection and decodes again, and its manifest is whole.
#[tokio::test]
async fn the_cut_names_satisfy_check_cut_names() {
    let store = Arc::new(CrashStore::new());
    let mut a = found(&store, &notes(), &["/bob"]);
    let mut b = found(&store, &photos(), &["/bob"]);
    let mut c1 = Chain::new(bob(), notes());
    let mut c2 = Chain::new(bob(), photos());
    applied(&mut a, &c1.put("/a", "1"), 1_000);
    applied(&mut a, &c1.put("/b", "2"), 1_000);
    applied(&mut b, &c2.put("/p", "1"), 1_000);
    let late = c1.put("/c", "3");
    applied(&mut a, &late, 3_000);

    let bound = CutBound {
        held_before: Some(Timestamp(2_000)),
        upto: [(notes(), 9), (photos(), 9)].into_iter().collect(),
    };
    let proposal = propose(&[&a, &b], &authority(), &bob().key, &bound).unwrap();
    assert_eq!(proposal.cut.ranges().len(), 2);
    for range in proposal.cut.ranges() {
        assert!(
            range
                .prefix
                .has_prefix(&ndn_cert::device_log_of(&bob().key))
        );
    }

    let ctx = SignedTrustContext::hierarchical(n("/bob"));
    ndn_cert::check_cut(&ctx, &[bob().key], &proposal.cut).unwrap();

    let file = ndn_cert::CutFile {
        cut: proposal.cut.clone(),
        held_before: bound.held_before.map(|t| t.0),
        upto: bound.upto.clone(),
        left_out: proposal.left_out.clone(),
        manifest: proposal.manifest.clone(),
    };
    assert_eq!(file.left_out, vec![late.full()]);
    file.check_manifest().unwrap();
    file.check_bound(2_500).unwrap();
    let decoded = ndn_cert::CutFile::decode(&file.encode()).unwrap();
    assert_eq!(decoded, file);
}

// -- The node's authority -------------------------------------------------------------

/// A certificate of Bob's phone's first key, issued by the key itself.
async fn bob_cert() -> Certificate {
    let subject = bob().signer;
    let wire = ndn_security::manager::encode_cert_data(
        &subject.key_name().clone().append("self").append_version(1),
        &subject.public_key_bytes(),
        &*subject,
        1_000_000_000_000_000_000,
        u64::MAX,
    )
    .await
    .unwrap();
    Certificate::decode(&Data::decode(wire).unwrap()).unwrap()
}

fn judge_over(ctx: SignedTrustContext, certs: Vec<Certificate>) -> Arc<Judge> {
    let keyring = Arc::new(Keyring::new());
    keyring.adopt(Arc::new(ctx)).unwrap();
    let cache = Arc::new(CertCache::new());
    for cert in certs {
        cache.insert(cert);
    }
    let validator = Arc::new(Validator::with_keyring(keyring, cache, None, 5));
    Judge::new(
        validator,
        Arc::new(MemoryStore::new()) as Arc<dyn DataStore>,
        None,
    )
}

/// The cut is made in the namespace of the context this node holds for the
/// key, bound (when nothing kept names it) to the public key the node holds a
/// certificate of; a key no held context governs cannot be cut; the manifest
/// made is held by the validator so the node judges by the cut at once; and a
/// held revocation of the key is what ends a suspicion.
#[tokio::test]
async fn the_authority_is_the_context_the_node_holds_for_the_key() {
    let cert = bob_cert().await;
    let judge = judge_over(
        SignedTrustContext::hierarchical(n("/bob")),
        vec![cert.clone()],
    );
    let held = cut_authority(&judge, &bob().key).unwrap();
    assert_eq!(held.namespace, n("/bob"));
    assert_eq!(held.certified, [key_digest(&bob())].into_iter().collect());
    let outside = cut_authority(&judge, &n("/zed/phone/KEY/k1"));
    assert!(matches!(outside, Err(HeapError::BadRequest { .. })));
    assert!(matches!(
        cut_authority(&judge, &n("/bob/phone")),
        Err(HeapError::BadRequest { .. })
    ));

    let store = Arc::new(CrashStore::new());
    let mut log = found(&store, &notes(), &["/bob"]);
    applied(&mut log, &Chain::new(bob(), notes()).put("/a", "1"), 1_000);
    let proposal = revocation_cut(&[&log], &judge, &bob().key, &lost_at(2_000)).unwrap();
    let root = proposal.cut.manifest().unwrap();
    assert!(judge.validator().cut_manifests().missing(root).is_empty());

    assert!(!revoked_by(&judge)(&bob().key));
    let revoking = judge_over(
        SignedTrustContext::hierarchical(n("/bob")).with_revocation(bob().key),
        vec![],
    );
    assert!(revoked_by(&revoking)(&bob().key));
    assert!(!revoked_by(&revoking)(&bob_k2().key));
}

// -- Suspicion ------------------------------------------------------------------------

/// A suspected key's new entries are refused (what was held stays served)
/// until a revocation of it is held: then the mark ends and the cut decides.
/// The mark is the node's, over every space it holds.
#[tokio::test]
async fn a_suspected_keys_new_entries_are_not_taken_until_its_revocation() {
    let store = Arc::new(CrashStore::new());
    let mut a = found(&store, &notes(), &["/bob"]);
    let mut b = found(&store, &photos(), &["/bob"]);
    let mut chain = Chain::new(bob(), notes());
    let one = chain.put("/a", "1");
    let two = chain.put("/b", "2");
    applied(&mut a, &one, 1_000);

    suspect(&mut [&mut a, &mut b], &bob().key, Timestamp(2_000)).unwrap();
    assert_eq!(suspected(&[&a, &b], &bob().key), Some(Timestamp(2_000)));
    assert_eq!(
        b.suspected(&bob().key),
        Some(Timestamp(2_000)),
        "every space"
    );
    let refused = admit_as(&mut a, &two, None, 3_000);
    assert!(
        matches!(refused, Outcome::Refused(Refusal::Suspected { .. })),
        "{refused:?}"
    );
    assert!(a.served(&bob().name, 1).is_some(), "what was held stays");
    assert!(a.served(&bob().name, 2).is_none(), "not taken");

    // The bound a cut takes by default: when the key was suspected.
    let lost = CutBound {
        held_before: suspected(&[&a, &b], &bob().key),
        ..CutBound::default()
    };
    let proposal = propose(&[&a, &b], &authority(), &bob().key, &lost).unwrap();
    assert_eq!(
        proposal.cut.ranges(),
        expected(&bob(), &[(&notes(), &[1])]).ranges()
    );

    // No revocation held: the mark stands.
    assert!(lift_revoked(&mut [&mut a, &mut b], |_| false).is_empty());
    assert!(suspected(&[&a, &b], &bob().key).is_some());
    // Its revocation is held: the mark ends everywhere.
    assert_eq!(
        lift_revoked(&mut [&mut a, &mut b], |k| *k == bob().key),
        vec![bob().key]
    );
    assert_eq!(suspected(&[&a, &b], &bob().key), None);
    assert_eq!(b.suspected(&bob().key), None);
    assert_eq!(admit_as(&mut a, &two, None, 4_000), Outcome::Applied);
}

/// `unsuspect` lifts the mark on every space, and says whether there was one;
/// a name that is no key is not marked.
#[tokio::test]
async fn unsuspect_lifts_every_space_and_a_non_key_is_refused() {
    let store = Arc::new(CrashStore::new());
    let mut a = found(&store, &notes(), &["/bob"]);
    let mut b = found(&store, &photos(), &["/bob"]);
    assert!(matches!(
        suspect(&mut [&mut a, &mut b], &n("/bob/phone"), Timestamp(1)),
        Err(HeapError::BadRequest { .. })
    ));
    assert!(!unsuspect(&mut [&mut a, &mut b], &bob().key));
    suspect(&mut [&mut a, &mut b], &bob().key, Timestamp(1)).unwrap();
    assert!(unsuspect(&mut [&mut a, &mut b], &bob().key));
    assert!(a.suspected(&bob().key).is_none() && b.suspected(&bob().key).is_none());
    assert!(!unsuspect(&mut [&mut a, &mut b], &bob().key));
}
