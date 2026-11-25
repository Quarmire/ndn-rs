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
    CertCache, Certificate, EcdsaP256Signer, Ed25519Signer, Keyring, RevocationCut,
    SignedTrustContext, Signer, Validator, public_key_digest,
};
use ndn_sync::{DataStore, MemoryStore};

use super::*;
use crate::error::{Cut, NextStep, Refusal, Timestamp};
use crate::log::{Log, Outcome, Params, Standing};
use crate::reserve::Flusher;
use crate::seal::{self, Keys};
use crate::test_kit::{CrashStore, n};
use crate::trust::{Judge, Judged, Verified};
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
    signer: Arc<dyn Signer>,
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
    public_key_digest(&d.signer.public_key().expect("a public key"))
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

/// One space as this node (Carol's) holds it, marking suspicion in
/// `suspicion`.
fn open_with(suspicion: &Arc<Suspicion>, store: &Arc<CrashStore>, space: &Name) -> Log {
    let raw = Arc::clone(store) as Arc<dyn DataStore>;
    let me = carol();
    Log::open(
        Params {
            space: space.clone(),
            device: me.name.clone(),
            person: me.person.clone(),
            owner_capable: true,
            signer: Arc::clone(&me.signer) as Arc<dyn Signer>,
            keys: Keys::new(RecipientKey::generate()),
            suspicion: Arc::clone(suspicion),
            block: 8,
        },
        Arc::clone(&raw),
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
        owner_capable: true,
        tip: None,
    };
    log.admit(&p.wire, &data, &v, now, false).0
}

fn applied(log: &mut Log, p: &Packet, now: u64) {
    assert_eq!(admit_as(log, p, None, now), Outcome::Applied);
}

/// Alice creates `space` (public) listing `writers`.
fn found(store: &Arc<CrashStore>, space: &Name, writers: &[&str]) -> Log {
    found_with(&suspicion_of(store), store, space, writers)
}

/// A fresh suspicion map over `store`.
fn suspicion_of(store: &Arc<CrashStore>) -> Arc<Suspicion> {
    Suspicion::open(Arc::clone(store) as Arc<dyn DataStore>)
}

fn found_with(
    suspicion: &Arc<Suspicion>,
    store: &Arc<CrashStore>,
    space: &Name,
    writers: &[&str],
) -> Log {
    let mut log = open_with(suspicion, store, space);
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

/// [`super::propose`] with a node that suspects nothing.
fn propose(
    logs: &[&Log],
    authority: &CutAuthority,
    key: &Name,
    bound: &CutBound,
) -> Result<CutProposal, HeapError> {
    super::propose(
        logs,
        &suspicion_of(&Arc::new(CrashStore::new())),
        authority,
        key,
        bound,
    )
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

/// Held verified, applied or still sealed, of this key only: a seq nothing
/// holds is not kept, an entry another key of the device signed is not the
/// key's, and an entry refused for what it carries is neither kept nor
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
    // Seq 3 is a hole: nothing is held there, so a cut cannot keep it.
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
        ..CutBound::default()
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
    let public = subject.public_key().unwrap();
    let wire = ndn_security::manager::encode_cert_data(
        &subject.key_name().clone().append("self").append_version(1),
        &public,
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
    .0
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
    let suspicion = suspicion_of(&store);
    let proposal =
        revocation_cut(&[&log], &judge, &suspicion, &bob().key, &lost_at(2_000)).unwrap();
    let root = proposal.cut.manifest().unwrap();
    assert!(judge.validator.cut_manifests().missing(root).is_empty());

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
    let suspicion = suspicion_of(&store);
    let mut a = found_with(&suspicion, &store, &notes(), &["/bob"]);
    let mut b = found_with(&suspicion, &store, &photos(), &["/bob"]);
    let elsewhere = Chain::new(bob(), photos()).put("/a", "1");
    let mut chain = Chain::new(bob(), notes());
    let one = chain.put("/a", "1");
    let two = chain.put("/b", "2");
    applied(&mut a, &one, 1_000);

    suspicion.mark(&bob().key, Timestamp(2_000)).unwrap();
    assert_eq!(suspicion.since(&bob().key), Some(Timestamp(2_000)));
    let refused = admit_as(&mut a, &two, None, 3_000);
    assert!(
        matches!(refused, Outcome::Refused(Refusal::Suspected { .. })),
        "{refused:?}"
    );
    assert!(
        matches!(
            admit_as(&mut b, &elsewhere, None, 3_000),
            Outcome::Refused(Refusal::Suspected { .. })
        ),
        "every space"
    );
    assert!(a.served(&bob().name, 1).is_some(), "what was held stays");
    assert!(a.served(&bob().name, 2).is_none(), "not taken");

    // The bound a cut takes by default: when the key was suspected.
    let lost = CutBound {
        held_before: suspicion.since(&bob().key),
        ..CutBound::default()
    };
    let proposal = propose(&[&a, &b], &authority(), &bob().key, &lost).unwrap();
    assert_eq!(
        proposal.cut.ranges(),
        expected(&bob(), &[(&notes(), &[1])]).ranges()
    );
    // Without a bound the refusal says since when the key is suspected.
    let why = refusal(super::propose(
        &[&a, &b],
        &suspicion,
        &authority(),
        &bob().key,
        &CutBound::default(),
    ));
    assert!(why.contains("marked suspected here since 2000"), "{why}");

    // No revocation held: the mark stands.
    assert!(suspicion.lift_revoked(|_| false).is_empty());
    assert!(suspicion.since(&bob().key).is_some());
    // Its revocation is held: the mark ends everywhere.
    assert_eq!(suspicion.lift_revoked(|k| *k == bob().key), vec![bob().key]);
    assert_eq!(suspicion.since(&bob().key), None);
    assert_eq!(admit_as(&mut a, &two, None, 4_000), Outcome::Applied);
    assert_eq!(admit_as(&mut b, &elsewhere, None, 4_000), Outcome::Applied);
}

/// `lift` ends the mark, and says whether there was one; a name that is no
/// key is not marked.
#[tokio::test]
async fn unsuspect_lifts_the_mark_and_a_non_key_is_refused() {
    let suspicion = suspicion_of(&Arc::new(CrashStore::new()));
    assert!(matches!(
        suspicion.mark(&n("/bob/phone"), Timestamp(1)),
        Err(HeapError::BadRequest { .. })
    ));
    assert!(!suspicion.lift(&bob().key));
    suspicion.mark(&bob().key, Timestamp(1)).unwrap();
    assert!(suspicion.lift(&bob().key));
    assert!(suspicion.since(&bob().key).is_none());
    assert!(!suspicion.lift(&bob().key));
}

/// Equivocation marks keys on its own, so they are bounded per person
/// (`SUSPECTS_PER_PERSON`): a person who mints keys and forks each one fills her
/// own allowance and no more of the map, other persons' keys are still marked,
/// the host's own `mark` is never refused, and lifting marks makes room again.
#[tokio::test]
async fn automatic_suspicions_are_bounded_per_person() {
    let store = Arc::new(CrashStore::new());
    let suspicion = suspicion_of(&store);
    let bob = n("/bob");
    let key = |i: usize| n(&format!("/bob/phone/KEY/{i}"));
    for i in 0..SUSPECTS_PER_PERSON {
        suspicion.mark_new(&key(i), &bob, Timestamp(1));
        assert!(suspicion.since(&key(i)).is_some(), "key {i} is marked");
    }
    let over = key(SUSPECTS_PER_PERSON);
    suspicion.mark_new(&over, &bob, Timestamp(2));
    assert!(
        suspicion.since(&over).is_none(),
        "past the allowance: not marked"
    );
    assert_eq!(suspicion.keys().len(), SUSPECTS_PER_PERSON);

    let carol = n("/carol/phone/KEY/1");
    suspicion.mark_new(&carol, &n("/carol"), Timestamp(3));
    assert!(suspicion.since(&carol).is_some(), "another person's key");

    suspicion.mark(&over, Timestamp(4)).unwrap();
    assert!(
        suspicion.since(&over).is_some(),
        "the host marks past the allowance"
    );

    // Two marks go (the host's own counts too): there is room for one more.
    assert!(suspicion.lift(&key(0)) && suspicion.lift(&key(1)));
    let fresh = n("/bob/tablet/KEY/1");
    suspicion.mark_new(&fresh, &bob, Timestamp(5));
    assert!(suspicion.since(&fresh).is_some(), "room after a lift");
}

/// A person who mints keys and forks each one is told for every fork (`Evidence`, the
/// equivocation alert), and has `SUSPECTS_PER_PERSON` of the keys marked, no more.
#[tokio::test]
async fn a_burst_of_equivocating_keys_of_one_person_marks_no_more_than_the_allowance() {
    let store = Arc::new(CrashStore::new());
    let suspicion = suspicion_of(&store);
    let mut log = found_with(&suspicion, &store, &notes(), &["/bob"]);
    let forks = SUSPECTS_PER_PERSON + 2;
    for i in 0..forks {
        let device = dev(&format!("/bob/d{i}"), "/bob", "1", 40 + i as u8);
        let first = Chain::new(device.clone(), notes()).put_at(1, "/a", "one");
        let second = Chain::new(device.clone(), notes()).put_at(1, "/a", "two");
        applied(&mut log, &first, 1_000);
        assert_eq!(
            admit_as(&mut log, &second, None, 2_000),
            Outcome::Evidence,
            "fork {i} is told"
        );
        assert_eq!(
            suspicion.since(&device.key).is_some(),
            i < SUSPECTS_PER_PERSON,
            "key {i}"
        );
    }
    assert_eq!(suspicion.keys().len(), SUSPECTS_PER_PERSON);
}

// -- A cut that names tips (spec §9.5) ---------------------------------------------------

fn tips_at(t: u64) -> CutBound {
    CutBound {
        held_before: Some(Timestamp(t)),
        tips: true,
        ..CutBound::default()
    }
}

/// The tips a cut over Bob's logs names: `(space, seq, the entry)` each.
fn expected_tips(key: &Dev, tips: &[(&Name, u64, &Packet)]) -> RevocationCut {
    let mut cut = RevocationCut::new(key.key.clone());
    for (space, seq, p) in tips {
        cut.add_tip(&prefix(space), *seq, signed_digest(&p.wire));
    }
    cut
}

/// Asked for tips, a cut names one tip per space (the highest entry it keeps whose chain below
/// is whole and kept) and no seqs and no manifest: the bytes below a tip are bound by its
/// chain, not by a list of every entry. The manifest form stays the default.
#[tokio::test]
async fn a_revocation_cut_as_tips_names_one_tip_per_space_and_no_manifest() {
    let store = Arc::new(CrashStore::new());
    let mut a = found(&store, &notes(), &["/bob"]);
    let mut b = found(&store, &photos(), &["/bob"]);
    let mut c = found(&store, &diary(), &[]);
    let mut in_notes = Chain::new(bob(), notes());
    applied(&mut a, &in_notes.put("/a", "1"), 1_000);
    applied(&mut a, &in_notes.put("/b", "2"), 1_000);
    // Seq 3 was never signed: the entry at 4 states the gap, which a chain walk follows.
    let top = in_notes.put_at(4, "/c", "4");
    applied(&mut a, &top, 1_000);
    let mut in_photos = Chain::new(bob(), photos());
    applied(&mut b, &in_photos.put("/p", "1"), 1_000);
    let newest = in_photos.put("/q", "2");
    applied(&mut b, &newest, 1_000);
    // The diary does not list Bob: refused as it arrives, neither kept nor listed.
    let refused = Chain::new(bob(), diary()).put("/x", "5");
    assert_eq!(
        admit_as(&mut c, &refused, None, 1_000),
        Outcome::Refused(Refusal::NotMember)
    );

    let logs = [&a, &b, &c];
    let proposal = propose(&logs, &authority(), &bob().key, &tips_at(2_000)).unwrap();
    let want = expected_tips(&bob(), &[(&notes(), 4, &top), (&photos(), 2, &newest)]);
    assert_eq!(proposal.cut.tips(), want.tips());
    assert!(proposal.cut.ranges().is_empty(), "no seqs are listed");
    assert!(
        proposal.cut.manifest().is_none() && proposal.manifest.is_empty(),
        "no manifest is made"
    );
    assert!(proposal.left_out.is_empty(), "{:?}", proposal.left_out);
    assert_eq!(proposal.cut.key_digest(), Some(&key_digest(&bob())));

    // By a certificate name of the key: the same cut.
    let cert_name = bob().key.append("self").append_version(1);
    let by_cert = propose(&logs, &authority(), &cert_name, &tips_at(2_000)).unwrap();
    assert_eq!(by_cert.cut.tips(), want.tips());

    // A bound that keeps nothing names no tip and lists what it leaves out; the key digest is
    // the one public key the authority holds of the key.
    let certified = CutAuthority {
        namespace: n("/bob"),
        certified: [[1u8; 32]].into_iter().collect(),
    };
    let none = propose(&logs, &certified, &bob().key, &tips_at(500)).unwrap();
    assert!(none.cut.tips().is_empty() && none.cut.manifest().is_none());
    assert_eq!(none.cut.key_digest(), Some(&[1u8; 32]));
    assert_eq!(none.left_out.len(), 5);

    // The seq bound caps the tip of each space it names, and a space it leaves out keeps nothing.
    let upto = CutBound {
        upto: [(notes(), 2)].into_iter().collect(),
        tips: true,
        ..CutBound::default()
    };
    let capped = propose(&logs, &authority(), &bob().key, &upto).unwrap();
    assert_eq!(capped.cut.tips().len(), 1);
    assert_eq!(capped.cut.tips()[0].seq, 2);
    assert_eq!(capped.left_out.len(), 3, "{:?}", capped.left_out);

    // Without the switch the cut is the manifest form.
    let manifest = propose(&logs, &authority(), &bob().key, &lost_at(2_000)).unwrap();
    assert!(manifest.cut.tips().is_empty() && manifest.cut.manifest().is_some());
}

/// A kept entry that is not on the chain of the tip (a fork beside the chain, or one whose chain
/// below is not held) is not covered by the tip: it is listed by its full name, for the owner to
/// re-admit one by one, and a space whose chain is not whole has no tip.
#[tokio::test]
async fn entries_off_the_chain_of_the_tip_are_left_out_and_listed() {
    let store = Arc::new(CrashStore::new());
    let mut log = found(&store, &notes(), &["/bob"]);
    let mut chain = Chain::new(bob(), notes());
    let e1 = chain.put("/a", "1");
    let e2 = chain.put("/b", "2");
    let fork = chain.put("/fork", "off the chain");
    // Seq 4 names seq 2 as its predecessor, so seq 3 is on no chain from 4 or above.
    chain.last = Some((2, signed_digest(&e2.wire)));
    let e4 = chain.put_at(4, "/c", "4");
    let e5 = chain.put("/d", "5");
    for p in [&e1, &e2, &fork, &e4, &e5] {
        applied(&mut log, p, 1_000);
    }

    let proposal = propose(&[&log], &authority(), &bob().key, &tips_at(2_000)).unwrap();
    assert_eq!(
        proposal.cut.tips(),
        expected_tips(&bob(), &[(&notes(), 5, &e5)]).tips()
    );
    assert_eq!(proposal.left_out, vec![fork.full()], "listed, to re-admit");

    // Bounded to seq 3, the fork is the highest entry kept and its chain is whole: the tip is
    // there, and what lies above the bound is listed as always.
    let upto = CutBound {
        upto: [(notes(), 3)].into_iter().collect(),
        tips: true,
        ..CutBound::default()
    };
    let capped = propose(&[&log], &authority(), &bob().key, &upto).unwrap();
    assert_eq!(
        capped.cut.tips(),
        expected_tips(&bob(), &[(&notes(), 3, &fork)]).tips()
    );
    let mut above = vec![e4.full(), e5.full()];
    above.sort();
    assert_eq!(capped.left_out, above);

    // A chain with a hole below the entries held has no tip: nothing is kept, all is listed.
    let mut b = found(&store, &photos(), &["/bob"]);
    let mut in_photos = Chain::new(bob(), photos());
    let (_missing, p2, p3) = (
        in_photos.put("/p", "1"),
        in_photos.put("/q", "2"),
        in_photos.put("/r", "3"),
    );
    applied(&mut b, &p2, 1_000);
    applied(&mut b, &p3, 1_000);
    let certified = CutAuthority {
        namespace: n("/bob"),
        certified: [key_digest(&bob())].into_iter().collect(),
    };
    let whole = propose(&[&b], &certified, &bob().key, &tips_at(2_000)).unwrap();
    assert!(whole.cut.tips().is_empty());
    let mut listed = vec![p2.full(), p3.full()];
    listed.sort();
    assert_eq!(whole.left_out, listed);
}

/// A certificate of `subject`'s key issued by `issuer`'s.
async fn issued(subject: &dyn Signer, issuer: &dyn Signer, id: &str) -> Certificate {
    let wire = ndn_security::manager::encode_cert_data(
        &subject.key_name().clone().append(id).append_version(1),
        &subject.public_key().unwrap(),
        issuer,
        1_000_000_000_000_000_000,
        u64::MAX,
    )
    .await
    .unwrap();
    Certificate::decode(&Data::decode(wire).unwrap()).unwrap()
}

/// A judge over the namespace `/bob`, anchored at a root key that certified `dev`'s key; `edit`
/// shapes the context (a revocation and its cut), `manifest` is what the validator holds of it.
async fn judge_for(
    dev: &Dev,
    edit: impl FnOnce(SignedTrustContext) -> SignedTrustContext,
    manifest: &[Bytes],
) -> Arc<Judge> {
    let root = Ed25519Signer::from_seed(&[70; 32], n("/bob/KEY/root"));
    let anchor = issued(&root, &root, "self").await;
    let leaf = issued(&*dev.signer, &root, "root").await;
    let ctx = edit(SignedTrustContext::hierarchical(n("/bob")).with_version(1));
    ctx.anchors().insert(Arc::clone(&anchor.name), anchor);
    let keyring = Arc::new(Keyring::new());
    keyring.adopt(Arc::new(ctx)).unwrap();
    let cache = Arc::new(CertCache::new());
    cache.insert(leaf);
    let validator = Arc::new(Validator::with_keyring(keyring, cache, None, 5));
    for packet in manifest {
        let data = Data::decode(packet.clone()).unwrap();
        validator.cut_manifests().insert(&data).unwrap();
    }
    Judge::new(
        validator,
        Arc::new(MemoryStore::new()) as Arc<dyn DataStore>,
        None,
    )
    .0
}

async fn judged(judge: &Judge, wire: &Bytes, space: &Name) -> Judged {
    judge
        .validate(&Data::decode(wire.clone()).unwrap(), space)
        .await
}

fn valid(judged: Judged) -> Verified {
    match judged {
        Judged::Valid(v) => v,
        other => panic!("not valid: {other:?}"),
    }
}

/// L10 closed: a relay's high-S copy of an ECDSA entry has the signed region of the entry and
/// not its implicit digest. A cut that lists implicit digests (the manifest form) does not
/// cover the copy, so the validator refuses it; a cut that names a tip by the signed-region
/// digest covers it, below the tip and at it, and the log takes the copy for the entry the
/// chain names.
#[tokio::test]
async fn a_high_s_copy_of_an_entry_below_the_tip_is_accepted() {
    let ecdsa = Dev {
        name: n("/bob/phone"),
        key: n("/bob/phone/KEY/e1"),
        person: n("/bob"),
        signer: Arc::new(EcdsaP256Signer::from_seed(&[11; 32], n("/bob/phone/KEY/e1")).unwrap()),
    };
    let store = Arc::new(CrashStore::new());
    let mut log = found(&store, &notes(), &["/bob"]);
    let mut chain = Chain::new(ecdsa.clone(), notes());
    let (e1, e2, e3) = (
        chain.put("/a", "1"),
        chain.put("/b", "2"),
        chain.put("/c", "3"),
    );
    for p in [&e1, &e2, &e3] {
        applied(&mut log, p, 1_000);
    }
    let by_manifest = propose(&[&log], &authority(), &ecdsa.key, &lost_at(2_000)).unwrap();
    let by_tip = propose(&[&log], &authority(), &ecdsa.key, &tips_at(2_000)).unwrap();
    assert!(by_manifest.cut.manifest().is_some() && by_tip.cut.tips().len() == 1);

    let (copy2, copy3) = (
        crate::test_kit::other_s_copy(&e2.wire, &*ecdsa.signer),
        crate::test_kit::other_s_copy(&e3.wire, &*ecdsa.signer),
    );
    assert_ne!(implicit_digest(&copy2), implicit_digest(&e2.wire));
    assert_eq!(signed_digest(&copy2), signed_digest(&e2.wire));

    // The manifest lists the implicit digest of the entry: the copy is another packet, refused.
    let (key, cut) = (ecdsa.key.clone(), by_manifest.cut.clone());
    let manifest_judge = judge_for(
        &ecdsa,
        |c| c.with_revocation(key).with_revocation_cut(cut),
        &by_manifest.manifest,
    )
    .await;
    valid(judged(&manifest_judge, &e2.wire, &notes()).await);
    assert!(
        matches!(
            judged(&manifest_judge, &copy2, &notes()).await,
            Judged::Refused(Refusal::OutsideCut(_))
        ),
        "the manifest form refuses a relay's copy of an entry it keeps"
    );

    // The tip names the signed region: the copy is the entry, below the tip and at it, and the
    // verdict tells the log the tip.
    let (key, cut) = (ecdsa.key.clone(), by_tip.cut.clone());
    let tip_judge = judge_for(
        &ecdsa,
        |c| c.with_revocation(key).with_revocation_cut(cut),
        &[],
    )
    .await;
    let below = valid(judged(&tip_judge, &copy2, &notes()).await);
    let at = valid(judged(&tip_judge, &copy3, &notes()).await);
    let tip = crate::trust::TipCut {
        tip: crate::store::Link {
            seq: 3,
            digest: signed_digest(&e3.wire),
        },
        readmitted: vec![],
    };
    assert_eq!(
        (below.tip.as_ref(), at.tip.as_ref()),
        (Some(&tip), Some(&tip))
    );

    // A device that took the copies keeps them as the entries the chain names: the entries
    // above name the signed digest, which a copy shares with the original.
    let other = Arc::new(CrashStore::new());
    let mut late = found(&other, &notes(), &["/bob"]);
    for wire in [&copy3, &copy2, &e1.wire] {
        let data = Data::decode(wire.clone()).unwrap();
        let v = valid(judged(&tip_judge, wire, &notes()).await);
        let (outcome, _) = late.admit(wire, &data, &v, 1_000, false);
        assert_eq!(outcome, Outcome::Applied, "{}", data.name);
    }
    let mut live = 0;
    late.each_held(&ecdsa.name, |held| {
        if held.standing == Standing::Live {
            live += 1;
        }
    });
    assert_eq!(live, 3, "the chain is whole and kept");
}
