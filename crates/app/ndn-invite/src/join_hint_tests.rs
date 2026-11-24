//! The joiner and the hint record of a short code (spec §19.2, §19.3; the cases of the
//! first contact, SHAPES-R10 §2–§4, §7): what a joiner does with an address or a relay
//! as first contact, what it believes of the record it fetches, and what it leaves
//! behind when the record does not verify.
//!
//! An inviter and a joiner are two real devices on one forwarder. The joiner's node
//! face passes through a [`Gate`] that carries its Interests the way a link or a relay
//! would — by the link the host dialled (the test host's `dial_first` / `dial`), by a
//! relay named in the Interest's ForwardingHint, or by name once the host adopted the
//! inviter's namespace — and records, holds back and tampers with what crosses.
//! Nothing of the thing under test is mocked: the mock is the host's link layer, which
//! is not this crate's.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_heap::{NextStep, Timestamp};
use ndn_packet::Data;
use ndn_packet::encode::DataBuilder;
use ndn_tlv::TlvWriter;
use tokio_util::sync::CancellationToken;

use crate::credentials::{Fingerprint, credentials};
use crate::error::InviteError;
use crate::host::{HintCandidate, HintKind, Joined, LinkHint, Offer, Role};
use crate::join_kit::{Gate, kit_config, sign_as};
use crate::policy::{HINT_RETRIES_MAX, IntroPolicy, IntroRefusal};
use crate::proofs::{SECRET_LEN, hint_token, keyed_fingerprint};
use crate::short::{Contact, ShortCode};
use crate::store;
use crate::test_kit::{
    Calls, Device, Net, Person, Setup as Start, alice_offers, n, notebook, skewed, start,
};
use crate::wire::{
    HINT_TOKEN_LEN, HintRecord, IntroRecord, hint_name, parse_hint_name, parse_intro_name,
    parse_offer_name,
};

mod proof;

/// How the rig's inviter is set up.
struct Shape {
    /// Candidate addresses its host gives for a link hint.
    candidates: Vec<&'static str>,
    /// Its namespace advertises the relay `/alice/node/relay`.
    relay: bool,
    /// The inviter's introduction policy.
    policy: IntroPolicy,
    /// The joiner's.
    joiner_policy: IntroPolicy,
}

impl Shape {
    /// An inviter whose host listens at one public IPv4 address.
    fn address() -> Shape {
        Shape {
            candidates: vec!["192.0.2.7:4433"],
            relay: false,
            policy: IntroPolicy::new(),
            joiner_policy: IntroPolicy::new(),
        }
    }

    /// An inviter that listens nowhere a joiner can dial, behind a relay.
    fn relayed() -> Shape {
        Shape {
            candidates: Vec::new(),
            relay: true,
            ..Shape::address()
        }
    }
}

/// How a joiner's Interests reach the inviter's device: the network between them.
struct Paths {
    /// The inviter's device name: the only device this network routes by a link.
    device: Name,
    /// The relay this network models: an Interest whose ForwardingHint names it reaches
    /// the inviter, as a relay forwards what it is asked to.
    relay: Name,
    relay_up: AtomicBool,
    /// Route every name of the inviter, as a joiner's forwarder with a route to it does.
    by_name: AtomicBool,
    /// Lose every Interest for a hint record.
    hint_lost: AtomicBool,
    /// The joiner's host: what its dials made.
    joiner_calls: Arc<Calls>,
    /// Interests the joiner's dialled link carried (whatever else could have).
    over_link: std::sync::Mutex<Vec<Name>>,
    hint_interests: AtomicUsize,
}

impl Paths {
    /// Whether the joiner's Interest `name`, hinted through `hints`, reaches the inviter.
    fn carries(&self, name: &Name, hints: &[Name]) -> bool {
        let calls = &self.joiner_calls;
        if !name.has_prefix(&self.device) {
            // The names of the inviter's namespace go where the host's adoption routed
            // them.
            return calls.adopted() || self.by_name.load(Ordering::SeqCst);
        }
        if parse_hint_name(name).is_some() {
            self.hint_interests.fetch_add(1, Ordering::SeqCst);
            if self.hint_lost.load(Ordering::SeqCst) {
                return false;
            }
        }
        let via_relay = self.relay_up.load(Ordering::SeqCst) && hints.contains(&self.relay);
        let linked = calls.linked()
            && (calls.adopted()
                || crate::wire::introduction_prefixes(&self.device)
                    .iter()
                    .any(|p| name.has_prefix(p)));
        if linked {
            self.over_link.lock().unwrap().push(name.clone());
        }
        via_relay || linked || calls.adopted() || self.by_name.load(Ordering::SeqCst)
    }
}

/// Alice's laptop and Bob's phone on one forwarder, an offer of Alice's notebook made.
struct Rig {
    laptop: Device,
    alice: Person,
    inviter_calls: Arc<Calls>,
    skew: Arc<std::sync::atomic::AtomicU64>,
    paths: Arc<Paths>,
    gate: Arc<Gate>,
    phone: Device,
    phone_calls: Arc<Calls>,
    code: crate::host::Code,
    secret: [u8; SECRET_LEN],
    folder: Name,
    cancel: CancellationToken,
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl Rig {
    async fn new(shape: Shape) -> Rig {
        let alice = if shape.relay {
            Person::relayed("/alice", "/alice/node/relay")
        } else {
            Person::new("/alice")
        };
        let (clock, skew) = skewed();
        let inviter_calls = Arc::new(Calls::default());
        let phone_calls = Arc::new(Calls::default());
        let net = Net::new().await;
        let cancel = CancellationToken::new();
        let laptop = Start::new(&alice, "/alice/laptop")
            .config(kit_config())
            .clock(clock)
            .calls(Arc::clone(&inviter_calls))
            .policy(shape.policy)
            .on(&net, &cancel)
            .start()
            .await;
        if !shape.candidates.is_empty() {
            *inviter_calls.hint.lock().unwrap() = Some(LinkHint {
                key: laptop.invites.inner().own_key_digest(),
                candidates: shape
                    .candidates
                    .iter()
                    .map(|a| HintCandidate {
                        kind: HintKind::Host,
                        addr: a.parse().unwrap(),
                    })
                    .collect(),
            });
        }
        let offered = alice_offers(laptop, alice, Role::Writer).await;
        let paths = Arc::new(Paths {
            device: n("/alice/laptop"),
            relay: n("/alice/node/relay"),
            relay_up: AtomicBool::new(true),
            by_name: AtomicBool::new(false),
            hint_lost: AtomicBool::new(false),
            joiner_calls: Arc::clone(&phone_calls),
            over_link: std::sync::Mutex::new(Vec::new()),
            hint_interests: AtomicUsize::new(0),
        });
        let gate = Gate::new();
        {
            let paths = Arc::clone(&paths);
            gate.route(move |name, hints| paths.carries(name, hints));
        }
        let bob = Person::new("/bob");
        let phone = {
            let gate = Arc::clone(&gate);
            Start::new(&bob, "/bob/phone")
                .config(kit_config())
                .calls(Arc::clone(&phone_calls))
                .policy(shape.joiner_policy)
                .on(&net, &cancel)
                .wrapping(move |face| gate.wrap(face))
                .start()
                .await
        };
        Rig {
            laptop: offered.laptop,
            alice: offered.alice,
            inviter_calls,
            skew,
            paths,
            gate,
            phone,
            phone_calls,
            code: offered.code,
            secret: offered.secret,
            folder: notebook(),
            cancel,
        }
    }

    /// The key the inviter's link proves: what a first contact answers.
    fn inviter_key(&self) -> [u8; 32] {
        self.laptop.invites.inner().own_key_digest()
    }

    /// The joiner's host dials the inviter's address: the link proves the inviter's key.
    fn first_contact_answers(&self) {
        *self.phone_calls.first_dial.lock().unwrap() = Some(Ok(self.inviter_key()));
    }

    /// The hint Interests the joiner sent.
    fn hint_fetches(&self) -> usize {
        self.paths.hint_interests.load(Ordering::SeqCst)
    }

    /// The Interests the joiner sent.
    fn sent(&self) -> Vec<crate::join_kit::Sent> {
        self.gate.sent()
    }
}

/// Whether `name` is a hint record's.
fn is_hint(name: &Name) -> bool {
    parse_hint_name(name).is_some()
}

/// The hint record's name of a rig's offer.
fn hint_of(rig: &Rig) -> Name {
    let token: [u8; HINT_TOKEN_LEN] = hint_token(&rig.secret);
    hint_name(&rig.laptop.name, &token)
}

/// What the inviter's device serves for `name`, decoded.
fn served(rig: &Rig, name: &Name) -> Option<Data> {
    rig.laptop
        .invites
        .inner()
        .hint_packet(name)
        .map(|wire| Data::decode(wire).unwrap())
}

/// The record a hint Data carries.
fn record_of(data: &Data) -> HintRecord {
    HintRecord::decode(data.content().unwrap().clone(), true).unwrap()
}

/// The anchor fingerprint of Alice's namespace.
fn alice_fingerprint(rig: &Rig) -> [u8; 32] {
    let anchors = rig.alice.ctx.anchors();
    let anchor = anchors.iter().next().expect("an anchor");
    ndn_security::anchor_fingerprint(anchor.value())
}

/// A short code written for `rig`'s inviter: its device, `contact`, `secret` and the
/// `fingerprint` octets, as a person would read them.
fn short_text(
    rig: &Rig,
    contact: Option<Contact>,
    secret: [u8; SECRET_LEN],
    fingerprint: &[u8],
) -> String {
    ShortCode {
        device: rig.laptop.name.clone(),
        contact,
        secret,
        fingerprint: fingerprint.to_vec(),
    }
    .encode()
    .unwrap()
}

/// The inviter's address, as a code's first contact.
fn address() -> Contact {
    Contact::Address("192.0.2.7:4433".parse().unwrap())
}

/// `rig`'s offer as an old link wrote it (TLVs of trust-envelope.md §5.1: an envelope of
/// format 1, kind 7, a body of the namespace, the fingerprint, the offer's name, the
/// secret and the link hint, names in text).
fn old_link(rig: &Rig, with_hint: bool) -> String {
    let hint = LinkHint {
        key: rig.inviter_key(),
        candidates: vec![HintCandidate {
            kind: HintKind::Host,
            addr: "192.0.2.7:4433".parse().unwrap(),
        }],
    };
    let mut body = TlvWriter::new();
    body.write_tlv(0x0489, b"/alice");
    body.write_tlv(0x048E, &alice_fingerprint(rig));
    body.write_tlv(
        0x0475,
        rig.code
            .offer
            .to_string()
            .replace("keyword=", "32=")
            .as_bytes(),
    );
    body.write_tlv(0x0477, &rig.secret);
    if with_hint {
        body.write_tlv(0x0478, &hint.encode());
    }
    let body = body.finish();
    let mut envelope = TlvWriter::new();
    envelope.write_nested(0x0470, |w| {
        w.write_tlv(0x0471, &[1]);
        w.write_tlv(0x0472, &[7]);
        w.write_tlv(0x0473, &body);
    });
    format!("ndn-trust://intro/{}", base64url(&envelope.finish()))
}

/// Unpadded base64url, as a link is written.
fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[(n >> (18 - 6 * i) & 63) as usize]));
        }
    }
    out
}

/// The refusal a hint record's verification gave: its reason.
fn hint_refusal(got: &Result<Joined, InviteError>) -> String {
    match got {
        Err(InviteError::Refused(IntroRefusal::Hint { why })) => why.clone(),
        other => panic!("not refused as a hint that does not verify: {other:?}"),
    }
}

/// The reason of a record that verifies — its signature checks under credentials that
/// open — but is not the code's inviter's: no damage in flight, so `AskOwner`, and no
/// retry.
fn mismatch_refusal(got: &Result<Joined, InviteError>) -> String {
    match got {
        Err(e @ InviteError::Refused(IntroRefusal::HintMismatch { why })) => {
            assert_eq!(e.next(), NextStep::AskOwner, "{e}");
            assert!(!e.retry(), "{e}");
            why.clone()
        }
        other => panic!("not refused as a mismatch of a record that verifies: {other:?}"),
    }
}

/// Whether the inviter holds a use mark for any offer.
fn offer_used(rig: &Rig) -> bool {
    let (_, id) = parse_offer_name(&rig.code.offer).expect("an offer's name");
    rig.laptop.store.get(&store::used_key(&id)).is_some()
}

/// Nothing was dialled, asked or adopted by a join that was refused at the hint record:
/// no dial but the first contact's, which was taken down; no Interest but for the hint;
/// nothing of Alice's namespace held.
fn assert_nothing_went_further(rig: &Rig, first_key: Option<[u8; 32]>) {
    assert!(
        rig.phone_calls.dialled().is_empty(),
        "dialled {:?} on the strength of a record that did not verify",
        rig.phone_calls.dialled()
    );
    let beyond: Vec<Name> = rig.gate.sent_where(|n| !is_hint(n));
    assert!(
        beyond.is_empty(),
        "sent {beyond:?} before the record verified"
    );
    assert!(
        rig.phone.validator.keyring().held(&n("/alice")).is_none(),
        "adopted the inviter's namespace"
    );
    assert_eq!(
        rig.phone_calls.undialled_keys(),
        first_key.into_iter().collect::<Vec<_>>(),
        "the first contact's link was not taken down"
    );
    assert!(!offer_used(rig), "the offer was used");
}

// ---- the joiner: a short code joins over an address and over a relay (§3) ----------------------

/// G4-shaped: a joiner with only the short code joins; its first contact is an address
/// dialled with no key to expect; the hint record is fetched by name over that link; the
/// inviter's key the link proved is the record's, so no second dial is made; every
/// Interest before the namespace is adopted is one the link routes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_joiner_with_only_the_short_code_joins_over_an_address_first_contact() {
    let rig = Rig::new(Shape::address()).await;
    rig.first_contact_answers();
    let short = rig.code.short.clone().unwrap();
    let joined = rig.phone.invites.join(&short).await.expect("joins");
    assert_eq!(joined.space, rig.folder);
    assert_eq!(joined.role, Role::Writer);
    assert_eq!(joined.inviter, n("/alice"));
    assert_eq!(
        rig.phone_calls.first_dialled(),
        vec![(n("/alice/laptop"), "192.0.2.7:4433".parse().unwrap())]
    );
    assert!(
        rig.phone_calls.dialled().is_empty(),
        "dialled again a key the first contact proved: {:?}",
        rig.phone_calls.dialled()
    );
    assert_eq!(rig.hint_fetches(), 1);
    assert!(
        rig.gate.refused().is_empty(),
        "Interests the first link does not carry: {:?}",
        rig.gate.refused()
    );
    assert!(
        rig.phone_calls.undialled().is_empty(),
        "a join that succeeded took its link down"
    );
}

/// G4-shaped: a joiner with only the short code joins by a relay first contact: the hint
/// Interest is routed by its ForwardingHint, and nothing is dialled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_joiner_with_only_the_short_code_joins_over_a_relay_first_contact() {
    let rig = Rig::new(Shape::relayed()).await;
    let short = rig.code.short.clone().unwrap();
    let joined = rig.phone.invites.join(&short).await.expect("joins");
    assert_eq!(joined.space, rig.folder);
    assert!(rig.phone_calls.first_dialled().is_empty());
    let hinted: Vec<_> = rig.sent().into_iter().filter(|(n, _)| is_hint(n)).collect();
    assert!(!hinted.is_empty());
    assert!(
        hinted
            .iter()
            .all(|(_, hints)| hints == &[n("/alice/node/relay")]),
        "the hint Interest did not go by the relay: {hinted:?}"
    );
}

/// A short code that names no first contact is routed by name.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_short_code_with_no_contact_is_routed_by_name() {
    let rig = Rig::new(Shape::address()).await;
    rig.paths.by_name.store(true, Ordering::SeqCst);
    let fp = alice_fingerprint(&rig);
    let text = short_text(&rig, None, rig.secret, &keyed_fingerprint(&rig.secret, &fp));
    let joined = rig.phone.invites.join(&text).await.expect("joins");
    assert_eq!(joined.space, rig.folder);
    assert!(rig.phone_calls.first_dialled().is_empty());
}

// ---- the compact full link and the old forms join with no fetch (§5, case 6) -------------------

/// The compact full link names the key and the addresses: it joins with no hint record
/// fetched.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_compact_full_link_joins_with_no_hint_fetch() {
    let rig = Rig::new(Shape::address()).await;
    rig.phone_calls.dial_succeeds.store(true, Ordering::SeqCst);
    let joined = rig.phone.invites.join(&rig.code.link).await.expect("joins");
    assert_eq!(joined.space, rig.folder);
    assert_eq!(rig.hint_fetches(), 0, "the full link fetched a hint");
    assert_eq!(rig.phone_calls.dialled(), vec![n("/alice/laptop")]);
    assert!(rig.phone_calls.first_dialled().is_empty());
}

/// Today's words form (the offer's name and 24 words) still joins, by name.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_old_words_form_joins_with_no_hint_fetch() {
    let rig = Rig::new(Shape::address()).await;
    rig.paths.by_name.store(true, Ordering::SeqCst);
    let joined = rig
        .phone
        .invites
        .join(&rig.code.words)
        .await
        .expect("joins");
    assert_eq!(joined.space, rig.folder);
    assert_eq!(rig.hint_fetches(), 0);
}

/// A link as every earlier version wrote it: names as text (the namespace, the offer, the
/// relays), the link hint beside, no compact tag. Nothing writes this form any more; it
/// is still read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_old_text_link_still_joins_with_no_hint_fetch() {
    let rig = Rig::new(Shape::address()).await;
    rig.phone_calls.dial_succeeds.store(true, Ordering::SeqCst);
    let link = old_link(&rig, true);
    let joined = rig.phone.invites.join(&link).await.expect("joins");
    assert_eq!(joined.space, rig.folder);
    assert_eq!(rig.hint_fetches(), 0);
    assert_eq!(rig.phone_calls.dialled(), vec![n("/alice/laptop")]);

    // Without a hint, by name.
    let rig = Rig::new(Shape::address()).await;
    rig.paths.by_name.store(true, Ordering::SeqCst);
    let link = old_link(&rig, false);
    let joined = rig.phone.invites.join(&link).await.expect("joins");
    assert_eq!(joined.space, rig.folder);
    assert_eq!(rig.hint_fetches(), 0);
    assert!(rig.phone_calls.dialled().is_empty());
}

// ---- refusals (§4) -----------------------------------------------------------------------------

/// A mistyped word, device or digit is refused before anything is dialled or sent, with
/// the text that says what to check; so are a word off the list and a count no form has.
#[tokio::test]
async fn a_typo_is_refused_with_the_message_before_anything_is_dialled() {
    let rig = Rig::new(Shape::address()).await;
    rig.first_contact_answers();
    let short = rig.code.short.clone().unwrap();
    let tokens: Vec<&str> = short.split_whitespace().collect();
    let swapped = |at: usize, with: &str| {
        let mut t = tokens.clone();
        t[at] = with;
        t.join(" ")
    };
    let other = if tokens[2] == "abandon" {
        "ability"
    } else {
        "abandon"
    };
    let cases = [
        (swapped(2, other), "does not read"),
        (swapped(1, "192.0.2.7:4434"), "does not read"),
        (swapped(0, "/alice/laptoq"), "does not read"),
        (swapped(5, "zzzzzz"), "word 4 is not a BIP39 English word"),
        (tokens[..tokens.len() - 1].join(" "), "19 words"),
    ];
    for (code, says) in cases {
        let got = rig.phone.invites.join(&code).await;
        match &got {
            Err(e @ InviteError::BadRequest { why }) => {
                assert!(why.contains(says), "{says:?} is not in {why:?}");
                assert_eq!(e.next(), NextStep::FixRequest);
            }
            other => panic!("{code:?} was not a bad request: {other:?}"),
        }
    }
    assert!(
        rig.phone_calls.first_dialled().is_empty(),
        "dialled for a typo"
    );
    assert!(rig.sent().is_empty(), "sent for a typo");
}

/// A loopback first contact is refused unless the joiner's policy allows it.
#[tokio::test]
async fn a_loopback_first_contact_is_refused_unless_the_joiners_policy_allows_it() {
    let rig = Rig::new(Shape::address()).await;
    let fp = alice_fingerprint(&rig);
    let text = short_text(
        &rig,
        Some(Contact::Address("127.0.0.1:4433".parse().unwrap())),
        rig.secret,
        &keyed_fingerprint(&rig.secret, &fp),
    );
    let got = rig.phone.invites.join(&text).await;
    assert!(
        matches!(&got, Err(InviteError::BadRequest { why }) if why.contains("local_candidates")),
        "{got:?}"
    );
    assert!(rig.phone_calls.first_dialled().is_empty());

    let allowed = Rig::new(Shape {
        joiner_policy: IntroPolicy {
            local_candidates: true,
            ..IntroPolicy::new()
        },
        ..Shape::address()
    })
    .await;
    let fp = alice_fingerprint(&allowed);
    let text = short_text(
        &allowed,
        Some(Contact::Address("127.0.0.1:4433".parse().unwrap())),
        allowed.secret,
        &keyed_fingerprint(&allowed.secret, &fp),
    );
    let _ = allowed.phone.invites.join(&text).await;
    assert_eq!(
        allowed.phone_calls.first_dialled().len(),
        1,
        "the policy did not allow it"
    );
}

/// A first contact that does not answer the dial is `NotReady`, saying so.
#[tokio::test]
async fn a_first_contact_that_does_not_answer_is_not_ready() {
    let rig = Rig::new(Shape::address()).await;
    *rig.phone_calls.first_dial.lock().unwrap() = Some(Err("connection refused".into()));
    let got = rig.phone.invites.join(rig.code.share()).await;
    let Err(e @ InviteError::NotReady { why, .. }) = &got else {
        panic!("not NotReady: {got:?}");
    };
    assert!(why.contains("192.0.2.7:4433"));
    assert!(why.contains("did not answer"));
    assert!(why.contains("connection refused"));
    assert!(why.contains("retry"));
    assert_eq!(e.next(), NextStep::RetryLater);
    assert!(rig.sent().is_empty());
}

/// A joiner that cannot fetch the record in its tries — lost, or an unknown token that is
/// not answered — is `NotReady` with the text that lists why; its first contact's link is
/// taken down.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_joiner_that_cannot_fetch_the_hint_is_not_ready() {
    let rig = Rig::new(Shape::address()).await;
    rig.first_contact_answers();
    rig.paths.hint_lost.store(true, Ordering::SeqCst);
    let got = rig.phone.invites.join(rig.code.share()).await;
    let Err(e @ InviteError::NotReady { why, .. }) = &got else {
        panic!("not NotReady: {got:?}");
    };
    for says in [
        "hint for this offer was not fetched",
        "offline",
        "wrong address or relay",
        "closed",
        "retry",
        "ask for a new code",
    ] {
        assert!(why.contains(says), "{says:?} is not in {why:?}");
    }
    assert_eq!(e.next(), NextStep::RetryLater);
    assert_eq!(rig.hint_fetches(), 8, "as often as the offer is fetched");
    assert_eq!(rig.phone_calls.undialled_keys(), vec![rig.inviter_key()]);

    // A token the inviter does not hold is not answered either.
    let rig = Rig::new(Shape::address()).await;
    rig.first_contact_answers();
    let fp = alice_fingerprint(&rig);
    let text = short_text(
        &rig,
        Some(address()),
        [0x77; 16],
        &keyed_fingerprint(&[0x77; 16], &fp),
    );
    let got = rig.phone.invites.join(&text).await;
    assert!(matches!(got, Err(InviteError::NotReady { .. })), "{got:?}");
    assert!(!offer_used(&rig));
}

/// A closed offer's record is the gone mark: the join is refused as closed, the first
/// contact's link taken down, nothing asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_closed_offer_is_a_gone_mark_and_the_join_is_refused_as_closed() {
    let rig = Rig::new(Shape::address()).await;
    rig.first_contact_answers();
    rig.laptop
        .invites
        .close_offer(&rig.code.offer)
        .await
        .unwrap();
    let got = rig.phone.invites.join(rig.code.share()).await;
    let Err(e @ InviteError::Refused(why)) = &got else {
        panic!("not a refusal: {got:?}");
    };
    assert_eq!(*why, IntroRefusal::Closed);
    assert_eq!(e.next(), NextStep::AskOwner);
    assert_nothing_went_further(&rig, Some(rig.inviter_key()));
}

/// An expired offer's record is the gone mark: refused as expired.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_expired_offer_is_a_gone_mark_and_the_join_is_refused_as_expired() {
    let rig = Rig::new(Shape::address()).await;
    rig.first_contact_answers();
    rig.skew.store(2 * 3_600_000, Ordering::SeqCst);
    let got = rig.phone.invites.join(rig.code.share()).await;
    assert!(
        matches!(&got, Err(InviteError::Refused(IntroRefusal::Expired))),
        "{got:?}"
    );
    assert_nothing_went_further(&rig, Some(rig.inviter_key()));
}

/// With `hint_while_open` off the record outlives the offer, and the join then meets the
/// offer's own refusal: the record joins no one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hint_that_outlives_its_offer_joins_no_one() {
    let rig = Rig::new(Shape {
        policy: IntroPolicy {
            hint_while_open: false,
            ..IntroPolicy::new()
        },
        ..Shape::address()
    })
    .await;
    rig.first_contact_answers();
    rig.laptop
        .invites
        .close_offer(&rig.code.offer)
        .await
        .unwrap();
    let got = rig.phone.invites.join(rig.code.share()).await;
    assert!(
        matches!(&got, Err(InviteError::Refused(IntroRefusal::Closed))),
        "{got:?}"
    );
    assert!(!offer_used(&rig));
    assert_eq!(rig.phone_calls.undialled_keys(), vec![rig.inviter_key()]);
}

/// A code whose fingerprint is not the anchor the record's credentials carry is refused:
/// whoever answers cannot make its own anchor the code's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_code_of_another_anchor_is_refused_by_the_record() {
    let rig = Rig::new(Shape::address()).await;
    rig.first_contact_answers();
    let text = short_text(&rig, Some(address()), rig.secret, &[0x42; 10]);
    let got = rig.phone.invites.join(&text).await;
    let why = mismatch_refusal(&got);
    assert!(why.starts_with("anchor"), "{why}");
    assert_nothing_went_further(&rig, Some(rig.inviter_key()));
}

/// What a tampering reads of the rig: the inviter's key, the offer, and Alice's signed
/// trust context as the record carries it.
struct Parts {
    key: [u8; 32],
    offer: Name,
    context: Bytes,
}

/// A joiner over an address is given the inviter's hint record with `flip` applied to its
/// wire (the packet, the range of its signature value and the bytes to edit): the
/// refusal's reason, the rig, after checking the refusal says what to do and that nothing
/// was dialled, asked or adopted.
async fn tampered(
    flip: impl Fn(&Parts, &Data, std::ops::Range<usize>, &mut Vec<u8>) + Send + Sync + 'static,
) -> (Rig, String) {
    let rig = Rig::new(Shape::address()).await;
    rig.first_contact_answers();
    let parts = Parts {
        key: rig.inviter_key(),
        offer: rig.code.offer.clone(),
        context: rig.alice.signed.clone(),
    };
    rig.gate.tamper(move |wire| {
        let Ok(data) = Data::decode(wire.clone()) else {
            return Some(wire);
        };
        if !is_hint(&data.name) {
            return Some(wire);
        }
        let sig = data.sig_value();
        let at = sig.as_ptr() as usize - wire.as_ptr() as usize;
        let mut v = wire.to_vec();
        flip(&parts, &data, at..at + sig.len(), &mut v);
        Some(Bytes::from(v))
    });
    let got = rig.phone.invites.join(rig.code.share()).await;
    let why = hint_refusal(&got);
    let err = got.unwrap_err();
    assert_eq!(
        err.next(),
        NextStep::RetryLater,
        "a record corrupted in flight is a retry, as a corrupted answer is"
    );
    let shown = err.to_string();
    for says in [
        "retry",
        "do not use this code's first contact",
        "ask the inviter for a new code",
        "copied whole",
    ] {
        assert!(
            shown.contains(says),
            "the refusal does not say {says:?}: {shown}"
        );
    }
    assert_nothing_went_further(&rig, Some(rig.inviter_key()));
    (rig, why)
}

/// The offset of `needle` in `hay`.
fn find(hay: &[u8], needle: &[u8]) -> usize {
    hay.windows(needle.len())
        .position(|w| w == needle)
        .expect("the part is in the packet")
}

/// The packet's last signature octet flipped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_record_with_a_flipped_signature_byte_is_refused() {
    let (_, why) = tampered(|_, _, sig, v| v[sig.end - 1] ^= 1).await;
    assert!(why.starts_with("signer"), "{why}");
}

/// The link key flipped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_record_with_a_flipped_key_byte_is_refused() {
    let (_, why) = tampered(|p, _, _, v| {
        let at = find(v, &p.key) + 7;
        v[at] ^= 1;
    })
    .await;
    assert!(why.starts_with("signer"), "{why}");
}

/// A candidate's port flipped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_record_with_a_flipped_candidate_byte_is_refused() {
    let (_, why) = tampered(|_, _, _, v| {
        let at = find(v, &[0, 192, 0, 2, 7, 0x11, 0x51]) + 6;
        v[at] ^= 1;
    })
    .await;
    assert!(why.starts_with("signer"), "{why}");
}

/// The offer's name flipped: the last octet of its id.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_record_with_a_flipped_offer_name_byte_is_refused() {
    let (_, why) = tampered(|p, _, _, v| {
        let name = p.offer.encode_to_tlv();
        let at = find(v, &name) + name.len() - 1;
        v[at] ^= 1;
    })
    .await;
    assert!(why.starts_with("signer"), "{why}");
}

/// The credentials flipped: the last octet of the trust context's signature.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_record_with_flipped_credentials_is_refused() {
    let (_, why) = tampered(|p, _, _, v| {
        let at = find(v, &p.context) + p.context.len() - 1;
        v[at] ^= 1;
    })
    .await;
    assert!(why.starts_with("credentials"), "{why}");
}

/// A record corrupted in flight is the same cause as a corrupted answer (`Forged`,
/// retry): the first join is refused as a hint that does not verify and told to retry,
/// nothing dialled further, and the host's retry — the record now intact — joins.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_record_corrupted_once_joins_on_the_hosts_retry() {
    let rig = Rig::new(Shape::address()).await;
    rig.first_contact_answers();
    let corrupt = Arc::new(AtomicBool::new(true));
    let flag = Arc::clone(&corrupt);
    rig.gate.tamper(move |wire| {
        let Ok(data) = Data::decode(wire.clone()) else {
            return Some(wire);
        };
        if !is_hint(&data.name) || !flag.swap(false, Ordering::SeqCst) {
            return Some(wire);
        }
        let sig = data.sig_value();
        let at = sig.as_ptr() as usize - wire.as_ptr() as usize + sig.len() - 1;
        let mut v = wire.to_vec();
        v[at] ^= 1;
        Some(Bytes::from(v))
    });
    let got = rig.phone.invites.join(rig.code.share()).await;
    let why = hint_refusal(&got);
    assert!(why.starts_with("signer"), "{why}");
    assert_eq!(
        got.unwrap_err().next(),
        NextStep::RetryLater,
        "a record corrupted in flight is a retry, as a corrupted answer is"
    );
    assert_nothing_went_further(&rig, Some(rig.inviter_key()));
    let joined = rig
        .phone
        .invites
        .join(rig.code.share())
        .await
        .expect("the retry joins");
    assert_eq!(joined.space, rig.folder);
}

/// A record under the token's name that no hint is: another content.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_packet_that_is_no_hint_record_or_is_named_otherwise_is_refused() {
    let rig = Rig::new(Shape::address()).await;
    rig.first_contact_answers();
    let device = Arc::clone(&rig.laptop);
    rig.gate.tamper(move |wire| {
        let data = Data::decode(wire.clone()).ok()?;
        if !is_hint(&data.name) {
            return Some(wire);
        }
        // Signed by the device, but the content is no record.
        sign_as(
            &device,
            DataBuilder::new((*data.name).clone(), b"hello").freshness(Duration::from_secs(5)),
        )
    });
    let got = rig.phone.invites.join(rig.code.share()).await;
    let why = hint_refusal(&got);
    assert!(why.starts_with("wrong record"), "{why}");
    assert_nothing_went_further(&rig, Some(rig.inviter_key()));

    // A genuine record that is not the one asked for: the Consumer does not hand a Data
    // of another name to an Interest, so the check is made on the packet itself, which
    // would also hold for a transport that did.
    let rig = Rig::new(Shape::address()).await;
    let genuine = served(&rig, &hint_of(&rig)).unwrap();
    let fingerprint = Fingerprint::Whole(alice_fingerprint(&rig));
    let other = hint_name(&rig.laptop.name, &[1; 16]);
    let inner = rig.phone.invites.inner();
    let got = inner
        .verify_hint(&genuine, &other, &rig.laptop.name, &fingerprint, None)
        .await;
    assert!(
        matches!(&got, Err(IntroRefusal::Hint { why }) if why.starts_with("wrong name")),
        "a record was taken for a name it does not carry"
    );
    let got = inner
        .verify_hint(
            &genuine,
            &hint_of(&rig),
            &rig.laptop.name,
            &fingerprint,
            None,
        )
        .await;
    assert!(
        got.is_ok(),
        "and the same record under its own name verifies"
    );
}

/// A record signed by another device of the inviter's namespace — a valid chain to the
/// code's anchor, but not the device the code names — is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_record_signed_by_another_device_of_the_namespace_is_refused() {
    let rig = Rig::new(Shape::address()).await;
    rig.first_contact_answers();
    let other = start(&rig.alice, "/alice/phone").await;
    let genuine = served(&rig, &hint_of(&rig)).unwrap();
    let HintRecord::Offered {
        offer,
        key: link_key,
        candidates,
        relays,
        until,
        ..
    } = record_of(&genuine)
    else {
        panic!("a record");
    };
    let inner = other.invites.inner();
    let record = HintRecord::Offered {
        offer,
        key: link_key,
        candidates,
        relays,
        until,
        credentials: credentials(&inner.node, &*inner.host).unwrap(),
    };
    let signer = Arc::clone(&other);
    rig.gate.tamper(move |wire| {
        let data = Data::decode(wire.clone()).ok()?;
        if !is_hint(&data.name) {
            return Some(wire);
        }
        sign_as(
            &signer,
            DataBuilder::new((*data.name).clone(), &record.encode())
                .freshness(Duration::from_secs(5)),
        )
    });
    let got = rig.phone.invites.join(rig.code.share()).await;
    let why = mismatch_refusal(&got);
    assert!(why.starts_with("signer"), "{why}");
    assert_nothing_went_further(&rig, Some(rig.inviter_key()));
}

/// A record the device itself signed for another offer of its own, presented under this
/// code's token, is refused before an ask is sent: the offer it names is not committed to
/// this code's secret.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_record_naming_another_offer_is_refused_before_the_ask() {
    let rig = Rig::new(Shape::address()).await;
    rig.first_contact_answers();
    let second = rig
        .laptop
        .invites
        .offer(
            &rig.folder,
            Offer {
                role: Role::Writer,
                until: Timestamp(rig.laptop.node.now().0 + 3_600_000),
                tries: 3,
            },
        )
        .await
        .unwrap();
    let genuine = served(&rig, &hint_of(&rig)).unwrap();
    let HintRecord::Offered {
        key: link_key,
        candidates,
        relays,
        until,
        credentials,
        ..
    } = record_of(&genuine)
    else {
        panic!("a record");
    };
    let record = HintRecord::Offered {
        offer: second.offer.clone(),
        key: link_key,
        candidates,
        relays,
        until,
        credentials,
    };
    let device = Arc::clone(&rig.laptop);
    rig.gate.tamper(move |wire| {
        let data = Data::decode(wire.clone()).ok()?;
        if !is_hint(&data.name) {
            return Some(wire);
        }
        sign_as(
            &device,
            DataBuilder::new((*data.name).clone(), &record.encode())
                .freshness(Duration::from_secs(5)),
        )
    });
    let got = rig.phone.invites.join(rig.code.share()).await;
    let why = mismatch_refusal(&got);
    assert!(why.starts_with("offer"), "{why}");
    let asked = rig.gate.sent_where(|n| parse_intro_name(n).is_some());
    assert!(
        asked.is_empty(),
        "an ask was sent for another offer: {asked:?}"
    );
    assert_eq!(rig.phone_calls.undialled_keys(), vec![rig.inviter_key()]);
    assert!(!offer_used(&rig));
}

/// A short code of a device under a namespace the joiner holds under another anchor dials
/// nothing, as every code is judged before a dial.
#[tokio::test]
async fn a_short_code_of_a_device_under_a_held_namespace_of_another_anchor_dials_nothing() {
    let rig = Rig::new(Shape::address()).await;
    rig.first_contact_answers();
    let real = Person::new("/alice");
    rig.phone
        .validator
        .adopt_context(Arc::clone(&real.ctx))
        .unwrap();
    let got = rig.phone.invites.join(rig.code.share()).await;
    assert!(
        matches!(
            &got,
            Err(InviteError::Refused(IntroRefusal::InviterConflict { .. }))
        ),
        "{got:?}"
    );
    assert!(rig.phone_calls.first_dialled().is_empty());
    assert!(rig.sent().is_empty());
}

// ---- a first link of another key than the record's (M2) and the offer's signer (I1) -------------

/// What a join through a party that answered the dial with a key of its own must leave:
/// its link taken down before anything but the hint went over it, and no Interest of the
/// join (the offer, the ask) carried by it.
fn assert_first_link_of_a_party_gone(rig: &Rig, party: [u8; 32]) {
    assert_eq!(
        rig.phone_calls.undialled_keys(),
        vec![party],
        "the first link of a key the record does not name was not taken down"
    );
    assert!(
        !rig.phone_calls.linked(),
        "a link to the party at the address outlives the join"
    );
    let beyond: Vec<Name> = rig
        .paths
        .over_link
        .lock()
        .unwrap()
        .iter()
        .filter(|n| !is_hint(n))
        .cloned()
        .collect();
    assert!(
        beyond.is_empty(),
        "the party's link carried the join's Interests: {beyond:?}"
    );
}

/// A party at the code's address answers the dial with a key of its own and relays the
/// genuine record, which names the inviter's key; that key's dial is blocked. The join
/// goes on by name, and the party's link is taken down as soon as the record shows it is
/// not the inviter's: neither the offer fetch nor the ask goes over it, and it does not
/// outlive the join.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_first_link_of_another_key_than_the_records_is_taken_down_at_once() {
    let rig = Rig::new(Shape::address()).await;
    let party = [0xA7; 32];
    *rig.phone_calls.first_dial.lock().unwrap() = Some(Ok(party));
    rig.paths.by_name.store(true, Ordering::SeqCst);
    let joined = rig
        .phone
        .invites
        .join(rig.code.share())
        .await
        .expect("joins by name");
    assert_eq!(joined.space, rig.folder);
    assert_eq!(
        rig.phone_calls.dialled(),
        vec![n("/alice/laptop")],
        "the record's key was not dialled"
    );
    assert_first_link_of_a_party_gone(&rig, party);
}

/// The same with a record that offers no address to dial: the join must not carry on over
/// the party's link either.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_first_link_of_another_key_than_a_record_with_no_address_is_not_used() {
    let rig = Rig::new(Shape::address()).await;
    let party = [0xA7; 32];
    *rig.phone_calls.first_dial.lock().unwrap() = Some(Ok(party));
    *rig.inviter_calls.hint.lock().unwrap() = None;
    rig.paths.by_name.store(true, Ordering::SeqCst);
    let joined = rig
        .phone
        .invites
        .join(rig.code.share())
        .await
        .expect("joins by name");
    assert_eq!(joined.space, rig.folder);
    assert!(rig.phone_calls.dialled().is_empty(), "nothing to dial");
    assert_first_link_of_a_party_gone(&rig, party);
}

/// A party on the path substitutes the offer's seal key and re-signs the offer with a key
/// of its own, keeping the commitment: the hint's credentials show the offer is not signed
/// by a key of the inviter's device, so it is refused before the ask is sealed to the
/// substituted key.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_offer_the_hints_credentials_do_not_vouch_for_is_refused_before_the_ask() {
    let rig = Rig::new(Shape::address()).await;
    rig.first_contact_answers();
    let own_seal_key = rig.phone.node.recipient().public();
    let attacker = Arc::clone(&rig.phone);
    rig.gate.tamper(move |wire| {
        let data = Data::decode(wire.clone()).ok()?;
        if parse_offer_name(&data.name).is_none() {
            return Some(wire);
        }
        let Ok(IntroRecord::Offer(mut offer)) = IntroRecord::decode(data.content()?.clone()) else {
            return Some(wire);
        };
        offer.seal_key = own_seal_key;
        sign_as(
            &attacker,
            DataBuilder::new((*data.name).clone(), &IntroRecord::Offer(offer).encode()),
        )
    });
    let got = rig.phone.invites.join(rig.code.share()).await;
    assert!(
        matches!(&got, Err(InviteError::Refused(IntroRefusal::Forged))),
        "{got:?}"
    );
    let asked = rig.gate.sent_where(|n| parse_intro_name(n).is_some());
    assert!(
        asked.is_empty(),
        "an ask was sent after the offer's signer was substituted: {asked:?}"
    );
    assert_eq!(rig.phone_calls.undialled_keys(), vec![rig.inviter_key()]);
}
