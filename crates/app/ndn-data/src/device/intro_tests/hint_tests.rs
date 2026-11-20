//! Round 10 (SHAPES-R10 §2–§4, §7): the hint record and the short code at the
//! `Device` level. An inviter and a joiner are two real devices over an in-process
//! network ([`Net`]) that carries the joiner's Interests to the inviter's own
//! serving path (`Inner::answer`, through its `Node`) the way a link or a relay
//! would: by the link a host dialled (the mock host's `dial_first` / `dial`), by a
//! relay named in the Interest's ForwardingHint, or by name once the joiner's host
//! adopted the inviter's namespace. Nothing of the thing under test is mocked: the
//! mock is the host's link layer, which is not this crate's.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use futures::StreamExt;

use super::super::hint::HintFault;
use super::super::intro::{Fingerprint, open_credentials};
use super::*;
use crate::intro::Joined;

/// Packets waiting for one end.
struct Queue {
    tx: futures::channel::mpsc::UnboundedSender<Bytes>,
    rx: futures::lock::Mutex<futures::channel::mpsc::UnboundedReceiver<Bytes>>,
}

impl Queue {
    fn new() -> Queue {
        let (tx, rx) = futures::channel::mpsc::unbounded();
        Queue {
            tx,
            rx: futures::lock::Mutex::new(rx),
        }
    }
}

/// What a joiner sent: the Interest's name and the relays of its ForwardingHint.
type Sent = (Name, Vec<Name>);

/// A function over the inviter's replies: the packet the joiner is given, or
/// `None` for nothing.
type Tamper = Arc<dyn Fn(Bytes) -> Option<Bytes> + Send + Sync>;

/// The network between a joiner and an inviter's device.
struct Net {
    /// What the inviter's node receives, and what the joiner's does.
    inviter: Queue,
    joiner: Queue,
    /// The inviter's device name: the only name this network routes.
    device: Name,
    /// The joiner's device name: what the inviter's Interests for it reach.
    joiner_device: Name,
    /// The relay this network models: an Interest whose ForwardingHint names it
    /// reaches the inviter, as a relay forwards what it is asked to.
    relay: Name,
    relay_up: AtomicBool,
    /// Route every name of the inviter, as a joiner's forwarder with a route to
    /// it does.
    by_name: AtomicBool,
    /// Lose every Interest for a hint record.
    hint_lost: AtomicBool,
    /// The joiner's host: what its dials made.
    joiner_calls: Arc<Calls>,
    /// Every Interest the joiner sent, in order.
    sent: std::sync::Mutex<Vec<Sent>>,
    /// Interests a link did not carry.
    refused: std::sync::Mutex<Vec<Name>>,
    tamper: std::sync::Mutex<Option<Tamper>>,
    hint_interests: AtomicUsize,
}

impl Net {
    fn new(device: &Name, joiner: &Name, relay: &Name, joiner_calls: &Arc<Calls>) -> Arc<Net> {
        Arc::new(Net {
            inviter: Queue::new(),
            joiner: Queue::new(),
            device: device.clone(),
            joiner_device: joiner.clone(),
            relay: relay.clone(),
            relay_up: AtomicBool::new(true),
            by_name: AtomicBool::new(false),
            hint_lost: AtomicBool::new(false),
            joiner_calls: Arc::clone(joiner_calls),
            sent: std::sync::Mutex::new(Vec::new()),
            refused: std::sync::Mutex::new(Vec::new()),
            tamper: std::sync::Mutex::new(None),
            hint_interests: AtomicUsize::new(0),
        })
    }

    /// Whether the joiner's Interest reaches the inviter.
    fn carries(&self, interest: &Interest) -> bool {
        let name: &Name = &interest.name;
        let hints: Vec<Name> = interest
            .forwarding_hint()
            .map(|h| h.iter().map(|n| (**n).clone()).collect())
            .unwrap_or_default();
        self.sent
            .lock()
            .unwrap()
            .push((name.clone(), hints.clone()));
        if !name.has_prefix(&self.device) {
            return false;
        }
        if crate::intro::parse_hint_name(name).is_some() {
            self.hint_interests.fetch_add(1, Ordering::SeqCst);
            if self.hint_lost.load(Ordering::SeqCst) {
                return false;
            }
        }
        let via_relay = self.relay_up.load(Ordering::SeqCst) && hints.contains(&self.relay);
        let calls = &self.joiner_calls;
        let linked = calls.linked()
            && (calls.adopted()
                || crate::intro::introduction_prefixes(&self.device)
                    .iter()
                    .any(|p| name.has_prefix(p)));
        if via_relay || linked || calls.adopted() || self.by_name.load(Ordering::SeqCst) {
            return true;
        }
        self.refused.lock().unwrap().push(name.clone());
        false
    }

    /// What the joiner sent for names that are hint records.
    fn hint_fetches(&self) -> usize {
        self.hint_interests.load(Ordering::SeqCst)
    }

    /// The Interests the joiner sent under the inviter, as the names and the
    /// relays they were hinted through.
    fn sent(&self) -> Vec<Sent> {
        self.sent.lock().unwrap().clone()
    }

    fn tamper(&self, f: impl Fn(Bytes) -> Option<Bytes> + Send + Sync + 'static) {
        *self.tamper.lock().unwrap() = Some(Arc::new(f));
    }
}

/// One end of a [`Net`].
struct End {
    net: Arc<Net>,
    is_joiner: bool,
}

#[async_trait::async_trait]
impl Connection for End {
    async fn send(&self, wire: Bytes) -> Result<(), AppError> {
        if self.is_joiner {
            match Interest::decode(wire.clone()) {
                Ok(interest) => {
                    if self.net.carries(&interest) {
                        let _ = self.net.inviter.tx.unbounded_send(wire);
                    }
                }
                // What the joiner's device answers the inviter's Interests with.
                Err(_) => {
                    let _ = self.net.inviter.tx.unbounded_send(wire);
                }
            }
        } else if let Ok(interest) = Interest::decode(wire.clone()) {
            // The inviter asks the joiner's device (the seal key of an asker it
            // grants a key to): the joiner is reached by its name.
            if interest.name.has_prefix(&self.net.joiner_device) {
                let _ = self.net.joiner.tx.unbounded_send(wire);
            }
        } else {
            let tamper = self.net.tamper.lock().unwrap().clone();
            let wire = match tamper {
                Some(f) => match f(wire) {
                    Some(w) => w,
                    None => return Ok(()),
                },
                None => wire,
            };
            let _ = self.net.joiner.tx.unbounded_send(wire);
        }
        Ok(())
    }

    async fn recv(&self) -> Option<Bytes> {
        let q = if self.is_joiner {
            &self.net.joiner
        } else {
            &self.net.inviter
        };
        q.rx.lock().await.next().await
    }

    async fn register_prefix(&self, _prefix: &Name) -> Result<(), AppError> {
        Ok(())
    }
}

/// How a rig's inviter is set up.
struct Setup {
    /// Candidate addresses its host gives for a link hint.
    candidates: Vec<&'static str>,
    /// Its namespace advertises the relay `/alice/node/relay`.
    relay: bool,
    /// The inviter's introduction policy.
    policy: IntroPolicy,
    /// The joiner's.
    joiner_policy: IntroPolicy,
}

impl Setup {
    /// An inviter whose host listens at one public IPv4 address.
    fn address() -> Setup {
        Setup {
            candidates: vec!["192.0.2.7:4433"],
            relay: false,
            policy: IntroPolicy::new(),
            joiner_policy: IntroPolicy::new(),
        }
    }

    /// An inviter that listens nowhere a joiner can dial, behind a relay.
    fn relayed() -> Setup {
        Setup {
            candidates: Vec::new(),
            relay: true,
            ..Setup::address()
        }
    }

    /// An inviter with no first contact at all.
    fn nowhere() -> Setup {
        Setup {
            candidates: Vec::new(),
            ..Setup::address()
        }
    }
}

/// Alice's laptop and Bob's phone on a [`Net`], an offer of Alice's notebook made.
struct Rig {
    laptop: Device,
    alice: Person,
    keys: Arc<SecurityManager>,
    store: Arc<dyn DataStore>,
    inviter_calls: Arc<Calls>,
    skew: Arc<std::sync::atomic::AtomicU64>,
    clock: Clock,
    net: Arc<Net>,
    phone: Device,
    phone_calls: Arc<Calls>,
    code: crate::intro::Code,
    secret: [u8; crate::intro::SECRET_LEN],
    folder: Name,
}

impl Rig {
    async fn new(setup: Setup) -> Rig {
        let alice = if setup.relay {
            Person::relayed("/alice", "/alice/node/relay")
        } else {
            Person::new("/alice")
        };
        let keys = keyed(&alice, "/alice/laptop").await;
        let (clock, skew) = skewed();
        let inviter_calls = Arc::new(Calls::default());
        let phone_calls = Arc::new(Calls::default());
        let net = Net::new(
            &n("/alice/laptop"),
            &n("/bob/phone"),
            &n("/alice/node/relay"),
            &phone_calls,
        );
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let laptop = start_wired(
            &alice,
            "/alice/laptop",
            Some(Arc::clone(&keys)),
            &[],
            None,
            Some(Arc::clone(&clock)),
            Arc::clone(&inviter_calls),
            setup.policy,
            Arc::clone(&store),
            Arc::new(End {
                net: Arc::clone(&net),
                is_joiner: false,
            }),
        )
        .await;
        if !setup.candidates.is_empty() {
            *inviter_calls.hint.lock().unwrap() = Some(crate::intro::LinkHint {
                key: laptop.inner.own_key.unwrap(),
                candidates: setup
                    .candidates
                    .iter()
                    .map(|a| crate::intro::HintCandidate {
                        kind: crate::intro::HintKind::Host,
                        addr: a.parse().unwrap(),
                    })
                    .collect(),
            });
        }
        let (laptop, code, secret, alice) = alice_offers(laptop, alice, Role::Writer).await;
        let bob = Person::new("/bob");
        let phone = start_wired(
            &bob,
            "/bob/phone",
            None,
            &[],
            None,
            None,
            Arc::clone(&phone_calls),
            setup.joiner_policy,
            Arc::new(MemoryStore::new()),
            Arc::new(End {
                net: Arc::clone(&net),
                is_joiner: true,
            }),
        )
        .await;
        Rig {
            laptop,
            alice,
            keys,
            store,
            inviter_calls,
            skew,
            net,
            phone,
            phone_calls,
            code,
            secret,
            folder: n("/alice/32=data/notebook"),
            clock,
        }
    }

    /// The key the inviter's link proves: what a first contact answers.
    fn inviter_key(&self) -> [u8; 32] {
        self.laptop.inner.own_key.unwrap()
    }

    /// The joiner's host dials the inviter's address: the link proves the
    /// inviter's key.
    fn first_contact_answers(&self) {
        *self.phone_calls.first_dial.lock().unwrap() = Some(Ok(self.inviter_key()));
    }
}

/// Whether `s` has the name of an introduction's hint record.
fn is_hint(name: &Name) -> bool {
    crate::intro::parse_hint_name(name).is_some()
}

/// The token of a rig's offer.
fn token_of(rig: &Rig) -> [u8; crate::intro::HINT_TOKEN_LEN] {
    crate::intro::hint_token(&rig.secret)
}

/// The hint record's name of a rig's offer.
fn hint_of(rig: &Rig) -> Name {
    crate::intro::hint_name(rig.laptop.name(), &token_of(rig))
}

/// What the inviter's device serves for `name`, decoded.
fn served(rig: &Rig, name: &Name) -> Option<Data> {
    rig.laptop
        .inner
        .hint_packet(name)
        .map(|wire| Data::decode(wire).unwrap())
}

/// The record a hint Data carries.
fn record_of(data: &Data) -> crate::intro::HintRecord {
    crate::intro::HintRecord::decode(data.content().unwrap().clone(), true).unwrap()
}

/// The anchor fingerprint of Alice's namespace.
fn alice_fingerprint(rig: &Rig) -> [u8; 32] {
    let anchors = rig.alice.ctx.anchors();
    let anchor = anchors.iter().next().expect("an anchor");
    ndn_security::anchor_fingerprint(anchor.value())
}

/// A short code written for `rig`'s inviter: its device, `contact`, `secret` and
/// the `fingerprint` octets, as a person would read them.
fn short_text(
    rig: &Rig,
    contact: Option<crate::intro::Contact>,
    secret: [u8; crate::intro::SECRET_LEN],
    fingerprint: &[u8],
) -> String {
    crate::intro::ShortCode {
        device: rig.laptop.name().clone(),
        contact,
        secret,
        fingerprint: fingerprint.to_vec(),
    }
    .encode()
    .unwrap()
}

/// The inviter's address, as a code's first contact.
fn address() -> crate::intro::Contact {
    crate::intro::Contact::Address("192.0.2.7:4433".parse().unwrap())
}

/// `rig`'s offer as an old link wrote it (TLVs of trust-envelope.md §5.1: an
/// envelope of format 1, kind 7, a body of the namespace, the fingerprint, the
/// offer's name, the secret and the link hint, names in text).
fn old_link(rig: &Rig, with_hint: bool) -> String {
    use ndn_tlv::TlvWriter;
    let hint = crate::intro::LinkHint {
        key: rig.inviter_key(),
        candidates: vec![crate::intro::HintCandidate {
            kind: crate::intro::HintKind::Host,
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
fn hint_refusal(got: &Result<Joined, DataError>) -> String {
    match got {
        Err(DataError::Introduction {
            why: IntroRefusal::Hint { why },
            ..
        }) => why.clone(),
        other => panic!("not refused as a hint that does not verify: {other:?}"),
    }
}

/// Nothing was dialled, asked or adopted by a join that was refused at the hint
/// record: no dial but the first contact's, which was taken down; no Interest
/// but for the hint; nothing of Alice's namespace held.
fn assert_nothing_went_further(rig: &Rig, first_key: Option<[u8; 32]>) {
    assert!(
        rig.phone_calls.dialled().is_empty(),
        "dialled {:?} on the strength of a record that did not verify",
        rig.phone_calls.dialled()
    );
    let beyond: Vec<Name> = rig
        .net
        .sent()
        .into_iter()
        .map(|(n, _)| n)
        .filter(|n| !is_hint(n))
        .collect();
    assert!(
        beyond.is_empty(),
        "sent {beyond:?} before the record verified"
    );
    assert!(
        rig.phone
            .inner
            .validator
            .keyring()
            .held(&n("/alice"))
            .is_none(),
        "adopted the inviter's namespace"
    );
    assert_eq!(
        rig.phone_calls.undialled_keys(),
        first_key.into_iter().collect::<Vec<_>>(),
        "the first contact's link was not taken down"
    );
    assert!(
        rig.laptop.inner.st.lock().intro.used.is_empty(),
        "the offer was used"
    );
}

// ---- the offer: the short code and what it publishes (§1, §2, §7) ------------------------------

/// G4-shaped: the short code is one line of words and the two text tokens, fits
/// three lines of 98 columns, is what `share()` shows, and names an address.
#[tokio::test]
async fn an_offer_with_an_address_makes_a_short_code_that_fits_three_lines_and_reads_as_words() {
    let rig = Rig::new(Setup::address()).await;
    let short = rig.code.short.clone().expect("a short code");
    assert_eq!(rig.code.short_why, None);
    assert_eq!(rig.code.share(), short);
    let columns = short.chars().count();
    eprintln!("short code with an IPv4 first contact: {columns} columns");
    assert!(columns <= 3 * 98, "{columns} columns: {short}");
    let tokens: Vec<&str> = short.split_whitespace().collect();
    assert_eq!(tokens[0], "/alice/laptop");
    assert_eq!(tokens[1], "192.0.2.7:4433");
    assert_eq!(tokens.len(), 2 + 20, "20 words for a named namespace");
    let read = crate::intro::ShortCode::parse(&short, false).expect("it reads back");
    assert_eq!(read.device, n("/alice/laptop"));
    assert_eq!(read.secret, rig.secret);
    assert_eq!(read.fingerprint, alice_fingerprint(&rig)[..10]);
    assert!(
        rig.code.link.contains("ndn-trust://intro/"),
        "the link is still made"
    );
}

/// A namespace that advertises a relay and a host with nothing to dial: the relay
/// is the first contact.
#[tokio::test]
async fn an_offer_with_only_a_relay_names_the_relay_as_first_contact() {
    let rig = Rig::new(Setup::relayed()).await;
    let short = rig.code.short.clone().expect("a short code");
    let tokens: Vec<&str> = short.split_whitespace().collect();
    assert_eq!(&tokens[..2], ["/alice/laptop", "/alice/node/relay"]);
    assert!(short.chars().count() <= 3 * 98);
}

/// The first contact is the first of the hint's order (dialable candidates, then
/// relays) whose line fits `short_width`: a worst-case IPv6 address that makes the
/// line too wide gives way to the relay; when none fits there is no short code and
/// the reason names the device. The width is set where the address sometimes does
/// not fit and the relay does; every offer is checked against the two lines its
/// own secret makes, and the branch that matters must occur.
#[tokio::test]
async fn a_contact_that_makes_the_line_too_wide_gives_way_to_the_next_that_fits() {
    const WIDTH: usize = 170;
    let worst: &'static str = "[2001:db8:1234:5678:9abc:def0:1234:5678]:65535";
    let mut seen_relay = false;
    let mut seen_address = false;
    for _ in 0..40 {
        let rig = Rig::new(Setup {
            candidates: vec![worst],
            relay: true,
            policy: IntroPolicy {
                short_width: WIDTH,
                ..IntroPolicy::new()
            },
            ..Setup::address()
        })
        .await;
        let fp = alice_fingerprint(&rig);
        let width = |contact| {
            short_text(&rig, Some(contact), rig.secret, &fp[..10])
                .chars()
                .count()
        };
        let by_address = width(crate::intro::Contact::Address(worst.parse().unwrap()));
        let by_relay = width(crate::intro::Contact::Relay(n("/alice/node/relay")));
        match (by_address <= WIDTH, by_relay <= WIDTH) {
            (true, _) => {
                seen_address = true;
                let short = rig.code.short.clone().expect("the address fits");
                assert_eq!(short.split_whitespace().nth(1), Some(worst));
            }
            (false, true) => {
                seen_relay = true;
                let short = rig.code.short.clone().expect("the relay fits");
                assert_eq!(short.split_whitespace().nth(1), Some("/alice/node/relay"));
                assert!(short.chars().count() <= WIDTH);
                assert!(served(&rig, &hint_of(&rig)).is_some());
            }
            (false, false) => {
                assert_eq!(rig.code.short, None);
                let why = rig.code.short_why.clone().unwrap();
                assert!(
                    why.contains("short_width") && why.contains("/alice/laptop"),
                    "{why}"
                );
            }
        }
        if seen_relay && seen_address {
            return;
        }
    }
    assert!(
        seen_relay,
        "no offer had an address too wide and a relay that fits"
    );
}

/// No short code, and nothing of a hint published, when the policy is off, when
/// the host gives no first contact, when the only address is this machine's, and
/// when the line is too wide: each says why.
#[tokio::test]
async fn no_short_code_says_why_and_publishes_nothing() {
    let policy_off = IntroPolicy {
        short_code: false,
        ..IntroPolicy::new()
    };
    let too_wide = IntroPolicy {
        short_width: 40,
        ..IntroPolicy::new()
    };
    let cases = [
        (
            Setup {
                policy: policy_off,
                ..Setup::address()
            },
            "short_code",
        ),
        (Setup::nowhere(), "first contact"),
        (
            Setup {
                candidates: vec!["127.0.0.1:4433"],
                ..Setup::address()
            },
            "first contact",
        ),
        (
            Setup {
                policy: too_wide,
                ..Setup::address()
            },
            "short_width",
        ),
    ];
    for (setup, says) in cases {
        let rig = Rig::new(setup).await;
        assert_eq!(rig.code.short, None);
        let why = rig.code.short_why.clone().expect("it says why");
        assert!(why.contains(says), "{says:?} is not in {why:?}");
        assert_eq!(rig.code.share(), rig.code.link);
        assert!(
            served(&rig, &hint_of(&rig)).is_none(),
            "a hint record is served for an offer with no short code ({why})"
        );
        assert!(!rig.laptop.introductions().carries(&hint_of(&rig)));
    }
}

/// A device of one machine's addresses, with the policy that allows them.
#[tokio::test]
async fn a_local_address_is_a_first_contact_only_under_the_policy() {
    let rig = Rig::new(Setup {
        candidates: vec!["127.0.0.1:4433"],
        policy: IntroPolicy {
            local_candidates: true,
            ..IntroPolicy::new()
        },
        ..Setup::address()
    })
    .await;
    let short = rig
        .code
        .short
        .clone()
        .expect("a short code under the policy");
    assert_eq!(short.split_whitespace().nth(1), Some("127.0.0.1:4433"));
}

/// A self-certifying namespace: the whole fingerprint, 36 words, and `161=*`
/// where the device's component is the anchor's fingerprint.
#[tokio::test]
async fn a_self_certifying_namespace_writes_its_fingerprint_whole_as_161_star() {
    let seed = [0x5c; 32];
    let pk = ndn_security::Ed25519Signer::from_seed(&seed, Name::root()).public_key_bytes();
    let ns = ndn_security::self_certifying::self_certifying_name(&pk);
    let mgr = SecurityManager::new();
    let root = ns.clone().append("KEY").append("root");
    mgr.generate_ed25519_from_seed(root.clone(), &seed).unwrap();
    let person = Person::rooted(&ns.to_string(), &mgr, &root);
    let device = format!("{ns}/laptop");
    let calls = Arc::new(Calls::default());
    let laptop = start_policy(
        &person,
        &device,
        None,
        &[],
        None,
        None,
        Arc::clone(&calls),
        IntroPolicy::new(),
        Arc::new(MemoryStore::new()),
    )
    .await;
    *calls.hint.lock().unwrap() = Some(crate::intro::LinkHint {
        key: laptop.inner.own_key.unwrap(),
        candidates: vec![crate::intro::HintCandidate {
            kind: crate::intro::HintKind::Host,
            addr: "[2001:db8:1:2:3:4:5:6]:4433".parse().unwrap(),
        }],
    });
    let folder: Name = format!("{ns}/32=data/notebook").parse().unwrap();
    laptop
        .share_folder(
            &folder,
            Share {
                rule: Rule::Log,
                writers: vec![ns.clone()],
                readers: Vec::new(),
            }
            .into(),
        )
        .await
        .unwrap();
    let code = laptop
        .offer(
            &folder,
            Offer {
                role: Role::Writer,
                until: Timestamp((laptop.inner.config.clock)().0 + 3_600_000),
                tries: 3,
            },
        )
        .await
        .unwrap();
    let short = code.short.clone().expect("a short code");
    let columns = short.chars().count();
    eprintln!("short code, self-certifying namespace, IPv6 first contact: {columns} columns");
    assert!(columns <= 3 * 98, "{columns} columns: {short}");
    assert!(short.starts_with("/user/161=*/laptop "), "{short}");
    assert_eq!(short.split_whitespace().count(), 2 + 36);
    let read = crate::intro::ShortCode::parse(&short, false).unwrap();
    assert_eq!(read.device, laptop.name().clone());
    assert_eq!(read.fingerprint.len(), 32);
}

// ---- serving: the record, the gone marks, the token (§2) ---------------------------------------

/// The record is signed by the device key, bound to the offer, and carries what a
/// joiner needs: the host's key and addresses, the credentials, the expiry.
#[tokio::test]
async fn the_hint_record_is_signed_by_the_device_and_carries_the_hint_and_credentials() {
    let rig = Rig::new(Setup::address()).await;
    let data = served(&rig, &hint_of(&rig)).expect("served for its token");
    assert_eq!(*data.name, hint_of(&rig));
    let crate::intro::HintRecord::Offered {
        offer,
        key: link_key,
        candidates,
        relays,
        until,
        credentials,
    } = record_of(&data)
    else {
        panic!("an open offer is served as a record");
    };
    assert_eq!(offer, rig.code.offer);
    assert_eq!(link_key, rig.inviter_key());
    assert_eq!(
        candidates
            .iter()
            .map(|c| c.addr.to_string())
            .collect::<Vec<_>>(),
        ["192.0.2.7:4433"]
    );
    assert!(relays.is_empty());
    assert_eq!(
        until,
        rig.laptop.inner.st.lock().intro.offers[&rig.code.offer].until
    );
    let opened = open_credentials(&credentials)
        .await
        .expect("credentials open");
    assert_eq!(
        opened.signer(&data).await.map(|(k, _)| k),
        Some(key(rig.laptop.name())),
        "signed by the device key, chained to the anchor"
    );
    let fresh = data.meta_info().and_then(|m| m.freshness_period);
    assert!(
        fresh.is_some_and(|f| f <= Duration::from_secs(10)),
        "a record is short-lived: {fresh:?}"
    );
}

/// The relays of the namespace are in the record, at most eight.
#[tokio::test]
async fn the_hint_record_names_the_namespaces_relays() {
    let rig = Rig::new(Setup::relayed()).await;
    let data = served(&rig, &hint_of(&rig)).expect("served");
    let crate::intro::HintRecord::Offered { relays, .. } = record_of(&data) else {
        panic!("a record");
    };
    assert_eq!(relays, [n("/alice/node/relay")]);
}

/// A token that is not one of this device's offers' is not answered: not by a
/// record, not by a gone mark; nor is another device's hint name.
#[tokio::test]
async fn an_unknown_token_gets_no_answer_and_no_gone_mark() {
    let rig = Rig::new(Setup::address()).await;
    let device = rig.laptop.name();
    for token in [[0u8; 16], [9; 16], crate::intro::hint_token(&[7; 16])] {
        assert!(
            served(&rig, &crate::intro::hint_name(device, &token)).is_none(),
            "answered for token {token:?}"
        );
    }
    let other = crate::intro::hint_name(&n("/alice/phone"), &token_of(&rig));
    assert!(
        served(&rig, &other).is_none(),
        "answered for another device's name"
    );
    assert!(
        served(&rig, &hint_of(&rig)).is_some(),
        "and the real one still is"
    );
}

/// Closed: a signed gone mark; expired by the device's clock: a gone mark.
#[tokio::test]
async fn a_closed_or_expired_offer_is_answered_by_a_signed_gone_mark() {
    let rig = Rig::new(Setup::address()).await;
    rig.laptop.close_offer(&rig.code.offer).await.unwrap();
    let data = served(&rig, &hint_of(&rig)).expect("a closed offer is answered");
    assert_eq!(
        record_of(&data),
        crate::intro::HintRecord::Gone(IntroRefusal::Closed)
    );
    let own = open_credentials(&rig.laptop.inner.credentials().unwrap())
        .await
        .unwrap();
    assert!(
        own.signer(&data).await.is_some(),
        "the gone mark is signed by the device"
    );

    let rig = Rig::new(Setup::address()).await;
    rig.skew
        .store(2 * 3_600_000, std::sync::atomic::Ordering::SeqCst);
    let data = served(&rig, &hint_of(&rig)).expect("an expired offer is answered");
    assert_eq!(
        record_of(&data),
        crate::intro::HintRecord::Gone(IntroRefusal::Expired)
    );
}

/// `hint_while_open = false`: the record is served until the device stops, past
/// a close and past the expiry; the offer itself still answers by its own rules.
#[tokio::test]
async fn with_the_policy_off_the_record_is_served_after_close_and_expiry() {
    let rig = Rig::new(Setup {
        policy: IntroPolicy {
            hint_while_open: false,
            ..IntroPolicy::new()
        },
        ..Setup::address()
    })
    .await;
    rig.laptop.close_offer(&rig.code.offer).await.unwrap();
    rig.skew
        .store(2 * 3_600_000, std::sync::atomic::Ordering::SeqCst);
    let data = served(&rig, &hint_of(&rig)).expect("served");
    assert!(matches!(
        record_of(&data),
        crate::intro::HintRecord::Offered { .. }
    ));
}

/// A signed record is answered again as it is for a few seconds (one signature),
/// and is made afresh from the host's current hint after.
#[tokio::test(start_paused = true)]
async fn a_record_is_cached_a_few_seconds_and_then_made_from_the_hosts_hint_again() {
    let rig = Rig::new(Setup::address()).await;
    let name = hint_of(&rig);
    let first = rig.laptop.inner.hint_packet(&name).unwrap();
    let signed = rig.laptop.signatures();
    assert_eq!(rig.laptop.inner.hint_packet(&name).unwrap(), first);
    assert_eq!(
        rig.laptop.signatures(),
        signed,
        "a second request signed again"
    );
    // The host's address moves.
    rig.inviter_calls
        .hint
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .candidates[0]
        .addr = "192.0.2.99:4433".parse().unwrap();
    tokio::time::advance(super::super::hint::HINT_CACHE + Duration::from_secs(1)).await;
    let data = Data::decode(rig.laptop.inner.hint_packet(&name).unwrap()).unwrap();
    let crate::intro::HintRecord::Offered { candidates, .. } = record_of(&data) else {
        panic!("a record");
    };
    assert_eq!(candidates[0].addr.to_string(), "192.0.2.99:4433");
    assert!(rig.laptop.signatures() > signed);
}

/// A closed offer is a gone mark at once, whatever the cache holds.
#[tokio::test]
async fn closing_an_offer_ends_the_record_at_once() {
    let rig = Rig::new(Setup::address()).await;
    let name = hint_of(&rig);
    assert!(matches!(
        record_of(&served(&rig, &name).unwrap()),
        crate::intro::HintRecord::Offered { .. }
    ));
    rig.laptop.close_offer(&rig.code.offer).await.unwrap();
    assert_eq!(
        record_of(&served(&rig, &name).unwrap()),
        crate::intro::HintRecord::Gone(IntroRefusal::Closed)
    );
}

/// The token is kept durably and read back at a start: a restarted inviter
/// serves the record of the offer it holds; a token note that is not wrapped to
/// its key publishes nothing.
#[tokio::test]
async fn the_token_is_kept_across_a_restart_and_a_forged_note_publishes_nothing() {
    let rig = Rig::new(Setup::address()).await;
    let name = hint_of(&rig);
    rig.laptop.shutdown();
    let restarted = start_wired(
        &rig.alice,
        "/alice/laptop",
        Some(Arc::clone(&rig.keys)),
        &[],
        None,
        Some(Arc::clone(&rig.clock)),
        Arc::clone(&rig.inviter_calls),
        IntroPolicy::new(),
        Arc::clone(&rig.store),
        Arc::new(Unconnected),
    )
    .await;
    assert!(
        restarted.inner.hint_packet(&name).is_some(),
        "a restarted inviter does not serve its open offer's hint"
    );
    restarted.shutdown();

    let note = super::super::intro::local_name("hint", &rig.code.offer);
    assert!(rig.store.get(&note).is_some(), "the token was kept durably");
    rig.store
        .insert(note, Bytes::from_static(b"not a wrapped key"));
    let forged = start_wired(
        &rig.alice,
        "/alice/laptop",
        Some(Arc::clone(&rig.keys)),
        &[],
        None,
        Some(Arc::clone(&rig.clock)),
        Arc::clone(&rig.inviter_calls),
        IntroPolicy::new(),
        Arc::clone(&rig.store),
        Arc::new(Unconnected),
    )
    .await;
    assert!(
        forged.inner.hint_packet(&name).is_none(),
        "a note that is not wrapped to the device's key was read"
    );
    forged.shutdown();
}

// ---- the introduction surface (round 4 L4) -----------------------------------------------------

/// A link dialled for an introduction carries the hint record of an own offer's
/// token and nothing else of the device: not a log entry, not a summary root,
/// not another device's hint, not an unknown token, not a longer name.
#[tokio::test]
async fn the_surface_carries_the_hint_of_an_own_token_and_nothing_else_of_the_device() {
    let rig = Rig::new(Setup::address()).await;
    let surface = rig.laptop.introductions();
    let device = rig.laptop.name().clone();
    let hint = hint_of(&rig);
    assert!(surface.carries(&hint));
    assert!(
        surface.carries(&wire::held_name(&device, &rig.code.offer)),
        "the offer record is still carried"
    );
    for refused in [
        crate::intro::hint_prefix(&device),
        crate::intro::hint_name(&device, &[3; 16]),
        crate::intro::hint_name(&n("/alice/phone"), &token_of(&rig)),
        hint.clone().append("more"),
        wire::log_name(&device, Some(&rig.folder), 1),
        wire::held_name(&device, &wire::log_name(&device, Some(&rig.folder), 1)),
        wire::held_name(&device, &hint),
        n("/alice/laptop/32=sum"),
        device.clone().append("32=head").append("x"),
    ] {
        assert!(!surface.carries(&refused), "{refused} is carried");
    }
    // A closed offer's hint is carried: its answer is the gone mark.
    rig.laptop.close_offer(&rig.code.offer).await.unwrap();
    assert!(surface.carries(&hint));
}

// ---- the joiner: a short code joins over an address and over a relay (§3) ----------------------

/// G4-shaped: a joiner with only the short code joins; its first contact is an
/// address dialled with no key to expect; the hint record is fetched by name
/// over that link; the inviter's key the link proved is the record's, so no
/// second dial is made; every Interest before the namespace is adopted is one
/// the link routes.
#[tokio::test]
async fn a_joiner_with_only_the_short_code_joins_over_an_address_first_contact() {
    let rig = Rig::new(Setup::address()).await;
    rig.first_contact_answers();
    let short = rig.code.short.clone().unwrap();
    let joined = rig.phone.join(&short).await.expect("joins");
    assert_eq!(joined.folder, rig.folder);
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
    assert_eq!(rig.net.hint_fetches(), 1);
    assert!(
        rig.net.refused.lock().unwrap().is_empty(),
        "Interests the first link does not carry: {:?}",
        rig.net.refused.lock().unwrap()
    );
    assert!(
        rig.phone_calls.undialled().is_empty(),
        "a join that succeeded took its link down"
    );
}

/// G4-shaped: a joiner with only the short code joins by a relay first contact:
/// the hint Interest is routed by its ForwardingHint, and nothing is dialled.
#[tokio::test]
async fn a_joiner_with_only_the_short_code_joins_over_a_relay_first_contact() {
    let rig = Rig::new(Setup::relayed()).await;
    let short = rig.code.short.clone().unwrap();
    let joined = rig.phone.join(&short).await.expect("joins");
    assert_eq!(joined.folder, rig.folder);
    assert!(rig.phone_calls.first_dialled().is_empty());
    let hinted: Vec<Sent> = rig
        .net
        .sent()
        .into_iter()
        .filter(|(n, _)| is_hint(n))
        .collect();
    assert!(!hinted.is_empty());
    assert!(
        hinted
            .iter()
            .all(|(_, hints)| hints == &[n("/alice/node/relay")]),
        "the hint Interest did not go by the relay: {hinted:?}"
    );
}

/// A short code that names no first contact is routed by name.
#[tokio::test]
async fn a_short_code_with_no_contact_is_routed_by_name() {
    let rig = Rig::new(Setup::address()).await;
    rig.net.by_name.store(true, Ordering::SeqCst);
    let fp = alice_fingerprint(&rig);
    let text = short_text(&rig, None, rig.secret, &fp[..10]);
    let joined = rig.phone.join(&text).await.expect("joins");
    assert_eq!(joined.folder, rig.folder);
    assert!(rig.phone_calls.first_dialled().is_empty());
}

// ---- the compact full link and the old forms join with no fetch (§5, case 6) -------------------

/// The compact full link names the key and the addresses: it joins with no hint
/// record fetched.
#[tokio::test]
async fn the_compact_full_link_joins_with_no_hint_fetch() {
    let rig = Rig::new(Setup::address()).await;
    rig.phone_calls
        .dial_succeeds
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let joined = rig.phone.join(&rig.code.link).await.expect("joins");
    assert_eq!(joined.folder, rig.folder);
    assert_eq!(rig.net.hint_fetches(), 0, "the full link fetched a hint");
    assert_eq!(rig.phone_calls.dialled(), vec![n("/alice/laptop")]);
    assert!(rig.phone_calls.first_dialled().is_empty());
}

/// Today's words form (the offer's name and 24 words) still joins, by name.
#[tokio::test]
async fn the_old_words_form_joins_with_no_hint_fetch() {
    let rig = Rig::new(Setup::address()).await;
    rig.net.by_name.store(true, Ordering::SeqCst);
    let joined = rig.phone.join(&rig.code.words).await.expect("joins");
    assert_eq!(joined.folder, rig.folder);
    assert_eq!(rig.net.hint_fetches(), 0);
}

/// A link as every earlier version wrote it: names as text (the namespace, the
/// offer, the relays), the link hint beside, no compact tag. Nothing writes this
/// form any more; it is still read.
#[tokio::test]
async fn an_old_text_link_still_joins_with_no_hint_fetch() {
    let rig = Rig::new(Setup::address()).await;
    rig.phone_calls
        .dial_succeeds
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let link = old_link(&rig, true);
    let joined = rig.phone.join(&link).await.expect("joins");
    assert_eq!(joined.folder, rig.folder);
    assert_eq!(rig.net.hint_fetches(), 0);
    assert_eq!(rig.phone_calls.dialled(), vec![n("/alice/laptop")]);

    // Without a hint, by name.
    let rig = Rig::new(Setup::address()).await;
    rig.net.by_name.store(true, Ordering::SeqCst);
    let link = old_link(&rig, false);
    let joined = rig.phone.join(&link).await.expect("joins");
    assert_eq!(joined.folder, rig.folder);
    assert_eq!(rig.net.hint_fetches(), 0);
    assert!(rig.phone_calls.dialled().is_empty());
}

// ---- refusals (§4) -----------------------------------------------------------------------------

/// A mistyped word, device or digit is refused before anything is dialled or sent,
/// with the text that says what to check; so are a word off the list and a count
/// no form has.
#[tokio::test]
async fn a_typo_is_refused_with_the_message_before_anything_is_dialled() {
    let rig = Rig::new(Setup::address()).await;
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
        let got = rig.phone.join(&code).await;
        match &got {
            Err(e @ DataError::BadRequest { why, .. }) => {
                assert!(why.contains(says), "{says:?} is not in {why:?}");
                assert_eq!(e.next(), crate::error::NextStep::FixRequest);
            }
            other => panic!("{code:?} was not a bad request: {other:?}"),
        }
    }
    assert!(
        rig.phone_calls.first_dialled().is_empty(),
        "dialled for a typo"
    );
    assert!(rig.net.sent().is_empty(), "sent for a typo");
}

/// A loopback first contact is refused unless the joiner's policy allows it.
#[tokio::test]
async fn a_loopback_first_contact_is_refused_unless_the_joiners_policy_allows_it() {
    let rig = Rig::new(Setup::address()).await;
    let fp = alice_fingerprint(&rig);
    let text = short_text(
        &rig,
        Some(crate::intro::Contact::Address(
            "127.0.0.1:4433".parse().unwrap(),
        )),
        rig.secret,
        &fp[..10],
    );
    let got = rig.phone.join(&text).await;
    assert!(
        matches!(&got, Err(DataError::BadRequest { why, .. }) if why.contains("local_candidates")),
        "{got:?}"
    );
    assert!(rig.phone_calls.first_dialled().is_empty());

    let allowed = Rig::new(Setup {
        joiner_policy: IntroPolicy {
            local_candidates: true,
            ..IntroPolicy::new()
        },
        ..Setup::address()
    })
    .await;
    let fp = alice_fingerprint(&allowed);
    let text = short_text(
        &allowed,
        Some(crate::intro::Contact::Address(
            "127.0.0.1:4433".parse().unwrap(),
        )),
        allowed.secret,
        &fp[..10],
    );
    let _ = allowed.phone.join(&text).await;
    assert_eq!(
        allowed.phone_calls.first_dialled().len(),
        1,
        "the policy did not allow it"
    );
}

/// A first contact that does not answer the dial is `NotReady`, saying so.
#[tokio::test]
async fn a_first_contact_that_does_not_answer_is_not_ready() {
    let rig = Rig::new(Setup::address()).await;
    *rig.phone_calls.first_dial.lock().unwrap() = Some(Err("connection refused".into()));
    let got = rig.phone.join(rig.code.share()).await;
    let Err(e @ DataError::NotReady { why, .. }) = &got else {
        panic!("not NotReady: {got:?}");
    };
    assert!(why.contains("192.0.2.7:4433"));
    assert!(why.contains("did not answer"));
    assert!(why.contains("connection refused"));
    assert!(why.contains("retry"));
    assert_eq!(e.next(), crate::error::NextStep::RetryLater);
    assert!(rig.net.sent().is_empty());
}

/// A joiner that cannot fetch the record in its tries — lost, or an unknown token
/// that is not answered — is `NotReady` with the text that lists why; its first
/// contact's link is taken down.
#[tokio::test(start_paused = true)]
async fn a_joiner_that_cannot_fetch_the_hint_is_not_ready() {
    let rig = Rig::new(Setup::address()).await;
    rig.first_contact_answers();
    rig.net.hint_lost.store(true, Ordering::SeqCst);
    let got = rig.phone.join(rig.code.share()).await;
    let Err(e @ DataError::NotReady { why, .. }) = &got else {
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
    assert_eq!(e.next(), crate::error::NextStep::RetryLater);
    assert_eq!(
        rig.net.hint_fetches(),
        8,
        "as often as the offer is fetched"
    );
    assert_eq!(rig.phone_calls.undialled_keys(), vec![rig.inviter_key()]);

    // A token the inviter does not hold is not answered either.
    let rig = Rig::new(Setup::address()).await;
    rig.first_contact_answers();
    let fp = alice_fingerprint(&rig);
    let text = short_text(&rig, Some(address()), [0x77; 16], &fp[..10]);
    let got = rig.phone.join(&text).await;
    assert!(matches!(got, Err(DataError::NotReady { .. })), "{got:?}");
    assert!(rig.laptop.inner.st.lock().intro.used.is_empty());
}

/// A closed offer's record is the gone mark: the join is refused as closed, the
/// first contact's link taken down, nothing asked.
#[tokio::test]
async fn a_closed_offer_is_a_gone_mark_and_the_join_is_refused_as_closed() {
    let rig = Rig::new(Setup::address()).await;
    rig.first_contact_answers();
    rig.laptop.close_offer(&rig.code.offer).await.unwrap();
    let got = rig.phone.join(rig.code.share()).await;
    let Err(e @ DataError::Introduction { why, .. }) = &got else {
        panic!("not a refusal: {got:?}");
    };
    assert_eq!(*why, IntroRefusal::Closed);
    assert_eq!(e.next(), crate::error::NextStep::AskOwner);
    assert_nothing_went_further(&rig, Some(rig.inviter_key()));
}

/// An expired offer's record is the gone mark: refused as expired.
#[tokio::test]
async fn an_expired_offer_is_a_gone_mark_and_the_join_is_refused_as_expired() {
    let rig = Rig::new(Setup::address()).await;
    rig.first_contact_answers();
    rig.skew
        .store(2 * 3_600_000, std::sync::atomic::Ordering::SeqCst);
    let got = rig.phone.join(rig.code.share()).await;
    assert!(
        matches!(
            &got,
            Err(DataError::Introduction {
                why: IntroRefusal::Expired,
                ..
            })
        ),
        "{got:?}"
    );
    assert_nothing_went_further(&rig, Some(rig.inviter_key()));
}

/// With `hint_while_open` off the record outlives the offer, and the join then
/// meets the offer's own refusal: the record joins no one.
#[tokio::test]
async fn a_hint_that_outlives_its_offer_joins_no_one() {
    let rig = Rig::new(Setup {
        policy: IntroPolicy {
            hint_while_open: false,
            ..IntroPolicy::new()
        },
        ..Setup::address()
    })
    .await;
    rig.first_contact_answers();
    rig.laptop.close_offer(&rig.code.offer).await.unwrap();
    let got = rig.phone.join(rig.code.share()).await;
    assert!(
        matches!(
            &got,
            Err(DataError::Introduction {
                why: IntroRefusal::Closed,
                ..
            })
        ),
        "{got:?}"
    );
    assert!(rig.laptop.inner.st.lock().intro.used.is_empty());
    assert_eq!(rig.phone_calls.undialled_keys(), vec![rig.inviter_key()]);
}

/// A code whose fingerprint is not the anchor the record's credentials carry is
/// refused: whoever answers cannot make its own anchor the code's.
#[tokio::test]
async fn a_code_of_another_anchor_is_refused_by_the_record() {
    let rig = Rig::new(Setup::address()).await;
    rig.first_contact_answers();
    let text = short_text(&rig, Some(address()), rig.secret, &[0x42; 10]);
    let got = rig.phone.join(&text).await;
    let why = hint_refusal(&got);
    assert!(why.starts_with("anchor"), "{why}");
    assert_nothing_went_further(&rig, Some(rig.inviter_key()));
}

/// What a tampering reads of the rig: the inviter's key, the offer, and Alice's
/// signed trust context as the record carries it.
struct Parts {
    key: [u8; 32],
    offer: Name,
    context: Bytes,
}

/// A joiner over an address is given the inviter's hint record with `flip`
/// applied to its wire (the packet, the range of its signature value and the
/// bytes to edit): the refusal's reason, the rig, after checking the refusal says
/// what to do and that nothing was dialled, asked or adopted.
async fn tampered(
    flip: impl Fn(&Parts, &Data, std::ops::Range<usize>, &mut Vec<u8>) + Send + Sync + 'static,
) -> (Rig, String) {
    let rig = Rig::new(Setup::address()).await;
    rig.first_contact_answers();
    let parts = Parts {
        key: rig.inviter_key(),
        offer: rig.code.offer.clone(),
        context: rig.alice.signed.clone(),
    };
    rig.net.tamper(move |wire| {
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
    let got = rig.phone.join(rig.code.share()).await;
    let why = hint_refusal(&got);
    let err = got.unwrap_err();
    assert_eq!(
        err.next(),
        crate::error::NextStep::RetryLater,
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
#[tokio::test]
async fn a_record_with_a_flipped_signature_byte_is_refused() {
    let (_, why) = tampered(|_, _, sig, v| v[sig.end - 1] ^= 1).await;
    assert!(why.starts_with("signer"), "{why}");
}

/// The link key flipped.
#[tokio::test]
async fn a_record_with_a_flipped_key_byte_is_refused() {
    let (_, why) = tampered(|p, _, _, v| {
        let at = find(v, &p.key) + 7;
        v[at] ^= 1;
    })
    .await;
    assert!(why.starts_with("signer"), "{why}");
}

/// A candidate's port flipped.
#[tokio::test]
async fn a_record_with_a_flipped_candidate_byte_is_refused() {
    let (_, why) = tampered(|_, _, _, v| {
        let at = find(v, &[0, 192, 0, 2, 7, 0x11, 0x51]) + 6;
        v[at] ^= 1;
    })
    .await;
    assert!(why.starts_with("signer"), "{why}");
}

/// The offer's name flipped: the last octet of its sequence number.
#[tokio::test]
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
#[tokio::test]
async fn a_record_with_flipped_credentials_is_refused() {
    let (_, why) = tampered(|p, _, _, v| {
        let at = find(v, &p.context) + p.context.len() - 1;
        v[at] ^= 1;
    })
    .await;
    assert!(why.starts_with("credentials"), "{why}");
}

/// A record corrupted in flight is the same cause as a corrupted answer
/// (`Forged`, retry): the first join is refused as a hint that does not verify
/// and told to retry, nothing dialled further, and the host's retry — the record
/// now intact — joins.
#[tokio::test]
async fn a_record_corrupted_once_joins_on_the_hosts_retry() {
    let rig = Rig::new(Setup::address()).await;
    rig.first_contact_answers();
    let corrupt = Arc::new(AtomicBool::new(true));
    let flag = Arc::clone(&corrupt);
    rig.net.tamper(move |wire| {
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
    let got = rig.phone.join(rig.code.share()).await;
    let why = hint_refusal(&got);
    assert!(why.starts_with("signer"), "{why}");
    assert_eq!(
        got.unwrap_err().next(),
        crate::error::NextStep::RetryLater,
        "a record corrupted in flight is a retry, as a corrupted answer is"
    );
    assert_nothing_went_further(&rig, Some(rig.inviter_key()));
    let joined = rig
        .phone
        .join(rig.code.share())
        .await
        .expect("the retry joins");
    assert_eq!(joined.folder, rig.folder);
}

/// A record under the token's name that no hint is: another content.
#[tokio::test]
async fn a_packet_that_is_no_hint_record_or_is_named_otherwise_is_refused() {
    let rig = Rig::new(Setup::address()).await;
    rig.first_contact_answers();
    let device = Arc::clone(&rig.laptop.inner);
    rig.net.tamper(move |wire| {
        let data = Data::decode(wire.clone()).ok()?;
        if !is_hint(&data.name) {
            return Some(wire);
        }
        // Signed by the device, but the content is no record.
        device
            .sign(
                DataBuilder::new((*data.name).clone(), b"hello").freshness(Duration::from_secs(5)),
            )
            .ok()
    });
    let got = rig.phone.join(rig.code.share()).await;
    let why = hint_refusal(&got);
    assert!(why.starts_with("wrong record"), "{why}");
    assert_nothing_went_further(&rig, Some(rig.inviter_key()));

    // A genuine record that is not the one asked for: the Consumer does not hand
    // a Data of another name to an Interest, so the check is made on the packet
    // itself, which would also hold for a transport that did.
    let rig = Rig::new(Setup::address()).await;
    let genuine = served(&rig, &hint_of(&rig)).unwrap();
    let fingerprint = Fingerprint::Prefix(alice_fingerprint(&rig)[..10].to_vec());
    let other = crate::intro::hint_name(rig.laptop.name(), &[1; 16]);
    let got = rig
        .phone
        .inner
        .verify_hint(&genuine, &other, rig.laptop.name(), &fingerprint, None)
        .await;
    assert!(
        matches!(&got, Err(HintFault::Bad(why)) if why.starts_with("wrong name")),
        "a record was taken for a name it does not carry"
    );
    let got = rig
        .phone
        .inner
        .verify_hint(
            &genuine,
            &hint_of(&rig),
            rig.laptop.name(),
            &fingerprint,
            None,
        )
        .await;
    assert!(
        got.is_ok(),
        "and the same record under its own name verifies"
    );
}

/// A record signed by another device of the inviter's namespace — a valid chain to
/// the code's anchor, but not the device the code names — is refused.
#[tokio::test]
async fn a_record_signed_by_another_device_of_the_namespace_is_refused() {
    let rig = Rig::new(Setup::address()).await;
    rig.first_contact_answers();
    let other = start(&rig.alice, "/alice/phone", None, &[], None).await;
    let genuine = served(&rig, &hint_of(&rig)).unwrap();
    let crate::intro::HintRecord::Offered {
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
    let record = crate::intro::HintRecord::Offered {
        offer,
        key: link_key,
        candidates,
        relays,
        until,
        credentials: other.inner.credentials().unwrap(),
    };
    let other = Arc::clone(&other.inner);
    rig.net.tamper(move |wire| {
        let data = Data::decode(wire.clone()).ok()?;
        if !is_hint(&data.name) {
            return Some(wire);
        }
        other
            .sign(
                DataBuilder::new((*data.name).clone(), &record.encode())
                    .freshness(Duration::from_secs(5)),
            )
            .ok()
    });
    let got = rig.phone.join(rig.code.share()).await;
    let why = hint_refusal(&got);
    assert!(why.starts_with("signer"), "{why}");
    assert_nothing_went_further(&rig, Some(rig.inviter_key()));
}

/// A record the device itself signed for another offer of its own, presented
/// under this code's token, is refused before an ask is sent: the offer it names
/// is not committed to this code's secret.
#[tokio::test]
async fn a_record_naming_another_offer_is_refused_before_the_ask() {
    let rig = Rig::new(Setup::address()).await;
    rig.first_contact_answers();
    let second = rig
        .laptop
        .offer(
            &rig.folder,
            Offer {
                role: Role::Writer,
                until: Timestamp((rig.laptop.inner.config.clock)().0 + 3_600_000),
                tries: 3,
            },
        )
        .await
        .unwrap();
    let genuine = served(&rig, &hint_of(&rig)).unwrap();
    let crate::intro::HintRecord::Offered {
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
    let record = crate::intro::HintRecord::Offered {
        offer: second.offer.clone(),
        key: link_key,
        candidates,
        relays,
        until,
        credentials,
    };
    let device = Arc::clone(&rig.laptop.inner);
    rig.net.tamper(move |wire| {
        let data = Data::decode(wire.clone()).ok()?;
        if !is_hint(&data.name) {
            return Some(wire);
        }
        device
            .sign(
                DataBuilder::new((*data.name).clone(), &record.encode())
                    .freshness(Duration::from_secs(5)),
            )
            .ok()
    });
    let got = rig.phone.join(rig.code.share()).await;
    let why = hint_refusal(&got);
    assert!(why.starts_with("offer"), "{why}");
    let asked: Vec<Name> = rig
        .net
        .sent()
        .into_iter()
        .map(|(n, _)| n)
        .filter(|n| crate::intro::parse_intro_name(n).is_some())
        .collect();
    assert!(
        asked.is_empty(),
        "an ask was sent for another offer: {asked:?}"
    );
    assert_eq!(rig.phone_calls.undialled_keys(), vec![rig.inviter_key()]);
    assert!(rig.laptop.inner.st.lock().intro.used.is_empty());
}

/// A short code of a device under a namespace the joiner holds under another
/// anchor dials nothing, as every code is judged before a dial.
#[tokio::test]
async fn a_short_code_of_a_device_under_a_held_namespace_of_another_anchor_dials_nothing() {
    let rig = Rig::new(Setup::address()).await;
    rig.first_contact_answers();
    let real = Person::new("/alice");
    rig.phone
        .inner
        .validator
        .adopt_context(Arc::clone(&real.ctx))
        .unwrap();
    let got = rig.phone.join(rig.code.share()).await;
    assert!(
        matches!(
            &got,
            Err(DataError::Introduction {
                why: IntroRefusal::InviterConflict { .. },
                ..
            })
        ),
        "{got:?}"
    );
    assert!(rig.phone_calls.first_dialled().is_empty());
    assert!(rig.net.sent().is_empty());
}
