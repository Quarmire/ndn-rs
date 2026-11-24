//! The hint record of a short code, as the inviter makes and serves it (spec §19.2,
//! §19.5): when an offer makes a short code and publishes its hint, what the record and
//! the gone marks carry and how they are signed, what an unknown token gets (nothing), the
//! few seconds a signed packet is kept, and the token kept across a restart. The joiner's
//! side of the same record is `join_hint_tests`.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_heap::{Readers, Share, Timestamp};
use ndn_packet::Data;
use ndn_security::SecurityManager;
use ndn_sync::DataStore;

use crate::credentials::open_credentials;
use crate::hint::HINT_CACHE;
use crate::host::{HintCandidate, HintKind, LinkHint, Offer, Role};
use crate::policy::{IntroPolicy, IntroRefusal};
use crate::proofs::{SECRET_LEN, hint_token, keyed_fingerprint};
use crate::short::{Contact, ShortCode};
use crate::store;
use crate::test_kit::{Calls, Device, Person, Setup, alice_offers, key, n, notebook, skewed};
use crate::wire::{HINT_TOKEN_LEN, HintRecord, OfferId, hint_name, hint_prefix, parse_offer_name};

/// How a rig's inviter is set up.
struct Spec {
    /// Candidate addresses its host gives for a link hint.
    candidates: Vec<&'static str>,
    /// Its namespace advertises the relay `/alice/node/relay`.
    relay: bool,
    /// The inviter's introduction policy.
    policy: IntroPolicy,
}

impl Spec {
    /// An inviter whose host listens at one public IPv4 address.
    fn address() -> Spec {
        Spec {
            candidates: vec!["192.0.2.7:4433"],
            relay: false,
            policy: IntroPolicy::new(),
        }
    }

    /// An inviter that listens nowhere a joiner can dial, behind a relay.
    fn relayed() -> Spec {
        Spec {
            candidates: Vec::new(),
            relay: true,
            ..Spec::address()
        }
    }

    /// An inviter with no first contact at all.
    fn nowhere() -> Spec {
        Spec {
            candidates: Vec::new(),
            ..Spec::address()
        }
    }
}

/// Alice's laptop, an offer of her notebook made, its host giving the hint `spec` says.
struct Rig {
    laptop: Device,
    alice: Person,
    calls: Arc<Calls>,
    skew: Arc<AtomicU64>,
    code: crate::host::Code,
    secret: [u8; SECRET_LEN],
}

impl Rig {
    async fn new(spec: Spec) -> Rig {
        let alice = if spec.relay {
            Person::relayed("/alice", "/alice/node/relay")
        } else {
            Person::new("/alice")
        };
        let (clock, skew) = skewed();
        let calls = Arc::new(Calls::default());
        let laptop = Setup::new(&alice, "/alice/laptop")
            .clock(Arc::clone(&clock))
            .calls(Arc::clone(&calls))
            .policy(spec.policy)
            .start()
            .await;
        if !spec.candidates.is_empty() {
            *calls.hint.lock().unwrap() = Some(LinkHint {
                key: laptop.invites.inner().own_key_digest(),
                candidates: spec
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
        Rig {
            laptop: offered.laptop,
            alice: offered.alice,
            calls,
            skew,
            code: offered.code,
            secret: offered.secret,
        }
    }

    /// The key the inviter's link proves.
    fn inviter_key(&self) -> [u8; 32] {
        self.laptop.invites.inner().own_key_digest()
    }

    fn id(&self) -> OfferId {
        parse_offer_name(&self.code.offer).unwrap().1
    }

    /// The token of the rig's offer.
    fn token(&self) -> [u8; HINT_TOKEN_LEN] {
        hint_token(&self.secret)
    }

    /// The hint record's name of the rig's offer.
    fn hint(&self) -> Name {
        hint_name(&self.laptop.name, &self.token())
    }

    /// What the inviter's device serves for `name`, decoded.
    fn served(&self, name: &Name) -> Option<Data> {
        self.laptop
            .invites
            .inner()
            .hint_packet(name)
            .map(|wire| Data::decode(wire).unwrap())
    }

    /// The anchor fingerprint of Alice's namespace.
    fn fingerprint(&self) -> [u8; 32] {
        let anchors = self.alice.ctx.anchors();
        let anchor = anchors.iter().next().expect("an anchor");
        ndn_security::anchor_fingerprint(anchor.value())
    }

    /// A short code written for the inviter: its device, `contact`, the rig's secret and
    /// the `fingerprint` octets, as a person would read them.
    fn short_text(&self, contact: Option<Contact>, fingerprint: &[u8]) -> String {
        ShortCode {
            device: self.laptop.name.clone(),
            contact,
            secret: self.secret,
            fingerprint: fingerprint.to_vec(),
        }
        .encode()
        .unwrap()
    }

    async fn close(&self) {
        self.laptop
            .invites
            .close_offer(&self.code.offer)
            .await
            .unwrap();
    }
}

/// The record a hint Data carries.
fn record_of(data: &Data) -> HintRecord {
    HintRecord::decode(data.content().unwrap().clone(), true).unwrap()
}

// ---- the offer: the short code and what it publishes (§1, §2, §7) --------------------------------

/// The short code is one line of words and the two text tokens, fits three lines of 98
/// columns, is what `share()` shows, and names an address.
#[tokio::test]
async fn an_offer_with_an_address_makes_a_short_code_that_fits_three_lines_and_reads_as_words() {
    let rig = Rig::new(Spec::address()).await;
    let short = rig.code.short.clone().expect("a short code");
    assert_eq!(rig.code.short_why, None);
    assert_eq!(rig.code.share(), short);
    let columns = short.chars().count();
    assert!(columns <= 3 * 98, "{columns} columns: {short}");
    let tokens: Vec<&str> = short.split_whitespace().collect();
    assert_eq!(tokens[0], "/alice/laptop");
    assert_eq!(tokens[1], "192.0.2.7:4433");
    assert_eq!(tokens.len(), 2 + 20, "20 words for a named namespace");
    let read = ShortCode::parse(&short, false).expect("it reads back");
    assert_eq!(read.device, n("/alice/laptop"));
    assert_eq!(read.secret, rig.secret);
    assert_eq!(
        read.fingerprint,
        keyed_fingerprint(&rig.secret, &rig.fingerprint()),
        "a named namespace's code carries the fingerprint keyed by its secret"
    );
    assert_ne!(
        read.fingerprint,
        rig.fingerprint()[..10],
        "not the anchor's plain first octets"
    );
    assert!(
        rig.code.link.contains("ndn-trust://intro/"),
        "the link is still made"
    );
}

/// A namespace that advertises a relay and a host with nothing to dial: the relay is the
/// first contact.
#[tokio::test]
async fn an_offer_with_only_a_relay_names_the_relay_as_first_contact() {
    let rig = Rig::new(Spec::relayed()).await;
    let short = rig.code.short.clone().expect("a short code");
    let tokens: Vec<&str> = short.split_whitespace().collect();
    assert_eq!(&tokens[..2], ["/alice/laptop", "/alice/node/relay"]);
    assert!(short.chars().count() <= 3 * 98);
}

/// The first contact is the first of the hint's order (dialable candidates, then relays)
/// whose line fits `short_width`: a worst-case IPv6 address that makes the line too wide
/// gives way to the relay; when none fits there is no short code and the reason names the
/// device. The width is set where the address sometimes does not fit and the relay does;
/// every offer is checked against the two lines its own secret makes, and the branch that
/// matters must occur.
#[tokio::test]
async fn a_contact_that_makes_the_line_too_wide_gives_way_to_the_next_that_fits() {
    const WIDTH: usize = 170;
    let worst: &'static str = "[2001:db8:1234:5678:9abc:def0:1234:5678]:65535";
    let mut seen_relay = false;
    let mut seen_address = false;
    for _ in 0..40 {
        let rig = Rig::new(Spec {
            candidates: vec![worst],
            relay: true,
            policy: IntroPolicy {
                short_width: WIDTH,
                ..IntroPolicy::new()
            },
        })
        .await;
        let fp = rig.fingerprint();
        let width = |contact| {
            rig.short_text(Some(contact), &keyed_fingerprint(&rig.secret, &fp))
                .chars()
                .count()
        };
        let by_address = width(Contact::Address(worst.parse().unwrap()));
        let by_relay = width(Contact::Relay(n("/alice/node/relay")));
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
                assert!(rig.served(&rig.hint()).is_some());
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

/// No short code, and nothing of a hint published, when the policy is off, when the host
/// gives no first contact, when the only address is this machine's, and when the line is
/// too wide: each says why.
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
            Spec {
                policy: policy_off,
                ..Spec::address()
            },
            "short_code",
        ),
        (Spec::nowhere(), "first contact"),
        (
            Spec {
                candidates: vec!["127.0.0.1:4433"],
                ..Spec::address()
            },
            "first contact",
        ),
        (
            Spec {
                policy: too_wide,
                ..Spec::address()
            },
            "short_width",
        ),
    ];
    for (spec, says) in cases {
        let rig = Rig::new(spec).await;
        assert_eq!(rig.code.short, None);
        let why = rig.code.short_why.clone().expect("it says why");
        assert!(why.contains(says), "{says:?} is not in {why:?}");
        assert_eq!(rig.code.share(), rig.code.link);
        assert!(
            rig.served(&rig.hint()).is_none(),
            "a hint record is served for an offer with no short code ({why})"
        );
        assert!(
            !rig.laptop.invites.inner().intro_carries(&rig.hint()),
            "the link carries the hint name of an offer with no short code"
        );
        assert!(
            !rig.laptop.store.contains(&store::hint_key(&rig.id())),
            "a hint token is kept for an offer with no short code"
        );
    }
}

/// A device of one machine's addresses, with the policy that allows them.
#[tokio::test]
async fn a_local_address_is_a_first_contact_only_under_the_policy() {
    let rig = Rig::new(Spec {
        candidates: vec!["127.0.0.1:4433"],
        policy: IntroPolicy {
            local_candidates: true,
            ..IntroPolicy::new()
        },
        ..Spec::address()
    })
    .await;
    let short = rig
        .code
        .short
        .clone()
        .expect("a short code under the policy");
    assert_eq!(short.split_whitespace().nth(1), Some("127.0.0.1:4433"));
}

/// A self-certifying namespace: the whole fingerprint, 36 words, and `161=*` where the
/// device's component is the anchor's fingerprint.
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
    let laptop = Setup::new(&person, &device)
        .calls(Arc::clone(&calls))
        .start()
        .await;
    *calls.hint.lock().unwrap() = Some(LinkHint {
        key: laptop.invites.inner().own_key_digest(),
        candidates: vec![HintCandidate {
            kind: HintKind::Host,
            addr: "[2001:db8:1:2:3:4:5:6]:4433".parse().unwrap(),
        }],
    });
    let space: Name = format!("{ns}/32=data/notebook").parse().unwrap();
    laptop
        .node
        .create(
            &space,
            Share {
                readers: Readers::Persons(vec![ns.clone()]),
                writers: vec![ns.clone()],
            },
        )
        .await
        .unwrap();
    let code = laptop
        .invites
        .offer(
            &space,
            Offer {
                role: Role::Writer,
                until: Timestamp(laptop.node.now().0 + 3_600_000),
                tries: 3,
            },
        )
        .await
        .unwrap();
    let short = code.short.clone().expect("a short code");
    let columns = short.chars().count();
    assert!(columns <= 3 * 98, "{columns} columns: {short}");
    assert!(short.starts_with("/user/161=*/laptop "), "{short}");
    assert_eq!(short.split_whitespace().count(), 2 + 36);
    let read = ShortCode::parse(&short, false).unwrap();
    assert_eq!(read.device, laptop.name);
    assert_eq!(read.fingerprint.len(), 32);
}

// ---- serving: the record, the gone marks, the token (§2) -----------------------------------------

/// The record is signed by the device key, bound to the offer, and carries what a joiner
/// needs: the host's key and addresses, the credentials, the expiry.
#[tokio::test]
async fn the_hint_record_is_signed_by_the_device_and_carries_the_hint_and_credentials() {
    let rig = Rig::new(Spec::address()).await;
    let data = rig.served(&rig.hint()).expect("served for its token");
    assert_eq!(*data.name, rig.hint());
    let HintRecord::Offered {
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
        rig.laptop.invites.inner().state.lock().offers[&rig.id()]
            .body
            .until
    );
    let opened = open_credentials(&credentials)
        .await
        .expect("credentials open");
    assert_eq!(
        opened.signer(&data).await.map(|(k, _)| k),
        Some(key(&rig.laptop.name)),
        "signed by the device key, chained to the anchor"
    );
    let fresh = data.meta_info().and_then(|m| m.freshness_period);
    assert_eq!(fresh, Some(HINT_CACHE), "a record is held for HINT_CACHE");
}

/// The relays of the namespace are in the record, at most eight.
#[tokio::test]
async fn the_hint_record_names_the_namespaces_relays() {
    let rig = Rig::new(Spec::relayed()).await;
    let data = rig.served(&rig.hint()).expect("served");
    let HintRecord::Offered { relays, .. } = record_of(&data) else {
        panic!("a record");
    };
    assert_eq!(relays, [n("/alice/node/relay")]);
}

/// A token that is not one of this device's offers' is not answered: not by a record, not
/// by a gone mark; nor is another device's hint name.
#[tokio::test]
async fn an_unknown_token_gets_no_answer_and_no_gone_mark() {
    let rig = Rig::new(Spec::address()).await;
    let device = rig.laptop.name.clone();
    for token in [[0u8; 16], [9; 16], hint_token(&[7; 16])] {
        assert!(
            rig.served(&hint_name(&device, &token)).is_none(),
            "answered for token {token:?}"
        );
    }
    let other = hint_name(&n("/alice/phone"), &rig.token());
    assert!(
        rig.served(&other).is_none(),
        "answered for another device's name"
    );
    assert!(
        rig.served(&hint_prefix(&device)).is_none(),
        "answered for the hint prefix"
    );
    assert!(
        rig.served(&rig.hint()).is_some(),
        "and the real one still is"
    );
}

/// Closed: a signed gone mark; expired by the device's clock: a gone mark.
#[tokio::test]
async fn a_closed_or_expired_offer_is_answered_by_a_signed_gone_mark() {
    let rig = Rig::new(Spec::address()).await;
    rig.close().await;
    let data = rig.served(&rig.hint()).expect("a closed offer is answered");
    assert!(matches!(
        record_of(&data),
        HintRecord::Gone {
            why: IntroRefusal::Closed,
            ..
        }
    ));
    let own = open_credentials(
        &crate::credentials::credentials(
            &rig.laptop.invites.inner().node,
            &*rig.laptop.invites.inner().host,
        )
        .unwrap(),
    )
    .await
    .unwrap();
    assert!(
        own.signer(&data).await.is_some(),
        "the gone mark is signed by the device"
    );

    let rig = Rig::new(Spec::address()).await;
    rig.skew.store(2 * 3_600_000, Ordering::SeqCst);
    let data = rig
        .served(&rig.hint())
        .expect("an expired offer is answered");
    assert!(matches!(
        record_of(&data),
        HintRecord::Gone {
            why: IntroRefusal::Expired,
            ..
        }
    ));
}

/// The person an offer admitted being removed from the space closes the offer: its hint
/// is a gone mark too, derived from the members in force.
#[tokio::test]
async fn the_removal_of_the_member_an_offer_admitted_ends_its_record() {
    let rig = Rig::new(Spec::address()).await;
    let bob = Person::new("/bob");
    let bob_phone = crate::test_kit::start(&bob, "/bob/phone").await;
    let got = crate::test_kit::answer(
        &rig.laptop,
        crate::test_kit::ask(&bob_phone, &rig.laptop, &rig.code.offer, &rig.secret, &[]),
    )
    .await;
    assert!(crate::test_kit::accepted(&got), "bob was answered {got:?}");
    crate::test_kit::heap(&rig.laptop, &notebook())
        .change(ndn_heap::MembersChange {
            remove: vec![n("/bob")],
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(matches!(
        record_of(&rig.served(&rig.hint()).unwrap()),
        HintRecord::Gone {
            why: IntroRefusal::Closed,
            ..
        }
    ));
}

/// `hint_while_open = false`: the record is served until the device stops, past a close
/// and past the expiry; the offer itself still answers by its own rules.
#[tokio::test]
async fn with_the_policy_off_the_record_is_served_after_close_and_expiry() {
    let rig = Rig::new(Spec {
        policy: IntroPolicy {
            hint_while_open: false,
            ..IntroPolicy::new()
        },
        ..Spec::address()
    })
    .await;
    rig.close().await;
    rig.skew.store(2 * 3_600_000, Ordering::SeqCst);
    let data = rig.served(&rig.hint()).expect("served");
    assert!(matches!(record_of(&data), HintRecord::Offered { .. }));
}

/// A signed record is answered again as it is for a few seconds (one signature), and is
/// made afresh from the host's current hint after.
#[tokio::test(start_paused = true)]
async fn a_record_is_cached_a_few_seconds_and_then_made_from_the_hosts_hint_again() {
    let rig = Rig::new(Spec::address()).await;
    let name = rig.hint();
    let inner = rig.laptop.invites.inner().clone();
    let first = inner.hint_packet(&name).unwrap();
    let signed = rig.laptop.node.signatures();
    assert_eq!(inner.hint_packet(&name).unwrap(), first);
    assert_eq!(
        rig.laptop.node.signatures(),
        signed,
        "a second request signed again"
    );
    // The host's address moves.
    rig.calls.hint.lock().unwrap().as_mut().unwrap().candidates[0].addr =
        "192.0.2.99:4433".parse().unwrap();
    tokio::time::advance(HINT_CACHE + Duration::from_secs(1)).await;
    let data = Data::decode(inner.hint_packet(&name).unwrap()).unwrap();
    let HintRecord::Offered { candidates, .. } = record_of(&data) else {
        panic!("a record");
    };
    assert_eq!(candidates[0].addr.to_string(), "192.0.2.99:4433");
    assert!(rig.laptop.node.signatures() > signed);
}

/// A closed offer is a gone mark at once, whatever the cache holds.
#[tokio::test]
async fn closing_an_offer_ends_the_record_at_once() {
    let rig = Rig::new(Spec::address()).await;
    let name = rig.hint();
    assert!(matches!(
        record_of(&rig.served(&name).unwrap()),
        HintRecord::Offered { .. }
    ));
    rig.close().await;
    assert!(matches!(
        record_of(&rig.served(&name).unwrap()),
        HintRecord::Gone {
            why: IntroRefusal::Closed,
            ..
        }
    ));
}

/// The token is kept durably and read back at a start: a restarted inviter serves the
/// record of the offer it holds; a token note that is not wrapped to its key publishes
/// nothing.
#[tokio::test]
async fn the_token_is_kept_across_a_restart_and_a_forged_note_publishes_nothing() {
    let disk = crate::test_kit::DiskStore::new();
    let alice = Person::new("/alice");
    let (clock, _skew) = skewed();
    let calls = Arc::new(Calls::default());
    let laptop = Setup::new(&alice, "/alice/laptop")
        .clock(Arc::clone(&clock))
        .calls(Arc::clone(&calls))
        .store(Arc::clone(&disk) as Arc<dyn DataStore>)
        .start()
        .await;
    *calls.hint.lock().unwrap() = Some(LinkHint {
        key: laptop.invites.inner().own_key_digest(),
        candidates: vec![HintCandidate {
            kind: HintKind::Host,
            addr: "192.0.2.7:4433".parse().unwrap(),
        }],
    });
    let keys = Arc::clone(&laptop.keys);
    let offered = alice_offers(laptop, alice, Role::Writer).await;
    let (secret, id) = (
        offered.secret,
        parse_offer_name(&offered.code.offer).unwrap().1,
    );
    let name = hint_name(&n("/alice/laptop"), &hint_token(&secret));
    assert!(offered.code.short.is_some());
    // The power goes: only what a flush covered is left. The token's note was durable
    // before the code was returned.
    let image = disk.crash();
    let alice = offered.alice;
    let rig = Arc::try_unwrap(offered.laptop)
        .ok()
        .expect("nothing else holds the laptop");
    rig.node.close().await;
    drop(rig.invites);

    let restart = |store: Arc<dyn DataStore>| {
        let (keys, clock, calls, alice) = (
            Arc::clone(&keys),
            Arc::clone(&clock),
            Arc::clone(&calls),
            &alice,
        );
        async move {
            Setup::new(alice, "/alice/laptop")
                .keys(keys)
                .clock(clock)
                .calls(calls)
                .store(store)
                .start()
                .await
        }
    };
    let restarted = restart(Arc::clone(&image)).await;
    assert!(
        restarted.invites.inner().hint_packet(&name).is_some(),
        "a restarted inviter does not serve its open offer's hint"
    );
    let note = store::hint_key(&id);
    assert!(image.get(&note).is_some(), "the token was kept durably");
    let rig = Arc::try_unwrap(restarted).ok().unwrap();
    rig.node.close().await;
    drop(rig.invites);

    image.insert(note, Bytes::from_static(b"not a wrapped key"));
    let forged = restart(image).await;
    assert!(
        forged.invites.inner().hint_packet(&name).is_none(),
        "a note that is not wrapped to the device's key was read"
    );
}

// ---- the introduction link (round 4 L4) ------------------------------------------------------------

/// A link dialled for an introduction carries the hint record of an own offer's token and
/// nothing else of the device: not a log entry, not another device's hint, not an unknown
/// token, not a longer name.
#[tokio::test]
async fn the_link_carries_the_hint_of_an_own_token_and_nothing_else_of_the_device() {
    let rig = Rig::new(Spec::address()).await;
    let inner = rig.laptop.invites.inner().clone();
    let device = rig.laptop.name.clone();
    let hint = rig.hint();
    assert!(inner.intro_carries(&hint));
    assert!(
        inner.intro_carries(&rig.code.offer),
        "the offer packet is still carried"
    );
    for refused in [
        hint_prefix(&device),
        hint_name(&device, &[3; 16]),
        hint_name(&n("/alice/phone"), &rig.token()),
        hint.clone().append("more"),
        n("/alice/laptop/32=log/alice/32=data/notebook/seq=1"),
        n("/alice/laptop/32=sum"),
        device.clone().append("32=head").append("x"),
    ] {
        assert!(!inner.intro_carries(&refused), "{refused} is carried");
    }
    // A closed offer's hint is carried: its answer is the gone mark.
    rig.close().await;
    assert!(inner.intro_carries(&hint));
}

// ---- what the inviter keeps of its served records (I2) ---------------------------------------------

/// Closing an offer drops the signed packet kept for its token at once (the token stays:
/// the offer is still held, and its gone mark is still served); the next ask signs and
/// keeps the gone mark.
#[tokio::test]
async fn closing_an_offer_drops_its_served_packet_and_keeps_its_token() {
    let rig = Rig::new(Spec::address()).await;
    let token = rig.token();
    let inner = rig.laptop.invites.inner().clone();
    rig.served(&rig.hint()).expect("served");
    assert!(inner.state.lock().hint_served.contains_key(&token));

    rig.close().await;
    {
        let st = inner.state.lock();
        assert!(
            st.hint_served.is_empty(),
            "the closed offer's record is still kept"
        );
        assert_eq!(
            st.hints.get(&token),
            Some(&rig.id()),
            "the token is the offer's while it is held: a gone mark is still served"
        );
    }
    let gone = rig.served(&rig.hint()).expect("a gone mark");
    assert!(matches!(
        record_of(&gone),
        HintRecord::Gone {
            why: IntroRefusal::Closed,
            ..
        }
    ));
    assert_eq!(
        gone.meta_info().and_then(|m| m.freshness_period),
        Some(Duration::ZERO),
        "a gone mark must not sit in a cache"
    );
}

/// A served packet is kept [`HINT_CACHE`] and no longer: the next hint Interest the device
/// answers or refuses sweeps what lapsed, an expired offer's gone mark with it, while the
/// offer's token stays for as long as the offer is held.
#[tokio::test(start_paused = true)]
async fn a_served_packet_is_dropped_once_its_time_lapses_and_the_token_stays() {
    let rig = Rig::new(Spec::address()).await;
    let token = rig.token();
    let device = rig.laptop.name.clone();
    let inner = rig.laptop.invites.inner().clone();
    rig.served(&rig.hint()).expect("served");
    assert_eq!(inner.state.lock().hint_served.len(), 1);

    // The offer expires by the device's clock: a gone mark replaces the record.
    rig.skew.store(2 * 3_600_000, Ordering::SeqCst);
    let gone = rig.served(&rig.hint()).expect("a gone mark");
    assert!(matches!(
        record_of(&gone),
        HintRecord::Gone {
            why: IntroRefusal::Expired,
            ..
        }
    ));
    assert_eq!(inner.state.lock().hint_served.len(), 1);

    tokio::time::advance(HINT_CACHE + Duration::from_secs(1)).await;
    // An Interest for a token nobody holds is a Nack, and sweeps what lapsed.
    assert!(rig.served(&hint_name(&device, &[0xEE; 16])).is_none());
    {
        let st = inner.state.lock();
        assert!(
            st.hint_served.is_empty(),
            "an expired offer's gone mark is kept past its time"
        );
        assert_eq!(st.hints.get(&token), Some(&rig.id()));
    }
    assert!(
        matches!(
            record_of(&rig.served(&rig.hint()).expect("still answered")),
            HintRecord::Gone {
                why: IntroRefusal::Expired,
                ..
            }
        ),
        "the expired offer's token still gets its gone mark"
    );
}
