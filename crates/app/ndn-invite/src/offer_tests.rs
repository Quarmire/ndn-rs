//! The offering side of an introduction (spec §19): devices of strangers' namespaces,
//! an ask built as `join` builds it and handed to the offering device's `answer_intro`.
//! What the network cases (conformance `i1`…) cannot see: what goes into the
//! validator's cache, a joiner whose key is its own anchor, a host that does not adopt,
//! a crowd of asks, what is durable before a reply, and the offer as the packet the
//! extension serves.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use ndn_app::AppError;
use ndn_foundation_types::Name;
use ndn_heap::{Clock, Timestamp};
use ndn_packet::Data;
use ndn_packet::encode::InterestBuilder;
use ndn_security::{SecurityManager, SignedTrustContext, ValidationResult};
use ndn_sync::DataStore;
use tokio::sync::{Notify, Semaphore};
use tokio_util::sync::CancellationToken;

use crate::error::InviteError;
use crate::host::{Offer, Role};
use crate::policy::{IntroPolicy, IntroRefusal};
use crate::proofs::SECRET_LEN;
use crate::store;
use crate::test_kit::{
    Calls, Device, Net, Offered, Person, Setup, accepted, alice, alice_offers, answer, ask, heap,
    key, n, notebook, skewed, start,
};
use crate::wire::{IntroRecord, OfferId, Outcome, offer_name, offer_prefix, parse_offer_name};

#[tokio::test]
async fn a_joiner_whose_key_is_its_own_anchor_is_answered() {
    let a = alice().await;
    // Carol's phone key is her namespace's anchor: no certificate to show.
    let phone = n("/carol/phone");
    let keys = Arc::new(SecurityManager::new());
    let k = keys.generate_ed25519(key(&phone)).unwrap();
    let carol = Person::rooted("/carol", &keys, &k);
    let carol_phone = Setup::new(&carol, "/carol/phone").keys(keys).start().await;
    let got = answer(
        &a.laptop,
        ask(&carol_phone, &a.laptop, &a.offer(), &a.secret, &[]),
    )
    .await;
    assert!(
        accepted(&got),
        "a joiner whose key is its anchor was answered {got:?}"
    );
}

#[tokio::test]
async fn only_the_certificates_of_the_verified_chain_go_into_the_validator() {
    let a = alice().await;
    let bob = Person::new("/bob");
    let bob_phone = start(&bob, "/bob/phone").await;
    // Bob also presents a certificate of a key under Alice's name, signed by his own
    // root: on no chain of his, it must not be cached.
    let planted_key = n("/alice/laptop/KEY/9");
    let planted = bob.certify(&planted_key, &[7u8; 32]).await;
    let got = answer(
        &a.laptop,
        ask(&bob_phone, &a.laptop, &a.offer(), &a.secret, &[planted]),
    )
    .await;
    assert!(accepted(&got), "bob was answered {got:?}");
    let cache = a.laptop.validator.cert_cache();
    assert!(
        cache.all(&planted_key).is_empty(),
        "a certificate on no verified chain was cached"
    );
    assert!(
        cache.get_valid(&key(&n("/bob/phone"))).is_some(),
        "the asker's own certificate was not cached"
    );
}

/// Bob's phone asks with credentials carrying his namespace's version 1, whose key his
/// version 2 — the one Alice's laptop holds — revokes. Its proof verifies under the
/// context the credentials carry, but the device judges it by what it holds after its
/// host's adoption: refused.
#[tokio::test]
async fn an_ask_by_a_key_the_held_version_revokes_is_refused() {
    let a = alice().await;
    let bob = Person::new("/bob");
    let bob_phone = start(&bob, "/bob/phone").await;
    let v2 = SignedTrustContext::hierarchical(n("/bob"))
        .with_version(2)
        .with_revocation(key(&n("/bob/phone")));
    let anchor = bob.ctx.anchors().iter().next().unwrap().value().clone();
    assert!(v2.add_anchor(anchor));
    a.laptop.validator.adopt_context(Arc::new(v2)).unwrap();
    let got = answer(
        &a.laptop,
        ask(&bob_phone, &a.laptop, &a.offer(), &a.secret, &[]),
    )
    .await;
    assert!(
        matches!(got, Some(Outcome::Refused(IntroRefusal::Conflict))),
        "a key the held version revokes was answered {got:?}"
    );
}

#[tokio::test]
async fn an_offer_is_not_spent_when_the_host_does_not_adopt_the_asker() {
    let alice_person = Person::new("/alice");
    let laptop = Setup::new(&alice_person, "/alice/laptop")
        .refusing(&["/bob"])
        .start()
        .await;
    let a = alice_offers(laptop, alice_person, Role::Writer).await;
    let bob = Person::new("/bob");
    let bob_phone = start(&bob, "/bob/phone").await;
    let got = answer(
        &a.laptop,
        ask(&bob_phone, &a.laptop, &a.offer(), &a.secret, &[]),
    )
    .await;
    assert!(
        got.is_none(),
        "bob, whose anchor the host refuses, was answered {got:?}"
    );
    assert!(
        !heap(&a.laptop, &notebook())
            .members()
            .writers
            .contains(&n("/bob")),
        "bob is listed though the host refused his anchor"
    );
    let carol = Person::new("/carol");
    let carol_phone = start(&carol, "/carol/phone").await;
    let got = answer(
        &a.laptop,
        ask(&carol_phone, &a.laptop, &a.offer(), &a.secret, &[]),
    )
    .await;
    assert!(
        accepted(&got),
        "the offer was spent by an adoption that failed: carol was answered {got:?}"
    );
}

/// Spec §19.2: a closed offer admits no one new, and still answers a retry of the writer
/// it admitted — its answer lost — until it expires. Another key is `Closed`; once the
/// offer expired its user is `Expired`.
#[tokio::test]
async fn a_closed_offer_admits_no_one_new_yet_answers_the_one_it_admitted_until_it_expires() {
    let (clock, skew) = skewed();
    let alice_person = Person::new("/alice");
    let laptop = Setup::new(&alice_person, "/alice/laptop")
        .clock(clock)
        .start()
        .await;
    let a = alice_offers(laptop, alice_person, Role::Writer).await;
    let bob = Person::new("/bob");
    let bob_phone = start(&bob, "/bob/phone").await;
    let carol = Person::new("/carol");
    let carol_phone = start(&carol, "/carol/phone").await;
    // Bob's answer is lost: the host closes the offer as soon as it sees the new member,
    // and Bob asks again.
    let first = answer(
        &a.laptop,
        ask(&bob_phone, &a.laptop, &a.offer(), &a.secret, &[]),
    )
    .await;
    assert!(accepted(&first), "bob was answered {first:?}");
    a.laptop.invites.close_offer(&a.offer()).await.unwrap();
    let again = answer(
        &a.laptop,
        ask(&bob_phone, &a.laptop, &a.offer(), &a.secret, &[]),
    )
    .await;
    assert_eq!(
        again, first,
        "the user of a closed offer asking again was not answered the acceptance it was given"
    );
    // Another key is refused as closed, even with the right secret.
    let other = answer(
        &a.laptop,
        ask(&carol_phone, &a.laptop, &a.offer(), &a.secret, &[]),
    )
    .await;
    assert!(
        matches!(other, Some(Outcome::Refused(IntroRefusal::Closed))),
        "another key asking a closed offer was answered {other:?}"
    );
    // Past its expiry the offer answers nobody, its user included.
    skew.store(2 * 3_600_000, Ordering::SeqCst);
    let late = answer(
        &a.laptop,
        ask(&bob_phone, &a.laptop, &a.offer(), &a.secret, &[]),
    )
    .await;
    assert!(
        matches!(late, Some(Outcome::Refused(IntroRefusal::Expired))),
        "the user of a closed offer asking after its expiry was answered {late:?}"
    );
}

/// An offer closed before anyone used it admits no one, whatever the key and the secret.
#[tokio::test]
async fn an_offer_closed_unused_refuses_every_ask() {
    let a = alice().await;
    let bob = Person::new("/bob");
    let bob_phone = start(&bob, "/bob/phone").await;
    a.laptop.invites.close_offer(&a.offer()).await.unwrap();
    let got = answer(
        &a.laptop,
        ask(&bob_phone, &a.laptop, &a.offer(), &a.secret, &[]),
    )
    .await;
    assert!(
        matches!(got, Some(Outcome::Refused(IntroRefusal::Closed))),
        "an unused closed offer was answered {got:?}"
    );
}

/// Spec §19.2, §19.7: the members' removal of the person an offer admitted closes the
/// offer, derived from the members in force: its user is answered as `close_offer` does
/// — what it was given, kept — and admitted nowhere: no members entry is signed again.
#[tokio::test]
async fn the_removal_of_the_member_closes_the_offer_yet_still_answers_it_and_never_readmits_it() {
    let a = alice().await;
    let space = notebook();
    let bob = Person::new("/bob");
    let bob_phone = start(&bob, "/bob/phone").await;
    let carol = Person::new("/carol");
    let carol_phone = start(&carol, "/carol/phone").await;
    let first = answer(
        &a.laptop,
        ask(&bob_phone, &a.laptop, &a.offer(), &a.secret, &[]),
    )
    .await;
    assert!(accepted(&first), "bob was answered {first:?}");
    heap(&a.laptop, &space)
        .change(ndn_heap::MembersChange {
            remove: vec![n("/bob")],
            ..Default::default()
        })
        .await
        .unwrap();
    // A new key finds the offer closed, not merely used.
    let other = answer(
        &a.laptop,
        ask(&carol_phone, &a.laptop, &a.offer(), &a.secret, &[]),
    )
    .await;
    assert!(
        matches!(other, Some(Outcome::Refused(IntroRefusal::Closed))),
        "another key asking the offer of a removed member was answered {other:?}"
    );
    let signed = a.laptop.node.signatures();
    let again = answer(
        &a.laptop,
        ask(&bob_phone, &a.laptop, &a.offer(), &a.secret, &[]),
    )
    .await;
    assert_eq!(
        again, first,
        "the removed member's retry was not answered as kept"
    );
    assert!(
        !heap(&a.laptop, &space)
            .members()
            .writers
            .contains(&n("/bob")),
        "the removed member was admitted again"
    );
    assert_eq!(
        a.laptop.node.signatures(),
        signed,
        "answering the removed member's retry signed something: it was admitted again"
    );
}

/// Only the device that made an offer closes it.
#[tokio::test]
async fn only_the_device_that_made_an_offer_closes_it() {
    let a = alice().await;
    let elsewhere = offer_name(&n("/alice/phone"), &[1; 16]);
    assert!(matches!(
        a.laptop.invites.close_offer(&elsewhere).await,
        Err(InviteError::BadRequest { .. })
    ));
    let unknown = offer_name(&n("/alice/laptop"), &[2; 16]);
    assert!(
        matches!(
            a.laptop.invites.close_offer(&unknown).await,
            Err(InviteError::BadRequest { .. })
        ),
        "an offer this device never made was closed"
    );
    assert!(matches!(
        a.laptop.invites.close_offer(&n("/alice/laptop")).await,
        Err(InviteError::BadRequest { .. })
    ));
}

#[tokio::test]
async fn asks_beyond_the_queue_get_no_answer_at_once() {
    let started = Arc::new(Notify::new());
    let gate = Arc::new(Semaphore::new(0));
    let alice_person = Person::new("/alice");
    let laptop = Setup::new(&alice_person, "/alice/laptop")
        .holding(Arc::clone(&started), Arc::clone(&gate))
        .start()
        .await;
    let a = alice_offers(laptop, alice_person, Role::Writer).await;
    let bob = Person::new("/bob");
    let bob_phone = start(&bob, "/bob/phone").await;
    // Bob's ask is judged, and held at the host's adoption.
    let first = ask(&bob_phone, &a.laptop, &a.offer(), &a.secret, &[]);
    let held = {
        let laptop = Arc::clone(&a.laptop);
        tokio::spawn(async move { answer(&laptop, first).await })
    };
    started.notified().await;
    // As many more ask meanwhile as the device holds at once: past what it holds, an ask
    // is not kept waiting.
    let crowd = a.laptop.invites.inner().policy.asks_queued;
    let mut asks = tokio::task::JoinSet::new();
    for _ in 0..crowd {
        let one = ask(&bob_phone, &a.laptop, &a.offer(), &a.secret, &[]);
        let laptop = Arc::clone(&a.laptop);
        asks.spawn(async move { answer(&laptop, one).await });
    }
    match tokio::time::timeout(Duration::from_secs(5), asks.join_next()).await {
        Ok(Some(got)) => assert!(got.unwrap().is_none(), "an ask past the queue was answered"),
        _ => panic!("every one of {crowd} asks waited behind an ask held in judgement"),
    }
    gate.add_permits(1);
    assert!(accepted(&held.await.unwrap()));
}

// ---- the offer is a packet the extension serves ------------------------------------------------

/// What `fetcher` gets for `name`, asked once and given two seconds.
async fn fetch(fetcher: &Device, name: &Name) -> Result<Data, AppError> {
    fetcher
        .node
        .consumer()
        .fetch_with(InterestBuilder::new(name.clone()).lifetime(Duration::from_secs(2)))
        .await
}

/// The offer is a Data `<D>/32=intro/offer/<id>` signed by the device's key and served by
/// the extension to anyone who asks for the name; it is not an entry of any log. An id
/// nobody made, the prefix and the ask keyword's proof names are Nacked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_offer_is_served_as_an_extension_under_32_intro_offer() {
    let net = Net::new().await;
    let cancel = CancellationToken::new();
    let alice_person = Person::new("/alice");
    let laptop = Setup::new(&alice_person, "/alice/laptop")
        .on(&net, &cancel)
        .start()
        .await;
    let bob = Person::new("/bob");
    let bob_phone = Setup::new(&bob, "/bob/phone")
        .on(&net, &cancel)
        .start()
        .await;
    let a = alice_offers(laptop, alice_person, Role::Writer).await;
    // Making the space wrote its entries; an offer writes none.
    let logs_before = a
        .laptop
        .store
        .scan_under(&n("/alice/laptop/32=log"), 0)
        .len();
    let offer = a.offer();
    let (device, id) = parse_offer_name(&offer).expect("an offer's name");
    assert_eq!(device, n("/alice/laptop"));

    let data = fetch(&bob_phone, &offer)
        .await
        .expect("a stranger fetches the offer by its name");
    assert_eq!(
        *data.name, offer,
        "the offer's name is <D>/32=intro/offer/<id>"
    );
    let signer = data.sig_info().and_then(|s| s.key_locator_name());
    assert_eq!(
        signer.as_deref(),
        Some(a.laptop.node.writer()),
        "the offer is signed by the offering device's key"
    );
    assert!(
        matches!(
            a.laptop.validator.validate(&data).await,
            ValidationResult::Valid(_)
        ),
        "the device's own validator does not verify its offer"
    );
    let Ok(IntroRecord::Offer(body)) =
        IntroRecord::decode(data.content().expect("content").clone())
    else {
        panic!("the packet carries no offer");
    };
    assert_eq!(body.space, notebook());
    assert_eq!(body.role, Role::Writer);
    assert_eq!(body.tries, 3);
    assert!(
        a.laptop.store.contains(&store::offer_key(&id)),
        "the offer is not kept at offer/<id>"
    );

    for refused in [
        offer_prefix(&n("/alice/laptop")),
        offer_name(&n("/alice/laptop"), &[0xA5; 16]),
        n("/alice/laptop/32=intro/offer"),
        offer.clone().append("extra"),
        n("/alice/laptop/32=ask/x"),
    ] {
        let got = fetch(&bob_phone, &refused).await;
        assert!(
            matches!(got, Err(AppError::Nacked { .. })),
            "{refused} was answered {got:?}, not left unanswered"
        );
    }
    a.laptop
        .invites
        .offer(
            &notebook(),
            Offer {
                role: Role::Reader,
                until: Timestamp(a.laptop.node.now().0 + 3_600_000),
                tries: 3,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        a.laptop
            .store
            .scan_under(&n("/alice/laptop/32=log"), 0)
            .len(),
        logs_before,
        "an offer wrote a log entry"
    );
}

/// The id of an offer is 16 octets of randomness: no two offers share a name, a name next
/// to an offer's is nobody's, and asking for one gets silence — not a refusal that tells
/// an offer is there or was.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_offer_name_cannot_be_guessed() {
    let net = Net::new().await;
    let cancel = CancellationToken::new();
    let alice_person = Person::new("/alice");
    let laptop = Setup::new(&alice_person, "/alice/laptop")
        .on(&net, &cancel)
        .start()
        .await;
    let bob = Person::new("/bob");
    let bob_phone = Setup::new(&bob, "/bob/phone")
        .on(&net, &cancel)
        .start()
        .await;
    let a = alice_offers(laptop, alice_person, Role::Writer).await;
    let space = notebook();
    let mut ids: Vec<OfferId> = vec![parse_offer_name(&a.offer()).unwrap().1];
    for _ in 0..8 {
        let code = a
            .laptop
            .invites
            .offer(
                &space,
                Offer {
                    role: Role::Reader,
                    until: Timestamp(a.laptop.node.now().0 + 3_600_000),
                    tries: 3,
                },
            )
            .await
            .unwrap();
        ids.push(parse_offer_name(&code.offer).unwrap().1);
    }
    let mut sorted = ids.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), ids.len(), "two offers share an id");
    assert!(
        ids.iter()
            .all(|id| id.len() == 16 && id.iter().any(|b| *b != 0)),
        "an id is not 16 octets of randomness"
    );
    // The octets are not a counter or a clock: no two ids agree on their first octets,
    // beyond what 9 random draws agree on by chance (a counter agrees on all but one).
    let fixed_prefix = ids.iter().filter(|id| id[..12] == ids[0][..12]).count();
    assert_eq!(fixed_prefix, 1, "ids share a long prefix: {ids:?}");

    // Every neighbour of an offer's id is nobody's, and asking gets silence (a Nack), the
    // same as for an id never made.
    let real = parse_offer_name(&a.offer()).unwrap().1;
    for at in [0usize, 7, 15] {
        let mut near = real;
        near[at] ^= 1;
        let got = fetch(&bob_phone, &offer_name(&n("/alice/laptop"), &near)).await;
        assert!(
            matches!(got, Err(AppError::Nacked { .. })),
            "an id one bit from an offer's answered {got:?}"
        );
    }
    let got = fetch(&bob_phone, &offer_name(&n("/alice/phone"), &real)).await;
    assert!(
        matches!(got, Err(AppError::Nacked { .. })) || got.is_err(),
        "the id of this device's offer under another device's name was answered"
    );
}

/// The surface of an introduction link: while an offer stands an ask and the offer's own
/// packet cross it; another offer's id, the prefix and a hint token nobody holds do not.
#[tokio::test]
async fn the_introduction_link_carries_the_asks_and_the_offer_while_one_stands() {
    let (clock, skew) = skewed();
    let alice_person = Person::new("/alice");
    let laptop = Setup::new(&alice_person, "/alice/laptop")
        .clock(clock)
        .start()
        .await;
    let inner = laptop.invites.inner().clone();
    assert!(
        !inner.intro_open(),
        "a device with no offer has an open surface"
    );
    assert!(
        !inner.intro_carries(&n("/alice/laptop/32=intro/offer/x")),
        "a device with no offer carries an offer name"
    );
    let a = alice_offers(laptop, alice_person, Role::Writer).await;
    assert!(inner.intro_open());
    let device = n("/alice/laptop");
    assert!(inner.intro_carries(&a.offer()));
    assert!(inner.intro_carries(&crate::wire::intro_name(&device, b"params")));
    assert!(
        !inner.intro_carries(&offer_name(&device, &[9; 16])),
        "the id of an offer nobody made crosses the link"
    );
    assert!(
        !inner.intro_carries(&n("/alice/laptop/32=seal/x")),
        "a name the device holds that is no introduction's crosses the link"
    );
    assert!(
        !inner.intro_carries(&n("/alice/laptop/32=log/alice/32=data/notebook/seq=1")),
        "an entry crosses the introduction link"
    );
    skew.store(2 * 3_600_000, Ordering::SeqCst);
    assert!(
        !inner.intro_open(),
        "an expired offer keeps the surface open"
    );
    assert!(
        !inner.intro_carries(&a.offer()),
        "an expired offer crosses the link"
    );
}

// ---- durability: what the reply stands on -------------------------------------------------------

/// Alice's laptop on a store and keys that outlive it, its notebook offered as `role`.
struct Inviter {
    laptop: Device,
    alice: Person,
    keys: Arc<SecurityManager>,
    calls: Arc<Calls>,
    clock: Clock,
    skew: Arc<AtomicU64>,
    policy: IntroPolicy,
    store: Arc<dyn DataStore>,
    offer: Name,
    secret: [u8; SECRET_LEN],
}

impl Inviter {
    async fn new(role: Role, grant_for: Option<Duration>, refuses: &[&str]) -> Inviter {
        let policy = IntroPolicy {
            grant_for,
            ..IntroPolicy::new()
        };
        Self::over(
            role,
            policy,
            refuses,
            Arc::new(ndn_sync::MemoryStore::new()),
        )
        .await
    }

    async fn over(
        role: Role,
        policy: IntroPolicy,
        refuses: &[&str],
        store: Arc<dyn DataStore>,
    ) -> Inviter {
        let (clock, skew) = skewed();
        let alice_person = Person::new("/alice");
        let calls = Arc::new(Calls::default());
        let laptop = Setup::new(&alice_person, "/alice/laptop")
            .refusing(refuses)
            .clock(Arc::clone(&clock))
            .calls(Arc::clone(&calls))
            .policy(policy.clone())
            .store(Arc::clone(&store))
            .start()
            .await;
        let keys = Arc::clone(&laptop.keys);
        let Offered {
            laptop,
            alice,
            code,
            secret,
        } = alice_offers(laptop, alice_person, role).await;
        Inviter {
            laptop,
            alice,
            keys,
            calls,
            clock,
            skew,
            policy,
            store,
            offer: code.offer,
            secret,
        }
    }

    /// Alice's laptop stopped and started again over `store` (what a power cut left, or
    /// the same one) and its keys: a restart, its host a new one.
    async fn restart(self, store: Arc<dyn DataStore>) -> Inviter {
        let Inviter {
            laptop,
            alice,
            keys,
            clock,
            skew,
            policy,
            offer,
            secret,
            ..
        } = self;
        let rig = Arc::try_unwrap(laptop)
            .ok()
            .expect("nothing else holds the laptop");
        rig.node.close().await;
        drop(rig.invites);
        let calls = Arc::new(Calls::default());
        let laptop = Setup::new(&alice, "/alice/laptop")
            .keys(Arc::clone(&keys))
            .clock(Arc::clone(&clock))
            .calls(Arc::clone(&calls))
            .policy(policy.clone())
            .store(Arc::clone(&store))
            .start()
            .await;
        Inviter {
            laptop,
            alice,
            keys,
            calls,
            clock,
            skew,
            policy,
            store,
            offer,
            secret,
        }
    }

    /// What the laptop answers `joiner`'s ask for the offer, with `secret`.
    async fn answers_with(&self, joiner: &Device, secret: &[u8; SECRET_LEN]) -> Option<Outcome> {
        answer(
            &self.laptop,
            ask(joiner, &self.laptop, &self.offer, secret, &[]),
        )
        .await
    }

    /// What the laptop answers `joiner`'s ask for the offer.
    async fn answers(&self, joiner: &Device) -> Option<Outcome> {
        self.answers_with(joiner, &self.secret).await
    }

    fn id(&self) -> OfferId {
        parse_offer_name(&self.offer).unwrap().1
    }
}

/// A person's phone.
async fn phone_of(ns: &str) -> Device {
    let person = Person::new(ns);
    start(&person, &format!("{ns}/phone")).await
}

/// Spec §19.4, i4: a wrong try is counted durably before it is answered, against the asker
/// and toward the offer's cap: a restart — even a power cut that takes everything not
/// flushed — does not give the tries back.
#[tokio::test]
async fn wrong_tries_survive_a_restart() {
    let disk = crate::test_kit::DiskStore::new();
    let alice = Inviter::over(
        Role::Writer,
        IntroPolicy::new(),
        &[],
        Arc::clone(&disk) as Arc<dyn DataStore>,
    )
    .await;
    let bob_phone = phone_of("/bob").await;
    let wrong = [9u8; SECRET_LEN];
    let got = alice.answers_with(&bob_phone, &wrong).await;
    assert!(
        matches!(
            got,
            Some(Outcome::Refused(IntroRefusal::WrongProof { left: 2 }))
        ),
        "the first wrong try was answered {got:?}"
    );
    let got = alice.answers_with(&bob_phone, &wrong).await;
    assert!(
        matches!(
            got,
            Some(Outcome::Refused(IntroRefusal::WrongProof { left: 1 }))
        ),
        "the second wrong try was answered {got:?}"
    );
    // The power goes: only what a flush covered is left.
    let id = alice.id();
    let image = disk.crash();
    let alice = alice.restart(image).await;
    assert!(
        alice.laptop.store.contains(&store::tries_key(&id)),
        "the wrong tries of the offer were not durable when their answer was sent"
    );
    // The third wrong try spends the asker's tries, though the process never saw the first
    // two: the offer is closed to this key for good, even to the right secret.
    let got = alice.answers_with(&bob_phone, &wrong).await;
    assert!(
        matches!(got, Some(Outcome::Refused(IntroRefusal::Closed))),
        "the third wrong try after a restart was answered {got:?}: the tries were given back"
    );
    let got = alice.answers(&bob_phone).await;
    assert!(
        matches!(got, Some(Outcome::Refused(IntroRefusal::Closed))),
        "a key whose tries are spent was answered {got:?} with the right secret"
    );
    // Another asker's tries are its own: it is not closed out by Bob's.
    let carol_phone = phone_of("/carol").await;
    let got = alice.answers(&carol_phone).await;
    assert!(accepted(&got), "carol was answered {got:?}");
}

/// Spec §19.4, i5: a code presented by two keys at once admits one, never two; asking
/// again changes no winner; a replay of the very ask is answered as it was, and a restart
/// that lost the process's memory still admits no second key.
#[tokio::test]
async fn a_replayed_ask_admits_one_key_never_two() {
    let alice = Inviter::new(Role::Writer, None, &[]).await;
    let (bob_phone, carol_phone) = (phone_of("/bob").await, phone_of("/carol").await);
    let space = notebook();
    let (bob_ask, carol_ask) = (
        ask(&bob_phone, &alice.laptop, &alice.offer, &alice.secret, &[]),
        ask(
            &carol_phone,
            &alice.laptop,
            &alice.offer,
            &alice.secret,
            &[],
        ),
    );
    let (bob_ask_again, carol_ask_again) = (bob_ask.clone(), carol_ask.clone());
    let (bob_got, carol_got) = tokio::join!(
        answer(&alice.laptop, bob_ask),
        answer(&alice.laptop, carol_ask)
    );
    let (winner, loser, winner_ask, loser_ask, first) = match (&bob_got, &carol_got) {
        (Some(Outcome::Accepted { .. }), Some(Outcome::Refused(IntroRefusal::Used))) => (
            n("/bob"),
            n("/carol"),
            bob_ask_again,
            carol_ask_again,
            bob_got,
        ),
        (Some(Outcome::Refused(IntroRefusal::Used)), Some(Outcome::Accepted { .. })) => (
            n("/carol"),
            n("/bob"),
            carol_ask_again,
            bob_ask_again,
            carol_got,
        ),
        other => panic!("two keys presenting one code answered {other:?}"),
    };
    let listed = |heap: &ndn_heap::Heap, who: &Name| heap.members().writers.contains(who);
    let h = heap(&alice.laptop, &space);
    assert!(listed(&h, &winner), "the admitted key is not listed");
    assert!(!listed(&h, &loser), "the refused key is listed");

    // The loser asking again is refused alike; the winner asking again is answered as kept.
    let loser_phone = if loser == n("/bob") {
        &bob_phone
    } else {
        &carol_phone
    };
    let winner_phone = if winner == n("/bob") {
        &bob_phone
    } else {
        &carol_phone
    };
    let again = alice.answers(loser_phone).await;
    assert!(
        matches!(again, Some(Outcome::Refused(IntroRefusal::Used))),
        "the loser asking again was answered {again:?}"
    );
    assert_eq!(alice.answers(winner_phone).await, first);
    // The very ask replayed is answered with the same packet.
    assert_eq!(answer(&alice.laptop, winner_ask.clone()).await, first);
    assert!(matches!(
        answer(&alice.laptop, loser_ask.clone()).await,
        Some(Outcome::Refused(IntroRefusal::Used))
    ));

    // A restart forgets what the process remembered: the replay still admits no second key.
    let signed_before = heap(&alice.laptop, &space).members();
    let store = Arc::clone(&alice.store);
    let alice = alice.restart(store).await;
    let signatures = alice.laptop.node.signatures();
    assert_eq!(answer(&alice.laptop, winner_ask).await, first);
    let late = answer(&alice.laptop, loser_ask).await;
    assert!(
        matches!(late, Some(Outcome::Refused(IntroRefusal::Used))),
        "the loser's replay after a restart was answered {late:?}"
    );
    assert_eq!(
        heap(&alice.laptop, &space).members(),
        signed_before,
        "a replay after a restart changed who the space lists"
    );
    assert_eq!(
        alice.laptop.node.signatures(),
        signatures,
        "a replay after a restart signed something"
    );
}

/// Spec §19.4, i6: an ask forged without the secret is counted and grants nothing. Carol
/// knows the offer's name and not its secret: refused as a wrong proof, counted durably
/// against her key; she is no member and was granted no link; Bob, holding the real code,
/// still joins, for one wrong try does not close an offer that allows three.
#[tokio::test]
async fn a_forged_ask_counts_and_grants_nothing() {
    let alice = Inviter::new(Role::Writer, None, &[]).await;
    let (bob_phone, carol_phone) = (phone_of("/bob").await, phone_of("/carol").await);
    let space = notebook();
    let got = alice.answers_with(&carol_phone, &[0xC4; SECRET_LEN]).await;
    assert!(
        matches!(
            got,
            Some(Outcome::Refused(IntroRefusal::WrongProof { left: 2 }))
        ),
        "carol's ask with a guessed secret was answered {got:?}"
    );
    assert!(
        alice.laptop.store.contains(&store::tries_key(&alice.id())),
        "the wrong try was not counted"
    );
    let carols = alice
        .laptop
        .store
        .scan_under(&store::tries_key(&alice.id()), 0)
        .into_iter()
        .filter(|(name, _)| *name != store::tries_key(&alice.id()))
        .count();
    assert_eq!(carols, 1, "the wrong try was not counted against its asker");
    let members = heap(&alice.laptop, &space).members();
    assert!(
        !members.writers.contains(&n("/carol")) && !members.readers.contains(&n("/carol")),
        "carol is listed after a forged ask"
    );
    assert_eq!(
        alice.calls.granted(),
        Vec::new(),
        "a forged ask was granted a link"
    );
    assert_eq!(alice.laptop.invites.grants(), Vec::new());
    assert!(
        !alice.laptop.store.contains(&store::used_key(&alice.id())),
        "a forged ask used the offer"
    );

    let got = alice.answers(&bob_phone).await;
    assert!(
        accepted(&got),
        "bob, holding the real code, was answered {got:?}"
    );
    assert!(
        heap(&alice.laptop, &space)
            .members()
            .writers
            .contains(&n("/bob")),
        "bob is not listed"
    );
    assert!(
        !heap(&alice.laptop, &space)
            .members()
            .writers
            .contains(&n("/carol")),
        "carol is listed once bob joined"
    );
}

/// A joiner whose namespace is a broad name is refused as a conflict, in the round trip,
/// not only by the policy's own check.
#[tokio::test]
async fn a_joiner_claiming_a_broad_name_is_answered_conflict() {
    let a = alice().await;
    let org = Person::new("/org");
    let org_phone = start(&org, "/org/phone").await;
    let got = answer(
        &a.laptop,
        ask(&org_phone, &a.laptop, &a.offer(), &a.secret, &[]),
    )
    .await;
    assert!(
        matches!(got, Some(Outcome::Refused(IntroRefusal::Conflict))),
        "a joiner claiming /org was answered {got:?}"
    );
}

// ---- what an admission writes ------------------------------------------------------------------

/// The admission is one members change whose entry the answer names; the use mark, the
/// acceptance and the proof key are in the store under `/localhost/ndn-invite/`, and the
/// offer is no log entry.
#[tokio::test]
async fn an_admission_is_one_members_entry_named_in_the_answer_and_marks_the_use() {
    let alice = Inviter::new(Role::Writer, None, &[]).await;
    let bob_phone = phone_of("/bob").await;
    let signed = alice.laptop.node.signatures();
    let space = notebook();
    let got = alice.answers(&bob_phone).await;
    let Some(Outcome::Accepted {
        space: got_space,
        role,
        admitted: Some(admitted),
        ..
    }) = got
    else {
        panic!("bob was answered {got:?}: no admitting entry is named");
    };
    assert_eq!((got_space, role), (space.clone(), Role::Writer));
    let h = heap(&alice.laptop, &space);
    assert!(
        h.applied(&admitted),
        "the named entry is not applied by the inviter"
    );
    let members = h.members();
    assert!(members.writers.contains(&n("/bob")));
    assert!(members.readers.contains(&n("/bob")));
    assert_eq!(
        admitted.device,
        n("/alice/laptop"),
        "the named entry is not the laptop's"
    );
    // One change: one members entry, plus the answer's proof packets (not entries).
    let id = alice.id();
    for kept in [
        store::used_key(&id),
        store::accepted_key(&id),
        store::key_key(&id),
        store::offer_key(&id),
    ] {
        assert!(alice.laptop.store.contains(&kept), "{kept} is not kept");
    }
    assert!(
        !alice.laptop.store.contains(&store::using_key(&id)),
        "the note of a use under way outlived the use"
    );
    assert!(
        alice.laptop.node.signatures() > signed,
        "the admission signed nothing"
    );
    // A second key finds the offer used; the space lists nobody more.
    let carol_phone = phone_of("/carol").await;
    let got = alice.answers(&carol_phone).await;
    assert!(matches!(got, Some(Outcome::Refused(IntroRefusal::Used))));
    assert_eq!(heap(&alice.laptop, &space).members(), members);
}

// ---- the cap on all askers' wrong tries (spec §19.7) --------------------------------------------------

/// Wrong tries of different keys are counted apart, and all together are bounded by the
/// policy: the try that reaches the cap closes the offer for everyone, durably, even to the
/// right secret.
#[tokio::test]
async fn the_wrong_tries_of_all_askers_together_close_the_offer_for_everyone() {
    let policy = IntroPolicy {
        wrong_tries_max: 2,
        backoff: Duration::ZERO,
        ..IntroPolicy::new()
    };
    let alice = Inviter::over(
        Role::Writer,
        policy,
        &[],
        Arc::new(ndn_sync::MemoryStore::new()),
    )
    .await;
    let wrong = [9u8; SECRET_LEN];
    let (bob, carol, dave) = (
        phone_of("/bob").await,
        phone_of("/carol").await,
        phone_of("/dave").await,
    );
    let got = alice.answers_with(&bob, &wrong).await;
    assert!(
        matches!(
            got,
            Some(Outcome::Refused(IntroRefusal::WrongProof { left: 2 }))
        ),
        "bob's wrong try was answered {got:?}"
    );
    assert!(
        !alice.laptop.store.contains(&store::closed_key(&alice.id())),
        "one wrong try closed the offer"
    );
    let got = alice.answers_with(&carol, &wrong).await;
    assert!(
        matches!(got, Some(Outcome::Refused(IntroRefusal::Closed))),
        "the try that reaches the cap was answered {got:?}"
    );
    assert!(
        alice.laptop.store.contains(&store::closed_key(&alice.id())),
        "the cap closed the offer without a durable closing mark"
    );
    let got = alice.answers(&dave).await;
    assert!(
        matches!(got, Some(Outcome::Refused(IntroRefusal::Closed))),
        "a third key with the right secret was answered {got:?} by an offer at its cap"
    );
    assert!(
        !heap(&alice.laptop, &notebook())
            .members()
            .writers
            .contains(&n("/dave")),
        "a key was admitted by an offer at its cap"
    );
}

/// The pause after each wrong try counted toward the cap doubles: a wrong try within it
/// counts against its own asker alone, so strangers cannot close an offer for everyone
/// by asking quickly.
#[tokio::test]
async fn wrong_tries_within_the_pause_count_against_their_asker_alone() {
    let policy = IntroPolicy {
        wrong_tries_max: 2,
        backoff: Duration::from_secs(3600),
        ..IntroPolicy::new()
    };
    let alice = Inviter::over(
        Role::Writer,
        policy,
        &[],
        Arc::new(ndn_sync::MemoryStore::new()),
    )
    .await;
    let wrong = [9u8; SECRET_LEN];
    let (bob, carol, dave) = (
        phone_of("/bob").await,
        phone_of("/carol").await,
        phone_of("/dave").await,
    );
    for who in [&bob, &carol] {
        let got = alice.answers_with(who, &wrong).await;
        assert!(
            matches!(
                got,
                Some(Outcome::Refused(IntroRefusal::WrongProof { left: 2 }))
            ),
            "a wrong try was answered {got:?}"
        );
    }
    assert_eq!(
        alice.laptop.invites.inner().overall_tries(&alice.id()).0,
        1,
        "a try within the pause was counted toward the cap"
    );
    let got = alice.answers(&dave).await;
    assert!(
        accepted(&got),
        "the offer was closed for everyone by tries within the pause: dave was answered {got:?}"
    );
}
