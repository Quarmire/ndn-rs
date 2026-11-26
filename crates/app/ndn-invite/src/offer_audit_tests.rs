//! What the audit of the introductions found missing, as guards: the notes an offer's
//! judgement stands on are authenticated by a key the data store cannot make (a forged
//! proof-key note admits no one, a forged offer is not served), an unreadable note fails
//! closed (a use mark that does not read is a used offer, a tries note that does not read
//! is the cap), and the inviter-side rules the old tests held without a case here: the
//! namespace overlaps, the crash between `using` and the members change, a removal
//! signed by another owner device, the bound on asks opened at once, and an offer that
//! the failed members change does not spend.
//!
//! A child of `offer_tests`: it uses its `Inviter`.

use bytes::Bytes;
use ndn_heap::{Alert, Change, Frontier, Readers, Share};
use ndn_packet::encode::DataBuilder;
use ndn_security::confidentiality::{ContentKey, wrap_ck_to};
use ndn_trust_envelope::TrustEnvelope;

use super::*;
use crate::invites::InviteConfig;
use crate::proofs::{commitment, proof_key};
use crate::sealed::wrap_note;
use crate::test_kit::{DiskStore, ask_sealed_to, ask_unproven, ask_unproven_sealed_to, fast};
use crate::wire::{IntroRecord, OfferBody, UsedBody};

/// A note as it was written before notes carried a MAC: the secret wrapped to the
/// device's public recipient key, which anyone can do.
fn publicly_wrapped(laptop: &Device, key: &Name, secret: [u8; 32]) -> Bytes {
    let (ephemeral, wrapped) = wrap_ck_to(
        &laptop.node.recipient().public(),
        &ContentKey::from_bytes(secret),
        &key.encode_to_tlv(),
    )
    .unwrap();
    let mut note = ephemeral.to_vec();
    note.extend_from_slice(&wrapped.to_bytes());
    Bytes::from(note)
}

fn listed(laptop: &Device, who: &str) -> bool {
    let members = heap(laptop, &notebook()).members();
    members.writers.contains(&n(who)) || members.readers.contains(&n(who))
}

/// Alice's laptop and phone, devices of one person that never met, hold each other's
/// certificate, as the host's enrolment would give them.
async fn meet(a: &Offered, phone: &Device) {
    for (from, to) in [(&a.laptop, phone), (phone, &a.laptop)] {
        let k = key(&from.name);
        let public = from.keys.get_signer_sync(&k).unwrap().public_key().unwrap();
        to.validator
            .cert_cache()
            .insert(a.alice.certify(&k, &public).await);
    }
}

// ---- F1: the proof key and the offer are authenticated -----------------------------------------

/// Whoever can write the data store (not the key store) knows the device's recipient
/// *public* key, so wrapping a proof key of their own to it makes a note that reads. The
/// note is authenticated by a key derived from the secret the key store keeps: a note of
/// anyone else's making is unread, the offer is `Unknown`, and nobody is admitted by the
/// attacker's secret.
#[tokio::test]
async fn a_forged_proof_key_note_admits_no_one() {
    let alice = Inviter::new(Role::Writer, None, &[]).await;
    let mallory = phone_of("/mallory").await;
    let id = alice.id();
    let guess = [7u8; SECRET_LEN];
    alice.laptop.store.insert(
        store::key_key(&id),
        publicly_wrapped(
            &alice.laptop,
            &store::key_key(&id),
            proof_key(&guess, &alice.offer),
        ),
    );
    let got = alice.answers_with(&mallory, &guess).await;
    assert!(
        !accepted(&got),
        "an ask by a secret of the attacker's choosing was answered {got:?} after its proof key was written into the store"
    );
    assert!(!listed(&alice.laptop, "/mallory"), "the attacker is listed");
    assert_eq!(
        alice.calls.granted(),
        Vec::new(),
        "the attacker was granted a link"
    );
    // The note that was there is not read either: not even the real code works, which is
    // the fail-closed side (the owner makes a new offer).
    let bob = phone_of("/bob").await;
    let got = alice.answers(&bob).await;
    assert!(
        !accepted(&got),
        "a proof key that is not the device's own was read: {got:?}"
    );
}

/// An offer note is a signed packet and the device's own key signed it: one that is not
/// (an attacker's writes into the store) is not served after a restart, not judged, and
/// its key note — here made honestly, to isolate the signature — admits no one.
#[tokio::test]
async fn a_forged_offer_note_is_not_served_or_judged() {
    let alice = Inviter::new(Role::Writer, None, &[]).await;
    let store = Arc::clone(&alice.store);
    let device = n("/alice/laptop");
    let id2: OfferId = [0x5A; 16];
    let offer2 = offer_name(&device, &id2);
    let secret2 = [0x33u8; SECRET_LEN];
    let body = OfferBody {
        space: notebook(),
        role: Role::Writer,
        until: Timestamp(alice.laptop.node.now().0 + 3_600_000),
        tries: 99,
        commitment: commitment(&secret2),
        seal_key: alice.laptop.node.recipient().public(),
    };
    // Signed by a key of the attacker's, not by the device's.
    let mgr = ndn_security::SecurityManager::new();
    let attacker = n("/mallory/laptop/KEY/1");
    mgr.generate_ed25519(attacker.clone()).unwrap();
    let signer = mgr.get_signer_sync(&attacker).unwrap();
    let forged = DataBuilder::new(offer2.clone(), &IntroRecord::Offer(body).encode()).sign_sync(
        signer.sig_type(),
        Some(&attacker),
        |region| signer.sign_sync(region).unwrap(),
    );
    store.insert(store::offer_key(&id2), forged);
    store.insert(
        store::key_key(&id2),
        wrap_note(
            alice.laptop.node.recipient(),
            &store::key_key(&id2),
            proof_key(&secret2, &offer2),
        )
        .unwrap(),
    );
    let seal_key = alice.laptop.node.recipient().public();
    let alice = alice.restart(store).await;
    let inner = alice.laptop.invites.inner();
    assert!(
        !inner.state.lock().offers.contains_key(&id2),
        "an offer note the device's key did not sign is held as an offer"
    );
    assert!(
        !inner.intro_carries(&offer2),
        "an offer note the device's key did not sign is carried by the link"
    );
    let mallory = phone_of("/mallory").await;
    let got = answer(
        &alice.laptop,
        ask_sealed_to(&mallory, &device, &seal_key, &offer2, &secret2, &[]),
    )
    .await;
    assert_eq!(
        got, None,
        "an ask for an offer the device never made was answered {got:?}, not met with silence"
    );
    assert!(!listed(&alice.laptop, "/mallory"), "the attacker is listed");
    // The real offer still stands.
    let bob = phone_of("/bob").await;
    assert!(accepted(&alice.answers(&bob).await));
}

// ---- F2: what does not read fails closed ------------------------------------------------------------

/// A use mark that does not read — junk, a torn write, a record naming a key of the
/// writer's choosing without the MAC — is a used offer: no key is admitted by it, not
/// even the one it was used by.
#[tokio::test]
async fn an_unreadable_use_mark_is_a_used_offer() {
    let alice = Inviter::new(Role::Writer, None, &[]).await;
    let (bob, carol) = (phone_of("/bob").await, phone_of("/carol").await);
    let first = alice.answers(&bob).await;
    assert!(accepted(&first), "bob was answered {first:?}");
    let id = alice.id();
    let carols_mark = IntroRecord::Used(UsedBody {
        offer: alice.offer.clone(),
        by: Some((
            carol.node.writer().clone(),
            carol.invites.inner().own_key_digest(),
        )),
    })
    .encode();
    for note in [Bytes::from_static(b"junk"), carols_mark, Bytes::new()] {
        alice.laptop.store.insert(store::used_key(&id), note);
        let got = alice.answers(&carol).await;
        assert!(
            matches!(
                got,
                Some(Outcome::Refused(IntroRefusal::Used | IntroRefusal::Closed))
            ),
            "a key was answered {got:?} by an offer whose use mark does not read"
        );
        assert!(
            !listed(&alice.laptop, "/carol"),
            "a second key was admitted"
        );
    }
}

/// A use under way (`using/<id>`) that does not read is a use by a key nobody knows: the
/// offer is not given to another.
#[tokio::test]
async fn an_unreadable_using_note_is_a_used_offer() {
    let alice = Inviter::new(Role::Writer, None, &[]).await;
    let carol = phone_of("/carol").await;
    alice
        .laptop
        .store
        .insert(store::using_key(&alice.id()), Bytes::from_static(b"junk"));
    let got = alice.answers(&carol).await;
    assert!(
        matches!(
            got,
            Some(Outcome::Refused(IntroRefusal::Used | IntroRefusal::Closed))
        ),
        "a key was answered {got:?} by an offer whose use under way does not read"
    );
    assert!(!listed(&alice.laptop, "/carol"));
}

/// The wrong tries that do not read are the cap: the offer's overall note closes it for
/// everyone, an asker's own note closes it to that asker.
#[tokio::test]
async fn an_unreadable_tries_note_is_the_cap() {
    let alice = Inviter::new(Role::Writer, None, &[]).await;
    let (bob, carol, dave) = (
        phone_of("/bob").await,
        phone_of("/carol").await,
        phone_of("/dave").await,
    );
    let id = alice.id();
    let got = alice.answers_with(&bob, &[9; SECRET_LEN]).await;
    assert!(matches!(
        got,
        Some(Outcome::Refused(IntroRefusal::WrongProof { left: 2 }))
    ));
    // Bob's own count does not read: he is at his cap, with the right secret too.
    let digest = bob.invites.inner().own_key_digest();
    alice.laptop.store.insert(
        store::tries_asker_key(&id, &digest),
        Bytes::from_static(b"x"),
    );
    let got = alice.answers(&bob).await;
    assert!(
        matches!(got, Some(Outcome::Refused(IntroRefusal::Closed))),
        "an asker whose tries do not read was answered {got:?}"
    );
    // The offer's overall count does not read: everyone is refused.
    alice
        .laptop
        .store
        .insert(store::tries_key(&id), Bytes::from_static(b"garbage"));
    for who in [&carol, &dave] {
        let got = alice.answers(who).await;
        assert!(
            matches!(got, Some(Outcome::Refused(IntroRefusal::Closed))),
            "a key was answered {got:?} by an offer whose overall tries do not read"
        );
    }
    assert!(!listed(&alice.laptop, "/carol") && !listed(&alice.laptop, "/dave"));
}

/// A tries note moved from one asker's key to another's (a MAC bound to its own key
/// name) does not read.
#[tokio::test]
async fn a_tries_note_moved_to_another_key_does_not_read() {
    let alice = Inviter::new(Role::Writer, None, &[]).await;
    let (bob, carol) = (phone_of("/bob").await, phone_of("/carol").await);
    let id = alice.id();
    let got = alice.answers_with(&bob, &[9; SECRET_LEN]).await;
    assert!(matches!(
        got,
        Some(Outcome::Refused(IntroRefusal::WrongProof { .. }))
    ));
    let (b, c) = (
        bob.invites.inner().own_key_digest(),
        carol.invites.inner().own_key_digest(),
    );
    let note = alice
        .laptop
        .store
        .get(&store::tries_asker_key(&id, &b))
        .expect("bob's count");
    alice
        .laptop
        .store
        .insert(store::tries_asker_key(&id, &c), note);
    let got = alice.answers(&carol).await;
    assert!(
        matches!(got, Some(Outcome::Refused(IntroRefusal::Closed))),
        "a count copied from another key was read: carol was answered {got:?}"
    );
}

// ---- T1: the inviter judges the joiner's namespace ----------------------------------------------------

/// The joiner's namespace is refused as a conflict when it overlaps a namespace the
/// inviter's device trusts (equal under another anchor, under it, over it), its own, or is
/// one no introduction brings; a namespace it already trusts under the same anchor is
/// a party known already and is welcome.
#[tokio::test]
async fn a_joiner_whose_namespace_overlaps_a_held_one_is_answered_conflict() {
    // Another anchor: the inviter holds a `/bob`, the joiner brings another `/bob`.
    let a = alice().await;
    let held = Person::new("/bob");
    a.laptop
        .validator
        .adopt_context(Arc::clone(&held.ctx))
        .unwrap();
    let impostor = Person::new("/bob");
    let impostor_phone = start(&impostor, "/bob/phone").await;
    let got = answer(
        &a.laptop,
        ask(&impostor_phone, &a.laptop, &a.offer(), &a.secret, &[]),
    )
    .await;
    assert!(
        matches!(got, Some(Outcome::Refused(IntroRefusal::Conflict))),
        "a namespace held under another anchor was answered {got:?}"
    );
    // Under a held namespace.
    let team = Person::new("/bob/team");
    let team_phone = start(&team, "/bob/team/phone").await;
    let got = answer(
        &a.laptop,
        ask(&team_phone, &a.laptop, &a.offer(), &a.secret, &[]),
    )
    .await;
    assert!(
        matches!(got, Some(Outcome::Refused(IntroRefusal::Conflict))),
        "a namespace under a held one was answered {got:?}"
    );
    // Over a held namespace.
    let a2 = alice().await;
    let carol_team = Person::new("/carol/team");
    a2.laptop
        .validator
        .adopt_context(Arc::clone(&carol_team.ctx))
        .unwrap();
    let carol = Person::new("/carol");
    let carol_phone = start(&carol, "/carol/phone").await;
    let got = answer(
        &a2.laptop,
        ask(&carol_phone, &a2.laptop, &a2.offer(), &a2.secret, &[]),
    )
    .await;
    assert!(
        matches!(got, Some(Outcome::Refused(IntroRefusal::Conflict))),
        "a namespace over a held one was answered {got:?}"
    );
    // The inviter's own namespace, and one under it.
    for ns in ["/alice", "/alice/team"] {
        let a3 = alice().await;
        let person = Person::new(ns);
        let phone = start(&person, &format!("{ns}/phone")).await;
        let got = answer(
            &a3.laptop,
            ask(&phone, &a3.laptop, &a3.offer(), &a3.secret, &[]),
        )
        .await;
        assert!(
            matches!(got, Some(Outcome::Refused(IntroRefusal::Conflict))),
            "the inviter's own namespace {ns} was answered {got:?}"
        );
    }
    // The same anchor is a party known already: welcome.
    let a4 = alice().await;
    let known = Person::new("/bob");
    a4.laptop
        .validator
        .adopt_context(Arc::clone(&known.ctx))
        .unwrap();
    let phone = start(&known, "/bob/phone").await;
    let got = answer(
        &a4.laptop,
        ask(&phone, &a4.laptop, &a4.offer(), &a4.secret, &[]),
    )
    .await;
    assert!(
        accepted(&got),
        "a namespace held under the same anchor was answered {got:?}"
    );
}

// ---- T2: the crash window and the removal elsewhere -----------------------------------------------------

/// A stop after the use was noted and before the members change (the host's adoption was
/// under way), the next start finding the node's stop unclean: the use noted is durable, and
/// nothing of it is finished. The unclean start closes the offer (the notes may be older than
/// what the device did), so no key is admitted by it, the key that was being admitted
/// included: it is told the offer is closed, and the owner makes a new one.
#[tokio::test]
async fn a_stop_between_using_and_the_members_change_closes_the_offer_at_the_next_start() {
    let started = Arc::new(Notify::new());
    let gate = Arc::new(Semaphore::new(0));
    let disk = DiskStore::new();
    let alice_person = Person::new("/alice");
    let laptop = Setup::new(&alice_person, "/alice/laptop")
        .holding(Arc::clone(&started), Arc::clone(&gate))
        .store(Arc::clone(&disk) as Arc<dyn DataStore>)
        .start()
        .await;
    let keys = Arc::clone(&laptop.keys);
    let a = alice_offers(laptop, alice_person, Role::Writer).await;
    let (bob, carol) = (phone_of("/bob").await, phone_of("/carol").await);
    let id = parse_offer_name(&a.offer()).unwrap().1;
    let first = ask(&bob, &a.laptop, &a.offer(), &a.secret, &[]);
    let held = {
        let laptop = Arc::clone(&a.laptop);
        tokio::spawn(async move { answer(&laptop, first).await })
    };
    started.notified().await;
    // Power goes while the host is adopting: what a flush covered is what is left.
    let image = disk.crash();
    held.abort();
    let _ = held.await;
    assert!(
        image.contains(&store::using_key(&id)),
        "the use under way was not durable before the host was asked to adopt"
    );
    assert!(!image.contains(&store::used_key(&id)));
    let Offered {
        laptop,
        alice: alice_person,
        code,
        secret,
    } = a;
    let rig = Arc::try_unwrap(laptop)
        .ok()
        .expect("only the test holds the laptop");
    rig.node.close().await;
    drop(rig.invites);
    let laptop = Setup::new(&alice_person, "/alice/laptop")
        .keys(keys)
        .store(image)
        .start()
        .await;
    // No key is admitted by the offer now: it is closed, the one being admitted included.
    for (who, name) in [(&carol, "another key"), (&bob, "the key being admitted")] {
        let got = answer(&laptop, ask(who, &laptop, &code.offer, &secret, &[])).await;
        assert!(
            matches!(got, Some(Outcome::Refused(IntroRefusal::Closed))),
            "{name} was answered {got:?} by an offer whose use was under way at an unclean stop"
        );
    }
    assert!(!listed(&laptop, "/carol") && !listed(&laptop, "/bob"));
}

/// The members change that removes the person an offer admitted may be signed by another
/// owner device: this device learns it by the space, and the offer closes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_removal_signed_by_another_owner_device_closes_the_offer() {
    let net = Net::new().await;
    let cancel = CancellationToken::new();
    let alice_person = Person::new("/alice");
    let laptop = Setup::new(&alice_person, "/alice/laptop")
        .config(fast())
        .on(&net, &cancel)
        .start()
        .await;
    let phone = Setup::new(&alice_person, "/alice/phone")
        .config(fast())
        .on(&net, &cancel)
        .start()
        .await;
    let a = alice_offers(laptop, alice_person, Role::Writer).await;
    let (bob, carol) = (phone_of("/bob").await, phone_of("/carol").await);
    let space = notebook();
    meet(&a, &phone).await;
    let theirs = phone.node.open(&space).await.unwrap();
    let got = answer(&a.laptop, ask(&bob, &a.laptop, &a.offer(), &a.secret, &[])).await;
    assert!(accepted(&got), "bob was answered {got:?}");
    // Alice's phone learns bob is listed, then removes him.
    for _ in 0..300 {
        if theirs.members().writers.contains(&n("/bob")) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        theirs.members().writers.contains(&n("/bob")),
        "the phone never saw bob listed"
    );
    theirs
        .change(ndn_heap::MembersChange {
            remove: vec![n("/bob")],
            ..Default::default()
        })
        .await
        .unwrap();
    let mut closed = false;
    for _ in 0..300 {
        let got = answer(
            &a.laptop,
            ask(&carol, &a.laptop, &a.offer(), &a.secret, &[]),
        )
        .await;
        if matches!(got, Some(Outcome::Refused(IntroRefusal::Closed))) {
            closed = true;
            break;
        }
        assert!(
            matches!(got, Some(Outcome::Refused(IntroRefusal::Used))),
            "another key was answered {got:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        closed,
        "the removal signed by the phone did not close the offer"
    );
    let hint_closed = a.laptop.invites.inner().offer_closed(
        &parse_offer_name(&a.offer()).unwrap().1,
        &OfferBody {
            space,
            role: Role::Writer,
            until: Timestamp(u64::MAX),
            tries: 3,
            commitment: [0; 32],
            seal_key: [0; 32],
        },
    );
    assert!(hint_closed);
}

// ---- T3: the bound on asks opened at once -----------------------------------------------------------------

/// Opening and verifying an ask waits for one of `asks_verifying` slots, taken before
/// anything of the ask is unwrapped: with every slot held, asks are held, not opened.
#[tokio::test]
async fn asks_opened_at_once_never_exceed_asks_verifying() {
    let alice_person = Person::new("/alice");
    let laptop = Setup::new(&alice_person, "/alice/laptop")
        .invite_config(InviteConfig {
            asks_verifying: 2,
            ..InviteConfig::new()
        })
        .start()
        .await;
    let a = alice_offers(laptop, alice_person, Role::Writer).await;
    let bob = phone_of("/bob").await;
    let inner = a.laptop.invites.inner().clone();
    assert_eq!(inner.verifying.available_permits(), 2);
    let slots = inner.verifying.acquire_many(2).await.unwrap();
    let mut tasks = Vec::new();
    for _ in 0..3 {
        let one = ask(&bob, &a.laptop, &a.offer(), &a.secret, &[]);
        let laptop = Arc::clone(&a.laptop);
        tasks.push(tokio::spawn(async move { answer(&laptop, one).await }));
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        tasks.iter().all(|t| !t.is_finished()),
        "an ask was opened with every verifying slot held"
    );
    assert_eq!(
        inner.state.lock().queued,
        3,
        "the asks are held in the queue"
    );
    drop(slots);
    for t in tasks {
        let got = tokio::time::timeout(Duration::from_secs(10), t)
            .await
            .expect("the asks finish once a slot is free")
            .unwrap();
        assert!(accepted(&got), "bob was answered {got:?}");
    }
}

// ---- T4: a members change that fails does not spend the offer --------------------------------------------

/// The members change fails after the asker's anchor was adopted (here the node stops while
/// the host adopts): nothing is written as used, the use under way is let go, and the asker is
/// told nothing. The node stopped, so the next start is unclean and closes the offer: the
/// retry is refused as closed (not as used: nothing was spent) and admits nobody.
#[tokio::test]
async fn an_offer_is_not_spent_when_the_members_change_fails() {
    let started = Arc::new(Notify::new());
    let gate = Arc::new(Semaphore::new(0));
    let disk = DiskStore::new();
    let calls = Arc::new(Calls::default());
    let alice_person = Person::new("/alice");
    let laptop = Setup::new(&alice_person, "/alice/laptop")
        .holding(Arc::clone(&started), Arc::clone(&gate))
        .calls(Arc::clone(&calls))
        .store(Arc::clone(&disk) as Arc<dyn DataStore>)
        .start()
        .await;
    let keys = Arc::clone(&laptop.keys);
    let a = alice_offers(laptop, alice_person, Role::Writer).await;
    let bob = phone_of("/bob").await;
    let id = parse_offer_name(&a.offer()).unwrap().1;
    let first = ask(&bob, &a.laptop, &a.offer(), &a.secret, &[]);
    let held = {
        let laptop = Arc::clone(&a.laptop);
        tokio::spawn(async move { answer(&laptop, first).await })
    };
    started.notified().await;
    a.laptop.node.shutdown();
    gate.add_permits(1);
    let got = held.await.unwrap();
    assert_eq!(got, None, "an admission that failed was answered");
    assert!(
        !a.laptop.store.contains(&store::used_key(&id)),
        "a failed admission spent the offer"
    );
    assert!(
        !a.laptop.store.contains(&store::using_key(&id)),
        "a failed admission left the offer to its asker"
    );
    assert_eq!(calls.granted(), Vec::new());
    // The device runs again over what it kept, after a stop it did not make: the offer is
    // closed and was never spent.
    let Offered {
        laptop,
        alice: alice_person,
        code,
        secret,
    } = a;
    let rig = Arc::try_unwrap(laptop)
        .ok()
        .expect("only the test holds the laptop");
    rig.node.close().await;
    drop(rig.invites);
    let laptop = Setup::new(&alice_person, "/alice/laptop")
        .keys(keys)
        .store(disk as Arc<dyn DataStore>)
        .start()
        .await;
    assert!(!laptop.store.contains(&store::used_key(&id)));
    let got = answer(&laptop, ask(&bob, &laptop, &code.offer, &secret, &[])).await;
    assert!(
        matches!(got, Some(Outcome::Refused(IntroRefusal::Closed))),
        "the retry was answered {got:?} after an unclean stop"
    );
    assert!(!listed(&laptop, "/bob"));
}

// ---- L3: a refusal travels only to an asker that proved a key (spec §9.2, §17.1) --------------------

/// An ask that opens and names a key with credentials, but whose asker proof does not
/// prove that key for this ask, is met with silence whatever the offer is: one this device
/// never made, one already used, one closed. Only an asker that proved a key is told
/// that an offer is used or closed, so a prober holding no proving key learns nothing of
/// what the device holds. A proven ask for the same offers is still refused with its
/// reason, so the joiner is told what to do.
#[tokio::test]
async fn an_unproven_ask_gets_silence_for_an_unknown_used_or_closed_offer() {
    let alice = Inviter::new(Role::Writer, None, &[]).await;
    let (bob, carol, mallory) = (
        phone_of("/bob").await,
        phone_of("/carol").await,
        phone_of("/mallory").await,
    );
    let device = n("/alice/laptop");
    let seal_key = alice.laptop.node.recipient().public();

    // An offer this device never made.
    let unknown = offer_name(&device, &[0x77; 16]);
    let got = answer(
        &alice.laptop,
        ask_unproven_sealed_to(&mallory, &device, &seal_key, &unknown, &[1; SECRET_LEN]),
    )
    .await;
    assert_eq!(
        got, None,
        "an unproven ask naming no held offer was answered {got:?}, not met with silence"
    );
    let got = answer(
        &alice.laptop,
        ask_sealed_to(
            &mallory,
            &device,
            &seal_key,
            &unknown,
            &[1; SECRET_LEN],
            &[],
        ),
    )
    .await;
    assert_eq!(
        got, None,
        "an ask naming no held offer was answered {got:?}, not met with silence"
    );

    // An offer used by Bob.
    let first = alice.answers(&bob).await;
    assert!(accepted(&first), "bob was answered {first:?}");
    let got = answer(
        &alice.laptop,
        ask_unproven(&carol, &alice.laptop, &alice.offer, &alice.secret),
    )
    .await;
    assert_eq!(
        got, None,
        "an unproven ask of a used offer was answered {got:?}, not met with silence"
    );
    let got = alice.answers(&carol).await;
    assert!(
        matches!(
            got,
            Some(Outcome::Refused(IntroRefusal::Used | IntroRefusal::Closed))
        ),
        "an ask that proved its key was answered {got:?}, not refused with its reason"
    );

    // An offer closed before anyone used it.
    let second = alice_offer_again(&alice).await;
    alice.laptop.invites.close_offer(&second.0).await.unwrap();
    let got = answer(
        &alice.laptop,
        ask_unproven(&mallory, &alice.laptop, &second.0, &second.1),
    )
    .await;
    assert_eq!(
        got, None,
        "an unproven ask of a closed offer was answered {got:?}, not met with silence"
    );
    let got = answer(
        &alice.laptop,
        ask(&mallory, &alice.laptop, &second.0, &second.1, &[]),
    )
    .await;
    assert!(
        matches!(got, Some(Outcome::Refused(IntroRefusal::Closed))),
        "an ask that proved its key was answered {got:?} by a closed offer"
    );
}

/// A second offer of Alice's notebook on her laptop: its name and secret.
async fn alice_offer_again(alice: &Inviter) -> (Name, [u8; SECRET_LEN]) {
    let code = alice
        .laptop
        .invites
        .offer(
            &notebook(),
            Offer {
                role: Role::Writer,
                until: Timestamp(alice.laptop.node.now().0 + 3_600_000),
                tries: 3,
            },
        )
        .await
        .unwrap();
    let Ok(ndn_trust_envelope::TrustEnvelope::Intro(intro)) =
        ndn_trust_envelope::TrustEnvelope::from_uri(&code.link)
    else {
        panic!("an offer's link is an introduction link");
    };
    (code.offer, intro.secret)
}

// ---- I2: only an owner device that holds the creation shows a code ----------------------------------

fn offer_of(laptop: &Device) -> Offer {
    Offer {
        role: Role::Writer,
        until: Timestamp(laptop.node.now().0 + 3_600_000),
        tries: 3,
    }
}

/// Of a space owned by `/alice`, a `guest` or `node` device of hers (in a namespace that
/// declares the role layout) that holds the space is no owner device: `Heap::change` refuses
/// it, so a code it showed would admit nobody and its joiner would meet silence. `offer`
/// refuses before anything is made or shown, says to use an owner device, and leaves nothing
/// behind: no offer is held, none is stored, none is served. A member device of the same
/// namespace is an owner device and makes its offer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_guest_or_relay_device_makes_no_offer() {
    let net = Net::new().await;
    let cancel = CancellationToken::new();
    let alice = Person::with_roles("/alice");
    let start_on = |device: &'static str| {
        Setup::new(&alice, device)
            .config(fast())
            .on(&net, &cancel)
            .start()
    };
    let laptop = start_on("/alice/member/laptop").await;
    let guests = [
        start_on("/alice/guest/phone").await,
        start_on("/alice/node/vps").await,
    ];
    let space = notebook();
    laptop
        .node
        .create(
            &space,
            Share {
                readers: Readers::Persons(vec![n("/alice")]),
                writers: vec![n("/alice")],
            },
        )
        .await
        .unwrap();
    for guest in &guests {
        for (from, to) in [(&laptop, guest), (guest, &laptop)] {
            let k = key(&from.name);
            let public = from.keys.get_signer_sync(&k).unwrap().public_key().unwrap();
            to.validator
                .cert_cache()
                .insert(alice.certify(&k, &public).await);
        }
        let heap = guest.node.open(&space).await.unwrap();
        for _ in 0..300 {
            if heap.members_known() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            heap.members_known(),
            "precondition: {} never held the creation",
            guest.name
        );
        let got = guest.invites.offer(&space, offer_of(guest)).await;
        let Err(err) = got else {
            panic!("{} was given a code to show: {got:?}", guest.name);
        };
        assert!(
            matches!(err, InviteError::Heap(ndn_heap::HeapError::NotOwner { .. })),
            "{} was refused with {err:?}, not as no owner device",
            guest.name
        );
        assert_eq!(
            err.next(),
            ndn_heap::NextStep::UseOwnerDevice,
            "the refusal does not say to use an owner device"
        );
        assert!(
            guest.invites.inner().state.lock().offers.is_empty(),
            "{} holds an offer it must not make",
            guest.name
        );
        assert!(
            store::list(guest.store.as_ref(), &store::offer_listing()).is_empty(),
            "{} stored an offer it must not make",
            guest.name
        );
    }
    laptop
        .invites
        .offer(&space, offer_of(&laptop))
        .await
        .expect("a member device of the owner makes an offer");
}

/// A space this device has open but whose creation it has not seen cannot be offered: until
/// the creation is held it is not known whether the space is public or who it lists, and
/// nothing is judged by what is not held. The refusal is `NotReady`: the same call can
/// succeed once the creation arrived.
#[tokio::test]
async fn a_space_whose_creation_is_not_held_makes_no_offer() {
    let alice = Person::new("/alice");
    let laptop = start(&alice, "/alice/laptop").await;
    let heap = laptop.node.open(&notebook()).await.unwrap();
    assert!(!heap.members_known(), "precondition: no creation is held");
    let got = laptop.invites.offer(&notebook(), offer_of(&laptop)).await;
    let Err(err) = got else {
        panic!("a code was shown for a space whose creation is not held: {got:?}");
    };
    assert!(
        matches!(err, InviteError::NotReady { .. }),
        "refused with {err:?}, not as not ready"
    );
    assert!(err.retry(), "the refusal does not say to try again");
    assert!(
        laptop.invites.inner().state.lock().offers.is_empty(),
        "an offer was held"
    );
}

// ---- residual: a restored store cannot reopen a code ----------------------------------------------

/// A start after a stop the node did not make (a crash, a power cut, an image copied while
/// the device ran) closes every offer held, with the closing mark durable: the notes of
/// the offers (`used/`, `using/`, `tries/`) may be older than what this device did, so a
/// code could be used a second time, and the owner makes a new one. A clean stop and start
/// leaves them open. Nobody is admitted by a closed offer, whoever asks and whatever they hold.
#[tokio::test]
async fn an_unclean_start_closes_every_open_offer() {
    let disk = DiskStore::new();
    let alice = Inviter::over(
        Role::Writer,
        IntroPolicy::new(),
        &[],
        Arc::clone(&disk) as Arc<dyn DataStore>,
    )
    .await;
    let (second, second_secret) = alice_offer_again(&alice).await;
    let ids = [alice.id(), parse_offer_name(&second).unwrap().1];
    // A clean stop and start leaves both open.
    let alice = alice.restart(Arc::clone(&disk) as Arc<dyn DataStore>).await;
    for id in &ids {
        assert!(
            !alice.laptop.store.contains(&store::closed_key(id)),
            "a clean stop and start closed an offer"
        );
    }
    // The power goes while the device runs: the image is what a copy of a running device holds.
    let image = disk.crash();
    let alice = alice.restart(image).await;
    for id in &ids {
        assert!(
            alice.laptop.store.contains(&store::closed_key(id)),
            "an offer stayed open across an unclean start: a restored copy of the store could let its code be used twice"
        );
    }
    let bob = phone_of("/bob").await;
    let got = alice.answers(&bob).await;
    assert!(
        matches!(got, Some(Outcome::Refused(IntroRefusal::Closed))),
        "a code was answered {got:?} after an unclean start"
    );
    let got = answer(
        &alice.laptop,
        ask(&bob, &alice.laptop, &second, &second_secret, &[]),
    )
    .await;
    assert!(
        matches!(got, Some(Outcome::Refused(IntroRefusal::Closed))),
        "a second code was answered {got:?} after an unclean start"
    );
    assert!(!listed(&alice.laptop, "/bob"), "bob was admitted");
}

/// Alice's laptop on the net over `store` (with its `keys` after the first run), her devices
/// of the test holding each other's certificates.
async fn laptop_on(
    net: &Net,
    cancel: &CancellationToken,
    alice: &Person,
    store: Arc<dyn DataStore>,
    keys: Option<Arc<SecurityManager>>,
    peers: &[&Device],
) -> Device {
    let mut setup = Setup::new(alice, "/alice/laptop")
        .config(fast())
        .on(net, cancel)
        .store(store);
    if let Some(keys) = keys {
        setup = setup.keys(keys);
    }
    let laptop = setup.start().await;
    for peer in peers {
        for (from, to) in [(&laptop, *peer), (*peer, &laptop)] {
            let k = key(&from.name);
            let public = from.keys.get_signer_sync(&k).unwrap().public_key().unwrap();
            to.validator
                .cert_cache()
                .insert(alice.certify(&k, &public).await);
        }
    }
    laptop
}

/// A laptop over a store restored from a backup older than what it did, with its offer open
/// and its phone online: the backup was taken while the offer was open, put back after the
/// offer was used and its person admitted. The image says the stop was clean, so nothing but
/// the space shows it: the phone holds entries signed under the laptop's name above what the
/// image reserved, and the laptop raises `RolledBack`. The `used/` note is gone with the
/// rollback, so another key holding the code would be admitted a second time.
struct RolledBack {
    _net: Net,
    _runs: Vec<CancellationToken>,
    /// The restored laptop and the offer it holds, open in its store.
    offered: Offered,
    id: OfferId,
    phone: Device,
    keys: Arc<ndn_security::SecurityManager>,
}

async fn rolled_back_laptop() -> RolledBack {
    let net = Net::new().await;
    let alice = Person::new("/alice");
    let disk = DiskStore::new();
    let store = || Arc::clone(&disk) as Arc<dyn DataStore>;
    let first_run = CancellationToken::new();
    let phone_net = CancellationToken::new();
    let laptop = laptop_on(&net, &first_run, &alice, store(), None, &[]).await;
    let keys = Arc::clone(&laptop.keys);
    let phone = Setup::new(&alice, "/alice/phone")
        .config(fast())
        .on(&net, &phone_net)
        .start()
        .await;
    let a = alice_offers(laptop, alice, Role::Writer).await;
    meet(&a, &phone).await;
    let theirs = phone.node.open(&notebook()).await.unwrap();
    for _ in 0..300 {
        if theirs.members_known() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(theirs.members_known(), "the phone never held the space");
    // The phone signs an entry the laptop holds: the laptop knows a peer, so a start from
    // this image waits for what the peers hold of the laptop.
    let mut written = false;
    for _ in 0..300 {
        if theirs
            .put(
                &n("/note"),
                Bytes::from_static(b"hello"),
                Default::default(),
            )
            .await
            .is_ok()
        {
            written = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(written, "the phone never wrote into the space");
    let mine = heap(&a.laptop, &notebook());
    for _ in 0..300 {
        if matches!(mine.kept(&n("/note")).await, Ok(Some(_))) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        matches!(mine.kept(&n("/note")).await, Ok(Some(_))),
        "the laptop never held the phone's entry"
    );
    drop(mine);
    let Offered {
        laptop,
        alice,
        code,
        secret,
    } = a;
    let id = parse_offer_name(&code.offer).unwrap().1;
    // The backup: the device stopped cleanly with its offer open.
    let rig = Arc::try_unwrap(laptop)
        .ok()
        .expect("only the test holds the laptop");
    rig.node.close().await;
    drop(rig.invites);
    first_run.cancel();
    let backup = disk.crash();

    // The device runs on (clean start: its offer stays open) and Bob uses the code; the phone
    // holds the entry that admitted him.
    let second_run = CancellationToken::new();
    let laptop = laptop_on(
        &net,
        &second_run,
        &alice,
        store(),
        Some(Arc::clone(&keys)),
        &[&phone],
    )
    .await;
    assert!(
        !laptop.store.contains(&store::closed_key(&id)),
        "a clean start closed the offer"
    );
    let bob = phone_of("/bob").await;
    let got = answer(&laptop, ask(&bob, &laptop, &code.offer, &secret, &[])).await;
    assert!(accepted(&got), "bob was answered {got:?}");
    for _ in 0..300 {
        if theirs.members().writers.contains(&n("/bob")) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        theirs.members().writers.contains(&n("/bob")),
        "the phone never saw bob listed"
    );
    let rig = Arc::try_unwrap(laptop)
        .ok()
        .expect("only the test holds the laptop");
    rig.node.close().await;
    drop(rig.invites);
    second_run.cancel();

    // The backup is restored under the running phone: used/ is gone, the offer is open again.
    let third_run = CancellationToken::new();
    let laptop = laptop_on(
        &net,
        &third_run,
        &alice,
        backup,
        Some(Arc::clone(&keys)),
        &[&phone],
    )
    .await;
    assert!(
        !laptop.store.contains(&store::used_key(&id)),
        "precondition: the restored store holds no use mark"
    );
    let heap = laptop.node.space(&notebook()).expect("the restored space");
    for _ in 0..400 {
        if heap.rolled_back() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        heap.rolled_back(),
        "precondition: the space never raised RolledBack"
    );
    RolledBack {
        _net: net,
        _runs: vec![phone_net, third_run],
        offered: Offered {
            laptop,
            alice,
            code,
            secret,
        },
        id,
        phone,
        keys,
    }
}

/// A rolled back store closes every offer: Carol holds the same code, the restored notes
/// would admit her a second time, and the offer is closed instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rolled_back_store_closes_every_open_offer() {
    let r = rolled_back_laptop().await;
    let Offered {
        laptop,
        code,
        secret,
        ..
    } = &r.offered;
    let carol = phone_of("/carol").await;
    let got = answer(laptop, ask(&carol, laptop, &code.offer, secret, &[])).await;
    assert!(
        matches!(got, Some(Outcome::Refused(IntroRefusal::Closed))),
        "a key was answered {got:?} by an offer of a store the device found rolled back: the code was used twice"
    );
    assert!(!listed(laptop, "/carol"), "carol was admitted");
    assert!(
        laptop.store.contains(&store::closed_key(&r.id)),
        "the offer was refused without a closing mark"
    );
}

/// Every rollback closes the offers held then, not the first one of the process: after the
/// first rollback closed the offers, the laptop makes a new one, and a copy of its key
/// signs an entry above what the laptop reserved. That is a rollback again (the notes of
/// the new offer cannot be trusted either), and the new offer is closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_later_rollback_closes_the_offers_made_since_the_first() {
    let r = rolled_back_laptop().await;
    let Offered {
        laptop,
        alice,
        code,
        secret,
    } = &r.offered;
    // The first rollback closes the offer held, once an ask judges it.
    let carol = phone_of("/carol").await;
    let got = answer(laptop, ask(&carol, laptop, &code.offer, secret, &[])).await;
    assert!(
        matches!(got, Some(Outcome::Refused(IntroRefusal::Closed))),
        "the first rollback closed nothing: {got:?}"
    );
    // An offer made after it.
    let later = laptop
        .invites
        .offer(
            &notebook(),
            Offer {
                role: Role::Writer,
                until: Timestamp(laptop.node.now().0 + 3_600_000),
                tries: 3,
            },
        )
        .await
        .unwrap();
    let Ok(TrustEnvelope::Intro(intro)) = TrustEnvelope::from_uri(&later.link) else {
        panic!("an offer's link is an introduction link");
    };
    let later_id = parse_offer_name(&later.offer).unwrap().1;
    assert!(
        !laptop.store.contains(&store::closed_key(&later_id)),
        "precondition: the new offer starts open"
    );

    // A copy of the laptop's key, over a store of its own, signs an entry in the space.
    let copy_run = CancellationToken::new();
    let copy = laptop_on(
        &r._net,
        &copy_run,
        alice,
        Arc::clone(&DiskStore::new()) as Arc<dyn DataStore>,
        Some(Arc::clone(&r.keys)),
        &[&r.phone, laptop],
    )
    .await;
    let theirs = copy.node.open(&notebook()).await.unwrap();
    for _ in 0..300 {
        if theirs.members_known() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(theirs.members_known(), "the copy never held the space");
    let mut signed = None;
    for _ in 0..300 {
        match theirs
            .put(
                &n("/copy"),
                Bytes::from_static(b"signed by a copy"),
                Default::default(),
            )
            .await
        {
            Ok(id) => {
                signed = Some(id.seq);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
    let signed = signed.expect("the copy never wrote into the space");
    // The laptop tells RolledBack for that entry.
    let mine = heap(laptop, &notebook());
    let mut changes = mine.watch(&Frontier::new()).await.unwrap();
    let told = tokio::time::timeout(Duration::from_secs(30), async {
        while let Some(change) = changes.next().await {
            if let Ok(Change::Alert(Alert::RolledBack { seen, .. })) = change
                && seen >= signed
            {
                return true;
            }
        }
        false
    })
    .await;
    assert_eq!(
        told,
        Ok(true),
        "precondition: the laptop never told RolledBack for seq {signed}"
    );
    let dave = phone_of("/dave").await;
    let got = answer(laptop, ask(&dave, laptop, &later.offer, &intro.secret, &[])).await;
    assert!(
        matches!(got, Some(Outcome::Refused(IntroRefusal::Closed))),
        "a key was answered {got:?} by an offer made after the first rollback, once the space raised RolledBack again"
    );
    assert!(!listed(laptop, "/dave"), "dave was admitted");
    assert!(
        laptop.store.contains(&store::closed_key(&later_id)),
        "the later rollback closed no offer"
    );
}
