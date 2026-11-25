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
use ndn_heap::{Readers, Share};
use ndn_packet::encode::DataBuilder;
use ndn_security::confidentiality::{ContentKey, wrap_ck_to};

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
/// under way) leaves the offer to the key being admitted: its retry finishes the use with
/// exactly one members entry, and another key finds the offer used.
#[tokio::test]
async fn a_stop_between_using_and_the_members_change_leaves_the_offer_to_its_key() {
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
    // Another key finds the offer its first key's.
    let got = answer(&laptop, ask(&carol, &laptop, &code.offer, &secret, &[])).await;
    assert!(
        matches!(got, Some(Outcome::Refused(IntroRefusal::Used))),
        "another key was answered {got:?} by an offer whose use was under way"
    );
    assert!(!listed(&laptop, "/carol"));
    // The key being admitted finishes it, once.
    let got = answer(&laptop, ask(&bob, &laptop, &code.offer, &secret, &[])).await;
    let Some(Outcome::Accepted { admitted, .. }) = got else {
        panic!("the key that was being admitted was answered {got:?}");
    };
    assert!(
        admitted.is_some(),
        "the finished use names no members entry"
    );
    assert!(listed(&laptop, "/bob"));
    let h = heap(&laptop, &notebook());
    assert_eq!(
        h.members()
            .writers
            .iter()
            .filter(|w| **w == n("/bob"))
            .count(),
        1,
        "the person is listed twice"
    );
    let again = answer(&laptop, ask(&bob, &laptop, &code.offer, &secret, &[])).await;
    assert!(accepted(&again));
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
/// the host adopts): nothing is written as used, the use under way is let go, the asker is
/// told nothing, and the offer is as it was — once the device runs again, the asker's retry
/// is answered and admits it once.
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
    // The device runs again over what it kept: the retry is judged again.
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
    let got = answer(&laptop, ask(&bob, &laptop, &code.offer, &secret, &[])).await;
    assert!(accepted(&got), "the retry was answered {got:?}");
    assert!(listed(&laptop, "/bob"));
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
