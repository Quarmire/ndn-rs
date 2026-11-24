//! The joiner's side (`join.rs`, spec §19.3): a code is judged before anything is
//! dialled (M2), a join that fails after its dial takes the link down, and `join`
//! returns only once this person may write in the space it joined.
//!
//! Devices of Alice and Bob run on one forwarder ([`Net`]) where they reach each
//! other, or alone on a forwarder that delivers nothing.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use ndn_heap::{EntryId, NextStep};
use ndn_packet::Data;
use ndn_packet::encode::DataBuilder;
use ndn_trust_envelope::TrustEnvelope;
use tokio_util::sync::CancellationToken;

use crate::error::InviteError;
use crate::host::{HintCandidate, HintKind, LinkHint, Role};
use crate::join_kit::{Gate, admitted_in, is_key, is_log_or_key, kit_config, sign_as};
use crate::policy::IntroRefusal;
use crate::proofs::{answer_proof, proof_key};
use crate::test_kit::{Calls, Net, Person, Setup, alice, alice_offers, heap, n, notebook};
use crate::wire::{AnswerBody, Outcome, ask_name, parse_intro_name, parse_offer_name};

// ---- the wait: a join returns once this person may write --------------------------------

/// Alice's laptop with an offer of her notebook, and Bob's phone, on one forwarder; the
/// phone's node face passes through `gate`.
async fn on_a_net(
    role: Role,
    gate: &Arc<Gate>,
) -> (
    crate::test_kit::Offered,
    crate::test_kit::Device,
    CancellationToken,
) {
    let net = Net::new().await;
    let cancel = CancellationToken::new();
    let alice = Person::new("/alice");
    let laptop = Setup::new(&alice, "/alice/laptop")
        .config(kit_config())
        .on(&net, &cancel)
        .start()
        .await;
    let offered = alice_offers(laptop, alice, role).await;
    let bob = Person::new("/bob");
    let gate = Arc::clone(gate);
    let phone = Setup::new(&bob, "/bob/phone")
        .config(kit_config())
        .on(&net, &cancel)
        .wrapping(move |face| gate.wrap(face))
        .start()
        .await;
    (offered, phone, cancel)
}

/// `join` returns `Ok` only when the space lists Bob (as a writer), holds the epoch key
/// and has applied the members entry that admitted him: what is read the instant it
/// returns says so, with no waiting of the test's own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn join_returns_only_when_listed_keyed_and_admitted() {
    let gate = Gate::new();
    let (offered, phone, cancel) = on_a_net(Role::Writer, &gate).await;
    let joined = phone
        .invites
        .join(&offered.code.link)
        .await
        .expect("the join returns once Bob may write");
    assert_eq!(joined.space, notebook());
    assert_eq!(joined.role, Role::Writer);
    assert_eq!(joined.inviter, n("/alice"));
    let bobs = heap(&phone, &joined.space);
    assert!(
        bobs.members().writers.contains(&n("/bob")),
        "the members of the space do not list Bob as a writer"
    );
    assert!(bobs.members().readers.contains(&n("/bob")));
    assert!(bobs.holds_epoch_key(), "the epoch key is not held");
    let admitting = admitted_in(&gate).expect("the answer names the entry that admitted Bob");
    assert!(
        bobs.applied(&admitting),
        "the entry that admitted Bob is not applied"
    );
    cancel.cancel();
}

/// While the data layer does not deliver what the join waits for, `join` does not
/// return; when it is let through, it does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn join_waits_for_what_the_data_layer_has_not_delivered() {
    let gate = Gate::new();
    gate.hold_names(is_log_or_key);
    let (offered, phone, cancel) = on_a_net(Role::Writer, &gate).await;
    let code = offered.code.link.clone();
    let joining = {
        let phone = Arc::clone(&phone);
        tokio::spawn(async move { phone.invites.join(&code).await })
    };
    gate.wait_held().await;
    assert!(
        !joining.is_finished(),
        "the join returned while the entries and keys it waits for were held back"
    );
    gate.release();
    let joined = joining
        .await
        .unwrap()
        .expect("the join returns once let through");
    assert_eq!(joined.space, notebook());
    cancel.cancel();
}

/// A join whose wait passes its bound is `NotReady`, says what it awaited (the space's
/// members, the epoch key, the admitting entry) and that the same call can be made again;
/// `next()` is `RetryLater`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn join_times_out_with_not_ready_naming_what_it_awaited() {
    // Nothing of the space reaches Bob: its creation is what is awaited.
    let gate = Gate::new();
    gate.drop_names(is_log_or_key);
    let (offered, phone, cancel) = on_a_net(Role::Writer, &gate).await;
    let got = phone.invites.join(&offered.code.link).await;
    let Err(e @ InviteError::NotReady { name, why }) = &got else {
        panic!("not NotReady: {got:?}");
    };
    assert_eq!(*name, notebook());
    assert!(why.contains("creation of"), "{why}");
    assert!(why.contains("join again with the same code"), "{why}");
    assert_eq!(e.next(), NextStep::RetryLater);
    assert!(e.retry());
    cancel.cancel();

    // The members arrive, the epoch key does not: the key is what is awaited.
    let gate = Gate::new();
    gate.drop_names(is_key);
    let (offered, phone, cancel) = on_a_net(Role::Writer, &gate).await;
    let got = phone.invites.join(&offered.code.link).await;
    let Err(InviteError::NotReady { why, .. }) = &got else {
        panic!("not NotReady: {got:?}");
    };
    assert!(why.contains("epoch key"), "{why}");
    assert!(why.contains("grant"), "{why}");
    cancel.cancel();
}

// ---- M2: a code is judged before anything is dialled -------------------------------------------

/// `code`'s link with the namespace it names replaced by `namespace`, and a link hint
/// to an address beyond this machine added: what a join would dial.
fn altered(code: &crate::host::Code, namespace: Option<&str>) -> String {
    let Ok(TrustEnvelope::Intro(mut intro)) = TrustEnvelope::from_uri(&code.link) else {
        panic!("an introduction link");
    };
    intro.namespace = namespace.map(str::to_string);
    intro.link_hint = Some(
        LinkHint {
            key: [0x42; 32],
            candidates: vec![HintCandidate {
                kind: HintKind::Host,
                addr: "192.0.2.7:6363".parse().unwrap(),
            }],
        }
        .encode(),
    );
    TrustEnvelope::Intro(intro).to_uri()
}

/// Bob's phone, its host recording what it is asked to dial.
async fn bobs_phone(calls: &Arc<Calls>) -> crate::test_kit::Device {
    let bob = Person::new("/bob");
    Setup::new(&bob, "/bob/phone")
        .calls(Arc::clone(calls))
        .config(kit_config())
        .start()
        .await
}

/// A code that names a namespace its device is not under is altered: the join refuses
/// it before it dials, since the dial gives whoever holds the key a link.
#[tokio::test]
async fn a_code_whose_device_is_outside_the_namespace_it_names_dials_nothing() {
    let offered = alice().await;
    let calls = Arc::new(Calls::default());
    let phone = bobs_phone(&calls).await;
    let got = phone
        .invites
        .join(&altered(&offered.code, Some("/evil")))
        .await;
    assert!(
        calls.dialled().is_empty(),
        "the join dialled {:?} for a code naming a namespace its device is not under (got {got:?})",
        calls.dialled()
    );
    assert!(
        matches!(got, Err(InviteError::Refused(IntroRefusal::Forged))),
        "{got:?}"
    );
}

/// A code whose device is under a namespace this device trusts, naming none or another
/// anchor of it, dials nothing: whoever holds its key would get that namespace's
/// Interests over the link.
#[tokio::test]
async fn a_code_whose_device_is_under_a_held_namespace_of_another_anchor_dials_nothing() {
    let offered = alice().await;
    let calls = Arc::new(Calls::default());
    let phone = bobs_phone(&calls).await;
    // This device holds the real /alice, rooted in another key.
    let real = Person::new("/alice");
    phone
        .validator
        .adopt_context(Arc::clone(&real.ctx))
        .unwrap();
    for named in [None, Some("/alice")] {
        let got = phone.invites.join(&altered(&offered.code, named)).await;
        assert!(
            calls.dialled().is_empty(),
            "the join dialled {:?} for a device under a held namespace the code does not \
             anchor (code names {named:?}; got {got:?})",
            calls.dialled()
        );
        assert!(
            matches!(
                got,
                Err(InviteError::Refused(IntroRefusal::InviterConflict { .. }))
            ),
            "{got:?}"
        );
    }
}

/// A second invitation from a namespace this device already holds, by the anchor it
/// holds, is still joined: the same anchor is a party known already.
#[tokio::test]
async fn a_code_from_a_held_namespace_by_its_own_anchor_is_still_dialled() {
    let crate::test_kit::Offered {
        laptop,
        alice,
        code,
        ..
    } = alice().await;
    let calls = Arc::new(Calls::default());
    let phone = bobs_phone(&calls).await;
    phone
        .validator
        .adopt_context(Arc::clone(&alice.ctx))
        .unwrap();
    for named in [None, Some("/alice")] {
        let got = phone.invites.join(&altered(&code, named)).await;
        assert_eq!(
            calls.dialled().last(),
            Some(&laptop.name),
            "the code names {named:?}; the join answered {got:?}"
        );
        // Past the dial it goes on to ask: nobody answers here, which is `NotReady`,
        // not a refusal of the code.
        assert!(matches!(got, Err(InviteError::NotReady { .. })), "{got:?}");
    }
    assert!(
        calls.undialled().is_empty(),
        "a dial that failed made nothing to take down: {:?}",
        calls.undialled()
    );
}

/// A join that fails after its dial succeeded takes the dial's link down.
#[tokio::test]
async fn a_join_that_fails_after_its_dial_takes_the_link_down() {
    let offered = alice().await;
    let calls = Arc::new(Calls::default());
    calls.dial_succeeds.store(true, Ordering::SeqCst);
    let phone = bobs_phone(&calls).await;
    let got = phone
        .invites
        .join(&altered(&offered.code, Some("/alice")))
        .await;
    assert!(matches!(got, Err(InviteError::NotReady { .. })), "{got:?}");
    assert_eq!(
        calls.undialled(),
        vec![offered.laptop.name.clone()],
        "the failed join left its dial's link up"
    );
}

/// A code that offers a space of the joiner's own namespace is refused as a request:
/// it is the joiner's already, and nothing is dialled.
#[tokio::test]
async fn a_code_of_this_devices_own_namespace_is_a_bad_request() {
    let offered = alice().await;
    let calls = Arc::new(Calls::default());
    let alice_again = Person::new("/alice");
    let phone = Setup::new(&alice_again, "/alice/phone")
        .calls(Arc::clone(&calls))
        .start()
        .await;
    let got = phone.invites.join(&offered.code.link).await;
    let Err(e @ InviteError::BadRequest { why }) = &got else {
        panic!("not a bad request: {got:?}");
    };
    assert!(why.contains("yours already"), "{why}");
    assert_eq!(e.next(), NextStep::FixRequest);
    assert!(calls.dialled().is_empty());
}

// ---- more of the joiner's side: roles, repeats, refusals, a host that does not adopt -------------

/// Alice's laptop with an offer of her notebook as `role`, on a forwarder devices of other
/// persons join.
struct World {
    net: Net,
    cancel: CancellationToken,
    offered: crate::test_kit::Offered,
}

impl Drop for World {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

async fn world(role: Role) -> World {
    let net = Net::new().await;
    let cancel = CancellationToken::new();
    let alice = Person::new("/alice");
    let laptop = Setup::new(&alice, "/alice/laptop")
        .config(kit_config())
        .on(&net, &cancel)
        .start()
        .await;
    let offered = alice_offers(laptop, alice, role).await;
    World {
        net,
        cancel,
        offered,
    }
}

/// `device` of a new person `ns`, on the world's forwarder.
async fn joiner(world: &World, ns: &str, device: &str) -> crate::test_kit::Device {
    let person = Person::new(ns);
    Setup::new(&person, device)
        .config(kit_config())
        .on(&world.net, &world.cancel)
        .start()
        .await
}

/// A reader's join returns once the space lists the joiner as a reader and its epoch key is
/// held: it is no writer of the space.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reader_join_returns_once_listed_as_a_reader_and_keyed() {
    let w = world(Role::Reader).await;
    let phone = joiner(&w, "/bob", "/bob/phone").await;
    let joined = phone
        .invites
        .join(&w.offered.code.link)
        .await
        .expect("the reader joins");
    assert_eq!(joined.role, Role::Reader);
    let bobs = heap(&phone, &notebook());
    assert!(bobs.members().readers.contains(&n("/bob")));
    assert!(
        !bobs.members().writers.contains(&n("/bob")),
        "a reader was listed as a writer"
    );
    assert!(bobs.holds_epoch_key());
}

/// Joining again with the same code, once joined, is answered again: the offer answers the
/// key it admitted, and the second join returns as the first did.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn joining_again_with_the_same_code_returns_the_same_join() {
    let w = world(Role::Writer).await;
    let phone = joiner(&w, "/bob", "/bob/phone").await;
    let first = phone
        .invites
        .join(&w.offered.code.link)
        .await
        .expect("joins");
    let again = phone
        .invites
        .join(&w.offered.code.link)
        .await
        .expect("the same code joins again");
    assert_eq!(again, first);
}

/// A code whose secret is wrong is refused by the inviter, and the refusal says how to go
/// on (`FixRequest`: check the code); nothing of the space is held afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wrong_secret_is_refused_and_the_space_is_not_opened() {
    let w = world(Role::Writer).await;
    let phone = joiner(&w, "/bob", "/bob/phone").await;
    let Ok(TrustEnvelope::Intro(mut intro)) = TrustEnvelope::from_uri(&w.offered.code.link) else {
        panic!("an introduction link");
    };
    intro.secret[0] ^= 1;
    let wrong = TrustEnvelope::Intro(intro).to_uri();
    let got = phone.invites.join(&wrong).await;
    let Err(e @ InviteError::Refused(IntroRefusal::WrongProof { .. })) = &got else {
        panic!("not refused as a wrong proof: {got:?}");
    };
    assert_eq!(e.next(), NextStep::FixRequest);
    assert!(
        phone.node.space(&notebook()).is_none(),
        "a refused join opened the space"
    );
}

/// An offer used by one key is refused to another: `Used`, `AskOwner`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_offer_used_by_one_device_is_refused_to_another_as_used() {
    let w = world(Role::Writer).await;
    let bob = joiner(&w, "/bob", "/bob/phone").await;
    bob.invites
        .join(&w.offered.code.link)
        .await
        .expect("the first joins");
    let carol = joiner(&w, "/carol", "/carol/phone").await;
    let got = carol.invites.join(&w.offered.code.link).await;
    let Err(e @ InviteError::Refused(IntroRefusal::Used)) = &got else {
        panic!("not refused as used: {got:?}");
    };
    assert_eq!(e.next(), NextStep::AskOwner);
    assert!(carol.node.space(&notebook()).is_none());
}

/// A host that does not adopt the inviter's namespace fails the join as a local failure
/// (`FixLocal`) that says what to do; the space is not opened, and the same code joins
/// once the host is fixed (the offer answers the key it admitted).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_does_not_adopt_the_inviter_fails_the_join_locally() {
    let w = world(Role::Writer).await;
    let bob = Person::new("/bob");
    let phone = Setup::new(&bob, "/bob/phone")
        .config(kit_config())
        .refusing(&["/alice"])
        .on(&w.net, &w.cancel)
        .start()
        .await;
    let got = phone.invites.join(&w.offered.code.link).await;
    let Err(e @ InviteError::Local { reason }) = &got else {
        panic!("not a local failure: {got:?}");
    };
    assert!(reason.contains("did not adopt"), "{reason}");
    assert!(reason.contains("join again with the same code"), "{reason}");
    assert_eq!(e.next(), NextStep::FixLocal);
    assert!(phone.node.space(&notebook()).is_none());
}

/// While a join waits it has opened the space and noted the join, so that a put before the
/// entry that lists the person arrives waits (`NotReady`), and does not tell the joiner to
/// ask the owner: the note is in the node's store while the join waits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_waiting_join_has_opened_the_space_and_noted_the_join() {
    let gate = Gate::new();
    gate.hold_names(is_log_or_key);
    let (offered, phone, cancel) = on_a_net(Role::Writer, &gate).await;
    let code = offered.code.link.clone();
    let joining = {
        let phone = Arc::clone(&phone);
        tokio::spawn(async move { phone.invites.join(&code).await })
    };
    gate.wait_held().await;
    let joined_notes = n("/localhost/ndn-heap/joined");
    for _ in 0..100 {
        if !phone.store.scan_under(&joined_notes, 0).is_empty() {
            break;
        }
        ndn_app::rt::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(
        !phone.store.scan_under(&joined_notes, 0).is_empty(),
        "the join did not note that it was admitted to the space"
    );
    assert!(
        phone.node.space(&notebook()).is_some(),
        "the space is not open"
    );
    gate.release();
    joining
        .await
        .unwrap()
        .expect("the join returns once let through");
    cancel.cancel();
}

// ---- what the answer must be, and what a joiner holds, before it is believed ---------------------

/// An answer that names, as the entry that admitted the joiner, one of a device outside the
/// inviter's namespace — made as the inviter would make it (a good proof, the inviter's own
/// signatures), so that no check but the device's fails — is forged: the join is refused as
/// `Forged` and no Interest is sent for an entry of that device.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_admitted_entry_of_a_device_outside_the_inviter_namespace_is_forged() {
    let gate = Gate::new();
    let (offered, phone, cancel) = on_a_net(Role::Writer, &gate).await;
    let pk = proof_key(&offered.secret, &offered.offer());
    let laptop = Arc::clone(&offered.laptop);
    gate.tamper(move |wire| {
        let data = Data::decode(wire.clone()).ok()?;
        if parse_intro_name(&data.name).is_none() {
            return Some(wire);
        }
        let mut answer = AnswerBody::decode(data.content()?.clone()).ok()?;
        let Outcome::Accepted { admitted, .. } = &mut answer.outcome else {
            return Some(wire);
        };
        *admitted = Some(EntryId {
            device: n("/mallory/laptop"),
            seq: 1,
            digest: [7; 32],
        });
        // The inviter's proof packet names the answer's fields, so it is made again; the
        // answer's own proof covers it, so it is made last.
        let proof_packet = sign_as(
            &laptop,
            DataBuilder::new(ask_name(&laptop.name, &answer.binding()), &[])
                .freshness(Duration::ZERO),
        )?;
        if let Outcome::Accepted { inviter, .. } = &mut answer.outcome {
            *inviter = proof_packet;
        }
        answer.proof = Some(answer_proof(&pk, &answer));
        sign_as(
            &laptop,
            DataBuilder::new((*data.name).clone(), &answer.encode()),
        )
    });
    let got = phone.invites.join(&offered.code.link).await;
    assert!(
        matches!(&got, Err(InviteError::Refused(IntroRefusal::Forged))),
        "an admitting entry of a device outside the inviter's namespace was believed: {got:?}"
    );
    let asked = gate.sent_where(|name| name.has_prefix(&n("/mallory")));
    assert!(
        asked.is_empty(),
        "the join asked for entries of a device outside the inviter's namespace: {asked:?}"
    );
    assert!(
        phone.node.space(&notebook()).is_none(),
        "the space was opened"
    );
    cancel.cancel();
}

/// A words code names no namespace, so the inviter's is judged only once the answer has
/// proved the code: a namespace that lies over one this device trusts is refused then, as
/// an inviter in conflict, and nothing of it is adopted or opened.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_words_code_whose_inviter_overlaps_a_held_namespace_is_refused_after_the_answer() {
    let w = world(Role::Writer).await;
    let bob = Person::new("/bob");
    let calls = Arc::new(Calls::default());
    let phone = Setup::new(&bob, "/bob/phone")
        .config(kit_config())
        .calls(Arc::clone(&calls))
        .on(&w.net, &w.cancel)
        .start()
        .await;
    // Bob trusts /alice/team: Alice's /alice lies over it, and her device /alice/laptop is not
    // under it, so nothing but the answer's credentials show the conflict.
    let team = Person::new("/alice/team");
    phone
        .validator
        .adopt_context(Arc::clone(&team.ctx))
        .unwrap();
    let got = phone.invites.join(&w.offered.code.words).await;
    let Err(e @ InviteError::Refused(IntroRefusal::InviterConflict { inviter, why })) = &got else {
        panic!("not refused as an inviter in conflict: {got:?}");
    };
    assert_eq!(*inviter, n("/alice"));
    assert!(why.contains("lies over"), "{why}");
    assert_eq!(e.next(), NextStep::AskOwner);
    assert!(!calls.adopted(), "the conflicting namespace was adopted");
    assert!(
        phone.node.space(&notebook()).is_none(),
        "the space was opened"
    );
}

// ---- a damaged offer must not be answered again from a cache -------------------------------------

/// A link or words code carries nothing that verifies the offer before the answer does, so
/// an offer whose signature was damaged in flight (a forged octet, ndn-link's fault layer)
/// is found out only after the ask. A forwarder on the way may keep that copy: it answers
/// every later Interest for the offer's name that does not ask for fresh Data, so the
/// joiner's retries would meet the same damaged copy until it is evicted. The offer is
/// therefore asked for as fresh Data only, and it carries no freshness period (a copy
/// that no cache can call fresh): every retry reaches the inviter's device.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_offer_is_asked_for_fresh_so_that_no_cache_answers_a_damaged_copy_again() {
    let gate = Gate::new();
    let (offered, phone, cancel) = on_a_net(Role::Writer, &gate).await;
    phone
        .invites
        .join(&offered.code.link)
        .await
        .expect("the join returns");
    let asked = gate.sent_fresh_where(|name| parse_offer_name(name).is_some());
    assert!(!asked.is_empty(), "the join asked for no offer");
    assert!(
        asked.iter().all(|(_, fresh)| *fresh),
        "an Interest for the offer did not ask for fresh Data, so a cache may answer it with a \
         damaged copy again and again: {asked:?}"
    );
    let packets: Vec<Data> = gate
        .received()
        .into_iter()
        .filter_map(|wire| Data::decode(wire).ok())
        .filter(|data| parse_offer_name(&data.name).is_some())
        .collect();
    assert!(!packets.is_empty(), "no offer reached the joiner");
    for offer in packets {
        let fresh = offer.meta_info().and_then(|m| m.freshness_period);
        assert!(
            fresh.is_none_or(|f| f.is_zero()),
            "the offer says it stays fresh for {fresh:?}: a cache would answer a fresh Interest \
             with a damaged copy of it"
        );
    }
    cancel.cancel();
}
