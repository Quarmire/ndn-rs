//! The joiner's side (`join.rs`, spec §19.3): a code is judged before anything is
//! dialled (M2), a join that fails after its dial takes the link down, and `join`
//! returns only once this person may write in the space it joined.
//!
//! Devices of Alice and Bob run on one forwarder ([`Net`]) where they reach each
//! other, or alone on a forwarder that delivers nothing.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use ndn_heap::NextStep;
use ndn_trust_envelope::TrustEnvelope;
use tokio_util::sync::CancellationToken;

use crate::error::InviteError;
use crate::host::{HintCandidate, HintKind, LinkHint, Role};
use crate::join_kit::{Gate, admitted_in, is_key, is_log_or_key, kit_config};
use crate::policy::IntroRefusal;
use crate::test_kit::{Calls, Net, Person, Setup, alice, alice_offers, heap, n, notebook};

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
