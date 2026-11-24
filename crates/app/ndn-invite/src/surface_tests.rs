//! What a device's invitations serve over a link (`surface.rs`, spec §13): the
//! introduction link's names while an offer stands, a grant link's names as the members
//! in force list the writers, and the departed person's take of the entry that lets them
//! go (spec §11 rule 15). Ported from the data layer's surface cases of
//! `intro_tests.rs`.

use std::sync::atomic::Ordering;

use ndn_heap::wire::{log_name, seal_key_name};

use crate::error::InviteError;
use crate::grants_kit::{Inviter, Joiner, eventually, phone_of, removal_of};
use crate::host::Role;
use crate::join_kit::{Gate, is_log};
use crate::test_kit::{Person, accepted, heap, n, notebook, start};
use crate::wire::{hint_prefix, intro_name, intro_prefix, offer_name, offer_prefix};

/// While an offer of the device has not expired by its clock the surface is open — a closed
/// one included, as it still answers the key it admitted — and carries the ask and the
/// offer's own packet, no other name the device holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_introduction_surface_is_open_while_an_offer_stands_and_carries_only_it() {
    let alice = Inviter::new(Role::Writer, None).await;
    let surface = alice.laptop().invites.surface();
    let device = alice.laptop().name.clone();
    let ask = intro_name(&device, b"parameters");
    let other = log_name(&device, &notebook(), 1);
    assert_ne!(other, alice.offer, "the space's own entry is another name");

    assert!(surface.open(), "an unexpired offer is open");
    assert!(surface.carries(&alice.offer), "the offer's packet");
    assert!(surface.carries(&ask), "an ask");
    assert!(
        !surface.carries(&other),
        "an entry the device holds is carried over an introduction link"
    );
    for name in [
        intro_prefix(&device),
        offer_prefix(&device),
        intro_prefix(&device).append("anything"),
        hint_prefix(&device),
        offer_name(&device, &[9; 16]),
        offer_name(&n("/alice/phone"), &crate::grants_kit::id_of(&alice.offer)),
    ] {
        assert!(
            !surface.carries(&name),
            "{name} crossed an introduction link: no offer of this device is named by it"
        );
    }

    alice
        .laptop()
        .invites
        .close_offer(&alice.offer)
        .await
        .unwrap();
    assert!(
        surface.open(),
        "a closed offer still answers the key it admitted until it expires"
    );
    alice.skew.store(2 * 3_600_000, Ordering::SeqCst);
    assert!(!surface.open(), "an expired offer is not open");
    assert!(!surface.carries(&alice.offer), "an expired offer's packet");
    assert!(!surface.carries(&ask), "an ask, with no offer open");
}

/// A device that has made no offer takes no stranger's introduction link.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_with_no_offer_has_no_open_surface() {
    let alice = Person::new("/alice");
    let laptop = start(&alice, "/alice/laptop").await;
    let surface = laptop.invites.surface();
    assert!(!surface.open());
    assert!(!surface.carries(&intro_name(&laptop.name, b"parameters")));
}

/// Spec §13.3 (co-writers): `Surface::grant_carries` reads the members in force on every
/// call: a listed writer's devices' seal keys are carried while the members list them
/// and not at the next call after an entry without them; the space's names and a name of
/// a listed writer outside the space follow `folder_carries` throughout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grant_carries_follows_the_writers_the_members_in_force_list() {
    let alice = Inviter::new(Role::Writer, None).await;
    let space = notebook();
    let bob_phone = phone_of("/bob").await;
    assert!(accepted(&alice.answers(&bob_phone).await));
    let surface = alice.laptop().invites.surface();
    let carol_seal = seal_key_name(&n("/carol/member/laptop"), &[5; 32]);
    let dave_seal = seal_key_name(&n("/dave/member/laptop"), &[5; 32]);
    // A name of Carol's outside the space: an entry of her own space.
    let carol_other = log_name(&n("/carol/member/laptop"), &n("/carol/32=data/diary"), 3);
    // An entry of the space by her device, which the space carries.
    let carol_entry = log_name(&n("/carol/member/laptop"), &space, 3);

    assert!(
        !surface.grant_carries(&space, &carol_seal),
        "a stranger's seal key crossed"
    );
    assert!(surface.grant_carries(&space, &carol_entry));
    assert_eq!(surface.writer_namespaces(&space), vec![n("/bob")]);

    // Members that list Carol as a writer.
    alice.changes(&space, &["/carol"], &["/carol"], &[]).await;
    assert_eq!(
        surface.writer_namespaces(&space),
        vec![n("/bob"), n("/carol")],
        "the writers' namespaces are not the listed writers', less the space's own"
    );
    assert!(
        surface.grant_carries(&space, &carol_seal),
        "a listed writer's seal key was not carried"
    );
    assert!(
        !surface.grant_carries(&space, &dave_seal),
        "an unlisted namespace's seal key crossed"
    );
    assert!(
        !surface.grant_carries(&space, &carol_other),
        "a writer's name outside the space crossed"
    );
    assert!(surface.grant_carries(&space, &carol_entry));

    // Members without Carol: her key is out at the next call, her entry of the space is
    // still carried.
    alice.changes(&space, &[], &[], &["/carol"]).await;
    assert!(
        !surface.grant_carries(&space, &carol_seal),
        "a removed writer's seal key is still carried"
    );
    assert_eq!(surface.writer_namespaces(&space), vec![n("/bob")]);
    assert_eq!(
        surface.writer_namespaces(&n("/alice/32=data/diary")),
        Vec::new()
    );
    assert!(surface.grant_carries(&space, &carol_entry));

    // A space this device does not hold lists no writer.
    assert!(!surface.grant_carries(&n("/alice/32=data/diary"), &carol_seal));
}

/// Spec §13.3 (which namespace): the namespace a listed writer unlocks is the writer's
/// own (a person is a namespace), never a name the writer's name merely starts with: a
/// writer `/home/carol` does not unlock the seal keys of the broader `/home`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_writer_below_a_namespace_unlocks_only_its_own_namespace_not_the_broader_one() {
    let alice = Inviter::new(Role::Writer, None).await;
    let space = notebook();
    let surface = alice.laptop().invites.surface();
    alice.changes(&space, &["/home/carol"], &[], &[]).await;
    let namespaces = surface.writer_namespaces(&space);
    assert_eq!(namespaces, vec![n("/home/carol")]);
    for ns in &namespaces {
        let key = seal_key_name(&ns.clone().append("member").append("x"), &[5; 32]);
        assert!(
            surface.grant_carries(&space, &key),
            "the seal key of a device of {ns}, a namespace of a listed writer, was not carried"
        );
    }
    for above in [n("/home"), n("/home/carol/member")] {
        let key = seal_key_name(&above.clone().append("member").append("x"), &[5; 32]);
        assert!(
            !surface.grant_carries(&space, &key),
            "the seal key of a device of {above}, not the writer's namespace, crossed"
        );
    }
}

/// The text of a refusal: a `BadRequest` that says why and what to do.
fn refused(e: InviteError, says: &str) {
    assert!(
        matches!(&e, InviteError::BadRequest { why } if why.contains(says) && why.contains(':')),
        "expected a refusal saying {says:?}, got {e:?}"
    );
}

/// Spec §11 rule 15 (`take_departure`, what it refuses): a hint that is no space, no entry
/// of the space, for a space this device does not hold, or signed under a namespace this
/// device holds no context of, is refused with why and what to do; an entry already held
/// is Ok at once; a hint from a device outside the space's namespace is refused first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn take_departure_takes_only_an_entry_of_a_space_it_is_a_member_of() {
    let j = Joiner::joined("/bob", Role::Writer).await;
    let surface = j.phone().invites.surface();
    let laptop = j.laptop.name.clone();
    let space = j.space.clone();
    // Not a space name.
    let e = surface
        .take_departure(
            &laptop,
            &n("/alice/notebook"),
            &log_name(&laptop, &space, 1),
        )
        .await
        .unwrap_err();
    refused(e, "no space name");
    // An entry of another space, a name that is no entry.
    let other = n("/alice/32=data/diary");
    let e = surface
        .take_departure(&laptop, &space, &log_name(&laptop, &other, 1))
        .await
        .unwrap_err();
    refused(e, "no entry of");
    let e = surface
        .take_departure(&laptop, &space, &space.clone().append("x"))
        .await
        .unwrap_err();
    refused(e, "no entry of");
    // A device that does not hold the space is no member of it.
    let carol = phone_of("/carol").await;
    let e = carol
        .invites
        .surface()
        .take_departure(&laptop, &space, &log_name(&laptop, &space, 1))
        .await
        .unwrap_err();
    refused(e, "not open here");
    // Signed under a namespace no context of which is held.
    let e = surface
        .take_departure(&laptop, &space, &log_name(&n("/mallory/phone"), &space, 1))
        .await
        .unwrap_err();
    refused(e, "no namespace this device holds");
    // An entry already held: nothing to do.
    surface
        .take_departure(&laptop, &space, &log_name(&laptop, &space, 1))
        .await
        .expect("an entry held is taken");
    // Told by a device outside the space's namespace: refused before anything is looked
    // at, even for an entry held (what the link layer passes is the peer's authenticated
    // device, and only the space's namespace lets a member go of it).
    let stranger = n("/carol/member/phone");
    let e = surface
        .take_departure(&stranger, &space, &log_name(&laptop, &space, 1))
        .await
        .unwrap_err();
    refused(e, "lies under no namespace of");
}

/// Spec §11 rule 15 (`take_departure`, bounds): an entry that cannot be fetched is
/// `NotReady`, saying what to do; one take of a space at a time; a bounded number begin a
/// minute.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn take_departure_is_one_at_a_time_for_a_space_and_bounded_a_minute() {
    let j = Joiner::joined("/bob", Role::Writer).await;
    let surface = j.phone().invites.surface();
    let laptop = j.laptop.name.clone();
    let missing = |seq: u64| log_name(&laptop, &j.space, 900 + seq);
    let e = surface
        .take_departure(&laptop, &j.space, &missing(0))
        .await
        .unwrap_err();
    assert!(
        matches!(&e, InviteError::NotReady { why, .. } if why.contains("could not be fetched") && why.contains("ask again")),
        "an entry nobody serves was answered {e:?}"
    );

    // Two at once for one space: the second is told one is under way.
    let (one, two) = (missing(1), missing(2));
    let (first, second) = tokio::join!(
        surface.take_departure(&laptop, &j.space, &one),
        surface.take_departure(&laptop, &j.space, &two),
    );
    assert!(
        matches!(&first, Err(InviteError::NotReady { why, .. }) if why.contains("could not be fetched")),
        "{first:?}"
    );
    assert!(
        matches!(&second, Err(InviteError::NotReady { why, .. }) if why.contains("being fetched already")),
        "a second take of one space was answered {second:?}"
    );

    // Two begun so far; the bound is six a minute, whatever the names.
    for seq in 3..7 {
        let e = surface
            .take_departure(&laptop, &j.space, &missing(seq))
            .await
            .unwrap_err();
        assert!(
            matches!(&e, InviteError::NotReady { why, .. } if why.contains("could not be fetched")),
            "{e:?}"
        );
    }
    let e = surface
        .take_departure(&laptop, &j.space, &missing(8))
        .await
        .unwrap_err();
    assert!(
        matches!(&e, InviteError::NotReady { why, .. } if why.contains("departure fetches in the last minute")),
        "past the minute's bound a take was answered {e:?}"
    );
}

/// Spec §11 rule 15 (the departed person's side): Bob's phone does not hear of the entry
/// that removes him (his fetches of entries are dropped), so his space still lists him and
/// his mirror stands; told which entry lets him go, he takes it by name — validated and
/// judged as any entry — and his space no longer lists him, the mirror ends, and the host
/// is told in memory, never of a departure.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_departed_person_takes_the_entry_that_lets_them_go() {
    let gate = Gate::new();
    let j = Joiner::unjoined_gated(
        "/bob",
        std::sync::Arc::new(ndn_sync::MemoryStore::new()),
        Some(std::sync::Arc::clone(&gate)),
    )
    .await;
    j.join(&j.space, Role::Writer).await;
    gate.drop_names(is_log);
    j.alice_changes(&j.space, &[], &[], &["/bob"]).await;
    let record = removal_of(&j.laptop, &j.space, "/bob");
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert!(
        heap(j.phone(), &j.space)
            .members()
            .writers
            .contains(&n("/bob")),
        "the case needs Bob's phone not to have heard of the removal"
    );
    assert_eq!(j.phone().invites.grants().len(), 1);

    gate.drop_names(|_| false);
    let surface = j.phone().invites.surface();
    let mut taken = Err(InviteError::local("not tried"));
    for _ in 0..20 {
        taken = surface
            .take_departure(&j.laptop.name, &j.space, &record)
            .await;
        if taken.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    taken.expect("Bob's phone takes the entry that lets him go");
    assert!(
        !heap(j.phone(), &j.space)
            .members()
            .writers
            .contains(&n("/bob")),
        "the entry that lets Bob go was taken and his space still lists him"
    );
    eventually("the mirror ends", || j.calls.revoked_in().len() == 1).await;
    assert_eq!(j.calls.revoked_in(), vec![(j.inviter, j.space.clone())]);
    assert_eq!(j.calls.departed(), Vec::new());
    assert_eq!(j.phone().invites.grants(), Vec::new());
}
