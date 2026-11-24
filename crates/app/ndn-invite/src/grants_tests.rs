//! The grants an offer's admission makes and the judgement of them against the members
//! of each grant's own space (`grants.rs`, spec §10, §11): ported from the data layer's
//! tests of `device/grants.rs` and the grant and departure cases of `intro_tests.rs`.
//! The first group is the notes' codec; the rest runs Alice's laptop (alone, or on a
//! forwarder with her other devices) with a host that records what it is told. The
//! members change by Alice's own `Heap::change`, and the grants follow what the data
//! layer's watch delivers.

use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::Bytes;
use hmac::Mac;
use ndn_foundation_types::Name;
use ndn_heap::Timestamp;
use ndn_sync::MemoryStore;

use crate::grants_kit::{
    Frozen, Inviter, NOTE_FLAGS, NOTE_UNTIL, Thaw, entry_name, eventually, grant_notes, key_of,
    phone_of, settle, tamper,
};
use crate::host::Role;
use crate::notes::{
    ENDED, GrantNote, HEAD, MAC_LEN, MARKED, MIRROR_HEAD, Mark, MirrorNote, NOTE_VERSION_2, Unread,
    mac_of, mirror_mac_of,
};
use crate::policy::{IntroPolicy, IntroRefusal};
use crate::test_kit::{Person, accepted, answer, ask, heap, n, notebook, start};
use crate::wire::Outcome;

const NINETY_DAYS_MS: u64 = 90 * 24 * 3600 * 1000;
const SEVEN_DAYS_MS: u64 = 7 * 24 * 3600 * 1000;
const TEN_YEARS_MS: u64 = 10 * 365 * 24 * 3600 * 1000;
const KEY: [u8; 32] = [7; 32];

// ---- the notes' codec ------------------------------------------------------------------

fn note(ended: bool, departure: Option<Mark>) -> GrantNote {
    GrantNote {
        offer: n("/alice/laptop/32=intro/offer/abc"),
        key: [9; 32],
        namespace: n("/bob"),
        space: n("/alice/32=data/notebook"),
        role: Role::Writer,
        until: Some(Timestamp(1234)),
        ended,
        departure,
    }
}

fn mark() -> Mark {
    Mark {
        record: n("/alice/phone/32=log/alice/32=data/notebook/seq=1"),
        until: Timestamp(99_000),
    }
}

/// `body` with the MAC a note of this device carries.
fn sealed(mut body: Vec<u8>) -> Bytes {
    let check = mac_of(&KEY, &body).finalize().into_bytes();
    body.extend_from_slice(&check);
    Bytes::from(body)
}

#[test]
fn a_note_with_a_mark_and_one_without_read_back_as_written() {
    for note in [
        note(false, None),
        note(true, None),
        note(true, Some(mark())),
    ] {
        let bytes = note.encode(&KEY);
        assert_eq!(GrantNote::decode(&bytes, &KEY), Ok(note));
    }
}

#[test]
fn a_version_2_note_reads_as_no_mark() {
    // The octets a build before departure marks wrote: version 2, no mark field.
    let n3 = note(true, None).encode(&KEY);
    let mut body = n3[..n3.len() - MAC_LEN].to_vec();
    body[0] = NOTE_VERSION_2;
    let v2 = sealed(body);
    assert_eq!(GrantNote::decode(&v2, &KEY), Ok(note(true, None)));

    // A version 2 note cannot carry a mark: its flag is not one it knows.
    let marked = note(true, Some(mark())).encode(&KEY);
    let mut body = marked[..marked.len() - MAC_LEN].to_vec();
    body[0] = NOTE_VERSION_2;
    assert_eq!(
        GrantNote::decode(&sealed(body), &KEY),
        Err(Unread::Form),
        "a version 2 note with the mark flag was read"
    );
}

#[test]
fn a_mark_on_a_note_not_ended_is_no_note() {
    let marked = note(true, Some(mark())).encode(&KEY);
    let mut body = marked[..marked.len() - MAC_LEN].to_vec();
    body[1] &= !ENDED;
    assert_eq!(GrantNote::decode(&sealed(body), &KEY), Err(Unread::Form));
}

#[test]
fn a_note_changed_after_its_mac_fails_it_whatever_the_change() {
    let bytes = note(true, Some(mark())).encode(&KEY);
    for at in [1, 3, 11, HEAD + 5, bytes.len() - MAC_LEN - 3] {
        let mut b = bytes.to_vec();
        b[at] ^= 1;
        assert_eq!(
            GrantNote::decode(&Bytes::from(b), &KEY),
            Err(Unread::Check),
            "a change at {at} passed"
        );
    }
    // Another device's key does not read it either.
    assert_eq!(GrantNote::decode(&bytes, &[8; 32]), Err(Unread::Check));
    // The mark's flag cleared, the check left as it was.
    let mut cleared = bytes.to_vec();
    cleared[1] &= !MARKED;
    assert_eq!(
        GrantNote::decode(&Bytes::from(cleared), &KEY),
        Err(Unread::Check)
    );
}

fn mirror(role: Role, ended: bool) -> MirrorNote {
    MirrorNote {
        key: [5; 32],
        owner: n("/alice"),
        space: n("/alice/32=data/notebook"),
        role,
        ended,
    }
}

#[test]
fn a_mirror_note_reads_back_as_written() {
    for role in [Role::Reader, Role::Writer] {
        for ended in [false, true] {
            let note = mirror(role, ended);
            assert_eq!(
                MirrorNote::decode(&note.encode(&KEY), &KEY),
                Ok(note),
                "a {role:?} mirror note (ended: {ended}) did not read back"
            );
        }
    }
}

#[test]
fn a_mirror_note_changed_or_under_another_key_does_not_read() {
    let bytes = mirror(Role::Reader, false).encode(&KEY);
    // The flags, the role, the key and a name each changed after the MAC.
    for at in [1, 2, 3, MIRROR_HEAD + 5, bytes.len() - MAC_LEN - 3] {
        let mut b = bytes.to_vec();
        b[at] ^= 1;
        assert_eq!(
            MirrorNote::decode(&Bytes::from(b), &KEY),
            Err(Unread::Check),
            "a change at {at} passed"
        );
    }
    assert_eq!(MirrorNote::decode(&bytes, &[8; 32]), Err(Unread::Check));
}

#[test]
fn an_inviters_note_does_not_read_as_a_mirror_nor_the_reverse() {
    let granted = note(false, None).encode(&KEY);
    let mirrored = mirror(Role::Writer, false).encode(&KEY);
    assert_eq!(MirrorNote::decode(&granted, &KEY), Err(Unread::Form));
    assert_eq!(GrantNote::decode(&mirrored, &KEY), Err(Unread::Form));

    // Whatever the version octet says, the MAC is of its own kind: a mirror note's body
    // sealed as an inviter's note does not check as a mirror, nor an inviter's body
    // sealed as a mirror's as an inviter's.
    let mut body = mirrored[..mirrored.len() - MAC_LEN].to_vec();
    let as_grant = {
        let check = mac_of(&KEY, &body).finalize().into_bytes();
        body.extend_from_slice(&check);
        Bytes::from(body)
    };
    assert_eq!(
        MirrorNote::decode(&as_grant, &KEY),
        Err(Unread::Check),
        "a mirror body under the inviter note's MAC read as a mirror"
    );
    let mut body = granted[..granted.len() - MAC_LEN].to_vec();
    let as_mirror = {
        let check = mirror_mac_of(&KEY, &body).finalize().into_bytes();
        body.extend_from_slice(&check);
        Bytes::from(body)
    };
    assert_eq!(
        GrantNote::decode(&as_mirror, &KEY),
        Err(Unread::Check),
        "an inviter's body under the mirror note's MAC read as an inviter's note"
    );
}

// ---- an admission makes a grant -------------------------------------------------------

async fn a_grant_is_made_once_for_the_admitted_key(role: Role, grant_for: Option<Duration>) {
    let alice = Inviter::new(role, grant_for).await;
    let bob_phone = phone_of("/bob").await;
    let before = (alice.clock)().0;
    let first = alice.answers(&bob_phone).await;
    let after = (alice.clock)().0;
    assert!(accepted(&first), "bob was answered {first:?}");
    let granted = alice.calls.granted();
    assert_eq!(
        granted.len(),
        1,
        "an admitted asker was granted {} times, not once",
        granted.len()
    );
    let g = &granted[0];
    assert_eq!(
        g.key,
        key_of(&bob_phone),
        "the grant names another key than the asker's"
    );
    assert_eq!(
        g.namespaces,
        vec![n("/bob")],
        "the grant names other namespaces than the asker's"
    );
    assert_eq!(g.folder, notebook());
    assert_eq!(g.role, role, "the grant does not carry the offer's role");
    match grant_for {
        Some(d) => {
            let ms = d.as_millis() as u64;
            assert!(
                g.until
                    .is_some_and(|t| (before + ms..=after + ms).contains(&t.0)),
                "the grant ends at {:?}, not grant_for after the admission",
                g.until
            );
        }
        None => assert_eq!(
            g.until, None,
            "a grant with no grant_for bound carries a date: it follows the members"
        ),
    }
    assert_eq!(
        alice.laptop().invites.grants(),
        granted,
        "Invites::grants is not what the host was told"
    );

    // The same key asking again is answered as before: no second grant, and the end is
    // not moved.
    alice.skew.store(5_000, Ordering::SeqCst);
    let again = alice.answers(&bob_phone).await;
    assert_eq!(again, first, "the retry was not answered as kept");
    assert_eq!(
        alice.calls.granted(),
        granted,
        "a retry of the admitted key was granted again"
    );
    assert_eq!(
        alice.laptop().invites.grants(),
        granted,
        "a retry moved the end of the grant"
    );

    // Another key finds the offer used: refused, and granted nothing.
    let carol_phone = phone_of("/carol").await;
    let other = alice.answers(&carol_phone).await;
    assert!(
        matches!(other, Some(Outcome::Refused(IntroRefusal::Used))),
        "another key asking a used offer was answered {other:?}"
    );
    assert_eq!(
        alice.calls.granted(),
        granted,
        "a refused ask was granted a link"
    );
    assert_eq!(alice.laptop().invites.grants(), granted);
}

/// Spec §10 rules 1, 2, 4: an offer's admission makes one grant, for the admitted key and
/// the asker's namespace, with the offer's role; a retry and a refused ask make none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_writers_admission_is_granted_once_and_only_to_its_key() {
    a_grant_is_made_once_for_the_admitted_key(
        Role::Writer,
        Some(Duration::from_millis(NINETY_DAYS_MS)),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_readers_admission_is_granted_once_with_the_readers_role() {
    a_grant_is_made_once_for_the_admitted_key(Role::Reader, None).await;
}

/// Spec §10 rule 1: no ask that is refused or not completed grants anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_or_unfinished_ask_grants_nothing() {
    let policy = IntroPolicy {
        grant_for: Some(Duration::from_millis(NINETY_DAYS_MS)),
        ..IntroPolicy::new()
    };
    let alice = Inviter::over(
        Role::Writer,
        policy,
        std::sync::Arc::new(MemoryStore::new()),
        &["/dave"],
    )
    .await;
    let bob_phone = phone_of("/bob").await;
    // A wrong secret.
    let wrong = ask(
        &bob_phone,
        alice.laptop(),
        &alice.offer,
        &[9; crate::proofs::SECRET_LEN],
        &[],
    );
    let got = answer(alice.laptop(), wrong).await;
    assert!(
        matches!(got, Some(Outcome::Refused(IntroRefusal::WrongProof { .. }))),
        "a wrong secret was answered {got:?}"
    );
    // A namespace that overlaps the inviter's own.
    let mallory = Person::new("/alice");
    let mallory_phone = start(&mallory, "/alice/mallory").await;
    let got = alice.answers(&mallory_phone).await;
    assert!(
        matches!(got, Some(Outcome::Refused(IntroRefusal::Conflict))),
        "a namespace over the inviter's own was answered {got:?}"
    );
    // A host that does not adopt the asker: the offer is not spent.
    let dave = Person::new("/dave");
    let dave_phone = start(&dave, "/dave/phone").await;
    let got = alice.answers(&dave_phone).await;
    assert_eq!(got, None, "an asker the host does not adopt was answered");
    assert_eq!(
        alice.calls.granted(),
        Vec::new(),
        "an ask that was refused or not completed was granted a link"
    );
    assert_eq!(alice.laptop().invites.grants(), Vec::new());
    // Once closed, a new key is refused, and granted nothing either.
    alice
        .laptop()
        .invites
        .close_offer(&alice.offer)
        .await
        .unwrap();
    let got = alice.answers(&bob_phone).await;
    assert!(
        matches!(got, Some(Outcome::Refused(IntroRefusal::Closed))),
        "an asker of a closed offer was answered {got:?}"
    );
    // Past its expiry, too.
    alice.skew.store(2 * 3_600_000, Ordering::SeqCst);
    let got = alice.answers(&bob_phone).await;
    assert!(
        matches!(
            got,
            Some(Outcome::Refused(
                IntroRefusal::Closed | IntroRefusal::Expired
            ))
        ),
        "an asker of an expired offer was answered {got:?}"
    );
    assert_eq!(alice.calls.granted(), Vec::new());
    assert_eq!(alice.laptop().invites.grants(), Vec::new());
}

/// Spec §10 rule 1: `grant_for` `Some(ZERO)`: the asker is admitted, nothing is kept, and
/// the host is told nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_zero_grant_for_makes_no_grant_and_keeps_no_note() {
    let alice = Inviter::new(Role::Writer, Some(Duration::ZERO)).await;
    let bob_phone = phone_of("/bob").await;
    let got = alice.answers(&bob_phone).await;
    assert!(accepted(&got), "bob was answered {got:?}");
    assert_eq!(
        alice.calls.granted(),
        Vec::new(),
        "grant_for = Some(ZERO) granted a link"
    );
    assert_eq!(alice.laptop().invites.grants(), Vec::new());
    let kept = grant_notes(&*alice.store);
    assert!(
        kept.is_empty(),
        "grant_for = Some(ZERO) kept {} grant notes",
        kept.len()
    );
}

/// Spec §10 rule 7: a grant is lapsed when its time passes by the device's clock: not in
/// force, and not announced as revoked (the link layer judges expiry itself).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_grant_lapses_with_its_time_and_is_not_announced_as_revoked() {
    let alice = Inviter::new(Role::Writer, Some(Duration::from_secs(3600))).await;
    let bob_phone = phone_of("/bob").await;
    assert!(accepted(&alice.answers(&bob_phone).await));
    assert_eq!(alice.laptop().invites.grants().len(), 1);
    alice.skew.store(3 * 3_600_000, Ordering::SeqCst);
    assert_eq!(
        alice.laptop().invites.grants(),
        Vec::new(),
        "a grant past its time is still in force"
    );
    settle(alice.laptop()).await;
    assert_eq!(alice.calls.revoked(), Vec::<[u8; 32]>::new());
}

// ---- the grants follow the members ------------------------------------------------------

/// Spec §10 rule 6, 7 (the plan's 5.3): the grants follow `Change::Members` of the
/// space, not a poll. The data layer syncs once an hour here, so a poll of the members
/// would come in half of it: what the host is told is what the watch delivered, and
/// the departure's record is the removing entry's log name.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_grant_follows_a_members_change_not_a_poll() {
    let alice = Inviter::slow(Role::Writer).await;
    let bob_phone = phone_of("/bob").await;
    let bob = key_of(&bob_phone);
    assert!(accepted(&alice.answers(&bob_phone).await));
    assert_eq!(alice.calls.order(), Vec::<&str>::new());
    // `change` returns the last entry it signed: the Members entry that removes Bob, and
    // the Epoch entry that follows it in a sealed space.
    let signed = alice.changes(&notebook(), &[], &[], &["/bob"]).await;
    eventually("the host is told of the end", || {
        alice.calls.revoked_in().len() == 1
    })
    .await;
    assert_eq!(
        alice.calls.order(),
        vec!["departure", "revoke_grant"],
        "the host is told of the departure just before the end of the grant"
    );
    assert_eq!(alice.calls.revoked_in(), vec![(bob, notebook())]);
    let departed = alice.calls.departed();
    assert_eq!(departed.len(), 1, "{departed:?}");
    assert_eq!(departed[0].key, bob);
    assert_eq!(departed[0].folder, notebook());
    assert_eq!(departed[0].namespaces, vec![n("/bob")]);
    let record = departed[0].record.clone();
    let parsed = ndn_heap::wire::parse_log_name(&record).expect("the record is an entry's name");
    assert_eq!(
        (&parsed.device, &parsed.space),
        (&signed.device, &notebook()),
        "the departure's record is not an entry of the removing device in the space"
    );
    assert!(
        parsed.seq <= signed.seq,
        "the departure's record {record} is above the last entry the change signed"
    );
    assert_eq!(
        Some(record),
        heap(alice.laptop(), &notebook())
            .removed_by(&n("/bob"))
            .map(|id| entry_name(&id, &notebook())),
        "the departure's record is not the entry Heap::removed_by names"
    );
    assert_eq!(alice.laptop().invites.grants(), Vec::new());
    assert_eq!(alice.laptop().invites.departures(), departed);
}

/// Spec §10 rule 6 (the plan's 5.3): a restart installs every live grant and every
/// departure mark in force through the host again, and nothing that ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restart_reinstalls_live_grants() {
    let mut alice = Inviter::new(Role::Writer, None).await;
    let bob_phone = phone_of("/bob").await;
    let carol_phone = phone_of("/carol").await;
    assert!(accepted(&alice.answers(&bob_phone).await));
    let diary = n("/alice/32=data/diary");
    alice.invites(&diary, Role::Reader, &carol_phone).await;
    assert_eq!(alice.calls.granted().len(), 2);
    // Bob is let go of the notebook: a mark, an end; Carol's grant stands.
    alice.changes(&notebook(), &[], &[], &["/bob"]).await;
    eventually("Bob's grant ends", || alice.calls.revoked_in().len() == 1).await;
    let live = alice.laptop().invites.grants();
    let marks = alice.laptop().invites.departures();
    assert_eq!(live.len(), 1, "{live:?}");
    assert_eq!(live[0].key, key_of(&carol_phone));
    assert_eq!(marks.len(), 1, "{marks:?}");

    let again = alice.restart().await;
    assert_eq!(
        again.granted(),
        live,
        "a restart did not install the live grants through the host"
    );
    assert_eq!(
        again.departed(),
        marks,
        "a restart did not install the departure marks in force through the host"
    );
    assert_eq!(again.revoked_in(), Vec::new(), "a restart revoked again");
    assert_eq!(alice.laptop().invites.grants(), live);
    assert_eq!(alice.laptop().invites.departures(), marks);
}

/// Spec §10 rule 7: a members change that leaves the person out ends the grant, whoever
/// of the owner's namespace signed it, once and durably; the others' grants stand, and
/// after a restart the grants are the same less the ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_entry_of_another_owner_device_that_leaves_the_person_out_revokes_the_grant() {
    let mut alice = Inviter::on_a_net(Role::Writer).await;
    let bob_phone = phone_of("/bob").await;
    let carol_phone = phone_of("/carol").await;
    assert!(accepted(&alice.answers(&bob_phone).await));
    let (offer2, secret2) = alice.another_offer(&notebook()).await;
    let got = answer(
        alice.laptop(),
        ask(&carol_phone, alice.laptop(), &offer2, &secret2, &[]),
    )
    .await;
    assert!(accepted(&got), "carol was answered {got:?}");
    let both = alice.laptop().invites.grants();
    assert_eq!(both.len(), 2, "two admissions, {} grants", both.len());
    let carols = both
        .iter()
        .find(|g| g.namespaces == [n("/carol")])
        .cloned()
        .expect("carol is granted");

    // Alice's phone drops Bob. No entry of the laptop is signed for it.
    let phone = alice.phone().await;
    eventually("the phone holds the notebook's members", || {
        heap(&phone, &notebook())
            .members()
            .writers
            .contains(&n("/bob"))
    })
    .await;
    heap(&phone, &notebook())
        .change(ndn_heap::MembersChange {
            remove: vec![n("/bob")],
            ..Default::default()
        })
        .await
        .expect("an owner device removes Bob");
    eventually("the laptop ends Bob's grant", || {
        alice.calls.revoked().len() == 1
    })
    .await;
    assert_eq!(
        alice.calls.revoked(),
        vec![key_of(&bob_phone)],
        "an entry signed by another device that leaves bob out did not revoke exactly bob's grant"
    );
    assert_eq!(
        alice.laptop().invites.grants(),
        vec![carols.clone()],
        "Invites::grants after an entry that leaves bob out is not carol's grant alone"
    );
    // Not again: the end is noted, however often the notes are judged.
    settle(alice.laptop()).await;
    assert_eq!(
        alice.calls.revoked().len(),
        1,
        "the end of a grant was announced more than once"
    );

    // After a restart the grants are the same, less the ended; nothing ended is revoked
    // again, and what stands is installed through the host.
    let again = alice.restart().await;
    assert_eq!(alice.laptop().invites.grants(), vec![carols.clone()]);
    assert_eq!(
        again.granted(),
        vec![carols],
        "a restart did not install what stands"
    );
    assert_eq!(
        again.revoked(),
        Vec::<[u8; 32]>::new(),
        "a restart revoked again"
    );

    // Bob, readmitted by a later entry, is not granted again by that.
    alice.changes(&notebook(), &["/bob"], &["/bob"], &[]).await;
    settle(alice.laptop()).await;
    assert!(
        alice
            .laptop()
            .invites
            .grants()
            .iter()
            .all(|g| g.key != key_of(&bob_phone)),
        "a person an entry readmitted was granted again by it"
    );
}

/// Spec §10 rule 7: the entry this device signs itself, leaving the person out, ends the
/// grant as well.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_entry_this_device_signs_that_leaves_the_person_out_revokes_the_grant() {
    let alice = Inviter::new(Role::Reader, None).await;
    let bob_phone = phone_of("/bob").await;
    assert!(accepted(&alice.answers(&bob_phone).await));
    assert_eq!(alice.laptop().invites.grants().len(), 1);
    alice.changes(&notebook(), &[], &[], &["/bob"]).await;
    eventually("the grant ends", || alice.calls.revoked().len() == 1).await;
    assert_eq!(alice.calls.revoked(), vec![key_of(&bob_phone)]);
    assert_eq!(alice.laptop().invites.grants(), Vec::new());
}

/// Spec §10 rule 7 (no cliff): a grant with no date lasts as long as the members list
/// the person, however far the clock goes; an entry that leaves the person out ends it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_grant_with_no_date_follows_the_members_not_the_clock() {
    let mut alice = Inviter::new(Role::Writer, None).await;
    let bob_phone = phone_of("/bob").await;
    assert!(accepted(&alice.answers(&bob_phone).await));
    let told = alice.calls.granted();
    assert_eq!(told.len(), 1);
    assert_eq!(told[0].until, None, "the default grant carries a date");
    alice.skew.store(TEN_YEARS_MS, Ordering::SeqCst);
    assert_eq!(
        alice.laptop().invites.grants(),
        told,
        "a grant with no date ended with the clock"
    );
    alice.restart().await;
    assert_eq!(
        alice.laptop().invites.grants(),
        told,
        "a grant with no date ended with the clock across a restart"
    );
    alice.changes(&notebook(), &[], &[], &["/bob"]).await;
    eventually("the entry ends the grant", || {
        alice.laptop().invites.grants().is_empty()
    })
    .await;
}

/// Spec §10 rules 9, 10 (host control): the host's end of a grant is durable — a restart
/// does not bring it back — and its renewal sets a date durably, for a grant the members
/// still list, past its old date or not; the invitations tell the host nothing of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_host_ends_and_renews_a_grant_durably() {
    let mut alice = Inviter::new(Role::Writer, Some(Duration::from_secs(3600))).await;
    let bob_phone = phone_of("/bob").await;
    let bob = key_of(&bob_phone);
    assert!(accepted(&alice.answers(&bob_phone).await));
    let first = alice.laptop().invites.grants();
    assert_eq!(first.len(), 1);

    // Past its date the grant is over; the host renews it: it is back, and stays back
    // across a restart.
    alice.skew.store(3 * 3_600_000, Ordering::SeqCst);
    assert_eq!(alice.laptop().invites.grants(), Vec::new());
    let now = (alice.clock)().0;
    let later = Timestamp(now + 3_600_000);
    let renewed = alice
        .laptop()
        .invites
        .renew_grant(&bob, Some(later))
        .await
        .expect("a renewal of a grant the members list")
        .expect("a grant past its date is renewable");
    assert_eq!(renewed.until, Some(later));
    assert_eq!(renewed.key, bob);
    assert_eq!(alice.laptop().invites.grants(), vec![renewed.clone()]);
    alice.restart().await;
    assert_eq!(
        alice.laptop().invites.grants(),
        vec![renewed.clone()],
        "a renewal did not survive a restart"
    );

    // A date not after the clock is refused, saying what to do; nothing moves.
    let e = alice
        .laptop()
        .invites
        .renew_grant(&bob, Some(Timestamp(now - 1)))
        .await
        .unwrap_err();
    assert!(
        matches!(&e, crate::InviteError::BadRequest { why } if why.contains("give a later date")),
        "a renewal to a past date was answered {e:?}"
    );
    assert_eq!(alice.laptop().invites.grants(), vec![renewed]);

    // No date: the grant follows the members from now on.
    let undated = alice
        .laptop()
        .invites
        .renew_grant(&bob, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(undated.until, None);
    alice.skew.store(TEN_YEARS_MS, Ordering::SeqCst);
    alice.restart().await;
    assert_eq!(alice.laptop().invites.grants(), vec![undated]);

    // The host ends it: durably, once; a key nobody granted is none.
    assert!(alice.laptop().invites.end_grant(&bob).await.unwrap());
    assert_eq!(alice.laptop().invites.grants(), Vec::new());
    assert!(
        !alice.laptop().invites.end_grant(&bob).await.unwrap(),
        "an ended grant was ended again"
    );
    assert_eq!(
        alice
            .laptop()
            .invites
            .renew_grant(&bob, None)
            .await
            .unwrap(),
        None
    );
    assert!(!alice.laptop().invites.end_grant(&[7; 32]).await.unwrap());
    let again = alice.restart().await;
    assert_eq!(
        alice.laptop().invites.grants(),
        Vec::new(),
        "the host's end of a grant did not survive a restart"
    );
    assert_eq!(again.granted(), Vec::new());
    // The invitations themselves told the host nothing of all of it.
    assert_eq!(alice.calls.revoked(), Vec::<[u8; 32]>::new());
    assert_eq!(alice.calls.granted().len(), 1);
}

/// Spec §10 rule 10: a grant an entry ended is not renewed — the person is out; offer the
/// space again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_grant_an_entry_ended_is_not_renewed() {
    let alice = Inviter::new(Role::Writer, Some(Duration::from_secs(3600))).await;
    let bob_phone = phone_of("/bob").await;
    let bob = key_of(&bob_phone);
    assert!(accepted(&alice.answers(&bob_phone).await));
    alice.changes(&notebook(), &[], &[], &["/bob"]).await;
    eventually("the grant ends", || alice.calls.revoked().len() == 1).await;
    assert_eq!(
        alice
            .laptop()
            .invites
            .renew_grant(&bob, Some(Timestamp((alice.clock)().0 + 1_000_000)))
            .await
            .unwrap(),
        None,
        "a person the members leave out was renewed a grant"
    );
    assert_eq!(alice.laptop().invites.grants(), Vec::new());
}

/// Spec §10 rule 11 (notes are checked): a party that can write the data store, but not
/// the key store, cannot bring an ended grant back or lengthen a lapsed one: a note that
/// was changed fails its MAC and is ignored.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tampered_grant_note_is_ignored_not_resurrected() {
    // The ended flag cleared on a grant the host ended.
    let mut alice = Inviter::new(Role::Writer, None).await;
    let bob_phone = phone_of("/bob").await;
    assert!(accepted(&alice.answers(&bob_phone).await));
    assert!(
        alice
            .laptop()
            .invites
            .end_grant(&key_of(&bob_phone))
            .await
            .unwrap()
    );
    assert_eq!(alice.laptop().invites.grants(), Vec::new());
    tamper(&*alice.store, |b| b[NOTE_FLAGS] &= !1);
    assert_eq!(
        alice.laptop().invites.grants(),
        Vec::new(),
        "a note with its ended flag cleared in the store brought the grant back"
    );
    let again = alice.restart().await;
    assert_eq!(
        alice.laptop().invites.grants(),
        Vec::new(),
        "a note with its ended flag cleared in the store brought the grant back at a restart"
    );
    assert_eq!(again.granted(), Vec::new());

    // The date pushed out, or taken off, on a grant that lapsed.
    for how in ["extended", "removed"] {
        let alice = Inviter::new(Role::Writer, Some(Duration::from_secs(3600))).await;
        let bob_phone = phone_of("/bob").await;
        assert!(accepted(&alice.answers(&bob_phone).await));
        alice.skew.store(3 * 3_600_000, Ordering::SeqCst);
        assert_eq!(alice.laptop().invites.grants(), Vec::new());
        tamper(&*alice.store, |b| {
            if how == "extended" {
                b[NOTE_UNTIL].copy_from_slice(&u64::MAX.to_be_bytes());
            } else {
                b[NOTE_FLAGS] &= !2;
            }
        });
        assert_eq!(
            alice.laptop().invites.grants(),
            Vec::new(),
            "a note whose date was {how} in the store brought a lapsed grant back"
        );
    }

    // An unchanged note is read: the check is not a refusal of everything.
    let alice = Inviter::new(Role::Writer, None).await;
    let bob_phone = phone_of("/bob").await;
    assert!(accepted(&alice.answers(&bob_phone).await));
    assert_eq!(alice.laptop().invites.grants().len(), 1);
}

/// Spec §10 rule 6 (role re-derived): the grant's role is the one the members give the
/// person, at every judgement — a reader promoted to a writer is listed as a writer at
/// once, and the host is told again, once; the note then bears it across a restart.
/// (A demotion is a removal and an admission: the removal ends the grant, since the
/// space's members list the person no more.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reader_promoted_to_a_writer_is_granted_as_a_writer() {
    let mut alice = Inviter::new(Role::Reader, None).await;
    let bob_phone = phone_of("/bob").await;
    let bob = key_of(&bob_phone);
    assert!(accepted(&alice.answers(&bob_phone).await));
    assert_eq!(alice.laptop().invites.grants()[0].role, Role::Reader);

    alice.changes(&notebook(), &["/bob"], &[], &[]).await;
    eventually("the host is told the new role", || {
        alice.calls.granted().len() == 2
    })
    .await;
    let now = alice.laptop().invites.grants();
    assert_eq!(now.len(), 1, "a promoted person lost the grant: {now:?}");
    assert_eq!(
        now[0].role,
        Role::Writer,
        "a reader the members promoted to a writer is still granted as a reader"
    );
    let told = alice.calls.granted();
    assert_eq!(told[1].role, Role::Writer);
    assert_eq!(told[1].key, bob);
    assert_eq!(alice.calls.revoked(), Vec::<[u8; 32]>::new());
    settle(alice.laptop()).await;
    assert_eq!(
        alice.calls.granted().len(),
        2,
        "the new role was told twice"
    );

    // Durable: after a restart the grant is a writer's and the host is told it, once.
    let again = alice.restart().await;
    assert_eq!(alice.laptop().invites.grants(), now);
    assert_eq!(again.granted(), now);
}

/// Spec §10 rule 7 (host first): an entry that leaves the person out tells the host before
/// the end is made durable — a disk that has stopped answering does not delay the link
/// layer's end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_host_is_told_of_an_end_before_it_is_durable() {
    let store = Frozen::new();
    let alice = Inviter::over(Role::Writer, IntroPolicy::new(), store.clone(), &[]).await;
    let bob_phone = phone_of("/bob").await;
    assert!(accepted(&alice.answers(&bob_phone).await));
    let _thaw = Thaw(store.clone());
    store.freeze(true);
    // The removal is signed in memory; its own flush waits for the disk, so it runs aside.
    let laptop = std::sync::Arc::clone(alice.laptop());
    let removing = tokio::spawn(async move {
        crate::grants_kit::change(&laptop, &notebook(), &[], &[], &["/bob"]).await
    });
    eventually(
        "the host is told of the end while the disk is stopped",
        || alice.calls.revoked() == vec![key_of(&bob_phone)],
    )
    .await;
    store.freeze(false);
    removing.await.unwrap();
}

// ---- a grant for each space, and the departure of a person let go -------------------------

/// Alice's notebook and diary, Bob (one phone, one key) let into both as a writer by two
/// offers: the inviter, Bob's phone, his key, the notebook, the diary.
async fn bob_in_two_spaces() -> (Inviter, crate::test_kit::Device, [u8; 32], Name, Name) {
    let alice = Inviter::new(Role::Writer, None).await;
    let bob_phone = phone_of("/bob").await;
    assert!(accepted(&alice.answers(&bob_phone).await));
    let diary = n("/alice/32=data/diary");
    alice.invites(&diary, Role::Writer, &bob_phone).await;
    let bob = key_of(&bob_phone);
    (alice, bob_phone, bob, notebook(), diary)
}

/// Spec §10 rule 13 (a second space): two offers to one person are two grants of one key;
/// a change that lets the person go of one space ends that space's grant alone and tells
/// the host which.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_offers_to_one_person_are_two_grants_and_a_removal_ends_one_spaces_alone() {
    let (alice, _bob_phone, bob, notebook, diary) = bob_in_two_spaces().await;
    let grants = alice.laptop().invites.grants();
    assert_eq!(grants.len(), 2, "two offers, {grants:?}");
    assert!(grants.iter().all(|g| g.key == bob));
    let spaces: std::collections::BTreeSet<Name> =
        grants.iter().map(|g| g.folder.clone()).collect();
    assert_eq!(
        spaces,
        std::collections::BTreeSet::from([notebook.clone(), diary.clone()]),
        "the two grants of one key are not one for each space"
    );
    assert_eq!(alice.calls.granted().len(), 2);

    alice.changes(&notebook, &[], &[], &["/bob"]).await;
    eventually("the notebook's grant ends", || {
        alice.calls.revoked_in().len() == 1
    })
    .await;
    assert_eq!(
        alice.calls.revoked_in(),
        vec![(bob, notebook.clone())],
        "a change that lets Bob go of the notebook did not revoke exactly (his key, the notebook)"
    );
    let left = alice.laptop().invites.grants();
    assert_eq!(
        left.iter().map(|g| g.folder.clone()).collect::<Vec<_>>(),
        vec![diary.clone()],
        "letting Bob go of the notebook ended his grant of the diary"
    );
    settle(alice.laptop()).await;
    assert_eq!(alice.calls.revoked_in().len(), 1);

    alice.changes(&diary, &[], &[], &["/bob"]).await;
    eventually("the diary's grant ends", || {
        alice.calls.revoked_in().len() == 2
    })
    .await;
    assert_eq!(
        alice.calls.revoked_in(),
        vec![(bob, notebook), (bob, diary)],
        "the second space's end was not told by itself, naming it"
    );
    assert_eq!(alice.laptop().invites.grants(), Vec::new());
}

/// Spec §11 rule 14 (the departure): an entry that lets the person go leaves a mark in the
/// grant's note — the entry's name and a date — that the host is told of before the end,
/// that `Invites::departures` lists, that a restart keeps (and tells the host again), and
/// that the clock ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_entry_that_lets_the_person_go_leaves_a_departure_mark() {
    let mut alice = Inviter::new(Role::Writer, None).await;
    let bob_phone = phone_of("/bob").await;
    let bob = key_of(&bob_phone);
    assert!(accepted(&alice.answers(&bob_phone).await));
    assert_eq!(
        alice.laptop().invites.departures(),
        Vec::new(),
        "a mark before an entry"
    );

    let before = (alice.clock)().0;
    alice.changes(&notebook(), &[], &[], &["/bob"]).await;
    eventually("the mark is made", || {
        !alice.laptop().invites.departures().is_empty()
    })
    .await;
    let after = (alice.clock)().0;
    let marks = alice.laptop().invites.departures();
    assert_eq!(marks.len(), 1, "{marks:?}");
    let mark = &marks[0];
    assert_eq!(mark.key, bob);
    assert_eq!(mark.namespaces, vec![n("/bob")]);
    assert_eq!(mark.folder, notebook());
    assert_eq!(
        mark.record,
        crate::grants_kit::removal_of(alice.laptop(), &notebook(), "/bob"),
        "the mark names another entry"
    );
    assert!(
        (before + SEVEN_DAYS_MS..=after + SEVEN_DAYS_MS).contains(&mark.until.0),
        "the mark ends at {:?}, not seven days after the end of the grant",
        mark.until
    );
    assert_eq!(
        alice.calls.departed(),
        marks,
        "the host was told another mark"
    );
    assert_eq!(
        alice.calls.order(),
        vec!["departure", "revoke_grant"],
        "the host is told of the departure just before the end of the grant"
    );

    // Durable: the same marks after a restart, and the host is told them again.
    let again = alice.restart().await;
    assert_eq!(
        alice.laptop().invites.departures(),
        marks,
        "a restart lost the mark"
    );
    assert_eq!(again.departed(), marks);
    assert_eq!(again.revoked_in(), Vec::new());

    // The clock ends it: not listed after its date.
    alice.skew.store(SEVEN_DAYS_MS + 5_000, Ordering::SeqCst);
    assert_eq!(
        alice.laptop().invites.departures(),
        Vec::new(),
        "a mark past its date is still listed"
    );
}

/// Spec §11 rule 14 (`departure_for`): zero makes no mark and the host is told of the end
/// alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_zero_departure_for_makes_no_mark() {
    let policy = IntroPolicy {
        departure_for: Duration::ZERO,
        ..IntroPolicy::new()
    };
    let alice = Inviter::over(
        Role::Writer,
        policy,
        std::sync::Arc::new(MemoryStore::new()),
        &[],
    )
    .await;
    let bob_phone = phone_of("/bob").await;
    assert!(accepted(&alice.answers(&bob_phone).await));
    alice.changes(&notebook(), &[], &[], &["/bob"]).await;
    eventually("the grant ends", || alice.calls.revoked().len() == 1).await;
    assert_eq!(alice.laptop().invites.grants(), Vec::new());
    assert_eq!(alice.laptop().invites.departures(), Vec::new());
    assert_eq!(alice.calls.departed(), Vec::new());
    assert_eq!(alice.calls.order(), vec!["revoke_grant"]);
}

/// Spec §10 rule 9, §11 rule 14: the host's own end makes no mark (the person was not let
/// go by an entry), and `end_grant_in` ends one space's grants alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_hosts_own_end_makes_no_mark_and_end_grant_in_ends_one_space() {
    let (mut alice, _bob_phone, bob, notebook, diary) = bob_in_two_spaces().await;
    assert!(
        alice
            .laptop()
            .invites
            .end_grant_in(&bob, &notebook)
            .await
            .unwrap()
    );
    assert!(
        !alice
            .laptop()
            .invites
            .end_grant_in(&bob, &notebook)
            .await
            .unwrap(),
        "an ended grant was ended again"
    );
    assert!(
        !alice
            .laptop()
            .invites
            .end_grant_in(&bob, &n("/alice/32=data/other"))
            .await
            .unwrap(),
        "a space nobody granted was ended"
    );
    assert_eq!(
        alice
            .laptop()
            .invites
            .grants()
            .iter()
            .map(|g| g.folder.clone())
            .collect::<Vec<_>>(),
        vec![diary.clone()],
        "ending one space's grant did not leave the other's"
    );
    assert_eq!(
        alice.laptop().invites.departures(),
        Vec::new(),
        "the host's end left a mark"
    );
    assert!(alice.laptop().invites.end_grant(&bob).await.unwrap());
    assert_eq!(alice.laptop().invites.grants(), Vec::new());
    assert_eq!(alice.laptop().invites.departures(), Vec::new());
    let again = alice.restart().await;
    assert_eq!(alice.laptop().invites.grants(), Vec::new());
    assert_eq!(alice.laptop().invites.departures(), Vec::new());
    assert_eq!(again.departed(), Vec::new());
    assert_eq!(
        alice.calls.revoked_in(),
        Vec::new(),
        "the invitations told the host of the host's own end"
    );
}

/// Spec §11 rule 14 (two notes of one key): the marks of two notes are two marks, each of
/// its space's entry, listed by space; the grant that stands is not affected; a person
/// invited again to the space they were let go of has no mark of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_notes_of_one_key_keep_a_mark_each_and_an_invitation_again_supersedes_one() {
    let (alice, bob_phone, bob, notebook, diary) = bob_in_two_spaces().await;
    alice.changes(&notebook, &[], &[], &["/bob"]).await;
    let r1 = crate::grants_kit::removal_of(alice.laptop(), &notebook, "/bob");
    eventually("the notebook's mark", || {
        alice.laptop().invites.departures().len() == 1
    })
    .await;
    let marks = alice.laptop().invites.departures();
    assert_eq!((&marks[0].folder, &marks[0].record), (&notebook, &r1));
    assert_eq!(
        alice.laptop().invites.grants().len(),
        1,
        "the diary's grant stands"
    );

    alice.changes(&diary, &[], &[], &["/bob"]).await;
    let r2 = crate::grants_kit::removal_of(alice.laptop(), &diary, "/bob");
    eventually("the diary's mark", || {
        alice.laptop().invites.departures().len() == 2
    })
    .await;
    let marks = alice.laptop().invites.departures();
    for (space, record) in [(&notebook, &r1), (&diary, &r2)] {
        assert!(
            marks
                .iter()
                .any(|m| m.key == bob && &m.folder == space && &m.record == record),
            "no mark of {space} by {record}: {marks:?}"
        );
    }

    // Invited into the notebook again: the old mark of the notebook is no longer shown
    // (the person holds a grant of it); the diary's stands.
    let (offer, secret) = alice.another_offer(&notebook).await;
    let got = answer(
        alice.laptop(),
        ask(&bob_phone, alice.laptop(), &offer, &secret, &[]),
    )
    .await;
    assert!(accepted(&got), "bob was invited again and answered {got:?}");
    let marks = alice.laptop().invites.departures();
    assert_eq!(
        marks.iter().map(|m| m.folder.clone()).collect::<Vec<_>>(),
        vec![diary],
        "a person invited again still has the mark of the space"
    );
    assert_eq!(
        alice
            .laptop()
            .invites
            .grants()
            .iter()
            .filter(|g| g.folder == notebook)
            .count(),
        1
    );
}

/// Spec §11 rule 14 (notes are MAC'd, the mark with them): a mark added to a note the
/// host ended, cleared from one an entry ended, or moved (its date pushed out) fails the
/// note's check; nothing is listed from it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mark_added_cleared_or_moved_in_the_store_is_ignored() {
    for how in ["added", "cleared", "moved"] {
        let alice = Inviter::new(Role::Writer, None).await;
        let bob_phone = phone_of("/bob").await;
        let bob = key_of(&bob_phone);
        assert!(accepted(&alice.answers(&bob_phone).await));
        if how == "added" {
            assert!(alice.laptop().invites.end_grant(&bob).await.unwrap());
        } else {
            alice.changes(&notebook(), &[], &[], &["/bob"]).await;
            eventually("the mark is made", || {
                alice.laptop().invites.departures().len() == 1
            })
            .await;
        }
        let until = alice.laptop().invites.departures().first().map(|m| m.until);
        tamper(&*alice.store, |b| match how {
            // The flag, and a date and a name where the mark would be.
            "added" => {
                b[NOTE_FLAGS] |= 4;
                let at = b.len() - 32;
                let mut mark = u64::MAX.to_be_bytes().to_vec();
                let name = n("/alice/phone/32=log/alice/32=data/notebook").encode_to_tlv();
                mark.extend_from_slice(&(name.len() as u16).to_be_bytes());
                mark.extend_from_slice(&name);
                b.splice(at..at, mark);
            }
            "cleared" => b[NOTE_FLAGS] &= !4,
            _ => {
                let old = until.unwrap().0.to_be_bytes();
                let at = b
                    .windows(8)
                    .position(|w| w == old)
                    .expect("the mark's date is in the note");
                b[at..at + 8].copy_from_slice(&u64::MAX.to_be_bytes());
            }
        });
        assert_eq!(
            alice.laptop().invites.departures(),
            Vec::new(),
            "{how}: a note whose mark was changed in the store still lists a mark"
        );
        assert_eq!(alice.laptop().invites.grants(), Vec::new(), "{how}");
    }

    // The note unchanged: its mark is listed (the check is not a refusal of all).
    let alice = Inviter::new(Role::Writer, None).await;
    let bob_phone = phone_of("/bob").await;
    assert!(accepted(&alice.answers(&bob_phone).await));
    alice.changes(&notebook(), &[], &[], &["/bob"]).await;
    eventually("the mark is made", || {
        alice.laptop().invites.departures().len() == 1
    })
    .await;
}

/// A public space Alice's laptop owns.
async fn public_space(alice: &Inviter) -> Name {
    let open = n("/alice/32=data/open");
    alice
        .laptop()
        .node
        .create(
            &open,
            ndn_heap::Share {
                readers: ndn_heap::Readers::Anyone,
                writers: vec![n("/alice")],
            },
        )
        .await
        .unwrap();
    open
}

/// Spec §10 rule 6, 7 (a public space): the members list no reader by being public, so a
/// writer's standing there is the members' while they list them. An entry that removes a
/// writer ends the grant (the removal is what `Heap::removed_by` names, and the mark names
/// it).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_grant_of_a_public_space_ends_when_an_entry_removes_the_person() {
    let alice = Inviter::new(Role::Writer, None).await;
    let open = public_space(&alice).await;
    let bob_phone = phone_of("/bob").await;
    alice.invites(&open, Role::Writer, &bob_phone).await;
    let grants = alice.laptop().invites.grants();
    assert_eq!(grants.len(), 1, "{grants:?}");
    assert_eq!(grants[0].role, Role::Writer);

    alice.changes(&open, &[], &[], &["/bob"]).await;
    eventually("the writer's grant ends", || {
        alice.calls.revoked_in().len() == 1
    })
    .await;
    assert_eq!(
        alice.calls.revoked_in(),
        vec![(key_of(&bob_phone), open.clone())]
    );
    let marks = alice.laptop().invites.departures();
    assert_eq!(marks.len(), 1, "{marks:?}");
    assert_eq!(
        marks[0].record,
        crate::grants_kit::removal_of(alice.laptop(), &open, "/bob")
    );
    assert_eq!(alice.laptop().invites.grants(), Vec::new());
}

/// Spec §10 rule 2 (a public space): a person who only reads a public space cannot be
/// removed from it (everybody reads it, and no entry lists them), so a grant for them
/// could not end by the members' change as the rule requires: a Reader's admission to a
/// public space makes **no grant** (and no note), and the host is told nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reader_grant_of_a_public_space_ends() {
    let alice = Inviter::new(Role::Writer, None).await;
    let open = public_space(&alice).await;
    let carol_phone = phone_of("/carol").await;
    alice.invites(&open, Role::Reader, &carol_phone).await;
    assert_eq!(
        alice.laptop().invites.grants(),
        Vec::new(),
        "a Reader of a public space was granted a link nothing can end"
    );
    assert_eq!(alice.calls.granted(), Vec::new());
    assert_eq!(grant_notes(&*alice.store), Vec::new());
    // A Reader of a private space is granted, and the members' change ends it.
    let dave_phone = phone_of("/dave").await;
    alice.invites(&notebook(), Role::Reader, &dave_phone).await;
    assert_eq!(alice.laptop().invites.grants().len(), 1);
}

/// Spec §10 rule 6: a grant whose space is not known when the invitations start (it was
/// not restored with the node's spaces) is told to the host when the space is known: the
/// first judgement that finds the person listed installs it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_grant_whose_space_is_known_only_after_start_is_installed_when_it_is() {
    let mut alice = Inviter::new(Role::Writer, None).await;
    let bob_phone = phone_of("/bob").await;
    assert!(accepted(&alice.answers(&bob_phone).await));
    let told = alice.calls.granted();
    assert_eq!(told.len(), 1);
    // The node's record of the space goes: it is not restored at the next start.
    let again = alice.restart_polling(Duration::from_millis(200)).await;
    assert_eq!(
        again.granted(),
        Vec::new(),
        "a grant of a space not known was installed"
    );
    assert_eq!(alice.laptop().invites.grants(), Vec::new());
    // The space is known again.
    alice
        .laptop()
        .node
        .open(&notebook())
        .await
        .expect("the space opens from what the store holds");
    eventually("the grant is installed once its space is known", || {
        again.granted() == told
    })
    .await;
    assert_eq!(alice.laptop().invites.grants(), told);
    settle(alice.laptop()).await;
    assert_eq!(again.granted().len(), 1, "the grant was installed twice");
}
