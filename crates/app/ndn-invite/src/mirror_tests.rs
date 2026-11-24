//! The mirror grant, the joiner's end of a grant (spec §11 rules 17, 18): kept by a join's
//! end (`Inner::keep_mirror`), listed by `Invites::grants`, judged against the members of
//! the joined space, and the spaces it joined (`Invites::joined_folders`,
//! `Invites::joined_changes`). Ported from the data layer's `mirror_tests.rs`.
//!
//! Bob's phone really joins Alice's notebook on one forwarder with her laptop
//! ([`Joiner`]): the members change by Alice's own `Heap::change`, and what Bob's device
//! judges is what the data layer delivers to it. A person who is let go learns it by taking
//! the entry that lets them go (`Surface::take_departure`), as ndn-link tells it to.

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_heap::{Readers, Share};
use ndn_security::self_certifying::self_certifying_name;
use tokio::sync::watch::Receiver;

use crate::grants_kit::{
    Frozen, Joiner, Thaw, eventually, mirror_notes, phone_of, removal_of, settle,
};
use crate::host::{JOINED_WRITERS_MAX, JoinedFolder, Role};
use crate::notes::MirrorNote;
use crate::test_kit::{heap, n, notebook};

/// The watcher saw a change: the generation rose above `last`.
async fn fired(rx: &mut Receiver<u64>, last: &mut u64, what: &str) {
    eventually(&format!("{what}: joined_changes did not fire"), || {
        rx.has_changed().unwrap()
    })
    .await;
    let now = *rx.borrow_and_update();
    assert!(
        now > *last,
        "{what}: the generation {now} did not rise above {last}"
    );
    *last = now;
}

fn quiet(rx: &Receiver<u64>, what: &str) {
    assert!(
        !rx.has_changed().unwrap(),
        "{what}: joined_changes fired though the list did not change"
    );
}

/// Spec §11 rule 17: a join's end keeps the mirror note; the grant lists it with the
/// inviter's key, the inviter's namespace as the owner, the space, the inviter's role in
/// the members and no date; the host is told once; `joined_folders` lists the space with
/// this device's role; a restart keeps both and tells the host the entry through
/// `Host::grant` again, as it does every grant in force.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_join_keeps_the_mirror_grant_lists_it_and_tells_the_host_once() {
    let mut j = Joiner::unjoined("/bob").await;
    assert_eq!(
        j.phone().invites.grants(),
        Vec::new(),
        "a grant before the join's end"
    );
    assert_eq!(j.phone().invites.joined_folders(), Vec::new());
    j.join(&notebook(), Role::Writer).await;

    let grant = j.mirror_grant(&j.space, Role::Writer);
    assert_eq!(j.phone().invites.grants(), vec![grant.clone()]);
    assert_eq!(
        j.calls.granted(),
        vec![grant.clone()],
        "the host was not told of the mirror grant exactly once"
    );
    assert_eq!(
        j.phone().invites.joined_folders(),
        vec![JoinedFolder {
            inviter: j.inviter,
            owner: n("/alice"),
            folder: j.space.clone(),
            role: Role::Writer,
            writers: Vec::new(),
        }]
    );
    assert_eq!(
        mirror_notes(&*j.store).len(),
        1,
        "one join, one mirror note"
    );
    assert_eq!(j.calls.departed(), Vec::new());

    // A restart brings the entry back, from the note and the entries it reads back, and
    // tells the host of it once.
    let again = j.restart().await;
    assert_eq!(
        j.phone().invites.grants(),
        vec![grant.clone()],
        "the entry did not survive a restart"
    );
    assert_eq!(j.phone().invites.joined_folders().len(), 1);
    assert_eq!(again.granted(), vec![grant]);
    assert_eq!(again.revoked_in(), Vec::new());
}

/// Spec §11 rule 18: `joined_folders` lists the other writers' namespaces as the members
/// give them, minus this device's own namespace and every namespace above or below it,
/// only namespaces, sorted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn joined_folders_lists_the_other_writers_but_never_this_devices_own_names() {
    // Bob's namespace is /home/bob: /home lies above it, its phone below.
    let j = Joiner::joined("/home/bob", Role::Writer).await;
    // Only the namespaces held here are routed.
    j.hold("/dave");
    j.hold("/carol");
    let writers = [
        "/home/bob",
        "/home",
        "/home/bob/phone/member",
        "/dave",
        "/carol",
    ];
    j.alice_changes(&j.space, &writers, &[], &[]).await;
    // "Sorted" is the canonical order of names.
    let mut expected = vec![n("/carol"), n("/dave")];
    expected.sort();
    eventually("Bob's joined list names the other writers", || {
        j.writers() == expected
    })
    .await;
    let surface = j.phone().invites.surface();
    assert_eq!(surface.joined_folders(), j.phone().invites.joined_folders());
}

/// Spec §11 rule 18: the members are the inviter's word, so a route is made only for a
/// name that names itself: the namespace of a trust context held here, or a
/// self-certifying person. A reserved name, a broad shared one, a name no context held
/// here covers, and any name strictly above or below a namespace held here (a longer
/// route than the one already held) are none of them listed: each would win the
/// forwarder's longest-prefix match over a better route of this device's own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn joined_folders_never_lists_a_name_the_inviter_picked_to_win_a_longer_match() {
    let j = Joiner::joined("/home/bob", Role::Writer).await;
    // Held here: /dave and, under it, /dave/team; /carol.
    j.hold("/dave");
    j.hold("/dave/team");
    j.hold("/carol");
    let person = self_certifying_name(&[7u8; 32]);
    let person_text = person.to_string();
    let writers = [
        "/com",
        "/user",
        "/localhop",
        "/localhost",
        "/localhost/x",
        "/frank/member/x",
        "/erin/member",
        "/dave/team/x",
        "/carol",
        &person_text,
    ];
    j.alice_changes(&j.space, &writers, &[], &[]).await;
    let mut expected = vec![n("/carol"), person];
    expected.sort();
    eventually("Bob's phone lists the writers Alice named", || {
        heap(j.phone(), &j.space).members().writers.len() > 10
    })
    .await;
    assert_eq!(
        j.writers(),
        expected,
        "the inviter's members made a route for a reserved, broad, unheld or longer-than-held \
         name: only the namespaces held here and a self-certifying person may be listed"
    );
}

/// Spec §11 rule 18: at most `JOINED_WRITERS_MAX` writers, the first of the sorted
/// namespaces, however many the members list.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn joined_folders_lists_at_most_the_bound_of_writers_sorted() {
    let j = Joiner::joined("/bob", Role::Writer).await;
    for i in 1..=20 {
        j.hold(&format!("/w{i:02}"));
    }
    let many: Vec<String> = (1..=20).rev().map(|i| format!("/w{i:02}")).collect();
    let writers: Vec<&str> = many.iter().map(String::as_str).collect();
    j.alice_changes(&j.space, &writers, &[], &[]).await;
    let expected: Vec<Name> = (1..=JOINED_WRITERS_MAX)
        .map(|i| n(&format!("/w{i:02}")))
        .collect();
    eventually("Bob's joined list is at its bound", || {
        j.writers() == expected
    })
    .await;
}

/// Spec §11 rule 18: `joined_changes` fires on a join, on an entry that adds a writer,
/// on one that removes a writer, on one that changes this device's role, on the mirror
/// ending — and on nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn joined_changes_fires_when_the_list_changes_and_only_then() {
    let j = Joiner::unjoined("/bob").await;
    let mut rx = j.phone().invites.joined_changes();
    let mut last = *rx.borrow_and_update();
    settle(j.phone()).await;
    quiet(&rx, "a judgement before the join");

    j.join(&notebook(), Role::Reader).await;
    fired(&mut rx, &mut last, "a join").await;
    settle(j.phone()).await;
    quiet(&rx, "a judgement with nothing new");
    j.hold("/carol");

    j.alice_changes(&j.space, &["/carol"], &["/carol"], &[])
        .await;
    fired(&mut rx, &mut last, "an entry that adds a writer").await;
    assert_eq!(j.writers(), vec![n("/carol")]);

    j.alice_changes(&j.space, &[], &[], &["/carol"]).await;
    fired(&mut rx, &mut last, "an entry that removes a writer").await;
    assert_eq!(j.writers(), Vec::<Name>::new());

    // Bob a reader until now; Alice makes him a writer.
    assert_eq!(j.phone().invites.joined_folders()[0].role, Role::Reader);
    j.alice_changes(&j.space, &["/bob"], &[], &[]).await;
    fired(
        &mut rx,
        &mut last,
        "an entry that changes this device's role",
    )
    .await;
    assert_eq!(j.phone().invites.joined_folders()[0].role, Role::Writer);

    j.let_go(&j.space).await;
    fired(&mut rx, &mut last, "an entry that leaves this device out").await;
    assert_eq!(j.phone().invites.joined_folders(), Vec::new());
    settle(j.phone()).await;
    quiet(&rx, "a judgement after the entry ended");

    // The host's end of a fresh entry fires too.
    let j = Joiner::joined("/bob", Role::Writer).await;
    let mut rx = j.phone().invites.joined_changes();
    let mut last = *rx.borrow_and_update();
    assert!(j.phone().invites.end_grant(&j.inviter).await.unwrap());
    fired(&mut rx, &mut last, "the host's end").await;
    assert!(!j.phone().invites.end_grant(&j.inviter).await.unwrap());
    quiet(&rx, "an end of what had ended");
}

/// Spec §11 rule 17: an entry that leaves this device out ends the mirror: the host is told
/// in memory (`revoke_grant` with the key and the space, once), **never a departure**;
/// `grants` and `joined_folders` drop it; the note is marked ended durably, so an entry that
/// lists this device again does not bring the mirror back (a re-invitation does, by a
/// join).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_mirror_ends_when_the_members_leave_this_device_out_without_a_departure() {
    let mut j = Joiner::joined("/bob", Role::Writer).await;
    j.let_go(&j.space).await;
    eventually("the host is told of the end", || {
        j.calls.revoked_in().len() == 1
    })
    .await;
    assert_eq!(
        j.calls.revoked_in(),
        vec![(j.inviter, j.space.clone())],
        "an entry that leaves bob out did not revoke exactly (the inviter's key, the space)"
    );
    assert_eq!(
        j.calls.departed(),
        Vec::new(),
        "a mirror grant made a departure"
    );
    assert!(!j.calls.order().contains(&"departure"));
    assert_eq!(j.phone().invites.grants(), Vec::new());
    assert_eq!(j.phone().invites.joined_folders(), Vec::new());
    // Once, however often the notes are judged.
    settle(j.phone()).await;
    assert_eq!(j.calls.revoked_in().len(), 1, "the end was told again");

    // An entry that lists Bob again does not bring the ended mirror back.
    j.alice_changes(&j.space, &["/bob"], &["/bob"], &[]).await;
    eventually("Bob's phone lists himself again", || {
        heap(j.phone(), &j.space)
            .members()
            .writers
            .contains(&n("/bob"))
    })
    .await;
    settle(j.phone()).await;
    assert_eq!(
        j.phone().invites.grants(),
        Vec::new(),
        "an entry that readmitted bob resurrected an ended mirror"
    );
    assert_eq!(j.phone().invites.joined_folders(), Vec::new());

    // And after a restart.
    let again = j.restart().await;
    assert_eq!(j.phone().invites.grants(), Vec::new());
    assert_eq!(again.granted(), Vec::new());
    assert_eq!(again.revoked_in(), Vec::new());
    assert_eq!(again.departed(), Vec::new());
}

/// Spec §11 rule 17: the host is told of an end in memory before it is durable: a disk that
/// has stopped answering does not delay the link layer's end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_host_is_told_of_a_mirrors_end_before_it_is_durable() {
    let store = Frozen::new();
    let j = Joiner::joined_over("/bob", Role::Writer, store.clone()).await;
    j.alice_changes(&j.space, &[], &[], &["/bob"]).await;
    let record = removal_of(&j.laptop, &j.space, "/bob");
    // Bob's phone holds the entry that lets him go before the disk stops.
    let surface = j.phone().invites.surface();
    let (from, space) = (j.laptop.name.clone(), j.space.clone());
    let _thaw = Thaw(store.clone());
    store.freeze(true);
    let taking = tokio::spawn(async move { surface.take_departure(&from, &space, &record).await });
    eventually(
        "the host is told of the end while the disk is stopped",
        || j.calls.revoked_in() == vec![(j.inviter, j.space.clone())],
    )
    .await;
    store.freeze(false);
    let _ = taking.await.unwrap();
}

/// Spec §11 rule 17: the host ends the mirror: `end_grant(key)` ends the key's inviter notes
/// **and** mirror notes, `end_grant_in(key, space)` those of the space; durable, no
/// departure, the host is not told; the note stays ended while the members still list this
/// device; a second join replaces the note, and another inviter key is another entry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_host_ends_the_mirror_and_a_second_join_replaces_it() {
    let j = Joiner::joined("/bob", Role::Writer).await;
    let other = n("/alice/32=data/other");
    assert!(
        !j.phone()
            .invites
            .end_grant_in(&j.inviter, &other)
            .await
            .unwrap(),
        "an end of a space that was not joined ended something"
    );
    assert!(!j.phone().invites.end_grant(&[9; 32]).await.unwrap());
    assert_eq!(
        j.phone().invites.grants().len(),
        1,
        "an end of another key or space ended the entry"
    );

    assert!(
        j.phone()
            .invites
            .end_grant_in(&j.inviter, &j.space)
            .await
            .unwrap()
    );
    assert_eq!(j.phone().invites.grants(), Vec::new());
    assert_eq!(j.phone().invites.joined_folders(), Vec::new());
    assert_eq!(
        j.calls.revoked_in(),
        Vec::new(),
        "the host was told of its own end"
    );
    assert_eq!(j.calls.departed(), Vec::new());
    assert!(
        !j.phone().invites.end_grant(&j.inviter).await.unwrap(),
        "what had ended ended again"
    );
    // The members still list Bob; the ended note does not come back by itself.
    settle(j.phone()).await;
    assert_eq!(j.phone().invites.grants(), Vec::new());

    // A second join of the same space by the same key replaces the note.
    j.phone()
        .invites
        .inner()
        .keep_mirror(j.inviter, &n("/alice"), &j.space)
        .await
        .unwrap();
    assert_eq!(
        j.phone().invites.grants(),
        vec![j.mirror_grant(&j.space, Role::Writer)]
    );
    assert_eq!(
        mirror_notes(&*j.store).len(),
        1,
        "the second join added a note"
    );
    assert_eq!(
        j.calls.granted().len(),
        2,
        "the second join did not tell the host"
    );

    // Another inviter key (a second device of Alice's) is another entry.
    j.phone()
        .invites
        .inner()
        .keep_mirror([3; 32], &n("/alice"), &j.space)
        .await
        .unwrap();
    assert_eq!(j.phone().invites.grants().len(), 2);
    assert_eq!(j.phone().invites.joined_folders().len(), 2);
    assert_eq!(mirror_notes(&*j.store).len(), 2);
    assert!(j.phone().invites.end_grant(&[3; 32]).await.unwrap());
    assert_eq!(
        j.phone().invites.grants(),
        vec![j.mirror_grant(&j.space, Role::Writer)],
        "ending one key's entry ended the other's"
    );
    // end_grant(key) ends it whatever the space.
    assert!(j.phone().invites.end_grant(&j.inviter).await.unwrap());
    assert_eq!(j.phone().invites.grants(), Vec::new());
}

/// Spec §10 rule 10, §11 rule 17: the mirror has no date and `renew_grant` leaves it
/// untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn renew_grant_leaves_a_mirror_undated() {
    let j = Joiner::joined("/bob", Role::Writer).await;
    let later = ndn_heap::Timestamp(j.phone().node.now().0 + 3_600_000);
    assert_eq!(
        j.phone()
            .invites
            .renew_grant(&j.inviter, Some(later))
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        j.phone().invites.grants(),
        vec![j.mirror_grant(&j.space, Role::Writer)]
    );
}

/// Spec §11 rule 17: a space not open here, no entry (nothing to judge by); and a space
/// that is not owned by the inviter's own namespace makes none (the inviter would be
/// granted a link into a space it does not own).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_note_is_kept_without_the_space_or_for_a_space_the_inviter_does_not_own() {
    let j = Joiner::joined("/bob", Role::Writer).await;
    // The join's end on a device that does not hold the space keeps nothing.
    let bare = phone_of("/carol").await;
    bare.invites
        .inner()
        .keep_mirror(j.inviter, &n("/alice"), &j.space)
        .await
        .unwrap();
    assert_eq!(bare.invites.grants(), Vec::new());
    assert_eq!(bare.invites.joined_folders(), Vec::new());
    assert_eq!(mirror_notes(&*bare.store), Vec::new());

    // A space of Bob's own, named by a hostile offer: Bob's own members list Bob, yet the
    // inviter is granted nothing for it.
    let own = n("/bob/32=data/diary");
    j.phone()
        .node
        .create(
            &own,
            Share {
                readers: Readers::Persons(vec![n("/bob")]),
                writers: vec![n("/bob")],
            },
        )
        .await
        .unwrap();
    let before = mirror_notes(&*j.store).len();
    j.phone()
        .invites
        .inner()
        .keep_mirror(j.inviter, &n("/alice"), &own)
        .await
        .unwrap();
    assert_eq!(
        j.phone().invites.grants(),
        vec![j.mirror_grant(&j.space, Role::Writer)],
        "a space of Bob's own was granted to the inviter"
    );
    assert_eq!(mirror_notes(&*j.store).len(), before);
}

/// Spec §11 rule 17: a mirror note whose MAC fails (made under another key, or changed in
/// the store, or a note the host ended with the flag cleared) grants nothing; an inviter's
/// note is no mirror note and the reverse.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mirror_note_that_fails_its_mac_or_is_of_the_other_kind_grants_nothing() {
    let rewrite = |j: &Joiner, edit: &dyn Fn(&Name, &Bytes) -> Bytes| {
        let mut notes = mirror_notes(&*j.store);
        assert_eq!(notes.len(), 1);
        let (name, value) = notes.pop().unwrap();
        j.store.insert(name.clone(), edit(&name, &value));
    };

    // Under another key.
    let j = Joiner::joined("/bob", Role::Writer).await;
    rewrite(&j, &|_, _| {
        MirrorNote {
            key: j.inviter,
            owner: n("/alice"),
            space: j.space.clone(),
            role: Role::Writer,
            ended: false,
        }
        .encode(&[1; 32])
    });
    assert_eq!(
        j.phone().invites.grants(),
        Vec::new(),
        "a note under another key was read"
    );
    assert_eq!(j.phone().invites.joined_folders(), Vec::new());

    // Changed in place: the role octet flipped.
    let j = Joiner::joined("/bob", Role::Writer).await;
    rewrite(&j, &|_, v| {
        let mut b = v.to_vec();
        b[2] ^= 1;
        Bytes::from(b)
    });
    assert_eq!(
        j.phone().invites.grants(),
        Vec::new(),
        "a changed note was read"
    );

    // Ended by the host, the flag cleared: the entry is not resurrected.
    let j = Joiner::joined("/bob", Role::Writer).await;
    assert!(j.phone().invites.end_grant(&j.inviter).await.unwrap());
    rewrite(&j, &|_, v| {
        let mut b = v.to_vec();
        b[1] = 0;
        Bytes::from(b)
    });
    assert_eq!(
        j.phone().invites.grants(),
        Vec::new(),
        "an ended note came back with its flag cleared"
    );

    // Alice's inviter note put where Bob's mirror note stood, and the reverse.
    let j = Joiner::joined("/bob", Role::Writer).await;
    let (_, mirror) = mirror_notes(&*j.store).pop().unwrap();
    // Alice's laptop holds the one inviter's note, made by Bob's join.
    let (_, inviters_note) = crate::grants_kit::grant_notes(&*j.laptop.store)
        .pop()
        .unwrap();
    assert_eq!(j.laptop.invites.grants().len(), 1);
    rewrite(&j, &|_, _| inviters_note.clone());
    assert_eq!(
        j.phone().invites.grants(),
        Vec::new(),
        "an inviter's note read as a mirror note"
    );
    let (name, _) = crate::grants_kit::grant_notes(&*j.laptop.store)
        .pop()
        .unwrap();
    j.laptop.store.insert(name, mirror);
    assert_eq!(
        j.laptop.invites.grants(),
        Vec::new(),
        "a mirror note read as an inviter's note"
    );
}

/// Spec §11 rule 17: two spaces of one inviter are two entries (per-entry ends): an entry
/// that leaves this device out of one space ends that mirror alone (`revoke_grant(key,
/// space)` once) and the other stands; the host's `end_grant_in` ends one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_entries_of_one_inviter_end_one_by_one() {
    let j = Joiner::joined("/bob", Role::Writer).await;
    let diary = n("/alice/32=data/diary");
    j.join(&diary, Role::Writer).await;
    let key = j.inviter;
    let spaces = |j: &Joiner| -> Vec<Name> {
        j.phone()
            .invites
            .grants()
            .into_iter()
            .map(|g| g.folder)
            .collect()
    };
    assert_eq!(
        j.phone().invites.grants().len(),
        2,
        "{:?}",
        j.phone().invites.grants()
    );
    assert_eq!(
        j.phone()
            .invites
            .joined_folders()
            .into_iter()
            .map(|f| f.folder)
            .collect::<Vec<_>>(),
        vec![diary.clone(), notebook()],
        "joined_folders is not sorted by space"
    );

    j.let_go(&diary).await;
    eventually("the diary's mirror ends", || {
        j.calls.revoked_in().len() == 1
    })
    .await;
    assert_eq!(
        j.calls.revoked_in(),
        vec![(key, diary.clone())],
        "an entry that leaves bob out of the diary did not revoke exactly (key, diary)"
    );
    assert_eq!(spaces(&j), vec![notebook()]);
    assert_eq!(
        j.phone()
            .invites
            .joined_folders()
            .into_iter()
            .map(|f| f.folder)
            .collect::<Vec<_>>(),
        vec![notebook()]
    );
    settle(j.phone()).await;
    assert_eq!(j.calls.revoked_in().len(), 1);
    assert_eq!(j.calls.departed(), Vec::new());

    assert!(
        j.phone()
            .invites
            .end_grant_in(&key, &notebook())
            .await
            .unwrap()
    );
    assert_eq!(j.phone().invites.grants(), Vec::new());
    assert_eq!(
        j.calls.revoked_in().len(),
        1,
        "the host's own end was told to the host"
    );
}

/// Spec §11 rule 17 (mutual invitations): Ann invites Bob to A and Bob invites Ann to B:
/// each holds an inviter's note of one space and a mirror note of the other for the same
/// peer key. They are entries of different spaces, so neither replaces the other,
/// `end_grant_in` ends one, `end_grant(key)` ends both; the inviter's note is no joined
/// space.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mutual_invitations_are_entries_of_different_spaces() {
    let j = Joiner::joined("/bob", Role::Writer).await;
    let journal = n("/bob/32=data/journal");
    // Bob invites Alice to his journal.
    j.phone()
        .node
        .create(
            &journal,
            Share {
                readers: Readers::Persons(vec![n("/bob")]),
                writers: vec![n("/bob")],
            },
        )
        .await
        .unwrap();
    let code = j
        .phone()
        .invites
        .offer(
            &journal,
            crate::host::Offer {
                role: Role::Writer,
                until: ndn_heap::Timestamp(j.phone().node.now().0 + 3_600_000),
                tries: 3,
            },
        )
        .await
        .unwrap();
    let joined = j
        .laptop
        .invites
        .join(&code.link)
        .await
        .expect("Alice joins Bob's journal");
    assert_eq!(joined.space, journal);

    let a = j.inviter;
    let b = crate::grants_kit::key_of(j.phone());
    // Bob: the inviter's grant of the journal and the mirror of the notebook, both for
    // Alice's key.
    let mut bobs = j.phone().invites.grants();
    bobs.sort_by(|x, y| x.folder.cmp(&y.folder));
    assert_eq!(bobs.len(), 2, "{bobs:?}");
    assert!(bobs.iter().all(|g| g.key == a), "{bobs:?}");
    assert_eq!(bobs.iter().map(|g| g.folder.clone()).collect::<Vec<_>>(), {
        let mut both = vec![notebook(), journal.clone()];
        both.sort();
        both
    });
    assert_eq!(
        j.phone()
            .invites
            .joined_folders()
            .into_iter()
            .map(|f| f.folder)
            .collect::<Vec<_>>(),
        vec![notebook()],
        "the space Bob invited to is no joined space"
    );
    assert_eq!(j.laptop.invites.grants().len(), 1 + 1);
    assert!(j.laptop.invites.grants().iter().all(|g| g.key == b));
    assert_eq!(
        j.laptop
            .invites
            .joined_folders()
            .into_iter()
            .map(|f| f.folder)
            .collect::<Vec<_>>(),
        vec![journal.clone()]
    );

    // end_grant_in ends one: the mirror of the notebook, the journal stands.
    assert!(
        j.phone()
            .invites
            .end_grant_in(&a, &notebook())
            .await
            .unwrap()
    );
    assert_eq!(
        j.phone()
            .invites
            .grants()
            .into_iter()
            .map(|g| g.folder)
            .collect::<Vec<_>>(),
        vec![journal.clone()],
        "ending the mirror ended the inviter's grant of the other space"
    );
    // A second join of the notebook starts the mirror again beside it.
    j.phone()
        .invites
        .inner()
        .keep_mirror(a, &n("/alice"), &notebook())
        .await
        .unwrap();
    assert_eq!(j.phone().invites.grants().len(), 2);
    // The host ended the person: both go.
    assert!(j.phone().invites.end_grant(&a).await.unwrap());
    assert_eq!(j.phone().invites.grants(), Vec::new());
    assert_eq!(j.calls.departed(), Vec::new());
    assert_eq!(j.calls.revoked_in(), Vec::new());
}

/// Spec §11 rule 18: the surface holds the invitations weakly and says what they say; once
/// they are gone it lists nothing and its watcher never sees a change.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_surface_says_what_the_invitations_say_and_nothing_once_they_are_gone() {
    let mut j = Joiner::unjoined("/bob").await;
    let surface = j.phone().invites.surface();
    let mut rx = surface.joined_changes();
    assert_eq!(surface.joined_folders(), Vec::new());
    j.join(&notebook(), Role::Writer).await;
    assert!(
        rx.has_changed().unwrap(),
        "a join did not reach the surface's watcher"
    );
    assert_eq!(
        *rx.borrow_and_update(),
        *j.phone().invites.joined_changes().borrow()
    );
    assert_eq!(surface.joined_folders(), j.phone().invites.joined_folders());
    assert_eq!(surface.joined_folders().len(), 1);

    // Bob's phone stops: the surface, which held it weakly, lists nothing.
    j.stop_phone();
    let mut gone = surface.joined_changes();
    eventually("the surface keeps the invitations alive", || {
        surface.joined_folders().is_empty()
    })
    .await;
    assert!(gone.changed().await.is_err());
}
