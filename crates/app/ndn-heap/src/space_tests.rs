//! The API a host sees: a space made, written, read and watched; who may
//! change its members; what a sealed space shows to whom.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_sync::DataStore;

use super::*;
use crate::error::NextStep;
use crate::log::Alert;
use crate::node::tests::{
    boot, bytes, cfg, deliver, durable, next, private, public, solo, space, until, world,
};
use crate::test_kit::n;
use crate::wire::{Body, Entry, log_name};

fn changed(add_writers: &[&str], add_readers: &[&str], remove: &[&str]) -> MembersChange {
    let names = |v: &[&str]| v.iter().map(|s| n(s)).collect();
    MembersChange {
        add_writers: names(add_writers),
        add_readers: names(add_readers),
        remove: names(remove),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_put_get_watch_remove_round_trip() {
    let dev = solo().await;
    let (node, _) = boot(&dev, cfg()).await;
    let heap = node.create(&space(), public()).await.unwrap();
    assert_eq!(heap.name(), &space());
    let id = heap
        .put(&n("/a"), bytes("one"), PutOptions::default())
        .await
        .unwrap();
    let item = heap.get(&n("/a")).await.unwrap().expect("held");
    assert_eq!(item.bytes, bytes("one"));
    assert_eq!((&item.by, &item.writer), (&n("/alice"), &dev.name));
    assert_eq!(item.id, id);

    let mut changes = heap.watch(&Frontier::new()).await.unwrap();
    assert_eq!(next(&mut changes).await, Change::Put(item.clone()));

    let gone = heap
        .put(&n("/a"), Bytes::new(), PutOptions::default())
        .await
        .unwrap();
    assert!(gone.seq > id.seq);
    match next(&mut changes).await {
        Change::Removed(removed) => assert_eq!(removed.id, gone),
        other => panic!("a removal is told as Removed, got {other:?}"),
    }
    assert_eq!(heap.get(&n("/a")).await.unwrap(), None);
    assert_eq!(heap.get(&n("/never")).await.unwrap(), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_put_never_waits_on_the_network() {
    let dev = solo().await;
    let mut slow = cfg();
    slow.settle = Duration::from_secs(60);
    slow.first_look = Duration::from_secs(60);
    slow.lifetime = Duration::from_secs(60);
    let (node, _) = boot(&dev, slow).await;
    let heap = node.create(&space(), public()).await.unwrap();
    for opts in [PutOptions::default(), durable(false), durable(true)] {
        tokio::time::timeout(
            Duration::from_secs(5),
            heap.put(&n("/a"), bytes("x"), opts.clone()),
        )
        .await
        .unwrap_or_else(|_| panic!("a put with {opts:?} waited for a peer that is not there"))
        .unwrap();
    }
    assert!(heap.get(&n("/a")).await.unwrap().is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn members_lists_owner_first() {
    let dev = solo().await;
    let (node, _) = boot(&dev, cfg()).await;
    let heap = node
        .create(
            &space(),
            Share {
                readers: Readers::Persons(vec![n("/zed"), n("/bob")]),
                writers: vec![n("/carl"), n("/bob")],
            },
        )
        .await
        .unwrap();
    assert_eq!(
        heap.members(),
        Members {
            owner: n("/alice"),
            writers: vec![n("/alice"), n("/bob"), n("/carl")],
            readers: Readers::Persons(vec![n("/alice"), n("/bob"), n("/zed")]),
        }
    );
    heap.change(changed(&[], &["/amy"], &["/bob"]))
        .await
        .unwrap();
    assert_eq!(
        heap.members(),
        Members {
            owner: n("/alice"),
            writers: vec![n("/alice"), n("/carl")],
            readers: Readers::Persons(vec![n("/alice"), n("/amy"), n("/zed")]),
        },
        "a removal takes the person from both roles"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn change_by_a_non_owner_device_is_refused_with_use_owner_device() {
    let devs = world(&["/alice/laptop", "/bob/laptop"]).await;
    let (alice, _) = boot(&devs[0], cfg()).await;
    alice.create(&space(), public()).await.unwrap();
    let (bob, _) = boot(&devs[1], cfg()).await;
    let heap = bob.open(&space()).await.unwrap();
    deliver(&devs[0], &bob).await;
    let refused = heap
        .change(changed(&["/bob"], &[], &[]))
        .await
        .expect_err("only an owner device changes the members");
    assert!(matches!(refused, HeapError::NotOwner { .. }), "{refused:?}");
    assert_eq!(refused.next(), NextStep::UseOwnerDevice);
    assert!(
        !heap.members().writers.contains(&n("/bob")),
        "nothing was signed"
    );
    let made = bob
        .create(&space(), public())
        .await
        .expect_err("not the owner's namespace");
    assert_eq!(made.next(), NextStep::UseOwnerDevice);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn watch_lists_held_then_live_and_lags_past_the_queue() {
    let dev = solo().await;
    let mut small = cfg();
    small.watch_queue = 4;
    let (node, _) = boot(&dev, small).await;
    let heap = node.create(&space(), public()).await.unwrap();
    let mut ids = Vec::new();
    for p in ["/h1", "/h2", "/h3"] {
        ids.push(
            heap.put(&n(p), bytes(p), PutOptions::default())
                .await
                .unwrap(),
        );
    }
    // Held first: every current head, however long the queue is.
    let mut changes = heap.watch(&Frontier::new()).await.unwrap();
    let mut listed = Vec::new();
    for _ in 0..3 {
        match next(&mut changes).await {
            Change::Put(item) => listed.push(item.path),
            other => panic!("the held heads come first, got {other:?}"),
        }
    }
    listed.sort();
    assert_eq!(listed, vec![n("/h1"), n("/h2"), n("/h3")]);

    // A watcher that has what the frontier says skips it.
    let mut frontier = Frontier::new();
    frontier.set(dev.name.clone(), ids[1].seq);
    let mut partial = heap.watch(&frontier).await.unwrap();
    match next(&mut partial).await {
        Change::Put(item) => assert_eq!(item.id, ids[2]),
        other => panic!("{other:?}"),
    }

    // Live: past the queue, changes are dropped and the watcher is told how
    // many, after what it was owed.
    for i in 0..10 {
        heap.put(&n(&format!("/l{i}")), bytes("v"), PutOptions::default())
            .await
            .unwrap();
    }
    for i in 0..4 {
        match next(&mut changes).await {
            Change::Put(item) => assert_eq!(item.path, n(&format!("/l{i}"))),
            other => panic!("queued changes first, got {other:?}"),
        }
    }
    assert_eq!(next(&mut changes).await, Change::Lagged { missed: 6 });
    let later = heap
        .put(&n("/later"), bytes("v"), PutOptions::default())
        .await
        .unwrap();
    match next(&mut changes).await {
        Change::Put(item) => assert_eq!(item.id, later, "the watch goes on after the lag"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_follower_holds_no_write_handle_and_the_space_is_not_opened_beside_it() {
    let dev = solo().await;
    let (node, _) = boot(&dev, cfg()).await;
    let follower = node.follow(&space()).await.unwrap();
    assert_eq!(follower.held(), 0);
    assert!(node.space(&space()).is_none(), "a carrier has no handle");
    let refused = node.open(&space()).await.expect_err("followed, not opened");
    assert!(
        matches!(refused, HeapError::BadRequest { .. }),
        "{refused:?}"
    );
    follower.close().await;
    node.open(&space())
        .await
        .expect("free to open once the carrier is closed");
}

// -- Sealed ------------------------------------------------------------------------

fn entry_body(dev: &crate::node::tests::Dev, seq: u64) -> Entry {
    let wire = dev
        .store
        .get(&log_name(&dev.name, &space(), seq))
        .expect("stored");
    let data = ndn_packet::Data::decode(wire).unwrap();
    Entry::decode(data.content().unwrap()).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_writer_in_a_private_space_seals_and_a_reader_outside_the_audience_gets_sealed() {
    let devs = world(&["/alice/laptop", "/bob/laptop"]).await;
    let (alice, _) = boot(&devs[0], cfg()).await;
    let heap = alice.create(&space(), private(&["/carol"])).await.unwrap();
    let id = heap
        .put(&n("/secret"), bytes("for carol"), PutOptions::default())
        .await
        .unwrap();
    assert!(
        matches!(entry_body(&devs[0], id.seq).body, Body::Sealed(_)),
        "the entry holds no plaintext"
    );
    assert_eq!(
        heap.get(&n("/secret")).await.unwrap().unwrap().bytes,
        bytes("for carol"),
        "the writer reads what it sealed"
    );

    let (bob, _) = boot(&devs[1], cfg()).await;
    let theirs = bob.open(&space()).await.unwrap();
    deliver(&devs[0], &bob).await;
    let sealed = theirs
        .get(&n("/secret"))
        .await
        .expect_err("bob is not in the audience");
    assert!(matches!(sealed, HeapError::Sealed { .. }), "{sealed:?}");
    assert_eq!(sealed.next(), NextStep::AskOwner);
    assert!(
        theirs.get(&n("/other")).await.is_err(),
        "a closed entry's path is unknown, so no path reads"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_writer_never_seals_in_an_outgrown_epoch() {
    let dev = solo().await;
    let (node, _) = boot(&dev, cfg()).await;
    let heap = node.create(&space(), private(&["/bob"])).await.unwrap();
    heap.put(&n("/a"), bytes("one"), PutOptions::default())
        .await
        .unwrap();
    // Bob is removed and the new epoch is not signed yet: the epoch in force
    // lists a person who is no reader.
    {
        let mut log = heap.inner.log.lock();
        let ops = log.remove_ops(&n("/bob"));
        assert!(!ops.is_empty());
        let step = log
            .sign_members(crate::wire::MembersBody { create: None, ops }, 0)
            .unwrap();
        assert!(matches!(step, crate::log::Step::Done(..)));
    }
    let refused = heap
        .put(&n("/a"), bytes("two"), PutOptions::default())
        .await
        .expect_err("the epoch in force is outgrown");
    assert!(matches!(refused, HeapError::NotReady { .. }), "{refused:?}");
    assert_eq!(refused.next(), NextStep::RetryLater);
    // The owner's device repairs it; the same put then succeeds.
    heap.change(MembersChange::default()).await.unwrap();
    heap.put(&n("/a"), bytes("two"), PutOptions::default())
        .await
        .unwrap();
}

/// A reader added by `change` holds the key of the epoch in force; removing
/// them again leaves that epoch's audience as it was, but the key is out, so
/// a new epoch is signed and nothing after the removal is sealed in the old.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reader_added_by_change_and_removed_again_cannot_open_the_next_put() {
    let dev = solo().await;
    let (node, _) = boot(&dev, cfg()).await;
    let heap = node.create(&space(), private(&[])).await.unwrap();
    let first = heap.inner.log.lock().fold.in_force().expect("an epoch");
    heap.change(changed(&[], &["/bob"], &[])).await.unwrap();
    assert_eq!(
        heap.inner.log.lock().fold.in_force(),
        Some(first.clone()),
        "an added reader needs no new epoch: it is granted the one in force"
    );
    heap.change(changed(&[], &[], &["/bob"])).await.unwrap();
    let now = heap.inner.log.lock().fold.in_force().expect("an epoch");
    assert_ne!(now, first, "bob holds the old key: a new epoch is signed");
    let id = heap
        .put(&n("/after"), bytes("not for bob"), PutOptions::default())
        .await
        .unwrap();
    let Body::Sealed(sealed) = entry_body(&dev, id.seq).body else {
        panic!("the put is sealed");
    };
    assert_eq!(sealed.epoch, now, "sealed in the epoch bob never held");
}

/// A reader's device whose key is revoked holds the epoch key, and its person
/// still reads, so no member changed: an owner device signs a new epoch that
/// replaces the old one, once; a restart owes nothing more.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoking_a_reader_devices_key_makes_an_owner_device_sign_a_new_epoch_once() {
    let devs = world(&["/alice/laptop", "/bob/phone"]).await;
    let (node, _) = boot(&devs[0], cfg()).await;
    let heap = node.create(&space(), private(&["/bob"])).await.unwrap();
    let in_force = |heap: &Heap| heap.inner.log.lock().fold.in_force();
    let first = in_force(&heap).expect("an epoch");
    let revoking = ndn_security::SignedTrustContext::hierarchical(n("/bob"))
        .with_version(2)
        .with_revocation(devs[1].name.clone().append("KEY").append("1"));
    devs[0]
        .validator
        .keyring()
        .adopt_update(Arc::new(revoking))
        .expect("adopted");
    let mut second = None;
    for _ in 0..100 {
        if let Some(e) = in_force(&heap)
            && e != first
        {
            second = Some(e);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let second = second.expect("an owner device signs a new epoch for the revocation");
    {
        let log = heap.inner.log.lock();
        let fold = &log.fold;
        assert!(fold.complete());
        assert_eq!(
            fold.epoch_tips(),
            vec![second.clone()],
            "it replaces the old"
        );
        assert_eq!(fold.epochs().len(), 2);
    }
    let id = heap
        .put(
            &n("/after"),
            bytes("not for the thief"),
            PutOptions::default(),
        )
        .await
        .unwrap();
    let Body::Sealed(sealed) = entry_body(&devs[0], id.seq).body else {
        panic!("the put is sealed");
    };
    assert_eq!(
        sealed.epoch, second,
        "sealed in the epoch the thief never held"
    );
    // A restart owes nothing: the revocation is accounted for.
    node.close().await;
    let (node, _) = boot(&devs[0], cfg()).await;
    let heap = node.open(&space()).await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(heap.inner.log.lock().fold.epochs().len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_owner_device_signs_the_epoch_a_members_entry_of_another_leaves_incomplete() {
    let devs = world(&["/alice/laptop", "/alice/phone"]).await;
    let (laptop, _) = boot(&devs[0], cfg()).await;
    let heap = laptop.create(&space(), private(&["/bob"])).await.unwrap();
    let (phone, _) = boot(&devs[1], cfg()).await;
    let theirs = phone.open(&space()).await.unwrap();
    deliver(&devs[0], &phone).await;
    assert!(theirs.inner.log.lock().fold.complete());
    // The laptop removes bob and does not sign the epoch (it goes dark).
    {
        let mut log = heap.inner.log.lock();
        let ops = log.remove_ops(&n("/bob"));
        let _ = log
            .sign_members(crate::wire::MembersBody { create: None, ops }, 0)
            .unwrap();
    }
    let removal = devs[0]
        .store
        .get(&log_name(&devs[0].name, &space(), 3))
        .expect("the removal is the third entry");
    let taken = phone.inner.take(&space(), removal, false).await;
    assert!(
        matches!(
            taken,
            crate::sync::Taken::Decided {
                outcome: crate::log::Outcome::Applied,
                ..
            }
        ),
        "{taken:?}"
    );
    // On arrival the phone, an owner device, repairs the epoch.
    for _ in 0..100 {
        if theirs.inner.log.lock().fold.complete() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("an owner device left the fold incomplete after a members entry arrived");
}

// -- Pieces ------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_payload_over_the_inline_limit_round_trips_in_pieces_in_one_entry_batch() {
    let dev = solo().await;
    let (node, _) = boot(&dev, cfg()).await;
    let heap = node.create(&space(), private(&[])).await.unwrap();
    let big: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let mut changes = heap.watch(&Frontier::new()).await.unwrap();
    let id = heap
        .put(&n("/big"), Bytes::from(big.clone()), PutOptions::default())
        .await
        .unwrap();
    let item = heap.get(&n("/big")).await.unwrap().expect("assembled");
    assert_eq!(&item.bytes[..], &big[..], "sealed, split, joined, opened");
    assert_eq!(item.id, id);
    match next(&mut changes).await {
        Change::Put(put) => assert_eq!(put.bytes.len(), big.len()),
        other => panic!("a blob is told once it is whole, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_path_that_is_no_path_is_refused_by_name() {
    let dev = solo().await;
    let (node, _) = boot(&dev, cfg()).await;
    let heap = node.create(&space(), public()).await.unwrap();
    let e = heap
        .put(&Name::root(), bytes("x"), PutOptions::default())
        .await
        .expect_err("an empty path names nothing");
    assert!(matches!(e, HeapError::BadName { .. }), "{e:?}");
    assert_eq!(e.next(), NextStep::FixName);
}

// -- Findings of the spec owner's review ----------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_path_the_codec_accepts_is_not_refused() {
    let dev = solo().await;
    let (node, _) = boot(&dev, cfg()).await;
    let heap = node.create(&space(), public()).await.unwrap();
    // 8 components of 22 octets: the codec counts a 2-octet header each, 192
    // in all, under its limit of 200.
    let part = "a".repeat(22);
    let path = n(&format!(
        "/{part}/{part}/{part}/{part}/{part}/{part}/{part}/{part}"
    ));
    heap.put(&path, bytes("deep"), PutOptions::default())
        .await
        .expect("a path the codec carries is carried");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_audience_over_the_cap_is_refused_before_anything_is_signed() {
    let dev = solo().await;
    let (node, _) = boot(&dev, cfg()).await;
    let readers: Vec<String> = (0..300).map(|i| format!("/r{i}")).collect();
    let refs: Vec<&str> = readers.iter().map(String::as_str).collect();
    let refused = node
        .create(&space(), private(&refs))
        .await
        .expect_err("300 readers are more than an epoch lists");
    assert!(
        matches!(refused, HeapError::BadRequest { .. }),
        "{refused:?}"
    );
    assert_eq!(refused.next(), NextStep::FixRequest);
    let text = refused.to_string();
    assert!(text.contains("256") && text.contains("301"), "{text}");
    assert!(node.space(&space()).is_none(), "nothing was opened");
    assert!(
        !dev.store.contains(&log_name(&dev.name, &space(), 1)),
        "nothing was signed"
    );

    // The same cap holds for a change of a space made within it.
    let few: Vec<&str> = refs[..250].to_vec();
    let heap = node.create(&space(), private(&few)).await.unwrap();
    let head = node.inner.head(&space());
    let more: Vec<&str> = refs[250..].to_vec();
    let refused = heap
        .change(changed(&[], &more, &[]))
        .await
        .expect_err("250 + 50 + the owner is over the cap");
    assert_eq!(refused.next(), NextStep::FixRequest);
    assert_eq!(node.inner.head(&space()), head, "nothing was signed");
    assert_eq!(
        heap.members().readers,
        Readers::Persons({
            let mut all = vec![n("/alice")];
            let mut rest: Vec<Name> = few.iter().map(|r| n(r)).collect();
            rest.sort();
            all.extend(rest);
            all
        })
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_writer_outside_the_audience_is_told_so_not_to_retry() {
    let devs = world(&["/alice/laptop", "/bob/laptop"]).await;
    let (alice, _) = boot(&devs[0], cfg()).await;
    alice
        .create(
            &space(),
            Share {
                readers: Readers::Persons(vec![n("/carol")]),
                writers: vec![n("/bob")],
            },
        )
        .await
        .unwrap();
    let (bob, _) = boot(&devs[1], cfg()).await;
    let heap = bob.open(&space()).await.unwrap();
    deliver(&devs[0], &bob).await;
    let refused = heap
        .put(&n("/a"), bytes("x"), PutOptions::default())
        .await
        .expect_err("bob may write and cannot seal");
    assert!(
        matches!(refused, HeapError::NotAllowed { .. }),
        "{refused:?}"
    );
    assert_eq!(refused.next(), NextStep::AskOwner);
    let text = refused.to_string();
    assert!(
        text.contains("sealed") && text.contains("audience") && text.contains("reader"),
        "the refusal says why and what to do: {text}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_audience_member_waiting_for_its_key_is_told_to_retry_not_sealed() {
    let devs = world(&["/alice/laptop", "/bob/laptop"]).await;
    let (alice, _) = boot(&devs[0], cfg()).await;
    let heap = alice.create(&space(), private(&["/bob"])).await.unwrap();
    heap.put(&n("/secret"), bytes("for bob"), PutOptions::default())
        .await
        .unwrap();
    let (bob, _) = boot(&devs[1], cfg()).await;
    let theirs = bob.open(&space()).await.unwrap();
    deliver(&devs[0], &bob).await;
    let waiting = theirs
        .get(&n("/secret"))
        .await
        .expect_err("the entry is held closed: bob has no key yet");
    assert!(matches!(waiting, HeapError::NotReady { .. }), "{waiting:?}");
    assert_eq!(waiting.next(), NextStep::RetryLater);
    assert!(
        waiting.to_string().contains("grant"),
        "it says the key is being fetched: {waiting}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refusal_the_judge_or_the_mark_makes_is_alerted_once_and_replayed() {
    let devs = world(&["/alice/laptop", "/bob/laptop"]).await;
    let (alice, _) = boot(&devs[0], cfg()).await;
    let heap = alice.create(&space(), public()).await.unwrap();
    let (bob, _) = boot(&devs[1], cfg()).await;
    let theirs = bob.open(&space()).await.unwrap();
    deliver(&devs[0], &bob).await;
    let mut changes = theirs.watch(&Frontier::new()).await.unwrap();
    // Bob marks alice's laptop key suspected: its new entries are not taken.
    let key = devs[0].name.clone().append("KEY").append("1");
    bob.suspect(&key, crate::error::Timestamp(1)).unwrap();
    let id = heap
        .put(&n("/a"), bytes("x"), PutOptions::default())
        .await
        .unwrap();
    let wire = devs[0]
        .store
        .get(&log_name(&devs[0].name, &space(), id.seq))
        .unwrap();
    for _ in 0..2 {
        bob.inner.take(&space(), wire.clone(), false).await;
    }
    let alert = until(&mut changes, |c| match c {
        Change::Alert(a @ Alert::Refused { .. }) => Some(a.clone()),
        _ => None,
    })
    .await;
    match alert {
        Alert::Refused {
            id: refused,
            why,
            next,
        } => {
            assert_eq!(refused.seq, id.seq);
            assert!(
                matches!(why, crate::error::Refusal::Suspected { .. }),
                "{why:?}"
            );
            assert_eq!(next, why.next());
        }
        other => panic!("{other:?}"),
    }
    // Once: the second take of the same entry says nothing more.
    let more = tokio::time::timeout(Duration::from_millis(300), changes.next()).await;
    assert!(more.is_err(), "told twice of one entry: {more:?}");
    // A watcher that begins later is told what is still true.
    let mut late = theirs.watch(&Frontier::new()).await.unwrap();
    until(&mut late, |c| match c {
        Change::Alert(Alert::Refused { .. }) => Some(()),
        _ => None,
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_whose_key_is_revoked_here_is_refused_by_name() {
    let dev = solo().await;
    let (node, _) = boot(&dev, cfg()).await;
    let heap = node.create(&space(), public()).await.unwrap();
    let key = dev.name.clone().append("KEY").append("1");
    let revoking = ndn_security::SignedTrustContext::hierarchical(n("/alice"))
        .with_version(2)
        .with_revocation(key);
    dev.validator
        .keyring()
        .adopt_update(Arc::new(revoking))
        .expect("adopted");
    let refused = heap
        .put(&n("/a"), bytes("x"), PutOptions::default())
        .await
        .expect_err("a revoked key signs nothing");
    assert!(matches!(refused, HeapError::Refused { .. }), "{refused:?}");
}

/// A device whose name lies under the owner's but of another person
/// (`/alice/kid/phone`, of `/alice/kid`) is not an owner device: `change` says
/// so at once instead of waiting `first_look` for entries of the persons it
/// would remove, and no epoch repair is started for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_of_another_person_under_the_owners_name_is_refused_at_once_and_repairs_nothing() {
    let devs = crate::node::tests::world_of(&["/alice/laptop", "/alice/kid/phone"], |name| {
        if name.has_prefix(&n("/alice/kid")) {
            n("/alice/kid")
        } else {
            Name::from_components(name.components()[..1].iter().cloned())
        }
    })
    .await;
    let (laptop, _) = boot(&devs[0], cfg()).await;
    laptop.create(&space(), private(&["/bob"])).await.unwrap();
    let mut config = cfg();
    config.first_look = Duration::from_secs(5);
    let (kid, _) = boot(&devs[1], config).await;
    let heap = kid.open(&space()).await.unwrap();
    // Only the creation arrives: the space seals and no epoch is held.
    let creation = devs[0]
        .store
        .get(&log_name(&devs[0].name, &space(), 1))
        .unwrap();
    assert!(matches!(
        kid.inner.take(&space(), creation, false).await,
        crate::sync::Taken::Decided { .. }
    ));
    // The owner's next entry is heard of and not here: a removal of the
    // owner's person would wait for it.
    kid.inner
        .space_of(&space())
        .unwrap()
        .group
        .on_update(ndn_sync::SyncUpdate {
            publisher: devs[0].name.to_string(),
            name: devs[0].name.clone(),
            low_seq: 1,
            high_seq: 2,
            mapping: None,
            serving_party: None,
        });

    let began = std::time::Instant::now();
    let refused = heap
        .change(changed(&[], &[], &["/alice"]))
        .await
        .expect_err("a device of another person is not an owner device");
    assert!(matches!(refused, HeapError::NotOwner { .. }), "{refused:?}");
    assert!(
        began.elapsed() < Duration::from_secs(2),
        "the refusal came after {:?}: it must not wait for first_look",
        began.elapsed()
    );

    let inner = kid.inner.space_of(&space()).unwrap();
    let log = inner.log.lock();
    assert!(log.sealed() && !log.fold.complete());
    let routed = inner.route(
        &kid.inner,
        &log,
        crate::log::Effects {
            membership: true,
            ..Default::default()
        },
        false,
    );
    assert!(
        !routed.repair,
        "an epoch repair was started for a device that cannot sign one"
    );
}

/// A watcher's queue holds a reference to a value in pieces, not the value: a
/// watch over many large values reads none of them until the watcher reaches
/// it, and reads one at a time.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_watch_reads_a_value_in_pieces_only_when_it_reaches_it() {
    let mut dev = solo().await;
    let metered = Arc::new(crate::test_kit::Metered::new(Arc::new(
        ndn_sync::MemoryStore::new(),
    )));
    dev.store = Arc::clone(&metered) as Arc<dyn DataStore>;
    let (node, _) = boot(&dev, cfg()).await;
    let heap = node.create(&space(), public()).await.unwrap();
    let payload = 100_000;
    for i in 0..6u8 {
        heap.put(
            &n(&format!("/big/{i}")),
            Bytes::from(vec![i; payload]),
            durable(false),
        )
        .await
        .unwrap();
    }
    metered.reset();
    let mut changes = heap.watch(&Frontier::new()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        metered.octets_read() < payload,
        "the watch read {} octets of 6 values of {payload} before the watcher asked for one",
        metered.octets_read()
    );
    let first = next(&mut changes).await;
    assert!(matches!(&first, Change::Put(item) if item.bytes.len() == payload));
    assert!(
        metered.octets_read() < 2 * payload,
        "one value was asked for and {} octets were read",
        metered.octets_read()
    );
}

/// The store lost a piece of a value it recorded whole: the value is
/// `Unavailable`, not an error and not a short value, nothing is allocated for
/// it again, and the record is dropped so that it is gathered anew.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_value_whose_piece_the_store_lost_is_unavailable_and_gathered_again() {
    let dev = solo().await;
    let (node, _) = boot(&dev, cfg()).await;
    let heap = node.create(&space(), public()).await.unwrap();
    let id = heap
        .put(&n("/big"), Bytes::from(vec![7u8; 50_000]), durable(false))
        .await
        .unwrap();
    assert_eq!(
        heap.get(&n("/big")).await.unwrap().unwrap().bytes.len(),
        50_000
    );
    let entry = log_name(&id.device, &space(), id.seq);
    let marker = crate::store::Kind::ASSEMBLED.of(&entry);
    assert!(
        dev.store.contains(&marker),
        "the writer records its value whole"
    );

    let chunk = crate::wire::piece_name(&entry, crate::wire::PieceKind::Chunk(3));
    assert!(dev.store.contains(&chunk));
    dev.store.remove(&chunk);
    let lost = heap.get(&n("/big")).await.unwrap_err();
    assert!(matches!(lost, HeapError::Unavailable { .. }), "{lost:?}");
    assert!(
        !dev.store.contains(&marker),
        "the record that the value was whole is dropped with the piece"
    );
    let again = heap.get(&n("/big")).await.unwrap_err();
    assert!(matches!(again, HeapError::Unavailable { .. }), "{again:?}");
}
