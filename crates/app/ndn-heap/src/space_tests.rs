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
use crate::{GetNotice, GetOptions, Live, Select};

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
    let item = heap.kept(&n("/a")).await.unwrap().expect("held");
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
    assert_eq!(heap.kept(&n("/a")).await.unwrap(), None);
    assert_eq!(heap.kept(&n("/never")).await.unwrap(), None);
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
    assert!(heap.kept(&n("/a")).await.unwrap().is_some());
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
        heap.kept(&n("/secret")).await.unwrap().unwrap().bytes,
        bytes("for carol"),
        "the writer reads what it sealed"
    );

    let (bob, _) = boot(&devs[1], cfg()).await;
    let theirs = bob.open(&space()).await.unwrap();
    deliver(&devs[0], &bob).await;
    let sealed = theirs
        .kept(&n("/secret"))
        .await
        .expect_err("bob is not in the audience");
    assert!(matches!(sealed, HeapError::Sealed { .. }), "{sealed:?}");
    assert_eq!(sealed.next(), NextStep::AskOwner);
    assert!(
        theirs.kept(&n("/other")).await.is_err(),
        "a closed entry's path is unknown, so no path reads"
    );
}

/// Bob is removed and the new epoch is not signed yet: the epoch in force
/// lists a person who is no reader. Signed under the lock and applied, as
/// another owner device's Members entry would be, but not routed: nothing is
/// told to repair.
fn outgrow_the_epoch(heap: &Heap) {
    let mut log = heap.inner.log.lock();
    let ops = log.remove_ops(&n("/bob"));
    assert!(!ops.is_empty());
    let step = log
        .sign_members(crate::wire::MembersBody { create: None, ops }, 0)
        .unwrap();
    assert!(matches!(step, crate::log::Step::Done(..)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_writer_never_seals_in_an_outgrown_epoch() {
    let dev = solo().await;
    let (node, _) = boot(&dev, cfg()).await;
    let heap = node.create(&space(), private(&["/bob"])).await.unwrap();
    heap.put(&n("/a"), bytes("one"), PutOptions::default())
        .await
        .unwrap();
    outgrow_the_epoch(&heap);
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

/// The epoch an own Members entry owes is signed by the call that signed the
/// entry, before it returns: no task is left behind to sign it later. Such a
/// task could sign an epoch the caller did not expect, or beat the caller's own
/// repair to it and so leave the caller waiting on a flush that does not cover
/// the epoch (a `create` that returned before its epoch was served). On one
/// thread a task spawned by the call is still alive when it returns.
#[tokio::test(flavor = "current_thread")]
async fn an_own_members_entry_spawns_no_task_to_sign_its_epoch() {
    let dev = solo().await;
    let (node, _) = boot(&dev, cfg()).await;
    let heap = node.create(&space(), private(&["/bob"])).await.unwrap();
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    let alive = || {
        tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks()
    };
    let before = alive();
    heap.inner
        .sign_with(&heap.node, |log| {
            let ops = log.remove_ops(&n("/bob"));
            log.sign_members(crate::wire::MembersBody { create: None, ops }, 0)
        })
        .await
        .unwrap();
    assert_eq!(alive(), before, "the entry left a task behind");
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

/// Stage-7 L5: a reader's device whose key this node suspects holds the epoch key in force and
/// its person still reads: the owner device that marked it signs a new epoch that replaces the
/// old one, once, as for a revocation; a restart owes nothing more.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn suspecting_a_reader_devices_key_makes_an_owner_device_sign_a_new_epoch_once() {
    let devs = world(&["/alice/laptop", "/bob/phone"]).await;
    let (node, _) = boot(&devs[0], cfg()).await;
    let heap = node.create(&space(), private(&["/bob"])).await.unwrap();
    let in_force = |heap: &Heap| heap.inner.log.lock().fold.in_force();
    let first = in_force(&heap).expect("an epoch");
    node.suspect(
        &devs[1].name.clone().append("KEY").append("1"),
        crate::error::Timestamp(1),
    )
    .unwrap();
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
    let second = second
        .expect("an owner device signs a new epoch for the suspicion of a reader device's key");
    {
        let log = heap.inner.log.lock();
        assert!(log.fold.complete());
        assert_eq!(
            log.fold.epoch_tips(),
            vec![second.clone()],
            "it replaces the old"
        );
        assert_eq!(log.fold.epochs().len(), 2);
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
    // A restart owes nothing: the suspicion is accounted for.
    node.close().await;
    let (node, _) = boot(&devs[0], cfg()).await;
    let heap = node.open(&space()).await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(heap.inner.log.lock().fold.epochs().len(), 2);
}

/// Stage-7 L6: lost keys of one person's devices (a burst of keys each marked suspected, as
/// an insider who mints keys and forks each one makes) owe the space at most one epoch per
/// `LOSS_EPOCH_INTERVAL_MS`: the first loss is rotated at once, the later ones inside the
/// interval stay owed and are folded into the one epoch that follows when the interval has
/// passed, and that epoch accounts for all of them, so no more is owed. The interval runs by
/// the node's clock, moved here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_burst_of_lost_keys_owes_one_epoch_per_interval() {
    let devs = world(&["/alice/laptop", "/bob/phone"]).await;
    let skew = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut config = cfg();
    config.lapse_sweep = Duration::from_millis(100);
    let clock = Arc::clone(&skew);
    let real = Arc::clone(&config.clock);
    config.clock = Arc::new(move || {
        crate::error::Timestamp(real().0 + clock.load(std::sync::atomic::Ordering::SeqCst))
    });
    let (node, _) = boot(&devs[0], config).await;
    let heap = node.create(&space(), private(&["/bob"])).await.unwrap();
    let epochs = |heap: &Heap| heap.inner.log.lock().fold.epochs().len();
    let key = |i: u32| n(&format!("/bob/d{i}")).append("KEY").append("1");
    let wait_for = |want: usize| {
        let heap = &heap;
        async move {
            for _ in 0..100 {
                if epochs(heap) >= want {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            panic!("no epoch {want} was signed");
        }
    };
    assert_eq!(epochs(&heap), 1);

    // The first loss is rotated at once.
    node.suspect(&key(1), crate::error::Timestamp(1)).unwrap();
    wait_for(2).await;

    // A burst inside the interval owes one more, not one for each key.
    for i in 2..=5 {
        node.suspect(&key(i), crate::error::Timestamp(1)).unwrap();
    }
    let owed = heap.inner.repair_epoch(&node.inner).await.unwrap();
    assert!(
        owed.is_none(),
        "a second epoch for lost keys was signed inside the interval: lost keys may owe at most \
         one epoch per LOSS_EPOCH_INTERVAL_MS, the rest folded into it"
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(epochs(&heap), 2, "no epoch inside the interval");

    // The interval ends: one epoch accounts for the whole burst, and it is not owed again.
    skew.fetch_add(LOSS_EPOCH_INTERVAL_MS, std::sync::atomic::Ordering::SeqCst);
    wait_for(3).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(epochs(&heap), 3, "one epoch for the four keys");
    assert!(
        heap.inner
            .repair_epoch(&node.inner)
            .await
            .unwrap()
            .is_none(),
        "the epoch accounts for every key lost before it"
    );

    // A loss after it starts a new interval.
    node.suspect(&key(6), crate::error::Timestamp(1)).unwrap();
    assert!(
        heap.inner
            .repair_epoch(&node.inner)
            .await
            .unwrap()
            .is_none(),
        "a loss inside the next interval waits for its end"
    );
    skew.fetch_add(LOSS_EPOCH_INTERVAL_MS, std::sync::atomic::Ordering::SeqCst);
    wait_for(4).await;
}

/// Stage-7 L1 (carried chain), end to end over real nodes: the asker's node gives the chain of
/// its signing key from its validator, and a granter whose validator holds none of it (and
/// has no fetcher) judges the asker's seal key packet with it, where without it the packet
/// waits for a certificate nobody sends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_granter_that_holds_none_of_the_askers_chain_judges_the_ask_that_carries_it() {
    use crate::trust::{Judged, Waiting};
    use crate::wire::seal_key_name;
    let devs = world(&["/alice/laptop", "/bob/phone"]).await;
    let phone_key = devs[1].name.clone().append("KEY").append("1");
    let (bob, _) = boot(&devs[1], cfg()).await;
    let chain = bob.inner.signer_chain();
    assert!(
        !chain.is_empty(),
        "a device whose validator holds its certificate carries it"
    );
    let own = seal_key_name(&devs[1].name, &bob.inner.seal_public());
    let packet = bob
        .inner
        .seal_key_packet(&own)
        .expect("its seal key packet");
    let data = ndn_packet::Data::decode(packet).unwrap();
    // The granter has never seen the phone's certificate.
    devs[0].validator.cert_cache().remove(&phone_key);
    let (alice, _) = boot(&devs[0], cfg()).await;
    alice.create(&space(), private(&["/bob"])).await.unwrap();
    let without = alice
        .inner
        .validate_asker_packet(&space(), &data, &devs[1].name, &[])
        .await;
    assert!(
        matches!(without, Judged::Pending(Waiting::Chain)),
        "without the chain the packet waits: {without:?}"
    );
    let with = alice
        .inner
        .validate_asker_packet(&space(), &data, &devs[1].name, &chain)
        .await;
    assert!(
        matches!(with, Judged::Valid(_)),
        "a granter that holds none of the chain did not judge the ask that carries it: {with:?}"
    );
}

/// Stage-7 M2: a reader's device this owner device granted the epoch key to whose certificate
/// lapses (by this node's clock) still holds that key, and nothing rotates it: the owner
/// device signs a new epoch that replaces the old one, once, and ends the record of the
/// device; a restart owes nothing more. The certificate of Bob's phone lasts four seconds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reader_devices_lapse_makes_an_owner_device_sign_a_new_epoch_once() {
    let devs = crate::node::tests::world_with(
        &["/alice/member/laptop", "/bob/member/phone"],
        |name| Name::from_components(name.components()[..1].iter().cloned()),
        |name| {
            if name.has_prefix(&n("/bob")) {
                4_000
            } else {
                365 * 24 * 3600 * 1000
            }
        },
    )
    .await;
    let mut config = cfg();
    config.lapse_sweep = Duration::from_millis(100);
    let (node, _) = boot(&devs[0].layered(), config.clone()).await;
    let heap = node.create(&space(), private(&["/bob"])).await.unwrap();
    let in_force = |heap: &Heap| heap.inner.log.lock().fold.in_force();
    let first = in_force(&heap).expect("an epoch");
    // The phone is granted the key: what the granter records once its seal key packet verifies.
    let (key, ask) = grant_ask_of(&node, &devs[1], &first, [9; 32]);
    node.inner.note_grantee(&space(), &key, &ask).unwrap();
    tokio::time::sleep(Duration::from_millis(1_000)).await;
    assert_eq!(
        in_force(&heap),
        Some(first.clone()),
        "no epoch is owed while the device's certificate is valid"
    );
    let mut second = None;
    for _ in 0..150 {
        if let Some(e) = in_force(&heap)
            && e != first
        {
            second = Some(e);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let second =
        second.expect("an owner device signs a new epoch for the lapse of a reader's device");
    {
        let log = heap.inner.log.lock();
        assert!(log.fold.complete());
        assert_eq!(
            log.fold.epoch_tips(),
            vec![second.clone()],
            "it replaces the old"
        );
        assert_eq!(log.fold.epochs().len(), 2);
    }
    assert!(
        node.inner
            .store
            .scan_under(&crate::store::Kind::GRANTED.listing(&space()), 0)
            .is_empty(),
        "the epoch ends the record of the device that lapsed"
    );
    // Not again: the lapse is accounted for.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(heap.inner.log.lock().fold.epochs().len(), 2);
    node.close().await;
    let (node, _) = boot(&devs[0].layered(), config).await;
    let heap = node.open(&space()).await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(heap.inner.log.lock().fold.epochs().len(), 2);
}

/// Stage-7 L6: the interval between epochs for lost keys covers the epochs a lapse owes too.
/// A key suspected signs the first epoch at once; the lapse of the phone's certificate that
/// follows inside the interval stays owed and is rotated when the interval has passed, not
/// before. The certificate of Bob's phone lasts four seconds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lapse_inside_the_interval_of_a_loss_epoch_waits_for_its_end() {
    let devs = crate::node::tests::world_with(
        &["/alice/member/laptop", "/bob/member/phone"],
        |name| Name::from_components(name.components()[..1].iter().cloned()),
        |name| {
            if name.has_prefix(&n("/bob")) {
                4_000
            } else {
                365 * 24 * 3600 * 1000
            }
        },
    )
    .await;
    let skew = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut config = cfg();
    config.lapse_sweep = Duration::from_millis(100);
    let clock = Arc::clone(&skew);
    let real = Arc::clone(&config.clock);
    config.clock = Arc::new(move || {
        crate::error::Timestamp(real().0 + clock.load(std::sync::atomic::Ordering::SeqCst))
    });
    let (node, _) = boot(&devs[0].layered(), config).await;
    let heap = node.create(&space(), private(&["/bob"])).await.unwrap();
    let epochs = |heap: &Heap| heap.inner.log.lock().fold.epochs().len();
    let first = heap.inner.log.lock().fold.in_force().expect("an epoch");
    let (key, ask) = grant_ask_of(&node, &devs[1], &first, [9; 32]);
    node.inner.note_grantee(&space(), &key, &ask).unwrap();

    node.suspect(
        &n("/bob/member/stolen").append("KEY").append("1"),
        crate::error::Timestamp(1),
    )
    .unwrap();
    for _ in 0..100 {
        if epochs(&heap) == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(epochs(&heap), 2, "the suspicion is rotated at once");

    // The phone's certificate lapses and a sweep sees it.
    let mut seen = false;
    for _ in 0..150 {
        if !heap.inner.lapsed.lock().is_empty() {
            seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(seen, "a sweep finds the lapsed certificate");
    assert!(
        heap.inner
            .repair_epoch(&node.inner)
            .await
            .unwrap()
            .is_none(),
        "an epoch for a lapse was signed inside the interval of the one for the suspicion"
    );
    assert_eq!(epochs(&heap), 2);

    skew.fetch_add(LOSS_EPOCH_INTERVAL_MS, std::sync::atomic::Ordering::SeqCst);
    for _ in 0..100 {
        if epochs(&heap) == 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        epochs(&heap),
        3,
        "the lapse is rotated once the interval ends"
    );
}

/// The ask a device's host sends for `epoch` of the test space: its seal key packet for
/// `public`, signed by the device's key, carrying the chain of that key as `node` holds it.
fn grant_ask_of(
    node: &crate::Node,
    dev: &crate::node::tests::Dev,
    epoch: &EpochId,
    public: [u8; 32],
) -> (Name, crate::wire::GrantAsk) {
    let key = dev.name.clone().append("KEY").append("1");
    let signer = dev.keys.get_signer_sync(&key).unwrap();
    let packet = crate::seal::seal_key_packet(&dev.name, &public, &*signer).unwrap();
    let ask = crate::wire::GrantAsk::new(space(), epoch.clone(), packet)
        .unwrap()
        .with_chain(node.inner.judge.chain_of(&key))
        .unwrap();
    (key, ask)
}

/// Stage-7 N1: an owner device that restarted holds none of a reader device's certificates
/// (nothing keeps other people's certificates across a restart), and judged each grantee
/// by the certificates held alone, so the lapse of the phone's certificate was never seen and the
/// key in force was never rotated. The record now keeps the chain the ask carried, and the
/// sweep judges the packet with it. The certificate of Bob's phone lasts four seconds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reader_devices_lapse_owes_an_epoch_after_the_owner_device_restarted() {
    let devs = crate::node::tests::world_with(
        &["/alice/member/laptop", "/bob/member/phone"],
        |name| Name::from_components(name.components()[..1].iter().cloned()),
        |name| {
            if name.has_prefix(&n("/bob")) {
                4_000
            } else {
                365 * 24 * 3600 * 1000
            }
        },
    )
    .await;
    let mut config = cfg();
    config.lapse_sweep = Duration::from_millis(100);
    let (node, _) = boot(&devs[0].layered(), config.clone()).await;
    let heap = node.create(&space(), private(&["/bob"])).await.unwrap();
    let first = heap.inner.log.lock().fold.in_force().expect("an epoch");
    let (key, ask) = grant_ask_of(&node, &devs[1], &first, [9; 32]);
    node.inner.note_grantee(&space(), &key, &ask).unwrap();
    node.close().await;
    // The owner device starts again with a validator that holds nothing of Bob's phone.
    let restarted = devs[0].layered();
    restarted.validator.cert_cache().remove(&key);
    let (node, _) = boot(&restarted, config).await;
    let heap = node.open(&space()).await.unwrap();
    let mut second = None;
    for _ in 0..150 {
        if let Some(e) = heap.inner.log.lock().fold.in_force()
            && e != first
        {
            second = Some(e);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        second.is_some(),
        "a reader device whose certificate lapsed was never re-keyed after the owner device restarted"
    );
}

/// Stage-7 N1, fail closed: a grantee the sweep cannot judge at all (no certificate held, none
/// kept with the record) owes the epoch once it stays undecided for `PENDING_SWEEPS_MAX`
/// sweeps in a row, and not before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_grantee_that_stays_undecided_for_the_stated_sweeps_owes_the_epoch() {
    let devs = world(&["/alice/member/laptop", "/bob/member/phone"]).await;
    let owner = devs[0].layered();
    let (node, _) = boot(&owner, cfg()).await;
    let heap = node.create(&space(), private(&["/bob"])).await.unwrap();
    let first = heap.inner.log.lock().fold.in_force().expect("an epoch");
    let (key, ask) = grant_ask_of(&node, &devs[1], &first, [9; 32]);
    // A record that carries no chain, on a node that holds no certificate of the phone.
    let ask = crate::wire::GrantAsk::new(space(), first.clone(), ask.seal_packet.clone()).unwrap();
    owner.validator.cert_cache().remove(&key);
    node.inner.note_grantee(&space(), &key, &ask).unwrap();
    let owed = |heap: &Heap| {
        let log = heap.inner.log.lock();
        heap.inner.loss_owed(&node.inner, &log)
    };
    for sweep in 1..PENDING_SWEEPS_MAX {
        heap.inner.sweep_lapsed(&node.inner).await;
        assert!(
            !owed(&heap),
            "no epoch is owed after {sweep} undecided sweeps"
        );
    }
    heap.inner.sweep_lapsed(&node.inner).await;
    assert!(
        owed(&heap),
        "a grantee undecided for {PENDING_SWEEPS_MAX} sweeps in a row owes no epoch"
    );
}

/// Stage-7 N2: one person's devices fill no more than `GRANTEES_PER_PERSON` records, so a reader
/// cannot make an owner device refuse every other person's new device; the refusal says why and
/// what to do.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_readers_devices_cannot_fill_the_grantee_table() {
    let devs = world(&[
        "/alice/member/laptop",
        "/bob/member/phone",
        "/carol/member/phone",
    ])
    .await;
    let (node, _) = boot(&devs[0].layered(), cfg()).await;
    let heap = node
        .create(&space(), private(&["/bob", "/carol"]))
        .await
        .unwrap();
    let first = heap.inner.log.lock().fold.in_force().expect("an epoch");
    let ask = |device: &str| {
        let key = n(device).append("KEY").append("1");
        let (_, ask) = grant_ask_of(&node, &devs[1], &first, [9; 32]);
        (key, ask)
    };
    for i in 0..GRANTEES_PER_PERSON + 8 {
        let (key, ask) = ask(&format!("/bob/member/d{i}"));
        let noted = node.inner.note_grantee(&space(), &key, &ask);
        if i < GRANTEES_PER_PERSON {
            noted.unwrap();
        } else {
            let said = noted.expect_err(&format!(
                "the {}th device of one person was recorded",
                i + 1
            ));
            assert!(
                said.contains(&GRANTEES_PER_PERSON.to_string()) && said.contains("ask"),
                "the refusal says how many and what to do: {said}"
            );
        }
    }
    let (key, carol) = ask("/carol/member/new");
    node.inner
        .note_grantee(&space(), &key, &carol)
        .expect("another person's new device is recorded");
}

/// Stage-7 N2: removing a reader ends the records of her devices at once, and the sweep ends
/// those of a person who reads no more and of a key a trust context revoked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_records_of_a_removed_reader_and_of_a_revoked_key_end() {
    let devs = world(&[
        "/alice/member/laptop",
        "/bob/member/phone",
        "/carol/member/phone",
        "/dave/member/phone",
    ])
    .await;
    let owner = devs[0].layered();
    let (node, _) = boot(&owner, cfg()).await;
    let heap = node
        .create(&space(), private(&["/bob", "/carol"]))
        .await
        .unwrap();
    let first = heap.inner.log.lock().fold.in_force().expect("an epoch");
    let records = || {
        node.inner
            .store
            .scan_under(&crate::store::Kind::GRANTED.listing(&space()), 0)
            .len()
    };
    let note = |dev: &crate::node::tests::Dev, device: &str| {
        let key = n(device).append("KEY").append("1");
        let (_, ask) = grant_ask_of(&node, dev, &first, [9; 32]);
        node.inner.note_grantee(&space(), &key, &ask).unwrap();
        key
    };
    for i in 0..5 {
        note(&devs[1], &format!("/bob/member/d{i}"));
    }
    let carol = note(&devs[2], "/carol/member/d0");
    assert_eq!(records(), 6);
    heap.change(changed(&[], &[], &["/bob"])).await.unwrap();
    assert_eq!(
        records(),
        1,
        "the records of the devices of a reader removed from the space stay"
    );
    // A person the space does not list (a record kept for her) is ended by the sweep.
    note(&devs[3], "/dave/member/d0");
    assert_eq!(records(), 2);
    heap.inner.sweep_lapsed(&node.inner).await;
    assert_eq!(
        records(),
        1,
        "the sweep ends the record of a person who does not read the space"
    );
    // A key a trust context revokes: its record ends at the sweep (the epoch it owes is
    // accounted for by `revoked/<S>`, not by the record).
    let revoking = ndn_security::SignedTrustContext::hierarchical(n("/carol"))
        .with_version(2)
        .with_revocation(carol);
    owner
        .validator
        .keyring()
        .adopt_update(Arc::new(revoking))
        .expect("adopted");
    heap.inner.sweep_lapsed(&node.inner).await;
    assert_eq!(records(), 0, "the record of a revoked key stays");
}

/// Stage-7 M2: a private space of a namespace with the role layout, an owner's `member`
/// device, and Bob's devices of each role (Bob reads the space). What `asker` is told when
/// it asks the owner's device for the epoch key in force, by the names alone and with the
/// key that signed its seal key packet known.
async fn grant_to_bobs(
    asker: &str,
) -> (
    Result<(), crate::seal::GrantRefusal>,
    Result<(), crate::seal::GrantRefusal>,
) {
    let devs = world(&[
        "/alice/member/laptop",
        "/bob/guest/g",
        "/bob/node/n",
        "/bob/admin/a",
        "/bob/member/m",
    ])
    .await;
    let (node, _) = boot(&devs[0].layered(), cfg()).await;
    let heap = node.create(&space(), private(&["/bob"])).await.unwrap();
    let epoch = heap.inner.log.lock().fold.in_force().expect("an epoch");
    let bob = devs
        .iter()
        .find(|d| d.name == n(asker))
        .expect("a device of the world");
    let key = bob.name.clone().append("KEY").append("1");
    (
        node.inner.may_grant(&space(), &epoch, &bob.name, None),
        node.inner
            .may_grant(&space(), &epoch, &bob.name, Some(&key)),
    )
}

/// A member's `guest` device is granted no epoch key: nothing rotates the epoch when it
/// lapses, and it would read every later entry. The refusal says why and what to do, before
/// the packet in the ask is judged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_members_guest_device_is_granted_no_epoch_key() {
    let (by_name, by_key) = grant_to_bobs("/bob/guest/g").await;
    assert_eq!(
        by_name,
        Err(crate::seal::GrantRefusal::NotAdminOrMemberDevice),
        "a member's guest device was granted an epoch key"
    );
    assert_eq!(by_key, by_name);
    let said = by_name.unwrap_err().to_string();
    assert!(
        said.contains("`admin` or `member`") && said.contains("ask the person"),
        "it says which devices are granted and what to do: {said}"
    );
}

/// A member's `node` relay device is granted no epoch key either.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_members_node_device_is_granted_no_epoch_key() {
    let (by_name, by_key) = grant_to_bobs("/bob/node/n").await;
    assert_eq!(
        by_name,
        Err(crate::seal::GrantRefusal::NotAdminOrMemberDevice),
        "a member's node device was granted an epoch key"
    );
    assert_eq!(by_key, by_name);
}

/// A member's `admin` and `member` devices are granted the epoch key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_members_admin_or_member_device_is_granted_the_epoch_key() {
    for asker in ["/bob/admin/a", "/bob/member/m"] {
        let (by_name, by_key) = grant_to_bobs(asker).await;
        assert_eq!(by_name, Ok(()), "{asker} by name");
        assert_eq!(by_key, Ok(()), "{asker} by key");
    }
}

/// Alice's private space, read by Bob. Bob's phone is a reader device that holds the epoch key
/// in force (its owner device, Alice's laptop, granted it); what it answers when Bob's tablet,
/// a `member` device of Bob's, asks it for the key, by the names alone and with the key that
/// signed the tablet's seal key packet known. `layered`: the namespaces declare the role layout.
async fn bobs_tablet_asks_bobs_phone(
    layered: bool,
) -> (
    Result<(), crate::seal::GrantRefusal>,
    Result<(), crate::seal::GrantRefusal>,
) {
    let devs = world(&[
        "/alice/member/laptop",
        "/bob/member/phone",
        "/bob/member/tablet",
    ])
    .await;
    let roles: Vec<_> = if layered {
        devs.iter().map(|d| d.layered()).collect()
    } else {
        Vec::new()
    };
    let pick = |i: usize| if layered { &roles[i] } else { &devs[i] };
    let (alice, _) = boot(pick(0), cfg()).await;
    let heap = alice.create(&space(), private(&["/bob"])).await.unwrap();
    let (epoch, key) = {
        let log = heap.inner.log.lock();
        let epoch = log.fold.in_force().expect("an epoch");
        let key = log
            .keys
            .key(&space(), &epoch)
            .expect("the creator's key")
            .clone();
        (epoch, key)
    };
    let (phone, _) = boot(pick(1), cfg()).await;
    let theirs = phone.open(&space()).await.unwrap();
    deliver(&devs[0], &phone).await;
    assert!(
        theirs.inner.log.lock().key_arrived(epoch.clone(), key).0,
        "the phone holds the epoch key"
    );
    let tablet = &devs[2];
    let key = tablet.name.clone().append("KEY").append("1");
    (
        phone.inner.may_grant(&space(), &epoch, &tablet.name, None),
        phone
            .inner
            .may_grant(&space(), &epoch, &tablet.name, Some(&key)),
    )
}

/// Stage-7 L7: in a space whose readers' namespaces declare the role layout, a reader device that
/// is no owner device grants no key: it keeps no record of the devices it grants to, so no
/// device would rotate the epoch when their certificates lapse. The refusal says why and
/// what to do.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reader_device_that_is_no_owner_device_grants_no_key_in_a_role_layout_space() {
    let (by_name, by_key) = bobs_tablet_asks_bobs_phone(true).await;
    assert_eq!(
        by_name,
        Err(crate::seal::GrantRefusal::GranterNotOwnerDevice),
        "a reader device that keeps no record of its grants handed out the epoch key"
    );
    assert_eq!(by_key, by_name);
    let said = by_name.unwrap_err().to_string();
    assert!(
        said.contains("owner") && said.contains("ask"),
        "it says why and what to do: {said}"
    );
}

/// Stage-7 L7: a flat namespace has no signed role layout, so the rule does not apply (an
/// accepted residual, spec §9.9): a reader device still hands the key to another device of
/// the same person (the conformance worlds' namespaces are flat).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reader_device_still_grants_the_key_in_a_flat_namespace() {
    let (by_name, by_key) = bobs_tablet_asks_bobs_phone(false).await;
    assert_eq!(by_name, Ok(()), "by name");
    assert_eq!(by_key, Ok(()), "by key");
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
    let item = heap.kept(&n("/big")).await.unwrap().expect("assembled");
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
        .kept(&n("/secret"))
        .await
        .expect_err("the entry is held closed: bob has no key yet");
    assert!(matches!(waiting, HeapError::NotReady { .. }), "{waiting:?}");
    assert_eq!(waiting.next(), NextStep::RetryLater);
    assert!(
        waiting.to_string().contains("grant"),
        "it says the key is being fetched: {waiting}"
    );
}

/// An entry sealed in an epoch whose Epoch entry has not arrived: the reader the members record
/// lists cannot tell it is left out of that epoch's audience, so it is told to wait for the
/// owner's entry, not to ask the owner to add it as a reader.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reader_that_lacks_the_epoch_entry_of_a_closed_entry_is_told_to_retry_not_sealed() {
    let devs = world(&["/alice/laptop", "/bob/laptop"]).await;
    let (alice, _) = boot(&devs[0], cfg()).await;
    let heap = alice.create(&space(), private(&["/bob"])).await.unwrap();
    let id = heap
        .put(&n("/secret"), bytes("for bob"), PutOptions::default())
        .await
        .unwrap();
    let (bob, _) = boot(&devs[1], cfg()).await;
    let theirs = bob.open(&space()).await.unwrap();
    // Everything of Alice's but her Epoch entry, the one before the put.
    for seq in (1..=id.seq).filter(|seq| *seq != id.seq - 1) {
        let wire = devs[0]
            .store
            .get(&log_name(&devs[0].name, &space(), seq))
            .expect("held");
        bob.inner.take(&space(), wire, false).await;
    }
    let waiting = theirs
        .kept(&n("/secret"))
        .await
        .expect_err("the entry is held closed: bob holds no epoch entry and no key");
    assert!(matches!(waiting, HeapError::NotReady { .. }), "{waiting:?}");
    assert_eq!(waiting.next(), NextStep::RetryLater);
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
        heap.kept(&n("/big")).await.unwrap().unwrap().bytes.len(),
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
    let lost = heap.kept(&n("/big")).await.unwrap_err();
    assert!(matches!(lost, HeapError::Unavailable { .. }), "{lost:?}");
    assert!(
        !dev.store.contains(&marker),
        "the record that the value was whole is dropped with the piece"
    );
    let again = heap.kept(&n("/big")).await.unwrap_err();
    assert!(matches!(again, HeapError::Unavailable { .. }), "{again:?}");
}

/// A removal is made before the additions, so a person listed in `remove` and
/// in `add_readers` is demoted: no longer a writer, still a reader. The
/// additions are not filtered against who stood before the removal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_person_removed_and_added_as_a_reader_is_demoted_not_dropped() {
    let dev = solo().await;
    let (node, _) = boot(&dev, cfg()).await;
    let heap = node
        .create(
            &space(),
            Share {
                readers: Readers::Persons(vec![n("/bob")]),
                writers: vec![n("/bob")],
            },
        )
        .await
        .unwrap();
    let members = heap.members();
    assert!(members.writers.contains(&n("/bob")), "{members:?}");
    heap.change(changed(&[], &["/bob"], &["/bob"]))
        .await
        .unwrap();
    let members = heap.members();
    assert_eq!(members.writers, vec![n("/alice")], "no longer a writer");
    match &members.readers {
        Readers::Persons(readers) => assert!(readers.contains(&n("/bob")), "{members:?}"),
        Readers::Anyone => panic!("the space is private: {members:?}"),
    }

    // And the other way: a reader removed and added as a writer is a writer.
    heap.change(changed(&["/bob"], &[], &["/bob"]))
        .await
        .unwrap();
    let members = heap.members();
    assert!(members.writers.contains(&n("/bob")), "{members:?}");
}

// -- The kept feed of `get` ---------------------------------------------------------------

/// `kept` is refused while an entry of a sealed space is held closed, because the path of that
/// entry is unknown (it may be a newer write or a removal of what the register shows). The
/// kept listing of `get` claims the same completeness and is refused the same way, with the
/// same reason, instead of listing the older head as the current value and saying it is whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_kept_listing_is_refused_while_an_entry_of_the_sealed_space_is_held_closed() {
    let devs = world(&["/alice/laptop", "/bob/laptop"]).await;
    let (alice, _) = boot(&devs[0], cfg()).await;
    let heap = alice.create(&space(), private(&["/bob"])).await.unwrap();
    heap.put(&n("/secret"), bytes("for bob"), PutOptions::default())
        .await
        .unwrap();
    let (bob, _) = boot(&devs[1], cfg()).await;
    let theirs = bob.open(&space()).await.unwrap();
    deliver(&devs[0], &bob).await;
    let kept = theirs
        .kept(&n("/secret"))
        .await
        .expect_err("the entry is held closed");
    let listed = theirs
        .get(Select::Prefix(Name::root()), GetOptions::default())
        .expect_err("a listing that cannot show the closed entry's path is not whole");
    assert!(matches!(listed, HeapError::NotReady { .. }), "{listed:?}");
    assert_eq!(listed.next(), NextStep::RetryLater);
    assert_eq!(
        listed.to_string(),
        kept.to_string(),
        "the reason `kept` gives"
    );
}

/// A kept feed whose queue overflowed reads the heads again; while an entry of the sealed space
/// is held closed it cannot trust them (the closed entry's path is unknown), so it ends and says
/// so, instead of listing an older head as current and going on as if it were caught up.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_kept_feed_that_reads_the_heads_again_ends_while_an_entry_is_held_closed() {
    let devs = world(&["/alice/laptop", "/bob/laptop"]).await;
    let (alice, _) = boot(&devs[0], cfg()).await;
    let heap = alice.create(&space(), private(&["/bob"])).await.unwrap();
    heap.put(&n("/secret"), bytes("for bob"), PutOptions::default())
        .await
        .unwrap();
    let item = heap
        .kept(&n("/secret"))
        .await
        .unwrap()
        .expect("alice holds it");
    let mut config = cfg();
    config.watch_queue = 1;
    let (bob, _) = boot(&devs[1], config).await;
    let theirs = bob.open(&space()).await.unwrap();
    // Made before anything is held: nothing is closed yet.
    let mut feed = theirs
        .inner
        .kept_feed(
            &bob.inner,
            Select::Prefix(Name::root()),
            crate::Heads::Winner,
        )
        .unwrap();
    // Two changes it wants into a queue of one: the second is dropped.
    feed.queue.push(Change::Put(item.clone()));
    feed.queue.push(Change::Put(item));
    deliver(&devs[0], &bob).await;
    assert!(
        matches!(feed.step(), KeptStep::Got(_)),
        "what the queue held"
    );
    let KeptStep::Notice(GetNotice::KeptEnded { why }) = feed.step() else {
        panic!("the feed read the heads of a register it cannot trust and went on")
    };
    assert!(why.contains("closed"), "it says why: {why}");
    assert!(matches!(feed.step(), KeptStep::Ended), "and it is over");
}

/// What a kept feed does not want never takes a place in its queue: a flood of changes of other
/// paths and of members does not overflow a feed over one path, so it never has to read the
/// heads again (which costs the log's lock and a scan of every head).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn changes_a_kept_feed_does_not_want_never_take_a_place_in_its_queue() {
    let dev = solo().await;
    let mut config = cfg();
    config.watch_queue = 4;
    let (node, _) = boot(&dev, config).await;
    let heap = node.create(&space(), public()).await.unwrap();
    let mut items = heap
        .get(
            Select::Path(n("/a")),
            GetOptions {
                live: Live::Off,
                ..GetOptions::default()
            },
        )
        .unwrap();
    for i in 0..12 {
        heap.put(
            &n(&format!("/other/{i}")),
            bytes("x"),
            PutOptions::default(),
        )
        .await
        .unwrap();
        heap.change(changed(&[&format!("/p{i}")], &[], &[]))
            .await
            .unwrap();
    }
    assert_eq!(
        heap.inner.overflowed(),
        0,
        "24 changes the feed over `/a` does not want filled its queue of 4"
    );
    heap.put(&n("/a"), bytes("wanted"), PutOptions::default())
        .await
        .unwrap();
    let got = tokio::time::timeout(Duration::from_secs(5), futures::StreamExt::next(&mut items))
        .await
        .expect("the wanted change arrives")
        .expect("the stream goes on")
        .expect("an item");
    assert_eq!((got.path, got.bytes), (n("/a"), bytes("wanted")));
}

#[test]
fn a_heads_event_holds_the_heads_of_highest_rank_and_how_many_there_are() {
    let max = crate::HEADS_MAX;
    let heads: Vec<Head> = (0..max + 6)
        .map(|i| Head {
            entry: crate::wire::EntryRef {
                device: n("/alice/d"),
                seq: i as u64 + 1,
                digest: [(max + 6 - i) as u8; 32],
            },
            path: n("/p"),
            person: n("/alice"),
            removal: false,
            size: 1,
        })
        .collect();
    let event = HeadsEvent::of(&n("/p"), &heads);
    assert_eq!(event.total, max + 6);
    assert_eq!(event.now.len(), max, "{} heads held", event.now.len());
    assert_eq!(
        event.now[..],
        heads[..max],
        "the highest ranked, the winner first"
    );
}

/// A real node answers for its own seal key packet under the keyed name and the keyless
/// `<D>/32=seal`, and for no other key and no other device's keyless name.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_serves_its_seal_key_packet_under_the_keyless_name_too() {
    use crate::wire::{seal_key_name, seal_prefix};
    let devs = world(&["/alice/laptop", "/bob/phone"]).await;
    let (alice, _) = boot(&devs[0], cfg()).await;
    let keyed = seal_key_name(&devs[0].name, &alice.inner.seal_public());
    let packet = alice.inner.seal_key_packet(&keyed).expect("the keyed name");
    assert_eq!(
        alice.inner.seal_key_packet(&seal_prefix(&devs[0].name)),
        Some(packet),
        "the keyless name of this device answers with the same signed packet"
    );
    assert_eq!(
        alice.inner.seal_key_packet(&seal_prefix(&devs[1].name)),
        None,
        "another device's keyless name"
    );
    assert_eq!(
        alice
            .inner
            .seal_key_packet(&seal_key_name(&devs[0].name, &[9; 32])),
        None,
        "a key this device never published"
    );
}
