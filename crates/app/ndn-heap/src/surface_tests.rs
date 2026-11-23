//! What a host or a conformance suite sees through the public surface of the
//! log: the wire module (an entry forged at an exact `(device, space, seq)`,
//! one stored by [`Heap::put`] read back) and [`Heap::applied`] (which
//! entries this node has applied, the superseded ones included).
//!
//! The wire items are used by their public paths (`crate::wire::…` names
//! that `tests/wire_surface.rs` also reaches from outside the crate).

use std::sync::Arc;

use bytes::Bytes;
use ndn_packet::Data;
use ndn_security::Signer;

use crate::error::Refusal;
use crate::fold::Readers;
use crate::log::Outcome;
use crate::node::Node;
use crate::node::tests::{Dev, boot, bytes, cfg, public, space, world};
use crate::space::{MembersChange, PutOptions, Share};
use crate::sync::Taken;
use crate::test_kit::n;
use crate::wire::{
    self, Body, Entry, EntryRef, Kind, Payload, Prev, PutBody, log_name, signed_digest,
};

/// The key a device of the world signs with.
fn signer_of(dev: &Dev) -> Arc<dyn Signer> {
    dev.keys
        .get_signer_sync(&dev.name.clone().append("KEY").append("1"))
        .expect("the device's key")
}

/// A Put body with an inline payload (empty: a removal).
fn put_body(path: &str, payload: &str) -> Body {
    Body::Put(PutBody {
        path: n(path),
        payload: Payload::Inline(bytes(payload)),
    })
}

/// Forge `dev`'s entry `seq` through the public wire surface, store it at its
/// log name in the device's store, and return its id and packet.
fn forge(
    dev: &Dev,
    seq: u64,
    prev: Option<Prev>,
    after: Vec<EntryRef>,
    body: Body,
) -> (EntryRef, Bytes) {
    let entry = Entry { prev, after, body };
    let name = log_name(&dev.name, &space(), seq);
    let packet = wire::sign_entry(&*signer_of(dev), &name, &entry).expect("the entry signs");
    dev.store.insert(name, packet.clone());
    let id = EntryRef {
        device: dev.name.clone(),
        seq,
        digest: signed_digest(&packet),
    };
    (id, packet)
}

/// What the node made of a packet handed to it, as a fetch would.
async fn take(node: &Node, packet: Bytes) -> Outcome {
    match node.inner.take(&space(), packet, false).await {
        Taken::Decided { outcome, .. } => outcome,
        Taken::Pending(w) => panic!("pending: {w}"),
    }
}

/// The entry a device stored at `seq`, decoded from its packet.
fn stored(dev: &Dev, seq: u64) -> (Entry, [u8; 32]) {
    let packet = dev
        .store
        .get(&log_name(&dev.name, &space(), seq))
        .expect("the entry is stored");
    let data = Data::decode(packet.clone()).expect("a Data packet");
    (
        Entry::decode(data.content().unwrap()).expect("an entry"),
        signed_digest(&packet),
    )
}

/// A forged entry of a peer device of the owner's person, handed to the node
/// as a fetch would, is applied: it reads back at its path under its id.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forged_entry_of_a_peer_device_is_applied_by_the_node() {
    let devs = world(&["/alice/laptop", "/alice/phone"]).await;
    let (node, _) = boot(&devs[0], cfg()).await;
    let heap = node.create(&space(), public()).await.unwrap();

    let (id, packet) = forge(
        &devs[1],
        1,
        None,
        vec![],
        put_body("/forged", "from the phone"),
    );
    assert!(!heap.applied(&id), "not held before it arrives");
    assert_eq!(take(&node, packet).await, Outcome::Applied);

    let item = heap.get(&n("/forged")).await.unwrap().expect("applied");
    assert_eq!(item.bytes, bytes("from the phone"));
    assert_eq!(item.id, id);
    assert!(heap.applied(&id), "applied after a peer's entry arrived");
}

/// What `Heap::put` stored decodes back into the fields the put was made of:
/// kind, path, payload, the chain link, and what an overwrite and a removal
/// supersede.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn what_a_put_stored_decodes_into_its_fields() {
    let devs = world(&["/alice/laptop"]).await;
    let (node, _) = boot(&devs[0], cfg()).await;
    let heap = node.create(&space(), public()).await.unwrap();
    let one = heap
        .put(&n("/a/b"), bytes("one"), PutOptions::default())
        .await
        .unwrap();
    let two = heap
        .put(&n("/a/b"), bytes("two"), PutOptions::default())
        .await
        .unwrap();
    let gone = heap
        .put(&n("/a/b"), Bytes::new(), PutOptions::default())
        .await
        .unwrap();

    let (creation, creation_digest) = stored(&devs[0], 1);
    assert_eq!(creation.kind(), Kind::Members);

    let (first, digest) = stored(&devs[0], one.seq);
    assert_eq!(digest, one.digest, "the id's digest is the signed digest");
    assert_eq!(first.kind(), Kind::Put);
    assert_eq!(
        first.prev,
        Some(Prev {
            digest: creation_digest,
            seq: None
        })
    );
    assert!(first.after.is_empty(), "nothing to supersede");
    assert_eq!(first.body, put_body("/a/b", "one"));

    let (second, _) = stored(&devs[0], two.seq);
    assert_eq!(second.after, vec![one], "an overwrite names the head");
    assert_eq!(second.body, put_body("/a/b", "two"));

    let (removal, _) = stored(&devs[0], gone.seq);
    assert_eq!(removal.after, vec![two]);
    assert_eq!(
        removal.body,
        put_body("/a/b", ""),
        "a removal is an empty payload"
    );
}

/// `Heap::applied` is true for an own entry, a superseded one (which `get`
/// no longer shows) and a peer's; false for one never held, for the right
/// seq under other bytes, for a non-member's entry and for one outside a cut.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn applied_says_which_entries_this_node_has_applied() {
    let devs = world(&[
        "/alice/laptop",
        "/alice/phone",
        "/bob/laptop",
        "/carol/laptop",
    ])
    .await;
    let (node, _) = boot(&devs[0], cfg()).await;
    let heap = node
        .create(
            &space(),
            Share {
                readers: Readers::Anyone,
                writers: vec![n("/bob")],
            },
        )
        .await
        .unwrap();

    let one = heap
        .put(&n("/a"), bytes("one"), PutOptions::default())
        .await
        .unwrap();
    let two = heap
        .put(&n("/a"), bytes("two"), PutOptions::default())
        .await
        .unwrap();
    assert!(heap.applied(&one), "an own entry");
    assert!(heap.applied(&two), "the head");
    assert_eq!(heap.get(&n("/a")).await.unwrap().unwrap().id, two);
    assert!(heap.applied(&one), "the superseded one is still applied");

    let (peer, packet) = forge(&devs[1], 1, None, vec![], put_body("/p", "peer"));
    assert_eq!(take(&node, packet).await, Outcome::Applied);
    assert!(heap.applied(&peer), "a peer's entry");

    let never = EntryRef {
        device: devs[1].name.clone(),
        seq: 7,
        digest: [3; 32],
    };
    assert!(!heap.applied(&never), "never held");
    let other_bytes = EntryRef {
        digest: [3; 32],
        ..peer.clone()
    };
    assert!(!heap.applied(&other_bytes), "the entry held is other bytes");

    // Bob is a writer: his first entry is applied; the owner removes him; his
    // second is outside the cut.
    let bob = &devs[2];
    let (b1, p1) = forge(bob, 1, None, vec![], put_body("/b", "bob one"));
    assert_eq!(take(&node, p1).await, Outcome::Applied);
    assert!(heap.applied(&b1));
    heap.change(MembersChange {
        remove: vec![n("/bob")],
        ..MembersChange::default()
    })
    .await
    .unwrap();
    let (b2, p2) = forge(
        bob,
        2,
        Some(Prev {
            digest: b1.digest,
            seq: None,
        }),
        vec![],
        put_body("/b", "bob two"),
    );
    assert!(
        matches!(
            take(&node, p2).await,
            Outcome::Refused(Refusal::OutsideCut(_))
        ),
        "bob's second entry is outside the cut"
    );
    assert!(!heap.applied(&b2), "refused: outside the cut");
    assert!(heap.applied(&b1), "what the cut keeps stays applied");

    // A person the space never listed.
    let (c1, pc) = forge(&devs[3], 1, None, vec![], put_body("/c", "carol"));
    assert!(
        matches!(take(&node, pc).await, Outcome::Refused(Refusal::NotMember)),
        "carol is no member"
    );
    assert!(!heap.applied(&c1), "a non-member's entry is not applied");
}
