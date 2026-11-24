//! The public wire surface: what a program outside the crate (the
//! conformance suite) can do with the log's wire format alone: build, name, read and digest
//! an entry. This file sees only `ndn_heap`'s public API, so every name used here is a promise.

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_heap::wire::{
    Body, Entry, EntryRef, Payload, Prev, PutBody, WireError, log_name, signed_digest,
    signed_digest_of,
};
use ndn_packet::Data;
use ndn_packet::encode::DataBuilder;
use ndn_security::verifier::{Ed25519Verifier, VerifyOutcome};
use ndn_security::{Ed25519Signer, Signer};

fn n(uri: &str) -> Name {
    uri.parse().expect("a valid name")
}

fn thief() -> (Name, Ed25519Signer) {
    let device = n("/alice/phone");
    let signer = Ed25519Signer::from_seed(&[9; 32], device.clone().append("KEY").append("1"));
    (device, signer)
}

fn put(path: &str, payload: &[u8]) -> Body {
    Body::Put(PutBody {
        path: n(path),
        payload: Payload::Inline(Bytes::copy_from_slice(payload)),
    })
}

/// The packet of `entry` at `name`, signed by `signer`, as a program outside the crate builds
/// one from the public surface and a signer of its own (the crate offers no function that
/// signs an entry: that is the node's own act).
fn forge(signer: &Ed25519Signer, name: &Name, entry: &Entry) -> Bytes {
    let content = entry.encode().expect("the entry encodes");
    DataBuilder::new(name.clone(), &content).sign_sync(
        signer.sig_type(),
        Some(signer.key_name()),
        |region| signer.sign_sync(region).expect("the signer signs"),
    )
}

/// A forged first entry is built, named, signed and read back from the
/// public surface alone.
#[test]
fn an_entry_is_built_named_signed_and_decoded_through_the_public_surface() {
    let (device, signer) = thief();
    let space = n("/alice/32=data/notes");
    let entry = Entry {
        prev: None,
        after: Vec::new(),
        body: put("/a/b", b"forged"),
    };
    let name = log_name(&device, &space, 1);
    let packet = forge(&signer, &name, &entry);

    let data = Data::decode(packet.clone()).expect("a Data packet");
    assert_eq!(*data.name, name);
    assert_eq!(
        Entry::decode(data.content().unwrap()).unwrap(),
        entry,
        "what was built is what is read"
    );
    assert_eq!(signed_digest(&packet), signed_digest_of(&data));
    assert_eq!(
        Ed25519Verifier.verify_sync(
            data.signed_region(),
            data.sig_value(),
            &signer.public_key().unwrap()
        ),
        VerifyOutcome::Valid,
        "signed by the signer given"
    );
}

/// The chain link, the superseded heads, a gap statement and a removal are
/// all expressible, and survive the encoding.
#[test]
fn prev_prev_seq_after_and_a_removal_survive_the_round_trip() {
    let (device, signer) = thief();
    let space = n("/alice/32=data/notes");
    let first = forge(
        &signer,
        &log_name(&device, &space, 1),
        &Entry {
            prev: None,
            after: Vec::new(),
            body: put("/a", b"one"),
        },
    );
    let head = EntryRef {
        device: device.clone(),
        seq: 1,
        digest: signed_digest(&first),
    };
    let removal = Entry {
        prev: Some(Prev {
            digest: head.digest,
            seq: Some(1),
        }),
        after: vec![head.clone()],
        body: put("/a", b""),
    };
    let packet = forge(&signer, &log_name(&device, &space, 5), &removal);
    let data = Data::decode(packet).unwrap();
    let back = Entry::decode(data.content().unwrap()).unwrap();
    assert_eq!(back, removal);
    assert_eq!(back.after, vec![head]);
    match back.body {
        Body::Put(PutBody {
            payload: Payload::Inline(bytes),
            ..
        }) => assert!(bytes.is_empty(), "an empty payload is a removal"),
        other => panic!("not a write: {other:?}"),
    }
}

/// What the format cannot carry is refused with the format's own error.
#[test]
fn an_entry_the_format_cannot_carry_is_refused_by_name() {
    let too_big = Entry {
        prev: None,
        after: Vec::new(),
        body: put("/a", &vec![0u8; 1 << 20]),
    };
    let refused = too_big.encode();
    assert!(
        matches!(refused, Err(WireError::TooLarge { .. })),
        "{refused:?}"
    );
}
