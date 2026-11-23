//! The public wire surface: what a program outside the crate (the
//! conformance suite) can do with the log's wire format alone. This file sees
//! only `ndn_heap`'s public API, so every name used here is a promise.

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_heap::wire::{
    self, Body, Entry, EntryRef, Payload, Prev, PutBody, SignError, WireError, log_name,
    signed_digest, signed_digest_of,
};
use ndn_packet::Data;
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
    let packet = wire::sign_entry(&signer, &name, &entry).expect("the entry signs");

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
    let first = wire::sign_entry(
        &signer,
        &log_name(&device, &space, 1),
        &Entry {
            prev: None,
            after: Vec::new(),
            body: put("/a", b"one"),
        },
    )
    .unwrap();
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
    let packet = wire::sign_entry(&signer, &log_name(&device, &space, 5), &removal).unwrap();
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

/// What the format cannot carry is refused with the format's own error, and
/// the signer's failure is told apart from it.
#[test]
fn an_entry_the_format_cannot_carry_is_refused_by_name() {
    let (device, signer) = thief();
    let space = n("/alice/32=data/notes");
    let too_big = Entry {
        prev: None,
        after: Vec::new(),
        body: put("/a", &vec![0u8; 1 << 20]),
    };
    let refused = wire::sign_entry(&signer, &log_name(&device, &space, 1), &too_big);
    assert!(
        matches!(refused, Err(SignError::Wire(WireError::TooLarge { .. }))),
        "{refused:?}"
    );
}
