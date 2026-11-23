//! The entry codec (spec §3): what every kind carries, what a decoder skips
//! and what it refuses.

use bytes::Bytes;
use ndn_foundation_types::{Name, NameComponent};
use ndn_packet::encode::DataBuilder;
use ndn_security::{Ed25519Signer, Signer};
use ndn_tlv::{TlvReader, TlvWriter};
use proptest::prelude::*;

use super::*;

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

fn eref(i: u8) -> EntryRef {
    EntryRef {
        device: n(&format!("/alice/member/laptop-{i}")),
        seq: u64::from(i) + 1,
        digest: [i; 32],
    }
}

fn epoch_id() -> EpochId {
    EpochId {
        creator: n("/alice/laptop"),
        seq: 2,
    }
}

fn dense() -> Option<Prev> {
    Some(Prev {
        digest: [7; 32],
        seq: None,
    })
}

fn put(payload: Payload) -> Entry {
    Entry {
        prev: dense(),
        after: vec![eref(1), eref(2)],
        body: Body::Put(PutBody {
            path: n("/notes/today"),
            payload,
        }),
    }
}

/// One entry of every shape the format has.
fn every_kind() -> Vec<Entry> {
    vec![
        put(Payload::Inline(Bytes::from_static(b"hello"))),
        // A removal: an inline payload of zero octets.
        put(Payload::Inline(Bytes::new())),
        put(Payload::Blob {
            size: 1 << 20,
            root: [3; 32],
        }),
        // The first entry of a log: no prev, nothing superseded.
        Entry {
            prev: None,
            after: vec![],
            body: Body::Put(PutBody {
                path: n("/a"),
                payload: Payload::Inline(Bytes::from_static(b"x")),
            }),
        },
        Entry {
            prev: dense(),
            after: vec![eref(4)],
            body: Body::Sealed(SealedBody {
                epoch: epoch_id(),
                sealed: Bytes::from(vec![0xAB; 300]),
            }),
        },
        Entry {
            prev: dense(),
            after: vec![],
            body: Body::Members(MembersBody {
                create: Some(true),
                ops: vec![
                    Op::Add {
                        id: [1; 16],
                        who: n("/alice"),
                        role: Role::Writer,
                        epoch: None,
                    },
                    Op::Add {
                        id: [2; 16],
                        who: n("/bob"),
                        role: Role::Reader,
                        epoch: Some(epoch_id()),
                    },
                    Op::Remove {
                        id: [1; 16],
                        tips: vec![eref(1), eref(2), eref(3)],
                    },
                    Op::Remove {
                        id: [2; 16],
                        tips: vec![],
                    },
                ],
            }),
        },
        Entry {
            prev: dense(),
            after: vec![],
            body: Body::Members(MembersBody {
                create: Some(false),
                ops: vec![],
            }),
        },
        Entry {
            prev: dense(),
            after: vec![],
            body: Body::Epoch(EpochBody {
                key_check: [5; 32],
                audience: vec![n("/alice"), n("/bob"), n("/home/carol")],
            }),
        },
    ]
}

/// TLVs as `(type, value)`.
type Tlvs = Vec<(u64, Bytes)>;

/// The TLVs of `value`, as `(type, value)`.
fn children(value: &Bytes) -> Vec<(u64, Bytes)> {
    let mut r = TlvReader::new(value.clone());
    let mut out = Vec::new();
    while !r.is_empty() {
        out.push(r.read_tlv().unwrap());
    }
    out
}

fn serialize(list: &[(u64, Bytes)]) -> Bytes {
    let mut w = TlvWriter::new();
    for (t, v) in list {
        w.write_tlv(*t, v);
    }
    w.finish()
}

/// `value` with `f` applied to the TLVs found by following `path` (the first
/// child of each type) from the top.
fn rewrite(value: &Bytes, path: &[u64], f: &dyn Fn(Tlvs) -> Tlvs) -> Bytes {
    let mut list = children(value);
    match path.split_first() {
        None => list = f(list),
        Some((first, rest)) => {
            let at = list.iter().position(|(t, _)| t == first).unwrap();
            list[at].1 = rewrite(&list[at].1, rest, f);
        }
    }
    serialize(&list)
}

/// The encoded `entry`, rewritten under its `ENTRY` TLV.
fn edit(entry: &Entry, path: &[u64], f: &dyn Fn(Tlvs) -> Tlvs) -> Vec<u8> {
    let wire = entry.encode().unwrap();
    let (typ, value) = children(&wire).remove(0);
    assert_eq!(typ, tlv::ENTRY);
    let mut w = TlvWriter::new();
    w.write_tlv(tlv::ENTRY, &rewrite(&value, path, f));
    w.finish().to_vec()
}

fn with_extra(entry: &Entry, path: &[u64], typ: u64) -> Vec<u8> {
    edit(entry, path, &|mut list| {
        list.push((typ, Bytes::from_static(b"future")));
        list
    })
}

fn types(entry: &Entry) -> Vec<u64> {
    let wire = entry.encode().unwrap();
    let (_, value) = children(&wire).remove(0);
    children(&value).into_iter().map(|(t, _)| t).collect()
}

#[test]
fn every_kind_round_trips() {
    let mut kinds = std::collections::BTreeSet::new();
    for entry in every_kind() {
        let wire = entry.encode().unwrap();
        assert_eq!(Entry::decode(&wire), Ok(entry.clone()), "{entry:?}");
        kinds.insert(entry.kind() as u8);
    }
    assert_eq!(kinds.len(), 3, "the table has every KIND");
}

#[test]
fn prev_seq_is_absent_when_the_log_is_dense_and_present_after_a_gap() {
    let mut e = put(Payload::Inline(Bytes::from_static(b"v")));
    assert!(!types(&e).contains(&tlv::PREV_SEQ));
    assert!(types(&e).contains(&tlv::PREV));

    e.prev = Some(Prev {
        digest: [9; 32],
        seq: Some(41),
    });
    assert!(types(&e).contains(&tlv::PREV_SEQ));
    assert_eq!(Entry::decode(&e.encode().unwrap()).unwrap().prev, e.prev);

    // The signed gap statement: zero digest, PREV_SEQ 0.
    e.prev = Some(Prev {
        digest: [0; 32],
        seq: Some(0),
    });
    assert_eq!(Entry::decode(&e.encode().unwrap()).unwrap().prev, e.prev);
    // The two halves of it go together, in both directions.
    for (digest, seq) in [([0; 32], None), ([0; 32], Some(3)), ([1; 32], Some(0))] {
        e.prev = Some(Prev { digest, seq });
        assert!(e.encode().is_err(), "{digest:?} {seq:?}");
    }
    // A seq without a digest to go with it.
    let wire = edit(&every_kind()[3], &[], &|mut list| {
        list.push((tlv::PREV_SEQ, Bytes::from_static(&[5])));
        list
    });
    assert!(Entry::decode(&wire).is_err());
}

#[test]
fn an_unknown_even_tlv_is_skipped_and_an_unknown_odd_one_refuses() {
    // Wherever a record nests: the entry, a ref, a member's addition, a
    // removal, an epoch, a blob, a sealed body.
    let all = every_kind();
    let members = &all[5];
    let cases: Vec<(&Entry, Vec<u64>)> = vec![
        (&all[0], vec![]),
        (&all[0], vec![tlv::ENTRY_REF]),
        (&all[2], vec![tlv::BLOB]),
        (&all[4], vec![tlv::SEALED]),
        (&all[4], vec![tlv::SEALED, tlv::EPOCH_ID]),
        (members, vec![tlv::MEMBERS]),
        (members, vec![tlv::MEMBERS, tlv::ADD]),
        (members, vec![tlv::MEMBERS, tlv::REMOVE]),
        (members, vec![tlv::MEMBERS, tlv::CREATE]),
        (&all[7], vec![tlv::EPOCH_BODY]),
        (&all[7], vec![tlv::EPOCH_BODY, tlv::AUDIENCE]),
    ];
    for (entry, path) in cases {
        // An even type the format does not use (and 0x0640 is outside the
        // block, so a later revision of it may use it too).
        for even in [0x0640, 0x063C, 0x0602] {
            let wire = with_extra(entry, &path, even);
            assert_eq!(
                Entry::decode(&wire).as_ref(),
                Ok(entry),
                "even {even:#x} in {path:?}"
            );
        }
        for odd in [0x063B, 0x063D, 0x0641, 0x0001] {
            let wire = with_extra(entry, &path, odd);
            assert_eq!(
                Entry::decode(&wire),
                Err(WireError::UnknownCritical(odd)),
                "odd {odd:#x} in {path:?}"
            );
        }
    }
}

#[test]
fn a_single_field_stated_twice_or_a_body_stated_twice_refuses() {
    let e = &every_kind()[0];
    for (typ, value) in [
        (tlv::KIND, Bytes::from_static(&[0])),
        (tlv::PREV, Bytes::from(vec![1u8; 32])),
        (tlv::PATH, Bytes::from_static(b"\x08\x01a")),
        (tlv::INLINE, Bytes::from_static(b"again")),
    ] {
        let wire = edit(e, &[], &|mut list| {
            list.push((typ, value.clone()));
            list
        });
        assert!(Entry::decode(&wire).is_err(), "{typ:#x} twice");
    }
    // A Put with both payloads, a body that is two bodies.
    let wire = edit(e, &[], &|mut list| {
        let mut blob = TlvWriter::new();
        blob.write_tlv(tlv::SIZE, &[9]);
        blob.write_tlv(tlv::ROOT, &[2; 32]);
        list.push((tlv::BLOB, blob.finish()));
        list
    });
    assert!(Entry::decode(&wire).is_err(), "inline and blob");
    let wire = edit(&every_kind()[7], &[], &|mut list| {
        list.push((tlv::MEMBERS, Bytes::new()));
        list
    });
    assert!(Entry::decode(&wire).is_err(), "epoch and members");
}

#[test]
fn an_entry_whose_kind_and_body_disagree_is_refused() {
    let set_kind = |entry: &Entry, kind: u8| {
        edit(entry, &[], &|list| {
            list.into_iter()
                .map(|(t, v)| {
                    if t == tlv::KIND {
                        (t, Bytes::copy_from_slice(&[kind]))
                    } else {
                        (t, v)
                    }
                })
                .collect()
        })
    };
    let all = every_kind();
    for entry in &all {
        for kind in 0..=2u8 {
            let wire = set_kind(entry, kind);
            if kind == entry.kind() as u8 {
                assert_eq!(Entry::decode(&wire).as_ref(), Ok(entry));
            } else {
                assert!(
                    matches!(Entry::decode(&wire), Err(WireError::KindMismatch { .. })),
                    "{entry:?} as kind {kind}"
                );
            }
        }
        assert_eq!(
            Entry::decode(&set_kind(entry, 3)),
            Err(WireError::UnknownKind(3))
        );
    }
    let no_kind = edit(&all[0], &[], &|list| {
        list.into_iter().filter(|(t, _)| *t != tlv::KIND).collect()
    });
    assert_eq!(Entry::decode(&no_kind), Err(WireError::Missing("KIND")));
}

#[test]
fn only_a_put_names_what_it_supersedes() {
    for entry in every_kind() {
        let wire = edit(&entry, &[], &|mut list| {
            let mut r = TlvWriter::new();
            r.write_nested(tlv::ENTRY_REF, |w| {
                prim::write_name(w, &n("/alice/laptop"));
                prim::write_nni(w, tlv::SEQ, 1);
                w.write_tlv(tlv::DIGEST, &[1; 32]);
            });
            let (t, v) = children(&r.finish()).remove(0);
            list.push((t, v));
            list
        });
        let has_after = !entry.after.is_empty();
        let decoded = Entry::decode(&wire);
        match (entry.kind(), has_after) {
            (Kind::Put, _) => assert_eq!(decoded.unwrap().after.len(), entry.after.len() + 1),
            _ => assert!(decoded.is_err(), "{entry:?}"),
        }
    }
    let mut e = every_kind()[5].clone();
    e.after = vec![eref(1)];
    assert!(e.encode().is_err(), "a Members entry supersedes nothing");
}

/// A device name of about a hundred octets, five components.
fn long_device(i: u8) -> Name {
    n(&format!(
        "/organisation-{i:02}/department-engineering/team-networking/member/laptop-{i:02}-abcd"
    ))
}

fn worst_case_put() -> Entry {
    let path: Vec<NameComponent> = (0..8)
        .map(|i| NameComponent::generic(Bytes::from(vec![b'a' + i; 22])))
        .collect();
    // 8 components of 22 octets: 8 × (2 + 22) = 192 octets of Name value.
    let path = Name::from_components(path);
    Entry {
        prev: Some(Prev {
            digest: [8; 32],
            seq: Some(u64::MAX),
        }),
        after: (0..AFTER_MAX as u8)
            .map(|i| EntryRef {
                device: long_device(i),
                seq: u64::MAX - u64::from(i),
                digest: [i; 32],
            })
            .collect(),
        body: Body::Put(PutBody {
            path,
            payload: Payload::Inline(Bytes::from(vec![0x5A; INLINE_MAX])),
        }),
    }
}

#[test]
fn the_worst_case_entry_fits() {
    // Eight superseded heads, the longest path, the largest inline payload,
    // the largest seq, a gap: one signed packet, under the signing device's
    // own (long) names, with the key locator an ECDSA-sized signature, still
    // fits one NDN packet.
    let entry = worst_case_put();
    let content = entry.encode().unwrap();
    assert_eq!(Entry::decode(&content), Ok(entry.clone()));
    let device = long_device(9);
    let space = n("/organisation-09/department-engineering/32=data/chat/room-with-a-long-id");
    let name = log_name(&device, &space, u64::MAX);
    let key = device.clone().append("KEY").append("1234567890");
    let signer = Ed25519Signer::from_seed(&[1; 32], key.clone());
    let wire =
        DataBuilder::new(name, &content).sign_sync(signer.sig_type(), Some(&key), |region| {
            signer.sign_sync(region).unwrap()
        });
    assert!(
        wire.len() <= MAX_NDN_PACKET_SIZE,
        "the worst case is {} octets, over the {MAX_NDN_PACKET_SIZE} an NDN packet may be: \
         lower INLINE_MAX",
        wire.len()
    );

    // The same, sealed: the largest ciphertext an entry carries.
    let sealed = Entry {
        body: Body::Sealed(SealedBody {
            epoch: EpochId {
                creator: long_device(1),
                seq: u64::MAX,
            },
            sealed: Bytes::from(vec![0xC3; SEALED_MAX]),
        }),
        ..entry
    };
    let content = sealed.encode().unwrap();
    assert_eq!(Entry::decode(&content), Ok(sealed));
    assert!(content.len() <= ENTRY_MAX);
}

#[test]
fn an_entry_over_8800_octets_is_refused_at_encode() {
    // Eight references to devices with very long names push the content over
    // the size of one NDN packet.
    let long = |i: u8| {
        Name::from_components(
            (0..10).map(|c| NameComponent::generic(Bytes::from(vec![b'a' + i + c; 120]))),
        )
    };
    let mut e = put(Payload::Inline(Bytes::from(vec![0; INLINE_MAX])));
    e.after = (0..AFTER_MAX as u8)
        .map(|i| EntryRef {
            device: long(i),
            seq: 1,
            digest: [i; 32],
        })
        .collect();
    match e.encode() {
        Err(WireError::TooLarge { size, max, .. }) => {
            assert!(size > MAX_NDN_PACKET_SIZE, "{size}");
            assert!(max <= MAX_NDN_PACKET_SIZE);
        }
        other => panic!("{other:?}"),
    }
    // A decoder meets the same limit on what arrives.
    let mut bytes = vec![0u8; MAX_NDN_PACKET_SIZE + 1];
    bytes[0] = 0xFD;
    bytes[1] = 0x06;
    bytes[2] = 0x01;
    assert!(matches!(
        Entry::decode(&bytes),
        Err(WireError::TooLarge { .. })
    ));
}

#[test]
fn the_limits_of_an_entry_are_held_at_encode_and_decode() {
    let inline = |len: usize| put(Payload::Inline(Bytes::from(vec![1; len])));
    assert!(inline(INLINE_MAX).encode().is_ok());
    assert!(matches!(
        inline(INLINE_MAX + 1).encode(),
        Err(WireError::TooLarge { .. })
    ));

    let at = |path: &str| {
        let mut e = inline(1);
        e.body = Body::Put(PutBody {
            path: n(path),
            payload: Payload::Inline(Bytes::from_static(b"x")),
        });
        e
    };
    assert!(at("/a/b/c/d/e/f/g/h").encode().is_ok());
    for bad in ["/a/b/c/d/e/f/g/h/i", "/a/32=data/c", "/a/seq=4"] {
        assert!(at(bad).encode().is_err(), "{bad}");
    }
    assert!(
        Entry {
            body: Body::Put(PutBody {
                path: Name::root(),
                payload: Payload::Inline(Bytes::new())
            }),
            ..inline(0)
        }
        .encode()
        .is_err(),
        "an empty path"
    );
    let wide = |octets: usize| {
        let mut e = inline(1);
        e.body = Body::Put(PutBody {
            // One component: 2 octets of TLV header and the value.
            path: Name::from_components([NameComponent::generic(Bytes::from(vec![b'a'; octets]))]),
            payload: Payload::Inline(Bytes::from_static(b"x")),
        });
        e
    };
    assert!(wide(198).encode().is_ok(), "200 octets of path in all");
    assert!(wide(199).encode().is_err(), "201 octets of path");

    let mut e = inline(1);
    e.after = (0..=AFTER_MAX as u8).map(eref).collect();
    assert!(matches!(e.encode(), Err(WireError::TooMany { max: 8, .. })));

    let members = |ops: Vec<Op>| Entry {
        prev: dense(),
        after: vec![],
        body: Body::Members(MembersBody { create: None, ops }),
    };
    let add = |i: u8| Op::Add {
        id: [i; 16],
        who: n("/alice"),
        role: Role::Writer,
        epoch: None,
    };
    assert!(members((0..32).map(add).collect()).encode().is_ok());
    assert!(matches!(
        members((0..33).map(add).collect()).encode(),
        Err(WireError::TooMany { max: 32, .. })
    ));
    let tips = |k: u8| {
        members(vec![Op::Remove {
            id: [1; 16],
            tips: (0..k).map(eref).collect(),
        }])
    };
    assert!(tips(64).encode().is_ok());
    // 65 tips are refused.
    assert!(matches!(
        tips(65).encode(),
        Err(WireError::TooMany { max: 64, .. })
    ));
    // Persons are namespaces, matched exactly: no keyword, no seq.
    for who in ["/alice/32=log", "/alice/seq=3"] {
        let mut op = add(1);
        if let Op::Add { who: w, .. } = &mut op {
            *w = n(who);
        }
        assert!(members(vec![op]).encode().is_err(), "{who}");
    }

    let epoch = |audience: usize| Entry {
        prev: dense(),
        after: vec![],
        body: Body::Epoch(EpochBody {
            key_check: [0; 32],
            audience: (0..audience).map(|i| n(&format!("/p{i}"))).collect(),
        }),
    };
    assert!(epoch(256).encode().is_ok());
    assert!(matches!(
        epoch(257).encode(),
        Err(WireError::TooMany { max: 256, .. })
    ));
    // A device named in a reference or an epoch has no keyword component.
    let mut e = inline(1);
    e.after = vec![EntryRef {
        device: n("/alice/32=log/x"),
        seq: 1,
        digest: [0; 32],
    }];
    assert!(e.encode().is_err());
}

#[test]
fn a_blob_entry_names_its_payload_by_size_and_root_and_refuses_an_absurd_size() {
    let blob = |size: u64| {
        put(Payload::Blob {
            size,
            root: [4; 32],
        })
    };
    assert!(blob(PAYLOAD_MAX).encode().is_ok());
    assert!(matches!(
        blob(PAYLOAD_MAX + 1).encode(),
        Err(WireError::TooLarge { .. })
    ));
    let wire = edit(&blob(5000), &[tlv::BLOB], &|list| {
        list.into_iter()
            .map(|(t, v)| {
                if t == tlv::ROOT {
                    (t, v.slice(1..))
                } else {
                    (t, v)
                }
            })
            .collect()
    });
    assert!(Entry::decode(&wire).is_err(), "a root is 32 octets");
}

#[test]
fn grant_ask_seal_key_and_manifest_content_round_trip() {
    let grant = Grant {
        ephemeral: [3; 32],
        ciphertext: Bytes::from_static(b"nonce tag and the wrapped key"),
    };
    assert_eq!(Grant::decode(grant.encode()), Ok(grant.clone()));
    // An ephemeral key of 31 octets, a grant without its ciphertext, two
    // grants in one packet, an unknown critical field.
    let (_, value) = children(&grant.encode()).remove(0);
    let short = rewrite(&value, &[], &|list| {
        list.into_iter()
            .map(|(t, v)| {
                if t == tlv::EPHEMERAL_KEY {
                    (t, v.slice(1..))
                } else {
                    (t, v)
                }
            })
            .collect()
    });
    let missing = rewrite(&value, &[], &|list| {
        list.into_iter()
            .filter(|(t, _)| *t != tlv::CIPHERTEXT)
            .collect()
    });
    let critical = rewrite(&value, &[], &|mut list| {
        list.push((0x063B, Bytes::new()));
        list
    });
    for body in [short, missing] {
        assert!(Grant::decode(serialize(&[(tlv::GRANT, body)])).is_err());
    }
    assert_eq!(
        Grant::decode(serialize(&[(tlv::GRANT, critical)])),
        Err(WireError::UnknownCritical(0x063B))
    );
    let doubled = serialize(&[(tlv::GRANT, value.clone()), (tlv::GRANT, value)]);
    assert!(Grant::decode(doubled).is_err());

    let key = encode_seal_key(&[6; 32]);
    assert_eq!(decode_seal_key(key.clone()), Ok([6; 32]));
    assert!(decode_seal_key(key.slice(..key.len() - 1)).is_err());
    assert!(decode_seal_key(serialize(&[(tlv::SEAL_KEY, Bytes::from(vec![1; 31]))])).is_err());
    assert!(decode_seal_key(Bytes::new()).is_err());

    let digests: Vec<[u8; 32]> = (0..FANOUT as u8).map(|i| [i; 32]).collect();
    assert_eq!(
        decode_manifest(encode_manifest(&digests)),
        Ok(digests.clone())
    );
    let mut over = digests;
    over.push([0; 32]);
    assert!(decode_manifest(encode_manifest(&over)).is_err());
    assert!(decode_manifest(Bytes::new()).is_err());
}

/// What a sealed Put seals is the entry's `PATH` and payload TLVs, held to
/// the limits of a plain Put, nothing else.
#[test]
fn the_sealed_plaintext_is_a_path_and_one_payload() {
    for payload in [
        Payload::Inline(Bytes::from_static(b"secret")),
        Payload::Inline(Bytes::new()),
        Payload::Inline(Bytes::from(vec![9; INLINE_MAX])),
        Payload::Blob {
            size: 1 << 20,
            root: [6; 32],
        },
    ] {
        let put = PutBody {
            path: n("/a/b"),
            payload,
        };
        let plain = encode_sealed_plain(&put).unwrap();
        assert_eq!(
            children(&plain)[0].0,
            tlv::PATH,
            "the plaintext starts at PATH, not at an ENTRY"
        );
        assert_eq!(decode_sealed_plain(&plain), Ok(put));
    }
    let put = PutBody {
        path: n("/a"),
        payload: Payload::Inline(Bytes::from_static(b"x")),
    };
    let plain = encode_sealed_plain(&put).unwrap();
    // A skippable field passes, a critical one refuses.
    let with = |typ: u64| {
        let mut w = TlvWriter::new();
        w.write_raw(&plain);
        w.write_tlv(typ, b"future");
        w.finish()
    };
    assert_eq!(decode_sealed_plain(&with(0x0640)), Ok(put.clone()));
    assert_eq!(
        decode_sealed_plain(&with(0x063B)),
        Err(WireError::UnknownCritical(0x063B))
    );
    // No payload, two payloads, no path, a path twice.
    let first = children(&plain);
    assert!(decode_sealed_plain(&serialize(&first[..1])).is_err());
    let mut two = first.clone();
    two.push((
        tlv::BLOB,
        serialize(&[
            (tlv::SIZE, Bytes::from_static(&[1])),
            (tlv::ROOT, Bytes::from(vec![0; 32])),
        ]),
    ));
    assert!(decode_sealed_plain(&serialize(&two)).is_err());
    assert!(decode_sealed_plain(&serialize(&first[1..])).is_err());
    let mut twice = first.clone();
    twice.push(first[0].clone());
    assert!(decode_sealed_plain(&serialize(&twice)).is_err());
    // The limits of a plain Put hold at encode and at decode.
    let big = PutBody {
        path: n("/a"),
        payload: Payload::Inline(Bytes::from(vec![0; INLINE_MAX + 1])),
    };
    assert!(matches!(
        encode_sealed_plain(&big),
        Err(WireError::TooLarge { .. })
    ));
    let deep = PutBody {
        path: n("/a/b/c/d/e/f/g/h/i"),
        ..put
    };
    assert!(encode_sealed_plain(&deep).is_err());
    let mut oversize = vec![(tlv::PATH, Bytes::from_static(b"\x08\x01a"))];
    oversize.push((tlv::INLINE, Bytes::from(vec![0; INLINE_MAX + 1])));
    assert!(decode_sealed_plain(&serialize(&oversize)).is_err());
}

fn mutate(wire: &[u8], at: usize, how: u8, byte: u8) -> Vec<u8> {
    let mut out = wire.to_vec();
    let at = at % (out.len() + 1);
    match how % 4 {
        0 if at < out.len() => out[at] ^= byte | 1,
        1 => out.truncate(at),
        2 => out.insert(at, byte),
        _ if at < out.len() => {
            out.remove(at);
        }
        _ => {}
    }
    out
}

proptest! {
    /// No bytes make a decoder panic, and what decodes also encodes (the
    /// two sides hold one set of limits).
    #[test]
    fn decode_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 0..400),
        inside in proptest::collection::vec(any::<u8>(), 0..400),
        which in 0usize..8,
        at in any::<usize>(),
        how in any::<u8>(),
        byte in any::<u8>(),
    ) {
        let check = |wire: &[u8]| {
            if let Ok(entry) = Entry::decode(wire) {
                let again = entry.encode().expect("a decoded entry encodes");
                assert_eq!(Entry::decode(&again), Ok(entry));
            }
        };
        check(&bytes);
        // Arbitrary content under a valid ENTRY header.
        let mut w = TlvWriter::new();
        w.write_tlv(tlv::ENTRY, &inside);
        check(&w.finish());
        // A valid entry with one octet changed, cut or inserted.
        let valid = every_kind()[which].encode().unwrap();
        check(&mutate(&valid, at, how, byte));
        // The other decoders.
        let b = Bytes::from(bytes);
        let _ = Grant::decode(b.clone());
        let _ = GrantAsk::decode(b.clone());
        let _ = decode_seal_key(b.clone());
        let _ = decode_manifest(b);
    }
}
