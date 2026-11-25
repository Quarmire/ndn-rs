//! Names, digests and the keyword router (spec §2).

use crate::wire::encode_seal_key;
use crate::wire::prim::{write_epoch_id, write_name};
use bytes::Bytes;
use ndn_foundation_types::{Name, NameComponent};
use ndn_packet::encode::DataBuilder;
use ndn_security::{Ed25519Signer, Signer};
use ndn_tlv::TlvWriter;

use super::*;

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

fn generic(s: &str) -> NameComponent {
    NameComponent::generic(Bytes::copy_from_slice(s.as_bytes()))
}

/// `<owner>/32=data/<rest…>`.
fn space_name(owner: &Name, rest: &[NameComponent]) -> Name {
    let mut comps = owner.components().to_vec();
    comps.push(kw(b"data"));
    comps.extend(rest.iter().cloned());
    Name::from_components(comps)
}

/// The names of every piece of the entry named `entry` whose blob is `chunks`:
/// its chunks in order, then its manifest nodes in heap order.
fn piece_names<'a>(entry: &'a Name, chunks: &ChunksBody) -> impl Iterator<Item = Name> + 'a {
    let shape = Shape::of(chunks.size);
    let manifests: Vec<u64> = shape.manifests().collect();
    (0..shape.chunks)
        .map(PieceKind::Chunk)
        .chain(manifests.into_iter().map(PieceKind::Manifest))
        .map(move |k| piece_name(entry, k))
}

fn epoch() -> EpochId {
    EpochId {
        creator: n("/alice/laptop"),
        seq: 3,
    }
}

/// A seal key packet of `name` carrying `key`, signed as a device would.
fn seal_packet_of(name: &Name, key: &[u8; 32]) -> Bytes {
    DataBuilder::new(name.clone(), &encode_seal_key(key)).sign_digest_sha256()
}

fn ask(space: &Name) -> GrantAsk {
    GrantAsk::new(
        space.clone(),
        epoch(),
        seal_packet_of(&seal_key_name(&n("/alice/laptop"), &[9; 32]), &[9; 32]),
    )
    .expect("a grant ask")
}

/// A certificate-shaped Data of `len` octets of Content, for the limits of a carried chain.
fn cert_of(name: &str, len: usize) -> Bytes {
    DataBuilder::new(n(name), &vec![1; len]).sign_digest_sha256()
}

/// A grant ask carries the asker's signer chain after the seal key packet: it round-trips in
/// the one canonical encoding, an ask without a chain still decodes, and the limits hold
/// (at most 4 certificates, each Data of at most 4,096 octets, 6,144 in all).
#[test]
fn a_grant_ask_may_carry_a_bounded_certificate_chain() {
    let space = n("/alice/32=data/notes");
    let plain = ask(&space);
    assert!(plain.chain.is_empty());
    assert_eq!(GrantAsk::decode(plain.encode()), Ok(plain.clone()));

    let chain = vec![
        cert_of("/alice/laptop/KEY/1/CA/v=1", 300),
        cert_of("/alice/CA/KEY/c/root/v=1", 300),
    ];
    let carrying = plain.clone().with_chain(chain.clone()).expect("a chain");
    assert_eq!(carrying.chain, chain);
    let device = n("/bob/phone");
    let name = grant_name(&device, &carrying);
    assert_eq!(
        parse_grant_name(&name),
        Some((device.clone(), carrying.clone())),
        "a chain is part of the one canonical name"
    );
    assert_ne!(
        name,
        grant_name(&device, &plain),
        "an ask with a chain is another ask"
    );

    let too_many = vec![cert_of("/a/KEY/1/x/v=1", 10); ASKER_CHAIN_MAX + 1];
    let too_big = vec![cert_of("/a/KEY/1/x/v=1", 4097)];
    let too_much = vec![
        cert_of("/a/KEY/1/x/v=1", 3000),
        cert_of("/a/KEY/1/y/v=1", 3000),
        cert_of("/a/KEY/1/z/v=1", 3000),
    ];
    for (what, chain) in [
        ("five", too_many),
        ("one over 4,096", too_big),
        ("over 6,144 in all", too_much),
    ] {
        assert!(plain.clone().with_chain(chain).is_err(), "{what}");
    }
    assert!(
        plain
            .clone()
            .with_chain(vec![Bytes::from_static(b"not a Data")])
            .is_err(),
        "a certificate is a Data"
    );
    // A decoder holds the same limits: the TLV of an over-long chain names no grant.
    let mut over = carrying.clone();
    over.chain = vec![cert_of("/a/KEY/1/x/v=1", 10); ASKER_CHAIN_MAX + 1];
    assert_eq!(parse_grant_name(&grant_name(&device, &over)), None);
}

/// Stage-7 I6: a grant ask's parser stops at the `ASKER_CHAIN_MAX + 1`th certificate: it keeps
/// no more and reads nothing after it, so a flood of certificates in one Interest costs no more
/// than the limit. (The proof: an unknown critical TLV after the fifth certificate is never
/// reached.)
#[test]
fn a_grant_ask_parse_stops_at_the_certificate_over_the_limit() {
    let plain = ask(&n("/alice/32=data/notes"));
    let mut w = TlvWriter::new();
    w.write_nested(tlv::GRANT_ASK, |w| {
        write_name(w, &plain.space);
        write_epoch_id(w, &plain.epoch);
        w.write_tlv(tlv::SEAL_KEY_PACKET, &plain.seal_packet);
        for _ in 0..=ASKER_CHAIN_MAX {
            w.write_tlv(tlv::ASKER_CERT, b"a certificate");
        }
        // Never reached: it would make the whole ask an unknown critical TLV.
        w.write_tlv(0x0FF1, b"after");
    });
    let error = GrantAsk::decode(w.finish()).expect_err("five certificates are too many");
    assert!(
        matches!(error, WireError::TooLarge { .. }),
        "the parse went on past the certificate over the limit: {error:?}"
    );
}

#[test]
fn space_names_of_one_to_four_components_parse_and_five_do_not() {
    let owner = n("/home/alice");
    for k in 1..=4 {
        let rest: Vec<NameComponent> = (0..k).map(|i| generic(&format!("c{i}"))).collect();
        let space = space_name(&owner, &rest);
        let parsed = parse_space_name(&space).unwrap_or_else(|| panic!("{k} components: {space}"));
        assert_eq!(parsed.owner, owner);
        assert_eq!(parsed.rest, rest);
        assert_eq!(space_name(&parsed.owner, &parsed.rest), space);
    }
    let five: Vec<NameComponent> = (0..5).map(|i| generic(&format!("c{i}"))).collect();
    assert_eq!(parse_space_name(&space_name(&owner, &five)), None);
    // None at all, a root owner, an owner with a keyword or a seq, a
    // keyword or a digest among the components, a second marker.
    for bad in [
        "/home/alice/32=data",
        "/32=data/x",
        "/home/32=log/32=data/x",
        "/home/alice/seq=4/32=data/x",
        "/home/alice/32=data/32=data/x",
        "/home/alice/32=data/x/32=log",
        "/home/alice/laptop",
    ] {
        assert_eq!(parse_space_name(&n(bad)), None, "{bad}");
    }
    let digest = owner
        .clone()
        .append_component(kw(b"data"))
        .append_implicit_digest([1; 32]);
    assert_eq!(parse_space_name(&digest), None);
    let typed = n("/home/alice/32=data").append_sequence_num(4);
    assert_eq!(
        parse_space_name(&typed),
        None,
        "a path component is generic"
    );
}

#[test]
fn the_sync_group_of_a_space_is_the_owners_group_plus_its_components() {
    assert_eq!(
        sync_group_of(&n("/home/alice/32=data/n/f1")),
        Some(n("/home/alice/32=sync/n/f1"))
    );
    assert_eq!(
        sync_group_of(&n("/alice/32=data/n")),
        Some(ndn_security::sync_group(&n("/alice")).append("n"))
    );
    assert_eq!(sync_group_of(&n("/alice/notes")), None);
}

#[test]
fn log_name_parses_back_and_refuses_a_device_with_a_keyword() {
    let device = n("/alice/member/laptop");
    let space = n("/alice/32=data/n/f1");
    let name = log_name(&device, &space, 7);
    assert_eq!(
        name,
        n("/alice/member/laptop/32=log/alice/32=data/n/f1/seq=7")
    );
    assert_eq!(
        parse_log_name(&name),
        Some(LogName {
            device: device.clone(),
            space: space.clone(),
            seq: 7
        })
    );
    // A device name has no keyword: the first 32=log ends it, so a keyword
    // before it (or a digest) is no device.
    for bad in [
        "/alice/32=held/laptop/32=log/alice/32=data/n/seq=1",
        "/alice/32=seal/laptop/32=log/alice/32=data/n/seq=1",
        "/32=log/alice/32=data/n/seq=1",
        // no seq, a seq that is not last, a space that is none
        "/alice/laptop/32=log/alice/32=data/n",
        "/alice/laptop/32=log/alice/32=data/n/seq=1/x",
        "/alice/laptop/32=log/alice/notes/seq=1",
        "/alice/laptop/32=log/seq=1",
        // a piece name is no entry name
        "/alice/laptop/32=log/alice/32=data/n/seq=1/32=piece/seg=0",
    ] {
        assert_eq!(parse_log_name(&n(bad)), None, "{bad}");
    }
    let digested = device
        .clone()
        .append_implicit_digest([4; 32])
        .append_component(kw(b"log"))
        .append_component(NameComponent::sequence_num(1));
    assert_eq!(parse_log_name(&digested), None);
}

#[test]
fn seal_key_grant_and_held_names_round_trip_and_refuse_what_they_are_not() {
    let device = n("/alice/laptop");
    let space = n("/alice/32=data/n");

    let seal = seal_key_name(&device, &[7; 32]);
    assert_eq!(parse_seal_key_name(&seal), Some((device.clone(), [7; 32])));
    assert_eq!(seal.components().len(), device.len() + 2);
    assert!(seal.has_prefix(&device.clone().append_component(kw(b"seal"))));
    for bad in [
        "/alice/laptop/32=seal",
        "/alice/laptop/32=seal/short",
        "/alice/laptop/32=seal/aa/bb",
        "/alice/32=held/x/32=seal/aa",
    ] {
        assert_eq!(parse_seal_key_name(&n(bad)), None, "{bad}");
    }
    let typed = device
        .clone()
        .append_component(kw(b"seal"))
        .append_component(NameComponent::new(0x3A, Bytes::copy_from_slice(&[7; 32])));
    assert_eq!(
        parse_seal_key_name(&typed),
        None,
        "the key is a generic component"
    );

    let ask = ask(&space);
    let grant = grant_name(&device, &ask);
    assert_eq!(
        parse_grant_name(&grant),
        Some((device.clone(), ask.clone()))
    );
    // The name carries the ask in one component.
    assert_eq!(grant.len(), device.len() + 2);
    assert_eq!(GrantAsk::decode(ask.encode()), Ok(ask.clone()));
    // The ask names the asker's device through its seal key packet.
    assert_eq!(
        parse_seal_key_name(&ask.seal_key),
        Some((n("/alice/laptop"), [9; 32]))
    );
    assert!(GrantAsk::decode(grant.components()[device.len() + 1].value.clone()).is_ok());
    for bad in [
        // an ask for a name that is no space
        grant_name(
            &device,
            &GrantAsk {
                space: n("/alice/notes"),
                ..ask.clone()
            },
        ),
        // an epoch whose creator is no device
        grant_name(
            &device,
            &GrantAsk {
                epoch: EpochId {
                    creator: n("/alice/32=log/x"),
                    seq: 1,
                },
                ..ask.clone()
            },
        ),
        // an ask whose packet is named for no seal key
        grant_name(
            &device,
            &GrantAsk {
                seal_packet: seal_packet_of(&n("/alice/laptop"), &[9; 32]),
                ..ask.clone()
            },
        ),
        grant_name(
            &device,
            &GrantAsk {
                seal_packet: seal_packet_of(&n("/alice/laptop/32=seal/short"), &[9; 32]),
                ..ask.clone()
            },
        ),
        // an ask whose packet is no Data
        grant_name(
            &device,
            &GrantAsk {
                seal_packet: Bytes::from_static(b"not a Data packet"),
                ..ask.clone()
            },
        ),
        // an ask whose packet is over the most an ask may carry
        grant_name(
            &device,
            &GrantAsk {
                seal_packet: Bytes::from(vec![0; SEAL_KEY_PACKET_MAX + 1]),
                ..ask.clone()
            },
        ),
        // the old form: the seal key's name or its 32 octets, not its packet
        device
            .clone()
            .append_component(kw(b"grant"))
            .append_component(NameComponent::generic({
                let mut w = ndn_tlv::TlvWriter::new();
                w.write_nested(tlv::GRANT_ASK, |w| {
                    w.write_tlv(tlv::SEAL_KEY, &[9; 32]);
                    prim::write_name(w, &space);
                    prim::write_epoch_id(w, &epoch());
                });
                w.finish()
            })),
        device
            .clone()
            .append_component(kw(b"grant"))
            .append_component(NameComponent::generic({
                let mut w = ndn_tlv::TlvWriter::new();
                w.write_nested(tlv::GRANT_ASK, |w| {
                    prim::write_name(w, &seal_key_name(&n("/alice/laptop"), &[9; 32]));
                    prim::write_name(w, &space);
                    prim::write_epoch_id(w, &epoch());
                });
                w.finish()
            })),
        // an ask that carries its packet twice
        device
            .clone()
            .append_component(kw(b"grant"))
            .append_component(NameComponent::generic({
                let mut w = ndn_tlv::TlvWriter::new();
                w.write_nested(tlv::GRANT_ASK, |w| {
                    prim::write_name(w, &space);
                    prim::write_epoch_id(w, &epoch());
                    w.write_tlv(tlv::SEAL_KEY_PACKET, &ask.seal_packet);
                    w.write_tlv(tlv::SEAL_KEY_PACKET, &ask.seal_packet);
                });
                w.finish()
            })),
        device.clone().append_component(kw(b"grant")),
        device
            .clone()
            .append_component(kw(b"grant"))
            .append("not a TLV"),
        n("/alice/32=held/x/32=grant/y"),
    ] {
        assert_eq!(parse_grant_name(&bad), None, "{bad}");
    }

    let piece = log_name(&n("/bob/phone"), &space, 4);
    let held = held_name(&device, &piece);
    assert_eq!(
        parse_held_name(&held),
        Some((device.clone(), piece.clone()))
    );
    for bad in [
        device.clone().append_component(kw(b"held")),
        device
            .clone()
            .append_component(kw(b"held"))
            .append("not a TLV"),
        n("/alice/32=seal/x/32=held/y"),
    ] {
        assert_eq!(parse_held_name(&bad), None, "{bad}");
    }
}

/// The routing a node does on an Interest is one look at the first keyword:
/// each kind's parser decides what the old chain of parsers decided, in the
/// same order, and a name no parser takes routes nowhere.
#[test]
fn the_keyword_router_names_each_served_kind_in_one_look() {
    let device = n("/alice/laptop");
    let space = n("/alice/32=data/docs/plan");
    let log = log_name(&device, &space, 7);
    let mut names = vec![
        Name::from_components([]),
        n("/alice/laptop"),
        space.clone(),
        log.clone(),
        piece_name(&log, PieceKind::Chunk(2)),
        piece_name(&log, PieceKind::Manifest(0)),
        seal_key_name(&device, &[9; 32]),
        grant_name(&device, &ask(&space)),
        held_name(&device, &log),
        chan_ask_name(&device, &[3; 32]),
        // A chan keyword with no digest, or with a generic component, is routed to the setup and
        // parses to nothing there.
        n("/alice/laptop/32=chan"),
        n("/alice/laptop/32=chan/x"),
        held_name(&device, &n("/bob/phone/32=log/bob/32=data/x/seq=1")),
        // Misplaced keywords: one after another, a lone keyword, a keyword
        // the layer does not use, the marker of a space.
        n("/alice/laptop/32=held/32=held/x"),
        n("/32=grant"),
        n("/alice/32=grant"),
        n("/alice/32=range/x"),
        n("/alice/laptop/32=log"),
        n("/alice/laptop/32=seal"),
        n("/alice/32=data/x/32=log/seq=1"),
    ];
    names.push(held_name(&device, &log).append_implicit_digest([5; 32]));
    names.push(
        device
            .clone()
            .append_implicit_digest([5; 32])
            .append_component(kw(b"held"))
            .append("x"),
    );

    // What a node tried before the router, as parsers alone, in order.
    let chain = |name: &Name| {
        if parse_grant_name(name).is_some() {
            Some(Served::Grant)
        } else if parse_held_name(name).is_some() {
            Some(Served::Held)
        } else if parse_seal_key_name(name).is_some() {
            Some(Served::Seal)
        } else if parse_chan_name(name).is_some() {
            Some(Served::Chan)
        } else if parse_log_name(name).is_some() || parse_piece_name(name).is_some() {
            Some(Served::Log)
        } else {
            None
        }
    };
    let routed = |name: &Name| match served_kind(name)? {
        Served::Grant => parse_grant_name(name).map(|_| Served::Grant),
        Served::Held => parse_held_name(name).map(|_| Served::Held),
        Served::Seal => parse_seal_key_name(name).map(|_| Served::Seal),
        Served::Log => (parse_log_name(name).is_some() || parse_piece_name(name).is_some())
            .then_some(Served::Log),
        Served::Chan => parse_chan_name(name).map(|_| Served::Chan),
    };
    let mut seen = std::collections::BTreeSet::new();
    for name in &names {
        assert_eq!(routed(name), chain(name), "{name}");
        seen.extend(chain(name).map(|k| format!("{k:?}")));
    }
    assert_eq!(seen.len(), 5, "the table reaches every route: {seen:?}");
    // The one look is the first keyword and nothing else.
    assert_eq!(served_kind(&log), Some(Served::Log));
    assert_eq!(served_kind(&held_name(&device, &log)), Some(Served::Held));
    assert_eq!(served_kind(&space), None);
}

/// An extension may claim any keyword the layer's own names do not carry
/// (`host::Extension`): so `CORE_KEYWORDS` must list every keyword a name
/// builder of the layer writes, or an extension could be given Interests the
/// core serves.
#[test]
fn every_keyword_the_layers_names_carry_is_a_core_keyword() {
    let device = n("/alice/laptop");
    let space = n("/alice/32=data/docs/plan");
    let log = log_name(&device, &space, 7);
    let names = [
        space.clone(),
        log.clone(),
        piece_name(&log, PieceKind::Chunk(2)),
        piece_name(&log, PieceKind::Manifest(0)),
        seal_key_name(&device, &[9; 32]),
        grant_name(&device, &ask(&space)),
        held_name(&device, &log),
        sync_group_of(&space).unwrap(),
        signal_run_name(&device, &space, &[3; RUN_ID_LEN]),
        chan_ask_name(&device, &[4; 32]),
        chan_announce_name(&sync_group_of(&space).unwrap(), &[5; 32]),
    ];
    let mut seen = std::collections::BTreeSet::new();
    for name in &names {
        for c in name.components() {
            if c.typ == ndn_foundation_types::tlv_type::KEYWORD {
                assert!(
                    CORE_KEYWORDS.contains(&c.value.as_ref()),
                    "{name} carries the keyword {:?}, which an extension could claim",
                    String::from_utf8_lossy(&c.value)
                );
                seen.insert(c.value.to_vec());
            }
        }
    }
    assert_eq!(
        seen.len(),
        CORE_KEYWORDS.len(),
        "the list names no keyword the builders do not write: {seen:?}"
    );
}

#[test]
fn owns_is_a_device_prefix_not_a_component_prefix() {
    let notes = n("/alice/32=data/notes/p1");
    // Every device of the namespace owns it, the namespace's own key too.
    for key in [
        "/alice/laptop/KEY/1",
        "/alice/phone/KEY/7",
        "/alice/member/tablet/KEY/2",
        "/alice/KEY/1",
    ] {
        assert!(owns(&notes, &n(key)), "{key} owns {notes}");
    }
    // Another namespace's device, one whose name only starts alike, and a
    // name that is no key name do not.
    for key in [
        "/bob/laptop/KEY/1",
        "/alicia/laptop/KEY/1",
        "/alice/laptop",
        "/alice/laptop/KEY",
    ] {
        assert!(!owns(&notes, &n(key)), "{key} does not own {notes}");
    }
    // The owner namespace ends at the marker, however many components.
    let home = n("/home/bob/32=data/x");
    assert!(owns(&home, &n("/home/bob/member/laptop/KEY/1")));
    assert!(!owns(&home, &n("/home/member/hub/KEY/1")));
    assert!(owns(
        &n("/home/32=data/x"),
        &n("/home/bob/member/laptop/KEY/1")
    ));
    // A name that is no space has no owner.
    assert!(!owns(&n("/alice/notes"), &n("/alice/laptop/KEY/1")));
    assert_eq!(
        device_of(&n("/alice/laptop/KEY/1")),
        Some(n("/alice/laptop"))
    );
    assert_eq!(device_of(&n("/alice/laptop")), None);
}

/// A packet signed by `key` over `name` and `content`, its signature value
/// replaced by `sig` when given; and the signature value it carries.
fn signed(name: &Name, content: &[u8], sig: Option<&[u8]>) -> (Bytes, Bytes) {
    let key = n("/alice/laptop/KEY/1");
    let signer = Ed25519Signer::from_seed(&[7; 32], key.clone());
    let mut carried = Bytes::new();
    let wire = DataBuilder::new(name.clone(), content).sign_sync(
        signer.sig_type(),
        Some(&key),
        |region| {
            carried = match sig {
                Some(s) => Bytes::copy_from_slice(s),
                None => signer.sign_sync(region).unwrap(),
            };
            carried.clone()
        },
    );
    (wire, carried)
}

/// An ECDSA signature is malleable, so a relay may hand on a copy whose
/// signature value differs: ordering, chain links and equivocation must
/// treat the two as one object.
#[test]
fn a_reencoded_copy_has_the_same_signed_digest() {
    let name = log_name(&n("/alice/laptop"), &n("/alice/32=data/n"), 1);
    let (wire, sig) = signed(&name, b"content", None);
    let mut flipped = sig.to_vec();
    for b in &mut flipped {
        *b ^= 0xFF;
    }
    let (copy, _) = signed(&name, b"content", Some(&flipped));
    assert_ne!(wire, copy, "the copies differ in their signature value");
    assert_ne!(implicit_digest(&wire), implicit_digest(&copy));
    assert_eq!(signed_digest(&wire), signed_digest(&copy));
    // What the signer signed is what the digest names: other content or
    // another name is another object.
    let (other, _) = signed(&name, b"other", None);
    assert_ne!(signed_digest(&wire), signed_digest(&other));
    let (renamed, _) = signed(
        &log_name(&n("/alice/laptop"), &n("/alice/32=data/n"), 2),
        b"content",
        None,
    );
    assert_ne!(signed_digest(&wire), signed_digest(&renamed));
}

#[test]
fn piece_names_are_unique_parse_back_and_cover_the_manifest_tree() {
    let entry = log_name(&n("/alice/laptop"), &n("/alice/32=data/n"), 5);
    for size in [
        0u64,
        1,
        CHUNK as u64,
        CHUNK as u64 + 1,
        (CHUNK * FANOUT) as u64,
        (CHUNK * FANOUT) as u64 + 1,
        (CHUNK * FANOUT * FANOUT) as u64 + 1,
    ] {
        let body = ChunksBody {
            size,
            root: [0; 32],
        };
        let names: Vec<Name> = piece_names(&entry, &body).collect();
        let shape = Shape::of(size);
        assert_eq!(names.len() as u64, shape.pieces(), "size {size}");
        let unique: std::collections::BTreeSet<_> = names.iter().collect();
        assert_eq!(unique.len(), names.len(), "size {size}: names are unique");
        // Chunks first, then the manifest nodes in heap order.
        assert_eq!(names[0], piece_name(&entry, PieceKind::Chunk(0)));
        assert_eq!(
            names.last().unwrap(),
            &piece_name(
                &entry,
                PieceKind::Manifest(shape.manifests().last().unwrap())
            )
        );
        for name in &names {
            let parsed = parse_piece_name(name).unwrap_or_else(|| panic!("{name}"));
            assert_eq!(parsed.entry, entry);
            assert_eq!(piece_name(&parsed.entry, parsed.kind), *name);
        }
        // Every node lists children that are pieces of the payload.
        for k in shape.manifests() {
            for child in shape.children(k).unwrap() {
                assert!(
                    unique.contains(&&piece_name(&entry, child)),
                    "size {size}: {k}"
                );
            }
        }
    }
    for bad in [
        "/alice/laptop/32=log/alice/32=data/n/seq=5/seg=0",
        "/alice/laptop/32=log/alice/32=data/n/seq=5/32=piece",
        "/alice/laptop/32=log/alice/32=data/n/seq=5/32=piece/x",
        "/alice/laptop/32=log/alice/32=data/n/32=piece/seg=0",
    ] {
        assert!(parse_piece_name(&n(bad)).is_none(), "{bad}");
    }
}

#[test]
fn signal_run_names_round_trip_and_refuse_what_they_are_not() {
    let device = n("/alice/laptop");
    let scope = n("/alice/32=data/chat/room");
    let run = [7u8; RUN_ID_LEN];
    let name = signal_run_name(&device, &scope, &run);
    assert_eq!(
        name,
        n("/alice/laptop/32=signal/alice/32=data/chat/room/32=run").append(run)
    );
    assert_eq!(
        parse_signal_run_name(&name),
        Some(SignalRunName {
            device: device.clone(),
            scope: scope.clone(),
            run
        })
    );
    let with_run =
        |run: &[u8]| n("/alice/laptop/32=signal/alice/32=data/chat/room/32=run").append(run);
    for bad in [
        // a run id of 15 or 17 octets
        with_run(&run[..15]),
        with_run(&[7; RUN_ID_LEN + 1]),
        // a scope that is no space, none at all
        signal_run_name(&device, &n("/alice/notes"), &run),
        n("/alice/laptop/32=signal/32=run").append(run),
        // a device with a keyword or a digest
        signal_run_name(&n("/alice/32=held/laptop"), &scope, &run),
        signal_run_name(
            &device.clone().append_implicit_digest([1; 32]),
            &scope,
            &run,
        ),
        // the run id not generic, no run keyword
        n("/alice/laptop/32=signal/alice/32=data/chat/room/32=run")
            .append_component(NameComponent::new(0x3A, Bytes::copy_from_slice(&run))),
        n("/alice/laptop/32=signal/alice/32=data/chat/room").append(run),
    ] {
        assert_eq!(parse_signal_run_name(&bad), None, "{bad}");
    }
}

/// `<device>/32=chan/<digest>` has exactly one component after the keyword, a
/// ParametersSha256DigestComponent of 32 octets, and nothing else parses: the router sends such
/// a name to the channel setup and the announce under a sync group to no device.
#[test]
fn a_chan_name_is_one_digest_under_a_device_and_nothing_else_parses() {
    let device = n("/alice/laptop");
    let digest = [9u8; 32];
    let name = chan_ask_name(&device, &digest);
    let comps = name.components();
    assert_eq!(comps.len(), 4, "device, device, the keyword, the digest");
    assert_eq!(comps[2], kw(b"chan"));
    assert_eq!(
        comps[3].typ,
        ndn_foundation_types::tlv_type::PARAMETERS_SHA256
    );
    assert_eq!(parse_chan_name(&name), Some((device.clone(), digest)));
    assert_eq!(served_kind(&name), Some(Served::Chan));
    assert_eq!(chan_prefix(&device), n("/alice/laptop/32=chan"));

    let with = |c: NameComponent| chan_prefix(&device).append_component(c);
    let digest_component = |v: &[u8]| {
        NameComponent::new(
            ndn_foundation_types::tlv_type::PARAMETERS_SHA256,
            Bytes::copy_from_slice(v),
        )
    };
    for bad in [
        // no component after the keyword, two, or one that is no parameters digest
        chan_prefix(&device),
        name.clone().append("more"),
        with(generic("digest")),
        with(NameComponent::new(
            ndn_foundation_types::tlv_type::IMPLICIT_SHA256,
            Bytes::copy_from_slice(&digest),
        )),
        // a digest of 31 or 33 octets
        with(digest_component(&digest[..31])),
        with(digest_component(&[9; 33])),
        // a device with a keyword, with a digest, or none at all
        chan_ask_name(&n("/alice/32=held/laptop"), &digest),
        chan_ask_name(&device.clone().append_implicit_digest([1; 32]), &digest),
        chan_ask_name(&Name::root(), &digest),
        // another keyword
        n("/alice/laptop/32=grant").append_component(digest_component(&digest)),
    ] {
        assert_eq!(parse_chan_name(&bad), None, "{bad}");
    }
    // The announce is the same shape under a sync group, and no device's ask.
    let group = sync_group_of(&n("/alice/32=data/chat/room")).unwrap();
    let announce = chan_announce_name(&group, &digest);
    assert_eq!(parse_chan_name(&announce), None);
    assert_eq!(
        parse_chan_announce_name(&announce),
        Some((group.clone(), digest))
    );
    assert_eq!(
        parse_chan_announce_name(&name),
        None,
        "a device's ask is no announce"
    );
    for bad in [
        chan_announce_name(&n("/alice/laptop"), &digest),
        chan_announce_name(&n("/alice/32=sync"), &digest),
        chan_announce_name(&n("/alice/32=sync/a/b/c/d/e"), &digest),
        group.clone().append("x"),
    ] {
        assert_eq!(parse_chan_announce_name(&bad), None, "{bad}");
    }
}
