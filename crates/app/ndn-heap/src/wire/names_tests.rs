//! Names, digests and the keyword router (spec §2).

use bytes::Bytes;
use ndn_foundation_types::{Name, NameComponent};
use ndn_packet::encode::DataBuilder;
use ndn_security::{Ed25519Signer, Signer};

use super::*;

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

fn generic(s: &str) -> NameComponent {
    NameComponent::generic(Bytes::copy_from_slice(s.as_bytes()))
}

fn epoch() -> EpochId {
    EpochId {
        creator: n("/alice/laptop"),
        seq: 3,
    }
}

fn ask(space: &Name) -> GrantAsk {
    GrantAsk {
        seal_key: [9; 32],
        space: space.clone(),
        epoch: epoch(),
    }
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
    assert!(seal.has_prefix(&seal_key_prefix(&device)));
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
    };
    let mut seen = std::collections::BTreeSet::new();
    for name in &names {
        assert_eq!(routed(name), chain(name), "{name}");
        seen.extend(chain(name).map(|k| format!("{k:?}")));
    }
    assert_eq!(seen.len(), 4, "the table reaches every route: {seen:?}");
    // The one look is the first keyword and nothing else.
    assert_eq!(served_kind(&log), Some(Served::Log));
    assert_eq!(served_kind(&held_name(&device, &log)), Some(Served::Held));
    assert_eq!(served_kind(&space), None);
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
