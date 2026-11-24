//! What a person admitted to one space may ask a device for by name
//! (`folder_scope`, spec §13.2–§13.4): ported from the data layer's tests of
//! `folder_scope.rs`, on the heap's names (`<D>/32=log/<S>/seq=<n>`, pieces, seal keys,
//! grants and held copies of the space; no summaries, no cut manifests, no sync groups).

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_heap::wire::{
    GrantAsk, PieceKind, grant_name, held_name, log_name, piece_name, seal_key_name,
    signal_run_name,
};
use ndn_heap::{RUN_ID_LEN, wire::EpochId};
use ndn_packet::encode::DataBuilder;

use crate::folder_scope::{departure_carries, folder_carries, writer_carries};

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

fn space() -> Name {
    n("/alice/32=data/notebook")
}

/// The device `/alice/member/laptop` and a writer of another namespace.
fn devices() -> [Name; 2] {
    [n("/alice/member/laptop"), n("/bob/member/phone")]
}

/// The grant name of a device `granter` for `space`'s epoch, asked by `reader`'s seal key.
fn grant(granter: &str, space: &Name) -> Name {
    let packet = DataBuilder::new(seal_key_name(&n("/alice/member/phone"), &[3; 32]), b"key").build();
    let ask = GrantAsk::new(
        space.clone(),
        EpochId {
            creator: n("/alice/member/laptop"),
            seq: 2,
        },
        packet,
    )
    .expect("a grant ask");
    grant_name(&n(granter), &ask)
}

/// The namespaces of the writers the members list: Alice's own, Bob's, and Carol's.
fn namespaces() -> Vec<Name> {
    vec![n("/alice"), n("/bob"), n("/carol")]
}

#[test]
fn the_spaces_entries_cross_and_no_other_space_does() {
    let space = space();
    for device in devices() {
        let entry = log_name(&device, &space, 3);
        assert!(folder_carries(&space, &entry), "{entry}");
        // Its pieces and the Interest that names the digest too.
        let chunk = piece_name(&entry, PieceKind::Chunk(1));
        assert!(folder_carries(&space, &chunk), "{chunk}");
        let manifest = piece_name(&entry, PieceKind::Manifest(0));
        assert!(folder_carries(&space, &manifest), "{manifest}");
        assert!(
            folder_carries(&space, &entry.clone().append_implicit_digest([9; 32])),
            "{entry} by digest"
        );
        // A sibling, a prefix of it, another namespace's space of the same path, a space
        // whose name merely starts like this one, **and one that extends this one**
        // (`<S>/<c>`: a space is exactly its name, never a prefix of others').
        for outside in [
            n("/alice/32=data/diary"),
            n("/alice/32=data/notebook2"),
            n("/alice/32=data/note"),
            n("/alice/32=data/other/notebook"),
            n("/alice/32=data/notebook/chapter"),
            n("/bob/32=data/notebook"),
        ] {
            let entry = log_name(&device, &outside, 3);
            assert!(
                !folder_carries(&space, &entry),
                "an entry of {outside} crossed the link of {space}"
            );
            assert!(!folder_carries(&space, &piece_name(&entry, PieceKind::Chunk(1))));
        }
    }
}

#[test]
fn names_that_are_no_name_of_the_layer_or_no_spaces_carry_nothing() {
    let space = space();
    let device = n("/alice/member/laptop");
    for name in [
        n("/alice/member/laptop"),
        n("/alice/32=sync"),
        n("/alice/32=sync/notebook"),
        n("/alice/member/laptop/KEY/1"),
        n("/alice/member/laptop/32=intro/offer/x"),
        n("/alice/32=data/notebook"),
        n("/"),
    ] {
        assert!(!folder_carries(&space, &name), "{name} crossed a space's link");
    }
    // A grant for no space carries nothing.
    let entry = log_name(&device, &space, 1);
    assert!(!folder_carries(&n("/alice/notebook"), &entry));
    assert!(!folder_carries(&n("/alice/32=data"), &entry));
}

#[test]
fn held_copies_and_grants_are_judged_by_the_name_they_are_about() {
    let space = space();
    let holder = n("/alice/member/laptop");
    let writer = n("/bob/member/phone");
    let inside = log_name(&writer, &space, 4);
    let outside = log_name(&writer, &n("/alice/32=data/diary"), 4);

    // A held copy is the one it names: carried when that is.
    assert!(folder_carries(&space, &held_name(&holder, &inside)));
    assert!(!folder_carries(&space, &held_name(&holder, &outside)));
    // One that names another held copy does not hide it.
    let nested = held_name(&holder, &held_name(&holder, &outside));
    assert!(!folder_carries(&space, &nested));
    // Two held names are unwrapped, not three.
    let twice = held_name(&holder, &held_name(&holder, &inside));
    assert!(folder_carries(&space, &twice));
    let thrice = held_name(&holder, &twice);
    assert!(!folder_carries(&space, &thrice));

    // A grant, by the space whose epoch key it is, to a device of the owner's namespace.
    assert!(folder_carries(&space, &grant("/alice/member/laptop", &space)));
    assert!(!folder_carries(
        &space,
        &grant("/alice/member/laptop", &n("/alice/32=data/diary"))
    ));
    // The name of a grant of another form is no grant.
    assert!(!folder_carries(&space, &n("/alice/member/laptop/32=grant/not-an-ask")));
}

#[test]
fn seals_cross_and_what_is_not_the_layers_does_not() {
    let space = space();
    let device = n("/alice/member/laptop");
    assert!(folder_carries(&space, &seal_key_name(&device, &[7; 32])));
    // A seal key of a device of any other namespace (a stranger's, or a writer's,
    // whom `writer_carries` adds only while the members list her) does not cross a link
    // of this space, whatever the key; nor does a name whose device is not
    // `<W>/<role>/<device>`.
    for other in [
        n("/carol/member/laptop"),
        n("/bob/member/phone"),
        n("/alicia/member/laptop"),
        n("/alice/member/laptop/nested"),
        n("/alice/member"),
        n("/alice/stranger/laptop"),
    ] {
        let seal = seal_key_name(&other, &[7; 32]);
        assert!(
            !folder_carries(&space, &seal),
            "the seal key {seal} of a device outside the space's namespace crossed the link"
        );
    }
    let run = signal_run_name(&device, &space, &[1; RUN_ID_LEN]);
    assert!(folder_carries(&space, &run));
    let other = signal_run_name(&device, &n("/alice/32=data/diary"), &[1; RUN_ID_LEN]);
    assert!(!folder_carries(&space, &other));
}

#[test]
fn a_grant_ask_crosses_only_to_a_granter_the_space_can_have() {
    // A grant ask crosses a grant link only to a granter the space's members can have: a
    // device of the space's own namespace (its epoch's creator), or of a namespace the
    // members list as a writer (a co-writer holds the key too). A grant ask to any other
    // device would make the owner's forwarder relay a member's asks to devices that
    // never held the key (round 12, H1).
    let space = space();
    let namespaces = namespaces();
    // The space's own namespace: `folder_carries`'s, with no writer listed.
    for own in ["/alice/member/laptop", "/alice/admin/tablet"] {
        let name = grant(own, &space);
        assert!(folder_carries(&space, &name), "{name}");
        assert!(!writer_carries(&space, &namespaces, &name), "{name}");
    }
    // A listed writer's device: added by `writer_carries`, only while listed.
    for listed in ["/bob/member/phone", "/carol/admin/tablet"] {
        let name = grant(listed, &space);
        assert!(
            !folder_carries(&space, &name),
            "a grant ask to {listed}, a device of another namespace, crossed on its own"
        );
        assert!(writer_carries(&space, &namespaces, &name), "{name}");
        assert!(
            !writer_carries(&space, &[], &name),
            "{name} crossed with no writer listed"
        );
        let held = held_name(&n("/alice/member/laptop"), &name);
        assert!(writer_carries(&space, &namespaces, &held), "{held}");
    }
    // A device of no namespace the members list, however it is named.
    for other in [
        "/dave/member/phone",
        "/bobby/member/phone",
        "/bob/member",
        "/bob/member/phone/nested",
        "/bob/stranger/phone",
        "/alicia/member/laptop",
    ] {
        let name = grant(other, &space);
        assert!(
            !folder_carries(&space, &name) && !writer_carries(&space, &namespaces, &name),
            "a grant ask to {other} crossed the space's link"
        );
    }
    // A listed writer's device is asked only for this space.
    let outside = grant("/bob/member/phone", &n("/alice/32=data/diary"));
    assert!(!writer_carries(&space, &namespaces, &outside));
}

#[test]
fn the_seal_keys_of_a_listed_writers_devices_are_added_and_no_others() {
    let space = space();
    let namespaces = namespaces();
    let seal = |device: &str| seal_key_name(&n(device), &[3; 32]);
    // `<W>/<role>/<device>/32=seal/<key>` of a listed namespace.
    for listed in ["/bob/member/phone", "/carol/admin/tablet"] {
        let name = seal(listed);
        assert!(writer_carries(&space, &namespaces, &name), "{name}");
        assert!(
            !writer_carries(&space, &[], &name),
            "{name} crossed with no writer listed"
        );
    }
    for other in [
        // A namespace the members do not list, and one a listed name merely starts.
        "/dave/member/phone",
        "/bobby/member/phone",
        // Not `<W>/<role>/<device>`: deeper or shallower.
        "/bob/member/phone/nested",
        "/bob/member",
        // A role the layout does not name.
        "/bob/stranger/phone",
        // The space's own namespace is `folder_carries`'s, not added again.
        "/alice/member/laptop",
    ] {
        let name = seal(other);
        assert!(
            !writer_carries(&space, &namespaces, &name),
            "the seal key {name} of a device the members do not list crossed"
        );
    }
}

#[test]
fn nothing_of_a_writer_outside_the_space_is_added() {
    let space = space();
    let namespaces = namespaces();
    let bob = n("/bob/member/phone");
    let diary = n("/bob/32=data/diary");
    for name in [
        // Her other space's entry, piece and run header.
        log_name(&bob, &diary, 3),
        piece_name(&log_name(&bob, &diary, 3), PieceKind::Chunk(0)),
        signal_run_name(&bob, &diary, &[1; RUN_ID_LEN]),
        // The sync group, and names of no layer.
        n("/bob/32=sync"),
        n("/bob/member/phone"),
    ] {
        assert!(
            !writer_carries(&space, &namespaces, &name),
            "{name} of a writer outside the space was added"
        );
    }
    // What is of the space is `folder_carries`'s whoever wrote it: not `writer_carries`'s
    // to add.
    let inside = log_name(&bob, &space, 3);
    assert!(folder_carries(&space, &inside));
    assert!(!writer_carries(&space, &namespaces, &inside));
    // A space that is no space name has no writers' names.
    assert!(!writer_carries(
        &n("/alice/notebook"),
        &namespaces,
        &seal_key_name(&bob, &[3; 32])
    ));
}

#[test]
fn a_held_copy_of_a_writers_key_is_carried_to_the_depth_folder_carries_unwraps() {
    let space = space();
    let holder = n("/alice/member/laptop");
    let namespaces = namespaces();
    let key = seal_key_name(&n("/carol/member/tablet"), &[3; 32]);
    let held = held_name(&holder, &key);
    assert!(writer_carries(&space, &namespaces, &held), "{held}");
    assert!(!folder_carries(&space, &held), "{held} was carried already");
    // Not for a writer the members do not list.
    assert!(!writer_carries(&space, &[n("/alice")], &held), "{held}");
    // An unlisted namespace's key, the owner's own, and nesting beyond the depth.
    let dave = held_name(&holder, &seal_key_name(&n("/dave/member/tablet"), &[3; 32]));
    assert!(!writer_carries(&space, &namespaces, &dave));
    let own = held_name(&holder, &seal_key_name(&n("/alice/member/phone"), &[3; 32]));
    assert!(!writer_carries(&space, &namespaces, &own));
    let twice = held_name(&holder, &held);
    assert!(writer_carries(&space, &namespaces, &twice));
    let deep = held_name(&holder, &twice);
    assert!(!writer_carries(&space, &namespaces, &deep), "{deep}");
}

#[test]
fn a_namespace_taken_out_of_the_list_is_out_and_only_the_namespace_itself_is_matched() {
    let space = space();
    let key = seal_key_name(&n("/carol/member/phone"), &[3; 32]);
    let with = [n("/alice"), n("/carol")];
    let without = [n("/alice")];
    assert!(writer_carries(&space, &with, &key));
    // The caller passes the namespaces of what the members in force list at the packet:
    // a removed writer is not in the list and her keys are not carried.
    assert!(!writer_carries(&space, &without, &key));
    // A namespace is matched whole: neither a longer one under the listed one, nor a
    // shorter one above it (a writer `/home/carol` does not unlock `/home`), nor one
    // that merely shares letters.
    assert!(!writer_carries(&space, &[n("/carol/member/phone")], &key));
    assert!(!writer_carries(&space, &[n("/car")], &key));
    let home = seal_key_name(&n("/home/member/phone"), &[3; 32]);
    assert!(!writer_carries(&space, &[n("/home/carol")], &home));
}

#[test]
fn the_departure_carries_the_entry_and_its_pieces_and_nothing_else() {
    let space = space();
    let signer = n("/alice/member/laptop");
    let record = log_name(&signer, &space, 7);
    let digest = |name: Name| name.append_implicit_digest([9; 32]);
    // The entry, by name and by digest; its pieces and manifest nodes.
    for name in [
        record.clone(),
        digest(record.clone()),
        piece_name(&record, PieceKind::Chunk(0)),
        digest(piece_name(&record, PieceKind::Chunk(3))),
        piece_name(&record, PieceKind::Manifest(2)),
    ] {
        assert!(departure_carries(&record, &name), "{name}");
        // The record named with a digest is the same record.
        assert!(departure_carries(&digest(record.clone()), &name), "{name}");
    }
    // Not the neighbours: another entry of the space, another seq, the pieces of an
    // entry of another space, a seal key, the sync group.
    let other_seq = log_name(&signer, &space, 8);
    for name in [
        other_seq.clone(),
        piece_name(&other_seq, PieceKind::Chunk(0)),
        log_name(&n("/alice/member/phone"), &space, 7),
        log_name(&signer, &n("/alice/32=data/diary"), 7),
        seal_key_name(&signer, &[7; 32]),
        record.clone().append("x"),
        n("/alice/32=sync"),
    ] {
        assert!(
            !departure_carries(&record, &name),
            "{name} crossed the departure link of {record}"
        );
    }
    // A record that names no log entry carries nothing.
    assert!(!departure_carries(&space, &record));
    assert!(!departure_carries(&n("/"), &record));
    let _ = Bytes::new();
}
