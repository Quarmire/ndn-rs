//! What a person admitted to one space may ask a device for by name (spec §13.2–§13.4,
//! ndn-link §8.7): the invitations' half of a grant link's name filter, as
//! [`Surface::carries`](crate::surface::Surface::carries) is for an introduction link.
//!
//! A grant admits a person to the *link*; the layer above answers by name to whoever
//! asks, and some of what it holds is not sealed (a public space, the members entries
//! themselves). So the link must carry only the names of **the space of the grant**:
//! its entries, their pieces, and the few names of the layer's own
//! that reach them (seal keys, grants, held copies). Everything else this device holds
//! by name (another space's entries, even one whose name extends this space's, the
//! introductions, the sync group, certificates) is not carried.
//!
//! The decision is a pure function of the two names, by the grammar of heap.md §2.3
//! (the parsers are `ndn_heap::wire`'s, not a copy of them): nothing is looked up and
//! nothing is cached.

use ndn_foundation_types::{Name, tlv_type};
use ndn_heap::wire::{
    is_namespace, parse_grant_name, parse_held_name, parse_log_name, parse_piece_name,
    parse_seal_key_name, parse_space_name,
};

/// How deep a held copy's name may nest another: a `<H>/32=held/<Name>` whose inner
/// name is itself one is judged to this depth.
const HELD_DEPTH: u8 = 2;

/// The roles of the namespace layout (`/<ns>/<role>/<device>`): the device roles every
/// namespace's certificate authority issues (`ndn_cert::Role`).
const LAYOUT_ROLES: [&[u8]; 4] = [b"admin", b"member", b"node", b"guest"];

/// Whether a packet named `name` may cross the link of a person admitted to `space`
/// (`<O>/32=data/<path>`): an Interest for it, and the Data that answers it. `false`
/// for a `space` that is no space name, so a grant for no space carries nothing.
///
/// Carried (with or without a trailing implicit digest):
/// - a log entry `<D>/32=log/<space>/seq=<n>` **of this space**, whatever device wrote
///   it, and a piece or manifest node of such an entry; never an entry of another space,
///   even one whose name extends this space's;
/// - a seal key of a device of the space's own owner namespace
///   (`<O>/<role>/<device>/32=seal/<public key>`) and a grant ask of this space **to a
///   device of the owner's namespace** (the epoch's creator, or another owner device
///   that holds the key);
/// - a held copy (`<H>/32=held/<name>`) about a name carried by these rules.
///
/// Not carried: the sync group, certificates and the trust context (the host's link
/// layer adds those: they are the namespaces', not the space's), introductions (the
/// surface's), anything that is not a name of this layer.
pub fn folder_carries(space: &Name, name: &Name) -> bool {
    parse_space_name(space).is_some() && carries(space, name, HELD_DEPTH)
}

/// Whether a packet named `name` may also cross the grant link of a person admitted to
/// `space` because a **co-writer** of the space is listed (spec §13.3): the **seal
/// keys** (`<W>/<role>/<device>/32=seal/<key>`) of the devices of each namespace `W` in
/// `namespaces` (the persons the members list as writers), so that a writer can ask the
/// other's device for the epoch key, and the **grant asks** (`<G>/32=grant/<GrantAsk>`)
/// of this space to a device `G` of each listed `W`, which holds the key of an epoch it
/// reads in too. Nothing else: every entry and piece of the space,
/// whatever device wrote it, is [`folder_carries`]'s already, and nothing of a writer's
/// outside the space is added. `false` for a `space` that is no space name.
///
/// The caller derives `namespaces` from the members in force (`Surface::writer_namespaces`),
/// so a writer the members no longer list drops out at the next packet. A namespace is
/// matched **whole**: a writer `/home/carol` unlocks the devices of `/home/carol`,
/// never those of the broader `/home`.
///
/// A **held** copy about a name these rules carry is carried, to the depth
/// [`folder_carries`] unwraps held names to.
pub fn writer_carries(space: &Name, namespaces: &[Name], name: &Name) -> bool {
    parse_space_name(space).is_some() && writer_names(space, namespaces, name, HELD_DEPTH)
}

fn writer_names(space: &Name, namespaces: &[Name], name: &Name, held_depth: u8) -> bool {
    let name = &undigested(name);
    let owner = parse_space_name(space).map(|parsed| parsed.owner);
    let listed = |device: &Name| {
        namespaces
            .iter()
            .any(|ns| owner.as_ref() != Some(ns) && device_of_namespace(device, ns))
    };
    if let Some((_, inner)) = parse_held_name(name) {
        return held_depth > 0 && writer_names(space, namespaces, &inner, held_depth - 1);
    }
    if let Some((granter, ask)) = parse_grant_name(name) {
        // A grant ask to a device of a listed writer's namespace, for this space: the
        // owner's forwarder relays it only to a device the members list, never to any
        // device a member names.
        return ask.space == *space && listed(&granter);
    }
    // The seal key `<W>/<role>/<device>/32=seal/<key>` of a device of a listed writer's
    // namespace: the key a signer is asked for (ndn-link §8.7 rule 20).
    parse_seal_key_name(name).is_some_and(|(device, _)| listed(&device))
}

/// Whether a packet named `name` may cross the **departure link** of a person let go by
/// the members entry whose log name is `record` (spec §13.4, ndn-link §8.8): the entry
/// itself, its pieces (`<record>/32=piece/seg=<i>`, `<record>/32=piece/32=manifest/seg=<k>`),
/// each with or without an implicit digest, and nothing else: not another entry of the
/// space, not the record's neighbours. `false` when `record` names no log entry of a
/// space.
pub fn departure_carries(record: &Name, name: &Name) -> bool {
    let record = undigested(record);
    if parse_log_name(&record).is_none() {
        return false;
    }
    let name = undigested(name);
    name == record || parse_piece_name(&name).is_some_and(|piece| piece.entry == record)
}

/// Whether `device` is a device name of `namespace`: `<W>/<role>/<device>`, exactly two
/// components below the namespace, the first a generic component that names a role of
/// the layout (ndn-link §8.7 rule 20), never one under another namespace that merely
/// starts like it.
fn device_of_namespace(device: &Name, namespace: &Name) -> bool {
    is_namespace(namespace)
        && device.len() == namespace.len() + 2
        && device.has_prefix(namespace)
        && device
            .components()
            .get(namespace.len())
            .is_some_and(|role| {
                role.typ == tlv_type::GENERIC_NAME_COMPONENT
                    && LAYOUT_ROLES.contains(&role.value.as_ref())
            })
}

/// `name` without a trailing implicit digest (an Interest may name the packet it wants
/// whole).
fn undigested(name: &Name) -> Name {
    match name.components().split_last() {
        Some((last, rest)) if last.typ == tlv_type::IMPLICIT_SHA256 => {
            Name::from_components(rest.iter().cloned())
        }
        _ => name.clone(),
    }
}

fn carries(space: &Name, name: &Name, held_depth: u8) -> bool {
    let name = &undigested(name);
    if let Some(log) = parse_log_name(name) {
        return log.space == *space;
    }
    if let Some(piece) = parse_piece_name(name) {
        return piece.log.space == *space;
    }
    let owner = parse_space_name(space).map(|parsed| parsed.owner);
    if let Some((device, _)) = parse_seal_key_name(name) {
        return owner.is_some_and(|own| device_of_namespace(&device, &own));
    }
    if let Some((granter, ask)) = parse_grant_name(name) {
        // Only to a device of the space's own namespace: the epoch's creator or another
        // owner device. A listed writer's device is `writer_carries`'s; no other device
        // holds a key of this space.
        return ask.space == *space && owner.is_some_and(|own| device_of_namespace(&granter, &own));
    }
    if let Some((_, inner)) = parse_held_name(name) {
        return held_depth > 0 && carries(space, &inner, held_depth - 1);
    }
    false
}
