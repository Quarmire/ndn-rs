//! What a person admitted to one folder may ask a device for by name (spec
//! §19.8, ndn-link §8.7): the data layer's half of a grant link's name
//! filter, as [`IntroductionSurface::carries`](crate::IntroductionSurface::carries)
//! is for an introduction link.
//!
//! A grant admits a person to the *link*; the layer above answers by name to
//! whoever asks, and some of what it holds is not sealed (a collection whose
//! members record names no readers, the members records and summaries
//! themselves). So the link must carry only the names of the folder: the
//! entries, pieces, summaries, heads and keys of **collections under the
//! folder**, and the few names of the layer's own that reach them. Everything
//! else this device holds by name — another folder's collections, a snapshot,
//! the log of its other namespaces' data, answers — is not carried.
//!
//! The decision is a pure function of the two names, by the grammar of spec
//! §16.1: nothing is looked up and nothing is cached, so a collection created
//! under the folder later is carried from its first entry on, and one outside
//! it never is.
//!
//! What the person can therefore still read is what the layer publishes about
//! the way *to* the folder, and it is public by the layer's model: a writer's
//! summary tree is walked from its root, so the nodes of the namespace and of
//! each folder on the path (`<O>`, `<O>/32=data`, `<O>/32=data/<a>`, …) cross
//! the link, and they list the next component of every collection beside the
//! folder with its head and digest — names and counts, never a payload — and
//! the root and nodes of a namespace are signed to be read by anyone who can
//! ask. No entry, chunk, head or key of a collection outside the folder
//! crosses.

use ndn_packet::Name;
use ndn_packet::tlv_type::IMPLICIT_SHA256;

use crate::wire::{
    LAYOUT_ROLES, is_data_name, is_kw, is_namespace, log_name, namespace_of, parse_audit_ask_name,
    parse_cut_bytes_name, parse_grant_name, parse_head_name, parse_head_prefix, parse_held_name,
    parse_hold_ask_name, parse_log_name, parse_piece_name, parse_seal_key_name,
    parse_signal_run_name, parse_summary_name,
};

/// How deep a held packet's name may nest another: a `<H>/32=held/<Name>`
/// whose inner name is itself one is judged to this depth.
const HELD_DEPTH: u8 = 2;

/// Whether a packet named `name` may cross the link of a person admitted to
/// `folder` (`<O>/32=data[/<path>]`): an Interest for it, and the Data that
/// answers it. `false` for a `folder` that is no folder name, so a grant for
/// no folder carries nothing.
///
/// Carried:
/// - a log entry, a piece of a large version (chunk, manifest node), a cut
///   manifest node, a one-key head, of a collection **under** `folder`;
///   never a snapshot (`<D>/32=log/seq=<n>`, no collection);
/// - a summary root of `folder`'s namespace and a summary node or page of
///   `folder`, of a collection under it, or **on the way** to it (an
///   ancestor: the walk from the root passes through them);
/// - a signal run header of a scope under `folder`;
/// - a seal key of a device of the folder's own namespace
///   (`<W>/<role>/<device>/32=seal/<public key>`: a public key, named by the
///   device that holds it; a device of another namespace is a listed writer's,
///   [`writer_carries`]'s while the record lists her) and a folder epoch's grant
///   of a collection under `folder`;
/// - a custody ask (hold, audit) and a held packet (`<H>/32=held/<name>`)
///   about a name carried by these rules.
///
/// Not carried: the sync group, certificates and the trust context (the
/// host's link layer adds those: they are the namespaces', not the folder's),
/// introductions (the introduction surface's), answers and questions
/// (answers.md), anything that is not a name of this layer.
pub fn folder_carries(folder: &Name, name: &Name) -> bool {
    is_data_name(folder) && carries(folder, name, HELD_DEPTH)
}

/// Whether a packet named `name` may also cross the grant link of a person
/// admitted to `folder` because a **co-writer** of the folder is listed
/// (spec §19.8, ndn-link §8.7): the **summary root** (`<D>/32=summary/<W>/32=root`,
/// with or without its head) of each namespace `W` in `namespaces` — the
/// namespaces of the writer prefixes the folder's members record in force
/// lists — so that a writer who never met another walks to the other's devices
/// through this device's copy; and the **seal keys**
/// (`<W>/<role>/<device>/32=seal/<key>`) of the devices of each listed `W`, so
/// that a writer can ask the other's device (ndn-link §8.7 rule 20). Nothing
/// else: a root's nodes and pages of the folder, and every entry, piece, head
/// and cut manifest of a collection under the folder, whatever device wrote
/// it, are [`folder_carries`]'s already;
/// nothing of a writer's outside the folder is added (not an entry of her other
/// collections, not a node of her other folders), and the folder's own
/// namespace's root is [`folder_carries`]'s, not added again. `false` for a
/// `folder` that is no folder name.
///
/// The caller derives `namespaces` from the record, as the device does for a
/// writer prefix `p` (`IntroductionSurface::writer_namespaces`): the namespace
/// of the trust context governing `p` where one is held, `p` itself otherwise.
/// A name is a root of `W` only when its subject **is** one of them — never
/// when a writer's name merely starts with the subject: a writer
/// `/home/carol/member/x` does not unlock the root of the broader `/home`. A
/// pure function of its arguments: the caller passes the namespaces of the
/// writers the record in force lists **at the packet**, so a writer removed from
/// the record drops out at the next one; a prefix only a cut keeps is not a
/// writer and is not passed.
///
/// A **held** packet (`<H>/32=held/<name>`, how a device asks another that
/// answers for a writer for that writer's root) is carried when the name it
/// wraps is, to the depth [`folder_carries`] unwraps to.
pub fn writer_carries(folder: &Name, namespaces: &[Name], name: &Name) -> bool {
    is_data_name(folder) && writer_root(folder, namespaces, name, HELD_DEPTH)
}

fn writer_root(folder: &Name, namespaces: &[Name], name: &Name, held_depth: u8) -> bool {
    let name = &undigested(name);
    if let Some((_, inner)) = parse_held_name(name) {
        return held_depth > 0 && writer_root(folder, namespaces, &inner, held_depth - 1);
    }
    let Some(summary) = parse_summary_name(name) else {
        // The seal key `<W>/<role>/<device>/32=seal/<key>` of a device of a listed
        // writer's namespace: the key a signer is asked for (ndn-link §8.7 rule 20).
        return parse_seal_key_name(name).is_some_and(|(device, _)| {
            namespaces.iter().any(|ns| {
                namespace_of(folder).as_ref() != Some(ns) && device_of_namespace(&device, ns)
            })
        });
    };
    // A root's subject is a namespace; a node's or page's is a data name.
    let ns = &summary.subject;
    is_namespace(ns) && namespace_of(folder).as_ref() != Some(ns) && namespaces.contains(ns)
}

/// Whether `device` is a device name of `namespace`: `<W>/<role>/<device>`,
/// exactly two components below the namespace, the first a generic component
/// that names a role of the layout (ndn-link §8.7 rule 20), never one under
/// another namespace that merely starts like it.
fn device_of_namespace(device: &Name, namespace: &Name) -> bool {
    device.len() == namespace.len() + 2
        && device.has_prefix(namespace)
        && device
            .components()
            .get(namespace.len())
            .is_some_and(|role| {
                role.typ == ndn_packet::tlv_type::NAME_COMPONENT
                    && LAYOUT_ROLES.contains(&role.value.as_ref())
            })
}

/// Whether a packet named `name` is traffic of the **sync group** of a listed
/// writer's namespace — `<W>/32=sync[/…]`, the group in which the namespace's
/// devices say they wrote (§12) — that a grant link of a person admitted to
/// `folder` may carry, both ways, so a writer invited by an invitation of its
/// own hears the other writers' devices and can walk to them (spec §19.8,
/// ndn-link §8.7). `W` is a namespace in `namespaces`, derived from the
/// writers as for [`writer_carries`] (equal to it, not merely a prefix of a
/// writer's name); the folder's own namespace's group is the host's, not added
/// here, and nothing under any other namespace is. A pure function of its
/// arguments, derived per packet from the record in force like
/// [`writer_carries`]. `false` for a `folder` that is no folder name.
pub fn writer_sync(folder: &Name, namespaces: &[Name], name: &Name) -> bool {
    if !is_data_name(folder) {
        return false;
    }
    let comps = name.components();
    let Some(at) = comps.iter().position(|c| is_kw(c, b"sync")) else {
        return false;
    };
    let ns = Name::from_components(comps[..at].iter().cloned());
    is_namespace(&ns) && namespace_of(folder).as_ref() != Some(&ns) && namespaces.contains(&ns)
}

/// Whether a packet named `name` may cross the **departure link** of a person
/// let go by the members record whose log entry is `record` (spec §19.8,
/// ndn-link §8.8): the record's entry, its pieces (`<record>/seg=<i>`,
/// `<record>/32=manifest/seg=<k>`) and its cut manifests
/// (`<record>/32=cut/seg=<i>`), each with or without an implicit digest — and
/// nothing else: not another entry of the folder, not a summary, not the
/// record's neighbours. `false` when `record` names no log entry of a
/// collection or folder.
pub fn departure_carries(record: &Name, name: &Name) -> bool {
    let record = undigested(record);
    if parse_log_name(&record).and_then(|l| l.subject).is_none() {
        return false;
    }
    let name = undigested(name);
    if name == record {
        return true;
    }
    if let Some(piece) = parse_piece_name(&name) {
        return piece.version == record;
    }
    parse_cut_bytes_name(&name)
        .is_some_and(|cut| log_name(&cut.device, cut.subject.as_ref(), cut.seq) == record)
}

fn within(folder: &Name, subject: &Name) -> bool {
    subject.has_prefix(folder)
}

/// `name` without a trailing implicit digest (an Interest may name the
/// packet it wants whole).
fn undigested(name: &Name) -> Name {
    match name.components().split_last() {
        Some((last, rest)) if last.typ == IMPLICIT_SHA256 => {
            Name::from_components(rest.iter().cloned())
        }
        _ => name.clone(),
    }
}

fn carries(folder: &Name, name: &Name, held_depth: u8) -> bool {
    let name = &undigested(name);
    if let Some(log) = parse_log_name(name) {
        return log.subject.as_ref().is_some_and(|c| within(folder, c));
    }
    if let Some(piece) = parse_piece_name(name) {
        return piece
            .log
            .subject
            .as_ref()
            .is_some_and(|c| within(folder, c));
    }
    if let Some(record) = parse_cut_bytes_name(name) {
        return record.subject.as_ref().is_some_and(|c| within(folder, c));
    }
    if let Some((_, collection, _)) = parse_head_name(name) {
        return within(folder, &collection);
    }
    if let Some((_, collection)) = parse_head_prefix(name) {
        return within(folder, &collection);
    }
    if let Some(summary) = parse_summary_name(name) {
        let subject = &summary.subject;
        return if is_namespace(subject) {
            namespace_of(folder).as_ref() == Some(subject)
        } else {
            // The folder's own nodes and everything under it, and the nodes
            // of the walk down to it.
            within(folder, subject) || folder.has_prefix(subject)
        };
    }
    if let Some(run) = parse_signal_run_name(name) {
        return within(folder, &run.scope);
    }
    if let Some((device, _)) = parse_seal_key_name(name) {
        return namespace_of(folder).is_some_and(|own| device_of_namespace(&device, &own));
    }
    if let Some((_, ask)) = parse_grant_name(name) {
        return within(folder, &ask.collection);
    }
    if let Some((_, ask)) = parse_hold_ask_name(name) {
        return parse_log_name(&ask.record)
            .and_then(|l| l.subject)
            .is_some_and(|c| within(folder, &c));
    }
    if let Some((_, ask)) = parse_audit_ask_name(name) {
        return held_depth > 0 && carries(folder, &ask.piece, held_depth - 1);
    }
    if let Some((_, inner)) = parse_held_name(name) {
        return held_depth > 0 && carries(folder, &inner, held_depth - 1);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{
        PieceKind, RUN_ID_LEN, data_folder, head_name, head_prefix, log_name, node_name, page_name,
        piece_name, root_name, root_prefix, signal_run_name,
    };

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn folder() -> Name {
        n("/alice/32=data/notebook")
    }

    /// The device `/alice/laptop/a` and a writer of another namespace.
    fn devices() -> [Name; 2] {
        [n("/alice/member/laptop"), n("/bob/member/phone")]
    }

    #[test]
    fn the_folders_collections_cross_and_no_other_collection_does() {
        let folder = folder();
        for device in devices() {
            // A collection under the folder, the folder's own record, a
            // collection created under it later.
            for inside in [
                n("/alice/32=data/notebook"),
                n("/alice/32=data/notebook/chapter"),
                n("/alice/32=data/notebook/a/b/c"),
            ] {
                let entry = log_name(&device, Some(&inside), 3);
                assert!(folder_carries(&folder, &entry), "{entry}");
                // Its pieces and the Interest that names the digest too.
                let piece = piece_name(&entry, PieceKind::Chunk(1));
                assert!(folder_carries(&folder, &piece), "{piece}");
                let manifest = piece_name(&entry, PieceKind::Manifest(0));
                assert!(folder_carries(&folder, &manifest), "{manifest}");
                assert!(
                    folder_carries(&folder, &entry.clone().append_implicit_digest([9; 32])),
                    "{entry} by digest"
                );
                assert!(folder_carries(&folder, &head_name(&device, &inside, 5)));
                assert!(folder_carries(&folder, &head_prefix(&device, &inside)));
            }
            // A sibling, a prefix of it, the namespace's other folder, a
            // folder whose name merely starts like this one, another
            // namespace's collection of the same path.
            for outside in [
                n("/alice/32=data/diary"),
                n("/alice/32=data/notebook2"),
                n("/alice/32=data/note"),
                n("/alice/32=data/other/notebook"),
                n("/bob/32=data/notebook"),
            ] {
                let entry = log_name(&device, Some(&outside), 3);
                assert!(
                    !folder_carries(&folder, &entry),
                    "an entry of {outside} crossed the link of {folder}"
                );
                assert!(!folder_carries(
                    &folder,
                    &piece_name(&entry, PieceKind::Chunk(1))
                ));
                assert!(!folder_carries(&folder, &head_name(&device, &outside, 5)));
                assert!(!folder_carries(&folder, &head_prefix(&device, &outside)));
                assert!(!folder_carries(&folder, &node_name(&device, &outside, 5)));
            }
            // A snapshot names no collection.
            assert!(!folder_carries(&folder, &log_name(&device, None, 3)));
        }
    }

    #[test]
    fn the_walk_to_the_folder_crosses_and_the_walk_to_another_does_not() {
        let folder = folder();
        let device = n("/alice/member/laptop");
        let ns = n("/alice");
        // The root of the folder's namespace and the nodes on the way down.
        assert!(folder_carries(&folder, &root_prefix(&device, &ns)));
        assert!(folder_carries(&folder, &root_name(&device, &ns, 4)));
        assert!(folder_carries(
            &folder,
            &node_name(&device, &data_folder(&ns), 4)
        ));
        assert!(folder_carries(&folder, &node_name(&device, &folder, 4)));
        assert!(folder_carries(
            &folder,
            &page_name(&device, &folder, &[1, 2], 4)
        ));
        assert!(folder_carries(
            &folder,
            &node_name(&device, &n("/alice/32=data/notebook/ch"), 4)
        ));
        // Another namespace's root, another folder's nodes and pages.
        assert!(!folder_carries(&folder, &root_prefix(&device, &n("/bob"))));
        assert!(!folder_carries(&folder, &root_name(&device, &n("/bob"), 4)));
        assert!(!folder_carries(
            &folder,
            &node_name(&device, &n("/alice/32=data/diary"), 4)
        ));
        assert!(!folder_carries(
            &folder,
            &page_name(&device, &n("/alice/32=data/diary"), &[1], 4)
        ));
    }

    #[test]
    fn custody_and_epoch_grants_are_judged_by_the_name_they_are_about() {
        use crate::collection::Epoch;
        use crate::version::Seq;
        use crate::wire::{
            AuditAsk, GrantAsk, HoldAsk, NONCE_LEN, audit_ask_name, grant_name, held_name,
            hold_ask_name,
        };
        let folder = folder();
        let holder = n("/alice/member/laptop");
        let writer = n("/bob/member/phone");
        let inside = log_name(&writer, Some(&n("/alice/32=data/notebook/ch")), 4);
        let outside = log_name(&writer, Some(&n("/alice/32=data/diary")), 4);

        // A held packet is the one it names: carried when that is.
        assert!(folder_carries(&folder, &held_name(&holder, &inside)));
        assert!(!folder_carries(&folder, &held_name(&holder, &outside)));
        assert!(!folder_carries(
            &folder,
            &held_name(&holder, &log_name(&writer, None, 4))
        ));
        // One that names another held packet does not hide it.
        let nested = held_name(&holder, &held_name(&holder, &outside));
        assert!(!folder_carries(&folder, &nested));

        // A hold ask and an audit ask, by the record or piece they concern.
        let hold = |record: &Name| {
            hold_ask_name(
                &holder,
                &HoldAsk {
                    record: record.clone(),
                    nonce: [1; NONCE_LEN],
                    asker: bytes::Bytes::from_static(b"proof"),
                },
            )
        };
        assert!(folder_carries(&folder, &hold(&inside)));
        assert!(!folder_carries(&folder, &hold(&outside)));
        let audit = |piece: &Name| {
            audit_ask_name(
                &holder,
                &AuditAsk {
                    nonce: [1; NONCE_LEN],
                    piece: piece.clone(),
                    whole: false,
                    asker: bytes::Bytes::from_static(b"proof"),
                },
            )
        };
        assert!(folder_carries(&folder, &audit(&inside)));
        assert!(!folder_carries(&folder, &audit(&outside)));

        // An epoch's grant, by the collection or folder whose key it is.
        let grant = |collection: &Name| {
            grant_name(
                &holder,
                &GrantAsk {
                    seal_key: crate::wire::seal_key_name(&writer, &[3; 32]),
                    collection: collection.clone(),
                    epoch: Epoch {
                        creator: holder.clone(),
                        seq: Seq(2),
                    },
                },
            )
        };
        assert!(folder_carries(&folder, &grant(&folder)));
        assert!(folder_carries(
            &folder,
            &grant(&n("/alice/32=data/notebook/ch"))
        ));
        assert!(!folder_carries(&folder, &grant(&n("/alice/32=data/diary"))));
    }

    #[test]
    fn seals_cross_and_what_is_not_the_layers_does_not() {
        let folder = folder();
        let device = n("/alice/member/laptop");
        assert!(folder_carries(
            &folder,
            &crate::wire::seal_key_name(&device, &[7; 32])
        ));
        // A seal key of a device of any other namespace (a stranger's, or a
        // writer's, whom `writer_carries` adds only while the record lists her)
        // does not cross a link of this folder, whatever the key; nor does a name
        // whose device is not `<W>/<role>/<device>`.
        for other in [
            n("/carol/member/laptop"),
            n("/bob/member/phone"),
            n("/alicia/member/laptop"),
            n("/alice/member/laptop/nested"),
            n("/alice/member"),
            n("/alice/stranger/laptop"),
        ] {
            let seal = crate::wire::seal_key_name(&other, &[7; 32]);
            assert!(
                !folder_carries(&folder, &seal),
                "the seal key {seal} of a device outside the folder's namespace crossed the \
                 folder's link"
            );
        }
        let run = signal_run_name(&device, &folder, &[1; RUN_ID_LEN]);
        assert!(folder_carries(&folder, &run));
        let other = signal_run_name(&device, &n("/alice/32=data/diary"), &[1; RUN_ID_LEN]);
        assert!(!folder_carries(&folder, &other));
        // Names that are no name of this layer, or no folder's.
        assert!(!folder_carries(&folder, &n("/alice/member/laptop")));
        assert!(!folder_carries(&folder, &n("/alice/32=sync")));
        assert!(!folder_carries(&folder, &n("/alice/member/laptop/KEY/1")));
        assert!(!folder_carries(&folder, &n("/")));
        // A grant for no folder carries nothing.
        let entry = log_name(&device, Some(&n("/alice/32=data/notebook")), 1);
        assert!(!folder_carries(&n("/alice/notebook"), &entry));
    }

    /// The namespaces of the writers a record lists: Alice's own, Bob's, and
    /// Carol's (listed by a device's name, her namespace is the person's).
    fn namespaces() -> Vec<Name> {
        vec![n("/alice"), n("/bob"), n("/carol")]
    }

    #[test]
    fn the_root_of_each_listed_writers_namespace_is_added_and_nothing_else_of_theirs() {
        use crate::wire::{root_name, root_prefix};
        let folder = folder();
        let device = n("/alice/member/laptop");
        let namespaces = namespaces();
        // Bob's root, with and without its head and with the digest an Interest
        // may name; Carol's likewise.
        for ns in [n("/bob"), n("/carol")] {
            for name in [
                root_prefix(&device, &ns),
                root_name(&device, &ns, 4),
                root_name(&device, &ns, 4).append_implicit_digest([5; 32]),
            ] {
                assert!(writer_carries(&folder, &namespaces, &name), "{name}");
                // Not a thing `folder_carries` carries: the addition is the root's alone.
                assert!(
                    !folder_carries(&folder, &name),
                    "{name} was carried already"
                );
            }
        }
        // The folder's own namespace is `folder_carries`'s, not added again.
        assert!(!writer_carries(
            &folder,
            &namespaces,
            &root_name(&device, &n("/alice"), 4)
        ));
        // A namespace nobody lists.
        assert!(!writer_carries(
            &folder,
            &namespaces,
            &root_name(&device, &n("/dave"), 4)
        ));
        assert!(!writer_carries(
            &folder,
            &[],
            &root_name(&device, &n("/bob"), 4)
        ));
    }

    #[test]
    fn nothing_of_a_writer_outside_the_folder_is_added() {
        use crate::wire::{node_name, page_name, root_name};
        let folder = folder();
        let device = n("/alice/member/laptop");
        let namespaces = namespaces();
        let bob = n("/bob/member/phone");
        for name in [
            // Her other collection's entry, piece, head and node; her other folder's page.
            log_name(&bob, Some(&n("/bob/32=data/diary")), 3),
            piece_name(
                &log_name(&bob, Some(&n("/bob/32=data/diary")), 3),
                PieceKind::Chunk(0),
            ),
            head_name(&bob, &n("/bob/32=data/diary"), 3),
            node_name(&device, &n("/bob/32=data/diary"), 4),
            page_name(&device, &n("/bob/32=data/diary"), &[1], 4),
            node_name(&device, &data_folder(&n("/bob")), 4),
            // A snapshot, the sync group, and names of no layer.
            log_name(&bob, None, 3),
            n("/bob/32=sync"),
            n("/bob/member/phone"),
        ] {
            assert!(
                !writer_carries(&folder, &namespaces, &name),
                "{name} of a writer outside the folder was added"
            );
        }
        // What is under the folder is `folder_carries`'s whoever wrote it: not
        // `writer_carries`'s to add.
        let inside = log_name(&bob, Some(&n("/alice/32=data/notebook/ch")), 3);
        assert!(folder_carries(&folder, &inside));
        assert!(!writer_carries(&folder, &namespaces, &inside));
        // A folder that is no folder name has no writers' roots.
        assert!(!writer_carries(
            &n("/alice/notebook"),
            &namespaces,
            &root_name(&device, &n("/bob"), 4)
        ));
    }

    #[test]
    fn the_seal_keys_of_a_listed_writers_devices_are_added_and_no_others() {
        let folder = folder();
        let namespaces = namespaces();
        let seal = |device: &str| crate::wire::seal_key_name(&n(device), &[3; 32]);
        // `<W>/<role>/<device>/32=seal/<key>` of a listed namespace.
        for listed in ["/bob/member/phone", "/carol/admin/tablet"] {
            let name = seal(listed);
            assert!(writer_carries(&folder, &namespaces, &name), "{name}");
            assert!(
                !writer_carries(&folder, &[], &name),
                "{name} crossed with no writer listed"
            );
        }
        for other in [
            // A namespace the record does not list, and one a listed name merely starts.
            "/dave/member/phone",
            "/bobby/member/phone",
            // Not `<W>/<role>/<device>`: deeper or shallower.
            "/bob/member/phone/nested",
            "/bob/member",
            // A role the layout does not name.
            "/bob/stranger/phone",
            // The folder's own namespace is `folder_carries`'s, not added again.
            "/alice/member/laptop",
        ] {
            let name = seal(other);
            assert!(
                !writer_carries(&folder, &namespaces, &name),
                "the seal key {name} of a device the record does not list crossed"
            );
        }
    }

    #[test]
    fn a_held_root_is_carried_when_the_root_it_wraps_is() {
        use crate::wire::{held_name, log_name, root_name, root_prefix};
        let folder = folder();
        let holder = n("/alice/member/laptop");
        let carol = n("/carol/member/tablet");
        let namespaces = namespaces();
        // How a walk asks the device that answers for Carol: the holder's `32=held`
        // wrapping her root, by prefix or by name, with or without a digest.
        for wrapped in [
            root_prefix(&carol, &n("/bob")),
            root_name(&carol, &n("/bob"), 4),
            root_name(&carol, &n("/carol"), 4).append_implicit_digest([5; 32]),
        ] {
            let held = held_name(&holder, &wrapped);
            assert!(writer_carries(&folder, &namespaces, &held), "{held}");
            assert!(
                !folder_carries(&folder, &held),
                "{held} was carried already"
            );
            // Not for a writer the record does not list.
            assert!(!writer_carries(&folder, &[n("/alice")], &held), "{held}");
        }
        // An unlisted namespace's root, one outside the folder, the folder's own
        // namespace, and nesting beyond the depth `folder_carries` allows.
        let dave = held_name(&holder, &root_name(&carol, &n("/dave"), 4));
        assert!(!writer_carries(&folder, &namespaces, &dave));
        let entry = log_name(&carol, Some(&n("/carol/32=data/diary")), 3);
        assert!(!writer_carries(
            &folder,
            &namespaces,
            &held_name(&holder, &entry)
        ));
        let own = held_name(&holder, &root_name(&carol, &n("/alice"), 4));
        assert!(!writer_carries(&folder, &namespaces, &own));
        let root = root_name(&carol, &n("/bob"), 4);
        let deep = held_name(&holder, &held_name(&holder, &held_name(&holder, &root)));
        assert!(!writer_carries(&folder, &namespaces, &deep), "{deep}");
        let twice = held_name(&holder, &held_name(&holder, &root));
        assert!(writer_carries(&folder, &namespaces, &twice));
    }

    #[test]
    fn the_sync_group_of_each_listed_writers_namespace_is_added_and_no_other() {
        let folder = folder();
        let namespaces = namespaces();
        // Bob's and Carol's groups, bare and with a notice.
        for group in [n("/bob/32=sync"), n("/carol/32=sync")] {
            for name in [group.clone(), group.clone().append("vector")] {
                assert!(writer_sync(&folder, &namespaces, &name), "{name}");
                assert!(
                    !folder_carries(&folder, &name),
                    "{name} was carried already"
                );
            }
        }
        // The folder's own namespace's group is the host's; an unlisted one, a removed
        // writer's, and a name that is no group are refused.
        assert!(!writer_sync(
            &folder,
            &namespaces,
            &n("/alice/32=sync/vector")
        ));
        assert!(!writer_sync(
            &folder,
            &namespaces,
            &n("/dave/32=sync/vector")
        ));
        assert!(!writer_sync(
            &folder,
            &[n("/alice")],
            &n("/carol/32=sync/vector")
        ));
        assert!(!writer_sync(&folder, &namespaces, &n("/bob/notes")));
        assert!(!writer_sync(
            &folder,
            &namespaces,
            &n("/bob/member/phone/32=sync")
        ));
        assert!(!writer_sync(&folder, &namespaces, &n("/32=sync")));
        // A folder that is no folder name has no writers' groups.
        assert!(!writer_sync(
            &n("/alice/notebook"),
            &namespaces,
            &n("/bob/32=sync")
        ));
    }

    #[test]
    fn a_namespace_taken_out_of_the_list_is_out_and_only_the_namespace_itself_is_matched() {
        use crate::wire::root_name;
        let folder = folder();
        let device = n("/alice/member/laptop");
        let root = root_name(&device, &n("/carol"), 4);
        let with = [n("/alice"), n("/carol")];
        let without = [n("/alice")];
        assert!(writer_carries(&folder, &with, &root));
        // The caller passes the namespaces of what the record in force lists at the
        // packet: a removed writer, only a cut now, is not in the list and her root is
        // not carried.
        assert!(!writer_carries(&folder, &without, &root));
        // A namespace is matched whole: neither a longer one under the listed one, nor
        // a shorter one above it (a writer `/home/carol/member/x` whose namespace is its
        // own prefix does not unlock `/home`), nor one that merely shares letters.
        assert!(!writer_carries(
            &folder,
            &[n("/carol")],
            &root_name(&device, &n("/carol/member/phone"), 4)
        ));
        assert!(!writer_carries(&folder, &[n("/carol/member/phone")], &root));
        assert!(!writer_sync(
            &folder,
            &[n("/carol/member/phone")],
            &n("/carol/32=sync/vector")
        ));
        assert!(!writer_carries(
            &folder,
            &[n("/car")],
            &root_name(&device, &n("/carol"), 4)
        ));
    }

    #[test]
    fn the_departure_carries_the_record_its_pieces_and_its_cut_and_nothing_else() {
        use crate::wire::cut_bytes_prefix;
        let folder = folder();
        let signer = n("/alice/member/laptop");
        let record = log_name(&signer, Some(&folder), 7);
        let digest = |name: Name| name.append_implicit_digest([9; 32]);
        // The entry, by name and by digest; its pieces; its cut manifests.
        for name in [
            record.clone(),
            digest(record.clone()),
            piece_name(&record, PieceKind::Chunk(0)),
            digest(piece_name(&record, PieceKind::Chunk(3))),
            piece_name(&record, PieceKind::Manifest(2)),
            cut_bytes_prefix(&record).append_segment(0),
            digest(cut_bytes_prefix(&record).append_segment(4)),
        ] {
            assert!(departure_carries(&record, &name), "{name}");
            // The record named with a digest is the same record.
            assert!(departure_carries(&digest(record.clone()), &name), "{name}");
        }
        // Not the neighbours: another entry of the folder, another seq, the
        // record's cut under another record, the pieces of an entry of another
        // collection, a summary, a head, the sync group, the cut's prefix itself.
        let other_seq = log_name(&signer, Some(&folder), 8);
        for name in [
            other_seq.clone(),
            piece_name(&other_seq, PieceKind::Chunk(0)),
            cut_bytes_prefix(&other_seq).append_segment(0),
            log_name(&n("/alice/member/phone"), Some(&folder), 7),
            log_name(&signer, Some(&n("/alice/32=data/diary")), 7),
            log_name(&signer, None, 7),
            head_name(&signer, &folder, 7),
            crate::wire::node_name(&signer, &folder, 4),
            crate::wire::root_name(&signer, &n("/alice"), 4),
            cut_bytes_prefix(&record),
            record.clone().append("x"),
            n("/alice/32=sync"),
        ] {
            assert!(
                !departure_carries(&record, &name),
                "{name} crossed the departure link of {record}"
            );
        }
        // A record that names no log entry of a collection carries nothing.
        assert!(!departure_carries(&folder, &record));
        assert!(!departure_carries(
            &log_name(&signer, None, 7),
            &log_name(&signer, None, 7)
        ));
        assert!(!departure_carries(&n("/"), &record));
    }
}
