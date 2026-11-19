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
    is_data_name, is_namespace, namespace_of, parse_audit_ask_name, parse_cut_bytes_name,
    parse_grant_name, parse_head_name, parse_head_prefix, parse_held_name, parse_hold_ask_name,
    parse_log_name, parse_piece_name, parse_seal_key_name, parse_signal_run_name,
    parse_summary_name,
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
/// - a seal key (`<D>/32=seal/<public key>`: a public key, named by the
///   device that holds it) and a folder epoch's grant of a collection under
///   `folder`;
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
    if parse_seal_key_name(name).is_some() {
        return true;
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
}
