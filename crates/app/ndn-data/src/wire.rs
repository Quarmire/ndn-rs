//! The data layer's bytes: the names it publishes under and the TLV records
//! those Data packets carry (`docs/specs/data-layer.md`, "Wire format").
//!
//! A collection is named `<O>/32=data/<path>`: its namespace `O` (any
//! number of components), the KeywordNameComponent `data` marking where `O`
//! ends, and at least one path component; no other component of it is a
//! keyword or digest. Every packet a device publishes is named under its own
//! device name `D` (its key name without `KEY/<id>`), so the hierarchical
//! trust schema — data and key share their identity prefix — admits it
//! everywhere, and Interests for it route to the device:
//!
//! | packet | name | signed by |
//! |---|---|---|
//! | log entry (version, members record) | `<D>/32=log/<C>/seq=<n>` | the device key |
//! | summary root of namespace `O` | `<D>/32=summary/<O>/seq=<head>` | the device key |
//! | summary node of `X` | `<D>/32=summary/<X>/seq=<head>` | DigestSha256; its parent lists its digest |
//! | summary page of `X` | `<D>/32=summary/<X>/32=page/<buckets>/seq=<head>` | DigestSha256; its parent lists its digest |
//! | seal key | `<D>/32=seal/<X25519 public key>` | the device key |
//! | grant | `<G>/32=grant/<GrantAsk TLV>` | the granter's device key |
//!
//! `X` is a name of the tree from `O` to a collection: `O/32=data` (the
//! root's one child) or `O/32=data/<path>`, a folder or collection. Some
//! names are never fetched: the sync
//! group `<O>/32=sync` (State Vector Sync Interests,
//! notifications only), [`ndn_security::sync_group`]: the one definition the
//! forwarder's trust and link libraries route and multicast it by.
//!
//! Every name parses one way: `D` and `O` have no keyword component, so
//! the first `32=log`, `32=summary`, `32=seal` or `32=grant` ends `D`,
//! `32=data` ends `O`, and the layer's other keyword (`32=page`)
//! follows a subject whose only keyword is its marker; a seal
//! key's and a grant's last component is one opaque value (a key, a TLV).
//! A node or page name always ends in its head:
//! only a root is discovered without one (`<D>/32=summary/<O>`), and a
//! namespace never ends in a `seq=` component.
//!
//! TLV-TYPEs are allocated from 0x0520–0x057F, all even (non-critical): a
//! decoder skips an even TLV it does not know and refuses an odd one, so a
//! later revision can add fields old readers pass over and fields they must
//! not.

use std::collections::BTreeSet;

use bytes::Bytes;
use ndn_foundation_types::{Name, NameComponent, tlv_type};
use ndn_tlv::{TlvReader, TlvWriter};

use crate::collection::{Accepted, Cut, Epoch, Members, Parent, Rule};
use crate::version::{
    Audience, Content, Frontier, Keep, Parents, Seal, Seq, Timestamp, TypeId, Writer,
};

/// TLV-TYPE numbers (0x0520–0x057F).
pub mod tlv {
    /// A version's record: the Content of a version log entry.
    pub const VERSION_RECORD: u64 = 0x0520;
    /// A frontier: `FrontierEntry*`, by writer.
    pub const FRONTIER: u64 = 0x0522;
    /// One writer of a frontier: `Name` (key) + `Seq`; in a version's
    /// parents, + `Digest` (the implicit digest of that writer's packet at
    /// that seq: the tip).
    pub const FRONTIER_ENTRY: u64 = 0x0524;
    /// A sequence number (NonNegativeInteger); in a members record, its
    /// parent's revision.
    pub const SEQ: u64 = 0x0526;
    /// A content type: `Name` + `Revision`.
    pub const TYPE_ID: u64 = 0x0528;
    /// A revision (NonNegativeInteger).
    pub const REVISION: u64 = 0x052A;
    /// Retention: `KeepForever`.
    pub const KEEP: u64 = 0x052C;
    /// A date (ms since the Unix epoch): an introduction offer's expiry.
    pub const KEEP_UNTIL: u64 = 0x052E;
    /// Keep until pruned (empty).
    pub const KEEP_FOREVER: u64 = 0x0532;
    /// A seal: `Audience*`.
    pub const SEAL: u64 = 0x0534;
    /// One audience: `AudienceKind` + `Name`.
    pub const AUDIENCE: u64 = 0x0536;
    /// 0 person, 1 device, 2 group.
    pub const AUDIENCE_KIND: u64 = 0x0538;
    /// The writer's clock reading (ms since the Unix epoch); display only.
    pub const DATED: u64 = 0x053A;
    /// The fields a version sets: `Field*`, by name.
    pub const FIELDS: u64 = 0x053C;
    /// One field: `FieldName` + `FieldValue`.
    pub const FIELD: u64 = 0x053E;
    /// A field's name (UTF-8).
    pub const FIELD_NAME: u64 = 0x0540;
    /// A field's value; empty removes the field.
    pub const FIELD_VALUE: u64 = 0x0542;
    /// The merge function's operation for this version (opaque to the layer).
    pub const MERGE_OP: u64 = 0x0544;
    /// A members record: the Content of a members log entry.
    pub const MEMBERS_RECORD: u64 = 0x0546;
    /// A collection rule: `RuleKind` [+ `Name` of the merge function]; in a
    /// merge version's record, the rule its operation was made for.
    pub const RULE: u64 = 0x0548;
    /// 1 log, 2 merge.
    pub const RULE_KIND: u64 = 0x054A;
    /// Writer key-name prefixes: `Name*`.
    pub const WRITERS: u64 = 0x054C;
    /// Readers: `Audience*`.
    pub const READERS: u64 = 0x054E;
    /// A summary node or page: the Content of a summary packet.
    pub const SUMMARY_NODE: u64 = 0x0552;
    /// The writer's own entries directly in the node's collection: `SeqRange*`.
    pub const ENTRIES: u64 = 0x0554;
    /// The writer's members records of the node's collection: `SeqRange*`.
    pub const MEMBERS_ENTRIES: u64 = 0x0556;
    /// An inclusive range: `Seq` (low) `Seq` (high).
    pub const SEQ_RANGE: u64 = 0x0558;
    /// Sub-collections, inline: `Child*`, by component.
    pub const CHILDREN: u64 = 0x055A;
    /// One sub-collection: `Name` (one component), `Seq` (head), `Digest`.
    pub const CHILD: u64 = 0x055C;
    /// SHA-256 implicit digest of a summary packet (32 octets); in a members
    /// record, SHA-256 of its parent's `MembersRecord`; in a version's
    /// parents, of the tip's packet.
    pub const DIGEST: u64 = 0x055E;
    /// Sub-collections, paged by hash: `Page*`, by bucket.
    pub const PAGES: u64 = 0x0560;
    /// One page: `Bucket`, `Seq` (head), `Digest`.
    pub const PAGE: u64 = 0x0562;
    /// A page's bucket (one nibble, 0–15).
    pub const BUCKET: u64 = 0x0564;
    /// A page's path from its node: the buckets taken (one octet each).
    pub const PAGE_PATH: u64 = 0x0566;
    /// The node's writer: `Name` (key).
    pub const WRITER: u64 = 0x0568;
    /// A members record's removals in force: `Cut*`, by prefix.
    pub const CUTS: u64 = 0x056A;
    /// One removal: `Name` (the removed writer prefix), `CutBytes*` (the
    /// manifests binding what it keeps to its bytes), then — in a
    /// collection's record — per key whose versions stay accepted in the
    /// collection, `Writer` and `Entries` (exactly those seqs), or — in a
    /// folder's record — one `CutIn` per collection under the folder.
    pub const CUT: u64 = 0x056C;
    /// The epoch a sealed collection is read in: `Name` (the device that
    /// signed the record starting it), `Seq` (that record's seq).
    pub const SEAL_EPOCH: u64 = 0x056E;
    /// The frontier the owner had applied when it changed the rule: `Frontier`.
    pub const RULE_SINCE: u64 = 0x0570;
    /// A sealed version's payload, in place of `Fields` and `MergeOp`:
    /// `SealEpoch`, `Ciphertext`.
    pub const SEALED: u64 = 0x0572;
    /// Octets: nonce (12) ‖ tag (16) ‖ ciphertext, ChaCha20-Poly1305.
    pub const CIPHERTEXT: u64 = 0x0574;
    /// A device's seal key: 32 octets, an X25519 public key.
    pub const SEAL_KEY: u64 = 0x0576;
    /// What a grant answers: `Name` (the asker's seal key name), `Name` (the
    /// collection), `SealEpoch`.
    pub const GRANT_ASK: u64 = 0x0578;
    /// A grant: `EphemeralKey`, `Ciphertext` (the key, wrapped).
    pub const GRANT: u64 = 0x057A;
    /// The granter's ephemeral X25519 public key: 32 octets.
    pub const EPHEMERAL_KEY: u64 = 0x057C;
    /// An epoch key's check: 32 octets, HKDF-SHA256 of the key (spec §9).
    pub const KEY_CHECK: u64 = 0x057E;

    // Slice 3: odd numbers, critical — a reader that does not know them
    // must refuse what carries them rather than pass over it.

    /// A version's payload carried in pieces, in place of `Fields` and
    /// `MergeOp` (or of a sealed payload's `Ciphertext`): `Size`, `Digest`
    /// (of the root manifest node's packet).
    pub const CHUNKS: u64 = 0x0521;
    /// NonNegativeInteger: the payload's octets.
    pub const SIZE: u64 = 0x0523;
    /// Octets: an ask's fresh random nonce (16).
    pub const NONCE: u64 = 0x0531;
    /// Octets: the asker's proof that it asks, a Data packet `<asker>/32=ask/
    /// <binding>` signed by the asker device's key.
    pub const ASKER: u64 = 0x053B;
    /// 32 octets: an introduction's proof (spec §19).
    pub const PROOF: u64 = 0x053F;

    // Slice 6: odd numbers, critical.

    /// Empty, in a members record right after its `Name`: the record is a
    /// folder's — it governs the folder that `Name` names and every
    /// collection under it (spec §6).
    pub const FOLDER: u64 = 0x0555;
    /// In a folder record's `Cut`, once per collection under the folder in
    /// which versions of the cut's keys stay accepted, collections
    /// ascending: `Name` (the collection), then per key `Writer` and
    /// `Entries` (exactly those seqs, in that collection). A key's log is
    /// one sequence across its collections, so a seq is accepted only in
    /// the collection it lists it under (spec §6.1, §8).
    pub const CUT_IN: u64 = 0x055F;
    /// In a `Cut`, right after its `Name`, once per manifest: `Name`, the
    /// full name (ending in its implicit digest) of the root packet of a
    /// cut manifest listing the implicit digest of every version the cut
    /// keeps (spec §8). A version is inside the cut only with those bytes;
    /// a cut that keeps versions carries one in every record signed now.
    pub const CUT_BYTES: u64 = 0x055B;

    // The introduction exchange (spec §19): odd numbers, critical.

    /// A log record: a one-use offer of a folder — `Name` (the folder),
    /// `Role`, `KeepUntil` (its expiry), `Tries`, `Digest` (the commitment
    /// to its secret), `SealKey` (the offering device's).
    pub const INTRO_OFFER: u64 = 0x0561;
    /// A log record: an offer used — `Name` (the offer), then `Writer` and
    /// `Digest` (the asker key it was used by) — or, without them, closed
    /// after too many wrong tries.
    pub const INTRO_USED: u64 = 0x0563;
    /// An ask, in its Interest's name: `EphemeralKey`, `Ciphertext` (a
    /// content key wrapped to the offer's seal key), `Ciphertext` (the ask's
    /// fields, sealed under it).
    pub const INTRO_ASK: u64 = 0x0565;
    /// An answer: `Name` (offer), `Writer`, `Digest` (the asker key), then
    /// `Name` (folder), `Role`, `Credentials`, `Asker` — or `IntroRefused` —
    /// then `Proof`.
    pub const INTRO_ANSWER: u64 = 0x0567;
    /// NonNegativeInteger: 0 reader, 1 writer.
    pub const ROLE: u64 = 0x0569;
    /// NonNegativeInteger: wrong tries (allowed, in an offer; left, in a
    /// refusal).
    pub const TRIES: u64 = 0x056B;
    /// NonNegativeInteger (1 unknown, 2 used, 3 expired, 4 closed, 5 wrong
    /// proof), then `Tries` (left) for a wrong proof.
    pub const INTRO_REFUSED: u64 = 0x056D;
    /// Data packets, each whole: a signed trust context, then certificates
    /// of its signer key's chain.
    pub const CREDENTIALS: u64 = 0x056F;

    // The link hint of an introduction's code (spec §19.2): even numbers, in
    // the block 0x05B0–0x05BF, carried as the value of the intro envelope's
    // `LinkHint` (0x0478, trust-envelope.md).

    /// 32 octets: SHA-256 of the inviter device's public key as a
    /// certificate carries it (an Ed25519 key's 32 octets): the key the link
    /// handshake must prove.
    pub const LINK_KEY: u64 = 0x05B0;
    /// One direct-path candidate address, repeatable: one octet of kind
    /// (0 host, 1 reflexive, 2 advertised, 3 mapped), the IP address (4
    /// octets for IPv4, 16 for IPv6), the UDP port (2 octets, big-endian).
    pub const LINK_CANDIDATE: u64 = 0x05B2;

    // The hint record of a short code (spec §19.2): even numbers, in the same
    // block, the content of a Data named `<device>/32=hint/<token>`.

    /// A hint record: `HintOffer`, `LinkKey`, `LinkCandidate`s, `HintRelay`s,
    /// `HintUntil`, `Credentials` — or, for an offer no longer served, just
    /// a `HintGone`.
    pub const INTRO_HINT: u64 = 0x05B4;
    /// The offer the record is bound to: a `Name` (the offer record's name).
    pub const HINT_OFFER: u64 = 0x05B6;
    /// A relay device that reaches the inviter, repeatable (at most 8): a
    /// `Name`.
    pub const HINT_RELAY: u64 = 0x05B8;
    /// NonNegativeInteger: 3 expired, 4 closed (the codes of
    /// `IntroRefused`). The offer is no longer served.
    pub const HINT_GONE: u64 = 0x05BA;
    /// NonNegativeInteger: the offer's expiry, in milliseconds. Informational.
    pub const HINT_UNTIL: u64 = 0x05BC;
}

/// Keyword components of the layer's names.
const DATA: &[u8] = b"data";
const LOG: &[u8] = b"log";
const SUMMARY: &[u8] = b"summary";
const PAGE: &[u8] = b"page";
const SEAL: &[u8] = b"seal";
const GRANT: &[u8] = b"grant";
const MANIFEST: &[u8] = b"manifest";
const HELD: &[u8] = b"held";
const ROOT: &[u8] = b"root";
const ASK: &[u8] = b"ask";
const CUT: &[u8] = b"cut";
const SIGNAL: &[u8] = b"signal";
const RUN: &[u8] = b"run";

/// The most payload octets a version carries in its own packet; a larger
/// payload travels in pieces, whatever the collection's rule.
pub const INLINE_MAX: usize = 6144;

/// The most payload octets a version carries at all (64 MiB): a reader
/// assembles a payload whole, so a record claiming more is refused when
/// decoded, and `put` of more answers `TooLarge`.
pub const PAYLOAD_MAX: u64 = 64 << 20;

/// The payload octets one chunk carries (the last may carry fewer).
pub const CHUNK: usize = 4096;

/// The digests one manifest node lists.
pub const FANOUT: usize = 128;

/// The octets of an ask's nonce.
pub const NONCE_LEN: usize = 16;

/// The most seqs one summary node lists in its `Entries` and
/// `MembersEntries` together; a node listing more is refused.
pub const NODE_SEQS: usize = 65_536;

/// A summary node lists its children inline up to this many; beyond it they
/// are paged into 16 buckets by the first nibble of SHA-256 of the child's
/// component, recursively.
pub const PAGE_FANOUT: usize = 64;

/// Why bytes do not decode.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("malformed data-layer record: {0}")]
pub struct WireError(pub String);

pub(crate) fn bad(what: impl Into<String>) -> WireError {
    WireError(what.into())
}

pub(crate) fn kw(word: &'static [u8]) -> NameComponent {
    NameComponent::keyword(Bytes::from_static(word))
}

pub(crate) fn is_kw(c: &NameComponent, word: &[u8]) -> bool {
    c.typ == tlv_type::KEYWORD && c.value.as_ref() == word
}

pub(crate) fn name_of(comps: &[NameComponent]) -> Name {
    Name::from_components(comps.iter().cloned())
}

/// A component that may stand in a namespace or a collection's path: no
/// keyword (those mark the layer's own names) and no digest.
fn is_plain(c: &NameComponent) -> bool {
    !matches!(
        c.typ,
        tlv_type::KEYWORD | tlv_type::IMPLICIT_SHA256 | tlv_type::PARAMETERS_SHA256
    )
}

/// Whether `name` can be a namespace: not the root, and only plain
/// components that are not sequence numbers (a summary root's name
/// `<D>/32=summary/<O>/seq=<head>` ends in one, so `O` must not).
pub fn is_namespace(name: &Name) -> bool {
    is_namespace_comps(name.components())
}

fn is_namespace_comps(comps: &[NameComponent]) -> bool {
    !comps.is_empty()
        && comps
            .iter()
            .all(|c| is_plain(c) && c.typ != tlv_type::SEQUENCE_NUM)
}

/// Whether `name` can be a device name: not the root, and no keyword or
/// digest component, so the first `32=log` or `32=summary` after it ends it.
pub fn is_device_name(name: &Name) -> bool {
    is_device_comps(name.components())
}

pub(crate) fn is_device_comps(comps: &[NameComponent]) -> bool {
    !comps.is_empty() && comps.iter().all(is_plain)
}

/// The roles of the namespace layout (`/<ns>/<role>/<device>`): the device
/// roles every namespace's certificate authority issues (`ndn_cert::Role`).
pub(crate) const LAYOUT_ROLES: [&[u8]; 4] = [b"admin", b"member", b"node", b"guest"];

/// Why a name is not a data-layer name `<namespace>/32=data/<path>`: each
/// says what to do instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NotDataName {
    /// It has no `32=data` component.
    #[error(
        "it has no 32=data component, so nothing in it says where its namespace ends; name a \
         collection <namespace>/32=data/<path> (for the namespace /home/bob: \
         /home/bob/32=data/notes)"
    )]
    NoMarker,
    /// Nothing that can be a namespace precedes its `32=data`.
    #[error(
        "what precedes its 32=data component is not a namespace (one or more components, none \
         a keyword, digest or sequence number); name a collection \
         <namespace>/32=data/<path> under the namespace that owns it"
    )]
    NoNamespace,
    /// Nothing follows its `32=data`, where a collection is asked for.
    #[error(
        "nothing follows its 32=data component; a collection has a path, \
         <namespace>/32=data/<path> (watch <namespace>/32=data to follow every collection of \
         the namespace)"
    )]
    NoPath,
    /// It has a keyword or digest component besides its one `32=data`.
    #[error(
        "it has a keyword or digest component besides its one 32=data marker; those mark the \
         layer's own names (32=log, 32=summary, 32=state), so a collection \
         <namespace>/32=data/<path> has only plain components besides it"
    )]
    OtherKeyword,
}

/// Where the namespace of a data name `<O>/32=data[/<path>]` ends: the
/// index of its one `32=data` component. `O` is a namespace
/// ([`is_namespace`]) and every path component is plain; the path may be
/// empty (`<O>/32=data` is the folder of every collection of `O`).
pub fn data_marker(name: &Name) -> Result<usize, NotDataName> {
    let comps = name.components();
    let at = comps
        .iter()
        .position(|c| is_kw(c, DATA))
        .ok_or(NotDataName::NoMarker)?;
    if !is_namespace_comps(&comps[..at]) {
        return Err(NotDataName::NoNamespace);
    }
    if !comps[at + 1..].iter().all(is_plain) {
        return Err(NotDataName::OtherKeyword);
    }
    Ok(at)
}

/// `<namespace>/32=data`: the folder of every collection of `namespace`, the
/// root's one child in a writer's summary of it.
pub fn data_folder(namespace: &Name) -> Name {
    namespace.clone().append_component(kw(DATA))
}

/// Whether `name` is a collection or folder name `<O>/32=data[/<path>]`.
pub fn is_data_name(name: &Name) -> bool {
    data_marker(name).is_ok()
}

/// Whether `name` can name a collection: `<O>/32=data/<path>`, with at
/// least one path component.
pub fn check_collection_name(name: &Name) -> Result<(), NotDataName> {
    let at = data_marker(name)?;
    if at + 1 == name.len() {
        return Err(NotDataName::NoPath);
    }
    Ok(())
}

/// Whether `name` can name a collection (see [`check_collection_name`]).
pub fn is_collection_name(name: &Name) -> bool {
    check_collection_name(name).is_ok()
}

/// The namespace of a collection or folder name: the components before its
/// `32=data` marker. A collection's owner is that namespace (spec §3); its
/// sync group and every writer's summary root are per namespace.
pub fn namespace_of(name: &Name) -> Option<Name> {
    let at = data_marker(name).ok()?;
    Some(name_of(&name.components()[..at]))
}

/// The namespace a summary subject lies in: the subject itself for a root
/// (a namespace), else the namespace of the data name it is.
pub fn subject_namespace(subject: &Name) -> Option<Name> {
    if is_namespace(subject) {
        Some(subject.clone())
    } else {
        namespace_of(subject)
    }
}

/// The device a key belongs to: the key name without `KEY/<key-id>`.
pub fn device_of(key: &Name) -> Option<Name> {
    device_len(key).map(|n| name_of(&key.components()[..n]))
}

/// How many leading components of key name `key` (`<D>/KEY/<key-id>`) name
/// its device `D`; `None` for a name that is no key name.
pub(crate) fn device_len(key: &Name) -> Option<usize> {
    let comps = key.components();
    let d = comps.len().checked_sub(2)?;
    (d >= 1
        && comps[d].typ == tlv_type::GENERIC_NAME_COMPONENT
        && comps[d].value.as_ref() == b"KEY")
        .then_some(d)
}

/// Whether the device named by `device` lies under the namespace of
/// `collection` (the components before its `32=data` marker): the name
/// half of the owner rule (spec §3), shared by the layer's judgement of
/// members records and by [`owns`].
pub(crate) fn device_owns(collection: &Name, device: &[NameComponent]) -> bool {
    data_marker(collection)
        .is_ok_and(|at| device.len() >= at && device[..at] == collection.components()[..at])
}

/// Whether `writer` is an owner device of `collection`: its device — the
/// key name `<D>/KEY/<key-id>` without `KEY/<key-id>` — lies under the
/// collection's namespace, the components before its `32=data` marker
/// (spec §3). Alice's laptop and phone both own `/alice/32=data/notes`;
/// Bob's laptop does not. It depends on the two names alone, never on what
/// a device holds, so every member judges a writer alike in any arrival
/// order; the layer judges its owner rule by this same test.
///
/// The owner rule also asks which held trust context governs the device:
/// a device of a longer namespace held beside the collection's (a
/// `/home/bob` device, for `/home/32=data/x`) is that namespace's device,
/// not an owner. Names alone cannot tell that, and a rule's answer may not
/// depend on the contexts one member holds, so `owns` answers the name
/// half: whether `D` lies under the namespace — what a reader holding the
/// collection's namespace and no longer one under it concludes.
///
/// A revoked owner device, or one outside a cut, needs no handling here:
/// its versions the layer refuses never reach a merge rule.
pub fn owns(collection: &Name, writer: &Writer) -> bool {
    let key = writer.key();
    device_len(key).is_some_and(|n| device_owns(collection, &key.components()[..n]))
}

/// A log entry's name: `<device>/32=log[/<subject>]/seq=<seq>`.
pub fn log_name(device: &Name, subject: Option<&Name>, seq: u64) -> Name {
    let mut comps = device.components().to_vec();
    comps.push(kw(LOG));
    if let Some(s) = subject {
        comps.extend(s.components().iter().cloned());
    }
    comps.push(NameComponent::sequence_num(seq));
    Name::from_components(comps)
}

/// A parsed log entry name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogName {
    /// The device whose log it is.
    pub device: Name,
    /// The collection it is about; `None` for an entry about none.
    pub subject: Option<Name>,
    /// Its sequence number in the device's log.
    pub seq: u64,
}

/// Parse `<device>/32=log[/<subject>]/seq=<seq>`: the device is everything
/// before the first `32=log` (a device name has no keyword), the subject a
/// collection name (its one keyword is its `32=data`).
pub fn parse_log_name(name: &Name) -> Option<LogName> {
    let comps = name.components();
    let at = comps.iter().position(|c| is_kw(c, LOG))?;
    let (last, subject) = comps[at + 1..].split_last()?;
    let seq = last.as_sequence_num()?;
    if !is_device_comps(&comps[..at]) {
        return None;
    }
    let subject = (!subject.is_empty()).then(|| name_of(subject));
    if subject.as_ref().is_some_and(|s| !is_collection_name(s)) {
        return None;
    }
    Some(LogName {
        device: name_of(&comps[..at]),
        subject,
        seq,
    })
}

/// The octets of a signal run's id (spec §20): the first 16 octets of the
/// SHA-256 of the run's public key.
pub const RUN_ID_LEN: usize = 16;

/// A signal run header's name (spec §20):
/// `<device>/32=signal/<scope>/32=run/<run>`, `device` the device whose key
/// signs it, `scope` the folder or collection the run's signals are of and
/// `run` the run's id, one generic component.
pub fn signal_run_name(device: &Name, scope: &Name, run: &[u8; RUN_ID_LEN]) -> Name {
    let mut comps = device.components().to_vec();
    comps.push(kw(SIGNAL));
    comps.extend(scope.components().iter().cloned());
    comps.push(kw(RUN));
    comps.push(NameComponent::generic(Bytes::copy_from_slice(run)));
    Name::from_components(comps)
}

/// A parsed signal run header name ([`signal_run_name`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignalRunName {
    /// The device whose key signs the header.
    pub device: Name,
    /// The folder or collection the run's signals are of.
    pub scope: Name,
    /// The run's id.
    pub run: [u8; RUN_ID_LEN],
}

/// Parse `<device>/32=signal/<scope>/32=run/<run>`: the device is
/// everything before the first `32=signal` (a device name has no keyword),
/// the scope a folder or collection name (its one keyword is its
/// `32=data`), the run a generic component of exactly [`RUN_ID_LEN`]
/// octets. `None` for any other name.
pub fn parse_signal_run_name(name: &Name) -> Option<SignalRunName> {
    let comps = name.components();
    let at = comps.iter().position(|c| is_kw(c, SIGNAL))?;
    let [scope @ .., run_kw, run] = &comps[at + 1..] else {
        return None;
    };
    if !is_device_comps(&comps[..at])
        || !is_kw(run_kw, RUN)
        || run.typ != tlv_type::GENERIC_NAME_COMPONENT
    {
        return None;
    }
    let run: [u8; RUN_ID_LEN] = run.value.as_ref().try_into().ok()?;
    let scope = name_of(scope);
    if !is_data_name(&scope) {
        return None;
    }
    Some(SignalRunName {
        device: name_of(&comps[..at]),
        scope,
        run,
    })
}

/// `<device>/32=summary/<subject>`: the prefix every summary node and page
/// of `subject` by `device` lies under.
fn summary_prefix(device: &Name, subject: &Name) -> Name {
    let mut comps = device.components().to_vec();
    comps.push(kw(SUMMARY));
    comps.extend(subject.components().iter().cloned());
    Name::from_components(comps)
}

/// `<device>/32=summary/<O>/32=root`: the discovery name of `device`'s
/// signed root of namespace `O`. No node or page name extends it (theirs
/// go on with `32=data`), so a prefix Interest for it can only be answered
/// by a root.
pub fn root_prefix(device: &Name, ns: &Name) -> Name {
    summary_prefix(device, ns).append_component(kw(ROOT))
}

/// A signed root's name: `<device>/32=summary/<O>/32=root/seq=<head>`.
pub fn root_name(device: &Name, ns: &Name, head: u64) -> Name {
    root_prefix(device, ns).append_sequence_num(head)
}

/// A summary node's name: `<device>/32=summary/<subject>/seq=<head>`,
/// `subject` a folder or collection.
pub fn node_name(device: &Name, subject: &Name, head: u64) -> Name {
    summary_prefix(device, subject).append_sequence_num(head)
}

/// A summary page's name:
/// `<device>/32=summary/<subject>/32=page/<path>/seq=<head>`.
pub fn page_name(device: &Name, subject: &Name, path: &[u8], head: u64) -> Name {
    summary_prefix(device, subject)
        .append_component(kw(PAGE))
        .append_component(NameComponent::generic(Bytes::copy_from_slice(path)))
        .append_sequence_num(head)
}

/// A parsed summary name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SummaryName {
    /// The device that wrote the summary.
    pub device: Name,
    /// What the node summarises: a namespace (the root), or a data name
    /// under it, `<O>/32=data[/<path>]` (a folder or collection).
    pub subject: Name,
    /// The page path, for a page.
    pub page: Option<Bytes>,
    /// The head, when named.
    pub head: Option<u64>,
}

/// Parse a summary name, or a root's discovery prefix
/// `<device>/32=summary/<O>`. The device is everything before the first
/// `32=summary`; a trailing sequence number is the head. Only a root's
/// discovery prefix lacks the head (a namespace never ends in a sequence
/// number), so a node or page without one is no summary name and a
/// collection path's own last component is never taken for the head.
pub fn parse_summary_name(name: &Name) -> Option<SummaryName> {
    let comps = name.components();
    let at = comps.iter().position(|c| is_kw(c, SUMMARY))?;
    if !is_device_comps(&comps[..at]) {
        return None;
    }
    let mut rest = &comps[at + 1..];
    let mut head = None;
    if let Some((s, before)) = rest
        .split_last()
        .and_then(|(last, before)| Some((last.as_sequence_num()?, before)))
    {
        head = Some(s);
        rest = before;
    }
    // A root's name ends its subject (a namespace) with `32=root`; a node's
    // or page's subject is a data name, which never carries it.
    let marked_root = rest.last().is_some_and(|c| is_kw(c, ROOT));
    if marked_root {
        rest = &rest[..rest.len() - 1];
    }
    let (subject, page) = match rest.iter().position(|c| is_kw(c, PAGE)) {
        Some(_) if marked_root => return None,
        Some(p) if p + 2 == rest.len() => (&rest[..p], Some(rest[p + 1].value.clone())),
        Some(_) => return None,
        None => (rest, None),
    };
    let subject = name_of(subject);
    let root = is_namespace(&subject);
    if root != marked_root {
        return None;
    }
    let named = head.is_some() || root;
    ((root || is_data_name(&subject)) && named).then(|| SummaryName {
        device: name_of(&comps[..at]),
        subject,
        page,
        head,
    })
}

/// `<device>/32=seal`: what a device's seal key packet is asked for by when its public key is not
/// known yet (a prefix of [`seal_key_name`]).
pub fn seal_key_prefix(device: &Name) -> Name {
    device.clone().append_component(kw(SEAL))
}

/// A device's seal key's name: `<device>/32=seal/<public key>`, the last
/// component the 32 octets of its X25519 public key.
pub fn seal_key_name(device: &Name, public: &[u8; 32]) -> Name {
    device
        .clone()
        .append_component(kw(SEAL))
        .append_component(NameComponent::generic(Bytes::copy_from_slice(public)))
}

/// Parse `<device>/32=seal/<public key>`.
pub fn parse_seal_key_name(name: &Name) -> Option<(Name, [u8; 32])> {
    let comps = name.components();
    let at = comps.iter().position(|c| is_kw(c, SEAL))?;
    if !is_device_comps(&comps[..at]) || at + 2 != comps.len() {
        return None;
    }
    let last = &comps[at + 1];
    if last.typ != tlv_type::GENERIC_NAME_COMPONENT {
        return None;
    }
    let public = <[u8; 32]>::try_from(last.value.as_ref()).ok()?;
    Some((name_of(&comps[..at]), public))
}

/// What a grant answers: the content key of one epoch of a collection, for
/// the holder of a seal key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GrantAsk {
    /// The asker's seal key's name (`<device>/32=seal/<public key>`).
    pub seal_key: Name,
    /// The collection whose epoch key is asked for.
    pub collection: Name,
    /// The epoch.
    pub epoch: Epoch,
}

pub(crate) fn write_epoch(w: &mut TlvWriter, e: &Epoch) {
    w.write_nested(tlv::SEAL_EPOCH, |w| {
        write_name(w, &e.creator);
        write_nni(w, tlv::SEQ, e.seq.0);
    });
}

pub(crate) fn read_epoch(value: Bytes) -> Result<Epoch, WireError> {
    let (mut creator, mut seq) = (None, None);
    each(value, |t, v| {
        match t {
            tlv_type::NAME => creator = Some(read_name(v)?),
            tlv::SEQ => seq = Some(read_nni(&v)?),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    match (creator, seq) {
        (Some(creator), Some(seq)) if is_device_name(&creator) => Ok(Epoch {
            creator,
            seq: Seq(seq),
        }),
        _ => Err(bad("an epoch names a device and a seq")),
    }
}

/// A grant's name: `<granter>/32=grant/<GrantAsk TLV>`.
pub fn grant_name(granter: &Name, ask: &GrantAsk) -> Name {
    let mut w = TlvWriter::new();
    w.write_nested(tlv::GRANT_ASK, |w| {
        write_name(w, &ask.seal_key);
        write_name(w, &ask.collection);
        write_epoch(w, &ask.epoch);
    });
    granter
        .clone()
        .append_component(kw(GRANT))
        .append_component(NameComponent::generic(w.finish()))
}

/// Parse `<granter>/32=grant/<GrantAsk TLV>`.
pub fn parse_grant_name(name: &Name) -> Option<(Name, GrantAsk)> {
    let comps = name.components();
    let at = comps.iter().position(|c| is_kw(c, GRANT))?;
    if !is_device_comps(&comps[..at]) || at + 2 != comps.len() {
        return None;
    }
    let mut r = TlvReader::new(comps[at + 1].value.clone());
    let (typ, value) = r.read_tlv().ok()?;
    if typ != tlv::GRANT_ASK || !r.is_empty() {
        return None;
    }
    let mut names = Vec::new();
    let mut epoch = None;
    each(value, |t, v| {
        match t {
            tlv_type::NAME => names.push(read_name(v)?),
            tlv::SEAL_EPOCH => epoch = Some(read_epoch(v)?),
            _ => return Ok(false),
        }
        Ok(true)
    })
    .ok()?;
    let [seal_key, collection]: [Name; 2] = names.try_into().ok()?;
    parse_seal_key_name(&seal_key)?;
    if !is_collection_name(&collection) {
        return None;
    }
    Some((
        name_of(&comps[..at]),
        GrantAsk {
            seal_key,
            collection,
            epoch: epoch?,
        },
    ))
}

// ---- slice 3: pieces ----------------------------------------------------------------------------

/// A piece of a large version (spec §13.1): a chunk of its payload, or a node
/// of its manifest tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PieceKind {
    /// Chunk `i` of the payload: `<V>/seg=<i>`.
    Chunk(u64),
    /// Manifest node `k`, in heap order from the root (0):
    /// `<V>/32=manifest/seg=<k>`.
    Manifest(u64),
}

/// A parsed piece name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PieceName {
    /// The version's log entry name, `V`.
    pub version: Name,
    /// The version as parsed.
    pub log: LogName,
    /// Which piece.
    pub kind: PieceKind,
}

/// The name of piece `kind` of the version named `version`.
pub fn piece_name(version: &Name, kind: PieceKind) -> Name {
    match kind {
        PieceKind::Chunk(i) => version.clone().append_segment(i),
        PieceKind::Manifest(k) => version
            .clone()
            .append_component(kw(MANIFEST))
            .append_segment(k),
    }
}

/// The names of every piece of the large version named `version` whose
/// record carries `chunks`: its manifest nodes in heap order, then its
/// chunks in order (spec §13.1).
pub fn piece_names<'a>(version: &'a Name, chunks: &ChunksBody) -> impl Iterator<Item = Name> + 'a {
    let shape = crate::pieces::Shape::of(chunks.size);
    let manifests: Vec<u64> = shape.manifests().collect();
    manifests
        .into_iter()
        .map(PieceKind::Manifest)
        .chain((0..shape.chunks).map(PieceKind::Chunk))
        .map(move |k| piece_name(version, k))
}

/// Parse `<V>/seg=<i>` or `<V>/32=manifest/seg=<k>`, `V` a version's log
/// entry name (with a collection).
pub fn parse_piece_name(name: &Name) -> Option<PieceName> {
    let comps = name.components();
    let (last, rest) = comps.split_last()?;
    let n = last.as_segment()?;
    let (rest, kind) = match rest.split_last() {
        Some((m, before)) if is_kw(m, MANIFEST) => (before, PieceKind::Manifest(n)),
        _ => (rest, PieceKind::Chunk(n)),
    };
    let version = name_of(rest);
    let log = parse_log_name(&version)?;
    log.subject.as_ref()?;
    Some(PieceName { version, log, kind })
}

/// `<R>/32=cut`, `R` a members record's log entry name: the prefix of the
/// packets of the cut manifest binding the versions its cuts keep to their
/// bytes (`seg=0` the root, spec §8, §16.1).
pub fn cut_bytes_prefix(record: &Name) -> Name {
    record.clone().append_component(kw(CUT))
}

/// Parse `<R>/32=cut/seg=<i>`, `R` a members record's log entry name (with
/// a subject): the record, parsed.
pub fn parse_cut_bytes_name(name: &Name) -> Option<LogName> {
    let comps = name.components();
    let (last, rest) = comps.split_last()?;
    last.as_segment()?;
    let (m, record) = rest.split_last()?;
    if !is_kw(m, CUT) {
        return None;
    }
    let log = parse_log_name(&name_of(record))?;
    log.subject.as_ref()?;
    Some(log)
}

/// A protocol whose asks or answers carry a proof `<device>/32=ask/
/// <binding>` ([`ask_name`]): its label opens every binding it makes (spec
/// §16.3), so a proof made for one protocol never verifies as another's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AskProtocol {
    /// An introduction ask ([`crate::intro::AskBody`]).
    IntroAsk,
    /// An introduction answer ([`crate::intro::AnswerBody`]).
    IntroAnswer,
}

impl AskProtocol {
    /// Every protocol.
    pub const ALL: [AskProtocol; 2] = [AskProtocol::IntroAsk, AskProtocol::IntroAnswer];

    /// The octets opening its bindings: ASCII ending in a zero octet, so
    /// none is a prefix of another.
    pub const fn label(self) -> &'static [u8] {
        match self {
            AskProtocol::IntroAsk => b"ndn-data intro ask\0",
            AskProtocol::IntroAnswer => b"ndn-data intro answer\0",
        }
    }
}

/// What a proof of `protocol` names: SHA-256 over its label, then `parts`
/// in order. The receiver computes it with the label of the protocol it
/// expects, and the proof verifies only if it names that binding.
pub fn ask_binding(protocol: AskProtocol, parts: &[&[u8]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(protocol.label());
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}

/// The name of an asker's proof: `<asker>/32=ask/<binding>`. Its Data
/// packet, signed by the asker device's key, rides in the ask it proves, so
/// a stranger's ask costs the answerer no work and no signature.
pub fn ask_name(asker: &Name, binding: &[u8; 32]) -> Name {
    asker
        .clone()
        .append_component(kw(ASK))
        .append_component(NameComponent::generic(Bytes::copy_from_slice(binding)))
}

/// Parse `<asker>/32=ask/<binding>`.
pub fn parse_ask_name(name: &Name) -> Option<(Name, [u8; 32])> {
    let comps = name.components();
    let at = comps.iter().position(|c| is_kw(c, ASK))?;
    if !is_device_comps(&comps[..at]) || at + 2 != comps.len() {
        return None;
    }
    let binding = <[u8; 32]>::try_from(comps[at + 1].value.as_ref()).ok()?;
    Some((name_of(&comps[..at]), binding))
}

pub(crate) fn read_nonce(v: &[u8]) -> Result<[u8; NONCE_LEN], WireError> {
    <[u8; NONCE_LEN]>::try_from(v).map_err(|_| bad("a nonce is 16 octets"))
}

/// The name that asks holder `holder` for a packet it keeps of another
/// device, `piece` (a log entry, a chunk or a manifest node):
/// `<holder>/32=held/<Name TLV>`. It routes to the holder by its own name.
pub fn held_name(holder: &Name, piece: &Name) -> Name {
    holder
        .clone()
        .append_component(kw(HELD))
        .append_component(NameComponent::generic(piece.encode_to_tlv()))
}

/// `<holder>/32=held`: the prefix of every [`held_name`] of `holder`.
pub fn held_prefix(holder: &Name) -> Name {
    holder.clone().append_component(kw(HELD))
}

/// Parse `<holder>/32=held/<Name TLV>`.
pub fn parse_held_name(name: &Name) -> Option<(Name, Name)> {
    let comps = name.components();
    let at = comps.iter().position(|c| is_kw(c, HELD))?;
    if !is_device_comps(&comps[..at]) || at + 2 != comps.len() {
        return None;
    }
    let mut r = TlvReader::new(comps[at + 1].value.clone());
    let (typ, value) = r.read_tlv().ok()?;
    if typ != tlv_type::NAME || !r.is_empty() {
        return None;
    }
    Some((name_of(&comps[..at]), read_name(value).ok()?))
}

/// The keywords of a name that `get` routes by, found in one pass over its components: each
/// parser `get` would try needs its own keyword in the name, so a name without it skips the
/// parser. A necessary condition only: the parsers still judge the name.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct NameWords(u8);

impl NameWords {
    const LOG: u8 = 1;

    pub(crate) fn of(name: &Name) -> Self {
        let mut bits = 0;
        for c in name.components() {
            if c.typ != tlv_type::KEYWORD {
                continue;
            }
            bits |= match c.value.as_ref() {
                LOG => Self::LOG,
                _ => 0,
            };
        }
        Self(bits)
    }

    pub(crate) fn log(self) -> bool {
        self.0 & Self::LOG != 0
    }
}

/// The asks and fetches a device serves by a keyword right after its own name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Served {
    /// `<granter>/32=grant/<ask>`.
    Grant,
    /// `<device>/32=intro/<digest>`.
    Intro,
    /// `<device>/32=hint/<token>`.
    Hint,
    /// `<holder>/32=held/<name>`.
    Held,
}

/// Which [`Served`] name `name` can be, by one look: each of their parsers takes everything
/// before its keyword as a device name, which holds no keyword and no digest, so only the
/// first such component can be that keyword. The parser of the kind still judges the name.
pub(crate) fn served_kind(name: &Name) -> Option<Served> {
    let first = name.components().iter().find(|c| !is_plain(c))?;
    if first.typ != tlv_type::KEYWORD {
        return None;
    }
    match first.value.as_ref() {
        GRANT => Some(Served::Grant),
        crate::intro::INTRO => Some(Served::Intro),
        crate::intro::HINT => Some(Served::Hint),
        HELD => Some(Served::Held),
        _ => None,
    }
}

/// A manifest node's Content: the digests it lists, in order.
pub fn encode_manifest(digests: &[[u8; 32]]) -> Bytes {
    let mut w = TlvWriter::new();
    for d in digests {
        w.write_tlv(tlv::DIGEST, d);
    }
    w.finish()
}

/// Decode a manifest node's Content.
pub fn decode_manifest(content: Bytes) -> Result<Vec<[u8; 32]>, WireError> {
    let mut out = Vec::new();
    each(content, |t, v| {
        if t != tlv::DIGEST {
            return Ok(false);
        }
        out.push(read_digest(&v)?);
        Ok(true)
    })?;
    if out.is_empty() || out.len() > FANOUT {
        return Err(bad(format!("a manifest node lists 1 to {FANOUT} digests")));
    }
    Ok(out)
}

/// The value of a component naming one epoch of one collection: the
/// collection's Name TLV, then its `SealEpoch`.
pub(crate) fn encode_epoch_of(c: &Name, e: &Epoch) -> Bytes {
    let mut w = TlvWriter::new();
    write_name(&mut w, c);
    write_epoch(&mut w, e);
    w.finish()
}

/// Parse [`encode_epoch_of`].
pub(crate) fn decode_epoch_of(value: Bytes) -> Option<(Name, Epoch)> {
    let (mut c, mut e) = (None, None);
    each(value, |t, v| {
        match t {
            tlv_type::NAME if c.is_none() => c = Some(read_name(v)?),
            tlv::SEAL_EPOCH => e = Some(read_epoch(v)?),
            _ => return Ok(false),
        }
        Ok(true)
    })
    .ok()?;
    Some((c?, e?))
}

/// Encode a seal key's Content: the X25519 public key.
pub fn encode_seal_key(public: &[u8; 32]) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_tlv(tlv::SEAL_KEY, public);
    w.finish()
}

/// Decode a seal key's Content.
pub fn decode_seal_key(content: Bytes) -> Result<[u8; 32], WireError> {
    let mut r = TlvReader::new(content);
    let (typ, v) = r.read_tlv().map_err(|e| bad(format!("bad TLV: {e:?}")))?;
    if typ != tlv::SEAL_KEY || !r.is_empty() {
        return Err(bad("a seal key packet carries one SealKey"));
    }
    read_digest(&v).map_err(|_| bad("a seal key is 32 octets"))
}

/// Encode a grant's Content: the granter's ephemeral public key and the
/// wrapped key.
pub fn encode_grant(ephemeral: &[u8; 32], wrapped: &[u8]) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_nested(tlv::GRANT, |w| {
        w.write_tlv(tlv::EPHEMERAL_KEY, ephemeral);
        w.write_tlv(tlv::CIPHERTEXT, wrapped);
    });
    w.finish()
}

/// Decode a grant's Content.
pub fn decode_grant(content: Bytes) -> Result<([u8; 32], Bytes), WireError> {
    let mut r = TlvReader::new(content);
    let (typ, value) = r.read_tlv().map_err(|e| bad(format!("bad TLV: {e:?}")))?;
    if typ != tlv::GRANT || !r.is_empty() {
        return Err(bad("a grant packet carries one Grant"));
    }
    let (mut eph, mut wrapped) = (None, None);
    each(value, |t, v| {
        match t {
            tlv::EPHEMERAL_KEY => eph = Some(read_digest(&v)?),
            tlv::CIPHERTEXT => wrapped = Some(v),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    match (eph, wrapped) {
        (Some(e), Some(w)) => Ok((e, w)),
        _ => Err(bad("a grant has an ephemeral key and a wrapped key")),
    }
}

// ---- primitives -------------------------------------------------------------------------------

pub(crate) fn write_nni(w: &mut TlvWriter, typ: u64, v: u64) {
    let b = v.to_be_bytes();
    let s = match v {
        0..=0xFF => &b[7..],
        0x100..=0xFFFF => &b[6..],
        0x1_0000..=0xFFFF_FFFF => &b[4..],
        _ => &b[..],
    };
    w.write_tlv(typ, s);
}

pub(crate) fn read_nni(v: &[u8]) -> Result<u64, WireError> {
    Ok(match v.len() {
        1 => u64::from(v[0]),
        2 => u64::from(u16::from_be_bytes([v[0], v[1]])),
        4 => u64::from(u32::from_be_bytes([v[0], v[1], v[2], v[3]])),
        8 => u64::from_be_bytes([v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]]),
        _ => return Err(bad("a NonNegativeInteger is 1, 2, 4 or 8 octets")),
    })
}

pub(crate) fn write_name(w: &mut TlvWriter, name: &Name) {
    w.write_nested(tlv_type::NAME, |w| {
        for c in name.components() {
            w.write_tlv(c.typ, &c.value);
        }
    });
}

pub(crate) fn read_name(value: Bytes) -> Result<Name, WireError> {
    Name::decode(value).map_err(|e| bad(format!("bad name: {e:?}")))
}

/// Iterate the TLVs of `value`, handing each known one to `f`; skip unknown
/// even types and refuse unknown odd (critical) ones. `f` returns whether it
/// knew the type.
pub(crate) fn each(
    value: Bytes,
    mut f: impl FnMut(u64, Bytes) -> Result<bool, WireError>,
) -> Result<(), WireError> {
    let mut r = TlvReader::new(value);
    while !r.is_empty() {
        let (typ, v) = r.read_tlv().map_err(|e| bad(format!("bad TLV: {e:?}")))?;
        if !f(typ, v)? && typ % 2 == 1 {
            return Err(bad(format!("unknown critical TLV-TYPE {typ:#x}")));
        }
    }
    Ok(())
}

fn write_frontier(w: &mut TlvWriter, f: &Frontier) {
    w.write_nested(tlv::FRONTIER, |w| {
        for (writer, seq) in f.iter() {
            w.write_nested(tlv::FRONTIER_ENTRY, |w| {
                write_name(w, writer.key());
                write_nni(w, tlv::SEQ, seq.0);
            });
        }
    });
}

fn read_frontier(value: Bytes) -> Result<Frontier, WireError> {
    let mut f = Frontier::new();
    read_tips(value, |id, _| {
        f.include(&id);
        Ok(())
    })?;
    Ok(f)
}

/// A version's parents: a `Frontier` whose entries each carry, after the
/// seq, the `Digest` of that writer's packet at that seq (spec §4).
pub(crate) fn write_parents(w: &mut TlvWriter, p: &Parents) {
    w.write_nested(tlv::FRONTIER, |w| {
        for (writer, seq, digest) in p.tips() {
            w.write_nested(tlv::FRONTIER_ENTRY, |w| {
                write_name(w, writer.key());
                write_nni(w, tlv::SEQ, seq.0);
                if let Some(d) = digest {
                    w.write_tlv(tlv::DIGEST, d);
                }
            });
        }
    });
}

pub(crate) fn read_parents(value: Bytes) -> Result<Parents, WireError> {
    let mut p = Parents::new();
    read_tips(value, |id, digest| {
        if p.get(&id.writer).is_some() {
            return Err(bad("a version names one tip per writer among its parents"));
        }
        p.insert(&id, digest);
        Ok(())
    })?;
    Ok(p)
}

/// Each `FrontierEntry` of a `Frontier`: its writer and seq, and its
/// `Digest` when it carries one.
fn read_tips(
    value: Bytes,
    mut tip: impl FnMut(crate::VersionId, Option<[u8; 32]>) -> Result<(), WireError>,
) -> Result<(), WireError> {
    each(value, |typ, v| {
        if typ != tlv::FRONTIER_ENTRY {
            return Ok(false);
        }
        let (mut key, mut seq, mut digest) = (None, None, None);
        each(v, |t, v| {
            match t {
                tlv_type::NAME => key = Some(read_name(v)?),
                tlv::SEQ => seq = Some(read_nni(&v)?),
                tlv::DIGEST => digest = Some(read_digest(&v)?),
                _ => return Ok(false),
            }
            Ok(true)
        })?;
        let (Some(key), Some(seq)) = (key, seq) else {
            return Err(bad("a frontier entry names a writer and a seq"));
        };
        tip(
            crate::VersionId {
                writer: Writer::new(key),
                seq: Seq(seq),
            },
            digest,
        )?;
        Ok(true)
    })
}

/// The rule a version's operation was made for: a `Rule` of kind merge.
fn read_made_under(value: Bytes) -> Result<Name, WireError> {
    let (mut kind, mut function) = (None, None);
    each(value, |t, v| {
        match t {
            tlv::RULE_KIND => kind = Some(read_nni(&v)?),
            tlv_type::NAME => function = Some(read_name(v)?),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    match (kind, function) {
        (Some(2), Some(function)) => Ok(function),
        _ => Err(bad(
            "a version names the merge rule its operation was made for",
        )),
    }
}

fn write_audiences(w: &mut TlvWriter, typ: u64, list: &[Audience]) {
    w.write_nested(typ, |w| {
        for a in list {
            let (kind, name) = match a {
                Audience::Person(n) => (0, n),
                Audience::Device(n) => (1, n),
                Audience::Group(n) => (2, n),
            };
            w.write_nested(tlv::AUDIENCE, |w| {
                write_nni(w, tlv::AUDIENCE_KIND, kind);
                write_name(w, name);
            });
        }
    });
}

fn read_audiences(value: Bytes) -> Result<Vec<Audience>, WireError> {
    let mut out = Vec::new();
    each(value, |typ, v| {
        if typ != tlv::AUDIENCE {
            return Ok(false);
        }
        let (mut kind, mut name) = (None, None);
        each(v, |t, v| {
            match t {
                tlv::AUDIENCE_KIND => kind = Some(read_nni(&v)?),
                tlv_type::NAME => name = Some(read_name(v)?),
                _ => return Ok(false),
            }
            Ok(true)
        })?;
        out.push(match (kind, name) {
            (Some(0), Some(n)) => Audience::Person(n),
            (Some(1), Some(n)) => Audience::Device(n),
            (Some(2), Some(n)) => Audience::Group(n),
            _ => return Err(bad("an audience is a known kind and a name")),
        });
        Ok(true)
    })?;
    Ok(out)
}

fn write_ranges(w: &mut TlvWriter, typ: u64, ranges: &[(u64, u64)]) {
    if ranges.is_empty() {
        return;
    }
    w.write_nested(typ, |w| {
        for (lo, hi) in ranges {
            w.write_nested(tlv::SEQ_RANGE, |w| {
                write_nni(w, tlv::SEQ, *lo);
                write_nni(w, tlv::SEQ, *hi);
            });
        }
    });
}

/// Write what a cut keeps of each key in one collection: `Writer` and
/// `Entries` per key, keys ascending.
fn write_kept<'a>(w: &mut TlvWriter, kept: impl Iterator<Item = (&'a Writer, &'a [(u64, u64)])>) {
    for (writer, ranges) in kept {
        w.write_nested(tlv::WRITER, |w| write_name(w, writer.key()));
        write_ranges(w, tlv::ENTRIES, ranges);
    }
}

fn read_ranges(value: Bytes) -> Result<Vec<(u64, u64)>, WireError> {
    let mut out = Vec::new();
    each(value, |typ, v| {
        if typ != tlv::SEQ_RANGE {
            return Ok(false);
        }
        let mut ends = Vec::with_capacity(2);
        each(v, |t, v| {
            if t != tlv::SEQ {
                return Ok(false);
            }
            ends.push(read_nni(&v)?);
            Ok(true)
        })?;
        match ends[..] {
            [lo, hi] if lo <= hi => out.push((lo, hi)),
            _ => return Err(bad("a seq range is low ≤ high")),
        }
        Ok(true)
    })?;
    Ok(out)
}

/// Sorted seqs as inclusive ranges of consecutive numbers.
pub(crate) fn ranges_of<'a>(seqs: impl IntoIterator<Item = &'a u64>) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    for &s in seqs {
        match out.last_mut() {
            Some((_, hi)) if *hi + 1 == s => *hi = s,
            _ => out.push((s, s)),
        }
    }
    out
}

pub(crate) fn read_digest(v: &[u8]) -> Result<[u8; 32], WireError> {
    <[u8; 32]>::try_from(v).map_err(|_| bad("a digest is 32 octets"))
}

// ---- log records ------------------------------------------------------------------------------

/// The body of a version log entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionBody {
    /// The collection.
    pub collection: Name,
    /// What the writer had applied, each tip with its packet's digest.
    pub parents: Parents,
    /// The type the writer wrote.
    pub type_id: TypeId,
    /// Who may read it, as declared by the writer.
    pub seal: Seal,
    /// Retention.
    pub keep: Keep,
    /// The writer's clock.
    pub dated: Timestamp,
    /// The merge rule the operation was made for (spec §5); `None` under
    /// the log rule.
    pub rule: Option<Name>,
    /// The fields the writer set (an empty value removes the field); empty
    /// while the payload is sealed and not opened.
    pub fields: Content,
    /// The merge function's operation (empty under the log rule, and while
    /// the payload is sealed and not opened).
    pub op: Bytes,
    /// The payload sealed: when present, `Fields` and `MergeOp` travel
    /// inside it ([`encode_payload`]) and not beside it.
    pub sealed: Option<SealedBody>,
    /// The payload carried in pieces (spec §13.1): when present, the
    /// payload — sealed or not — travels in them, and neither `Fields` nor
    /// `MergeOp` nor the sealed `Ciphertext` stands in the record.
    pub chunks: Option<ChunksBody>,
}

/// A sealed payload: the epoch whose key seals it, and the ciphertext of
/// [`encode_payload`] (`nonce ‖ tag ‖ ciphertext`), its AAD the TLV of the
/// version's own name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedBody {
    /// The epoch.
    pub epoch: Epoch,
    /// The ciphertext; empty when the version's payload travels in pieces
    /// (the pieces carry it).
    pub ciphertext: Bytes,
}

/// A payload carried in pieces: its octets and the digest of its manifest
/// tree's root node packet (spec §13.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ChunksBody {
    /// The payload's octets as carried (sealed: the ciphertext's).
    pub size: u64,
    /// SHA-256 of the root manifest node's whole Data packet.
    pub root: [u8; 32],
}

/// One removal in a members record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CutBody {
    /// The removed writer prefix.
    pub of: Name,
    /// Exactly the versions of its keys that stay accepted, each in its
    /// collection: of a collection's record, that collection only; of a
    /// folder's, collections strictly under the folder.
    pub accept: Accepted,
}

/// The body of a members log entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembersBody {
    /// The collection governed; of a folder record, the folder.
    pub collection: Name,
    /// A folder's record (`Folder`), not a collection's.
    pub folder: bool,
    /// The record's revision.
    pub revision: u64,
    /// The collection's rule.
    pub rule: Rule,
    /// Writer key-name prefixes.
    pub writers: Vec<Name>,
    /// Readers.
    pub readers: Vec<Audience>,
    /// Removals in force, by prefix.
    pub cuts: Vec<CutBody>,
    /// The epoch the collection is sealed in (readers listed only).
    pub epoch: Option<Epoch>,
    /// The epoch key's check; present exactly when `epoch` is.
    pub key_check: Option<[u8; 32]>,
    /// The frontier the owner had applied when the rule last changed (or
    /// when it sealed a collection that was not sealed).
    pub since: Option<Frontier>,
    /// The record in force at the signer when it signed this one (spec
    /// §6); none at revision 1.
    pub parent: Option<Parent>,
}

impl From<&Members> for MembersBody {
    fn from(m: &Members) -> Self {
        Self {
            collection: m.collection.clone(),
            folder: m.folder,
            revision: m.revision.0,
            rule: m.rule.clone(),
            writers: m.writers.clone(),
            readers: m.readers.clone(),
            cuts: m
                .cuts
                .iter()
                .map(|Cut { of, accept, .. }| CutBody {
                    of: of.clone(),
                    accept: accept.clone(),
                })
                .collect(),
            epoch: m.epoch.clone(),
            key_check: m.key_check,
            since: m.since.clone(),
            parent: m.parent,
        }
    }
}

/// What a log entry says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    /// A version.
    Version(VersionBody),
    /// A members record.
    Members(MembersBody),
    /// An introduction's offer or use mark (spec §19).
    Intro(crate::intro::IntroRecord),
}

impl Record {
    /// The collection a log entry with this record is about (its name's
    /// subject): `None` for a record about no collection.
    pub fn subject(&self) -> Option<Name> {
        match self {
            Record::Version(b) => Some(b.collection.clone()),
            Record::Members(b) => Some(b.collection.clone()),
            Record::Intro(r) => r.subject(),
        }
    }
}

/// Encode a version record.
pub fn encode_version(b: &VersionBody) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_nested(tlv::VERSION_RECORD, |w| {
        write_name(w, &b.collection);
        write_parents(w, &b.parents);
        w.write_nested(tlv::TYPE_ID, |w| {
            write_name(w, &b.type_id.name);
            write_nni(w, tlv::REVISION, b.type_id.revision);
        });
        write_audiences(w, tlv::SEAL, &b.seal.any_of);
        write_keep(w, b.keep);
        write_nni(w, tlv::DATED, b.dated.0);
        if let Some(function) = &b.rule {
            w.write_nested(tlv::RULE, |w| {
                write_nni(w, tlv::RULE_KIND, 2);
                write_name(w, function);
            });
        }
        match (&b.sealed, &b.chunks) {
            (Some(s), chunks) => {
                w.write_nested(tlv::SEALED, |w| {
                    write_epoch(w, &s.epoch);
                    if chunks.is_none() {
                        w.write_tlv(tlv::CIPHERTEXT, &s.ciphertext);
                    }
                });
                if let Some(c) = chunks {
                    write_chunks(w, c);
                }
            }
            (None, Some(c)) => write_chunks(w, c),
            (None, None) => write_payload(w, &b.fields, &b.op),
        }
    });
    w.finish()
}

fn write_payload(w: &mut TlvWriter, fields: &Content, op: &[u8]) {
    write_fields(w, fields);
    w.write_tlv(tlv::MERGE_OP, op);
}

fn write_fields(w: &mut TlvWriter, fields: &Content) {
    w.write_nested(tlv::FIELDS, |w| {
        for (name, value) in fields.fields() {
            w.write_nested(tlv::FIELD, |w| {
                w.write_tlv(tlv::FIELD_NAME, name.as_bytes());
                w.write_tlv(tlv::FIELD_VALUE, value);
            });
        }
    });
}

fn write_chunks(w: &mut TlvWriter, c: &ChunksBody) {
    w.write_nested(tlv::CHUNKS, |w| {
        write_nni(w, tlv::SIZE, c.size);
        w.write_tlv(tlv::DIGEST, &c.root);
    });
}

/// What a sealed version's ciphertext carries: its `Fields` and `MergeOp`
/// TLVs, as an unsealed version carries them.
pub fn encode_payload(fields: &Content, op: &[u8]) -> Bytes {
    let mut w = TlvWriter::new();
    write_payload(&mut w, fields, op);
    w.finish()
}

/// Decode an opened payload ([`encode_payload`]).
pub fn decode_payload(bytes: Bytes) -> Result<(Content, Bytes), WireError> {
    let (mut fields, mut op) = (None, None);
    each(bytes, |typ, v| {
        match typ {
            tlv::FIELDS => fields = Some(read_fields(v)?),
            tlv::MERGE_OP => op = Some(v),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    match (fields, op) {
        (Some(f), Some(o)) => Ok((f, o)),
        _ => Err(bad("a sealed payload carries fields and a merge op")),
    }
}

fn write_keep(w: &mut TlvWriter, keep: Keep) {
    w.write_nested(tlv::KEEP, |w| match keep {
        Keep::Forever => w.write_tlv(tlv::KEEP_FOREVER, &[]),
    });
}

fn read_keep(v: Bytes) -> Result<Option<Keep>, WireError> {
    let mut keep = None;
    each(v, |t, _| {
        keep = Some(match t {
            tlv::KEEP_FOREVER => Keep::Forever,
            _ => return Ok(false),
        });
        Ok(true)
    })?;
    Ok(keep)
}

/// Encode a members record.
pub fn encode_members(b: &MembersBody) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_nested(tlv::MEMBERS_RECORD, |w| {
        write_name(w, &b.collection);
        if b.folder {
            w.write_tlv(tlv::FOLDER, &[]);
        }
        write_nni(w, tlv::REVISION, b.revision);
        w.write_nested(tlv::RULE, |w| match &b.rule {
            Rule::Log => write_nni(w, tlv::RULE_KIND, 1),
            Rule::Merge { function } => {
                write_nni(w, tlv::RULE_KIND, 2);
                write_name(w, function);
            }
        });
        w.write_nested(tlv::WRITERS, |w| {
            for p in &b.writers {
                write_name(w, p);
            }
        });
        write_audiences(w, tlv::READERS, &b.readers);
        if !b.cuts.is_empty() {
            w.write_nested(tlv::CUTS, |w| {
                for c in &b.cuts {
                    w.write_nested(tlv::CUT, |w| {
                        write_name(w, &c.of);
                        // A collection's record keeps its own versions only.
                        let written = |coll: &Name| b.folder || *coll == b.collection;
                        let bound: BTreeSet<&Name> = c
                            .accept
                            .iter()
                            .filter(|(coll, _, _)| written(coll))
                            .flat_map(|(coll, key, _)| c.accept.manifests(coll, key))
                            .collect();
                        for root in bound {
                            w.write_nested(tlv::CUT_BYTES, |w| write_name(w, root));
                        }
                        for (coll, accepted) in c.accept.collections() {
                            match b.folder {
                                // A collection's own versions, bare.
                                false if *coll == b.collection => write_kept(w, accepted),
                                false => {}
                                true => w.write_nested(tlv::CUT_IN, |w| {
                                    write_name(w, coll);
                                    write_kept(w, accepted);
                                }),
                            }
                        }
                    });
                }
            });
        }
        if let (Some(e), Some(check)) = (&b.epoch, &b.key_check) {
            write_epoch(w, e);
            w.write_tlv(tlv::KEY_CHECK, check);
        }
        if let Some(since) = &b.since {
            w.write_nested(tlv::RULE_SINCE, |w| write_frontier(w, since));
        }
        if let Some(p) = &b.parent {
            write_nni(w, tlv::SEQ, p.revision.0);
            w.write_tlv(tlv::DIGEST, &p.digest);
        }
    });
    w.finish()
}

/// Encode any log record.
pub fn encode_record(r: &Record) -> Bytes {
    match r {
        Record::Version(b) => encode_version(b),
        Record::Members(b) => encode_members(b),
        Record::Intro(r) => r.encode(),
    }
}

/// Decode a log entry's Content.
pub fn decode_record(content: Bytes) -> Result<Record, WireError> {
    let mut r = TlvReader::new(content);
    let (typ, value) = r.read_tlv().map_err(|e| bad(format!("bad TLV: {e:?}")))?;
    if !r.is_empty() {
        return Err(bad("a log entry carries one record"));
    }
    match typ {
        tlv::VERSION_RECORD => decode_version(value).map(Record::Version),
        tlv::MEMBERS_RECORD => decode_members(value).map(Record::Members),
        tlv::INTRO_OFFER | tlv::INTRO_USED => {
            crate::intro::IntroRecord::decode(typ, value).map(Record::Intro)
        }
        other => Err(bad(format!("{other:#x} is not a log record"))),
    }
}

fn decode_version(value: Bytes) -> Result<VersionBody, WireError> {
    let mut collection = None;
    let mut parents = None;
    let mut type_id = None;
    let mut seal = None;
    let mut keep = None;
    let mut dated = None;
    let mut fields = None;
    let mut op = None;
    let mut sealed = None;
    let mut chunks = None;
    let mut rule = None;
    each(value, |typ, v| {
        match typ {
            tlv_type::NAME => collection = Some(read_name(v)?),
            tlv::FRONTIER => parents = Some(read_parents(v)?),
            tlv::TYPE_ID => {
                let (mut name, mut rev) = (None, None);
                each(v, |t, v| {
                    match t {
                        tlv_type::NAME => name = Some(read_name(v)?),
                        tlv::REVISION => rev = Some(read_nni(&v)?),
                        _ => return Ok(false),
                    }
                    Ok(true)
                })?;
                let (Some(name), Some(revision)) = (name, rev) else {
                    return Err(bad("a type names a type and a revision"));
                };
                type_id = Some(TypeId { name, revision });
            }
            tlv::SEAL => {
                seal = Some(Seal {
                    any_of: read_audiences(v)?,
                })
            }
            tlv::KEEP => keep = read_keep(v)?,
            tlv::DATED => dated = Some(Timestamp(read_nni(&v)?)),
            tlv::RULE => {
                if rule.is_some() {
                    return Err(bad("a version names one rule"));
                }
                rule = Some(read_made_under(v)?);
            }
            tlv::FIELDS => fields = Some(read_fields(v)?),
            tlv::MERGE_OP => op = Some(v),
            tlv::SEALED => {
                let (mut epoch, mut ciphertext) = (None, None);
                each(v, |t, v| {
                    match t {
                        tlv::SEAL_EPOCH => epoch = Some(read_epoch(v)?),
                        tlv::CIPHERTEXT => ciphertext = Some(v),
                        _ => return Ok(false),
                    }
                    Ok(true)
                })?;
                let Some(epoch) = epoch else {
                    return Err(bad("a sealed payload names its epoch"));
                };
                sealed = Some((epoch, ciphertext));
            }
            tlv::CHUNKS => {
                let (mut size, mut root) = (None, None);
                each(v, |t, v| {
                    match t {
                        tlv::SIZE => size = Some(read_nni(&v)?),
                        tlv::DIGEST => root = Some(read_digest(&v)?),
                        _ => return Ok(false),
                    }
                    Ok(true)
                })?;
                let (Some(size), Some(root)) = (size, root) else {
                    return Err(bad("a payload in pieces has a size and a root digest"));
                };
                if size <= INLINE_MAX as u64 {
                    return Err(bad(format!(
                        "a payload of {size} octets travels inline, not in pieces"
                    )));
                }
                if size > PAYLOAD_MAX {
                    return Err(bad(format!(
                        "a payload of {size} octets is larger than the {PAYLOAD_MAX} a version \
                         carries"
                    )));
                }
                chunks = Some(ChunksBody { size, root });
            }
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    let missing = |what| bad(format!("a version record has {what}"));
    let sealed = match (sealed, &chunks) {
        (None, _) => None,
        (Some((epoch, Some(ciphertext))), None) => Some(SealedBody { epoch, ciphertext }),
        (Some((epoch, None)), Some(_)) => Some(SealedBody {
            epoch,
            ciphertext: Bytes::new(),
        }),
        (Some((_, None)), None) => return Err(bad("a sealed payload has a ciphertext")),
        (Some((_, Some(_))), Some(_)) => {
            return Err(bad("a payload in pieces has no ciphertext in its record"));
        }
    };
    let elsewhere = sealed.is_some() || chunks.is_some();
    let (fields, op) = match (fields, op, elsewhere) {
        (None, None, true) => (Content::new(), Bytes::new()),
        (Some(f), Some(o), false) => (f, o),
        (_, _, true) => {
            return Err(bad(
                "a sealed version or one in pieces carries its fields only there",
            ));
        }
        (None, _, false) => return Err(missing("fields")),
        (_, None, false) => return Err(missing("a merge op")),
    };
    Ok(VersionBody {
        collection: collection.ok_or_else(|| missing("a collection"))?,
        parents: parents.ok_or_else(|| missing("parents"))?,
        type_id: type_id.ok_or_else(|| missing("a type"))?,
        seal: seal.ok_or_else(|| missing("a seal"))?,
        keep: keep.ok_or_else(|| missing("a keep"))?,
        dated: dated.ok_or_else(|| missing("a date"))?,
        rule,
        fields,
        op,
        sealed,
        chunks,
    })
}

fn read_fields(v: Bytes) -> Result<Content, WireError> {
    let mut c = Content::new();
    each(v, |t, v| {
        if t != tlv::FIELD {
            return Ok(false);
        }
        let (mut name, mut value) = (None, None);
        each(v, |t, v| {
            match t {
                tlv::FIELD_NAME => {
                    name = Some(
                        String::from_utf8(v.to_vec()).map_err(|_| bad("a field name is UTF-8"))?,
                    )
                }
                tlv::FIELD_VALUE => value = Some(v),
                _ => return Ok(false),
            }
            Ok(true)
        })?;
        let (Some(name), Some(value)) = (name, value) else {
            return Err(bad("a field has a name and a value"));
        };
        c = std::mem::take(&mut c).with(name, value);
        Ok(true)
    })?;
    Ok(c)
}

fn decode_members(value: Bytes) -> Result<MembersBody, WireError> {
    let mut collection = None;
    let mut folder = false;
    let mut revision = None;
    let mut rule = None;
    let mut writers = None;
    let mut readers = None;
    let mut cuts = Vec::new();
    let mut epoch = None;
    let mut key_check = None;
    let mut since = None;
    let (mut parent_revision, mut parent_digest) = (None, None);
    each(value, |typ, v| {
        match typ {
            tlv_type::NAME => collection = Some(read_name(v)?),
            tlv::FOLDER => {
                let first = collection.is_some()
                    && !folder
                    && revision.is_none()
                    && rule.is_none()
                    && writers.is_none()
                    && readers.is_none();
                if !first || !v.is_empty() {
                    return Err(bad(
                        "a members record's Folder is empty and comes once, right after its Name",
                    ));
                }
                folder = true;
            }
            tlv::REVISION => revision = Some(read_nni(&v)?),
            tlv::RULE => {
                let (mut kind, mut function) = (None, None);
                each(v, |t, v| {
                    match t {
                        tlv::RULE_KIND => kind = Some(read_nni(&v)?),
                        tlv_type::NAME => function = Some(read_name(v)?),
                        _ => return Ok(false),
                    }
                    Ok(true)
                })?;
                rule = Some(match (kind, function) {
                    (Some(1), None) => Rule::Log,
                    (Some(2), Some(function)) => Rule::Merge { function },
                    _ => return Err(bad("a rule is log, or merge with a function")),
                });
            }
            tlv::WRITERS => {
                let mut list = Vec::new();
                each(v, |t, v| {
                    if t != tlv_type::NAME {
                        return Ok(false);
                    }
                    list.push(read_name(v)?);
                    Ok(true)
                })?;
                writers = Some(list);
            }
            tlv::READERS => readers = Some(read_audiences(v)?),
            tlv::CUTS => {
                let subject = collection
                    .as_ref()
                    .ok_or_else(|| bad("a members record's cuts follow its name"))?;
                each(v, |t, v| {
                    if t != tlv::CUT {
                        return Ok(false);
                    }
                    cuts.push(read_cut(v, subject, folder)?);
                    Ok(true)
                })?;
            }
            tlv::SEAL_EPOCH => epoch = Some(read_epoch(v)?),
            tlv::KEY_CHECK => {
                key_check = Some(read_digest(&v).map_err(|_| bad("a key check is 32 octets"))?)
            }
            tlv::RULE_SINCE => {
                each(v, |t, v| {
                    if t != tlv::FRONTIER {
                        return Ok(false);
                    }
                    since = Some(read_frontier(v)?);
                    Ok(true)
                })?;
            }
            tlv::SEQ => parent_revision = Some(read_nni(&v)?),
            tlv::DIGEST => {
                parent_digest = Some(read_digest(&v).map_err(|_| bad("a digest is 32 octets"))?)
            }
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    let missing = |what| bad(format!("a members record has {what}"));
    if epoch.is_some() != key_check.is_some() {
        return Err(bad(
            "a members record that names an epoch carries its key check, and only then",
        ));
    }
    let revision = revision.ok_or_else(|| missing("a revision"))?;
    let parent = match (parent_revision, parent_digest) {
        (None, None) => None,
        (Some(r), Some(digest)) if r.checked_add(1) == Some(revision) => Some(Parent {
            revision: Seq(r),
            digest,
        }),
        _ => {
            return Err(bad(
                "a members record's parent is a revision one below its own and a digest",
            ));
        }
    };
    Ok(MembersBody {
        collection: collection.ok_or_else(|| missing("a collection"))?,
        folder,
        revision,
        rule: rule.ok_or_else(|| missing("a rule"))?,
        writers: writers.ok_or_else(|| missing("writers"))?,
        readers: readers.ok_or_else(|| missing("readers"))?,
        cuts,
        epoch,
        key_check,
        since,
        parent,
    })
}

/// Reads the `Writer` and `Entries` pairs of one collection's versions a
/// cut keeps: keys ascending, once each, each key's ranges ascending and
/// disjoint.
#[derive(Default)]
struct KeptReader {
    writer: Option<Writer>,
    last: Option<Writer>,
}

impl KeptReader {
    /// Take a `Writer` or `Entries` TLV of collection `c` into `accept`.
    fn take(&mut self, t: u64, v: Bytes, c: &Name, accept: &mut Accepted) -> Result<(), WireError> {
        if t == tlv::WRITER {
            if self.writer.is_some() {
                return Err(bad("a cut's writer is followed by its entries"));
            }
            self.writer = Some(Writer::new(read_writer(v)?));
            return Ok(());
        }
        let w = self
            .writer
            .take()
            .ok_or_else(|| bad("a cut's entries follow their writer"))?;
        if self.last.as_ref().is_some_and(|l| *l >= w) {
            return Err(bad("a cut lists its writers once each, ascending"));
        }
        let ranges = read_ranges(v)?;
        check_ranges(&ranges, u64::MAX, usize::MAX)?;
        for (lo, hi) in ranges {
            accept.insert_range(c, &w, lo, hi);
        }
        self.last = Some(w);
        Ok(())
    }

    /// Every writer read has its entries.
    fn end(&self) -> Result<(), WireError> {
        match self.writer {
            Some(_) => Err(bad("a cut's writer is followed by its entries")),
            None => Ok(()),
        }
    }
}

/// Decode one `Cut` of the members record of `subject` — a folder's when
/// `folder`: its prefix, the manifests binding what it keeps to its bytes
/// (`CutBytes`, ascending, once each), then of a collection's record the
/// `Writer` and `Entries` pairs of the versions kept in it, of a folder's
/// one `CutIn` per collection strictly under it, collections ascending.
/// A cut that keeps nothing binds nothing: it carries no `CutBytes`.
fn read_cut(value: Bytes, subject: &Name, folder: bool) -> Result<CutBody, WireError> {
    let mut of = None;
    let mut accept = Accepted::new();
    let mut own = KeptReader::default();
    let mut last: Option<Name> = None;
    let mut bytes: Vec<Name> = Vec::new();
    each(value, |t, v| {
        match t {
            tlv_type::NAME if of.is_none() => of = Some(read_name(v)?),
            tlv::CUT_BYTES => {
                if of.is_none() || !accept.is_empty() || own.writer.is_some() || last.is_some() {
                    return Err(bad(
                        "a cut's CutBytes come right after its prefix, before what it keeps",
                    ));
                }
                let root = read_full_name(v)?;
                if bytes.last().is_some_and(|l| *l >= root) {
                    return Err(bad("a cut lists its CutBytes once each, ascending"));
                }
                bytes.push(root);
            }
            tlv::WRITER | tlv::ENTRIES if !folder => own.take(t, v, subject, &mut accept)?,
            tlv::WRITER | tlv::ENTRIES => {
                return Err(bad(
                    "a folder record's cut lists the versions it keeps per collection, in CutIn",
                ));
            }
            tlv::CUT_IN if folder => {
                let mut c = None;
                let mut kept = KeptReader::default();
                each(v, |t, v| {
                    match (t, &c) {
                        (tlv_type::NAME, None) => {
                            let n = read_name(v)?;
                            if n.len() <= subject.len() || !n.has_prefix(subject) {
                                return Err(bad(
                                    "a folder cut's CutIn names a collection under the folder",
                                ));
                            }
                            c = Some(n);
                        }
                        (tlv::WRITER | tlv::ENTRIES, Some(c)) => kept.take(t, v, c, &mut accept)?,
                        (tlv::WRITER | tlv::ENTRIES, None) => {
                            return Err(bad("a CutIn names its collection first"));
                        }
                        _ => return Ok(false),
                    }
                    Ok(true)
                })?;
                kept.end()?;
                let c = c.ok_or_else(|| bad("a CutIn names its collection"))?;
                if last.as_ref().is_some_and(|l| *l >= c) {
                    return Err(bad("a cut lists its collections once each, ascending"));
                }
                last = Some(c);
            }
            tlv::CUT_IN => {
                return Err(bad(
                    "a collection record's cut lists the versions it keeps in the collection, \
                     never a CutIn",
                ));
            }
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    own.end()?;
    let of = of.ok_or_else(|| bad("a cut names a prefix"))?;
    if !bytes.is_empty() && accept.is_empty() {
        return Err(bad(
            "a cut's CutBytes bind the versions it keeps; this cut keeps none",
        ));
    }
    for root in &bytes {
        accept.bind(root);
    }
    Ok(CutBody { of, accept })
}

/// Read a `Writer` TLV's value: one Name, a key.
pub(crate) fn read_writer(v: Bytes) -> Result<Name, WireError> {
    let mut r = TlvReader::new(v);
    let (t, v) = r.read_tlv().map_err(|e| bad(format!("bad TLV: {e:?}")))?;
    if t != tlv_type::NAME || !r.is_empty() {
        return Err(bad("a writer is a key name"));
    }
    read_name(v)
}

/// Read a `CutBytes` TLV's value: one Name, a packet's full name, ending
/// in its 32-octet implicit digest.
fn read_full_name(v: Bytes) -> Result<Name, WireError> {
    let mut r = TlvReader::new(v);
    let (t, v) = r.read_tlv().map_err(|e| bad(format!("bad TLV: {e:?}")))?;
    if t != tlv_type::NAME || !r.is_empty() {
        return Err(bad("a CutBytes is one name"));
    }
    let name = read_name(v)?;
    match name.components().last() {
        Some(c) if c.typ == tlv_type::IMPLICIT_SHA256 && c.value.len() == 32 => Ok(name),
        _ => Err(bad(
            "a CutBytes names a manifest packet by its full name, ending in its implicit digest",
        )),
    }
}

/// Check seq ranges read from a record: ascending and disjoint, none above
/// `head`, at most `most` seqs in all.
fn check_ranges(ranges: &[(u64, u64)], head: u64, most: usize) -> Result<(), WireError> {
    let mut prev: Option<u64> = None;
    let mut count: u128 = 0;
    for (lo, hi) in ranges {
        if prev.is_some_and(|p| *lo <= p) {
            return Err(bad("seq ranges are ascending and disjoint"));
        }
        if *hi > head {
            return Err(bad(format!(
                "a seq range reaches {hi}, above the node's head {head}"
            )));
        }
        count += u128::from(hi - lo) + 1;
        prev = Some(*hi);
    }
    if count > most as u128 {
        return Err(bad(format!(
            "a node lists {count} seqs; at most {most} are listed in one node"
        )));
    }
    Ok(())
}

// ---- summaries --------------------------------------------------------------------------------

/// A reference to a child summary node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChildRef {
    /// The child's last name component.
    pub component: NameComponent,
    /// The writer's highest seq in the child's subtree.
    pub head: u64,
    /// The implicit digest of the child's summary packet.
    pub digest: [u8; 32],
}

/// A reference to a page of children.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageRef {
    /// The bucket (0–15).
    pub bucket: u8,
    /// The writer's highest seq in the page's children.
    pub head: u64,
    /// The implicit digest of the page packet.
    pub digest: [u8; 32],
}

/// A node's children: inline, or paged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Branches {
    /// Up to [`PAGE_FANOUT`] children, by component.
    Children(Vec<ChildRef>),
    /// Pages, by bucket.
    Pages(Vec<PageRef>),
}

/// A summary node (or page).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeBody {
    /// The collection or folder summarised.
    pub subject: Name,
    /// The writer (key) whose log it summarises.
    pub writer: Name,
    /// The writer's highest seq in the subtree (or page).
    pub head: u64,
    /// For a page, the buckets from the node to it.
    pub page: Option<Bytes>,
    /// The writer's version entries directly in `subject`.
    pub entries: Vec<(u64, u64)>,
    /// The writer's members records of `subject`.
    pub members: Vec<(u64, u64)>,
    /// Sub-collections.
    pub branches: Branches,
}

/// Encode a summary node.
pub fn encode_node(b: &NodeBody) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_nested(tlv::SUMMARY_NODE, |w| {
        write_name(w, &b.subject);
        w.write_nested(tlv::WRITER, |w| write_name(w, &b.writer));
        write_nni(w, tlv::SEQ, b.head);
        if let Some(path) = &b.page {
            w.write_tlv(tlv::PAGE_PATH, path);
        }
        write_ranges(w, tlv::ENTRIES, &b.entries);
        write_ranges(w, tlv::MEMBERS_ENTRIES, &b.members);
        match &b.branches {
            Branches::Children(c) if c.is_empty() => {}
            Branches::Children(c) => w.write_nested(tlv::CHILDREN, |w| {
                for child in c {
                    w.write_nested(tlv::CHILD, |w| {
                        write_name(w, &Name::from_components([child.component.clone()]));
                        write_nni(w, tlv::SEQ, child.head);
                        w.write_tlv(tlv::DIGEST, &child.digest);
                    });
                }
            }),
            Branches::Pages(p) => w.write_nested(tlv::PAGES, |w| {
                for page in p {
                    w.write_nested(tlv::PAGE, |w| {
                        write_nni(w, tlv::BUCKET, u64::from(page.bucket));
                        write_nni(w, tlv::SEQ, page.head);
                        w.write_tlv(tlv::DIGEST, &page.digest);
                    });
                }
            }),
        }
    });
    w.finish()
}

/// Decode a summary node.
pub fn decode_node(content: Bytes) -> Result<NodeBody, WireError> {
    let mut r = TlvReader::new(content);
    let (typ, value) = r.read_tlv().map_err(|e| bad(format!("bad TLV: {e:?}")))?;
    if typ != tlv::SUMMARY_NODE || !r.is_empty() {
        return Err(bad("a summary packet carries one summary node"));
    }
    let mut subject = None;
    let mut writer = None;
    let mut head = None;
    let mut page = None;
    let mut entries = Vec::new();
    let mut members = Vec::new();
    let mut branches = Branches::Children(Vec::new());
    each(value, |typ, v| {
        match typ {
            tlv_type::NAME => subject = Some(read_name(v)?),
            tlv::WRITER => writer = Some(read_writer(v)?),
            tlv::SEQ => head = Some(read_nni(&v)?),
            tlv::PAGE_PATH => page = Some(v),
            tlv::ENTRIES => entries = read_ranges(v)?,
            tlv::MEMBERS_ENTRIES => members = read_ranges(v)?,
            tlv::CHILDREN => {
                let mut list = Vec::new();
                each(v, |t, v| {
                    if t != tlv::CHILD {
                        return Ok(false);
                    }
                    let (mut comp, mut head, mut digest) = (None, None, None);
                    each(v, |t, v| {
                        match t {
                            tlv_type::NAME => {
                                let n = read_name(v)?;
                                match n.components() {
                                    [c] => comp = Some(c.clone()),
                                    _ => return Err(bad("a child is named by one component")),
                                }
                            }
                            tlv::SEQ => head = Some(read_nni(&v)?),
                            tlv::DIGEST => digest = Some(read_digest(&v)?),
                            _ => return Ok(false),
                        }
                        Ok(true)
                    })?;
                    let (Some(component), Some(head), Some(digest)) = (comp, head, digest) else {
                        return Err(bad("a child has a component, a head and a digest"));
                    };
                    list.push(ChildRef {
                        component,
                        head,
                        digest,
                    });
                    Ok(true)
                })?;
                branches = Branches::Children(list);
            }
            tlv::PAGES => {
                let mut list = Vec::new();
                each(v, |t, v| {
                    if t != tlv::PAGE {
                        return Ok(false);
                    }
                    let (mut bucket, mut head, mut digest) = (None, None, None);
                    each(v, |t, v| {
                        match t {
                            tlv::BUCKET => bucket = Some(read_nni(&v)?),
                            tlv::SEQ => head = Some(read_nni(&v)?),
                            tlv::DIGEST => digest = Some(read_digest(&v)?),
                            _ => return Ok(false),
                        }
                        Ok(true)
                    })?;
                    let (Some(bucket @ 0..=15), Some(head), Some(digest)) = (bucket, head, digest)
                    else {
                        return Err(bad("a page has a bucket 0–15, a head and a digest"));
                    };
                    list.push(PageRef {
                        bucket: bucket as u8,
                        head,
                        digest,
                    });
                    Ok(true)
                })?;
                branches = Branches::Pages(list);
            }
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    let missing = |what| bad(format!("a summary node has {what}"));
    let head = head.ok_or_else(|| missing("a head"))?;
    check_ranges(&entries, head, NODE_SEQS)?;
    check_ranges(&members, head, NODE_SEQS - seqs_in(&entries))?;
    Ok(NodeBody {
        subject: subject.ok_or_else(|| missing("a subject"))?,
        writer: writer.ok_or_else(|| missing("a writer"))?,
        head,
        page,
        entries,
        members,
        branches,
    })
}

/// The bucket of `component` at page depth `depth`: nibble `depth` of
/// SHA-256 over the component's TLV encoding.
pub fn bucket_of(component: &NameComponent, depth: usize) -> u8 {
    use sha2::{Digest, Sha256};
    let mut w = TlvWriter::new();
    w.write_tlv(component.typ, &component.value);
    let h = Sha256::digest(w.finish());
    let byte = h[(depth / 2) % 32];
    if depth.is_multiple_of(2) {
        byte >> 4
    } else {
        byte & 0x0F
    }
}

/// The implicit digest of a packet: SHA-256 over its whole wire encoding.
pub fn implicit_digest(wire: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(wire).into()
}

/// The digest of what the signer of `wire` signed: SHA-256 over its signed region, the Name
/// through the `SignatureInfo`, which excludes the signature value; `None` for a packet that
/// does not decode as Data.
///
/// Two packets with one signed digest are one signed object. They differ only in the signature
/// value, which an ECDSA signature leaves malleable (`S` and `n - S` both verify; a signer that
/// randomizes signs the same content to another value each time), and which no one but the
/// signer's key may be held to. Equivocation is decided by this digest; the implicit digest
/// ([`implicit_digest`]) names exact wire bytes.
pub fn signed_digest(wire: &Bytes) -> Option<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let data = ndn_packet::Data::decode(wire.clone()).ok()?;
    Some(Sha256::digest(data.signed_region()).into())
}

/// How many seqs `ranges` (checked: disjoint, at most [`NODE_SEQS`]) hold.
fn seqs_in(ranges: &[(u64, u64)]) -> usize {
    ranges.iter().map(|(lo, hi)| (hi - lo) as usize + 1).sum()
}

/// The seqs of ranges, ascending.
pub(crate) fn seqs_of(ranges: &[(u64, u64)]) -> impl Iterator<Item = u64> + '_ {
    ranges.iter().flat_map(|(lo, hi)| *lo..=*hi)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn owns_is_a_device_prefix_not_a_component_prefix() {
        let w = |s: &str| Writer::new(n(s));
        let notes = n("/alice/32=data/notes/p1");
        // Every device of the namespace owns it, the namespace's own key too.
        for key in [
            "/alice/laptop/KEY/1",
            "/alice/phone/KEY/7",
            "/alice/member/tablet/KEY/2",
            "/alice/KEY/1",
        ] {
            assert!(owns(&notes, &w(key)), "{key} owns {notes}");
        }
        // Another namespace's device, one whose name only starts alike, and
        // a name that is no key name do not.
        for key in [
            "/bob/laptop/KEY/1",
            "/alicia/laptop/KEY/1",
            "/alice/laptop",
            "/alice/laptop/KEY",
        ] {
            assert!(!owns(&notes, &w(key)), "{key} does not own {notes}");
        }
        // The namespace ends at the marker, however many components it has:
        // the folder and every collection under it alike.
        let home = n("/home/bob/32=data/x");
        assert!(owns(&home, &w("/home/bob/member/laptop/KEY/1")));
        assert!(!owns(&home, &w("/home/member/hub/KEY/1")));
        assert!(owns(
            &n("/home/32=data/x"),
            &w("/home/bob/member/laptop/KEY/1")
        ));
        assert!(owns(&n("/alice/32=data"), &w("/alice/laptop/KEY/1")));
        // A name that is no data name has no owner.
        assert!(!owns(&n("/alice/notes"), &w("/alice/laptop/KEY/1")));
    }

    /// A `32=ask` proof made for one protocol never verifies as another's:
    /// the same octets bound under two protocols name two proofs (spec
    /// §16.3).
    #[test]
    fn a_proof_binding_of_one_protocol_never_verifies_as_another() {
        let asker = n("/alice/laptop");
        let parts: [&[u8]; 2] = [&n("/alice/repo").encode_to_tlv(), b"the same fields"];
        for p in AskProtocol::ALL {
            let proof = ask_name(&asker, &ask_binding(p, &parts));
            for q in AskProtocol::ALL.into_iter().filter(|q| *q != p) {
                assert_ne!(
                    proof,
                    ask_name(&asker, &ask_binding(q, &parts)),
                    "a {p:?} proof verifies as a {q:?} proof"
                );
            }
        }
        for (i, p) in AskProtocol::ALL.into_iter().enumerate() {
            for q in &AskProtocol::ALL[i + 1..] {
                assert!(
                    !p.label().starts_with(q.label()) && !q.label().starts_with(p.label()),
                    "no label is a prefix of another: {p:?} {q:?}"
                );
            }
        }
    }

    #[test]
    fn names_parse_back() {
        for (d, ns, c) in [
            ("/alice/laptop", "/alice", "/alice/32=data/notes/trip"),
            (
                "/home/bob/member/phone",
                "/home/bob",
                "/home/bob/32=data/notes/trip",
            ),
            // A writer of another namespace: the log entry names both.
            (
                "/home/bob/member/phone",
                "/alice",
                "/alice/32=data/docs/plan",
            ),
            // A path may end in a sequence number; the head still parses.
            ("/alice/laptop", "/alice", "/alice/32=data/sensor/seq=4"),
        ] {
            let (d, ns, c) = (n(d), n(ns), n(c));
            assert_eq!(namespace_of(&c), Some(ns.clone()), "{c}");
            let log = log_name(&d, Some(&c), 9);
            assert_eq!(
                parse_log_name(&log),
                Some(LogName {
                    device: d.clone(),
                    subject: Some(c.clone()),
                    seq: 9
                }),
                "{log}"
            );
            let snap = log_name(&d, None, 3);
            assert_eq!(parse_log_name(&snap).unwrap().subject, None);
            let node = parse_summary_name(&node_name(&d, &c, 5)).unwrap();
            assert_eq!(
                (&node.device, &node.subject, node.head, &node.page),
                (&d, &c, Some(5), &None)
            );
            let page = page_name(&d, &c, &[3, 10], 7);
            let p = parse_summary_name(&page).unwrap();
            assert_eq!((&p.device, &p.subject), (&d, &c));
            assert_eq!(p.page.as_deref(), Some(&[3u8, 10][..]));
            assert_eq!(p.head, Some(7));
            let root = parse_summary_name(&root_prefix(&d, &ns)).unwrap();
            assert_eq!(
                (root.device, root.subject, root.head, root.page),
                (d.clone(), ns.clone(), None, None)
            );
            let signed = parse_summary_name(&root_name(&d, &ns, 11)).unwrap();
            assert_eq!((signed.subject, signed.head), (ns.clone(), Some(11)));
            // A root is named only with its marker, and no node name lies
            // under a root's discovery name: a prefix Interest for a root
            // can be answered by a root alone.
            assert_eq!(parse_summary_name(&node_name(&d, &ns, 11)), None);
            let folder_node = node_name(&d, &data_folder(&ns), 11);
            assert!(!folder_node.has_prefix(&root_prefix(&d, &ns)));
            // The root's one child, the folder of every collection.
            let folder = data_folder(&ns);
            assert_eq!(folder, n(&format!("{ns}/32=data")));
            assert_eq!(subject_namespace(&folder), Some(ns.clone()));
            assert_eq!(subject_namespace(&ns), Some(ns.clone()));
            assert_eq!(subject_namespace(&c), Some(ns.clone()));
            assert!(is_data_name(&folder) && !is_collection_name(&folder));
        }
        assert_eq!(
            device_of(&n("/home/bob/member/phone/KEY/1")),
            Some(n("/home/bob/member/phone"))
        );
    }

    #[test]
    fn a_name_without_its_marker_is_no_collection() {
        for (name, why) in [
            ("/alice/notes/trip", NotDataName::NoMarker),
            ("/home/bob/notes", NotDataName::NoMarker),
            ("/32=data/notes", NotDataName::NoNamespace),
            ("/alice/seq=3/32=data/notes", NotDataName::NoNamespace),
            ("/alice/32=data", NotDataName::NoPath),
            ("/alice/32=data/notes/32=data/x", NotDataName::OtherKeyword),
            ("/alice/32=data/notes/32=state", NotDataName::OtherKeyword),
        ] {
            assert_eq!(check_collection_name(&n(name)), Err(why), "{name}");
            assert_eq!(
                namespace_of(&n(name)).is_some(),
                why == NotDataName::NoPath,
                "{name}"
            );
        }
        let d = n("/alice/laptop");
        // An unmarked subject is no log entry's collection.
        assert_eq!(
            parse_log_name(&log_name(&d, Some(&n("/alice/notes")), 1)),
            None
        );
        // An unmarked subject is a namespace: this names the root of
        // `/alice/notes`, never a node of the namespace `/alice`.
        let root =
            parse_summary_name(&n("/alice/laptop/32=summary/alice/notes/32=root/seq=2")).unwrap();
        assert_eq!(subject_namespace(&root.subject), Some(n("/alice/notes")));
        // Without its head a node name is not one (only a root is discovered).
        assert_eq!(
            parse_summary_name(&summary_prefix(&d, &n("/alice/32=data/notes"))),
            None
        );
        // A data subject never takes the root marker.
        assert_eq!(
            parse_summary_name(&root_prefix(&d, &n("/alice/32=data/notes"))),
            None
        );
        // A device name has no keyword: the first 32=log ends it.
        assert_eq!(
            parse_log_name(&n("/alice/32=data/x/32=log/alice/32=data/y/seq=1")),
            None
        );
    }

    #[test]
    fn unknown_even_fields_are_skipped_and_odd_ones_refused() {
        let body = MembersBody {
            collection: n("/alice/32=data/notes"),
            folder: false,
            revision: 1,
            rule: Rule::Merge {
                function: n(crate::merge::NEWEST),
            },
            writers: vec![n("/alice")],
            readers: vec![Audience::Person(n("/alice"))],
            cuts: vec![CutBody {
                of: n("/bob"),
                accept: {
                    let mut a = Accepted::new();
                    for s in [40, 41, 100] {
                        let id = crate::VersionId {
                            writer: Writer::new(n("/bob/laptop/KEY/1")),
                            seq: Seq(s),
                        };
                        a.insert(&n("/alice/32=data/notes"), &id);
                    }
                    a.bind(&manifest_root(1, 5));
                    a
                },
            }],
            epoch: Some(Epoch {
                creator: n("/alice/laptop"),
                seq: Seq(7),
            }),
            key_check: Some([7; 32]),
            since: None,
            parent: None,
        };
        let wire = encode_members(&body);
        let with = |extra: u64| {
            let mut r = TlvReader::new(wire.clone());
            let (_, inner) = r.read_tlv().unwrap();
            let mut w = TlvWriter::new();
            w.write_nested(tlv::MEMBERS_RECORD, |w| {
                w.write_raw(&inner);
                w.write_tlv(extra, b"future");
            });
            w.finish()
        };
        assert_eq!(
            decode_record(wire.clone()),
            Ok(Record::Members(body.clone()))
        );
        // Beyond this revision's numbers: a later revision's fields.
        assert_eq!(
            decode_record(with(0x0580)),
            Ok(Record::Members(body.clone()))
        );
        assert!(decode_record(with(0x0581)).is_err());
        // A record names its parent, of the revision before its own; a
        // parent of any other revision, or half a parent, is refused.
        let parented = MembersBody {
            revision: 2,
            parent: Some(Parent {
                revision: Seq(1),
                digest: [9; 32],
            }),
            ..body.clone()
        };
        assert_eq!(
            decode_record(encode_members(&parented)),
            Ok(Record::Members(parented.clone()))
        );
        let skewed = MembersBody {
            revision: 3,
            ..parented.clone()
        };
        assert!(decode_record(encode_members(&skewed)).is_err());
        let mut w = TlvWriter::new();
        w.write_nested(tlv::MEMBERS_RECORD, |w| {
            let mut r = TlvReader::new(encode_members(&body));
            let (_, inner) = r.read_tlv().unwrap();
            w.write_raw(&inner);
            w.write_tlv(tlv::DIGEST, &[9; 32]);
        });
        assert!(decode_record(w.finish()).is_err());
        // An epoch comes with its key check.
        let unchecked = MembersBody {
            key_check: None,
            ..body
        };
        let mut w = TlvWriter::new();
        w.write_nested(tlv::MEMBERS_RECORD, |w| {
            let mut r = TlvReader::new(encode_members(&unchecked));
            let (_, inner) = r.read_tlv().unwrap();
            w.write_raw(&inner);
            write_epoch(w, unchecked.epoch.as_ref().unwrap());
        });
        assert!(decode_record(w.finish()).is_err());
    }

    #[test]
    fn a_folder_record_parses_back_and_a_reader_that_does_not_know_folder_refuses_it() {
        let body = MembersBody {
            collection: n("/alice/32=data/photos"),
            folder: true,
            revision: 1,
            rule: Rule::Log,
            writers: vec![n("/alice")],
            readers: vec![Audience::Person(n("/alice"))],
            cuts: Vec::new(),
            epoch: Some(Epoch {
                creator: n("/alice/laptop"),
                seq: Seq(3),
            }),
            key_check: Some([3; 32]),
            since: None,
            parent: None,
        };
        let wire = encode_members(&body);
        assert_eq!(
            decode_record(wire.clone()),
            Ok(Record::Members(body.clone()))
        );
        // The same record of the collection is another record.
        let collection = MembersBody {
            folder: false,
            ..body.clone()
        };
        assert_ne!(encode_members(&collection), wire);
        // A reader of the shape before folders knows every field but
        // `Folder`, which is critical: it refuses the record rather than
        // take it as the collection's.
        let mut r = TlvReader::new(wire.clone());
        let (_, inner) = r.read_tlv().unwrap();
        assert!(each(inner.clone(), |t, _| Ok(t != tlv::FOLDER)).is_err());
        // `Folder` comes once, empty, right after the Name.
        let with = |extra: &dyn Fn(&mut TlvWriter)| {
            let mut w = TlvWriter::new();
            w.write_nested(tlv::MEMBERS_RECORD, |w| {
                w.write_raw(&inner);
                extra(w);
            });
            w.finish()
        };
        assert!(decode_record(with(&|w| w.write_tlv(tlv::FOLDER, &[]))).is_err());
        let unplaced = encode_members(&collection);
        let mut r = TlvReader::new(unplaced);
        let (_, plain) = r.read_tlv().unwrap();
        let mut w = TlvWriter::new();
        w.write_nested(tlv::MEMBERS_RECORD, |w| {
            w.write_raw(&plain);
            w.write_tlv(tlv::FOLDER, &[]);
        });
        assert!(decode_record(w.finish()).is_err());
        let mut w = TlvWriter::new();
        w.write_nested(tlv::MEMBERS_RECORD, |w| {
            write_name(w, &body.collection);
            w.write_tlv(tlv::FOLDER, b"x");
        });
        assert!(decode_record(w.finish()).is_err());
    }

    #[test]
    fn a_folder_cut_keeps_each_seq_in_its_own_collection_on_the_wire() {
        let f = n("/alice/32=data/docs");
        let (plan, notes) = (
            n("/alice/32=data/docs/plan"),
            n("/alice/32=data/docs/notes"),
        );
        let bob = |s| crate::VersionId {
            writer: Writer::new(n("/bob/phone/KEY/1")),
            seq: Seq(s),
        };
        let mut accept = Accepted::new();
        accept.insert(&plan, &bob(1));
        accept.insert(&notes, &bob(2));
        accept.bind(&manifest_root(2, 1));
        let body = MembersBody {
            collection: f.clone(),
            folder: true,
            revision: 2,
            rule: Rule::Log,
            writers: vec![n("/alice")],
            readers: Vec::new(),
            cuts: vec![CutBody {
                of: n("/bob"),
                accept,
            }],
            epoch: None,
            key_check: None,
            since: None,
            parent: Some(Parent {
                revision: Seq(1),
                digest: [1; 32],
            }),
        };
        let Ok(Record::Members(back)) = decode_record(encode_members(&body)) else {
            panic!("a folder record with a cut parses back");
        };
        assert_eq!(back, body);
        let kept = &back.cuts[0].accept;
        assert!(kept.contains(&plan, &bob(1)) && kept.contains(&notes, &bob(2)));
        assert!(!kept.contains(&notes, &bob(1)) && !kept.contains(&plan, &bob(2)));
        // A cut of the wrong shape for its record is refused: bare pairs
        // in a folder's, a CutIn in a collection's, a CutIn of a collection
        // outside the folder.
        let record = |folder: bool, collection: &Name, cut: &dyn Fn(&mut TlvWriter)| {
            let mut w = TlvWriter::new();
            w.write_nested(tlv::MEMBERS_RECORD, |w| {
                write_name(w, collection);
                if folder {
                    w.write_tlv(tlv::FOLDER, &[]);
                }
                write_nni(w, tlv::REVISION, 1);
                w.write_nested(tlv::RULE, |w| write_nni(w, tlv::RULE_KIND, 1));
                w.write_nested(tlv::WRITERS, |w| write_name(w, &n("/alice")));
                write_audiences(w, tlv::READERS, &[]);
                w.write_nested(tlv::CUTS, |w| {
                    w.write_nested(tlv::CUT, |w| {
                        write_name(w, &n("/bob"));
                        cut(w);
                    })
                });
            });
            w.finish()
        };
        let pair = |w: &mut TlvWriter| {
            w.write_nested(tlv::WRITER, |w| write_name(w, &n("/bob/phone/KEY/1")));
            write_ranges(w, tlv::ENTRIES, &[(1, 1)]);
        };
        let cut_in = |c: Name| {
            move |w: &mut TlvWriter| {
                w.write_nested(tlv::CUT_IN, |w| {
                    write_name(w, &c);
                    pair(w);
                })
            }
        };
        assert!(decode_record(record(true, &f, &cut_in(plan.clone()))).is_ok());
        assert!(decode_record(record(false, &plan, &pair)).is_ok());
        assert!(decode_record(record(true, &f, &pair)).is_err());
        assert!(decode_record(record(false, &plan, &cut_in(plan.clone()))).is_err());
        for outside in [f.clone(), n("/alice/32=data/home/list")] {
            assert!(decode_record(record(true, &f, &cut_in(outside))).is_err());
        }
        // `CutIn` is critical: a reader that does not know it refuses.
        assert_eq!(tlv::CUT_IN % 2, 1);
    }

    /// The full name of the root of the cut manifest of `/alice/laptop`'s
    /// members record of seq `seq` (spec §16.1), of digest `[d; 32]`.
    fn manifest_root(seq: u64, d: u8) -> Name {
        let record = log_name(&n("/alice/laptop"), Some(&n("/alice/32=data/notes")), seq);
        cut_bytes_prefix(&record)
            .append_segment(0)
            .append_implicit_digest([d; 32])
    }

    #[test]
    fn a_cut_names_the_manifests_binding_what_it_keeps_right_after_its_prefix() {
        let c = n("/alice/32=data/notes");
        let mut accept = Accepted::new();
        for (key, seq) in [("/bob/phone/KEY/1", 3), ("/bob/laptop/KEY/1", 8)] {
            let id = crate::VersionId {
                writer: Writer::new(n(key)),
                seq: Seq(seq),
            };
            accept.insert(&c, &id);
        }
        let (one, two) = (manifest_root(2, 1), manifest_root(3, 2));
        accept.bind(&two);
        accept.bind(&one);
        let body = MembersBody {
            collection: c.clone(),
            folder: false,
            revision: 3,
            rule: Rule::Log,
            writers: vec![n("/alice")],
            readers: Vec::new(),
            cuts: vec![CutBody {
                of: n("/bob"),
                accept,
            }],
            epoch: None,
            key_check: None,
            since: None,
            parent: Some(Parent {
                revision: Seq(2),
                digest: [1; 32],
            }),
        };
        let Ok(Record::Members(back)) = decode_record(encode_members(&body)) else {
            panic!("a record with a bound cut parses back");
        };
        assert_eq!(back, body);
        let kept = &back.cuts[0].accept;
        for key in ["/bob/phone/KEY/1", "/bob/laptop/KEY/1"] {
            let roots: Vec<&Name> = kept.manifests(&c, &Writer::new(n(key))).collect();
            assert_eq!(
                roots,
                [&one, &two],
                "every manifest binds every key it keeps"
            );
        }
        // A cut of hand-made fields, in a collection's record.
        let record = |parts: &[&dyn Fn(&mut TlvWriter)]| {
            let mut w = TlvWriter::new();
            w.write_nested(tlv::MEMBERS_RECORD, |w| {
                write_name(w, &c);
                write_nni(w, tlv::REVISION, 1);
                w.write_nested(tlv::RULE, |w| write_nni(w, tlv::RULE_KIND, 1));
                w.write_nested(tlv::WRITERS, |w| write_name(w, &n("/alice")));
                write_audiences(w, tlv::READERS, &[]);
                w.write_nested(tlv::CUTS, |w| {
                    w.write_nested(tlv::CUT, |w| {
                        for part in parts {
                            part(w);
                        }
                    })
                });
            });
            w.finish()
        };
        let prefix = |w: &mut TlvWriter| write_name(w, &n("/bob"));
        let bytes = |root: Name| {
            move |w: &mut TlvWriter| w.write_nested(tlv::CUT_BYTES, |w| write_name(w, &root))
        };
        let pair = |w: &mut TlvWriter| {
            w.write_nested(tlv::WRITER, |w| write_name(w, &n("/bob/phone/KEY/1")));
            write_ranges(w, tlv::ENTRIES, &[(3, 3)]);
        };
        let (b1, b2) = (bytes(one.clone()), bytes(two.clone()));
        assert!(decode_record(record(&[&prefix, &b1, &b2, &pair])).is_ok());
        // Not right after the prefix: before it, or after what it keeps.
        assert!(decode_record(record(&[&b1, &prefix, &pair])).is_err());
        assert!(decode_record(record(&[&prefix, &pair, &b1])).is_err());
        // Once each, ascending.
        assert!(decode_record(record(&[&prefix, &b2, &b1, &pair])).is_err());
        assert!(decode_record(record(&[&prefix, &b1, &b1, &pair])).is_err());
        // A packet's full name, ending in its implicit digest.
        let unnamed =
            bytes(cut_bytes_prefix(&log_name(&n("/alice/laptop"), Some(&c), 2)).append_segment(0));
        assert!(decode_record(record(&[&prefix, &unnamed, &pair])).is_err());
        // A cut that keeps nothing binds nothing.
        assert!(decode_record(record(&[&prefix])).is_ok());
        assert!(decode_record(record(&[&prefix, &b1])).is_err());
        // `CutBytes` is critical: a reader that does not know it refuses
        // the record rather than take what the cut keeps unbound.
        assert_eq!(tlv::CUT_BYTES % 2, 1);
    }

    #[test]
    fn a_node_listing_entries_beyond_its_head_or_out_of_order_or_too_many_is_refused() {
        let node = |head: u64, entries: Vec<(u64, u64)>| NodeBody {
            subject: n("/alice/32=data/notes"),
            writer: n("/alice/laptop/KEY/1"),
            head,
            page: None,
            entries,
            members: vec![(1, 1)],
            branches: Branches::Children(Vec::new()),
        };
        let ok = node(9, vec![(2, 4), (6, 9)]);
        assert_eq!(decode_node(encode_node(&ok)), Ok(ok));
        for (head, entries, why) in [
            (9, vec![(2, 10)], "above the node's head"),
            (9, vec![(6, 9), (2, 4)], "ascending and disjoint"),
            (9, vec![(2, 6), (5, 9)], "ascending and disjoint"),
            (u64::MAX, vec![(2, u64::MAX)], "at most"),
            (70_000, vec![(2, 65_537)], "at most"),
        ] {
            let refused = decode_node(encode_node(&node(head, entries)));
            assert!(
                refused.as_ref().is_err_and(|e| e.0.contains(why)),
                "{refused:?}, expected {why}"
            );
        }
    }

    #[test]
    fn sealed_versions_and_grants_parse_back() {
        let epoch = Epoch {
            creator: n("/alice/laptop"),
            seq: Seq(3),
        };
        let body = VersionBody {
            collection: n("/alice/32=data/docs/plan"),
            parents: Parents::new(),
            type_id: TypeId {
                name: n("/types/note"),
                revision: 1,
            },
            seal: Seal {
                any_of: vec![Audience::Person(n("/bob"))],
            },
            keep: Keep::Forever,
            dated: Timestamp(5),
            rule: None,
            fields: Content::new(),
            op: Bytes::new(),
            sealed: Some(SealedBody {
                epoch: epoch.clone(),
                ciphertext: Bytes::from_static(b"opaque"),
            }),
            chunks: None,
        };
        assert_eq!(
            decode_record(encode_version(&body)),
            Ok(Record::Version(body))
        );
        let fields = Content::new().with("text", Bytes::from_static(b"hi"));
        assert_eq!(
            decode_payload(encode_payload(&fields, b"op")),
            Ok((fields, Bytes::from_static(b"op")))
        );
        let key = seal_key_name(&n("/bob/phone"), &[9; 32]);
        assert_eq!(parse_seal_key_name(&key), Some((n("/bob/phone"), [9; 32])));
        let ask = GrantAsk {
            seal_key: key.clone(),
            collection: n("/alice/32=data/docs/plan"),
            epoch: epoch.clone(),
        };
        let name = grant_name(&n("/alice/laptop"), &ask);
        assert_eq!(parse_grant_name(&name), Some((n("/alice/laptop"), ask)));
        let c = n("/alice/32=data/docs/plan");
        assert_eq!(
            decode_epoch_of(encode_epoch_of(&c, &epoch)),
            Some((c, epoch))
        );
        assert_eq!(
            decode_grant(encode_grant(&[1; 32], b"wrapped")),
            Ok(([1; 32], Bytes::from_static(b"wrapped")))
        );
    }

    #[test]
    fn a_versions_parents_carry_their_tips_digests_and_its_rule_parses_back() {
        let tip = |key: &str, seq: u64| crate::VersionId {
            writer: Writer::new(n(key)),
            seq: Seq(seq),
        };
        let parents: Parents = [
            (tip("/bob/laptop/KEY/1", 4), Some([4; 32])),
            (tip("/carol/phone/KEY/1", 9), None),
        ]
        .into_iter()
        .collect();
        let body = VersionBody {
            collection: n("/alice/32=data/notes"),
            parents,
            type_id: TypeId {
                name: n("/types/note"),
                revision: 1,
            },
            seal: Seal { any_of: Vec::new() },
            keep: Keep::Forever,
            dated: Timestamp(5),
            rule: Some(n("/ndf/merge/element/v=1")),
            fields: Content::new(),
            op: Bytes::from_static(b"op"),
            sealed: None,
            chunks: None,
        };
        assert_eq!(
            decode_record(encode_version(&body)),
            Ok(Record::Version(body.clone()))
        );
        // A frontier elsewhere reads the same entries, digests aside.
        let mut w = TlvWriter::new();
        write_parents(&mut w, &body.parents);
        let mut r = TlvReader::new(w.finish());
        let (_, v) = r.read_tlv().unwrap();
        assert_eq!(read_frontier(v).as_ref(), Ok(body.parents.frontier()));
        // Two tips of one writer are refused: which one was made over?
        let mut w = TlvWriter::new();
        w.write_nested(tlv::FRONTIER, |w| {
            for s in [3, 4] {
                w.write_nested(tlv::FRONTIER_ENTRY, |w| {
                    write_name(w, &n("/bob/laptop/KEY/1"));
                    write_nni(w, tlv::SEQ, s);
                });
            }
        });
        let mut r = TlvReader::new(w.finish());
        let (_, v) = r.read_tlv().unwrap();
        assert!(read_parents(v).is_err());
    }

    #[test]
    fn a_version_in_pieces_larger_than_the_payload_limit_is_refused() {
        let body = |size: u64| VersionBody {
            collection: n("/alice/32=data/photos"),
            parents: Parents::new(),
            type_id: TypeId {
                name: n("/types/photo"),
                revision: 1,
            },
            seal: Seal { any_of: Vec::new() },
            keep: Keep::Forever,
            dated: Timestamp(5),
            rule: None,
            fields: Content::new(),
            op: Bytes::new(),
            sealed: None,
            chunks: Some(ChunksBody {
                size,
                root: [1; 32],
            }),
        };
        let fits = body(1 << 20);
        assert_eq!(
            decode_record(encode_version(&fits)),
            Ok(Record::Version(fits))
        );
        // A terabyte claimed: a reader would reserve it whole to read it.
        assert!(decode_record(encode_version(&body(1 << 40))).is_err());
    }

    /// Routing a name by its keyword (`served_kind`, `NameWords`) decides what the chains of
    /// parsers it replaced decided by trying each: over every name the layer makes, and names
    /// that mix or misplace keywords, the parser of the kind the keyword picks accepts exactly
    /// when the first of the old chain that accepted, and a parser is skipped only for a name
    /// it would refuse.
    #[test]
    fn routing_by_keyword_is_what_the_chain_of_parsers_decided() {
        let device = n("/alice/laptop");
        let c = n("/alice/32=data/docs/plan");
        let epoch = Epoch {
            creator: device.clone(),
            seq: Seq(3),
        };
        let log = log_name(&device, Some(&c), 7);
        let mut names = vec![
            Name::from_components([]),
            n("/alice/laptop"),
            c.clone(),
            log.clone(),
            log_name(&device, None, 2),
            piece_name(&log, PieceKind::Chunk(2)),
            piece_name(&log, PieceKind::Manifest(0)),
            root_name(&device, &n("/alice"), 4),
            node_name(&device, &c, 4),
            seal_key_name(&device, &[9; 32]),
            grant_name(
                &device,
                &GrantAsk {
                    seal_key: seal_key_name(&device, &[9; 32]),
                    collection: c.clone(),
                    epoch,
                },
            ),
            held_name(&device, &log),
            held_name(&device, &n("/bob/phone/32=log/seq=1")),
            crate::intro::intro_name(&device, b"params"),
            crate::intro::hint_name(&device, &[3; crate::intro::HINT_TOKEN_LEN]),
            // Mixed and misplaced keywords: a keyword after another, after a digest, twice.
            n("/alice/laptop/32=held/32=held/x"),
            n("/32=grant"),
            n("/alice/32=grant"),
            n("/alice/32=range/x"),
            n("/alice/laptop/32=intro"),
            n("/alice/laptop/32=hint"),
        ];
        names.push(held_name(&device, &log).append_implicit_digest([5; 32]));
        names.push(
            device
                .clone()
                .append_implicit_digest([5; 32])
                .append_component(kw(HELD))
                .append(b"x"),
        );

        // What `Inner::answer` tried in order, as parsers alone.
        let chain = |name: &Name| {
            if parse_grant_name(name).is_some() {
                Some(Served::Grant)
            } else if crate::intro::parse_intro_name(name).is_some() {
                Some(Served::Intro)
            } else if crate::intro::parse_hint_name(name).is_some() {
                Some(Served::Hint)
            } else if parse_held_name(name).is_some() {
                Some(Served::Held)
            } else {
                None
            }
        };
        let routed = |name: &Name| match served_kind(name)? {
            Served::Grant => parse_grant_name(name).map(|_| Served::Grant),
            Served::Intro => crate::intro::parse_intro_name(name).map(|_| Served::Intro),
            Served::Hint => crate::intro::parse_hint_name(name).map(|_| Served::Hint),
            Served::Held => parse_held_name(name).map(|_| Served::Held),
        };
        let mut seen = std::collections::BTreeSet::new();
        for name in &names {
            assert_eq!(routed(name), chain(name), "{name}");
            seen.extend(chain(name).map(|k| format!("{k:?}")));

            let words = NameWords::of(name);
            assert!(
                words.log() || parse_log_name(name).is_none(),
                "{name}: a log name without 32=log"
            );
        }
        assert_eq!(seen.len(), 4, "the table reaches every route: {seen:?}");
    }
}
