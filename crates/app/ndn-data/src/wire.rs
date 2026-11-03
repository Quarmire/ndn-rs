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
//! | log entry (snapshot) | `<D>/32=log/seq=<n>` | the device key |
//! | summary root of namespace `O` | `<D>/32=summary/<O>/seq=<head>` | the device key |
//! | summary node of `X` | `<D>/32=summary/<X>/seq=<head>` | DigestSha256; its parent lists its digest |
//! | summary page of `X` | `<D>/32=summary/<X>/32=page/<buckets>/seq=<head>` | DigestSha256; its parent lists its digest |
//! | seal key | `<D>/32=seal/<X25519 public key>` | the device key |
//! | grant | `<G>/32=grant/<GrantAsk TLV>` | the granter's device key |
//!
//! `X` is a name of the tree from `O` to a collection: `O/32=data` (the
//! root's one child) or `O/32=data/<path>`, a folder or collection. Two
//! names are never fetched: the state name
//! `<C>/32=state/<F>` (the merged value at frontier `F`, computed by every
//! reader) and the sync group `<O>/32=sync` (State Vector Sync Interests,
//! notifications only), [`ndn_security::sync_group`]: the one definition the
//! forwarder's trust and link libraries route and multicast it by.
//!
//! Every name parses one way: `D` and `O` have no keyword component, so
//! the first `32=log`, `32=summary`, `32=seal` or `32=grant` ends `D`,
//! `32=data` ends `O`, and the layer's other keywords (`32=page`,
//! `32=state`) follow a subject whose only keyword is its marker; a seal
//! key's and a grant's last component is one opaque value (a key, a TLV).
//! A node or page name always ends in its head:
//! only a root is discovered without one (`<D>/32=summary/<O>`), and a
//! namespace never ends in a `seq=` component.
//!
//! TLV-TYPEs are allocated from 0x0520–0x057F, all even (non-critical): a
//! decoder skips an even TLV it does not know and refuses an odd one, so a
//! later revision can add fields old readers pass over and fields they must
//! not.

use bytes::Bytes;
use ndn_foundation_types::{Name, NameComponent, tlv_type};
use ndn_tlv::{TlvReader, TlvWriter};

use crate::collection::{Accepted, Cut, Epoch, Members, Parent, Rule};
use crate::version::{Audience, Content, Frontier, Keep, Seal, Seq, Timestamp, TypeId, Writer};

/// TLV-TYPE numbers (0x0520–0x057F).
pub mod tlv {
    /// A version's record: the Content of a version log entry.
    pub const VERSION_RECORD: u64 = 0x0520;
    /// A frontier: `FrontierEntry*`, by writer.
    pub const FRONTIER: u64 = 0x0522;
    /// One writer of a frontier: `Name` (key) + `Seq`.
    pub const FRONTIER_ENTRY: u64 = 0x0524;
    /// A sequence number (NonNegativeInteger); in a members record, its
    /// parent's revision.
    pub const SEQ: u64 = 0x0526;
    /// A content type: `Name` + `Revision`.
    pub const TYPE_ID: u64 = 0x0528;
    /// A revision (NonNegativeInteger).
    pub const REVISION: u64 = 0x052A;
    /// Retention: one of `KeepUntil`, `KeepLastN`, `KeepForever`.
    pub const KEEP: u64 = 0x052C;
    /// Keep until this date (ms since the Unix epoch).
    pub const KEEP_UNTIL: u64 = 0x052E;
    /// Keep the writer's last N versions.
    pub const KEEP_LAST_N: u64 = 0x0530;
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
    /// A collection rule: `RuleKind` [+ `Name` of the merge function].
    pub const RULE: u64 = 0x0548;
    /// 0 one key, 1 log, 2 merge.
    pub const RULE_KIND: u64 = 0x054A;
    /// Writer key-name prefixes: `Name*`.
    pub const WRITERS: u64 = 0x054C;
    /// Readers: `Audience*`.
    pub const READERS: u64 = 0x054E;
    /// A snapshot record: the Content of a snapshot log entry, `Name*` (pins).
    pub const SNAPSHOT_RECORD: u64 = 0x0550;
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
    /// record, SHA-256 of its parent's `MembersRecord`.
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
    /// One removal: `Name` (the removed writer prefix), then per key whose
    /// versions stay accepted, `Writer` and `Entries` (exactly those seqs).
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
    /// The Content of a hold log entry: `Name` (collection), `Copies`,
    /// `KeepUntil` (until), `Frontier` (what the asker had applied).
    pub const HOLD_RECORD: u64 = 0x0525;
    /// NonNegativeInteger: how many holders.
    pub const COPIES: u64 = 0x0527;
    /// The Content of a lease log entry: `Name` (collection), `Name` (the
    /// hold record answered), `KeepUntil` (until), `Frontier` (what it
    /// holds).
    pub const LEASE_RECORD: u64 = 0x0529;
    /// The Content of a prune log entry: `Name` (collection or version),
    /// `Frontier` (up to).
    pub const PRUNE_RECORD: u64 = 0x052B;
    /// What a hold ask names: `Name` (the hold record).
    pub const HOLD_ASK: u64 = 0x052D;
    /// What an audit asks: `Nonce`, `Name` (the piece).
    pub const AUDIT_ASK: u64 = 0x052F;
    /// Octets: an audit's fresh random nonce (16).
    pub const NONCE: u64 = 0x0531;
    /// An audit's answer: `Piece` or `Missing`.
    pub const AUDIT_ANSWER: u64 = 0x0533;
    /// Octets: the piece's whole Data packet.
    pub const PIECE: u64 = 0x0535;
    /// Empty: the holder does not hold the piece.
    pub const MISSING: u64 = 0x0537;
}

/// Keyword components of the layer's names.
const DATA: &[u8] = b"data";
const LOG: &[u8] = b"log";
const SUMMARY: &[u8] = b"summary";
const PAGE: &[u8] = b"page";
const STATE: &[u8] = b"state";
const SEAL: &[u8] = b"seal";
const GRANT: &[u8] = b"grant";
const MANIFEST: &[u8] = b"manifest";
const HOLD: &[u8] = b"hold";
const AUDIT: &[u8] = b"audit";
const HELD: &[u8] = b"held";
const ROOT: &[u8] = b"root";

/// The most payload octets a version carries in its own packet; a larger
/// payload travels in pieces (log rule) or is refused (merge rule).
pub const INLINE_MAX: usize = 6144;

/// The payload octets one chunk carries (the last may carry fewer).
pub const CHUNK: usize = 4096;

/// The digests one manifest node lists.
pub const FANOUT: usize = 128;

/// The octets of an audit's nonce.
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

fn bad(what: impl Into<String>) -> WireError {
    WireError(what.into())
}

fn kw(word: &'static [u8]) -> NameComponent {
    NameComponent::keyword(Bytes::from_static(word))
}

fn is_kw(c: &NameComponent, word: &[u8]) -> bool {
    c.typ == tlv_type::KEYWORD && c.value.as_ref() == word
}

fn name_of(comps: &[NameComponent]) -> Name {
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

fn is_device_comps(comps: &[NameComponent]) -> bool {
    !comps.is_empty() && comps.iter().all(is_plain)
}

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
    let comps = key.components();
    let n = comps.len();
    (n >= 3
        && comps[n - 2].typ == tlv_type::GENERIC_NAME_COMPONENT
        && comps[n - 2].value.as_ref() == b"KEY")
        .then(|| name_of(&comps[..n - 2]))
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
    /// The collection it is about; `None` for a snapshot.
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

/// The name of a collection's merged state at `at`:
/// `<collection>/32=state/<Frontier TLV>`.
pub fn state_name(collection: &Name, at: &Frontier) -> Name {
    let mut w = TlvWriter::new();
    write_frontier(&mut w, at);
    collection
        .clone()
        .append_component(kw(STATE))
        .append_component(NameComponent::generic(w.finish()))
}

/// Parse `<collection>/32=state/<Frontier TLV>`.
pub fn parse_state_name(name: &Name) -> Option<(Name, Frontier)> {
    let comps = name.components();
    let n = comps.len();
    if n < 3 || !is_kw(&comps[n - 2], STATE) {
        return None;
    }
    let collection = name_of(&comps[..n - 2]);
    if !is_collection_name(&collection) {
        return None;
    }
    let mut r = TlvReader::new(comps[n - 1].value.clone());
    let (typ, value) = r.read_tlv().ok()?;
    (typ == tlv::FRONTIER && r.is_empty())
        .then(|| read_frontier(value).ok())
        .flatten()
        .map(|f| (collection, f))
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

fn write_epoch(w: &mut TlvWriter, e: &Epoch) {
    w.write_nested(tlv::SEAL_EPOCH, |w| {
        write_name(w, &e.creator);
        write_nni(w, tlv::SEQ, e.seq.0);
    });
}

fn read_epoch(value: Bytes) -> Result<Epoch, WireError> {
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

// ---- slice 3: pieces, hold asks, audits ---------------------------------------------------------

/// A piece of a large version (spec §4.1): a chunk of its payload, or a node
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

/// A hold ask's name: `<holder>/32=hold/<HoldAsk TLV>`, the TLV naming the
/// owner device's hold record.
pub fn hold_ask_name(holder: &Name, record: &Name) -> Name {
    let mut w = TlvWriter::new();
    w.write_nested(tlv::HOLD_ASK, |w| write_name(w, record));
    holder
        .clone()
        .append_component(kw(HOLD))
        .append_component(NameComponent::generic(w.finish()))
}

/// Parse `<holder>/32=hold/<HoldAsk TLV>`: the holder and the hold record's
/// name, a log entry with a collection.
pub fn parse_hold_ask_name(name: &Name) -> Option<(Name, Name)> {
    let comps = name.components();
    let at = comps.iter().position(|c| is_kw(c, HOLD))?;
    if !is_device_comps(&comps[..at]) || at + 2 != comps.len() {
        return None;
    }
    let mut r = TlvReader::new(comps[at + 1].value.clone());
    let (typ, value) = r.read_tlv().ok()?;
    if typ != tlv::HOLD_ASK || !r.is_empty() {
        return None;
    }
    let mut record = None;
    each(value, |t, v| {
        if t != tlv_type::NAME {
            return Ok(false);
        }
        record = Some(read_name(v)?);
        Ok(true)
    })
    .ok()?;
    let record = record?;
    parse_log_name(&record)?.subject?;
    Some((name_of(&comps[..at]), record))
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

/// What an audit asks a holder for: one piece, under a fresh nonce.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AuditAsk {
    /// Random octets the auditor chose for this ask alone.
    pub nonce: [u8; NONCE_LEN],
    /// The piece: a version's log entry, or a chunk or manifest node of it.
    pub piece: Name,
}

/// An audit ask's name: `<holder>/32=audit/<AuditAsk TLV>`.
pub fn audit_ask_name(holder: &Name, ask: &AuditAsk) -> Name {
    let mut w = TlvWriter::new();
    w.write_nested(tlv::AUDIT_ASK, |w| {
        w.write_tlv(tlv::NONCE, &ask.nonce);
        write_name(w, &ask.piece);
    });
    holder
        .clone()
        .append_component(kw(AUDIT))
        .append_component(NameComponent::generic(w.finish()))
}

/// Parse `<holder>/32=audit/<AuditAsk TLV>`.
pub fn parse_audit_ask_name(name: &Name) -> Option<(Name, AuditAsk)> {
    let comps = name.components();
    let at = comps.iter().position(|c| is_kw(c, AUDIT))?;
    if !is_device_comps(&comps[..at]) || at + 2 != comps.len() {
        return None;
    }
    let mut r = TlvReader::new(comps[at + 1].value.clone());
    let (typ, value) = r.read_tlv().ok()?;
    if typ != tlv::AUDIT_ASK || !r.is_empty() {
        return None;
    }
    let (mut nonce, mut piece) = (None, None);
    each(value, |t, v| {
        match t {
            tlv::NONCE => {
                nonce = Some(
                    <[u8; NONCE_LEN]>::try_from(v.as_ref())
                        .map_err(|_| bad("a nonce is 16 octets"))?,
                )
            }
            tlv_type::NAME => piece = Some(read_name(v)?),
            _ => return Ok(false),
        }
        Ok(true)
    })
    .ok()?;
    Some((
        name_of(&comps[..at]),
        AuditAsk {
            nonce: nonce?,
            piece: piece?,
        },
    ))
}

/// A holder's answer to an audit ask.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditAnswer {
    /// The piece's whole Data packet.
    Piece(Bytes),
    /// The holder does not hold it.
    Missing,
}

/// Encode an audit answer (the Content of the holder's signed reply).
pub fn encode_audit_answer(a: &AuditAnswer) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_nested(tlv::AUDIT_ANSWER, |w| match a {
        AuditAnswer::Piece(wire) => w.write_tlv(tlv::PIECE, wire),
        AuditAnswer::Missing => w.write_tlv(tlv::MISSING, &[]),
    });
    w.finish()
}

/// Decode an audit answer.
pub fn decode_audit_answer(content: Bytes) -> Result<AuditAnswer, WireError> {
    let mut r = TlvReader::new(content);
    let (typ, value) = r.read_tlv().map_err(|e| bad(format!("bad TLV: {e:?}")))?;
    if typ != tlv::AUDIT_ANSWER || !r.is_empty() {
        return Err(bad("an audit answer is one AuditAnswer"));
    }
    let mut answer = None;
    each(value, |t, v| {
        match t {
            tlv::PIECE => answer = Some(AuditAnswer::Piece(v)),
            tlv::MISSING => answer = Some(AuditAnswer::Missing),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    answer.ok_or_else(|| bad("an audit answer carries a piece or says it is missing"))
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

fn write_nni(w: &mut TlvWriter, typ: u64, v: u64) {
    let b = v.to_be_bytes();
    let s = match v {
        0..=0xFF => &b[7..],
        0x100..=0xFFFF => &b[6..],
        0x1_0000..=0xFFFF_FFFF => &b[4..],
        _ => &b[..],
    };
    w.write_tlv(typ, s);
}

fn read_nni(v: &[u8]) -> Result<u64, WireError> {
    Ok(match v.len() {
        1 => u64::from(v[0]),
        2 => u64::from(u16::from_be_bytes([v[0], v[1]])),
        4 => u64::from(u32::from_be_bytes([v[0], v[1], v[2], v[3]])),
        8 => u64::from_be_bytes([v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]]),
        _ => return Err(bad("a NonNegativeInteger is 1, 2, 4 or 8 octets")),
    })
}

fn write_name(w: &mut TlvWriter, name: &Name) {
    w.write_nested(tlv_type::NAME, |w| {
        for c in name.components() {
            w.write_tlv(c.typ, &c.value);
        }
    });
}

fn read_name(value: Bytes) -> Result<Name, WireError> {
    Name::decode(value).map_err(|e| bad(format!("bad name: {e:?}")))
}

/// Iterate the TLVs of `value`, handing each known one to `f`; skip unknown
/// even types and refuse unknown odd (critical) ones. `f` returns whether it
/// knew the type.
fn each(
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
    each(value, |typ, v| {
        if typ != tlv::FRONTIER_ENTRY {
            return Ok(false);
        }
        let (mut key, mut seq) = (None, None);
        each(v, |t, v| {
            match t {
                tlv_type::NAME => key = Some(read_name(v)?),
                tlv::SEQ => seq = Some(read_nni(&v)?),
                _ => return Ok(false),
            }
            Ok(true)
        })?;
        let (Some(key), Some(seq)) = (key, seq) else {
            return Err(bad("a frontier entry names a writer and a seq"));
        };
        f.include(&crate::VersionId {
            writer: Writer::new(key),
            seq: Seq(seq),
        });
        Ok(true)
    })?;
    Ok(f)
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

fn read_digest(v: &[u8]) -> Result<[u8; 32], WireError> {
    <[u8; 32]>::try_from(v).map_err(|_| bad("a digest is 32 octets"))
}

// ---- log records ------------------------------------------------------------------------------

/// The body of a version log entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionBody {
    /// The collection.
    pub collection: Name,
    /// What the writer had seen.
    pub parents: Frontier,
    /// The type the writer wrote.
    pub type_id: TypeId,
    /// Who may read it, as declared by the writer.
    pub seal: Seal,
    /// Retention.
    pub keep: Keep,
    /// The writer's clock.
    pub dated: Timestamp,
    /// The fields the writer set (an empty value removes the field); empty
    /// while the payload is sealed and not opened.
    pub fields: Content,
    /// The merge function's operation (empty under the log rule, and while
    /// the payload is sealed and not opened).
    pub op: Bytes,
    /// The payload sealed: when present, `Fields` and `MergeOp` travel
    /// inside it ([`encode_payload`]) and not beside it.
    pub sealed: Option<SealedBody>,
    /// The payload carried in pieces (spec §4.1): when present, the
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
/// tree's root node packet (spec §4.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ChunksBody {
    /// The payload's octets as carried (sealed: the ciphertext's).
    pub size: u64,
    /// SHA-256 of the root manifest node's whole Data packet.
    pub root: [u8; 32],
}

/// The body of a hold log entry: an owner device's custody policy for a
/// collection (spec §13).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HoldBody {
    /// The collection to hold.
    pub collection: Name,
    /// How many holders.
    pub copies: u32,
    /// Until when.
    pub until: Timestamp,
    /// What the asker had applied of the collection when it asked.
    pub at: Frontier,
}

/// The body of a lease log entry: a holder's promise (spec §13).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseBody {
    /// The collection held.
    pub collection: Name,
    /// The owner's hold record the lease answers.
    pub hold: Name,
    /// Until when.
    pub until: Timestamp,
    /// What the holder held, verified, when it signed.
    pub holds: Frontier,
}

/// The body of a prune log entry (spec §14).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PruneBody {
    /// A collection, or one of the pruner's version names in it.
    pub prefix: Name,
    /// Up to where, for the pruner's own key only.
    pub upto: Frontier,
}

/// One removal in a members record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CutBody {
    /// The removed writer prefix.
    pub of: Name,
    /// Exactly the versions of its keys that stay accepted.
    pub accept: Accepted,
}

/// The body of a members log entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembersBody {
    /// The collection governed.
    pub collection: Name,
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
    /// A snapshot's pins.
    Snapshot(Vec<Name>),
    /// A hold record.
    Hold(HoldBody),
    /// A lease.
    Lease(LeaseBody),
    /// A prune record.
    Prune(PruneBody),
}

impl Record {
    /// The collection a log entry with this record is about (its name's
    /// subject): `None` for a snapshot.
    pub fn subject(&self) -> Option<Name> {
        match self {
            Record::Version(b) => Some(b.collection.clone()),
            Record::Members(b) => Some(b.collection.clone()),
            Record::Snapshot(_) => None,
            Record::Hold(b) => Some(b.collection.clone()),
            Record::Lease(b) => Some(b.collection.clone()),
            Record::Prune(b) => match parse_log_name(&b.prefix) {
                Some(l) => l.subject,
                None => Some(b.prefix.clone()),
            },
        }
    }
}

/// Encode a version record.
pub fn encode_version(b: &VersionBody) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_nested(tlv::VERSION_RECORD, |w| {
        write_name(w, &b.collection);
        write_frontier(w, &b.parents);
        w.write_nested(tlv::TYPE_ID, |w| {
            write_name(w, &b.type_id.name);
            write_nni(w, tlv::REVISION, b.type_id.revision);
        });
        write_audiences(w, tlv::SEAL, &b.seal.any_of);
        w.write_nested(tlv::KEEP, |w| match b.keep {
            Keep::Until(t) => write_nni(w, tlv::KEEP_UNTIL, t.0),
            Keep::LastN(n) => write_nni(w, tlv::KEEP_LAST_N, u64::from(n)),
            Keep::Forever => w.write_tlv(tlv::KEEP_FOREVER, &[]),
        });
        write_nni(w, tlv::DATED, b.dated.0);
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
    w.write_nested(tlv::FIELDS, |w| {
        for (name, value) in fields.fields() {
            w.write_nested(tlv::FIELD, |w| {
                w.write_tlv(tlv::FIELD_NAME, name.as_bytes());
                w.write_tlv(tlv::FIELD_VALUE, value);
            });
        }
    });
    w.write_tlv(tlv::MERGE_OP, op);
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

/// Encode a members record.
pub fn encode_members(b: &MembersBody) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_nested(tlv::MEMBERS_RECORD, |w| {
        write_name(w, &b.collection);
        write_nni(w, tlv::REVISION, b.revision);
        w.write_nested(tlv::RULE, |w| match &b.rule {
            Rule::OneKey => write_nni(w, tlv::RULE_KIND, 0),
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
                        for (writer, ranges) in c.accept.iter() {
                            w.write_nested(tlv::WRITER, |w| write_name(w, writer.key()));
                            write_ranges(w, tlv::ENTRIES, ranges);
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

/// Encode a snapshot record.
pub fn encode_snapshot(pins: &[Name]) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_nested(tlv::SNAPSHOT_RECORD, |w| {
        for p in pins {
            write_name(w, p);
        }
    });
    w.finish()
}

/// Encode a hold record.
pub fn encode_hold(b: &HoldBody) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_nested(tlv::HOLD_RECORD, |w| {
        write_name(w, &b.collection);
        write_nni(w, tlv::COPIES, u64::from(b.copies));
        write_nni(w, tlv::KEEP_UNTIL, b.until.0);
        write_frontier(w, &b.at);
    });
    w.finish()
}

/// Encode a lease.
pub fn encode_lease(b: &LeaseBody) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_nested(tlv::LEASE_RECORD, |w| {
        write_name(w, &b.collection);
        write_name(w, &b.hold);
        write_nni(w, tlv::KEEP_UNTIL, b.until.0);
        write_frontier(w, &b.holds);
    });
    w.finish()
}

/// Encode a prune record.
pub fn encode_prune(b: &PruneBody) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_nested(tlv::PRUNE_RECORD, |w| {
        write_name(w, &b.prefix);
        write_frontier(w, &b.upto);
    });
    w.finish()
}

/// Encode any log record.
pub fn encode_record(r: &Record) -> Bytes {
    match r {
        Record::Version(b) => encode_version(b),
        Record::Members(b) => encode_members(b),
        Record::Snapshot(p) => encode_snapshot(p),
        Record::Hold(b) => encode_hold(b),
        Record::Lease(b) => encode_lease(b),
        Record::Prune(b) => encode_prune(b),
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
        tlv::SNAPSHOT_RECORD => {
            let mut pins = Vec::new();
            each(value, |t, v| {
                if t != tlv_type::NAME {
                    return Ok(false);
                }
                pins.push(read_name(v)?);
                Ok(true)
            })?;
            Ok(Record::Snapshot(pins))
        }
        tlv::HOLD_RECORD => decode_hold(value).map(Record::Hold),
        tlv::LEASE_RECORD => decode_lease(value).map(Record::Lease),
        tlv::PRUNE_RECORD => decode_prune(value).map(Record::Prune),
        other => Err(bad(format!("{other:#x} is not a log record"))),
    }
}

fn decode_hold(value: Bytes) -> Result<HoldBody, WireError> {
    let (mut collection, mut copies, mut until, mut at) = (None, None, None, None);
    each(value, |t, v| {
        match t {
            tlv_type::NAME => collection = Some(read_name(v)?),
            tlv::COPIES => {
                copies = Some(u32::try_from(read_nni(&v)?).map_err(|_| bad("copies fit 32 bits"))?)
            }
            tlv::KEEP_UNTIL => until = Some(Timestamp(read_nni(&v)?)),
            tlv::FRONTIER => at = Some(read_frontier(v)?),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    match (collection, copies, until, at) {
        (Some(collection), Some(copies), Some(until), Some(at))
            if is_collection_name(&collection) =>
        {
            Ok(HoldBody {
                collection,
                copies,
                until,
                at,
            })
        }
        _ => Err(bad(
            "a hold record names a collection, how many copies, until when, and a frontier",
        )),
    }
}

fn decode_lease(value: Bytes) -> Result<LeaseBody, WireError> {
    let mut names = Vec::new();
    let (mut until, mut holds) = (None, None);
    each(value, |t, v| {
        match t {
            tlv_type::NAME => names.push(read_name(v)?),
            tlv::KEEP_UNTIL => until = Some(Timestamp(read_nni(&v)?)),
            tlv::FRONTIER => holds = Some(read_frontier(v)?),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    let bad_lease = || {
        bad("a lease names a collection, the hold record it answers, until when, and a frontier")
    };
    let [collection, hold]: [Name; 2] = names.try_into().map_err(|_| bad_lease())?;
    let held_about = parse_log_name(&hold).and_then(|l| l.subject);
    match (until, holds) {
        (Some(until), Some(holds))
            if is_collection_name(&collection) && held_about.as_ref() == Some(&collection) =>
        {
            Ok(LeaseBody {
                collection,
                hold,
                until,
                holds,
            })
        }
        _ => Err(bad_lease()),
    }
}

fn decode_prune(value: Bytes) -> Result<PruneBody, WireError> {
    let (mut prefix, mut upto) = (None, None);
    each(value, |t, v| {
        match t {
            tlv_type::NAME => prefix = Some(read_name(v)?),
            tlv::FRONTIER => upto = Some(read_frontier(v)?),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    match (prefix, upto) {
        (Some(prefix), Some(upto))
            if is_collection_name(&prefix)
                || parse_log_name(&prefix).is_some_and(|l| l.subject.is_some()) =>
        {
            Ok(PruneBody { prefix, upto })
        }
        _ => Err(bad(
            "a prune record names a collection or a version, and the frontier it prunes up to",
        )),
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
    each(value, |typ, v| {
        match typ {
            tlv_type::NAME => collection = Some(read_name(v)?),
            tlv::FRONTIER => parents = Some(read_frontier(v)?),
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
            tlv::KEEP => {
                each(v, |t, v| {
                    keep = Some(match t {
                        tlv::KEEP_UNTIL => Keep::Until(Timestamp(read_nni(&v)?)),
                        tlv::KEEP_LAST_N => Keep::LastN(
                            u32::try_from(read_nni(&v)?).map_err(|_| bad("last N fits 32 bits"))?,
                        ),
                        tlv::KEEP_FOREVER => Keep::Forever,
                        _ => return Ok(false),
                    });
                    Ok(true)
                })?;
            }
            tlv::DATED => dated = Some(Timestamp(read_nni(&v)?)),
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
                if size as usize <= INLINE_MAX {
                    return Err(bad(format!(
                        "a payload of {size} octets travels inline, not in pieces"
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
    let (fields, op) = match (fields, op, sealed.is_some() || chunks.is_some()) {
        (None, None, true) => (Content::new(), Bytes::new()),
        (Some(f), Some(o), false) => (f, o),
        (_, _, true) => {
            return Err(bad(
                "a sealed version, or one in pieces, carries its fields only there",
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
                    (Some(0), None) => Rule::OneKey,
                    (Some(1), None) => Rule::Log,
                    (Some(2), Some(function)) => Rule::Merge { function },
                    _ => return Err(bad("a rule is one key, log, or merge with a function")),
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
                each(v, |t, v| {
                    if t != tlv::CUT {
                        return Ok(false);
                    }
                    cuts.push(read_cut(v)?);
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

/// Decode one `Cut`: its prefix, then per key `Writer` and `Entries`, keys
/// ascending, each key's ranges ascending and disjoint.
fn read_cut(value: Bytes) -> Result<CutBody, WireError> {
    let mut of = None;
    let mut accept = Accepted::new();
    let mut writer: Option<Writer> = None;
    let mut last: Option<Writer> = None;
    each(value, |t, v| {
        match t {
            tlv_type::NAME if of.is_none() => of = Some(read_name(v)?),
            tlv::WRITER => {
                if writer.is_some() {
                    return Err(bad("a cut's writer is followed by its entries"));
                }
                writer = Some(Writer::new(read_writer(v)?));
            }
            tlv::ENTRIES => {
                let w = writer
                    .take()
                    .ok_or_else(|| bad("a cut's entries follow their writer"))?;
                if last.as_ref().is_some_and(|l| *l >= w) {
                    return Err(bad("a cut lists its writers once each, ascending"));
                }
                let ranges = read_ranges(v)?;
                check_ranges(&ranges, u64::MAX, usize::MAX)?;
                for (lo, hi) in ranges {
                    accept.insert_range(&w, lo, hi);
                }
                last = Some(w);
            }
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    if writer.is_some() {
        return Err(bad("a cut's writer is followed by its entries"));
    }
    let of = of.ok_or_else(|| bad("a cut names a prefix"))?;
    Ok(CutBody { of, accept })
}

/// Read a `Writer` TLV's value: one Name, a key.
fn read_writer(v: Bytes) -> Result<Name, WireError> {
    let mut r = TlvReader::new(v);
    let (t, v) = r.read_tlv().map_err(|e| bad(format!("bad TLV: {e:?}")))?;
    if t != tlv_type::NAME || !r.is_empty() {
        return Err(bad("a writer is a key name"));
    }
    read_name(v)
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
            let at: Frontier = [crate::VersionId {
                writer: Writer::new(d.clone().append("KEY").append("1")),
                seq: Seq(4),
            }]
            .into_iter()
            .collect();
            assert_eq!(parse_state_name(&state_name(&c, &at)), Some((c, at)));
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
            revision: 1,
            rule: Rule::Merge {
                function: n("/merge/yrs"),
            },
            writers: vec![n("/alice")],
            readers: vec![Audience::Person(n("/alice"))],
            cuts: vec![CutBody {
                of: n("/bob"),
                accept: [40, 41, 100]
                    .into_iter()
                    .map(|s| crate::VersionId {
                        writer: Writer::new(n("/bob/laptop/KEY/1")),
                        seq: Seq(s),
                    })
                    .collect(),
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
            parents: Frontier::new(),
            type_id: TypeId {
                name: n("/types/note"),
                revision: 1,
            },
            seal: Seal {
                any_of: vec![Audience::Person(n("/bob"))],
            },
            keep: Keep::Forever,
            dated: Timestamp(5),
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
}
