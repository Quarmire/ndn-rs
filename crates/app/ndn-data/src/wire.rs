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

use crate::collection::{Epoch, Rule};
use crate::version::{Audience, Content, Frontier, Keep, Seal, Seq, Timestamp, TypeId, Writer};

/// TLV-TYPE numbers (0x0520–0x057F).
pub mod tlv {
    /// A version's record: the Content of a version log entry.
    pub const VERSION_RECORD: u64 = 0x0520;
    /// A frontier: `FrontierEntry*`, by writer.
    pub const FRONTIER: u64 = 0x0522;
    /// One writer of a frontier: `Name` (key) + `Seq`.
    pub const FRONTIER_ENTRY: u64 = 0x0524;
    /// A sequence number (NonNegativeInteger).
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
    /// SHA-256 implicit digest of a summary packet (32 octets).
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
    /// One removal: `Name` (the removed writer prefix), `Frontier` (what
    /// stays accepted of its keys).
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
    /// What a grant answers: `Name` (the asker's seal key name), then for a
    /// collection's epoch key `Name` (the collection) and `SealEpoch`.
    pub const GRANT_ASK: u64 = 0x0578;
    /// A grant: `EphemeralKey`, `Ciphertext` (the key, wrapped).
    pub const GRANT: u64 = 0x057A;
    /// The granter's ephemeral X25519 public key: 32 octets.
    pub const EPHEMERAL_KEY: u64 = 0x057C;
}

/// Keyword components of the layer's names.
const DATA: &[u8] = b"data";
const LOG: &[u8] = b"log";
const SUMMARY: &[u8] = b"summary";
const PAGE: &[u8] = b"page";
const STATE: &[u8] = b"state";
const SEAL: &[u8] = b"seal";
const GRANT: &[u8] = b"grant";

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

/// `<device>/32=summary/<subject>`: the prefix every summary packet of
/// `subject` by `device` lies under, and the root's discovery name.
pub fn summary_prefix(device: &Name, subject: &Name) -> Name {
    let mut comps = device.components().to_vec();
    comps.push(kw(SUMMARY));
    comps.extend(subject.components().iter().cloned());
    Name::from_components(comps)
}

/// A summary node's (or root's) name: `<device>/32=summary/<subject>/seq=<head>`.
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
    let (subject, page) = match rest.iter().position(|c| is_kw(c, PAGE)) {
        Some(p) if p + 2 == rest.len() => (&rest[..p], Some(rest[p + 1].value.clone())),
        Some(_) => return None,
        None => (rest, None),
    };
    let subject = name_of(subject);
    let root = is_namespace(&subject);
    let named = head.is_some() || (root && page.is_none());
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

/// What a grant answers: the master secret of the granter (no collection),
/// or the content key of one epoch of a collection, for the holder of a
/// seal key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GrantAsk {
    /// The asker's seal key's name (`<device>/32=seal/<public key>`).
    pub seal_key: Name,
    /// The collection and epoch whose key is asked for; `None` asks for the
    /// granter's master secret.
    pub of: Option<(Name, Epoch)>,
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
        if let Some((c, e)) = &ask.of {
            write_name(w, c);
            write_epoch(w, e);
        }
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
    let mut names = names.into_iter();
    let seal_key = names.next()?;
    parse_seal_key_name(&seal_key)?;
    let of = match (names.next(), epoch, names.next()) {
        (None, None, None) => None,
        (Some(c), Some(e), None) if is_collection_name(&c) => Some((c, e)),
        _ => return None,
    };
    Some((name_of(&comps[..at]), GrantAsk { seal_key, of }))
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
}

/// A sealed payload: the epoch whose key seals it, and the ciphertext of
/// [`encode_payload`] (`nonce ‖ tag ‖ ciphertext`), its AAD the TLV of the
/// version's own name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedBody {
    /// The epoch.
    pub epoch: Epoch,
    /// The ciphertext.
    pub ciphertext: Bytes,
}

/// One removal in a members record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CutBody {
    /// The removed writer prefix.
    pub of: Name,
    /// What stays accepted of its keys.
    pub accept: Frontier,
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
    /// The frontier the owner had applied when the rule last changed.
    pub since: Option<Frontier>,
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
        match &b.sealed {
            Some(s) => w.write_nested(tlv::SEALED, |w| {
                write_epoch(w, &s.epoch);
                w.write_tlv(tlv::CIPHERTEXT, &s.ciphertext);
            }),
            None => write_payload(w, &b.fields, &b.op),
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
                        write_frontier(w, &c.accept);
                    });
                }
            });
        }
        if let Some(e) = &b.epoch {
            write_epoch(w, e);
        }
        if let Some(since) = &b.since {
            w.write_nested(tlv::RULE_SINCE, |w| write_frontier(w, since));
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
                let (Some(epoch), Some(ciphertext)) = (epoch, ciphertext) else {
                    return Err(bad("a sealed payload has an epoch and a ciphertext"));
                };
                sealed = Some(SealedBody { epoch, ciphertext });
            }
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    let missing = |what| bad(format!("a version record has {what}"));
    let (fields, op) = match (fields, op, &sealed) {
        (None, None, Some(_)) => (Content::new(), Bytes::new()),
        (Some(f), Some(o), None) => (f, o),
        (_, _, Some(_)) => return Err(bad("a sealed version carries its fields sealed only")),
        (None, _, None) => return Err(missing("fields")),
        (_, None, None) => return Err(missing("a merge op")),
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
    let mut since = None;
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
                    let (mut of, mut accept) = (None, None);
                    each(v, |t, v| {
                        match t {
                            tlv_type::NAME => of = Some(read_name(v)?),
                            tlv::FRONTIER => accept = Some(read_frontier(v)?),
                            _ => return Ok(false),
                        }
                        Ok(true)
                    })?;
                    let (Some(of), Some(accept)) = (of, accept) else {
                        return Err(bad("a cut names a prefix and a frontier"));
                    };
                    cuts.push(CutBody { of, accept });
                    Ok(true)
                })?;
            }
            tlv::SEAL_EPOCH => epoch = Some(read_epoch(v)?),
            tlv::RULE_SINCE => {
                each(v, |t, v| {
                    if t != tlv::FRONTIER {
                        return Ok(false);
                    }
                    since = Some(read_frontier(v)?);
                    Ok(true)
                })?;
            }
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    let missing = |what| bad(format!("a members record has {what}"));
    Ok(MembersBody {
        collection: collection.ok_or_else(|| missing("a collection"))?,
        revision: revision.ok_or_else(|| missing("a revision"))?,
        rule: rule.ok_or_else(|| missing("a rule"))?,
        writers: writers.ok_or_else(|| missing("writers"))?,
        readers: readers.ok_or_else(|| missing("readers"))?,
        cuts,
        epoch,
        since,
    })
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
            tlv::WRITER => {
                let mut r = TlvReader::new(v);
                let (t, v) = r.read_tlv().map_err(|e| bad(format!("bad TLV: {e:?}")))?;
                if t != tlv_type::NAME {
                    return Err(bad("a summary's writer is a key name"));
                }
                writer = Some(read_name(v)?);
            }
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
    Ok(NodeBody {
        subject: subject.ok_or_else(|| missing("a subject"))?,
        writer: writer.ok_or_else(|| missing("a writer"))?,
        head: head.ok_or_else(|| missing("a head"))?,
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
            let root = parse_summary_name(&summary_prefix(&d, &ns)).unwrap();
            assert_eq!(
                (root.device, root.subject, root.head, root.page),
                (d.clone(), ns.clone(), None, None)
            );
            let signed = parse_summary_name(&node_name(&d, &ns, 11)).unwrap();
            assert_eq!((signed.subject, signed.head), (ns.clone(), Some(11)));
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
        let root = parse_summary_name(&n("/alice/laptop/32=summary/alice/notes/seq=2")).unwrap();
        assert_eq!(subject_namespace(&root.subject), Some(n("/alice/notes")));
        // Without its head a node name is not one (only a root is discovered).
        assert_eq!(
            parse_summary_name(&summary_prefix(&d, &n("/alice/32=data/notes"))),
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
                accept: [crate::VersionId {
                    writer: Writer::new(n("/bob/laptop/KEY/1")),
                    seq: Seq(41),
                }]
                .into_iter()
                .collect(),
            }],
            epoch: Some(Epoch {
                creator: n("/alice/laptop"),
                seq: Seq(7),
            }),
            since: None,
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
        assert_eq!(decode_record(with(0x057E)), Ok(Record::Members(body)));
        assert!(decode_record(with(0x057F)).is_err());
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
        for of in [None, Some((n("/alice/32=data/docs/plan"), epoch))] {
            let ask = GrantAsk {
                seal_key: key.clone(),
                of,
            };
            let name = grant_name(&n("/alice/laptop"), &ask);
            assert_eq!(parse_grant_name(&name), Some((n("/alice/laptop"), ask)));
        }
        assert_eq!(
            decode_grant(encode_grant(&[1; 32], b"wrapped")),
            Ok(([1; 32], Bytes::from_static(b"wrapped")))
        );
    }
}
