//! The data layer's bytes: the names it publishes under and the TLV records
//! those Data packets carry (`docs/specs/data-layer.md`, "Wire format").
//!
//! Every packet a device publishes is named under its own device name `D`
//! (its key name without `KEY/<id>`), so the hierarchical trust schema — data
//! and key share their first component — admits it everywhere, and Interests
//! for it route to the device:
//!
//! | packet | name | signed by |
//! |---|---|---|
//! | log entry (version, members record) | `<D>/32=log/<collection>/seq=<n>` | the device key |
//! | log entry (snapshot) | `<D>/32=log/seq=<n>` | the device key |
//! | summary root of namespace `O` | `<D>/32=summary/<O>/seq=<head>` | the device key |
//! | summary node of `X` | `<D>/32=summary/<X>/seq=<head>` | DigestSha256; its parent lists its digest |
//! | summary page of `X` | `<D>/32=summary/<X>/32=page/<path>/seq=<head>` | DigestSha256; its parent lists its digest |
//!
//! Two names are never fetched: the state name `<collection>/32=state/<F>`
//! (the merged value at frontier `F`, computed by every reader) and the sync
//! group `<O>/32=sync` (State Vector Sync Interests, notifications only).
//!
//! TLV-TYPEs are allocated from 0x0520–0x057F, all even (non-critical): a
//! decoder skips an even TLV it does not know and refuses an odd one, so a
//! later revision can add fields old readers pass over and fields they must
//! not.

use bytes::Bytes;
use ndn_foundation_types::{Name, NameComponent, tlv_type};
use ndn_tlv::{TlvReader, TlvWriter};

use crate::collection::Rule;
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
}

/// Keyword components of the layer's names.
const LOG: &[u8] = b"log";
const SUMMARY: &[u8] = b"summary";
const PAGE: &[u8] = b"page";
const STATE: &[u8] = b"state";
const SYNC: &[u8] = b"sync";

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

/// Whether `name` can name a collection: not the root, and free of keyword
/// components (those mark the layer's own names).
pub fn is_collection_name(name: &Name) -> bool {
    !name.is_empty()
        && name
            .components()
            .iter()
            .all(|c| c.typ != tlv_type::KEYWORD && c.typ != tlv_type::IMPLICIT_SHA256)
}

/// The namespace a name lies in: its first component. A collection's owner
/// is the person whose namespace it is (the hierarchical trust schema's
/// unit); its sync group and every writer's summary root are per namespace.
pub fn namespace_of(name: &Name) -> Option<Name> {
    name.components()
        .first()
        .map(|c| Name::from_components([c.clone()]))
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

/// The sync group of namespace `ns`: `<ns>/32=sync`.
pub fn group_name(ns: &Name) -> Name {
    ns.clone().append_component(kw(SYNC))
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

/// Parse `<device>/32=log[/<subject>]/seq=<seq>`.
pub fn parse_log_name(name: &Name) -> Option<LogName> {
    let comps = name.components();
    let at = comps.iter().position(|c| is_kw(c, LOG))?;
    let seq = comps.last()?.as_sequence_num()?;
    if at == 0 || at + 1 >= comps.len() {
        return None;
    }
    let subject = &comps[at + 1..comps.len() - 1];
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
    /// The collection or folder summarised.
    pub subject: Name,
    /// The page path, for a page.
    pub page: Option<Bytes>,
    /// The head, when named.
    pub head: Option<u64>,
}

/// Parse a summary name or discovery prefix.
pub fn parse_summary_name(name: &Name) -> Option<SummaryName> {
    let comps = name.components();
    let at = comps.iter().position(|c| is_kw(c, SUMMARY))?;
    if at == 0 {
        return None;
    }
    let mut rest = &comps[at + 1..];
    let mut head = None;
    if let Some(s) = rest.last().and_then(NameComponent::as_sequence_num) {
        head = Some(s);
        rest = &rest[..rest.len() - 1];
    }
    let (subject, page) = match rest.iter().position(|c| is_kw(c, PAGE)) {
        Some(p) if p + 2 == rest.len() => (&rest[..p], Some(rest[p + 1].value.clone())),
        Some(_) => return None,
        None => (rest, None),
    };
    let subject = name_of(subject);
    is_collection_name(&subject).then(|| SummaryName {
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
    /// The fields the writer set (an empty value removes the field).
    pub fields: Content,
    /// The merge function's operation.
    pub op: Bytes,
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
        w.write_nested(tlv::FIELDS, |w| {
            for (name, value) in b.fields.fields() {
                w.write_nested(tlv::FIELD, |w| {
                    w.write_tlv(tlv::FIELD_NAME, name.as_bytes());
                    w.write_tlv(tlv::FIELD_VALUE, value);
                });
            }
        });
        w.write_tlv(tlv::MERGE_OP, &b.op);
    });
    w.finish()
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
            tlv::FIELDS => {
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
                                    String::from_utf8(v.to_vec())
                                        .map_err(|_| bad("a field name is UTF-8"))?,
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
                fields = Some(c);
            }
            tlv::MERGE_OP => op = Some(v),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    let missing = |what| bad(format!("a version record has {what}"));
    Ok(VersionBody {
        collection: collection.ok_or_else(|| missing("a collection"))?,
        parents: parents.ok_or_else(|| missing("parents"))?,
        type_id: type_id.ok_or_else(|| missing("a type"))?,
        seal: seal.ok_or_else(|| missing("a seal"))?,
        keep: keep.ok_or_else(|| missing("a keep"))?,
        dated: dated.ok_or_else(|| missing("a date"))?,
        fields: fields.ok_or_else(|| missing("fields"))?,
        op: op.ok_or_else(|| missing("a merge op"))?,
    })
}

fn decode_members(value: Bytes) -> Result<MembersBody, WireError> {
    let mut collection = None;
    let mut revision = None;
    let mut rule = None;
    let mut writers = None;
    let mut readers = None;
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
        let d = n("/alice/laptop");
        let c = n("/alice/notes/trip");
        let log = log_name(&d, Some(&c), 9);
        assert_eq!(
            parse_log_name(&log),
            Some(LogName {
                device: d.clone(),
                subject: Some(c.clone()),
                seq: 9
            })
        );
        let snap = log_name(&d, None, 3);
        assert_eq!(parse_log_name(&snap).unwrap().subject, None);
        let page = page_name(&d, &c, &[3, 10], 7);
        let p = parse_summary_name(&page).unwrap();
        assert_eq!((p.device, p.subject), (d.clone(), c.clone()));
        assert_eq!(p.page.as_deref(), Some(&[3u8, 10][..]));
        assert_eq!(p.head, Some(7));
        let root = parse_summary_name(&summary_prefix(&d, &n("/alice"))).unwrap();
        assert_eq!(
            (root.subject, root.head, root.page),
            (n("/alice"), None, None)
        );
        let at: Frontier = [crate::VersionId {
            writer: Writer::new(n("/alice/laptop/KEY/1")),
            seq: Seq(4),
        }]
        .into_iter()
        .collect();
        assert_eq!(parse_state_name(&state_name(&c, &at)), Some((c, at)));
        assert_eq!(device_of(&n("/alice/laptop/KEY/1")), Some(d));
    }

    #[test]
    fn unknown_even_fields_are_skipped_and_odd_ones_refused() {
        let body = MembersBody {
            collection: n("/alice/notes"),
            revision: 1,
            rule: Rule::Merge {
                function: n("/merge/yrs"),
            },
            writers: vec![n("/alice")],
            readers: vec![Audience::Person(n("/alice"))],
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
        assert_eq!(decode_record(with(0x0570)), Ok(Record::Members(body)));
        assert!(decode_record(with(0x0571)).is_err());
    }
}
