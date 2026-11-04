//! Cut manifests: the bytes a [`RevocationCut`](crate::RevocationCut)'s
//! ranges accept.
//!
//! A cut's ranges name Data (`<prefix>/seq=<n>`); a manifest binds each of
//! those names to one packet. It is a tree of self-certifying Data packets
//! (DigestSha256 signature) named
//! `/<ns>/32=trust-context/32=cut/<SHA-256 of the key Name TLV>/seg=<i>`
//! ([`manifest_prefix`]), the root `seg=0`. The cut carries the root's full
//! name ([`tlv::CUT_MANIFEST`]), so
//! the root-signed context vouches for the root packet by its implicit
//! digest, and each node vouches for its children the same way: any holder
//! may serve them, and a packet is only ever taken under its own digest.
//!
//! Content (all TLV-TYPEs even, see [`tlv`]):
//!
//! ```text
//! CutManifestNode = 0x0436 TLV-LENGTH (*ManifestRange / 1*ManifestChild)
//! ManifestRange   = 0x0438 TLV-LENGTH Name 1*ManifestEntry
//! ManifestEntry   = 0x043A TLV-LENGTH SequenceNumNameComponent ImplicitSha256DigestComponent
//! ManifestChild   = 0x043C TLV-LENGTH ManifestBound ManifestBound Name
//! ManifestBound   = 0x043E TLV-LENGTH Name SequenceNumNameComponent
//! ```
//!
//! A leaf lists, per CutRange prefix (canonical order, once per node), the
//! sequence number (strictly ascending) and implicit digest of every entry
//! the cut keeps. When the entries do not fit one packet
//! ([`MAX_PACKET_SIZE`]), they are split over leaves, and interior nodes list
//! their children with the first and last (prefix, sequence number) each
//! covers (strictly ascending, non-overlapping) and the child's full name.
//! A packet that breaks these rules lists nothing.
//!
//! The validator holds manifest packets in its certificate cache
//! ([`CertCache::cut_manifests`](crate::CertCache::cut_manifests)); a durable
//! walk that needs one it does not hold is pending on that packet's full
//! name, fetched like a missing certificate.

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use dashmap::DashMap;
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Name, NameComponent, SignatureType, tlv_type};
use ndn_tlv::TlvWriter;

use crate::trust_context::{TRUST_CONTEXT_KEYWORD, tlv};
use crate::verifier::{VerifyOutcome, verify_digest};

/// Largest manifest packet the builder makes, in octets (whole Data wire).
pub const MAX_PACKET_SIZE: usize = 8000;

/// Deepest manifest tree a lookup follows (root at depth 0); a deeper path
/// lists nothing.
pub const MAX_DEPTH: usize = 8;

/// FreshnessPeriod of manifest packets: their content never changes (each
/// is named by its digest wherever it is referenced), so a cached copy
/// answers fetches that ask for fresh Data.
pub const FRESHNESS: Duration = Duration::from_secs(3600);

/// Manifest packets a [`CutManifests`] holds by default.
pub const DEFAULT_CAPACITY: usize = 1024;

const CUT_KEYWORD: &[u8] = b"cut";

/// Why a manifest could not be built or a packet is no manifest node.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CutManifestError {
    /// The packet is not signed with a valid DigestSha256: manifest packets
    /// are self-certifying, trusted by the digest that names them.
    #[error(
        "a cut-manifest packet must carry a valid DigestSha256 signature (it is trusted by its \
         implicit digest); this one does not"
    )]
    NotDigestSigned,
    /// The content is not a well-formed manifest node.
    #[error("malformed cut-manifest content: {0}")]
    Malformed(&'static str),
    /// Two different digests were given for one entry.
    #[error(
        "two different digests for {prefix}/seq={seq}: a manifest lists one packet per entry \
         (keep only the entry the root holds verified)"
    )]
    TwoDigests {
        /// The entry's CutRange prefix.
        prefix: Name,
        /// Its sequence number.
        seq: u64,
    },
    /// A name is too long for even one entry or child per packet.
    #[error(
        "a prefix or the manifest name is too long to fit one entry per {MAX_PACKET_SIZE}-octet \
         packet; shorten the namespace or the collection names"
    )]
    TooLarge,
}

/// The name prefix of the manifest packets of the cut of `key` in the
/// namespace `namespace`: `/<ns>/32=trust-context/32=cut/<h>`, `<h>` a
/// GenericNameComponent holding the SHA-256 of `key`'s Name TLV.
pub fn manifest_prefix(namespace: &Name, key: &Name) -> Name {
    use sha2::{Digest, Sha256};
    let hash: [u8; 32] = Sha256::digest(key.encode_to_tlv()).into();
    namespace
        .clone()
        .append_component(NameComponent::keyword(Bytes::from_static(
            TRUST_CONTEXT_KEYWORD,
        )))
        .append_component(NameComponent::keyword(Bytes::from_static(CUT_KEYWORD)))
        .append_component(NameComponent::generic(Bytes::copy_from_slice(&hash)))
}

/// A built manifest: the root's full name (for
/// [`RevocationCut::set_manifest`](crate::RevocationCut::set_manifest)) and
/// every packet's wire, the root first.
#[derive(Clone, Debug)]
pub struct BuiltManifest {
    /// Full name (ending in its implicit digest) of the root packet.
    pub root: Name,
    /// Every packet of the tree, root first.
    pub packets: Vec<Bytes>,
}

/// One CutRange prefix of a leaf: the entries listed under it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestRange {
    /// The CutRange prefix.
    pub prefix: Name,
    /// `(sequence number, implicit digest)`, strictly ascending.
    pub entries: Vec<(u64, [u8; 32])>,
}

/// One child of an interior node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestChild {
    /// The first (prefix, sequence number) the child covers.
    pub first: (Name, u64),
    /// The last (prefix, sequence number) the child covers.
    pub last: (Name, u64),
    /// The child packet's full name (ending in its implicit digest).
    pub child: Name,
}

/// The content of one manifest packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManifestNode {
    /// Entries, per prefix.
    Leaf(Vec<ManifestRange>),
    /// Children, each covering a span of entries.
    Interior(Vec<ManifestChild>),
}

/// What a manifest says about one entry ([`CutManifests::lookup`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManifestLookup {
    /// The manifest lists the entry with this implicit digest.
    Listed([u8; 32]),
    /// The manifest does not list the entry (or a packet on its path is
    /// malformed, or the path is deeper than [`MAX_DEPTH`]).
    NotListed,
    /// A manifest packet on the entry's path is not held: fetch it by this
    /// full name, then look again.
    Missing(Name),
}

/// One step of a lookup through a node.
enum Step<'a> {
    Found([u8; 32]),
    Absent,
    Child(&'a Name),
}

fn cmp_key(a: (&Name, u64), b: (&Name, u64)) -> std::cmp::Ordering {
    a.0.cmp(b.0).then(a.1.cmp(&b.1))
}

impl ManifestNode {
    fn step(&self, prefix: &Name, seq: u64) -> Step<'_> {
        match self {
            ManifestNode::Leaf(ranges) => ranges
                .binary_search_by(|r| r.prefix.cmp(prefix))
                .ok()
                .and_then(|i| {
                    let entries = &ranges[i].entries;
                    entries
                        .binary_search_by(|(s, _)| s.cmp(&seq))
                        .ok()
                        .map(|j| Step::Found(entries[j].1))
                })
                .unwrap_or(Step::Absent),
            ManifestNode::Interior(children) => {
                let key = (prefix, seq);
                let i = children.partition_point(|c| cmp_key((&c.last.0, c.last.1), key).is_lt());
                children
                    .get(i)
                    .filter(|c| cmp_key((&c.first.0, c.first.1), key).is_le())
                    .map_or(Step::Absent, |c| Step::Child(&c.child))
            }
        }
    }

    /// The full names of this node's children (none for a leaf).
    pub fn children(&self) -> Vec<Name> {
        match self {
            ManifestNode::Leaf(_) => Vec::new(),
            ManifestNode::Interior(children) => children.iter().map(|c| c.child.clone()).collect(),
        }
    }

    /// The node as its [`tlv::MANIFEST_NODE`] TLV (a packet's Content).
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(tlv::MANIFEST_NODE, |w| match self {
            ManifestNode::Leaf(ranges) => {
                for range in ranges {
                    w.write_nested(tlv::MANIFEST_RANGE, |w| {
                        w.write_raw(&range.prefix.encode_to_tlv());
                        for (seq, digest) in &range.entries {
                            w.write_nested(tlv::MANIFEST_ENTRY, |w| {
                                let seq = NameComponent::sequence_num(*seq);
                                w.write_tlv(seq.typ, &seq.value);
                                w.write_tlv(tlv_type::IMPLICIT_SHA256, digest);
                            });
                        }
                    });
                }
            }
            ManifestNode::Interior(children) => {
                for child in children {
                    w.write_nested(tlv::MANIFEST_CHILD, |w| {
                        for (prefix, seq) in [&child.first, &child.last] {
                            w.write_nested(tlv::MANIFEST_BOUND, |w| {
                                w.write_raw(&prefix.encode_to_tlv());
                                let seq = NameComponent::sequence_num(*seq);
                                w.write_tlv(seq.typ, &seq.value);
                            });
                        }
                        w.write_raw(&child.child.encode_to_tlv());
                    });
                }
            }
        });
        w.finish()
    }

    /// Decode a [`tlv::MANIFEST_NODE`] TLV (a packet's Content), refusing
    /// anything that breaks the canonical rules (see the module docs).
    pub fn decode(content: &[u8]) -> Result<Self, CutManifestError> {
        let malformed = CutManifestError::Malformed;
        let (t, value, rest) = read_tlv(content).ok_or(malformed("not a TLV"))?;
        if t != tlv::MANIFEST_NODE || !rest.is_empty() {
            return Err(malformed(
                "the content must be one CutManifestNode (0x0436)",
            ));
        }
        let mut ranges: Vec<ManifestRange> = Vec::new();
        let mut children: Vec<ManifestChild> = Vec::new();
        let mut cur = value;
        while !cur.is_empty() {
            let (t, v, rest) = read_tlv(cur).ok_or(malformed("a truncated element"))?;
            cur = rest;
            match t {
                tlv::MANIFEST_RANGE => {
                    let range = decode_range(v)?;
                    if ranges
                        .last()
                        .is_some_and(|prev| prev.prefix >= range.prefix)
                    {
                        return Err(malformed("ranges out of canonical order or repeated"));
                    }
                    ranges.push(range);
                }
                tlv::MANIFEST_CHILD => {
                    let child = decode_child(v)?;
                    if children.last().is_some_and(|prev| {
                        cmp_key((&prev.last.0, prev.last.1), (&child.first.0, child.first.1))
                            .is_ge()
                    }) {
                        return Err(malformed("children out of order or overlapping"));
                    }
                    children.push(child);
                }
                other if other <= 31 || other & 1 == 1 => {
                    return Err(malformed("an unknown critical element"));
                }
                _ => {}
            }
        }
        match (ranges.is_empty(), children.is_empty()) {
            (_, true) => Ok(ManifestNode::Leaf(ranges)),
            (true, false) => Ok(ManifestNode::Interior(children)),
            (false, false) => Err(malformed("a node holds both ranges and children")),
        }
    }
}

fn read_tlv(input: &[u8]) -> Option<(u64, &[u8], &[u8])> {
    let (t, tn) = ndn_tlv::read_varu64(input).ok()?;
    let (l, ln) = ndn_tlv::read_varu64(&input[tn..]).ok()?;
    let start = tn + ln;
    let end = start.checked_add(usize::try_from(l).ok()?)?;
    (end <= input.len()).then(|| (t, &input[start..end], &input[end..]))
}

/// A Name TLV at the head of `v`, and what follows it.
fn read_name(v: &[u8]) -> Result<(Name, &[u8]), CutManifestError> {
    let (t, name, rest) = read_tlv(v).ok_or(CutManifestError::Malformed("a truncated Name"))?;
    if t != tlv_type::NAME {
        return Err(CutManifestError::Malformed("a Name was expected"));
    }
    let name = Name::decode(Bytes::copy_from_slice(name))
        .map_err(|_| CutManifestError::Malformed("a malformed Name"))?;
    Ok((name, rest))
}

/// A minimally encoded SequenceNumNameComponent at the head of `v`.
fn read_seq(v: &[u8]) -> Result<(u64, &[u8]), CutManifestError> {
    let bad = CutManifestError::Malformed("a minimally encoded SequenceNumNameComponent");
    let (t, value, rest) = read_tlv(v).ok_or(bad.clone())?;
    let comp = NameComponent::new(t, Bytes::copy_from_slice(value));
    let seq = comp.as_sequence_num().ok_or(bad.clone())?;
    if comp != NameComponent::sequence_num(seq) {
        return Err(bad);
    }
    Ok((seq, rest))
}

fn decode_range(v: &[u8]) -> Result<ManifestRange, CutManifestError> {
    let malformed = CutManifestError::Malformed;
    let (prefix, mut cur) = read_name(v)?;
    let mut entries: Vec<(u64, [u8; 32])> = Vec::new();
    while !cur.is_empty() {
        let (t, e, rest) = read_tlv(cur).ok_or(malformed("a truncated entry"))?;
        cur = rest;
        if t != tlv::MANIFEST_ENTRY {
            if t <= 31 || t & 1 == 1 {
                return Err(malformed("an unknown critical element in a range"));
            }
            continue;
        }
        let (seq, rest) = read_seq(e)?;
        let (dt, digest, rest) = read_tlv(rest).ok_or(malformed("a truncated digest"))?;
        let digest = <[u8; 32]>::try_from(digest)
            .ok()
            .filter(|_| dt == tlv_type::IMPLICIT_SHA256 && rest.is_empty())
            .ok_or(malformed(
                "an entry must be a SequenceNum and a 32-octet ImplicitSha256Digest",
            ))?;
        if entries.last().is_some_and(|&(prev, _)| prev >= seq) {
            return Err(malformed("entries not strictly ascending"));
        }
        entries.push((seq, digest));
    }
    if entries.is_empty() {
        return Err(malformed("a range without entries"));
    }
    Ok(ManifestRange { prefix, entries })
}

fn decode_bound(v: &[u8]) -> Result<((Name, u64), &[u8]), CutManifestError> {
    let malformed = CutManifestError::Malformed;
    let (t, b, rest) = read_tlv(v).ok_or(malformed("a truncated bound"))?;
    if t != tlv::MANIFEST_BOUND {
        return Err(malformed("a child starts with two ManifestBounds"));
    }
    let (prefix, b) = read_name(b)?;
    let (seq, b) = read_seq(b)?;
    if !b.is_empty() {
        return Err(malformed("octets after a bound's sequence number"));
    }
    Ok(((prefix, seq), rest))
}

fn decode_child(v: &[u8]) -> Result<ManifestChild, CutManifestError> {
    let malformed = CutManifestError::Malformed;
    let (first, rest) = decode_bound(v)?;
    let (last, rest) = decode_bound(rest)?;
    let (child, rest) = read_name(rest)?;
    if !rest.is_empty() {
        return Err(malformed("octets after a child's name"));
    }
    if cmp_key((&first.0, first.1), (&last.0, last.1)).is_gt() {
        return Err(malformed("a child whose first bound is after its last"));
    }
    if !child
        .components()
        .last()
        .is_some_and(|c| c.typ == tlv_type::IMPLICIT_SHA256 && c.value.len() == 32)
    {
        return Err(malformed(
            "a child name must end in its 32-octet implicit digest",
        ));
    }
    Ok(ManifestChild { first, last, child })
}

/// The manifest node `data` carries: it must be signed with a valid
/// DigestSha256 and hold a well-formed [`tlv::MANIFEST_NODE`].
pub fn parse(data: &Data) -> Result<ManifestNode, CutManifestError> {
    let signed = data.sig_info().is_some_and(|s| {
        s.sig_type == SignatureType::DigestSha256
            && matches!(
                verify_digest(s.sig_type, data.signed_region(), data.sig_value()),
                Ok(VerifyOutcome::Valid)
            )
    });
    if !signed {
        return Err(CutManifestError::NotDigestSigned);
    }
    let content = data
        .content()
        .ok_or(CutManifestError::Malformed("no Content"))?;
    ManifestNode::decode(content)
}

/// The full names of the children `data` (a manifest packet) lists, to
/// fetch the whole tree by full name.
pub fn children(data: &Data) -> Result<Vec<Name>, CutManifestError> {
    parse(data).map(|node| node.children())
}

/// A node being built, with the first and last entry it covers.
struct Built {
    node: ManifestNode,
    first: Option<(Name, u64)>,
    last: Option<(Name, u64)>,
}

/// Octets of a TLV header (type + length) for `typ` and a value of `len`.
fn header(typ: u64, len: usize) -> usize {
    let var = |v: u64| match v {
        0..=252 => 1,
        253..=0xFFFF => 3,
        0x1_0000..=0xFFFF_FFFF => 5,
        _ => 9,
    };
    var(typ) + var(len as u64)
}

fn seq_size(seq: u64) -> usize {
    let c = NameComponent::sequence_num(seq);
    header(c.typ, c.value.len()) + c.value.len()
}

/// Build the manifest of the cut of `key` in `namespace` listing `entries`
/// (`(CutRange prefix, sequence number, implicit digest)`, any order;
/// repeats of one entry with one digest are listed once). Packets are at
/// most [`MAX_PACKET_SIZE`] octets: entries are split over leaves, and
/// interior nodes are added until one root remains. Set the result's
/// [`root`](BuiltManifest::root) on the cut and publish every packet.
pub fn build(
    namespace: &Name,
    key: &Name,
    entries: &[(Name, u64, [u8; 32])],
) -> Result<BuiltManifest, CutManifestError> {
    let prefix = manifest_prefix(namespace, key);
    let mut sorted: Vec<&(Name, u64, [u8; 32])> = entries.iter().collect();
    sorted.sort_by(|a, b| cmp_key((&a.0, a.1), (&b.0, b.1)));
    sorted.dedup();
    if let Some(w) = sorted
        .windows(2)
        .find(|w| w[0].0 == w[1].0 && w[0].1 == w[1].1)
    {
        return Err(CutManifestError::TwoDigests {
            prefix: w[0].0.clone(),
            seq: w[0].1,
        });
    }

    // Octets left for the node's elements: a packet of the largest
    // segment number with empty content, plus the growth of the Content
    // and Data length fields and the node's own header (bounded).
    let empty = packet(&prefix, u64::MAX, &[]);
    let budget = MAX_PACKET_SIZE
        .checked_sub(empty.len() + 4 + header(tlv::MANIFEST_NODE, MAX_PACKET_SIZE))
        .ok_or(CutManifestError::TooLarge)?;

    let mut level = pack_leaves(&sorted, budget)?;
    let mut packets: Vec<Bytes> = Vec::new();
    let mut next_seg: u64 = 1;
    for _ in 0..MAX_DEPTH {
        if level.len() == 1 {
            let root = packet(&prefix, 0, &level[0].node.encode());
            let root_name = full_name(&root);
            packets.insert(0, root);
            return Ok(BuiltManifest {
                root: root_name,
                packets,
            });
        }
        let mut refs: Vec<ManifestChild> = Vec::with_capacity(level.len());
        for built in level {
            let wire = packet(&prefix, next_seg, &built.node.encode());
            next_seg += 1;
            refs.push(ManifestChild {
                // Only the root of a one-node level may be empty.
                first: built.first.ok_or(CutManifestError::TooLarge)?,
                last: built.last.ok_or(CutManifestError::TooLarge)?,
                child: full_name(&wire),
            });
            packets.push(wire);
        }
        let count = refs.len();
        level = pack_children(refs, budget)?;
        if level.len() >= count {
            return Err(CutManifestError::TooLarge);
        }
    }
    Err(CutManifestError::TooLarge)
}

/// The manifest packet `seg` under `prefix` holding `content`.
fn packet(prefix: &Name, seg: u64, content: &[u8]) -> Bytes {
    DataBuilder::new(prefix.clone().append_segment(seg), content)
        .freshness(FRESHNESS)
        .sign_digest_sha256()
}

fn full_name(wire: &Bytes) -> Name {
    // Our own encoding: it decodes.
    let data = Data::decode(wire.clone()).expect("a manifest packet this module encoded");
    data.name
        .as_ref()
        .clone()
        .append_implicit_digest(data.implicit_digest())
}

fn pack_leaves(
    sorted: &[&(Name, u64, [u8; 32])],
    budget: usize,
) -> Result<Vec<Built>, CutManifestError> {
    let entry_size = |seq: u64| {
        let value = seq_size(seq) + header(tlv_type::IMPLICIT_SHA256, 32) + 32;
        header(tlv::MANIFEST_ENTRY, value) + value
    };
    // A range header with the largest length field a packet needs.
    let range_size =
        |prefix: &Name| header(tlv::MANIFEST_RANGE, MAX_PACKET_SIZE) + prefix.encode_to_tlv().len();
    let mut leaves: Vec<Built> = Vec::new();
    let mut ranges: Vec<ManifestRange> = Vec::new();
    let mut used = 0usize;
    let mut first: Option<(Name, u64)> = None;
    let mut last: Option<(Name, u64)> = None;
    for (p, seq, digest) in sorted.iter().map(|e| (&e.0, e.1, e.2)) {
        let open = ranges.last().is_some_and(|r| r.prefix == *p);
        let cost = entry_size(seq) + if open { 0 } else { range_size(p) };
        if used + cost > budget {
            if ranges.is_empty() {
                return Err(CutManifestError::TooLarge);
            }
            leaves.push(Built {
                node: ManifestNode::Leaf(std::mem::take(&mut ranges)),
                first: first.take(),
                last: last.take(),
            });
            used = 0;
            return_if_too_large(entry_size(seq) + range_size(p), budget)?;
        }
        match ranges.last_mut() {
            Some(r) if r.prefix == *p => r.entries.push((seq, digest)),
            _ => {
                used += range_size(p);
                ranges.push(ManifestRange {
                    prefix: p.clone(),
                    entries: vec![(seq, digest)],
                });
            }
        }
        used += entry_size(seq);
        first.get_or_insert_with(|| (p.clone(), seq));
        last = Some((p.clone(), seq));
    }
    leaves.push(Built {
        node: ManifestNode::Leaf(ranges),
        first,
        last,
    });
    Ok(leaves)
}

fn return_if_too_large(cost: usize, budget: usize) -> Result<(), CutManifestError> {
    if cost > budget {
        return Err(CutManifestError::TooLarge);
    }
    Ok(())
}

fn pack_children(refs: Vec<ManifestChild>, budget: usize) -> Result<Vec<Built>, CutManifestError> {
    let bound_size = |(prefix, seq): &(Name, u64)| {
        let value = prefix.encode_to_tlv().len() + seq_size(*seq);
        header(tlv::MANIFEST_BOUND, value) + value
    };
    let child_size = |c: &ManifestChild| {
        let value = bound_size(&c.first) + bound_size(&c.last) + c.child.encode_to_tlv().len();
        header(tlv::MANIFEST_CHILD, value) + value
    };
    let mut nodes: Vec<Built> = Vec::new();
    let mut children: Vec<ManifestChild> = Vec::new();
    let mut used = 0usize;
    for child in refs {
        let cost = child_size(&child);
        return_if_too_large(cost, budget)?;
        if used + cost > budget {
            nodes.push(interior(std::mem::take(&mut children)));
            used = 0;
        }
        used += cost;
        children.push(child);
    }
    nodes.push(interior(children));
    Ok(nodes)
}

fn interior(children: Vec<ManifestChild>) -> Built {
    Built {
        first: children.first().map(|c| c.first.clone()),
        last: children.last().map(|c| c.last.clone()),
        node: ManifestNode::Interior(children),
    }
}

/// A held manifest packet.
enum Held {
    Node(Arc<ManifestNode>, Bytes),
    /// Taken under its digest, but no manifest node: it lists nothing.
    Malformed(Bytes),
}

/// Manifest packets a node holds, by full name, bounded (the oldest taken
/// leaves first). Shared by a validator and its certificate fetcher through
/// the [`CertCache`](crate::CertCache).
pub struct CutManifests {
    held: DashMap<Name, Held>,
    order: Mutex<VecDeque<Name>>,
    capacity: usize,
}

impl Default for CutManifests {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}

impl std::fmt::Debug for CutManifests {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CutManifests")
            .field("held", &self.held.len())
            .field("capacity", &self.capacity)
            .finish()
    }
}

impl CutManifests {
    /// An empty store holding at most `capacity` packets (at least one).
    pub fn new(capacity: usize) -> Self {
        Self {
            held: DashMap::new(),
            order: Mutex::new(VecDeque::new()),
            capacity: capacity.max(1),
        }
    }

    /// Take the manifest packet `data` under its full name (its name plus
    /// its implicit digest), returned. A packet that is no manifest node is
    /// held too — it is what that full name names, and it lists nothing —
    /// and its error returned.
    pub fn insert(&self, data: &Data) -> Result<Name, CutManifestError> {
        let full = data
            .name
            .as_ref()
            .clone()
            .append_implicit_digest(data.implicit_digest());
        let parsed = parse(data);
        let held = match &parsed {
            Ok(node) => Held::Node(Arc::new(node.clone()), data.raw().clone()),
            Err(_) => Held::Malformed(data.raw().clone()),
        };
        if self.held.insert(full.clone(), held).is_none() {
            let mut order = self.order.lock().unwrap_or_else(PoisonError::into_inner);
            order.push_back(full.clone());
            while order.len() > self.capacity {
                if let Some(oldest) = order.pop_front() {
                    self.held.remove(&oldest);
                }
            }
        }
        parsed.map(|_| full)
    }

    /// Whether the packet `full_name` names is held.
    pub fn contains(&self, full_name: &Name) -> bool {
        self.held.contains_key(full_name)
    }

    /// The wire of the packet `full_name` names, if held.
    pub fn get(&self, full_name: &Name) -> Option<Bytes> {
        self.held.get(full_name).map(|h| match h.value() {
            Held::Node(_, wire) | Held::Malformed(wire) => wire.clone(),
        })
    }

    /// What the manifest rooted at `root` (a full name) says about the
    /// entry `prefix` + `seq`.
    pub fn lookup(&self, root: &Name, prefix: &Name, seq: u64) -> ManifestLookup {
        let mut at = root.clone();
        for _ in 0..=MAX_DEPTH {
            let node = match self.held.get(&at) {
                None => return ManifestLookup::Missing(at),
                Some(held) => match held.value() {
                    Held::Malformed(_) => return ManifestLookup::NotListed,
                    Held::Node(node, _) => Arc::clone(node),
                },
            };
            match node.step(prefix, seq) {
                Step::Found(digest) => return ManifestLookup::Listed(digest),
                Step::Absent => return ManifestLookup::NotListed,
                Step::Child(child) => at = child.clone(),
            }
        }
        ManifestLookup::NotListed
    }

    /// The full names of the packets of the tree rooted at `root` that are
    /// not held, as far as the held ones tell (the root itself when it is
    /// not held). Fetch them by full name and ask again until it is empty:
    /// the whole tree is then held, each packet under its own digest.
    pub fn missing(&self, root: &Name) -> Vec<Name> {
        let mut missing = Vec::new();
        let mut seen: HashSet<Name> = HashSet::new();
        let mut queue: VecDeque<(Name, usize)> = VecDeque::from([(root.clone(), 0)]);
        while let Some((at, depth)) = queue.pop_front() {
            if depth > MAX_DEPTH || !seen.insert(at.clone()) {
                continue;
            }
            let children = match self.held.get(&at) {
                None => {
                    missing.push(at);
                    continue;
                }
                Some(held) => match held.value() {
                    Held::Node(node, _) => node.children(),
                    Held::Malformed(_) => Vec::new(),
                },
            };
            queue.extend(children.into_iter().map(|c| (c, depth + 1)));
        }
        missing
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn entries(prefixes: &[&str], per_prefix: u64) -> Vec<(Name, u64, [u8; 32])> {
        let mut out = Vec::new();
        for (p, prefix) in prefixes.iter().enumerate() {
            for seq in 1..=per_prefix {
                let mut digest = [0u8; 32];
                digest[..8].copy_from_slice(&seq.to_be_bytes());
                digest[8] = p as u8;
                out.push((n(prefix), seq, digest));
            }
        }
        out
    }

    fn held(built: &BuiltManifest) -> CutManifests {
        let store = CutManifests::default();
        for wire in &built.packets {
            store.insert(&Data::decode(wire.clone()).unwrap()).unwrap();
        }
        store
    }

    /// Every listed entry is found with its digest, through as many levels
    /// as it takes, and nothing else is listed.
    #[test]
    fn a_manifest_lists_exactly_its_entries_whatever_its_size() {
        let ns = n("/home/bob");
        let key = n("/home/bob/member/phone/KEY/k1");
        for (prefixes, per) in [
            (&["/home/bob/member/phone/log/notes"][..], 3),
            (
                &["/home/bob/member/phone/log", "/home/bob/member/phone/log/a"][..],
                900,
            ),
            (
                &[
                    "/home/bob/member/phone/log/a",
                    "/home/bob/member/phone/log/b",
                ][..],
                20_000,
            ),
        ] {
            let listed = entries(prefixes, per);
            let built = build(&ns, &key, &listed).unwrap();
            assert!(
                built.packets.iter().all(|p| p.len() <= MAX_PACKET_SIZE),
                "every packet fits"
            );
            assert_eq!(built.packets.len() > 1, per > 3, "split only when needed");
            let root = Data::decode(built.packets[0].clone()).unwrap();
            assert_eq!(
                root.name
                    .as_ref()
                    .clone()
                    .append_implicit_digest(root.implicit_digest()),
                built.root
            );
            assert!(root.name.has_prefix(&manifest_prefix(&ns, &key)));
            let store = held(&built);
            assert!(store.missing(&built.root).is_empty());
            for (prefix, seq, digest) in &listed {
                assert_eq!(
                    store.lookup(&built.root, prefix, *seq),
                    ManifestLookup::Listed(*digest)
                );
            }
            for (prefix, seq) in [
                (n(prefixes[0]), 0),
                (n(prefixes[0]), per + 1),
                (n("/home/bob/member/phone/log/zzz"), 1),
                (n("/home/bob/member/phone"), 1),
            ] {
                assert_eq!(
                    store.lookup(&built.root, &prefix, seq),
                    ManifestLookup::NotListed,
                    "{prefix}/{seq}"
                );
            }
        }
    }

    /// A lookup names the first packet on the path that is not held, and a
    /// packet is only taken under its own digest.
    #[test]
    fn a_missing_node_is_named_and_only_its_bytes_answer() {
        let ns = n("/home/bob");
        let key = n("/home/bob/member/phone/KEY/k1");
        let listed = entries(&["/home/bob/member/phone/log/a"], 2_000);
        let built = build(&ns, &key, &listed).unwrap();
        let store = CutManifests::default();
        let (prefix, seq, digest) = &listed[1_500];
        assert_eq!(
            store.lookup(&built.root, prefix, *seq),
            ManifestLookup::Missing(built.root.clone())
        );
        store
            .insert(&Data::decode(built.packets[0].clone()).unwrap())
            .unwrap();
        let ManifestLookup::Missing(child) = store.lookup(&built.root, prefix, *seq) else {
            panic!("the leaf is not held yet");
        };
        assert!(store.missing(&built.root).contains(&child));
        // Another packet under the child's name does not answer for it.
        let mut forged_name = child.clone();
        forged_name = Name::from_components(
            forged_name.components()[..forged_name.len() - 1]
                .iter()
                .cloned(),
        );
        let forged = DataBuilder::new(forged_name, &ManifestNode::Leaf(Vec::new()).encode())
            .sign_digest_sha256();
        store.insert(&Data::decode(forged).unwrap()).unwrap();
        assert_eq!(
            store.lookup(&built.root, prefix, *seq),
            ManifestLookup::Missing(child)
        );
        for wire in &built.packets {
            store.insert(&Data::decode(wire.clone()).unwrap()).unwrap();
        }
        assert_eq!(
            store.lookup(&built.root, prefix, *seq),
            ManifestLookup::Listed(*digest)
        );
    }

    #[test]
    fn two_digests_for_one_entry_are_refused() {
        let p = n("/home/bob/member/phone/log/a");
        let err = build(
            &n("/home/bob"),
            &n("/home/bob/member/phone/KEY/k1"),
            &[
                (p.clone(), 3, [1; 32]),
                (p.clone(), 3, [2; 32]),
                (p, 3, [1; 32]),
            ],
        )
        .unwrap_err();
        assert!(matches!(err, CutManifestError::TwoDigests { seq: 3, .. }));
    }

    /// A packet that is not DigestSha256-signed, or whose content breaks
    /// the canonical rules, is no manifest node.
    #[test]
    fn malformed_manifest_packets_are_refused() {
        let name = n("/home/bob/32=trust-context/32=cut/x/seg=0");
        let p = n("/p");
        let leaf = |ranges: Vec<ManifestRange>| ManifestNode::Leaf(ranges).encode();
        let range = |prefix: &Name, entries: Vec<(u64, [u8; 32])>| ManifestRange {
            prefix: prefix.clone(),
            entries,
        };
        let digest_signed = |content: &[u8]| {
            Data::decode(DataBuilder::new(name.clone(), content).sign_digest_sha256()).unwrap()
        };
        let good = leaf(vec![range(&p, vec![(1, [0; 32]), (2, [0; 32])])]);
        assert!(parse(&digest_signed(&good)).is_ok());
        // Another signature type (here an Ed25519 signature by some key):
        // a manifest packet is trusted by its digest, never by a signer.
        let signed = Data::decode(DataBuilder::new(name.clone(), &good).sign_sync(
            SignatureType::SignatureEd25519,
            Some(&n("/home/bob/KEY/k")),
            |_| Bytes::from_static(&[0; 64]),
        ))
        .unwrap();
        assert_eq!(parse(&signed), Err(CutManifestError::NotDigestSigned));
        for bad in [
            leaf(vec![range(&p, vec![(2, [0; 32]), (1, [0; 32])])]),
            leaf(vec![range(&p, vec![(1, [0; 32]), (1, [0; 32])])]),
            leaf(vec![range(&p, Vec::new())]),
            leaf(vec![
                range(&n("/q"), vec![(1, [0; 32])]),
                range(&p, vec![(1, [0; 32])]),
            ]),
            ManifestNode::Interior(vec![ManifestChild {
                first: (p.clone(), 5),
                last: (p.clone(), 1),
                child: n("/c").append_implicit_digest([0; 32]),
            }])
            .encode(),
            ManifestNode::Interior(vec![ManifestChild {
                first: (p.clone(), 1),
                last: (p.clone(), 5),
                child: n("/c"),
            }])
            .encode(),
            Bytes::from_static(&[0x06, 0x00]),
        ] {
            assert!(
                matches!(
                    parse(&digest_signed(&bad)),
                    Err(CutManifestError::Malformed(_))
                ),
                "{bad:02x?}"
            );
        }
    }
}
