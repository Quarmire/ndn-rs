//! SVS-PS mapping provider (gap #6): the seq→name backfill that lets a
//! late joiner learn what application name each sequence number stands
//! for, so it can selectively fetch history it never saw advertised.
//!
//! A [`SyncUpdate`](crate::SyncUpdate) tells a subscriber that node *N*
//! reached seq *S*, but not *what* `N#S` is. ndn-svs solves this two
//! ways, both implemented here:
//!
//! * **Piggyback** — the publisher rides a [`MappingList`] (recent
//!   seq→name pairs) in its Sync Interest's `MappingData` TLV.
//! * **Query** — for ranges the piggyback didn't cover, a subscriber
//!   expresses `/<node>/<group>/MAPPING/<low>/<high>` and the publisher
//!   answers with the [`MappingList`] for that range
//!   (`mapping-provider.cpp`).
//!
//! Wire format (`MappingList::encode`, ndn-svs `mapping-provider.cpp`):
//!
//! ```text
//! MappingData  (205)
//!   Name       (7)            -- the node id
//!   MappingEntry (206)        -- one per publication
//!     SeqNo    (204)          -- NonNegativeInteger
//!     Name     (7)            -- the application name
//! ```

use std::collections::{BTreeMap, HashMap};
use std::sync::RwLock;

use bytes::Bytes;
use ndn_tlv::{TlvReader, TlvWriter};

use ndn_packet::{Name, NameComponent};

use crate::tlv::encode_nni;

const TLV_SEQ_NO: u64 = 204;
const TLV_MAPPING_DATA: u64 = 205;
const TLV_MAPPING_ENTRY: u64 = 206;
const TLV_NAME: u64 = 7;

/// The `MAPPING` marker component in a mapping-query name.
const MAPPING_MARKER: &[u8] = b"MAPPING";

/// A node's `(seq → application name)` mapping pairs, the payload of a
/// piggyback `MappingData` TLV or a mapping-query response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MappingList {
    pub node: Name,
    pub pairs: Vec<(u64, Name)>,
}

impl MappingList {
    pub fn new(node: Name) -> Self {
        Self {
            node,
            pairs: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    /// Encode as a `MappingData` (205) TLV.
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(TLV_MAPPING_DATA, |md| {
            md.write_raw(&self.node.encode_to_tlv());
            for (seq, name) in &self.pairs {
                md.write_nested(TLV_MAPPING_ENTRY, |me| {
                    me.write_tlv(TLV_SEQ_NO, &encode_nni(*seq));
                    me.write_raw(&name.encode_to_tlv());
                });
            }
        });
        w.finish()
    }

    /// Decode a `MappingData` (205) TLV. Returns `None` on a wrong outer
    /// type or truncation; unknown inner TLVs are skipped (forward-compat).
    pub fn decode(bytes: &Bytes) -> Option<Self> {
        let mut r = TlvReader::new(bytes.clone());
        let (typ, value) = r.read_tlv().ok()?;
        if typ != TLV_MAPPING_DATA {
            return None;
        }
        let mut inner = TlvReader::new(value);
        let mut node: Option<Name> = None;
        let mut pairs = Vec::new();
        while !inner.is_empty() {
            let (t, v) = inner.read_tlv().ok()?;
            match t {
                TLV_NAME => node = Some(Name::decode(v).ok()?),
                TLV_MAPPING_ENTRY => {
                    let mut e = TlvReader::new(v);
                    let mut seq: Option<u64> = None;
                    let mut app: Option<Name> = None;
                    while !e.is_empty() {
                        let (et, ev) = e.read_tlv().ok()?;
                        match et {
                            TLV_SEQ_NO => seq = Some(decode_nni_lax(&ev)),
                            TLV_NAME => app = Some(Name::decode(ev).ok()?),
                            _ => {}
                        }
                    }
                    if let (Some(s), Some(a)) = (seq, app) {
                        pairs.push((s, a));
                    }
                }
                _ => {}
            }
        }
        Some(Self {
            node: node.unwrap_or_else(Name::root),
            pairs,
        })
    }
}

/// Lenient NNI decode (the `crate::tlv` cursor variant works on `&[u8]`;
/// here the reader hands us `Bytes`).
fn decode_nni_lax(b: &Bytes) -> u64 {
    crate::tlv::decode_nni(b)
}

/// Append a sequence number as a generic component holding its NNI bytes
/// (ndn-cxx `Name::appendNumber`).
fn append_number(name: Name, n: u64) -> Name {
    name.append_component(NameComponent::generic(Bytes::from(encode_nni(n))))
}

/// Per-node `seq → application name` table with the ndn-svs
/// `MAPPING/<low>/<high>` query naming.
#[derive(Default)]
pub struct MappingProvider {
    map: RwLock<HashMap<Name, BTreeMap<u64, Name>>>,
}

impl MappingProvider {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `node#seq → app_name`.
    pub fn insert(&self, node: &Name, seq: u64, app_name: Name) {
        self.map
            .write()
            .expect("MappingProvider poisoned")
            .entry(node.clone())
            .or_default()
            .insert(seq, app_name);
    }

    /// Merge a received [`MappingList`] (from a piggyback or query reply).
    pub fn ingest(&self, list: &MappingList) {
        let mut g = self.map.write().expect("MappingProvider poisoned");
        let entry = g.entry(list.node.clone()).or_default();
        for (seq, name) in &list.pairs {
            entry.insert(*seq, name.clone());
        }
    }

    /// Look up a single `node#seq`.
    pub fn get(&self, node: &Name, seq: u64) -> Option<Name> {
        self.map
            .read()
            .expect("MappingProvider poisoned")
            .get(node)
            .and_then(|m| m.get(&seq).cloned())
    }

    /// Build the [`MappingList`] for the inclusive `[low, high]` range of
    /// `node`, skipping seqs we have no name for.
    pub fn list_range(&self, node: &Name, low: u64, high: u64) -> MappingList {
        let mut list = MappingList::new(node.clone());
        if let Some(m) = self.map.read().expect("MappingProvider poisoned").get(node) {
            for (&seq, name) in m.range(low..=high) {
                list.pairs.push((seq, name.clone()));
            }
        }
        list
    }

    /// The Interest filter under which this node answers mapping queries:
    /// `<node>/<group>/MAPPING`.
    pub fn query_prefix(node: &Name, group: &Name) -> Name {
        let mut n = node.clone();
        for c in group.components() {
            n = n.append_component(c.clone());
        }
        n.append(MAPPING_MARKER)
    }

    /// The full mapping-query name `<node>/<group>/MAPPING/<low>/<high>`
    /// (ndn-svs `getMappingQueryDataName`).
    pub fn query_name(node: &Name, group: &Name, low: u64, high: u64) -> Name {
        let prefix = Self::query_prefix(node, group);
        append_number(append_number(prefix, low), high)
    }

    /// Parse a mapping-query name back into `(node, low, high)`, given the
    /// known `group`. `None` if the shape doesn't match.
    pub fn parse_query(name: &Name, group: &Name) -> Option<(Name, u64, u64)> {
        let comps = name.components();
        let group_len = group.components().len();
        // node(?) + group + MAPPING + low + high
        if comps.len() < group_len + 3 {
            return None;
        }
        let node_len = comps.len() - group_len - 3;
        // MAPPING marker just before low/high.
        if comps[node_len + group_len].value.as_ref() != MAPPING_MARKER {
            return None;
        }
        // Verify the group sits between node and MAPPING.
        for (i, gc) in group.components().iter().enumerate() {
            if comps[node_len + i] != *gc {
                return None;
            }
        }
        let node = Name::from_components(comps[..node_len].iter().cloned());
        let low = crate::tlv::decode_nni(&comps[comps.len() - 2].value);
        let high = crate::tlv::decode_nni(&comps[comps.len() - 1].value);
        Some((node, low, high))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn mapping_list_roundtrip() {
        let mut list = MappingList::new(n("/app/node-a"));
        list.pairs.push((1, n("/app/files/readme")));
        list.pairs.push((2, n("/app/files/photo")));
        let wire = list.encode();
        assert_eq!(wire[0], 0xCD, "MappingData type must be 205 (0xCD)");
        let decoded = MappingList::decode(&wire).expect("decode");
        assert_eq!(decoded, list);
    }

    #[test]
    fn mapping_list_rejects_wrong_type() {
        let mut w = TlvWriter::new();
        w.write_tlv(0xAA, &[1, 2]);
        assert!(MappingList::decode(&w.finish()).is_none());
    }

    #[test]
    fn provider_insert_get_and_range() {
        let p = MappingProvider::new();
        let node = n("/app/a");
        p.insert(&node, 1, n("/app/x/1"));
        p.insert(&node, 2, n("/app/x/2"));
        p.insert(&node, 5, n("/app/x/5"));
        assert_eq!(p.get(&node, 2), Some(n("/app/x/2")));
        assert_eq!(p.get(&node, 3), None);

        let list = p.list_range(&node, 1, 3);
        assert_eq!(list.pairs, vec![(1, n("/app/x/1")), (2, n("/app/x/2"))]);
    }

    #[test]
    fn query_name_roundtrips_through_parse() {
        let node = n("/app/producer");
        let group = n("/app/grp");
        let qname = MappingProvider::query_name(&node, &group, 3, 9);
        // <node>/<group>/MAPPING/<3>/<9>
        assert_eq!(
            qname.components().len(),
            node.components().len() + group.components().len() + 3
        );
        let (pn, low, high) = MappingProvider::parse_query(&qname, &group).expect("parse");
        assert_eq!(pn, node);
        assert_eq!((low, high), (3, 9));
    }

    #[test]
    fn parse_query_rejects_non_mapping_name() {
        let group = n("/app/grp");
        let not_a_query = n("/app/producer/app/grp/3");
        assert!(MappingProvider::parse_query(&not_a_query, &group).is_none());
    }

    #[test]
    fn ingest_merges_lists() {
        let p = MappingProvider::new();
        let mut l = MappingList::new(n("/app/a"));
        l.pairs.push((7, n("/app/late/7")));
        p.ingest(&l);
        assert_eq!(p.get(&n("/app/a"), 7), Some(n("/app/late/7")));
    }
}
