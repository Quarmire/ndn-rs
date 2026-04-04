//! `HelloPayload` — NDN neighbor discovery hello packet TLV codec.
//!
//! Both `EtherNeighborDiscovery` and `UdpNeighborDiscovery` encode their
//! Data Content using this shared format.
//!
//! ## Wire format
//!
//! ```text
//! HelloPayload  ::= NODE-NAME TLV
//!                   (SERVED-PREFIX TLV)*
//!                   CAPABILITIES TLV?
//!                   (NEIGHBOR-DIFF TLV)*
//!
//! NODE-NAME     ::= 0xC1 length Name
//! SERVED-PREFIX ::= 0xC2 length Name
//! CAPABILITIES  ::= 0xC3 length FLAGS-BYTE*
//! NEIGHBOR-DIFF ::= 0xC4 length (ADD-ENTRY | REMOVE-ENTRY)*
//! ADD-ENTRY     ::= 0xC5 length Name
//! REMOVE-ENTRY  ::= 0xC6 length Name
//! ```
//!
//! TLV types use the application-specific range (≥ 0xC0) to avoid collisions
//! with NDN packet-level types.
//!
//! ## Hello Interest / Data names
//!
//! ```text
//! Interest: /ndn/local/nd/hello/<nonce-u32>
//! Data:     /ndn/local/nd/hello/<nonce-u32>
//!           Content = HelloPayload TLV (this module)
//! ```
//!
//! The Interest carries no AppParams.  The sender's link-layer address is
//! obtained from the socket (`recv_with_source`) and never embedded in the
//! NDN packet.

use bytes::Bytes;
use ndn_packet::Name;
use ndn_tlv::{TlvReader, TlvWriter};

use crate::wire::{parse_name_from_tlv, write_name_tlv};

// ─── TLV type constants ───────────────────────────────────────────────────────

/// `NODE-NAME` TLV type: the sender's NDN node name.
pub const T_NODE_NAME: u64 = 0xC1;
/// `SERVED-PREFIX` TLV type: a prefix the sender can serve.
pub const T_SERVED_PREFIX: u64 = 0xC2;
/// `CAPABILITIES` TLV type: advisory capability flags byte.
pub const T_CAPABILITIES: u64 = 0xC3;
/// `NEIGHBOR-DIFF` TLV type: SWIM gossip piggyback.
pub const T_NEIGHBOR_DIFF: u64 = 0xC4;
/// `ADD-ENTRY` within a `NEIGHBOR-DIFF`: a newly discovered neighbor.
pub const T_ADD_ENTRY: u64 = 0xC5;
/// `REMOVE-ENTRY` within a `NEIGHBOR-DIFF`: a departed neighbor.
pub const T_REMOVE_ENTRY: u64 = 0xC6;

// ─── Capability flags ─────────────────────────────────────────────────────────

/// Capability flag: this node can reassemble NDN fragments.
pub const CAP_FRAGMENTATION: u8 = 0x01;
/// Capability flag: this node has an active content store.
pub const CAP_CONTENT_STORE: u8 = 0x02;
/// Capability flag: this node validates signatures on forwarded data.
pub const CAP_VALIDATION: u8 = 0x04;
/// Capability flag: this node supports State Vector Sync (SVS).
pub const CAP_SVS: u8 = 0x08;

// ─── NeighborDiff entry ───────────────────────────────────────────────────────

/// A single entry inside a [`NeighborDiff`]: add or remove a neighbor name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiffEntry {
    Add(Name),
    Remove(Name),
}

/// SWIM gossip piggyback carried in hello Data Content.
///
/// Encodes recently discovered and departed neighbors so that other nodes
/// on the link can update their neighbor tables without waiting for their own
/// hellos to complete.  Zero additional messages are required — the diff rides
/// in spare capacity of existing hello traffic.
#[derive(Clone, Debug, Default)]
pub struct NeighborDiff {
    pub entries: Vec<DiffEntry>,
}

// ─── HelloPayload ─────────────────────────────────────────────────────────────

/// Payload carried in the Content of a hello Data packet.
#[derive(Clone, Debug)]
pub struct HelloPayload {
    /// Mandatory: the sender's NDN node name.
    pub node_name: Name,
    /// Prefixes this node produces (for service discovery bootstrapping).
    pub served_prefixes: Vec<Name>,
    /// Advisory capability flags (see `CAP_*` constants).
    pub capabilities: u8,
    /// SWIM gossip diffs piggybacked on this hello.
    pub neighbor_diffs: Vec<NeighborDiff>,
}

impl HelloPayload {
    /// Construct a minimal hello payload with just the node name.
    pub fn new(node_name: Name) -> Self {
        Self {
            node_name,
            served_prefixes: Vec::new(),
            capabilities: 0,
            neighbor_diffs: Vec::new(),
        }
    }

    // ─── Encoding ──────────────────────────────────────────────────────────

    /// Encode the payload to wire bytes (the Content TLV value).
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        // NODE-NAME
        w.write_nested(T_NODE_NAME, |w: &mut TlvWriter| {
            write_name_tlv(w, &self.node_name);
        });
        // SERVED-PREFIX (zero or more)
        for prefix in &self.served_prefixes {
            w.write_nested(T_SERVED_PREFIX, |w: &mut TlvWriter| {
                write_name_tlv(w, prefix);
            });
        }
        // CAPABILITIES (omit if zero)
        if self.capabilities != 0 {
            w.write_tlv(T_CAPABILITIES, &[self.capabilities]);
        }
        // NEIGHBOR-DIFF (zero or more)
        for diff in &self.neighbor_diffs {
            w.write_nested(T_NEIGHBOR_DIFF, |w: &mut TlvWriter| {
                for entry in &diff.entries {
                    match entry {
                        DiffEntry::Add(name) => {
                            w.write_nested(T_ADD_ENTRY, |w: &mut TlvWriter| {
                                write_name_tlv(w, name);
                            });
                        }
                        DiffEntry::Remove(name) => {
                            w.write_nested(T_REMOVE_ENTRY, |w: &mut TlvWriter| {
                                write_name_tlv(w, name);
                            });
                        }
                    }
                }
            });
        }
        w.finish()
    }

    // ─── Decoding ──────────────────────────────────────────────────────────

    /// Decode a `HelloPayload` from Content bytes.
    ///
    /// Returns `None` if the `NODE-NAME` field is missing or malformed;
    /// unknown TLV types are silently skipped for forward compatibility.
    pub fn decode(content: &Bytes) -> Option<Self> {
        let mut r = TlvReader::new(content.clone());
        let mut node_name: Option<Name> = None;
        let mut served_prefixes = Vec::new();
        let mut capabilities: u8 = 0;
        let mut neighbor_diffs = Vec::new();

        while !r.is_empty() {
            let (t, v) = r.read_tlv().ok()?;
            match t {
                T_NODE_NAME => {
                    node_name = Some(decode_name_from_nested(&v)?);
                }
                T_SERVED_PREFIX => {
                    if let Some(name) = decode_name_from_nested(&v) {
                        served_prefixes.push(name);
                    }
                }
                T_CAPABILITIES => {
                    capabilities = *v.first().unwrap_or(&0);
                }
                T_NEIGHBOR_DIFF => {
                    if let Some(diff) = decode_neighbor_diff(&v) {
                        neighbor_diffs.push(diff);
                    }
                }
                _ => {} // forward-compatible: skip unknown types
            }
        }

        Some(HelloPayload {
            node_name: node_name?,
            served_prefixes,
            capabilities,
            neighbor_diffs,
        })
    }
}

// ─── Private decode helpers ───────────────────────────────────────────────────

/// The value of a `NODE-NAME` or `SERVED-PREFIX` TLV is a Name TLV.
/// This function parses a Name from the nested Name TLV bytes.
fn decode_name_from_nested(v: &Bytes) -> Option<Name> {
    parse_name_from_tlv(v)
}

fn decode_neighbor_diff(v: &Bytes) -> Option<NeighborDiff> {
    let mut r = TlvReader::new(v.clone());
    let mut entries = Vec::new();
    while !r.is_empty() {
        let (t, val) = r.read_tlv().ok()?;
        match t {
            T_ADD_ENTRY => {
                if let Some(name) = decode_name_from_nested(&val) {
                    entries.push(DiffEntry::Add(name));
                }
            }
            T_REMOVE_ENTRY => {
                if let Some(name) = decode_name_from_nested(&val) {
                    entries.push(DiffEntry::Remove(name));
                }
            }
            _ => {}
        }
    }
    Some(NeighborDiff { entries })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn name(s: &str) -> Name {
        Name::from_str(s).unwrap()
    }

    #[test]
    fn minimal_roundtrip() {
        let payload = HelloPayload::new(name("/ndn/test/node"));
        let wire = payload.encode();
        let decoded = HelloPayload::decode(&wire).unwrap();
        assert_eq!(decoded.node_name, name("/ndn/test/node"));
        assert!(decoded.served_prefixes.is_empty());
        assert_eq!(decoded.capabilities, 0);
        assert!(decoded.neighbor_diffs.is_empty());
    }

    #[test]
    fn served_prefixes_roundtrip() {
        let mut payload = HelloPayload::new(name("/ndn/site/router"));
        payload.served_prefixes.push(name("/ndn/edu/ucla/cs"));
        payload.served_prefixes.push(name("/ndn/edu/ucla/math"));
        let wire = payload.encode();
        let decoded = HelloPayload::decode(&wire).unwrap();
        assert_eq!(decoded.served_prefixes.len(), 2);
        assert_eq!(decoded.served_prefixes[0], name("/ndn/edu/ucla/cs"));
        assert_eq!(decoded.served_prefixes[1], name("/ndn/edu/ucla/math"));
    }

    #[test]
    fn capabilities_roundtrip() {
        let mut payload = HelloPayload::new(name("/ndn/test/node"));
        payload.capabilities = CAP_CONTENT_STORE | CAP_SVS;
        let wire = payload.encode();
        let decoded = HelloPayload::decode(&wire).unwrap();
        assert_eq!(decoded.capabilities, CAP_CONTENT_STORE | CAP_SVS);
    }

    #[test]
    fn capabilities_zero_omitted() {
        let payload = HelloPayload::new(name("/ndn/test/node"));
        let wire = payload.encode();
        // CAPABILITIES TLV should not appear at all when flags == 0.
        assert!(!wire.windows(1).any(|b| b[0] == T_CAPABILITIES as u8));
    }

    #[test]
    fn neighbor_diff_roundtrip() {
        let mut payload = HelloPayload::new(name("/ndn/test/node"));
        payload.neighbor_diffs.push(NeighborDiff {
            entries: vec![
                DiffEntry::Add(name("/ndn/site/peerA")),
                DiffEntry::Remove(name("/ndn/site/peerB")),
            ],
        });
        let wire = payload.encode();
        let decoded = HelloPayload::decode(&wire).unwrap();
        assert_eq!(decoded.neighbor_diffs.len(), 1);
        let diff = &decoded.neighbor_diffs[0];
        assert_eq!(diff.entries.len(), 2);
        assert_eq!(diff.entries[0], DiffEntry::Add(name("/ndn/site/peerA")));
        assert_eq!(diff.entries[1], DiffEntry::Remove(name("/ndn/site/peerB")));
    }

    #[test]
    fn unknown_tlv_types_skipped() {
        // Inject an unknown TLV type (0xFF) between known fields.
        let mut payload = HelloPayload::new(name("/ndn/test/node"));
        payload.capabilities = CAP_FRAGMENTATION;
        let mut wire = payload.encode().to_vec();
        // Append an unknown TLV at the end (0xD0 = 208, valid 1-byte type).
        wire.extend_from_slice(&[0xD0, 0x02, 0xDE, 0xAD]);
        let bytes = Bytes::from(wire);
        // Should decode successfully, ignoring the unknown TLV.
        let decoded = HelloPayload::decode(&bytes).unwrap();
        assert_eq!(decoded.node_name, name("/ndn/test/node"));
        assert_eq!(decoded.capabilities, CAP_FRAGMENTATION);
    }

    #[test]
    fn missing_node_name_returns_none() {
        // Build wire bytes with only a CAPABILITIES field.
        let mut w = TlvWriter::new();
        w.write_tlv(T_CAPABILITIES, &[CAP_SVS]);
        let wire = w.finish();
        assert!(HelloPayload::decode(&wire).is_none());
    }
}
