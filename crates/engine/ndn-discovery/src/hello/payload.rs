//! `HelloPayload` — hello Data content TLV codec.
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

use bytes::Bytes;
use ndn_packet::Name;
use ndn_tlv::{TlvReader, TlvWriter};

use crate::wire::{parse_name_from_tlv, write_name_tlv};


pub const T_NODE_NAME: u64 = 0xC1;
pub const T_SERVED_PREFIX: u64 = 0xC2;
pub const T_CAPABILITIES: u64 = 0xC3;
pub const T_NEIGHBOR_DIFF: u64 = 0xC4;
pub const T_ADD_ENTRY: u64 = 0xC5;
pub const T_REMOVE_ENTRY: u64 = 0xC6;
pub const T_PUBLIC_KEY: u64 = 0xC8;
/// Sender's UDP unicast listen port (big-endian u16).  Receivers create
/// unicast faces on this port rather than the multicast source port.
pub const T_UNICAST_PORT: u64 = 0xC9;


pub const CAP_FRAGMENTATION: u8 = 0x01;
pub const CAP_CONTENT_STORE: u8 = 0x02;
pub const CAP_VALIDATION: u8 = 0x04;
pub const CAP_SVS: u8 = 0x08;


#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiffEntry {
    Add(Name),
    Remove(Name),
}

/// SWIM gossip piggyback: recently discovered/departed neighbors riding in
/// spare capacity of existing hello traffic.
#[derive(Clone, Debug, Default)]
pub struct NeighborDiff {
    pub entries: Vec<DiffEntry>,
}


/// Payload carried in the Content of a hello Data packet.
#[derive(Clone, Debug)]
pub struct HelloPayload {
    pub node_name: Name,
    pub served_prefixes: Vec<Name>,
    pub capabilities: u8,
    pub neighbor_diffs: Vec<NeighborDiff>,
    /// Ed25519 public key for self-attesting signed hellos.
    pub public_key: Option<Bytes>,
    /// When present, receivers create unicast faces on this port instead
    /// of the multicast source port.
    pub unicast_port: Option<u16>,
}

impl HelloPayload {
    pub fn new(node_name: Name) -> Self {
        Self {
            node_name,
            served_prefixes: Vec::new(),
            capabilities: 0,
            neighbor_diffs: Vec::new(),
            public_key: None,
            unicast_port: None,
        }
    }


    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(T_NODE_NAME, |w: &mut TlvWriter| {
            write_name_tlv(w, &self.node_name);
        });
        for prefix in &self.served_prefixes {
            w.write_nested(T_SERVED_PREFIX, |w: &mut TlvWriter| {
                write_name_tlv(w, prefix);
            });
        }
        if self.capabilities != 0 {
            w.write_tlv(T_CAPABILITIES, &[self.capabilities]);
        }
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
        if let Some(ref pk) = self.public_key {
            w.write_tlv(T_PUBLIC_KEY, pk);
        }
        if let Some(port) = self.unicast_port {
            w.write_tlv(T_UNICAST_PORT, &port.to_be_bytes());
        }
        w.finish()
    }


    pub fn decode(content: &Bytes) -> Option<Self> {
        let mut r = TlvReader::new(content.clone());
        let mut node_name: Option<Name> = None;
        let mut served_prefixes = Vec::new();
        let mut capabilities: u8 = 0;
        let mut neighbor_diffs = Vec::new();
        let mut public_key: Option<Bytes> = None;
        let mut unicast_port: Option<u16> = None;

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
                T_PUBLIC_KEY => {
                    if v.len() == 32 {
                        public_key = Some(v);
                    }
                }
                T_UNICAST_PORT => {
                    if v.len() == 2 {
                        unicast_port = Some(u16::from_be_bytes([v[0], v[1]]));
                    }
                }
                _ => {}
            }
        }

        Some(HelloPayload {
            node_name: node_name?,
            served_prefixes,
            capabilities,
            neighbor_diffs,
            public_key,
            unicast_port,
        })
    }
}


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
