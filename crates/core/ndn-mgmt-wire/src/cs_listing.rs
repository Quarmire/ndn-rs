//! The `cs/list` dataset (`/localhost/nfd/cs/list`): the names a forwarder's
//! content store holds under a prefix, capped, with the total held there.
//!
//! An ndn-rs extension (NFD has no CS enumeration). The single source of
//! truth for this wire shape: the native engine (`ndn-mgmt`) encodes it and
//! every client (`ndn-ipc`) decodes it through here.
//!
//! ```text
//! CsListing  = CsListTotal *CsListEntry
//! CsListTotal = 0x0500 NonNegativeInteger   ; entries held under the prefix
//! CsListEntry = 0x0502 (Name                ; the standard Name TLV (0x07)
//!                       CsEntryBytes        ; 0x0504 NonNegativeInteger, wire size
//!                       CsEntryFresh)       ; 0x0506 NonNegativeInteger, 1 fresh / 0 stale
//! ```

use alloc::vec::Vec;
use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_tlv::{TlvReader, TlvWriter};

use crate::{nni_bytes, read_nni};

/// `cs/list` TLV-TYPE codes: 0x0500–0x0507, clear of the trust context
/// (0x0410–0x042F), the link messages (0x0440–0x046F), the trust envelope
/// (0x0470–0x049F) and the link status dataset (0x04A0–0x04F3).
pub mod cs_tlv {
    /// NonNegativeInteger: how many entries the CS holds under the prefix.
    pub const TOTAL: u64 = 0x0500;
    /// Nested: one listed entry.
    pub const ENTRY: u64 = 0x0502;
    /// NonNegativeInteger in an entry: the cached Data's wire size in bytes.
    pub const BYTES: u64 = 0x0504;
    /// NonNegativeInteger in an entry: 1 while it satisfies MustBeFresh, else 0.
    pub const FRESH: u64 = 0x0506;
    /// The standard Name TLV, in an entry: the cached Data's name.
    pub const NAME: u64 = 0x07;
}

/// One cached Data, as `cs/list` lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsEntry {
    pub name: Name,
    /// Wire size of the cached Data, in bytes.
    pub bytes: u64,
    /// Whether it still satisfies `MustBeFresh`.
    pub fresh: bool,
}

impl Default for CsEntry {
    /// The root name, empty and stale.
    fn default() -> Self {
        Self {
            name: Name::root(),
            bytes: 0,
            fresh: false,
        }
    }
}

/// The `cs/list` answer.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CsListing {
    /// The first entries under the prefix in canonical name order, at most
    /// the asked count.
    pub entries: Vec<CsEntry>,
    /// How many entries the CS holds under the prefix, listed or not.
    pub total: u64,
}

impl CsListing {
    /// Encode into the `cs/list` dataset body.
    pub fn encode(&self) -> Bytes {
        self.encode_within(usize::MAX)
    }

    /// As [`encode`](Self::encode), but the body never exceeds `max_len`
    /// bytes: entries that would take it past are left out (the total still
    /// counts them). Lets the daemon answer in one dataset segment.
    pub fn encode_within(&self, max_len: usize) -> Bytes {
        let mut w = TlvWriter::new();
        let (b, n) = nni_bytes(self.total);
        w.write_tlv(cs_tlv::TOTAL, &b[..n]);
        for e in &self.entries {
            let mut entry = TlvWriter::new();
            entry.write_nested(cs_tlv::ENTRY, |inner| {
                inner.write_nested(cs_tlv::NAME, |name| {
                    for comp in e.name.components() {
                        name.write_tlv(comp.typ, &comp.value);
                    }
                });
                for (typ, v) in [
                    (cs_tlv::BYTES, e.bytes),
                    (cs_tlv::FRESH, u64::from(e.fresh)),
                ] {
                    let (b, n) = nni_bytes(v);
                    inner.write_tlv(typ, &b[..n]);
                }
            });
            if w.len() + entry.len() > max_len {
                break;
            }
            w.write_raw(&entry.finish());
        }
        w.finish()
    }

    /// Decode the dataset body. Unknown TLVs are skipped (evolvability); an
    /// entry without a valid name is dropped.
    pub fn decode(bytes: &[u8]) -> CsListing {
        let mut out = CsListing::default();
        let mut reader = TlvReader::new(Bytes::copy_from_slice(bytes));
        while !reader.is_empty() {
            let Ok((typ, body)) = reader.read_tlv() else {
                break;
            };
            match typ {
                cs_tlv::TOTAL => out.total = read_nni(&body).unwrap_or(0),
                cs_tlv::ENTRY => {
                    if let Some(entry) = decode_entry(body) {
                        out.entries.push(entry);
                    }
                }
                _ => {}
            }
        }
        out
    }
}

/// A `cs/list` entry's body; `None` without a valid name.
fn decode_entry(body: Bytes) -> Option<CsEntry> {
    let mut name = None;
    let mut entry = CsEntry::default();
    let mut reader = TlvReader::new(body);
    while !reader.is_empty() {
        let Ok((t, v)) = reader.read_tlv() else { break };
        match t {
            cs_tlv::NAME => name = Name::decode(v).ok(),
            cs_tlv::BYTES => entry.bytes = read_nni(&v).unwrap_or(0),
            cs_tlv::FRESH => entry.fresh = read_nni(&v).unwrap_or(0) != 0,
            _ => {}
        }
    }
    entry.name = name?;
    Some(entry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use ndn_foundation_types::NameComponent;

    fn name(components: &[&[u8]]) -> Name {
        Name::from_components(
            components
                .iter()
                .map(|c| NameComponent::generic(Bytes::copy_from_slice(c))),
        )
    }

    fn listing() -> CsListing {
        CsListing {
            entries: vec![
                CsEntry {
                    name: name(&[b"home", b"bob", b"photos", b"1"]),
                    bytes: 1_200,
                    fresh: true,
                },
                CsEntry {
                    name: name(&[b"home", b"bob", b"photos", b"2"]),
                    bytes: 70_000,
                    fresh: false,
                },
            ],
            total: 312,
        }
    }

    #[test]
    fn cs_listing_round_trips() {
        let l = listing();
        assert_eq!(CsListing::decode(&l.encode()), l);
        let empty = CsListing::default();
        assert_eq!(CsListing::decode(&empty.encode()), empty);
    }

    #[test]
    fn encode_within_keeps_whole_entries_and_the_total() {
        let l = listing();
        let full = l.encode();
        let one = CsListing::decode(&l.encode_within(full.len() - 1));
        assert_eq!(one.total, 312, "the total survives the cut");
        assert_eq!(one.entries, l.entries[..1], "only whole entries are kept");
        assert_eq!(CsListing::decode(&l.encode_within(full.len())), l);
    }

    #[test]
    fn unknown_tlvs_and_nameless_entries_are_skipped() {
        let mut w = TlvWriter::new();
        w.write_tlv(0x0508, b"future");
        w.write_tlv(cs_tlv::TOTAL, &[3]);
        w.write_nested(cs_tlv::ENTRY, |i| i.write_tlv(cs_tlv::BYTES, &[9]));
        let decoded = CsListing::decode(&w.finish());
        assert_eq!(decoded.total, 3);
        assert!(decoded.entries.is_empty());
    }
}
