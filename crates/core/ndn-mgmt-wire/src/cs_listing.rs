//! The `cs/list` dataset (`/localhost/nfd/cs/list`): one page of the names a
//! forwarder's content store holds under a prefix, with the total held there
//! and whether more follow the page.
//!
//! An ndn-rs extension (NFD has no CS enumeration). The single source of
//! truth for this wire shape: the native engine (`ndn-mgmt`) encodes it and
//! every client (`ndn-ipc`) decodes it through here.
//!
//! ```text
//! CsListing  = CsListTotal [CsListMore] *CsListEntry
//! CsListTotal = 0x0500 NonNegativeInteger   ; entries held under the prefix
//! CsListMore  = 0x0508 NonNegativeInteger   ; 1: entries follow the page
//! CsListEntry = 0x0502 (Name                ; the standard Name TLV (0x07)
//!                       CsEntryBytes        ; 0x0504 NonNegativeInteger, wire size
//!                       CsEntryFresh)       ; 0x0506 NonNegativeInteger, 1 fresh / 0 stale
//! ```

use alloc::vec::Vec;
use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_tlv::{TlvReader, TlvWriter};

use crate::{nni_bytes, read_nni};

/// `cs/list` TLV-TYPE codes: 0x0500–0x0509, clear of the trust context
/// (0x0410–0x042F), the link messages (0x0440–0x046F), the trust envelope
/// (0x0470–0x049F) and the link status dataset (0x04A0–0x04F3). All even:
/// non-critical, so an older decoder skips what it does not know.
pub mod cs_tlv {
    /// NonNegativeInteger: how many entries the CS holds under the prefix.
    pub const TOTAL: u64 = 0x0500;
    /// Nested: one listed entry.
    pub const ENTRY: u64 = 0x0502;
    /// NonNegativeInteger in an entry: the cached Data's wire size in bytes.
    pub const BYTES: u64 = 0x0504;
    /// NonNegativeInteger in an entry: 1 while it satisfies MustBeFresh, else 0.
    pub const FRESH: u64 = 0x0506;
    /// NonNegativeInteger: 1 when entries under the prefix follow the page;
    /// absent (or 0) on the last page.
    pub const MORE: u64 = 0x0508;
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

/// The `cs/list` answer: one page of a listing.
///
/// Pages run in canonical name order. The first page is asked with no
/// cursor; each next one with [`next_after`](Self::next_after) of the
/// previous page as the cursor, until a page says no more follow. Paging so
/// visits every entry under the prefix exactly once while the store is
/// unchanged; entries added or evicted meanwhile show up or drop out
/// without shifting the rest.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CsListing {
    /// The page: the first entries under the prefix after the cursor, in
    /// canonical name order, at most the asked count.
    pub entries: Vec<CsEntry>,
    /// How many entries the CS holds under the prefix, on any page.
    pub total: u64,
    /// Whether entries under the prefix follow this page.
    pub more: bool,
}

impl CsListing {
    /// The cursor for the next page — the last listed name — or `None` when
    /// this is the last page.
    pub fn next_after(&self) -> Option<&Name> {
        if self.more {
            self.entries.last().map(|e| &e.name)
        } else {
            None
        }
    }

    /// Encode into the `cs/list` dataset body.
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        let (b, n) = nni_bytes(self.total);
        w.write_tlv(cs_tlv::TOTAL, &b[..n]);
        if self.more {
            w.write_tlv(cs_tlv::MORE, &[1]);
        }
        for e in &self.entries {
            w.write_nested(cs_tlv::ENTRY, |inner| {
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
                cs_tlv::MORE => out.more = read_nni(&body).unwrap_or(0) != 0,
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
            more: true,
        }
    }

    #[test]
    fn cs_listing_round_trips() {
        let l = listing();
        assert_eq!(CsListing::decode(&l.encode()), l);
        let last = CsListing {
            more: false,
            ..listing()
        };
        assert_eq!(CsListing::decode(&last.encode()), last);
        let empty = CsListing::default();
        assert_eq!(CsListing::decode(&empty.encode()), empty);
    }

    #[test]
    fn the_next_cursor_is_the_last_name_while_more_follow() {
        let l = listing();
        assert_eq!(l.next_after(), Some(&l.entries[1].name));
        let last = CsListing {
            more: false,
            ..listing()
        };
        assert_eq!(last.next_after(), None);
    }

    #[test]
    fn unknown_tlvs_and_nameless_entries_are_skipped() {
        let mut w = TlvWriter::new();
        w.write_tlv(0x050A, b"future");
        w.write_tlv(cs_tlv::TOTAL, &[3]);
        w.write_nested(cs_tlv::ENTRY, |i| i.write_tlv(cs_tlv::BYTES, &[9]));
        let decoded = CsListing::decode(&w.finish());
        assert_eq!(decoded.total, 3);
        assert!(decoded.entries.is_empty());
        assert!(!decoded.more);
    }
}
