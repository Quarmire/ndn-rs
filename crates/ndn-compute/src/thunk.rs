//! Thunk encoding for long-running computations (wire spec §7 / §11).
//!
//! A thunk is the Data content a node returns when a computation cannot finish
//! within ~one RTT: it names a not-yet-ready result plus a completion estimate.
//! The client waits the estimate, then Interests the thunk name; the node
//! returns the result when ready, or an updated thunk otherwise.

use std::time::Duration;

use bytes::Bytes;
use ndn_packet::Name;
use ndn_tlv::{TlvReader, TlvWriter};

/// `Thunk` container TLV.
pub const THUNK_TYPE: u64 = 0xC910;
/// `ThunkName` sub-TLV (a Name the client re-Interests for the result).
pub const THUNK_NAME_TYPE: u64 = 0xC911;
/// `ThunkEta` sub-TLV (estimated completion, milliseconds, NonNegativeInteger).
pub const THUNK_ETA_TYPE: u64 = 0xC913;

/// A decoded thunk: where to fetch the eventual result, and when to try.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Thunk {
    /// The name the client should Interest for the result.
    pub thunk_name: Name,
    /// Estimated time until the result is ready.
    pub eta: Duration,
}

impl Thunk {
    /// Encode as Data content (`THUNK_TYPE` container).
    pub fn to_content(&self) -> Bytes {
        let name_tlv = self.thunk_name.encode_to_tlv();
        let eta = (self.eta.as_millis() as u64).to_be_bytes();
        let mut w = TlvWriter::new();
        w.write_nested(THUNK_TYPE, |inner| {
            inner.write_tlv(THUNK_NAME_TYPE, &name_tlv);
            inner.write_tlv(THUNK_ETA_TYPE, &eta);
        });
        w.finish()
    }

    /// Decode from Data content. Returns `None` if `content` is not a thunk.
    pub fn from_content(content: &[u8]) -> Option<Thunk> {
        let mut r = TlvReader::new(Bytes::copy_from_slice(content));
        let (typ, body) = r.read_tlv().ok()?;
        if typ != THUNK_TYPE {
            return None;
        }
        let mut inner = TlvReader::new(body);
        let mut thunk_name = None;
        let mut eta_ms = 0u64;
        while !inner.is_empty() {
            let (t, v) = inner.read_tlv().ok()?;
            match t {
                THUNK_NAME_TYPE => thunk_name = Name::decode_from_tlv(v).ok(),
                THUNK_ETA_TYPE => eta_ms = decode_nonneg(&v),
                _ => {}
            }
        }
        Some(Thunk {
            thunk_name: thunk_name?,
            eta: Duration::from_millis(eta_ms),
        })
    }

    /// Whether `content` is a thunk (vs. a final result), by leading TLV type.
    pub fn content_is_thunk(content: &[u8]) -> bool {
        TlvReader::new(Bytes::copy_from_slice(content))
            .peek_type()
            .ok()
            == Some(THUNK_TYPE)
    }
}

fn decode_nonneg(bytes: &[u8]) -> u64 {
    let mut x = 0u64;
    for &b in bytes.iter().take(8) {
        x = (x << 8) | u64::from(b);
    }
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thunk_round_trip() {
        let t = Thunk {
            thunk_name: "/job/render/thunk/42".parse().unwrap(),
            eta: Duration::from_millis(1500),
        };
        let content = t.to_content();
        assert!(Thunk::content_is_thunk(&content));
        assert_eq!(Thunk::from_content(&content), Some(t));
    }

    #[test]
    fn non_thunk_content_rejected() {
        assert!(!Thunk::content_is_thunk(b"42"));
        assert_eq!(Thunk::from_content(b"42"), None);
    }
}
