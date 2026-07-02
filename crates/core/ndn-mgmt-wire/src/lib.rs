//! Layer: spec — shared NFD management wire codec (no_std + alloc).
//!
//! One source of truth for NFD management dataset formats, so the native engine
//! (`ndn-mgmt`) and the embedded forwarder (`ndn-embedded`) emit **byte-identical**
//! wire output by construction rather than by two encoders kept in sync.
//!
//! Today it carries the **ForwarderStatus / GeneralStatus** dataset returned by
//! `/localhost/nfd/status/general`. TLV codes and field order cross-referenced
//! against `~/Documents/Dev/ndn-cxx/ndn-cxx/encoding/tlv-nfd.hpp` and
//! `mgmt/nfd/forwarder-status.cpp` (wireEncode prepends in reverse, so the wire
//! order is NfdVersion → … → NUnsatisfiedInterests).

#![cfg_attr(docsrs, feature(doc_cfg))]
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;
use bytes::Bytes;
use ndn_tlv::{TlvReader, TlvWriter};

// NFD management WIRE codecs (moved here from ndn-config so the spec crates that
// consume them — ndn-mgmt/ndn-ipc/ndn-routing — depend on this spec crate, not
// the forwarder-TOML extension crate). ndn-config re-exports them for back-compat.
pub mod control_parameters;
pub mod control_response;
pub mod control_surface;
pub mod nfd_command;
pub mod nfd_dataset;

pub use control_parameters::ControlParameters;
pub use control_response::ControlResponse;
pub use control_surface::{ControlInfo, ControlStats, ControlSurface, render_pairs};
pub use nfd_command::{ParsedCommand, command_name, dataset_name, parse_command_name};
pub use nfd_dataset::{FaceStatus, FibEntry, NextHopRecord, RibEntry, Route, StrategyChoice};

/// Parse a 64-char hex SHA-256 digest (e.g. a `FaceCreate` certificate-pin
/// argument) into its 32 raw bytes. Returns `None` on the wrong length or a
/// non-hex character. Lives here (not in the forwarder TOML crate) because it
/// decodes a management *wire* argument.
pub fn parse_cert_sha256_hex(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// NFD ForwarderStatus TLV-TYPE codes (`tlv-nfd.hpp`).
pub mod tlv {
    pub const NFD_VERSION: u64 = 128; // 0x80, UTF-8 string
    pub const START_TIMESTAMP: u64 = 129; // 0x81, ms since Unix epoch (NNI)
    pub const CURRENT_TIMESTAMP: u64 = 130; // 0x82
    pub const N_NAME_TREE_ENTRIES: u64 = 131; // 0x83
    pub const N_FIB_ENTRIES: u64 = 132; // 0x84
    pub const N_PIT_ENTRIES: u64 = 133; // 0x85
    pub const N_MEASUREMENTS_ENTRIES: u64 = 134; // 0x86
    pub const N_CS_ENTRIES: u64 = 135; // 0x87
    pub const N_IN_INTERESTS: u64 = 144; // 0x90
    pub const N_IN_DATA: u64 = 145; // 0x91
    pub const N_OUT_INTERESTS: u64 = 146; // 0x92
    pub const N_OUT_DATA: u64 = 147; // 0x93
    pub const N_IN_NACKS: u64 = 151; // 0x97
    pub const N_OUT_NACKS: u64 = 152; // 0x98
    pub const N_SATISFIED_INTERESTS: u64 = 153; // 0x99
    pub const N_UNSATISFIED_INTERESTS: u64 = 154; // 0x9a
}

/// NFD ForwarderStatus (general status dataset). All numeric fields are
/// NonNegativeIntegers on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GeneralStatus {
    pub nfd_version: String,
    pub start_timestamp_ms: u64,
    pub current_timestamp_ms: u64,
    pub n_name_tree_entries: u64,
    pub n_fib_entries: u64,
    pub n_pit_entries: u64,
    pub n_measurements_entries: u64,
    pub n_cs_entries: u64,
    pub n_in_interests: u64,
    pub n_in_data: u64,
    pub n_in_nacks: u64,
    pub n_out_interests: u64,
    pub n_out_data: u64,
    pub n_out_nacks: u64,
    pub n_satisfied_interests: u64,
    pub n_unsatisfied_interests: u64,
}

/// Decode failure: a required field was missing or a count was malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    Malformed,
    MissingField(u64),
}

/// NDN NonNegativeInteger: 1, 2, 4, or 8 big-endian bytes by magnitude.
fn nni_bytes(v: u64) -> ([u8; 8], usize) {
    let mut b = [0u8; 8];
    if v <= 0xFF {
        b[0] = v as u8;
        (b, 1)
    } else if v <= 0xFFFF {
        b[..2].copy_from_slice(&(v as u16).to_be_bytes());
        (b, 2)
    } else if v <= 0xFFFF_FFFF {
        b[..4].copy_from_slice(&(v as u32).to_be_bytes());
        (b, 4)
    } else {
        b.copy_from_slice(&v.to_be_bytes());
        (b, 8)
    }
}

fn read_nni(bytes: &[u8]) -> Option<u64> {
    match bytes.len() {
        1 => Some(bytes[0] as u64),
        2 => Some(u16::from_be_bytes([bytes[0], bytes[1]]) as u64),
        4 => Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64),
        8 => Some(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])),
        _ => None,
    }
}

impl GeneralStatus {
    /// Encode the field blocks (the Data Content value), in NFD wire order.
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_tlv(tlv::NFD_VERSION, self.nfd_version.as_bytes());
        let mut nni = |typ: u64, v: u64| {
            let (b, n) = nni_bytes(v);
            w.write_tlv(typ, &b[..n]);
        };
        nni(tlv::START_TIMESTAMP, self.start_timestamp_ms);
        nni(tlv::CURRENT_TIMESTAMP, self.current_timestamp_ms);
        nni(tlv::N_NAME_TREE_ENTRIES, self.n_name_tree_entries);
        nni(tlv::N_FIB_ENTRIES, self.n_fib_entries);
        nni(tlv::N_PIT_ENTRIES, self.n_pit_entries);
        nni(tlv::N_MEASUREMENTS_ENTRIES, self.n_measurements_entries);
        nni(tlv::N_CS_ENTRIES, self.n_cs_entries);
        nni(tlv::N_IN_INTERESTS, self.n_in_interests);
        nni(tlv::N_IN_DATA, self.n_in_data);
        nni(tlv::N_IN_NACKS, self.n_in_nacks);
        nni(tlv::N_OUT_INTERESTS, self.n_out_interests);
        nni(tlv::N_OUT_DATA, self.n_out_data);
        nni(tlv::N_OUT_NACKS, self.n_out_nacks);
        nni(tlv::N_SATISFIED_INTERESTS, self.n_satisfied_interests);
        nni(tlv::N_UNSATISFIED_INTERESTS, self.n_unsatisfied_interests);
        w.finish()
    }

    /// Decode the field blocks from a Data Content value. Required fields per
    /// NFD: NfdVersion, StartTimestamp, CurrentTimestamp, and all counts.
    pub fn decode(value: Bytes) -> Result<Self, DecodeError> {
        let mut s = GeneralStatus::default();
        let mut seen: u32 = 0;
        let mut r = TlvReader::new(value);
        while !r.is_empty() {
            let (typ, val) = r.read_tlv().map_err(|_| DecodeError::Malformed)?;
            match typ {
                tlv::NFD_VERSION => {
                    s.nfd_version =
                        String::from_utf8(val.to_vec()).map_err(|_| DecodeError::Malformed)?;
                    seen |= 1;
                }
                _ => {
                    let v = read_nni(&val).ok_or(DecodeError::Malformed)?;
                    match typ {
                        tlv::START_TIMESTAMP => s.start_timestamp_ms = v,
                        tlv::CURRENT_TIMESTAMP => s.current_timestamp_ms = v,
                        tlv::N_NAME_TREE_ENTRIES => s.n_name_tree_entries = v,
                        tlv::N_FIB_ENTRIES => s.n_fib_entries = v,
                        tlv::N_PIT_ENTRIES => s.n_pit_entries = v,
                        tlv::N_MEASUREMENTS_ENTRIES => s.n_measurements_entries = v,
                        tlv::N_CS_ENTRIES => s.n_cs_entries = v,
                        tlv::N_IN_INTERESTS => s.n_in_interests = v,
                        tlv::N_IN_DATA => s.n_in_data = v,
                        tlv::N_IN_NACKS => s.n_in_nacks = v,
                        tlv::N_OUT_INTERESTS => s.n_out_interests = v,
                        tlv::N_OUT_DATA => s.n_out_data = v,
                        tlv::N_OUT_NACKS => s.n_out_nacks = v,
                        tlv::N_SATISFIED_INTERESTS => s.n_satisfied_interests = v,
                        tlv::N_UNSATISFIED_INTERESTS => s.n_unsatisfied_interests = v,
                        _ => {} // unknown non-critical: ignore (NFD evolvability)
                    }
                }
            }
        }
        // Minimum required header fields.
        if seen & 1 == 0 {
            return Err(DecodeError::MissingField(tlv::NFD_VERSION));
        }
        Ok(s)
    }
}

/// CA pending-approval dataset TLV-TYPE codes (`/localhost/nfd/ca/list-approvals`).
///
/// An ndn-rs extension (no NFD analogue), so codes sit in the application range.
pub mod ca_tlv {
    pub const PENDING_APPROVAL: u64 = 0xCA; // nested entry
    pub const REQUEST_ID: u64 = 0xCC; // UTF-8 string
    pub const CERT_NAME: u64 = 0xCE; // UTF-8 string
    pub const DESCRIPTION: u64 = 0xD0; // UTF-8 string, optional
}

/// One row of the CA pending-approval queue. The single source of truth for
/// this wire shape: the native engine (`ndn-mgmt`) encodes it, every client
/// (`ndn-ipc`, the dashboard web build, `ndn-dashboard-core`) decodes it
/// through here rather than re-deriving the TLV codes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PendingApproval {
    pub request_id: String,
    pub cert_name: String,
    pub description: String,
}

impl PendingApproval {
    /// Encode a queue into the `ca/list-approvals` dataset body. `description`
    /// is omitted when empty (decoders default it to `""`).
    pub fn encode_all(rows: &[PendingApproval]) -> Bytes {
        let mut w = TlvWriter::new();
        for r in rows {
            w.write_nested(ca_tlv::PENDING_APPROVAL, |inner| {
                inner.write_tlv(ca_tlv::REQUEST_ID, r.request_id.as_bytes());
                inner.write_tlv(ca_tlv::CERT_NAME, r.cert_name.as_bytes());
                if !r.description.is_empty() {
                    inner.write_tlv(ca_tlv::DESCRIPTION, r.description.as_bytes());
                }
            });
        }
        w.finish()
    }

    /// Decode the dataset body. Unknown top-level TLVs are skipped (evolvability);
    /// an entry missing `request_id` or `cert_name` is dropped.
    pub fn decode_all(bytes: &[u8]) -> alloc::vec::Vec<PendingApproval> {
        let mut out = alloc::vec::Vec::new();
        let mut reader = TlvReader::new(Bytes::copy_from_slice(bytes));
        while !reader.is_empty() {
            let Ok((typ, body)) = reader.read_tlv() else {
                break;
            };
            if typ != ca_tlv::PENDING_APPROVAL {
                continue;
            }
            let mut row = PendingApproval::default();
            let mut inner = TlvReader::new(body);
            while !inner.is_empty() {
                let Ok((t, v)) = inner.read_tlv() else { break };
                let s = String::from_utf8_lossy(&v).into_owned();
                match t {
                    ca_tlv::REQUEST_ID => row.request_id = s,
                    ca_tlv::CERT_NAME => row.cert_name = s,
                    ca_tlv::DESCRIPTION => row.description = s,
                    _ => {}
                }
            }
            if !row.request_id.is_empty() && !row.cert_name.is_empty() {
                out.push(row);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_approval_round_trips() {
        let rows = alloc::vec![
            PendingApproval {
                request_id: "req-1".into(),
                cert_name: "/ndn/alice/KEY/k/CA/v".into(),
                description: "Touch ID".into(),
            },
            PendingApproval {
                request_id: "req-2".into(),
                cert_name: "/ndn/bob/KEY/k/CA/v".into(),
                description: String::new(), // omitted on the wire
            },
        ];
        let wire = PendingApproval::encode_all(&rows);
        let back = PendingApproval::decode_all(&wire);
        assert_eq!(back, rows);
        // The first byte is the nested entry type.
        assert_eq!(wire[0] as u64, ca_tlv::PENDING_APPROVAL);
    }

    #[test]
    fn pending_approval_drops_incomplete_entries() {
        // An entry with only a request id (no cert name) is dropped.
        let mut w = TlvWriter::new();
        w.write_nested(ca_tlv::PENDING_APPROVAL, |i| {
            i.write_tlv(ca_tlv::REQUEST_ID, b"orphan");
        });
        assert!(PendingApproval::decode_all(&w.finish()).is_empty());
    }

    #[test]
    fn round_trips() {
        let s = GeneralStatus {
            nfd_version: "ndn-rs 0.1.0".into(),
            start_timestamp_ms: 1_700_000_000_000,
            current_timestamp_ms: 1_700_000_005_000,
            n_fib_entries: 3,
            n_pit_entries: 1,
            n_cs_entries: 2,
            n_in_interests: 10,
            n_out_data: 9,
            n_satisfied_interests: 9,
            ..Default::default()
        };
        let wire = s.encode();
        assert_eq!(GeneralStatus::decode(wire).unwrap(), s);
    }

    #[test]
    fn wire_order_starts_with_version() {
        let s = GeneralStatus {
            nfd_version: "v".into(),
            ..Default::default()
        };
        let wire = s.encode();
        assert_eq!(wire[0] as u64, tlv::NFD_VERSION); // NfdVersion is first on the wire
    }

    #[test]
    fn nni_width_by_magnitude() {
        // 200 -> 1 byte, 404 -> 2 bytes.
        let (_, n1) = nni_bytes(200);
        let (_, n2) = nni_bytes(404);
        assert_eq!((n1, n2), (1, 2));
    }
}
