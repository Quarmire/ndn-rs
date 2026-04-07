//! NDN TLV encoder/decoder for the Packet Explorer view.
//!
//! Encoding uses `ndn_tlv::TlvWriter` from the shared workspace crate.
//! Decoding produces a generic `TlvNode` tree for the hex viewer UI.

use ndn_packet::tlv_type;
use ndn_tlv::TlvWriter;
use serde::{Deserialize, Serialize};

// ── TLV type code table ───────────────────────────────────────────────────────

/// Human-readable name for a well-known NDN TLV type code.
pub fn type_name(t: u64) -> &'static str {
    use tlv_type::*;
    match t {
        INTEREST                  => "Interest",
        DATA                      => "Data",
        NAME                      => "Name",
        NAME_COMPONENT            => "GenericNameComponent",
        IMPLICIT_SHA256           => "ImplicitSha256DigestComponent",
        PARAMETERS_SHA256         => "ParametersSha256DigestComponent",
        CAN_BE_PREFIX             => "CanBePrefix",
        MUST_BE_FRESH             => "MustBeFresh",
        FORWARDING_HINT           => "ForwardingHint",
        NONCE                     => "Nonce",
        INTEREST_LIFETIME         => "InterestLifetime",
        HOP_LIMIT                 => "HopLimit",
        APP_PARAMETERS            => "ApplicationParameters",
        META_INFO                 => "MetaInfo",
        CONTENT                   => "Content",
        SIGNATURE_INFO            => "SignatureInfo",
        SIGNATURE_VALUE           => "SignatureValue",
        CONTENT_TYPE              => "ContentType",
        FRESHNESS_PERIOD          => "FreshnessPeriod",
        FINAL_BLOCK_ID            => "FinalBlockId",
        SIGNATURE_TYPE            => "SignatureType",
        KEY_LOCATOR               => "KeyLocator",
        KEY_DIGEST                => "KeyDigest",
        SIGNATURE_NONCE           => "SignatureNonce",
        SIGNATURE_TIME            => "SignatureTime",
        SIGNATURE_SEQ_NUM         => "SignatureSeqNum",
        INTEREST_SIGNATURE_INFO   => "InterestSignatureInfo",
        INTEREST_SIGNATURE_VALUE  => "InterestSignatureValue",
        NACK                      => "Nack",
        NACK_REASON               => "NackReason",
        LP_PACKET                 => "LpPacket",
        LP_FRAGMENT               => "LpFragment",
        LP_PIT_TOKEN              => "LpPitToken",
        _ => "Unknown",
    }
}

// ── Encoder ───────────────────────────────────────────────────────────────────

/// Write NDN Name TLV components into a writer.
fn write_name_components(w: &mut TlvWriter, name: &str) {
    for comp in name.trim_matches('/').split('/').filter(|s| !s.is_empty()) {
        w.write_tlv(tlv_type::NAME_COMPONENT, comp.as_bytes());
    }
}

/// Encode a big-endian NonNegativeInteger (used for Nonce, lifetimes, etc.).
pub fn encode_nonneg_integer(value: u64) -> Vec<u8> {
    if value <= 0xFF {
        vec![value as u8]
    } else if value <= 0xFFFF {
        vec![(value >> 8) as u8, value as u8]
    } else if value <= 0xFFFF_FFFF {
        vec![(value >> 24) as u8, (value >> 16) as u8, (value >> 8) as u8, value as u8]
    } else {
        vec![
            (value >> 56) as u8, (value >> 48) as u8, (value >> 40) as u8, (value >> 32) as u8,
            (value >> 24) as u8, (value >> 16) as u8, (value >> 8) as u8, value as u8,
        ]
    }
}

/// Encode a synthetic Interest packet using `ndn_tlv::TlvWriter`.
pub fn encode_interest(name: &str, can_be_prefix: bool, must_be_fresh: bool, nonce: u32, lifetime_ms: u64) -> Vec<u8> {
    let mut w = TlvWriter::new();
    w.write_nested(tlv_type::INTEREST, |w| {
        w.write_nested(tlv_type::NAME, |w| write_name_components(w, name));
        if can_be_prefix {
            w.write_tlv(tlv_type::CAN_BE_PREFIX, &[]);
        }
        if must_be_fresh {
            w.write_tlv(tlv_type::MUST_BE_FRESH, &[]);
        }
        w.write_tlv(tlv_type::NONCE, &nonce.to_be_bytes());
        if lifetime_ms != 4000 {
            w.write_tlv(tlv_type::INTEREST_LIFETIME, &encode_nonneg_integer(lifetime_ms));
        }
    });
    w.finish().to_vec()
}

/// Encode a synthetic Data packet with DigestSha256 signature using `ndn_tlv::TlvWriter`.
pub fn encode_data(name: &str, content: &[u8], freshness_ms: u64) -> Vec<u8> {
    let mut w = TlvWriter::new();
    w.write_nested(tlv_type::DATA, |w| {
        w.write_nested(tlv_type::NAME, |w| write_name_components(w, name));
        w.write_nested(tlv_type::META_INFO, |w| {
            if freshness_ms > 0 {
                w.write_tlv(tlv_type::FRESHNESS_PERIOD, &encode_nonneg_integer(freshness_ms));
            }
        });
        w.write_tlv(tlv_type::CONTENT, content);
        // SignatureInfo: DigestSha256 (type 0)
        w.write_nested(tlv_type::SIGNATURE_INFO, |w| {
            w.write_tlv(tlv_type::SIGNATURE_TYPE, &encode_nonneg_integer(0));
        });
        // SignatureValue: 32 dummy bytes
        w.write_tlv(tlv_type::SIGNATURE_VALUE, &[0xAA; 32]);
    });
    w.finish().to_vec()
}

// ── Decoder / tree ────────────────────────────────────────────────────────────

/// A single node in the decoded TLV tree.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TlvNode {
    pub typ: u64,
    pub type_name: String,
    pub length: u64,
    /// Byte offset of this TLV's type field in the original buffer.
    pub start_byte: usize,
    /// Byte offset just after this TLV's last value byte.
    pub end_byte: usize,
    /// Hex-encoded value (for leaf nodes).
    pub value_hex: String,
    /// UTF-8 value if the bytes are printable ASCII (human-readable hint).
    pub value_text: Option<String>,
    pub children: Vec<TlvNode>,
}

/// Decode a VLI from `buf` at offset `pos`. Returns (value, bytes_consumed).
fn decode_vli(buf: &[u8], pos: usize) -> Option<(u64, usize)> {
    let first = *buf.get(pos)? as u64;
    match first {
        0xFD => {
            let high = *buf.get(pos + 1)? as u64;
            let low = *buf.get(pos + 2)? as u64;
            Some(((high << 8) | low, 3))
        }
        0xFE => {
            let a = *buf.get(pos + 1)? as u64;
            let b = *buf.get(pos + 2)? as u64;
            let c = *buf.get(pos + 3)? as u64;
            let d = *buf.get(pos + 4)? as u64;
            Some(((a << 24) | (b << 16) | (c << 8) | d, 5))
        }
        0xFF => {
            let mut v = 0u64;
            for i in 0..8 {
                v = (v << 8) | (*buf.get(pos + 1 + i)? as u64);
            }
            Some((v, 9))
        }
        v => Some((v, 1)),
    }
}

/// Decode TLV nodes from a byte slice. Returns the root-level nodes.
pub fn decode_tlv_tree(buf: &[u8]) -> Vec<TlvNode> {
    decode_tlv_range(buf, 0, buf.len())
}

fn decode_tlv_range(buf: &[u8], mut pos: usize, end: usize) -> Vec<TlvNode> {
    let mut nodes = Vec::new();
    while pos < end {
        let (typ, t_len) = match decode_vli(buf, pos) {
            Some(v) => v,
            None => break,
        };
        let type_start = pos;
        pos += t_len;

        let (length, l_len) = match decode_vli(buf, pos) {
            Some(v) => v,
            None => break,
        };
        pos += l_len;

        let value_start = pos;
        let value_end = pos + length as usize;
        if value_end > buf.len() {
            break;
        }

        let value_bytes = &buf[value_start..value_end];
        let value_hex: String = value_bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
        let value_text = if value_bytes.iter().all(|&b| b >= 32 && b < 127) && !value_bytes.is_empty() {
            Some(String::from_utf8_lossy(value_bytes).to_string())
        } else {
            None
        };

        // Recursively decode known container types.
        let children = if is_container(typ) {
            decode_tlv_range(buf, value_start, value_end)
        } else {
            Vec::new()
        };

        nodes.push(TlvNode {
            typ,
            type_name: type_name(typ).to_string(),
            length,
            start_byte: type_start,
            end_byte: value_end,
            value_hex,
            value_text,
            children,
        });

        pos = value_end;
    }
    nodes
}

fn is_container(typ: u64) -> bool {
    matches!(typ,
        t if t == tlv_type::INTEREST
          || t == tlv_type::DATA
          || t == tlv_type::NAME
          || t == tlv_type::META_INFO
          || t == tlv_type::SIGNATURE_INFO
          || t == tlv_type::FORWARDING_HINT
          || t == tlv_type::NACK
          || t == tlv_type::LP_PACKET
    )
}

/// Parse hex bytes string (space-separated or continuous) into a byte Vec.
pub fn parse_hex(hex: &str) -> Result<Vec<u8>, String> {
    let clean: String = hex.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if clean.len() % 2 != 0 {
        return Err("Odd number of hex digits".to_string());
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// Encode bytes as a hex string (space-separated, uppercase-style groups).
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ")
}
