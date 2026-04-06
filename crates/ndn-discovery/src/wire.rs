//! Shared TLV encoding/decoding helpers for discovery packet builders.

use bytes::Bytes;
use ndn_packet::{Name, tlv_type};
use ndn_tlv::{TlvReader, TlvWriter};

// ─── Encoding ────────────────────────────────────────────────────────────────

/// Encode a non-negative integer as the minimal-width big-endian representation.
pub fn write_nni(w: &mut TlvWriter, typ: u64, val: u64) {
    if val <= 0xFF {
        w.write_tlv(typ, &[val as u8]);
    } else if val <= 0xFFFF {
        w.write_tlv(typ, &(val as u16).to_be_bytes());
    } else if val <= 0xFFFF_FFFF {
        w.write_tlv(typ, &(val as u32).to_be_bytes());
    } else {
        w.write_tlv(typ, &val.to_be_bytes());
    }
}

/// Write a Name TLV (type 0x07) into a `TlvWriter`.
pub fn write_name_tlv(w: &mut TlvWriter, name: &Name) {
    w.write_nested(tlv_type::NAME, |w: &mut TlvWriter| {
        for comp in name.components() {
            w.write_tlv(comp.typ, &comp.value);
        }
    });
}

/// Encode a standalone Name TLV and return its wire bytes.
pub fn encode_name_tlv(name: &Name) -> Vec<u8> {
    let mut w = TlvWriter::new();
    write_name_tlv(&mut w, name);
    w.finish().to_vec()
}

// ─── Decoding ─────────────────────────────────────────────────────────────────

/// Parse a `Name` from a slice that starts with a Name TLV (type 0x07).
pub fn parse_name_from_tlv(wire: &Bytes) -> Option<Name> {
    let mut r = TlvReader::new(wire.clone());
    let (typ, val) = r.read_tlv().ok()?;
    if typ != tlv_type::NAME {
        return None;
    }
    Name::decode(val).ok()
}

/// Parsed fields from a raw Interest TLV without digest validation.
///
/// Used by discovery protocols for link-local hello Interests where the full
/// NDN AppParams digest requirement (`ParametersSha256DigestComponent`) is not
/// enforced — the receiver trusts the link rather than a cryptographic chain.
pub struct RawInterest {
    pub name: Name,
    pub app_params: Option<Bytes>,
}

/// Parse Interest name and AppParams from raw wire bytes without validating
/// the `ParametersSha256DigestComponent` that `Interest::decode` requires.
pub fn parse_raw_interest(raw: &Bytes) -> Option<RawInterest> {
    let mut r = TlvReader::new(raw.clone());
    let (typ, value) = r.read_tlv().ok()?;
    if typ != tlv_type::INTEREST {
        return None;
    }
    let mut inner = TlvReader::new(value);
    let mut name: Option<Name> = None;
    let mut app_params: Option<Bytes> = None;
    while !inner.is_empty() {
        let (t, v) = inner.read_tlv().ok()?;
        match t {
            t if t == tlv_type::NAME => {
                name = Some(Name::decode(v).ok()?);
            }
            t if t == tlv_type::APP_PARAMETERS => {
                app_params = Some(v);
            }
            _ => {}
        }
    }
    Some(RawInterest {
        name: name?,
        app_params,
    })
}

/// Parse Data name and Content from raw wire bytes.
pub struct RawData {
    pub name: Name,
    pub content: Option<Bytes>,
}

pub fn parse_raw_data(raw: &Bytes) -> Option<RawData> {
    let mut r = TlvReader::new(raw.clone());
    let (typ, value) = r.read_tlv().ok()?;
    if typ != tlv_type::DATA {
        return None;
    }
    let mut inner = TlvReader::new(value);
    let mut name: Option<Name> = None;
    let mut content: Option<Bytes> = None;
    while !inner.is_empty() {
        let (t, v) = inner.read_tlv().ok()?;
        match t {
            t if t == tlv_type::NAME => {
                name = Some(Name::decode(v).ok()?);
            }
            t if t == tlv_type::CONTENT => {
                content = Some(v);
            }
            _ => {}
        }
    }
    Some(RawData {
        name: name?,
        content,
    })
}

/// If `raw` is an LP-framed packet (`0x64`), extract and return the inner
/// fragment bytes.  Otherwise return `raw` unchanged.
///
/// Returns `None` if the LP packet is malformed or carries no fragment (e.g.
/// an ACK-only packet).
pub fn unwrap_lp(raw: &Bytes) -> Option<Bytes> {
    if !ndn_packet::lp::is_lp_packet(raw) {
        return Some(raw.clone());
    }
    ndn_packet::lp::LpPacket::decode(raw.clone()).ok()?.fragment
}
