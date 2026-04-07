//! Encoding and decoding between NDN [`Name`]s and `did:ndn` DID strings.

use ndn_packet::Name;
use ndn_packet::name::NameComponent;

use crate::resolver::DidError;

/// TLV type for GenericNameComponent.
const GENERIC_NAME_COMPONENT: u64 = 8;
/// TLV type for Name container.
const NAME_TLV_TYPE: u64 = 7;

/// Encode an NDN [`Name`] as a `did:ndn` DID string.
///
/// Simple names (all `GenericNameComponent`s with ASCII alphanumeric, `-`, `_`, or `.` values)
/// use colon-encoded form: `/com/acme/alice` → `did:ndn:com:acme:alice`.
///
/// All other names fall back to `did:ndn:v1:<base64url(TLV)>`.
pub fn name_to_did(name: &Name) -> String {
    if let Some(simple) = try_simple_encode(name) {
        format!("did:ndn:{simple}")
    } else {
        let tlv = encode_name_tlv(name);
        let encoded = base64_url_encode(&tlv);
        format!("did:ndn:v1:{encoded}")
    }
}

/// Decode a `did:ndn` DID string back to an NDN [`Name`].
pub fn did_to_name(did: &str) -> Result<Name, DidError> {
    let rest = did
        .strip_prefix("did:ndn:")
        .ok_or_else(|| DidError::InvalidDid(did.to_string()))?;

    if let Some(encoded) = rest.strip_prefix("v1:") {
        // TLV base64url form
        let bytes = base64_url_decode(encoded)
            .map_err(|_| DidError::InvalidDid(format!("invalid base64url in {did}")))?;
        decode_name_tlv(&bytes)
            .map_err(|_| DidError::InvalidDid(format!("invalid TLV name in {did}")))
    } else {
        // Colon-encoded form
        colon_decode(rest)
            .ok_or_else(|| DidError::InvalidDid(format!("invalid colon-encoded did:ndn: {did}")))
    }
}

// --- internals ---

fn try_simple_encode(name: &Name) -> Option<String> {
    let mut parts = Vec::with_capacity(name.len());
    for comp in name.components() {
        if comp.typ != GENERIC_NAME_COMPONENT {
            return None;
        }
        let s = std::str::from_utf8(&comp.value).ok()?;
        if s.is_empty()
            || !s
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        {
            return None;
        }
        parts.push(s.to_string());
    }
    Some(parts.join(":"))
}

fn colon_decode(s: &str) -> Option<Name> {
    if s.is_empty() {
        return Some(Name::root());
    }
    let mut name = Name::root();
    for part in s.split(':') {
        if part.is_empty() {
            return None;
        }
        name = name.append(part);
    }
    Some(name)
}

/// Encode a Name as TLV bytes (type=7, then each component as type=8).
fn encode_name_tlv(name: &Name) -> Vec<u8> {
    let mut inner: Vec<u8> = Vec::new();
    for comp in name.components() {
        write_tlv_to(&mut inner, comp.typ, &comp.value);
    }
    let mut out = Vec::new();
    write_tlv_to(&mut out, NAME_TLV_TYPE, &inner);
    out
}

fn decode_name_tlv(data: &[u8]) -> Result<Name, ()> {
    // Read outer Name TLV
    let (typ, inner, _) = read_tlv(data).ok_or(())?;
    if typ != NAME_TLV_TYPE {
        return Err(());
    }
    let mut comps = Vec::new();
    let mut rest = inner;
    while !rest.is_empty() {
        let (typ, val, remaining) = read_tlv(rest).ok_or(())?;
        comps.push(NameComponent {
            typ,
            value: bytes::Bytes::copy_from_slice(val),
        });
        rest = remaining;
    }
    Ok(Name::from_components(comps))
}

fn write_tlv_to(buf: &mut Vec<u8>, typ: u64, value: &[u8]) {
    write_varu64(buf, typ);
    write_varu64(buf, value.len() as u64);
    buf.extend_from_slice(value);
}

fn write_varu64(buf: &mut Vec<u8>, v: u64) {
    if v <= 252 {
        buf.push(v as u8);
    } else if v <= 0xFFFF {
        buf.push(0xFD);
        buf.extend_from_slice(&(v as u16).to_be_bytes());
    } else if v <= 0xFFFF_FFFF {
        buf.push(0xFE);
        buf.extend_from_slice(&(v as u32).to_be_bytes());
    } else {
        buf.push(0xFF);
        buf.extend_from_slice(&v.to_be_bytes());
    }
}

fn read_varu64(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    match first {
        0..=252 => Some((first as u64, 1)),
        0xFD => {
            let b = buf.get(1..3)?;
            Some((u16::from_be_bytes([b[0], b[1]]) as u64, 3))
        }
        0xFE => {
            let b = buf.get(1..5)?;
            Some((u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64, 5))
        }
        0xFF => {
            let b = buf.get(1..9)?;
            Some((u64::from_be_bytes(b.try_into().ok()?), 9))
        }
    }
}

fn read_tlv(buf: &[u8]) -> Option<(u64, &[u8], &[u8])> {
    let (typ, t_sz) = read_varu64(buf)?;
    let rest = &buf[t_sz..];
    let (len, l_sz) = read_varu64(rest)?;
    let rest = &rest[l_sz..];
    let len = len as usize;
    if rest.len() < len {
        return None;
    }
    Some((typ, &rest[..len], &rest[len..]))
}

fn base64_url_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn base64_url_decode(s: &str) -> Result<Vec<u8>, ()> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_packet::Name;

    #[test]
    fn roundtrip_simple() {
        let name: Name = "/com/acme/alice".parse().unwrap();
        let did = name_to_did(&name);
        assert_eq!(did, "did:ndn:com:acme:alice");
        let back = did_to_name(&did).unwrap();
        assert_eq!(back, name);
    }

    #[test]
    fn roundtrip_root() {
        let name = Name::root();
        let did = name_to_did(&name);
        assert_eq!(did, "did:ndn:");
        let back = did_to_name(&did).unwrap();
        assert_eq!(back, name);
    }

    #[test]
    fn fallback_to_tlv_for_non_ascii() {
        // A name with a version component (non-generic type) falls back to base64url TLV
        let name: Name = "/com/acme".parse().unwrap();
        let name = name.append_version(42);
        let did = name_to_did(&name);
        assert!(did.starts_with("did:ndn:v1:"));
        let back = did_to_name(&did).unwrap();
        assert_eq!(back, name);
    }
}
