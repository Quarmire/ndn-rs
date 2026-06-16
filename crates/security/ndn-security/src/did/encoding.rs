//! Encoding and decoding between NDN [`Name`]s and `did:ndn` DID strings.
//!
//! # Encoding
//!
//! A `did:ndn` DID is the base64url (no padding) encoding of the complete NDN
//! Name TLV wire format, including the outer `Name-Type` and `TLV-Length` octets.
//!
//! ```text
//! did:ndn:<base64url(Name TLV)>
//! ```
//!
//! Every NDN name maps to exactly one DID, and every valid `did:ndn` DID maps to
//! exactly one NDN name. The encoding is lossless across all component types
//! (GenericNameComponent, BLAKE3_DIGEST, ImplicitSha256Digest, versioned
//! components, etc.) without any type-specific special cases.
//!
//! # Backward compatibility
//!
//! Earlier drafts of the spec used two forms that are now deprecated:
//!
//! - **Simple form** — colon-joined ASCII component values:
//!   `/com/acme/alice` → `did:ndn:com:acme:alice`
//! - **`v1:` binary form** — `did:ndn:v1:<base64url(Name TLV)>`
//!
//! Both forms are still accepted by [`did_to_name`] for backward compatibility.
//! [`name_to_did`] no longer produces either deprecated form.
//!
//! # Ambiguity in the deprecated scheme
//!
//! The `v1:` prefix occupied the same position as the first name-component in the
//! simple form. A name whose first component is literally `v1` would produce the
//! same `did:ndn:v1:...` string as a binary-encoded name, making round-trip
//! decoding impossible without external context. The unified binary form has no
//! such ambiguity.

use ndn_packet::Name;
use ndn_packet::name::NameComponent;

use crate::did::resolver::DidError;

const NAME_TLV_TYPE: u64 = 7;

/// Encode an NDN [`Name`] as a `did:ndn` DID string.
///
/// The method-specific identifier is the base64url (no padding) encoding of the
/// complete NDN Name TLV wire format, including the outer `07 <length>` bytes.
///
/// ```
/// # use ndn_security::did::encoding::name_to_did;
/// # use ndn_packet::Name;
/// let name: Name = "/com/acme/alice".parse().unwrap();
/// let did = name_to_did(&name);
/// assert!(did.starts_with("did:ndn:"));
/// // The method-specific-id is base64url — no colons, no v1: prefix.
/// assert!(!did["did:ndn:".len()..].contains(':'));
/// ```
pub fn name_to_did(name: &Name) -> String {
    let tlv = encode_name_tlv(name);
    let encoded = base64_url_encode(&tlv);
    format!("did:ndn:{encoded}")
}

/// Decode a `did:ndn` DID string back to an NDN [`Name`].
///
/// Accepts:
/// - **Current form**: `did:ndn:<base64url(Name TLV)>` — no colons in the
///   method-specific identifier.
/// - **Deprecated `v1:` form**: `did:ndn:v1:<base64url(Name TLV)>` — parsed
///   for backward compatibility but no longer produced by [`name_to_did`].
/// - **Deprecated simple form**: `did:ndn:com:acme:alice` — parsed for backward
///   compatibility as colon-separated GenericNameComponent ASCII values.
pub fn did_to_name(did: &str) -> Result<Name, DidError> {
    let rest = did
        .strip_prefix("did:ndn:")
        .ok_or_else(|| DidError::InvalidDid(did.to_string()))?;

    if rest.contains(':') {
        if let Some(encoded) = rest.strip_prefix("v1:") {
            let bytes = base64_url_decode(encoded)
                .map_err(|_| DidError::InvalidDid(format!("invalid base64url in {did}")))?;
            decode_name_tlv(&bytes)
                .map_err(|_| DidError::InvalidDid(format!("invalid TLV name in {did}")))
        } else {
            colon_decode(rest)
                .ok_or_else(|| DidError::InvalidDid(format!("invalid did:ndn: {did}")))
        }
    } else {
        let bytes = base64_url_decode(rest)
            .map_err(|_| DidError::InvalidDid(format!("invalid base64url in {did}")))?;
        decode_name_tlv(&bytes)
            .map_err(|_| DidError::InvalidDid(format!("invalid TLV name in {did}")))
    }
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
    fn roundtrip_ascii_name() {
        let name: Name = "/com/acme/alice".parse().unwrap();
        let did = name_to_did(&name);
        // Current form: binary, no colons in method-specific-id.
        assert!(did.starts_with("did:ndn:"));
        assert!(!did["did:ndn:".len()..].contains(':'));
        let back = did_to_name(&did).unwrap();
        assert_eq!(back, name);
    }

    #[test]
    fn roundtrip_root() {
        let name = Name::root();
        let did = name_to_did(&name);
        assert!(did.starts_with("did:ndn:"));
        let back = did_to_name(&did).unwrap();
        assert_eq!(back, name);
    }

    #[test]
    fn roundtrip_versioned_component() {
        let name: Name = "/com/acme".parse().unwrap();
        let name = name.append_version(42);
        let did = name_to_did(&name);
        // Must be binary form — no v1: prefix.
        assert!(did.starts_with("did:ndn:"));
        assert!(!did["did:ndn:".len()..].starts_with("v1:"));
        let back = did_to_name(&did).unwrap();
        assert_eq!(back, name);
    }

    #[test]
    fn no_v1_ambiguity() {
        // A name literally starting with "v1" must round-trip correctly.
        // Under the old scheme this was ambiguous; under binary-only it is not.
        let name: Name = "/v1/BwEA".parse().unwrap();
        let did = name_to_did(&name);
        assert!(did.starts_with("did:ndn:"));
        // The DID does NOT contain "v1:" — it's all base64url.
        assert!(!did.contains("v1:"));
        let back = did_to_name(&did).unwrap();
        assert_eq!(back, name);
    }

    #[test]
    fn compat_simple_form() {
        // Old `did:ndn:com:acme:alice` form still parses.
        let name = did_to_name("did:ndn:com:acme:alice").unwrap();
        assert_eq!(name, "/com/acme/alice".parse::<Name>().unwrap());
    }

    #[test]
    fn compat_v1_binary_form() {
        // Old `did:ndn:v1:<base64>` form still parses.
        let original: Name = "/com/acme".parse().unwrap();
        let original = original.append_version(42);
        // Produce old form manually.
        let tlv = encode_name_tlv(&original);
        let b64 = base64_url_encode(&tlv);
        let old_did = format!("did:ndn:v1:{b64}");
        let back = did_to_name(&old_did).unwrap();
        assert_eq!(back, original);
    }
}
