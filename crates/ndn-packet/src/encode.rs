/// Packet encoding utilities.
///
/// Produces minimal wire-format Interest and Data TLVs using `TlvWriter`.
/// Intended for applications and the management plane, not the forwarding
/// pipeline (which operates on already-encoded `Bytes`).
use std::sync::atomic::{AtomicU32, Ordering};

use bytes::Bytes;
use ndn_tlv::{TlvReader, TlvWriter};

use crate::{Name, tlv_type};

// ─── Public API ───────────────────────────────────────────────────────────────

/// Encode a minimal Interest TLV.
///
/// Includes:
/// - `Name` built from `name`
/// - `Nonce` (4 bytes, process-local counter XOR process ID — sufficient for
///   loop detection; not cryptographically random)
/// - `InterestLifetime` fixed at 4 000 ms
/// - `ApplicationParameters` (TLV type 0x24) if `app_params` is `Some`
///
/// The returned `Bytes` is a complete, self-contained TLV suitable for direct
/// transmission over any NDN face.
pub fn encode_interest(name: &Name, app_params: Option<&[u8]>) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_nested(tlv_type::INTEREST, |w| {
        write_name(w, name);
        w.write_tlv(tlv_type::NONCE, &next_nonce().to_be_bytes());
        w.write_tlv(tlv_type::INTEREST_LIFETIME, &4000u64.to_be_bytes());
        if let Some(params) = app_params {
            w.write_tlv(tlv_type::APP_PARAMETERS, params);
        }
    });
    w.finish()
}

/// Encode a Data TLV with a placeholder `DigestSha256` signature.
///
/// The signature type is `0` (DigestSha256) and the value is 32 zero bytes.
/// This is intentionally unsigned — correctness for the management plane is
/// guaranteed by the transport (local Unix socket / shared-memory IPC), not by
/// the NDN signature chain.  Full `Ed25519` signing can be layered on later via
/// `SecurityManager`.
///
/// `FreshnessPeriod` is 0 so management responses are never served from cache.
pub fn encode_data_unsigned(name: &Name, content: &[u8]) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_nested(tlv_type::DATA, |w| {
        write_name(w, name);
        // MetaInfo: FreshnessPeriod = 0
        w.write_nested(tlv_type::META_INFO, |w| {
            w.write_tlv(tlv_type::FRESHNESS_PERIOD, &0u64.to_be_bytes());
        });
        w.write_tlv(tlv_type::CONTENT, content);
        // SignatureInfo: DigestSha256 (type code 0)
        w.write_nested(tlv_type::SIGNATURE_INFO, |w| {
            w.write_tlv(tlv_type::SIGNATURE_TYPE, &[0u8]);
        });
        // 32-byte placeholder signature value
        w.write_tlv(tlv_type::SIGNATURE_VALUE, &[0u8; 32]);
    });
    w.finish()
}

/// Encode a Nack as an NDNLPv2 LpPacket wrapping the original Interest.
///
/// The resulting packet is an LpPacket (0x64) containing:
/// - Nack header (0x0320) with NackReason (0x0321)
/// - Fragment (0x50) containing the original Interest wire bytes
///
/// `interest_wire` must be a complete Interest TLV (type + length + value).
pub fn encode_nack(reason: crate::NackReason, interest_wire: &[u8]) -> Bytes {
    crate::lp::encode_lp_nack(reason, interest_wire)
}

/// Ensure an Interest has a Nonce field.
///
/// If the Interest wire bytes already contain a Nonce (TLV 0x0A), returns the
/// bytes unchanged. Otherwise, re-encodes the Interest with a generated Nonce
/// inserted after the Name.
///
/// Per RFC 8569 §4.2, a forwarder MUST add a Nonce before forwarding.
pub fn ensure_nonce(interest_wire: &Bytes) -> Bytes {
    // Quick scan: does a Nonce TLV already exist?
    let mut reader = TlvReader::new(interest_wire.clone());
    let Ok((typ, value)) = reader.read_tlv() else { return interest_wire.clone() };
    if typ != tlv_type::INTEREST { return interest_wire.clone(); }

    let mut inner = TlvReader::new(value.clone());
    while !inner.is_empty() {
        let Ok((t, _)) = inner.read_tlv() else { break };
        if t == tlv_type::NONCE {
            return interest_wire.clone(); // already has Nonce
        }
    }

    // No Nonce found — re-encode with one inserted.
    let mut w = TlvWriter::new();
    w.write_nested(tlv_type::INTEREST, |w| {
        let mut inner = TlvReader::new(value);
        let mut name_written = false;
        while !inner.is_empty() {
            let Ok((t, v)) = inner.read_tlv() else { break };
            w.write_tlv(t, &v);
            // Insert Nonce right after Name (type 0x07).
            if !name_written && t == tlv_type::NAME {
                w.write_tlv(tlv_type::NONCE, &next_nonce().to_be_bytes());
                name_written = true;
            }
        }
        if !name_written {
            // Name wasn't found (malformed), add Nonce at end as fallback.
            w.write_tlv(tlv_type::NONCE, &next_nonce().to_be_bytes());
        }
    });
    w.finish()
}

// ─── Private helpers ──────────────────────────────────────────────────────────

/// Write a `Name` TLV into an in-progress writer, preserving each component's
/// original type code (e.g. `0x08` generic, `0x01` ImplicitSha256Digest).
fn write_name(w: &mut TlvWriter, name: &Name) {
    w.write_nested(tlv_type::NAME, |w| {
        for comp in name.components() {
            w.write_tlv(comp.typ, &comp.value);
        }
    });
}

/// Produce a per-process-unique 4-byte nonce.
///
/// Combines a monotonically-increasing per-process counter with the low 16 bits
/// of the process ID.  Sufficient for loop detection; not cryptographically
/// random.
fn next_nonce() -> u32 {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    (std::process::id() << 16).wrapping_add(seq)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use crate::{Data, Interest, NameComponent};

    fn name(components: &[&[u8]]) -> Name {
        Name::from_components(
            components.iter().map(|c| NameComponent::generic(Bytes::copy_from_slice(c)))
        )
    }

    #[test]
    fn interest_roundtrip_name() {
        let n = name(&[b"localhost", b"ndn-ctl", b"get-stats"]);
        let bytes = encode_interest(&n, None);
        let interest = Interest::decode(bytes).unwrap();
        assert_eq!(*interest.name, n);
    }

    #[test]
    fn interest_with_app_params_roundtrip() {
        let n = name(&[b"localhost", b"ndn-ctl", b"add-route"]);
        let params = br#"{"cmd":"add_route","prefix":"/ndn","face":1,"cost":10}"#;
        let bytes = encode_interest(&n, Some(params));
        let interest = Interest::decode(bytes).unwrap();
        assert_eq!(*interest.name, n);
        assert_eq!(interest.app_parameters().map(|b| b.as_ref()), Some(params.as_ref()));
    }

    #[test]
    fn interest_has_nonce_and_lifetime() {
        use core::time::Duration;
        let n = name(&[b"test"]);
        let bytes = encode_interest(&n, None);
        let interest = Interest::decode(bytes).unwrap();
        assert!(interest.nonce().is_some());
        assert_eq!(interest.lifetime(), Some(Duration::from_millis(4000)));
    }

    #[test]
    fn data_roundtrip_name_and_content() {
        let n = name(&[b"localhost", b"ndn-ctl", b"get-stats"]);
        let content = br#"{"status":"ok","pit_size":42}"#;
        let bytes = encode_data_unsigned(&n, content);
        let data = Data::decode(bytes).unwrap();
        assert_eq!(*data.name, n);
        assert_eq!(data.content().map(|b| b.as_ref()), Some(content.as_ref()));
    }

    #[test]
    fn data_freshness_is_zero() {
        use std::time::Duration;
        let n = name(&[b"test"]);
        let bytes = encode_data_unsigned(&n, b"hello");
        let data = Data::decode(bytes).unwrap();
        let mi = data.meta_info().expect("meta_info present");
        assert_eq!(mi.freshness_period, Some(Duration::from_millis(0)));
    }

    #[test]
    fn nack_roundtrip() {
        use crate::{Nack, NackReason};
        let n = name(&[b"test", b"nack"]);
        let interest_wire = encode_interest(&n, None);
        let nack_wire = encode_nack(NackReason::NoRoute, &interest_wire);
        let nack = Nack::decode(nack_wire).unwrap();
        assert_eq!(nack.reason, NackReason::NoRoute);
        assert_eq!(*nack.interest.name, n);
    }

    #[test]
    fn nack_congestion_roundtrip() {
        use crate::{Nack, NackReason};
        let n = name(&[b"hello"]);
        let interest_wire = encode_interest(&n, None);
        let nack_wire = encode_nack(NackReason::Congestion, &interest_wire);
        let nack = Nack::decode(nack_wire).unwrap();
        assert_eq!(nack.reason, NackReason::Congestion);
    }

    #[test]
    fn ensure_nonce_adds_when_missing() {
        // Build Interest without Nonce.
        let n = name(&[b"test"]);
        let mut w = TlvWriter::new();
        w.write_nested(tlv_type::INTEREST, |w| {
            write_name(w, &n);
            w.write_tlv(tlv_type::INTEREST_LIFETIME, &4000u64.to_be_bytes());
        });
        let no_nonce = w.finish();
        let interest = Interest::decode(no_nonce.clone()).unwrap();
        assert!(interest.nonce().is_none());

        let with_nonce = ensure_nonce(&no_nonce);
        let interest2 = Interest::decode(with_nonce).unwrap();
        assert!(interest2.nonce().is_some());
    }

    #[test]
    fn ensure_nonce_preserves_existing() {
        let n = name(&[b"test"]);
        let bytes = encode_interest(&n, None);
        let original_nonce = Interest::decode(bytes.clone()).unwrap().nonce();
        let result = ensure_nonce(&bytes);
        assert_eq!(result, bytes); // unchanged
        let after = Interest::decode(result).unwrap().nonce();
        assert_eq!(original_nonce, after);
    }

    #[test]
    fn nonces_are_unique() {
        let n = name(&[b"test"]);
        let b1 = encode_interest(&n, None);
        let b2 = encode_interest(&n, None);
        let i1 = Interest::decode(b1).unwrap();
        let i2 = Interest::decode(b2).unwrap();
        // Sequential calls should produce different nonces.
        assert_ne!(i1.nonce(), i2.nonce());
    }
}
