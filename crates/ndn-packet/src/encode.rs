/// Packet encoding utilities.
///
/// Produces minimal wire-format Interest and Data TLVs using `TlvWriter`.
/// Intended for applications and the management plane, not the forwarding
/// pipeline (which operates on already-encoded `Bytes`).
use std::sync::atomic::{AtomicU32, Ordering};

use bytes::Bytes;
use ndn_tlv::TlvWriter;

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
