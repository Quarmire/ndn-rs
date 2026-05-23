//! Minimal DER SubjectPublicKeyInfo (SPKI) wrap / unwrap for Ed25519
//! certificate Content per RFC 8410 + ndn-cxx
//! `security/transform/public-key.cpp:101` (`loadPkcs8`).
//!
//! The Ed25519 SPKI envelope is a fixed 12-byte prefix followed by the
//! 32-byte raw key:
//!
//! ```text
//! SEQUENCE {                       30 2A
//!   SEQUENCE {                       30 05
//!     OBJECT IDENTIFIER 1.3.101.112    06 03 2B 65 70   -- id-Ed25519
//!   }
//!   BIT STRING {                     03 21
//!     unused-bits=0                    00
//!     <32 bytes of key>
//!   }
//! }
//! ```
//!
//! Total wire length: 44 bytes. The canonical prefix never varies.

use bytes::Bytes;

/// Total bytes in an Ed25519 SPKI envelope.
pub const ED25519_SPKI_LEN: usize = 44;
/// Length of the raw Ed25519 public key.
pub const ED25519_KEY_LEN: usize = 32;

/// 12-byte fixed prefix preceding the 32-byte key value in an Ed25519
/// SPKI envelope. Matches RFC 8410 §4.
pub const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Wrap a 32-byte Ed25519 public key as a DER SPKI envelope.
pub fn wrap_ed25519(raw_key: &[u8; ED25519_KEY_LEN]) -> Bytes {
    let mut out = [0u8; ED25519_SPKI_LEN];
    out[..12].copy_from_slice(&ED25519_SPKI_PREFIX);
    out[12..].copy_from_slice(raw_key);
    Bytes::copy_from_slice(&out)
}

/// Extract the 32-byte Ed25519 raw key from a DER SPKI envelope.
/// Returns `None` if the envelope's algorithm OID, structure, or length
/// does not match the Ed25519 SPKI shape.
pub fn unwrap_ed25519(spki: &[u8]) -> Option<[u8; ED25519_KEY_LEN]> {
    if spki.len() != ED25519_SPKI_LEN || spki[..12] != ED25519_SPKI_PREFIX {
        return None;
    }
    let mut key = [0u8; ED25519_KEY_LEN];
    key.copy_from_slice(&spki[12..]);
    Some(key)
}

/// True if `bytes` looks like an Ed25519 SPKI envelope (length and
/// prefix match). Used by `Certificate::decode` to decide whether
/// Content needs unwrapping.
pub fn is_ed25519_spki(bytes: &[u8]) -> bool {
    bytes.len() == ED25519_SPKI_LEN && bytes[..12] == ED25519_SPKI_PREFIX
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_known_key() {
        let key = [0x42u8; 32];
        let spki = wrap_ed25519(&key);
        assert_eq!(spki.len(), ED25519_SPKI_LEN);
        assert!(is_ed25519_spki(&spki));
        let back = unwrap_ed25519(&spki).expect("must unwrap");
        assert_eq!(back, key);
    }

    #[test]
    fn unwrap_rejects_wrong_prefix() {
        let mut bad = [0u8; ED25519_SPKI_LEN];
        bad[..12].copy_from_slice(&[0xFF; 12]);
        assert!(unwrap_ed25519(&bad).is_none());
    }

    #[test]
    fn unwrap_rejects_wrong_length() {
        assert!(unwrap_ed25519(&[0u8; 32]).is_none());
        assert!(unwrap_ed25519(&[0u8; 64]).is_none());
    }

    #[test]
    fn prefix_matches_rfc8410() {
        // SEQUENCE(42 bytes) { SEQUENCE(5 bytes) { OID 1.3.101.112 } BIT STRING(33 bytes) { 00 ... } }
        assert_eq!(
            ED25519_SPKI_PREFIX,
            [
                0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00
            ]
        );
    }
}
