//! # ndn-abe — Attribute-Based Encryption for NDN content
//!
//! A heavyweight confidentiality **extension** for ndn-rs: encrypt content
//! under an attribute *policy* (e.g. `"dept:eng AND clearance:high"`) so that
//! any consumer holding a satisfying set of attribute keys can decrypt, without
//! the producer enumerating recipients. This is the one-to-many tier of the
//! confidentiality layering — the ChaCha20-Poly1305 AEAD baseline and
//! per-recipient key-wrap (NAC) sit below it in `ndn-crypto-core`. ABE is for
//! named-radio / broadcast fan-out where enumerating recipients does not scale.
//!
//! Two schemes are wrapped:
//! - [`bsw_setup`] / [`bsw_keygen`] / [`bsw_encrypt`] / [`bsw_decrypt`] —
//!   Bethencourt-Sahai-Waters CP-ABE (single authority).
//! - [`aw11_global_setup`] and friends — Lewko-Waters / AW11 MA-ABE
//!   (multi-authority).
//!
//! [`AbeCiphertext`] is the versioned NDN-TLV container that carries a
//! scheme-produced ciphertext plus the policy string and KGC references; it
//! round-trips through [`ndn_tlv`] and can be placed in the Content of a
//! signable Data packet.
//!
//! ## Curve / dependency note
//! rabe 0.4.2 uses BN-254 (rabe-bn). BLS12-381 is not available in rabe 0.4,
//! and rabe is a niche, lightly maintained crate — the version is pinned, and
//! this layer should be revisited if rabe stalls. ABE decryption is heavy
//! pairing crypto: keep it on producer / capable nodes. Do **not** wire it into
//! the embedded forwarder; a constrained node at most consumes ABE content
//! (possibly offloading the decrypt). ABE is an optimization layer, never the
//! security baseline.
//!
//! ## Hybrid encryption
//! rabe performs hybrid encryption internally — a random Gt element AES-GCMs
//! the payload and ABE wraps the Gt. No additional symmetric layer is needed.

#![deny(missing_docs)]
#![allow(clippy::module_name_repetitions)]

pub mod ciphertext;
pub mod error;
pub mod multi_authority;
pub mod policy;
pub mod policy_block;
pub mod scheme;
pub mod types;

pub use ciphertext::{AbeCiphertext, KgcRef, CIPHERTEXT_SCHEMA_VERSION};
pub use error::AbeError;
pub use multi_authority::{
    aw11_add_attr, aw11_authgen, aw11_decrypt, aw11_encrypt, aw11_global_setup, aw11_keygen,
    Aw11GlobalKeyBytes, Aw11MasterKeyBytes, Aw11PubKeyBytes, Aw11UserKey,
};
pub use policy::{AttributeRef, PolicyExpr};
pub use policy_block::{PolicyBlockPayload, POLICY_BLOCK_SCHEMA_VERSION};
pub use scheme::{
    bsw_decrypt, bsw_encrypt, bsw_keygen, bsw_setup, BswAttributeKeys, BswMasterParams,
    BswMasterSecret,
};

use ndn_foundation_types::{Hash, Name};

/// ABE scheme discriminator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum AbeSchemeId {
    /// Bethencourt-Sahai-Waters CP-ABE (single-authority).
    BSW,
    /// Lewko-Waters / AW11 MA-ABE (multi-authority).
    LewkoWaters,
}

/// Encrypt `plaintext` under `policy` using BSW CP-ABE (single-authority).
///
/// `kgc_master` is `(kgc_name, master_params_hash, BswMasterParams)`.
/// The `kgc_name` and `master_params_hash` are embedded in the ciphertext
/// container so consumers can locate the KGC to fetch their attribute keys.
pub fn encrypt(
    policy: &PolicyExpr,
    plaintext: &[u8],
    kgc_master: &(Name, Hash, BswMasterParams),
) -> Result<AbeCiphertext, AbeError> {
    let (kgc_name, params_hash, mp) = kgc_master;
    let rabe_ct_bytes = bsw_encrypt(mp, policy, plaintext)?;
    Ok(AbeCiphertext {
        schema_version: CIPHERTEXT_SCHEMA_VERSION,
        scheme: AbeSchemeId::BSW,
        policy_source: policy.to_canonical(),
        kgc_refs: vec![KgcRef {
            kgc_did: kgc_name.clone(),
            master_params_hash: *params_hash,
        }],
        rabe_ciphertext_bytes: rabe_ct_bytes,
    })
}

/// Decrypt a BSW ciphertext using consumer attribute keys.
pub fn decrypt(
    ciphertext: &AbeCiphertext,
    attribute_keys: &BswAttributeKeys,
) -> Result<Vec<u8>, AbeError> {
    if ciphertext.scheme != AbeSchemeId::BSW {
        return Err(AbeError::UnsupportedScheme(ciphertext.scheme));
    }
    if ciphertext.schema_version != CIPHERTEXT_SCHEMA_VERSION {
        return Err(AbeError::UnsupportedCiphertextVersion(ciphertext.schema_version));
    }
    bsw_decrypt(attribute_keys, &ciphertext.rabe_ciphertext_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_foundation_types::{TlvDecode, TlvEncode};

    fn setup_kgc(name: &str) -> (Name, Hash, BswMasterParams, BswMasterSecret) {
        let kgc_name: Name = name.parse().unwrap();
        let (mp, ms) = bsw_setup().unwrap();
        let hash = Hash::of(&mp.public_key_bytes);
        (kgc_name, hash, mp, ms)
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let policy = PolicyExpr::parse("role:doctor AND dept:cardiology").unwrap();
        let (kgc_name, hash, mp, ms) = setup_kgc("/hospital/kgc");
        let ak = bsw_keygen(&mp, &ms, &["role:doctor".into(), "dept:cardiology".into()]).unwrap();
        let ct = encrypt(&policy, b"patient record", &(kgc_name, hash, mp)).unwrap();
        let recovered = decrypt(&ct, &ak).unwrap();
        assert_eq!(recovered, b"patient record");
    }

    #[test]
    fn decrypt_fails_wrong_attributes() {
        let policy = PolicyExpr::parse("role:doctor AND dept:cardiology").unwrap();
        let (kgc_name, hash, mp, ms) = setup_kgc("/hospital/kgc");
        let charlie_ak = bsw_keygen(&mp, &ms, &["role:nurse".into()]).unwrap();
        let ct = encrypt(&policy, b"secret", &(kgc_name, hash, mp)).unwrap();
        assert!(matches!(decrypt(&ct, &charlie_ak), Err(AbeError::DecryptionFailed)));
        drop(ms);
    }

    #[test]
    fn ciphertext_wire_round_trip_with_real_rabe() {
        let policy = PolicyExpr::parse("x:y").unwrap();
        let (kgc_name, hash, mp, ms) = setup_kgc("/test/kgc");
        // clone mp so we can still use it after encrypt consumes the tuple
        let mp_clone = mp.clone();
        let ct = encrypt(&policy, b"hello", &(kgc_name, hash, mp)).unwrap();

        let encoded = ct.encode_to_bytes();
        let decoded = AbeCiphertext::decode_from_bytes(encoded).unwrap();
        assert_eq!(ct, decoded);

        // Verify we can still decrypt after the wire round-trip
        let ak = bsw_keygen(&mp_clone, &ms, &["x:y".into()]).unwrap();
        let plaintext = decrypt(&decoded, &ak).unwrap();
        assert_eq!(plaintext, b"hello");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let policy = PolicyExpr::parse("role:doctor").unwrap();
        let (kgc_name, hash, mp, ms) = setup_kgc("/hospital/kgc");
        let ak = bsw_keygen(&mp, &ms, &["role:doctor".into()]).unwrap();
        let mut ct = encrypt(&policy, b"secret data", &(kgc_name, hash, mp)).unwrap();

        // Flip a byte in the rabe ciphertext blob
        let mut blob = ct.rabe_ciphertext_bytes.to_vec();
        let mid = blob.len() / 2;
        blob[mid] ^= 0xff;
        ct.rabe_ciphertext_bytes = bytes::Bytes::from(blob);

        assert!(decrypt(&ct, &ak).is_err());
    }

    #[test]
    fn unsupported_scheme_returns_error() {
        let (kgc_name, hash, mp, ms) = setup_kgc("/kgc");
        let policy = PolicyExpr::parse("a:b").unwrap();
        let ak = bsw_keygen(&mp, &ms, &["a:b".into()]).unwrap();
        let mut ct = encrypt(&policy, b"x", &(kgc_name, hash, mp)).unwrap();
        ct.scheme = AbeSchemeId::LewkoWaters; // wrong scheme
        assert!(matches!(decrypt(&ct, &ak), Err(AbeError::UnsupportedScheme(_))));
    }
}
