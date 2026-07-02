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
//! ## Security level (audit ABE-2)
//!
//! ABE is anchored on the `rabe` crate (0.4.x), a niche, lightly-maintained
//! pairing library using the **BN-254** curve, whose effective security is
//! ~100 bits — **below the 128-bit baseline** the ChaCha20-Poly1305 AEAD layer
//! provides. Treat ABE as an opt-in tier whose confidentiality strength is
//! weaker than the symmetric baseline, and keep `rabe` (and its transitive
//! pairing crates) in `cargo audit` / `cargo deny` scope. Off by default
//! (`abe` feature) and never wired into the embedded forwarder.
//!
//! Three schemes are wrapped, one per access-control topology:
//! - [`bsw_setup`] / [`bsw_keygen`] / [`bsw_encrypt`] / [`bsw_decrypt`] —
//!   Bethencourt-Sahai-Waters **CP-ABE** (single authority; producer sets the
//!   policy). For producer-owned content confidentiality.
//! - [`lsw_setup`] / [`lsw_keygen`] / [`lsw_encrypt`] / [`lsw_decrypt`] —
//!   Lewko-Sahai-Waters **KP-ABE** (single authority; the *key* carries the
//!   policy, the *ciphertext* carries attributes). For centrally-governed access
//!   — the model the faithful NDNSF `ServiceController` uses.
//! - [`aw11_global_setup`] and friends — Lewko-Waters / AW11 **MA-ABE**
//!   (multi-authority). For cross-domain federation.
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
pub mod scheme_kp;
pub mod types;

pub use ciphertext::{AbeCiphertext, CIPHERTEXT_SCHEMA_VERSION, KgcRef};
pub use error::AbeError;
pub use multi_authority::{
    Aw11GlobalKeyBytes, Aw11MasterKeyBytes, Aw11PubKeyBytes, Aw11UserKey, aw11_add_attr,
    aw11_authgen, aw11_decrypt, aw11_encrypt, aw11_global_setup, aw11_keygen,
};
pub use policy::{AttributeRef, PolicyExpr};
pub use policy_block::{POLICY_BLOCK_SCHEMA_VERSION, PolicyBlockPayload};
pub use scheme::{
    BswAttributeKeys, BswMasterParams, BswMasterSecret, bsw_decrypt, bsw_encrypt, bsw_keygen,
    bsw_setup,
};
pub use scheme_kp::{
    KpMasterParams, KpMasterSecret, KpPolicyKey, lsw_decrypt, lsw_encrypt, lsw_keygen, lsw_setup,
};

use ndn_foundation_types::{Hash, Name};

/// ABE scheme discriminator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum AbeSchemeId {
    /// Bethencourt-Sahai-Waters CP-ABE (single-authority).
    BSW,
    /// Lewko-Waters / AW11 MA-ABE (multi-authority).
    LewkoWaters,
    /// Lewko-Sahai-Waters KP-ABE (single-authority, key-policy). The inverse of
    /// BSW: the key carries the policy, the ciphertext carries the attributes.
    KpAbe,
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
        attributes: vec![],
        kgc_refs: vec![KgcRef {
            kgc_did: kgc_name.clone(),
            master_params_hash: *params_hash,
        }],
        rabe_ciphertext_bytes: rabe_ct_bytes,
    })
}

/// Upper bound on the opaque rabe ciphertext blob (audit ABE-3). `rabe`
/// bincode-deserializes this blob *before* the pairing check, and bincode has no
/// inherent length cap, so an attacker-controlled blob could over-allocate on a
/// decoding node. ABE ciphertexts are far smaller than this.
const MAX_RABE_BLOB: usize = 1 << 20;

fn check_rabe_blob(ciphertext: &AbeCiphertext) -> Result<(), AbeError> {
    if ciphertext.rabe_ciphertext_bytes.len() > MAX_RABE_BLOB {
        return Err(AbeError::CiphertextMalformed(
            "rabe ciphertext blob exceeds maximum size".into(),
        ));
    }
    Ok(())
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
        return Err(AbeError::UnsupportedCiphertextVersion(
            ciphertext.schema_version,
        ));
    }
    check_rabe_blob(ciphertext)?;
    bsw_decrypt(attribute_keys, &ciphertext.rabe_ciphertext_bytes)
}

/// Encrypt `plaintext` tagged with `attributes` using LSW KP-ABE
/// (single-authority, key-policy). The controller-issued key carries the policy;
/// here the producer only tags the ciphertext with service attributes. This is
/// the model the faithful NDNSF `ServiceController` uses.
///
/// `kgc_master` is `(kgc_name, master_params_hash, KpMasterParams)`; the name and
/// hash are embedded so consumers can locate the authority to fetch their key.
pub fn encrypt_kp(
    attributes: &[String],
    plaintext: &[u8],
    kgc_master: &(Name, Hash, KpMasterParams),
) -> Result<AbeCiphertext, AbeError> {
    let (kgc_name, params_hash, mp) = kgc_master;
    let rabe_ct_bytes = lsw_encrypt(mp, attributes, plaintext)?;
    Ok(AbeCiphertext {
        schema_version: CIPHERTEXT_SCHEMA_VERSION,
        scheme: AbeSchemeId::KpAbe,
        policy_source: String::new(),
        attributes: attributes.to_vec(),
        kgc_refs: vec![KgcRef {
            kgc_did: kgc_name.clone(),
            master_params_hash: *params_hash,
        }],
        rabe_ciphertext_bytes: rabe_ct_bytes,
    })
}

/// Decrypt a KP-ABE ciphertext using a consumer's policy key.
pub fn decrypt_kp(
    ciphertext: &AbeCiphertext,
    policy_key: &KpPolicyKey,
) -> Result<Vec<u8>, AbeError> {
    if ciphertext.scheme != AbeSchemeId::KpAbe {
        return Err(AbeError::UnsupportedScheme(ciphertext.scheme));
    }
    if ciphertext.schema_version != CIPHERTEXT_SCHEMA_VERSION {
        return Err(AbeError::UnsupportedCiphertextVersion(
            ciphertext.schema_version,
        ));
    }
    check_rabe_blob(ciphertext)?;
    lsw_decrypt(policy_key, &ciphertext.rabe_ciphertext_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_foundation_types::{TlvDecode, TlvEncode};

    /// O2 spike: confirm `rabe` 0.4 exposes a usable **KP-ABE** scheme (`lsw`) —
    /// the inverse of CP-ABE (the *key* carries the policy, the *ciphertext*
    /// carries the attributes) — and that its ciphertext is serde/bincode
    /// serializable (a pinnable wire). The faithful NDNSF `KpAttributeAuthority`
    /// requires exactly this. If this passes, the KP-ABE wrapper can mirror the
    /// existing BSW (CP-ABE) wrapper with the keygen/encrypt arguments swapped.
    #[test]
    fn lsw_kp_abe_round_trips_and_serializes() {
        use rabe::schemes::lsw;
        use rabe::utils::policy::pest::PolicyLanguage;

        let (pk, msk) = lsw::setup();
        let plaintext = b"content-key bytes under KP-ABE".to_vec();

        // KP-ABE: the ciphertext is tagged with ATTRIBUTES...
        let ct = lsw::encrypt(&pk, &["mavlink", "execute"], &plaintext).expect("kp encrypt");

        // ...and the KEY carries the POLICY. A satisfied policy decrypts.
        let sk_ok = lsw::keygen(
            &pk,
            &msk,
            r#""mavlink" or "camera""#,
            PolicyLanguage::HumanPolicy,
        )
        .expect("keygen ok");
        assert_eq!(lsw::decrypt(&sk_ok, &ct).expect("decrypt ok"), plaintext);

        // An unsatisfied policy fails (negative control).
        let sk_no = lsw::keygen(
            &pk,
            &msk,
            r#""camera" and "admin""#,
            PolicyLanguage::HumanPolicy,
        )
        .expect("keygen no");
        assert!(lsw::decrypt(&sk_no, &ct).is_err());

        // Pinnable wire: bincode round-trip the ciphertext; it still decrypts.
        let wire = bincode::serialize(&ct).expect("serialize");
        let ct2: lsw::KpAbeCiphertext = bincode::deserialize(&wire).expect("deserialize");
        assert_eq!(
            lsw::decrypt(&sk_ok, &ct2).expect("decrypt after wire"),
            plaintext
        );
    }

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
    fn kp_encrypt_decrypt_round_trip_through_container() {
        // The NDNSF controller model: producer tags content with attributes; the
        // controller issues a key whose policy is satisfied by them.
        let (mp, ms) = lsw_setup().unwrap();
        let kgc_name: Name = "/muas/controller".parse().unwrap();
        let hash = Hash::of(&mp.public_key_bytes);
        let attrs = vec!["service:mavlink".to_string(), "perm:execute".to_string()];

        // `mp` is cloned into the encrypt tuple so it remains available for keygen.
        let ct = encrypt_kp(&attrs, b"flight command", &(kgc_name, hash, mp.clone())).unwrap();
        // The container records scheme + the inspectable attribute set.
        assert_eq!(ct.scheme, AbeSchemeId::KpAbe);
        assert_eq!(ct.attributes, attrs);
        assert!(ct.policy_source.is_empty());

        // Round-trip the container through TLV, then decrypt with a satisfied key.
        let ct = AbeCiphertext::decode_from_bytes(ct.encode_to_bytes()).unwrap();
        let policy = PolicyExpr::parse("service:mavlink OR service:camera").unwrap();
        let key = lsw_keygen(&mp, &ms, &policy).unwrap();
        assert_eq!(decrypt_kp(&ct, &key).unwrap(), b"flight command");

        // A non-satisfying key is rejected through the typed path too.
        let bad_policy = PolicyExpr::parse("service:camera AND perm:admin").unwrap();
        let bad_key = lsw_keygen(&mp, &ms, &bad_policy).unwrap();
        assert!(matches!(
            decrypt_kp(&ct, &bad_key),
            Err(AbeError::DecryptionFailed)
        ));
    }

    #[test]
    fn decrypt_fails_wrong_attributes() {
        let policy = PolicyExpr::parse("role:doctor AND dept:cardiology").unwrap();
        let (kgc_name, hash, mp, ms) = setup_kgc("/hospital/kgc");
        let charlie_ak = bsw_keygen(&mp, &ms, &["role:nurse".into()]).unwrap();
        let ct = encrypt(&policy, b"secret", &(kgc_name, hash, mp)).unwrap();
        assert!(matches!(
            decrypt(&ct, &charlie_ak),
            Err(AbeError::DecryptionFailed)
        ));
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
        assert!(matches!(
            decrypt(&ct, &ak),
            Err(AbeError::UnsupportedScheme(_))
        ));
    }
}
