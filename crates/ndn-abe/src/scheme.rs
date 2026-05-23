//! rabe BSW CP-ABE wrappers (single-authority).
//!
//! rabe 0.4.2 uses BN-254 (rabe-bn); BLS12-381 is not available.
//! `rabe::schemes::bsw` already performs hybrid encryption internally:
//! a random Gt element seeds AES-GCM for the payload; ABE wraps the Gt.
//! We do not add a second AES layer.
//!
//! Serialization of rabe types: serde + bincode (deterministic, compact).

use bytes::Bytes;
use rabe::schemes::bsw::{self, CpAbeCiphertext, CpAbeMasterKey, CpAbePublicKey, CpAbeSecretKey};
use rabe::utils::policy::pest::PolicyLanguage;
use tracing::instrument;

use crate::{AbeError, PolicyExpr};

// ── Opaque byte containers for rabe crypto types ──────────────────────────

/// BSW master public parameters (the encryption/E-KEY material).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BswMasterParams {
    /// bincode-serialized `CpAbePublicKey`.
    pub public_key_bytes: Bytes,
}

/// BSW master secret (held only by the KGC, never published).
#[derive(Clone, Debug)]
pub struct BswMasterSecret {
    /// bincode-serialized `CpAbeMasterKey`.
    pub master_key_bytes: Bytes,
}

/// BSW attribute keys issued to a consumer (the decryption/D-KEY material).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BswAttributeKeys {
    /// bincode-serialized `CpAbeSecretKey`.
    pub keys_bytes: Bytes,
}

// ── Serialization helpers ─────────────────────────────────────────────────

fn serialize<T: serde::Serialize>(v: &T) -> Result<Bytes, AbeError> {
    bincode::serialize(v)
        .map(Bytes::from)
        .map_err(|e| AbeError::Serialization(e.to_string()))
}

fn deserialize<T: serde::de::DeserializeOwned>(b: &[u8]) -> Result<T, AbeError> {
    bincode::deserialize(b)
        .map_err(|e| AbeError::CiphertextMalformed(e.to_string()))
}

impl BswMasterParams {
    /// Construct from a rabe public key.
    pub fn from_rabe(pk: &CpAbePublicKey) -> Result<Self, AbeError> {
        Ok(Self { public_key_bytes: serialize(pk)? })
    }

    /// Deserialize back to the rabe type.
    pub fn to_rabe(&self) -> Result<CpAbePublicKey, AbeError> {
        deserialize(&self.public_key_bytes)
    }
}

impl BswMasterSecret {
    /// Construct from a rabe master key.
    pub fn from_rabe(msk: &CpAbeMasterKey) -> Result<Self, AbeError> {
        Ok(Self { master_key_bytes: serialize(msk)? })
    }

    /// Deserialize back to the rabe type.
    pub fn to_rabe(&self) -> Result<CpAbeMasterKey, AbeError> {
        deserialize(&self.master_key_bytes)
    }
}

impl BswAttributeKeys {
    /// Construct from a rabe secret key.
    pub fn from_rabe(sk: &CpAbeSecretKey) -> Result<Self, AbeError> {
        Ok(Self { keys_bytes: serialize(sk)? })
    }

    /// Deserialize back to the rabe type.
    pub fn to_rabe(&self) -> Result<CpAbeSecretKey, AbeError> {
        deserialize(&self.keys_bytes)
    }
}

// ── BSW scheme functions ──────────────────────────────────────────────────

/// Generate fresh BSW master key pair.
#[instrument(skip_all)]
pub fn bsw_setup() -> Result<(BswMasterParams, BswMasterSecret), AbeError> {
    let (pk, msk) = bsw::setup();
    Ok((BswMasterParams::from_rabe(&pk)?, BswMasterSecret::from_rabe(&msk)?))
}

/// Derive attribute keys for a consumer. `attrs` are flat `key:value` strings.
#[instrument(skip_all)]
pub fn bsw_keygen(
    mp: &BswMasterParams,
    ms: &BswMasterSecret,
    attrs: &[String],
) -> Result<BswAttributeKeys, AbeError> {
    let pk = mp.to_rabe()?;
    let msk = ms.to_rabe()?;
    let attr_refs: Vec<&str> = attrs.iter().map(String::as_str).collect();
    let sk = bsw::keygen(&pk, &msk, &attr_refs)
        .ok_or_else(|| AbeError::SchemeError("keygen returned None (empty attributes?)".into()))?;
    BswAttributeKeys::from_rabe(&sk)
}

/// Encrypt `plaintext` under `policy`. Returns bincode-serialized `CpAbeCiphertext`.
///
/// rabe performs hybrid encryption internally: a random Gt element encrypts
/// the payload via AES-GCM; ABE wraps the Gt. No additional symmetric layer needed.
#[instrument(skip(plaintext, mp))]
pub fn bsw_encrypt(
    mp: &BswMasterParams,
    policy: &PolicyExpr,
    plaintext: &[u8],
) -> Result<Bytes, AbeError> {
    let pk = mp.to_rabe()?;
    let rabe_policy = policy.to_rabe_bsw()?;
    let ct: CpAbeCiphertext = bsw::encrypt(&pk, &rabe_policy, PolicyLanguage::HumanPolicy, plaintext)
        .map_err(|e| AbeError::SchemeError(e.to_string()))?;
    serialize(&ct)
}

/// Decrypt BSW ciphertext bytes using attribute keys.
#[instrument(skip(ak, ct_bytes))]
pub fn bsw_decrypt(ak: &BswAttributeKeys, ct_bytes: &Bytes) -> Result<Vec<u8>, AbeError> {
    let sk = ak.to_rabe()?;
    let ct: CpAbeCiphertext = deserialize(ct_bytes)?;
    bsw::decrypt(&sk, &ct).map_err(|e| {
        tracing::debug!(error = %e, "bsw_decrypt failed");
        AbeError::DecryptionFailed
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_with_attrs(attrs: &[&str]) -> (BswMasterParams, BswMasterSecret, BswAttributeKeys) {
        let (mp, ms) = bsw_setup().unwrap();
        let ak = bsw_keygen(&mp, &ms, &attrs.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        (mp, ms, ak)
    }

    #[test]
    fn bsw_setup_keygen_encrypt_decrypt_round_trip() {
        let policy = PolicyExpr::parse("role:doctor AND dept:cardiology").unwrap();
        let (mp, ms, ak) = setup_with_attrs(&["role:doctor", "dept:cardiology"]);
        let plaintext = b"sensitive medical record";
        let ct_bytes = bsw_encrypt(&mp, &policy, plaintext).unwrap();
        let recovered = bsw_decrypt(&ak, &ct_bytes).unwrap();
        assert_eq!(recovered, plaintext);
        drop(ms);
    }

    #[test]
    fn bsw_decrypt_fails_with_unauthorized_attributes() {
        let policy = PolicyExpr::parse("role:doctor AND dept:cardiology").unwrap();
        let (mp, ms, _) = setup_with_attrs(&["role:doctor", "dept:cardiology"]);
        let (_, _, unauthorized_ak) = setup_with_attrs(&["role:nurse"]);
        let ct_bytes = bsw_encrypt(&mp, &policy, b"secret").unwrap();
        let result = bsw_decrypt(&unauthorized_ak, &ct_bytes);
        assert!(matches!(result, Err(AbeError::DecryptionFailed)));
        drop(ms);
    }
}
