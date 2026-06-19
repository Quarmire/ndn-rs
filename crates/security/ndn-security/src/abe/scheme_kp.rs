//! rabe LSW KP-ABE wrappers (single-authority, **key-policy**).
//!
//! The inverse of the BSW CP-ABE wrappers in [`super::scheme`]: in KP-ABE the
//! issued **key carries the policy** and the **ciphertext carries the
//! attributes**, so [`lsw_keygen`] takes a [`PolicyExpr`] and [`lsw_encrypt`]
//! takes an attribute set. This is the model the faithful NDNSF `ServiceController`
//! uses (a `KpAttributeAuthority`): the controller bakes each principal's allowed
//! services into the key it issues, and producers tag content with service
//! attributes.
//!
//! rabe 0.4.2 `lsw` uses BN-254 (rabe-bn) and performs hybrid encryption
//! internally (a random Gt element AES-GCMs the payload; ABE wraps the Gt), the
//! same as BSW — no second symmetric layer is added. rabe types are serialized
//! with serde + bincode, matching [`super::scheme`]; the O2 spike
//! (`super::tests::lsw_kp_abe_round_trips_and_serializes`) pins this.

use bytes::Bytes;
use rabe::schemes::lsw::{self, KpAbeCiphertext, KpAbeMasterKey, KpAbePublicKey, KpAbeSecretKey};
use rabe::utils::policy::pest::PolicyLanguage;
use tracing::instrument;

use crate::abe::{AbeError, PolicyExpr};

/// LSW master public parameters (the encryption material).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KpMasterParams {
    /// bincode-serialized `KpAbePublicKey`.
    pub public_key_bytes: Bytes,
}

/// LSW master secret (held only by the authority, never published).
#[derive(Clone, Debug)]
pub struct KpMasterSecret {
    /// bincode-serialized `KpAbeMasterKey`.
    pub master_key_bytes: Bytes,
}

/// An LSW policy key issued to a decryptor — the secret key that **encodes the
/// decryptor's access policy** (the KP-ABE D-KEY). Named for what it carries
/// (a policy), unlike CP-ABE's attribute keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KpPolicyKey {
    /// bincode-serialized `KpAbeSecretKey`.
    pub key_bytes: Bytes,
}

fn serialize<T: serde::Serialize>(v: &T) -> Result<Bytes, AbeError> {
    bincode::serialize(v)
        .map(Bytes::from)
        .map_err(|e| AbeError::Serialization(e.to_string()))
}

fn deserialize<T: serde::de::DeserializeOwned>(b: &[u8]) -> Result<T, AbeError> {
    bincode::deserialize(b).map_err(|e| AbeError::CiphertextMalformed(e.to_string()))
}

impl KpMasterParams {
    /// Construct from a rabe public key.
    pub fn from_rabe(pk: &KpAbePublicKey) -> Result<Self, AbeError> {
        Ok(Self {
            public_key_bytes: serialize(pk)?,
        })
    }
    /// Deserialize back to the rabe type.
    pub fn to_rabe(&self) -> Result<KpAbePublicKey, AbeError> {
        deserialize(&self.public_key_bytes)
    }
}

impl KpMasterSecret {
    /// Construct from a rabe master key.
    pub fn from_rabe(msk: &KpAbeMasterKey) -> Result<Self, AbeError> {
        Ok(Self {
            master_key_bytes: serialize(msk)?,
        })
    }
    /// Deserialize back to the rabe type.
    pub fn to_rabe(&self) -> Result<KpAbeMasterKey, AbeError> {
        deserialize(&self.master_key_bytes)
    }
}

impl KpPolicyKey {
    /// Construct from a rabe secret key.
    pub fn from_rabe(sk: &KpAbeSecretKey) -> Result<Self, AbeError> {
        Ok(Self {
            key_bytes: serialize(sk)?,
        })
    }
    /// Deserialize back to the rabe type.
    pub fn to_rabe(&self) -> Result<KpAbeSecretKey, AbeError> {
        deserialize(&self.key_bytes)
    }
}

/// Generate a fresh LSW master key pair.
#[instrument(skip_all)]
pub fn lsw_setup() -> Result<(KpMasterParams, KpMasterSecret), AbeError> {
    let (pk, msk) = lsw::setup();
    Ok((
        KpMasterParams::from_rabe(&pk)?,
        KpMasterSecret::from_rabe(&msk)?,
    ))
}

/// Issue a policy key for a decryptor. In KP-ABE the **key** carries the policy:
/// the decryptor can read any ciphertext whose attribute set satisfies `policy`.
#[instrument(skip_all)]
pub fn lsw_keygen(
    mp: &KpMasterParams,
    ms: &KpMasterSecret,
    policy: &PolicyExpr,
) -> Result<KpPolicyKey, AbeError> {
    let pk = mp.to_rabe()?;
    let msk = ms.to_rabe()?;
    // lsw::keygen accepts the same HumanPolicy string form as bsw::encrypt.
    let policy_str = policy.to_rabe_bsw()?;
    let sk = lsw::keygen(&pk, &msk, &policy_str, PolicyLanguage::HumanPolicy)
        .map_err(|e| AbeError::SchemeError(e.to_string()))?;
    KpPolicyKey::from_rabe(&sk)
}

/// Encrypt `plaintext` tagged with `attributes`. In KP-ABE the **ciphertext**
/// carries the attributes; a decryptor reads it iff its key-policy is satisfied
/// by them. Returns bincode-serialized `KpAbeCiphertext`.
#[instrument(skip(plaintext, mp))]
pub fn lsw_encrypt(
    mp: &KpMasterParams,
    attributes: &[String],
    plaintext: &[u8],
) -> Result<Bytes, AbeError> {
    let pk = mp.to_rabe()?;
    let attr_refs: Vec<&str> = attributes.iter().map(String::as_str).collect();
    let ct: KpAbeCiphertext = lsw::encrypt(&pk, &attr_refs, plaintext)
        .map_err(|e| AbeError::SchemeError(e.to_string()))?;
    serialize(&ct)
}

/// Decrypt LSW ciphertext bytes using a policy key.
#[instrument(skip(pk, ct_bytes))]
pub fn lsw_decrypt(pk: &KpPolicyKey, ct_bytes: &Bytes) -> Result<Vec<u8>, AbeError> {
    let sk = pk.to_rabe()?;
    let ct: KpAbeCiphertext = deserialize(ct_bytes)?;
    lsw::decrypt(&sk, &ct).map_err(|e| {
        tracing::debug!(error = %e, "lsw_decrypt failed");
        AbeError::DecryptionFailed
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lsw_setup_encrypt_keygen_decrypt_round_trip() {
        let (mp, ms) = lsw_setup().unwrap();
        let plaintext = b"central-controller-governed content";
        // Ciphertext tagged with service attributes.
        let ct = lsw_encrypt(
            &mp,
            &["service:mavlink".to_string(), "perm:execute".to_string()],
            plaintext,
        )
        .unwrap();
        // A key whose policy is satisfied by those attributes decrypts.
        let policy = PolicyExpr::parse("service:mavlink OR service:camera").unwrap();
        let key = lsw_keygen(&mp, &ms, &policy).unwrap();
        assert_eq!(lsw_decrypt(&key, &ct).unwrap(), plaintext);
    }

    #[test]
    fn lsw_decrypt_fails_when_policy_unsatisfied() {
        let (mp, ms) = lsw_setup().unwrap();
        let ct = lsw_encrypt(&mp, &["service:mavlink".to_string()], b"secret").unwrap();
        // Key policy requires an attribute the ciphertext does not carry.
        let policy = PolicyExpr::parse("service:camera AND perm:admin").unwrap();
        let key = lsw_keygen(&mp, &ms, &policy).unwrap();
        assert!(matches!(
            lsw_decrypt(&key, &ct),
            Err(AbeError::DecryptionFailed)
        ));
    }
}
