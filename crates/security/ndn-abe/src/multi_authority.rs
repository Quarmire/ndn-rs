//! Lewko-Waters AW11 multi-authority ABE wrappers.
//!
//! AW11 key roles:
//!   `Aw11GlobalKey`  — one shared generator, known to all parties.
//!   `Aw11PublicKey`  — per-authority public params; needed at encrypt time.
//!   `Aw11MasterKey`  — per-authority master secret; used to issue user keys.
//!   `Aw11SecretKey`  — per-user key; accumulates attributes across authorities
//!                       via `add_to_attribute`.
//!
//! Each KGC that participates in a multi-authority policy:
//!
//! 1. Calls `aw11_authgen(global_bytes, attrs)` once to create its key pair.
//! 2. Calls `aw11_keygen(...)` / `aw11_add_attr(...)` to issue user keys.
//!
//! All encryptions require the shared global key + every relevant authority's
//! public key.

use bytes::Bytes;
use rabe::schemes::aw11::{self, Aw11GlobalKey, Aw11MasterKey, Aw11PublicKey, Aw11SecretKey};
use rabe::utils::policy::pest::PolicyLanguage;

use crate::error::AbeError;

/// Serialized `Aw11GlobalKey` — shared across all authorities in a deployment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Aw11GlobalKeyBytes(pub Bytes);

/// Serialized `Aw11PublicKey` for one authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Aw11PubKeyBytes(pub Bytes);

/// Serialized `Aw11MasterKey` for one authority (never leaves the KGC).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Aw11MasterKeyBytes(pub Bytes);

/// Serialized `Aw11SecretKey` for one user, potentially with attributes
/// accumulated from multiple authorities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Aw11UserKey(pub Bytes);

fn serialize_gk(gk: &Aw11GlobalKey) -> Result<Bytes, AbeError> {
    bincode::serialize(gk)
        .map(Bytes::from)
        .map_err(|e| AbeError::Serialization(e.to_string()))
}

fn deserialize_gk(b: &[u8]) -> Result<Aw11GlobalKey, AbeError> {
    bincode::deserialize(b).map_err(|e| AbeError::Serialization(e.to_string()))
}

fn serialize_pk(pk: &Aw11PublicKey) -> Result<Bytes, AbeError> {
    bincode::serialize(pk)
        .map(Bytes::from)
        .map_err(|e| AbeError::Serialization(e.to_string()))
}

fn deserialize_pk(b: &[u8]) -> Result<Aw11PublicKey, AbeError> {
    bincode::deserialize(b).map_err(|e| AbeError::Serialization(e.to_string()))
}

fn serialize_mk(mk: &Aw11MasterKey) -> Result<Bytes, AbeError> {
    bincode::serialize(mk)
        .map(Bytes::from)
        .map_err(|e| AbeError::Serialization(e.to_string()))
}

fn deserialize_mk(b: &[u8]) -> Result<Aw11MasterKey, AbeError> {
    bincode::deserialize(b).map_err(|e| AbeError::Serialization(e.to_string()))
}

fn serialize_sk(sk: &Aw11SecretKey) -> Result<Bytes, AbeError> {
    bincode::serialize(sk)
        .map(Bytes::from)
        .map_err(|e| AbeError::Serialization(e.to_string()))
}

fn deserialize_sk(b: &[u8]) -> Result<Aw11SecretKey, AbeError> {
    bincode::deserialize(b).map_err(|e| AbeError::Serialization(e.to_string()))
}

fn deserialize_ct(b: &[u8]) -> Result<rabe::schemes::aw11::Aw11Ciphertext, AbeError> {
    bincode::deserialize(b).map_err(|e| AbeError::Serialization(e.to_string()))
}

/// Generate the shared AW11 global key.
/// Every authority and consumer in a deployment uses the same global key.
pub fn aw11_global_setup() -> Result<Aw11GlobalKeyBytes, AbeError> {
    let gk = aw11::setup();
    Ok(Aw11GlobalKeyBytes(serialize_gk(&gk)?))
}

/// Create a new authority key pair for the given set of attribute strings.
///
/// `attrs` are the attribute names this authority owns, e.g. `["ROLE:DOCTOR"]`.
/// AW11 uppercases attribute names internally; pass them in uppercase to be explicit.
///
/// Returns `(pub_key_bytes, master_key_bytes)`.
pub fn aw11_authgen(
    global: &Aw11GlobalKeyBytes,
    attrs: &[&str],
) -> Result<(Aw11PubKeyBytes, Aw11MasterKeyBytes), AbeError> {
    let gk = deserialize_gk(&global.0)?;
    let (pk, mk) = aw11::authgen(&gk, attrs).ok_or_else(|| {
        AbeError::SchemeError("aw11::authgen returned None (empty attrs?)".into())
    })?;
    Ok((
        Aw11PubKeyBytes(serialize_pk(&pk)?),
        Aw11MasterKeyBytes(serialize_mk(&mk)?),
    ))
}

/// Generate a user secret key from one authority's master key.
///
/// `gid` is the user's global identifier (e.g. their NDN Name as a string).
/// `attrs` is the subset of this authority's attributes to grant (uppercase).
pub fn aw11_keygen(
    global: &Aw11GlobalKeyBytes,
    master: &Aw11MasterKeyBytes,
    gid: &str,
    attrs: &[&str],
) -> Result<Aw11UserKey, AbeError> {
    let gk = deserialize_gk(&global.0)?;
    let mk = deserialize_mk(&master.0)?;
    let sk =
        aw11::keygen(&gk, &mk, gid, attrs).map_err(|e| AbeError::SchemeError(e.to_string()))?;
    Ok(Aw11UserKey(serialize_sk(&sk)?))
}

/// Accumulate one more attribute from a different authority into an existing user key.
///
/// Call this for each additional authority that holds attributes the user needs.
/// `attr` must be uppercase and owned by the authority whose master key is passed.
pub fn aw11_add_attr(
    global: &Aw11GlobalKeyBytes,
    master: &Aw11MasterKeyBytes,
    attr: &str,
    user_key: &Aw11UserKey,
) -> Result<Aw11UserKey, AbeError> {
    let gk = deserialize_gk(&global.0)?;
    let mk = deserialize_mk(&master.0)?;
    let mut sk = deserialize_sk(&user_key.0)?;
    aw11::add_to_attribute(&gk, &mk, attr, &mut sk)
        .map_err(|e| AbeError::SchemeError(e.to_string()))?;
    Ok(Aw11UserKey(serialize_sk(&sk)?))
}

/// Encrypt `plaintext` under `policy_str` (HumanPolicy, uppercase attributes).
///
/// `pub_keys` must include the public key of every authority whose attributes
/// appear in the policy.
pub fn aw11_encrypt(
    global: &Aw11GlobalKeyBytes,
    pub_keys: &[&Aw11PubKeyBytes],
    policy_str: &str,
    plaintext: &[u8],
) -> Result<Bytes, AbeError> {
    let gk = deserialize_gk(&global.0)?;
    let pks: Vec<Aw11PublicKey> = pub_keys
        .iter()
        .map(|b| deserialize_pk(&b.0))
        .collect::<Result<_, _>>()?;
    let pk_refs: Vec<&Aw11PublicKey> = pks.iter().collect();

    let ct = aw11::encrypt(
        &gk,
        &pk_refs,
        policy_str,
        PolicyLanguage::HumanPolicy,
        plaintext,
    )
    .map_err(|e| AbeError::SchemeError(e.to_string()))?;

    bincode::serialize(&ct)
        .map(Bytes::from)
        .map_err(|e| AbeError::Serialization(e.to_string()))
}

/// Decrypt an AW11 ciphertext produced by [`aw11_encrypt`].
///
/// `user_key` must contain attributes sufficient to satisfy the ciphertext policy.
pub fn aw11_decrypt(
    global: &Aw11GlobalKeyBytes,
    user_key: &Aw11UserKey,
    ct_bytes: &[u8],
) -> Result<Vec<u8>, AbeError> {
    let gk = deserialize_gk(&global.0)?;
    let sk = deserialize_sk(&user_key.0)?;
    let ct = deserialize_ct(ct_bytes)?;
    aw11::decrypt(&gk, &sk, &ct).map_err(|_| AbeError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_two_authorities() -> (
        Aw11GlobalKeyBytes,
        Aw11PubKeyBytes,
        Aw11MasterKeyBytes,
        Aw11PubKeyBytes,
        Aw11MasterKeyBytes,
    ) {
        let global = aw11_global_setup().unwrap();
        let (pk1, mk1) = aw11_authgen(&global, &["ROLE:DOCTOR", "ROLE:NURSE"]).unwrap();
        let (pk2, mk2) = aw11_authgen(&global, &["DEPT:CARDIOLOGY", "DEPT:SURGERY"]).unwrap();
        (global, pk1, mk1, pk2, mk2)
    }

    #[test]
    fn aw11_single_authority_round_trip() {
        let global = aw11_global_setup().unwrap();
        let (pk, mk) = aw11_authgen(&global, &["ROLE:DOCTOR"]).unwrap();
        let user_key = aw11_keygen(&global, &mk, "alice", &["ROLE:DOCTOR"]).unwrap();

        let policy = "\"ROLE:DOCTOR\"";
        let ct = aw11_encrypt(&global, &[&pk], policy, b"secret").unwrap();
        let pt = aw11_decrypt(&global, &user_key, &ct).unwrap();
        assert_eq!(pt, b"secret");
    }

    #[test]
    fn aw11_multi_authority_and_policy_round_trip() {
        let (global, pk1, mk1, pk2, mk2) = setup_two_authorities();

        // Bob needs role:doctor from auth1 AND dept:cardiology from auth2
        let user_key = aw11_keygen(&global, &mk1, "bob", &["ROLE:DOCTOR"]).unwrap();
        let user_key = aw11_add_attr(&global, &mk2, "DEPT:CARDIOLOGY", &user_key).unwrap();

        let policy = "\"ROLE:DOCTOR\" and \"DEPT:CARDIOLOGY\"";
        let ct = aw11_encrypt(&global, &[&pk1, &pk2], policy, b"top secret").unwrap();
        let pt = aw11_decrypt(&global, &user_key, &ct).unwrap();
        assert_eq!(pt, b"top secret");
    }

    #[test]
    fn aw11_multi_authority_missing_one_grant_fails() {
        let (global, pk1, mk1, pk2, _mk2) = setup_two_authorities();

        // Eve only has role:doctor, not dept:cardiology
        let user_key = aw11_keygen(&global, &mk1, "eve", &["ROLE:DOCTOR"]).unwrap();

        let policy = "\"ROLE:DOCTOR\" and \"DEPT:CARDIOLOGY\"";
        let ct = aw11_encrypt(&global, &[&pk1, &pk2], policy, b"top secret").unwrap();
        let result = aw11_decrypt(&global, &user_key, &ct);
        assert!(matches!(result, Err(AbeError::DecryptionFailed)));
    }

    #[test]
    fn aw11_tampered_ciphertext_fails() {
        let global = aw11_global_setup().unwrap();
        let (pk, mk) = aw11_authgen(&global, &["ROLE:DOCTOR"]).unwrap();
        let user_key = aw11_keygen(&global, &mk, "alice", &["ROLE:DOCTOR"]).unwrap();

        let policy = "\"ROLE:DOCTOR\"";
        let mut ct = aw11_encrypt(&global, &[&pk], policy, b"secret").unwrap();
        // Flip a byte near the end
        let last = ct.len() - 1;
        let mut ct_vec = ct.to_vec();
        ct_vec[last] ^= 0xFF;
        ct = Bytes::from(ct_vec);

        let result = aw11_decrypt(&global, &user_key, &ct);
        assert!(result.is_err(), "tampered ciphertext should fail");
    }
}
