//! The secret and its proofs (spec §19.1, §19.7): the commitment an offer carries
//! to its secret, the proof key, an ask's and an answer's HMAC, the hint token and
//! the keyed fingerprint of a short code. Audited crates only (`sha2`, `hkdf`,
//! `hmac`, `subtle` through `verify`); each derivation is opened by a label that
//! is part of the wire.

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use ndn_foundation_types::Name;
use sha2::{Digest, Sha256};

use crate::short::SHORT_FINGERPRINT_LEN;
use crate::wire::{AnswerBody, HINT_TOKEN_LEN, NONCE_LEN};

/// Octets of an offer's secret ([`ndn_trust_envelope::INTRO_SECRET_LEN`]).
pub const SECRET_LEN: usize = ndn_trust_envelope::INTRO_SECRET_LEN;

/// Domain labels of the exchange's derivations.
const COMMIT: &[u8] = b"ndn-invite/intro/commit/1";
const PROOF_KEY: &[u8] = b"ndn-invite/intro/proof/1";
const ASK_PROOF: &[u8] = b"ndn-invite/intro/ask/1";
const ANSWER_PROOF: &[u8] = b"ndn-invite/intro/answer/1";
/// The label a hint token is derived under.
const HINT_LABEL: &[u8] = b"ndn-invite/intro/hint/1";
/// The label of a short code's keyed fingerprint.
const FINGERPRINT_LABEL: &[u8] = b"ndn-invite/intro/fp/1";

type HmacSha256 = Hmac<Sha256>;

/// The commitment an offer carries to its secret: SHA-256 over the label
/// `ndn-invite/intro/commit/1` and the secret.
pub fn commitment(secret: &[u8; SECRET_LEN]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(COMMIT);
    h.update(secret);
    h.finalize().into()
}

/// The offer's proof key: HKDF-SHA256 with the secret as input keying material,
/// no salt, and as info the label `ndn-invite/intro/proof/1` and the offer's Name
/// TLV.
pub fn proof_key(secret: &[u8; SECRET_LEN], offer: &Name) -> [u8; 32] {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, secret)
        .expand_multi_info(&[PROOF_KEY, &offer.encode_to_tlv()], &mut key)
        .expect("32 octets is a valid HKDF-SHA256 output length");
    key
}

fn mac(key: &[u8], label: &[u8], parts: &[&[u8]]) -> HmacSha256 {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC accepts a key of any length");
    m.update(label);
    for p in parts {
        m.update(p);
    }
    m
}

/// An ask's proof: HMAC-SHA256 under the proof key over the label
/// `ndn-invite/intro/ask/1`, the offer's and the asker key's Name TLVs, the key's
/// public key digest and the ask's nonce.
pub fn ask_proof(
    key: &[u8; 32],
    offer: &Name,
    asker: &Name,
    digest: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
) -> [u8; 32] {
    let tlvs = (offer.encode_to_tlv(), asker.encode_to_tlv());
    mac(key, ASK_PROOF, &[&tlvs.0, &tlvs.1, digest, nonce])
        .finalize()
        .into_bytes()
        .into()
}

/// Whether `proof` is the ask's proof ([`ask_proof`]), compared in constant time.
pub fn ask_proves(
    key: &[u8; 32],
    offer: &Name,
    asker: &Name,
    digest: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    proof: &[u8; 32],
) -> bool {
    let tlvs = (offer.encode_to_tlv(), asker.encode_to_tlv());
    mac(key, ASK_PROOF, &[&tlvs.0, &tlvs.1, digest, nonce])
        .verify_slice(proof)
        .is_ok()
}

/// An answer's proof: HMAC-SHA256 under the proof key over the label
/// `ndn-invite/intro/answer/1` and [`AnswerBody::proven`].
pub fn answer_proof(key: &[u8; 32], answer: &AnswerBody) -> [u8; 32] {
    mac(key, ANSWER_PROOF, &[&answer.proven()])
        .finalize()
        .into_bytes()
        .into()
}

/// Whether `answer` carries its proof under `key`, compared in constant time.
pub fn answer_proves(key: &[u8; 32], answer: &AnswerBody) -> bool {
    answer.proof.is_some_and(|p| {
        mac(key, ANSWER_PROOF, &[&answer.proven()])
            .verify_slice(&p)
            .is_ok()
    })
}

/// The token a short code's hint record is named by: the first 16 octets of
/// `HMAC-SHA256(key = secret, "ndn-invite/intro/hint/1")`. Unguessable without
/// the secret (128 bits), and reveals nothing of it: the secret is never in a
/// name.
pub fn hint_token(secret: &[u8; SECRET_LEN]) -> [u8; HINT_TOKEN_LEN] {
    let mut m = HmacSha256::new_from_slice(secret).expect("HMAC accepts a key of any length");
    m.update(HINT_LABEL);
    let tag = m.finalize().into_bytes();
    let mut token = [0u8; HINT_TOKEN_LEN];
    token.copy_from_slice(&tag[..HINT_TOKEN_LEN]);
    token
}

/// The HMAC a short code's fingerprint is the first octets of.
fn fingerprint_mac(secret: &[u8; SECRET_LEN], anchor: &[u8; 32]) -> HmacSha256 {
    let mut m = HmacSha256::new_from_slice(secret).expect("HMAC accepts a key of any length");
    m.update(FINGERPRINT_LABEL);
    m.update(anchor);
    m
}

/// The fingerprint a named namespace's short code carries: the first
/// [`SHORT_FINGERPRINT_LEN`] octets of `HMAC-SHA256(key = secret,
/// "ndn-invite/intro/fp/1" ‖ anchor)`, `anchor` being the whole 32-octet
/// fingerprint of the namespace's anchor. Keyed by the code's own secret, so a
/// search for an anchor that collides with it can begin only once that code is
/// known, and serves that one code (spec §19.7); not the anchor's own octets,
/// which are public and the same for every code of the namespace.
pub fn keyed_fingerprint(
    secret: &[u8; SECRET_LEN],
    anchor: &[u8; 32],
) -> [u8; SHORT_FINGERPRINT_LEN] {
    let tag = fingerprint_mac(secret, anchor).finalize().into_bytes();
    let mut out = [0u8; SHORT_FINGERPRINT_LEN];
    out.copy_from_slice(&tag[..SHORT_FINGERPRINT_LEN]);
    out
}

/// Whether `tag` is the keyed fingerprint ([`keyed_fingerprint`]) of `anchor`
/// under `secret`, compared in constant time; a tag of any length but
/// [`SHORT_FINGERPRINT_LEN`] is not.
pub fn keyed_fingerprint_matches(secret: &[u8; SECRET_LEN], anchor: &[u8; 32], tag: &[u8]) -> bool {
    tag.len() == SHORT_FINGERPRINT_LEN
        && fingerprint_mac(secret, anchor)
            .verify_truncated_left(tag)
            .is_ok()
}
