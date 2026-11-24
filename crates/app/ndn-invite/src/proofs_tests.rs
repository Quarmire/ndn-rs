//! The secret and its proofs (`proofs.rs`): commitment, proof key, ask and
//! answer proofs, hint token, keyed fingerprint. The labels are wire: a test
//! recomputes each with the audited crates and the label spelled out.

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use ndn_foundation_types::Name;
use sha2::{Digest, Sha256};

use crate::proofs::{
    SECRET_LEN, ask_proof, ask_proves, commitment, hint_token, keyed_fingerprint,
    keyed_fingerprint_matches, proof_key,
};
use crate::short::SHORT_FINGERPRINT_LEN;
use crate::wire::{NONCE_LEN, OFFER_ID_LEN, offer_name};

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

fn offer() -> Name {
    offer_name(&n("/alice/laptop"), &[7; OFFER_ID_LEN])
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).unwrap();
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// The labels, and what each derivation is, spelled out once: a change to a
/// label or to the construction is a change of the wire, and fails here.
#[test]
fn the_derivations_are_the_documented_ones() {
    let secret = [0x42; SECRET_LEN];
    let anchor = [0x77; 32];
    let offer = offer();

    let mut h = Sha256::new();
    h.update(b"ndn-invite/intro/commit/1");
    h.update(secret);
    assert_eq!(commitment(&secret), <[u8; 32]>::from(h.finalize()));

    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, &secret)
        .expand_multi_info(&[b"ndn-invite/intro/proof/1", &offer.encode_to_tlv()], &mut key)
        .unwrap();
    assert_eq!(proof_key(&secret, &offer), key);

    let (asker, digest, nonce) = (n("/bob/phone/KEY/k1"), [5; 32], [6; NONCE_LEN]);
    assert_eq!(
        ask_proof(&key, &offer, &asker, &digest, &nonce),
        hmac(
            &key,
            &[
                b"ndn-invite/intro/ask/1",
                &offer.encode_to_tlv(),
                &asker.encode_to_tlv(),
                &digest,
                &nonce
            ]
        )
    );

    assert_eq!(
        hint_token(&secret)[..],
        hmac(&secret, &[b"ndn-invite/intro/hint/1"])[..16]
    );
    assert_eq!(
        keyed_fingerprint(&secret, &anchor)[..],
        hmac(&secret, &[b"ndn-invite/intro/fp/1", &anchor])[..SHORT_FINGERPRINT_LEN]
    );
}

/// The ask's proof binds the offer, the asker key, its digest and the nonce:
/// changing any one fails it, as does another secret.
#[test]
fn an_ask_proof_binds_offer_key_digest_and_nonce() {
    let secret = [0x11; SECRET_LEN];
    let key = proof_key(&secret, &offer());
    let (bob, digest, nonce) = (n("/bob/phone/KEY/k1"), [5; 32], [6; NONCE_LEN]);
    let p = ask_proof(&key, &offer(), &bob, &digest, &nonce);
    assert!(ask_proves(&key, &offer(), &bob, &digest, &nonce, &p));
    let other_offer = offer_name(&n("/alice/laptop"), &[8; OFFER_ID_LEN]);
    assert!(!ask_proves(&key, &other_offer, &bob, &digest, &nonce, &p));
    assert!(!ask_proves(
        &key,
        &offer(),
        &n("/carol/phone/KEY/k1"),
        &digest,
        &nonce,
        &p
    ));
    assert!(!ask_proves(&key, &offer(), &bob, &[6; 32], &nonce, &p));
    assert!(!ask_proves(
        &key,
        &offer(),
        &bob,
        &digest,
        &[7; NONCE_LEN],
        &p
    ));
    let guessed = proof_key(&[0x12; SECRET_LEN], &offer());
    assert!(!ask_proves(&guessed, &offer(), &bob, &digest, &nonce, &p));
    assert_ne!(commitment(&secret), commitment(&[0x12; SECRET_LEN]));
}

/// The proof key depends on the offer's name: the same secret under another
/// offer opens nothing of the first.
#[test]
fn the_proof_key_is_bound_to_the_offer_name() {
    let secret = [0x31; SECRET_LEN];
    let other = offer_name(&n("/alice/laptop"), &[9; OFFER_ID_LEN]);
    assert_ne!(proof_key(&secret, &offer()), proof_key(&secret, &other));
}

/// The keyed fingerprint a named namespace's short code carries: ten octets
/// that depend on the code's secret and on the whole anchor fingerprint, and
/// are not the anchor's own octets; a verifier compares it in constant time and
/// refuses a tag of another length.
#[test]
fn the_keyed_fingerprint_depends_on_the_secret_and_the_whole_anchor() {
    let secret: [u8; SECRET_LEN] = core::array::from_fn(|i| (i * 17 + 3) as u8);
    let anchor: [u8; 32] = core::array::from_fn(|i| (i * 7 + 1) as u8);
    let tag = keyed_fingerprint(&secret, &anchor);
    assert_eq!(tag.len(), SHORT_FINGERPRINT_LEN);
    assert_eq!(tag, keyed_fingerprint(&secret, &anchor), "deterministic");
    assert_ne!(tag[..], anchor[..SHORT_FINGERPRINT_LEN], "not the plain truncation");
    let mut other_secret = secret;
    other_secret[15] ^= 1;
    assert_ne!(tag, keyed_fingerprint(&other_secret, &anchor));
    // An anchor that differs only past the first ten octets gives another tag:
    // the whole fingerprint is bound, not a prefix of it.
    let mut other_anchor = anchor;
    other_anchor[31] ^= 1;
    assert_ne!(tag, keyed_fingerprint(&secret, &other_anchor));

    assert!(keyed_fingerprint_matches(&secret, &anchor, &tag));
    assert!(!keyed_fingerprint_matches(&other_secret, &anchor, &tag));
    assert!(!keyed_fingerprint_matches(&secret, &other_anchor, &tag));
    assert!(
        !keyed_fingerprint_matches(&secret, &anchor, &anchor[..SHORT_FINGERPRINT_LEN]),
        "the plain truncation of the anchor is no tag"
    );
    assert!(!keyed_fingerprint_matches(&secret, &anchor, &tag[..9]), "short");
    let mut long = tag.to_vec();
    long.push(0);
    assert!(!keyed_fingerprint_matches(&secret, &anchor, &long), "long");
    assert!(!keyed_fingerprint_matches(&secret, &anchor, &[]), "empty");
}
