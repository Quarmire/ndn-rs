//! An ephemeral-X25519 **sealed box**: encrypt a secret to a recipient's public
//! key so only the holder of the matching private key can open it.
//!
//! Scheme (forward-secret, per call): X25519 ECDH between a fresh sender
//! ephemeral key and the recipient's ephemeral key → HKDF-SHA256 (domain-
//! separated by `salt`) → a 256-bit AES-GCM key. The blob is
//! `sender_pub(32) ‖ nonce(12) ‖ AES-256-GCM(plaintext)`.
//!
//! Handshake: the recipient generates a [`Recipient`], advertises its `public`
//! key, the sender [`seal`]s to it, and the recipient [`open`](Recipient::open)s
//! the blob — once (the private key is single-use).
//!
//! **Authenticity is out of scope.** Bare ECDH is open to an active on-path MITM
//! that rewrites the ephemeral keys; pair this with a signature over the blob (or
//! over the recipient's advertised key) to bind it to an identity. The `salt`
//! gives domain separation so a blob sealed in one protocol context cannot be
//! opened in another.

use ring::aead;
use ring::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey};
use ring::hkdf;
use ring::rand::{SecureRandom, SystemRandom};

/// X25519 public-key length.
pub const PUB_LEN: usize = 32;
/// AES-GCM nonce length.
pub const NONCE_LEN: usize = 12;
/// AES-GCM tag length.
pub const TAG_LEN: usize = 16;
/// Smallest possible sealed blob (empty plaintext): pubkey + nonce + tag.
pub const OVERHEAD: usize = PUB_LEN + NONCE_LEN + TAG_LEN;

const HKDF_INFO: &[u8] = b"aes-256-gcm-key";

struct Aes256KeyLen;
impl hkdf::KeyType for Aes256KeyLen {
    fn len(&self) -> usize {
        32
    }
}

fn derive_key(salt: &[u8], shared: &[u8]) -> [u8; 32] {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(shared);
    let okm = prk
        .expand(&[HKDF_INFO], Aes256KeyLen)
        .expect("hkdf expand for 32 bytes is infallible");
    let mut out = [0u8; 32];
    okm.fill(&mut out)
        .expect("hkdf fill for 32 bytes is infallible");
    out
}

/// A recipient's ephemeral X25519 keypair for one sealed-box exchange. `public`
/// is advertised to the sender; the private half is consumed by [`Self::open`].
pub struct Recipient {
    /// The 32-byte X25519 public key to advertise.
    pub public: [u8; PUB_LEN],
    private: EphemeralPrivateKey,
}

impl Recipient {
    /// Generate a fresh recipient keypair. `None` on RNG/keygen failure.
    pub fn generate() -> Option<Self> {
        let rng = SystemRandom::new();
        let private = EphemeralPrivateKey::generate(&agreement::X25519, &rng).ok()?;
        let pubk = private.compute_public_key().ok()?;
        let mut public = [0u8; PUB_LEN];
        public.copy_from_slice(pubk.as_ref());
        Some(Self { public, private })
    }

    /// Open a blob produced by [`seal`] for this recipient under `salt`. `None`
    /// if the blob is malformed/too short or fails authenticated decryption.
    pub fn open(self, salt: &[u8], blob: &[u8]) -> Option<Vec<u8>> {
        if blob.len() < OVERHEAD {
            return None;
        }
        let sender_pub = &blob[..PUB_LEN];
        let nonce: [u8; NONCE_LEN] = blob[PUB_LEN..PUB_LEN + NONCE_LEN].try_into().ok()?;
        let ciphertext = &blob[PUB_LEN + NONCE_LEN..];

        let peer = UnparsedPublicKey::new(&agreement::X25519, sender_pub);
        let key = agreement::agree_ephemeral(self.private, &peer, |s| derive_key(salt, s)).ok()?;

        let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, &key).ok()?;
        let opening = aead::LessSafeKey::new(unbound);
        let mut in_out = ciphertext.to_vec();
        let plain = opening
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::empty(),
                &mut in_out,
            )
            .ok()?;
        Some(plain.to_vec())
    }
}

/// Seal `plaintext` to `recipient_public` (a 32-byte X25519 key) under `salt`.
/// Returns `sender_pub(32) ‖ nonce(12) ‖ AES-256-GCM(plaintext)`, or `None` on
/// crypto failure (e.g. a malformed recipient key).
pub fn seal(salt: &[u8], recipient_public: &[u8], plaintext: &[u8]) -> Option<Vec<u8>> {
    let rng = SystemRandom::new();
    let eph = EphemeralPrivateKey::generate(&agreement::X25519, &rng).ok()?;
    let sender_pub = eph.compute_public_key().ok()?;

    let peer = UnparsedPublicKey::new(&agreement::X25519, recipient_public);
    let key = agreement::agree_ephemeral(eph, &peer, |s| derive_key(salt, s)).ok()?;

    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut nonce).ok()?;

    let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, &key).ok()?;
    let sealing = aead::LessSafeKey::new(unbound);
    let mut in_out = plaintext.to_vec();
    sealing
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::empty(),
            &mut in_out,
        )
        .ok()?;

    let mut blob = Vec::with_capacity(PUB_LEN + NONCE_LEN + in_out.len());
    blob.extend_from_slice(sender_pub.as_ref());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&in_out);
    Some(blob)
}

/// `n` cryptographically-random bytes (e.g. a minted id or key).
pub fn random_bytes(n: usize) -> Option<Vec<u8>> {
    let rng = SystemRandom::new();
    let mut v = vec![0u8; n];
    rng.fill(&mut v).ok()?;
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: &[u8] = b"ndn-sealed-box/test/v1";

    #[test]
    fn round_trips_and_blob_is_opaque() {
        let r = Recipient::generate().unwrap();
        let pubk = r.public;
        let blob = seal(SALT, &pubk, b"top secret").unwrap();
        assert!(!blob.windows(6).any(|w| w == b"secret"), "blob is ciphertext");
        assert_eq!(r.open(SALT, &blob).unwrap(), b"top secret");
    }

    #[test]
    fn a_different_recipient_cannot_open() {
        let r1 = Recipient::generate().unwrap();
        let p1 = r1.public;
        let r2 = Recipient::generate().unwrap();
        let blob = seal(SALT, &p1, b"for r1").unwrap();
        assert!(r2.open(SALT, &blob).is_none());
    }

    #[test]
    fn a_different_salt_cannot_open() {
        let r = Recipient::generate().unwrap();
        let pubk = r.public;
        let blob = seal(SALT, &pubk, b"domain-bound").unwrap();
        // Domain separation: the same keys but a different salt → different key.
        assert!(r.open(b"other-domain", &blob).is_none());
    }

    #[test]
    fn tampered_or_truncated_is_rejected() {
        let r = Recipient::generate().unwrap();
        let pubk = r.public;
        let mut blob = seal(SALT, &pubk, b"x").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(r.open(SALT, &blob).is_none());
        assert!(Recipient::generate().unwrap().open(SALT, &[0u8; 8]).is_none());
    }
}
