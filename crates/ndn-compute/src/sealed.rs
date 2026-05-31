//! Confidential reflexive parameters: an ephemeral-ECDH "sealed box" so the
//! parameters a consumer sends back over the reverse path (D2) are encrypted
//! and unreadable by on-path forwarders.
//!
//! Scheme (per request, forward-secret): X25519 ECDH between the node's
//! ephemeral key and a fresh consumer ephemeral key → HKDF-SHA256 → a 256-bit
//! AES-GCM key. The sealed blob is `consumer_pubkey(32) || nonce(12) ||
//! AES-256-GCM(params)`.
//!
//! Handshake: the node generates a [`NodeKeypair`], puts `public` on the
//! reverse Interest (so the consumer can derive the shared key), and later
//! [`NodeKeypair::open`]s the blob the consumer returns.
//!
//! **Authenticity is out of scope here.** An unauthenticated ECDH is open to an
//! active on-path attacker who rewrites the ephemeral keys (MITM). Pair this
//! with the signed-D2 authorization leg
//! ([`function_reflexive_authenticated`](crate::ComputeService::function_reflexive_authenticated))
//! so the consumer's blob (and its ephemeral key) is signed — that binds the
//! key exchange to an authenticated identity.

use ring::aead;
use ring::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey};
use ring::hkdf;
use ring::rand::{SecureRandom, SystemRandom};

const HKDF_SALT: &[u8] = b"ndn-compute/reflexive-params/v1";
const HKDF_INFO: &[u8] = b"aes-256-gcm-key";
const PUB_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// Why a seal/open operation failed.
#[derive(Debug, PartialEq, Eq)]
pub enum SealError {
    /// A `ring` cryptographic primitive failed (keygen, agreement, RNG).
    Crypto,
    /// The sealed blob is too short to contain pubkey + nonce + tag.
    Malformed,
    /// Authenticated decryption failed (wrong key or tampered ciphertext).
    Decrypt,
}

impl core::fmt::Display for SealError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SealError::Crypto => write!(f, "sealed-params crypto failure"),
            SealError::Malformed => write!(f, "sealed blob is malformed"),
            SealError::Decrypt => write!(f, "sealed blob failed authenticated decryption"),
        }
    }
}

impl std::error::Error for SealError {}

struct Aes256KeyLen;
impl hkdf::KeyType for Aes256KeyLen {
    fn len(&self) -> usize {
        32
    }
}

fn derive_key(shared: &[u8]) -> [u8; 32] {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, HKDF_SALT).extract(shared);
    let okm = prk
        .expand(&[HKDF_INFO], Aes256KeyLen)
        .expect("hkdf expand for 32 bytes is infallible");
    let mut out = [0u8; 32];
    okm.fill(&mut out)
        .expect("hkdf fill for 32 bytes is infallible");
    out
}

/// The node's ephemeral X25519 keypair for one reflexive handshake. `public`
/// is sent on the reverse Interest; the private half is consumed by
/// [`Self::open`].
pub struct NodeKeypair {
    /// The 32-byte X25519 public key to advertise on the reverse Interest.
    pub public: [u8; PUB_LEN],
    private: EphemeralPrivateKey,
}

impl NodeKeypair {
    /// Generate a fresh node keypair.
    pub fn generate() -> Result<Self, SealError> {
        let rng = SystemRandom::new();
        let private = EphemeralPrivateKey::generate(&agreement::X25519, &rng)
            .map_err(|_| SealError::Crypto)?;
        let pubk = private
            .compute_public_key()
            .map_err(|_| SealError::Crypto)?;
        let mut public = [0u8; PUB_LEN];
        public.copy_from_slice(pubk.as_ref());
        Ok(Self { public, private })
    }

    /// Open a sealed blob produced by [`seal`] against this node's public key.
    pub fn open(self, blob: &[u8]) -> Result<Vec<u8>, SealError> {
        if blob.len() < PUB_LEN + NONCE_LEN + TAG_LEN {
            return Err(SealError::Malformed);
        }
        let consumer_pub = &blob[..PUB_LEN];
        let nonce: [u8; NONCE_LEN] = blob[PUB_LEN..PUB_LEN + NONCE_LEN]
            .try_into()
            .map_err(|_| SealError::Malformed)?;
        let ciphertext = &blob[PUB_LEN + NONCE_LEN..];

        let peer = UnparsedPublicKey::new(&agreement::X25519, consumer_pub);
        let key = agreement::agree_ephemeral(self.private, &peer, derive_key)
            .map_err(|_| SealError::Crypto)?;

        let unbound =
            aead::UnboundKey::new(&aead::AES_256_GCM, &key).map_err(|_| SealError::Crypto)?;
        let opening = aead::LessSafeKey::new(unbound);
        let mut in_out = ciphertext.to_vec();
        let plain = opening
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::empty(),
                &mut in_out,
            )
            .map_err(|_| SealError::Decrypt)?;
        Ok(plain.to_vec())
    }
}

/// Seal `plaintext` for the node whose X25519 public key is `node_public`.
/// Returns `consumer_pubkey(32) || nonce(12) || AES-256-GCM(plaintext)`.
pub fn seal(node_public: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
    let rng = SystemRandom::new();
    let eph =
        EphemeralPrivateKey::generate(&agreement::X25519, &rng).map_err(|_| SealError::Crypto)?;
    let consumer_pub = eph.compute_public_key().map_err(|_| SealError::Crypto)?;

    let peer = UnparsedPublicKey::new(&agreement::X25519, node_public);
    let key = agreement::agree_ephemeral(eph, &peer, derive_key).map_err(|_| SealError::Crypto)?;

    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut nonce).map_err(|_| SealError::Crypto)?;

    let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, &key).map_err(|_| SealError::Crypto)?;
    let sealing = aead::LessSafeKey::new(unbound);
    let mut in_out = plaintext.to_vec();
    sealing
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::empty(),
            &mut in_out,
        )
        .map_err(|_| SealError::Crypto)?;

    let mut blob = Vec::with_capacity(PUB_LEN + NONCE_LEN + in_out.len());
    blob.extend_from_slice(consumer_pub.as_ref());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&in_out);
    Ok(blob)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip() {
        let node = NodeKeypair::generate().unwrap();
        let node_pub = node.public;
        let blob = seal(&node_pub, b"top secret params").unwrap();
        // The blob is ciphertext, not the plaintext.
        assert!(!blob.windows(6).any(|w| w == b"secret"));
        assert_eq!(node.open(&blob).unwrap(), b"top secret params");
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let node = NodeKeypair::generate().unwrap();
        let node_pub = node.public;
        let mut blob = seal(&node_pub, b"params").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert_eq!(node.open(&blob), Err(SealError::Decrypt));
    }

    #[test]
    fn wrong_node_key_cannot_open() {
        let node1 = NodeKeypair::generate().unwrap();
        let node1_pub = node1.public;
        let node2 = NodeKeypair::generate().unwrap();
        let blob = seal(&node1_pub, b"params").unwrap();
        // Sealed for node1; node2 derives a different shared secret.
        assert_eq!(node2.open(&blob), Err(SealError::Decrypt));
    }

    #[test]
    fn truncated_blob_is_malformed() {
        let node = NodeKeypair::generate().unwrap();
        assert_eq!(node.open(&[0u8; 8]), Err(SealError::Malformed));
    }
}
