//! Confidential reflexive parameters: an ephemeral-ECDH "sealed box" so the
//! parameters a consumer sends back over the reverse path (D2) are encrypted
//! and unreadable by on-path forwarders.
//!
//! The sealed-box primitive lives in [`ndn_sealed_box`] (shared with ndn-pipes);
//! this module is a thin wrapper that fixes the compute domain salt and keeps
//! the `Result<_, SealError>` API the compute service uses.
//!
//! Handshake: the node generates a [`NodeKeypair`], puts `public` on the reverse
//! Interest (so the consumer can derive the shared key), and later
//! [`NodeKeypair::open`]s the blob the consumer returns.
//!
//! **Authenticity is out of scope here.** An unauthenticated ECDH is open to an
//! active on-path attacker who rewrites the ephemeral keys (MITM). Pair this
//! with the signed-D2 authorization leg
//! ([`function_reflexive_authenticated`](crate::ComputeService::function_reflexive_authenticated))
//! so the consumer's blob (and its ephemeral key) is signed.

use ndn_sealed_box::{OVERHEAD, Recipient};

/// HKDF domain separation for compute's reflexive params (distinct from other
/// users of the shared sealed box, e.g. ndn-pipes).
const SALT: &[u8] = b"ndn-compute/reflexive-params/v1";

/// Why a seal/open operation failed.
#[derive(Debug, PartialEq, Eq)]
pub enum SealError {
    /// A cryptographic primitive failed (keygen, agreement, RNG).
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

/// The node's ephemeral X25519 keypair for one reflexive handshake. `public` is
/// sent on the reverse Interest; the private half is consumed by [`Self::open`].
pub struct NodeKeypair {
    /// The 32-byte X25519 public key to advertise on the reverse Interest.
    pub public: [u8; 32],
    recipient: Recipient,
}

impl NodeKeypair {
    /// Generate a fresh node keypair.
    pub fn generate() -> Result<Self, SealError> {
        let recipient = Recipient::generate().ok_or(SealError::Crypto)?;
        Ok(Self {
            public: recipient.public,
            recipient,
        })
    }

    /// Open a sealed blob produced by [`seal`] against this node's public key.
    pub fn open(self, blob: &[u8]) -> Result<Vec<u8>, SealError> {
        if blob.len() < OVERHEAD {
            return Err(SealError::Malformed);
        }
        self.recipient.open(SALT, blob).ok_or(SealError::Decrypt)
    }
}

/// Seal `plaintext` for the node whose X25519 public key is `node_public`.
/// Returns `consumer_pubkey(32) || nonce(12) || AES-256-GCM(plaintext)`.
pub fn seal(node_public: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
    ndn_sealed_box::seal(SALT, node_public, plaintext).ok_or(SealError::Crypto)
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
