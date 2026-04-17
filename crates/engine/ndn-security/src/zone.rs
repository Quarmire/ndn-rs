//! Self-certifying namespace primitives for the Named Data Architecture (NDA).
//!
//! A **zone** is a namespace whose root name is derived directly from its
//! signing key — no CA required. Anyone who holds the private key owns the
//! zone; anyone who knows the zone root name can verify zone-signed content.
//!
//! ## Zone root encoding
//!
//! ```text
//! zone_root = Name[ BLAKE3_DIGEST(blake3(public_key_bytes)) ]
//! ```
//!
//! The single name component has TLV type 0x03 (`BLAKE3_DIGEST`) and a
//! 32-byte value that is the BLAKE3 hash of the raw Ed25519 verifying key.
//!
//! **Experimental / NDA extension** — type 0x03 is not yet in the NDN spec.

use std::sync::Arc;

use ndn_packet::Name;

use crate::{Ed25519Signer, Signer};

/// A zone signing key: an Ed25519 key bound to its self-certifying zone root name.
///
/// The zone root is computed deterministically from the public key, so this
/// struct owns both the signing capability and the canonical zone namespace.
pub struct ZoneKey {
    signer: Ed25519Signer,
    zone_root: Name,
    pub_key_bytes: [u8; 32],
}

impl ZoneKey {
    /// Derive a `ZoneKey` from a raw 32-byte Ed25519 seed.
    ///
    /// The zone root name is computed as `blake3(verifying_key_bytes)`.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        use ed25519_dalek::SigningKey;
        let sk = SigningKey::from_bytes(seed);
        let pub_key_bytes = sk.verifying_key().to_bytes();
        let zone_root = zone_root_from_pubkey(&pub_key_bytes);
        let signer = Ed25519Signer::from_seed(seed, zone_root.clone());
        Self {
            signer,
            zone_root,
            pub_key_bytes,
        }
    }

    /// Derive a `ZoneKey` from raw Ed25519 signing-key bytes (32-byte seed).
    pub fn from_signing_key_bytes(bytes: &[u8; 32]) -> Self {
        Self::from_seed(bytes)
    }

    /// The self-certifying zone root name derived from this key.
    ///
    /// This is a single-component name containing the BLAKE3 digest of the
    /// Ed25519 verifying key bytes.
    pub fn zone_root_name(&self) -> &Name {
        &self.zone_root
    }

    pub fn public_key_bytes(&self) -> &[u8; 32] {
        &self.pub_key_bytes
    }

    pub fn signer(&self) -> &Ed25519Signer {
        &self.signer
    }

    pub fn into_arc_signer(self) -> Arc<dyn Signer> {
        Arc::new(self.signer)
    }

    /// Derive a child name under this zone root.
    ///
    /// Example: if zone root is `/[blake3:abcd…]`, then
    /// `zone.child_name("/sensor/temp")` returns `/[blake3:abcd…]/sensor/temp`.
    pub fn child_name(&self, suffix: &str) -> Result<Name, ndn_packet::PacketError> {
        let suffix: Name = suffix.parse()?;
        let mut components = self.zone_root.components().to_vec();
        components.extend_from_slice(suffix.components());
        Ok(Name::from_components(components))
    }

    /// The `did:ndn` DID string for this zone root.
    ///
    /// Returns `did:ndn:<base64url(Name-TLV)>` — the unified binary encoding.
    pub fn zone_root_did(&self) -> String {
        zone_root_to_did(&self.zone_root)
    }

    pub fn is_zone_child(&self, name: &Name) -> bool {
        let zc = self.zone_root.components();
        let nc = name.components();
        nc.len() > zc.len() && nc[..zc.len()] == *zc
    }
}

pub fn zone_root_from_pubkey(public_key_bytes: &[u8]) -> Name {
    let hash = blake3::hash(public_key_bytes);
    Name::zone_root_from_hash(*hash.as_bytes())
}

pub fn zone_root_to_did(zone_root: &Name) -> String {
    crate::did::name_to_did(zone_root)
}

pub fn verify_zone_root(zone_root: &Name, public_key_bytes: &[u8]) -> bool {
    let expected = zone_root_from_pubkey(public_key_bytes);
    zone_root == &expected
}
