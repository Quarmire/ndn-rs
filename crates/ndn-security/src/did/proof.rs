//! Identity-proof rotation chain — the `did:ndn` key-state history.
//!
//! Canonical NDN expresses key rotation as independent re-issued certificates
//! (see `ndn_identity::transition::CertRotation`). The `did:ndn` extension adds a
//! verifiable *history*: a chain of DID Documents, each carrying a
//! content-addressed back-link ([`parent_ref`](IdentityProof::parent_ref)) to its
//! predecessor and signed by the prior key. The chain is published as signed NDN
//! Data at the stable name `/<namespace>/IDENTITY-PROOF` and replicated via SVS.
//!
//! This is the substrate type; the rotation *rule* (who authorizes a link) lives
//! in `ndn_identity::transition::DidDocumentRotation`. The shape is aligned with
//! ndf-rs's `Kind::Sovereignty` IdentityProof (single-SHA-256 `parent_ref`,
//! monotonic seq, stable name) so ndf builds on it unchanged — see the design
//! note §11 cross-reference.

use bytes::Bytes;
use sha2::{Digest, Sha256};

use ndn_packet::SignatureType;

use super::document::DidDocument;

/// One link in a `did:ndn` rotation-history chain: a DID Document plus a
/// content-addressed back-link to its predecessor.
///
/// The [`parent_ref`](Self::parent_ref) is `None` for the genesis link
/// (`seq == 0`, self-signed) and otherwise the SHA-256 of the predecessor's
/// [`canonical_bytes`](Self::canonical_bytes). [`sig_value`](Self::sig_value) is
/// produced by the *authorizing* key — the prior key for a rotation, the
/// subject's own key for genesis.
#[derive(Clone, Debug)]
pub struct IdentityProof {
    /// The DID Document this proof publishes (the current key-state). A rotation
    /// keeps the same `document.id` and changes the verification method (key).
    pub document: DidDocument,
    /// SHA-256 of the predecessor proof's canonical bytes; `None` for genesis.
    pub parent_ref: Option<[u8; 32]>,
    /// Monotonic position in the chain (genesis = 0).
    pub seq: u64,
    /// The recovery authority this key-state **pre-commits** to: the out-of-band
    /// key (or quorum) that may later authorize a recovery transition if the
    /// operational key is lost. Declared here, before loss, and signed into
    /// [`canonical_bytes`](Self::canonical_bytes) — recovery cannot be
    /// bootstrapped after the fact. `None` if no recovery is committed.
    pub recovery: Option<RecoveryCommitment>,
    /// Signature over [`canonical_bytes`](Self::canonical_bytes).
    pub sig_value: Bytes,
    /// Signature algorithm of `sig_value`.
    pub sig_type: SignatureType,
}

/// A pre-committed recovery authority — the out-of-band key material declared in
/// an [`IdentityProof`] that may authorize a later recovery transition. This is
/// substrate key material (public keys + a threshold); the recovery *rule* that
/// consumes it lives in `ndn_identity::transition::KeyRecovery`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryCommitment {
    /// A single pre-designated recovery key (Ed25519 public key).
    Key([u8; 32]),
    /// m-of-n: any `threshold` of the listed recovery keys must authorize.
    Quorum {
        keys: Vec<[u8; 32]>,
        threshold: usize,
    },
}

impl RecoveryCommitment {
    /// Append a deterministic encoding to `out` so the commitment is bound into
    /// the proof's [`canonical_bytes`](IdentityProof::canonical_bytes).
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Key(k) => {
                out.push(0);
                out.extend_from_slice(k);
            }
            Self::Quorum { keys, threshold } => {
                out.push(1);
                out.extend_from_slice(&(*threshold as u64).to_be_bytes());
                out.extend_from_slice(&(keys.len() as u64).to_be_bytes());
                for k in keys {
                    out.extend_from_slice(k);
                }
            }
        }
    }
}

impl IdentityProof {
    /// The deterministic byte string the signature covers: the DID Document, the
    /// parent back-link, and the sequence number, each length- or
    /// presence-framed so the encoding is unambiguous. Re-derived (never stored
    /// independently) so the signature is bound to the actual fields.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let doc = serde_json::to_vec(&self.document).unwrap_or_default();
        out.extend_from_slice(&(doc.len() as u64).to_be_bytes());
        out.extend_from_slice(&doc);
        match self.parent_ref {
            Some(h) => {
                out.push(1);
                out.extend_from_slice(&h);
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.seq.to_be_bytes());
        match &self.recovery {
            Some(commitment) => {
                out.push(1);
                commitment.encode_into(&mut out);
            }
            None => out.push(0),
        }
        out
    }

    /// SHA-256 of [`canonical_bytes`](Self::canonical_bytes) — the value a
    /// successor proof carries in its [`parent_ref`](Self::parent_ref).
    pub fn content_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.canonical_bytes());
        hasher.finalize().into()
    }
}
