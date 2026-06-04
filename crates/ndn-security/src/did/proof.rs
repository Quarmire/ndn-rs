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

    /// Decode the form [`encode_into`](Self::encode_into) produced.
    fn decode_from(c: &mut Cursor<'_>) -> Result<Self, ProofDecodeError> {
        match c.byte()? {
            0 => Ok(Self::Key(c.array32()?)),
            1 => {
                let threshold = c.u64()? as usize;
                let count = c.u64()? as usize;
                let mut keys = Vec::with_capacity(count);
                for _ in 0..count {
                    keys.push(c.array32()?);
                }
                Ok(Self::Quorum { keys, threshold })
            }
            _ => Err(ProofDecodeError::Malformed),
        }
    }
}

/// A [`IdentityProof::decode`] failure — the wire was truncated, carried an
/// unknown tag, or the embedded DID Document didn't parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofDecodeError {
    /// Truncated, mis-tagged, or otherwise unparseable.
    Malformed,
}

impl core::fmt::Display for ProofDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("malformed identity-proof wire")
    }
}

impl std::error::Error for ProofDecodeError {}

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

    /// Encode to a transmittable record: the [`canonical_bytes`](Self::canonical_bytes)
    /// signed region, then the signature type and value. The chain of these is
    /// what backs up a `did:ndn` history off-device (for recovery) or replicates
    /// it over SVS — `canonical_bytes` alone omits the signature.
    pub fn encode(&self) -> Bytes {
        let mut out = self.canonical_bytes();
        out.extend_from_slice(&self.sig_type.code().to_be_bytes());
        out.extend_from_slice(&(self.sig_value.len() as u64).to_be_bytes());
        out.extend_from_slice(&self.sig_value);
        Bytes::from(out)
    }

    /// Decode a record produced by [`encode`](Self::encode). The fields are
    /// re-parsed exactly as [`canonical_bytes`](Self::canonical_bytes) frames
    /// them, so a successful decode round-trips. Still unverified — the caller
    /// checks the chain (parent links + signatures) before trusting it.
    pub fn decode(wire: &[u8]) -> Result<Self, ProofDecodeError> {
        let mut c = Cursor { buf: wire, pos: 0 };
        let document: DidDocument =
            serde_json::from_slice(c.blob()?).map_err(|_| ProofDecodeError::Malformed)?;
        let parent_ref = match c.byte()? {
            0 => None,
            1 => Some(c.array32()?),
            _ => return Err(ProofDecodeError::Malformed),
        };
        let seq = c.u64()?;
        let recovery = match c.byte()? {
            0 => None,
            1 => Some(RecoveryCommitment::decode_from(&mut c)?),
            _ => return Err(ProofDecodeError::Malformed),
        };
        let sig_type = SignatureType::from_code(c.u64()?);
        let sig_value = Bytes::copy_from_slice(c.blob()?);
        Ok(Self {
            document,
            parent_ref,
            seq,
            recovery,
            sig_value,
            sig_type,
        })
    }
}

/// A read cursor over an [`IdentityProof::encode`] record. Every accessor
/// bounds-checks and advances `pos`, returning [`ProofDecodeError::Malformed`]
/// on truncation.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ProofDecodeError> {
        if self.pos + n > self.buf.len() {
            return Err(ProofDecodeError::Malformed);
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn byte(&mut self) -> Result<u8, ProofDecodeError> {
        Ok(self.take(1)?[0])
    }

    fn u64(&mut self) -> Result<u64, ProofDecodeError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn array32(&mut self) -> Result<[u8; 32], ProofDecodeError> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    fn blob(&mut self) -> Result<&'a [u8], ProofDecodeError> {
        let len = self.u64()? as usize;
        self.take(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_proof(
        seq: u64,
        recovery: Option<RecoveryCommitment>,
        parent: Option<[u8; 32]>,
    ) -> IdentityProof {
        IdentityProof {
            document: DidDocument::new_simple("did:ndn:/alice", "did:ndn:/alice#key-0", &[9u8; 32]),
            parent_ref: parent,
            seq,
            recovery,
            sig_value: Bytes::from_static(&[1, 2, 3, 4]),
            sig_type: SignatureType::SignatureEd25519,
        }
    }

    #[test]
    fn wire_round_trips_with_quorum_recovery_and_parent() {
        let commitment = RecoveryCommitment::Quorum {
            keys: vec![[1u8; 32], [2u8; 32], [3u8; 32]],
            threshold: 2,
        };
        let p = sample_proof(3, Some(commitment.clone()), Some([7u8; 32]));
        let back = IdentityProof::decode(&p.encode()).expect("decode");

        assert_eq!(back.seq, 3);
        assert_eq!(back.parent_ref, Some([7u8; 32]));
        assert_eq!(back.recovery, Some(commitment));
        assert_eq!(back.sig_value, p.sig_value);
        // The signature still binds: decoded canonical bytes match the original.
        assert_eq!(back.canonical_bytes(), p.canonical_bytes());
        assert_eq!(back.content_hash(), p.content_hash());
    }

    #[test]
    fn genesis_with_single_key_recovery_round_trips() {
        let p = sample_proof(0, Some(RecoveryCommitment::Key([5u8; 32])), None);
        let back = IdentityProof::decode(&p.encode()).expect("decode");
        assert_eq!(back.parent_ref, None);
        assert_eq!(back.recovery, Some(RecoveryCommitment::Key([5u8; 32])));
        assert_eq!(back.canonical_bytes(), p.canonical_bytes());
    }

    #[test]
    fn no_recovery_round_trips() {
        let p = sample_proof(1, None, Some([0u8; 32]));
        let back = IdentityProof::decode(&p.encode()).expect("decode");
        assert_eq!(back.recovery, None);
        assert_eq!(back.canonical_bytes(), p.canonical_bytes());
    }

    #[test]
    fn truncated_wire_is_malformed() {
        let wire = sample_proof(1, None, None).encode();
        assert!(matches!(
            IdentityProof::decode(&wire[..wire.len() / 2]),
            Err(ProofDecodeError::Malformed)
        ));
    }
}
