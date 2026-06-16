//! Recovery bundle — the encodable `did:ndn` history an identity backs up so a
//! fresh device can recover it with the committed recovery key(s).
//!
//! The bundle is **public**: DID Documents, public recovery commitments, and
//! signatures — *no private keys*. So it's safe to store off-device (cloud,
//! paper, another device). Recovery is still gated by the committed recovery
//! key, which lives only with the user; the bundle alone authorizes nothing.

use ndn_security::did::{IdentityProof, ProofDecodeError};

/// Encode a rotation history as a recovery bundle: a count, then each
/// length-framed [`IdentityProof`] wire.
pub fn encode_history(history: &[IdentityProof]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(history.len() as u64).to_be_bytes());
    for proof in history {
        let wire = proof.encode();
        out.extend_from_slice(&(wire.len() as u64).to_be_bytes());
        out.extend_from_slice(&wire);
    }
    out
}

/// Decode a bundle produced by [`encode_history`]. Each proof is still
/// unverified — the recovery rule (`Identity::recover`) checks the chain.
pub fn decode_history(wire: &[u8]) -> Result<Vec<IdentityProof>, ProofDecodeError> {
    let read_u64 = |pos: usize| -> Result<u64, ProofDecodeError> {
        wire.get(pos..pos + 8)
            .map(|s| u64::from_be_bytes(s.try_into().unwrap()))
            .ok_or(ProofDecodeError::Malformed)
    };
    let count = read_u64(0)?;
    let mut pos = 8;
    // Don't pre-allocate from an untrusted count — grow as proofs decode.
    let mut out = Vec::new();
    for _ in 0..count {
        let len = read_u64(pos)? as usize;
        pos += 8;
        let end = pos.checked_add(len).ok_or(ProofDecodeError::Malformed)?;
        let slice = wire.get(pos..end).ok_or(ProofDecodeError::Malformed)?;
        out.push(IdentityProof::decode(slice)?);
        pos = end;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_security::did::{DidDocument, RecoveryCommitment};
    use ndn_packet::SignatureType;

    fn proof(seq: u64, parent: Option<[u8; 32]>) -> IdentityProof {
        IdentityProof {
            document: DidDocument::new_simple("did:ndn:/a", "did:ndn:/a#k", &[1u8; 32]),
            parent_ref: parent,
            seq,
            recovery: Some(RecoveryCommitment::Key([3u8; 32])),
            sig_value: bytes::Bytes::from_static(&[9, 9]),
            sig_type: SignatureType::SignatureEd25519,
        }
    }

    #[test]
    fn history_chain_round_trips() {
        let history = vec![proof(0, None), proof(1, Some([1u8; 32]))];
        let back = decode_history(&encode_history(&history)).expect("decode");
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].seq, 0);
        assert_eq!(back[1].seq, 1);
        assert_eq!(back[1].parent_ref, Some([1u8; 32]));
    }

    #[test]
    fn empty_history_round_trips() {
        assert!(decode_history(&encode_history(&[])).unwrap().is_empty());
    }

    #[test]
    fn truncated_bundle_is_malformed() {
        let wire = encode_history(&[proof(0, None)]);
        assert!(decode_history(&wire[..wire.len() / 2]).is_err());
        assert!(decode_history(&[]).is_err()); // missing even the count
    }
}
