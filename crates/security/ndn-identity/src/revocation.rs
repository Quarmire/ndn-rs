//! Revocation record — a signed, transmittable statement that a key is dead.
//!
//! `TrustContext` already *enforces* revocation
//! (`is_revoked` / `with_revocation` over a list of names); what was missing is
//! the wire artifact that **distributes** one. A [`RevocationRecord`] is a
//! signed statement — "key X is revoked as of T, because …" — that a verifier
//! checks and then feeds into its trust context's revocation list.
//!
//! The most defensible form is **self-revocation**: a key signs its own death
//! ("I am compromised, stop trusting me"). No authority question arises — a key
//! can always revoke itself — so a verifier that already trusts the key accepts
//! the revocation unconditionally. Revoking *another* key (issuer/principal
//! authority) is left to the consumer's trust policy: `verify` confirms the
//! signature; whether the signer *may* revoke `revoked` is the caller's call.

use ndn_packet::{Name, SignatureType};
use ndn_security::verifier::verify_by_sig_type;
use ndn_security::{KeyChain, VerifyOutcome};

use bytes::Bytes;

use crate::IdentityError;

/// A signed revocation. Produce a self-revocation with
/// [`self_revoke`](Self::self_revoke); check it with [`verify`](Self::verify);
/// move it with [`encode`](Self::encode) / [`decode`](Self::decode).
#[derive(Debug, Clone)]
pub struct RevocationRecord {
    /// The key/cert name being revoked.
    pub revoked: Name,
    /// Human-readable reason (e.g. `compromised`, `lost`, `superseded`).
    pub reason: String,
    /// When the revocation takes effect — ms since the Unix epoch.
    pub revoked_at_ms: u64,
    /// The key that signed this record (the revoking authority).
    pub key_locator: Name,
    /// Signature algorithm of `sig_value`.
    pub sig_type: SignatureType,
    /// Signature over [`canonical_bytes`](Self::canonical_bytes).
    pub sig_value: Bytes,
}

/// Why a [`RevocationRecord`] failed to decode or verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationError {
    /// Truncated or mis-framed wire.
    Malformed,
    /// The signature does not verify under the provided key.
    SignatureInvalid,
}

impl RevocationRecord {
    /// A key revokes **itself**: `revoked` and `key_locator` are both the
    /// principal's signing key, signed by it. Always-verifiable by anyone who
    /// trusts the key.
    pub fn self_revoke(
        principal: &KeyChain,
        reason: impl Into<String>,
        revoked_at_ms: u64,
    ) -> Result<Self, IdentityError> {
        let signer = principal
            .signer()
            .map_err(|e| IdentityError::Lifecycle(format!("principal has no signer: {e}")))?;
        let key = signer.key_name().clone();
        let mut rec = RevocationRecord {
            revoked: key.clone(),
            reason: reason.into(),
            revoked_at_ms,
            key_locator: key,
            sig_type: signer.sig_type(),
            sig_value: Bytes::new(),
        };
        rec.sig_value = signer
            .sign_sync(&rec.canonical_bytes())
            .map_err(|e| IdentityError::Lifecycle(format!("revocation signing failed: {e}")))?;
        Ok(rec)
    }

    /// Whether this record is a self-revocation (the signing key revoked
    /// itself). A verifier can trust a self-revocation from any key it already
    /// trusts, with no further authority check.
    pub fn is_self_revocation(&self) -> bool {
        self.revoked == self.key_locator
    }

    /// Verify the signature against the signer's public key (resolved from
    /// `key_locator` through the caller's trust). On success the `revoked` name
    /// may be fed into a `TrustContext`'s
    /// revocation list. Whether the signer is *authorized* to revoke a name
    /// other than its own is the caller's policy decision (see
    /// [`is_self_revocation`](Self::is_self_revocation)).
    pub async fn verify(&self, signer_public_key: &[u8]) -> Result<(), RevocationError> {
        let region = self.canonical_bytes();
        match verify_by_sig_type(self.sig_type, &region, &self.sig_value, signer_public_key).await {
            Ok(VerifyOutcome::Valid) => Ok(()),
            _ => Err(RevocationError::SignatureInvalid),
        }
    }

    /// Deterministic signed region: revoked name, reason, timestamp,
    /// key-locator, and sig-type, each length- or fixed-framed.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_str(&mut out, &self.revoked.to_string());
        put_str(&mut out, &self.reason);
        out.extend_from_slice(&self.revoked_at_ms.to_be_bytes());
        put_str(&mut out, &self.key_locator.to_string());
        out.extend_from_slice(&self.sig_type.code().to_be_bytes());
        out
    }

    /// Encode to a transmittable record (canonical fields + framed signature).
    pub fn encode(&self) -> Bytes {
        let mut out = self.canonical_bytes();
        put_blob(&mut out, &self.sig_value);
        Bytes::from(out)
    }

    /// Decode a record produced by [`encode`](Self::encode). Still unverified.
    pub fn decode(wire: &[u8]) -> Result<Self, RevocationError> {
        let mut c = Cursor { buf: wire, pos: 0 };
        let revoked = get_name(&mut c)?;
        let reason = String::from_utf8(get_blob(&mut c)?.to_vec())
            .map_err(|_| RevocationError::Malformed)?;
        let revoked_at_ms = get_u64(&mut c)?;
        let key_locator = get_name(&mut c)?;
        let sig_type = SignatureType::from_code(get_u64(&mut c)?);
        let sig_value = Bytes::copy_from_slice(get_blob(&mut c)?);
        Ok(Self {
            revoked,
            reason,
            revoked_at_ms,
            key_locator,
            sig_type,
            sig_value,
        })
    }
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    put_blob(out, s.as_bytes());
}

fn put_blob(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u64).to_be_bytes());
    out.extend_from_slice(b);
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

fn get_blob<'a>(c: &mut Cursor<'a>) -> Result<&'a [u8], RevocationError> {
    if c.pos + 8 > c.buf.len() {
        return Err(RevocationError::Malformed);
    }
    let len = u64::from_be_bytes(c.buf[c.pos..c.pos + 8].try_into().unwrap()) as usize;
    c.pos += 8;
    if c.pos + len > c.buf.len() {
        return Err(RevocationError::Malformed);
    }
    let out = &c.buf[c.pos..c.pos + len];
    c.pos += len;
    Ok(out)
}

fn get_u64(c: &mut Cursor<'_>) -> Result<u64, RevocationError> {
    if c.pos + 8 > c.buf.len() {
        return Err(RevocationError::Malformed);
    }
    let v = u64::from_be_bytes(c.buf[c.pos..c.pos + 8].try_into().unwrap());
    c.pos += 8;
    Ok(v)
}

fn get_name(c: &mut Cursor<'_>) -> Result<Name, RevocationError> {
    let s = std::str::from_utf8(get_blob(c)?).map_err(|_| RevocationError::Malformed)?;
    s.parse::<Name>().map_err(|_| RevocationError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_security::SecurityManager;
    use std::sync::Arc;

    fn keychain(name: &str) -> (KeyChain, Vec<u8>) {
        let mgr = Arc::new(SecurityManager::new());
        let id: Name = name.parse().unwrap();
        let key_name: Name = format!("{name}/KEY/k0").parse().unwrap();
        mgr.generate_ed25519(key_name.clone()).unwrap();
        let pubkey = mgr
            .get_signer_sync(&key_name)
            .unwrap()
            .public_key()
            .unwrap()
            .to_vec();
        (KeyChain::from_parts(mgr, id, key_name), pubkey)
    }

    #[tokio::test]
    async fn self_revoke_then_verify() {
        let (kc, pubkey) = keychain("/alice");
        let rec = RevocationRecord::self_revoke(&kc, "compromised", 1_700_000_000_000).unwrap();
        assert!(rec.is_self_revocation());
        assert_eq!(rec.revoked.to_string(), "/alice/KEY/k0");
        rec.verify(&pubkey).await.expect("verify");
    }

    #[tokio::test]
    async fn wire_round_trips() {
        let (kc, pubkey) = keychain("/alice");
        let rec = RevocationRecord::self_revoke(&kc, "lost", 42).unwrap();
        let back = RevocationRecord::decode(&rec.encode()).expect("decode");
        assert_eq!(back.revoked, rec.revoked);
        assert_eq!(back.reason, "lost");
        assert_eq!(back.revoked_at_ms, 42);
        back.verify(&pubkey).await.expect("decoded verifies");
    }

    #[tokio::test]
    async fn tampered_reason_fails_verification() {
        let (kc, pubkey) = keychain("/alice");
        let mut rec = RevocationRecord::self_revoke(&kc, "lost", 42).unwrap();
        rec.reason = "not compromised, ignore".into(); // forge after signing
        assert_eq!(
            rec.verify(&pubkey).await,
            Err(RevocationError::SignatureInvalid)
        );
    }

    #[tokio::test]
    async fn wrong_key_fails_verification() {
        let (kc, _) = keychain("/alice");
        let (_other, other_pub) = keychain("/alice");
        let rec = RevocationRecord::self_revoke(&kc, "x", 1).unwrap();
        assert_eq!(
            rec.verify(&other_pub).await,
            Err(RevocationError::SignatureInvalid)
        );
    }

    #[test]
    fn truncated_wire_is_malformed() {
        let (kc, _) = keychain("/alice");
        let wire = RevocationRecord::self_revoke(&kc, "x", 1).unwrap().encode();
        assert!(matches!(
            RevocationRecord::decode(&wire[..wire.len() / 2]),
            Err(RevocationError::Malformed)
        ));
    }

    /// The full distribution loop: a verified self-revocation's `revoked` name
    /// flows into a trust context (via a version bump), and a peer that adopts
    /// the bumped context sees the key as revoked — which the validator's
    /// chain walk then enforces (witnessed in ndn-security).
    #[tokio::test]
    async fn self_revocation_flows_into_a_context_revocation() {
        use ndn_security::SignedTrustContext;

        let (kc, pubkey) = keychain("/alice");
        let rec = RevocationRecord::self_revoke(&kc, "compromised", 1).unwrap();
        rec.verify(&pubkey).await.expect("self-revocation verifies");

        // The context authority bumps the context with the revoked name; the
        // bumped content is what a peer adopts.
        let ctx = SignedTrustContext::hierarchical("/alice".parse().unwrap())
            .with_revocation(rec.revoked.clone());
        let adopted = SignedTrustContext::decode_content(&ctx.encode_content(), 2)
            .expect("adopt the bumped context");
        assert!(adopted.is_revoked(&rec.revoked));
    }
}
