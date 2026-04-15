use std::future::Future;
use std::pin::Pin;

use crate::TrustError;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Outcome of a signature verification attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    Valid,
    /// Signature is cryptographically invalid.
    Invalid,
}

/// Verifies a signature against a public key.
pub trait Verifier: Send + Sync + 'static {
    fn verify<'a>(
        &'a self,
        region: &'a [u8],
        sig_value: &'a [u8],
        public_key: &'a [u8],
    ) -> BoxFuture<'a, Result<VerifyOutcome, TrustError>>;
}

/// Ed25519 verifier.
pub struct Ed25519Verifier;

impl Ed25519Verifier {
    /// Synchronous Ed25519 verification — avoids boxing a Future for CPU-only work.
    pub fn verify_sync(&self, region: &[u8], sig_value: &[u8], public_key: &[u8]) -> VerifyOutcome {
        use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};

        let Ok(vk) = VerifyingKey::from_bytes(public_key.try_into().unwrap_or(&[0u8; 32])) else {
            return VerifyOutcome::Invalid;
        };

        let Ok(sig_bytes): Result<&[u8; 64], _> = sig_value.try_into() else {
            return VerifyOutcome::Invalid;
        };
        let sig = Signature::from_bytes(sig_bytes);

        match vk.verify(region, &sig) {
            Ok(()) => VerifyOutcome::Valid,
            Err(_) => VerifyOutcome::Invalid,
        }
    }
}

impl Verifier for Ed25519Verifier {
    fn verify<'a>(
        &'a self,
        region: &'a [u8],
        sig_value: &'a [u8],
        public_key: &'a [u8],
    ) -> BoxFuture<'a, Result<VerifyOutcome, TrustError>> {
        Box::pin(async move {
            use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};

            let vk = VerifyingKey::from_bytes(
                public_key.try_into().map_err(|_| TrustError::InvalidKey)?,
            )
            .map_err(|_| TrustError::InvalidKey)?;

            let sig_bytes: &[u8; 64] = sig_value
                .try_into()
                .map_err(|_| TrustError::InvalidSignature)?;
            let sig = Signature::from_bytes(sig_bytes);

            match vk.verify(region, &sig) {
                Ok(()) => Ok(VerifyOutcome::Valid),
                Err(_) => Ok(VerifyOutcome::Invalid),
            }
        })
    }
}

// ─── Batch Ed25519 verification ────────────────────────────────────────────
//
// For a forwarder or consumer ingesting many independent Ed25519
// signatures at once (sync snapshot, batched Interest set, a fetch
// of N segment Data packets), verifying them **together** via
// `ed25519_dalek::verify_batch` is ~2–3× faster than N separate
// `verify()` calls. The technique combines the N verification
// equations into one big check using random coefficients — if every
// signature is valid the batch passes in one shot; if any is invalid
// the batch fails and you don't know which one (fallback is to
// re-verify individually).

/// Batch-verify a homogeneous slice of Ed25519 signatures. All three
/// inputs must have the same length. Returns `Ok(())` if every
/// signature is valid under its paired `(message, public_key)`; any
/// single invalid signature causes the whole batch to fail with
/// [`VerifyOutcome::Invalid`] (you then have to fall back to
/// per-signature verify to find the culprit).
///
/// For a homogeneous-message workload (all messages identical — e.g.
/// SVS sync state blobs in a group), callers can pass the same
/// `&[u8]` multiple times in `messages` and still get the batch
/// speedup because `ed25519_dalek::verify_batch` is message-by-
/// reference.
pub fn ed25519_verify_batch(
    messages: &[&[u8]],
    signatures: &[&[u8; 64]],
    public_keys: &[&[u8; 32]],
) -> Result<VerifyOutcome, TrustError> {
    use ed25519_dalek::{Signature, VerifyingKey, verify_batch};

    let n = messages.len();
    if signatures.len() != n || public_keys.len() != n {
        return Err(TrustError::InvalidSignature);
    }
    if n == 0 {
        return Ok(VerifyOutcome::Valid); // vacuous truth
    }

    // Decode signatures into `ed25519_dalek::Signature` objects.
    // `Signature::from_bytes` is infallible for `[u8; 64]` inputs.
    let sigs: Vec<Signature> = signatures
        .iter()
        .map(|s| Signature::from_bytes(s))
        .collect();

    // Decode verifying keys. Any malformed public key makes the
    // whole batch undecodable — return InvalidKey so the caller
    // knows this is a structural error, not a signature mismatch.
    let mut keys: Vec<VerifyingKey> = Vec::with_capacity(n);
    for pk in public_keys {
        match VerifyingKey::from_bytes(pk) {
            Ok(vk) => keys.push(vk),
            Err(_) => return Err(TrustError::InvalidKey),
        }
    }

    // Run the batch verify. A failed batch returns Invalid, not
    // Err — the signatures are well-formed, one (or more) is just
    // wrong, which is the same semantic as a single `verify()`
    // returning `VerifyOutcome::Invalid`.
    match verify_batch(messages, &sigs, &keys) {
        Ok(()) => Ok(VerifyOutcome::Valid),
        Err(_) => Ok(VerifyOutcome::Invalid),
    }
}

/// BLAKE3 digest verifier — checks that `sig_value` is the BLAKE3 hash of `region`.
///
/// `public_key` is unused (BLAKE3 digest signing has no key). Pass an empty slice.
///
/// Hashes large inputs (≥ [`BLAKE3_RAYON_THRESHOLD`]) via `update_rayon`,
/// which scales with available cores. Per-packet verification never
/// reaches the threshold; bulk content verification (large segmented
/// Data with a tree-signed root) does.
pub struct Blake3DigestVerifier;

impl Verifier for Blake3DigestVerifier {
    fn verify<'a>(
        &'a self,
        region: &'a [u8],
        sig_value: &'a [u8],
        _public_key: &'a [u8],
    ) -> BoxFuture<'a, Result<VerifyOutcome, TrustError>> {
        Box::pin(async move {
            let Ok(expected): Result<&[u8; 32], _> = sig_value.try_into() else {
                return Ok(VerifyOutcome::Invalid);
            };
            let hash = crate::signer::blake3_hash_auto(region);
            if hash.as_bytes() == expected {
                Ok(VerifyOutcome::Valid)
            } else {
                Ok(VerifyOutcome::Invalid)
            }
        })
    }
}

/// BLAKE3 keyed verifier — checks that `sig_value` is the BLAKE3 keyed hash of `region`.
///
/// `public_key` must be exactly 32 bytes (the BLAKE3 key). Same large-
/// input dispatch as [`Blake3DigestVerifier`].
pub struct Blake3KeyedVerifier;

impl Verifier for Blake3KeyedVerifier {
    fn verify<'a>(
        &'a self,
        region: &'a [u8],
        sig_value: &'a [u8],
        public_key: &'a [u8],
    ) -> BoxFuture<'a, Result<VerifyOutcome, TrustError>> {
        Box::pin(async move {
            let key: &[u8; 32] = public_key.try_into().map_err(|_| TrustError::InvalidKey)?;
            let Ok(expected): Result<&[u8; 32], _> = sig_value.try_into() else {
                return Ok(VerifyOutcome::Invalid);
            };
            let hash = crate::signer::blake3_keyed_hash_auto(key, region);
            if hash.as_bytes() == expected {
                Ok(VerifyOutcome::Valid)
            } else {
                Ok(VerifyOutcome::Invalid)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    fn keypair(seed: &[u8; 32]) -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::from_bytes(seed);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    #[tokio::test]
    async fn valid_signature_returns_valid() {
        let (sk, pk) = keypair(&[1u8; 32]);
        let region = b"signed region";
        let sig = sk.sign(region).to_bytes();
        let outcome = Ed25519Verifier.verify(region, &sig, &pk).await.unwrap();
        assert_eq!(outcome, VerifyOutcome::Valid);
    }

    #[tokio::test]
    async fn wrong_signature_returns_invalid() {
        let (_sk, pk) = keypair(&[1u8; 32]);
        let region = b"signed region";
        let bad_sig = [0u8; 64];
        let outcome = Ed25519Verifier.verify(region, &bad_sig, &pk).await.unwrap();
        assert_eq!(outcome, VerifyOutcome::Invalid);
    }

    #[tokio::test]
    async fn wrong_key_returns_invalid() {
        let (sk, _) = keypair(&[1u8; 32]);
        let (_, pk2) = keypair(&[2u8; 32]); // different key
        let region = b"signed region";
        let sig = sk.sign(region).to_bytes();
        let outcome = Ed25519Verifier.verify(region, &sig, &pk2).await.unwrap();
        assert_eq!(outcome, VerifyOutcome::Invalid);
    }

    #[tokio::test]
    async fn short_public_key_returns_err() {
        let sig = [0u8; 64];
        let result = Ed25519Verifier.verify(b"region", &sig, &[0u8; 16]).await;
        assert!(matches!(result, Err(TrustError::InvalidKey)));
    }

    #[tokio::test]
    async fn short_signature_returns_err() {
        let (_, pk) = keypair(&[1u8; 32]);
        let result = Ed25519Verifier.verify(b"region", &[0u8; 32], &pk).await;
        assert!(matches!(result, Err(TrustError::InvalidSignature)));
    }

    // ── batch verification ──────────────────────────────────────────────

    /// A batch of all-valid signatures over per-key messages verifies.
    #[test]
    fn batch_all_valid_returns_valid() {
        // Generate 10 independent keypairs, sign a distinct message with
        // each, and batch-verify.
        let ns: Vec<(SigningKey, [u8; 32], Vec<u8>, [u8; 64])> = (0u8..10)
            .map(|i| {
                let (sk, pk) = keypair(&[i; 32]);
                let msg = format!("message {i}").into_bytes();
                let sig = sk.sign(&msg).to_bytes();
                (sk, pk, msg, sig)
            })
            .collect();
        let messages: Vec<&[u8]> = ns.iter().map(|(_, _, m, _)| m.as_slice()).collect();
        let signatures: Vec<&[u8; 64]> = ns.iter().map(|(_, _, _, s)| s).collect();
        let public_keys: Vec<&[u8; 32]> = ns.iter().map(|(_, pk, _, _)| pk).collect();
        let out = ed25519_verify_batch(&messages, &signatures, &public_keys).unwrap();
        assert_eq!(out, VerifyOutcome::Valid);
    }

    /// A batch with one bad signature fails the whole batch (per
    /// `verify_batch` semantics — the caller then falls back to
    /// per-signature verify to locate the culprit).
    #[test]
    fn batch_one_bad_sig_returns_invalid() {
        let ns: Vec<(SigningKey, [u8; 32], Vec<u8>, [u8; 64])> = (0u8..10)
            .map(|i| {
                let (sk, pk) = keypair(&[i; 32]);
                let msg = format!("message {i}").into_bytes();
                let sig = sk.sign(&msg).to_bytes();
                (sk, pk, msg, sig)
            })
            .collect();
        let messages: Vec<&[u8]> = ns.iter().map(|(_, _, m, _)| m.as_slice()).collect();
        let mut signatures: Vec<[u8; 64]> = ns.iter().map(|(_, _, _, s)| *s).collect();
        // Corrupt one byte of one signature.
        signatures[4][0] ^= 0x80;
        let sig_refs: Vec<&[u8; 64]> = signatures.iter().collect();
        let public_keys: Vec<&[u8; 32]> = ns.iter().map(|(_, pk, _, _)| pk).collect();
        let out = ed25519_verify_batch(&messages, &sig_refs, &public_keys).unwrap();
        assert_eq!(out, VerifyOutcome::Invalid);
    }

    #[test]
    fn batch_length_mismatch_returns_err() {
        let (sk, pk) = keypair(&[1u8; 32]);
        let msg: &[u8] = b"a message";
        let sig = sk.sign(msg).to_bytes();
        let messages: &[&[u8]] = &[msg, msg];
        let sigs = [&sig];
        let keys = [&pk, &pk];
        let out = ed25519_verify_batch(messages, &sigs, &keys);
        assert!(matches!(out, Err(TrustError::InvalidSignature)));
    }

    #[test]
    fn batch_empty_is_vacuously_valid() {
        let out = ed25519_verify_batch(&[], &[], &[]).unwrap();
        assert_eq!(out, VerifyOutcome::Valid);
    }

    // Note: no test for "malformed public key returns InvalidKey"
    // because `ed25519_dalek::VerifyingKey::from_bytes` is more
    // lenient than I expected — all-0x00 and all-0xFF both decode as
    // (unusable) curve points, so the InvalidKey mapping in
    // `ed25519_verify_batch` only fires for genuinely malformed
    // 32-byte sequences that ed25519-dalek considers non-points,
    // which is hard to construct without internal knowledge of the
    // curve encoding. The functional behaviour is correct — a bogus
    // key produces a `VerifyOutcome::Invalid` rather than an Err —
    // which is fine for the forwarder-ingest use case (you'd
    // fall back to per-signature verify either way).
}
