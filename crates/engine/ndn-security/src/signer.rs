use std::future::Future;
use std::pin::Pin;

use crate::TrustError;
use bytes::Bytes;
use ndn_packet::{Name, SignatureType};

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Signs a region of bytes and produces a signature value.
///
/// Implemented as a dyn-compatible trait using `BoxFuture` so it can be stored
/// as `Arc<dyn Signer>` in the key store.
pub trait Signer: Send + Sync + 'static {
    fn sig_type(&self) -> SignatureType;
    fn key_name(&self) -> &Name;
    /// The certificate name to embed as a key locator in SignatureInfo, if any.
    fn cert_name(&self) -> Option<&Name> {
        None
    }
    /// Return the raw public key bytes, if available.
    fn public_key(&self) -> Option<Bytes> {
        None
    }

    fn sign<'a>(&'a self, region: &'a [u8]) -> BoxFuture<'a, Result<Bytes, TrustError>>;

    /// Synchronous signing — avoids `Box::pin` and async state machine overhead.
    ///
    /// Signers whose work is pure CPU (Ed25519, HMAC) should override this.
    fn sign_sync(&self, region: &[u8]) -> Result<Bytes, TrustError> {
        let _ = region;
        unimplemented!(
            "sign_sync not implemented for this signer — override if signing is CPU-only"
        )
    }
}

/// Ed25519 signer using `ed25519-dalek`.
pub struct Ed25519Signer {
    signing_key: ed25519_dalek::SigningKey,
    key_name: Name,
    cert_name: Option<Name>,
}

impl Ed25519Signer {
    pub fn new(
        signing_key: ed25519_dalek::SigningKey,
        key_name: Name,
        cert_name: Option<Name>,
    ) -> Self {
        Self {
            signing_key,
            key_name,
            cert_name,
        }
    }

    /// Construct from raw 32-byte seed bytes.
    pub fn from_seed(seed: &[u8; 32], key_name: Name) -> Self {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(seed);
        Self::new(signing_key, key_name, None)
    }

    /// Return the 32-byte compressed Ed25519 public key (verifying key).
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }
}

impl Signer for Ed25519Signer {
    fn sig_type(&self) -> SignatureType {
        SignatureType::SignatureEd25519
    }

    fn key_name(&self) -> &Name {
        &self.key_name
    }

    fn cert_name(&self) -> Option<&Name> {
        self.cert_name.as_ref()
    }

    fn public_key(&self) -> Option<Bytes> {
        Some(Bytes::copy_from_slice(&self.public_key_bytes()))
    }

    fn sign<'a>(&'a self, region: &'a [u8]) -> BoxFuture<'a, Result<Bytes, TrustError>> {
        Box::pin(async move { self.sign_sync(region) })
    }

    fn sign_sync(&self, region: &[u8]) -> Result<Bytes, TrustError> {
        use ed25519_dalek::Signer as _;
        let sig = self.signing_key.sign(region);
        Ok(Bytes::copy_from_slice(&sig.to_bytes()))
    }
}

/// HMAC-SHA256 signer for symmetric (pre-shared key) authentication.
///
/// Significantly faster than Ed25519 (~10x) since it only computes a keyed
/// hash rather than elliptic curve math.
pub struct HmacSha256Signer {
    key: ring::hmac::Key,
    key_name: Name,
}

impl HmacSha256Signer {
    /// Create from raw key bytes (any length; 32+ bytes recommended).
    pub fn new(key_bytes: &[u8], key_name: Name) -> Self {
        Self {
            key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key_bytes),
            key_name,
        }
    }
}

impl Signer for HmacSha256Signer {
    fn sig_type(&self) -> SignatureType {
        SignatureType::SignatureHmacWithSha256
    }

    fn key_name(&self) -> &Name {
        &self.key_name
    }

    fn sign<'a>(&'a self, region: &'a [u8]) -> BoxFuture<'a, Result<Bytes, TrustError>> {
        Box::pin(async move { self.sign_sync(region) })
    }

    fn sign_sync(&self, region: &[u8]) -> Result<Bytes, TrustError> {
        let tag = ring::hmac::sign(&self.key, region);
        Ok(Bytes::copy_from_slice(tag.as_ref()))
    }
}

// ── BLAKE3 signature type codes ───────────────────────────────────────────────
//
// NDN defines separate SignatureType values for plain digests and keyed
// digests for a reason: the verifier must be able to tell which algorithm to
// run, and a shared code opens a trivial downgrade attack (an attacker strips
// a keyed signature and replaces the Content with a plain BLAKE3 hash over
// their forged payload — on the wire both look identical, so a verifier that
// dispatches on type code alone picks the plain-digest path and validates
// the forgery). This matches the existing NDN pattern:
//
//   type 0  DigestSha256           (plain, unauthenticated)
//   type 4  SignatureHmacWithSha256 (keyed, authenticated)
//
// ndn-rs therefore assigns BLAKE3 two distinct type codes rather than reusing
// one. Both values are **reserved** on the NDN TLV SignatureType registry
// (<https://redmine.named-data.net/projects/ndn-tlv/wiki/SignatureType>).
// The wire format and verification rules are documented in
// `docs/wiki/src/reference/blake3-signature-spec.md`.

/// Signature type code for **plain** BLAKE3 digest. Analogous to
/// `DigestSha256` (type 0) — provides content integrity / self-certifying
/// names but **no authentication**. Anyone can produce a valid signature.
/// See `DigestBlake3` in `blake3-signature-spec.md`.
pub const SIGNATURE_TYPE_DIGEST_BLAKE3_PLAIN: u64 = 6;

/// Signature type code for **keyed** BLAKE3. Analogous to
/// `SignatureHmacWithSha256` (type 4) — requires a 32-byte shared secret;
/// provides both integrity **and** authentication of the source. Distinct
/// from the plain-digest code on purpose: see the plain-vs-keyed rationale
/// above. See `SignatureBlake3Keyed` in `blake3-signature-spec.md`.
pub const SIGNATURE_TYPE_DIGEST_BLAKE3_KEYED: u64 = 7;

/// BLAKE3 digest signer for high-throughput self-certifying content.
///
/// Uses signature type code [`SIGNATURE_TYPE_DIGEST_BLAKE3_PLAIN`] (6),
/// reserved on the NDN TLV SignatureType registry. Analogous to
/// `DigestSha256` (type 0) but uses BLAKE3, which is 3–8× faster on modern
/// CPUs due to SIMD parallelism.
///
/// The "signature" is a 32-byte BLAKE3 hash of the signed region. There is no
/// secret key — this provides integrity (content addressing) but **not**
/// authentication. For keyed BLAKE3 (authentication), use [`Blake3KeyedSigner`],
/// which uses a distinct type code so verifiers cannot be downgraded from
/// keyed to plain mode via a substitution attack.
pub struct Blake3Signer {
    key_name: Name,
}

impl Blake3Signer {
    pub fn new(key_name: Name) -> Self {
        Self { key_name }
    }
}

impl Signer for Blake3Signer {
    fn sig_type(&self) -> SignatureType {
        SignatureType::Other(SIGNATURE_TYPE_DIGEST_BLAKE3_PLAIN)
    }

    fn key_name(&self) -> &Name {
        &self.key_name
    }

    fn sign<'a>(&'a self, region: &'a [u8]) -> BoxFuture<'a, Result<Bytes, TrustError>> {
        Box::pin(async move { self.sign_sync(region) })
    }

    fn sign_sync(&self, region: &[u8]) -> Result<Bytes, TrustError> {
        let hash = blake3::hash(region);
        Ok(Bytes::copy_from_slice(hash.as_bytes()))
    }
}

/// BLAKE3 keyed signer for authenticated high-throughput content.
///
/// Uses signature type code [`SIGNATURE_TYPE_DIGEST_BLAKE3_KEYED`] (7),
/// reserved on the NDN TLV SignatureType registry, distinct from the plain
/// BLAKE3 code on purpose (see the plain-vs-keyed rationale on the type code
/// constants above). Uses a 32-byte secret key with BLAKE3's built-in keyed
/// hashing mode — faster than HMAC-SHA256 while providing equivalent security
/// guarantees.
pub struct Blake3KeyedSigner {
    key: [u8; 32],
    key_name: Name,
}

impl Blake3KeyedSigner {
    /// Create from an exact 32-byte key. The `SignatureBlake3Keyed` spec
    /// (`docs/wiki/src/reference/blake3-signature-spec.md`) requires keys
    /// to be exactly 32 octets; the `[u8; 32]` argument enforces this at
    /// compile time, eliminating any silent padding or truncation that
    /// would let a caller weaken the MAC by accident.
    pub fn new(key: [u8; 32], key_name: Name) -> Self {
        Self { key, key_name }
    }
}

impl Signer for Blake3KeyedSigner {
    fn sig_type(&self) -> SignatureType {
        SignatureType::Other(SIGNATURE_TYPE_DIGEST_BLAKE3_KEYED)
    }

    fn key_name(&self) -> &Name {
        &self.key_name
    }

    fn sign<'a>(&'a self, region: &'a [u8]) -> BoxFuture<'a, Result<Bytes, TrustError>> {
        Box::pin(async move { self.sign_sync(region) })
    }

    fn sign_sync(&self, region: &[u8]) -> Result<Bytes, TrustError> {
        let hash = blake3::keyed_hash(&self.key, region);
        Ok(Bytes::copy_from_slice(hash.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_packet::NameComponent;

    fn test_key_name() -> Name {
        Name::from_components([NameComponent::generic(bytes::Bytes::from_static(
            b"testkey",
        ))])
    }

    #[tokio::test]
    async fn sig_type_is_ed25519() {
        let s = Ed25519Signer::from_seed(&[1u8; 32], test_key_name());
        assert_eq!(s.sig_type(), SignatureType::SignatureEd25519);
    }

    #[tokio::test]
    async fn sign_produces_64_bytes() {
        let s = Ed25519Signer::from_seed(&[2u8; 32], test_key_name());
        let sig = s.sign(b"hello ndn").await.unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[tokio::test]
    async fn deterministic_signature() {
        let seed = [3u8; 32];
        let s1 = Ed25519Signer::from_seed(&seed, test_key_name());
        let s2 = Ed25519Signer::from_seed(&seed, test_key_name());
        let sig1 = s1.sign(b"region").await.unwrap();
        let sig2 = s2.sign(b"region").await.unwrap();
        assert_eq!(sig1, sig2);
    }

    #[tokio::test]
    async fn different_region_different_signature() {
        let s = Ed25519Signer::from_seed(&[4u8; 32], test_key_name());
        let sig1 = s.sign(b"region-a").await.unwrap();
        let sig2 = s.sign(b"region-b").await.unwrap();
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn key_name_accessor() {
        let name = test_key_name();
        let s = Ed25519Signer::from_seed(&[0u8; 32], name.clone());
        assert_eq!(s.key_name(), &name);
    }

    #[test]
    fn cert_name_defaults_to_none() {
        let s = Ed25519Signer::from_seed(&[0u8; 32], test_key_name());
        assert!(s.cert_name().is_none());
    }

    // ── HMAC-SHA256 tests ──────────────────────────────────────────────────

    #[test]
    fn hmac_sig_type() {
        let s = HmacSha256Signer::new(b"secret", test_key_name());
        assert_eq!(s.sig_type(), SignatureType::SignatureHmacWithSha256);
    }

    #[test]
    fn hmac_sign_sync_produces_32_bytes() {
        let s = HmacSha256Signer::new(b"secret", test_key_name());
        let sig = s.sign_sync(b"hello ndn").unwrap();
        assert_eq!(sig.len(), 32);
    }

    #[test]
    fn hmac_deterministic() {
        let s1 = HmacSha256Signer::new(b"key", test_key_name());
        let s2 = HmacSha256Signer::new(b"key", test_key_name());
        assert_eq!(
            s1.sign_sync(b"data").unwrap(),
            s2.sign_sync(b"data").unwrap()
        );
    }

    #[test]
    fn hmac_different_key_different_sig() {
        let s1 = HmacSha256Signer::new(b"key-a", test_key_name());
        let s2 = HmacSha256Signer::new(b"key-b", test_key_name());
        assert_ne!(
            s1.sign_sync(b"data").unwrap(),
            s2.sign_sync(b"data").unwrap()
        );
    }

    #[tokio::test]
    async fn hmac_async_matches_sync() {
        let s = HmacSha256Signer::new(b"key", test_key_name());
        let async_sig = s.sign(b"data").await.unwrap();
        let sync_sig = s.sign_sync(b"data").unwrap();
        assert_eq!(async_sig, sync_sig);
    }

    // ── Ed25519 sign_sync tests ────────────────────────────────────────────

    #[test]
    fn ed25519_sign_sync_produces_64_bytes() {
        let s = Ed25519Signer::from_seed(&[2u8; 32], test_key_name());
        let sig = s.sign_sync(b"hello ndn").unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[tokio::test]
    async fn ed25519_async_matches_sync() {
        let s = Ed25519Signer::from_seed(&[5u8; 32], test_key_name());
        let async_sig = s.sign(b"data").await.unwrap();
        let sync_sig = s.sign_sync(b"data").unwrap();
        assert_eq!(async_sig, sync_sig);
    }

    // ── BLAKE3 tests ───────────────────────────────────────────────────────

    /// Plain and keyed BLAKE3 must use distinct SignatureType codes so that
    /// a verifier dispatching on type code cannot be tricked into running
    /// the unauthenticated plain-digest path against a packet that was
    /// originally signed with the keyed (authenticated) mode. This mirrors
    /// the existing NDN pattern (`DigestSha256` = 0, `HmacWithSha256` = 4).
    #[test]
    fn blake3_plain_and_keyed_use_distinct_sig_types() {
        let plain = Blake3Signer::new(test_key_name());
        let keyed = Blake3KeyedSigner::new([9u8; 32], test_key_name());
        assert_eq!(
            plain.sig_type(),
            SignatureType::Other(SIGNATURE_TYPE_DIGEST_BLAKE3_PLAIN)
        );
        assert_eq!(
            keyed.sig_type(),
            SignatureType::Other(SIGNATURE_TYPE_DIGEST_BLAKE3_KEYED)
        );
        assert_ne!(
            plain.sig_type(),
            keyed.sig_type(),
            "plain and keyed BLAKE3 must not share a type code"
        );
    }

    /// Historical values that external callers may have depended on. Kept
    /// as an explicit assertion so any future change to the numbers is a
    /// deliberate, flagged break.
    #[test]
    fn blake3_sig_type_code_values_are_pinned() {
        assert_eq!(SIGNATURE_TYPE_DIGEST_BLAKE3_PLAIN, 6);
        assert_eq!(SIGNATURE_TYPE_DIGEST_BLAKE3_KEYED, 7);
    }

    #[test]
    fn blake3_plain_produces_32_bytes() {
        let s = Blake3Signer::new(test_key_name());
        let sig = s.sign_sync(b"hello ndn").unwrap();
        assert_eq!(sig.len(), 32);
    }

    #[test]
    fn blake3_keyed_produces_32_bytes() {
        let s = Blake3KeyedSigner::new([1u8; 32], test_key_name());
        let sig = s.sign_sync(b"hello ndn").unwrap();
        assert_eq!(sig.len(), 32);
    }

    /// Regression: with distinct keys, keyed signatures over the same region
    /// must differ. This is the core authenticity property that makes the
    /// keyed variant meaningful (vs. the plain one).
    #[test]
    fn blake3_keyed_different_key_different_sig() {
        let s1 = Blake3KeyedSigner::new([1u8; 32], test_key_name());
        let s2 = Blake3KeyedSigner::new([2u8; 32], test_key_name());
        assert_ne!(
            s1.sign_sync(b"data").unwrap(),
            s2.sign_sync(b"data").unwrap()
        );
    }

    /// Plain BLAKE3 and keyed BLAKE3 with an all-zero key must still produce
    /// different bytes over the same region (BLAKE3's keyed mode is not just
    /// plain hash when key = 0). This is the main reason sharing a type code
    /// would be unsafe: a verifier that picked the wrong mode would compute
    /// a different expected hash and (usually) reject the packet — but under
    /// a shared type code, a substitution attack recomputes the plain digest
    /// to match, and the verifier cannot tell the difference.
    #[test]
    fn blake3_plain_and_keyed_with_zero_key_differ() {
        let plain = Blake3Signer::new(test_key_name());
        let keyed = Blake3KeyedSigner::new([0u8; 32], test_key_name());
        assert_ne!(
            plain.sign_sync(b"region").unwrap(),
            keyed.sign_sync(b"region").unwrap()
        );
    }
}
