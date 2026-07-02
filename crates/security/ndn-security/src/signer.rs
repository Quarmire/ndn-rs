use std::future::Future;
use std::pin::Pin;

use crate::TrustError;
use bytes::Bytes;
use ndn_packet::{Name, SignatureType};

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait Signer: Send + Sync + 'static {
    fn sig_type(&self) -> SignatureType;
    fn key_name(&self) -> &Name;
    fn cert_name(&self) -> Option<&Name> {
        None
    }
    fn public_key(&self) -> Option<Bytes> {
        None
    }

    fn sign<'a>(&'a self, region: &'a [u8]) -> BoxFuture<'a, Result<Bytes, TrustError>>;

    /// Synchronous signing for CPU-only signers. The default refuses rather
    /// than panics: signers whose keys live behind an async boundary
    /// (custodian, remote signer, hardware token) cannot sign synchronously,
    /// and callers must be able to treat that as a recoverable error.
    fn sign_sync(&self, region: &[u8]) -> Result<Bytes, TrustError> {
        let _ = region;
        Err(TrustError::KeyStore(
            "sign_sync unsupported: this signer signs asynchronously — use sign()".into(),
        ))
    }
}

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

    pub fn from_seed(seed: &[u8; 32], key_name: Name) -> Self {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(seed);
        Self::new(signing_key, key_name, None)
    }

    /// Load from a PKCS#8 DER private key (the format a SafeBag or a FileTpm
    /// stores). Lets a decrypted SafeBag key be deposited into a custodian.
    pub fn from_pkcs8_der(pkcs8_der: &[u8], key_name: Name) -> Result<Self, TrustError> {
        use ed25519_dalek::pkcs8::DecodePrivateKey;
        let signing_key = ed25519_dalek::SigningKey::from_pkcs8_der(pkcs8_der)
            .map_err(|e| TrustError::KeyStore(format!("ed25519 from_pkcs8_der: {e}")))?;
        Ok(Self::new(signing_key, key_name, None))
    }

    /// PKCS#8 DER of this key. Round-trips with [`Self::from_pkcs8_der`].
    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>, TrustError> {
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        Ok(self
            .signing_key
            .to_pkcs8_der()
            .map_err(|e| TrustError::KeyStore(format!("ed25519 to_pkcs8_der: {e}")))?
            .as_bytes()
            .to_vec())
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Generate a fresh key from the OS RNG.
    pub fn generate(key_name: Name) -> Result<Self, TrustError> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|_| TrustError::KeyStore("rng failure".into()))?;
        Ok(Self::from_seed(&seed, key_name))
    }

    /// Stamp `KeyLocator = cert_name` on produced signatures.
    pub fn with_cert_name(mut self, cert_name: Name) -> Self {
        self.cert_name = Some(cert_name);
        self
    }
}

#[cfg(test)]
mod ed25519_pkcs8_tests {
    use super::*;

    #[test]
    fn pkcs8_round_trip_preserves_key() {
        let name: Name = "/op/alice/KEY/k1".parse().unwrap();
        let original = Ed25519Signer::from_seed(&[9u8; 32], name.clone());
        let der = original.to_pkcs8_der().expect("encode pkcs8");
        let loaded = Ed25519Signer::from_pkcs8_der(&der, name).expect("decode pkcs8");
        assert_eq!(original.public_key_bytes(), loaded.public_key_bytes());
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

pub struct EcdsaP256Signer {
    signing_key: p256_ecdsa::ecdsa::SigningKey,
    spki_der: Bytes,
    key_name: Name,
    cert_name: Option<Name>,
}

impl EcdsaP256Signer {
    pub fn new(
        signing_key: p256_ecdsa::ecdsa::SigningKey,
        key_name: Name,
        cert_name: Option<Name>,
    ) -> Self {
        let point = signing_key.verifying_key().to_encoded_point(false);
        let spki = crate::file_tpm::p256_spki_wrap(point.as_bytes());
        Self {
            signing_key,
            spki_der: Bytes::from(spki),
            key_name,
            cert_name,
        }
    }

    pub fn from_seed(seed: &[u8; 32], key_name: Name) -> Result<Self, TrustError> {
        let sk = p256_ecdsa::ecdsa::SigningKey::from_bytes(seed.into())
            .map_err(|_| TrustError::InvalidKey)?;
        Ok(Self::new(sk, key_name, None))
    }

    pub fn generate(key_name: Name) -> Result<Self, TrustError> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|_| TrustError::KeyStore("rng failure".into()))?;
        Self::from_seed(&seed, key_name)
    }

    /// Construct from a PKCS#8 `PrivateKeyInfo` DER (the shape stored
    /// inside a `SafeBag`'s encrypted key).
    pub fn from_pkcs8_der(pkcs8_der: &[u8], key_name: Name) -> Result<Self, TrustError> {
        use p256_ecdsa::ecdsa::SigningKey;
        use p256_ecdsa::pkcs8::DecodePrivateKey;
        let sk = SigningKey::from_pkcs8_der(pkcs8_der)
            .map_err(|e| TrustError::KeyStore(format!("from_pkcs8_der: {e}")))?;
        Ok(Self::new(sk, key_name, None))
    }

    /// Export the private key as PKCS#8 `PrivateKeyInfo` DER — the unencrypted
    /// shape [`SafeBag::encrypt`](../../ndn_safebag/struct.SafeBag.html) wraps.
    /// Round-trips with [`Self::from_pkcs8_der`].
    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>, TrustError> {
        use p256_ecdsa::pkcs8::EncodePrivateKey;
        // `ecdsa::SigningKey` doesn't impl `EncodePrivateKey`; go via the
        // `p256::SecretKey` (same scalar) which does.
        let sk = p256_ecdsa::SecretKey::from_bytes(&self.signing_key.to_bytes())
            .map_err(|_| TrustError::InvalidKey)?;
        let der = sk
            .to_pkcs8_der()
            .map_err(|e| TrustError::KeyStore(format!("to_pkcs8_der: {e}")))?;
        Ok(der.as_bytes().to_vec())
    }

    /// Attach the issued certificate name (set after NDNCERT enrollment so the
    /// signer stamps `KeyLocator=<cert_name>`).
    pub fn with_cert_name(mut self, cert_name: Name) -> Self {
        self.cert_name = Some(cert_name);
        self
    }
}

impl Signer for EcdsaP256Signer {
    fn sig_type(&self) -> SignatureType {
        SignatureType::SignatureSha256WithEcdsa
    }

    fn key_name(&self) -> &Name {
        &self.key_name
    }

    fn cert_name(&self) -> Option<&Name> {
        self.cert_name.as_ref()
    }

    fn public_key(&self) -> Option<Bytes> {
        Some(self.spki_der.clone())
    }

    fn sign<'a>(&'a self, region: &'a [u8]) -> BoxFuture<'a, Result<Bytes, TrustError>> {
        Box::pin(async move { self.sign_sync(region) })
    }

    fn sign_sync(&self, region: &[u8]) -> Result<Bytes, TrustError> {
        use p256_ecdsa::ecdsa::{Signature, signature::Signer as _};
        let sig: Signature = self.signing_key.sign(region);
        Ok(Bytes::from(sig.to_der().as_bytes().to_vec()))
    }
}

pub struct HmacSha256Signer {
    key: Vec<u8>,
    key_name: Name,
}

impl HmacSha256Signer {
    pub fn new(key_bytes: &[u8], key_name: Name) -> Self {
        Self {
            key: key_bytes.to_vec(),
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
        let tag = crate::hmac_sha256::sign(&self.key, region);
        Ok(Bytes::copy_from_slice(&tag))
    }
}

// Plain and keyed BLAKE3 use distinct SignatureType codes to prevent
// downgrade attacks. Both are registered on the NDN TLV registry.
// See `docs/wiki/src/reference/blake3-signature-spec.md`.

pub const SIGNATURE_TYPE_DIGEST_BLAKE3_PLAIN: u64 = 6;
pub const SIGNATURE_TYPE_DIGEST_BLAKE3_KEYED: u64 = 7;

/// Plain BLAKE3 digest signer (type 6). No secret key; integrity only.
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
        let hash = blake3_hash_auto(region);
        Ok(Bytes::copy_from_slice(hash.as_bytes()))
    }
}

/// 128 KiB: crossover where rayon thread-spawn overhead pays for itself.
pub const BLAKE3_RAYON_THRESHOLD: usize = 128 * 1024;

pub fn blake3_hash_auto(region: &[u8]) -> blake3::Hash {
    if region.len() >= BLAKE3_RAYON_THRESHOLD {
        let mut h = blake3::Hasher::new();
        h.update_rayon(region);
        h.finalize()
    } else {
        blake3::hash(region)
    }
}

pub fn blake3_keyed_hash_auto(key: &[u8; 32], region: &[u8]) -> blake3::Hash {
    if region.len() >= BLAKE3_RAYON_THRESHOLD {
        let mut h = blake3::Hasher::new_keyed(key);
        h.update_rayon(region);
        h.finalize()
    } else {
        blake3::keyed_hash(key, region)
    }
}

/// Keyed BLAKE3 signer (type 7). Requires a 32-byte secret.
pub struct Blake3KeyedSigner {
    key: [u8; 32],
    key_name: Name,
}

impl Blake3KeyedSigner {
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
        let hash = blake3_keyed_hash_auto(&self.key, region);
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

    #[test]
    fn blake3_keyed_different_key_different_sig() {
        let s1 = Blake3KeyedSigner::new([1u8; 32], test_key_name());
        let s2 = Blake3KeyedSigner::new([2u8; 32], test_key_name());
        assert_ne!(
            s1.sign_sync(b"data").unwrap(),
            s2.sign_sync(b"data").unwrap()
        );
    }

    #[test]
    fn blake3_plain_and_keyed_with_zero_key_differ() {
        let plain = Blake3Signer::new(test_key_name());
        let keyed = Blake3KeyedSigner::new([0u8; 32], test_key_name());
        assert_ne!(
            plain.sign_sync(b"region").unwrap(),
            keyed.sign_sync(b"region").unwrap()
        );
    }

    #[test]
    fn ecdsa_pkcs8_round_trips_and_preserves_key() {
        let original = EcdsaP256Signer::from_seed(&[7u8; 32], test_key_name()).unwrap();
        let der = original.to_pkcs8_der().unwrap();
        // Re-import the exported PKCS#8 and confirm it is the same key:
        // identical SPKI public key and identical signatures.
        let reimported = EcdsaP256Signer::from_pkcs8_der(&der, test_key_name()).unwrap();
        assert_eq!(original.public_key(), reimported.public_key());
        assert_eq!(
            original.sign_sync(b"enroll witness").unwrap(),
            reimported.sign_sync(b"enroll witness").unwrap()
        );
    }
}
