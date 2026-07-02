//! Content-key (CK) indirection — the confidentiality tier's reuse primitive.
//!
//! Content is sealed under a random **content key** (CK); the CK is then wrapped
//! — by per-recipient AEAD key-wrap here, or by ABE in `ndn-nacabe` — into a
//! separately-nameable, cacheable object. This separates the *expensive*
//! operation (key wrap) from the *cheap* one (AEAD seal): a producer wraps a CK
//! once and seals many payloads under it, and re-keys without re-wrapping for an
//! unchanged policy. A producer publishing 100 telemetry frames under one policy
//! runs the wrap once and the AEAD 100 times.
//!
//! AEAD is delegated to [`ndn_crypto_core::seal_in_place`] /
//! [`ndn_crypto_core::open_in_place`] (the shared `no_std`/no-alloc baseline);
//! this module adds key generation, alloc-level seal/open ergonomics,
//! per-recipient key-wrap, and the epoch-rotation policy.
//!
//! # Cipher choice
//!
//! The cipher is **ChaCha20-Poly1305**, not NDNSF's AES-256-GCM. ABE/encrypted
//! *content* does not interoperate with the C++ NAC-ABE/NDNSF stack regardless
//! (see `docs/specs/service-layer.md` §7.3), so there is no reason to match its
//! cipher — and ChaCha20-Poly1305 is the already-present, `no_std`, wasm-safe,
//! constant-time baseline. The CK is 32 bytes, the nonce 12, the tag 16, and the
//! default epoch-rotation thresholds (60 s / 10 000 uses) mirror NDNSF's
//! `HybridMessageCrypto` for parity of the *rotation discipline*.
//!
//! # AAD discipline
//!
//! Every seal binds an `aad` (associated data) argument that is authenticated
//! but not encrypted. Callers MUST bind the surrounding NDN context into it (the
//! Data name, and for the service layer the type / request-id / service / sender
//! / key-id / epoch — the fields `HybridMessageCrypto` binds), so that metadata
//! is tamper-evident locally rather than relying on an outer Data signature.

use core::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use ndn_crypto_core::{open_in_place, seal_in_place};
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length of a content key, in bytes (ChaCha20-Poly1305 key = 256 bits).
pub const CK_LEN: usize = 32;
/// Length of an AEAD nonce, in bytes.
pub const NONCE_LEN: usize = 12;
/// Length of the AEAD authentication tag, in bytes.
pub const TAG_LEN: usize = 16;
/// Length of an epoch identifier, in bytes.
pub const EPOCH_ID_LEN: usize = 8;

/// Default maximum age of a content key before rotation (NDNSF parity).
pub const DEFAULT_MAX_EPOCH_AGE: Duration = Duration::from_secs(60);
/// Default maximum number of seals under one content key before rotation
/// (NDNSF parity).
pub const DEFAULT_MAX_EPOCH_USES: u64 = 10_000;

/// Errors from the content-key confidentiality layer.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConfidentialityError {
    /// AEAD authentication failed: wrong key, nonce, or AAD, or the ciphertext
    /// (or tag) was tampered with. The plaintext is never exposed on failure.
    #[error("AEAD open failed: wrong key/nonce/aad or tampered ciphertext")]
    OpenFailed,
    /// A serialized [`Sealed`] was too short or otherwise malformed.
    #[error("malformed sealed bytes")]
    Malformed,
    /// An unwrapped content key did not have exactly [`CK_LEN`] bytes.
    #[error("wrapped content key has wrong length")]
    BadKeyLength,
}

/// A symmetric content key (ChaCha20-Poly1305, 256-bit). The raw bytes are
/// zeroized on drop; obtain them only through [`ContentKey::expose`], which is
/// named to make the sensitivity visible at every call site.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ContentKey {
    key: [u8; CK_LEN],
}

impl ContentKey {
    /// Generate a fresh content key from the system CSPRNG.
    pub fn generate() -> Self {
        let mut key = [0u8; CK_LEN];
        OsRng.fill_bytes(&mut key);
        Self { key }
    }

    /// Construct a content key from raw bytes (e.g. an unwrapped key).
    pub fn from_bytes(key: [u8; CK_LEN]) -> Self {
        Self { key }
    }

    /// Borrow the raw key bytes — needed to wrap the CK under another scheme
    /// (ABE, an X25519-derived KEK). Treat the result as secret.
    pub fn expose(&self) -> &[u8; CK_LEN] {
        &self.key
    }

    /// Seal `plaintext` under this key with a fresh random nonce, binding `aad`.
    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Sealed {
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let mut buffer = plaintext.to_vec();
        // seal_in_place only returns None on a bad key length, which is
        // statically impossible here (the key is [u8; 32]).
        let tag = seal_in_place(&self.key, &nonce, aad, &mut buffer)
            .expect("ChaCha20-Poly1305 key length is fixed at 32 bytes");
        Sealed {
            nonce,
            ciphertext: Bytes::from(buffer),
            tag,
        }
    }

    /// Open a [`Sealed`] under this key, verifying `aad`. Returns the plaintext,
    /// or [`ConfidentialityError::OpenFailed`] if authentication fails.
    pub fn open(&self, sealed: &Sealed, aad: &[u8]) -> Result<Vec<u8>, ConfidentialityError> {
        let mut buffer = sealed.ciphertext.to_vec();
        if open_in_place(&self.key, &sealed.nonce, aad, &mut buffer, &sealed.tag) {
            Ok(buffer)
        } else {
            Err(ConfidentialityError::OpenFailed)
        }
    }
}

/// A detached-AEAD output: the nonce, the ciphertext, and the authentication
/// tag. Self-describing on the wire via [`Sealed::to_bytes`] /
/// [`Sealed::from_bytes`] (`nonce ‖ tag ‖ ciphertext`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sealed {
    /// The random 96-bit nonce used for this seal.
    pub nonce: [u8; NONCE_LEN],
    /// The ciphertext (same length as the plaintext; the tag is separate).
    pub ciphertext: Bytes,
    /// The 128-bit Poly1305 authentication tag.
    pub tag: [u8; TAG_LEN],
}

impl Sealed {
    /// Serialize as `nonce ‖ tag ‖ ciphertext`. (A higher layer wraps this in an
    /// NDN-TLV container with the scheme/policy/epoch metadata.)
    pub fn to_bytes(&self) -> Bytes {
        let mut out = BytesMut::with_capacity(NONCE_LEN + TAG_LEN + self.ciphertext.len());
        out.put_slice(&self.nonce);
        out.put_slice(&self.tag);
        out.put_slice(&self.ciphertext);
        out.freeze()
    }

    /// Parse `nonce ‖ tag ‖ ciphertext`.
    pub fn from_bytes(b: &[u8]) -> Result<Self, ConfidentialityError> {
        if b.len() < NONCE_LEN + TAG_LEN {
            return Err(ConfidentialityError::Malformed);
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&b[..NONCE_LEN]);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&b[NONCE_LEN..NONCE_LEN + TAG_LEN]);
        let ciphertext = Bytes::copy_from_slice(&b[NONCE_LEN + TAG_LEN..]);
        Ok(Self {
            nonce,
            ciphertext,
            tag,
        })
    }
}

/// Wrap a content key under a key-encryption key (KEK) by AEAD-sealing its raw
/// bytes — the per-recipient key-wrap path of the confidentiality tier. The KEK
/// is itself a symmetric key (derived from X25519 ECDH to a recipient, or
/// supplied by an ABE unwrap). `aad` binds the wrap context (e.g. the CK-data
/// name).
pub fn wrap_ck(kek: &ContentKey, ck: &ContentKey, aad: &[u8]) -> Sealed {
    kek.seal(ck.expose(), aad)
}

/// Recover a content key wrapped by [`wrap_ck`] under the same KEK and `aad`.
pub fn unwrap_ck(
    kek: &ContentKey,
    wrapped: &Sealed,
    aad: &[u8],
) -> Result<ContentKey, ConfidentialityError> {
    let bytes = kek.open(wrapped, aad)?;
    let arr: [u8; CK_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| ConfidentialityError::BadKeyLength)?;
    Ok(ContentKey::from_bytes(arr))
}

/// When to rotate a content key: after `max_age`, or after `max_uses` seals,
/// whichever comes first (NDNSF `HybridMessageCrypto` semantics).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochPolicy {
    /// Maximum wall-clock age of a key before rotation.
    pub max_age: Duration,
    /// Maximum number of seals under one key before rotation.
    pub max_uses: u64,
}

impl Default for EpochPolicy {
    fn default() -> Self {
        Self {
            max_age: DEFAULT_MAX_EPOCH_AGE,
            max_uses: DEFAULT_MAX_EPOCH_USES,
        }
    }
}

/// A content key with an epoch identifier and a rotation policy. The caller
/// supplies a monotonic time (in seconds) at each seal, keeping this clock-free
/// and deterministic — wasm-safe and trivially testable — while the integrating
/// producer (which has a runtime clock) decides what "now" means.
pub struct RotatingKey {
    ck: ContentKey,
    epoch_id: [u8; EPOCH_ID_LEN],
    created_at_secs: u64,
    uses: u64,
    policy: EpochPolicy,
}

impl RotatingKey {
    /// Start a new rotating key at `now_secs` with the given policy.
    pub fn new(now_secs: u64, policy: EpochPolicy) -> Self {
        let mut epoch_id = [0u8; EPOCH_ID_LEN];
        OsRng.fill_bytes(&mut epoch_id);
        Self {
            ck: ContentKey::generate(),
            epoch_id,
            created_at_secs: now_secs,
            uses: 0,
            policy,
        }
    }

    /// The current epoch identifier (changes on every rotation).
    pub fn epoch_id(&self) -> &[u8; EPOCH_ID_LEN] {
        &self.epoch_id
    }

    /// Whether the current key is stale at `now_secs` (too old or too used).
    pub fn is_stale(&self, now_secs: u64) -> bool {
        let age = now_secs.saturating_sub(self.created_at_secs);
        age >= self.policy.max_age.as_secs() || self.uses >= self.policy.max_uses
    }

    /// Replace the key and epoch id, resetting age and use count to `now_secs`.
    pub fn rotate(&mut self, now_secs: u64) {
        self.ck = ContentKey::generate();
        OsRng.fill_bytes(&mut self.epoch_id);
        self.created_at_secs = now_secs;
        self.uses = 0;
    }

    /// Seal `plaintext`, rotating first if the key is stale at `now_secs`.
    /// Returns the epoch id in force for this seal alongside the ciphertext, so
    /// the receiver can locate the matching key.
    pub fn seal(
        &mut self,
        now_secs: u64,
        plaintext: &[u8],
        aad: &[u8],
    ) -> ([u8; EPOCH_ID_LEN], Sealed) {
        if self.is_stale(now_secs) {
            self.rotate(now_secs);
        }
        self.uses += 1;
        (self.epoch_id, self.ck.seal(plaintext, aad))
    }

    /// Borrow the current content key (e.g. to wrap it for distribution).
    pub fn content_key(&self) -> &ContentKey {
        &self.ck
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trips() {
        let ck = ContentKey::generate();
        let sealed = ck.seal(b"telemetry frame 42", b"/muas/drone-A/telemetry");
        let pt = ck.open(&sealed, b"/muas/drone-A/telemetry").unwrap();
        assert_eq!(pt, b"telemetry frame 42");
    }

    #[test]
    fn open_rejects_wrong_aad() {
        let ck = ContentKey::generate();
        let sealed = ck.seal(b"secret", b"/name/v1");
        // A mismatched AAD (e.g. a swapped name) must fail authentication.
        assert_eq!(
            ck.open(&sealed, b"/name/v2"),
            Err(ConfidentialityError::OpenFailed)
        );
    }

    #[test]
    fn open_rejects_tampered_ciphertext() {
        let ck = ContentKey::generate();
        let mut sealed = ck.seal(b"secret payload", b"aad");
        let mut bad = sealed.ciphertext.to_vec();
        bad[0] ^= 0xff;
        sealed.ciphertext = Bytes::from(bad);
        assert_eq!(
            ck.open(&sealed, b"aad"),
            Err(ConfidentialityError::OpenFailed)
        );
    }

    #[test]
    fn open_rejects_wrong_key() {
        let ck = ContentKey::generate();
        let other = ContentKey::generate();
        let sealed = ck.seal(b"secret", b"aad");
        assert_eq!(
            other.open(&sealed, b"aad"),
            Err(ConfidentialityError::OpenFailed)
        );
    }

    #[test]
    fn wrap_unwrap_recovers_the_same_key() {
        let kek = ContentKey::generate();
        let ck = ContentKey::generate();
        // Seal something under the original CK...
        let sealed = ck.seal(b"under the content key", b"ctx");
        // ...wrap the CK under the KEK, unwrap it, and prove the recovered key
        // opens what the original sealed (i.e. it is byte-identical).
        let wrapped = wrap_ck(&kek, &ck, b"/ck-data/name");
        let recovered = unwrap_ck(&kek, &wrapped, b"/ck-data/name").unwrap();
        assert_eq!(recovered.expose(), ck.expose());
        assert_eq!(
            recovered.open(&sealed, b"ctx").unwrap(),
            b"under the content key"
        );
    }

    #[test]
    fn unwrap_rejects_wrong_kek() {
        let kek = ContentKey::generate();
        let wrong = ContentKey::generate();
        let ck = ContentKey::generate();
        let wrapped = wrap_ck(&kek, &ck, b"n");
        // `ContentKey` has no `Debug`/`PartialEq` (it is secret key material), so
        // assert on the error variant rather than the whole `Result`.
        assert!(matches!(
            unwrap_ck(&wrong, &wrapped, b"n"),
            Err(ConfidentialityError::OpenFailed)
        ));
    }

    #[test]
    fn sealed_bytes_round_trip() {
        let ck = ContentKey::generate();
        let sealed = ck.seal(b"frame", b"aad");
        let bytes = sealed.to_bytes();
        let parsed = Sealed::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, sealed);
        assert_eq!(ck.open(&parsed, b"aad").unwrap(), b"frame");
    }

    #[test]
    fn sealed_from_bytes_rejects_short_input() {
        assert_eq!(
            Sealed::from_bytes(&[0u8; 10]),
            Err(ConfidentialityError::Malformed)
        );
    }

    #[test]
    fn nonces_are_unique_per_seal() {
        let ck = ContentKey::generate();
        let a = ck.seal(b"x", b"");
        let b = ck.seal(b"x", b"");
        // Identical plaintext + key, but fresh nonces ⇒ different nonce and
        // different ciphertext (no deterministic reuse).
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn rotates_after_max_uses() {
        let policy = EpochPolicy {
            max_age: Duration::from_secs(60),
            max_uses: 3,
        };
        let mut rk = RotatingKey::new(0, policy);
        let e0 = *rk.epoch_id();
        // 3 seals are allowed under the first epoch; the 4th triggers rotation.
        for _ in 0..3 {
            let (e, _) = rk.seal(0, b"m", b"");
            assert_eq!(e, e0);
        }
        let (e4, _) = rk.seal(0, b"m", b"");
        assert_ne!(e4, e0, "key should rotate once max_uses is reached");
    }

    #[test]
    fn rotates_after_max_age() {
        let policy = EpochPolicy {
            max_age: Duration::from_secs(60),
            max_uses: 10_000,
        };
        let mut rk = RotatingKey::new(0, policy);
        let e0 = *rk.epoch_id();
        let (e_before, _) = rk.seal(59, b"m", b""); // still within the window
        assert_eq!(e_before, e0);
        let (e_after, _) = rk.seal(60, b"m", b""); // age == max_age ⇒ rotate
        assert_ne!(e_after, e0, "key should rotate once max_age is reached");
    }

    #[test]
    fn receiver_with_rotated_epoch_key_can_open() {
        // End-to-end: a producer seals under a rotating key and ships the epoch
        // id + CK; the receiver, holding that CK, opens it.
        let mut rk = RotatingKey::new(0, EpochPolicy::default());
        let (_epoch, sealed) = rk.seal(0, b"hello", b"/svc/topic");
        let shipped_ck = ContentKey::from_bytes(*rk.content_key().expose());
        assert_eq!(shipped_ck.open(&sealed, b"/svc/topic").unwrap(), b"hello");
    }
}
