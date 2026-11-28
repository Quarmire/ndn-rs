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
use curve25519_dalek::montgomery::MontgomeryPoint;
use hkdf::Hkdf;
use ndn_crypto_core::{open_in_place, seal_in_place};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
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
    /// An X25519 public key gave an all-zero shared secret (a low-order
    /// point): no key can be agreed with it.
    #[error("the X25519 public key agrees no shared secret (low-order point)")]
    BadPublicKey,
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

/// Length of an X25519 key (public or secret), in bytes.
pub const X25519_LEN: usize = 32;

/// Domain label of the KEK derivation in [`wrap_ck_to`] / [`RecipientKey::unwrap_ck`].
const X25519_KEK_LABEL: &[u8] = b"ndn-security/confidentiality/x25519-kek/1";

/// A recipient's long-lived X25519 key pair: the per-recipient key-wrap path
/// for a recipient whose signing key cannot agree keys (or must not). The
/// public half is published, authenticated by the recipient's signing key;
/// a sender wraps a content key to it with [`wrap_ck_to`], and only the
/// holder of the secret opens it. The secret is zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RecipientKey {
    secret: [u8; X25519_LEN],
}

impl RecipientKey {
    /// A fresh key pair from the system CSPRNG.
    pub fn generate() -> Self {
        let mut secret = [0u8; X25519_LEN];
        OsRng.fill_bytes(&mut secret);
        Self { secret }
    }

    /// The key pair of a stored secret.
    pub fn from_bytes(secret: [u8; X25519_LEN]) -> Self {
        Self { secret }
    }

    /// The secret, to store it. Treat the result as secret.
    pub fn expose(&self) -> &[u8; X25519_LEN] {
        &self.secret
    }

    /// The public half, to publish.
    pub fn public(&self) -> [u8; X25519_LEN] {
        MontgomeryPoint::mul_base_clamped(self.secret).to_bytes()
    }

    /// Open a content key [`wrap_ck_to`] wrapped to this key's public half,
    /// given the sender's `ephemeral` public key and the same `aad`.
    pub fn unwrap_ck(
        &self,
        ephemeral: &[u8; X25519_LEN],
        wrapped: &Sealed,
        aad: &[u8],
    ) -> Result<ContentKey, ConfidentialityError> {
        let shared = MontgomeryPoint(*ephemeral).mul_clamped(self.secret);
        let kek = x25519_kek(&shared, ephemeral, &self.public())?;
        unwrap_ck(&kek, wrapped, aad)
    }

    /// Open a content key [`wrap_ck_to_pair`] wrapped to this key's public half and the pair
    /// keys of the same agreement, given the sender's `ephemeral` public key, the same `aad` and
    /// the same `context`. One X25519 agreement gives both: the wrap key (label
    /// `X25519_KEK_LABEL`) and the pair keys (the channel path's labels, which differ from it
    /// and from the signed query path's).
    pub fn unwrap_ck_pair(
        &self,
        ephemeral: &[u8; X25519_LEN],
        wrapped: &Sealed,
        aad: &[u8],
        context: &[u8],
    ) -> Result<(ContentKey, PairKeys), ConfidentialityError> {
        let shared = MontgomeryPoint(*ephemeral).mul_clamped(self.secret);
        let kek = x25519_kek(&shared, ephemeral, &self.public())?;
        let ck = unwrap_ck(&kek, wrapped, aad)?;
        let keys = pair_keys(&CHANNEL_PAIR, &shared, ephemeral, &self.public(), context)?;
        Ok((ck, keys))
    }
}

/// Wrap `ck` to the X25519 public key `recipient`: a fresh ephemeral key
/// agrees a secret with it, a KEK is derived from that secret and both
/// public keys (HKDF-SHA256, domain-separated), and the CK is wrapped under
/// it binding `aad` ([`wrap_ck`]). Returns the ephemeral public key, which
/// the recipient needs, and the wrapped key. Authenticity is the caller's:
/// sign what carries them, and take `recipient` only from data its holder
/// signed.
pub fn wrap_ck_to(
    recipient: &[u8; X25519_LEN],
    ck: &ContentKey,
    aad: &[u8],
) -> Result<([u8; X25519_LEN], Sealed), ConfidentialityError> {
    let ephemeral = RecipientKey::generate();
    let public = ephemeral.public();
    let shared = MontgomeryPoint(*recipient).mul_clamped(ephemeral.secret);
    let kek = x25519_kek(&shared, &public, recipient)?;
    Ok((public, wrap_ck(&kek, ck, aad)))
}

/// [`wrap_ck_to`], and from the **same** agreement the pair keys of the channel path
/// ([`PairKeys`]) bound to `context`: what the sender (the one that agreed the secret) keeps for
/// the receiver, who derives the same with [`RecipientKey::unwrap_ck_pair`]. A second agreement
/// would cost a second scalar multiplication for nothing; the labels keep the wrap key and the
/// pair keys apart. Returns the ephemeral public key, the wrapped key and the pair keys.
pub fn wrap_ck_to_pair(
    recipient: &[u8; X25519_LEN],
    ck: &ContentKey,
    aad: &[u8],
    context: &[u8],
) -> Result<([u8; X25519_LEN], Sealed, PairKeys), ConfidentialityError> {
    let ephemeral = RecipientKey::generate();
    let public = ephemeral.public();
    let shared = MontgomeryPoint(*recipient).mul_clamped(ephemeral.secret);
    let kek = x25519_kek(&shared, &public, recipient)?;
    let keys = pair_keys(&CHANNEL_PAIR, &shared, &public, recipient, context)?;
    Ok((public, wrap_ck(&kek, ck, aad), keys))
}

/// The KEK of an X25519 agreement: HKDF-SHA256 with the shared secret as
/// input key material, no salt, and `info` the domain label followed by the
/// ephemeral and the recipient public keys.
fn x25519_kek(
    shared: &MontgomeryPoint,
    ephemeral: &[u8; X25519_LEN],
    recipient: &[u8; X25519_LEN],
) -> Result<ContentKey, ConfidentialityError> {
    let shared = zeroize::Zeroizing::new(shared.to_bytes());
    if *shared == [0u8; X25519_LEN] {
        return Err(ConfidentialityError::BadPublicKey);
    }
    let mut kek = zeroize::Zeroizing::new([0u8; CK_LEN]);
    Hkdf::<Sha256>::new(None, shared.as_ref())
        .expand_multi_info(&[X25519_KEK_LABEL, ephemeral, recipient], kek.as_mut())
        .expect("32 octets is a valid HKDF-SHA256 output length");
    Ok(ContentKey::from_bytes(*kek))
}

/// Domain label of the pair secret of [`pair_keys_to`] / [`RecipientKey::pair_keys_from`], the
/// signed query path's. It differs from [`X25519_KEK_LABEL`] and from the channel path's
/// ([`CHANNEL_PAIR`]), so one agreement cannot yield a wrap key, nor a key of another path.
const PAIR_LABEL: &[u8] = b"ndn-query/pair/1";
/// Label of the key that seals an asker's queries.
const PAIR_QUERY_LABEL: &[u8] = b"ndn-query/pair/q/1";
/// Label of the key that seals a server's answers.
const PAIR_ANSWER_LABEL: &[u8] = b"ndn-query/pair/a/1";
/// Label of the pair id of the signed path (not used on the wire there).
const PAIR_ID_LABEL: &[u8] = b"ndn-query/pair/id/1";

/// Octets of a pair id: the first eight of an HKDF-Expand of the pair secret, public by design (a
/// server finds the pair a frame names in one lookup).
pub const PAIR_ID_LEN: usize = 8;

/// The four labels of one path's pair keys. Two paths share the derivation and no label.
struct PairLabels {
    pair: &'static [u8],
    query: &'static [u8],
    answer: &'static [u8],
    id: &'static [u8],
}

/// The signed query path's labels.
const QUERY_PAIR: PairLabels = PairLabels {
    pair: PAIR_LABEL,
    query: PAIR_QUERY_LABEL,
    answer: PAIR_ANSWER_LABEL,
    id: PAIR_ID_LABEL,
};

/// The channel path's labels: a pair of keys from the agreement of the session answer
/// ([`wrap_ck_to_pair`]).
const CHANNEL_PAIR: PairLabels = PairLabels {
    pair: b"ndn-channel/pair/1",
    query: b"ndn-channel/pair/q/1",
    answer: b"ndn-channel/pair/a/1",
    id: b"ndn-channel/pair/id/1",
};

/// The two directional keys of one asker and one server: `query` seals what the asker sends,
/// `answer` what the server sends back. Neither is the other's, so a frame of one direction never
/// opens as the other. Zeroized on drop; not `Clone`, and its `Debug` shows no octet.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PairKeys {
    /// Seals the asker's queries.
    pub query: [u8; CK_LEN],
    /// Seals the server's answers.
    pub answer: [u8; CK_LEN],
    /// The pair's public name: the first [`PAIR_ID_LEN`] octets of an HKDF-Expand of the pair
    /// secret. It is derived from the key, so a re-key (a new ephemeral key) is a new id.
    pub id: [u8; PAIR_ID_LEN],
}

impl core::fmt::Debug for PairKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PairKeys(..)")
    }
}

/// The pair keys of an X25519 agreement. The pair secret is HKDF-SHA256 over the shared secret
/// (no salt) with `info` = the pair label, the ephemeral and the recipient public keys, the
/// big-endian `u32` length of `context` and `context`; each directional key is then an HKDF-Expand
/// of that secret under its own label. `context` binds what the two ends agree on (the names and
/// the epoch); a different one gives other keys.
fn pair_keys(
    labels: &PairLabels,
    shared: &MontgomeryPoint,
    ephemeral: &[u8; X25519_LEN],
    recipient: &[u8; X25519_LEN],
    context: &[u8],
) -> Result<PairKeys, ConfidentialityError> {
    let shared = zeroize::Zeroizing::new(shared.to_bytes());
    if *shared == [0u8; X25519_LEN] {
        return Err(ConfidentialityError::BadPublicKey);
    }
    let context_len = u32::try_from(context.len())
        .map_err(|_| ConfidentialityError::Malformed)?
        .to_be_bytes();
    let mut pair = zeroize::Zeroizing::new([0u8; CK_LEN]);
    Hkdf::<Sha256>::new(None, shared.as_ref())
        .expand_multi_info(
            &[labels.pair, ephemeral, recipient, &context_len, context],
            pair.as_mut(),
        )
        .expect("32 octets is a valid HKDF-SHA256 output length");
    let prk = Hkdf::<Sha256>::from_prk(pair.as_ref())
        .expect("a 32-octet pseudorandom key is a valid HKDF-SHA256 key");
    let mut keys = PairKeys {
        query: [0u8; CK_LEN],
        answer: [0u8; CK_LEN],
        id: [0u8; PAIR_ID_LEN],
    };
    prk.expand(labels.query, &mut keys.query)
        .expect("32 octets is a valid HKDF-SHA256 output length");
    prk.expand(labels.answer, &mut keys.answer)
        .expect("32 octets is a valid HKDF-SHA256 output length");
    prk.expand(labels.id, &mut keys.id)
        .expect("8 octets is a valid HKDF-SHA256 output length");
    Ok(keys)
}

/// The pair keys of an asker and the server whose X25519 public key is `recipient`: a fresh
/// ephemeral key agrees one secret with it and both directional keys derive from that
/// ([`PairKeys`]), bound to `context`. Returns the ephemeral public key, which the recipient
/// needs ([`RecipientKey::pair_keys_from`]). Authenticity is the caller's: take `recipient` only
/// from data its holder signed, and sign what carries the ephemeral key.
pub fn pair_keys_to(
    recipient: &[u8; X25519_LEN],
    context: &[u8],
) -> Result<([u8; X25519_LEN], PairKeys), ConfidentialityError> {
    let ephemeral = RecipientKey::generate();
    let public = ephemeral.public();
    let shared = MontgomeryPoint(*recipient).mul_clamped(ephemeral.secret);
    let keys = pair_keys(&QUERY_PAIR, &shared, &public, recipient, context)?;
    Ok((public, keys))
}

impl RecipientKey {
    /// The pair keys [`pair_keys_to`] derived to this key's public half, given the asker's
    /// `ephemeral` public key and the same `context`.
    pub fn pair_keys_from(
        &self,
        ephemeral: &[u8; X25519_LEN],
        context: &[u8],
    ) -> Result<PairKeys, ConfidentialityError> {
        let shared = MontgomeryPoint(*ephemeral).mul_clamped(self.secret);
        pair_keys(&QUERY_PAIR, &shared, ephemeral, &self.public(), context)
    }
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

    #[test]
    fn only_the_recipient_opens_a_key_wrapped_to_it() {
        let ck = ContentKey::generate();
        let bob = RecipientKey::generate();
        let (ephemeral, wrapped) = wrap_ck_to(&bob.public(), &ck, b"/grant/1").unwrap();
        let opened = bob.unwrap_ck(&ephemeral, &wrapped, b"/grant/1").unwrap();
        assert_eq!(opened.expose(), ck.expose());
        let mallory = RecipientKey::generate();
        assert!(
            mallory
                .unwrap_ck(&ephemeral, &wrapped, b"/grant/1")
                .is_err()
        );
        assert!(bob.unwrap_ck(&ephemeral, &wrapped, b"/grant/2").is_err());
        assert_eq!(
            wrap_ck_to(&[0u8; X25519_LEN], &ck, b"").err(),
            Some(ConfidentialityError::BadPublicKey)
        );
    }
}

#[cfg(test)]
mod pair_tests {
    use super::*;

    #[test]
    fn both_ends_derive_the_same_keys_and_they_are_distinct_per_direction() {
        let server = RecipientKey::generate();
        let (ephemeral, asker) = pair_keys_to(&server.public(), b"ctx").unwrap();
        let at_server = server.pair_keys_from(&ephemeral, b"ctx").unwrap();
        assert_eq!(asker.query, at_server.query);
        assert_eq!(asker.answer, at_server.answer);
        assert_ne!(
            asker.query, asker.answer,
            "one direction's key is not the other's"
        );
    }

    #[test]
    fn another_context_ephemeral_or_recipient_gives_other_keys() {
        let server = RecipientKey::generate();
        let (ephemeral, asker) = pair_keys_to(&server.public(), b"ctx").unwrap();
        let same = |a: &PairKeys, b: &PairKeys| a.query == b.query || a.answer == b.answer;
        // A different context.
        let other_ctx = server.pair_keys_from(&ephemeral, b"ctx2").unwrap();
        assert!(!same(&asker, &other_ctx));
        // A context that moves octets across the length prefix.
        let empty = server.pair_keys_from(&ephemeral, b"").unwrap();
        assert!(!same(&asker, &empty));
        // A different ephemeral (a second asker).
        let (ephemeral2, asker2) = pair_keys_to(&server.public(), b"ctx").unwrap();
        assert_ne!(ephemeral, ephemeral2);
        assert!(!same(&asker, &asker2));
        let wrong_ephemeral = server.pair_keys_from(&ephemeral2, b"ctx").unwrap();
        assert!(!same(&asker, &wrong_ephemeral));
        // A different recipient.
        let mallory = RecipientKey::generate();
        let wrong_recipient = mallory.pair_keys_from(&ephemeral, b"ctx").unwrap();
        assert!(!same(&asker, &wrong_recipient));
    }

    #[test]
    fn a_low_order_ephemeral_or_recipient_is_refused() {
        let server = RecipientKey::generate();
        assert_eq!(
            pair_keys_to(&[0u8; X25519_LEN], b"ctx").err(),
            Some(ConfidentialityError::BadPublicKey)
        );
        assert_eq!(
            server.pair_keys_from(&[0u8; X25519_LEN], b"ctx").err(),
            Some(ConfidentialityError::BadPublicKey)
        );
    }

    #[test]
    fn the_pair_label_is_not_the_wrap_key_label() {
        // The same agreement as `wrap_ck_to`: its KEK is not a pair key.
        let server = RecipientKey::generate();
        let (ephemeral, keys) = pair_keys_to(&server.public(), b"").unwrap();
        let shared = MontgomeryPoint(ephemeral).mul_clamped(server.secret);
        let kek = x25519_kek(&shared, &ephemeral, &server.public()).unwrap();
        assert_ne!(kek.expose(), &keys.query);
        assert_ne!(kek.expose(), &keys.answer);
        assert_ne!(PAIR_LABEL, X25519_KEK_LABEL);
        assert_ne!(PAIR_LABEL, b"ndn-channel/pair/1".as_slice());
    }

    #[test]
    fn the_debug_of_pair_keys_shows_no_octet() {
        let server = RecipientKey::generate();
        let (_, keys) = pair_keys_to(&server.public(), b"c").unwrap();
        assert_eq!(format!("{keys:?}"), "PairKeys(..)");
    }

    /// What the channel path derives: one agreement, the wrapped key and the pair.
    fn wrapped(
        asker: &RecipientKey,
        context: &[u8],
    ) -> ([u8; X25519_LEN], Sealed, PairKeys, ContentKey) {
        let ck = ContentKey::generate();
        let (ephemeral, sealed, keys) =
            wrap_ck_to_pair(&asker.public(), &ck, b"aad", context).unwrap();
        (ephemeral, sealed, keys, ck)
    }

    #[test]
    fn the_channel_pair_is_the_same_on_both_ends_and_the_key_still_opens() {
        let asker = RecipientKey::generate();
        let (ephemeral, sealed, at_server, ck) = wrapped(&asker, b"ctx");
        let (opened, at_asker) = asker
            .unwrap_ck_pair(&ephemeral, &sealed, b"aad", b"ctx")
            .unwrap();
        assert_eq!(opened.expose(), ck.expose());
        assert_eq!(at_asker.query, at_server.query);
        assert_eq!(at_asker.answer, at_server.answer);
        assert_eq!(at_asker.id, at_server.id);
        assert_ne!(at_server.query, at_server.answer);
        assert_ne!(
            at_server.query,
            *ck.expose(),
            "the channel key is not a pair key"
        );
        assert_ne!(at_server.answer, *ck.expose());
    }

    #[test]
    fn the_channel_pair_differs_per_asker_per_context_and_per_ask() {
        let asker = RecipientKey::generate();
        let (ephemeral, sealed, keys, _) = wrapped(&asker, b"ctx");
        let same =
            |a: &PairKeys, b: &PairKeys| a.query == b.query || a.answer == b.answer || a.id == b.id;
        // Another context (another channel, epoch or device name) opens the key but not the
        // pair of the first.
        let (_, other_ctx) = asker
            .unwrap_ck_pair(&ephemeral, &sealed, b"aad", b"ctx2")
            .unwrap();
        assert!(!same(&keys, &other_ctx));
        // Another asker (another recipient key) derives other keys from another agreement.
        let (_, _, other_asker, _) = wrapped(&RecipientKey::generate(), b"ctx");
        assert!(!same(&keys, &other_asker));
        // The same asker asked again: a new ephemeral key, a new pair, a new id.
        let (_, _, again, _) = wrapped(&asker, b"ctx");
        assert!(!same(&keys, &again));
    }

    #[test]
    fn the_channel_pair_is_not_the_signed_paths_nor_the_wrap_key() {
        // The same shared secret, ephemeral, recipient and context under the two paths'
        // labels give no key in common, and neither is the KEK.
        let asker = RecipientKey::generate();
        let ephemeral = RecipientKey::generate();
        let shared = MontgomeryPoint(asker.public()).mul_clamped(ephemeral.secret);
        let (e, r) = (ephemeral.public(), asker.public());
        let channel = pair_keys(&CHANNEL_PAIR, &shared, &e, &r, b"ctx").unwrap();
        let query = pair_keys(&QUERY_PAIR, &shared, &e, &r, b"ctx").unwrap();
        let kek = x25519_kek(&shared, &e, &r).unwrap();
        assert_ne!(channel.query, query.query);
        assert_ne!(channel.answer, query.answer);
        assert_ne!(channel.id, query.id);
        for key in [&channel.query, &channel.answer, &query.query, &query.answer] {
            assert_ne!(key, kek.expose());
        }
        for (a, b) in [
            (CHANNEL_PAIR.pair, QUERY_PAIR.pair),
            (CHANNEL_PAIR.query, QUERY_PAIR.query),
            (CHANNEL_PAIR.answer, QUERY_PAIR.answer),
            (CHANNEL_PAIR.id, QUERY_PAIR.id),
            (CHANNEL_PAIR.pair, X25519_KEK_LABEL),
        ] {
            assert_ne!(a, b);
        }
    }

    #[test]
    fn a_low_order_ephemeral_or_recipient_is_refused_for_the_channel_pair_too() {
        let asker = RecipientKey::generate();
        let ck = ContentKey::generate();
        assert_eq!(
            wrap_ck_to_pair(&[0u8; X25519_LEN], &ck, b"aad", b"ctx").err(),
            Some(ConfidentialityError::BadPublicKey)
        );
        let (_, sealed, _, _) = wrapped(&asker, b"ctx");
        assert_eq!(
            asker
                .unwrap_ck_pair(&[0u8; X25519_LEN], &sealed, b"aad", b"ctx")
                .err(),
            Some(ConfidentialityError::BadPublicKey)
        );
    }

    #[test]
    fn a_wrong_aad_opens_no_key_and_so_no_pair() {
        let asker = RecipientKey::generate();
        let (ephemeral, sealed, _, _) = wrapped(&asker, b"ctx");
        assert!(
            asker
                .unwrap_ck_pair(&ephemeral, &sealed, b"other", b"ctx")
                .is_err()
        );
    }
}
