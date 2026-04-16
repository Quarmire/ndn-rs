//! File-backed TPM (private-key store), wire-compatible with
//! `ndn-cxx`'s `tpm-file` backend (path B + Ed25519 superset).
//!
//! # Compatibility model
//!
//! The on-disk format for **RSA** and **ECDSA-P256** keys is bit-for-bit
//! compatible with `ndnsec`. An ndn-rs binary writing an RSA or ECDSA
//! key under this TPM produces a file `ndnsec key-list` and `ndnsec sign`
//! can read, and vice versa. Pinned to ndn-cxx tag `ndn-cxx-0.9.0`,
//! commit `0751bba8`, file `ndn-cxx/security/tpm/impl/back-end-file.cpp`
//! (lines 51–229).
//!
//! Ed25519 is **not** supported by ndn-cxx `tpm-file` — its
//! `d2i_AutoPrivateKey` path only autodetects RSA and EC from ASN.1
//! tags, and `BackEndFile::createKey` rejects anything else
//! (`back-end-file.cpp:130-139`). To preserve Ed25519 as a first-class
//! algorithm in ndn-rs without breaking ndn-cxx interop, this module
//! stores Ed25519 keys with a sentinel filename suffix:
//!
//! - `<HEX>.privkey`          → RSA / ECDSA, exactly as ndn-cxx writes
//! - `<HEX>.privkey-ed25519`  → ndn-rs Ed25519 PKCS#8, ignored by ndnsec
//!
//! ndn-cxx's loader only opens `*.privkey` files and silently ignores
//! the sentinel suffix; ndn-rs reads both. This is "path B" in the
//! design discussion: superset compatibility, not strict.
//!
//! # Storage rules (MUST match ndn-cxx for `.privkey` files)
//!
//! - **Directory**: `$HOME/.ndn/ndnsec-key-file/`. Honours `TEST_HOME`
//!   first, then `HOME`, then CWD. Created with `0o700` (ndn-cxx omits
//!   the explicit chmod but inherits umask; we set it explicitly because
//!   it's the right thing).
//! - **Filename**: `hex(SHA256(key_name.wire_encode())).to_uppercase()`
//!   plus `.privkey` (or `.privkey-ed25519` for Ed25519). The hash input
//!   is the **TLV wire encoding** of the Name (outer type 0x07 + length
//!   + components), not the URI string. Easy to get wrong; the test
//!     `filename_matches_known_hash` asserts the format.
//! - **File body**: base64 of the raw private-key DER, no PEM armor, no
//!   header, no encryption.
//!     - RSA → PKCS#1 `RSAPrivateKey` DER
//!     - ECDSA-P256 → SEC1 `ECPrivateKey` DER
//!     - Ed25519 (sentinel) → PKCS#8 `PrivateKeyInfo` DER
//! - **Permissions**: per-file `chmod 0o400` on save (read-only by
//!   owner, no write even by owner). `back-end-file.cpp:228`.
//!
//! Public-key recovery is on demand from the loaded private key — there
//! are no separate public-key files; the PIB references the public
//! material via `key_bits` BLOBs.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use bytes::Bytes;
use ndn_packet::{Name, tlv_type};
use ndn_tlv::TlvWriter;
use sha2::{Digest, Sha256};

use crate::TrustError;

// ─── Errors ───────────────────────────────────────────────────────────────────

/// Errors returned by `FileTpm` operations. Mapped to `TrustError` at the
/// public boundary so callers don't need to depend on this module's type.
#[derive(Debug, thiserror::Error)]
pub enum FileTpmError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("key not found: {0}")]
    KeyNotFound(String),
    #[error("invalid key encoding: {0}")]
    InvalidKey(String),
    #[error("base64 decode error: {0}")]
    Base64(String),
    #[error("unsupported algorithm in tpm-file: {0}")]
    UnsupportedAlgorithm(String),
    #[error("signing error: {0}")]
    Sign(String),
}

impl From<FileTpmError> for TrustError {
    fn from(e: FileTpmError) -> Self {
        TrustError::KeyStore(e.to_string())
    }
}

// ─── Algorithm tag ────────────────────────────────────────────────────────────

/// Algorithm of a key stored in the TPM. Determined by file suffix and
/// (for `.privkey` files) by ASN.1 autodetection of the inner DER.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmKeyKind {
    /// PKCS#1 `RSAPrivateKey` DER. Filename ends `.privkey`. Compatible
    /// with ndn-cxx `tpm-file`.
    Rsa,
    /// SEC1 `ECPrivateKey` DER for the NIST P-256 curve. Filename ends
    /// `.privkey`. Compatible with ndn-cxx `tpm-file`.
    EcdsaP256,
    /// PKCS#8 `PrivateKeyInfo` DER. Filename ends `.privkey-ed25519`.
    /// **Not** loaded by ndn-cxx `tpm-file`; ndn-rs reads it via the
    /// sentinel suffix. See module docs for the rationale.
    Ed25519,
}

impl TpmKeyKind {
    fn extension(self) -> &'static str {
        match self {
            TpmKeyKind::Rsa | TpmKeyKind::EcdsaP256 => "privkey",
            TpmKeyKind::Ed25519 => "privkey-ed25519",
        }
    }
}

// ─── Path / filename derivation ──────────────────────────────────────────────

/// Encode a Name to its canonical TLV wire form, the byte sequence that
/// is hashed to produce the on-disk filename.
fn name_wire_encode(name: &Name) -> Vec<u8> {
    let mut w = TlvWriter::new();
    w.write_nested(tlv_type::NAME, |w| {
        for c in name.components() {
            w.write_tlv(c.typ, &c.value);
        }
    });
    w.finish().to_vec()
}

/// Hex-encode bytes in **uppercase** — matching ndn-cxx's
/// `transform/hex-encode` filter, which `BackEndFile::toFileName` uses.
fn upper_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02X}"));
    }
    s
}

/// Compute the on-disk filename stem (the SHA-256 hex prefix, no
/// extension). Same for all kinds — the extension is appended by the
/// caller depending on `TpmKeyKind`.
fn filename_stem(key_name: &Name) -> String {
    let wire = name_wire_encode(key_name);
    let digest = Sha256::digest(&wire);
    upper_hex(&digest)
}

// ─── Base64 (no-newline, no-armor) ──────────────────────────────────────────

fn b64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
fn b64_decode(s: &str) -> Result<Vec<u8>, FileTpmError> {
    use base64::Engine;
    // Permissive: ignore embedded whitespace so files written by other
    // tools with line wrapping still load cleanly. ndn-cxx's
    // `base64Decode` filter does the same.
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(cleaned.as_bytes())
        .map_err(|e| FileTpmError::Base64(e.to_string()))
}

// ─── FileTpm ─────────────────────────────────────────────────────────────────

/// File-backed TPM. Stores private keys under
/// `<root>/<HEX>.privkey[-ed25519]` files and reads them back on
/// demand. All operations take `&self`; concurrent access is safe
/// because each call performs an independent open/read/close.
pub struct FileTpm {
    root: PathBuf,
}

impl FileTpm {
    /// Open or create a TPM at the given directory. Creates the
    /// directory tree (with `0o700` permissions) if absent.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, FileTpmError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        // 0o700 — ndn-cxx omits this but we set it explicitly. Setting
        // it is strictly safer than leaving it to umask, and it doesn't
        // affect interop because ndn-cxx doesn't check directory mode.
        #[cfg(unix)]
        {
            let _ = fs::set_permissions(&root, fs::Permissions::from_mode(0o700));
        }
        Ok(Self { root })
    }

    /// Open the default TPM at `$HOME/.ndn/ndnsec-key-file/`, mirroring
    /// ndn-cxx `BackEndFile`'s default constructor.
    pub fn open_default() -> Result<Self, FileTpmError> {
        let dir = if let Ok(p) = std::env::var("TEST_HOME") {
            PathBuf::from(p).join(".ndn").join("ndnsec-key-file")
        } else if let Ok(p) = std::env::var("HOME") {
            PathBuf::from(p).join(".ndn").join("ndnsec-key-file")
        } else {
            std::env::current_dir()?
                .join(".ndn")
                .join("ndnsec-key-file")
        };
        Self::open(dir)
    }

    /// Locator string the PIB persists for this TPM. Matches ndn-cxx's
    /// canonical form: `tpm-file:` for the default location, or
    /// `tpm-file:<absolute-path>` for a custom one. ndn-cxx's
    /// `parseAndCheckTpmLocator` rejects mismatches at KeyChain open
    /// time, so writing the wrong string here will break interop.
    pub fn locator(&self) -> String {
        // We can't easily tell whether `self.root` is "the default"
        // without re-running the env var lookup, so always emit the
        // explicit form. ndn-cxx accepts both.
        format!("tpm-file:{}", self.root.display())
    }

    /// Path to a key file given its name and kind.
    fn path_for(&self, key_name: &Name, kind: TpmKeyKind) -> PathBuf {
        let stem = filename_stem(key_name);
        self.root.join(format!("{stem}.{}", kind.extension()))
    }

    /// Save raw DER bytes for a key. The DER must already be in the
    /// algorithm's canonical form for `kind`:
    /// - `Rsa` → PKCS#1 `RSAPrivateKey`
    /// - `EcdsaP256` → SEC1 `ECPrivateKey`
    /// - `Ed25519` → PKCS#8 `PrivateKeyInfo`
    ///
    /// The bytes are base64-encoded and written with `0o400`.
    pub fn save_raw(
        &self,
        key_name: &Name,
        kind: TpmKeyKind,
        der: &[u8],
    ) -> Result<(), FileTpmError> {
        let path = self.path_for(key_name, kind);
        let body = b64_encode(der);
        fs::write(&path, body.as_bytes())?;
        #[cfg(unix)]
        {
            // ndn-cxx uses 0o400. Match exactly.
            fs::set_permissions(&path, fs::Permissions::from_mode(0o400))?;
        }
        Ok(())
    }

    /// Load raw DER bytes for a key. Tries the `.privkey` file first
    /// (RSA / ECDSA), then `.privkey-ed25519`. Returns the kind alongside
    /// the bytes so callers can dispatch on algorithm.
    pub fn load_raw(&self, key_name: &Name) -> Result<(TpmKeyKind, Vec<u8>), FileTpmError> {
        let stem = filename_stem(key_name);

        // Try .privkey first (the ndn-cxx-compatible file). Autodetect
        // RSA vs ECDSA from the inner DER.
        let primary = self.root.join(format!("{stem}.privkey"));
        if let Ok(body) = fs::read_to_string(&primary) {
            let der = b64_decode(&body)?;
            let kind = autodetect_pkcs1_or_sec1(&der)?;
            return Ok((kind, der));
        }

        // Then try the Ed25519 sentinel.
        let secondary = self.root.join(format!("{stem}.privkey-ed25519"));
        if let Ok(body) = fs::read_to_string(&secondary) {
            let der = b64_decode(&body)?;
            return Ok((TpmKeyKind::Ed25519, der));
        }

        Err(FileTpmError::KeyNotFound(format!("{key_name}")))
    }

    /// Delete a key file (whichever form exists).
    pub fn delete(&self, key_name: &Name) -> Result<(), FileTpmError> {
        let stem = filename_stem(key_name);
        for ext in ["privkey", "privkey-ed25519"] {
            let p = self.root.join(format!("{stem}.{ext}"));
            if p.exists() {
                fs::remove_file(p)?;
            }
        }
        Ok(())
    }

    /// Check whether a key exists in the TPM.
    pub fn has_key(&self, key_name: &Name) -> bool {
        let stem = filename_stem(key_name);
        self.root.join(format!("{stem}.privkey")).exists()
            || self.root.join(format!("{stem}.privkey-ed25519")).exists()
    }

    // ── High-level: generate, sign, derive public key ───────────────────────

    /// Generate a fresh Ed25519 key, persist it under the sentinel
    /// suffix, and return the 32-byte raw seed. Callers that want a
    /// `Signer` should pass the seed to `Ed25519Signer::from_seed`.
    pub fn generate_ed25519(&self, key_name: &Name) -> Result<[u8; 32], FileTpmError> {
        use ed25519_dalek::SigningKey;
        use ed25519_dalek::pkcs8::EncodePrivateKey;

        // Generate a fresh seed via OsRng (reuse the same source that
        // ed25519-dalek's example uses; we don't need a separate RNG).
        let mut seed = [0u8; 32];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut seed)
            .map_err(|_| FileTpmError::Sign("rng failure".into()))?;
        let sk = SigningKey::from_bytes(&seed);

        // PKCS#8 PrivateKeyInfo for Ed25519 — pkcs8 1.0 / RFC 8410.
        let pkcs8 = sk
            .to_pkcs8_der()
            .map_err(|e| FileTpmError::InvalidKey(format!("ed25519 pkcs8: {e}")))?;
        self.save_raw(key_name, TpmKeyKind::Ed25519, pkcs8.as_bytes())?;
        Ok(seed)
    }

    /// Sign `region` with the key stored under `key_name`. Returns raw
    /// signature bytes. Algorithm is determined by which file form
    /// exists on disk.
    pub fn sign(&self, key_name: &Name, region: &[u8]) -> Result<Bytes, FileTpmError> {
        let (kind, der) = self.load_raw(key_name)?;
        match kind {
            TpmKeyKind::Rsa => sign_rsa(&der, region),
            TpmKeyKind::EcdsaP256 => sign_ecdsa_p256(&der, region),
            TpmKeyKind::Ed25519 => sign_ed25519(&der, region),
        }
    }

    /// Derive the public key bytes for `key_name`. Format matches what
    /// the PIB's `key_bits` column expects: SubjectPublicKeyInfo DER
    /// for RSA / ECDSA, raw 32-byte key for Ed25519.
    pub fn public_key(&self, key_name: &Name) -> Result<Vec<u8>, FileTpmError> {
        let (kind, der) = self.load_raw(key_name)?;
        match kind {
            TpmKeyKind::Rsa => public_key_rsa(&der),
            TpmKeyKind::EcdsaP256 => public_key_ecdsa_p256(&der),
            TpmKeyKind::Ed25519 => public_key_ed25519(&der),
        }
    }

    // ── SafeBag import / export ──────────────────────────────────────────

    /// Export `key_name` as a [`crate::safe_bag::SafeBag`] for transfer
    /// to another machine. Bundles the password-encrypted private key
    /// with the certificate the caller looked up from the PIB.
    ///
    /// The on-disk private key is converted to an unencrypted PKCS#8
    /// `PrivateKeyInfo` first (RSA goes PKCS#1 → PKCS#8, ECDSA goes
    /// SEC1 → PKCS#8, Ed25519 is already PKCS#8 on disk) and then
    /// encrypted via PBES2 + PBKDF2-HMAC-SHA256 + AES-256-CBC inside
    /// the rustcrypto `pkcs8` crate's `encrypt` method. The resulting
    /// `EncryptedPrivateKeyInfo` is wire-compatible with what
    /// `ndnsec export` and OpenSSL `i2d_PKCS8PrivateKey_bio` produce.
    ///
    /// **Caveat:** Ed25519 SafeBags roundtrip ndn-rs ↔ ndn-rs but not
    /// to ndn-cxx, because ndn-cxx `tpm-file` has no Ed25519 path
    /// regardless of how the bytes arrive on disk
    /// (`back-end-file.cpp:130-139` rejects Ed25519 at the algorithm
    /// switch). RSA and ECDSA-P256 SafeBags roundtrip with `ndnsec`
    /// in both directions.
    pub fn export_to_safebag(
        &self,
        key_name: &Name,
        certificate: Bytes,
        password: &[u8],
    ) -> Result<crate::safe_bag::SafeBag, crate::safe_bag::SafeBagError> {
        let (kind, der) = self.load_raw(key_name)?;
        let pkcs8_der: Vec<u8> = match kind {
            TpmKeyKind::Rsa => crate::safe_bag::rsa_pkcs1_to_pkcs8(&der)?,
            TpmKeyKind::EcdsaP256 => crate::safe_bag::ec_sec1_to_pkcs8(&der)?,
            TpmKeyKind::Ed25519 => der, // already PKCS#8 on disk
        };
        crate::safe_bag::SafeBag::encrypt(certificate, &pkcs8_der, password)
    }

    /// Import a [`crate::safe_bag::SafeBag`] as a stored private key
    /// under `key_name`. Decrypts the embedded `EncryptedPrivateKeyInfo`
    /// with `password`, dispatches on the PKCS#8 algorithm OID to
    /// pick the on-disk format, converts back to the FileTpm form
    /// (PKCS#1 / SEC1 / PKCS#8), and writes it.
    ///
    /// Returns the certificate Data wire bytes from the SafeBag so
    /// the caller can insert them into their PIB. FileTpm itself
    /// does not store certs — the certificate side of the bag is
    /// the PIB's responsibility.
    ///
    /// `key_name` is an explicit argument because the SafeBag does
    /// not record where the key should land in any particular PIB —
    /// the caller is expected to extract it from the certificate's
    /// Name (typically a prefix of the cert name) and pass it in.
    pub fn import_from_safebag(
        &self,
        safebag: &crate::safe_bag::SafeBag,
        key_name: &Name,
        password: &[u8],
    ) -> Result<Bytes, crate::safe_bag::SafeBagError> {
        let pkcs8_der = safebag.decrypt_key(password)?;
        let kind = crate::safe_bag::detect_pkcs8_algorithm(&pkcs8_der)?;
        let on_disk: Vec<u8> = match kind {
            TpmKeyKind::Rsa => crate::safe_bag::rsa_pkcs8_to_pkcs1(&pkcs8_der)?,
            TpmKeyKind::EcdsaP256 => crate::safe_bag::ec_pkcs8_to_sec1(&pkcs8_der)?,
            TpmKeyKind::Ed25519 => pkcs8_der, // on-disk form IS pkcs8
        };
        self.save_raw(key_name, kind, &on_disk)?;
        Ok(safebag.certificate.clone())
    }
}

// ─── Algorithm autodetection (RSA vs ECDSA from DER) ────────────────────────

/// Look at the first few ASN.1 bytes to decide whether a `.privkey`
/// file holds PKCS#1 RSA or SEC1 EC. ndn-cxx defers to OpenSSL's
/// `d2i_AutoPrivateKey` for this; we do a coarse but reliable check
/// based on the first SEQUENCE element:
///
/// - PKCS#1 `RSAPrivateKey` SEQUENCE { version INTEGER (0 or 1), n INTEGER, ... }
///   → second element is a large INTEGER (the modulus), so the structure
///   is `30 LL 02 01 vv 02 LL ...`.
/// - SEC1 `ECPrivateKey`   SEQUENCE { version INTEGER (1), privateKey OCTET STRING, ... }
///   → second element is OCTET STRING `04 LL ...`, so it starts
///   `30 LL 02 01 01 04 LL ...`.
///
/// We dispatch on the byte at offset 5 (the second element's tag): `02`
/// → RSA, `04` → ECDSA. Anything else is an error.
fn autodetect_pkcs1_or_sec1(der: &[u8]) -> Result<TpmKeyKind, FileTpmError> {
    if der.len() < 6 || der[0] != 0x30 {
        return Err(FileTpmError::InvalidKey("not a DER SEQUENCE".into()));
    }
    // Skip outer length (1 or 2+ bytes) to find the inner version + next.
    let mut i = 1usize;
    let len_byte = der[i];
    i += 1;
    if len_byte & 0x80 != 0 {
        i += (len_byte & 0x7F) as usize;
    }
    // Inner: version INTEGER must be `02 01 vv`.
    if i + 3 > der.len() || der[i] != 0x02 || der[i + 1] != 0x01 {
        return Err(FileTpmError::InvalidKey(
            "inner version field missing".into(),
        ));
    }
    let next_tag_idx = i + 3;
    if next_tag_idx >= der.len() {
        return Err(FileTpmError::InvalidKey("DER too short".into()));
    }
    match der[next_tag_idx] {
        0x02 => Ok(TpmKeyKind::Rsa),       // INTEGER → RSA modulus
        0x04 => Ok(TpmKeyKind::EcdsaP256), // OCTET STRING → SEC1 priv key
        b => Err(FileTpmError::UnsupportedAlgorithm(format!(
            "unknown second-element tag 0x{b:02x}"
        ))),
    }
}

// ─── Signing implementations ─────────────────────────────────────────────────

fn sign_rsa(pkcs1_der: &[u8], region: &[u8]) -> Result<Bytes, FileTpmError> {
    use pkcs1::DecodeRsaPrivateKey;
    // Use the sha2 re-export bundled by `rsa` rather than our top-level
    // `sha2 0.11`. `rsa = 0.9` is on the older rustcrypto release wave
    // with `digest 0.10`, and `Pkcs1v15Sign::new::<D>` is bound to that
    // crate's own `Digest` trait — handing it a `Sha256` from `sha2 0.11`
    // (which implements `digest 0.11::Digest`) is a different trait and
    // fails type-check. The bundled re-export gives us the exact type
    // `Pkcs1v15Sign::new` expects. When we eventually bump `rsa` to
    // 0.10 alongside the rest of the rustcrypto stack, this and the
    // matching block in the test module can drop the `rsa::` prefix.
    use rsa::sha2::{Digest, Sha256};
    use rsa::{Pkcs1v15Sign, RsaPrivateKey};

    let sk = RsaPrivateKey::from_pkcs1_der(pkcs1_der)
        .map_err(|e| FileTpmError::InvalidKey(format!("rsa pkcs1: {e}")))?;

    // NDN signs SHA-256(signed region) with PKCS#1 v1.5 padding —
    // matching SignatureSha256WithRsa (TLV type 1).
    let hash = Sha256::digest(region);
    let sig = sk
        .sign(Pkcs1v15Sign::new::<Sha256>(), &hash)
        .map_err(|e| FileTpmError::Sign(format!("rsa sign: {e}")))?;
    Ok(Bytes::from(sig))
}

fn public_key_rsa(pkcs1_der: &[u8]) -> Result<Vec<u8>, FileTpmError> {
    use pkcs1::DecodeRsaPrivateKey;
    use pkcs8::EncodePublicKey;
    use rsa::RsaPrivateKey;

    let sk = RsaPrivateKey::from_pkcs1_der(pkcs1_der)
        .map_err(|e| FileTpmError::InvalidKey(format!("rsa pkcs1: {e}")))?;
    let pk = sk.to_public_key();
    // SubjectPublicKeyInfo DER — what the PIB key_bits column expects.
    pk.to_public_key_der()
        .map(|d| d.as_bytes().to_vec())
        .map_err(|e| FileTpmError::InvalidKey(format!("rsa spki: {e}")))
}

/// Hand-extract the 32-byte private scalar from a SEC1 `ECPrivateKey`
/// DER envelope for the P-256 curve. We bypass `SigningKey::from_sec1_der`
/// because pairing it with `verifying_key()` triggers the spki crate's
/// "AlgorithmIdentifier parameters missing" check on the embedded
/// `publicKey [1] BIT STRING` field, which fails for SEC1 blobs that
/// omit the optional parameters even though the curve is known
/// statically. The wire layout we accept is:
///
/// ```text
/// SEQUENCE {
///   INTEGER version (== 1)              -- 02 01 01
///   OCTET STRING privateKey (32 bytes)  -- 04 20 <X..32>
///   [parameters [0] OPTIONAL]
///   [publicKey [1] OPTIONAL]
/// }
/// ```
///
/// We only need the privateKey OCTET STRING to construct an ECDSA
/// signing key; the rest of the envelope is intentionally ignored.
pub(crate) fn parse_sec1_p256_priv_scalar(sec1: &[u8]) -> Result<[u8; 32], FileTpmError> {
    if sec1.len() < 9 || sec1[0] != 0x30 {
        return Err(FileTpmError::InvalidKey("not a SEC1 SEQUENCE".into()));
    }
    let mut i = 1usize;
    let len_byte = sec1[i];
    i += 1;
    if len_byte & 0x80 != 0 {
        // Long-form length: skip the length-of-length octets.
        i += (len_byte & 0x7F) as usize;
    }
    if i + 3 > sec1.len() || sec1[i] != 0x02 || sec1[i + 1] != 0x01 {
        return Err(FileTpmError::InvalidKey("expected version INTEGER".into()));
    }
    i += 3; // skip `02 01 vv`
    if i + 2 > sec1.len() || sec1[i] != 0x04 {
        return Err(FileTpmError::InvalidKey(
            "expected privateKey OCTET STRING".into(),
        ));
    }
    let key_len = sec1[i + 1] as usize;
    if key_len != 32 {
        return Err(FileTpmError::InvalidKey(format!(
            "expected 32-byte P-256 scalar, got {key_len}"
        )));
    }
    i += 2;
    if i + 32 > sec1.len() {
        return Err(FileTpmError::InvalidKey(
            "SEC1 truncated in privateKey".into(),
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&sec1[i..i + 32]);
    Ok(out)
}

/// Build an `ecdsa::SigningKey<NistP256>` from a SEC1 ECPrivateKey blob,
/// bypassing the broken-on-missing-params `from_sec1_der` path.
fn signing_key_from_sec1(sec1_der: &[u8]) -> Result<p256_ecdsa::ecdsa::SigningKey, FileTpmError> {
    use p256_ecdsa::ecdsa::SigningKey;
    let scalar = parse_sec1_p256_priv_scalar(sec1_der)?;
    SigningKey::from_bytes((&scalar).into())
        .map_err(|e| FileTpmError::InvalidKey(format!("ecdsa scalar: {e}")))
}

fn sign_ecdsa_p256(sec1_der: &[u8], region: &[u8]) -> Result<Bytes, FileTpmError> {
    use p256_ecdsa::ecdsa::{Signature, signature::Signer};

    let sk = signing_key_from_sec1(sec1_der)?;
    // DER-encoded signature for ndn-cxx compatibility.
    let sig: Signature = sk.sign(region);
    Ok(Bytes::from(sig.to_der().as_bytes().to_vec()))
}

fn public_key_ecdsa_p256(sec1_der: &[u8]) -> Result<Vec<u8>, FileTpmError> {
    let sk = signing_key_from_sec1(sec1_der)?;
    // Uncompressed SEC1 point: 0x04 || X(32) || Y(32) = 65 bytes.
    let point = sk.verifying_key().to_encoded_point(false);
    let sec1_bytes = point.as_bytes();
    debug_assert_eq!(sec1_bytes.len(), 65);
    debug_assert_eq!(sec1_bytes[0], 0x04);
    Ok(p256_spki_wrap(sec1_bytes))
}

/// Wrap a 65-byte P-256 uncompressed SEC1 point (`04 || X || Y`) in a
/// canonical SubjectPublicKeyInfo DER, hand-built so we don't rely on
/// the rustcrypto pkcs8 trait machinery (which is brittle across the
/// 0.10/0.11 split when paired with elliptic-curve 0.13).
///
/// Output structure:
///
/// ```text
/// SEQUENCE (0x30 0x59 = 89 bytes total inner) {
///   SEQUENCE (0x30 0x13 = 19 bytes) {
///     OID id-ecPublicKey  06 07 2A 86 48 CE 3D 02 01
///     OID prime256v1      06 08 2A 86 48 CE 3D 03 01 07
///   }
///   BIT STRING (0x03 0x42 = 66 bytes) {
///     00                  -- 0 unused bits
///     04 X(32) Y(32)      -- uncompressed SEC1 point
///   }
/// }
/// ```
///
/// Total length: 91 bytes (2 outer header + 21 algorithm + 68 bitstring).
fn p256_spki_wrap(sec1_uncompressed: &[u8]) -> Vec<u8> {
    const PREFIX: [u8; 26] = [
        0x30, 0x59, // SEQUENCE, 89 bytes
        0x30, 0x13, // SEQUENCE, 19 bytes (algorithm)
        0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // OID id-ecPublicKey
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, // OID prime256v1
        0x03, 0x42, // BIT STRING, 66 bytes
        0x00, // 0 unused bits
    ];
    let mut out = Vec::with_capacity(PREFIX.len() + sec1_uncompressed.len());
    out.extend_from_slice(&PREFIX);
    out.extend_from_slice(sec1_uncompressed);
    out
}

fn sign_ed25519(pkcs8_der: &[u8], region: &[u8]) -> Result<Bytes, FileTpmError> {
    use ed25519_dalek::Signer;
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::pkcs8::DecodePrivateKey;

    let sk = SigningKey::from_pkcs8_der(pkcs8_der)
        .map_err(|e| FileTpmError::InvalidKey(format!("ed25519 pkcs8: {e}")))?;
    let sig = sk.sign(region);
    Ok(Bytes::copy_from_slice(&sig.to_bytes()))
}

fn public_key_ed25519(pkcs8_der: &[u8]) -> Result<Vec<u8>, FileTpmError> {
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::pkcs8::DecodePrivateKey;

    let sk = SigningKey::from_pkcs8_der(pkcs8_der)
        .map_err(|e| FileTpmError::InvalidKey(format!("ed25519 pkcs8: {e}")))?;
    Ok(sk.verifying_key().to_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_packet::NameComponent;
    use tempfile::tempdir;

    fn comp(s: &'static str) -> NameComponent {
        NameComponent::generic(Bytes::from_static(s.as_bytes()))
    }
    fn name(parts: &[&'static str]) -> Name {
        Name::from_components(parts.iter().map(|p| comp(p)))
    }

    #[test]
    fn filename_stem_is_uppercase_sha256_of_wire() {
        // Build a known name and verify the stem matches an
        // independently-computed SHA-256(wire) hex.
        let n = name(&["alice", "KEY", "k1"]);
        let stem = filename_stem(&n);
        // Compute expected: TLV (0x07 + len + 3 components) → SHA-256 → hex upper.
        let mut wire = Vec::new();
        // Outer header: 0x07, len=11+ inner. Just compare against the
        // helper's own output to ensure stability across runs.
        for c in n.components() {
            wire.push(c.typ as u8);
            wire.push(c.value.len() as u8);
            wire.extend_from_slice(&c.value);
        }
        let inner_len = wire.len();
        let mut full = Vec::new();
        full.push(0x07);
        full.push(inner_len as u8);
        full.extend_from_slice(&wire);
        let expected = upper_hex(&sha2::Sha256::digest(&full));
        assert_eq!(stem, expected);
        // Sanity: 64 hex chars = 32 bytes.
        assert_eq!(stem.len(), 64);
        // All uppercase hex.
        assert!(
            stem.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase())
        );
    }

    #[test]
    fn ed25519_save_load_sign_roundtrip() {
        let dir = tempdir().unwrap();
        let tpm = FileTpm::open(dir.path()).unwrap();
        let kn = name(&["alice", "KEY", "k1"]);
        let _seed = tpm.generate_ed25519(&kn).unwrap();
        assert!(tpm.has_key(&kn));

        let region = b"hello ndn-rs file tpm";
        let sig = tpm.sign(&kn, region).unwrap();
        assert_eq!(sig.len(), 64);

        // Verify the signature using the TPM-derived public key.
        use ed25519_dalek::Verifier;
        use ed25519_dalek::{Signature, VerifyingKey};
        let pk_bytes = tpm.public_key(&kn).unwrap();
        let pk = VerifyingKey::from_bytes(&pk_bytes.as_slice().try_into().unwrap()).unwrap();
        let sig_obj = Signature::from_bytes(&sig.as_ref().try_into().unwrap());
        pk.verify(region, &sig_obj).unwrap();
    }

    #[test]
    fn ecdsa_p256_save_load_sign_roundtrip() {
        use p256_ecdsa::SecretKey;

        let dir = tempdir().unwrap();
        let tpm = FileTpm::open(dir.path()).unwrap();
        let kn = name(&["bob", "KEY", "k1"]);

        // Generate an ECDSA-P256 key via the elliptic-curve SecretKey
        // surface (which directly implements EncodeEcPrivateKey) and
        // store it as SEC1 DER, matching the ndn-cxx tpm-file format.
        // `to_sec1_der` returns Zeroizing<Vec<u8>>; deref to a slice.
        let sk = SecretKey::random(&mut rand_core_compat());
        let der = sk.to_sec1_der().unwrap();
        tpm.save_raw(&kn, TpmKeyKind::EcdsaP256, der.as_slice())
            .unwrap();

        // Re-detect on load.
        let (kind, _der) = tpm.load_raw(&kn).unwrap();
        assert_eq!(kind, TpmKeyKind::EcdsaP256);

        let region = b"ecdsa test region";
        let sig = tpm.sign(&kn, region).unwrap();
        assert!(!sig.is_empty(), "sig must be non-empty");

        // Verify with the recovered public key.
        use p256_ecdsa::ecdsa::{Signature, VerifyingKey, signature::Verifier};
        use pkcs8::DecodePublicKey;
        let pk_der = tpm.public_key(&kn).unwrap();
        let vk = VerifyingKey::from_public_key_der(&pk_der).unwrap();
        let sig_obj = Signature::from_der(&sig).unwrap();
        vk.verify(region, &sig_obj).unwrap();
    }

    #[test]
    fn rsa_save_load_sign_roundtrip() {
        use pkcs1::EncodeRsaPrivateKey;
        use rsa::RsaPrivateKey;

        let dir = tempdir().unwrap();
        let tpm = FileTpm::open(dir.path()).unwrap();
        let kn = name(&["carol", "KEY", "k1"]);

        // 2048-bit key: small enough that the test runs in ~0.5 s.
        let mut rng = rand_core_compat();
        let sk = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let der = sk.to_pkcs1_der().unwrap();
        tpm.save_raw(&kn, TpmKeyKind::Rsa, der.as_bytes()).unwrap();

        let (kind, _) = tpm.load_raw(&kn).unwrap();
        assert_eq!(kind, TpmKeyKind::Rsa);

        let region = b"rsa test region";
        let sig = tpm.sign(&kn, region).unwrap();
        // 2048-bit RSA signature is 256 bytes.
        assert_eq!(sig.len(), 256);

        // Verify using the recovered public key. As in `sign_rsa`, we
        // use rsa's bundled `sha2` re-export so the `Pkcs1v15Sign::new`
        // type bound is satisfied — the workspace's top-level
        // `sha2 0.11::Sha256` belongs to a different `Digest` trait
        // family.
        use pkcs8::DecodePublicKey;
        use rsa::sha2::{Digest, Sha256};
        use rsa::{Pkcs1v15Sign, RsaPublicKey};
        let pk_der = tpm.public_key(&kn).unwrap();
        let pk = RsaPublicKey::from_public_key_der(&pk_der).unwrap();
        let hash = Sha256::digest(region);
        pk.verify(Pkcs1v15Sign::new::<Sha256>(), &hash, &sig)
            .unwrap();
    }

    #[test]
    fn delete_removes_both_extensions() {
        let dir = tempdir().unwrap();
        let tpm = FileTpm::open(dir.path()).unwrap();
        let kn = name(&["alice", "KEY", "k1"]);
        tpm.generate_ed25519(&kn).unwrap();
        assert!(tpm.has_key(&kn));
        tpm.delete(&kn).unwrap();
        assert!(!tpm.has_key(&kn));
    }

    #[test]
    fn load_missing_key_returns_not_found() {
        let dir = tempdir().unwrap();
        let tpm = FileTpm::open(dir.path()).unwrap();
        let kn = name(&["nobody"]);
        match tpm.load_raw(&kn) {
            Err(FileTpmError::KeyNotFound(_)) => {}
            other => panic!("expected KeyNotFound, got {other:?}"),
        }
    }

    #[test]
    fn locator_string_is_canonical() {
        let dir = tempdir().unwrap();
        let tpm = FileTpm::open(dir.path()).unwrap();
        let loc = tpm.locator();
        assert!(loc.starts_with("tpm-file:"));
        assert!(loc.contains(&dir.path().display().to_string()));
    }

    #[test]
    fn autodetect_distinguishes_rsa_and_ecdsa() {
        // RSA SEQUENCE: 30 LL 02 01 00 02 ...
        let rsa_like = [0x30, 0x82, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x82];
        assert_eq!(
            autodetect_pkcs1_or_sec1(&rsa_like).unwrap(),
            TpmKeyKind::Rsa
        );
        // SEC1 SEQUENCE: 30 LL 02 01 01 04 LL ...
        let ec_like = [0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20];
        assert_eq!(
            autodetect_pkcs1_or_sec1(&ec_like).unwrap(),
            TpmKeyKind::EcdsaP256
        );
    }

    /// Bridge helper: rsa 0.9 and p256 0.13 both use rand_core 0.6
    /// traits internally, and `rsa` re-exports `rand_core` so we get
    /// a stable handle without adding rand_core to our deps directly.
    /// `OsRng` satisfies the `CryptoRngCore` bound both crates need.
    fn rand_core_compat() -> rsa::rand_core::OsRng {
        rsa::rand_core::OsRng
    }

    // ── SafeBag roundtrip tests ───────────────────────────────────────────
    //
    // For each supported algorithm, generate or import a key into TPM
    // A, export to a SafeBag, decode the SafeBag wire bytes, import
    // into a fresh TPM B, and verify the imported key produces a
    // signature that the original key's public key can verify. This
    // exercises the full path:
    //
    //   on-disk → PKCS#8 → encrypt → SafeBag TLV → decode → decrypt
    //   → PKCS#8 → on-disk → load → sign
    //
    // If any link in that chain has a format error, the verify at the
    // end fails. A wrong password also fails decryption (separately
    // tested in safe_bag.rs).

    fn fake_cert_bytes() -> Bytes {
        // SafeBag treats the certificate as opaque; any well-formed
        // Data TLV is fine for a roundtrip test.
        use ndn_tlv::TlvWriter;
        let mut w = TlvWriter::new();
        w.write_tlv(0x06, b"placeholder cert body");
        w.finish()
    }

    #[test]
    fn safebag_ed25519_roundtrip() {
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();
        let tpm_a = FileTpm::open(dir_a.path()).unwrap();
        let tpm_b = FileTpm::open(dir_b.path()).unwrap();
        let kn = name(&["alice", "KEY", "k1"]);
        let pw = b"transfer-password";

        // Generate Ed25519 in tpm_a, export to SafeBag, transport
        // through wire bytes, import into tpm_b.
        tpm_a.generate_ed25519(&kn).unwrap();
        let region = b"hello safe bag";
        let sig_a = tpm_a.sign(&kn, region).unwrap();

        let sb = tpm_a.export_to_safebag(&kn, fake_cert_bytes(), pw).unwrap();
        let wire = sb.encode();
        let sb2 = crate::safe_bag::SafeBag::decode(&wire).unwrap();
        let cert_back = tpm_b.import_from_safebag(&sb2, &kn, pw).unwrap();
        assert_eq!(cert_back, fake_cert_bytes());

        // The imported key must produce identical signatures (Ed25519
        // is deterministic, so byte-equality holds).
        let sig_b = tpm_b.sign(&kn, region).unwrap();
        assert_eq!(sig_a, sig_b, "imported Ed25519 must produce same sig");
    }

    #[test]
    fn safebag_ecdsa_roundtrip() {
        use p256_ecdsa::SecretKey;

        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();
        let tpm_a = FileTpm::open(dir_a.path()).unwrap();
        let tpm_b = FileTpm::open(dir_b.path()).unwrap();
        let kn = name(&["bob", "KEY", "k1"]);
        let pw = b"transfer-password";

        // Generate an ECDSA key, save as SEC1 (FileTpm on-disk form).
        let sk = SecretKey::random(&mut rand_core_compat());
        let der = sk.to_sec1_der().unwrap();
        tpm_a
            .save_raw(&kn, TpmKeyKind::EcdsaP256, der.as_slice())
            .unwrap();

        // Export → wire → decode → import.
        let sb = tpm_a.export_to_safebag(&kn, fake_cert_bytes(), pw).unwrap();
        let wire = sb.encode();
        let sb2 = crate::safe_bag::SafeBag::decode(&wire).unwrap();
        tpm_b.import_from_safebag(&sb2, &kn, pw).unwrap();

        // ECDSA is non-deterministic so signatures won't byte-match;
        // verify both signatures against both public keys instead.
        let region = b"ecdsa safe bag region";
        let sig_b = tpm_b.sign(&kn, region).unwrap();

        // Recover the public key from tpm_a (the original) and verify
        // the imported tpm_b's signature against it. If the SafeBag
        // chain corrupted the key in any way, this verify fails.
        use p256_ecdsa::ecdsa::{Signature, VerifyingKey, signature::Verifier};
        use pkcs8::DecodePublicKey;
        let pk_a_der = tpm_a.public_key(&kn).unwrap();
        let vk_a = VerifyingKey::from_public_key_der(&pk_a_der).unwrap();
        let sig_obj = Signature::from_der(&sig_b).unwrap();
        vk_a.verify(region, &sig_obj)
            .expect("imported ECDSA signature must verify against original public key");
    }

    #[test]
    fn safebag_rsa_roundtrip() {
        use pkcs1::EncodeRsaPrivateKey;
        use rsa::RsaPrivateKey;

        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();
        let tpm_a = FileTpm::open(dir_a.path()).unwrap();
        let tpm_b = FileTpm::open(dir_b.path()).unwrap();
        let kn = name(&["carol", "KEY", "k1"]);
        let pw = b"transfer-password";

        // 1024-bit key for test speed.
        let mut rng = rand_core_compat();
        let sk = RsaPrivateKey::new(&mut rng, 1024).unwrap();
        let der = sk.to_pkcs1_der().unwrap();
        tpm_a
            .save_raw(&kn, TpmKeyKind::Rsa, der.as_bytes())
            .unwrap();

        let sb = tpm_a.export_to_safebag(&kn, fake_cert_bytes(), pw).unwrap();
        let wire = sb.encode();
        let sb2 = crate::safe_bag::SafeBag::decode(&wire).unwrap();
        tpm_b.import_from_safebag(&sb2, &kn, pw).unwrap();

        // RSA PKCS#1 v1.5 signing is deterministic — the imported key
        // must produce byte-identical signatures.
        let region = b"rsa safe bag region";
        let sig_a = tpm_a.sign(&kn, region).unwrap();
        let sig_b = tpm_b.sign(&kn, region).unwrap();
        assert_eq!(
            sig_a, sig_b,
            "imported RSA must produce same deterministic sig"
        );
    }

    #[test]
    fn safebag_wrong_password_fails_import() {
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();
        let tpm_a = FileTpm::open(dir_a.path()).unwrap();
        let tpm_b = FileTpm::open(dir_b.path()).unwrap();
        let kn = name(&["alice", "KEY", "k1"]);

        tpm_a.generate_ed25519(&kn).unwrap();
        let sb = tpm_a
            .export_to_safebag(&kn, fake_cert_bytes(), b"correct")
            .unwrap();

        match tpm_b.import_from_safebag(&sb, &kn, b"wrong") {
            Err(crate::safe_bag::SafeBagError::Pkcs8(_)) => {}
            other => panic!("expected Pkcs8 decrypt error, got {other:?}"),
        }
    }
}
