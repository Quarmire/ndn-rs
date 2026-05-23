//! File-backed TPM (private-key store), wire-compatible with `ndn-cxx`'s
//! `tpm-file` backend for RSA and ECDSA-P256.
//!
//! RSA and ECDSA-P256 are bit-for-bit compatible with `ndnsec`. Ed25519 is
//! not supported by ndn-cxx's `tpm-file` (its `d2i_AutoPrivateKey` only
//! autodetects RSA and EC), so ndn-rs stores Ed25519 with a sentinel
//! filename suffix that ndn-cxx ignores:
//!
//! - `<HEX>.privkey`          — RSA / ECDSA, as ndn-cxx writes
//! - `<HEX>.privkey-ed25519`  — PKCS#8 Ed25519, ndn-rs-only
//!
//! Storage rules for `.privkey` files (matching ndn-cxx):
//! - Directory: `$HOME/.ndn/ndnsec-key-file/` (`TEST_HOME` overrides),
//!   created `0o700`.
//! - Filename: `hex(SHA256(name.wire_encode())).to_uppercase()` + suffix;
//!   the hash input is the TLV wire encoding, not the URI string.
//! - File body: base64 of the raw private-key DER (PKCS#1
//!   `RSAPrivateKey`, SEC1 `ECPrivateKey`, or PKCS#8 `PrivateKeyInfo` for
//!   the Ed25519 sentinel). No PEM, no encryption.
//! - Permissions: `chmod 0o400` on save.
//!
//! Public keys are recovered on demand from the private key; there are
//! no separate public-key files.

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use bytes::Bytes;
use ndn_packet::{Name, tlv_type};
use ndn_tlv::TlvWriter;
use sha2::{Digest, Sha256};

use crate::TrustError;

/// Errors returned by `FileTpm`; mapped to `TrustError` at the public boundary.
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

/// Algorithm of a key stored in the TPM; dispatched by file suffix and
/// (for `.privkey` files) by ASN.1 autodetection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmKeyKind {
    /// PKCS#1 `RSAPrivateKey` DER, ndn-cxx-compatible `.privkey`.
    Rsa,
    /// SEC1 `ECPrivateKey` DER (P-256), ndn-cxx-compatible `.privkey`.
    EcdsaP256,
    /// PKCS#8 `PrivateKeyInfo` DER, ndn-rs-only `.privkey-ed25519` sentinel.
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

/// Canonical TLV wire form of the Name; hashed to produce the filename.
fn name_wire_encode(name: &Name) -> Vec<u8> {
    let mut w = TlvWriter::new();
    w.write_nested(tlv_type::NAME, |w| {
        for c in name.components() {
            w.write_tlv(c.typ, &c.value);
        }
    });
    w.finish().to_vec()
}

/// Uppercase hex; matches `ndn-cxx`'s `transform/hex-encode`.
fn upper_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02X}"));
    }
    s
}

fn filename_stem(key_name: &Name) -> String {
    let wire = name_wire_encode(key_name);
    let digest = Sha256::digest(&wire);
    upper_hex(&digest)
}

fn b64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
fn b64_decode(s: &str) -> Result<Vec<u8>, FileTpmError> {
    use base64::Engine;
    // Strip embedded whitespace for ndn-cxx interop.
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(cleaned.as_bytes())
        .map_err(|e| FileTpmError::Base64(e.to_string()))
}

/// File-backed TPM. All operations take `&self` and perform an
/// independent open/read/close, so concurrent access is safe.
pub struct FileTpm {
    root: PathBuf,
}

impl FileTpm {
    /// Open or create a TPM at `root`, creating it with `0o700` if absent.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, FileTpmError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        #[cfg(unix)]
        {
            let _ = fs::set_permissions(&root, fs::Permissions::from_mode(0o700));
        }
        Ok(Self { root })
    }

    /// Default TPM at `$HOME/.ndn/ndnsec-key-file/`. `TEST_HOME` overrides.
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

    /// Locator string the PIB persists for this TPM. ndn-cxx requires
    /// either `tpm-file:` (default location) or `tpm-file:<absolute-path>`;
    /// we always emit the explicit form, which ndn-cxx accepts.
    pub fn locator(&self) -> String {
        format!("tpm-file:{}", self.root.display())
    }

    fn path_for(&self, key_name: &Name, kind: TpmKeyKind) -> PathBuf {
        let stem = filename_stem(key_name);
        self.root.join(format!("{stem}.{}", kind.extension()))
    }

    /// Save raw DER bytes (base64-encoded, `0o400`). `der` must already
    /// be in the algorithm's canonical form: PKCS#1 RSA, SEC1 ECDSA, or
    /// PKCS#8 Ed25519.
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
            fs::set_permissions(&path, fs::Permissions::from_mode(0o400))?;
        }
        Ok(())
    }

    /// Load raw DER bytes, trying `.privkey` (RSA / ECDSA autodetected)
    /// then `.privkey-ed25519`.
    pub fn load_raw(&self, key_name: &Name) -> Result<(TpmKeyKind, Vec<u8>), FileTpmError> {
        let stem = filename_stem(key_name);

        let primary = self.root.join(format!("{stem}.privkey"));
        if let Ok(body) = fs::read_to_string(&primary) {
            let der = b64_decode(&body)?;
            let kind = autodetect_pkcs1_or_sec1(&der)?;
            return Ok((kind, der));
        }

        let secondary = self.root.join(format!("{stem}.privkey-ed25519"));
        if let Ok(body) = fs::read_to_string(&secondary) {
            let der = b64_decode(&body)?;
            return Ok((TpmKeyKind::Ed25519, der));
        }

        Err(FileTpmError::KeyNotFound(format!("{key_name}")))
    }

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

    pub fn has_key(&self, key_name: &Name) -> bool {
        let stem = filename_stem(key_name);
        self.root.join(format!("{stem}.privkey")).exists()
            || self.root.join(format!("{stem}.privkey-ed25519")).exists()
    }

    /// Generate a fresh Ed25519 key under the sentinel suffix and return
    /// the 32-byte raw seed for `Ed25519Signer::from_seed`.
    pub fn generate_ed25519(&self, key_name: &Name) -> Result<[u8; 32], FileTpmError> {
        use ed25519_dalek::SigningKey;
        use ed25519_dalek::pkcs8::EncodePrivateKey;

        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|_| FileTpmError::Sign("rng failure".into()))?;
        let sk = SigningKey::from_bytes(&seed);

        let pkcs8 = sk
            .to_pkcs8_der()
            .map_err(|e| FileTpmError::InvalidKey(format!("ed25519 pkcs8: {e}")))?;
        self.save_raw(key_name, TpmKeyKind::Ed25519, pkcs8.as_bytes())?;
        Ok(seed)
    }

    /// Sign `region` with the key stored under `key_name`; algorithm is
    /// chosen by which file form exists on disk.
    pub fn sign(&self, key_name: &Name, region: &[u8]) -> Result<Bytes, FileTpmError> {
        let (kind, der) = self.load_raw(key_name)?;
        match kind {
            TpmKeyKind::Rsa => sign_rsa(&der, region),
            TpmKeyKind::EcdsaP256 => sign_ecdsa_p256(&der, region),
            TpmKeyKind::Ed25519 => sign_ed25519(&der, region),
        }
    }

    /// Public key for `key_name` in the PIB's `key_bits` format:
    /// SubjectPublicKeyInfo DER for RSA / ECDSA, 32 raw bytes for Ed25519.
    pub fn public_key(&self, key_name: &Name) -> Result<Vec<u8>, FileTpmError> {
        let (kind, der) = self.load_raw(key_name)?;
        match kind {
            TpmKeyKind::Rsa => public_key_rsa(&der),
            TpmKeyKind::EcdsaP256 => public_key_ecdsa_p256(&der),
            TpmKeyKind::Ed25519 => public_key_ed25519(&der),
        }
    }

    /// Export `key_name` as a [`crate::safe_bag::SafeBag`] bundled with
    /// `certificate`. The on-disk key is converted to PKCS#8 then
    /// encrypted via PBES2 + PBKDF2-HMAC-SHA256 + AES-256-CBC; the
    /// resulting `EncryptedPrivateKeyInfo` is wire-compatible with
    /// `ndnsec export`.
    ///
    /// Ed25519 SafeBags only roundtrip ndn-rs ↔ ndn-rs (ndn-cxx
    /// `tpm-file` has no Ed25519 path); RSA and ECDSA-P256 roundtrip
    /// with `ndnsec` in both directions.
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
            TpmKeyKind::Ed25519 => der,
        };
        crate::safe_bag::SafeBag::encrypt(certificate, &pkcs8_der, password)
    }

    /// Import a [`crate::safe_bag::SafeBag`] as a stored private key
    /// under `key_name`. Decrypts the `EncryptedPrivateKeyInfo` with
    /// `password`, dispatches on the PKCS#8 algorithm OID, converts to
    /// the FileTpm on-disk form, and writes it. Returns the cert Data
    /// wire bytes; persisting the cert is the PIB's responsibility.
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
            TpmKeyKind::Ed25519 => pkcs8_der,
        };
        self.save_raw(key_name, kind, &on_disk)?;
        Ok(safebag.certificate.clone())
    }
}

/// Dispatch a `.privkey` file by its first ASN.1 tags: PKCS#1 RSA has
/// `30 LL 02 01 vv 02 LL ...` (second INTEGER is the modulus); SEC1
/// ECDSA has `30 LL 02 01 01 04 LL ...` (OCTET STRING). The byte at the
/// second-element tag position selects: `02` -> RSA, `04` -> ECDSA.
fn autodetect_pkcs1_or_sec1(der: &[u8]) -> Result<TpmKeyKind, FileTpmError> {
    if der.len() < 6 || der[0] != 0x30 {
        return Err(FileTpmError::InvalidKey("not a DER SEQUENCE".into()));
    }
    let mut i = 1usize;
    let len_byte = der[i];
    i += 1;
    if len_byte & 0x80 != 0 {
        i += (len_byte & 0x7F) as usize;
    }
    // Expect inner `INTEGER version (02 01 vv)` then dispatch on next tag.
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
        0x02 => Ok(TpmKeyKind::Rsa),
        0x04 => Ok(TpmKeyKind::EcdsaP256),
        b => Err(FileTpmError::UnsupportedAlgorithm(format!(
            "unknown second-element tag 0x{b:02x}"
        ))),
    }
}

fn sign_rsa(pkcs1_der: &[u8], region: &[u8]) -> Result<Bytes, FileTpmError> {
    use pkcs1::DecodeRsaPrivateKey;
    // Use the sha2 re-export bundled by `rsa` 0.9 (digest 0.10) — the
    // top-level sha2 0.11 implements a different trait that
    // `Pkcs1v15Sign::new::<D>` won't accept.
    use rsa::sha2::{Digest, Sha256};
    use rsa::{Pkcs1v15Sign, RsaPrivateKey};

    let sk = RsaPrivateKey::from_pkcs1_der(pkcs1_der)
        .map_err(|e| FileTpmError::InvalidKey(format!("rsa pkcs1: {e}")))?;

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
    pk.to_public_key_der()
        .map(|d| d.as_bytes().to_vec())
        .map_err(|e| FileTpmError::InvalidKey(format!("rsa spki: {e}")))
}

/// Extract the 32-byte private scalar from a SEC1 `ECPrivateKey` DER
/// envelope (P-256). Bypasses `SigningKey::from_sec1_der`, which the
/// spki crate rejects on SEC1 blobs that omit the optional algorithm
/// parameters. Only the privateKey OCTET STRING is needed; the
/// parameters / publicKey fields are intentionally ignored.
pub(crate) fn parse_sec1_p256_priv_scalar(sec1: &[u8]) -> Result<[u8; 32], FileTpmError> {
    if sec1.len() < 9 || sec1[0] != 0x30 {
        return Err(FileTpmError::InvalidKey("not a SEC1 SEQUENCE".into()));
    }
    let mut i = 1usize;
    let len_byte = sec1[i];
    i += 1;
    if len_byte & 0x80 != 0 {
        i += (len_byte & 0x7F) as usize;
    }
    if i + 3 > sec1.len() || sec1[i] != 0x02 || sec1[i + 1] != 0x01 {
        return Err(FileTpmError::InvalidKey("expected version INTEGER".into()));
    }
    i += 3;
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

fn signing_key_from_sec1(sec1_der: &[u8]) -> Result<p256_ecdsa::ecdsa::SigningKey, FileTpmError> {
    use p256_ecdsa::ecdsa::SigningKey;
    let scalar = parse_sec1_p256_priv_scalar(sec1_der)?;
    SigningKey::from_bytes((&scalar).into())
        .map_err(|e| FileTpmError::InvalidKey(format!("ecdsa scalar: {e}")))
}

fn sign_ecdsa_p256(sec1_der: &[u8], region: &[u8]) -> Result<Bytes, FileTpmError> {
    use p256_ecdsa::ecdsa::{Signature, signature::Signer};

    let sk = signing_key_from_sec1(sec1_der)?;
    let sig: Signature = sk.sign(region);
    Ok(Bytes::from(sig.to_der().as_bytes().to_vec()))
}

fn public_key_ecdsa_p256(sec1_der: &[u8]) -> Result<Vec<u8>, FileTpmError> {
    let sk = signing_key_from_sec1(sec1_der)?;
    let point = sk.verifying_key().to_encoded_point(false);
    let sec1_bytes = point.as_bytes();
    debug_assert_eq!(sec1_bytes.len(), 65);
    debug_assert_eq!(sec1_bytes[0], 0x04);
    Ok(p256_spki_wrap(sec1_bytes))
}

/// Wrap a 65-byte P-256 uncompressed SEC1 point (`04 || X || Y`) in a
/// canonical SubjectPublicKeyInfo DER. Hand-built to avoid the
/// rustcrypto pkcs8 / elliptic-curve trait shuffle. Output is 91 bytes:
/// outer SEQUENCE (0x30 0x59) + algorithm SEQUENCE with id-ecPublicKey
/// and prime256v1 OIDs + BIT STRING containing the uncompressed point.
pub(crate) fn p256_spki_wrap(sec1_uncompressed: &[u8]) -> Vec<u8> {
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
