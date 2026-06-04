use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use thiserror::Error;

use ndn_packet::Name;

use crate::signer::{EcdsaP256Signer, Ed25519Signer};
use crate::{Signer, TrustError, cert_cache::Certificate};

#[derive(Debug, Error)]
pub enum PibError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("key not found in PIB: {0}")]
    KeyNotFound(String),
    #[error("certificate not found in PIB: {0}")]
    CertNotFound(String),
    #[error("corrupt PIB data: {0}")]
    Corrupt(String),
    #[error("invalid name")]
    InvalidName,
}

impl From<PibError> for TrustError {
    fn from(e: PibError) -> Self {
        TrustError::KeyStore(e.to_string())
    }
}

/// File-based Public Info Base for persistent key and certificate storage.
///
/// Directory layout:
/// ```text
/// <root>/
///   keys/<sha256>/
///     name.uri              # NDN name in URI form
///     private.pkcs8.der     # PKCS#8 PrivateKeyInfo DER (algorithm OID
///                           # carries Ed25519 / ECDSA-P256 / …)
///     private.key           # Legacy 32-byte raw Ed25519 seed — read
///                           # path kept for back-compat
///     cert.ndnc             # NDNC-format certificate (optional)
///   anchors/<sha256>/
///     name.uri
///     cert.ndnc
/// ```
///
/// Key directories use SHA-256 of the canonical name bytes to avoid
/// filesystem special characters; `name.uri` carries the human form.
///
/// NDNC v2 cert format: 4B magic `NDNC`, 1B version=2, 2B SignatureType
/// (BE), 8B valid_from (ns, BE), 8B valid_until (ns, BE; `u64::MAX` =
/// never), 4B pk_len (BE), then the public key bytes. V1 omits the
/// `sig_type` field and defaults to `SignatureEd25519` on read.
pub struct FilePib {
    root: PathBuf,
}

impl FilePib {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, PibError> {
        let root = root.into();
        std::fs::create_dir_all(root.join("keys"))?;
        std::fs::create_dir_all(root.join("anchors"))?;
        Ok(Self { root })
    }

    pub fn open(root: impl Into<PathBuf>) -> Result<Self, PibError> {
        let root = root.into();
        if !root.join("keys").exists() {
            return Err(PibError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "PIB not found at {} (run `ndn-sec keygen` to create one)",
                    root.display()
                ),
            )));
        }
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Generate a new Ed25519 key using a cryptographically random seed,
    /// persist it as PKCS#8 to the PIB, and return the concrete signer.
    /// Existing PIBs with the legacy 32-byte `private.key` format keep
    /// loading through the read path; this just writes the new format
    /// for fresh keys.
    pub fn generate_ed25519(&self, key_name: &Name) -> Result<Ed25519Signer, PibError> {
        let seed = random_seed();
        let signer = Ed25519Signer::from_seed(&seed, key_name.clone());
        let pkcs8 = ndn_safebag::ed25519_seed_to_pkcs8(&seed)
            .map_err(|e| PibError::Corrupt(format!("ed25519 → pkcs8: {e}")))?;
        let dir = self.key_dir(key_name)?;
        std::fs::write(dir.join("private.pkcs8.der"), &pkcs8)?;
        std::fs::write(dir.join("name.uri"), name_to_uri(key_name))?;
        Ok(signer)
    }

    /// Generate a new ECDSA-P256 key and persist it as PKCS#8. Use this
    /// when the identity must be verifiable by ndn-cxx / NFD, which
    /// don't support Ed25519.
    pub fn generate_ecdsa_p256(&self, key_name: &Name) -> Result<EcdsaP256Signer, PibError> {
        use p256_ecdsa::SecretKey;
        use p256_ecdsa::pkcs8::EncodePrivateKey;
        let sk = SecretKey::random(&mut rand_core::OsRng);
        let pkcs8 = sk
            .to_pkcs8_der()
            .map_err(|e| PibError::Corrupt(format!("ecdsa → pkcs8: {e}")))?;
        let signer = EcdsaP256Signer::from_pkcs8_der(pkcs8.as_bytes(), key_name.clone())
            .map_err(|e| PibError::Corrupt(format!("ecdsa from_pkcs8: {e}")))?;
        let dir = self.key_dir(key_name)?;
        std::fs::write(dir.join("private.pkcs8.der"), pkcs8.as_bytes())?;
        std::fs::write(dir.join("name.uri"), name_to_uri(key_name))?;
        Ok(signer)
    }

    /// Load the persisted signing key. The algorithm is dispatched at
    /// read time from the PKCS#8 OID, or for legacy keys from the raw
    /// 32-byte seed shape (defaults to Ed25519).
    pub fn get_signer(&self, key_name: &Name) -> Result<Arc<dyn Signer>, PibError> {
        let dir = self
            .existing_key_dir(key_name)
            .ok_or_else(|| PibError::KeyNotFound(name_to_uri(key_name)))?;

        if let Ok(pkcs8) = std::fs::read(dir.join("private.pkcs8.der")) {
            return signer_from_pkcs8(&pkcs8, key_name);
        }

        // Legacy 32-byte raw-Ed25519-seed format.
        match std::fs::read(dir.join("private.key")) {
            Ok(seed_bytes) => {
                if seed_bytes.len() != 32 {
                    return Err(PibError::Corrupt(
                        "private.key must be exactly 32 bytes (legacy Ed25519 seed)".into(),
                    ));
                }
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&seed_bytes);
                Ok(Arc::new(Ed25519Signer::from_seed(&seed, key_name.clone())))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(PibError::KeyNotFound(name_to_uri(key_name)))
            }
            Err(e) => Err(PibError::Io(e)),
        }
    }

    pub fn delete_key(&self, key_name: &Name) -> Result<(), PibError> {
        if let Some(dir) = self.existing_key_dir(key_name) {
            std::fs::remove_dir_all(dir)?;
        }
        Ok(())
    }

    pub fn list_keys(&self) -> Result<Vec<Name>, PibError> {
        list_names_in(&self.root.join("keys"))
    }

    pub fn store_cert(&self, key_name: &Name, cert: &Certificate) -> Result<(), PibError> {
        let dir = self.key_dir(key_name)?;
        std::fs::write(dir.join("cert.ndnc"), encode_cert(cert))?;
        Ok(())
    }

    /// Import an ndn-cxx-compatible `SafeBag` (TLV 0x80 wrapping a Data +
    /// EncryptedKey 0x81): decrypts PKCS#8 with `passphrase`, verifies the
    /// cert decodes and matches `key_name`, then persists both. Returns the
    /// decoded cert.
    pub fn store_safebag(
        &self,
        key_name: &Name,
        safebag_wire: &[u8],
        passphrase: &[u8],
    ) -> Result<Certificate, PibError> {
        use ndn_packet::Data;
        use ndn_safebag::SafeBag;
        let bag = SafeBag::decode(safebag_wire)
            .map_err(|e| PibError::Corrupt(format!("SafeBag decode: {e}")))?;
        let pkcs8 = bag
            .decrypt_pkcs8(passphrase)
            .map_err(|e| PibError::Corrupt(format!("SafeBag decrypt: {e}")))?;
        let cert_data = Data::decode(Bytes::copy_from_slice(&bag.certificate))
            .map_err(|e| PibError::Corrupt(format!("cert Data decode: {e:?}")))?;
        let cert = Certificate::decode(&cert_data)
            .map_err(|e| PibError::Corrupt(format!("Certificate decode: {e}")))?;
        if *cert.name != *key_name {
            return Err(PibError::Corrupt(format!(
                "SafeBag cert name {} does not match requested key {}",
                cert.name, key_name
            )));
        }
        // Fail fast on unsupported algorithms before writing to disk.
        let _ = signer_from_pkcs8(&pkcs8, key_name)?;
        let dir = self.key_dir(key_name)?;
        std::fs::write(dir.join("private.pkcs8.der"), &pkcs8)?;
        std::fs::write(dir.join("name.uri"), name_to_uri(key_name))?;
        std::fs::write(dir.join("cert.ndnc"), encode_cert(&cert))?;
        Ok(cert)
    }

    /// Read the stored private key as PKCS#8 `PrivateKeyInfo` DER. Handles
    /// both the current `private.pkcs8.der` format and the legacy 32-byte
    /// raw Ed25519 seed (re-encoded to PKCS#8 on the fly). The returned
    /// bytes are the *unencrypted* secret — callers must not persist or log
    /// them; [`Self::export_safebag`] wraps them under a passphrase.
    pub fn export_pkcs8(&self, key_name: &Name) -> Result<Vec<u8>, PibError> {
        let dir = self
            .existing_key_dir(key_name)
            .ok_or_else(|| PibError::KeyNotFound(name_to_uri(key_name)))?;
        if let Ok(pkcs8) = std::fs::read(dir.join("private.pkcs8.der")) {
            return Ok(pkcs8);
        }
        // Legacy 32-byte raw-Ed25519-seed format.
        let seed_bytes = std::fs::read(dir.join("private.key"))
            .map_err(|_| PibError::KeyNotFound(name_to_uri(key_name)))?;
        if seed_bytes.len() != 32 {
            return Err(PibError::Corrupt(
                "private.key must be exactly 32 bytes (legacy Ed25519 seed)".into(),
            ));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);
        ndn_safebag::ed25519_seed_to_pkcs8(&seed)
            .map_err(|e| PibError::Corrupt(format!("legacy seed → pkcs8: {e}")))
    }

    /// Export a stored identity as an ndn-cxx-compatible `SafeBag` (TLV
    /// 0x80): a freshly self-signed certificate Data wrapping the public
    /// key, alongside the PKCS#8 private key encrypted under `passphrase`
    /// (PBES2 / PBKDF2-HMAC-SHA256 + AES-256-CBC, matching `ndnsec export`).
    ///
    /// Works for both Ed25519 and ECDSA-P256 keys — the algorithm is taken
    /// from the stored PKCS#8 OID via [`Self::get_signer`]. The embedded
    /// certificate is signed *now* with the key itself, so the SafeBag is a
    /// self-contained, verifiable bundle even when the PIB only kept the
    /// compact NDNC cert summary.
    pub fn export_safebag(&self, key_name: &Name, passphrase: &[u8]) -> Result<Vec<u8>, PibError> {
        use ndn_safebag::SafeBag;
        let pkcs8 = self.export_pkcs8(key_name)?;
        let signer = self.get_signer(key_name)?;
        let cert = self.get_cert(key_name)?;
        // Re-issue a self-signed cert Data so the SafeBag carries a real,
        // verifiable Data TLV (the on-disk NDNC summary drops the signature).
        let cert_wire = futures::executor::block_on(crate::manager::encode_cert_data(
            key_name,
            &cert.public_key,
            signer.as_ref(),
            cert.valid_from,
            cert.valid_until,
        ))
        .map_err(|e| PibError::Corrupt(format!("re-sign cert for export: {e}")))?;
        let bag = SafeBag::encrypt(cert_wire, &pkcs8, passphrase)
            .map_err(|e| PibError::Corrupt(format!("SafeBag encrypt: {e}")))?;
        Ok(bag.encode().to_vec())
    }

    pub fn get_cert(&self, key_name: &Name) -> Result<Certificate, PibError> {
        let dir = self
            .existing_key_dir(key_name)
            .ok_or_else(|| PibError::CertNotFound(name_to_uri(key_name)))?;
        let data = std::fs::read(dir.join("cert.ndnc"))
            .map_err(|_| PibError::CertNotFound(name_to_uri(key_name)))?;
        decode_cert(Arc::new(key_name.clone()), &data)
    }

    pub fn add_trust_anchor(&self, key_name: &Name, cert: &Certificate) -> Result<(), PibError> {
        if !cert.is_valid_now() {
            return Err(PibError::Corrupt(format!(
                "trust anchor {} is expired or not yet valid",
                cert.name
            )));
        }
        let dir = self.anchor_dir(key_name)?;
        std::fs::write(dir.join("cert.ndnc"), encode_cert(cert))?;
        std::fs::write(dir.join("name.uri"), name_to_uri(key_name))?;
        Ok(())
    }

    pub fn remove_trust_anchor(&self, key_name: &Name) -> Result<(), PibError> {
        let dir = self.root.join("anchors").join(name_hash(key_name));
        if dir.exists() {
            std::fs::remove_dir_all(dir)?;
        }
        Ok(())
    }

    pub fn trust_anchors(&self) -> Result<Vec<Certificate>, PibError> {
        let anchors_root = self.root.join("anchors");
        if !anchors_root.exists() {
            return Ok(vec![]);
        }
        let mut certs = Vec::new();
        for entry in std::fs::read_dir(&anchors_root)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let name_uri = std::fs::read_to_string(path.join("name.uri")).unwrap_or_default();
            let name = name_from_uri(name_uri.trim()).unwrap_or_else(|_| Name::root());
            if let Ok(data) = std::fs::read(path.join("cert.ndnc"))
                && let Ok(cert) = decode_cert(Arc::new(name), &data)
            {
                certs.push(cert);
            }
        }
        Ok(certs)
    }

    pub fn list_anchors(&self) -> Result<Vec<Name>, PibError> {
        list_names_in(&self.root.join("anchors"))
    }

    /// Key directory for `name`, creating it on demand.
    fn key_dir(&self, name: &Name) -> Result<PathBuf, PibError> {
        let dir = self.root.join("keys").join(name_hash(name));
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    /// Key directory only if already on disk.
    fn existing_key_dir(&self, name: &Name) -> Option<PathBuf> {
        let dir = self.root.join("keys").join(name_hash(name));
        if dir.exists() { Some(dir) } else { None }
    }

    fn anchor_dir(&self, name: &Name) -> Result<PathBuf, PibError> {
        let dir = self.root.join("anchors").join(name_hash(name));
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }
}

const NDNC_MAGIC: &[u8; 4] = b"NDNC";
const NDNC_VERSION_V1: u8 = 1;
const NDNC_VERSION_V2: u8 = 2;

/// Dispatch a stored PKCS#8 PrivateKeyInfo DER to the concrete signer
/// matching its algorithm OID.
fn signer_from_pkcs8(pkcs8: &[u8], key_name: &Name) -> Result<Arc<dyn Signer>, PibError> {
    use pkcs8::PrivateKeyInfo;
    let pki = PrivateKeyInfo::try_from(pkcs8)
        .map_err(|e| PibError::Corrupt(format!("parse PrivateKeyInfo: {e}")))?;
    let oid = pki.algorithm.oid.to_string();
    match oid.as_str() {
        // Ed25519 OID (RFC 8410).
        "1.3.101.112" => {
            let seed = ndn_safebag::pkcs8_to_ed25519_seed(pkcs8)
                .map_err(|e| PibError::Corrupt(format!("pkcs8 → ed25519 seed: {e}")))?;
            Ok(Arc::new(Ed25519Signer::from_seed(&seed, key_name.clone())))
        }
        // ECDSA with namedCurve parameters.
        "1.2.840.10045.2.1" => {
            let signer = EcdsaP256Signer::from_pkcs8_der(pkcs8, key_name.clone())
                .map_err(|e| PibError::Corrupt(format!("pkcs8 → ecdsa-p256: {e}")))?;
            Ok(Arc::new(signer))
        }
        other => Err(PibError::Corrupt(format!(
            "stored key uses unsupported algorithm OID {other} \
             (only Ed25519 / ECDSA-P256 wired today)"
        ))),
    }
}

fn encode_cert(cert: &Certificate) -> Vec<u8> {
    let pk = cert.public_key.as_ref();
    // PIB-on-disk SignatureType is u16 — wider codes (`Other(u64)`)
    // are truncated.
    let sig_type_code: u16 = (cert.sig_type.code() & 0xFFFF) as u16;
    let mut buf = Vec::with_capacity(27 + pk.len());
    buf.extend_from_slice(NDNC_MAGIC);
    buf.push(NDNC_VERSION_V2);
    buf.extend_from_slice(&sig_type_code.to_be_bytes());
    buf.extend_from_slice(&cert.valid_from.to_be_bytes());
    buf.extend_from_slice(&cert.valid_until.to_be_bytes());
    buf.extend_from_slice(&(pk.len() as u32).to_be_bytes());
    buf.extend_from_slice(pk);
    buf
}

fn sig_type_from_code(code: u16) -> ndn_packet::SignatureType {
    ndn_packet::SignatureType::from_code(code as u64)
}

/// Decode an NDNC-format certificate. Handles both v1 (Ed25519-only,
/// no sig_type field) and v2 layouts.
pub fn decode_cert(name: Arc<Name>, data: &[u8]) -> Result<Certificate, PibError> {
    if data.len() < 5 {
        return Err(PibError::Corrupt("cert too short".into()));
    }
    if &data[..4] != NDNC_MAGIC {
        return Err(PibError::Corrupt("invalid magic bytes".into()));
    }
    match data[4] {
        NDNC_VERSION_V1 => {
            if data.len() < 25 {
                return Err(PibError::Corrupt("v1 cert too short".into()));
            }
            let valid_from = u64::from_be_bytes(data[5..13].try_into().unwrap());
            let valid_until = u64::from_be_bytes(data[13..21].try_into().unwrap());
            let pk_len = u32::from_be_bytes(data[21..25].try_into().unwrap()) as usize;
            if data.len() < 25 + pk_len {
                return Err(PibError::Corrupt("v1 cert data truncated".into()));
            }
            let pk = Bytes::copy_from_slice(&data[25..25 + pk_len]);
            Ok(Certificate {
                name,
                public_key: pk,
                valid_from,
                valid_until,
                issuer: None,
                signed_region: None,
                sig_value: None,
                // v1 predates sig_type — default Ed25519.
                sig_type: ndn_packet::SignatureType::SignatureEd25519,
            })
        }
        NDNC_VERSION_V2 => {
            if data.len() < 27 {
                return Err(PibError::Corrupt("v2 cert too short".into()));
            }
            let sig_type_code = u16::from_be_bytes(data[5..7].try_into().unwrap());
            let valid_from = u64::from_be_bytes(data[7..15].try_into().unwrap());
            let valid_until = u64::from_be_bytes(data[15..23].try_into().unwrap());
            let pk_len = u32::from_be_bytes(data[23..27].try_into().unwrap()) as usize;
            if data.len() < 27 + pk_len {
                return Err(PibError::Corrupt("v2 cert data truncated".into()));
            }
            let pk = Bytes::copy_from_slice(&data[27..27 + pk_len]);
            Ok(Certificate {
                name,
                public_key: pk,
                valid_from,
                valid_until,
                issuer: None,
                signed_region: None,
                sig_value: None,
                sig_type: sig_type_from_code(sig_type_code),
            })
        }
        v => Err(PibError::Corrupt(format!("unknown NDNC version {v}"))),
    }
}

/// Compute a hex-encoded SHA-256 of the canonical name bytes for use as a
/// stable, filesystem-safe directory name.
fn name_hash(name: &Name) -> String {
    use sha2::Digest;
    let mut bytes: Vec<u8> = Vec::new();
    for comp in name.components() {
        let len = comp.value.len() as u32;
        bytes.extend_from_slice(&len.to_be_bytes());
        bytes.extend_from_slice(&comp.value);
    }
    let hash = sha2::Sha256::digest(&bytes);
    hex_encode(&hash)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Convert a `Name` to its NDN URI form. Non-URI-safe bytes are
/// percent-encoded as `%XX`.
pub fn name_to_uri(name: &Name) -> String {
    if name.components().is_empty() {
        return "/".to_string();
    }
    // Use the canonical NDN URI form so *typed* components (version,
    // timestamp, segment, …) round-trip. The previous value-only encoding
    // dropped the component type, so an anchor whose cert name carried a
    // typed version (`…/self/v=0`) reloaded as a *generic* component and no
    // longer matched the on-wire KeyLocator — signed commands then failed
    // validation with "signing certificate not yet resolved".
    name.to_string()
}

pub fn name_from_uri(uri: &str) -> Result<Name, PibError> {
    if uri == "/" || uri.is_empty() {
        return Ok(Name::root());
    }
    // Canonical parse — the inverse of [`name_to_uri`]. Round-trips typed
    // components so a reloaded anchor name equals the original (and the
    // on-wire KeyLocator). Legacy value-only `name.uri` files (all-generic
    // names) still parse identically.
    uri.parse::<Name>().map_err(|_| PibError::InvalidName)
}

fn list_names_in(dir: &Path) -> Result<Vec<Name>, PibError> {
    if !dir.exists() {
        return Ok(vec![]);
    }
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let uri_path = path.join("name.uri");
        if uri_path.exists() {
            let uri = std::fs::read_to_string(&uri_path)?;
            if let Ok(name) = name_from_uri(uri.trim()) {
                names.push(name);
            }
        }
    }
    Ok(names)
}

fn random_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("system RNG unavailable");
    seed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Signer;
    use bytes::Bytes;
    use ndn_packet::NameComponent;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn key_name(s: &str) -> Name {
        Name::from_components([NameComponent::generic(Bytes::copy_from_slice(s.as_bytes()))])
    }

    fn tmp_pib() -> (tempfile::TempDir, FilePib) {
        let dir = tempfile::tempdir().unwrap();
        let pib = FilePib::new(dir.path()).unwrap();
        (dir, pib)
    }

    fn now_ns() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }

    #[test]
    fn create_pib_creates_dirs() {
        let dir = tempfile::tempdir().unwrap();
        FilePib::new(dir.path()).unwrap();
        assert!(dir.path().join("keys").exists());
        assert!(dir.path().join("anchors").exists());
    }

    #[test]
    fn open_nonexistent_pib_errors() {
        let r = FilePib::open("/tmp/ndn_pib_nonexistent_xyz_abc");
        assert!(r.is_err());
    }

    #[test]
    fn generate_and_retrieve_signer() {
        let (_dir, pib) = tmp_pib();
        let name = key_name("mykey");
        pib.generate_ed25519(&name).unwrap();
        let signer = pib.get_signer(&name).unwrap();
        assert_eq!(signer.key_name(), &name);
        assert_eq!(
            signer.sig_type(),
            ndn_packet::SignatureType::SignatureEd25519
        );
    }

    #[test]
    fn generate_and_retrieve_ecdsa_signer() {
        let (_dir, pib) = tmp_pib();
        let name = key_name("ecdsa-key");
        let signer = pib.generate_ecdsa_p256(&name).unwrap();
        assert_eq!(
            signer.sig_type(),
            ndn_packet::SignatureType::SignatureSha256WithEcdsa
        );

        let loaded = pib.get_signer(&name).unwrap();
        assert_eq!(loaded.key_name(), &name);
        assert_eq!(
            loaded.sig_type(),
            ndn_packet::SignatureType::SignatureSha256WithEcdsa
        );

        let sig = loaded.sign_sync(b"hello pib ecdsa").expect("sign");
        assert!(!sig.is_empty(), "ECDSA signature must not be empty");
    }

    /// Legacy `private.key` (32-byte raw Ed25519 seed, no PKCS#8) still
    /// opens via the back-compat fallback.
    #[test]
    fn legacy_raw_seed_file_still_loads_as_ed25519() {
        let (_dir, pib) = tmp_pib();
        let name = key_name("legacy");
        let dir = pib.key_dir(&name).unwrap();
        let seed = [0xCDu8; 32];
        std::fs::write(dir.join("private.key"), seed).unwrap();
        std::fs::write(dir.join("name.uri"), name_to_uri(&name)).unwrap();

        let loaded = pib.get_signer(&name).unwrap();
        assert_eq!(loaded.key_name(), &name);
        assert_eq!(
            loaded.sig_type(),
            ndn_packet::SignatureType::SignatureEd25519
        );
    }

    #[test]
    fn get_signer_missing_key_errors() {
        let (_dir, pib) = tmp_pib();
        let name = key_name("missing");
        assert!(matches!(
            pib.get_signer(&name),
            Err(PibError::KeyNotFound(_))
        ));
    }

    #[test]
    fn delete_key_removes_it() {
        let (_dir, pib) = tmp_pib();
        let name = key_name("delkey");
        pib.generate_ed25519(&name).unwrap();
        pib.delete_key(&name).unwrap();
        assert!(matches!(
            pib.get_signer(&name),
            Err(PibError::KeyNotFound(_))
        ));
    }

    #[test]
    fn list_keys_returns_all() {
        let (_dir, pib) = tmp_pib();
        let n1 = key_name("key1");
        let n2 = key_name("key2");
        pib.generate_ed25519(&n1).unwrap();
        pib.generate_ed25519(&n2).unwrap();
        let mut keys = pib.list_keys().unwrap();
        keys.sort_by_key(|a| a.to_string());
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn store_and_get_cert() {
        let (_dir, pib) = tmp_pib();
        let name = key_name("certkey");
        let signer = pib.generate_ed25519(&name).unwrap();
        let pk = Bytes::copy_from_slice(&signer.public_key_bytes());
        let now = now_ns();
        let cert = Certificate {
            name: Arc::new(name.clone()),
            public_key: pk.clone(),
            valid_from: now,
            valid_until: now + 365 * 24 * 3600 * 1_000_000_000u64,
            issuer: None,
            signed_region: None,
            sig_value: None,
            sig_type: ndn_packet::SignatureType::SignatureEd25519,
        };
        pib.store_cert(&name, &cert).unwrap();
        let loaded = pib.get_cert(&name).unwrap();
        assert_eq!(loaded.public_key, pk);
        assert_eq!(loaded.valid_from, now);
    }

    #[test]
    fn get_cert_missing_errors() {
        let (_dir, pib) = tmp_pib();
        let name = key_name("nocert");
        pib.generate_ed25519(&name).unwrap();
        assert!(matches!(
            pib.get_cert(&name),
            Err(PibError::CertNotFound(_))
        ));
    }

    #[test]
    fn trust_anchor_roundtrip() {
        let (_dir, pib) = tmp_pib();
        let name = key_name("anchor");
        let cert = Certificate {
            name: Arc::new(name.clone()),
            public_key: Bytes::from_static(&[0xAB; 32]),
            valid_from: 0,
            valid_until: u64::MAX,
            issuer: None,
            signed_region: None,
            sig_value: None,
            sig_type: ndn_packet::SignatureType::SignatureEd25519,
        };
        pib.add_trust_anchor(&name, &cert).unwrap();
        let anchors = pib.trust_anchors().unwrap();
        assert_eq!(anchors.len(), 1);
        assert_eq!(anchors[0].public_key.as_ref(), &[0xABu8; 32]);
    }

    #[test]
    fn list_anchors_returns_names() {
        let (_dir, pib) = tmp_pib();
        let name = key_name("ta");
        let cert = Certificate {
            name: Arc::new(name.clone()),
            public_key: Bytes::from_static(&[1u8; 32]),
            valid_from: 0,
            valid_until: u64::MAX,
            issuer: None,
            signed_region: None,
            sig_value: None,
            sig_type: ndn_packet::SignatureType::SignatureEd25519,
        };
        pib.add_trust_anchor(&name, &cert).unwrap();
        let names = pib.list_anchors().unwrap();
        assert_eq!(names.len(), 1);
    }

    #[test]
    fn name_uri_roundtrip_ascii() {
        let name = Name::from_components([
            NameComponent::generic(Bytes::from_static(b"ndn")),
            NameComponent::generic(Bytes::from_static(b"router1")),
        ]);
        let uri = name_to_uri(&name);
        assert_eq!(uri, "/ndn/router1");
        let back = name_from_uri(&uri).unwrap();
        assert_eq!(back, name);
    }

    #[test]
    fn name_uri_roundtrip_binary() {
        let name = Name::from_components([
            NameComponent::generic(Bytes::from_static(b"ndn")),
            NameComponent::generic(Bytes::from(vec![0x08, 0x01, 0xFF])),
        ]);
        let uri = name_to_uri(&name);
        let back = name_from_uri(&uri).unwrap();
        assert_eq!(back, name);
    }

    #[test]
    fn root_name_uri() {
        let uri = name_to_uri(&Name::root());
        assert_eq!(uri, "/");
        let back = name_from_uri(&uri).unwrap();
        assert_eq!(back, Name::root());
    }

    #[test]
    fn cert_encode_decode_roundtrip() {
        let name = Arc::new(key_name("enc"));
        let cert = Certificate {
            name: Arc::clone(&name),
            public_key: Bytes::from_static(&[0x55; 32]),
            valid_from: 1_000_000,
            valid_until: 9_999_999,
            issuer: None,
            signed_region: None,
            sig_value: None,
            sig_type: ndn_packet::SignatureType::SignatureEd25519,
        };
        let encoded = encode_cert(&cert);
        let decoded = decode_cert(Arc::clone(&name), &encoded).unwrap();
        assert_eq!(decoded.public_key, cert.public_key);
        assert_eq!(decoded.valid_from, cert.valid_from);
        assert_eq!(decoded.valid_until, cert.valid_until);
    }

    #[test]
    fn corrupt_cert_errors() {
        let name = Arc::new(key_name("bad"));
        assert!(decode_cert(name.clone(), b"").is_err());
        assert!(decode_cert(name.clone(), b"BADC\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00").is_err());
    }

    #[test]
    fn store_safebag_rejects_garbage_wire() {
        let (_dir, pib) = tmp_pib();
        let name = key_name("alice");
        let err = pib
            .store_safebag(&name, b"\x00not-a-safebag", b"pw")
            .unwrap_err();
        assert!(matches!(err, PibError::Corrupt(_)));
        // No partial state on disk — the rejected import must not
        // leave a half-written keys/<hash>/ behind.
        assert!(pib.existing_key_dir(&name).is_none());
    }

    // Positive round-trip coverage for `store_safebag` lives in
    // `crates/ndn-mgmt/tests/` — the witness builds a real
    // SafeBag from a generated identity, fires the
    // `security/safebag-import` verb, and asserts the PIB exposes
    // the key after import. Keeping this unit-test surface narrow to
    // the error paths avoids duplicating cert-wire helpers across
    // crates.
}
