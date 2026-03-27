use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use thiserror::Error;

use ndn_packet::{Name, NameComponent};

use crate::{cert_cache::Certificate, signer::Ed25519Signer, TrustError};

// ─── Error ────────────────────────────────────────────────────────────────────

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

// ─── FilePib ──────────────────────────────────────────────────────────────────

/// File-based Public Info Base (PIB) for persistent key and certificate storage.
///
/// # Directory layout
/// ```text
/// <root>/
///   keys/<sha256>/
///     name.uri          # NDN name in URI form (human-readable)
///     private.key       # 32-byte raw Ed25519 seed
///     cert.ndnc         # NDNC-format certificate (optional)
///   anchors/<sha256>/
///     name.uri
///     cert.ndnc
/// ```
///
/// Key directories are named by the SHA-256 of the canonical name bytes to
/// avoid filesystem special-character issues.  The `name.uri` file provides
/// the human-readable name for `list` operations.
///
/// # Certificate format (NDNC v1)
/// ```text
/// [4]  magic "NDNC"
/// [1]  version = 1
/// [8]  valid_from  (u64 be, nanoseconds since Unix epoch)
/// [8]  valid_until (u64 be, nanoseconds since Unix epoch; u64::MAX = never)
/// [4]  pk_len      (u32 be)
/// [pk_len] public key bytes
/// ```
pub struct FilePib {
    root: PathBuf,
}

impl FilePib {
    /// Create or open a PIB at `root`, creating the directory tree if needed.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, PibError> {
        let root = root.into();
        std::fs::create_dir_all(root.join("keys"))?;
        std::fs::create_dir_all(root.join("anchors"))?;
        Ok(Self { root })
    }

    /// Open an existing PIB without creating it.  Returns an error if `root`
    /// does not contain an initialised PIB.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, PibError> {
        let root = root.into();
        if !root.join("keys").exists() {
            return Err(PibError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("PIB not found at {} (run `ndn-sec keygen` to create one)", root.display()),
            )));
        }
        Ok(Self { root })
    }

    /// Return the root directory of this PIB.
    pub fn root(&self) -> &Path {
        &self.root
    }

    // ─── Keys ─────────────────────────────────────────────────────────────────

    /// Generate a new Ed25519 key using a cryptographically random seed and
    /// persist it to the PIB.  Returns the signer so the caller can immediately
    /// issue a certificate without re-reading from disk.
    pub fn generate_ed25519(&self, key_name: &Name) -> Result<Ed25519Signer, PibError> {
        let seed = random_seed();
        let signer = Ed25519Signer::from_seed(&seed, key_name.clone());
        let dir = self.key_dir(key_name)?;
        std::fs::write(dir.join("private.key"), seed)?;
        std::fs::write(dir.join("name.uri"), name_to_uri(key_name))?;
        Ok(signer)
    }

    /// Load the signer for `key_name` from the PIB.
    pub fn get_signer(&self, key_name: &Name) -> Result<Ed25519Signer, PibError> {
        let dir = self.existing_key_dir(key_name)
            .ok_or_else(|| PibError::KeyNotFound(name_to_uri(key_name)))?;
        let seed_bytes = std::fs::read(dir.join("private.key"))?;
        if seed_bytes.len() != 32 {
            return Err(PibError::Corrupt("private.key must be exactly 32 bytes".into()));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);
        Ok(Ed25519Signer::from_seed(&seed, key_name.clone()))
    }

    /// Delete a key and its associated certificate from the PIB.
    pub fn delete_key(&self, key_name: &Name) -> Result<(), PibError> {
        if let Some(dir) = self.existing_key_dir(key_name) {
            std::fs::remove_dir_all(dir)?;
        }
        Ok(())
    }

    /// List all key names stored in the PIB.
    pub fn list_keys(&self) -> Result<Vec<Name>, PibError> {
        list_names_in(&self.root.join("keys"))
    }

    // ─── Certificates ─────────────────────────────────────────────────────────

    /// Persist a certificate for `key_name` in its key directory.
    pub fn store_cert(&self, key_name: &Name, cert: &Certificate) -> Result<(), PibError> {
        let dir = self.key_dir(key_name)?;
        std::fs::write(dir.join("cert.ndnc"), encode_cert(cert))?;
        Ok(())
    }

    /// Load the certificate for `key_name`.
    pub fn get_cert(&self, key_name: &Name) -> Result<Certificate, PibError> {
        let dir = self.existing_key_dir(key_name)
            .ok_or_else(|| PibError::CertNotFound(name_to_uri(key_name)))?;
        let data = std::fs::read(dir.join("cert.ndnc"))
            .map_err(|_| PibError::CertNotFound(name_to_uri(key_name)))?;
        decode_cert(Arc::new(key_name.clone()), &data)
    }

    // ─── Trust anchors ────────────────────────────────────────────────────────

    /// Persist a certificate as a trust anchor.
    pub fn add_trust_anchor(&self, key_name: &Name, cert: &Certificate) -> Result<(), PibError> {
        let dir = self.anchor_dir(key_name)?;
        std::fs::write(dir.join("cert.ndnc"), encode_cert(cert))?;
        std::fs::write(dir.join("name.uri"), name_to_uri(key_name))?;
        Ok(())
    }

    /// Remove a trust anchor from the PIB.
    pub fn remove_trust_anchor(&self, key_name: &Name) -> Result<(), PibError> {
        let dir = self.root.join("anchors").join(name_hash(key_name));
        if dir.exists() {
            std::fs::remove_dir_all(dir)?;
        }
        Ok(())
    }

    /// Load all trust anchor certificates from the PIB.
    pub fn trust_anchors(&self) -> Result<Vec<Certificate>, PibError> {
        let anchors_root = self.root.join("anchors");
        if !anchors_root.exists() { return Ok(vec![]); }
        let mut certs = Vec::new();
        for entry in std::fs::read_dir(&anchors_root)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_dir() { continue; }
            let name_uri = std::fs::read_to_string(path.join("name.uri"))
                .unwrap_or_default();
            let name = name_from_uri(name_uri.trim())
                .unwrap_or_else(|_| Name::root());
            if let Ok(data) = std::fs::read(path.join("cert.ndnc")) {
                if let Ok(cert) = decode_cert(Arc::new(name), &data) {
                    certs.push(cert);
                }
            }
        }
        Ok(certs)
    }

    /// List all trust anchor names stored in the PIB.
    pub fn list_anchors(&self) -> Result<Vec<Name>, PibError> {
        list_names_in(&self.root.join("anchors"))
    }

    // ─── Internal helpers ─────────────────────────────────────────────────────

    /// Return the key directory for `name`, creating it (and `name.uri`) if
    /// it does not already exist.
    fn key_dir(&self, name: &Name) -> Result<PathBuf, PibError> {
        let dir = self.root.join("keys").join(name_hash(name));
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    /// Return the key directory only if it already exists on disk.
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

// ─── Certificate encoding ─────────────────────────────────────────────────────

const NDNC_MAGIC: &[u8; 4] = b"NDNC";
const NDNC_VERSION: u8 = 1;

fn encode_cert(cert: &Certificate) -> Vec<u8> {
    let pk = cert.public_key.as_ref();
    let mut buf = Vec::with_capacity(25 + pk.len());
    buf.extend_from_slice(NDNC_MAGIC);
    buf.push(NDNC_VERSION);
    buf.extend_from_slice(&cert.valid_from.to_be_bytes());
    buf.extend_from_slice(&cert.valid_until.to_be_bytes());
    buf.extend_from_slice(&(pk.len() as u32).to_be_bytes());
    buf.extend_from_slice(pk);
    buf
}

fn decode_cert(name: Arc<Name>, data: &[u8]) -> Result<Certificate, PibError> {
    if data.len() < 25 {
        return Err(PibError::Corrupt("cert too short".into()));
    }
    if &data[..4] != NDNC_MAGIC {
        return Err(PibError::Corrupt("invalid magic bytes".into()));
    }
    // data[4] = version (reserved for future format changes)
    let valid_from  = u64::from_be_bytes(data[5..13].try_into().unwrap());
    let valid_until = u64::from_be_bytes(data[13..21].try_into().unwrap());
    let pk_len      = u32::from_be_bytes(data[21..25].try_into().unwrap()) as usize;
    if data.len() < 25 + pk_len {
        return Err(PibError::Corrupt("cert data truncated".into()));
    }
    let pk = Bytes::copy_from_slice(&data[25..25 + pk_len]);
    Ok(Certificate { name, public_key: pk, valid_from, valid_until })
}

// ─── Name helpers ─────────────────────────────────────────────────────────────

/// Compute a hex-encoded SHA-256 of the canonical name bytes for use as a
/// stable, filesystem-safe directory name.
fn name_hash(name: &Name) -> String {
    use ring::digest;
    let mut bytes: Vec<u8> = Vec::new();
    for comp in name.components() {
        let len = comp.value.len() as u32;
        bytes.extend_from_slice(&len.to_be_bytes());
        bytes.extend_from_slice(&comp.value);
    }
    let hash = digest::digest(&digest::SHA256, &bytes);
    hex_encode(hash.as_ref())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Convert a `Name` to its NDN URI representation.
///
/// Component bytes that are not URI-safe (alphanumeric, `-`, `.`, `_`, `~`)
/// are percent-encoded as `%XX`.
pub fn name_to_uri(name: &Name) -> String {
    if name.components().is_empty() { return "/".to_string(); }
    name.components().iter().map(|c| {
        let mut s = String::from("/");
        for &b in c.value.iter() {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                s.push(b as char);
            } else {
                s.push_str(&format!("%{:02X}", b));
            }
        }
        s
    }).collect()
}

/// Parse an NDN URI such as `/ndn/router1` or `/ndn/KEY/%08abc` into a `Name`.
pub fn name_from_uri(uri: &str) -> Result<Name, PibError> {
    if uri == "/" || uri.is_empty() {
        return Ok(Name::root());
    }
    let comps: Result<Vec<NameComponent>, PibError> = uri
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|seg| {
            let mut bytes: Vec<u8> = Vec::new();
            let seg = seg.as_bytes();
            let mut i = 0;
            while i < seg.len() {
                if seg[i] == b'%' && i + 2 < seg.len() {
                    let hi = hex_digit(seg[i + 1]).ok_or(PibError::InvalidName)?;
                    let lo = hex_digit(seg[i + 2]).ok_or(PibError::InvalidName)?;
                    bytes.push((hi << 4) | lo);
                    i += 3;
                } else {
                    bytes.push(seg[i]);
                    i += 1;
                }
            }
            Ok(NameComponent::generic(Bytes::from(bytes)))
        })
        .collect();
    Ok(Name::from_components(comps?))
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn list_names_in(dir: &Path) -> Result<Vec<Name>, PibError> {
    if !dir.exists() { return Ok(vec![]); }
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() { continue; }
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

// ─── Randomness ───────────────────────────────────────────────────────────────

fn random_seed() -> [u8; 32] {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    let mut seed = [0u8; 32];
    rng.fill(&mut seed).expect("system RNG unavailable");
    seed
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ndn_packet::NameComponent;
    use std::time::{SystemTime, UNIX_EPOCH};
    use crate::Signer;

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
    }

    #[test]
    fn get_signer_missing_key_errors() {
        let (_dir, pib) = tmp_pib();
        let name = key_name("missing");
        assert!(matches!(pib.get_signer(&name), Err(PibError::KeyNotFound(_))));
    }

    #[test]
    fn delete_key_removes_it() {
        let (_dir, pib) = tmp_pib();
        let name = key_name("delkey");
        pib.generate_ed25519(&name).unwrap();
        pib.delete_key(&name).unwrap();
        assert!(matches!(pib.get_signer(&name), Err(PibError::KeyNotFound(_))));
    }

    #[test]
    fn list_keys_returns_all() {
        let (_dir, pib) = tmp_pib();
        let n1 = key_name("key1");
        let n2 = key_name("key2");
        pib.generate_ed25519(&n1).unwrap();
        pib.generate_ed25519(&n2).unwrap();
        let mut keys = pib.list_keys().unwrap();
        keys.sort_by(|a, b| a.to_string().cmp(&b.to_string()));
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
            name:        Arc::new(name.clone()),
            public_key:  pk.clone(),
            valid_from:  now,
            valid_until: now + 365 * 24 * 3600 * 1_000_000_000u64,
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
        assert!(matches!(pib.get_cert(&name), Err(PibError::CertNotFound(_))));
    }

    #[test]
    fn trust_anchor_roundtrip() {
        let (_dir, pib) = tmp_pib();
        let name = key_name("anchor");
        let cert = Certificate {
            name:        Arc::new(name.clone()),
            public_key:  Bytes::from_static(&[0xAB; 32]),
            valid_from:  0,
            valid_until: u64::MAX,
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
            name:        Arc::new(name.clone()),
            public_key:  Bytes::from_static(&[1u8; 32]),
            valid_from:  0,
            valid_until: u64::MAX,
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
            name:        Arc::clone(&name),
            public_key:  Bytes::from_static(&[0x55; 32]),
            valid_from:  1_000_000,
            valid_until: 9_999_999,
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
}
