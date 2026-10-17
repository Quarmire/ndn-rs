//! Durable CA state: the issued certificates a CA serves on cert-fetch, its
//! revocation set and the one-time tokens already redeemed.
//! [`CaState::with_store`](crate::CaState::with_store) loads a [`CaSnapshot`]
//! at construction and writes every new issuance / revocation through the
//! [`CaStore`] before it takes effect, so a restarted CA keeps serving the
//! certs it issued and keeps refusing the ones it revoked;
//! [`TokenStore::with_store`](crate::TokenStore::with_store) does the same
//! for token redemptions, so a redeemed invite stays spent across restarts.

use std::path::{Path, PathBuf};

use ndn_security::secure_fs;

use crate::{ca::deserialize_cert, error::CertError};

/// What a [`CaStore`] holds, as loaded at CA startup.
#[derive(Debug, Default, Clone)]
pub struct CaSnapshot {
    /// `(cert name URI, signed cert Data wire)` for every issued certificate.
    pub issued: Vec<(String, Vec<u8>)>,
    /// Revoked certificate name URIs.
    pub revoked: Vec<String>,
}

/// Persistence seam for [`CaState`](crate::CaState).
pub trait CaStore: Send + Sync {
    fn load(&self) -> Result<CaSnapshot, CertError>;
    /// Durably record an issued certificate (`wire` is its signed Data TLV).
    fn record_issued(&self, cert_name: &str, wire: &[u8]) -> Result<(), CertError>;
    /// Durably record a revocation.
    fn record_revoked(&self, cert_name: &str) -> Result<(), CertError>;
    /// Hashes of the one-time tokens already redeemed (see
    /// [`TokenStore::with_store`](crate::TokenStore::with_store)). The
    /// default refuses: a store that cannot persist redemptions must not
    /// back a single-use token challenge.
    fn redeemed_tokens(&self) -> Result<Vec<String>, CertError> {
        Err(CertError::Storage(
            "this CA store does not persist token redemptions".into(),
        ))
    }
    /// Durably record that the token hashing to `token_hash` was redeemed.
    /// Only the hash is ever given to the store, never the token itself.
    fn record_redeemed_token(&self, token_hash: &str) -> Result<(), CertError> {
        let _ = token_hash;
        Err(CertError::Storage(
            "this CA store does not persist token redemptions".into(),
        ))
    }
}

/// Directory-backed [`CaStore`]. Layout under `dir` (the forwarder uses
/// `<pib_path>/ca`):
///
/// ```text
/// issued/<sha256(name-uri)>.data   signed certificate Data TLV
/// revoked/<sha256(name-uri)>       revoked certificate name URI
/// redeemed-tokens/<sha256(hash)>   hash of a redeemed one-time token
/// ```
///
/// Entry file names hash the name (long names would overflow a file name). Each
/// entry is written to a temporary file and renamed into place, so a crash never
/// leaves a truncated entry. Issued entries are keyed by the name the wire itself
/// decodes to; entries that fail to decode are skipped with a warning rather
/// than failing startup.
///
/// The store is owner-only (directories `0700`, entries `0600`, via
/// [`ndn_security::secure_fs`]): the redeemed-token hashes and the issuance
/// record are the CA's private state. Opening an existing store tightens
/// group/other-accessible entries and refuses ones owned by another user.
pub struct FileCaStore {
    dir: PathBuf,
}

impl FileCaStore {
    /// Open (creating if needed) a store rooted at `dir`.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, CertError> {
        let dir = dir.into();
        for sub in ["issued", "revoked", REDEEMED_TOKENS_DIR] {
            secure_fs::create_private_dir_all(&dir.join(sub)).map_err(|e| io_err(&dir.join(sub), e))?;
        }
        secure_fs::repair_tree(&dir).map_err(|e| io_err(&dir, e))?;
        Ok(Self { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), CertError> {
        secure_fs::write_private(path, bytes).map_err(|e| io_err(path, e))
    }
}

impl CaStore for FileCaStore {
    fn load(&self) -> Result<CaSnapshot, CertError> {
        let mut snapshot = CaSnapshot::default();

        let issued_dir = self.dir.join("issued");
        for entry in std::fs::read_dir(&issued_dir).map_err(|e| io_err(&issued_dir, e))? {
            let path = entry.map_err(|e| io_err(&issued_dir, e))?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("data") {
                continue;
            }
            let wire = std::fs::read(&path).map_err(|e| io_err(&path, e))?;
            match deserialize_cert(&wire) {
                Some(cert) => snapshot.issued.push((cert.name.to_string(), wire)),
                None => tracing::warn!(
                    path = %path.display(),
                    "CA store: skipping issued entry that does not decode as a certificate"
                ),
            }
        }

        let revoked_dir = self.dir.join("revoked");
        for entry in std::fs::read_dir(&revoked_dir).map_err(|e| io_err(&revoked_dir, e))? {
            let path = entry.map_err(|e| io_err(&revoked_dir, e))?.path();
            if path.extension().is_some() {
                continue;
            }
            let name = std::fs::read_to_string(&path).map_err(|e| io_err(&path, e))?;
            let name = name.trim();
            if !name.is_empty() {
                snapshot.revoked.push(name.to_string());
            }
        }

        Ok(snapshot)
    }

    fn record_issued(&self, cert_name: &str, wire: &[u8]) -> Result<(), CertError> {
        let path = self
            .dir
            .join("issued")
            .join(format!("{}.data", hex(cert_name)));
        Self::write_atomic(&path, wire)
    }

    fn record_revoked(&self, cert_name: &str) -> Result<(), CertError> {
        let path = self.dir.join("revoked").join(hex(cert_name));
        Self::write_atomic(&path, cert_name.as_bytes())
    }

    fn redeemed_tokens(&self) -> Result<Vec<String>, CertError> {
        let dir = self.dir.join(REDEEMED_TOKENS_DIR);
        let mut hashes = Vec::new();
        for entry in std::fs::read_dir(&dir).map_err(|e| io_err(&dir, e))? {
            let path = entry.map_err(|e| io_err(&dir, e))?.path();
            if path.extension().is_some() {
                continue;
            }
            let hash = std::fs::read_to_string(&path).map_err(|e| io_err(&path, e))?;
            let hash = hash.trim();
            if !hash.is_empty() {
                hashes.push(hash.to_string());
            }
        }
        Ok(hashes)
    }

    fn record_redeemed_token(&self, token_hash: &str) -> Result<(), CertError> {
        // The token hash is already a fixed-length hex digest, but hash it
        // again for the file name so a malformed value can never escape `dir`.
        let path = self.dir.join(REDEEMED_TOKENS_DIR).join(hex(token_hash));
        Self::write_atomic(&path, token_hash.as_bytes())
    }
}

const REDEEMED_TOKENS_DIR: &str = "redeemed-tokens";

fn hex(s: &str) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(s.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn io_err(path: &Path, e: std::io::Error) -> CertError {
    CertError::Storage(format!("{}: {e}", path.display()))
}
