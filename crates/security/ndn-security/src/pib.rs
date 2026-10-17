use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use thiserror::Error;

use ndn_packet::Name;

use crate::signer::{EcdsaP256Signer, Ed25519Signer};
use crate::{Signer, TrustError, cert_cache::Certificate, secure_fs};

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
///     certs/<sha256>.data   # each certificate of the key as signed Data,
///                           # named `<key>/<issuer-id>/<version>`
///     cert.ndnc             # NDNC summary of a certificate that has no
///                           # signed wire (and legacy PIBs' summary)
///     cert.data             # legacy: the issued certificate as signed Data
///                           # (read only; new certificates go to certs/)
///   anchors/<sha256>/
///     name.uri
///     cert.ndnc
///   root/                   # a namespace root device's root store, kept by
///     store.toml            # `ndn_cert::root_store`: where the root key
///     root.safebag          # lives, and its passphrase-sealed SafeBag
///   default-identity        # the node's default identity, NDN URI (optional)
/// ```
///
/// A key holds any number of certificates (NDN Certificate Format v2): a
/// renewal adds one under a new name while the one it replaces stays valid.
/// [`get_cert`](Self::get_cert) returns the newest valid one,
/// [`certs`](Self::certs) all of them. PIBs written by earlier releases keep
/// loading: their `cert.data` / `cert.ndnc` (a certificate named after its
/// key) count as one more certificate of the key and are never rewritten.
///
/// Key directories use SHA-256 of the canonical name bytes to avoid
/// filesystem special characters; `name.uri` carries the human form.
///
/// Permissions: the whole PIB is owner-only — directories `0700`, files
/// `0600`, each file created with its mode before any content is written
/// (see [`crate::secure_fs`]). [`new`](Self::new) and [`open`](Self::open)
/// tighten group/other-accessible entries of an existing PIB (with a warning)
/// and refuse one containing entries owned by another user.
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
        secure_fs::create_private_dir_all(&root.join("keys"))?;
        secure_fs::create_private_dir_all(&root.join("anchors"))?;
        secure_fs::repair_tree(&root)?;
        Ok(Self { root })
    }

    pub fn open(root: impl Into<PathBuf>) -> Result<Self, PibError> {
        let root = root.into();
        // NotFound only when there is no PIB: a PIB this user may not read
        // is reported as that, not as missing.
        if let Err(e) = std::fs::metadata(root.join("keys")) {
            return Err(PibError::Io(if e.kind() == std::io::ErrorKind::NotFound {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!(
                        "PIB not found at {} (run `ndn-sec keygen` to create one)",
                        root.display()
                    ),
                )
            } else {
                std::io::Error::new(e.kind(), format!("PIB at {}: {e}", root.display()))
            }));
        }
        secure_fs::repair_tree(&root)?;
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
        let pkcs8 = crate::safebag::ed25519_seed_to_pkcs8(&seed)
            .map_err(|e| PibError::Corrupt(format!("ed25519 → pkcs8: {e}")))?;
        let dir = self.key_dir(key_name)?;
        secure_fs::write_private(&dir.join("private.pkcs8.der"), &pkcs8)?;
        secure_fs::write_private(&dir.join("name.uri"), name_to_uri(key_name))?;
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
        secure_fs::write_private(&dir.join("private.pkcs8.der"), pkcs8.as_bytes())?;
        secure_fs::write_private(&dir.join("name.uri"), name_to_uri(key_name))?;
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

    /// Delete `key_name` with its certificates. Its private key file is
    /// overwritten before removal ([`secure_fs::shred_file`]).
    pub fn delete_key(&self, key_name: &Name) -> Result<(), PibError> {
        if let Some(dir) = self.existing_key_dir(key_name) {
            for secret in ["private.pkcs8.der", "private.key"] {
                secure_fs::shred_file(&dir.join(secret))?;
            }
            std::fs::remove_dir_all(dir)?;
        }
        Ok(())
    }

    /// Whether the PIB holds the private key of `key_name` (without reading
    /// it).
    pub fn has_private_key(&self, key_name: &Name) -> bool {
        self.existing_key_dir(key_name).is_some_and(|dir| {
            dir.join("private.pkcs8.der").is_file() || dir.join("private.key").is_file()
        })
    }

    pub fn list_keys(&self) -> Result<Vec<Name>, PibError> {
        list_names_in(&self.root.join("keys"))
    }

    /// Keys stored for `identity`, sorted by name: every key whose name
    /// starts with `<identity>/KEY/`. Covers each naming form in use —
    /// `<identity>/KEY/<keyid>`, `/KEY/root`, legacy `/KEY/self`, and
    /// the cert-named `<identity>/KEY/<keyid>/self/v=0` earlier `ndn-sec keygen` releases stored.
    pub fn identity_keys(&self, identity: &Name) -> Result<Vec<Name>, PibError> {
        let mut keys: Vec<Name> = self
            .list_keys()?
            .into_iter()
            .filter(|k| crate::manager::is_key_of(k, identity))
            .collect();
        keys.sort();
        Ok(keys)
    }

    /// The key `identity` signs with, `None` if it has none. Among its keys
    /// ([`identity_keys`](Self::identity_keys)) the one whose stored
    /// certificate is valid now and was issued most recently wins — a
    /// freshly enrolled key supersedes an older self-signed one. Without a
    /// currently valid certificate, the first key in name order is used.
    pub fn default_key(&self, identity: &Name) -> Result<Option<Name>, PibError> {
        let keys = self.identity_keys(identity)?;
        let certified = keys
            .iter()
            .filter_map(|k| {
                let cert = self.get_cert(k).ok()?;
                cert.is_valid_now().then_some((cert.valid_from, k))
            })
            // Latest `valid_from`; on a tie the smaller name wins.
            .max_by(|a, b| a.0.cmp(&b.0).then_with(|| b.1.cmp(a.1)))
            .map(|(_, k)| k.clone());
        Ok(certified.or_else(|| keys.into_iter().next()))
    }

    /// Store `cert` as a certificate of `key_name`. A certificate carrying
    /// its signed wire is kept as Data under its own name next to the key's
    /// other certificates, so certificates of one key (e.g. before and after
    /// a renewal) coexist; stored certificates of the key that have expired
    /// are dropped. A certificate without wire bytes is kept as the key's
    /// NDNC summary.
    pub fn store_cert(&self, key_name: &Name, cert: &Certificate) -> Result<(), PibError> {
        let dir = self.key_dir(key_name)?;
        match cert.data_wire() {
            Some(wire) => self.store_cert_wire(&dir, &cert.name, &wire),
            None => {
                secure_fs::write_private(&dir.join("cert.ndnc"), encode_cert(cert))?;
                Ok(())
            }
        }
    }

    /// Write a signed certificate Data under `<dir>/certs/`, then drop the
    /// key's stored certificates that have expired (never the new one).
    fn store_cert_wire(&self, dir: &Path, cert_name: &Name, wire: &[u8]) -> Result<(), PibError> {
        let certs = dir.join(CERTS_DIR);
        secure_fs::create_private_dir_all(&certs)?;
        let file = certs.join(format!("{}.data", name_hash(cert_name)));
        secure_fs::write_private(&file, wire)?;
        for (path, cert) in stored_cert_files(&certs) {
            if path != file && cert.valid_until < crate::validator::now_ns() {
                let _ = std::fs::remove_file(path);
            }
        }
        Ok(())
    }

    /// Every certificate stored for `key_name`: those under `certs/`, a
    /// legacy `cert.data`, and — only when the key has no signed certificate
    /// at all — its NDNC summary (named after the key). Unordered.
    pub fn certs(&self, key_name: &Name) -> Result<Vec<Certificate>, PibError> {
        Ok(self
            .cert_entries(key_name)?
            .into_iter()
            .map(|(cert, _)| cert)
            .collect())
    }

    /// Each stored certificate of `key_name` with its signed Data wire
    /// (`None` for an NDNC summary).
    fn cert_entries(&self, key_name: &Name) -> Result<Vec<(Certificate, Option<Bytes>)>, PibError> {
        let Some(dir) = self.existing_key_dir(key_name) else {
            return Ok(Vec::new());
        };
        let mut entries: Vec<(Certificate, Option<Bytes>)> = stored_cert_files(&dir.join(CERTS_DIR))
            .into_iter()
            .filter_map(|(path, cert)| {
                let wire = std::fs::read(path).ok()?;
                Some((cert, Some(Bytes::from(wire))))
            })
            .collect();
        // Legacy: the issued certificate earlier releases kept beside the key.
        if let Ok(wire) = std::fs::read(dir.join(LEGACY_CERT_DATA))
            && let Some(cert) = decode_cert_wire(&wire)
            && !entries.iter().any(|(c, _)| c.name == cert.name)
        {
            entries.push((cert, Some(Bytes::from(wire))));
        }
        if entries.is_empty()
            && let Ok(data) = std::fs::read(dir.join("cert.ndnc"))
        {
            entries.push((decode_cert(Arc::new(key_name.clone()), &data)?, None));
        }
        Ok(entries)
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
        use crate::safebag::SafeBag;
        use ndn_packet::Data;
        let bag = SafeBag::decode(safebag_wire)
            .map_err(|e| PibError::Corrupt(format!("SafeBag decode: {e}")))?;
        let pkcs8 = bag
            .decrypt_pkcs8(passphrase)
            .map_err(|e| PibError::Corrupt(format!("SafeBag decrypt: {e}")))?;
        let cert_data = Data::decode(Bytes::copy_from_slice(&bag.certificate))
            .map_err(|e| PibError::Corrupt(format!("cert Data decode: {e:?}")))?;
        let cert = Certificate::decode(&cert_data)
            .map_err(|e| PibError::Corrupt(format!("Certificate decode: {e}")))?;
        // The bag's certificate is `key_name` itself (a key named after its
        // certificate, or a legacy key-named certificate) or one of its
        // certificates `<key_name>/<issuer>/<version>`.
        if *cert.name != *key_name && !crate::cert_name::is_cert_of(&cert.name, key_name) {
            return Err(PibError::Corrupt(format!(
                "SafeBag cert name {} does not match requested key {}",
                cert.name, key_name
            )));
        }
        // Fail fast on unsupported algorithms before writing to disk.
        let _ = signer_from_pkcs8(&pkcs8, key_name)?;
        let dir = self.key_dir(key_name)?;
        secure_fs::write_private(&dir.join("private.pkcs8.der"), &pkcs8)?;
        secure_fs::write_private(&dir.join("name.uri"), name_to_uri(key_name))?;
        self.store_cert_wire(&dir, &cert.name, &bag.certificate)?;
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
        crate::safebag::ed25519_seed_to_pkcs8(&seed)
            .map_err(|e| PibError::Corrupt(format!("legacy seed → pkcs8: {e}")))
    }

    /// Export a stored identity as an ndn-cxx-compatible `SafeBag` (TLV
    /// 0x80): the key's current certificate (newest valid, as `ndnsec
    /// export` exports the default certificate) alongside the PKCS#8 private
    /// key encrypted under `passphrase` (PBES2 / PBKDF2-HMAC-SHA256 +
    /// AES-256-CBC, matching `ndnsec export`).
    ///
    /// Works for both Ed25519 and ECDSA-P256 keys — the algorithm is taken
    /// from the stored PKCS#8 OID via [`Self::get_signer`]. When the key has
    /// only an NDNC summary (no signed certificate), a certificate
    /// `<key>/self/<version>` is self-signed now with the key itself, so the
    /// SafeBag is still a self-contained, verifiable bundle.
    pub fn export_safebag(&self, key_name: &Name, passphrase: &[u8]) -> Result<Vec<u8>, PibError> {
        use crate::safebag::SafeBag;
        let pkcs8 = self.export_pkcs8(key_name)?;
        let signer = self.get_signer(key_name)?;
        let cert_wire = match self.get_issued_cert(key_name)? {
            Some(wire) => wire,
            None => {
                let cert = self.get_cert(key_name)?;
                let cert_name = if crate::cert_name::is_cert_name(key_name) {
                    key_name.clone()
                } else {
                    crate::cert_name::new_cert_name(key_name, crate::cert_name::SELF_ISSUER)
                };
                futures::executor::block_on(crate::manager::encode_cert_data(
                    &cert_name,
                    &cert.public_key,
                    signer.as_ref(),
                    cert.valid_from,
                    cert.valid_until,
                ))
                .map_err(|e| PibError::Corrupt(format!("re-sign cert for export: {e}")))?
            }
        };
        let bag = SafeBag::encrypt(cert_wire, &pkcs8, passphrase)
            .map_err(|e| PibError::Corrupt(format!("SafeBag encrypt: {e}")))?;
        Ok(bag.encode().to_vec())
    }

    /// The key's current certificate: the newest one valid now among
    /// [`certs`](Self::certs) (latest `valid_from`, then the later name),
    /// else the newest one. Legacy summaries are named after the key.
    pub fn get_cert(&self, key_name: &Name) -> Result<Certificate, PibError> {
        newest(self.cert_entries(key_name)?)
            .map(|(cert, _)| cert)
            .ok_or_else(|| PibError::CertNotFound(name_to_uri(key_name)))
    }

    /// Store the certificate a CA issued for `key_name` exactly as received
    /// (`cert_data`, the signed Certificate v2 Data) as one more certificate
    /// of the key (see [`store_cert`](Self::store_cert)). The key must already
    /// be in the PIB and the certificate must be one of its certificates.
    pub fn store_issued_cert(&self, key_name: &Name, cert_data: &[u8]) -> Result<Certificate, PibError> {
        let dir = self
            .existing_key_dir(key_name)
            .ok_or_else(|| PibError::KeyNotFound(name_to_uri(key_name)))?;
        let data = ndn_packet::Data::decode(Bytes::copy_from_slice(cert_data))
            .map_err(|e| PibError::Corrupt(format!("issued cert Data: {e:?}")))?;
        let cert = Certificate::decode(&data)
            .map_err(|e| PibError::Corrupt(format!("issued cert: {e}")))?;
        if !cert.name.has_prefix(key_name) {
            return Err(PibError::Corrupt(format!(
                "certificate {} is not a certificate of key {}",
                cert.name, key_name
            )));
        }
        self.store_cert_wire(&dir, &cert.name, cert_data)?;
        Ok(cert)
    }

    /// The signed Data of the key's current certificate (as
    /// [`get_cert`](Self::get_cert) picks it, among certificates stored with
    /// their wire), `None` if the key has none.
    pub fn get_issued_cert(&self, key_name: &Name) -> Result<Option<Bytes>, PibError> {
        Ok(newest(
            self.cert_entries(key_name)?
                .into_iter()
                .filter(|(_, wire)| wire.is_some()),
        )
        .and_then(|(_, wire)| wire))
    }

    /// The signed Data of every stored certificate of `key_name` that is
    /// valid now (a renewed key's old and new certificate, until the old
    /// one expires).
    pub fn valid_cert_wires(&self, key_name: &Name) -> Result<Vec<Bytes>, PibError> {
        Ok(self
            .cert_entries(key_name)?
            .into_iter()
            .filter(|(cert, _)| cert.is_valid_now())
            .filter_map(|(_, wire)| wire)
            .collect())
    }

    /// Make `identity` the PIB's default identity — the one a node loads when
    /// its configuration names none. The PIB must hold a key of `identity`.
    /// The record is replaced atomically (temp file, then rename), so a reader
    /// sees the old default or the new one, never a partial name.
    pub fn set_default_identity(&self, identity: &Name) -> Result<(), PibError> {
        if self.identity_keys(identity)?.is_empty() {
            return Err(PibError::KeyNotFound(name_to_uri(identity)));
        }
        secure_fs::write_private(&self.root.join(DEFAULT_IDENTITY_FILE), name_to_uri(identity))?;
        Ok(())
    }

    /// The PIB's default identity ([`set_default_identity`](Self::set_default_identity)),
    /// `None` when none was set.
    pub fn get_default_identity(&self) -> Result<Option<Name>, PibError> {
        match std::fs::read_to_string(self.root.join(DEFAULT_IDENTITY_FILE)) {
            Ok(uri) => name_from_uri(uri.trim()).map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(PibError::Io(e)),
        }
    }

    /// Store `cert` as a trust anchor, indexed by `key_name` (the anchor's
    /// key; anchors match by key). A certificate with its signed wire is kept
    /// as Data too, so it reloads under its own (cert-v2) name.
    pub fn add_trust_anchor(&self, key_name: &Name, cert: &Certificate) -> Result<(), PibError> {
        if !cert.is_valid_now() {
            return Err(PibError::Corrupt(format!(
                "trust anchor {} is expired or not yet valid",
                cert.name
            )));
        }
        let dir = self.anchor_dir(key_name)?;
        secure_fs::write_private(&dir.join("cert.ndnc"), encode_cert(cert))?;
        match cert.data_wire() {
            Some(wire) => secure_fs::write_private(&dir.join(LEGACY_CERT_DATA), &wire)?,
            None => {
                let _ = std::fs::remove_file(dir.join(LEGACY_CERT_DATA));
            }
        }
        secure_fs::write_private(&dir.join("name.uri"), name_to_uri(key_name))?;
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
            // An anchor whose name file is missing or malformed is skipped, like one
            // whose certificate does not decode — never loaded under the root name.
            // The signed certificate wins when stored; an NDNC-only anchor (and
            // every anchor of earlier releases) is named by its `name.uri`.
            if let Some(cert) = std::fs::read(path.join(LEGACY_CERT_DATA))
                .ok()
                .and_then(|wire| decode_cert_wire(&wire))
            {
                certs.push(cert);
            } else if let Ok(name_uri) = std::fs::read_to_string(path.join("name.uri"))
                && let Ok(name) = name_from_uri(name_uri.trim())
                && let Ok(data) = std::fs::read(path.join("cert.ndnc"))
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
        secure_fs::create_private_dir_all(&dir)?;
        Ok(dir)
    }

    /// Key directory only if already on disk.
    fn existing_key_dir(&self, name: &Name) -> Option<PathBuf> {
        let dir = self.root.join("keys").join(name_hash(name));
        if dir.exists() { Some(dir) } else { None }
    }

    fn anchor_dir(&self, name: &Name) -> Result<PathBuf, PibError> {
        let dir = self.root.join("anchors").join(name_hash(name));
        secure_fs::create_private_dir_all(&dir)?;
        Ok(dir)
    }
}

/// `<pib>/default-identity`: the default identity's NDN URI.
const DEFAULT_IDENTITY_FILE: &str = "default-identity";
const NDNC_MAGIC: &[u8; 4] = b"NDNC";
const NDNC_VERSION_V1: u8 = 1;
const NDNC_VERSION_V2: u8 = 2;
/// Per-key directory of the key's certificates as signed Data.
const CERTS_DIR: &str = "certs";
/// Earlier releases' single issued certificate per key (read only).
const LEGACY_CERT_DATA: &str = "cert.data";

fn decode_cert_wire(wire: &[u8]) -> Option<Certificate> {
    let data = ndn_packet::Data::decode(Bytes::copy_from_slice(wire)).ok()?;
    Certificate::decode(&data).ok()
}

/// The decodable certificate files in a key's `certs/` directory. A file
/// that cannot be read or decoded is logged by name and left out.
fn stored_cert_files(dir: &Path) -> Vec<(PathBuf, Certificate)> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(dir = %dir.display(), error = %e, "cannot list stored certificates");
            }
            return Vec::new();
        }
    };
    entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "data"))
        .filter_map(|p| {
            let cert = match std::fs::read(&p) {
                Ok(wire) => decode_cert_wire(&wire),
                Err(e) => {
                    tracing::warn!(file = %p.display(), error = %e, "cannot read a stored certificate");
                    return None;
                }
            };
            if cert.is_none() {
                tracing::warn!(file = %p.display(), "a stored certificate does not decode; ignored");
            }
            Some((p, cert?))
        })
        .collect()
}

/// The newest of `entries` valid now (latest `valid_from`, then the greater
/// name), else the newest of all.
fn newest<T>(entries: impl IntoIterator<Item = (Certificate, T)>) -> Option<(Certificate, T)> {
    let now = crate::validator::now_ns();
    entries.into_iter().max_by(|(a, _), (b, _)| {
        (a.is_valid_at(now), a.valid_from, &a.name).cmp(&(b.is_valid_at(now), b.valid_from, &b.name))
    })
}

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
            let seed = crate::safebag::pkcs8_to_ed25519_seed(pkcs8)
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

    /// Every entry under `root` is owner-only (no group/other bits).
    #[cfg(unix)]
    fn assert_owner_only(root: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(root).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "{} is {:o}", root.display(), mode & 0o777);
        if root.is_dir() {
            for e in std::fs::read_dir(root).unwrap() {
                assert_owner_only(&e.unwrap().path());
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn keys_and_dirs_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        // A world-readable PIB root must not leak keys either.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let pib = FilePib::new(dir.path()).unwrap();
        pib.generate_ed25519(&key_name("a")).unwrap();
        pib.generate_ecdsa_p256(&key_name("b")).unwrap();
        assert_owner_only(dir.path());
    }

    #[cfg(unix)]
    #[test]
    fn open_tightens_existing_pib() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, pib) = tmp_pib();
        pib.generate_ed25519(&key_name("a")).unwrap();
        let keydir = pib.existing_key_dir(&key_name("a")).unwrap();
        let set = |p: &Path, m: u32| std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
        set(&keydir.join("private.pkcs8.der"), 0o644);
        set(&keydir, 0o755);
        set(&dir.path().join("keys"), 0o755);
        set(dir.path(), 0o755);
        let pib = FilePib::open(dir.path()).unwrap();
        assert_owner_only(dir.path());
        assert!(pib.get_signer(&key_name("a")).is_ok());
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

    /// `default_key` only considers the identity's own keys and prefers the
    /// most recently issued valid certificate (e.g. an enrolled key).
    #[test]
    fn default_key_selects_identity_key_most_recently_certified() {
        let (_dir, pib) = tmp_pib();
        let n = |s: &str| -> Name { s.parse().unwrap() };
        let cert = |name: &Name, valid_from: u64, valid_until: u64| Certificate {
            name: Arc::new(name.clone()),
            public_key: Bytes::from_static(&[1; 32]),
            valid_from,
            valid_until,
            issuer: None,
            signed_region: None,
            sig_value: None,
            sig_type: ndn_packet::SignatureType::SignatureEd25519,
        };
        let now = now_ns();
        let hour = 3_600_000_000_000;

        let id = n("/home/bob/node");
        let older = n("/home/bob/node/KEY/aa");
        let newer = n("/home/bob/node/KEY/bb");
        let expired = n("/home/bob/node/KEY/00");
        let other = n("/home/bob/node/sub/KEY/zz");
        for k in [&older, &newer, &expired, &other] {
            pib.generate_ed25519(k).unwrap();
        }
        pib.store_cert(&older, &cert(&older, now - 2 * hour, now + hour))
            .unwrap();
        pib.store_cert(&newer, &cert(&newer, now - hour, now + hour))
            .unwrap();
        pib.store_cert(&expired, &cert(&expired, now - 3 * hour, now - hour))
            .unwrap();
        pib.store_cert(&other, &cert(&other, now, now + hour)).unwrap();

        assert_eq!(
            pib.identity_keys(&id).unwrap(),
            vec![expired.clone(), older, newer.clone()]
        );
        assert_eq!(pib.default_key(&id).unwrap(), Some(newer));
        assert_eq!(pib.default_key(&n("/home/bob")).unwrap(), None);

        // No valid cert at all: first key in name order.
        let (_dir2, bare) = tmp_pib();
        for k in ["/x/KEY/b", "/x/KEY/a"] {
            bare.generate_ed25519(&n(k)).unwrap();
        }
        assert_eq!(bare.default_key(&n("/x")).unwrap(), Some(n("/x/KEY/a")));
    }

    /// The default identity names an identity the PIB holds a key for, reads
    /// back after reopening, and is replaced (not appended) when changed.
    #[test]
    fn default_identity_needs_a_key_and_persists() {
        let n = |s: &str| s.parse::<Name>().unwrap();
        let (dir, pib) = tmp_pib();
        assert_eq!(pib.get_default_identity().unwrap(), None);
        assert!(matches!(
            pib.set_default_identity(&n("/home/bob/member/phone")),
            Err(PibError::KeyNotFound(_))
        ));
        assert_eq!(pib.get_default_identity().unwrap(), None);

        pib.generate_ed25519(&n("/home/bob/member/phone/KEY/a")).unwrap();
        pib.generate_ed25519(&n("/home/bob/guest/phone/KEY/b")).unwrap();
        pib.set_default_identity(&n("/home/bob/member/phone")).unwrap();
        pib.set_default_identity(&n("/home/bob/guest/phone")).unwrap();
        let reopened = FilePib::open(dir.path()).unwrap();
        assert_eq!(
            reopened.get_default_identity().unwrap(),
            Some(n("/home/bob/guest/phone"))
        );
    }

    /// An issued certificate is stored verbatim beside its key, and only for
    /// the key it certifies.
    #[test]
    fn issued_cert_is_stored_verbatim_for_its_key_only() {
        let n = |s: &str| s.parse::<Name>().unwrap();
        let (_dir, pib) = tmp_pib();
        let key = n("/home/bob/member/phone/KEY/a");
        let other = n("/home/bob/member/tablet/KEY/b");
        let signer = pib.generate_ed25519(&key).unwrap();
        pib.generate_ed25519(&other).unwrap();
        let wire = futures::executor::block_on(crate::manager::encode_cert_data(
            &key,
            &signer.public_key().unwrap(),
            &signer,
            now_ns(),
            now_ns() + 3_600_000_000_000,
        ))
        .unwrap();

        assert!(pib.store_issued_cert(&other, &wire).is_err());
        assert_eq!(pib.get_issued_cert(&other).unwrap(), None);
        assert!(pib.store_issued_cert(&n("/nobody/KEY/x"), &wire).is_err());
        assert!(pib.store_issued_cert(&key, b"not a data packet").is_err());

        let cert = pib.store_issued_cert(&key, &wire).unwrap();
        assert_eq!(pib.get_issued_cert(&key).unwrap(), Some(wire));
        assert_eq!(pib.get_cert(&key).unwrap().public_key, cert.public_key);
    }

    /// A key keeps every certificate under its own cert-v2 name: a renewal's
    /// new certificate and the old one coexist, the newest valid one is the
    /// key's certificate, and an expired one is dropped on the next store.
    #[test]
    fn certificates_of_a_key_coexist_and_the_newest_valid_wins() {
        let n = |s: &str| s.parse::<Name>().unwrap();
        let (_dir, pib) = tmp_pib();
        let key = n("/home/bob/member/phone/KEY/a");
        let signer = pib.generate_ed25519(&key).unwrap();
        let pk = signer.public_key().unwrap();
        let hour = 3_600_000_000_000u64;
        let issue = |name: &str, from: u64, until: u64| {
            futures::executor::block_on(crate::manager::encode_cert_data(
                &n(name), &pk, &signer, from, until,
            ))
            .unwrap()
        };
        let now = now_ns();
        let old = issue("/home/bob/member/phone/KEY/a/NDNCERT/v=1", now - 2 * hour, now + hour);
        let new = issue("/home/bob/member/phone/KEY/a/NDNCERT/v=2", now - hour, now + 2 * hour);
        pib.store_issued_cert(&key, &old).unwrap();
        pib.store_issued_cert(&key, &new).unwrap();

        assert_eq!(pib.certs(&key).unwrap().len(), 2);
        assert_eq!(pib.valid_cert_wires(&key).unwrap().len(), 2);
        assert_eq!(
            pib.get_cert(&key).unwrap().name.to_string(),
            "/home/bob/member/phone/KEY/a/NDNCERT/v=2"
        );
        assert_eq!(pib.get_issued_cert(&key).unwrap(), Some(new));

        let expired = issue("/home/bob/member/phone/KEY/a/NDNCERT/v=0", now - 3 * hour, now - hour);
        pib.store_issued_cert(&key, &expired).unwrap();
        let third = issue("/home/bob/member/phone/KEY/a/NDNCERT/v=3", now, now + 3 * hour);
        pib.store_issued_cert(&key, &third).unwrap();
        let names: Vec<String> = pib.certs(&key).unwrap().iter().map(|c| c.name.to_string()).collect();
        assert_eq!(names.len(), 3, "the expired certificate is dropped: {names:?}");
        assert!(!names.iter().any(|n| n.ends_with("v=0")));
    }

    /// A PIB written by an earlier release (a key-named certificate as
    /// `cert.data` plus its `cert.ndnc` summary) still loads; a newer cert-v2
    /// certificate stored later supersedes it without rewriting it.
    #[test]
    fn legacy_key_named_certificate_still_loads() {
        let n = |s: &str| s.parse::<Name>().unwrap();
        let (_dir, pib) = tmp_pib();
        let key = n("/home/bob/member/phone/KEY/a");
        let signer = pib.generate_ed25519(&key).unwrap();
        let pk = signer.public_key().unwrap();
        let now = now_ns();
        let hour = 3_600_000_000_000u64;
        let legacy = futures::executor::block_on(crate::manager::encode_cert_data(
            &key, &pk, &signer, now - hour, now + hour,
        ))
        .unwrap();
        let dir = pib.existing_key_dir(&key).unwrap();
        std::fs::write(dir.join("cert.data"), &legacy).unwrap();
        std::fs::write(dir.join("cert.ndnc"), encode_cert(&decode_cert_wire(&legacy).unwrap()))
            .unwrap();

        let cert = pib.get_cert(&key).unwrap();
        assert_eq!(*cert.name, key, "the legacy certificate is named after its key");
        assert_eq!(pib.certs(&key).unwrap().len(), 1, "summary and Data are one certificate");
        assert_eq!(pib.get_issued_cert(&key).unwrap(), Some(legacy.clone()));

        let renewed = futures::executor::block_on(crate::manager::encode_cert_data(
            &n("/home/bob/member/phone/KEY/a/NDNCERT/v=5"), &pk, &signer, now, now + 2 * hour,
        ))
        .unwrap();
        pib.store_issued_cert(&key, &renewed).unwrap();
        assert_eq!(
            pib.get_cert(&key).unwrap().name.to_string(),
            "/home/bob/member/phone/KEY/a/NDNCERT/v=5"
        );
        assert_eq!(std::fs::read(dir.join("cert.data")).unwrap(), legacy.to_vec());
        assert_eq!(pib.valid_cert_wires(&key).unwrap().len(), 2);
    }
}
