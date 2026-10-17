//! Where a namespace root key lives on its root device: the **root store**.
//!
//! The root key (`<ns>/KEY/root` from `ndn-fwd init`, `<ns>/KEY/<id>` after a
//! recovery, [`crate::recovery`]) signs rarely — the namespace anchor, the CA's
//! certificate and each new version of the trust context (a revocation) —
//! and always because an operator asked. So it is kept apart from the keys
//! the daemon uses unattended and is unlocked for one operation at a time.
//!
//! A root device records its store in data, `<pib>/root/store.toml` (written
//! owner-only, [`ndn_security::secure_fs`]): the [`RootStoreKind`], the root
//! key name, its public key and anchor certificate name, and kind-specific
//! fields. Whether a node is the root device of a context is decided from
//! that descriptor and the context's anchor public keys
//! ([`RootStore::holds_anchor_of`]) — the private key is never loaded for it.
//!
//! | Kind          | Private key                                  | Unlock per operation |
//! |---------------|----------------------------------------------|----------------------|
//! | `os-keyring`  | SafeBag `<pib>/root/root-keychain.safebag`, sealed by a random 32-byte passphrase kept in the OS keychain (Secret Service, macOS Keychain, Windows Credential Manager) | none: the keychain releases it to the logged-in user |
//! | `sealed-file` | SafeBag `<pib>/root/root.safebag`, sealed by the operator's passphrase | the passphrase |
//! | `yubikey-piv` | generated on a YubiKey PIV slot (P-256), never exportable | the PIV PIN (and a touch, per the recorded policy) |
//! | `file`        | plaintext PKCS#8 in the FilePib (`<pib>/keys/…`) | none — unprotected; namespaces made before root stores, and tests |
//!
//! SafeBags use the PBES2 sealing of [`ndn_security::safebag`] (PBKDF2-HMAC-
//! SHA256, 600 000 iterations, AES-256-CBC) and carry the anchor certificate,
//! so a sealed root is self-describing. [`RootStore::signer`] unlocks the
//! store for one operation; the decrypted key lives in the returned signer
//! and is zeroed when it is dropped (as are [`RootSecret`]s).
//!
//! The namespace CA key and the root device's admin key stay in the FilePib:
//! the daemon signs with them unattended (every issued certificate, every
//! management response), so they cannot wait for an operator. What they can
//! do is bounded — the CA issues what its policy allows, under a certificate
//! the root signed and a context the root controls (revocation) — while the
//! root is what every adopter trusts.
//!
//! Any anchor key of a held context can sign its next version
//! ([`crate::bump_context_revoking`] takes the signer); a root store is the
//! usual source of that signer.

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use bytes::Bytes;
use ndn_packet::Name;
use ndn_security::safebag::SafeBag;
use ndn_security::{
    Certificate, Ed25519Signer, FilePib, PibError, SignedTrustContext, Signer, TrustError,
};
use zeroize::Zeroizing;

use crate::namespace::{ANCHOR_CERT_FILE, CA_DIR};

/// Directory (under the PIB root) of the root store.
pub const ROOT_STORE_DIR: &str = "root";
/// The root store descriptor in [`ROOT_STORE_DIR`].
pub const ROOT_STORE_FILE: &str = "store.toml";
/// The passphrase-sealed root of a `sealed-file` store.
pub const SEALED_SAFEBAG_FILE: &str = "root.safebag";
/// The keychain-sealed root of an `os-keyring` store.
pub const KEYCHAIN_SAFEBAG_FILE: &str = "root-keychain.safebag";
/// Environment variable a CLI reads a `sealed-file` passphrase from (scripts,
/// tests) instead of prompting.
pub const PASSPHRASE_ENV: &str = "NDN_ROOT_PASSPHRASE";
/// Environment variable a CLI reads a `yubikey-piv` PIN from instead of
/// prompting.
pub const PIN_ENV: &str = "NDN_ROOT_PIN";
/// The PIV slot a `yubikey-piv` root is generated in by default (`9c`,
/// "Digital Signature").
pub const DEFAULT_YUBIKEY_SLOT: &str = "9c";
/// The keychain service name of `os-keyring` roots.
pub const KEYCHAIN_SERVICE: &str = "ndn-fwd namespace root";

/// Where a namespace root key lives (see the module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RootStoreKind {
    OsKeyring,
    SealedFile,
    YubikeyPiv,
    File,
}

impl RootStoreKind {
    pub const ALL: [RootStoreKind; 4] = [
        RootStoreKind::OsKeyring,
        RootStoreKind::SealedFile,
        RootStoreKind::YubikeyPiv,
        RootStoreKind::File,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            RootStoreKind::OsKeyring => "os-keyring",
            RootStoreKind::SealedFile => "sealed-file",
            RootStoreKind::YubikeyPiv => "yubikey-piv",
            RootStoreKind::File => "file",
        }
    }

    /// What a root operation needs from the operator to unlock this kind.
    pub fn unlock(self) -> RootUnlockKind {
        match self {
            RootStoreKind::SealedFile => RootUnlockKind::Passphrase,
            RootStoreKind::YubikeyPiv => RootUnlockKind::Pin,
            RootStoreKind::OsKeyring | RootStoreKind::File => RootUnlockKind::Nothing,
        }
    }
}

impl fmt::Display for RootStoreKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RootStoreKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        RootStoreKind::ALL
            .into_iter()
            .find(|k| k.as_str() == s)
            .ok_or_else(|| {
                format!("unknown root store {s:?} (os-keyring, sealed-file, yubikey-piv, file)")
            })
    }
}

/// What unlocking a root store takes from the operator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootUnlockKind {
    Nothing,
    Passphrase,
    Pin,
}

impl RootUnlockKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RootUnlockKind::Nothing => "none",
            RootUnlockKind::Passphrase => "passphrase",
            RootUnlockKind::Pin => "pin",
        }
    }

    /// The environment variable a CLI reads this secret from.
    pub fn env_var(self) -> Option<&'static str> {
        match self {
            RootUnlockKind::Nothing => None,
            RootUnlockKind::Passphrase => Some(PASSPHRASE_ENV),
            RootUnlockKind::Pin => Some(PIN_ENV),
        }
    }
}

impl FromStr for RootUnlockKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "none" => Ok(RootUnlockKind::Nothing),
            "passphrase" => Ok(RootUnlockKind::Passphrase),
            "pin" => Ok(RootUnlockKind::Pin),
            _ => Err(format!("unknown unlock kind {s:?}")),
        }
    }
}

/// A root store's passphrase or PIN. Zeroed when dropped; `Debug` is
/// redacted.
#[derive(Clone)]
pub struct RootSecret(Zeroizing<Vec<u8>>);

impl RootSecret {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for RootSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RootSecret(<redacted>)")
    }
}

/// The store `ndn-fwd init` creates a new namespace root in.
#[derive(Debug)]
pub enum NewRootStore {
    /// The platform keychain (no operator secret).
    OsKeyring,
    /// A SafeBag sealed by `passphrase`.
    SealedFile { passphrase: RootSecret },
    /// Generated on a YubiKey PIV slot, PIN verified before each signature.
    YubikeyPiv {
        pin: RootSecret,
        /// `9a`, `9c` (default), `9d`, `9e`.
        slot: String,
        /// `always` (default), `cached`, `never`.
        touch_policy: String,
        /// The token, when several are connected.
        serial: Option<u32>,
        /// What generating on the token must not destroy.
        guard: SlotGuard,
    },
    /// Plaintext in the FilePib (unprotected; tests and development).
    File,
}

impl NewRootStore {
    pub fn kind(&self) -> RootStoreKind {
        match self {
            NewRootStore::OsKeyring => RootStoreKind::OsKeyring,
            NewRootStore::SealedFile { .. } => RootStoreKind::SealedFile,
            NewRootStore::YubikeyPiv { .. } => RootStoreKind::YubikeyPiv,
            NewRootStore::File => RootStoreKind::File,
        }
    }
}

/// What generating a key on a YubiKey must not destroy: generating replaces
/// whatever key the slot held, for good, and a key on the same token as
/// another needed key is lost with it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SlotGuard {
    /// Generate even when the slot holds a key (the operator said it is not
    /// needed); otherwise an occupied slot, or one whose state the token
    /// cannot report, is refused.
    pub replace: bool,
    /// A token the key must not go on — its serial and what it holds (a
    /// namespace root, the recovery kit of a recovery).
    pub not_on: Option<(u32, String)>,
}

/// Refuse generating into `slot` of `token` when `guard` forbids it.
#[cfg(feature = "yubikey-piv")]
pub(crate) async fn check_generation_target(
    token: &ndn_security::YubikeyPiv,
    slot: ndn_security::YubikeySlot,
    guard: &SlotGuard,
) -> Result<(), RootStoreError> {
    use ndn_security::YubikeySlotState;
    if let Some((serial, holds)) = &guard.not_on
        && *serial == token.serial()
    {
        return Err(RootStoreError::TokenInUse {
            serial: *serial,
            holds: holds.clone(),
        });
    }
    if guard.replace {
        return Ok(());
    }
    let state = match token.slot_state(slot).await? {
        YubikeySlotState::Empty => return Ok(()),
        YubikeySlotState::Holds => "already holds a key".to_string(),
        YubikeySlotState::Unknown(why) => format!("may hold a key ({why})"),
    };
    Err(RootStoreError::SlotInUse {
        serial: token.serial(),
        slot: slot.as_str().to_string(),
        state,
    })
}

/// Why a root store could not be created, opened, unlocked or moved.
#[derive(Debug, thiserror::Error)]
pub enum RootStoreError {
    #[error(
        "the root key {key} is in a {kind} store ({location}): this operation needs its \
         {need}. The ndn-fwd CLI asks for it on the terminal, or reads it from {env} or a \
         --{need}-file",
        need = .kind.unlock().as_str(),
        env = .kind.unlock().env_var().unwrap_or("-"),
    )]
    UnlockNeeded {
        kind: RootStoreKind,
        key: String,
        location: String,
    },
    #[error(
        "the passphrase does not open {path}: nothing was signed and the root store is \
         unchanged"
    )]
    WrongPassphrase { path: PathBuf },
    #[error("YubiKey: {0}")]
    Yubikey(String),
    #[error(
        "YubiKey {serial} holds {holds}: a key generated on the same token is lost with it. \
         Plug in another YubiKey for it (select it by serial when several are connected)"
    )]
    TokenInUse { serial: u32, holds: String },
    #[error(
        "PIV slot {slot} of YubiKey {serial} {state}: generating a key there destroys the one it \
         holds for good (a namespace root or recovery kit in it would be lost). Choose a free \
         slot, or, if nothing in that slot is needed, replace it deliberately (`--replace-slot` \
         in the ndn-fwd CLI)"
    )]
    SlotInUse {
        serial: u32,
        slot: String,
        state: String,
    },
    #[error(
        "no OS keychain is reachable ({reason}). Keep the root in a passphrase-sealed file \
         instead: `--root-store sealed-file` (the passphrase is asked for each root \
         operation), or start a keychain for this user (on Linux a Secret Service such as \
         gnome-keyring or KeePassXC on the session D-Bus)"
    )]
    KeychainUnavailable { reason: String },
    #[error(
        "the OS keychain holds no entry {service:?}/{account:?} for the sealed root key: the \
         keychain was reset or this PIB was copied from another user or machine; nothing can \
         open {path} without that entry"
    )]
    KeychainEntryMissing {
        service: String,
        account: String,
        path: PathBuf,
    },
    #[error("this build has no {kind} root store support (cargo feature `{feature}`)")]
    NotBuilt {
        kind: RootStoreKind,
        feature: &'static str,
    },
    #[error(
        "the {kind} store ({location}) holds a different key than the namespace root {key} \
         recorded in {descriptor}"
    )]
    WrongKey {
        kind: RootStoreKind,
        key: String,
        location: String,
        descriptor: PathBuf,
    },
    #[error("{path}: {reason}")]
    Descriptor { path: PathBuf, reason: String },
    #[error(
        "{pib} holds the root of {held}; a PIB holds one namespace root. Initialize {requested} \
         with another --pib"
    )]
    OtherNamespace {
        pib: String,
        held: String,
        requested: String,
    },
    #[error("cannot move the root from {from} to {to}: {reason}")]
    Unmovable {
        from: RootStoreKind,
        to: RootStoreKind,
        reason: String,
    },
    #[error("{0}")]
    Secret(String),
    #[error("I/O on {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error(transparent)]
    Pib(#[from] PibError),
    #[error(transparent)]
    Trust(#[from] TrustError),
}

fn io_err(path: &Path) -> impl FnOnce(std::io::Error) -> RootStoreError + '_ {
    move |source| RootStoreError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// `<pib>/root/store.toml`.
pub fn descriptor_path(pib_root: &Path) -> PathBuf {
    pib_root.join(ROOT_STORE_DIR).join(ROOT_STORE_FILE)
}

/// Whether two encodings of a public key are the same key (an Ed25519 key
/// is stored raw by in-memory signers and as SPKI in some certificates).
pub fn same_public_key(a: &[u8], b: &[u8]) -> bool {
    let norm = |k: &[u8]| -> Vec<u8> {
        if ndn_security::spki::is_ed25519_spki(k)
            && let Some(raw) = ndn_security::spki::unwrap_ed25519(k)
        {
            return raw.to_vec();
        }
        k.to_vec()
    };
    norm(a) == norm(b)
}

// ── Descriptor (on disk) ───────────────────────────────────────────────────

#[derive(serde::Serialize, serde::Deserialize)]
struct Descriptor {
    kind: RootStoreKind,
    namespace: String,
    key_name: String,
    anchor_cert: String,
    /// Base64 (standard) of the root's public key as its anchor carries it.
    public_key: String,
    /// `sealed-file` / `os-keyring`: the SafeBag file in `<pib>/root/`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    safebag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    keychain: Option<KeychainEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    yubikey: Option<YubikeyRoot>,
}

/// The keychain entry holding an `os-keyring` root's sealing secret.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KeychainEntry {
    pub service: String,
    pub account: String,
}

/// The token and slot of a `yubikey-piv` root.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct YubikeyRoot {
    pub serial: u32,
    pub slot: String,
    pub pin_policy: String,
    pub touch_policy: String,
}

const DESCRIPTOR_HEADER: &str = "\
# Where the namespace root key of this root device lives. Written by
# `ndn-fwd init` and `ndn-fwd root-key move`; the private key is not in
# this file. See ndn_cert::root_store.
";

/// A root device's root store, as its descriptor records it.
#[derive(Clone, Debug)]
pub struct RootStore {
    pib_root: PathBuf,
    kind: RootStoreKind,
    namespace: Name,
    key_name: Name,
    anchor_cert: Name,
    public_key: Bytes,
    safebag: Option<String>,
    keychain: Option<KeychainEntry>,
    yubikey: Option<YubikeyRoot>,
    /// No descriptor: a root kept in the FilePib by a release before root
    /// stores.
    legacy: bool,
}

impl RootStore {
    /// The root store of the PIB at `pib`: its descriptor, else a root key
    /// `<ns>/KEY/root` that is a trust anchor of the PIB with its private
    /// key in the FilePib (a namespace made before root stores; kind
    /// `file`). `None`: this PIB holds no namespace root.
    pub fn open(pib: &FilePib) -> Result<Option<RootStore>, RootStoreError> {
        let path = descriptor_path(pib.root());
        match std::fs::read_to_string(&path) {
            Ok(text) => Self::parse(pib.root(), &path, &text).map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::legacy(pib),
            Err(e) => Err(io_err(&path)(e)),
        }
    }

    fn parse(pib_root: &Path, path: &Path, text: &str) -> Result<RootStore, RootStoreError> {
        let bad = |reason: String| RootStoreError::Descriptor {
            path: path.to_path_buf(),
            reason,
        };
        let d: Descriptor = toml::from_str(text).map_err(|e| bad(e.to_string()))?;
        let name = |field: &str, s: &str| -> Result<Name, RootStoreError> {
            s.parse::<Name>()
                .map_err(|e| bad(format!("{field} {s:?} is not an NDN name: {e}")))
        };
        use base64::Engine as _;
        let public_key = base64::engine::general_purpose::STANDARD
            .decode(&d.public_key)
            .map_err(|e| bad(format!("public_key is not base64: {e}")))?;
        let store = RootStore {
            pib_root: pib_root.to_path_buf(),
            kind: d.kind,
            namespace: name("namespace", &d.namespace)?,
            key_name: name("key_name", &d.key_name)?,
            anchor_cert: name("anchor_cert", &d.anchor_cert)?,
            public_key: Bytes::from(public_key),
            safebag: d.safebag,
            keychain: d.keychain,
            yubikey: d.yubikey,
            legacy: false,
        };
        let missing = match store.kind {
            RootStoreKind::SealedFile if store.safebag.is_none() => Some("safebag"),
            RootStoreKind::OsKeyring if store.safebag.is_none() => Some("safebag"),
            RootStoreKind::OsKeyring if store.keychain.is_none() => Some("[keychain]"),
            RootStoreKind::YubikeyPiv if store.yubikey.is_none() => Some("[yubikey]"),
            _ => None,
        };
        if let Some(field) = missing {
            return Err(bad(format!("a {} store needs {field}", store.kind)));
        }
        if let Some(bag) = &store.safebag
            && (bag.contains('/') || bag.contains('\\') || bag.starts_with('.'))
        {
            return Err(bad(format!("safebag {bag:?} must be a file name in {ROOT_STORE_DIR}/")));
        }
        Ok(store)
    }

    fn legacy(pib: &FilePib) -> Result<Option<RootStore>, RootStoreError> {
        for anchor in pib.trust_anchors()? {
            let key = ndn_security::cert_name::key_name_of(&anchor.name);
            let comps = key.components();
            let is_root = comps.len() >= 2
                && comps[comps.len() - 2].value.as_ref() == b"KEY"
                && comps[comps.len() - 1].value.as_ref() == b"root";
            if !is_root || !pib.has_private_key(&key) {
                continue;
            }
            let namespace = Name::from_components(comps[..comps.len() - 2].iter().cloned());
            return Ok(Some(RootStore {
                pib_root: pib.root().to_path_buf(),
                kind: RootStoreKind::File,
                namespace,
                key_name: key,
                anchor_cert: (*anchor.name).clone(),
                public_key: anchor.public_key.clone(),
                safebag: None,
                keychain: None,
                yubikey: None,
                legacy: true,
            }));
        }
        Ok(None)
    }

    pub fn kind(&self) -> RootStoreKind {
        self.kind
    }

    pub fn namespace(&self) -> &Name {
        &self.namespace
    }

    /// The root key, as the descriptor records it (`<ns>/KEY/<id>`).
    pub fn key_name(&self) -> &Name {
        &self.key_name
    }

    /// The root's self-signed anchor certificate name.
    pub fn anchor_cert(&self) -> &Name {
        &self.anchor_cert
    }

    /// The root's public key, as its anchor certificate carries it.
    pub fn public_key(&self) -> &Bytes {
        &self.public_key
    }

    /// A `file` root kept by a release before root stores (no descriptor).
    pub fn is_legacy(&self) -> bool {
        self.legacy
    }

    /// What a root operation needs from the operator.
    pub fn unlock_kind(&self) -> RootUnlockKind {
        self.kind.unlock()
    }

    /// The keychain entry of an `os-keyring` root.
    pub fn keychain(&self) -> Option<&KeychainEntry> {
        self.keychain.as_ref()
    }

    /// The token and slot of a `yubikey-piv` root.
    pub fn yubikey(&self) -> Option<&YubikeyRoot> {
        self.yubikey.as_ref()
    }

    fn safebag_path(&self) -> Option<PathBuf> {
        self.safebag
            .as_ref()
            .map(|f| self.pib_root.join(ROOT_STORE_DIR).join(f))
    }

    /// Where the private key is, for messages.
    pub fn location(&self) -> String {
        match self.kind {
            RootStoreKind::File => format!(
                "plaintext in the PIB {} (unprotected)",
                self.pib_root.display()
            ),
            RootStoreKind::SealedFile => self
                .safebag_path()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            RootStoreKind::OsKeyring => match (&self.keychain, self.safebag_path()) {
                (Some(k), Some(p)) => format!(
                    "{}, sealed by the OS keychain entry {:?}/{:?}",
                    p.display(),
                    k.service,
                    k.account
                ),
                _ => String::new(),
            },
            RootStoreKind::YubikeyPiv => match &self.yubikey {
                Some(y) => format!(
                    "YubiKey {} slot {} (PIN {}, touch {})",
                    y.serial, y.slot, y.pin_policy, y.touch_policy
                ),
                None => String::new(),
            },
        }
    }

    /// Whether the root of this store is an anchor of `ctx` — this node is
    /// the root device of `ctx`'s namespace. Compares public keys only; the
    /// private key is not touched.
    pub fn holds_anchor_of(&self, ctx: &SignedTrustContext) -> bool {
        ctx.anchors()
            .iter()
            .any(|a| same_public_key(&a.value().public_key, &self.public_key))
    }

    fn unlock_needed(&self) -> RootStoreError {
        RootStoreError::UnlockNeeded {
            kind: self.kind,
            key: self.key_name.to_string(),
            location: self.location(),
        }
    }

    /// Unlock the root for one operation: a signer for the root key. A
    /// `sealed-file` store needs the passphrase, a `yubikey-piv` store the
    /// PIN (`secret`); `os-keyring` and `file` need nothing. The signer is
    /// checked to carry the recorded public key. Drop it when the operation
    /// is done: a software key is zeroed then.
    pub async fn signer(
        &self,
        secret: Option<&RootSecret>,
    ) -> Result<Arc<dyn Signer>, RootStoreError> {
        let signer: Arc<dyn Signer> = match self.kind {
            RootStoreKind::File => FilePib::open(&self.pib_root)?.get_signer(&self.key_name)?,
            RootStoreKind::SealedFile => {
                let secret = secret.ok_or_else(|| self.unlock_needed())?;
                Arc::new(self.open_safebag(secret.expose())?)
            }
            RootStoreKind::OsKeyring => {
                let entry = self.keychain.as_ref().ok_or_else(|| self.unlock_needed())?;
                let path = self.safebag_path().unwrap_or_default();
                let sealing = keychain::get(entry, &path)?;
                Arc::new(self.open_safebag(sealing.as_bytes())?)
            }
            RootStoreKind::YubikeyPiv => {
                let secret = secret.ok_or_else(|| self.unlock_needed())?;
                self.yubikey_signer(secret).await?
            }
        };
        let matches = signer
            .public_key()
            .is_some_and(|pk| same_public_key(&pk, &self.public_key));
        if !matches {
            return Err(RootStoreError::WrongKey {
                kind: self.kind,
                key: self.key_name.to_string(),
                location: self.location(),
                descriptor: descriptor_path(&self.pib_root),
            });
        }
        Ok(signer)
    }

    /// The SafeBag of a sealed store, decrypted with `passphrase`.
    fn open_safebag(&self, passphrase: &[u8]) -> Result<Ed25519Signer, RootStoreError> {
        let path = self.safebag_path().unwrap_or_default();
        let wire = std::fs::read(&path).map_err(io_err(&path))?;
        let bag = SafeBag::decode(&wire).map_err(|e| RootStoreError::Descriptor {
            path: path.clone(),
            reason: format!("not a SafeBag: {e}"),
        })?;
        let pkcs8 = Zeroizing::new(
            bag.decrypt_pkcs8(passphrase)
                .map_err(|_| RootStoreError::WrongPassphrase { path: path.clone() })?,
        );
        Ed25519Signer::from_pkcs8_der(&pkcs8, self.key_name.clone())
            .map_err(|_| RootStoreError::WrongPassphrase { path })
    }

    #[cfg(feature = "yubikey-piv")]
    async fn yubikey_signer(&self, pin: &RootSecret) -> Result<Arc<dyn Signer>, RootStoreError> {
        use ndn_security::{YubikeyPiv, YubikeySlot};
        let y = self.yubikey.as_ref().ok_or_else(|| self.unlock_needed())?;
        let slot: YubikeySlot = y.slot.parse().map_err(RootStoreError::Yubikey)?;
        let token = YubikeyPiv::open_by_serial(y.serial)
            .map_err(|e| RootStoreError::Yubikey(format!("{e}; plug in the root's YubiKey")))?;
        token
            .verify_pin(pin.expose())
            .await
            .map_err(|e| RootStoreError::Yubikey(e.to_string()))?;
        // Firmware 5.3+ reports the slot's key: refuse a slot that was
        // regenerated since, before asking for a touch.
        if let Ok(on_token) = token.slot_public_key(slot).await
            && !same_public_key(&on_token, &self.public_key)
        {
            return Err(RootStoreError::WrongKey {
                kind: self.kind,
                key: self.key_name.to_string(),
                location: self.location(),
                descriptor: descriptor_path(&self.pib_root),
            });
        }
        Ok(token.signer_with(
            self.key_name.clone(),
            slot,
            self.public_key.clone(),
            Some(Zeroizing::new(pin.expose().to_vec())),
        ))
    }

    #[cfg(not(feature = "yubikey-piv"))]
    async fn yubikey_signer(&self, _pin: &RootSecret) -> Result<Arc<dyn Signer>, RootStoreError> {
        Err(RootStoreError::NotBuilt {
            kind: RootStoreKind::YubikeyPiv,
            feature: "yubikey-piv",
        })
    }

    /// The plaintext PKCS#8 of a software root (to move it).
    fn export_pkcs8(&self, secret: Option<&RootSecret>) -> Result<Zeroizing<Vec<u8>>, RootStoreError> {
        let bag_pkcs8 = |passphrase: &[u8]| -> Result<Zeroizing<Vec<u8>>, RootStoreError> {
            let path = self.safebag_path().unwrap_or_default();
            let wire = std::fs::read(&path).map_err(io_err(&path))?;
            let bag = SafeBag::decode(&wire).map_err(|e| RootStoreError::Descriptor {
                path: path.clone(),
                reason: format!("not a SafeBag: {e}"),
            })?;
            bag.decrypt_pkcs8(passphrase)
                .map(Zeroizing::new)
                .map_err(|_| RootStoreError::WrongPassphrase { path })
        };
        match self.kind {
            RootStoreKind::File => Ok(Zeroizing::new(
                FilePib::open(&self.pib_root)?.export_pkcs8(&self.key_name)?,
            )),
            RootStoreKind::SealedFile => {
                bag_pkcs8(secret.ok_or_else(|| self.unlock_needed())?.expose())
            }
            RootStoreKind::OsKeyring => {
                let entry = self.keychain.as_ref().ok_or_else(|| self.unlock_needed())?;
                let sealing = keychain::get(entry, &self.safebag_path().unwrap_or_default())?;
                bag_pkcs8(sealing.as_bytes())
            }
            RootStoreKind::YubikeyPiv => Err(RootStoreError::Unmovable {
                from: self.kind,
                to: self.kind,
                reason: "a YubiKey PIV key cannot leave the token".into(),
            }),
        }
    }

    /// The root's anchor certificate as signed Data (for a SafeBag).
    fn anchor_wire(&self, pib: &FilePib) -> Result<Bytes, RootStoreError> {
        let path = pib.root().join(CA_DIR).join(ANCHOR_CERT_FILE);
        if let Ok(wire) = std::fs::read(&path) {
            return Ok(Bytes::from(wire));
        }
        if let Some(bag) = self.safebag_path()
            && let Ok(wire) = std::fs::read(&bag)
            && let Ok(bag) = SafeBag::decode(&wire)
        {
            return Ok(bag.certificate);
        }
        pib.valid_cert_wires(&self.key_name)?
            .into_iter()
            .next()
            .ok_or_else(|| RootStoreError::Descriptor {
                path,
                reason: format!("no signed anchor certificate of {} found", self.key_name),
            })
    }

    /// Move a software root to the store `target`, never losing it: the new
    /// store is written and must sign with the same public key before the
    /// descriptor switches to it, and only then is the old material removed
    /// (a plaintext file is overwritten first, [`FilePib::delete_key`]).
    /// `current` unlocks the current store; `new_passphrase` seals a
    /// `sealed-file` target. Moving onto a YubiKey is refused (PIV takes no
    /// Ed25519 key), as is moving back to plaintext `file`.
    pub async fn move_to(
        &self,
        pib: &FilePib,
        target: RootStoreKind,
        current: Option<&RootSecret>,
        new_passphrase: Option<&RootSecret>,
    ) -> Result<RootStore, RootStoreError> {
        let refuse = |reason: &str| RootStoreError::Unmovable {
            from: self.kind,
            to: target,
            reason: reason.into(),
        };
        if target == self.kind {
            return Err(refuse("the root is already there"));
        }
        match target {
            RootStoreKind::YubikeyPiv => {
                return Err(refuse(
                    "a YubiKey PIV slot holds only a P-256 key generated on it (yubikey 0.8 imports \
                     no Ed25519 key), and this root is Ed25519. A hardware root needs a new \
                     namespace (`ndn-fwd init --force --root-store yubikey-piv`; every adopter \
                     adopts it again) or root rotation, which is not built yet",
                ));
            }
            RootStoreKind::File => {
                return Err(refuse(
                    "a root is never moved back into plaintext; keep it sealed",
                ));
            }
            _ => {}
        }
        if self.kind == RootStoreKind::YubikeyPiv {
            return Err(refuse("a YubiKey PIV key cannot leave the token"));
        }
        if target == RootStoreKind::OsKeyring {
            keychain::probe()?;
        }

        let new_passphrase = match target {
            RootStoreKind::SealedFile => Some(
                new_passphrase
                    .filter(|p| !p.expose().is_empty())
                    .ok_or_else(|| {
                        RootStoreError::Secret("a sealed-file root needs a passphrase".into())
                    })?,
            ),
            _ => None,
        };
        let pkcs8 = self.export_pkcs8(current)?;
        let anchor = self.anchor_wire(pib)?;
        let pending = PendingRoot {
            key: self.key_name.clone(),
            signer: Arc::new(
                Ed25519Signer::from_pkcs8_der(&pkcs8, self.key_name.clone())
                    .map_err(RootStoreError::Trust)?,
            ),
            seal: Seal::Software {
                pkcs8,
                passphrase: new_passphrase.cloned(),
                kind: target,
            },
        };
        if !pending
            .signer
            .public_key()
            .is_some_and(|pk| same_public_key(&pk, &self.public_key))
        {
            return Err(RootStoreError::WrongKey {
                kind: self.kind,
                key: self.key_name.to_string(),
                location: self.location(),
                descriptor: descriptor_path(pib.root()),
            });
        }
        let draft = pending.write_material(pib, &self.key_name, anchor)?;
        let moved = RootStore {
            kind: target,
            namespace: self.namespace.clone(),
            key_name: self.key_name.clone(),
            anchor_cert: self.anchor_cert.clone(),
            public_key: self.public_key.clone(),
            legacy: false,
            ..draft
        };

        // The new store must sign as the root before anything else changes.
        let check = moved
            .signer(new_passphrase)
            .await;
        let verified = match check {
            Ok(signer) => verify_signs(signer.as_ref(), &self.public_key).await,
            Err(e) => Err(e),
        };
        if let Err(e) = verified {
            moved.remove_material(pib);
            return Err(e);
        }
        moved.write_descriptor()?;

        // Committed: the old material goes.
        match self.kind {
            RootStoreKind::File => pib.delete_key(&self.key_name)?,
            _ => self.remove_material(pib),
        }
        Ok(moved)
    }

    /// Remove this store's private material (keychain entry, SafeBag, PIB
    /// key; a YubiKey slot is left as it is) and its descriptor — for
    /// `ndn-fwd init --force`, which replaces the root.
    pub(crate) fn destroy(&self, pib: &FilePib) -> Result<(), RootStoreError> {
        match self.kind {
            RootStoreKind::File => pib.delete_key(&self.key_name)?,
            _ => self.remove_material(pib),
        }
        let path = descriptor_path(pib.root());
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io_err(&path)(e)),
        }
    }

    /// Best effort: the SafeBag (overwritten, then removed) and keychain
    /// entry of a sealed store.
    fn remove_material(&self, _pib: &FilePib) {
        if let Some(path) = self.safebag_path()
            && let Err(e) = ndn_security::secure_fs::shred_file(&path)
        {
            tracing::warn!(target: "security", path = %path.display(), error = %e, "could not remove the old sealed root");
        }
        if let Some(entry) = &self.keychain
            && let Err(e) = keychain::delete(entry)
        {
            tracing::warn!(target: "security", service = %entry.service, account = %entry.account, error = %e, "could not remove the old keychain entry");
        }
    }

    fn write_descriptor(&self) -> Result<(), RootStoreError> {
        use base64::Engine as _;
        let d = Descriptor {
            kind: self.kind,
            namespace: self.namespace.to_string(),
            key_name: self.key_name.to_string(),
            anchor_cert: self.anchor_cert.to_string(),
            public_key: base64::engine::general_purpose::STANDARD.encode(&self.public_key),
            safebag: self.safebag.clone(),
            keychain: self.keychain.clone(),
            yubikey: self.yubikey.clone(),
        };
        let path = descriptor_path(&self.pib_root);
        let body = toml::to_string(&d).map_err(|e| RootStoreError::Descriptor {
            path: path.clone(),
            reason: e.to_string(),
        })?;
        let dir = self.pib_root.join(ROOT_STORE_DIR);
        ndn_security::secure_fs::create_private_dir_all(&dir).map_err(io_err(&dir))?;
        ndn_security::secure_fs::write_private(&path, format!("{DESCRIPTOR_HEADER}{body}"))
            .map_err(io_err(&path))
    }
}

/// Sign a fresh challenge with `signer` and verify it under `public_key`.
async fn verify_signs(signer: &dyn Signer, public_key: &[u8]) -> Result<(), RootStoreError> {
    let mut challenge = [0u8; 32];
    getrandom::getrandom(&mut challenge)
        .map_err(|_| RootStoreError::Trust(TrustError::KeyStore("system RNG unavailable".into())))?;
    let sig = signer.sign(&challenge).await?;
    let outcome =
        ndn_security::verify_by_sig_type(signer.sig_type(), &challenge, &sig, public_key).await?;
    if outcome == ndn_security::VerifyOutcome::Valid {
        Ok(())
    } else {
        Err(RootStoreError::Trust(TrustError::KeyStore(format!(
            "{} signed a challenge that does not verify under the root's public key",
            signer.key_name()
        ))))
    }
}

// ── Creating a root (ndn-fwd init) ─────────────────────────────────────────

/// A new root key, generated but not yet recorded: sign the namespace with
/// [`signer`](Self::signer), then [`commit`](Self::commit) it with the
/// anchor certificate.
pub(crate) struct PendingRoot {
    key: Name,
    signer: Arc<dyn Signer>,
    seal: Seal,
}

enum Seal {
    /// Already in the FilePib.
    File,
    /// In memory, to be sealed into a SafeBag.
    Software {
        pkcs8: Zeroizing<Vec<u8>>,
        /// `sealed-file`: the operator's; `os-keyring`: generated.
        passphrase: Option<RootSecret>,
        kind: RootStoreKind,
    },
    /// On the token.
    #[cfg_attr(not(feature = "yubikey-piv"), allow(dead_code))]
    Yubikey(YubikeyRoot),
}

impl PendingRoot {
    pub(crate) fn signer(&self) -> Arc<dyn Signer> {
        Arc::clone(&self.signer)
    }

    /// Generate the root key `key` (`<namespace>/KEY/<id>`) in the store
    /// `spec`.
    pub(crate) async fn create(
        pib: &FilePib,
        key: &Name,
        spec: &NewRootStore,
    ) -> Result<PendingRoot, RootStoreError> {
        let key = key.clone();
        match spec {
            NewRootStore::File => Ok(PendingRoot {
                signer: Arc::new(pib.generate_ed25519(&key)?),
                key,
                seal: Seal::File,
            }),
            NewRootStore::SealedFile { passphrase } => {
                if passphrase.expose().is_empty() {
                    return Err(RootStoreError::Secret(
                        "refusing an empty passphrase for the sealed root".into(),
                    ));
                }
                Self::software(key, RootStoreKind::SealedFile, Some(passphrase.clone()))
            }
            NewRootStore::OsKeyring => {
                keychain::probe()?;
                Self::software(key, RootStoreKind::OsKeyring, None)
            }
            NewRootStore::YubikeyPiv {
                pin,
                slot,
                touch_policy,
                serial,
                guard,
            } => Self::yubikey(key, pin, slot, touch_policy, *serial, guard).await,
        }
    }

    fn software(
        key: Name,
        kind: RootStoreKind,
        passphrase: Option<RootSecret>,
    ) -> Result<PendingRoot, RootStoreError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(&mut seed[..]).map_err(|_| {
            RootStoreError::Trust(TrustError::KeyStore("system RNG unavailable".into()))
        })?;
        let pkcs8 = Zeroizing::new(
            ndn_security::safebag::ed25519_seed_to_pkcs8(&seed)
                .map_err(|e| RootStoreError::Trust(TrustError::KeyStore(e.to_string())))?,
        );
        Ok(PendingRoot {
            signer: Arc::new(Ed25519Signer::from_seed(&seed, key.clone())),
            key,
            seal: Seal::Software {
                pkcs8,
                passphrase,
                kind,
            },
        })
    }

    #[cfg(feature = "yubikey-piv")]
    async fn yubikey(
        key: Name,
        pin: &RootSecret,
        slot: &str,
        touch_policy: &str,
        serial: Option<u32>,
        guard: &SlotGuard,
    ) -> Result<PendingRoot, RootStoreError> {
        use ndn_security::{YubikeyPinPolicy, YubikeyPiv, YubikeySlot, YubikeyTouchPolicy};
        let slot_id: YubikeySlot = slot.parse().map_err(RootStoreError::Yubikey)?;
        let touch: YubikeyTouchPolicy = touch_policy.parse().map_err(RootStoreError::Yubikey)?;
        let token = match serial {
            Some(s) => YubikeyPiv::open_by_serial(s),
            None => YubikeyPiv::open(),
        }
        .map_err(|e| RootStoreError::Yubikey(e.to_string()))?;
        check_generation_target(&token, slot_id, guard).await?;
        let pin_policy = YubikeyPinPolicy::Always;
        let (signer, _spki) = token
            .generate_with_policy(
                key.clone(),
                slot_id,
                pin_policy,
                touch,
                Zeroizing::new(pin.expose().to_vec()),
            )
            .await
            .map_err(|e| RootStoreError::Yubikey(e.to_string()))?;
        Ok(PendingRoot {
            key,
            signer,
            seal: Seal::Yubikey(YubikeyRoot {
                serial: token.serial(),
                slot: slot_id.as_str().to_string(),
                pin_policy: pin_policy.as_str().to_string(),
                touch_policy: touch.as_str().to_string(),
            }),
        })
    }

    #[cfg(not(feature = "yubikey-piv"))]
    async fn yubikey(
        _key: Name,
        _pin: &RootSecret,
        _slot: &str,
        _touch_policy: &str,
        _serial: Option<u32>,
        _guard: &SlotGuard,
    ) -> Result<PendingRoot, RootStoreError> {
        Err(RootStoreError::NotBuilt {
            kind: RootStoreKind::YubikeyPiv,
            feature: "yubikey-piv",
        })
    }

    /// Write the store's material (SafeBag, keychain entry) for the root
    /// `key` whose anchor certificate is `anchor`; the descriptor is not
    /// written. Returns the store, its identity fields to be completed.
    fn write_material(
        &self,
        pib: &FilePib,
        key: &Name,
        anchor: Bytes,
    ) -> Result<RootStore, RootStoreError> {
        let mut store = RootStore {
            pib_root: pib.root().to_path_buf(),
            kind: RootStoreKind::File,
            namespace: Name::root(),
            key_name: key.clone(),
            anchor_cert: Name::root(),
            public_key: Bytes::new(),
            safebag: None,
            keychain: None,
            yubikey: None,
            legacy: false,
        };
        match &self.seal {
            Seal::File => {}
            Seal::Yubikey(y) => {
                store.kind = RootStoreKind::YubikeyPiv;
                store.yubikey = Some(y.clone());
            }
            Seal::Software {
                pkcs8,
                passphrase,
                kind,
            } => {
                store.kind = *kind;
                let (file, sealing) = match kind {
                    RootStoreKind::OsKeyring => {
                        let entry = KeychainEntry {
                            service: KEYCHAIN_SERVICE.to_string(),
                            account: format!("{key} @ {}", canonical(pib.root()).display()),
                        };
                        let secret = keychain::new_sealing_secret()?;
                        keychain::set(&entry, &secret)?;
                        store.keychain = Some(entry);
                        (KEYCHAIN_SAFEBAG_FILE, RootSecret::new(secret.as_bytes().to_vec()))
                    }
                    _ => (
                        SEALED_SAFEBAG_FILE,
                        passphrase.clone().ok_or_else(|| {
                            RootStoreError::Secret("a sealed root needs a passphrase".into())
                        })?,
                    ),
                };
                let bag = SafeBag::encrypt(anchor, pkcs8, sealing.expose())
                    .map_err(|e| RootStoreError::Trust(TrustError::KeyStore(e.to_string())))?;
                let dir = pib.root().join(ROOT_STORE_DIR);
                ndn_security::secure_fs::create_private_dir_all(&dir).map_err(io_err(&dir))?;
                let path = dir.join(file);
                ndn_security::secure_fs::write_private(&path, bag.encode())
                    .map_err(io_err(&path))?;
                store.safebag = Some(file.to_string());
            }
        }
        Ok(store)
    }

    /// Record the root, now that the namespace anchor `anchor` is signed:
    /// seal it (SafeBag, keychain) and write the descriptor.
    pub(crate) fn commit(
        self,
        pib: &FilePib,
        namespace: &Name,
        anchor: &Certificate,
    ) -> Result<RootStore, RootStoreError> {
        let key = self.key.clone();
        if matches!(self.seal, Seal::File) {
            pib.store_cert(&key, anchor)?;
        }
        let wire = anchor.data_wire().ok_or_else(|| {
            RootStoreError::Trust(TrustError::KeyStore(
                "the root anchor certificate has no signed wire".into(),
            ))
        })?;
        let draft = self.write_material(pib, &key, wire)?;
        let store = RootStore {
            namespace: namespace.clone(),
            anchor_cert: (*anchor.name).clone(),
            public_key: anchor.public_key.clone(),
            ..draft
        };
        store.write_descriptor()?;
        Ok(store)
    }
}

fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

// ── OS keychain ────────────────────────────────────────────────────────────

/// The platform keychain through the `keyring` crate (feature `os-keyring`):
/// Secret Service (D-Bus) on Linux and the BSDs, Keychain on macOS/iOS,
/// Credential Manager on Windows. Anywhere else — and in builds without the
/// feature — no keychain is reachable (`keyring`'s in-memory mock store would
/// lose the secret at exit, so it is never used).
mod keychain {
    use std::path::Path;

    use zeroize::Zeroizing;

    use super::{KeychainEntry, RootStoreError};

    /// A fresh sealing secret: 32 random bytes, base64.
    pub(super) fn new_sealing_secret() -> Result<Zeroizing<String>, RootStoreError> {
        use base64::Engine as _;
        let mut raw = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(&mut raw[..])
            .map_err(|_| RootStoreError::Secret("system RNG unavailable".into()))?;
        Ok(Zeroizing::new(
            base64::engine::general_purpose::STANDARD.encode(&raw[..]),
        ))
    }

    #[cfg(all(
        feature = "os-keyring",
        any(
            target_os = "linux",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "macos",
            target_os = "ios",
            target_os = "windows"
        )
    ))]
    mod imp {
        use std::path::Path;

        use zeroize::Zeroizing;

        use super::super::{KEYCHAIN_SERVICE, KeychainEntry, RootStoreError};

        fn unavailable(e: keyring::Error) -> RootStoreError {
            RootStoreError::KeychainUnavailable {
                reason: e.to_string(),
            }
        }

        fn entry(e: &KeychainEntry) -> Result<keyring::Entry, RootStoreError> {
            keyring::Entry::new(&e.service, &e.account).map_err(unavailable)
        }

        pub(in super::super) fn probe() -> Result<(), RootStoreError> {
            let probe = keyring::Entry::new(KEYCHAIN_SERVICE, "reachability probe")
                .map_err(unavailable)?;
            match probe.get_password() {
                Ok(_) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(unavailable(e)),
            }
        }

        pub(in super::super) fn set(
            e: &KeychainEntry,
            secret: &Zeroizing<String>,
        ) -> Result<(), RootStoreError> {
            let handle = entry(e)?;
            handle.set_password(secret).map_err(unavailable)?;
            // Read it back through a fresh handle: a keychain that accepts
            // and forgets (no persistent collection) is not a store.
            match entry(e)?.get_password() {
                Ok(back) if back.as_str() == secret.as_str() => {
                    drop(Zeroizing::new(back));
                    Ok(())
                }
                Ok(back) => {
                    drop(Zeroizing::new(back));
                    Err(RootStoreError::KeychainUnavailable {
                        reason: "the keychain returned a different secret than it was given".into(),
                    })
                }
                Err(err) => Err(unavailable(err)),
            }
        }

        pub(in super::super) fn get(
            e: &KeychainEntry,
            safebag: &Path,
        ) -> Result<Zeroizing<String>, RootStoreError> {
            match entry(e)?.get_password() {
                Ok(secret) => Ok(Zeroizing::new(secret)),
                Err(keyring::Error::NoEntry) => Err(RootStoreError::KeychainEntryMissing {
                    service: e.service.clone(),
                    account: e.account.clone(),
                    path: safebag.to_path_buf(),
                }),
                Err(err) => Err(unavailable(err)),
            }
        }

        pub(in super::super) fn delete(e: &KeychainEntry) -> Result<(), RootStoreError> {
            match entry(e)?.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(err) => Err(unavailable(err)),
            }
        }
    }

    #[cfg(not(all(
        feature = "os-keyring",
        any(
            target_os = "linux",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "macos",
            target_os = "ios",
            target_os = "windows"
        )
    )))]
    mod imp {
        use std::path::Path;

        use zeroize::Zeroizing;

        use super::super::{KeychainEntry, RootStoreError};

        fn unavailable() -> RootStoreError {
            RootStoreError::KeychainUnavailable {
                reason: if cfg!(feature = "os-keyring") {
                    "this platform has no supported OS keychain".into()
                } else {
                    "this build has no OS keychain support (cargo feature `os-keyring`)".into()
                },
            }
        }

        pub(in super::super) fn probe() -> Result<(), RootStoreError> {
            Err(unavailable())
        }

        pub(in super::super) fn set(
            _e: &KeychainEntry,
            _secret: &Zeroizing<String>,
        ) -> Result<(), RootStoreError> {
            Err(unavailable())
        }

        pub(in super::super) fn get(
            _e: &KeychainEntry,
            _safebag: &Path,
        ) -> Result<Zeroizing<String>, RootStoreError> {
            Err(unavailable())
        }

        pub(in super::super) fn delete(_e: &KeychainEntry) -> Result<(), RootStoreError> {
            Err(unavailable())
        }
    }

    pub(super) fn probe() -> Result<(), RootStoreError> {
        imp::probe()
    }

    pub(super) fn set(e: &KeychainEntry, secret: &Zeroizing<String>) -> Result<(), RootStoreError> {
        imp::set(e, secret)
    }

    pub(super) fn get(e: &KeychainEntry, safebag: &Path) -> Result<Zeroizing<String>, RootStoreError> {
        imp::get(e, safebag)
    }

    pub(super) fn delete(e: &KeychainEntry) -> Result<(), RootStoreError> {
        imp::delete(e)
    }
}

/// Whether an OS keychain is reachable for this user now (what `ndn-fwd
/// init` defaults to); the error says why not and what to do instead.
pub fn os_keychain_reachable() -> Result<(), RootStoreError> {
    keychain::probe()
}

// ── Asking the operator (CLIs) ─────────────────────────────────────────────

/// The secret `kind` of a root store, for a CLI: from the environment
/// variable [`RootUnlockKind::env_var`], else the first line of `file`
/// (`--passphrase-file` / `--pin-file`), else asked on the terminal without
/// echo — twice when `confirm` (choosing a new passphrase). Never from the
/// command line. An empty secret is refused.
pub fn read_root_secret(
    kind: RootUnlockKind,
    file: Option<&Path>,
    confirm: bool,
    purpose: &str,
) -> Result<RootSecret, RootStoreError> {
    read_secret(
        kind.env_var(),
        &format!("--{}-file", kind.as_str()),
        file,
        confirm,
        purpose,
        &format!("root key {}", kind.as_str()),
    )
}

/// A secret for a CLI (a root store's or a recovery kit's): from the
/// environment variable `env`, else the first line of `file` (the option
/// `file_flag` names it), else asked on the terminal without echo — twice
/// when `confirm`. Never from the command line. An empty secret is refused.
/// `label` names the secret in prompts and errors.
pub fn read_secret(
    env: Option<&str>,
    file_flag: &str,
    file: Option<&Path>,
    confirm: bool,
    purpose: &str,
    label: &str,
) -> Result<RootSecret, RootStoreError> {
    let secret = if let Some(var) = env
        && let Ok(value) = std::env::var(var)
    {
        Zeroizing::new(value)
    } else if let Some(path) = file {
        let text = Zeroizing::new(std::fs::read_to_string(path).map_err(io_err(path))?);
        Zeroizing::new(
            text.lines()
                .next()
                .unwrap_or_default()
                .trim_end_matches('\r')
                .to_string(),
        )
    } else {
        let no_terminal = |e: std::io::Error| {
            RootStoreError::Secret(format!(
                "cannot ask for the {label} ({e}): no terminal. Set {} or pass {file_flag} \
                 <path>",
                env.unwrap_or("-")
            ))
        };
        let first = tty::read_hidden(&format!("{purpose} — {label}: ")).map_err(no_terminal)?;
        if confirm {
            let again = tty::read_hidden(&format!("Repeat the {label}: ")).map_err(no_terminal)?;
            if *first != *again {
                return Err(RootStoreError::Secret(format!("the two {label}s differ")));
            }
        }
        first
    };
    if secret.is_empty() {
        return Err(RootStoreError::Secret(format!("refusing an empty {label}")));
    }
    Ok(RootSecret::new(secret.as_bytes().to_vec()))
}

mod tty {
    use zeroize::Zeroizing;

    /// Ask on the controlling terminal with echo off.
    #[cfg(unix)]
    #[allow(unsafe_code)]
    pub(super) fn read_hidden(prompt: &str) -> std::io::Result<Zeroizing<String>> {
        use std::io::{BufRead, Write};
        use std::os::fd::AsRawFd;
        let tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")?;
        let fd = tty.as_raw_fd();
        // SAFETY: `termios` is plain data; tcgetattr fills it for a valid fd.
        let mut term: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut term) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let saved = term;
        term.c_lflag &= !libc::ECHO;
        term.c_lflag |= libc::ECHONL;
        // SAFETY: valid fd and termios.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &term) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut line = Zeroizing::new(String::new());
        let read = (&tty)
            .write_all(prompt.as_bytes())
            .and_then(|()| (&tty).flush())
            .and_then(|()| std::io::BufReader::new(&tty).read_line(&mut line));
        // SAFETY: restores the attributes read above on the same fd.
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &saved) };
        read?;
        let len = line.trim_end_matches(['\r', '\n']).len();
        line.truncate(len);
        Ok(line)
    }

    #[cfg(not(unix))]
    pub(super) fn read_hidden(_prompt: &str) -> std::io::Result<Zeroizing<String>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "hidden terminal input is implemented on unix only",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_parse_and_name_their_unlock() {
        for kind in RootStoreKind::ALL {
            assert_eq!(kind.as_str().parse::<RootStoreKind>(), Ok(kind));
            assert_eq!(kind.unlock().as_str().parse::<RootUnlockKind>(), Ok(kind.unlock()));
        }
        assert!("tpm".parse::<RootStoreKind>().is_err());
    }

    #[test]
    fn secrets_are_redacted() {
        let s = RootSecret::new(b"hunter2".to_vec());
        assert!(!format!("{s:?}").contains("hunter2"));
    }

    /// A descriptor naming a yubikey-piv root parses without hardware, and
    /// one missing its kind's fields (or escaping `root/`) is refused.
    #[test]
    fn descriptors_are_validated() {
        let dir = tempfile::tempdir().unwrap();
        let path = descriptor_path(dir.path());
        let ok = r#"
kind = "yubikey-piv"
namespace = "/home/bob"
key_name = "/home/bob/KEY/root"
anchor_cert = "/home/bob/KEY/root/self/v=1"
public_key = "AAEC"
[yubikey]
serial = 1234
slot = "9c"
pin_policy = "always"
touch_policy = "always"
"#;
        let store = RootStore::parse(dir.path(), &path, ok).unwrap();
        assert_eq!(store.kind(), RootStoreKind::YubikeyPiv);
        assert_eq!(store.unlock_kind(), RootUnlockKind::Pin);
        assert_eq!(store.yubikey().unwrap().serial, 1234);

        let no_fields = ok.split("[yubikey]").next().unwrap();
        assert!(RootStore::parse(dir.path(), &path, no_fields).is_err());
        let escaping = r#"
kind = "sealed-file"
namespace = "/home/bob"
key_name = "/home/bob/KEY/root"
anchor_cert = "/home/bob/KEY/root/self/v=1"
public_key = "AAEC"
safebag = "../keys/x"
"#;
        assert!(RootStore::parse(dir.path(), &path, escaping).is_err());
    }
}
