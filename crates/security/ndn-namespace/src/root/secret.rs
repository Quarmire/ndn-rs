//! The secrets a root operation asks its host for: the root store's
//! passphrase or PIN, a recovery kit's passphrase, PIN or words.
//!
//! The library never reads a terminal or a file for them: the host's
//! [`SecretSource`] is asked with what kind of secret, what for (as data —
//! a host words its own prompt) and whether a new one is chosen (to be
//! confirmed). A secret is used for one operation and dropped (zeroed) right
//! after; it never goes to the running device.

use ndn_cert::{RecoverySeed, RootSecret, RootUnlockKind};
use ndn_packet::Name;

use super::RootError;
use ndn_cert::report::code;

/// What kind of secret is asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKind {
    /// A `sealed-file` root store's passphrase.
    RootPassphrase,
    /// A `yubikey-piv` root store's PIV PIN.
    RootPin,
    /// A file kit's passphrase.
    KitPassphrase,
    /// A YubiKey kit's PIV PIN.
    KitPin,
    /// A word kit's 24 recovery words, space-separated.
    KitWords,
}

impl SecretKind {
    /// The secret a root store of unlock kind `kind` needs; `None` for one
    /// that needs nothing.
    pub fn of_root(kind: RootUnlockKind) -> Option<SecretKind> {
        match kind {
            RootUnlockKind::Nothing => None,
            RootUnlockKind::Passphrase => Some(SecretKind::RootPassphrase),
            RootUnlockKind::Pin => Some(SecretKind::RootPin),
        }
    }

    /// Stable id, as in the `secret` param of refusals.
    pub fn as_str(self) -> &'static str {
        match self {
            SecretKind::RootPassphrase => "root-passphrase",
            SecretKind::RootPin => "root-pin",
            SecretKind::KitPassphrase => "kit-passphrase",
            SecretKind::KitPin => "kit-pin",
            SecretKind::KitWords => "kit-words",
        }
    }
}

/// The new trust-context version a root signature makes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionChange {
    /// Revoking the keys `name` designates.
    Revoke { name: Name },
    /// Adding a recovery kit to `namespace`.
    AddKit { namespace: Name },
    /// Revoking the recovery kit `key`.
    RevokeKit { key: Name },
    /// Updating the schema of `namespace`.
    UpdateSchema { namespace: Name },
}

/// What a secret is asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretPurpose {
    /// Creating a namespace root (init, or a recovery's new root).
    CreateRoot,
    /// Unlocking the root to sign a new version.
    SignVersion(VersionChange),
    /// Unlocking the root to move it to another store.
    MoveRoot,
    /// Sealing the root in its new store.
    SealRoot,
    /// Creating a YubiKey recovery kit for `namespace`.
    CreateKit { namespace: Name },
    /// Sealing a new file kit.
    SealKit,
    /// Opening a kit of `namespace` to check it (nothing is signed).
    CheckKit { namespace: Name },
    /// Opening a kit to recover `namespace`.
    Recover { namespace: Name },
}

/// One secret asked of the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRequest {
    pub kind: SecretKind,
    pub purpose: SecretPurpose,
    /// A new secret is chosen: ask for it twice.
    pub confirm: bool,
}

/// Where the host gets the secrets a root operation needs — an operator's
/// terminal, an app's dialog. Asked only once every check that needs no
/// secret passed, in the order the operation needs them.
#[async_trait::async_trait]
pub trait SecretSource: Send + Sync {
    /// The secret `request` asks for; a refusal (code `secret-unavailable`
    /// when none can be had) ends the operation with nothing signed.
    async fn secret(&self, request: &SecretRequest) -> Result<RootSecret, RootError>;

    /// Called when a new root is about to be created in the plaintext
    /// `file` store, which no secret protects (to warn the person).
    fn unprotected_root(&self) {}
}

impl dyn SecretSource + '_ {
    /// [`SecretSource::secret`] for an owned request.
    pub(crate) async fn secret_for(&self, request: SecretRequest) -> Result<RootSecret, RootError> {
        self.secret(&request).await
    }
}

/// The secret a root store of unlock kind `kind` needs for `purpose`;
/// `None` when it needs none.
pub(crate) async fn root_secret(
    secrets: &dyn SecretSource,
    kind: RootUnlockKind,
    purpose: SecretPurpose,
    confirm: bool,
) -> Result<Option<RootSecret>, RootError> {
    let Some(kind) = SecretKind::of_root(kind) else {
        return Ok(None);
    };
    let request = SecretRequest {
        kind,
        purpose,
        confirm,
    };
    Ok(Some(secrets.secret(&request).await?))
}

/// A kit secret of `kind` for `purpose`.
pub(crate) async fn kit_secret(
    secrets: &dyn SecretSource,
    kind: SecretKind,
    purpose: SecretPurpose,
    confirm: bool,
) -> Result<RootSecret, RootError> {
    secrets
        .secret(&SecretRequest {
            kind,
            purpose,
            confirm,
        })
        .await
}

/// A word kit's seed, from its words asked for `purpose`.
pub(crate) async fn kit_words(
    secrets: &dyn SecretSource,
    purpose: SecretPurpose,
) -> Result<RecoverySeed, RootError> {
    let words = kit_secret(secrets, SecretKind::KitWords, purpose, false).await?;
    let words = std::str::from_utf8(words.expose()).map_err(|e| {
        RootError::new(code::BAD_RECOVERY_WORDS, "the recovery words are not text")
            .with("error", e)
            .caused_by(e)
    })?;
    Ok(RecoverySeed::from_words(words)?)
}
