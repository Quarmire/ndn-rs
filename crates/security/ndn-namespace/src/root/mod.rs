//! Root-device operations, as a library: everything done where a
//! namespace's root (or a recovery kit) is unlocked — an operator's CLI, an
//! app's admin screen — never inside the running device, which holds only
//! public keys.
//!
//! - [`init`]: a new namespace on this device, its root in the store the
//!   person picks ([`init::RootStoreChoice`]: the OS keychain, a
//!   passphrase-sealed file, a YubiKey, or plaintext `file`).
//! - [`revoke`]: a new version revoking a device, key or certificate.
//! - [`kit`]: recovery kits — create (24 words, a sealed file, or a key on a
//!   second YubiKey, listed as a recovery anchor by a new version), list,
//!   check, revoke.
//! - [`recover`]: make a replacement device the root device with a kit.
//! - [`key`]: where the root key lives, and moving it.
//! - [`schema`]: the held schema as data, why a key may sign a name, and
//!   bringing a namespace's schema up to date.
//!
//! Each operation checks first whatever needs no key ("plan"); a host may
//! show the plan before going on. Only then are secrets asked and the root
//! unlocked, for the one signature: the signer is dropped (a software key
//! zeroed) right after signing. The secret never leaves the host: the
//! running device receives only the signed version.
//!
//! # Namespaces
//!
//! A PIB can hold the roots of several namespaces, one root store each
//! ([`ndn_cert::RootStore::open_all`]). Every operation acts on one
//! namespace and touches only its root, its held version and its kits: the
//! namespace named by the host, else the only one held (several held and
//! none named is `several-namespaces`, listing them; one named that the PIB
//! holds no root of is `other-namespace-root`). A revocation without a
//! namespace acts on the namespace covering the name revoked.
//!
//! # What the host provides
//!
//! - a [`SecretSource`]: the root's passphrase or PIN, a kit's passphrase,
//!   PIN or words, asked with what they are for as data
//!   ([`SecretRequest`]) — a host words its own prompt, and decides where
//!   secrets come from (`ndn-fwd`: environment, a file, the terminal);
//! - a [`RunningDevice`]: the running device that uses the same PIB, which
//!   takes each signed version ([`device::hand_over`]: the retry and undo
//!   rules of [`crate::admin`]); the library checks it uses the same PIB,
//!   and keeps the version for its next start when none runs. A daemon
//!   reached over its management socket is [`daemon::MgmtDevice`].
//!
//! # Outcomes and refusals
//!
//! Outcomes are typed data (versions `N → N+1`, keys revoked, where a
//! version went, kit facts, anchor links, root store kind and location,
//! schema changes); a host words them. Every refusal is a [`RootError`]: a
//! [`TrustRefusal`](ndn_cert::report::TrustRefusal) with a code of the
//! root-device section of [`ndn_cert::report::code`], params and a neutral
//! sentence, plus the failure of the step underneath as its source. The
//! codes are listed in `ndn-rs/docs/specs/mgmt-trust.md` ("Root-device
//! operations (library)").

pub mod daemon;
pub mod device;
mod error;
pub mod init;
pub mod key;
pub mod kit;
pub mod recover;
pub mod revoke;
pub mod schema;
mod secret;
#[cfg(test)]
mod tests;

use std::path::Path;
use std::sync::Arc;

use ndn_cert::RootStore;
use ndn_cert::report::code;
use ndn_security::{FilePib, Signer};

pub use device::{DeviceSession, Reach, RunningDevice};
pub use error::{RootError, Source};
pub use secret::{SecretKind, SecretPurpose, SecretRequest, SecretSource, VersionChange};

/// The PIB at `pib_dir`, which must exist (`pib-unreadable`).
pub(crate) fn open_pib(pib_dir: &Path) -> Result<FilePib, RootError> {
    FilePib::open(pib_dir).map_err(|e| pib_unreadable(pib_dir, e))
}

/// The PIB at `pib_dir`, created when missing (`pib-unreadable`).
pub(crate) fn create_pib(pib_dir: &Path) -> Result<FilePib, RootError> {
    FilePib::new(pib_dir).map_err(|e| pib_unreadable(pib_dir, e))
}

fn pib_unreadable(pib_dir: &Path, e: ndn_security::PibError) -> RootError {
    RootError::new(code::PIB_UNREADABLE, "the PIB could not be opened")
        .with("pib", pib_dir.display())
        .caused_by(e)
}

/// The root of `store`, unlocked to sign `change` (its secret asked of
/// `secrets`). A store that does not unlock is `root-not-unlocked`. Drop
/// the signer right after signing.
pub(crate) async fn unlock_root(
    store: &RootStore,
    secrets: &dyn SecretSource,
    change: VersionChange,
) -> Result<Arc<dyn Signer>, RootError> {
    let unlock = secret::root_secret(
        secrets,
        store.unlock_kind(),
        SecretPurpose::SignVersion(change),
        false,
    )
    .await?;
    let root = store.signer(unlock.as_ref()).await.map_err(|e| {
        RootError::wrapping(
            code::ROOT_NOT_UNLOCKED,
            "the root did not unlock; nothing was signed",
            e.into(),
        )
    });
    drop(unlock);
    root
}
