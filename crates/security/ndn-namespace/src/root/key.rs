//! Where the namespace root keys live on their root device, and moving one
//! ([`ndn_cert::root_store`]). A device can hold the roots of several
//! namespaces, one store each: an operation on one root names its
//! namespace, or acts on the only one the PIB holds.
//!
//! Moving is offline on the PIB and safe while the running device runs: it
//! reads the store's descriptor per operation. The new store signs as the
//! root before the old copy is removed (a plaintext key file is overwritten
//! first). The roots of the other namespaces are not touched.

use std::path::{Path, PathBuf};

use ndn_cert::report::code;
use ndn_cert::{RootStore, RootStoreError, RootStoreKind, RootUnlockKind};
use ndn_packet::Name;
use ndn_security::{FilePib, KeyRole};

use super::secret::root_secret;
use super::{RootError, SecretPurpose, SecretSource, open_pib};

/// What `operation` a root-key status reports, for refusals.
const STATUS_WORK: &str = "its root key is reported";
/// What `operation` a root-key move does, for refusals.
const MOVE_WORK: &str = "a root key is moved";

/// Where a root key lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootStoreFacts {
    pub kind: RootStoreKind,
    /// The store's location as the store describes it (a file, a keychain
    /// entry, a token and slot).
    pub location: String,
}

impl RootStoreFacts {
    pub fn of(store: &RootStore) -> Self {
        Self {
            kind: store.kind(),
            location: store.location(),
        }
    }
}

/// The recovery kits of the namespace held with the root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeldKits {
    /// `kits` recovery anchors in the held version `version`.
    Held { version: u64, kits: usize },
    /// No stored trust context of the namespace.
    NotStored,
    /// The stored trust context could not be read (why).
    Unreadable(String),
}

/// The root key of one namespace on its root device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootKeyStatus {
    pub namespace: Name,
    pub key: Name,
    pub store: RootStoreFacts,
    pub unlock: RootUnlockKind,
    /// The namespace was made before root stores (a plaintext root).
    pub legacy: bool,
    pub kits: HeldKits,
}

/// A root key moved to another store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootMoved {
    pub namespace: Name,
    pub key: Name,
    pub from: RootStoreKind,
    pub to: RootStoreFacts,
}

/// A PIB and the namespace roots it holds, by namespace.
pub struct HeldRoots {
    pib_dir: PathBuf,
    pib: FilePib,
    stores: Vec<RootStore>,
}

/// The PIB at `pib_dir` and its root stores.
pub fn open(pib_dir: &Path) -> Result<HeldRoots, RootError> {
    let pib = open_pib(pib_dir)?;
    let stores = RootStore::open_all(&pib)?;
    Ok(HeldRoots {
        pib_dir: pib_dir.to_path_buf(),
        pib,
        stores,
    })
}

impl HeldRoots {
    /// Every root store, by namespace; empty on a device that is no root
    /// device.
    pub fn stores(&self) -> &[RootStore] {
        &self.stores
    }

    /// The root store of `namespace`, else the only one held. Refusals:
    /// `not-root-device` (none held), `other-namespace-root` (none of the
    /// namespace named), `several-namespaces` (none named, several held).
    /// `work` is what is done on the root device (param `operation`).
    pub fn store(&self, namespace: Option<&Name>, work: &str) -> Result<&RootStore, RootError> {
        let held = || -> Vec<String> {
            self.stores
                .iter()
                .map(|s| s.namespace().to_string())
                .collect()
        };
        let none = || {
            RootError::new(
                code::NOT_ROOT_DEVICE,
                "this device holds no namespace root: do this on the root device",
            )
            .with("pib", self.pib_dir.display())
            .with("operation", work)
        };
        match (namespace, self.stores.as_slice()) {
            (_, []) => Err(none()),
            (Some(ns), stores) => stores.iter().find(|s| s.namespace() == ns).ok_or_else(|| {
                RootError::new(
                    code::OTHER_NAMESPACE_ROOT,
                    "this device holds the roots of other namespaces only: do this on the \
                     namespace's root device",
                )
                .with("pib", self.pib_dir.display())
                .with("namespace", held().join(","))
                .with("requested", ns)
                .with("operation", work)
            }),
            (None, [one]) => Ok(one),
            (None, _) => Err(RootStoreError::SeveralRoots {
                pib: self.pib_dir.display().to_string(),
                held: held(),
            }
            .into()),
        }
    }

    /// The status of every root key, or of the one of `namespace` only
    /// (refused as [`store`](Self::store) when it holds none of it). Empty
    /// on a device that is no root device.
    pub fn status(&self, namespace: Option<&Name>) -> Result<Vec<RootKeyStatus>, RootError> {
        let stores: Vec<&RootStore> = match namespace {
            Some(_) => vec![self.store(namespace, STATUS_WORK)?],
            None => self.stores.iter().collect(),
        };
        Ok(stores.into_iter().map(|s| self.status_of(s)).collect())
    }

    fn status_of(&self, store: &RootStore) -> RootKeyStatus {
        let kits = match ndn_cert::read_stored_context(&self.pib_dir, store.namespace()) {
            Ok(Some((ctx, _))) => HeldKits::Held {
                version: ctx.version(),
                kits: ctx.keys_with_role(KeyRole::RECOVERY_ANCHOR).count(),
            },
            Ok(None) => HeldKits::NotStored,
            Err(e) => HeldKits::Unreadable(e.to_string()),
        };
        RootKeyStatus {
            namespace: store.namespace().clone(),
            key: store.key_name().clone(),
            store: RootStoreFacts::of(store),
            unlock: store.unlock_kind(),
            legacy: store.is_legacy(),
            kits,
        }
    }

    /// Move the root of `namespace` (else the only one held, as
    /// [`store`](Self::store)) to a store of kind `to`. Secrets are asked
    /// only for a move the store can make (the others are refused with why,
    /// `root-store-unmovable`): the current store's, then a new passphrase
    /// for a `sealed-file` target.
    pub async fn move_to(
        &self,
        namespace: Option<&Name>,
        to: RootStoreKind,
        secrets: &dyn SecretSource,
    ) -> Result<RootMoved, RootError> {
        let store = self.store(namespace, MOVE_WORK)?;
        let from = store.kind();
        // The current store and the target never need the same secret — a
        // store is never moved to its own kind.
        let movable = !matches!(to, RootStoreKind::YubikeyPiv | RootStoreKind::File)
            && to != from
            && from != RootStoreKind::YubikeyPiv;
        let (current, new_passphrase) = if movable {
            let current =
                root_secret(secrets, store.unlock_kind(), SecretPurpose::MoveRoot, false).await?;
            let new_passphrase = match to {
                RootStoreKind::SealedFile => {
                    root_secret(
                        secrets,
                        RootUnlockKind::Passphrase,
                        SecretPurpose::SealRoot,
                        true,
                    )
                    .await?
                }
                _ => None,
            };
            (current, new_passphrase)
        } else {
            (None, None)
        };
        let moved = store
            .move_to(&self.pib, to, current.as_ref(), new_passphrase.as_ref())
            .await?;
        Ok(RootMoved {
            namespace: store.namespace().clone(),
            key: moved.key_name().clone(),
            from,
            to: RootStoreFacts::of(&moved),
        })
    }
}
