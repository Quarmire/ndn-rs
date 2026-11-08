//! A new namespace on this device, which becomes its root device
//! ([`ndn_cert::init_namespace_in_pib_with`]): the root `<ns>/KEY/root` in
//! the root store chosen, the CA identity `<ns>/CA` certified by the root,
//! this device's admin identity `<ns>/admin/<device>` certified by the CA,
//! and the root-signed trust context — carrying the generated namespace
//! schema and the stated policies — stored in the PIB. An existing root is
//! never replaced unless forced. A self-certifying namespace
//! (`/user/<0xA1: …>`, [`InitNamespace::SelfCertifying`]) is named from its
//! new Ed25519 root ([`ndn_cert::init_self_certifying_in_pib_with`]).

use std::path::{Path, PathBuf};

use ndn_cert::report::code;
use ndn_cert::{
    GenesisKey, NamespaceInitError, NamespacePolicies, NewRootStore, PersistedNamespace,
    PolicyInput, SlotGuard, anchor_fingerprint, init_namespace_in_pib_with,
    init_self_certifying_in_pib_with,
};
use ndn_packet::Name;
use ndn_trust_envelope::TrustEnvelope;

use super::{RootError, SecretKind, SecretPurpose, SecretRequest, SecretSource, create_pib};

/// Where a new root goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootStoreChoice {
    /// The OS keychain when one is reachable; refused
    /// (`no-default-root-store`) when none is.
    Default,
    OsKeyring,
    /// A file sealed by a new passphrase (asked, confirmed).
    SealedFile,
    /// Generated on a YubiKey (PIN asked).
    YubikeyPiv(YubikeyRoot),
    /// Plaintext in the PIB: tests and development
    /// ([`SecretSource::unprotected_root`] is told).
    File,
}

/// The token and slot of a new `yubikey-piv` root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YubikeyRoot {
    /// `9a`, `9c` (default), `9d`, `9e`.
    pub slot: String,
    /// `always` (default), `cached`, `never`.
    pub touch_policy: String,
    /// The token, when several are connected.
    pub serial: Option<u32>,
    /// Generate even over a slot holding a key (it is not needed).
    pub replace_slot: bool,
}

impl Default for YubikeyRoot {
    fn default() -> Self {
        Self {
            slot: ndn_cert::root_store::DEFAULT_YUBIKEY_SLOT.to_string(),
            touch_policy: "always".to_string(),
            serial: None,
            replace_slot: false,
        }
    }
}

/// The store a new root is created in, with its secret asked of `secrets`
/// (purpose [`SecretPurpose::CreateRoot`]).
pub async fn new_root_store(
    choice: &RootStoreChoice,
    secrets: &dyn SecretSource,
) -> Result<NewRootStore, RootError> {
    let ask = |kind, confirm| {
        secrets.secret_for(SecretRequest {
            kind,
            purpose: SecretPurpose::CreateRoot,
            confirm,
        })
    };
    Ok(match choice {
        RootStoreChoice::Default => {
            if let Err(why) = ndn_cert::os_keychain_reachable() {
                let reason = why.to_string();
                return Err(RootError::new(
                    code::NO_DEFAULT_ROOT_STORE,
                    "no OS keychain is reachable: choose the root store",
                )
                .with("reason", reason)
                .caused_by(why));
            }
            NewRootStore::OsKeyring
        }
        RootStoreChoice::OsKeyring => NewRootStore::OsKeyring,
        RootStoreChoice::SealedFile => NewRootStore::SealedFile {
            passphrase: ask(SecretKind::RootPassphrase, true).await?,
        },
        RootStoreChoice::YubikeyPiv(token) => NewRootStore::YubikeyPiv {
            pin: ask(SecretKind::RootPin, false).await?,
            slot: token.slot.clone(),
            touch_policy: token.touch_policy.clone(),
            serial: token.serial,
            // An occupied slot is refused unless its key is not needed; a
            // recovery also keeps the root off the kit's token.
            guard: SlotGuard {
                replace: token.replace_slot,
                not_on: None,
            },
        },
        RootStoreChoice::File => {
            secrets.unprotected_root();
            NewRootStore::File
        }
    })
}

/// Which namespace [`init`] makes.
pub enum InitNamespace {
    /// This name, with a new root.
    Named(Name),
    /// The self-certifying namespace of `key`, `/user/<0xA1: SHA-256 of its
    /// public key>`: `key` is its root and signs its genesis. `given`, a
    /// name the person typed, must be that one: a new key never hashes to
    /// a name chosen before it.
    SelfCertifying {
        key: GenesisKey,
        given: Option<Name>,
    },
}

impl InitNamespace {
    /// A self-certifying namespace named from a new root key, which must
    /// make `given` when one is given.
    pub fn self_certifying(given: Option<Name>) -> Result<Self, RootError> {
        let key = GenesisKey::generate().map_err(|e| {
            RootError::new(code::ROOT_BAD_REQUEST, "no root key could be made")
                .with("error", &e)
                .caused_by(e)
        })?;
        Ok(Self::SelfCertifying { key, given })
    }
}

/// What [`init`] makes.
pub struct InitRequest {
    pub pib_dir: PathBuf,
    pub namespace: InitNamespace,
    /// This device's name (`<ns>/admin/<device>`).
    pub device: String,
    /// Replace an existing root of the namespace (every adopter must then
    /// adopt again). A self-certifying namespace is never made again: its
    /// root is replaced by a recovery, which keeps its name.
    pub force: bool,
    /// What enrollment needs an admin's approval for, which devices may
    /// link, relay and make direct paths, which relays are advertised: the
    /// context advertises them and the CA enforces exactly that.
    pub stated: PolicyInput,
    pub root: RootStoreChoice,
}

/// A namespace made on this device.
pub struct Initialized {
    /// What was made: the root, CA and admin identities, the context.
    pub persisted: PersistedNamespace,
    /// What the context advertises.
    pub policies: NamespacePolicies,
    /// The PIB, absolute (a running device may run from elsewhere).
    pub pib_abs: PathBuf,
    /// The namespace's expected fingerprint (the root anchor's).
    pub anchor_fingerprint: [u8; 32],
    /// The anchor link without the context: a short QR; the context is
    /// fetched by name. (The full link is `persisted.init.envelope`.)
    pub fingerprint_link: TrustEnvelope,
    /// Whether it is self-certifying (`/user/<0xA1: …>`): its name alone
    /// adopts it, with no expected fingerprint.
    pub self_certifying: bool,
}

/// The anchor link of `namespace`: its expected `fingerprint`, `version`,
/// and the signed context inline when `context_data` is given.
pub fn anchor_link(
    namespace: &Name,
    fingerprint: [u8; 32],
    version: u64,
    context_data: Option<bytes::Bytes>,
) -> TrustEnvelope {
    TrustEnvelope::Anchor {
        namespace: Some(namespace.to_string()),
        fingerprint: Some(fingerprint),
        version: Some(version),
        context_data,
        context_content: None,
    }
}

/// `path`, absolute when it can be resolved.
pub(crate) fn absolute(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Make the namespace `request` names on this device. The stated policies
/// are checked first, then the root's secret asked, then everything made;
/// the root signer is dropped once done. A self-certifying namespace is
/// named from its root key: a name given that the key does not make, or a
/// YubiKey root store (which takes no Ed25519 key), is refused before
/// anything is asked or made.
pub async fn init(
    request: InitRequest,
    secrets: &dyn SecretSource,
) -> Result<Initialized, RootError> {
    let InitRequest {
        pib_dir,
        namespace,
        device,
        force,
        stated,
        root,
    } = request;
    let (namespace, genesis) = match namespace {
        InitNamespace::Named(namespace) => {
            let self_certifying = ndn_security::self_certifying::self_certifying_digest(&namespace)
                .map_err(NamespaceInitError::from)?;
            if self_certifying.is_some() {
                return Err(NamespaceInitError::SelfCertifying {
                    namespace: namespace.to_string(),
                }
                .into());
            }
            (namespace, None)
        }
        InitNamespace::SelfCertifying { key, given } => {
            let namespace = key.namespace();
            if let Some(given) = given.filter(|given| *given != namespace) {
                return Err(NamespaceInitError::SelfCertifying {
                    namespace: given.to_string(),
                }
                .into());
            }
            if matches!(root, RootStoreChoice::YubikeyPiv(_)) {
                return Err(NamespaceInitError::GenesisOnToken.into());
            }
            (namespace, Some(key))
        }
    };
    let policies = stated.new_namespace_policies(&namespace)?;
    let root = new_root_store(&root, secrets).await?;
    let pib = create_pib(&pib_dir)?;
    let persisted = match &genesis {
        None => {
            init_namespace_in_pib_with(&pib, &namespace, &device, force, &root, &policies).await?
        }
        Some(key) => init_self_certifying_in_pib_with(&pib, key, &device, &root, &policies).await?,
    };
    let self_certifying = genesis.is_some();
    drop(root);
    let init = &persisted.init;
    let fingerprint = anchor_fingerprint(&init.anchor);
    let fingerprint_link = anchor_link(&namespace, fingerprint, init.context.version(), None);
    Ok(Initialized {
        pib_abs: absolute(&pib_dir),
        anchor_fingerprint: fingerprint,
        fingerprint_link,
        self_certifying,
        persisted,
        policies,
    })
}
