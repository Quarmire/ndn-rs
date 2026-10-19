//! Recovery kits of a namespace ([`ndn_cert::recovery`]).
//!
//! A kit holds a separate **recovery key**, never a copy of the root. On the
//! root device, [`create`] makes the key (24 words shown once, a
//! passphrase-sealed file, or a key generated on a second YubiKey) and the
//! root — unlocked for this one signature — signs a new version listing it
//! as a recovery anchor; [`revoke`] signs a version without it, revoking its
//! key. Both hand the version to the running device that uses the same PIB
//! ([`super::device::hand_over`]). [`list`] and [`check`] read the held
//! context only and sign nothing.
//!
//! A YubiKey kit is never made on the root's own token, nor over an
//! occupied slot unless the person says the slot's key is not needed
//! ([`ndn_cert::SlotGuard`]).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use ndn_cert::report::code;
use ndn_cert::{
    FileKit, KitFormat, RecoverySeed, RootStore, SlotGuard, YubikeyKit, add_recovery_anchor,
    anchor_fingerprint, held_context, kit_anchor, recovery_anchor, remove_recovery_anchor,
    seal_file_kit,
};
use ndn_packet::Name;
use ndn_security::{KeyRole, Signer};

use super::device::{hand_over, not_taken, settle};
use super::secret::{kit_secret, kit_words};
use super::{
    RootError, RunningDevice, SecretKind, SecretPurpose, SecretSource, VersionChange, open_pib,
    unlock_root,
};
use crate::admin::{HandedOver, NotTaken};

/// What `operation` the root device does, for `not-root-device`.
const KIT_WORK: &str = "recovery kits are made and revoked";

/// A kit to open: its words, a YubiKey (token and slot), or a kit file.
#[derive(Debug, Clone)]
pub enum KitSpec {
    Words,
    Yubikey(YubikeyKit),
    File(PathBuf),
}

impl KitSpec {
    pub fn format(&self) -> KitFormat {
        match self {
            KitSpec::Words => KitFormat::Words,
            KitSpec::Yubikey(_) => KitFormat::Yubikey,
            KitSpec::File(_) => KitFormat::File,
        }
    }
}

/// The namespace a kit operation acts on: `named`, else the one a file kit
/// names, else the only context the PIB at `pib_dir` holds.
pub fn kit_namespace(
    named: Option<&Name>,
    spec: Option<&KitSpec>,
    pib_dir: &Path,
) -> Result<Name, RootError> {
    if let Some(namespace) = named {
        return Ok(namespace.clone());
    }
    let kit_file = match spec {
        Some(KitSpec::File(path)) => Some(path.as_path()),
        _ => None,
    };
    Ok(ndn_cert::kit_namespace(kit_file, pib_dir)?)
}

/// An opened kit: its key and, for a YubiKey kit, its token's serial.
pub struct OpenedKit {
    pub signer: Arc<dyn Signer>,
    pub token: Option<u32>,
}

/// Open the kit `spec` as the recovery key of `namespace`, its words,
/// passphrase or PIN asked for `purpose`. Nothing is signed.
pub async fn open_kit(
    spec: &KitSpec,
    namespace: &Name,
    purpose: SecretPurpose,
    secrets: &dyn SecretSource,
) -> Result<OpenedKit, RootError> {
    Ok(match spec {
        KitSpec::Words => OpenedKit {
            signer: Arc::new(kit_words(secrets, purpose).await?.signer(namespace)),
            token: None,
        },
        KitSpec::File(path) => {
            let kit = FileKit::read(path)?;
            if kit.namespace != *namespace {
                return Err(RootError::new(
                    code::KIT_OTHER_NAMESPACE,
                    "the kit recovers another namespace",
                )
                .with("path", path.display())
                .with("kit", &kit.namespace)
                .with("namespace", namespace));
            }
            let passphrase = kit_secret(secrets, SecretKind::KitPassphrase, purpose, false).await?;
            OpenedKit {
                signer: Arc::new(kit.open(&passphrase)?),
                token: None,
            }
        }
        KitSpec::Yubikey(kit) => {
            let pin = kit_secret(secrets, SecretKind::KitPin, purpose, false).await?;
            let (signer, serial) = kit.signer(namespace, &pin).await?;
            OpenedKit {
                signer,
                token: Some(serial),
            }
        }
    })
}

/// The public key of an opened kit.
pub(crate) fn kit_public_key(kit: &OpenedKit) -> Result<bytes::Bytes, RootError> {
    kit.signer.public_key().ok_or_else(|| {
        RootError::new(
            code::ROOT_LOCAL_FAILURE,
            "the kit's key reports no public key",
        )
        .with("error", "the kit's key reports no public key")
    })
}

/// Where a new kit is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KitLocation {
    /// The words, shown once ([`KitCreated::words`]).
    Words,
    /// A sealed file.
    File(PathBuf),
    /// Generated on a token, never leaving it.
    Yubikey { serial: u32, slot: String },
}

/// What [`create`] makes.
pub struct KitRequest {
    pub pib_dir: PathBuf,
    /// The namespace whose root signs; `None`: the only one whose root the
    /// PIB holds (several: `several-namespaces`, listing them).
    pub namespace: Option<Name>,
    pub format: KitFormat,
    /// A file kit: where to write it (never over an existing file).
    pub out: Option<PathBuf>,
    /// A YubiKey kit: its token and slot.
    pub yubikey: YubikeyKit,
    /// A YubiKey kit: generate even over a slot holding a key.
    pub replace_slot: bool,
}

/// A recovery kit made, and the version listing it.
pub struct KitCreated {
    pub namespace: Name,
    pub format: KitFormat,
    /// The recovery key.
    pub key: Name,
    /// Its anchor's fingerprint.
    pub fingerprint: [u8; 32],
    pub kit: KitLocation,
    /// A word kit's seed: [`RecoverySeed::to_words`] gives the 24 words to
    /// show once (zeroed on drop).
    pub words: Option<RecoverySeed>,
    pub held_version: u64,
    /// The new version listing the kit (`held_version + 1`).
    pub version: u64,
    /// The root key that signed.
    pub root_key: Name,
    /// Where the version went, and the recovery kits it lists; Err
    /// (`hand-over-unknown`): whether the running device took it is not
    /// known — the kit is kept, as that version may still be taken.
    pub handed: Result<(HandedOver, usize), RootError>,
}

/// Make a recovery kit of the namespace `request` names (else of the only
/// one whose root the PIB of `request` holds), and a version listing it.
/// Refusals before the root signs leave nothing behind; from then on
/// (`kit-not-added`) the kit file written is removed and nothing changed.
/// The other namespaces whose roots the PIB holds are not touched.
pub async fn create(
    request: KitRequest,
    device: &dyn RunningDevice,
    secrets: &dyn SecretSource,
) -> Result<KitCreated, RootError> {
    let KitRequest {
        pib_dir,
        namespace,
        format,
        out,
        yubikey,
        replace_slot,
    } = request;
    let out = match format {
        KitFormat::File => {
            let out = out.ok_or_else(|| {
                RootError::new(
                    code::ROOT_BAD_REQUEST,
                    "a file kit needs a path to write it to",
                )
                .with("error", "no kit file path")
            })?;
            if out.exists() {
                return Err(RootError::new(
                    code::KIT_FILE_EXISTS,
                    "a file exists where the kit would be written",
                )
                .with("path", out.display()));
            }
            Some(out)
        }
        _ => None,
    };
    let pib = open_pib(&pib_dir)?;
    let ndn_cert::RootDevice {
        store,
        context: ctx,
        data: held_data,
    } = ndn_cert::root_device(&pib, namespace.as_ref(), KIT_WORK)?;
    let namespace = store.namespace().clone();

    // The recovery key: in memory (words, file) or on the token.
    let (seed, signer, kit): (Option<RecoverySeed>, Arc<dyn Signer>, KitLocation) = match format {
        KitFormat::Words | KitFormat::File => {
            let seed = RecoverySeed::generate()?;
            let signer = Arc::new(seed.signer(&namespace));
            let kit = match &out {
                Some(out) => KitLocation::File(out.clone()),
                None => KitLocation::Words,
            };
            (Some(seed), signer, kit)
        }
        KitFormat::Yubikey => {
            let pin = kit_secret(
                secrets,
                SecretKind::KitPin,
                SecretPurpose::CreateKit {
                    namespace: namespace.clone(),
                },
                false,
            )
            .await?;
            // Never on the root's own token (one lost token would lose both),
            // never over a slot's key unless it is said to be unneeded.
            let guard = SlotGuard {
                replace: replace_slot,
                not_on: store
                    .yubikey()
                    .map(|y| (y.serial, format!("the root of {namespace}"))),
            };
            let (signer, serial) = yubikey.generate(&namespace, &pin, &guard).await?;
            (
                None,
                signer,
                KitLocation::Yubikey {
                    serial,
                    slot: yubikey.slot.clone(),
                },
            )
        }
    };
    let anchor = recovery_anchor(Arc::clone(&signer)).await?;
    drop(signer);
    let key = anchor.key_name();

    // A file kit is written before the root signs, and removed again if the
    // new version does not land: no anchor without its kit.
    if let (Some(out), Some(seed)) = (&out, &seed) {
        let passphrase = kit_secret(
            secrets,
            SecretKind::KitPassphrase,
            SecretPurpose::SealKit,
            true,
        )
        .await?;
        let root_fp = ctx
            .anchors()
            .iter()
            .find(|a| {
                ndn_cert::root_store::same_public_key(&a.value().public_key, store.public_key())
            })
            .map(|a| anchor_fingerprint(a.value()));
        let uri = seal_file_kit(seed, &anchor, &namespace, root_fp, &passphrase)?;
        ndn_security::secure_fs::write_private(out, format!("{uri}\n")).map_err(|e| {
            RootError::new(
                code::ROOT_LOCAL_FAILURE,
                "the kit file could not be written",
            )
            .with("error", &e)
            .with("write", out.display())
            .caused_by(e)
        })?;
    }
    let not_added = |e: RootError| {
        let mut refused = RootError::wrapping(
            code::KIT_NOT_ADDED,
            "no recovery kit was added; the trust context is unchanged",
            e,
        );
        if let Some(out) = &out {
            let _ = std::fs::remove_file(out);
            refused = refused.with("removed", out.display());
        }
        refused
    };

    let signed = async {
        let root = unlock_root(
            &store,
            secrets,
            VersionChange::AddKit {
                namespace: namespace.clone(),
            },
        )
        .await?;
        let bump = add_recovery_anchor(root.as_ref(), &held_data, &anchor).await;
        drop(root);
        Ok::<_, RootError>(bump?)
    }
    .await;
    let bump = signed.map_err(not_added)?;
    let version = bump.context.version();
    let handed = match hand_over(device, &pib_dir, &bump).await {
        Ok(handed) => Ok((
            handed,
            bump.context
                .keys_with_role(KeyRole::RECOVERY_ANCHOR)
                .count(),
        )),
        Err(NotTaken::Refused(e)) => return Err(not_added(e)),
        // The version listing the kit may still be taken: the kit is kept,
        // so no anchor is left without its kit.
        Err(unknown) => Err(not_taken(
            unknown,
            version,
            ctx.version(),
            &[("key", key.to_string())],
        )),
    };
    Ok(KitCreated {
        namespace,
        format,
        key,
        fingerprint: anchor_fingerprint(&anchor),
        kit,
        words: seed.filter(|_| format == KitFormat::Words),
        held_version: ctx.version(),
        version,
        root_key: store.key_name().clone(),
        handed,
    })
}

/// One anchor of a held version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedAnchor {
    pub key: Name,
    /// A recovery kit's key, else a root's.
    pub recovery_kit: bool,
    pub fingerprint: [u8; 32],
}

/// The anchors of one held trust context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedContext {
    pub namespace: Name,
    pub version: u64,
    /// By key name.
    pub anchors: Vec<ListedAnchor>,
    /// The keys of the namespace's root device.
    pub root_device_keys: Vec<Name>,
    pub recovery_kits: usize,
}

/// The kits of the contexts a PIB holds.
#[derive(Debug, Clone, Default)]
pub struct KitList {
    pub contexts: Vec<ListedContext>,
    /// Stored contexts that could not be read: where, and why.
    pub skipped: Vec<(PathBuf, String)>,
}

/// The recovery kits (and roots) of every context the PIB at `pib_dir`
/// holds, or of `namespace` only.
pub fn list(pib_dir: &Path, namespace: Option<&Name>) -> Result<KitList, RootError> {
    let mut listed = KitList::default();
    for (path, read) in ndn_cert::read_stored_contexts(pib_dir)? {
        let (ctx, _) = match read {
            Ok(held) => held,
            Err(e) => {
                listed.skipped.push((path, e.to_string()));
                continue;
            }
        };
        if namespace.is_some_and(|ns| ns != ctx.namespace()) {
            continue;
        }
        let mut anchors: Vec<ListedAnchor> = ctx
            .anchors()
            .iter()
            .map(|a| {
                let anchor = a.value();
                let key = anchor.key_name();
                ListedAnchor {
                    recovery_kit: ctx.has_key_role(&key, KeyRole::RECOVERY_ANCHOR),
                    fingerprint: anchor_fingerprint(anchor),
                    key,
                }
            })
            .collect();
        anchors.sort_by_key(|a| a.key.to_string());
        listed.contexts.push(ListedContext {
            namespace: ctx.namespace().clone(),
            version: ctx.version(),
            recovery_kits: anchors.iter().filter(|a| a.recovery_kit).count(),
            anchors,
            root_device_keys: ctx.keys_with_role(KeyRole::ROOT_DEVICE).cloned().collect(),
        });
    }
    Ok(listed)
}

/// A kit checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KitChecked {
    pub namespace: Name,
    pub format: KitFormat,
    /// The kit's key: a recovery anchor of the held version.
    pub key: Name,
    pub version: u64,
}

/// Check that the kit `spec` opens and its key is a recovery anchor of the
/// held version of `namespace` (else the one [`kit_namespace`] finds).
/// Nothing is signed.
pub async fn check(
    pib_dir: &Path,
    spec: &KitSpec,
    namespace: Option<&Name>,
    secrets: &dyn SecretSource,
) -> Result<KitChecked, RootError> {
    let namespace = kit_namespace(namespace, Some(spec), pib_dir)?;
    let (ctx, _) = held_context(pib_dir, &namespace)?;
    let kit = open_kit(
        spec,
        &namespace,
        SecretPurpose::CheckKit {
            namespace: namespace.clone(),
        },
        secrets,
    )
    .await?;
    let key = kit_anchor(&ctx, &kit_public_key(&kit)?)?;
    Ok(KitChecked {
        namespace,
        format: spec.format(),
        key,
        version: ctx.version(),
    })
}

/// A kit revoked.
#[derive(Debug)]
pub struct KitRevoked {
    pub namespace: Name,
    pub key: Name,
    pub held_version: u64,
    pub version: u64,
    pub root_key: Name,
    pub handed_over: HandedOver,
    /// The recovery kits the new version lists.
    pub recovery_kits: usize,
}

/// Revoke the recovery kit `key` on the root device of `namespace` (else of
/// the namespace covering `key`, of those whose root the PIB at `pib_dir`
/// holds: `revoke-outside-namespace` when none does): a version without
/// it, revoking its key. Refusals: `not-a-recovery-kit` (nothing signed),
/// the secret's, `version-not-taken` (nothing changed), `hand-over-unknown`
/// (param `key`).
pub async fn revoke(
    pib_dir: &Path,
    key: &Name,
    namespace: Option<&Name>,
    device: &dyn RunningDevice,
    secrets: &dyn SecretSource,
) -> Result<KitRevoked, RootError> {
    let pib = open_pib(pib_dir)?;
    let root = match namespace {
        Some(_) => ndn_cert::root_device(&pib, namespace, KIT_WORK)?,
        None => match ndn_cert::root_device_covering(&pib, key, KIT_WORK)? {
            Some(root) => root,
            None => {
                let held: Vec<String> = RootStore::open_all(&pib)?
                    .iter()
                    .map(|s| s.namespace().to_string())
                    .collect();
                return Err(RootError::new(
                    code::REVOKE_OUTSIDE_NAMESPACE,
                    "the key is outside every namespace this device holds the root of; \
                     nothing was signed",
                )
                .with("name", key)
                .with("namespace", held.join(","))
                .with("operation", KIT_WORK));
            }
        },
    };
    let ndn_cert::RootDevice {
        store,
        context: ctx,
        data: held_data,
    } = root;
    let namespace = store.namespace().clone();
    if !ctx.has_key_role(key, KeyRole::RECOVERY_ANCHOR) {
        return Err(RootError::new(
            code::NOT_A_RECOVERY_KIT,
            "the key is no recovery kit of the held version; nothing was signed",
        )
        .with("key", key)
        .with("namespace", &namespace)
        .with("version", ctx.version()));
    }
    let root = unlock_root(
        &store,
        secrets,
        VersionChange::RevokeKit { key: key.clone() },
    )
    .await?;
    let bump = remove_recovery_anchor(root.as_ref(), &held_data, key).await;
    drop(root);
    let bump = bump?;
    let version = bump.context.version();
    let handed_over = settle(
        hand_over(device, pib_dir, &bump).await,
        version,
        ctx.version(),
        &[("key", key.to_string())],
    )?;
    Ok(KitRevoked {
        namespace,
        key: key.clone(),
        held_version: ctx.version(),
        version,
        root_key: store.key_name().clone(),
        handed_over,
        recovery_kits: bump
            .context
            .keys_with_role(KeyRole::RECOVERY_ANCHOR)
            .count(),
    })
}
