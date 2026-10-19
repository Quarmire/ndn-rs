//! Making a replacement device the root device of a namespace whose root
//! device is lost, with a recovery kit ([`ndn_cert::recovery`]).
//!
//! On the replacement device, its running device (the one that uses the
//! PIB recovered into) linked to the namespace:
//!
//! 1. **The newest version, by name** ([`crate::admin::fetch_newest`]): the
//!    running device refreshes the context it holds; one holding none
//!    adopts it first from a file kit's expected fingerprint. Recovering
//!    from an older version than the namespace serves would fork it, so a
//!    failed refresh stops here; when nothing answers, the person may vouch
//!    that the held version is the newest (`from_held`).
//! 2. **The kit**: its key must be a recovery anchor of that version (which
//!    must verify under its own anchors), else nothing is signed.
//! 3. **The new root device** ([`ndn_cert::recover_namespace_in_pib`]): a
//!    new root in the store chosen (never on the kit's token), a new CA key
//!    and admin identity, version `N+1` signed by the recovery key — the old
//!    root kept as an anchor (destroyed) or removed and revoked with the old
//!    root device's keys and every kit but the one used and those kept
//!    (compromised) — and `N+2`, the same content signed by the new root.
//! 4. **Hand-over**: `N+1`, then `N+2`. Only the running device's refusal
//!    of `N+1` removes what step 3 wrote. Once `N+2` is taken, the newest
//!    version is signed by the new root, so its fingerprint is the
//!    namespace's expected fingerprint again ([`Recovered::anchor_links`]).

use std::path::{Path, PathBuf};

use ndn_cert::report::code;
use ndn_cert::{
    NewRootStore, OldRoot, RecoveredNamespace, RootStore, anchor_fingerprint, kit_anchor,
    read_stored_context, recover_namespace_in_pib,
};
use ndn_packet::Name;
use ndn_trust_envelope::TrustEnvelope;

use super::device::{Newest, hand_over, not_taken, session_on};
use super::init::{RootStoreChoice, absolute, anchor_link, new_root_store};
use super::kit::{KitSpec, kit_namespace, kit_public_key, open_kit};
use super::{RootError, RunningDevice, SecretPurpose, SecretSource, create_pib};
use crate::admin::{HandedOver, NotTaken, fetch_newest};

/// What [`recover`] does.
pub struct RecoverRequest {
    /// The PIB of the replacement device (its running device's).
    pub pib_dir: PathBuf,
    pub kit: KitSpec,
    /// The namespace; else the one a file kit names, else the only one held.
    pub namespace: Option<Name>,
    /// This device's name (`<ns>/admin/<device>`).
    pub device: String,
    pub old_root: OldRoot,
    /// With the old root compromised: the other kits to keep.
    pub kept_kits: Vec<Name>,
    /// Nothing answers: the person vouches that no version newer than the
    /// held one exists.
    pub from_held: bool,
    pub root: RootStoreChoice,
}

/// What an anchor of `N+1` is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorKind {
    NewRoot,
    /// The recovery kit that signed `N+1`.
    KitUsed,
    RecoveryKit,
    /// The old root (its certificates stay valid).
    OldRoot,
}

/// What a key `N+1` revokes was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokedKind {
    /// A recovery kit not kept.
    UnkeptKit,
    OldRoot,
    /// A key of the old root device.
    OldRootDeviceKey,
}

/// A namespace recovered onto this device.
pub struct Recovered {
    pub namespace: Name,
    pub kit_format: ndn_cert::KitFormat,
    /// Whether a node confirmed the version recovered from is the newest
    /// (`false`: nothing answered and the person vouched for it).
    pub confirmed: bool,
    pub recovered: RecoveredNamespace,
    /// Where `N+1` went.
    pub handed: HandedOver,
    /// Where `N+2` went, or why it is not (known to be) taken.
    pub root_handed: Result<HandedOver, NotTaken<RootError>>,
    /// The new root's anchor fingerprint: the namespace's expected
    /// fingerprint once `N+2` is taken.
    pub anchor_fingerprint: [u8; 32],
    /// The PIB, absolute.
    pub pib_abs: PathBuf,
    /// Every anchor of `N+1`, by key name.
    pub anchors: Vec<(Name, AnchorKind)>,
    /// Every key `N+1` revokes.
    pub revoked: Vec<(Name, RevokedKind)>,
}

impl Recovered {
    /// The anchor links of the namespace (full, fingerprint-only), once the
    /// newest version is the new root's (`N+2` taken); `None` before — a
    /// link with the recovery key's fingerprint would stop working as soon
    /// as the root signs anything.
    pub fn anchor_links(&self) -> Option<(TrustEnvelope, TrustEnvelope)> {
        self.root_handed.as_ref().ok()?;
        let version = self.recovered.root_version.context.version();
        let link = |data| anchor_link(&self.namespace, self.anchor_fingerprint, version, data);
        Some((
            link(Some(self.recovered.root_version.data.raw().clone())),
            link(None),
        ))
    }
}

/// Refuse a recovery into a PIB that holds the root of `namespace` already
/// (`store`); the roots of other namespaces stay beside the recovered one.
fn no_root_here(
    pib_dir: &Path,
    namespace: &Name,
    store: Option<RootStore>,
) -> Result<(), RootError> {
    match store {
        None => Ok(()),
        Some(store) => Err(RootError::new(
            code::ALREADY_ROOT_DEVICE,
            "this device holds the namespace's root already: recover on a replacement device \
             whose key storage holds no root of it",
        )
        .with("pib", pib_dir.display())
        .with("namespace", namespace)
        .with("store", store.kind())),
    }
}

/// Recover the namespace of `request` onto this device (see the
/// [module docs](self)). Refusals: the anti-fork ones of
/// [`crate::admin::NewestRefusal`], the kit's, the running device's,
/// `version-not-taken` (`N+1` refused: everything written was removed) and
/// `hand-over-unknown` (whether `N+1` was taken is not known; nothing was
/// removed — params `root_key`, `ca_key`, `device_key`).
pub async fn recover(
    request: RecoverRequest,
    device: &dyn RunningDevice,
    secrets: &dyn SecretSource,
) -> Result<Recovered, RootError> {
    let RecoverRequest {
        pib_dir,
        kit,
        namespace,
        device: device_name,
        old_root,
        kept_kits,
        from_held,
        root: root_choice,
    } = request;
    let namespace = kit_namespace(namespace.as_ref(), Some(&kit), &pib_dir)?;
    let kit_fingerprint = match &kit {
        KitSpec::File(path) => ndn_cert::FileKit::read(path)?.fingerprint,
        _ => None,
    };
    let pib = create_pib(&pib_dir)?;
    no_root_here(&pib_dir, &namespace, RootStore::open_for(&pib, &namespace)?)?;

    // 1. The newest version, by name — from the running device that uses
    //    this PIB, which is also the one the new versions go to.
    let session = session_on(device, &pib_dir).await?;
    let newest = fetch_newest(&Newest(&*session), &namespace, kit_fingerprint, from_held).await?;
    drop(session);
    let mismatch = || {
        RootError::new(
            code::DEVICE_STORE_MISMATCH,
            "the running device holds another version than its PIB stores",
        )
        .with("namespace", &namespace)
        .with("version", newest.version)
        .with("pib", pib_dir.display())
    };
    let (held, held_data) = read_stored_context(&pib_dir, &namespace)?.ok_or_else(mismatch)?;
    if held.version() != newest.version {
        return Err(mismatch().with("stored", held.version()));
    }
    // The stored version verifies under its own anchors (self-consistent).
    ndn_security::SignedTrustContext::open_signed(&held_data)
        .await
        .map_err(|e| {
            RootError::new(
                code::HELD_CONTEXT_INVALID,
                "the stored version does not verify",
            )
            .with("namespace", &namespace)
            .with("version", newest.version)
            .caused_by(e)
        })?;

    // 2. The kit: its key must be a recovery anchor of the newest version.
    let opened = open_kit(
        &kit,
        &namespace,
        SecretPurpose::Recover {
            namespace: namespace.clone(),
        },
        secrets,
    )
    .await?;
    kit_anchor(&held, &kit_public_key(&opened)?)?;

    // 3. The new root device: never on the kit's token, which must sign
    //    N+1 after the new root exists.
    let mut root = new_root_store(&root_choice, secrets).await?;
    if let (NewRootStore::YubikeyPiv { guard, .. }, Some(serial)) = (&mut root, opened.token) {
        guard.not_on = Some((serial, "the recovery kit used here".to_string()));
    }
    let recovered = recover_namespace_in_pib(
        &pib,
        &held_data,
        opened.signer.as_ref(),
        &device_name,
        old_root,
        &kept_kits,
        &root,
    )
    .await;
    // Both keys signed what they sign here: drop them now.
    drop(root);
    drop(opened);
    let recovered = recovered?;

    // 4. Hand N+1, then N+2. Only the running device's refusal of N+1
    //    undoes step 3: without an answer it may still adopt N+1, which
    //    names the new root.
    let next = recovered.version.bump.context.version();
    let handed = match hand_over(device, &pib_dir, &recovered.version.bump).await {
        Ok(handed) => handed,
        Err(not) => {
            let refused = not.is_refused();
            if refused {
                recovered.undo(&pib);
            }
            let params = [
                ("root_key", recovered.anchor.key_name().to_string()),
                ("ca_key", recovered.ca_key.to_string()),
                ("device_key", recovered.device_key.to_string()),
                ("pib", pib_dir.display().to_string()),
            ];
            return Err(not_taken(not, next, recovered.previous_version, &params));
        }
    };
    // N+1 is the namespace's from here on: nothing is undone any more. N+2
    // makes the new root the signer of the newest version.
    let root_handed = hand_over(device, &pib_dir, &recovered.root_version).await;

    let v = &recovered.version;
    let new_root = recovered.anchor.key_name();
    let mut anchor_keys: Vec<Name> = v
        .bump
        .context
        .anchors()
        .iter()
        .map(|a| a.value().key_name())
        .collect();
    anchor_keys.sort();
    anchor_keys.dedup();
    let anchors = anchor_keys
        .into_iter()
        .map(|key| {
            let kind = if key == new_root {
                AnchorKind::NewRoot
            } else if key == v.recovery_key {
                AnchorKind::KitUsed
            } else if v.kept_kits.contains(&key) {
                AnchorKind::RecoveryKit
            } else {
                AnchorKind::OldRoot
            };
            (key, kind)
        })
        .collect();
    let revoked = v
        .bump
        .added
        .iter()
        .map(|key| {
            let kind = if v.removed_kits.contains(key) {
                RevokedKind::UnkeptKit
            } else if v.old_root_keys.contains(key) {
                RevokedKind::OldRoot
            } else {
                RevokedKind::OldRootDeviceKey
            };
            (key.clone(), kind)
        })
        .collect();
    Ok(Recovered {
        namespace,
        kit_format: kit.format(),
        confirmed: newest.confirmed,
        anchor_fingerprint: anchor_fingerprint(&recovered.anchor),
        pib_abs: absolute(&pib_dir),
        anchors,
        revoked,
        recovered,
        handed,
        root_handed,
    })
}
