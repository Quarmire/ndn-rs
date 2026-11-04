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
//!
//! Both versions carry every revocation cut of `N`, except orphan cuts and
//! cuts naming packets outside their key's device log, which `N` (perhaps
//! signed by whoever held a compromised root) may hold and `N+1` drops
//! ([`ndn_cert::RecoveryVersion::dropped_cuts`]). With the old root
//! compromised, `N+1` may add a cut for each key it newly revokes
//! ([`RecoverRequest::cuts`]): each from a cut file bounded at or before
//! the time the person says the key was lost and carrying its whole
//! manifest, checked before anything is asked; its manifest packets are
//! stored beside the contexts before `N+1` is handed over, so the running
//! device serves them with it. Then, only once the person has seen the cuts
//! carried and confirmed ([`RecoverRequest::recertify`]), the new CA
//! certifies again each key revoked with a cut whose certificate with the
//! public key the cut names this PIB holds (the old CA's certificates no
//! longer chain, and such a key cannot renew), recorded in the CA's store
//! and served from the CA's next start. A key of none held is listed; once
//! such a certificate is at hand, [`recertify`] certifies it.

use std::path::{Path, PathBuf};

use ndn_cert::report::code;
use ndn_cert::{
    CutFile, CutKeyCertificates, GivenCut, NewRootStore, OldRoot, RecoveredNamespace, RootStore,
    anchor_fingerprint, kit_anchor, read_stored_context, recertify_cut_keys_in_pib,
    recover_namespace_in_pib,
};
use ndn_packet::Name;
use ndn_security::{Certificate, RevocationCut};
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
    /// With the old root compromised: the cut files of some of the keys
    /// `N+1` newly revokes (the old root's, the old root device's, the kits
    /// not kept), at most one per key, each with when the person says the
    /// key was lost: it must be bounded at or before then and carry its
    /// whole manifest ([`ndn_cert::CutFile::check_bound`],
    /// [`ndn_cert::CutFile::check_manifest`]; `cut-refused` otherwise).
    pub cuts: Vec<GivenCut>,
    /// Nothing answers: the person vouches that no version newer than the
    /// held one exists.
    pub from_held: bool,
    pub root: RootStoreChoice,
    /// With the old root compromised: whether the keys `N+1` revokes with a
    /// cut are certified again by the new CA, asked once `N+1` is taken.
    pub recertify: Recertify,
}

/// The question a compromised recovery asks before certifying the keys
/// revoked with a cut again: shown the cuts `N+1` carries, `true` certifies.
pub type AskRecertify = Box<dyn Fn(&[RevocationCut]) -> bool + Send + Sync>;

/// Whether a compromised recovery certifies the keys revoked with a cut
/// again ([`RecoverRequest::recertify`]).
pub enum Recertify {
    /// Not now (`ndn-fwd recertify` does it later).
    No,
    /// Yes, without asking (the person said so beforehand).
    Yes,
    /// Ask the person ([`AskRecertify`]).
    Ask(AskRecertify),
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
    /// The cut files `N+1` signed the cuts of, as given: with the bound
    /// each used and the entries it left out (refused with the rest; a
    /// genuine one is re-admitted by its full name, [`super::readmit`]).
    pub cuts: Vec<CutFile>,
    /// With the old root compromised: the keys revoked with a cut certified
    /// again by the new CA (recorded in its store), or why not — `None`
    /// when the person did not confirm it (or the old root was destroyed).
    pub recertified: Option<Result<CutKeyCertificates, RootError>>,
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
/// [module docs](self)). Refusals: `cut-refused` (a cut file unbounded,
/// bounded after its loss time, without its whole manifest, or not the cut
/// of a key `N+1` newly revokes; its manifest packets cannot be stored),
/// the anti-fork ones of [`crate::admin::NewestRefusal`], the kit's, the
/// running device's, `version-not-taken` (`N+1` refused: everything
/// written was removed) and `hand-over-unknown` (whether `N+1` was taken is
/// not known; nothing was removed — params `root_key`, `ca_key`,
/// `device_key`).
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
        cuts,
        from_held,
        root: root_choice,
        recertify: recertify_choice,
    } = request;
    // A cut file is checked before anything is asked: bounded at or before
    // the loss time, so it cannot accept what a thief wrote after it, and
    // carrying the whole manifest the cut names.
    for given in &cuts {
        given
            .file
            .check_bound(given.lost)
            .and_then(|()| given.file.check_manifest())?;
    }
    let cut_files: Vec<CutFile> = cuts.into_iter().map(|given| given.file).collect();
    let cuts: Vec<RevocationCut> = cut_files.iter().map(|file| file.cut.clone()).collect();
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
        &cuts,
        &root,
    )
    .await;
    // Both keys signed what they sign here: drop them now.
    drop(root);
    drop(opened);
    let recovered = recovered?;
    // The cuts' manifest packets go beside the contexts before N+1 is
    // handed over, so the running device serves them with it.
    for file in &cut_files {
        if let Err(e) = super::revoke::store_manifest(&pib_dir, &namespace, file) {
            recovered.undo(&pib);
            return Err(e);
        }
    }

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
    // N+1 is taken: with the old root compromised, the keys it revokes with
    // a cut are certified again by the new CA — once the person has seen
    // the cuts carried and confirmed.
    let cut_keys = v_cuts(&recovered);
    let confirmed = old_root == OldRoot::Compromised
        && !cut_keys.is_empty()
        && match &recertify_choice {
            Recertify::No => false,
            Recertify::Yes => true,
            Recertify::Ask(ask) => ask(&cut_keys),
        };
    let recertified = if confirmed {
        Some(
            recertify_cut_keys_in_pib(&pib, &namespace, &[])
                .await
                .map_err(RootError::from),
        )
    } else {
        None
    };

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
        cuts: cut_files,
        revoked,
        recovered,
        handed,
        root_handed,
        recertified,
    })
}

/// The cuts of keys `N+1` revokes (what re-certification considers).
fn v_cuts(recovered: &RecoveredNamespace) -> Vec<RevocationCut> {
    let ctx = &recovered.version.bump.context;
    ctx.revocation_cuts()
        .iter()
        .filter(|c| ctx.revocations().contains(c.key()))
        .cloned()
        .collect()
}

/// On the root device of `namespace` (else the only namespace whose root
/// the PIB at `pib_dir` holds): certify again, with the namespace CA's key,
/// every key the held version revokes with a cut naming its public key
/// (CutKeyDigest) that this CA has not certified for it yet, from a
/// certificate of it with exactly that public key in `certificates` (ones
/// the operator vouches for, e.g. a device's certificate file) or stored in
/// the PIB ([`ndn_cert::recertify_cut_keys_in_pib`]) — what a compromised
/// recovery lists as held nowhere. Recorded in the CA's store: the CA serves
/// them from its next start. Keys still without such a certificate are
/// listed in [`CutKeyCertificates::unheld`], cuts naming no public key in
/// [`CutKeyCertificates::no_key_digest`]. Signs no version; the root is not
/// unlocked. A host shows the cuts ([`cut_keys`]) and asks before calling it.
pub async fn recertify(
    pib_dir: &Path,
    namespace: Option<&Name>,
    certificates: &[Certificate],
) -> Result<(Name, CutKeyCertificates), RootError> {
    let pib = super::open_pib(pib_dir)?;
    let root = ndn_cert::root_device(&pib, namespace, "keys are re-certified")?;
    let namespace = root.context.namespace().clone();
    let done = recertify_cut_keys_in_pib(&pib, &namespace, certificates).await?;
    Ok((namespace, done))
}

/// The cuts re-certification on the root device of `namespace` (else the
/// only namespace whose root the PIB at `pib_dir` holds) considers — those
/// of keys the held version revokes — for a host to show before it asks to
/// [`recertify`]; with the namespace.
pub fn cut_keys(
    pib_dir: &Path,
    namespace: Option<&Name>,
) -> Result<(Name, Vec<RevocationCut>), RootError> {
    let pib = super::open_pib(pib_dir)?;
    let root = ndn_cert::root_device(&pib, namespace, "keys are re-certified")?;
    let ctx = &root.context;
    let cuts = ctx
        .revocation_cuts()
        .iter()
        .filter(|c| ctx.revocations().contains(c.key()))
        .cloned()
        .collect();
    Ok((ctx.namespace().clone(), cuts))
}
