//! Ending, on the root device, the keys whose authority over Data has ended
//! but which no version revokes yet ([`ndn_cert::ending_keys`]): lapsed keys
//! of a role the trust context lists in `DataRequiresCut` (`guest` by
//! default) and keys replaced by a newer key of the same device identity.
//!
//! [`pending`] lists them, read from the PIB (the namespace CA's issued
//! certificates and the held version), each with the moment its authority
//! ended. Nothing is queued: a key leaves the list once a version revokes
//! it. [`plan`] matches the cut files given (one per key, written by the
//! root's data layer: its `cut <key> <file> --held-before <when>`) to them —
//! each bounded at or before its key's end, with its whole manifest — and
//! [`end`] signs ONE version revoking every key that has its cut, with its
//! cut beside it, and hands it over. A key without a cut file is never
//! revoked here: a cut is added only with its key's revocation, so revoking
//! without one would refuse forever what the key published honestly; it is
//! listed instead. Meanwhile a lapsed key fails closed by itself (its Data
//! is refused once no certificate of it is valid by the reader's clock),
//! while a replaced key of an unlisted role keeps signing accepted Data
//! until it is ended.
//!
//! The running device never unlocks the root, and the data layer runs
//! beside it, so ending keys is a root operation like any other: a host
//! proposes it whenever the root is used (and in its status), and an owner
//! whose root unlocks without a secret (OS keychain, plain file) may run it
//! unattended from a timer, with the cut files the data layer writes.

use std::path::Path;

use ndn_cert::report::code;
use ndn_cert::{
    BumpError, CutFile, EndingKey, FileCaStore, RootDevice, bump_context_revoking, ca_dir,
    check_cuts, ending_keys,
};
use ndn_packet::Name;
use ndn_security::{Certificate, FilePib};

use super::device::{check_device, hand_over, settle};
use super::revoke::store_manifest;
use super::{RootError, RunningDevice, SecretSource, VersionChange, open_pib, unlock_root};
use crate::admin::HandedOver;

/// The keys of one namespace whose authority ended and that its held
/// version does not revoke.
#[derive(Debug, Clone)]
pub struct Pending {
    pub namespace: Name,
    /// The held version.
    pub version: u64,
    pub ending: Vec<EndingKey>,
}

/// The certificates the namespace CA of `namespace` issued, as recorded in
/// its store in the PIB at `pib_dir` (none when it has no store).
fn issued(pib_dir: &Path, namespace: &Name) -> Result<Vec<Certificate>, RootError> {
    let dir = ca_dir(pib_dir, namespace);
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let loaded = FileCaStore::open(&dir)
        .and_then(|store| ndn_cert::CaStore::load(&store))
        .map_err(|e| {
            RootError::new(code::ROOT_LOCAL_FAILURE, "the CA's store cannot be read")
                .with("dir", dir.display())
                .caused_by(e)
        })?;
    Ok(loaded
        .issued
        .iter()
        .filter_map(|(_, wire)| ndn_cert::ca::deserialize_cert(wire))
        .collect())
}

fn pending_of(pib_dir: &Path, root: &RootDevice, now: u64) -> Result<Pending, RootError> {
    let namespace = root.context.namespace().clone();
    let issued = issued(pib_dir, &namespace)?;
    Ok(Pending {
        ending: ending_keys(&root.context, &issued, now),
        version: root.context.version(),
        namespace,
    })
}

/// The keys to end of `namespace` (else the only namespace whose root the
/// PIB at `pib_dir` holds) at `now` (ms since the Unix epoch).
pub fn pending(pib_dir: &Path, namespace: Option<&Name>, now: u64) -> Result<Pending, RootError> {
    let pib = open_pib(pib_dir)?;
    let root = ndn_cert::root_device(&pib, namespace, "keys are ended")?;
    pending_of(pib_dir, &root, now)
}

/// The keys to end of every namespace whose root the PIB at `pib_dir`
/// holds, at `now`: what a host lists after any root operation and in its
/// status. A PIB holding no root lists none.
pub fn pending_all(pib_dir: &Path, now: u64) -> Result<Vec<Pending>, RootError> {
    let Ok(pib) = FilePib::open(pib_dir) else {
        return Ok(Vec::new());
    };
    let stores = ndn_cert::RootStore::open_all(&pib).map_err(RootError::from)?;
    let mut all = Vec::new();
    for store in stores {
        let root = ndn_cert::root_device(&pib, Some(store.namespace()), "keys are ended")?;
        all.push(pending_of(pib_dir, &root, now)?);
    }
    Ok(all)
}

/// What [`end`] signs, decided before the root is unlocked.
pub struct EndPlan {
    pub root: RootDevice,
    /// The keys ended in this version, each with its cut file.
    pub ending: Vec<(EndingKey, CutFile)>,
    /// The keys to end that no cut file was given for: not revoked.
    pub without_cut: Vec<EndingKey>,
}

/// Every check of ending the keys of `namespace` (else the only namespace
/// whose root the PIB at `pib_dir` holds) at `now` with the cut files
/// `cuts`: each must be the cut of a key to end (`cut-refused`, `why`
/// `not-ending` otherwise), bounded at or before the moment that key's
/// authority ended, with its whole manifest, naming its public key, listing
/// only its device log (`cut-refused`).
pub fn plan(
    pib_dir: &Path,
    namespace: Option<&Name>,
    cuts: Vec<CutFile>,
    now: u64,
) -> Result<EndPlan, RootError> {
    let pib = open_pib(pib_dir)?;
    let root = ndn_cert::root_device(&pib, namespace, "keys are ended")?;
    let pending = pending_of(pib_dir, &root, now)?;
    let mut ending: Vec<(EndingKey, CutFile)> = Vec::new();
    for file in cuts {
        let key = file.cut.key().clone();
        let Some(end) = pending.ending.iter().find(|e| e.key == key) else {
            return Err(RootError::new(
                code::CUT_REFUSED,
                "the cut's key is not one whose authority ended (lapsed or replaced) and is still \
                 unrevoked; nothing was signed",
            )
            .with("key", &key)
            .with("namespace", &pending.namespace)
            .with("why", "not-ending"));
        };
        file.check_bound(end.held_before)
            .and_then(|()| file.check_manifest())
            .map_err(RootError::from)?;
        if ending.iter().any(|(e, _)| e.key == key) {
            return Err(RootError::from(BumpError::DuplicateCut {
                key: key.to_string(),
            }));
        }
        ending.push((end.clone(), file));
    }
    let keys: Vec<Name> = ending.iter().map(|(e, _)| e.key.clone()).collect();
    let cut_list: Vec<_> = ending.iter().map(|(_, f)| f.cut.clone()).collect();
    check_cuts(&root.context, &keys, &cut_list).map_err(RootError::from)?;
    let without_cut = pending
        .ending
        .into_iter()
        .filter(|e| !keys.contains(&e.key))
        .collect();
    Ok(EndPlan {
        root,
        ending,
        without_cut,
    })
}

/// The keys ended in one version, signed and handed over.
#[derive(Debug)]
pub struct Ended {
    pub namespace: Name,
    pub held_version: u64,
    pub version: u64,
    pub root_key: Name,
    /// Each key revoked, with the cut file whose cut was signed beside it.
    pub ended: Vec<(EndingKey, CutFile)>,
    pub handed_over: HandedOver,
}

/// Sign and hand over `planned` on the PIB at `pib_dir`: one version
/// revoking every key of [`EndPlan::ending`] with its cut. Refusals:
/// `nothing-to-sign` (no key has a cut file), the running device's, the
/// manifest's (`cut-refused`), the secret's and `root-not-unlocked`,
/// `version-not-taken`, `hand-over-unknown` (params `keys`).
pub async fn end(
    planned: EndPlan,
    pib_dir: &Path,
    device: &dyn RunningDevice,
    secrets: &dyn SecretSource,
) -> Result<Ended, RootError> {
    let EndPlan { root, ending, .. } = planned;
    let held_version = root.context.version();
    let namespace = root.context.namespace().clone();
    if ending.is_empty() {
        return Err(RootError::new(
            code::NOTHING_TO_SIGN,
            "no key to end has a cut file; nothing was signed",
        )
        .with("version", held_version));
    }
    check_device(device, pib_dir).await?;
    for (_, file) in &ending {
        store_manifest(pib_dir, &namespace, file)?;
    }
    let keys: Vec<Name> = ending.iter().map(|(e, _)| e.key.clone()).collect();
    let cuts: Vec<_> = ending.iter().map(|(_, f)| f.cut.clone()).collect();
    let signer = unlock_root(
        &root.store,
        secrets,
        VersionChange::EndKeys {
            namespace: namespace.clone(),
        },
    )
    .await?;
    let bump = bump_context_revoking(signer.as_ref(), &root.data, &keys, &cuts).await;
    drop(signer);
    let bump = bump?.ok_or_else(|| {
        RootError::new(
            code::NOTHING_TO_SIGN,
            "the held trust context revokes every key named already; nothing was signed",
        )
        .with("version", held_version)
    })?;
    let version = bump.context.version();
    let names: Vec<String> = keys.iter().map(Name::to_string).collect();
    let handed_over = settle(
        hand_over(device, pib_dir, &bump).await,
        version,
        held_version,
        &[("keys", names.join(", "))],
    )?;
    Ok(Ended {
        namespace,
        held_version,
        version,
        root_key: root.store.key_name().clone(),
        ended: ending,
        handed_over,
    })
}
