//! Ending, on the root device, the keys whose authority over Data has ended
//! but which no version revokes yet ([`ndn_cert::ending_keys`]): lapsed keys
//! of a role the trust context lists in `DataRequiresCut` (every role, in a
//! context `ndn-fwd init` makes; an older one lists `guest` alone) and keys
//! replaced by a newer key of the same device identity.
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
//! while a replaced key keeps signing accepted Data until it is ended (or,
//! for a listed role, until its certificate lapses).
//!
//! The running device never unlocks the root, and the data layer runs
//! beside it, so ending keys is a root operation like any other: a host
//! proposes it whenever the root is used (and in its status), and an owner
//! whose root unlocks without a secret (OS keychain, plain file) may run it
//! unattended from a timer, with the cut files the data layer writes.

use std::path::Path;

use ndn_cert::report::code;
use ndn_cert::{
    BumpError, CutFile, EndingKey, FileCaStore, Role, RootDevice, bump_context_revoking, ca_dir,
    check_cuts, ending_keys, load_persisted_contexts,
};
use ndn_packet::Name;
use ndn_security::{Certificate, FilePib, Keyring};

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
    /// The device roles the held version lists in `DataRequiresCut`, sorted:
    /// the roles whose lapsed keys' Data is refused (and whose lapsed keys
    /// are listed in `ending`). A context made before every role was listed
    /// lists fewer.
    pub data_requires_cut: Vec<String>,
    pub ending: Vec<EndingKey>,
}

/// What a host says of a held root context that lists fewer than every
/// device role in `DataRequiresCut`: such a context was made before
/// `ndn-fwd init` listed every role, and a context is root-signed data that
/// nothing rewrites, so the owner is told the one command that does. `None`
/// when `listed` (the roles the held version lists) holds every role.
pub fn data_requires_cut_notice(namespace: &Name, listed: &[String]) -> Option<String> {
    if Role::ALL
        .iter()
        .all(|role| listed.iter().any(|l| l == role.as_str()))
    {
        return None;
    }
    let every = Role::ALL.map(Role::as_str).join(",");
    let refused = if listed.is_empty() {
        "for no role".to_string()
    } else {
        format!("only for roles {}", listed.join(","))
    };
    Some(format!(
        "{namespace}: Data of lapsed keys is refused {refused}; to refuse it for every role, \
         run on the root device: ndn-fwd schema data-requires-cut {every} --namespace {namespace}"
    ))
}

/// A key in a device's own PIB whose certificate lapsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnLapse {
    pub key: Name,
    /// The latest NotAfter of its certificates (ms since the Unix epoch).
    pub not_after: u64,
}

/// The keys in the PIB at `pib_dir` (a relay's or member's as much as a root
/// device's) whose device role a held trust context lists in
/// `DataRequiresCut` and none of whose certificates is valid at `now` (ms
/// since the Unix epoch): every node refuses the Data they sign until they
/// are enrolled again, and nothing but this says so on the device itself.
pub fn lapsed_own_keys(pib_dir: &Path, now: u64) -> Result<Vec<OwnLapse>, RootError> {
    let Ok(pib) = FilePib::open(pib_dir) else {
        return Ok(Vec::new());
    };
    let local = |what: &'static str, e: &dyn std::fmt::Display| {
        RootError::new(code::ROOT_LOCAL_FAILURE, what)
            .with("error", e)
            .with("read", pib_dir.display())
    };
    let keyring = Keyring::new();
    load_persisted_contexts(pib_dir, &keyring)
        .map_err(|e| local("the held contexts could not be read", &e))?;
    let now_ns = now.saturating_mul(1_000_000);
    let mut lapsed = Vec::new();
    for key in pib
        .list_keys()
        .map_err(|e| local("the PIB's keys could not be listed", &e))?
    {
        if !keyring.context_for(&key).requires_cut_for(&key) {
            continue;
        }
        let certs = pib
            .certs(&key)
            .map_err(|e| local("the key's certificates could not be read", &e))?;
        if certs.iter().any(|c| c.is_valid_at(now_ns)) {
            continue;
        }
        if let Some(latest) = certs.iter().map(|c| c.valid_until).max() {
            lapsed.push(OwnLapse {
                key,
                not_after: latest / 1_000_000,
            });
        }
    }
    lapsed.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(lapsed)
}

/// The certificates of the device keys of `namespace` that the PIB at
/// `pib_dir` knows: what the namespace CA issued, as recorded in its store,
/// and the root device's own admin certificate, which `init` writes beside
/// the store ([`ndn_cert::namespace::DEVICE_CERT_FILE`]) without recording it
/// there (none when the PIB holds no CA directory).
pub(super) fn issued(pib_dir: &Path, namespace: &Name) -> Result<Vec<Certificate>, RootError> {
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
    let mut certs: Vec<Certificate> = loaded
        .issued
        .iter()
        .filter_map(|(_, wire)| ndn_cert::ca::deserialize_cert(wire))
        .collect();
    let own = dir.join(ndn_cert::namespace::DEVICE_CERT_FILE);
    match std::fs::read(&own) {
        Ok(wire) => certs.extend(ndn_cert::ca::deserialize_cert(&wire)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(RootError::new(
                code::ROOT_LOCAL_FAILURE,
                "the root device's certificate cannot be read",
            )
            .with("file", own.display())
            .caused_by(e));
        }
    }
    Ok(certs)
}

fn pending_of(pib_dir: &Path, root: &RootDevice, now: u64) -> Result<Pending, RootError> {
    let namespace = root.context.namespace().clone();
    let issued = issued(pib_dir, &namespace)?;
    Ok(Pending {
        ending: ending_keys(&root.context, &issued, now),
        version: root.context.version(),
        data_requires_cut: root.context.data_requires_cut().to_vec(),
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
