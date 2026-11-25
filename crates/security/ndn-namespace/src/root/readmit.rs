//! Re-admitting single packets of a key revoked with a cut, on the root
//! device: a new version of the trust context adding exact full names to
//! the key's revocation cut.
//!
//! A cut accepts the log entries the key's device published before it was
//! revoked, as the cut lists them (by a manifest, or by tips: below a tip's
//! sequence number by name); a packet the device made after (or a
//! reader only learns of later) is refused, and reported with its full name
//! (its name and implicit SHA-256 digest). The owner who decides that packet
//! is genuine re-admits it by that full name: an exact entry accepts that
//! name with those bytes only — never a range, so a neighbouring sequence
//! number or another packet at that name stays refused. A cut that names
//! tips takes exact entries too, below a tip's number as well as above it:
//! the tip accepts a name below it by name, but a device's data layer keeps
//! below a tip only the chain ancestors of the tip, and an exact entry
//! exempts a packet it lists from that test.
//!
//! [`plan`] checks, before anything is asked, that this is the root device
//! of the namespace the key is in (a namespace named must be that one),
//! that the held version holds a cut for exactly that key (`readmit-no-cut`
//! otherwise: a key not revoked is revoked with a cut first; one revoked
//! without a cut has none to add to), and that each name is a full name in
//! the key's device log `<device>/32=log/...` (`readmit-refused`). Names a
//! range decides, and names an exact entry of the cut lists already, are
//! left out (a name below a tip is not: it is added as an exact entry); none
//! left is `nothing-to-sign`.
//! [`readmit`] then checks the running device uses the same PIB, unlocks the
//! root to sign version `N+1` ([`ndn_cert::bump_context_readmitting`]),
//! drops the signer, and hands the version to the running device
//! ([`super::device::hand_over`]), as a revocation does.

use std::path::Path;

use ndn_cert::report::code;
use ndn_cert::{RootDevice, bump_context_readmitting, readmissions_to_add, root_device_covering};
use ndn_packet::Name;

use super::device::{check_device, hand_over, settle};
use super::{RootError, RunningDevice, SecretSource, VersionChange, open_pib, unlock_root};
use crate::admin::HandedOver;

/// What a re-admission signs, decided before the root is unlocked.
pub struct ReadmitPlan {
    /// The root device and the version the re-admission follows.
    pub root: RootDevice,
    /// The key revoked with a cut.
    pub key: Name,
    /// The full names asked that the cut does not decide or list already
    /// (a range, an exact entry), each once; empty when there are none.
    pub adding: Vec<Name>,
}

/// Every check of re-admitting the full names `names` into the cut of
/// `key`, on the PIB at `pib_dir`, that needs no key. `namespace`, when
/// named, must be the namespace `key` is in (`revoke-other-namespace`
/// otherwise). Refusals: `not-root-device` and the root device's,
/// `revoke-outside-namespace` (param `operation` = `readmit`),
/// `readmit-no-cut`, `readmit-refused`, `revoke-refused` (`key` is not a
/// key name of the namespace).
pub fn plan(
    pib_dir: &Path,
    key: &Name,
    names: &[Name],
    namespace: Option<&Name>,
) -> Result<ReadmitPlan, RootError> {
    let pib = open_pib(pib_dir)?;
    let Some(root) = root_device_covering(&pib, key, "packets are re-admitted")? else {
        let held: Vec<String> = ndn_cert::RootStore::open_all(&pib)?
            .iter()
            .map(|s| s.namespace().to_string())
            .collect();
        return Err(RootError::new(
            code::REVOKE_OUTSIDE_NAMESPACE,
            "the key is outside every namespace this device holds the root of; nothing was \
             signed",
        )
        .with("name", key)
        .with("namespace", held.join(","))
        .with("operation", "readmit"));
    };
    let held = root.context.namespace();
    if let Some(asked) = namespace
        && asked != held
    {
        return Err(RootError::new(
            code::REVOKE_OTHER_NAMESPACE,
            "the key is in another namespace than the one named; nothing was signed",
        )
        .with("name", key)
        .with("namespace", held)
        .with("requested", asked));
    }
    let adding = readmissions_to_add(&root.context, key, names)?;
    Ok(ReadmitPlan {
        root,
        key: key.clone(),
        adding,
    })
}

/// A re-admission signed and handed over.
#[derive(Debug)]
pub struct Readmitted {
    pub namespace: Name,
    /// The version re-admitted from, and the new one.
    pub held_version: u64,
    pub version: u64,
    /// The root key that signed.
    pub root_key: Name,
    /// The key revoked with a cut.
    pub key: Name,
    /// The full names the new version adds to its cut.
    pub readmitted: Vec<Name>,
    pub handed_over: HandedOver,
}

/// Sign and hand over the re-admission `planned` (on the PIB at
/// `pib_dir`). Refusals: `nothing-to-sign` (no name given is left to add:
/// each is decided by a range of the cut or listed by one of its exact
/// entries already; a name below a tip is added, not left out), the running
/// device's (`device-*`, before the root is
/// unlocked), the secret's and `root-not-unlocked`, `version-not-taken`
/// (nothing changed) and `hand-over-unknown` (params `key`, `names`: asking
/// again once the device is idle settles it).
pub async fn readmit(
    planned: ReadmitPlan,
    pib_dir: &Path,
    device: &dyn RunningDevice,
    secrets: &dyn SecretSource,
) -> Result<Readmitted, RootError> {
    let ReadmitPlan { root, key, adding } = planned;
    let held_version = root.context.version();
    let nothing = || {
        RootError::new(
            code::NOTHING_TO_SIGN,
            "every name given is decided by the key's cut or listed in it already (by a range, \
             or as an exact entry); nothing was signed",
        )
        .with("version", held_version)
    };
    if adding.is_empty() {
        return Err(nothing());
    }
    check_device(device, pib_dir).await?;
    let signer = unlock_root(
        &root.store,
        secrets,
        VersionChange::Readmit { key: key.clone() },
    )
    .await?;
    let bump = bump_context_readmitting(signer.as_ref(), &root.data, &key, &adding).await;
    // The root signed its one version: drop it now (a software key is
    // zeroed). The running device gets only the signed version.
    drop(signer);
    let bump = bump?.ok_or_else(nothing)?;
    let version = bump.context.version();
    let names: Vec<String> = adding.iter().map(Name::to_string).collect();
    let handed_over = settle(
        hand_over(device, pib_dir, &bump).await,
        version,
        held_version,
        &[("key", key.to_string()), ("names", names.join(", "))],
    )?;
    Ok(Readmitted {
        namespace: root.context.namespace().clone(),
        held_version,
        version,
        root_key: root.store.key_name().clone(),
        key,
        readmitted: adding,
        handed_over,
    })
}
