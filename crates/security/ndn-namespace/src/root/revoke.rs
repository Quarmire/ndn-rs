//! Revoking a device identity, key or certificate on the root device: a new
//! version of the trust context listing the keys as revoked.
//!
//! [`plan`] checks, before anything is asked, that this is the root device
//! of the namespace the name is in (of those whose root the PIB holds, the
//! longest covering it; a namespace named must be that one), which keys the
//! name designates (a key or certificate name: its key; a device identity:
//! every key the namespace CA certified for it, read from that CA's store in
//! the PIB), that none is the root's or the CA's, and which of them the held
//! version does not revoke yet ([`ndn_cert::plan_revocation`]). [`revoke`]
//! then checks the running device uses the same PIB, unlocks that
//! namespace's root to sign version `N+1`
//! ([`ndn_cert::bump_context_revoking`]), drops the signer, and hands the
//! version to the running device ([`super::device::hand_over`]). The other
//! namespaces whose roots the PIB holds are not touched.
//!
//! The namespace CA follows the signed version
//! ([`ndn_cert::CaState::follow_context`]) wherever its device holds it:
//! it stops serving every certificate of a revoked key, and the device name
//! is free for a new key. Every node's validator refuses a chain through a
//! revoked key once it holds the version.

use std::path::Path;

use ndn_cert::report::code;
use ndn_cert::{RevocationPlan, bump_context_revoking};
use ndn_packet::Name;

use super::device::{check_device, hand_over, settle};
use super::{RootError, RunningDevice, SecretSource, VersionChange, open_pib, unlock_root};
use crate::admin::HandedOver;

/// Every check of revoking what `name` designates that needs no key, on the
/// PIB at `pib_dir`. `namespace`, when named, must be the namespace the
/// revocation is made in (`revoke-other-namespace` otherwise). `adding`
/// empty: the held version revokes them all already, nothing to sign.
pub fn plan(
    pib_dir: &Path,
    name: &Name,
    namespace: Option<&Name>,
) -> Result<RevocationPlan, RootError> {
    let pib = open_pib(pib_dir)?;
    let plan = ndn_cert::plan_revocation(&pib, name)?;
    let held = plan.root.context.namespace();
    if let Some(asked) = namespace
        && asked != held
    {
        return Err(RootError::new(
            code::REVOKE_OTHER_NAMESPACE,
            "the name is in another namespace than the one named; nothing was signed",
        )
        .with("name", name)
        .with("namespace", held)
        .with("requested", asked));
    }
    Ok(plan)
}

/// A revocation signed and handed over.
#[derive(Debug)]
pub struct Revoked {
    pub namespace: Name,
    /// The version revoked from, and the new one.
    pub held_version: u64,
    pub version: u64,
    /// The root key that signed.
    pub root_key: Name,
    /// The keys the new version revokes that the held one did not.
    pub revoked: Vec<Name>,
    pub handed_over: HandedOver,
}

/// Sign and hand over the revocation `planned` (of `name`, on the PIB at
/// `pib_dir`). Refusals: `nothing-to-sign` (the held version revokes them
/// all), the running device's (`device-*`, before the root is unlocked),
/// the secret's and `root-not-unlocked`, `version-not-taken` (nothing
/// changed) and `hand-over-unknown` (params `keys`, `name`: asking again
/// once the device is idle settles it).
pub async fn revoke(
    planned: RevocationPlan,
    name: &Name,
    pib_dir: &Path,
    device: &dyn RunningDevice,
    secrets: &dyn SecretSource,
) -> Result<Revoked, RootError> {
    let RevocationPlan { root, keys, adding } = planned;
    let held_version = root.context.version();
    let nothing = || {
        RootError::new(
            code::NOTHING_TO_SIGN,
            "the held trust context revokes every key named already; nothing was signed",
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
        VersionChange::Revoke { name: name.clone() },
    )
    .await?;
    let bump = bump_context_revoking(signer.as_ref(), &root.data, &keys).await;
    // The root signed its one version: drop it now (a software key is
    // zeroed). The running device gets only the signed version.
    drop(signer);
    let bump = bump?.ok_or_else(nothing)?;
    let version = bump.context.version();
    let added: Vec<String> = bump.added.iter().map(Name::to_string).collect();
    let handed_over = settle(
        hand_over(device, pib_dir, &bump).await,
        version,
        held_version,
        &[("keys", added.join(", ")), ("name", name.to_string())],
    )?;
    Ok(Revoked {
        namespace: root.context.namespace().clone(),
        held_version,
        version,
        root_key: root.store.key_name().clone(),
        revoked: bump.added,
        handed_over,
    })
}
