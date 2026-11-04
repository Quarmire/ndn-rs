//! Revoking a device identity, key or certificate on the root device: a new
//! version of the trust context listing the keys as revoked — and, given
//! one, the revocation cut of one of them beside its revocation.
//!
//! [`plan`] checks, before anything is asked, that this is the root device
//! of the namespace the name is in (of those whose root the PIB holds, the
//! longest covering it; a namespace named must be that one), which keys the
//! name designates (a key or certificate name: its key; a device identity:
//! every key the namespace CA certified for it, read from that CA's store in
//! the PIB), that none is the root's or the CA's, which of them the held
//! version does not revoke yet ([`ndn_cert::plan_revocation`]), and that a
//! cut file given is bounded at or before the time the owner says the key
//! was lost, carries its whole manifest, and holds the cut of one of those
//! keys, listing only its device's log, naming its public key
//! ([`ndn_cert::GivenCut`], [`ndn_cert::check_cut`]: `cut-refused`
//! otherwise). [`revoke`] then checks the running device uses the same PIB,
//! stores the cut's manifest packets beside the contexts (the running
//! device serves them with the version), unlocks that namespace's root to
//! sign version `N+1` ([`ndn_cert::bump_context_revoking`]), drops the
//! signer, and hands the version to the running device
//! ([`super::device::hand_over`]). The other namespaces whose roots the PIB
//! holds are not touched.
//!
//! Without a cut, every packet a revoked key signed is refused once a node
//! holds the version. With one, the packets the cut accepts (the log
//! entries the root's data layer first verified before the loss, each by
//! its exact bytes as the manifest lists them) stay accepted, and the key's
//! certificates stay served so they can be verified; everything else it
//! signed is refused. The entries the cut's bound left out
//! ([`ndn_cert::CutFile::left_out`]) are refused with the rest; a genuine
//! one is re-admitted later by its full name ([`super::readmit`]).
//!
//! The namespace CA follows the signed version
//! ([`ndn_cert::CaState::follow_context`]) wherever its device holds it:
//! it never certifies or renews a revoked key again, and the device name is
//! free for a new key. Every node's validator refuses a chain through a
//! revoked key once it holds the version (outside the key's cut).

use std::path::Path;

use ndn_cert::report::code;
use ndn_cert::{CutFile, GivenCut, RevocationPlan, bump_context_revoking};
use ndn_packet::Name;

use super::device::{check_device, hand_over, settle};
use super::{RootError, RunningDevice, SecretSource, VersionChange, open_pib, unlock_root};
use crate::admin::HandedOver;

/// Every check of revoking what `name` designates that needs no key, on the
/// PIB at `pib_dir`. `namespace`, when named, must be the namespace the
/// revocation is made in (`revoke-other-namespace` otherwise). `cut`, when
/// given, must be bounded at or before its loss time, carry its whole
/// manifest and be the revocation cut of one of the keys the version adds,
/// listing only that key's device log and naming its public key
/// (`cut-refused` otherwise); it is signed beside the revocation. `adding`
/// empty: the held version revokes them all already, nothing to sign.
pub fn plan(
    pib_dir: &Path,
    name: &Name,
    namespace: Option<&Name>,
    cut: Option<GivenCut>,
) -> Result<RevocationPlan, RootError> {
    let pib = open_pib(pib_dir)?;
    let plan = ndn_cert::plan_revocation(&pib, name, cut)?;
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

/// What a host asks before it revokes with a cut, in plain words.
pub const LOSS_QUESTION: &str = "When did you lose it?";

/// When the owner says a key was lost (the answer to [`LOSS_QUESTION`]),
/// in ms since the Unix epoch, read against `now` (ms since the epoch): a
/// date and time in RFC 3339 (`2026-11-04T10:00:00Z`, with fractional
/// seconds or an offset; a space for `T` and no zone are read as UTC), a
/// span before now (`2h ago`, `90min ago`, `3days ago`), or `now`. A time
/// after `now` is refused: a loss has happened.
pub fn parse_when(text: &str, now: u64) -> Result<u64, String> {
    let text = text.trim();
    let at = if text.eq_ignore_ascii_case("now") {
        now
    } else if let Some(span) = text.strip_suffix("ago") {
        let span = humantime::parse_duration(span.trim())
            .map_err(|e| format!("{text:?} is not a span of time before now ({e})"))?;
        let ms = u64::try_from(span.as_millis()).unwrap_or(u64::MAX);
        now.checked_sub(ms)
            .ok_or_else(|| format!("{text:?} is before 1970"))?
    } else {
        let at = humantime::parse_rfc3339_weak(text).map_err(|e| {
            format!(
                "{text:?} is not a date and time ({e}): give it in RFC 3339 \
                 (2026-11-04T10:00:00Z), as a span before now (2h ago), or now"
            )
        })?;
        let since = at
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| format!("{text:?} is before 1970"))?;
        u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
    };
    if at > now {
        return Err(format!(
            "{text:?} is in the future: give the time the device was lost (or `now`)"
        ));
    }
    Ok(at)
}

/// `ms` since the Unix epoch in RFC 3339 with milliseconds
/// (`2026-11-04T10:00:00.000Z`): how a host shows a cut's bound or a loss
/// time, and what [`parse_when`] reads back.
pub fn format_when(ms: u64) -> String {
    let at = std::time::UNIX_EPOCH + std::time::Duration::from_millis(ms);
    humantime::format_rfc3339_millis(at).to_string()
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
    /// The cut file whose cut was signed beside them, if any: its
    /// [`CutFile::left_out`] entries are refused with the rest.
    pub cut: Option<CutFile>,
    pub handed_over: HandedOver,
}

/// Store the manifest packets of `cut` beside the contexts of `namespace`
/// in the PIB at `pib_dir`, so the running device (now, or at its next
/// start) serves them with the version (`cut-refused` when one cannot be
/// stored: nothing is signed).
pub(crate) fn store_manifest(
    pib_dir: &Path,
    namespace: &Name,
    cut: &CutFile,
) -> Result<(), RootError> {
    for wire in &cut.manifest {
        ndn_cert::persist_cut_manifest_packet(pib_dir, namespace, wire).map_err(|e| {
            RootError::new(
                code::CUT_REFUSED,
                "the cut's manifest packets cannot be stored beside the contexts; nothing was \
                 signed",
            )
            .with("key", cut.cut.key())
            .with("pib", pib_dir.display())
            .caused_by(e)
        })?;
    }
    Ok(())
}

/// Sign and hand over the revocation `planned` (of `name`, on the PIB at
/// `pib_dir`). Refusals: `nothing-to-sign` (the held version revokes them
/// all), the running device's (`device-*`, before the root is unlocked),
/// `cut-refused` (its manifest packets cannot be stored), the secret's and
/// `root-not-unlocked`, `version-not-taken` (nothing changed) and
/// `hand-over-unknown` (params `keys`, `name`: asking again once the device
/// is idle settles it).
pub async fn revoke(
    planned: RevocationPlan,
    name: &Name,
    pib_dir: &Path,
    device: &dyn RunningDevice,
    secrets: &dyn SecretSource,
) -> Result<Revoked, RootError> {
    let RevocationPlan {
        root,
        keys,
        adding,
        cut,
    } = planned;
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
    if let Some(cut) = &cut {
        store_manifest(pib_dir, root.context.namespace(), cut)?;
    }
    let signer = unlock_root(
        &root.store,
        secrets,
        VersionChange::Revoke { name: name.clone() },
    )
    .await?;
    let cuts: Vec<_> = cut.iter().map(|c| c.cut.clone()).collect();
    let bump = bump_context_revoking(signer.as_ref(), &root.data, &keys, &cuts).await;
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
        cut,
        handed_over,
    })
}
