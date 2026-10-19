//! Keeping the trust-context versions a device holds.
//!
//! Every version a device adopts — by link, by refresh, over its
//! namespace's sync group, or made on the device itself — goes through
//! [`keep`]: the namespace CA running on the device follows it (it stops
//! serving every certificate the version revokes, [`ndn_cert::CaState::follow_context`]),
//! then it is stored ([`ContextStore::persist`](crate::ContextStore::persist)),
//! published by name ([`crate::publish`]) and handed to the namespace's sync
//! group ([`crate::sync`]). A newer version adopted meanwhile by another
//! path wins: the older one is refused (`409`), never stored over it.
//!
//! The versions a refresh walked through to reach the newest
//! (`ndn_cert::ContextUpdate::walked`) are stored and published too
//! ([`keep_update`]), so the devices behind this one follow the namespace
//! the same way, version by version.
//!
//! A version made on the device by a tool that signs offline (a revocation,
//! a recovery kit, a schema update on the root device; a recovery on a
//! replacement) is taken with [`apply_update`] under the same continuity
//! rule as a fetched one.

use std::sync::Arc;

use bytes::Bytes;
use ndn_cert::report::{
    AdoptedContextInfo, ContextChange, ContextRefreshInfo, Detail, RefreshState, TrustRefusal,
    code, detail_code,
};
use ndn_cert::{AdoptError, AnchorLink, CaRevocation, ContextUpdate, LinkAdoption};
use ndn_packet::{Data, Name};
use ndn_security::SignedTrustContext;

use crate::words::{detail, refuse};
use crate::{Participant, hex};

/// The refusal of an adoption that failed with `e`.
pub fn adopt_refusal(e: &AdoptError) -> TrustRefusal {
    // The two that tell what to check on this device's routes, worded by
    // each host ([`crate::HostWords::add_route`], `list_routes`).
    match e {
        AdoptError::Fetch { namespace, source } => {
            return refuse(
                code::CONTEXT_UNREACHABLE,
                [
                    ("namespace", namespace.clone()),
                    ("source", source.to_string()),
                    ("error", e.to_string()),
                ],
            );
        }
        AdoptError::WrongContext { namespace, reason } => {
            return refuse(
                code::CONTEXT_REFUSED,
                [
                    ("namespace", namespace.clone()),
                    ("wrong_context", reason.clone()),
                    ("error", e.to_string()),
                ],
            );
        }
        _ => {}
    }
    let kind = match e {
        AdoptError::BadLink(_)
        | AdoptError::NotAnchor(_)
        | AdoptError::LinkMissing(_)
        | AdoptError::BadNamespace(_)
        | AdoptError::BadData(_)
        | AdoptError::UnsignedLegacyContext => code::LINK_INVALID,
        AdoptError::Fetch { .. } => code::CONTEXT_UNREACHABLE,
        AdoptError::InProgress(_) => code::TRUST_CHANGE_IN_PROGRESS,
        _ => code::CONTEXT_REFUSED,
    };
    TrustRefusal::new(kind, e.to_string()).with("error", e)
}

/// What [`keep`] did with a version this device adopted.
pub struct Kept {
    /// Where it is stored, or why storing it failed (it holds for this run,
    /// and is gone after a restart).
    pub stored: Result<String, TrustRefusal>,
    /// What this device's CA of the namespace stopped serving because the
    /// version revokes it; `None` when the device runs no CA of it.
    pub ca: Option<CaRevocation>,
}

/// The params of a detail saying what became of a version adopted
/// (`kept`, [`keep`]'s result): `stored` (where) or `cause` (why it is not
/// kept) with its params, `published`, and the CA's part (`ca_revoked`,
/// `ca_not_persisted`).
pub(crate) fn kept_params(
    p: &Participant,
    kept: &Result<Kept, TrustRefusal>,
) -> Vec<(&'static str, String)> {
    let mut params = vec![("published", p.publisher().is_some().to_string())];
    let not_kept = match kept {
        Ok(kept) => {
            if let Some(ca) = &kept.ca {
                if !ca.revoked.is_empty() {
                    let names: Vec<String> = ca.revoked.iter().map(ToString::to_string).collect();
                    params.push(("ca_revoked", names.join(", ")));
                }
                if let Some(e) = &ca.not_persisted {
                    params.push(("ca_not_persisted", e.to_string()));
                }
            }
            match &kept.stored {
                Ok(stored) => {
                    params.push(("stored", stored.clone()));
                    None
                }
                Err(e) => Some(e),
            }
        }
        Err(e) => Some(e),
    };
    if let Some(e) = not_kept {
        // The cause's params, then its code; this detail's own win.
        for (k, v) in &e.params {
            if let Some(k) = cause_param(k) {
                params.push((k, v.clone()));
            }
        }
        params.push(("cause", e.code.clone()));
    }
    params
}

/// The params a cause of [`kept_params`] may carry (those of
/// `context-not-stored` and `context-superseded`).
fn cause_param(key: &str) -> Option<&'static str> {
    ["namespace", "version", "now", "error", "location"]
        .into_iter()
        .find(|k| *k == key)
}

/// Keep `ctx` (signed Data `data`), already in the keyring, reached `how`:
/// this device's CA of its namespace stops serving every certificate it
/// revokes, the host is told ([`crate::Participant::events`]), and it is
/// stored and published by name as the namespace's newest version (the
/// versions before it stay stored and served). Refused (`409`) when the
/// keyring meanwhile holds a newer version of the namespace: that one is
/// what is kept (and followed). A failure to store it is reported in
/// [`Kept::stored`]: the version holds for this run all the same.
pub fn keep(
    p: &Participant,
    ctx: &SignedTrustContext,
    data: &Data,
    how: ContextChange,
) -> Result<Kept, TrustRefusal> {
    let _keeping = p
        .keeping
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(held) = p.keyring().version_of(ctx.namespace())
        && held > ctx.version()
    {
        return Err(refuse(
            code::CONTEXT_SUPERSEDED,
            [
                ("namespace", ctx.namespace().to_string()),
                ("version", ctx.version().to_string()),
                ("now", held.to_string()),
            ],
        ));
    }
    let ca = p
        .ca_for(ctx.namespace())
        .and_then(|ca| ca.follow_context(ctx));
    // The version holds for this run whether or not it is stored: the host
    // is told of it, and of what it changes about the device's membership,
    // now.
    crate::membership::kept(p, ctx, how);
    Ok(Kept {
        stored: store_and_publish(p, ctx, data),
        ca,
    })
}

/// Store and publish `ctx` (signed Data `data`), a version this device went
/// through to reach the one its keyring holds
/// (`ndn_cert::ContextUpdate::walked`): kept by its exact name for the
/// devices behind this one, which follow the namespace the same way. The
/// stored and published newest version never moves back to it.
pub fn keep_walked(
    p: &Participant,
    ctx: &SignedTrustContext,
    data: &Data,
) -> Result<String, TrustRefusal> {
    let _keeping = p
        .keeping
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    store_and_publish(p, ctx, data)
}

/// Under `keeping`.
fn store_and_publish(
    p: &Participant,
    ctx: &SignedTrustContext,
    data: &Data,
) -> Result<String, TrustRefusal> {
    let stored = p.store().persist(ctx, data).map_err(|e| {
        refuse(
            code::CONTEXT_NOT_STORED,
            [
                ("namespace", ctx.namespace().to_string()),
                ("version", ctx.version().to_string()),
                ("error", e),
                ("location", p.store().location()),
            ],
        )
    })?;
    if let Some(publisher) = p.publisher() {
        publisher.publish(ctx, data);
    }
    if let Some(sync) = p.sync() {
        sync.kept(ctx, data);
    }
    Ok(stored)
}

/// Keep a context adopted into the keyring by link: stored and published.
/// Refused (`409`) when the keyring meanwhile holds a newer version of the
/// namespace: that one is what is kept.
pub fn keep_adopted(
    p: &Participant,
    adopted: &LinkAdoption,
    expected_fingerprint: &[u8; 32],
) -> Result<AdoptedContextInfo, TrustRefusal> {
    let ctx = &adopted.context;
    let stored = keep(p, ctx, &adopted.data, ContextChange::Adopt)?.stored?;
    tracing::info!(
        target: "security",
        namespace = %ctx.namespace(),
        version = ctx.version(),
        fetched = adopted.fetched,
        stored = %stored,
        "adopted trust context"
    );
    Ok(AdoptedContextInfo {
        namespace: ctx.namespace().to_string(),
        version: ctx.version(),
        expected_fingerprint: hex(expected_fingerprint),
        anchors: ctx.anchors().len(),
        ca_endpoints: ctx.ca_endpoints().len(),
        fetched: adopted.fetched,
        stored,
        published: p.publisher().is_some(),
    })
}

/// Adopt the trust context `link` names — inline: verified against the
/// link; fingerprint only: fetched by name through the engine while its
/// validator expects exactly that context — then keep it: stored and
/// published. A fetch goes to the forwarders serving the namespace, not to
/// this device's own publisher, and never takes a pointer this device
/// cached.
pub async fn adopt_link(
    p: &Participant,
    link: &AnchorLink,
) -> Result<AdoptedContextInfo, TrustRefusal> {
    // A fetched context must come from the forwarders serving the
    // namespace, not from this device's own publisher (which holds only the
    // versions this device already has).
    let bypass = match (p.publisher(), &link.context_data) {
        (Some(publisher), None) => Some(publisher.bypass(&link.namespace)),
        _ => None,
    };
    if link.context_data.is_none() {
        crate::publish::forget_cached_metadata(p.engine(), &link.namespace);
    }
    let adopted = ndn_identity::adopt_anchor_link_via_engine(p.engine(), p.keyring(), link)
        .await
        .map_err(|e| {
            tracing::warn!(
                target: "security",
                namespace = %link.namespace,
                error = %e,
                "trust context not adopted"
            );
            adopt_refusal(&e)
        })?;
    drop(bypass);
    keep_adopted(p, &adopted, &link.expected_fingerprint)
}

/// Keep `update`, adopted into the keyring by a refresh or from the
/// namespace's sync group (`how`): store and publish every version walked
/// through, then the newest — so this device comes back with it after a
/// restart and the devices behind it can follow the same versions by name. A
/// failure to store one is logged and does not undo the adoption; what
/// became of the newest is returned ([`keep`]).
pub fn keep_update(
    p: &Participant,
    update: &ContextUpdate,
    how: ContextChange,
) -> Result<Kept, TrustRefusal> {
    let namespace = update.context.namespace();
    for step in &update.walked {
        if let Err(e) = keep_walked(p, &step.context, &step.data) {
            tracing::warn!(
                target: "security",
                namespace = %namespace,
                version = step.context.version(),
                error = %e.reason,
                "could not keep a trust-context version walked through"
            );
        }
    }
    let kept = keep(p, &update.context, &update.data, how);
    let walked: Vec<u64> = update.walked.iter().map(|s| s.context.version()).collect();
    let revoked: Vec<String> = update.revoked.iter().map(Name::to_string).collect();
    tracing::info!(
        target: "security",
        namespace = %namespace,
        how = ?how,
        previous = update.previous,
        version = update.context.version(),
        walked = ?walked,
        signer = %update.signer.name,
        revoked = ?revoked,
        stored = matches!(&kept, Ok(Kept { stored: Ok(_), .. })),
        "adopted trust-context update"
    );
    kept
}

/// Adopt `wire` (a signed trust-context Data) as the next version of the
/// context this device holds for its namespace — only if it is strictly
/// newer and signed by an anchor of the held version, as a refresh requires
/// — then keep it ([`keep`]).
///
/// The answer says what became of the version, so the tool that made it
/// may undo its own work only on a refusal: `200` once it is adopted (even
/// if storing it then failed — the detail says so), and `200` for a version
/// this device already took and stores byte for byte, so a tool that got no
/// answer can hand the same version over again and learn the outcome (the
/// second request waits for the first). Any other answer means it was not
/// adopted.
pub async fn apply_update(
    p: &Participant,
    wire: Bytes,
) -> Result<ContextRefreshInfo, TrustRefusal> {
    let invalid =
        |error: String| TrustRefusal::new(code::UPDATE_INVALID, error.clone()).with("error", error);
    let data = Data::decode(wire).map_err(|e| invalid(format!("not a Data packet: {e}")))?;
    let namespace = ndn_security::context_namespace_of(&data.name).ok_or_else(|| {
        invalid(format!(
            "{} is not a trust-context name (<ns>/32=trust-context/v=<N>)",
            data.name
        ))
    })?;
    let _one_change = p.context_change.lock().await;
    let held = p.held_context(&namespace).ok_or_else(|| {
        refuse(
            code::CONTEXT_NOT_HELD,
            [("namespace", namespace.to_string())],
        )
    })?;
    if let Some((version, location)) = stored_copy(p, &held, &data) {
        return Ok(ContextRefreshInfo {
            namespace: namespace.to_string(),
            state: RefreshState::Current,
            held_version: held.version(),
            version,
            revoked: Vec::new(),
            detail: Detail::new(
                detail_code::UPDATE_ALREADY_TAKEN,
                format!(
                    "already took v{version} (holds v{}); stored {location}",
                    held.version(),
                ),
            )
            .with("version", version)
            .with("held", held.version())
            .with("stored", location),
        });
    }
    let (ctx, signer) = ndn_cert::open_context_update(&held, &data)
        .await
        .map_err(|e| {
            TrustRefusal::new(
                code::UPDATE_REFUSED,
                format!(
                    "refused a trust-context update for {namespace}: {e}; the held version v{} \
                     stays in force",
                    held.version()
                ),
            )
            .with("namespace", &namespace)
            .with("held_version", held.version())
            .with("error", e)
        })?;
    let context = Arc::new(ctx);
    p.keyring()
        .adopt_update_from(&held, Arc::clone(&context))
        .map_err(|now| {
            let now = now.unwrap_or_default();
            TrustRefusal::new(
                code::CONTEXT_CHANGED_MEANWHILE,
                format!("{namespace} changed meanwhile (now v{now}); make the new version again"),
            )
            .with("namespace", &namespace)
            .with("now", now)
        })?;
    let kept = keep(p, &context, &data, ContextChange::Update);
    let revoked: Vec<String> = context
        .revocations()
        .iter()
        .filter(|r| !held.revocations().contains(r))
        .map(Name::to_string)
        .collect();
    tracing::info!(
        target: "security",
        namespace = %namespace,
        previous = held.version(),
        version = context.version(),
        signer = %signer.name,
        revoked = ?revoked,
        stored = kept.as_ref().is_ok_and(|k| k.stored.is_ok()),
        "adopted trust-context version made on this device"
    );
    let mut params = kept_params(p, &kept);
    params.extend([
        ("version", context.version().to_string()),
        ("signer", signer.name.to_string()),
        ("held", held.version().to_string()),
    ]);
    Ok(ContextRefreshInfo {
        namespace: namespace.to_string(),
        state: RefreshState::Updated,
        held_version: held.version(),
        version: context.version(),
        revoked,
        detail: detail(detail_code::UPDATE_ADOPTED, params),
    })
}

/// The version `data` carries and where this device stores it, when it is
/// no newer than `held` and stored exactly (a version this device already
/// took).
fn stored_copy(p: &Participant, held: &SignedTrustContext, data: &Data) -> Option<(u64, String)> {
    let version = data
        .name
        .components()
        .last()
        .and_then(ndn_packet::NameComponent::as_version)?;
    if version > held.version() {
        return None;
    }
    p.store()
        .stored_versions(held.namespace())
        .ok()?
        .into_iter()
        .find_map(|stored| {
            let (_, kept) = stored.read.ok()?;
            (kept.raw() == data.raw()).then_some((version, stored.location))
        })
}
