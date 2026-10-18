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
use ndn_cert::report::{AdoptedContextInfo, ContextRefreshInfo, RefreshState, TrustRefusal};
use ndn_cert::{AdoptError, AnchorLink, CaRevocation, ContextUpdate, LinkAdoption};
use ndn_mgmt_wire::control_response::status;
use ndn_packet::{Data, Name};
use ndn_security::SignedTrustContext;

use crate::{Participant, hex, refusal};

/// The status code an adoption refusal is reported with.
pub fn adopt_status(e: &AdoptError) -> u64 {
    match e {
        AdoptError::BadLink(_)
        | AdoptError::NotAnchor(_)
        | AdoptError::LinkMissing(_)
        | AdoptError::BadNamespace(_)
        | AdoptError::BadData(_)
        | AdoptError::UnsignedLegacyContext => status::BAD_PARAMS,
        AdoptError::Fetch { .. } => 504,
        AdoptError::InProgress(_) => 409,
        _ => status::UNAUTHORIZED,
    }
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

impl Kept {
    /// The CA's part, worded to end an answer's detail; empty when the CA
    /// had nothing to stop serving.
    pub fn ca_detail(&self) -> String {
        let Some(ca) = &self.ca else {
            return String::new();
        };
        let mut detail = String::new();
        if !ca.revoked.is_empty() {
            let names: Vec<String> = ca.revoked.iter().map(ToString::to_string).collect();
            detail = format!(
                "; this node's CA no longer serves {} (the version revokes their keys) and \
                 their device names are free for a new key",
                names.join(", ")
            );
        }
        if let Some(e) = &ca.not_persisted {
            detail.push_str(&format!(
                "; the CA could not record that in its store ({e}): it holds for this run, and \
                 the CA follows the stored trust context again when the daemon starts"
            ));
        }
        detail
    }
}

/// How an update reached this device, for the log.
#[derive(Debug, Clone, Copy)]
pub enum Adopted {
    /// A refresh fetched it from upstream.
    ByRefresh,
    /// It was pushed over the namespace's sync group.
    OverSync,
}

/// Keep `ctx` (signed Data `data`), already in the keyring: this device's
/// CA of its namespace stops serving every certificate it revokes, and it is
/// stored and published by name as the namespace's newest version (the
/// versions before it stay stored and served). Refused (`409`) when the
/// keyring meanwhile holds a newer version of the namespace: that one is
/// what is kept (and followed). A failure to store it is reported in
/// [`Kept::stored`]: the version holds for this run all the same.
pub fn keep(p: &Participant, ctx: &SignedTrustContext, data: &Data) -> Result<Kept, TrustRefusal> {
    let _keeping = p
        .keeping
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(held) = p.keyring().version_of(ctx.namespace())
        && held > ctx.version()
    {
        return Err(refusal(
            409,
            format!(
                "{} v{} was adopted, but v{held} was adopted meanwhile by another command; \
                 v{held} is the version this node holds, stores and publishes",
                ctx.namespace(),
                ctx.version()
            ),
        ));
    }
    let ca = p.ca().and_then(|ca| ca.follow_context(ctx));
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
        refusal(
            status::SERVER_ERROR,
            format!(
                "adopted {} v{} for this run, but storing it failed ({e}); it will be gone \
                 after a restart — fix {}",
                ctx.namespace(),
                ctx.version(),
                p.store().location()
            ),
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
    let stored = keep(p, ctx, &adopted.data)?.stored?;
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
    let refuse = |e: AdoptError| refusal(adopt_status(&e), e.to_string());
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
            refuse(e)
        })?;
    drop(bypass);
    keep_adopted(p, &adopted, &link.expected_fingerprint)
}

/// Keep `update`, adopted into the keyring by a refresh or from the
/// namespace's sync group: store and publish every version walked through,
/// then the newest — so this device comes back with it after a restart and
/// the devices behind it can follow the same versions by name. A failure to
/// store one is logged and does not undo the adoption; what became of the
/// newest is returned ([`keep`]).
pub fn keep_update(
    p: &Participant,
    update: &ContextUpdate,
    how: Adopted,
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
    let kept = keep(p, &update.context, &update.data);
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

/// Whether a version this device keeps is published ([`keep`] publishes
/// only with a publisher), worded for a detail.
pub(crate) fn publication(p: &Participant) -> String {
    if p.publisher().is_some() {
        " and published".into()
    } else {
        p.words().not_published()
    }
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
pub async fn apply_update(p: &Participant, wire: Bytes) -> Result<ContextRefreshInfo, TrustRefusal> {
    let data = Data::decode(wire)
        .map_err(|e| refusal(status::BAD_PARAMS, format!("not a Data packet: {e}")))?;
    let namespace = ndn_security::context_namespace_of(&data.name).ok_or_else(|| {
        refusal(
            status::BAD_PARAMS,
            format!("{} is not a trust-context name (<ns>/32=trust-context/v=<N>)", data.name),
        )
    })?;
    let _one_change = p.context_change.lock().await;
    let held = p
        .held_context(&namespace)
        .ok_or_else(|| refusal(status::NOT_FOUND, p.words().no_context(&namespace)))?;
    if let Some((version, location)) = stored_copy(p, &held, &data) {
        return Ok(ContextRefreshInfo {
            namespace: namespace.to_string(),
            state: RefreshState::Current,
            held_version: held.version(),
            version,
            revoked: Vec::new(),
            detail: format!(
                "already took v{version} (holds v{}); stored {location}",
                held.version(),
            ),
        });
    }
    let (ctx, signer) = ndn_cert::open_context_update(&held, &data)
        .await
        .map_err(|e| {
            refusal(
                403,
                format!(
                    "refused a trust-context update for {namespace}: {e}; the held version v{} \
                     stays in force",
                    held.version()
                ),
            )
        })?;
    let context = Arc::new(ctx);
    p.keyring()
        .adopt_update_from(&held, Arc::clone(&context))
        .map_err(|now| {
            refusal(
                409,
                format!(
                    "{namespace} changed meanwhile (now v{}); make the new version again",
                    now.unwrap_or_default()
                ),
            )
        })?;
    let kept = keep(p, &context, &data);
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
    let adopted = format!(
        "adopted v{} (signed by {}, an anchor of v{})",
        context.version(),
        signer.name,
        held.version()
    );
    Ok(ContextRefreshInfo {
        namespace: namespace.to_string(),
        state: RefreshState::Updated,
        held_version: held.version(),
        version: context.version(),
        revoked,
        detail: match kept {
            Ok(kept) => match &kept.stored {
                Ok(stored) => format!(
                    "{adopted}; stored {stored}{}{}",
                    publication(p),
                    kept.ca_detail()
                ),
                Err(e) => format!("{adopted}, but {}{}", e.reason, kept.ca_detail()),
            },
            Err(e) => format!("{adopted}, but {}", e.reason),
        },
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
