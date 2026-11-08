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
        // Adopted by name only: no inline context is the way round.
        AdoptError::GenesisUnreachable { namespace, source } => {
            return refuse(
                code::CONTEXT_UNREACHABLE,
                [
                    ("namespace", namespace.clone()),
                    ("source", source.to_string()),
                    ("self_certifying", "true".to_owned()),
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
        AdoptError::Fetch { .. } | AdoptError::GenesisUnreachable { .. } => {
            code::CONTEXT_UNREACHABLE
        }
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
    // Stored first, then told: a host that follows the stored versions on
    // the `context-updated` event finds the version on disk when it is told
    // of it. The version holds for this run whether or not it is stored:
    // the host is told of it, and of what it changes about the device's
    // membership, either way.
    let stored = store_and_publish(p, ctx, data);
    crate::membership::kept(p, ctx, how);
    Ok(Kept { stored, ca })
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
    // The manifests of its cuts: served from the store, the missing ones
    // fetched by full name.
    crate::cut_manifests::keep(p.engine(), &p.store, p.publisher(), ctx);
    Ok(stored)
}

/// Keep a context adopted into the keyring by link: stored and published,
/// after the versions it was reached through (a self-certifying
/// namespace's genesis and the versions walked from it, which a restart
/// needs). Refused (`409`) when the keyring meanwhile holds a newer version
/// of the namespace: that one is what is kept.
pub fn keep_adopted(
    p: &Participant,
    adopted: &LinkAdoption,
    expected_fingerprint: &[u8; 32],
) -> Result<AdoptedContextInfo, TrustRefusal> {
    let ctx = &adopted.context;
    for step in &adopted.earlier {
        keep_walked(p, &step.context, &step.data)?;
    }
    let stored = keep(p, ctx, &adopted.data, ContextChange::Adopt)?.stored?;
    tracing::info!(
        target: "security",
        namespace = %ctx.namespace(),
        version = ctx.version(),
        fetched = adopted.fetched,
        offline_genesis = adopted.offline_genesis,
        stored = %stored,
        "adopted trust context"
    );
    if adopted.offline_genesis {
        tracing::warn!(
            target: "security",
            namespace = %ctx.namespace(),
            "{}",
            LinkAdoption::OFFLINE_GENESIS_NOTE
        );
    }
    Ok(AdoptedContextInfo {
        namespace: ctx.namespace().to_string(),
        version: ctx.version(),
        expected_fingerprint: hex(expected_fingerprint),
        anchors: ctx.anchors().len(),
        ca_endpoints: ctx.ca_endpoints().len(),
        fetched: adopted.fetched,
        offline_genesis: adopted.offline_genesis,
        stored,
        published: p.publisher().is_some(),
    })
}

/// Adopt the trust context `link` names — inline: verified against the
/// link; fingerprint only: fetched by name through the engine while its
/// validator expects exactly that context; a self-certifying namespace not
/// held, whatever the link carries: adopted by name from its genesis — then
/// keep it: stored and published. Every fetch an adoption makes
/// ([`AnchorLink::fetches`]) goes to the forwarders serving the namespace,
/// not to this device's own publisher, and never takes a pointer this
/// device cached.
pub async fn adopt_link(
    p: &Participant,
    link: &AnchorLink,
) -> Result<AdoptedContextInfo, TrustRefusal> {
    // A fetched context must come from the forwarders serving the
    // namespace, not from this device's own publisher (which holds only the
    // versions this device already has).
    let fetches = link.fetches(p.keyring());
    let bypass = p
        .publisher()
        .filter(|_| fetches)
        .map(|publisher| publisher.bypass(&link.namespace));
    if fetches {
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

#[cfg(test)]
mod tests {
    use ndn_engine::{EngineBuilder, EngineConfig};
    use ndn_security::self_certifying::self_certifying_name;
    use ndn_security::{Ed25519Signer, FilePib, Keyring, SecurityManager, Signer};
    use ndn_transport::FaceId;
    use ndn_trust_envelope::TrustEnvelope;

    use super::*;
    use crate::{ParticipantParts, PibContextStore};

    /// A self-certifying namespace's line after a recovery: v1 (its
    /// genesis), v2 adding a recovery anchor, v3 (signed by it) and v4 (the
    /// new root's); and a thief's own version 1, signed with the stolen
    /// genesis key, which nothing of that line follows from.
    async fn recovered_line() -> (Name, Vec<Data>, Data) {
        let seed = [43u8; 32];
        let public = Ed25519Signer::from_seed(&seed, Name::root()).public_key_bytes();
        let ns = self_certifying_name(&public);
        let root: Arc<dyn Signer> = Arc::new(Ed25519Signer::from_seed(
            &seed,
            ns.clone().append("KEY").append("genesis"),
        ));
        let ctx = SignedTrustContext::hierarchical(ns.clone()).with_version(1);
        assert!(ctx.add_anchor(ndn_cert::recovery_anchor(Arc::clone(&root)).await.unwrap()));
        let v1 = ctx.sign_into_data_async(root.as_ref()).await.unwrap();
        let recovery = ndn_cert::RecoverySeed::generate().unwrap();
        let kit = ndn_cert::recovery_anchor(Arc::new(recovery.signer(&ns)))
            .await
            .unwrap();
        let v2 = ndn_cert::add_recovery_anchor(root.as_ref(), &v1, &kit)
            .await
            .unwrap()
            .data;
        let dir = tempfile::tempdir().unwrap();
        let recovered = ndn_cert::recover_namespace_in_pib(
            &FilePib::new(dir.path()).unwrap(),
            &v2,
            &recovery.signer(&ns),
            "phone",
            ndn_cert::OldRoot::Compromised,
            &[],
            &[],
            &ndn_cert::NewRootStore::File,
        )
        .await
        .unwrap();
        let thief = SignedTrustContext::decode_content(v1.content().unwrap(), 1)
            .unwrap()
            .with_ca_endpoint(ns.clone().append("thief").append("CA"))
            .sign_into_data_async(root.as_ref())
            .await
            .unwrap();
        (
            ns,
            vec![
                v1,
                v2,
                recovered.version.bump.data,
                recovered.root_version.data,
            ],
            thief,
        )
    }

    fn store(dir: &std::path::Path, versions: &[Data]) {
        for data in versions {
            let (ctx, _) = ndn_cert::open_signed_context(data).unwrap();
            ndn_cert::persist_context(dir, &ctx, data).unwrap();
        }
    }

    /// A link carrying a later version of a self-certifying namespace not
    /// held inline (an introduction's credentials) is adopted by name, and
    /// that fetch, like any by-name fetch of a link, goes to the forwarders
    /// serving the namespace — not to this device's own publisher, which
    /// serves the older versions this device stored — so the version the
    /// link names is reached, not refused as a downgrade.
    #[tokio::test]
    async fn a_link_with_its_context_inline_that_fetches_bypasses_the_own_publisher() {
        let (ns, line, _) = recovered_line().await;
        let (upstream, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        store(upstream.path(), &line);
        store(device.path(), &line[..2]);
        let (upstream_face, upstream_publisher) =
            crate::publish::prepare(&PibContextStore::new(upstream.path()), FaceId(0xFFFF_0005));
        let (own_face, own_publisher) =
            crate::publish::prepare(&PibContextStore::new(device.path()), FaceId(0xFFFF_0006));
        let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
            .security_profile(ndn_security::SecurityProfile::Disabled)
            .security(Arc::new(SecurityManager::new()))
            .face(upstream_face)
            .face(own_face)
            .build()
            .await
            .unwrap();
        let _upstream = upstream_publisher.spawn(&engine);
        // The upstream is farther than this device's own publisher.
        let prefix = ndn_cert::rdr_prefix(&ns);
        engine.fib().remove_nexthop(&prefix, FaceId(0xFFFF_0005));
        engine.fib().add_nexthop(&prefix, FaceId(0xFFFF_0005), 10);
        let own = own_publisher.spawn(&engine);
        let p = Participant::new(ParticipantParts {
            engine,
            keyring: Arc::new(Keyring::new()),
            store: Arc::new(PibContextStore::new(device.path())),
            publisher: Some(own),
            own_certs: None,
            sync: None,
            cas: Vec::new(),
            words: Default::default(),
        });
        let newest = line.last().unwrap();
        let link = AnchorLink::from_envelope(&TrustEnvelope::Anchor {
            namespace: Some(ns.to_string()),
            fingerprint: None,
            version: Some(4),
            context_data: Some(newest.raw().clone()),
            context_content: None,
        })
        .unwrap();
        let adopted = adopt_link(&p, &link).await;
        let adopted = adopted.unwrap_or_else(|e| panic!("{}", e.reason));
        assert_eq!((adopted.version, adopted.fetched), (4, true));
        assert_eq!(p.keyring().version_of(&ns), Some(4));
        shutdown.shutdown().await;
    }

    /// The daemon's `security/context-adopt` (and so an introduction's
    /// host): the thief's version 1 inline, the owner's recovered line
    /// served upstream. The daemon fetches version 1, refuses the link's as
    /// a fork, and holds and stores nothing of the namespace.
    #[tokio::test]
    async fn a_thiefs_inline_genesis_is_refused_as_a_fork_by_the_daemon() {
        let (ns, line, thief) = recovered_line().await;
        let (upstream, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        store(upstream.path(), &line);
        let (face, publisher) =
            crate::publish::prepare(&PibContextStore::new(upstream.path()), FaceId(0xFFFF_0005));
        let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
            .security_profile(ndn_security::SecurityProfile::Disabled)
            .security(Arc::new(SecurityManager::new()))
            .face(face)
            .build()
            .await
            .unwrap();
        let _upstream = publisher.spawn(&engine);
        let p = Participant::new(ParticipantParts {
            engine,
            keyring: Arc::new(Keyring::new()),
            store: Arc::new(PibContextStore::new(device.path())),
            publisher: None,
            own_certs: None,
            sync: None,
            cas: Vec::new(),
            words: Default::default(),
        });
        let link = AnchorLink::from_envelope(&TrustEnvelope::Anchor {
            namespace: Some(ns.to_string()),
            fingerprint: None,
            version: Some(1),
            context_data: Some(thief.raw().clone()),
            context_content: None,
        })
        .unwrap();
        let refused = adopt_link(&p, &link)
            .await
            .expect_err("the daemon adopted the thief's version 1");
        assert!(refused.reason.contains("fork"), "{}", refused.reason);
        assert!(p.keyring().held(&ns).is_none());
        assert!(
            ndn_cert::read_stored_context(device.path(), &ns)
                .unwrap()
                .is_none()
        );
        shutdown.shutdown().await;
    }
}
