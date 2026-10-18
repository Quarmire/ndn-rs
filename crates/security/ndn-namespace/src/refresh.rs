//! Keeping held trust contexts current: a check on request
//! ([`refresh_contexts`]) and periodically ([`spawn_periodic`]).
//!
//! For each held context the device asks its upstream for the newest
//! version ([`ndn_identity::refresh_context_via_engine`]: RDR metadata, then
//! the signed context Data) and adopts it only if it is newer and signed by
//! an anchor of the version it holds (continuity), then keeps it
//! ([`crate::keep::keep_update`]: stored and published) — so the next
//! device downstream fetches it from this one: updates travel hop by hop
//! through relays that hold the context. When the newest is not signed by
//! an anchor of the held version (a recovery kit installed a new root in a
//! version this device missed), the versions in between are fetched by
//! exact name and followed one by one ([`ndn_cert::follow_versions`]); they
//! are kept too, so the devices behind this one follow the same way. During
//! the fetch the route from the namespace's trust-context prefix to this
//! device's own publisher is withdrawn
//! ([`crate::publish::PublishedContexts::bypass`]) and the metadata this
//! device cached is dropped ([`crate::publish::forget_cached_metadata`]),
//! so the Interests go upstream instead of being answered with the versions
//! held.
//!
//! A device holding the namespace root key (the root device) is where new
//! versions are made, so it does not fetch its own namespace
//! ([`ContextStore::holds_root_key`](crate::ContextStore::holds_root_key)).
//! A failed or refused refresh is logged with its reason and changes
//! nothing: the held version stays in force, and a missed refresh only
//! delays an update.
//!
//! An answer naming a version older than one this device verified over its
//! namespace's sync group ([`crate::sync::ContextSync::verified`]) is
//! reported as [`RefreshState::Behind`], not current.

use std::sync::Arc;
use std::time::Duration;

use ndn_cert::ContextRefresh;
use ndn_cert::report::{ContextRefreshInfo, RefreshState, TrustRefusal};
use ndn_engine::ForwarderEngine;
use ndn_mgmt_wire::control_response::status;
use ndn_packet::Name;
use ndn_security::SignedTrustContext;
use tokio_util::sync::CancellationToken;

use crate::keep::{Adopted, keep_update, publication};
use crate::{Participant, refusal};

/// The latest the first periodic check runs after start (or after one
/// period, if shorter) when the routes of the held namespaces never get a
/// face (a namespace reached over routes installed later, or none), so a
/// device that was off catches up without waiting a period.
const FIRST_CHECK_LATEST: Duration = Duration::from_secs(30);

/// How often [`faces_up`] looks at the FIB and the face table.
const FACE_POLL: Duration = Duration::from_millis(50);

/// The namespaces this device fetches: those it holds whose root key it
/// does not hold.
pub fn fetched_namespaces(p: &Participant) -> Vec<Name> {
    p.keyring()
        .contexts()
        .into_iter()
        .filter(|ctx| !p.store().holds_root_key(ctx))
        .map(|ctx| ctx.namespace().clone())
        .collect()
}

/// Wait until the route of every namespace in `namespaces` has a nexthop
/// whose face is up, or `within` passed. At start the FIB may hold routes
/// before the faces they point at are open, and an Interest forwarded to a
/// face not yet up is dropped: a check, or a Sync Interest, sent then would
/// be lost until the next period.
pub async fn faces_up(engine: &ForwarderEngine, namespaces: &[Name], within: Duration) {
    let deadline = tokio::time::Instant::now() + within;
    let has_face = |ns: &Name| {
        engine.fib().lpm(ns).is_some_and(|entry| {
            entry.nexthops.iter().any(|hop| engine.faces().get(hop.face_id).is_some())
        })
    };
    while !namespaces.iter().all(has_face) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(FACE_POLL).await;
    }
}

/// Check the held context of `namespace` (every held one when `None`) for a
/// newer version.
pub async fn refresh_contexts(
    p: &Participant,
    namespace: Option<Name>,
) -> Result<Vec<ContextRefreshInfo>, TrustRefusal> {
    let held = p.keyring().contexts();
    let targets = match namespace {
        Some(ns) => vec![held
            .into_iter()
            .find(|c| *c.namespace() == ns)
            .ok_or_else(|| refusal(status::NOT_FOUND, p.words().no_context(&ns)))?],
        None => held,
    };
    // No lock across the fetches (a catch-up walk may take many round
    // trips): `ndn_cert::refresh_context` adopts only if the version it
    // checked against is still held (`Keyring::adopt_update_from`), so a
    // version a revocation or hand-over adopts meanwhile is never skipped.
    let mut results = Vec::with_capacity(targets.len());
    for ctx in targets {
        results.push(refresh_one(p, &ctx).await);
    }
    Ok(results)
}

/// [`refresh_contexts`] of one held context: what became of it, and the
/// version kept when a newer one was adopted.
async fn refresh_one(p: &Participant, held: &SignedTrustContext) -> ContextRefreshInfo {
    let namespace = held.namespace().clone();
    let held_version = p.keyring().version_of(&namespace).unwrap_or(held.version());
    let info = |state, version, revoked: Vec<String>, detail: String| ContextRefreshInfo {
        namespace: namespace.to_string(),
        state,
        held_version,
        version,
        revoked,
        detail,
    };
    if p.store().holds_root_key(held) {
        return info(
            RefreshState::Source,
            held_version,
            Vec::new(),
            "this node holds the namespace root key: new versions are made here".into(),
        );
    }

    let bypass = p.publisher().map(|publisher| publisher.bypass(&namespace));
    // The question is "what is newest now": not a pointer this device cached.
    crate::publish::forget_cached_metadata(p.engine(), &namespace);
    let result =
        ndn_identity::refresh_context_via_engine(p.engine(), p.keyring(), &namespace).await;
    drop(bypass);

    // A version this device knows exists (a member of its sync group served
    // its signed Data and it passed the continuity rule, see `crate::sync`)
    // and does not hold: an answer naming an older one is stale, not
    // current. A sequence number announced in the group proves nothing and
    // never counts.
    let known_newer = |answered: u64| {
        let held = p.keyring().version_of(&namespace).unwrap_or(held_version);
        p.sync()
            .and_then(|s| s.verified(&namespace))
            .filter(|(verified, _)| *verified > held && *verified > answered)
    };
    let behind = |answered: u64, (verified, by): (u64, Name)| {
        tracing::info!(
            target: "security",
            namespace = %namespace,
            answered,
            verified,
            by = %by,
            "the refresh got an answer older than a version verified over sync"
        );
        info(
            RefreshState::Behind,
            held_version,
            Vec::new(),
            format!(
                "the answer names v{answered}, but v{verified} exists (its signed Data, served \
                 over the namespace's sync group by {by}, follows from the held version under \
                 the continuity rule) and is not held: a cache may answer with the previous \
                 metadata for up to {} s after a new version, or the upstream has not \
                 refreshed yet; nothing changed — refresh again",
                crate::publish::METADATA_FRESHNESS.as_secs()
            ),
        )
    };
    match result {
        Ok(ContextRefresh::Current { version }) => {
            if let Some(known) = known_newer(version) {
                return behind(version, known);
            }
            tracing::debug!(target: "security", namespace = %namespace, version, "trust context is current");
            info(
                RefreshState::Current,
                version,
                Vec::new(),
                format!("the namespace serves v{version}, the version held"),
            )
        }
        Ok(ContextRefresh::UpstreamOlder { held, offered }) => {
            if let Some(known) = known_newer(offered) {
                return behind(offered, known);
            }
            tracing::info!(
                target: "security",
                namespace = %namespace,
                held,
                offered,
                "upstream serves an older trust context; keeping the held one"
            );
            info(
                RefreshState::UpstreamOlder,
                held,
                Vec::new(),
                format!(
                    "the answer names v{offered}, older than the held v{held}: the forwarder \
                     that answered has not refreshed yet, or a cache answered with the metadata \
                     of an earlier version (it may for up to {} s after a new one); nothing \
                     changed",
                    crate::publish::METADATA_FRESHNESS.as_secs()
                ),
            )
        }
        Ok(ContextRefresh::Updated(update)) => {
            let version = update.context.version();
            let revoked: Vec<String> = update.revoked.iter().map(Name::to_string).collect();
            let kept = keep_update(p, &update, Adopted::ByRefresh);
            let walked: Vec<u64> = update.walked.iter().map(|s| s.context.version()).collect();
            let through = match walked.as_slice() {
                [] => String::new(),
                walked => format!(
                    " through {} (each signed by an anchor of the version before it)",
                    walked
                        .iter()
                        .map(|v| format!("v{v}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            };
            let from = walked.last().copied().unwrap_or(update.previous);
            let detail = match &kept {
                Ok(k) => match &k.stored {
                    Ok(stored) => format!(
                        "adopted v{version} (signed by {}, an anchor of v{from}){through}; stored \
                         {stored}{}{}",
                        update.signer.name,
                        publication(p),
                        k.ca_detail()
                    ),
                    Err(e) => format!(
                        "adopted v{version}{through} for this run, but {}{}",
                        e.reason,
                        k.ca_detail()
                    ),
                },
                Err(e) => format!("adopted v{version}{through} for this run, but {}", e.reason),
            };
            info(RefreshState::Updated, version, revoked, detail)
        }
        Err(e) => {
            tracing::warn!(
                target: "security",
                namespace = %namespace,
                error = %e,
                "trust-context refresh failed"
            );
            let state = match e {
                ndn_cert::RefreshError::NoAnswer { .. } => RefreshState::Unreachable,
                _ => RefreshState::Failed,
            };
            info(state, held_version, Vec::new(), e.to_string())
        }
    }
}

/// Check every held context every `period` until `cancel`. The first check
/// runs as soon as the routes of the namespaces this device fetches have
/// their faces ([`faces_up`]), so a device that starts, or comes back after
/// being off, catches up at once rather than a period later.
pub fn spawn_periodic(p: Arc<Participant>, period: Duration, cancel: CancellationToken) {
    tokio::spawn(async move {
        let fetched = fetched_namespaces(&p);
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = faces_up(p.engine(), &fetched, period.min(FIRST_CHECK_LATEST)) => {}
        }
        loop {
            // Each namespace's outcome is logged by `refresh_one`.
            if !p.keyring().is_empty()
                && let Err(e) = refresh_contexts(&p, None).await
            {
                tracing::warn!(target: "security", error = %e.reason, "trust-context refresh failed");
            }
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tokio::time::sleep(period) => {}
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use ndn_cert::RootStore;
    use ndn_security::FilePib;

    use super::*;
    use crate::ParticipantParts;

    /// A node offline across a recovery catches up through the daemon's
    /// refresh: it holds v2; an upstream node that kept every version serves
    /// v3 (signed by the recovery key) and v4 (the new root's, newest). v4
    /// alone does not follow from v2, so the daemon follows v3 then v4 by
    /// exact name, adopts v4, and keeps both, so the nodes behind it can
    /// follow the same way.
    #[tokio::test]
    async fn a_refresh_follows_a_recovery_and_keeps_every_version_it_walked() {
        use ndn_engine::{EngineBuilder, EngineConfig};
        use ndn_security::{Keyring, SecurityManager};

        let dirs: Vec<_> = (0..4).map(|_| tempfile::tempdir().unwrap()).collect();
        let (root_dev, replacement, upstream, device) =
            (dirs[0].path(), dirs[1].path(), dirs[2].path(), dirs[3].path());
        let ns: Name = "/home/bob".parse().unwrap();

        let pib = FilePib::new(root_dev).unwrap();
        let init =
            ndn_cert::init_namespace_in_pib(&pib, &ns, "desk", false, &ndn_cert::NewRootStore::File)
                .await
                .unwrap();
        let root = RootStore::open(&pib).unwrap().unwrap().signer(None).await.unwrap();
        let seed = ndn_cert::RecoverySeed::generate().unwrap();
        let kit = ndn_cert::recovery_anchor(Arc::new(seed.signer(&ns))).await.unwrap();
        let v2 = ndn_cert::add_recovery_anchor(root.as_ref(), &init.init.context_data, &kit)
            .await
            .unwrap();
        let recovered = ndn_cert::recover_namespace_in_pib(
            &FilePib::new(replacement).unwrap(),
            &v2.data,
            &seed.signer(&ns),
            "phone",
            ndn_cert::OldRoot::Destroyed,
            &[],
            &ndn_cert::NewRootStore::File,
        )
        .await
        .unwrap();
        for bump in [&v2, &recovered.version.bump, &recovered.root_version] {
            ndn_cert::persist_context(upstream, &bump.context, &bump.data).unwrap();
        }

        let (face, publisher) = crate::publish::prepare(
            &crate::PibContextStore::new(upstream),
            ndn_transport::FaceId(0xFFFF_0005),
        );
        let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
            .security_profile(ndn_security::SecurityProfile::Disabled)
            .security(Arc::new(SecurityManager::new()))
            .face(face)
            .build()
            .await
            .unwrap();
        let _serving = publisher.spawn(&engine);
        let keyring = Arc::new(Keyring::new());
        assert!(keyring.adopt(Arc::new(ndn_cert::open_signed_context(&v2.data).unwrap().0)));
        let admin = Participant::new(ParticipantParts {
            engine,
            keyring,
            store: Arc::new(crate::PibContextStore::new(device)),
            publisher: None,
            own_certs: None,
            sync: None,
            ca: None,
            words: Default::default(),
        });

        let results = refresh_contexts(&admin, Some(ns.clone())).await.unwrap();
        assert_eq!(results[0].state, RefreshState::Updated, "{}", results[0].detail);
        assert_eq!((results[0].held_version, results[0].version), (2, 4));
        assert_eq!(admin.keyring().version_of(&ns), Some(4));
        let (newest, _) = ndn_cert::read_stored_context(device, &ns).unwrap().unwrap();
        assert_eq!(newest.version(), 4);
        let kept: Vec<u64> = ndn_cert::read_stored_versions(device, &ns)
            .unwrap()
            .into_iter()
            .map(|(_, stored)| stored.unwrap().0.version())
            .collect();
        assert_eq!(kept, [3, 4]);
        shutdown.shutdown().await;
    }

    /// A node that reaches nobody serving its namespace (the recovering
    /// device after the root device is gone) reports `unreachable`, not a
    /// refusal, keeping the held version: `ndn-fwd recover --from-held` may
    /// go on from there, never from a version that answered and was refused.
    #[tokio::test]
    async fn a_refresh_nobody_answers_is_unreachable_not_refused() {
        use ndn_engine::{EngineBuilder, EngineConfig};
        use ndn_security::{Keyring, SecurityManager};

        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let ns: Name = "/home/bob".parse().unwrap();
        let init = ndn_cert::init_namespace_in_pib(
            &FilePib::new(root_dev.path()).unwrap(),
            &ns,
            "desk",
            false,
            &ndn_cert::NewRootStore::File,
        )
        .await
        .unwrap();
        let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
            .security_profile(ndn_security::SecurityProfile::Disabled)
            .security(Arc::new(SecurityManager::new()))
            .build()
            .await
            .unwrap();
        let keyring = Arc::new(Keyring::new());
        let held = ndn_cert::open_signed_context(&init.init.context_data).unwrap().0;
        assert!(keyring.adopt(Arc::new(held)));
        let admin = Participant::new(ParticipantParts {
            engine,
            keyring,
            store: Arc::new(crate::PibContextStore::new(device.path())),
            publisher: None,
            own_certs: None,
            sync: None,
            ca: None,
            words: Default::default(),
        });

        let results = refresh_contexts(&admin, Some(ns.clone())).await.unwrap();
        assert_eq!(results[0].state, RefreshState::Unreachable, "{}", results[0].detail);
        assert_eq!((results[0].held_version, results[0].version), (1, 1));
        assert_eq!(admin.keyring().version_of(&ns), Some(1));
        shutdown.shutdown().await;
    }

    /// A node that starts checks its held contexts as soon as the route of
    /// each namespace it fetches has its face, not a period (here an hour)
    /// or 30 s later, and not before: at start `[[route]]` entries are in
    /// the FIB before face setup has opened the faces they name.
    #[tokio::test]
    async fn the_first_periodic_check_runs_once_the_namespace_route_has_its_face() {
        use ndn_engine::{EngineBuilder, EngineConfig};
        use ndn_face::local::InProcFace;
        use ndn_security::{Keyring, SecurityManager};

        let dirs: Vec<_> = (0..3).map(|_| tempfile::tempdir().unwrap()).collect();
        let (root_dev, upstream, device) = (dirs[0].path(), dirs[1].path(), dirs[2].path());
        let ns: Name = "/home/bob".parse().unwrap();
        let pib = FilePib::new(root_dev).unwrap();
        let init =
            ndn_cert::init_namespace_in_pib(&pib, &ns, "desk", false, &ndn_cert::NewRootStore::File)
                .await
                .unwrap();
        let root = RootStore::open(&pib).unwrap().unwrap().signer(None).await.unwrap();
        let seed = ndn_cert::RecoverySeed::generate().unwrap();
        let kit = ndn_cert::recovery_anchor(Arc::new(seed.signer(&ns))).await.unwrap();
        let v2 = ndn_cert::add_recovery_anchor(root.as_ref(), &init.init.context_data, &kit)
            .await
            .unwrap();
        ndn_cert::persist_context(upstream, &v2.context, &v2.data).unwrap();

        let (face, publisher) = crate::publish::prepare(
            &crate::PibContextStore::new(upstream),
            ndn_transport::FaceId(0xFFFF_0005),
        );
        let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
            .security_profile(ndn_security::SecurityProfile::Disabled)
            .security(Arc::new(SecurityManager::new()))
            .face(face)
            .build()
            .await
            .unwrap();
        let _serving = publisher.spawn(&engine);
        // The namespace's route names a face that is not up yet.
        let late = engine.faces().alloc_id();
        engine.fib().add_nexthop(&ns, late, 10);
        let keyring = Arc::new(Keyring::new());
        let held = ndn_cert::open_signed_context(&init.init.context_data).unwrap().0;
        assert!(keyring.adopt(Arc::new(held)));
        let admin = Arc::new(Participant::new(ParticipantParts {
            engine: engine.clone(),
            keyring,
            store: Arc::new(crate::PibContextStore::new(device)),
            publisher: None,
            own_certs: None,
            sync: None,
            ca: None,
            words: Default::default(),
        }));
        let cancel = CancellationToken::new();
        spawn_periodic(Arc::clone(&admin), Duration::from_secs(3600), cancel.clone());

        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(admin.keyring().version_of(&ns), Some(1), "checked before the face was up");
        let (face, _handle) = InProcFace::new(late, 16);
        engine.add_face(face, cancel.child_token());
        let adopted = tokio::time::timeout(Duration::from_secs(3), async {
            while admin.keyring().version_of(&ns) != Some(2) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(adopted.is_ok(), "no check once the face was up");
        cancel.cancel();
        shutdown.shutdown().await;
    }
}
