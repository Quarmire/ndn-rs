//! Context-sync subscription (NDF F11): the push alternative to the pull
//! refresh.
//!
//! Subscribes to a trust context's SVS group so a republished
//! [`SignedTrustContext`](ndn_security::SignedTrustContext) propagates to
//! fleet nodes without polling, and adopts each new version into the local
//! [`Keyring`] under the same rule as the pull refresh. This is the
//! *subscribe* half; a publisher puts the signed context Data into the group
//! (see *Wire*).
//!
//! # Layering
//!
//! The orchestrator lives here, in `ndn-identity`, because it composes layers
//! that already meet here: the SVS primitive ([`ndn_sync`]), the update check
//! ([`ndn_cert::open_context_update`]) and [`Keyring`] adoption
//! ([`ndn_security`]). `ndn-sync` stays free of any trust-context dependency
//! (sync is the lower layer).
//!
//! # Wire
//!
//! The synced payload is the context's **signed Data** exactly as the root
//! signed it (`/<ns>/32=trust-context/v=<N>`, the wire of
//! [`sign_into_data`](ndn_security::SignedTrustContext::sign_into_data) or of
//! a stored context), carried as the Content of the group Data at
//! `<group>/<publisher>/seg=N`. The SVS sequence number is the version the
//! publisher republishes at; whether the update is adopted is decided by the
//! signed version inside. Anchors, schema blobs, CA endpoints, enrollment
//! hint, revocations and source-bundle hash arrive intact because the signed
//! Content is carried verbatim.
//!
//! # Adoption rule
//!
//! An update is adopted only under the **continuity rule** of the pull
//! refresh ([`ndn_cert::open_context_update`], then
//! [`Keyring::adopt_update`]): it is a self-consistent signed context of a
//! namespace this node already holds, it is signed by a key that is an anchor
//! of the **held** version, and it is strictly newer. Who published it into
//! the group, and whether the group Data itself was validated, does not
//! matter: a group member that is not the namespace root cannot produce an
//! update this node adopts. A namespace this node does not hold yet is never
//! adopted from the group — first adoption needs a link or invite
//! (`ndn-fwd adopt` / `ndn-fwd enroll`).
//!
//! # Transport seam
//!
//! `ndn-sync` is sans-IO (the caller wires the SVS Interest channels to a
//! face), and fetching the group Data is likewise abstracted behind
//! [`ContextFetcher`] so this module needs no face/engine of its own and is unit
//! testable.
//!
//! # Relation to the pull refresh
//!
//! The `ndn-fwd` daemon does **not** use this module: it keeps held contexts
//! current by pulling ([`ndn_cert::refresh_context`] via
//! [`crate::refresh_context_via_engine`]) — the newest version's name over
//! RDR metadata, then the signed context Data itself — and stores and
//! republishes each adopted version so updates travel hop by hop through
//! relays that hold the context. That path needs no sync group and no
//! per-namespace setup. This module is for fleets that already run an SVS
//! group per context and want updates without waiting for a poll; both apply
//! the same check, so neither can adopt what the other would refuse.

use std::sync::Arc;

use bytes::Bytes;
use ndn_cert::{UpdateRefusal, open_context_update};
use ndn_packet::{Data, Name};
use ndn_security::{Keyring, context_namespace_of};
use ndn_sync::{SyncHandle, SyncUpdate};
use tokio_util::sync::CancellationToken;

/// Fetches the Content bytes of the Data published at a name. The caller backs
/// this with its consumer/face; an in-process engine, an `ndn-app` `Consumer`,
/// or a test stub all satisfy it. For a context-sync group the Content is the
/// signed context Data wire.
#[async_trait::async_trait]
pub trait ContextFetcher: Send + Sync {
    async fn fetch_content(&self, name: Name) -> Option<Bytes>;
}

/// What happened when a sync update was processed.
#[derive(Debug)]
pub enum ContextSyncOutcome {
    /// A newer version, signed by an anchor of the held one, was adopted.
    Adopted {
        previous: u64,
        version: u64,
        /// Revocation entries this version adds.
        revoked: Vec<Name>,
    },
    /// The update is for a namespace this node holds no context for; nothing
    /// to continue from, so nothing was adopted.
    NotHeld { namespace: Name },
    /// The update failed the continuity check or is not newer than the held
    /// version ([`UpdateRefusal::NotNewer`] is the ordinary stale-update
    /// case). The held version stays in force.
    Refused(UpdateRefusal),
    /// The group Data could not be fetched.
    FetchFailed,
    /// The fetched Content is not a Data named
    /// `/<ns>/32=trust-context/v=<N>`.
    DecodeFailed,
}

/// Fetch, check, and adopt the context advertised by one [`SyncUpdate`].
/// Only the highest sequence is fetched — a trust context fully supersedes its
/// predecessor, so older versions in the gap need not be retrieved. The
/// fetched signed context is adopted only if it passes
/// [`open_context_update`] against the held version of its namespace and
/// [`Keyring::adopt_update`] (strictly newer, atomic); see the module docs.
pub async fn process_update(
    update: &SyncUpdate,
    fetcher: &dyn ContextFetcher,
    keyring: &Keyring,
) -> ContextSyncOutcome {
    let fetch_name = update.name.clone().append_segment(update.high_seq);
    let Some(content) = fetcher.fetch_content(fetch_name).await else {
        return ContextSyncOutcome::FetchFailed;
    };
    let Ok(data) = Data::decode(content) else {
        return ContextSyncOutcome::DecodeFailed;
    };
    let Some(namespace) = context_namespace_of(&data.name) else {
        return ContextSyncOutcome::DecodeFailed;
    };
    let Some(held) = keyring
        .contexts()
        .into_iter()
        .find(|c| *c.namespace() == namespace)
    else {
        return ContextSyncOutcome::NotHeld { namespace };
    };

    let ctx = match open_context_update(&held, &data).await {
        Ok((ctx, _signer)) => Arc::new(ctx),
        Err(refusal) => return ContextSyncOutcome::Refused(refusal),
    };
    match keyring.adopt_update(Arc::clone(&ctx)) {
        Ok(()) => ContextSyncOutcome::Adopted {
            previous: held.version(),
            version: ctx.version(),
            revoked: ctx
                .revocations()
                .iter()
                .filter(|r| !held.revocations().contains(r))
                .cloned()
                .collect(),
        },
        // A concurrent adoption got there first.
        Err(Some(now_held)) => ContextSyncOutcome::Refused(UpdateRefusal::NotNewer {
            offered: ctx.version(),
            held: now_held,
        }),
        Err(None) => ContextSyncOutcome::NotHeld { namespace },
    }
}

/// Run the subscription loop until `cancel` fires or the sync group closes:
/// each peer update is fetched and adopted via [`process_update`]. The caller
/// has already [`join`](ndn_sync::join_svs_group)ed the group for the context
/// and spawns this on its runtime. An adopted version is only held in memory:
/// persisting it is the caller's (keep the signed Data it fetched).
pub async fn run(
    mut handle: SyncHandle,
    fetcher: Arc<dyn ContextFetcher>,
    keyring: Arc<Keyring>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            update = handle.recv() => {
                let Some(update) = update else { break };
                let outcome = process_update(&update, fetcher.as_ref(), &keyring).await;
                match &outcome {
                    ContextSyncOutcome::Adopted { previous, version, revoked } => tracing::info!(
                        target: "ndn::trust", %previous, %version, ?revoked,
                        publisher = %update.publisher,
                        "context-sync adopted a newer trust context"
                    ),
                    ContextSyncOutcome::Refused(UpdateRefusal::NotNewer { offered, held }) => {
                        tracing::debug!(
                            target: "ndn::trust", %offered, %held,
                            "context-sync update not newer than the held version"
                        )
                    }
                    ContextSyncOutcome::Refused(refusal) => tracing::warn!(
                        target: "ndn::trust", %refusal, publisher = %update.publisher,
                        "context-sync refused a trust-context update; the held version stays"
                    ),
                    other => tracing::warn!(
                        target: "ndn::trust", ?other, publisher = %update.publisher,
                        "context-sync could not adopt an update"
                    ),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashmap::DashMap;

    use ndn_cert::{NamespaceInit, anchor_fingerprint, init_namespace};
    use ndn_security::{SecurityManager, SignedTrustContext};

    const GROUP: &str = "/home/bob/_sync/v1/devices/device-a";

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    /// Maps a fetch name → group Data Content (a signed context Data wire).
    struct MapFetcher(DashMap<String, Bytes>);

    impl MapFetcher {
        fn new() -> Self {
            Self(DashMap::new())
        }
        /// Publish `context` (signed Data) into the group at `seq`.
        fn publish(&self, seq: u64, context: &Data) {
            self.publish_raw(seq, context.raw().clone());
        }
        fn publish_raw(&self, seq: u64, content: Bytes) {
            self.0
                .insert(n(GROUP).append_segment(seq).to_string(), content);
        }
    }

    #[async_trait::async_trait]
    impl ContextFetcher for MapFetcher {
        async fn fetch_content(&self, name: Name) -> Option<Bytes> {
            self.0.get(&name.to_string()).map(|c| c.value().clone())
        }
    }

    fn update_at(seq: u64) -> SyncUpdate {
        SyncUpdate {
            publisher: "device-a".into(),
            name: n(GROUP),
            low_seq: seq,
            high_seq: seq,
            mapping: None,
            serving_party: None,
        }
    }

    /// A root device for `/home/bob`: its signing key lives in the manager.
    struct Root {
        mgr: SecurityManager,
        init: NamespaceInit,
    }

    impl Root {
        fn new() -> Self {
            let mgr = SecurityManager::new();
            let init = init_namespace(&mgr, &n("/home/bob")).unwrap();
            Self { mgr, init }
        }

        /// Version `version` of the context with `revoked` added, signed by
        /// this root's key.
        fn version(&self, version: u64, revoked: &[&str]) -> Data {
            let content = self.init.context.encode_content();
            let mut ctx = SignedTrustContext::decode_content(&content, version).unwrap();
            for r in revoked {
                ctx = ctx.with_revocation(n(r));
            }
            let signer = self.mgr.get_signer_sync(&self.init.anchor_key).unwrap();
            ctx.sign_into_data(signer.as_ref()).unwrap()
        }
    }

    /// A node holding `root`'s v1, adopted from its link.
    fn node_holding(root: &Root) -> Keyring {
        let keyring = Keyring::new();
        ndn_cert::adopt_with_tofu(
            &keyring,
            &root.init.context_data,
            &n("/home/bob"),
            &anchor_fingerprint(&root.init.anchor),
        )
        .unwrap();
        keyring
    }

    fn held_version(keyring: &Keyring) -> u64 {
        keyring.version_of(&n("/home/bob")).unwrap()
    }

    #[tokio::test]
    async fn an_update_signed_by_the_held_root_is_adopted_intact() {
        let root = Root::new();
        let keyring = node_holding(&root);
        let fetcher = MapFetcher::new();
        let revoked = "/home/bob/member/phone/KEY/k1";
        fetcher.publish(2, &root.version(2, &[revoked]));

        match process_update(&update_at(2), &fetcher, &keyring).await {
            ContextSyncOutcome::Adopted {
                previous: 1,
                version: 2,
                revoked: added,
            } => assert_eq!(added, vec![n(revoked)]),
            other => panic!("update from the held root not adopted: {other:?}"),
        }
        let held = keyring.context_for(&n("/home/bob"));
        assert_eq!(held.version(), 2);
        assert!(held.is_revoked(&n(revoked)));
        // Everything else is carried over verbatim.
        assert_eq!(held.ca_endpoints(), root.init.context.ca_endpoints());
        let bodies = |c: &SignedTrustContext| {
            c.published_schemas()
                .into_iter()
                .map(|s| s.body)
                .collect::<Vec<_>>()
        };
        assert_eq!(bodies(&held), bodies(&root.init.context));
    }

    #[tokio::test]
    async fn an_update_not_signed_by_a_held_anchor_is_never_adopted() {
        let root = Root::new();
        let keyring = node_holding(&root);
        // Another root claiming the same namespace (its key is also named
        // /home/bob/KEY/root) publishes a higher version into the group.
        let forged = Root::new();
        let fetcher = MapFetcher::new();
        fetcher.publish(9, &forged.version(9, &["/home/bob/admin/desk/KEY/device"]));

        match process_update(&update_at(9), &fetcher, &keyring).await {
            ContextSyncOutcome::Refused(UpdateRefusal::NotSignedByHeldAnchor {
                held: 1, ..
            }) => {}
            other => panic!("forged update not refused: {other:?}"),
        }
        assert_eq!(held_version(&keyring), 1, "the held version stays");

        // Bare Content (the old wire) is unauthenticated and never adopted.
        fetcher.publish_raw(10, root.init.context.encode_content());
        assert!(matches!(
            process_update(&update_at(10), &fetcher, &keyring).await,
            ContextSyncOutcome::DecodeFailed
        ));
        // Neither is a genuine context whose signature no longer verifies.
        let genuine = root.version(11, &[]);
        let mut wire = genuine.raw().to_vec();
        let last = wire.len() - 1;
        wire[last] ^= 0xff;
        fetcher.publish_raw(11, Bytes::from(wire));
        assert!(matches!(
            process_update(&update_at(11), &fetcher, &keyring).await,
            ContextSyncOutcome::Refused(UpdateRefusal::Unauthentic(_))
        ));
        assert_eq!(held_version(&keyring), 1, "the held version stays");
    }

    #[tokio::test]
    async fn a_lower_or_equal_version_never_replaces_the_held_one() {
        let root = Root::new();
        let keyring = node_holding(&root);
        let fetcher = MapFetcher::new();
        fetcher.publish(5, &root.version(5, &[]));
        assert!(matches!(
            process_update(&update_at(5), &fetcher, &keyring).await,
            ContextSyncOutcome::Adopted { version: 5, .. }
        ));
        // A different v5 and an older v3, both genuinely signed.
        fetcher.publish(6, &root.version(5, &["/home/bob/member/x/KEY/k"]));
        fetcher.publish(3, &root.version(3, &[]));
        for seq in [6, 3] {
            assert!(matches!(
                process_update(&update_at(seq), &fetcher, &keyring).await,
                ContextSyncOutcome::Refused(UpdateRefusal::NotNewer { held: 5, .. })
            ));
        }
        let held = keyring.context_for(&n("/home/bob"));
        assert_eq!(held.version(), 5);
        assert!(!held.is_revoked(&n("/home/bob/member/x/KEY/k")));
    }

    #[tokio::test]
    async fn a_namespace_not_held_is_never_adopted_from_the_group() {
        let root = Root::new();
        let keyring = Keyring::new();
        let fetcher = MapFetcher::new();
        fetcher.publish(2, &root.version(2, &[]));
        assert!(matches!(
            process_update(&update_at(2), &fetcher, &keyring).await,
            ContextSyncOutcome::NotHeld { .. }
        ));
        assert!(keyring.is_empty());
    }

    #[tokio::test]
    async fn fetch_and_decode_failures_are_reported() {
        let keyring = Keyring::new();
        let fetcher = MapFetcher::new();
        assert!(matches!(
            process_update(&update_at(1), &fetcher, &keyring).await,
            ContextSyncOutcome::FetchFailed
        ));
        fetcher.publish_raw(1, Bytes::from_static(b"not a trust context"));
        assert!(matches!(
            process_update(&update_at(1), &fetcher, &keyring).await,
            ContextSyncOutcome::DecodeFailed
        ));
    }
}
