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
//! A namespace's group is [`group_prefix`]: `/<ns>/32=trust-context/32=sync`,
//! beside the RDR publication of its versions. A member's SVS node name is
//! `<group>/<member>`, so the Data it publishes, `<group>/<member>/seg=N`,
//! is routed like the group itself.
//!
//! The synced payload is the context's **signed Data** exactly as the root
//! signed it (`/<ns>/32=trust-context/v=<N>`, the wire of
//! [`sign_into_data`](ndn_security::SignedTrustContext::sign_into_data) or of
//! a stored context), carried as the Content of the group Data at
//! `<group>/<publisher>/seg=N` ([`group_data`]). The SVS sequence number is
//! the version the publisher republishes at; whether the update is adopted is
//! decided by the signed version inside. Anchors, schema blobs, CA endpoints,
//! enrollment hint, revocations and source-bundle hash arrive intact because
//! the signed Content is carried verbatim. The group Data itself is signed
//! with DigestSha256 (integrity only), like the RDR metadata: what it carries
//! is checked by its own signature, and a validating forwarder admits a
//! DigestSha256 Data without a schema rule for its name, where a key-signed
//! one would be dropped one hop away.
//!
//! # Adoption rule
//!
//! An update is adopted only under the **continuity rule** of the pull
//! refresh ([`ndn_cert::open_context_update`], then
//! [`Keyring::adopt_update_from`]): it is a self-consistent signed context of a
//! namespace this node already holds, it is signed by a key that is an anchor
//! of the **held** version, and it is strictly newer. Who published it into
//! the group, and whether the group Data itself was validated, does not
//! matter: a group member that is not the namespace root cannot produce an
//! update this node adopts. A namespace this node does not hold yet is never
//! adopted from the group — first adoption needs a link or invite
//! (`ndn-fwd adopt` / `ndn-fwd enroll`).
//!
//! When the newest version is not signed by an anchor of the held one — a
//! recovery kit installed a new root in a version this node missed — the
//! publisher's earlier sequence numbers (each the version it republished)
//! are fetched oldest first and followed one by one, each under the
//! continuity rule from the one before ([`ndn_cert::follow_versions`], the
//! same walk as the pull refresh); the newest is adopted only if the walk
//! reaches it.
//!
//! # Keeping what was adopted
//!
//! An adopted version is held in the keyring only; [`ContextSyncOutcome::Adopted`]
//! carries its signed Data and the versions walked through (an
//! [`ndn_cert::ContextUpdate`], as a pull refresh returns), and [`run`] hands
//! each to the caller's `keep`, which persists and serves them — so this node
//! comes back with the version it adopted, and the nodes behind it can follow
//! the same versions by name.
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
//! The pull refresh ([`ndn_cert::refresh_context`] via
//! [`crate::refresh_context_via_engine`]) fetches the newest version's name
//! over RDR metadata, then the signed context Data itself, and every holder
//! stores and republishes each adopted version so updates travel hop by hop
//! through relays that hold the context. It needs no sync group and no
//! per-namespace setup; its latency is the refresh period. This module adds
//! the push: a version the root puts into the group reaches the members at
//! once. Both apply the same check, so neither can adopt what the other
//! would refuse. The `ndn-fwd` daemon runs both when `[security]
//! context_sync = true` (the refresh alone by default).

use std::sync::Arc;

use bytes::Bytes;
use ndn_cert::{
    ContextStep, ContextUpdate, UpdateRefusal, Unfetched, VersionSource, follow_versions,
    open_context_update,
};
use ndn_packet::{Data, Name, NameComponent};
use ndn_security::{Keyring, SignedTrustContext, context_namespace_of};
use ndn_sync::{SyncHandle, SyncUpdate};
use tokio_util::sync::CancellationToken;

/// The name of `namespace`'s context-sync group:
/// `/<ns>/32=trust-context/32=sync`.
pub fn group_prefix(namespace: &Name) -> Name {
    ndn_cert::rdr_prefix(namespace).append_component(NameComponent::keyword(Bytes::from_static(
        b"sync",
    )))
}

/// The group Data a member named `publisher` (`<group>/<member>`) publishes
/// for the signed context Data `context`: named
/// `<publisher>/seg=<version>`, Content = `context`'s wire verbatim, signed
/// with DigestSha256. `None` when `context` is not named
/// `/<ns>/32=trust-context/v=<N>`.
pub fn group_data(publisher: &Name, context: &Data) -> Option<Bytes> {
    context_namespace_of(&context.name)?;
    let version = context.name.components().last()?.as_version()?;
    Some(
        ndn_packet::encode::DataBuilder::new(publisher.clone().append_segment(version), context.raw())
            .build(),
    )
}

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
    /// A newer version, signed by an anchor of the held one (directly or
    /// through the versions walked), was adopted into the keyring. Keep
    /// (persist and serve) its `data` and every step of its `walked`.
    Adopted(ContextUpdate),
    /// The update is for a namespace this node holds no context for; nothing
    /// to continue from, so nothing was adopted.
    NotHeld { namespace: Name },
    /// The update failed the continuity check or is not newer than the held
    /// version ([`UpdateRefusal::NotNewer`] is the ordinary stale-update
    /// case). The held version stays in force.
    Refused(UpdateRefusal),
    /// Another adoption replaced the held version `held` (by `now`, older
    /// than this update) while this update was checked against it, so
    /// nothing was adopted; the next update is checked against the version
    /// held then.
    ChangedMeanwhile { held: u64, now: u64 },
    /// The group Data could not be fetched.
    FetchFailed,
    /// The fetched Content is not a Data named
    /// `/<ns>/32=trust-context/v=<N>`.
    DecodeFailed,
}

/// Fetch, check, and adopt the context advertised by one [`SyncUpdate`].
/// The highest sequence is fetched first: a trust context fully supersedes
/// its predecessor, so when the newest is signed by an anchor of the held
/// version nothing else is needed. When it is not, the sequence numbers in
/// between (from the first one newer than the held version) are followed
/// oldest first ([`follow_versions`]). The newest is adopted only if it
/// passes [`open_context_update`] against the held version of its namespace
/// — directly or through that walk — and [`Keyring::adopt_update_from`]
/// (that version still held, strictly newer, atomic); see the module docs.
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

    let (newest, walked) = match open_context_update(&held, &data).await {
        Ok((context, signer)) => (
            ContextStep {
                context: Arc::new(context),
                data,
                signer,
            },
            Vec::new(),
        ),
        Err(refusal @ UpdateRefusal::NotSignedByHeldAnchor { .. }) => {
            // The sequence numbers are the versions republished: start at
            // the first one newer than the held version.
            let first = update.low_seq.max(held.version() + 1);
            if first >= update.high_seq {
                return ContextSyncOutcome::Refused(refusal);
            }
            let offered = data
                .name
                .components()
                .last()
                .and_then(NameComponent::as_version)
                .unwrap_or(update.high_seq);
            let mut group = GroupVersions {
                fetcher,
                group: &update.name,
                newest: Some((update.high_seq, data)),
            };
            match follow_versions(&held, first..=update.high_seq, &mut group).await {
                Ok(mut walked) => match walked.pop() {
                    Some(newest) => (newest, walked),
                    None => return ContextSyncOutcome::Refused(refusal),
                },
                Err(stop) => {
                    return ContextSyncOutcome::Refused(UpdateRefusal::CatchUp {
                        held: held.version(),
                        offered,
                        stop,
                    });
                }
            }
        }
        Err(refusal) => return ContextSyncOutcome::Refused(refusal),
    };
    let ContextStep {
        context,
        data,
        signer,
    } = newest;
    match keyring.adopt_update_from(&held, Arc::clone(&context)) {
        Ok(()) => ContextSyncOutcome::Adopted(ContextUpdate {
            previous: held.version(),
            revoked: context
                .revocations()
                .iter()
                .filter(|r| !held.revocations().contains(r))
                .cloned()
                .collect(),
            context,
            data,
            signer,
            walked,
        }),
        // Another adoption changed the namespace while this one was checked.
        Err(Some(now)) if now >= context.version() => {
            ContextSyncOutcome::Refused(UpdateRefusal::NotNewer {
                offered: context.version(),
                held: now,
            })
        }
        Err(Some(now)) => ContextSyncOutcome::ChangedMeanwhile {
            held: held.version(),
            now,
        },
        Err(None) => ContextSyncOutcome::NotHeld { namespace },
    }
}

/// The walk's [`VersionSource`] over a sync group: position `n` is the
/// publisher's group Data `<group>/seg=n`, whose Content is a signed context
/// Data.
struct GroupVersions<'a> {
    fetcher: &'a dyn ContextFetcher,
    group: &'a Name,
    /// The newest version, fetched already.
    newest: Option<(u64, Data)>,
}

impl VersionSource for GroupVersions<'_> {
    async fn fetch(&mut self, position: u64, _from: &SignedTrustContext) -> Result<Data, Unfetched> {
        if let Some((_, data)) = self.newest.take_if(|(seq, _)| *seq == position) {
            return Ok(data);
        }
        let name = self.group.clone().append_segment(position);
        let content = self
            .fetcher
            .fetch_content(name.clone())
            .await
            .ok_or_else(|| Unfetched::Missing(format!("nothing published at {name}")))?;
        Data::decode(content)
            .map_err(|e| Unfetched::Missing(format!("{name} carries no Data packet: {e}")))
    }
}

/// Run the subscription loop until `cancel` fires or the sync group closes:
/// each peer update is fetched and adopted via [`process_update`]. The caller
/// has already [`join`](ndn_sync::join_svs_group)ed the group for the context
/// and spawns this on its runtime. The keyring holds an adopted version in
/// memory only: `keep` is handed each adoption to persist and serve its
/// signed Data and the versions walked through.
pub async fn run(
    mut handle: SyncHandle,
    fetcher: Arc<dyn ContextFetcher>,
    keyring: Arc<Keyring>,
    keep: impl Fn(&ContextUpdate) + Send,
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
                    ContextSyncOutcome::Adopted(adopted) => {
                        tracing::info!(
                            target: "ndn::trust",
                            previous = adopted.previous,
                            version = adopted.context.version(),
                            revoked = ?adopted.revoked.iter().map(Name::to_string).collect::<Vec<_>>(),
                            publisher = %update.publisher,
                            "context-sync adopted a newer trust context"
                        );
                        keep(adopted);
                    }
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

    use ndn_cert::{CatchUpStop, NamespaceInit, anchor_fingerprint, init_namespace};
    use ndn_security::{Ed25519Signer, SecurityManager, Signer};

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
        let v2 = root.version(2, &[revoked]);
        fetcher.publish(2, &v2);

        match process_update(&update_at(2), &fetcher, &keyring).await {
            ContextSyncOutcome::Adopted(adopted) => {
                assert_eq!((adopted.previous, adopted.context.version()), (1, 2));
                assert_eq!(adopted.revoked, vec![n(revoked)]);
                // The signed Data exactly as published: what the caller keeps.
                assert_eq!(adopted.data.raw(), v2.raw());
            }
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
            ContextSyncOutcome::Adopted(a) if a.context.version() == 5
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

    /// A node that missed a recovery follows it from the group: it holds v2
    /// (listing a recovery key); the publisher republished v3 (the recovery
    /// key installs a new root) and v4 (the new root's, newest). v4 alone
    /// does not follow from v2, so the sequence numbers in between are
    /// followed one by one. A forged v3 stops it and the held version stays.
    #[tokio::test]
    async fn a_node_behind_a_recovery_follows_the_sequence_numbers_in_between() {
        let root = Root::new();
        let ns = n("/home/bob");
        let root_signer = root.mgr.get_signer_sync(&root.init.anchor_key).unwrap();
        let seed = ndn_cert::RecoverySeed::generate().unwrap();
        let recovery: Arc<dyn Signer> = Arc::new(seed.signer(&ns));
        let kit = ndn_cert::recovery_anchor(Arc::clone(&recovery)).await.unwrap();
        let v2 = ndn_cert::add_recovery_anchor(root_signer.as_ref(), &root.init.context_data, &kit)
            .await
            .unwrap();
        let keyring = node_holding(&root);
        let fetcher = MapFetcher::new();
        fetcher.publish(2, &v2.data);
        assert!(matches!(
            process_update(&update_at(2), &fetcher, &keyring).await,
            ContextSyncOutcome::Adopted(a) if a.context.version() == 2
        ));

        let new_root_mgr = SecurityManager::new();
        let new_root_key = n("/home/bob/KEY/root2");
        new_root_mgr.generate_ed25519(new_root_key.clone()).unwrap();
        let new_root = new_root_mgr.get_signer_sync(&new_root_key).unwrap();
        let new_anchor = new_root_mgr
            .issue_self_signed_async(&new_root_key, new_root.public_key().unwrap(), u64::MAX)
            .await
            .unwrap();
        let plan = ndn_cert::RecoveryPlan {
            new_root: &new_anchor,
            new_root_device_keys: &[],
            old_root: ndn_cert::OldRoot::Destroyed,
            kept_kits: &[],
        };
        let v3 = ndn_cert::recovery_version(recovery.as_ref(), &v2.data, &plan)
            .await
            .unwrap()
            .bump;
        let v4 = ndn_cert::reissue_version(new_root.as_ref(), &v3.data).await.unwrap();
        let missed = SyncUpdate {
            low_seq: 3,
            ..update_at(4)
        };

        let stranger: Arc<dyn Signer> =
            Arc::new(Ed25519Signer::from_seed(&[7; 32], n("/home/bob/KEY/stranger")));
        let forged = SignedTrustContext::decode_content(v2.data.content().unwrap(), 3).unwrap();
        forged.add_anchor(ndn_cert::recovery_anchor(Arc::clone(&stranger)).await.unwrap());
        let forged_group = MapFetcher::new();
        forged_group.publish(3, &forged.sign_into_data_async(stranger.as_ref()).await.unwrap());
        forged_group.publish(4, &v4.data);
        match process_update(&missed, &forged_group, &keyring).await {
            ContextSyncOutcome::Refused(UpdateRefusal::CatchUp {
                stop: CatchUpStop::Refused { version: 3, .. },
                ..
            }) => {}
            other => panic!("a forged intermediate version was not refused: {other:?}"),
        }
        assert_eq!(held_version(&keyring), 2, "the held version stays");

        fetcher.publish(3, &v3.data);
        fetcher.publish(4, &v4.data);
        match process_update(&missed, &fetcher, &keyring).await {
            ContextSyncOutcome::Adopted(adopted) => {
                assert_eq!((adopted.previous, adopted.context.version()), (2, 4));
                // The newest and the version walked through, as signed: what
                // the caller keeps and serves for the nodes behind it.
                assert_eq!(adopted.data.raw(), v4.data.raw());
                let walked: Vec<_> = adopted.walked.iter().map(|s| s.data.raw()).collect();
                assert_eq!(walked, vec![v3.data.raw()]);
            }
            other => panic!("the recovery was not followed: {other:?}"),
        }
        assert_eq!(held_version(&keyring), 4);
    }
}
