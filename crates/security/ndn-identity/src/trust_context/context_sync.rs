//! Context-sync subscription (NDF F11, TrustContext "Phase 2").
//!
//! Subscribes to a trust context's SVS group so a republished context
//! propagates to fleet nodes without polling, and adopts each new version into
//! the local [`Keyring`] with anti-rollback. This is the *subscribe* half;
//! publishing a node's own bundle is a later phase.
//!
//! # Layering
//!
//! The orchestrator lives here, in `ndn-identity`, because it composes three
//! layers that already meet here: the `SyncBundle` wire codec (this crate),
//! the SVS primitive ([`ndn_sync`]), and [`SignedTrustContext`] /
//! [`Keyring`] adoption ([`ndn_security`]). `ndn-sync` stays free of any
//! trust-context dependency (sync is the lower layer).
//!
//! # Transport seam
//!
//! `ndn-sync` is sans-IO (the caller wires the SVS Interest channels to a
//! face), and fetching a bundle Data is likewise abstracted behind
//! [`BundleFetcher`] so this module needs no face/engine of its own and is unit
//! testable. A node republishes its context bundle into the group at
//! `<group>/<publisher>/seg=<seq>`; the SVS sequence number doubles as the
//! context version for anti-rollback.

use std::sync::Arc;

use bytes::Bytes;
use ndn_packet::Name;
use ndn_security::{Keyring, SignedTrustContext};
use ndn_sync::{SyncHandle, SyncUpdate};
use tokio_util::sync::CancellationToken;

use super::sync::SyncBundle;

/// Fetches the Content bytes of the Data published at a name. The caller backs
/// this with its consumer/face; an in-process engine, an `ndn-app` `Consumer`,
/// or a test stub all satisfy it.
#[async_trait::async_trait]
pub trait BundleFetcher: Send + Sync {
    async fn fetch_content(&self, name: Name) -> Option<Bytes>;
}

/// What happened when a sync update was processed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextSyncOutcome {
    /// A newer context version was fetched, reconstructed, and adopted.
    Adopted { version: u64 },
    /// Fetched and decoded, but the keyring refused it (anti-rollback: the held
    /// version is the same or newer). Convergence is unaffected.
    Rejected { version: u64 },
    /// The bundle Data could not be fetched.
    FetchFailed,
    /// The fetched Data was not a decodable `SyncBundle`.
    DecodeFailed,
}

/// Reconstruct a [`SignedTrustContext`] from a synced bundle at `version`. The
/// hierarchical authorization floor is re-imposed (the N1 safety default for
/// any context arriving over the wire), and the bundle's published schema +
/// anchors + CA endpoints are installed.
fn bundle_to_context(bundle: SyncBundle, version: u64) -> SignedTrustContext {
    let mut ctx = SignedTrustContext::hierarchical(bundle.context_name).with_version(version);
    for ca in bundle.ca_endpoints {
        ctx = ctx.with_ca_endpoint(ca);
    }
    for anchor in bundle.anchors {
        let _: bool = ctx.add_anchor(anchor);
    }
    ctx.set_schema(bundle.schema);
    ctx
}

/// Fetch, reconstruct, and adopt the context advertised by one [`SyncUpdate`].
/// Only the highest sequence is fetched — a trust context fully supersedes its
/// predecessor, so older versions in the gap need not be retrieved. The SVS
/// sequence is the context version (anti-rollback monotonicity).
pub async fn process_update(
    update: &SyncUpdate,
    fetcher: &dyn BundleFetcher,
    keyring: &Keyring,
) -> ContextSyncOutcome {
    let version = update.high_seq;
    let fetch_name = update.name.clone().append_segment(version);
    let Some(content) = fetcher.fetch_content(fetch_name).await else {
        return ContextSyncOutcome::FetchFailed;
    };
    let Ok(bundle) = SyncBundle::decode_wire(&content) else {
        return ContextSyncOutcome::DecodeFailed;
    };
    let ctx = bundle_to_context(bundle, version);
    if keyring.adopt(Arc::new(ctx)) {
        ContextSyncOutcome::Adopted { version }
    } else {
        ContextSyncOutcome::Rejected { version }
    }
}

/// Run the subscription loop until `cancel` fires or the sync group closes:
/// each peer update is fetched and adopted via [`process_update`]. The caller
/// has already [`join`](ndn_sync::join_svs_group)ed the group for the context
/// and spawns this on its runtime.
pub async fn run(
    mut handle: SyncHandle,
    fetcher: Arc<dyn BundleFetcher>,
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
                    ContextSyncOutcome::Adopted { version } => tracing::info!(
                        target: "ndn::trust", %version, publisher = %update.publisher,
                        "context-sync adopted a newer trust context"
                    ),
                    ContextSyncOutcome::Rejected { version } => tracing::debug!(
                        target: "ndn::trust", %version,
                        "context-sync update refused (anti-rollback)"
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
    use ndn_security::trust_schema::TrustSchema;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Maps a fetch name → bundle wire.
    struct MapFetcher(Mutex<HashMap<String, Bytes>>);

    #[async_trait::async_trait]
    impl BundleFetcher for MapFetcher {
        async fn fetch_content(&self, name: Name) -> Option<Bytes> {
            self.0.lock().unwrap().get(&name.to_string()).cloned()
        }
    }

    fn bundle_wire(ns: &str) -> Bytes {
        SyncBundle {
            context_name: ns.parse().unwrap(),
            anchors: Vec::new(),
            schema: TrustSchema::hierarchical(),
            ca_endpoints: Vec::new(),
        }
        .encode_wire()
    }

    fn update_at(name: &str, seq: u64) -> SyncUpdate {
        SyncUpdate {
            publisher: "device-a".into(),
            name: name.parse().unwrap(),
            low_seq: seq,
            high_seq: seq,
            mapping: None,
        }
    }

    #[tokio::test]
    async fn adopts_newer_version_and_anti_rollback_refuses_older() {
        let group = "/home/bob/_sync/v1/devices/device-a";
        let m = MapFetcher(Mutex::new(HashMap::new()));
        // Publish version 5 and version 3 bundles at their seg names.
        {
            let mut g = m.0.lock().unwrap();
            let v5 = Name::from(group).append_segment(5).to_string();
            let v3 = Name::from(group).append_segment(3).to_string();
            g.insert(v5, bundle_wire("/home/bob"));
            g.insert(v3, bundle_wire("/home/bob"));
        }
        let keyring = Keyring::new();

        // Seq 5 arrives → adopted.
        let out = process_update(&update_at(group, 5), &m, &keyring).await;
        assert_eq!(out, ContextSyncOutcome::Adopted { version: 5 });
        assert_eq!(
            keyring.context_for(&"/home/bob".parse().unwrap()).version(),
            5
        );

        // A stale seq 3 arrives → fetched + decoded, but refused by anti-rollback.
        let out = process_update(&update_at(group, 3), &m, &keyring).await;
        assert_eq!(out, ContextSyncOutcome::Rejected { version: 3 });
        assert_eq!(
            keyring.context_for(&"/home/bob".parse().unwrap()).version(),
            5,
            "held context stays at the newer version"
        );
    }

    #[tokio::test]
    async fn fetch_and_decode_failures_are_reported() {
        let keyring = Keyring::new();
        let empty = MapFetcher(Mutex::new(HashMap::new()));
        assert_eq!(
            process_update(&update_at("/x/_sync/v1/devices/d", 1), &empty, &keyring).await,
            ContextSyncOutcome::FetchFailed
        );

        let garbage = MapFetcher(Mutex::new(HashMap::from([(
            Name::from("/x/_sync/v1/devices/d")
                .append_segment(1)
                .to_string(),
            Bytes::from_static(b"not a bundle"),
        )])));
        assert_eq!(
            process_update(&update_at("/x/_sync/v1/devices/d", 1), &garbage, &keyring).await,
            ContextSyncOutcome::DecodeFailed
        );
    }
}
