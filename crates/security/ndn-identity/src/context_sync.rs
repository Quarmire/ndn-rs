//! Context-sync subscription (NDF F11).
//!
//! Subscribes to a trust context's SVS group so a republished
//! [`SignedTrustContext`] propagates to fleet nodes without polling, and adopts
//! each new version into the local [`Keyring`] with anti-rollback. This is the
//! *subscribe* half; publishing a node's own context is a later phase.
//!
//! # Layering
//!
//! The orchestrator lives here, in `ndn-identity`, because it composes two
//! layers that already meet here: the SVS primitive ([`ndn_sync`]) and
//! [`SignedTrustContext`] / [`Keyring`] adoption ([`ndn_security`]).
//! `ndn-sync` stays free of any trust-context dependency (sync is the lower
//! layer).
//!
//! # Wire
//!
//! The synced payload is the context's canonical Content,
//! [`SignedTrustContext::encode_content`] (TLV `0x0410`), so anchors, the
//! schema blob (LVS carried verbatim), CA endpoints, enrollment hint,
//! revocations and source-bundle hash all arrive intact. A publisher
//! republishes context version `N` into the group at
//! `<group>/<publisher>/seg=N`: the SVS sequence number *is* the context
//! version (the role `v=N` plays in [`SignedTrustContext::rdr_name`]) and
//! drives anti-rollback.
//!
//! # Transport seam
//!
//! `ndn-sync` is sans-IO (the caller wires the SVS Interest channels to a
//! face), and fetching a context Data is likewise abstracted behind
//! [`ContextFetcher`] so this module needs no face/engine of its own and is unit
//! testable.

use std::sync::Arc;

use bytes::Bytes;
use ndn_packet::Name;
use ndn_security::{Keyring, SignedTrustContext};
use ndn_sync::{SyncHandle, SyncUpdate};
use tokio_util::sync::CancellationToken;

/// Fetches the Content bytes of the Data published at a name. The caller backs
/// this with its consumer/face; an in-process engine, an `ndn-app` `Consumer`,
/// or a test stub all satisfy it.
#[async_trait::async_trait]
pub trait ContextFetcher: Send + Sync {
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
    /// The context Data could not be fetched.
    FetchFailed,
    /// The fetched Content was not a decodable [`SignedTrustContext`].
    DecodeFailed,
}

/// Fetch, decode, and adopt the context advertised by one [`SyncUpdate`].
/// Only the highest sequence is fetched — a trust context fully supersedes its
/// predecessor, so older versions in the gap need not be retrieved. The SVS
/// sequence is the context version (anti-rollback monotonicity); the decoded
/// context keeps the hierarchical authorization floor (N1) every context
/// arriving over the wire gets.
pub async fn process_update(
    update: &SyncUpdate,
    fetcher: &dyn ContextFetcher,
    keyring: &Keyring,
) -> ContextSyncOutcome {
    let version = update.high_seq;
    let fetch_name = update.name.clone().append_segment(version);
    let Some(content) = fetcher.fetch_content(fetch_name).await else {
        return ContextSyncOutcome::FetchFailed;
    };
    let Ok(ctx) = SignedTrustContext::decode_content(&content, version) else {
        return ContextSyncOutcome::DecodeFailed;
    };
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
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Maps a fetch name → context Content.
    struct MapFetcher(Mutex<HashMap<String, Bytes>>);

    #[async_trait::async_trait]
    impl ContextFetcher for MapFetcher {
        async fn fetch_content(&self, name: Name) -> Option<Bytes> {
            self.0.lock().unwrap().get(&name.to_string()).cloned()
        }
    }

    fn context_wire(ns: &str) -> Bytes {
        SignedTrustContext::hierarchical(ns.parse().unwrap()).encode_content()
    }

    fn update_at(name: &str, seq: u64) -> SyncUpdate {
        SyncUpdate {
            publisher: "device-a".into(),
            name: name.parse().unwrap(),
            low_seq: seq,
            high_seq: seq,
            mapping: None,
            serving_party: None,
        }
    }

    #[tokio::test]
    async fn adopts_newer_version_and_anti_rollback_refuses_older() {
        let group = "/home/bob/_sync/v1/devices/device-a";
        let m = MapFetcher(Mutex::new(HashMap::new()));
        // Publish version 5 and version 3 contexts at their seg names.
        {
            let mut g = m.0.lock().unwrap();
            let v5 = group.parse::<Name>().unwrap().append_segment(5).to_string();
            let v3 = group.parse::<Name>().unwrap().append_segment(3).to_string();
            g.insert(v5, context_wire("/home/bob"));
            g.insert(v3, context_wire("/home/bob"));
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
    async fn synced_context_keeps_revocations_hint_and_lvs_schema() {
        use ndn_security::{EnrollmentHint, SchemaBlob, SchemaFormat};

        let group = "/home/bob/_sync/v1/devices/device-a";
        let revoked: Name = "/home/bob/KEY/old-ca".parse().unwrap();
        let lvs = Bytes::from_static(include_bytes!(
            "../../ndn-security/tests/fixtures/lvs_ndnd_test_model.tlv"
        ));
        let published = SignedTrustContext::hierarchical("/home/bob".parse().unwrap())
            .with_ca_endpoint("/home/bob/CA".parse().unwrap())
            .with_enrollment_hint(EnrollmentHint::namespace_default())
            .with_revocation(revoked.clone())
            .with_schema_blob(SchemaBlob::lvs(lvs.clone()))
            .expect("LVS schema imports");
        let m = MapFetcher(Mutex::new(HashMap::from([(
            group.parse::<Name>().unwrap().append_segment(7).to_string(),
            published.encode_content(),
        )])));
        let keyring = Keyring::new();

        let out = process_update(&update_at(group, 7), &m, &keyring).await;
        assert_eq!(out, ContextSyncOutcome::Adopted { version: 7 });
        let held = keyring.context_for(&"/home/bob".parse().unwrap());
        assert_eq!(held.version(), 7);
        assert!(held.is_revoked(&revoked), "revocation survives sync");
        assert_eq!(held.ca_endpoints(), published.ca_endpoints());
        assert_eq!(held.enrollment_hint(), Some(&EnrollmentHint::namespace_default()));
        let schemas = held.published_schemas();
        assert_eq!(schemas.len(), 1);
        assert_eq!(schemas[0].format, SchemaFormat::Lvs);
        assert_eq!(schemas[0].body, lvs, "LVS blob travels byte-for-byte");
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
            ndn_packet::name!("/x/_sync/v1/devices/d")
                .append_segment(1)
                .to_string(),
            Bytes::from_static(b"not a trust context"),
        )])));
        assert_eq!(
            process_update(&update_at("/x/_sync/v1/devices/d", 1), &garbage, &keyring).await,
            ContextSyncOutcome::DecodeFailed
        );
    }
}
