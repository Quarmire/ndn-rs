//! The trust / links change-notification streams (`MgmtEvents`): a
//! subscriber starting at 0 is told to resync at the next event, then
//! receives events in order by sequence number; one asking for an event the
//! ring dropped, or for a number from an earlier run, is told to resync. The
//! trust-admin backend's events reach the trust stream once management is
//! mounted.

use std::sync::Arc;
use std::time::Duration;

use ndn_cert::report::{ContextChange, Decision};
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::{InProcFace, InProcHandle};
use ndn_mgmt::{
    AdoptedContextInfo, ContextRefreshInfo, EnrollOutcome, EnrollRequest, MgmtEvents, MgmtHandles,
    TrustAdminMgmtBackend, TrustEvent, TrustRefusal, mount_management,
};
use ndn_mgmt_wire::events::{LinkEvent, RESYNC_KIND};
use ndn_packet::{Data, Name, encode::InterestBuilder};
use ndn_transport::FaceId;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

const SUBSCRIBER: FaceId = FaceId(99);

async fn served() -> (MgmtEvents, InProcHandle, CancellationToken) {
    let (face, handle) = InProcFace::new(SUBSCRIBER, 64);
    let (engine, _shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(face)
        .build()
        .await
        .expect("engine build");
    let cancel = CancellationToken::new();
    let events = MgmtEvents::default();
    Arc::clone(&events.trust).install(&engine, cancel.clone());
    Arc::clone(&events.links).install(&engine, cancel.clone());
    tokio::time::sleep(Duration::from_millis(50)).await;
    (events, handle, cancel)
}

/// Ask `prefix/seq=<seq>`: the Data's seq and content as JSON.
async fn fetch(handle: &InProcHandle, prefix: &Name, seq: u64) -> (u64, serde_json::Value) {
    let name = prefix.clone().append_sequence_num(seq);
    let interest = InterestBuilder::new(name.clone())
        .must_be_fresh()
        .lifetime(Duration::from_secs(3))
        .build();
    handle.send(interest).await.expect("send Interest");
    let wire = tokio::time::timeout(Duration::from_secs(5), handle.recv())
        .await
        .expect("answer within 5s")
        .expect("face open");
    let data = Data::decode(wire).expect("Data");
    assert_eq!(*data.name, name, "answered at the requested name");
    let content = data.content().cloned().unwrap_or_default();
    (seq, serde_json::from_slice(&content).expect("JSON content"))
}

fn decided(request: &str) -> TrustEvent {
    TrustEvent::ApprovalDecided {
        ca: "/alice/CA".into(),
        request: request.into(),
        decision: Decision::Approved,
    }
}

#[tokio::test]
async fn subscriber_resyncs_then_follows_in_order() {
    let (events, handle, cancel) = served().await;
    let prefix = events.trust.prefix().clone();

    // A new subscriber asks for 0: told where the stream goes on.
    let (_, first) = fetch(&handle, &prefix, 0).await;
    assert_eq!(first["kind"], RESYNC_KIND);
    let next = first["next"].as_u64().expect("next");
    assert_eq!(next, events.trust.current_seq() + 1);

    // Held until published (long-poll), then the rest in order.
    let sink = events.trust_sink();
    let publisher = {
        let sink = Arc::clone(&sink);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            sink.publish(decided("r1"));
            sink.publish(decided("r2"));
        })
    };
    let (_, e1) = fetch(&handle, &prefix, next).await;
    publisher.await.unwrap();
    let (_, e2) = fetch(&handle, &prefix, next + 1).await;
    let e1: TrustEvent = serde_json::from_value(e1).unwrap();
    let e2: TrustEvent = serde_json::from_value(e2).unwrap();
    assert_eq!(e1, decided("r1"));
    assert_eq!(e2, decided("r2"));
    cancel.cancel();
}

#[tokio::test]
async fn dropped_or_earlier_run_events_answer_resync() {
    let (events, handle, cancel) = served().await;
    let prefix = events.links.prefix().clone();
    let start = events.links.current_seq();
    assert!(start > 1_000_000, "numbered after the start time");

    for i in 0..150 {
        events.links.publish(LinkEvent::LinkGone {
            label: format!("l{i}"),
            key: None,
        });
    }
    // The ring keeps the newest; the first ones are gone: a gap.
    let (_, gap) = fetch(&handle, &prefix, start + 1).await;
    assert_eq!(gap["kind"], RESYNC_KIND);
    assert_eq!(gap["next"].as_u64(), Some(start + 151));
    // The newest is still served by number.
    let (_, last) = fetch(&handle, &prefix, start + 150).await;
    assert_eq!(last["kind"], "link-gone");
    assert_eq!(last["label"], "l149");
    // A number from an earlier run (below this run's start).
    let (_, old) = fetch(&handle, &prefix, start - 5).await;
    assert_eq!(old["kind"], RESYNC_KIND);
    // A number beyond the next (a clock that went back): resync too.
    let (_, ahead) = fetch(&handle, &prefix, start + 10_000).await;
    assert_eq!(ahead["kind"], RESYNC_KIND);
    assert_eq!(ahead["next"].as_u64(), Some(start + 151));
    cancel.cancel();
}

/// A trust-admin backend that only makes events.
struct Eventful(broadcast::Sender<TrustEvent>);

#[async_trait::async_trait]
impl TrustAdminMgmtBackend for Eventful {
    async fn adopt(&self, _link_uri: String) -> Result<AdoptedContextInfo, TrustRefusal> {
        Err(ndn_mgmt::not_at_runtime(
            "context-adopt",
            "not in this test",
        ))
    }

    async fn enroll(&self, _request: EnrollRequest) -> Result<EnrollOutcome, TrustRefusal> {
        Err(ndn_mgmt::not_at_runtime("enroll", "not in this test"))
    }

    async fn update_context(
        &self,
        _context_data: bytes::Bytes,
    ) -> Result<ContextRefreshInfo, TrustRefusal> {
        Err(ndn_mgmt::not_at_runtime(
            "context-update",
            "not in this test",
        ))
    }

    async fn refresh_contexts(
        &self,
        _namespace: Option<Name>,
    ) -> Result<Vec<ContextRefreshInfo>, TrustRefusal> {
        Err(ndn_mgmt::not_at_runtime(
            "context-refresh",
            "not in this test",
        ))
    }

    fn trust_events(&self) -> Option<broadcast::Receiver<TrustEvent>> {
        Some(self.0.subscribe())
    }
}

#[tokio::test]
async fn the_backend_events_reach_the_trust_stream_beside_the_hosts_own() {
    let (face, handle) = InProcFace::new(SUBSCRIBER, 64);
    let (engine, _shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(face)
        .build()
        .await
        .expect("engine build");
    let cancel = CancellationToken::new();
    let backend = broadcast::channel(16).0;
    let events = MgmtEvents::default();
    tokio::spawn(mount_management(
        &engine,
        cancel.clone(),
        Arc::new(ndn_config::ForwarderConfig::default()),
        None,
        MgmtHandles {
            events: events.clone(),
            trust_context_handler: Some(Arc::new(Eventful(backend.clone()))),
            ..Default::default()
        },
    ));
    tokio::time::sleep(Duration::from_millis(50)).await;
    let prefix = events.trust.prefix().clone();
    let (_, first) = fetch(&handle, &prefix, 0).await;
    let next = first["next"].as_u64().expect("next");

    let kept = TrustEvent::ContextUpdated {
        namespace: "/alice".into(),
        held_version: Some(1),
        version: 2,
        how: ContextChange::Refresh,
        revoked: Vec::new(),
    };
    backend
        .send(kept.clone())
        .expect("forwarded from the stream");
    let (_, e1) = fetch(&handle, &prefix, next).await;
    // A CA of the host publishes to the same stream, in order.
    events.trust.publish(decided("r1"));
    let (_, e2) = fetch(&handle, &prefix, next + 1).await;
    assert_eq!(serde_json::from_value::<TrustEvent>(e1).unwrap(), kept);
    assert_eq!(
        serde_json::from_value::<TrustEvent>(e2).unwrap(),
        decided("r1")
    );
    cancel.cancel();
}
