//! ARCH-6 / S11 — witness for the `/localhost/<proto>/status`
//! status-bridge Producer.
//!
//! Subscribes a Consumer face to `/localhost/test/status` and checks
//! that the Data Content matches the bytes the status_provider
//! produced. Exercises [`mount_routing_status`] without standing up a
//! real `RoutingProtocol`.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_engine::{EngineBuilder, EngineConfig, InstallableProtocol, PostBuildQueue};
use ndn_face_local::InProcFace;
use ndn_mgmt::mount_routing_status;
use ndn_packet::{Data, Name, encode::InterestBuilder};
use ndn_transport::FaceId;
use tokio_util::sync::CancellationToken;

const SUBSCRIBER_FACE_ID: FaceId = FaceId(99);

/// Trivial installer that calls `mount_routing_status` with a fixed
/// payload so the test exercises the full install → build → apply path.
struct TestStatusInstaller {
    prefix: Name,
    payload: Bytes,
}

impl InstallableProtocol for TestStatusInstaller {
    fn install(self: Arc<Self>, builder: &mut EngineBuilder, post: &mut PostBuildQueue) {
        let payload = self.payload.clone();
        mount_routing_status(builder, post, self.prefix.clone(), move || payload.clone());
    }
}

#[tokio::test]
async fn status_bridge_serves_provider_bytes() {
    let (subscriber_face, subscriber_handle) = InProcFace::new(SUBSCRIBER_FACE_ID, 16);
    let prefix: Name = "/localhost/test/status".parse().unwrap();
    let payload = Bytes::from_static(b"PAYLOAD_SENTINEL");

    let mut post = PostBuildQueue::new();
    let installer = Arc::new(TestStatusInstaller {
        prefix: prefix.clone(),
        payload: payload.clone(),
    });
    let builder = EngineBuilder::new(EngineConfig::default())
        .face(subscriber_face)
        .install(installer, &mut post);
    let (engine, _shutdown) = builder.build().await.expect("engine build");
    let cancel = CancellationToken::new();
    post.apply(&engine, &cancel);

    // Give the producer task a tick to mount.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Subscriber expresses an Interest at the status prefix.
    let interest = InterestBuilder::new(prefix.clone())
        .can_be_prefix()
        .must_be_fresh()
        .lifetime(Duration::from_secs(2))
        .build();
    subscriber_handle
        .send(interest)
        .await
        .expect("send Interest");

    let wire = tokio::time::timeout(Duration::from_secs(2), subscriber_handle.recv())
        .await
        .expect("response within 2s")
        .expect("response not None");
    let data = Data::decode(wire).expect("Data decode");
    let content = data.content().cloned().unwrap_or_default();
    assert_eq!(content, payload, "Data Content matches provider output");

    cancel.cancel();
}
