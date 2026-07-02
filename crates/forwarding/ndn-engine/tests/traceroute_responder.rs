//! G9 per-hop identity: a forwarder with a traceroute responder answers a *marked* trace
//! probe whose HopLimit has expired (arrives as 0) with its own name, out the in-face —
//! while an unmarked hop-limited Interest is still dropped silently.

use std::time::Duration;

use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::InProcFace;
use ndn_packet::encode::InterestBuilder;
use ndn_packet::{Data, Name, NameComponent};
use ndn_transport::FaceId;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_trace_probe_draws_node_identity() {
    let node: Name = "/router/edge-1".parse().unwrap();
    let (face, handle) = InProcFace::new(FaceId(1), 64);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(face)
        .with_traceroute_responder(node.clone())
        .build()
        .await
        .expect("engine build");

    let marker = NameComponent::keyword(bytes::Bytes::from_static(
        ndn_engine::traceroute::TRACEROUTE_KEYWORD,
    ));

    // A marked probe arriving with HopLimit 0 (expired at this hop) → identity reply.
    let probe: Name = "/svc/ping/1".parse().unwrap();
    let marked = probe.clone().append_component(marker.clone());
    let interest = InterestBuilder::new(marked.clone())
        .hop_limit(0)
        .must_be_fresh()
        .build();
    handle.send(interest).await.unwrap();

    let reply = tokio::time::timeout(Duration::from_secs(2), handle.recv())
        .await
        .expect("identity reply timed out")
        .expect("face closed");
    let data = Data::decode(reply).expect("reply decodes");
    assert_eq!(*data.name, marked, "reply satisfies the probe name");
    let id = ndn_engine::traceroute::parse_identity(data.content().expect("content"))
        .expect("hop identity");
    assert_eq!(id, node, "the hop reported its own name");

    // An *unmarked* expired Interest is dropped silently — no reply.
    let plain = InterestBuilder::new("/svc/other/1".parse::<Name>().unwrap())
        .hop_limit(0)
        .must_be_fresh()
        .build();
    handle.send(plain).await.unwrap();
    let silent = tokio::time::timeout(Duration::from_millis(300), handle.recv()).await;
    assert!(
        silent.is_err(),
        "an unmarked hop-limited Interest must drop silently"
    );

    drop(engine);
    shutdown.shutdown().await;
}
