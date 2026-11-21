//! A face whose link service frames NDNLPv2 reliability sends what the forwarder
//! decided: a Nack stays a Nack. The reliable send path framed the payload of every
//! egress item through the reliability layer and dropped the item's intent, so the
//! Interest a Nack wraps went out as that **Interest**, with a TxSequence: the peer
//! was asked for the name it had asked for, and answered itself.

use std::sync::Arc;
use std::time::Duration;

use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::InProcFace;
use ndn_packet::encode::InterestBuilder;
use ndn_packet::lp::LpPacket;
use ndn_transport::reliability::ReliabilityConfig;
use ndn_transport::{ErasedTransport, Face, FaceId, LpLinkService};

#[tokio::test]
async fn a_nack_leaves_a_reliable_face_as_a_nack() {
    let (transport, handle) = InProcFace::new(FaceId(1), 128);
    let transport: Arc<dyn ErasedTransport> = Arc::new(transport);
    let service = Arc::new(LpLinkService::with_reliability(ReliabilityConfig::ethernet()));
    let (_engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face_composed(Face::from_parts(transport, service))
        .build()
        .await
        .expect("engine build");

    // No route: the forwarder answers on the face the Interest came in on.
    let interest = InterestBuilder::new(ndn_packet::name!("/unrouted/data"))
        .lifetime(Duration::from_secs(2))
        .build();
    handle.send(interest).await.expect("inject interest");
    let sent = tokio::time::timeout(Duration::from_millis(500), handle.recv())
        .await
        .expect("the forwarder answered")
        .expect("the face is open");

    let lp = LpPacket::decode(sent.clone()).expect("an LpPacket");
    assert!(
        lp.nack.is_some(),
        "the reliable face sent an Interest where the forwarder sent a Nack: {sent:02x?}"
    );
    shutdown.shutdown().await;
}
