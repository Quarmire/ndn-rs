//! Self-learning strategy: discovery-broadcast on no route, and route-learning
//! from a PrefixAnnouncement carried on Data.
//!
//! Two gates protect route installation: (1) the active strategy for the
//! announced prefix must be self-learning, and (2) the announcement must pass
//! the engine's `Validator` (try_self_learn calls `validate` and installs only
//! on `Valid`). This file pins both gates + the broadcast behavior. The default
//! validator here accepts the DigestSha256 test announcement; a strict
//! trust-anchor leg that *rejects* an untrusted announcement is a follow-up.

use std::time::Duration;

use bytes::Bytes;
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::{InProcFace, InProcHandle};
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Name, NameComponent};
use ndn_tlv::TlvWriter;
use ndn_transport::FaceId;

const CONSUMER: u64 = 1;
const NEIGHBOR: u64 = 2;
const OTHER: u64 = 3;

async fn recv_timeout(h: &InProcHandle) -> Option<bytes::Bytes> {
    tokio::time::timeout(Duration::from_millis(300), h.recv())
        .await
        .ok()
        .flatten()
}

fn is_interest(wire: &bytes::Bytes) -> bool {
    use ndn_packet::lp::LpPacket;
    wire.first() == Some(&0x05)
        || LpPacket::decode(wire.clone())
            .ok()
            .and_then(|lp| lp.fragment)
            .is_some_and(|f| f.first() == Some(&0x05))
}

/// `[LP [PrefixAnnouncement <pa>] [Fragment <data>]]`.
fn data_with_prefix_announcement(data_wire: &[u8], pa_wire: &[u8]) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_nested(ndn_packet::tlv_type::LP_PACKET, |w| {
        w.write_tlv(ndn_packet::tlv_type::LP_PREFIX_ANNOUNCEMENT, pa_wire);
        w.write_tlv(ndn_packet::tlv_type::LP_FRAGMENT, data_wire);
    });
    w.finish()
}

fn pa_for(prefix: &str) -> Bytes {
    let name: Name = prefix.parse().unwrap();
    let pa_name = name
        .append_component(NameComponent::keyword(Bytes::from_static(b"PA")))
        .append_version(1);
    DataBuilder::new(pa_name, b"").sign_digest_sha256()
}

fn use_self_learning(engine: &ndn_engine::ForwarderEngine) {
    let sl = ndn_strategy::registry::create_by_name(b"self-learning")
        .expect("self-learning strategy registered");
    engine
        .strategy_table()
        .insert(&"/".parse::<Name>().unwrap(), sl);
}

/// Drive a consumer Interest for `/carrier/d` that the neighbor answers with a
/// Data carrying a PrefixAnnouncement for `/learned`. Returns the engine so the
/// caller can inspect the FIB. `self_learning` chooses the gate.
async fn run_announcement_flow(
    self_learning: bool,
) -> (ndn_engine::ForwarderEngine, ndn_engine::ShutdownHandle) {
    let (fc, hc) = InProcFace::new(FaceId(CONSUMER), 128);
    let (fnb, hnb) = InProcFace::new(FaceId(NEIGHBOR), 128);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(fc)
        .face(fnb)
        .build()
        .await
        .expect("engine build");
    if self_learning {
        use_self_learning(&engine);
    }
    engine
        .fib()
        .add_nexthop(&"/carrier".parse().unwrap(), FaceId(NEIGHBOR), 0);

    let interest = InterestBuilder::new("/carrier/d")
        .lifetime(Duration::from_secs(2))
        .build();
    hc.send(interest).await.unwrap();
    let _ = recv_timeout(&hnb).await;

    let data = DataBuilder::new("/carrier/d", b"x").sign_digest_sha256();
    let wire = data_with_prefix_announcement(&data, &pa_for("/learned"));
    hnb.send(wire).await.unwrap();
    let _ = recv_timeout(&hc).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    (engine, shutdown)
}

/// Self-learning + a validated PrefixAnnouncement → a route is installed toward
/// the announcing (neighbor) face.
#[tokio::test]
async fn validated_announcement_installs_route() {
    let (engine, shutdown) = run_announcement_flow(true).await;
    let entry = engine.fib().lpm(&"/learned".parse().unwrap());
    assert!(
        entry
            .as_ref()
            .is_some_and(|e| e.nexthops.iter().any(|h| h.face_id == FaceId(NEIGHBOR))),
        "self-learning must install a /learned route toward the neighbor face"
    );
    shutdown.shutdown().await;
}

/// Strategy gate: when the active strategy is NOT self-learning, a
/// PrefixAnnouncement is ignored — no route is installed.
#[tokio::test]
async fn non_self_learning_strategy_ignores_announcement() {
    let (engine, shutdown) = run_announcement_flow(false).await;
    assert!(
        engine.fib().lpm(&"/learned".parse().unwrap()).is_none(),
        "without the self-learning strategy, a PrefixAnnouncement installs no route"
    );
    shutdown.shutdown().await;
}

/// Self-learning floods an Interest with no route to all other faces.
#[tokio::test]
async fn no_route_interest_is_broadcast() {
    let (fc, hc) = InProcFace::new(FaceId(CONSUMER), 128);
    let (fnb, hnb) = InProcFace::new(FaceId(NEIGHBOR), 128);
    let (fo, ho) = InProcFace::new(FaceId(OTHER), 128);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(fc)
        .face(fnb)
        .face(fo)
        .build()
        .await
        .expect("engine build");
    use_self_learning(&engine);

    let interest = InterestBuilder::new("/undiscovered/d")
        .lifetime(Duration::from_secs(2))
        .build();
    hc.send(interest).await.unwrap();

    // Both other faces receive the discovery flood.
    assert!(
        recv_timeout(&hnb).await.as_ref().is_some_and(is_interest),
        "neighbor must receive the discovery broadcast"
    );
    assert!(
        recv_timeout(&ho).await.as_ref().is_some_and(is_interest),
        "other face must receive the discovery broadcast"
    );
    shutdown.shutdown().await;
}
