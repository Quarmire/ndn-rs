//! Broadcast-bearer Data-path parity with NFD.
//!
//! Two NFD `onIncomingData` behaviors that matter on a shared/ad-hoc medium:
//!
//!  - **UnsolicitedDataPolicy** (NFD `onDataUnsolicited`): Data with no pending
//!    PIT entry is dropped by default, but may be opportunistically cached so a
//!    later Interest is served locally.
//!  - **Ad-hoc re-radiation** (NFD `forwarder.cpp:383`, the `!= LINK_TYPE_AD_HOC`
//!    guard): forwarded Data is not echoed back out the face it arrived on,
//!    *except* on ad-hoc links where re-radiating onto the medium is how other
//!    listeners hear it.
//!
//! Driven through a real `ForwarderEngine` with in-process faces.

use std::time::Duration;

use ndn_engine::{EngineBuilder, EngineConfig, UnsolicitedDataPolicy};
use ndn_face_local::{InProcFace, InProcHandle};
use ndn_packet::Name;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_transport::FaceId;

const FACE_A: u64 = 1;
const FACE_B: u64 = 2;

/// A thin wrapper that presents an [`InProcFace`] as an **ad-hoc** link. The
/// only behavioral difference from `InProcFace` is `link_type()` — enough to
/// exercise the `forwarder.cpp:383` carve-out where Data IS echoed back onto an
/// ad-hoc medium.
mod adhoc {
    use super::*;
    use bytes::Bytes;
    use ndn_transport::{
        FaceError, FaceKind, FacePersistency, LinkType, MtuError, PersistencyError, Transport,
    };

    pub struct AdHocFace(pub InProcFace);

    impl Transport for AdHocFace {
        fn id(&self) -> FaceId {
            self.0.id()
        }
        fn kind(&self) -> FaceKind {
            self.0.kind()
        }
        fn link_type(&self) -> LinkType {
            LinkType::AdHoc
        }
        async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
            self.0.recv_bytes().await
        }
        async fn send_bytes(&self, pkt: Bytes) -> Result<(), FaceError> {
            self.0.send_bytes(pkt).await
        }
        async fn send_bytes_with_source(
            &self,
            pkt: Bytes,
            source: FaceId,
        ) -> Result<(), FaceError> {
            self.0.send_bytes_with_source(pkt, source).await
        }
        fn set_send_mtu(&self, mtu: Option<u64>) -> Result<Option<u64>, MtuError> {
            self.0.set_send_mtu(mtu)
        }
        fn set_persistency(&self, p: FacePersistency) -> Result<(), PersistencyError> {
            self.0.set_persistency(p)
        }
    }
}

async fn recv_timeout(handle: &InProcHandle) -> Option<bytes::Bytes> {
    tokio::time::timeout(Duration::from_millis(300), handle.recv())
        .await
        .ok()
        .flatten()
}

fn is_data(wire: &bytes::Bytes) -> bool {
    use ndn_packet::lp::LpPacket;
    const T_DATA: u8 = 0x06;
    if wire.first() == Some(&T_DATA) {
        return true;
    }
    if let Ok(lp) = LpPacket::decode(wire.clone()) {
        if let Some(frag) = lp.fragment {
            return frag.first() == Some(&T_DATA);
        }
    }
    false
}

/// `AdmitAll`: unsolicited Data is cached, so a later Interest with no route is
/// answered from the Content Store.
#[tokio::test]
async fn admit_all_caches_unsolicited_data_served_from_cs() {
    let (face_a, handle_a) = InProcFace::new(FaceId(FACE_A), 128);
    let (face_b, handle_b) = InProcFace::new(FaceId(FACE_B), 128);

    let (_engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .unsolicited_data_policy(UnsolicitedDataPolicy::AdmitAll)
        .face(face_a)
        .face(face_b)
        .build()
        .await
        .expect("engine build");

    // Unsolicited Data on face B (no pending Interest). Fresh so it is admissible.
    let data = DataBuilder::new("/u/obj", b"payload")
        .freshness(Duration::from_secs(60))
        .sign_digest_sha256();
    handle_b.send(data).await.expect("inject data");
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Consumer Interest on face A with NO route → only a CS hit can answer it.
    let interest = InterestBuilder::new("/u/obj")
        .lifetime(Duration::from_secs(2))
        .build();
    handle_a.send(interest).await.expect("inject interest");
    assert!(
        recv_timeout(&handle_a).await.as_ref().is_some_and(is_data),
        "AdmitAll must cache unsolicited Data so a later Interest is served from CS"
    );

    shutdown.shutdown().await;
}

/// `DropAll` (default): unsolicited Data is not cached, so a later Interest has
/// no CS hit — no Data comes back to the consumer.
#[tokio::test]
async fn drop_all_does_not_cache_unsolicited_data() {
    let (face_a, handle_a) = InProcFace::new(FaceId(FACE_A), 128);
    let (face_b, handle_b) = InProcFace::new(FaceId(FACE_B), 128);

    let (_engine, shutdown) = EngineBuilder::new(EngineConfig::default()) // default DropAll
        .face(face_a)
        .face(face_b)
        .build()
        .await
        .expect("engine build");

    let data = DataBuilder::new("/u/obj2", b"payload")
        .freshness(Duration::from_secs(60))
        .sign_digest_sha256();
    handle_b.send(data).await.expect("inject data");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let interest = InterestBuilder::new("/u/obj2")
        .lifetime(Duration::from_secs(2))
        .build();
    handle_a.send(interest).await.expect("inject interest");
    let got = recv_timeout(&handle_a).await;
    assert!(
        got.as_ref().is_none_or(|w| !is_data(w)),
        "DropAll must not cache unsolicited Data; the later Interest must not be served from CS"
    );

    shutdown.shutdown().await;
}

/// Ad-hoc carve-out (suppression half): on a point-to-point face, forwarded
/// Data is not echoed back out the face it arrived on. Here face A both
/// expresses the Interest (PIT in-record = A) and later delivers the Data; the
/// Data must NOT be echoed back to A.
#[tokio::test]
async fn data_not_echoed_back_out_point_to_point_ingress() {
    let (face_a, handle_a) = InProcFace::new(FaceId(FACE_A), 128);
    let (face_b, handle_b) = InProcFace::new(FaceId(FACE_B), 128);

    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(face_a)
        .face(face_b)
        .build()
        .await
        .expect("engine build");

    // Route /echo toward face B so the Interest from A forwards (PIT in-record A).
    let prefix: Name = "/echo".parse().unwrap();
    engine.fib().add_nexthop(&prefix, FaceId(FACE_B), 0);

    let interest = InterestBuilder::new("/echo/x")
        .lifetime(Duration::from_secs(2))
        .build();
    handle_a.send(interest).await.expect("inject interest");
    // Drain the forwarded Interest on B so it doesn't confuse later reads.
    let _ = recv_timeout(&handle_b).await;

    // Data arrives on face A — the same face that holds the PIT in-record.
    // The carve-out must suppress echoing it back out A (point-to-point).
    let data = DataBuilder::new("/echo/x", b"payload").sign_digest_sha256();
    handle_a.send(data).await.expect("inject data");
    let got = recv_timeout(&handle_a).await;
    assert!(
        got.as_ref().is_none_or(|w| !is_data(w)),
        "Data must not be echoed back out the point-to-point face it arrived on"
    );

    shutdown.shutdown().await;
}

/// Ad-hoc carve-out (exception half): on an ad-hoc link, forwarded Data IS
/// re-radiated back out the face it arrived on, so other listeners on the
/// shared medium (including the node we relay for) can hear it
/// (NFD `forwarder.cpp:383`, the `!= LINK_TYPE_AD_HOC` exemption).
#[tokio::test]
async fn data_echoed_back_out_adhoc_ingress() {
    let (inner_a, handle_a) = InProcFace::new(FaceId(FACE_A), 128);
    let (face_b, handle_b) = InProcFace::new(FaceId(FACE_B), 128);
    let face_a = adhoc::AdHocFace(inner_a);

    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(face_a)
        .face(face_b)
        .build()
        .await
        .expect("engine build");

    let prefix: Name = "/echo".parse().unwrap();
    engine.fib().add_nexthop(&prefix, FaceId(FACE_B), 0);

    let interest = InterestBuilder::new("/echo/x")
        .lifetime(Duration::from_secs(2))
        .build();
    handle_a.send(interest).await.expect("inject interest");
    let _ = recv_timeout(&handle_b).await;

    let data = DataBuilder::new("/echo/x", b"payload").sign_digest_sha256();
    handle_a.send(data).await.expect("inject data");
    let got = recv_timeout(&handle_a).await;
    assert!(
        got.as_ref().is_some_and(is_data),
        "on an ad-hoc link, Data must be re-radiated back out the ingress face"
    );

    shutdown.shutdown().await;
}
