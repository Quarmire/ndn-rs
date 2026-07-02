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
use ndn_transport::{FaceId, FaceKind};

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

/// Same in-process harness, but stamped as a multi-access link so Nack policy
/// can distinguish shared-medium feedback from point-to-point feedback.
mod multiaccess {
    use super::*;
    use bytes::Bytes;
    use ndn_transport::{
        FaceError, FaceKind, FacePersistency, LinkType, MtuError, PersistencyError, Transport,
    };

    pub struct MultiAccessFace(pub InProcFace);

    impl Transport for MultiAccessFace {
        fn id(&self) -> FaceId {
            self.0.id()
        }
        fn kind(&self) -> FaceKind {
            self.0.kind()
        }
        fn link_type(&self) -> LinkType {
            LinkType::MultiAccess
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
    if let Ok(lp) = LpPacket::decode(wire.clone())
        && let Some(frag) = lp.fragment
    {
        return frag.first() == Some(&T_DATA);
    }
    false
}

fn is_nack(wire: &bytes::Bytes) -> bool {
    ndn_packet::lp::LpPacket::decode(wire.clone())
        .ok()
        .is_some_and(|lp| lp.nack.is_some())
}

/// `AdmitAll`: unsolicited Data is cached, so a later Interest with no route is
/// answered from the Content Store.
#[tokio::test]
async fn n08_admit_all_caches_unsolicited_data_served_from_cs() {
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
async fn n08_drop_all_does_not_cache_unsolicited_data() {
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

/// `AdmitLocal`: cache only same-host unsolicited Data. This is the policy
/// split that the simple `AdmitAll`/`DropAll` tests cannot prove.
#[tokio::test]
async fn n08_admit_local_only_caches_local_unsolicited_data() {
    let (face_a, handle_a) = InProcFace::new(FaceId(FACE_A), 128);
    let (local_face, local_handle) = InProcFace::new(FaceId(FACE_B), 128);
    let (network_face, network_handle) = InProcFace::new_kind(FaceId(3), 128, FaceKind::Multicast);

    let (_engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .unsolicited_data_policy(UnsolicitedDataPolicy::AdmitLocal)
        .face(face_a)
        .face(local_face)
        .face(network_face)
        .build()
        .await
        .expect("engine build");

    let local_data = DataBuilder::new("/u/local", b"local")
        .freshness(Duration::from_secs(60))
        .sign_digest_sha256();
    local_handle
        .send(local_data)
        .await
        .expect("inject local data");

    let network_data = DataBuilder::new("/u/network", b"network")
        .freshness(Duration::from_secs(60))
        .sign_digest_sha256();
    network_handle
        .send(network_data)
        .await
        .expect("inject network data");
    tokio::time::sleep(Duration::from_millis(50)).await;

    handle_a
        .send(
            InterestBuilder::new("/u/local")
                .lifetime(Duration::from_secs(2))
                .build(),
        )
        .await
        .expect("inject local Interest");
    assert!(
        recv_timeout(&handle_a).await.as_ref().is_some_and(is_data),
        "AdmitLocal must cache unsolicited Data from a local face"
    );

    handle_a
        .send(
            InterestBuilder::new("/u/network")
                .lifetime(Duration::from_secs(2))
                .build(),
        )
        .await
        .expect("inject network Interest");
    let got = recv_timeout(&handle_a).await;
    assert!(
        got.as_ref().is_none_or(|w| !is_data(w)),
        "AdmitLocal must not cache unsolicited Data from a non-local face"
    );

    shutdown.shutdown().await;
}

/// `AdmitNetwork`: the broadcast/ad-hoc policy caches overheard network Data
/// but does not let a local app inject unsolicited cache entries.
#[tokio::test]
async fn n08_admit_network_only_caches_network_unsolicited_data() {
    let (face_a, handle_a) = InProcFace::new(FaceId(FACE_A), 128);
    let (local_face, local_handle) = InProcFace::new(FaceId(FACE_B), 128);
    let (network_face, network_handle) = InProcFace::new_kind(FaceId(3), 128, FaceKind::Multicast);

    let (_engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .unsolicited_data_policy(UnsolicitedDataPolicy::AdmitNetwork)
        .face(face_a)
        .face(local_face)
        .face(network_face)
        .build()
        .await
        .expect("engine build");

    let local_data = DataBuilder::new("/u/local2", b"local")
        .freshness(Duration::from_secs(60))
        .sign_digest_sha256();
    local_handle
        .send(local_data)
        .await
        .expect("inject local data");

    let network_data = DataBuilder::new("/u/network2", b"network")
        .freshness(Duration::from_secs(60))
        .sign_digest_sha256();
    network_handle
        .send(network_data)
        .await
        .expect("inject network data");
    tokio::time::sleep(Duration::from_millis(50)).await;

    handle_a
        .send(
            InterestBuilder::new("/u/local2")
                .lifetime(Duration::from_secs(2))
                .build(),
        )
        .await
        .expect("inject local Interest");
    let got = recv_timeout(&handle_a).await;
    assert!(
        got.as_ref().is_none_or(|w| !is_data(w)),
        "AdmitNetwork must not cache unsolicited Data from a local face"
    );

    handle_a
        .send(
            InterestBuilder::new("/u/network2")
                .lifetime(Duration::from_secs(2))
                .build(),
        )
        .await
        .expect("inject network Interest");
    assert!(
        recv_timeout(&handle_a).await.as_ref().is_some_and(is_data),
        "AdmitNetwork must cache unsolicited Data from a non-local face"
    );

    shutdown.shutdown().await;
}

/// N.09: a locally generated NoRoute Nack is point-to-point feedback. On a
/// multi-access ingress face it must be suppressed, because another listener on
/// the shared medium may still satisfy the Interest.
#[tokio::test]
async fn n09_no_route_nack_suppressed_on_multi_access_ingress() {
    let (inner_a, handle_a) = InProcFace::new(FaceId(FACE_A), 128);
    let face_a = multiaccess::MultiAccessFace(inner_a);

    let (_engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(face_a)
        .build()
        .await
        .expect("engine build");

    let interest = InterestBuilder::new("/n09/no-route")
        .lifetime(Duration::from_secs(2))
        .build();
    handle_a.send(interest).await.expect("inject interest");

    let got = recv_timeout(&handle_a).await;
    assert!(
        got.as_ref().is_none_or(|w| !is_nack(w)),
        "NoRoute Nack must not be emitted on a multi-access ingress face"
    );

    shutdown.shutdown().await;
}

/// N.09: an incoming Nack from a multi-access face must be ignored rather than
/// propagated to downstream PIT in-records.
#[tokio::test]
async fn n09_incoming_nack_on_multi_access_face_is_ignored() {
    let (face_a, handle_a) = InProcFace::new(FaceId(FACE_A), 128);
    let (inner_b, handle_b) = InProcFace::new(FaceId(FACE_B), 128);
    let face_b = multiaccess::MultiAccessFace(inner_b);

    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(face_a)
        .face(face_b)
        .build()
        .await
        .expect("engine build");

    let prefix: Name = "/n09".parse().unwrap();
    engine.fib().add_nexthop(&prefix, FaceId(FACE_B), 0);

    let interest = InterestBuilder::new("/n09/item")
        .lifetime(Duration::from_secs(2))
        .build();
    handle_a.send(interest).await.expect("inject interest");
    let forwarded = recv_timeout(&handle_b)
        .await
        .expect("Interest should forward to multi-access face");

    let nack = ndn_packet::lp::encode_lp_nack(ndn_packet::NackReason::NoRoute, &forwarded);
    handle_b.send(nack).await.expect("inject incoming Nack");

    let got = recv_timeout(&handle_a).await;
    assert!(
        got.as_ref().is_none_or(|w| !is_nack(w)),
        "Nack arriving from a multi-access face must not propagate downstream"
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
