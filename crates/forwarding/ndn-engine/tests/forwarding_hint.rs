//! NDNLPv2 ForwardingHint forwarding (NFD onIncomingInterest + NetworkRegionTable).
//! An Interest whose name has no route is forwarded toward its forwarding-hint
//! delegation instead — unless the hint has reached this forwarder (a
//! configured producer region or an ancestor of one, or one of its own names
//! or a name under one), in which case the hint is stripped and the Interest
//! name is used.

use std::time::Duration;

use ndn_engine::stages::strategy::NetworkRegionTable;
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::{InProcFace, InProcHandle};
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_transport::FaceId;

const CONSUMER: u64 = 1;
const TARGET: u64 = 2;

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

/// No route for the Interest name, but a route for the hint delegation → the
/// Interest is forwarded toward the delegation.
#[tokio::test]
async fn forwarding_hint_routes_by_delegation() {
    let (fc, hc) = InProcFace::new(FaceId(CONSUMER), 128);
    let (ft, ht) = InProcFace::new(FaceId(TARGET), 128);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(fc)
        .face(ft)
        .build()
        .await
        .expect("engine build");
    // Route only for the hint delegation; the Interest name is unrouted.
    let hint: Name = "/hint".parse().unwrap();
    engine.fib().add_nexthop(&hint, FaceId(TARGET), 0);

    let i = InterestBuilder::new(ndn_packet::name!("/app/data"))
        .lifetime(Duration::from_secs(2))
        .forwarding_hint(vec![hint])
        .build();
    hc.send(i).await.unwrap();

    assert!(
        recv_timeout(&ht).await.as_ref().is_some_and(is_interest),
        "Interest must be forwarded toward the forwarding-hint delegation"
    );
    shutdown.shutdown().await;
}

/// With the delegation inside a configured producer region, the hint is
/// stripped → the (unrouted) Interest name is used → no route → not forwarded.
#[tokio::test]
async fn forwarding_hint_stripped_in_producer_region() {
    let cfg = EngineConfig {
        network_region: vec!["/hint".parse().unwrap()],
        ..Default::default()
    };
    let (fc, hc) = InProcFace::new(FaceId(CONSUMER), 128);
    let (ft, ht) = InProcFace::new(FaceId(TARGET), 128);
    let (engine, shutdown) = EngineBuilder::new(cfg)
        .face(fc)
        .face(ft)
        .build()
        .await
        .expect("engine build");
    let hint: Name = "/hint".parse().unwrap();
    engine.fib().add_nexthop(&hint, FaceId(TARGET), 0);

    let i = InterestBuilder::new(ndn_packet::name!("/app/data"))
        .lifetime(Duration::from_secs(2))
        .forwarding_hint(vec![hint])
        .build();
    hc.send(i).await.unwrap();

    assert!(
        recv_timeout(&ht).await.is_none(),
        "in producer region the hint is stripped; unrouted Interest name is not forwarded"
    );
    shutdown.shutdown().await;
}

/// The hint reached a producer region of this forwarder and the Interest
/// name is routed: the Interest goes on by its name, without its hint, so
/// the next forwarder (outside the region) forwards it by name too rather
/// than back toward the delegation (NFD strips it in `onIncomingInterest`).
#[tokio::test]
async fn forwarding_hint_in_producer_region_goes_on_by_name_without_it() {
    let cfg = EngineConfig {
        network_region: vec!["/hint".parse().unwrap()],
        ..Default::default()
    };
    let (fc, hc) = InProcFace::new(FaceId(CONSUMER), 128);
    let (ft, ht) = InProcFace::new(FaceId(TARGET), 128);
    let (engine, shutdown) = EngineBuilder::new(cfg)
        .face(fc)
        .face(ft)
        .build()
        .await
        .expect("engine build");
    engine
        .fib()
        .add_nexthop(&"/app".parse().unwrap(), FaceId(TARGET), 0);

    let i = InterestBuilder::new(ndn_packet::name!("/app/data"))
        .lifetime(Duration::from_secs(2))
        .forwarding_hint(vec!["/hint".parse().unwrap()])
        .build();
    hc.send(i).await.unwrap();

    let out = recv_timeout(&ht)
        .await
        .filter(is_interest)
        .expect("the Interest is forwarded by its name");
    let fragment = match ndn_packet::lp::LpPacket::decode(out.clone()) {
        Ok(lp) => lp.fragment.expect("an Interest fragment"),
        Err(_) => out,
    };
    let forwarded = ndn_packet::Interest::decode(fragment).unwrap();
    assert_eq!(forwarded.name.to_string(), "/app/data");
    assert!(
        forwarded.forwarding_hint().is_none(),
        "the hint is stripped once it reached the producer region"
    );
    shutdown.shutdown().await;
}

const DEVICE: u64 = 3;

/// The Interest a face received, LP header taken off.
fn interest_out(wire: bytes::Bytes) -> ndn_packet::Interest {
    let fragment = match ndn_packet::lp::LpPacket::decode(wire.clone()) {
        Ok(lp) => lp.fragment.expect("an Interest fragment"),
        Err(_) => wire,
    };
    ndn_packet::Interest::decode(fragment).unwrap()
}

/// A forwarder for the device `/ns/member/dev`, `declare` telling its table
/// of that name, with a route for `/ns` toward the namespace (`TARGET`,
/// where its CA is) and one for its own name toward its local producer
/// (`DEVICE`).
async fn device_forwarder(
    declare: impl FnOnce(&NetworkRegionTable, Name),
) -> (
    ndn_engine::ForwarderEngine,
    ndn_engine::ShutdownHandle,
    InProcHandle,
    InProcHandle,
    InProcHandle,
) {
    let (fc, hc) = InProcFace::new(FaceId(CONSUMER), 128);
    let (ft, ht) = InProcFace::new(FaceId(TARGET), 128);
    let (fd, hd) = InProcFace::new(FaceId(DEVICE), 128);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(fc)
        .face(ft)
        .face(fd)
        .build()
        .await
        .expect("engine build");
    declare(&engine.network_region(), "/ns/member/dev".parse().unwrap());
    engine
        .fib()
        .add_nexthop(&"/ns".parse().unwrap(), FaceId(TARGET), 0);
    engine
        .fib()
        .add_nexthop(&"/ns/member/dev".parse().unwrap(), FaceId(DEVICE), 0);
    (engine, shutdown, hc, ht, hd)
}

/// A hint naming an ancestor of this device's name (its namespace, served
/// by its CA elsewhere) has not reached this device: the Interest — here
/// the fetch of the device's own new certificate, a name under its own —
/// goes toward the delegation with its hint, not by name to the device.
#[tokio::test]
async fn forwarding_hint_naming_an_ancestor_of_the_device_is_kept_at_the_device() {
    let (_engine, shutdown, hc, ht, hd) =
        device_forwarder(|table, own| table.add_own_name(own)).await;
    let i = InterestBuilder::new(ndn_packet::name!("/ns/member/dev/KEY/k/NDNCERT/v=1"))
        .lifetime(Duration::from_secs(2))
        .forwarding_hint(vec!["/ns".parse().unwrap()])
        .build();
    hc.send(i).await.unwrap();

    let out = recv_timeout(&ht)
        .await
        .filter(is_interest)
        .expect("the Interest goes toward its hint's delegation");
    let forwarded = interest_out(out);
    assert_eq!(
        forwarded
            .forwarding_hint()
            .map(|h| h.iter().map(|d| d.to_string()).collect::<Vec<_>>()),
        Some(vec!["/ns".to_owned()]),
        "a hint naming the device's namespace has not reached the device: it stays"
    );
    assert!(
        recv_timeout(&hd).await.is_none(),
        "the Interest is not forwarded by name to the device's own producer"
    );
    shutdown.shutdown().await;
}

/// A hint naming this device, or a name under it, has reached it: the
/// Interest goes on by its name, without its hint.
#[tokio::test]
async fn forwarding_hint_naming_the_device_is_stripped_at_the_device() {
    for hint in ["/ns/member/dev", "/ns/member/dev/app"] {
        let (_engine, shutdown, hc, ht, hd) =
            device_forwarder(|table, own| table.add_own_name(own)).await;
        let i = InterestBuilder::new(ndn_packet::name!("/ns/member/dev/app/x"))
            .lifetime(Duration::from_secs(2))
            .forwarding_hint(vec![hint.parse().unwrap()])
            .build();
        hc.send(i).await.unwrap();

        let out = recv_timeout(&hd)
            .await
            .filter(is_interest)
            .unwrap_or_else(|| panic!("hint {hint}: the Interest is forwarded by its name"));
        assert!(
            interest_out(out).forwarding_hint().is_none(),
            "hint {hint}: stripped once it reached the device it names"
        );
        assert!(
            recv_timeout(&ht).await.is_none(),
            "hint {hint}: not toward /ns"
        );
        shutdown.shutdown().await;
    }
}

/// A region keeps NFD's sense: a hint naming an ancestor of a region this
/// forwarder is in (`/ns` of `/ns/member/dev`) has reached it, unlike an
/// ancestor of an own name.
#[tokio::test]
async fn forwarding_hint_naming_an_ancestor_of_a_region_is_stripped() {
    let (_engine, shutdown, hc, ht, hd) =
        device_forwarder(|table, region| table.add_region(region)).await;
    let i = InterestBuilder::new(ndn_packet::name!("/ns/member/dev/app/x"))
        .lifetime(Duration::from_secs(2))
        .forwarding_hint(vec!["/ns".parse().unwrap()])
        .build();
    hc.send(i).await.unwrap();

    let out = recv_timeout(&hd)
        .await
        .filter(is_interest)
        .expect("the Interest is forwarded by its name");
    assert!(interest_out(out).forwarding_hint().is_none());
    assert!(recv_timeout(&ht).await.is_none());
    shutdown.shutdown().await;
}
