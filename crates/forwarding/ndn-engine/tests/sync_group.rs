//! A namespace's sync group (`/<O>/32=sync`) crosses a link with no route or
//! strategy for it: the member's own registration of the group does not hide
//! the link routed toward the namespace's other device (data-layer spec §12).

use std::time::Duration;

use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::{InProcFace, InProcHandle};
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_transport::{FaceId, FaceKind};

const SYNC: u64 = 1;
const PHONE: u64 = 2;

/// How long a forwarded packet may take to come out (a failure bound only).
async fn recv_within(h: &InProcHandle) -> Option<bytes::Bytes> {
    tokio::time::timeout(Duration::from_secs(2), h.recv())
        .await
        .ok()
        .flatten()
}

#[tokio::test]
async fn a_group_registered_by_its_member_still_reaches_the_namespaces_other_device() {
    let (sync, sync_h) = InProcFace::new(FaceId(SYNC), 16);
    let (phone, phone_h) = InProcFace::new_kind(FaceId(PHONE), 16, FaceKind::Udp);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(sync)
        .face(phone)
        .build()
        .await
        .expect("engine build");
    let group: Name = "/nt/32=sync".parse().unwrap();
    // What the member registers, and what the link layer routes: the other
    // device by its name. Nothing routes the group toward the phone.
    engine.fib().add_nexthop(&group, FaceId(SYNC), 0);
    engine
        .fib()
        .add_nexthop(&"/nt/member/phone".parse().unwrap(), FaceId(PHONE), 10);

    let out = InterestBuilder::new(group.clone().append("laptop")).build();
    sync_h.send(out).await.unwrap();
    assert!(
        recv_within(&phone_h).await.is_some(),
        "the member's Sync Interest goes over the link toward the namespace"
    );

    let back = InterestBuilder::new(group.append("phone")).build();
    phone_h.send(back).await.unwrap();
    assert!(
        recv_within(&sync_h).await.is_some(),
        "the other device's Sync Interest reaches the member"
    );

    shutdown.shutdown().await;
}
