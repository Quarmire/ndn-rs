//! ARCH-15 / S17 — witness for `NotificationStream<T>`.
//!
//! Verifies that publishing a `FaceEvent` (or any `NotificationEvent`)
//! to the long-lived Producer at `/localhost/nfd/faces/notifications`
//! reaches a subscriber that issued a persistent Interest with
//! `seg=<N>`. The persistent-Interest pattern matches NFD's
//! `daemon/mgmt/notification-stream.hpp` (subscriber polls by sequence
//! number; producer holds the Interest until the next event lands).

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::InProcFace;
use ndn_mgmt::{FaceEvent, NotificationEvent, NotificationStream};
use ndn_packet::{Data, Name, encode::InterestBuilder};
use ndn_transport::FaceId;
use tokio_util::sync::CancellationToken;

const TEST_FACE_ID: FaceId = FaceId(99);

#[tokio::test]
async fn published_event_reaches_subscriber_by_segment() {
    let (test_face, test_handle) = InProcFace::new(TEST_FACE_ID, 64);
    let (engine, _shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(test_face)
        .build()
        .await
        .expect("engine build");
    let cancel = CancellationToken::new();

    let prefix: Name = "/localhost/nfd/faces/notifications".parse().unwrap();
    let stream = NotificationStream::<FaceEvent>::new(prefix.clone());
    Arc::clone(&stream).install(&engine, cancel.clone());

    // Give the producer a tick to register on the FIB.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Subscriber sends Interest for seg=1 BEFORE the event is
    // published — long-poll path.
    let pending_name = prefix.clone().append_sequence_num(1);
    let interest = InterestBuilder::new(pending_name.clone())
        .must_be_fresh()
        .lifetime(Duration::from_secs(3))
        .build();
    test_handle.send(interest).await.expect("send pending");

    // Wait a tick to ensure the producer has the Interest queued
    // before we publish.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Publish.
    stream.publish(FaceEvent::Created {
        face_id: FaceId(42),
    });

    // Receive the response.
    let wire = tokio::time::timeout(Duration::from_secs(2), test_handle.recv())
        .await
        .expect("response within 2s")
        .expect("response not None");

    let data = Data::decode(wire).expect("Data decode");
    assert_eq!(*data.name, pending_name, "Data name matches Interest");

    let content = data.content().cloned().unwrap_or(Bytes::new());
    let expected = FaceEvent::Created {
        face_id: FaceId(42),
    }
    .encode();
    assert_eq!(content, expected, "Data content matches published event");

    cancel.cancel();
}

#[tokio::test]
async fn cached_event_serves_immediately() {
    let (test_face, test_handle) = InProcFace::new(TEST_FACE_ID, 64);
    let (engine, _shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(test_face)
        .build()
        .await
        .expect("engine build");
    let cancel = CancellationToken::new();

    let prefix: Name = "/localhost/nfd/faces/notifications".parse().unwrap();
    let stream = NotificationStream::<FaceEvent>::new(prefix.clone());
    Arc::clone(&stream).install(&engine, cancel.clone());
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Publish first.
    stream.publish(FaceEvent::Destroyed { face_id: FaceId(7) });
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Then subscribe — should hit the ring cache.
    let name = prefix.clone().append_sequence_num(1);
    let interest = InterestBuilder::new(name.clone())
        .must_be_fresh()
        .lifetime(Duration::from_secs(3))
        .build();
    test_handle.send(interest).await.expect("send Interest");

    let wire = tokio::time::timeout(Duration::from_secs(2), test_handle.recv())
        .await
        .expect("response within 2s")
        .expect("response not None");
    let data = Data::decode(wire).expect("Data decode");
    assert_eq!(*data.name, name);
    cancel.cancel();
}

/// Phase-2b S17 — wire shape of `FaceEvent::encode` matches NFD's
/// `FaceEventNotification` TLV (0xC0) carrying `FaceEventKind` (0xC1)
/// and `FaceId` (0x69). Reference: ndn-cxx
/// `mgmt/nfd/face-event-notification.hpp:62-78`.
#[test]
fn face_event_wire_shape_matches_nfd_tlv() {
    let event = FaceEvent::Created {
        face_id: FaceId(257),
    };
    let wire = event.encode();
    // FaceEventNotification(0xC0) length=7 {
    //   FaceEventKind(0xC1) length=1 value=1     (3 bytes)
    //   FaceId(0x69) length=2 value=0x0101       (4 bytes)
    // }
    assert_eq!(
        wire.as_ref(),
        &[0xC0, 0x07, 0xC1, 0x01, 0x01, 0x69, 0x02, 0x01, 0x01]
    );

    let destroyed = FaceEvent::Destroyed {
        face_id: FaceId(42),
    }
    .encode();
    // FaceEventNotification(0xC0) length=6 {
    //   FaceEventKind(0xC1) length=1 value=2     (3 bytes)
    //   FaceId(0x69) length=1 value=0x2A         (3 bytes)
    // }
    assert_eq!(
        destroyed.as_ref(),
        &[0xC0, 0x06, 0xC1, 0x01, 0x02, 0x69, 0x01, 0x2A]
    );
}
