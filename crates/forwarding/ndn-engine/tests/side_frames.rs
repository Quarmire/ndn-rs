//! A side frame (first octet `SIDE_MARKER`) is peeled by the face reader before
//! the NDN pipeline: it is counted per face and dropped, never decoded, never
//! a PIT entry, never a malformed packet, never an inbound-queue drop, and it
//! changes nothing about the NDN packet that follows it on the same face.

use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::Bytes;
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::{InProcFace, InProcHandle};
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_transport::{FaceId, SIDE_MARKER};

const FACE_A: u64 = 1; // sends the side frame and the Interest
const FACE_B: u64 = 2; // the nexthop for the name

async fn recv_timeout(handle: &InProcHandle) -> Option<Bytes> {
    tokio::time::timeout(Duration::from_millis(300), handle.recv())
        .await
        .ok()
        .flatten()
}

#[tokio::test]
async fn a_marked_frame_never_enters_the_ndn_pipeline() {
    let (face_a, handle_a) = InProcFace::new(FaceId(FACE_A), 128);
    let (face_b, handle_b) = InProcFace::new(FaceId(FACE_B), 128);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(face_a)
        .face(face_b)
        .build()
        .await
        .expect("engine build");
    let prefix: Name = "/side/frames".parse().unwrap();
    engine.fib().add_nexthop(&prefix, FaceId(FACE_B), 0);

    // A marked frame, then a real Interest, on the same face.
    let mut marked = vec![0xC3; 40];
    marked[0] = SIDE_MARKER;
    marked[1] = 0x20;
    let marked = Bytes::from(marked);
    handle_a.send(marked.clone()).await.expect("inject frame");
    let name: Name = "/side/frames/x".parse().unwrap();
    let interest = InterestBuilder::new(name)
        .lifetime(Duration::from_secs(4))
        .build();
    handle_a.send(interest).await.expect("inject Interest");

    // The Interest is forwarded and recorded as before; nothing else reaches B
    // (the frame was not forwarded) and nothing comes back to A (no Nack).
    let forwarded = recv_timeout(&handle_b).await.expect("the Interest on B");
    assert_ne!(
        forwarded.first(),
        Some(&SIDE_MARKER),
        "B receives the Interest, not the frame"
    );
    assert!(recv_timeout(&handle_b).await.is_none(), "one packet on B");
    assert!(recv_timeout(&handle_a).await.is_none(), "no Nack on A");
    assert_eq!(engine.pit().len(), 1, "one PIT entry: the Interest's");

    {
        let states = engine.face_states();
        let a = states.get(&FaceId(FACE_A)).expect("face A state");
        let c = &a.counters;
        assert_eq!(c.in_side_frames.load(Ordering::Relaxed), 1);
        assert_eq!(c.in_side_bytes.load(Ordering::Relaxed), marked.len() as u64);
        assert_eq!(c.in_drops.load(Ordering::Relaxed), 0, "not an inbound drop");
        assert_eq!(
            c.in_interests.load(Ordering::Relaxed),
            1,
            "only the Interest went through the pipeline"
        );
        assert_eq!(c.out_nacks.load(Ordering::Relaxed), 0);
        let b = states.get(&FaceId(FACE_B)).expect("face B state");
        assert_eq!(b.counters.in_side_frames.load(Ordering::Relaxed), 0);
    }

    shutdown.shutdown().await;
}
