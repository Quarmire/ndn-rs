//! CopeMesh auto-installation: from a neighbor set, install one egress member
//! face per neighbor + an ingress face on a live engine, with a report/flush
//! ticker. Gated by `f3-link-mesh`.

#![cfg(feature = "f3-link-mesh")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use ndn_app::EngineBuilder;
use ndn_engine::EngineConfig;
use ndn_transport::{FaceError, FaceId, FaceKind, Transport};

use ndn_coding::cope::{CopeWire, decode_wire};
use ndn_coding::cope_mesh::CopeMesh;

/// A broadcast transport that captures everything sent (the shared medium),
/// and whose receive parks (this test exercises egress + installation).
struct Capture {
    id: FaceId,
    sent: Arc<Mutex<Vec<Bytes>>>,
}
impl Transport for Capture {
    fn id(&self) -> FaceId {
        self.id
    }
    fn kind(&self) -> FaceKind {
        FaceKind::EtherMulticast
    }
    async fn send_bytes(&self, pkt: Bytes) -> Result<(), FaceError> {
        self.sent.lock().unwrap().push(pkt);
        Ok(())
    }
    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        std::future::pending().await
    }
}

#[tokio::test]
async fn mesh_installs_member_faces_and_codes_over_engine() {
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .build()
        .await
        .expect("engine build");

    let sent = Arc::new(Mutex::new(Vec::new()));
    let capture = Capture {
        id: FaceId(1000),
        sent: Arc::clone(&sent),
    };

    let neighbors = [1u64, 2, 3];
    let mesh = CopeMesh::install(&engine, capture, 99, &neighbors);

    // Each neighbor maps to FaceId(neighbor), and the engine has those faces.
    for &n in &neighbors {
        assert_eq!(mesh.neighbor_face(n), Some(FaceId(n)));
        assert!(
            engine.faces().get(FaceId(n)).is_some(),
            "member face for neighbor {n} is registered"
        );
    }
    assert!(engine.faces().get(mesh.ingress_face_id()).is_some());
    assert_eq!(mesh.neighbor_face(999), None);

    // Reception report broadcast goes out over the shared medium.
    mesh.link().report(1, 7).await; // pretend neighbor 1 holds frame 7
    mesh.link().announce().await.unwrap();
    // Two natives to two neighbors, each holding the other → one coded frame.
    let id_a = mesh.link().enqueue(1, Bytes::from_static(b"to-one")).await;
    let id_b = mesh.link().enqueue(2, Bytes::from_static(b"to-two")).await;
    mesh.link().report(1, id_b).await;
    mesh.link().report(2, id_a).await;
    let (sent_n, coded_n) = mesh.link().flush().await.unwrap();
    assert_eq!((sent_n, coded_n), (1, 1), "the two natives coded into one");

    // The shared medium saw a report frame and a coded frame.
    let frames = sent.lock().unwrap().clone();
    assert!(
        frames
            .iter()
            .any(|f| matches!(decode_wire(f), Some(CopeWire::Report { .. }))),
        "announce() emitted a reception report"
    );
    assert!(
        frames
            .iter()
            .any(|f| matches!(decode_wire(f), Some(CopeWire::Coded(_)))),
        "flush() emitted a coded frame"
    );

    // The ticker runs without panicking and stops on drop.
    mesh.start_ticker(Duration::from_millis(10));
    tokio::time::sleep(Duration::from_millis(35)).await;
    drop(mesh);

    drop(engine);
    shutdown.shutdown().await;
}
