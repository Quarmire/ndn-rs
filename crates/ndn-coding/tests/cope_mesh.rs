//! CopeMesh auto-installation + live routing feed: install one egress member
//! face per neighbor + an ingress face on a live engine, code over the medium,
//! and track routing neighbor-table changes via `sync_neighbors`. Neighbor ids
//! are engine-allocated (so they don't collide with the ingress face). Gated by
//! `f3-link-mesh`.

#![cfg(feature = "f3-link-mesh")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use ndn_app::EngineBuilder;
use ndn_engine::{EngineConfig, ForwarderEngine, ShutdownHandle};
use ndn_transport::{FaceError, FaceId, FaceKind, Transport};

use ndn_coding::cope::{CopeWire, decode_wire};
use ndn_coding::cope_mesh::CopeMesh;

/// A broadcast transport that captures everything sent; receive parks.
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

async fn engine() -> (ForwarderEngine, ShutdownHandle) {
    EngineBuilder::new(EngineConfig::default())
        .build()
        .await
        .expect("engine build")
}

#[tokio::test]
async fn mesh_installs_member_faces_and_codes_over_engine() {
    let (engine, shutdown) = engine().await;
    // Engine-allocated neighbor ids (won't collide with the ingress face).
    let neighbors = [
        engine.faces().alloc_id().0,
        engine.faces().alloc_id().0,
        engine.faces().alloc_id().0,
    ];
    let sent = Arc::new(Mutex::new(Vec::new()));
    let capture = Capture {
        id: engine.faces().alloc_id(),
        sent: Arc::clone(&sent),
    };
    let mesh = CopeMesh::install(&engine, capture, 9999, &neighbors);

    for &n in &neighbors {
        assert_eq!(mesh.neighbor_face(n), Some(FaceId(n)));
        assert!(engine.faces().get(FaceId(n)).is_some());
    }
    assert!(engine.faces().get(mesh.ingress_face_id()).is_some());

    // Two natives to two neighbors, each holding the other → one coded frame.
    let id_a = mesh
        .link()
        .enqueue(neighbors[0], Bytes::from_static(b"to-a"))
        .await;
    let id_b = mesh
        .link()
        .enqueue(neighbors[1], Bytes::from_static(b"to-b"))
        .await;
    mesh.link().report(neighbors[0], id_b).await;
    mesh.link().report(neighbors[1], id_a).await;
    mesh.link().announce().await.unwrap();
    let (sent_n, coded_n) = mesh.link().flush().await.unwrap();
    assert_eq!((sent_n, coded_n), (1, 1));

    let frames = sent.lock().unwrap().clone();
    assert!(
        frames
            .iter()
            .any(|f| matches!(decode_wire(f), Some(CopeWire::Report { .. })))
    );
    assert!(
        frames
            .iter()
            .any(|f| matches!(decode_wire(f), Some(CopeWire::Coded(_))))
    );

    drop(mesh);
    drop(engine);
    shutdown.shutdown().await;
}

#[tokio::test]
async fn mesh_tracks_routing_neighbor_changes() {
    let (engine, shutdown) = engine().await;
    let (n1, n2) = (engine.faces().alloc_id().0, engine.faces().alloc_id().0);
    let capture = Capture {
        id: engine.faces().alloc_id(),
        sent: Arc::new(Mutex::new(Vec::new())),
    };
    let mut mesh = CopeMesh::install(&engine, capture, 9999, &[n1, n2]);
    assert!(engine.faces().get(FaceId(n1)).is_some());
    assert!(engine.faces().get(FaceId(n2)).is_some());

    // Routing update: n1 drops, n3 appears.
    let n3 = engine.faces().alloc_id().0;
    mesh.sync_neighbors(&[n2, n3]);

    assert_eq!(mesh.neighbor_face(n1), None);
    assert!(
        engine.faces().get(FaceId(n1)).is_none(),
        "dropped member face evicted"
    );
    assert_eq!(mesh.neighbor_face(n3), Some(FaceId(n3)));
    assert!(engine.faces().get(FaceId(n3)).is_some());

    // add_neighbor is idempotent.
    assert_eq!(mesh.add_neighbor(n2), FaceId(n2));
    let mut ns = mesh.neighbors();
    ns.sort_unstable();
    let mut want = [n2, n3];
    want.sort_unstable();
    assert_eq!(ns, want);

    // Ticker runs without panicking; drop stops it and reaps the faces.
    mesh.start_ticker(Duration::from_millis(10));
    tokio::time::sleep(Duration::from_millis(25)).await;
    drop(mesh);
    drop(engine);
    shutdown.shutdown().await;
}

/// The neighbor-sync driver reconciles the mesh from a routing protocol's
/// neighbor-change stream (a `watch<Vec<NeighborId>>` an adapter feeds from,
/// e.g., NLSR's `adjacency_watch`). ndn-coding stays decoupled from any
/// routing crate; here we drive the watch directly to model routing updates.
#[tokio::test]
async fn neighbor_sync_driver_tracks_routing_stream() {
    let (engine, shutdown) = engine().await;
    let n1 = engine.faces().alloc_id().0;
    let n2 = engine.faces().alloc_id().0;
    let n3 = engine.faces().alloc_id().0;
    let capture = Capture {
        id: engine.faces().alloc_id(),
        sent: Arc::new(Mutex::new(Vec::new())),
    };
    let mesh = CopeMesh::install(&engine, capture, 9999, &[]); // start empty
    let cancel = mesh.cancel_token();
    let mesh = Arc::new(tokio::sync::Mutex::new(mesh));

    let (tx, rx) = tokio::sync::watch::channel(Vec::<u64>::new());
    CopeMesh::spawn_neighbor_sync(Arc::clone(&mesh), rx, cancel);

    // Routing reports {n1, n2} active.
    tx.send(vec![n1, n2]).unwrap();
    tokio::time::sleep(Duration::from_millis(40)).await;
    {
        let g = mesh.lock().await;
        assert_eq!(g.neighbor_face(n1), Some(FaceId(n1)));
        assert_eq!(g.neighbor_face(n2), Some(FaceId(n2)));
    }
    assert!(engine.faces().get(FaceId(n1)).is_some());

    // Routing update: n1 drops, n3 appears.
    tx.send(vec![n2, n3]).unwrap();
    tokio::time::sleep(Duration::from_millis(40)).await;
    {
        let g = mesh.lock().await;
        assert_eq!(g.neighbor_face(n1), None, "dropped neighbor removed");
        assert_eq!(
            g.neighbor_face(n3),
            Some(FaceId(n3)),
            "new neighbor installed"
        );
    }
    assert!(engine.faces().get(FaceId(n1)).is_none());
    assert!(engine.faces().get(FaceId(n3)).is_some());

    drop(tx); // routing stream closes → driver task exits
    drop(mesh);
    drop(engine);
    shutdown.shutdown().await;
}
