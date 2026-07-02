//! G1 closed loop, end-to-end through the engine: NDNLPv2 congestion marks on
//! returning Data are bridged into per-face [`LinkSignals::congestion`], which the
//! `congestion-aware` strategy reads. This drives the *engine* path — the
//! `data_pipeline` hot-path hook records marks, and the background congestion source
//! decays them into the shared signal store — complementing the unit tests of the
//! classification/decay logic in `ndn-strategy`.

use std::time::Duration;

use ndn_engine::{EngineBuilder, EngineConfig, SignalView};
use ndn_face_local::InProcFace;
use ndn_packet::encode::DataBuilder;
use ndn_packet::lp::{LpHeaders, encode_lp_with_headers};
use ndn_strategy::{CongestionConfig, CongestionLevel};
use ndn_transport::{FaceId, FaceKind};

const FACE_B: u64 = 2; // the upstream face whose returning Data carry marks

/// Inject several congestion-marked Data on a face; after a decay window the bridge
/// raises that face's `LinkSignals.congestion`. A later quiet window clears it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn marks_raise_then_decay_face_congestion() {
    // Tcp kind ⇒ the face uses LP framing, so inbound LP fields are decoded.
    let (face_b, handle_b) = InProcFace::new_kind(FaceId(FACE_B), 128, FaceKind::Tcp);

    let cfg = CongestionConfig {
        window: Duration::from_millis(80),
        medium: 2,
        high: 100,
    };
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(face_b)
        .with_congestion_feedback_config(cfg)
        .build()
        .await
        .expect("engine build");

    let signals = engine.signals();
    assert_eq!(
        signals.link(FaceId(FACE_B)).and_then(|l| l.congestion),
        None,
        "no congestion before any marks"
    );

    // Inject 5 congestion-marked Data on face B (unsolicited is fine — the bridge
    // records the link-level mark at the top of the data pipeline).
    for i in 0..5u32 {
        let name = format!("/cf/{i}");
        let data = DataBuilder::new(name.as_str(), b"x").sign_digest_sha256();
        let wire = encode_lp_with_headers(
            &data,
            &LpHeaders {
                congestion_mark: Some(1),
                ..Default::default()
            },
        );
        handle_b.send(wire).await.expect("inject marked data");
    }

    // Wait for the congestion source to poll (>1 window) and raise the level.
    let raised = wait_until(Duration::from_secs(2), || {
        signals
            .link(FaceId(FACE_B))
            .and_then(|l| l.congestion)
            .is_some()
    })
    .await;
    assert!(raised, "marks must raise the face's congestion signal");
    assert!(
        signals.link(FaceId(FACE_B)).and_then(|l| l.congestion) >= Some(CongestionLevel::Medium),
        "5 marks (>= medium threshold 2) ⇒ at least Medium"
    );

    // No further marks ⇒ the next window decays congestion back to clear.
    let cleared = wait_until(Duration::from_secs(2), || {
        signals
            .link(FaceId(FACE_B))
            .and_then(|l| l.congestion)
            .is_none()
    })
    .await;
    assert!(cleared, "congestion must decay to clear once marks stop");

    shutdown.shutdown().await;
}

/// Poll `cond` until true or `budget` elapses.
async fn wait_until(budget: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < budget {
        if cond() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    cond()
}
