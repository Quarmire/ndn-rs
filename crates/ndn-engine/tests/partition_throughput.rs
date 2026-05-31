//! Crypto-bound throughput harness: shared vs partitioned(N) with per-packet
//! Data validation engaged. Decides whether private per-worker PITs (Phase 2b)
//! are worth pursuing — by measuring whether the partitioned fixed-worker +
//! NDT-affinity model beats the shared per-packet-spawn model under per-packet
//! CPU load.
//!
//! Validation is forced even on Local faces via `require_data_validation`, so
//! the forwarder SHA-256-verifies every Data through the real `ValidationStage`
//! (DigestSha256 self-validates against the default accept-all validator — no
//! trust chain needed). Ed25519 would amplify the per-packet cost, so any
//! partitioned win here is a lower bound on the crypto-heavy case.
//!
//! `#[ignore]` — a benchmark, not a correctness test. Run on a quiet multi-core
//! box (NOT macOS/loopback for absolute numbers):
//!
//!   cargo test -p ndn-engine --features partitioned-fwd --release \
//!     --test partition_throughput -- --ignored --nocapture
//!
//! Env: DURATION_MS=3000 WINDOW=512 SIZE=8192 WORKERS_LIST=1,2,4,8 VALIDATE=1
#![cfg(feature = "partitioned-fwd")]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ndn_engine::{DataPlane, EngineBuilder, EngineConfig};
use ndn_face_local::InProcFace;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Interest, Name};
use ndn_transport::FaceId;

const FACE_A: u64 = 1; // consumer
const FACE_B: u64 = 2; // producer

fn env_u64(k: &str, d: u64) -> u64 {
    std::env::var(k)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(d)
}

/// Decode an Interest from a (possibly LP-wrapped) forwarded wire.
fn interest_name(wire: &bytes::Bytes) -> Option<Name> {
    if let Ok(i) = Interest::decode(wire.clone()) {
        return Some((*i.name).clone());
    }
    let lp = ndn_packet::lp::LpPacket::decode(wire.clone()).ok()?;
    let frag = lp.fragment?;
    Interest::decode(frag).ok().map(|i| (*i.name).clone())
}

fn is_data_wire(wire: &bytes::Bytes) -> bool {
    const T_DATA: u8 = 0x06;
    if wire.first() == Some(&T_DATA) {
        return true;
    }
    ndn_packet::lp::LpPacket::decode(wire.clone())
        .ok()
        .and_then(|lp| lp.fragment)
        .is_some_and(|f| f.first() == Some(&T_DATA))
}

/// Measure satisfied-Data throughput (Gbps) for one runtime configuration.
async fn measure(data_plane: DataPlane, validate: bool) -> f64 {
    let duration = Duration::from_millis(env_u64("DURATION_MS", 3000));
    let window = env_u64("WINDOW", 512) as usize;
    let size = env_u64("SIZE", 8192) as usize;

    let (face_a, handle_a) = InProcFace::new(FaceId(FACE_A), 8192);
    let (face_b, handle_b) = InProcFace::new(FaceId(FACE_B), 8192);
    let config = EngineConfig {
        data_plane,
        ..Default::default()
    };
    let (engine, shutdown) = EngineBuilder::new(config)
        .face(face_a)
        .face(face_b)
        .build()
        .await
        .expect("engine build");

    if validate {
        // Force the forwarder to verify every Data even though B is Local.
        engine.set_require_data_validation(FaceId(FACE_B), true);
    }
    engine
        .fib()
        .add_nexthop(&"/t".parse::<Name>().unwrap(), FaceId(FACE_B), 0);

    let stop = Arc::new(AtomicBool::new(false));
    let payload = vec![0u8; size];

    // Producer: echo each forwarded Interest with a DigestSha256 Data.
    let producer = {
        let stop = Arc::clone(&stop);
        let payload = payload.clone();
        tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                let Some(raw) = tokio::time::timeout(Duration::from_millis(200), handle_b.recv())
                    .await
                    .ok()
                    .flatten()
                else {
                    continue;
                };
                if let Some(name) = interest_name(&raw) {
                    let data = DataBuilder::new(name, payload.as_slice()).sign_digest_sha256();
                    let _ = handle_b.send(data).await;
                }
            }
        })
    };

    let count = Arc::new(AtomicU64::new(0));
    let mut seq: u64 = 0;
    let send_interest = |seq: u64| -> bytes::Bytes {
        let name: Name = format!("/t/{seq}").parse().expect("name");
        InterestBuilder::new(name)
            .lifetime(Duration::from_secs(4))
            .build()
    };

    // Prime the window.
    for _ in 0..window {
        handle_a.send(send_interest(seq)).await.unwrap();
        seq += 1;
    }

    let start = Instant::now();
    while start.elapsed() < duration {
        match tokio::time::timeout(Duration::from_millis(200), handle_a.recv()).await {
            Ok(Some(w)) if is_data_wire(&w) => {
                count.fetch_add(1, Ordering::Relaxed);
                handle_a.send(send_interest(seq)).await.unwrap();
                seq += 1;
            }
            Ok(Some(_)) => {}
            _ => break,
        }
    }
    let elapsed = start.elapsed();
    stop.store(true, Ordering::Relaxed);
    let _ = tokio::time::timeout(Duration::from_millis(300), producer).await;
    shutdown.shutdown().await;

    let n = count.load(Ordering::Relaxed);
    (n * size as u64 * 8) as f64 / elapsed.as_secs_f64() / 1e9
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "throughput benchmark; run with --ignored --release"]
async fn partition_throughput_sweep() {
    let validate = env_u64("VALIDATE", 1) == 1;
    let workers_list: Vec<usize> = std::env::var("WORKERS_LIST")
        .unwrap_or_else(|_| "1,2,4,8".into())
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    eprintln!(
        "=== partition throughput (validate={validate}, window={}, size={}B, {}ms) ===",
        env_u64("WINDOW", 512),
        env_u64("SIZE", 8192),
        env_u64("DURATION_MS", 3000),
    );

    let shared = measure(DataPlane::Shared, validate).await;
    eprintln!("  shared            : {shared:.2} Gbps");
    for &w in &workers_list {
        let g = measure(DataPlane::Partitioned { workers: w }, validate).await;
        eprintln!(
            "  partitioned(N={w}) : {g:.2} Gbps  ({:+.0}% vs shared)",
            100.0 * (g - shared) / shared
        );
    }
}
