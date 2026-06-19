//! Tier-0 RPC latency experiment.
//!
//! ```sh
//! cargo run -p example-tier0-rpc-latency --release            # 20k calls
//! cargo run -p example-tier0-rpc-latency --release -- 50000   # custom count
//! ```
//!
//! # What this measures and why
//!
//! The v2 service-layer thesis is that NDNSF's ~166 ms latency floor is
//! *structural*, not a crypto or code cost: it routes point-to-point RPC through
//! a multi-party sync-pub/sub layer, so every call pays four one-way SVS/NFD
//! delivery legs (~46–50 ms each) for what should be one Interest -> Data
//! exchange. The v2 design inverts the default: **a call to a known provider is
//! one signed Interest -> one signed, verified Data — ~1 RTT.**
//!
//! The justification for the design is *structural* — one Interest/Data RTT vs
//! four sync-convergence legs — not a benchmark. This harness only establishes
//! that the Tier-0 path's **software floor** is negligible: that the cost of a
//! secure call is dominated by transport, not by PIT/FIB dispatch, signing, or
//! verification. It runs the engine in-process over an [`InProcFace`] pair,
//! which isolates that software cost from network transport. It is deliberately
//! NOT a cross-stack speedup figure: a fair comparison against NDNSF requires
//! both stacks on the same testbed, and even then the numbers are supporting
//! evidence, not the primary argument.
//!
//! Each iteration uses a **unique name** (`/svc/echo/<seq>`) so the Content
//! Store never short-circuits the round-trip — every call genuinely reaches the
//! producer, which signs a fresh Data each time (a realistic per-call producer
//! cost). Two configs are timed so the verification cost is attributable:
//!
//! * **verified**   = transport + dispatch + producer-sign + consumer-verify
//!   (the honest cost of a secure service call)
//! * **unverified** = transport + dispatch + producer-sign
//!   (the same, minus the consumer's signature check)
//!
//! `verified − unverified ≈ consumer-side verify cost`.
//!
//! No NDNSF baseline is run or quoted here: their C++ stack (ndn-cxx + openabe)
//! is not built on this machine, and a cross-stack ratio is only meaningful with
//! both stacks on the same testbed. The output is an absolute software floor.

use std::time::Instant;

use ndn_app::{Consumer, EngineBuilder, Producer};
use ndn_engine::EngineConfig;
use ndn_face::local::InProcFace;
use ndn_packet::Name;
use ndn_packet::encode::DataBuilder;
use ndn_security::{KeyChain, SignWith};
use ndn_transport::FaceId;

const WARMUP: usize = 1_000;
const DEFAULT_ITERS: usize = 20_000;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let iters: usize = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(DEFAULT_ITERS);

    // Provider identity; its self-signed cert is the anchor the caller pins.
    let server_kc = KeyChain::ephemeral("/svc/server")?;
    let signer = server_kc.signer()?;

    // In-process engine: one face for the caller, one for the provider, and a
    // route sending /svc Interests to the provider face.
    let (consumer_face, consumer_handle) = InProcFace::new(FaceId(1), 256);
    let (producer_face, producer_handle) = InProcFace::new(FaceId(2), 256);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(consumer_face)
        .face(producer_face)
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("engine build: {e}"))?;
    let svc_prefix: Name = "/svc".parse()?;
    engine.fib().add_nexthop(&svc_prefix, FaceId(2), 0);

    let consumer = Consumer::from_handle(consumer_handle);
    let producer = Producer::from_handle(producer_handle, svc_prefix.clone());

    // The provider: a minimal "echo" service. Each call's request is encoded in
    // the Interest name; the provider returns a small signed Data response.
    let producer_task = tokio::spawn(async move {
        producer
            .serve(move |interest, responder| {
                let name = (*interest.name).clone();
                let signer = signer.clone();
                async move {
                    let wire = DataBuilder::new(name, b"tier0-response-payload-64-bytes-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
                        .sign_with_sync(&*signer)
                        .expect("sign");
                    responder.respond_bytes(wire).await.ok();
                }
            })
            .await
    });

    // --- verified config: signed Data + consumer verification (secure call) ---
    // `verifying(self)` consumes the raw consumer; its `unverified()` later hands
    // back the underlying `&mut Consumer` for the no-verify config.
    let mut vc = consumer.verifying(server_kc.validator());
    // Warm up: build the consumer connection, prime caches, JIT the path.
    for i in 0..WARMUP {
        let n: Name = format!("/svc/echo/warm/{i}").parse()?;
        vc.fetch(n).await.map_err(|e| anyhow::anyhow!("warmup: {e}"))?;
    }
    let mut verified = Vec::with_capacity(iters);
    for i in 0..iters {
        let n: Name = format!("/svc/echo/v/{i}").parse()?;
        let t = Instant::now();
        let _safe = vc.fetch(n).await.map_err(|e| anyhow::anyhow!("verified: {e}"))?;
        verified.push(t.elapsed().as_nanos());
    }

    // --- unverified config: signed Data, no consumer verify ---
    // The raw consumer's `fetch` returns `Data` (round-trip, no signature check).
    let uc = vc.unverified();
    for i in 0..WARMUP {
        let n: Name = format!("/svc/echo/uwarm/{i}").parse()?;
        uc.fetch(n).await.map_err(|e| anyhow::anyhow!("uwarmup: {e}"))?;
    }
    let mut unverified = Vec::with_capacity(iters);
    for i in 0..iters {
        let n: Name = format!("/svc/echo/u/{i}").parse()?;
        let t = Instant::now();
        let _u = uc
            .fetch(n)
            .await
            .map_err(|e| anyhow::anyhow!("unverified: {e}"))?;
        unverified.push(t.elapsed().as_nanos());
    }

    drop(vc);
    drop(engine);
    shutdown.shutdown().await;
    let _ = producer_task.await;

    report("verified  (sign+RTT+verify)", &mut verified, iters);
    report("unverified (sign+RTT)      ", &mut unverified, iters);
    attribute(&verified, &unverified);
    Ok(())
}

fn pct(sorted: &[u128], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((p / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx] as f64 / 1_000.0 // ns -> µs
}

fn report(label: &str, d: &mut [u128], iters: usize) {
    d.sort_unstable();
    let mean = d.iter().sum::<u128>() as f64 / d.len().max(1) as f64 / 1_000.0;
    let p50 = pct(d, 50.0);
    let p90 = pct(d, 90.0);
    let p99 = pct(d, 99.0);
    println!(
        "{label}  n={iters:>6}  mean={mean:8.1}µs  p50={p50:8.1}µs  p90={p90:8.1}µs  p99={p99:8.1}µs"
    );
}

fn attribute(verified: &[u128], unverified: &[u128]) {
    let med = |d: &[u128]| {
        let mut v = d.to_vec();
        v.sort_unstable();
        pct(&v, 50.0)
    };
    let verify_cost = med(verified) - med(unverified);
    println!(
        "\nattribution: consumer-verify ≈ {verify_cost:.1}µs (verified p50 − unverified p50). \
         A signed-Interest request (capability PoP) would add ~one more verify of this order on the provider."
    );
}
