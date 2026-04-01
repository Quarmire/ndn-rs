//! `ndn-traffic` — NDN traffic generator.
//!
//! Embeds a forwarding engine with producer/consumer `AppFace` pairs and
//! drives configurable Interest/Data traffic through the full pipeline.
//!
//! Usage:
//! ```text
//! ndn-traffic [--mode echo|sink] [--count N] [--rate PPS] [--size BYTES]
//!             [--prefix NAME] [--concurrency C]
//! ```

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::Bytes;
use clap::Parser;
use tokio::task::JoinSet;

use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::{AppFace, AppHandle};
use ndn_packet::encode::{encode_data_unsigned, encode_interest};
use ndn_packet::lp::is_lp_packet;
use ndn_packet::{Interest, Name};
use ndn_transport::FaceId;

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "ndn-traffic", about = "NDN traffic generator")]
struct Cli {
    /// Traffic mode: "echo" (producer replies with Data) or "sink" (no producer, all Nack).
    #[arg(long, default_value = "echo")]
    mode: String,

    /// Total number of Interests to send (split across flows).
    #[arg(long, default_value_t = 10_000)]
    count: u64,

    /// Target aggregate rate in packets/sec. 0 = unlimited.
    #[arg(long, default_value_t = 0)]
    rate: u64,

    /// Data payload size in bytes.
    #[arg(long, default_value_t = 1024)]
    size: usize,

    /// Name prefix for generated traffic.
    #[arg(long, default_value = "/traffic")]
    prefix: String,

    /// Number of parallel consumer flows.
    #[arg(long, default_value_t = 1)]
    concurrency: u64,
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn build_name(prefix: &Name, flow: u64, seq: u64) -> Name {
    prefix.clone()
        .append(format!("flow-{flow}"))
        .append(format!("{seq}"))
}

struct FlowResult {
    sent:     u64,
    received: u64,
    rtts:     Vec<u64>, // microseconds
}

fn print_stats(results: &[FlowResult], elapsed: Duration, size: usize) {
    let sent: u64 = results.iter().map(|r| r.sent).sum();
    let received: u64 = results.iter().map(|r| r.received).sum();
    let lost = sent.saturating_sub(received);
    let loss_pct = if sent > 0 {
        lost as f64 / sent as f64 * 100.0
    } else {
        0.0
    };

    let pps = if elapsed.as_secs_f64() > 0.0 {
        received as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };
    let mbps = pps * size as f64 * 8.0 / 1_000_000.0;

    println!("  sent={sent}  received={received}  lost={lost} ({loss_pct:.2}%)");
    println!("  throughput: {pps:.0} pps, {mbps:.2} Mbps");

    let mut all_rtts: Vec<u64> = results.iter().flat_map(|r| r.rtts.iter().copied()).collect();
    if !all_rtts.is_empty() {
        all_rtts.sort_unstable();
        let n = all_rtts.len();
        let min = all_rtts[0];
        let max = all_rtts[n - 1];
        let avg = all_rtts.iter().sum::<u64>() / n as u64;
        let p50 = all_rtts[n / 2];
        let p95 = all_rtts[(n * 95) / 100];
        let p99 = all_rtts[(n * 99) / 100];
        println!("  latency: min={min}us avg={avg}us p50={p50}us p95={p95}us p99={p99}us max={max}us");
    }

    println!("  elapsed: {:.2}s", elapsed.as_secs_f64());
}

// ─── Producer ────────────────────────────────────────────────────────────────

async fn run_producer(mut handle: AppHandle, payload: Arc<Vec<u8>>) {
    loop {
        let raw = match handle.recv().await {
            Some(b) => b,
            None => break,
        };
        let interest = match Interest::decode(raw) {
            Ok(i) => i,
            Err(_) => continue,
        };
        let data = encode_data_unsigned(&interest.name, &payload);
        if handle.send(data).await.is_err() {
            break;
        }
    }
}

// ─── Consumer ────────────────────────────────────────────────────────────────

async fn run_consumer(
    mut handle: AppHandle,
    prefix: Name,
    flow_id: u64,
    count: u64,
    rate_interval: Option<Duration>,
) -> FlowResult {
    let mut result = FlowResult {
        sent: 0,
        received: 0,
        rtts: Vec::with_capacity(count as usize),
    };

    let mut interval = rate_interval.map(tokio::time::interval);

    for seq in 0..count {
        if let Some(ref mut iv) = interval {
            iv.tick().await;
        }

        let name = build_name(&prefix, flow_id, seq);
        let wire = encode_interest(&name, None);

        let t0 = Instant::now();
        if handle.send(wire).await.is_err() {
            break;
        }
        result.sent += 1;

        match tokio::time::timeout(Duration::from_secs(4), handle.recv()).await {
            Ok(Some(data)) => {
                if !is_lp_packet(&data) {
                    // Got Data (0x06), not a Nack.
                    result.received += 1;
                    result.rtts.push(t0.elapsed().as_micros() as u64);
                }
                // else: Nack — counts as loss
            }
            _ => {} // timeout — counts as loss
        }
    }

    result
}

// ─── Main ────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let prefix: Name = cli.prefix.parse().unwrap_or_else(|_| Name::root());
    let echo_mode = cli.mode == "echo";

    println!(
        "ndn-traffic: mode={} count={} rate={} size={}B concurrency={}",
        cli.mode,
        cli.count,
        if cli.rate == 0 { "unlimited".to_string() } else { format!("{}", cli.rate) },
        cli.size,
        cli.concurrency,
    );

    // ── Build engine with faces ──────────────────────────────────────────────

    let concurrency = cli.concurrency.max(1);
    let buf_size = 4096;

    // Consumer faces: FaceId(1) .. FaceId(concurrency)
    let mut consumer_handles: Vec<AppHandle> = Vec::new();
    let mut builder = EngineBuilder::new(EngineConfig {
        pipeline_channel_cap: buf_size,
        ..Default::default()
    });

    for i in 0..concurrency {
        let (face, handle) = AppFace::new(FaceId((i + 1) as u32), buf_size);
        consumer_handles.push(handle);
        builder = builder.face(face);
    }

    // Producer face (echo mode only).
    let producer_face_id = FaceId((concurrency + 1) as u32);
    let mut producer_handle: Option<AppHandle> = None;
    if echo_mode {
        let (face, handle) = AppFace::new(producer_face_id, buf_size);
        producer_handle = Some(handle);
        builder = builder.face(face);
    }

    let (engine, shutdown) = builder.build().await?;

    // FIB route: prefix -> producer face.
    if echo_mode {
        engine.fib().add_nexthop(&prefix, producer_face_id, 0);
    }

    // ── Spawn producer ───────────────────────────────────────────────────────

    let producer_task = if let Some(handle) = producer_handle {
        let payload = Arc::new(vec![0xAAu8; cli.size]);
        Some(tokio::spawn(run_producer(handle, payload)))
    } else {
        None
    };

    // ── Spawn consumers ──────────────────────────────────────────────────────

    let per_flow = cli.count / concurrency;
    let rate_interval = if cli.rate > 0 {
        let per_flow_rate = (cli.rate as f64 / concurrency as f64).max(1.0);
        Some(Duration::from_secs_f64(1.0 / per_flow_rate))
    } else {
        None
    };

    let start = Instant::now();
    let mut set: JoinSet<FlowResult> = JoinSet::new();

    for (i, handle) in consumer_handles.into_iter().enumerate() {
        let pfx = prefix.clone();
        let ri = rate_interval;
        set.spawn(async move {
            run_consumer(handle, pfx, i as u64, per_flow, ri).await
        });
    }

    let mut results: Vec<FlowResult> = Vec::new();
    while let Some(r) = set.join_next().await {
        results.push(r?);
    }
    let elapsed = start.elapsed();

    // ── Report ───────────────────────────────────────────────────────────────

    print_stats(&results, elapsed, cli.size);

    // ── Shutdown ─────────────────────────────────────────────────────────────

    drop(results); // drop consumer handles (already moved)
    if let Some(task) = producer_task {
        task.abort();
        let _ = task.await;
    }
    shutdown.shutdown().await;

    Ok(())
}
