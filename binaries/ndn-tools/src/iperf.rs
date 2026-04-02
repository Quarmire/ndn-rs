//! `ndn-iperf` — NDN bandwidth measurement tool (external mode).
//!
//! Connects to a running `ndn-router` via Unix socket + optional SHM data plane.
//!
//! ## Server mode
//!
//! Registers a prefix and responds to Interests with Data packets.
//! Optionally signs each Data packet with Ed25519 (`--sign`).
//!
//! ```text
//! ndn-iperf server [--prefix /iperf] [--size 8192] [--sign] [--freshness 0]
//! ```
//!
//! ## Client mode
//!
//! Sends Interests in a sliding window and measures throughput + RTT.
//! Prints per-interval statistics and a final summary.
//!
//! ```text
//! ndn-iperf client [--prefix /iperf] [--duration 10] [--window 64]
//!                   [--lifetime 4000] [--interval 1]
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::Bytes;
use clap::{Args, Parser, Subcommand};

use ndn_app::KeyChain;
use ndn_ipc::RouterClient;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Data, Interest, Name};
use ndn_security::Signer;

// ─── CLI ────────────────────────────────────────────────────────────────────

#[derive(Args, Clone)]
struct ConnectOpts {
    /// Router face socket path.
    #[arg(long, default_value = "/tmp/ndn-faces.sock")]
    face_socket: String,

    /// Disable SHM and use Unix socket for data plane.
    #[arg(long)]
    no_shm: bool,
}

#[derive(Parser)]
#[command(name = "ndn-iperf", about = "NDN bandwidth measurement tool")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run as server: register prefix and respond to Interests.
    Server {
        #[command(flatten)]
        conn: ConnectOpts,

        /// Name prefix to register.
        #[arg(long, default_value = "/iperf")]
        prefix: String,

        /// Data payload size in bytes.
        #[arg(long, default_value_t = 8192)]
        size: usize,

        /// Sign Data packets with Ed25519.
        #[arg(long)]
        sign: bool,

        /// Sign Data packets with HMAC-SHA256 (faster than Ed25519).
        #[arg(long)]
        hmac: bool,

        /// Data freshness period in milliseconds (0 = omit).
        #[arg(long, default_value_t = 0)]
        freshness: u64,

        /// Suppress periodic status reports.
        #[arg(long, short)]
        quiet: bool,

        /// Status report interval in seconds.
        #[arg(long, default_value_t = 1)]
        interval: u64,
    },
    /// Run as client: send Interests and measure throughput.
    Client {
        #[command(flatten)]
        conn: ConnectOpts,

        /// Name prefix to query.
        #[arg(long, default_value = "/iperf")]
        prefix: String,

        /// Test duration in seconds.
        #[arg(long, default_value_t = 10)]
        duration: u64,

        /// Sliding window size (max outstanding Interests).
        #[arg(long, default_value_t = 64)]
        window: usize,

        /// Interest lifetime in milliseconds.
        #[arg(long, default_value_t = 4000)]
        lifetime: u64,

        /// Suppress periodic status reports.
        #[arg(long, short)]
        quiet: bool,

        /// Status report interval in seconds.
        #[arg(long, default_value_t = 1)]
        interval: u64,
    },
}

// ─── Helpers ────────────────────────────────────────────────────────────────

async fn connect(opts: &ConnectOpts) -> Result<RouterClient> {
    if opts.no_shm {
        Ok(RouterClient::connect_unix_only(&opts.face_socket).await?)
    } else {
        Ok(RouterClient::connect(&opts.face_socket).await?)
    }
}

fn extract_seq(raw: &Bytes) -> Option<u64> {
    let data = Data::decode(raw.clone()).ok()?;
    let last = data.name.components().last()?;
    std::str::from_utf8(&last.value).ok()?.parse().ok()
}

fn format_throughput(bytes: u64, duration: Duration) -> String {
    let secs = duration.as_secs_f64();
    if secs == 0.0 {
        return "0 bps".into();
    }
    let bps = bytes as f64 * 8.0 / secs;
    if bps >= 1_000_000_000.0 {
        format!("{:.2} Gbps", bps / 1_000_000_000.0)
    } else if bps >= 1_000_000.0 {
        format!("{:.2} Mbps", bps / 1_000_000.0)
    } else if bps >= 1_000.0 {
        format!("{:.2} Kbps", bps / 1_000.0)
    } else {
        format!("{:.0} bps", bps)
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.2} GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.2} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

// ─── Interval stats (lock-free) ─────────────────────────────────────────────

struct IntervalCounters {
    bytes:     AtomicU64,
    pkts:      AtomicU64,
    rtt_sum:   AtomicU64,
    rtt_count: AtomicU64,
}

impl IntervalCounters {
    fn new() -> Self {
        Self {
            bytes:     AtomicU64::new(0),
            pkts:      AtomicU64::new(0),
            rtt_sum:   AtomicU64::new(0),
            rtt_count: AtomicU64::new(0),
        }
    }

    fn record(&self, bytes: u64) {
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
        self.pkts.fetch_add(1, Ordering::Relaxed);
    }

    fn record_rtt(&self, rtt_us: u64) {
        self.rtt_sum.fetch_add(rtt_us, Ordering::Relaxed);
        self.rtt_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Atomically drain all interval counters, returning (bytes, pkts, rtt_sum, rtt_count).
    fn drain(&self) -> (u64, u64, u64, u64) {
        (
            self.bytes.swap(0, Ordering::Relaxed),
            self.pkts.swap(0, Ordering::Relaxed),
            self.rtt_sum.swap(0, Ordering::Relaxed),
            self.rtt_count.swap(0, Ordering::Relaxed),
        )
    }
}

// ─── Server ─────────────────────────────────────────────────────────────────

async fn run_server(
    conn: &ConnectOpts,
    prefix: &Name,
    payload_size: usize,
    sign: bool,
    hmac: bool,
    freshness_ms: u64,
    quiet: bool,
    interval_secs: u64,
) -> Result<()> {
    let client = connect(conn).await?;
    client.register_prefix(prefix).await?;

    let transport = if client.is_shm() { "SHM" } else { "Unix" };
    eprintln!("ndn-iperf server: prefix={prefix} transport={transport} payload={payload_size}B");
    if sign {
        eprintln!("  signing:  Ed25519");
    } else if hmac {
        eprintln!("  signing:  HMAC-SHA256");
    }
    if freshness_ms > 0 {
        eprintln!("  freshness: {freshness_ms}ms");
    }
    eprintln!("  waiting for Interests... (Ctrl-C to stop)");

    // Set up optional signing.
    let signer: Option<Arc<dyn Signer>> = if sign {
        let keychain = KeyChain::new();
        Some(keychain.create_identity(prefix.clone(), None)?)
    } else if hmac {
        use ndn_packet::{NameComponent, Name as NdnName};
        let key_name = NdnName::from_components([
            NameComponent::generic(Bytes::from_static(b"iperf")),
            NameComponent::generic(Bytes::from_static(b"hmac-key")),
        ]);
        // Fixed test key — iperf is a benchmark tool, not production security.
        Some(Arc::new(ndn_security::HmacSha256Signer::new(b"ndn-iperf-bench-key", key_name)))
    } else {
        None
    };

    let freshness = if freshness_ms > 0 {
        Some(Duration::from_millis(freshness_ms))
    } else {
        None
    };

    let payload = vec![0xAAu8; payload_size];
    let counters = Arc::new(IntervalCounters::new());
    let start = Instant::now();

    // Periodic stats printer.
    if !quiet {
        let counters = counters.clone();
        let interval_dur = Duration::from_secs(interval_secs);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval_dur);
            ticker.tick().await; // skip first immediate tick
            loop {
                ticker.tick().await;
                let (bytes, pkts, _, _) = counters.drain();
                let elapsed = start.elapsed();
                let tp = format_throughput(bytes, interval_dur);
                eprintln!(
                    "[{:>6.1}s]  {tp:>14}  {pkts:>8} pkt/s",
                    elapsed.as_secs_f64(),
                );
            }
        });
    }

    let mut total_interests: u64 = 0;
    let mut total_sent: u64 = 0;
    let mut non_interest: u64 = 0;

    loop {
        let raw = match client.recv().await {
            Some(b) => b,
            None => {
                eprintln!("  connection closed after {total_interests} Interests");
                break;
            }
        };

        let interest = match Interest::decode(raw) {
            Ok(i) => i,
            Err(_) => {
                non_interest += 1;
                continue;
            }
        };
        total_interests += 1;

        // Build the Data packet using DataBuilder.
        let mut builder = DataBuilder::new((*interest.name).clone(), &payload);
        if let Some(f) = freshness {
            builder = builder.freshness(f);
        }

        let data = if let Some(ref signer) = signer {
            let sig_type = signer.sig_type();
            let key_name = signer.key_name().clone();
            let s = Arc::clone(signer);
            // sign_sync on the blocking pool — scales across cores.
            tokio::task::spawn_blocking(move || {
                builder.sign_sync(sig_type, Some(&key_name), |region| {
                    s.sign_sync(region).expect("signing failed")
                })
            }).await?
        } else {
            builder.build()
        };

        let data_len = data.len() as u64;
        if let Err(e) = client.send(data).await {
            eprintln!("  send error: {e}");
            break;
        }
        total_sent += 1;
        counters.record(data_len);
    }

    let elapsed = start.elapsed();
    eprintln!();
    eprintln!("--- server summary ---");
    eprintln!("  uptime:        {:.1}s", elapsed.as_secs_f64());
    eprintln!("  interests:     {total_interests}");
    eprintln!("  data sent:     {total_sent}");
    if non_interest > 0 {
        eprintln!("  non-interest:  {non_interest}");
    }

    Ok(())
}

// ─── Client ─────────────────────────────────────────────────────────────────

async fn run_client(
    conn: &ConnectOpts,
    prefix: &Name,
    duration_secs: u64,
    window: usize,
    lifetime_ms: u64,
    quiet: bool,
    interval_secs: u64,
) -> Result<()> {
    let client = connect(conn).await?;

    let transport = if client.is_shm() { "SHM" } else { "Unix" };
    let lifetime = Duration::from_millis(lifetime_ms);

    eprintln!("ndn-iperf client: prefix={prefix} transport={transport}");
    eprintln!("  duration={duration_secs}s  window={window}  lifetime={lifetime_ms}ms");
    eprintln!("  testing...");

    let counters = Arc::new(IntervalCounters::new());
    let start = Instant::now();
    let deadline = start + Duration::from_secs(duration_secs);

    // Periodic stats printer.
    if !quiet {
        let counters = counters.clone();
        let interval_dur = Duration::from_secs(interval_secs);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval_dur);
            ticker.tick().await; // skip first immediate tick
            loop {
                ticker.tick().await;
                let (bytes, pkts, rtt_sum, rtt_count) = counters.drain();
                let elapsed = start.elapsed();
                let tp = format_throughput(bytes, interval_dur);
                let rtt_str = if rtt_count > 0 {
                    format!("rtt={:.0}us", rtt_sum as f64 / rtt_count as f64)
                } else {
                    "rtt=n/a".into()
                };
                eprintln!(
                    "[{:>6.1}s]  {tp:>14}  {pkts:>8} pkt/s  {rtt_str}",
                    elapsed.as_secs_f64(),
                );
            }
        });
    }

    let mut timestamps: HashMap<u64, Instant> = HashMap::new();
    let mut next_seq: u64 = 0;
    let mut total_bytes: u64 = 0;
    let mut received: u64 = 0;
    let mut timeouts: u64 = 0;
    let mut rtts: Vec<u64> = Vec::new();

    // Fill the initial window.
    for _ in 0..window {
        let name = prefix.clone().append(format!("{next_seq}"));
        let wire = InterestBuilder::new(name).lifetime(lifetime).build();
        timestamps.insert(next_seq, Instant::now());
        client.send(wire).await?;
        next_seq += 1;
    }

    let recv_timeout = Duration::from_millis(lifetime_ms + 1000);
    // After the test deadline, use a short drain timeout to collect
    // any Data already in flight without waiting for the full lifetime.
    let drain_timeout = Duration::from_millis(500);
    let mut past_deadline = false;

    let sent = loop {
        let timeout = if past_deadline { drain_timeout } else { recv_timeout };
        match tokio::time::timeout(timeout, client.recv()).await {
            Ok(Some(data_bytes)) => {
                let data_len = data_bytes.len() as u64;
                total_bytes += data_len;
                received += 1;

                let rtt_us = extract_seq(&data_bytes).and_then(|seq| {
                    timestamps.remove(&seq).map(|t0| t0.elapsed().as_micros() as u64)
                });

                if let Some(rtt) = rtt_us {
                    rtts.push(rtt);
                    counters.record_rtt(rtt);
                }
                counters.record(data_len);

                // Send next Interest if still within test duration.
                if !past_deadline {
                    if Instant::now() < deadline {
                        let name = prefix.clone().append(format!("{next_seq}"));
                        let wire = InterestBuilder::new(name).lifetime(lifetime).build();
                        timestamps.insert(next_seq, Instant::now());
                        client.send(wire).await?;
                        next_seq += 1;
                    } else {
                        past_deadline = true;
                    }
                }
                if past_deadline && timestamps.is_empty() {
                    break next_seq;
                }
            }
            Ok(None) => {
                eprintln!("  connection closed");
                break next_seq;
            }
            Err(_) => {
                if past_deadline || Instant::now() >= deadline {
                    break next_seq;
                }
                timeouts += 1;
                // Expire stale timestamps.
                let now = Instant::now();
                timestamps.retain(|_, t0| {
                    now.duration_since(*t0) < recv_timeout
                });
            }
        }
    };

    let actual_elapsed = start.elapsed();
    let loss_pct = if sent > 0 {
        (1.0 - received as f64 / sent as f64) * 100.0
    } else {
        0.0
    };

    // ── Final Report ──────────────────────────────────────────────────────

    eprintln!();
    println!("--- ndn-iperf results ---");
    println!("  duration:    {:.2}s", actual_elapsed.as_secs_f64());
    println!(
        "  transferred: {} ({total_bytes} bytes)",
        format_bytes(total_bytes),
    );
    println!(
        "  throughput:  {}",
        format_throughput(total_bytes, actual_elapsed),
    );
    println!("  packets:     {sent} sent, {received} received ({loss_pct:.1}% loss)");
    if timeouts > 0 {
        println!("  timeouts:    {timeouts}");
    }

    if !rtts.is_empty() {
        rtts.sort_unstable();
        let n = rtts.len();
        let avg = rtts.iter().sum::<u64>() / n as u64;
        let min = rtts[0];
        let max = rtts[n - 1];
        let p50 = rtts[n / 2];
        let p95 = rtts[n * 95 / 100];
        let p99 = rtts[n * 99 / 100];
        println!("  RTT:         avg={avg}us min={min}us max={max}us");
        println!("               p50={p50}us p95={p95}us p99={p99}us");
    } else {
        println!("  RTT:         no samples");
    }

    Ok(())
}

// ─── Main ───────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Server {
            conn, prefix, size, sign, hmac, freshness, quiet, interval,
        } => {
            let prefix: Name = prefix.parse()?;
            run_server(&conn, &prefix, size, sign, hmac, freshness, quiet, interval).await
        }
        Command::Client {
            conn, prefix, duration, window, lifetime, quiet, interval,
        } => {
            let prefix: Name = prefix.parse()?;
            run_client(&conn, &prefix, duration, window, lifetime, quiet, interval).await
        }
    }
}
