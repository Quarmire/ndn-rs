//! `ndn-iperf` — NDN bandwidth measurement tool (external mode).
//!
//! Connects to a running `ndn-router` via Unix socket + optional SHM data plane.
//!
//! ## Server mode
//!
//! Registers a prefix and responds to Interests with Data packets containing
//! a fixed-size payload.
//!
//! ```text
//! ndn-iperf server [--prefix /iperf] [--size 8192] [--face-socket /tmp/ndn-faces.sock]
//! ```
//!
//! ## Client mode
//!
//! Sends Interests in a sliding window and measures throughput + RTT.
//!
//! ```text
//! ndn-iperf client [--prefix /iperf] [--duration 10] [--window 64] [--size 8192]
//!                   [--face-socket /tmp/ndn-faces.sock]
//! ```

use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::Bytes;
use clap::{Parser, Subcommand};

use ndn_ipc::RouterClient;
use ndn_packet::encode::{encode_data_unsigned, encode_interest};
use ndn_packet::{Data, Interest, Name, NameComponent};

// ─── CLI ─────────────────────────────────────────────────────────────────────

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
        /// Name prefix to register.
        #[arg(long, default_value = "/iperf")]
        prefix: String,

        /// Data payload size in bytes.
        #[arg(long, default_value_t = 8192)]
        size: usize,

        /// Router face socket path.
        #[arg(long, default_value = "/tmp/ndn-faces.sock")]
        face_socket: String,

        /// Disable SHM and use Unix socket for data plane.
        #[arg(long)]
        no_shm: bool,
    },
    /// Run as client: send Interests and measure throughput.
    Client {
        /// Name prefix to query.
        #[arg(long, default_value = "/iperf")]
        prefix: String,

        /// Test duration in seconds.
        #[arg(long, default_value_t = 10)]
        duration: u64,

        /// Sliding window size (max outstanding Interests).
        #[arg(long, default_value_t = 64)]
        window: usize,

        /// Expected Data payload size (for display only).
        #[arg(long, default_value_t = 8192)]
        size: usize,

        /// Router face socket path.
        #[arg(long, default_value = "/tmp/ndn-faces.sock")]
        face_socket: String,

        /// Disable SHM and use Unix socket for data plane.
        #[arg(long)]
        no_shm: bool,
    },
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn parse_name(s: &str) -> Name {
    let components: Vec<NameComponent> = s
        .split('/')
        .filter(|c| !c.is_empty())
        .map(|c| NameComponent::generic(Bytes::copy_from_slice(c.as_bytes())))
        .collect();
    if components.is_empty() {
        Name::root()
    } else {
        Name::from_components(components)
    }
}

fn build_name(prefix: &Name, seq: u64) -> Name {
    let seq_comp = NameComponent::generic(Bytes::copy_from_slice(format!("{seq}").as_bytes()));
    Name::from_components(prefix.components().iter().cloned().chain([seq_comp]))
}

fn extract_seq(raw: &Bytes) -> Option<u64> {
    let data = Data::decode(raw.clone()).ok()?;
    let last = data.name.components().last()?;
    std::str::from_utf8(&last.value).ok()?.parse().ok()
}

// ─── Server ──────────────────────────────────────────────────────────────────

async fn run_server(
    face_socket: &str,
    no_shm: bool,
    prefix: &Name,
    payload_size: usize,
) -> Result<()> {
    let client = if no_shm {
        RouterClient::connect_unix_only(face_socket).await?
    } else {
        RouterClient::connect(face_socket).await?
    };
    client.register_prefix(prefix).await?;

    let transport = if client.is_shm() { "SHM" } else { "Unix" };
    println!(
        "ndn-iperf server: prefix={} transport={transport} payload={payload_size}B",
        format_name(prefix)
    );
    println!("  waiting for Interests... (Ctrl-C to stop)");

    let payload = vec![0xAAu8; payload_size];
    let mut recv_count: u64 = 0;
    let mut interest_count: u64 = 0;
    let mut send_count: u64 = 0;
    let mut non_interest_count: u64 = 0;

    loop {
        let raw = match client.recv().await {
            Some(b) => b,
            None => {
                eprintln!(
                    "  server: recv returned None (channel closed) after {recv_count} packets"
                );
                break;
            }
        };
        recv_count += 1;

        let interest = match Interest::decode(raw.clone()) {
            Ok(i) => i,
            Err(_) => {
                non_interest_count += 1;
                if non_interest_count <= 5 {
                    eprintln!(
                        "  server: non-Interest packet #{non_interest_count} (first byte: 0x{:02X}, len={})",
                        raw.first().copied().unwrap_or(0),
                        raw.len()
                    );
                }
                continue;
            }
        };
        interest_count += 1;

        let data = encode_data_unsigned(&interest.name, &payload);
        if let Err(e) = client.send(data).await {
            eprintln!("send error: {e}");
            break;
        }
        send_count += 1;
    }

    eprintln!(
        "  server stats: recv={recv_count} interests={interest_count} non_interest={non_interest_count} sent={send_count}"
    );

    Ok(())
}

// ─── Client ──────────────────────────────────────────────────────────────────

async fn run_client(
    face_socket: &str,
    no_shm: bool,
    prefix: &Name,
    duration_secs: u64,
    window: usize,
    _payload_size: usize,
) -> Result<()> {
    let client = if no_shm {
        RouterClient::connect_unix_only(face_socket).await?
    } else {
        RouterClient::connect(face_socket).await?
    };

    let transport = if client.is_shm() { "SHM" } else { "Unix" };
    println!(
        "ndn-iperf client: prefix={} transport={transport} duration={duration_secs}s window={window}",
        format_name(prefix),
    );

    let deadline = Instant::now() + Duration::from_secs(duration_secs);
    let mut timestamps: HashMap<u64, Instant> = HashMap::new();
    let mut next_seq: u64 = 0;
    let mut total_bytes: u64 = 0;
    let mut received: u64 = 0;
    let mut rtts: Vec<u64> = Vec::new();

    // Fill the window.
    for _ in 0..window {
        let name = build_name(prefix, next_seq);
        let wire = encode_interest(&name, None);
        timestamps.insert(next_seq, Instant::now());
        client.send(wire).await?;
        next_seq += 1;
    }

    eprintln!("  client: sent initial window of {window} Interests, waiting for Data...");

    let mut timeouts: u64 = 0;
    let mut recv_none: u64 = 0;
    let sent = loop {
        match tokio::time::timeout(Duration::from_secs(4), client.recv()).await {
            Ok(Some(data_bytes)) => {
                total_bytes += data_bytes.len() as u64;
                received += 1;

                if let Some(seq) = extract_seq(&data_bytes) {
                    if let Some(t0) = timestamps.remove(&seq) {
                        rtts.push(t0.elapsed().as_micros() as u64);
                    }
                }

                if Instant::now() < deadline {
                    let name = build_name(prefix, next_seq);
                    let wire = encode_interest(&name, None);
                    timestamps.insert(next_seq, Instant::now());
                    client.send(wire).await?;
                    next_seq += 1;
                } else if timestamps.is_empty() {
                    break next_seq;
                }
            }
            Ok(None) => {
                recv_none += 1;
                eprintln!("  client: recv returned None (channel closed)");
                break next_seq;
            }
            Err(_) => {
                timeouts += 1;
                eprintln!(
                    "  client: recv timeout #{timeouts} (4s), outstanding={}",
                    timestamps.len()
                );
                if Instant::now() >= deadline {
                    break next_seq;
                }
            }
        }
    };

    if received == 0 {
        eprintln!("  client: WARNING — received 0 packets! timeouts={timeouts} none={recv_none}");
        eprintln!(
            "  client: sent {next_seq} Interests total; check that server is running and prefix is registered"
        );
    }

    // ── Report ───────────────────────────────────────────────────────────────

    let elapsed = Duration::from_secs(duration_secs);
    let total_mb = total_bytes as f64 / (1024.0 * 1024.0);
    let mbps = total_bytes as f64 * 8.0 / elapsed.as_secs_f64() / 1_000_000.0;
    let avg_rtt = if !rtts.is_empty() {
        rtts.iter().sum::<u64>() / rtts.len() as u64
    } else {
        0
    };

    println!("  transferred: {total_mb:.2} MB ({total_bytes} bytes)");
    println!("  throughput:  {mbps:.2} Mbps");
    println!("  packets:     {sent} sent, {received} received");
    println!("  avg RTT:     {avg_rtt} us");

    if !rtts.is_empty() {
        rtts.sort_unstable();
        let n = rtts.len();
        let p50 = rtts[n / 2];
        let p95 = rtts[(n * 95) / 100];
        let p99 = rtts[(n * 99) / 100];
        println!("  RTT detail:  p50={p50}us p95={p95}us p99={p99}us");
    }

    Ok(())
}

// ─── Main ────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Server {
            prefix,
            size,
            face_socket,
            no_shm,
        } => {
            let prefix = parse_name(&prefix);
            run_server(&face_socket, no_shm, &prefix, size).await
        }
        Command::Client {
            prefix,
            duration,
            window,
            size,
            face_socket,
            no_shm,
        } => {
            let prefix = parse_name(&prefix);
            run_client(&face_socket, no_shm, &prefix, duration, window, size).await
        }
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn format_name(name: &Name) -> String {
    let mut s = String::new();
    for comp in name.components() {
        s.push('/');
        for &b in comp.value.iter() {
            if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' {
                s.push(b as char);
            } else {
                s.push_str(&format!("%{b:02X}"));
            }
        }
    }
    if s.is_empty() {
        s.push('/');
    }
    s
}
