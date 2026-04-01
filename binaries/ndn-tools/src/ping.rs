//! `ndn-ping` — measure round-trip time to a named prefix.
//!
//! Connects to a running `ndn-router` via Unix socket + optional SHM data plane.
//!
//! ## Server mode
//!
//! Registers a prefix and responds to ping Interests with empty Data packets.
//!
//! ```text
//! ndn-ping server [--prefix /ping] [--freshness 0] [--sign]
//! ```
//!
//! ## Client mode
//!
//! Sends ping Interests sequentially and measures RTT.
//! Prints per-packet timing and a final summary.
//!
//! ```text
//! ndn-ping client [--prefix /ping] [--count 0] [--interval 1000]
//!                  [--lifetime 4000]
//! ```

use std::time::{Duration, Instant};

use anyhow::Result;
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
#[command(name = "ndn-ping", about = "NDN round-trip time measurement")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run as server: register prefix and respond to ping Interests.
    Server {
        #[command(flatten)]
        conn: ConnectOpts,

        /// Name prefix to register.
        #[arg(long, default_value = "/ping")]
        prefix: String,

        /// Data freshness period in milliseconds (0 = omit).
        #[arg(long, default_value_t = 0)]
        freshness: u64,

        /// Sign Data packets with Ed25519.
        #[arg(long)]
        sign: bool,
    },
    /// Run as client: send ping Interests and measure RTT.
    Client {
        #[command(flatten)]
        conn: ConnectOpts,

        /// Name prefix to ping.
        #[arg(long, default_value = "/ping")]
        prefix: String,

        /// Number of pings (0 = unlimited).
        #[arg(long, short = 'c', default_value_t = 4)]
        count: u64,

        /// Interval between pings in milliseconds.
        #[arg(long, short = 'i', default_value_t = 1000)]
        interval: u64,

        /// Interest lifetime in milliseconds.
        #[arg(long, default_value_t = 4000)]
        lifetime: u64,
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

// ─── Server ─────────────────────────────────────────────────────────────────

async fn run_server(
    conn: ConnectOpts,
    prefix: String,
    freshness: u64,
    sign: bool,
) -> Result<()> {
    let prefix: Name = prefix.parse()?;
    let client = connect(&conn).await?;
    client.register_prefix(&prefix).await?;

    let freshness = if freshness > 0 {
        Some(Duration::from_millis(freshness))
    } else {
        None
    };

    let signer: Option<Arc<dyn Signer>> = if sign {
        let keychain = KeyChain::new();
        let signer = keychain.create_identity(prefix.clone())?;
        eprintln!(
            "Signing with {} ({:?})",
            signer.key_name(),
            signer.sig_type(),
        );
        Some(signer)
    } else {
        None
    };

    eprintln!("PING SERVER {prefix} (listening)");

    let mut served: u64 = 0;
    loop {
        let raw = match client.recv().await {
            Some(b) => b,
            None => break,
        };
        let interest = match Interest::decode(raw) {
            Ok(i) => i,
            Err(_) => continue,
        };

        // Respond with an empty Data packet (payload is the timestamp).
        let payload = served.to_be_bytes();
        let mut builder = DataBuilder::new((*interest.name).clone(), &payload);
        if let Some(f) = freshness {
            builder = builder.freshness(f);
        }

        let data = if let Some(ref signer) = signer {
            let sig_type = signer.sig_type();
            let key_name = signer.key_name().clone();
            let s = signer.clone();
            builder
                .sign(sig_type, Some(&key_name), |region| {
                    let owned = region.to_vec();
                    async move { s.sign(&owned).await.expect("signing failed") }
                })
                .await
        } else {
            builder.build()
        };

        client.send(data).await?;
        served += 1;
        eprintln!("  reply #{served}: {}", interest.name);
    }

    Ok(())
}

// ─── Client ─────────────────────────────────────────────────────────────────

struct PingResult {
    rtt_us: u64,
}

async fn run_client(
    conn: ConnectOpts,
    prefix: String,
    count: u64,
    interval: u64,
    lifetime: u64,
) -> Result<()> {
    let prefix: Name = prefix.parse()?;
    let client = connect(&conn).await?;
    let lifetime_dur = Duration::from_millis(lifetime);
    let interval_dur = Duration::from_millis(interval);

    let unlimited = count == 0;
    let display_count = if unlimited {
        "∞".to_string()
    } else {
        count.to_string()
    };
    eprintln!(
        "PING {prefix} — {display_count} packets, interval {interval}ms, lifetime {lifetime}ms"
    );

    let mut results: Vec<PingResult> = Vec::new();
    let mut timeouts: u64 = 0;
    let mut seq: u64 = 0;
    let start = Instant::now();

    loop {
        if !unlimited && seq >= count {
            break;
        }

        let name = prefix.clone().append("ping").append(seq.to_string());
        let wire = InterestBuilder::new(name.clone()).lifetime(lifetime_dur).build();

        let t0 = Instant::now();
        client.send(wire).await?;

        // Wait for Data or timeout.
        let reply = tokio::time::timeout(lifetime_dur, client.recv()).await;

        match reply {
            Ok(Some(raw)) => {
                let rtt_us = t0.elapsed().as_micros() as u64;
                let data_name = Data::decode(raw)
                    .map(|d| d.name.to_string())
                    .unwrap_or_else(|_| "?".into());
                results.push(PingResult { rtt_us });
                eprintln!("  {data_name}: seq={seq} rtt={}", format_rtt(rtt_us));
            }
            Ok(None) => {
                eprintln!("  connection closed");
                break;
            }
            Err(_) => {
                timeouts += 1;
                eprintln!("  seq={seq}: timeout");
            }
        }

        seq += 1;
        if unlimited || seq < count {
            tokio::time::sleep(interval_dur).await;
        }
    }

    let elapsed = start.elapsed();

    // ─── Summary ────────────────────────────────────────────────────────
    let sent = seq;
    let received = results.len() as u64;
    let loss_pct = if sent > 0 {
        (sent - received) as f64 / sent as f64 * 100.0
    } else {
        0.0
    };

    println!();
    println!("--- {prefix} ping statistics ---");
    println!(
        "{sent} packets transmitted, {received} received, {loss_pct:.1}% loss, time {:.1}s",
        elapsed.as_secs_f64(),
    );

    if !results.is_empty() {
        let mut rtts: Vec<u64> = results.iter().map(|r| r.rtt_us).collect();
        rtts.sort_unstable();
        let min = rtts[0];
        let max = *rtts.last().unwrap();
        let avg = rtts.iter().sum::<u64>() / rtts.len() as u64;
        let p50 = rtts[rtts.len() / 2];
        let p99 = rtts[(rtts.len() as f64 * 0.99) as usize];

        // Standard deviation.
        let avg_f = avg as f64;
        let var = rtts.iter().map(|&r| (r as f64 - avg_f).powi(2)).sum::<f64>()
            / rtts.len() as f64;
        let stddev = var.sqrt();

        println!(
            "rtt min/avg/max/p50/p99/stddev = {}/{}/{}/{}/{}/{:.0} µs",
            format_rtt(min),
            format_rtt(avg),
            format_rtt(max),
            format_rtt(p50),
            format_rtt(p99),
            stddev,
        );
    }

    if timeouts > 0 {
        println!("{timeouts} timeouts");
    }

    Ok(())
}

fn format_rtt(us: u64) -> String {
    if us >= 1_000_000 {
        format!("{:.1}s", us as f64 / 1_000_000.0)
    } else if us >= 1_000 {
        format!("{:.2}ms", us as f64 / 1_000.0)
    } else {
        format!("{us}µs")
    }
}

// ─── Main ───────────────────────────────────────────────────────────────────

use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Server {
            conn,
            prefix,
            freshness,
            sign,
        } => run_server(conn, prefix, freshness, sign).await,
        Command::Client {
            conn,
            prefix,
            count,
            interval,
            lifetime,
        } => run_client(conn, prefix, count, interval, lifetime).await,
    }
}
