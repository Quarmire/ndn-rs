//! `ndn-ping` — measure round-trip time to a named prefix.
//!
//! Usage: ndn-ping /name/prefix [--count <n>] [--interval-ms <ms>]

use anyhow::{bail, Result};
use bytes::Bytes;
use ndn_packet::{Interest, Name, NameComponent};
use std::time::{Duration, Instant};

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

/// Simulated RTT entry — a real implementation would use AppFace.
struct PingResult {
    seq:    u32,
    rtt_us: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let prefix_str = match args.next() {
        Some(s) => s,
        None => {
            eprintln!("usage: ndn-ping <prefix> [--count <n>] [--interval-ms <ms>]");
            std::process::exit(1);
        }
    };

    let mut count: u32 = 4;
    let mut interval_ms: u64 = 1000;

    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--count" => {
                let val = args.next().unwrap_or_default();
                count = val.parse().unwrap_or(4);
            }
            "--interval-ms" => {
                let val = args.next().unwrap_or_default();
                interval_ms = val.parse().unwrap_or(1000);
            }
            other => bail!("unknown flag: {other}"),
        }
    }

    let prefix = parse_name(&prefix_str);
    println!("ndn-ping: pinging {} ({} packets, interval {}ms)", prefix_str, count, interval_ms);

    // TODO: wire to AppFace for real forwarder pings.
    // Simulate the ping loop structure without a live forwarder.
    let mut results: Vec<PingResult> = Vec::new();
    for seq in 0..count {
        // Build a ping Interest: prefix + /ping/<seq>
        let ping_comp = NameComponent::generic(Bytes::from_static(b"ping"));
        let seq_bytes = seq.to_be_bytes();
        let seq_comp  = NameComponent::generic(Bytes::copy_from_slice(&seq_bytes));
        let _interest = Interest::new(Name::from_components(
            prefix.components().iter().cloned()
                .chain([ping_comp, seq_comp])
        ));

        let t0 = Instant::now();
        // TODO: express Interest and await Data
        tokio::time::sleep(Duration::from_millis(1)).await; // placeholder
        let rtt_us = t0.elapsed().as_micros() as u64;

        results.push(PingResult { seq, rtt_us });
        println!("  seq={} rtt={}µs (simulated)", seq, rtt_us);

        if seq + 1 < count {
            tokio::time::sleep(Duration::from_millis(interval_ms)).await;
        }
    }

    if !results.is_empty() {
        let min = results.iter().map(|r| r.rtt_us).min().unwrap_or(0);
        let max = results.iter().map(|r| r.rtt_us).max().unwrap_or(0);
        let avg = results.iter().map(|r| r.rtt_us).sum::<u64>() / results.len() as u64;
        println!("rtt min/avg/max = {}/{}/{} µs", min, avg, max);
    }

    Ok(())
}
