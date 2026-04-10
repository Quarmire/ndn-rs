//! `ndn-put` — publish a file as named Data segments.
//!
//! Always uses ndn-cxx compatible naming:
//! `/<prefix>/v=<µs-timestamp>/<seg>` with VersionNameComponent (0x36)
//! and SegmentNameComponent (0x32). Compatible with `ndnpeekdata --pipeline`
//! and `ndngetfile` consumers.

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use tokio::sync::mpsc;

use ndn_ipc::chunked::NDN_DEFAULT_SEGMENT_SIZE;
use ndn_tools_core::common::{ConnectConfig, EventLevel, ToolEvent};
use ndn_tools_core::put::{PutParams, run_producer};

#[derive(Parser)]
#[command(name = "ndn-put", about = "Publish a file as named Data segments (ndn-cxx format)")]
struct Cli {
    /// Name prefix.
    name: String,

    /// Path to the file to publish.
    file: String,

    #[arg(long, default_value_t = NDN_DEFAULT_SEGMENT_SIZE)]
    chunk_size: usize,

    #[arg(long)]
    sign: bool,

    #[arg(long)]
    hmac: bool,

    #[arg(long, default_value_t = 10_000)]
    freshness: u64,

    #[arg(long, default_value_t = 0)]
    timeout: u64,

    #[arg(long, short = 'q')]
    quiet: bool,

    #[arg(long, default_value_t = ndn_config::ManagementConfig::default().face_socket)]
    face_socket: String,

    #[arg(long)]
    no_shm: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let payload = tokio::fs::read(&cli.file)
        .await
        .with_context(|| format!("reading {}", cli.file))?;

    let (tx, mut rx) = mpsc::channel::<ToolEvent>(256);
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            match ev.level {
                EventLevel::Error | EventLevel::Warn => eprintln!("{}", ev.text),
                _ => { if !ev.text.is_empty() { eprintln!("{}", ev.text); } }
            }
        }
    });

    run_producer(PutParams {
        conn: ConnectConfig { face_socket: cli.face_socket, use_shm: !cli.no_shm },
        name: cli.name,
        data: Bytes::from(payload),
        chunk_size: cli.chunk_size,
        sign: cli.sign,
        hmac: cli.hmac,
        freshness_ms: cli.freshness,
        timeout_secs: cli.timeout,
        quiet: cli.quiet,
    }, tx).await
}
