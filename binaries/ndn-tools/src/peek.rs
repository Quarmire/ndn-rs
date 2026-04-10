//! `ndn-peek` — fetch a named Data packet and print its content.
//!
//! Always uses ndn-cxx compatible naming for segmented fetch.
//! The `--ndn-cxx` flag is no longer needed (and is removed).
//!
//! ## Single-packet fetch (default)
//!
//! ```text
//! ndn-peek /example/data
//! ndn-peek /example/data --output /tmp/data.bin
//! ndn-peek --can-be-prefix /example
//! ```
//!
//! ## Segmented fetch
//!
//! ```text
//! ndn-peek --pipeline 16 /example/data --output /tmp/data.bin
//! ```
//!
//! Sends the initial Interest with CanBePrefix, discovers the versioned prefix
//! from the first response, then fetches remaining segments with
//! SegmentNameComponent (TLV 0x32). Compatible with `ndnputchunks` producers.

use anyhow::Result;
use clap::Parser;
use tokio::sync::mpsc;

use ndn_tools_core::common::{EventLevel, ToolEvent};
use ndn_tools_core::common::ConnectConfig;
use ndn_tools_core::peek::{PeekParams, run_peek};

#[derive(Parser)]
#[command(name = "ndn-peek", about = "Fetch a named Data packet from the NDN network")]
struct Cli {
    name: String,

    #[arg(long, default_value_t = 4000)]
    lifetime: u64,

    #[arg(long, short = 'o')]
    output: Option<String>,

    /// Segmented fetch pipeline depth.
    #[arg(long, short = 'p')]
    pipeline: Option<usize>,

    #[arg(long)]
    hex: bool,

    #[arg(long, short = 'm')]
    meta: bool,

    #[arg(long, short = 'v')]
    verbose: bool,

    #[arg(long)]
    can_be_prefix: bool,

    #[arg(long, default_value_t = ndn_config::ManagementConfig::default().face_socket)]
    face_socket: String,

    #[arg(long)]
    no_shm: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let (tx, mut rx) = mpsc::channel::<ToolEvent>(256);
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            match ev.level {
                EventLevel::Error | EventLevel::Warn => eprintln!("{}", ev.text),
                _ => {
                    if !ev.text.is_empty() { println!("{}", ev.text); }
                }
            }
        }
    });

    run_peek(PeekParams {
        conn: ConnectConfig { face_socket: cli.face_socket, use_shm: !cli.no_shm },
        name: cli.name,
        lifetime_ms: cli.lifetime,
        output: cli.output,
        pipeline: cli.pipeline,
        hex: cli.hex,
        meta_only: cli.meta,
        verbose: cli.verbose,
        can_be_prefix: cli.can_be_prefix,
    }, tx).await
}
