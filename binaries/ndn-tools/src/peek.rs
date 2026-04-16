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

use clap::ValueEnum;
use ndn_tools_core::common::ConnectConfig;
use ndn_tools_core::common::{EventLevel, ToolEvent};
use ndn_tools_core::peek::{CcAlgo, PeekParams, VerifyMode, run_peek};

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum CliVerify {
    /// No verification (default). Faster, matches historical behaviour.
    None,
    /// DigestSha256 (recompute SHA-256 of signed region).
    DigestSha256,
    /// DigestBlake3 (ndn-rs experimental type 6).
    DigestBlake3,
    /// Ed25519 with `--pubkey`. Pair with `--batch-verify` for a
    /// single batch verify at the end.
    Ed25519,
    /// Auto-detect Merkle from the segment SignatureType (codes 8/9),
    /// fetch the manifest by KeyLocator name, and verify each segment
    /// against the cached root.
    Merkle,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum CliCc {
    Fixed,
    Aimd,
    Cubic,
}

impl From<CliVerify> for VerifyMode {
    fn from(c: CliVerify) -> Self {
        match c {
            CliVerify::None => VerifyMode::None,
            CliVerify::DigestSha256 => VerifyMode::DigestSha256,
            CliVerify::DigestBlake3 => VerifyMode::DigestBlake3,
            CliVerify::Ed25519 => VerifyMode::Ed25519,
            CliVerify::Merkle => VerifyMode::Merkle,
        }
    }
}

impl From<CliCc> for CcAlgo {
    fn from(c: CliCc) -> Self {
        match c {
            CliCc::Fixed => CcAlgo::Fixed,
            CliCc::Aimd => CcAlgo::Aimd,
            CliCc::Cubic => CcAlgo::Cubic,
        }
    }
}

#[derive(Parser)]
#[command(
    name = "ndn-peek",
    about = "Fetch a named Data packet from the NDN network"
)]
struct Cli {
    name: String,

    #[arg(long, default_value_t = 4000)]
    lifetime: u64,

    #[arg(long, short = 'o')]
    output: Option<String>,

    /// Segmented fetch pipeline depth (turns on segmented mode).
    /// Used as the initial congestion window when `--cc != fixed`.
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

    /// Per-segment verification (segmented fetch only).
    #[arg(long, value_enum, default_value_t = CliVerify::None)]
    verify: CliVerify,

    /// 32-byte Ed25519 public key as hex, for `--verify=ed25519`.
    #[arg(long)]
    pubkey: Option<String>,

    /// Use ed25519_verify_batch for `--verify=ed25519` (collects all
    /// signatures then runs one batch verify at the end of the fetch).
    #[arg(long)]
    batch_verify: bool,

    /// Congestion control algorithm for the segmented pipeline.
    #[arg(long, value_enum, default_value_t = CliCc::Fixed)]
    cc: CliCc,

    /// AIMD/Cubic minimum congestion window.
    #[arg(long)]
    cc_min_window: Option<f64>,

    /// AIMD/Cubic maximum congestion window.
    #[arg(long)]
    cc_max_window: Option<f64>,

    /// AIMD additive increase per RTT.
    #[arg(long)]
    cc_ai: Option<f64>,

    /// AIMD/Cubic multiplicative decrease factor.
    #[arg(long)]
    cc_md: Option<f64>,

    /// Cubic `C` parameter.
    #[arg(long)]
    cc_cubic_c: Option<f64>,

    /// Partial fetch: starting segment index.
    #[arg(long, default_value_t = 0)]
    start: usize,

    /// Partial fetch: number of segments to retrieve. 0 = all from
    /// `--start` to the end of the file.
    #[arg(long, default_value_t = 0)]
    count: usize,

    /// Print one machine-parseable JSON line at the end of the run
    /// (`metrics: { ... }`).
    #[arg(long)]
    metrics: bool,

    /// Stream segments directly to `--output` instead of buffering
    /// the assembled file in memory. Uses positional writes so
    /// out-of-order arrival is fine. Requires `--output` to be set.
    #[arg(long)]
    no_assemble: bool,

    #[arg(long, default_value_t = ndn_config::ManagementConfig::default().face_socket)]
    face_socket: String,

    #[arg(long)]
    no_shm: bool,

    /// Hint for the SHM ring slot size: maximum Data content body
    /// the consumer expects to receive, in bytes. Use this when
    /// fetching segments larger than ~256 KiB over SHM. Ignored with
    /// `--no-shm`.
    #[arg(long)]
    mtu: Option<usize>,
}

fn parse_pubkey(hex: &str) -> Result<[u8; 32]> {
    let cleaned: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() != 64 {
        anyhow::bail!(
            "--pubkey must be 32 bytes (64 hex chars), got {}",
            cleaned.len()
        );
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&cleaned[i * 2..i * 2 + 2], 16)
            .map_err(|e| anyhow::anyhow!("--pubkey hex: {e}"))?;
    }
    Ok(out)
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
                    if !ev.text.is_empty() {
                        println!("{}", ev.text);
                    }
                }
            }
        }
    });

    let pubkey = match cli.pubkey {
        Some(s) => Some(parse_pubkey(&s)?),
        None => None,
    };

    // The legacy `--pipeline N` flag still toggles segmented mode and
    // also sets the initial congestion window so existing scripts
    // keep working unchanged.
    let initial_window = cli.pipeline.unwrap_or(16).max(1);

    run_peek(
        PeekParams {
            conn: ConnectConfig {
                face_socket: cli.face_socket,
                use_shm: !cli.no_shm,
                mtu: cli.mtu,
            },
            name: cli.name,
            lifetime_ms: cli.lifetime,
            output: cli.output,
            pipeline: cli.pipeline,
            hex: cli.hex,
            meta_only: cli.meta,
            verbose: cli.verbose,
            can_be_prefix: cli.can_be_prefix,
            verify_mode: cli.verify.into(),
            ed25519_public_key: pubkey,
            batch_verify: cli.batch_verify,
            cc_algo: cli.cc.into(),
            initial_window,
            min_window: cli.cc_min_window,
            max_window: cli.cc_max_window,
            ai: cli.cc_ai,
            md: cli.cc_md,
            cubic_c: cli.cc_cubic_c,
            start_seg: cli.start,
            count_segs: cli.count,
            metrics: cli.metrics,
            no_assemble: cli.no_assemble,
        },
        tx,
    )
    .await
}
