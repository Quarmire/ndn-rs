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

use clap::ValueEnum;
use ndn_ipc::chunked::NDN_DEFAULT_SEGMENT_SIZE;
use ndn_tools_core::common::{ConnectConfig, EventLevel, ToolEvent};
use ndn_tools_core::put::{HashAlgo, PutParams, SignMode, run_producer};

/// CLI sign mode mirror — clap can't directly use `ndn_tools_core::SignMode`
/// because it lives in a sibling crate that doesn't depend on clap.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum CliSign {
    /// No SignatureValue (debug only).
    None,
    /// NDN spec DigestSha256 (type 0). Default. ndn-cxx interoperable.
    Digest,
    /// ndn-rs experimental DigestBlake3 (type 6).
    Blake3digest,
    /// NDN spec HmacWithSha256 (type 4) with an ephemeral key.
    Hmac,
    /// ndn-rs experimental Blake3Keyed (type 7) with an ephemeral key.
    Blake3keyed,
    /// NDN spec SignatureSha256WithEd25519 (type 5).
    Ed25519,
    /// ndn-rs experimental Merkle-tree segment signing.
    /// Pick the hash function with `--hash`.
    Merkle,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum CliHash {
    Sha256,
    Blake3,
}

impl From<CliSign> for SignMode {
    fn from(c: CliSign) -> Self {
        match c {
            CliSign::None => SignMode::None,
            CliSign::Digest => SignMode::DigestSha256,
            CliSign::Blake3digest => SignMode::DigestBlake3,
            CliSign::Hmac => SignMode::HmacSha256,
            CliSign::Blake3keyed => SignMode::Blake3Keyed,
            CliSign::Ed25519 => SignMode::Ed25519,
            CliSign::Merkle => SignMode::Merkle,
        }
    }
}

impl From<CliHash> for HashAlgo {
    fn from(c: CliHash) -> Self {
        match c {
            CliHash::Sha256 => HashAlgo::Sha256,
            CliHash::Blake3 => HashAlgo::Blake3,
        }
    }
}

#[derive(Parser)]
#[command(
    name = "ndn-put",
    about = "Publish a file as named Data segments (ndn-cxx format)"
)]
struct Cli {
    /// Name prefix.
    name: String,

    /// Path to the file to publish.
    file: String,

    #[arg(long, default_value_t = NDN_DEFAULT_SEGMENT_SIZE)]
    chunk_size: usize,

    /// Signing algorithm. `digest` (the default) is ndn-cxx
    /// interoperable; `merkle` is ndn-rs only and pairs with
    /// `--hash`. See the SignMode docs in ndn_tools_core::put.
    #[arg(long, value_enum, default_value_t = CliSign::Digest)]
    sign: CliSign,

    /// Hash function (only meaningful for `--sign=merkle`).
    #[arg(long, value_enum, default_value_t = CliHash::Sha256)]
    hash: CliHash,

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
                _ => {
                    if !ev.text.is_empty() {
                        eprintln!("{}", ev.text);
                    }
                }
            }
        }
    });

    run_producer(
        PutParams {
            conn: ConnectConfig {
                face_socket: cli.face_socket,
                use_shm: !cli.no_shm,
            },
            name: cli.name,
            data: Bytes::from(payload),
            chunk_size: cli.chunk_size,
            sign_mode: cli.sign.into(),
            hash_algo: cli.hash.into(),
            freshness_ms: cli.freshness,
            timeout_secs: cli.timeout,
            quiet: cli.quiet,
        },
        tx,
    )
    .await
}
