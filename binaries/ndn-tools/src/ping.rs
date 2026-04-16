//! `ndn-ping` — measure round-trip time to a named prefix.
//!
//! Connects to a running `ndn-fwd` forwarder via Unix socket + optional SHM data plane.
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

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use tokio::sync::mpsc;

use ndn_tools_core::common::{ConnectConfig, EventLevel, ToolEvent};
use ndn_tools_core::ping::{PingClientParams, PingServerParams};

// ─── CLI ────────────────────────────────────────────────────────────────────

#[derive(Args, Clone)]
struct ConnectOpts {
    /// Forwarder face socket path.
    #[arg(long, default_value = "/run/nfd/nfd.sock")]
    face_socket: String,

    /// Disable SHM and use Unix socket for data plane.
    #[arg(long)]
    no_shm: bool,
}

impl From<ConnectOpts> for ConnectConfig {
    fn from(o: ConnectOpts) -> Self {
        Self {
            face_socket: o.face_socket,
            use_shm: !o.no_shm,
            mtu: None,
        }
    }
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

// ─── Main ────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    let (tx, mut rx) = mpsc::channel::<ToolEvent>(256);

    // Print events to stderr/stdout as they arrive.
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            match ev.level {
                EventLevel::Error | EventLevel::Warn => eprintln!("{}", ev.text),
                _ => println!("{}", ev.text),
            }
        }
    });

    match cli.command {
        Command::Server {
            conn,
            prefix,
            freshness,
            sign,
        } => {
            ndn_tools_core::ping::run_server(
                PingServerParams {
                    conn: conn.into(),
                    prefix,
                    freshness_ms: freshness,
                    sign,
                },
                tx,
            )
            .await
        }
        Command::Client {
            conn,
            prefix,
            count,
            interval,
            lifetime,
        } => {
            ndn_tools_core::ping::run_client(
                PingClientParams {
                    conn: conn.into(),
                    prefix,
                    count,
                    interval_ms: interval,
                    lifetime_ms: lifetime,
                },
                tx,
            )
            .await
        }
    }
}
