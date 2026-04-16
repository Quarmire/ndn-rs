//! `ndn-iperf` — NDN bandwidth measurement tool.
//!
//! See `ndn_tools_core::iperf` for the embedded library implementation.

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use tokio::sync::mpsc;

use ndn_tools_core::common::ConnectConfig;
use ndn_tools_core::common::{EventLevel, ToolEvent};
use ndn_tools_core::iperf::{IperfClientParams, IperfServerParams, run_client, run_server};

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Args, Clone)]
struct ConnectOpts {
    #[arg(long, default_value_t = ndn_config::ManagementConfig::default().face_socket)]
    face_socket: String,
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
#[command(name = "ndn-iperf", about = "NDN bandwidth measurement tool")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Server {
        #[command(flatten)]
        conn: ConnectOpts,
        #[arg(long, default_value = "/iperf")]
        prefix: String,
        #[arg(long, default_value_t = 8192)]
        size: usize,
        #[arg(long, default_value_t = 0)]
        freshness: u64,
        #[arg(long, short)]
        quiet: bool,
        #[arg(long, default_value_t = 1)]
        interval: u64,
    },
    Client {
        #[command(flatten)]
        conn: ConnectOpts,
        #[arg(long, default_value = "/iperf")]
        prefix: String,
        #[arg(long, default_value_t = 10)]
        duration: u64,
        #[arg(long, default_value_t = 64)]
        window: usize,
        #[arg(long, default_value = "aimd")]
        cc: String,
        #[arg(long)]
        min_window: Option<f64>,
        #[arg(long)]
        max_window: Option<f64>,
        #[arg(long)]
        ai: Option<f64>,
        #[arg(long)]
        md: Option<f64>,
        #[arg(long)]
        cubic_c: Option<f64>,
        #[arg(long, default_value_t = 4000)]
        lifetime: u64,
        #[arg(long, short)]
        quiet: bool,
        #[arg(long, default_value_t = 1)]
        interval: u64,
        #[arg(long)]
        reverse: bool,
        #[arg(long)]
        node_prefix: Option<String>,
        /// Signing mode for session negotiation: none | ed25519 | hmac.
        #[arg(long, default_value = "none")]
        sign_mode: String,
    },
}

// ── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    let (tx, mut rx) = mpsc::channel::<ToolEvent>(512);
    // Spawn the event consumer; capture the handle so we can await it after the
    // command finishes.  When the command drops `tx`, `rx.recv()` returns `None`
    // and the consumer exits naturally.  Awaiting the handle ensures every queued
    // event is printed before the process exits (avoids a Tokio runtime-shutdown
    // race that could silently drop the results summary).
    let consumer = tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            match ev.level {
                EventLevel::Summary | EventLevel::Info => println!("{}", ev.text),
                EventLevel::Warn | EventLevel::Error => eprintln!("{}", ev.text),
            }
        }
    });

    let result = match cli.command {
        Command::Server {
            conn,
            prefix,
            size,
            freshness,
            quiet,
            interval,
        } => {
            run_server(
                IperfServerParams {
                    conn: conn.into(),
                    prefix,
                    payload_size: size,
                    freshness_ms: freshness,
                    quiet,
                    interval_ms: interval * 1000,
                },
                tx,
            )
            .await
        }

        Command::Client {
            conn,
            prefix,
            duration,
            window,
            cc,
            min_window,
            max_window,
            ai,
            md,
            cubic_c,
            lifetime,
            quiet,
            interval,
            reverse,
            node_prefix,
            sign_mode,
        } => {
            run_client(
                IperfClientParams {
                    conn: conn.into(),
                    prefix,
                    duration_secs: duration,
                    initial_window: window,
                    cc,
                    min_window,
                    max_window,
                    ai,
                    md,
                    cubic_c,
                    lifetime_ms: lifetime,
                    quiet,
                    interval_ms: interval * 1000,
                    reverse,
                    node_prefix,
                    sign_mode,
                },
                tx,
            )
            .await
        }
    };
    // Wait for all queued events to be printed.
    let _ = consumer.await;
    result
}
