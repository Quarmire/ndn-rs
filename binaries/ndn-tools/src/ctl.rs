/// ndn-ctl — send management commands to a running ndn-router.
///
/// Commands follow the `<noun> <verb>` pattern (like NFD's `nfdc`):
///
/// ```sh
/// ndn-ctl route add /ndn --face 1 --cost 10
/// ndn-ctl route list
/// ndn-ctl face create udp4://192.168.1.1:6363
/// ndn-ctl face list
/// ndn-ctl strategy set /ndn --strategy /localhost/nfd/strategy/best-route
/// ndn-ctl cs info
/// ndn-ctl status
/// ndn-ctl shutdown
/// ```
///
/// An optional `--bypass` flag falls back to the legacy transport: raw JSON
/// over a Unix socket.
use clap::{Parser, Subcommand};

use ndn_config::ControlResponse;
use ndn_ipc::MgmtClient;

// Legacy JSON types (bypass path only).
#[cfg(unix)]
use ndn_config::{ManagementRequest, ManagementResponse};

// ─── CLI definition ───────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "ndn-ctl",
    about = "Send management commands to a running ndn-router",
    version
)]
struct Cli {
    /// Use the legacy bypass transport (raw JSON over Unix socket).
    #[arg(long)]
    bypass: bool,

    /// NDN face socket path (NDN transport).
    ///
    /// May also be set via $NDN_FACE_SOCK.
    #[arg(long, env = "NDN_FACE_SOCK", default_value = "/tmp/ndn-faces.sock")]
    face_socket: String,

    /// Unix socket path (bypass transport only).
    ///
    /// May also be set via $NDN_MGMT_SOCK.
    #[arg(long, env = "NDN_MGMT_SOCK", default_value = "/tmp/ndn-router.sock")]
    socket: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage routes.
    Route {
        #[command(subcommand)]
        action: RouteAction,
    },
    /// Manage faces.
    Face {
        #[command(subcommand)]
        action: FaceAction,
    },
    /// Manage forwarding strategies.
    Strategy {
        #[command(subcommand)]
        action: StrategyAction,
    },
    /// Content store operations.
    Cs {
        #[command(subcommand)]
        action: CsAction,
    },
    /// Display forwarder status.
    Status,
    /// Request graceful shutdown of the router.
    Shutdown,
}

#[derive(Subcommand)]
enum RouteAction {
    /// Add (or update) a route.
    Add {
        /// NDN name prefix (e.g. /ndn/test).
        prefix: String,
        /// Face ID (nexthop).
        #[arg(long, alias = "nexthop")]
        face: u32,
        /// Routing cost; lower is preferred (default: 10).
        #[arg(long, default_value = "10")]
        cost: u32,
    },
    /// Remove a route.
    Remove {
        /// NDN name prefix.
        prefix: String,
        /// Face ID.
        #[arg(long, alias = "nexthop")]
        face: u32,
    },
    /// List all routes.
    List,
}

#[derive(Subcommand)]
enum FaceAction {
    /// Create a face.
    Create {
        /// Face URI (e.g. udp4://192.168.1.1:6363, tcp4://router.example.com:6363).
        uri: String,
    },
    /// Destroy a face.
    Destroy {
        /// Face ID to destroy.
        face_id: u32,
    },
    /// List all faces.
    List,
}

#[derive(Subcommand)]
enum StrategyAction {
    /// Set the forwarding strategy for a name prefix.
    Set {
        /// NDN name prefix (e.g. /ndn/test).
        prefix: String,
        /// Strategy name (e.g. /localhost/nfd/strategy/best-route).
        #[arg(long)]
        strategy: String,
    },
    /// Unset (remove) the forwarding strategy for a name prefix.
    Unset {
        /// NDN name prefix.
        prefix: String,
    },
    /// List all strategy choices.
    List,
}

#[derive(Subcommand)]
enum CsAction {
    /// Display content store info (capacity, entries, memory).
    Info,
    /// Get or set CS capacity.
    Config {
        /// Set max capacity in bytes. Omit to query current.
        #[arg(long)]
        capacity: Option<u64>,
    },
    /// Erase cached entries by name prefix.
    Erase {
        /// Name prefix to erase from CS (e.g. /ndn/video).
        prefix: String,
        /// Maximum number of entries to erase (default: all).
        #[arg(long)]
        count: Option<u64>,
    },
}

// ─── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if cli.bypass {
        run_bypass(&cli).await
    } else {
        run_nfd(&cli).await
    }
}

// ─── NFD transport (primary) ────────────────────────────────────────────────

#[cfg(unix)]
async fn run_nfd(cli: &Cli) -> anyhow::Result<()> {
    use anyhow::Context as _;

    let mgmt = MgmtClient::connect(&cli.face_socket)
        .await
        .with_context(|| {
            format!(
                "Cannot connect to '{}'. Is ndn-router running?",
                cli.face_socket
            )
        })?;

    match &cli.command {
        Command::Route { action } => match action {
            RouteAction::Add { prefix, face, cost } => {
                let resp = mgmt
                    .route_add(
                        &prefix
                            .parse()
                            .map_err(|e| anyhow::anyhow!("bad prefix: {e}"))?,
                        *face as u64,
                        *cost as u64,
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                print_params(&resp);
            }
            RouteAction::Remove { prefix, face } => {
                let resp = mgmt
                    .route_remove(
                        &prefix
                            .parse()
                            .map_err(|e| anyhow::anyhow!("bad prefix: {e}"))?,
                        *face as u64,
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                print_params(&resp);
            }
            RouteAction::List => {
                let resp = mgmt
                    .route_list()
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                print_control_response(&resp);
            }
        },
        Command::Face { action } => match action {
            FaceAction::Create { uri } => {
                let resp = mgmt
                    .face_create(uri)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                print_params(&resp);
            }
            FaceAction::Destroy { face_id } => {
                let resp = mgmt
                    .face_destroy(*face_id as u64)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                print_params(&resp);
            }
            FaceAction::List => {
                let resp = mgmt.face_list().await.map_err(|e| anyhow::anyhow!("{e}"))?;
                print_control_response(&resp);
            }
        },
        Command::Strategy { action } => match action {
            StrategyAction::Set { prefix, strategy } => {
                let resp = mgmt
                    .strategy_set(
                        &prefix
                            .parse()
                            .map_err(|e| anyhow::anyhow!("bad prefix: {e}"))?,
                        &strategy
                            .parse()
                            .map_err(|e| anyhow::anyhow!("bad strategy: {e}"))?,
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                print_params(&resp);
            }
            StrategyAction::Unset { prefix } => {
                let resp = mgmt
                    .strategy_unset(
                        &prefix
                            .parse()
                            .map_err(|e| anyhow::anyhow!("bad prefix: {e}"))?,
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                print_params(&resp);
            }
            StrategyAction::List => {
                let resp = mgmt
                    .strategy_list()
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                print_control_response(&resp);
            }
        },
        Command::Cs { action } => match action {
            CsAction::Info => {
                let resp = mgmt.cs_info().await.map_err(|e| anyhow::anyhow!("{e}"))?;
                print_control_response(&resp);
            }
            CsAction::Config { capacity } => {
                let resp = mgmt
                    .cs_config(*capacity)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                print_params(&resp);
            }
            CsAction::Erase { prefix, count } => {
                let name: ndn_packet::Name = prefix
                    .parse()
                    .map_err(|e| anyhow::anyhow!("bad prefix: {e}"))?;
                let resp = mgmt
                    .cs_erase(&name, *count)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                print_params(&resp);
            }
        },
        Command::Status => {
            let resp = mgmt.status().await.map_err(|e| anyhow::anyhow!("{e}"))?;
            print_control_response(&resp);
        }
        Command::Shutdown => {
            let resp = mgmt.shutdown().await.map_err(|e| anyhow::anyhow!("{e}"))?;
            print_control_response(&resp);
        }
    }

    Ok(())
}

#[cfg(not(unix))]
async fn run_nfd(_cli: &Cli) -> anyhow::Result<()> {
    anyhow::bail!("NDN management transport requires Unix domain sockets")
}

// ─── Bypass transport (legacy) ────────────────────────────────────────────────

#[cfg(unix)]
async fn run_bypass(cli: &Cli) -> anyhow::Result<()> {
    let req = build_legacy_request(&cli.command);
    let resp = send_unix(&cli.socket, &req).await?;
    print_legacy_response(resp);
    Ok(())
}

#[cfg(not(unix))]
async fn run_bypass(_cli: &Cli) -> anyhow::Result<()> {
    anyhow::bail!("Bypass transport requires Unix domain sockets")
}

#[cfg(unix)]
async fn send_unix(
    socket_path: &str,
    req: &ManagementRequest,
) -> anyhow::Result<ManagementResponse> {
    use anyhow::Context as _;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    let stream = UnixStream::connect(socket_path).await.with_context(|| {
        format!(
            "Could not connect to '{socket_path}'. Is ndn-router running with bypass transport?"
        )
    })?;

    let (reader, mut writer) = stream.into_split();
    let mut json = serde_json::to_string(req)?;
    json.push('\n');
    writer.write_all(json.as_bytes()).await?;

    let mut lines = BufReader::new(reader).lines();
    let line = lines
        .next_line()
        .await?
        .ok_or_else(|| anyhow::anyhow!("Connection closed before a response was received."))?;

    serde_json::from_str::<ManagementResponse>(&line)
        .with_context(|| format!("Unparseable response: {line}"))
}

#[cfg(unix)]
fn build_legacy_request(cmd: &Command) -> ManagementRequest {
    match cmd {
        Command::Route { action } => match action {
            RouteAction::Add { prefix, face, cost } => ManagementRequest::AddRoute {
                prefix: prefix.clone(),
                face: *face,
                cost: *cost,
            },
            RouteAction::Remove { prefix, face } => ManagementRequest::RemoveRoute {
                prefix: prefix.clone(),
                face: *face,
            },
            RouteAction::List => ManagementRequest::ListRoutes,
        },
        Command::Face { action } => match action {
            FaceAction::List => ManagementRequest::ListFaces,
            // These commands have no legacy equivalent — fall back to stats.
            _ => ManagementRequest::GetStats,
        },
        Command::Status => ManagementRequest::GetStats,
        Command::Shutdown => ManagementRequest::Shutdown,
        // Commands with no legacy equivalent.
        _ => ManagementRequest::GetStats,
    }
}

// ─── Output ──────────────────────────────────────────────────────────────────

fn print_params(params: &ndn_config::ControlParameters) {
    println!("200 OK");
    if let Some(ref name) = params.name {
        println!("  Name:    {}", name);
    }
    if let Some(id) = params.face_id {
        println!("  FaceId:  {id}");
    }
    if let Some(ref uri) = params.uri {
        println!("  Uri:     {uri}");
    }
    if let Some(ref local_uri) = params.local_uri {
        println!("  LocalUri: {local_uri}");
    }
    if let Some(cost) = params.cost {
        println!("  Cost:    {cost}");
    }
    if let Some(origin) = params.origin {
        println!("  Origin:  {origin}");
    }
    if let Some(flags) = params.flags {
        println!("  Flags:   {flags:#x}");
    }
    if let Some(ref strategy) = params.strategy {
        println!("  Strategy: {}", strategy);
    }
    if let Some(capacity) = params.capacity {
        println!("  Capacity: {capacity}");
    }
    if let Some(count) = params.count {
        println!("  Count:   {count}");
    }
}

fn print_control_response(resp: &ControlResponse) {
    println!("{} {}", resp.status_code, resp.status_text);
    if let Some(ref body) = resp.body {
        print_params(body);
    }
}

#[cfg(unix)]
fn print_legacy_response(resp: ManagementResponse) {
    match resp {
        ManagementResponse::Ok => println!("ok"),
        ManagementResponse::OkData { data } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&data).unwrap_or_else(|_| data.to_string())
            );
        }
        ManagementResponse::Error { message } => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
    }
}
