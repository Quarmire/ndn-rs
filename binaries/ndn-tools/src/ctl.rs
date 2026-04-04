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
    /// Manage security identities and trust anchors (local, no router needed).
    Security {
        #[command(subcommand)]
        action: SecurityAction,
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

#[derive(Subcommand)]
enum SecurityAction {
    /// Initialize a new identity (generate key + self-signed cert).
    Init {
        /// NDN name for the identity (e.g. /ndn/router1).
        #[arg(long)]
        name: String,
        /// PIB directory path.
        #[arg(long, default_value = "~/.ndn/pib")]
        pib: String,
    },
    /// Add a trust anchor from a certificate file.
    Trust {
        /// Path to a certificate file (.ndnc).
        cert_file: String,
        /// PIB directory path.
        #[arg(long, default_value = "~/.ndn/pib")]
        pib: String,
    },
    /// Export the identity's certificate.
    Export {
        /// Identity name (default: first identity in PIB).
        #[arg(long)]
        name: Option<String>,
        /// Output file (default: stdout as hex).
        #[arg(long, short)]
        output: Option<String>,
        /// PIB directory path.
        #[arg(long, default_value = "~/.ndn/pib")]
        pib: String,
    },
    /// Display security info (identities, trust anchors).
    Info {
        /// PIB directory path.
        #[arg(long, default_value = "~/.ndn/pib")]
        pib: String,
    },
}

// ─── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Security commands operate on the local PIB — no router connection needed.
    if let Command::Security { ref action } = cli.command {
        return run_security(action);
    }

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
        // Security is handled before run_nfd is called.
        Command::Security { .. } => unreachable!(),
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

// ─── Security subcommands (local PIB, no router) ────────────────────────────

fn run_security(action: &SecurityAction) -> anyhow::Result<()> {
    use ndn_security::{FilePib, SecurityManager};

    match action {
        SecurityAction::Init { name, pib } => {
            let pib_path = expand_tilde(pib);
            let identity: ndn_packet::Name = name
                .parse()
                .map_err(|e| anyhow::anyhow!("bad identity name: {e}"))?;
            let (mgr, generated) = SecurityManager::auto_init(&identity, &pib_path)?;
            if generated {
                println!("Generated new identity: {name}");
                println!("  PIB: {}", pib_path.display());
                println!(
                    "  Trust anchors: {}",
                    mgr.trust_anchor_names().len()
                );
            } else {
                println!("Identity already exists, loaded from PIB");
                println!("  PIB: {}", pib_path.display());
            }
        }

        SecurityAction::Trust { cert_file, pib } => {
            let pib_path = expand_tilde(pib);
            let pib = FilePib::open(&pib_path).map_err(|e| {
                anyhow::anyhow!("Cannot open PIB at '{}': {e}", pib_path.display())
            })?;
            let data = std::fs::read(cert_file)
                .map_err(|e| anyhow::anyhow!("Cannot read '{cert_file}': {e}"))?;
            // The NDNC file contains the cert; we need a name to associate it.
            // Read the name.uri sidecar if present, otherwise derive from filename.
            let uri_path = std::path::Path::new(cert_file).with_extension("uri");
            let cert_name: ndn_packet::Name = if uri_path.exists() {
                let uri = std::fs::read_to_string(&uri_path)?;
                uri.trim()
                    .parse()
                    .map_err(|e| anyhow::anyhow!("bad name in .uri file: {e}"))?
            } else {
                // Fall back: use the file stem as a single-component name.
                let stem = std::path::Path::new(cert_file)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown");
                stem.parse()
                    .map_err(|e| anyhow::anyhow!("bad name from filename: {e}"))?
            };
            let cert = ndn_security::pib::decode_cert(
                std::sync::Arc::new(cert_name.clone()),
                &data,
            )
            .map_err(|e| anyhow::anyhow!("Invalid certificate file: {e}"))?;
            pib.add_trust_anchor(&cert_name, &cert)?;
            println!("Added trust anchor from '{cert_file}'");
        }

        SecurityAction::Export { name, output, pib } => {
            let pib_path = expand_tilde(pib);
            let pib = FilePib::open(&pib_path).map_err(|e| {
                anyhow::anyhow!("Cannot open PIB at '{}': {e}", pib_path.display())
            })?;
            let key_name = if let Some(n) = name {
                n.parse()
                    .map_err(|e| anyhow::anyhow!("bad key name: {e}"))?
            } else {
                let keys = pib.list_keys()?;
                keys.into_iter()
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("No keys in PIB"))?
            };
            let cert = pib.get_cert(&key_name)?;
            let hex = cert
                .public_key
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            if let Some(path) = output {
                std::fs::write(path, &hex)?;
                println!("Certificate exported to '{path}'");
            } else {
                println!("{hex}");
            }
        }

        SecurityAction::Info { pib } => {
            let pib_path = expand_tilde(pib);
            let pib = FilePib::open(&pib_path).map_err(|e| {
                anyhow::anyhow!("Cannot open PIB at '{}': {e}", pib_path.display())
            })?;
            let keys = pib.list_keys()?;
            let anchors = pib.list_anchors()?;

            println!("PIB: {}", pib_path.display());
            println!();
            println!("Keys ({}):", keys.len());
            for k in &keys {
                println!("  {k}");
                if let Ok(cert) = pib.get_cert(k) {
                    let valid = if cert.valid_until == u64::MAX {
                        "never".to_string()
                    } else {
                        format!("{}", cert.valid_until)
                    };
                    println!("    cert: valid_until={valid}");
                }
            }
            println!();
            println!("Trust anchors ({}):", anchors.len());
            for a in &anchors {
                println!("  {a}");
            }
        }
    }

    Ok(())
}

/// Expand a leading `~` to the user's home directory.
fn expand_tilde(path: &str) -> std::path::PathBuf {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return std::path::PathBuf::from(home).join(rest);
    }
    std::path::PathBuf::from(path)
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
