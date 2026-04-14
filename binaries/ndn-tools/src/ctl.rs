/// ndn-ctl — send management commands to a running ndn-fwd forwarder.
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
/// ndn-ctl neighbors list
/// ndn-ctl service list
/// ndn-ctl service browse
/// ndn-ctl service browse /ndn/sensors
/// ndn-ctl service announce /ndn/app
/// ndn-ctl service withdraw /ndn/app
/// ndn-ctl status
/// ndn-ctl shutdown
/// ```
use clap::{Parser, Subcommand};

use ndn_config::ControlResponse;
use ndn_ipc::MgmtClient;

// ─── CLI definition ───────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "ndn-ctl",
    about = "Send management commands to a running ndn-fwd forwarder",
    version
)]
struct Cli {
    /// Router socket path.
    ///
    /// On Unix: path to a Unix domain socket (e.g. `/run/nfd/nfd.sock`).
    /// On Windows: a Named Pipe path (e.g. `\\.\pipe\ndn`).
    /// May also be set via $NDN_SOCK.
    #[arg(
        long,
        env = "NDN_SOCK",
        default_value_t = ndn_config::ManagementConfig::default().face_socket,
    )]
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
    /// List discovered neighbors.
    Neighbors {
        #[command(subcommand)]
        action: NeighborsAction,
    },
    /// Manage service discovery announcements.
    Service {
        #[command(subcommand)]
        action: ServiceAction,
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
    /// List all FIB routes (forwarding table).
    List,
    /// List all RIB routes (routing information base).
    RibList,
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
enum NeighborsAction {
    /// List all discovered neighbors.
    List,
}

#[derive(Subcommand)]
enum ServiceAction {
    /// List locally announced service prefixes.
    List,
    /// Browse all known service records (local + received from peers).
    Browse {
        /// Optional prefix filter — only show records under this prefix.
        prefix: Option<String>,
    },
    /// Announce a service prefix at runtime.
    Announce {
        /// NDN name prefix to announce (e.g. /ndn/app/sensor).
        prefix: String,
    },
    /// Withdraw a previously announced service prefix.
    Withdraw {
        /// NDN name prefix to withdraw.
        prefix: String,
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

    run_nfd(&cli).await
}

// ─── NFD transport (primary) ────────────────────────────────────────────────

async fn run_nfd(cli: &Cli) -> anyhow::Result<()> {
    use anyhow::Context as _;

    let mgmt = MgmtClient::connect(&cli.socket)
        .await
        .with_context(|| format!("Cannot connect to '{}'. Is ndn-fwd running?", cli.socket))?;

    match &cli.command {
        Command::Route { action } => match action {
            RouteAction::Add { prefix, face, cost } => {
                let resp = mgmt
                    .route_add(
                        &prefix
                            .parse()
                            .map_err(|e| anyhow::anyhow!("bad prefix: {e}"))?,
                        Some(*face as u64),
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
                        Some(*face as u64),
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                print_params(&resp);
            }
            RouteAction::List => {
                let entries = mgmt
                    .route_list()
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                print_fib_list(&entries);
            }
            RouteAction::RibList => {
                let entries = mgmt.rib_list().await.map_err(|e| anyhow::anyhow!("{e}"))?;
                print_rib_list(&entries);
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
                let entries = mgmt.face_list().await.map_err(|e| anyhow::anyhow!("{e}"))?;
                print_face_list(&entries);
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
                let entries = mgmt
                    .strategy_list()
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                print_strategy_list(&entries);
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
        Command::Neighbors { action } => match action {
            NeighborsAction::List => {
                let resp = mgmt
                    .neighbors_list()
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                print_control_response(&resp);
            }
        },
        Command::Service { action } => match action {
            ServiceAction::List => {
                let resp = mgmt
                    .service_list()
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                print_control_response(&resp);
            }
            ServiceAction::Browse { prefix } => {
                let parsed = prefix
                    .as_ref()
                    .map(|p| p.parse::<ndn_packet::Name>())
                    .transpose()
                    .map_err(|e| anyhow::anyhow!("bad prefix: {e}"))?;
                let resp = mgmt
                    .service_browse(parsed.as_ref())
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                print_control_response(&resp);
            }
            ServiceAction::Announce { prefix } => {
                let resp = mgmt
                    .service_announce(
                        &prefix
                            .parse()
                            .map_err(|e| anyhow::anyhow!("bad prefix: {e}"))?,
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                print_params(&resp);
            }
            ServiceAction::Withdraw { prefix } => {
                let resp = mgmt
                    .service_withdraw(
                        &prefix
                            .parse()
                            .map_err(|e| anyhow::anyhow!("bad prefix: {e}"))?,
                    )
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
                println!("  Trust anchors: {}", mgr.trust_anchor_names().len());
            } else {
                println!("Identity already exists, loaded from PIB");
                println!("  PIB: {}", pib_path.display());
            }
        }

        SecurityAction::Trust { cert_file, pib } => {
            let pib_path = expand_tilde(pib);
            let pib = FilePib::open(&pib_path)
                .map_err(|e| anyhow::anyhow!("Cannot open PIB at '{}': {e}", pib_path.display()))?;
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
            let cert =
                ndn_security::pib::decode_cert(std::sync::Arc::new(cert_name.clone()), &data)
                    .map_err(|e| anyhow::anyhow!("Invalid certificate file: {e}"))?;
            pib.add_trust_anchor(&cert_name, &cert)?;
            println!("Added trust anchor from '{cert_file}'");
        }

        SecurityAction::Export { name, output, pib } => {
            let pib_path = expand_tilde(pib);
            let pib = FilePib::open(&pib_path)
                .map_err(|e| anyhow::anyhow!("Cannot open PIB at '{}': {e}", pib_path.display()))?;
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
            let pib = FilePib::open(&pib_path)
                .map_err(|e| anyhow::anyhow!("Cannot open PIB at '{}': {e}", pib_path.display()))?;
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

// ─── Output helpers ──────────────────────────────────────────────────────────

fn face_kind(uri: &str) -> &'static str {
    if uri.starts_with("udp4://") || uri.starts_with("udp6://") || uri.starts_with("udp://") {
        "UDP"
    } else if uri.starts_with("tcp4://") || uri.starts_with("tcp6://") || uri.starts_with("tcp://")
    {
        "TCP"
    } else if uri.starts_with("ws://") || uri.starts_with("wss://") {
        "WS"
    } else if uri.starts_with("ether://") {
        "Ether"
    } else if uri.starts_with("shm://") {
        "SHM"
    } else if uri.starts_with("unix://") {
        "Unix"
    } else if uri.starts_with("null://") {
        "Null"
    } else {
        "?"
    }
}

fn link_type_str(v: u64) -> &'static str {
    match v {
        0 => "point-to-point",
        1 => "multi-access",
        254 => "ad-hoc",
        _ => "?",
    }
}

fn origin_str(v: u64) -> String {
    match v {
        0 => "app".to_string(),
        64 => "autoreg".to_string(),
        65 => "client".to_string(),
        66 => "autoconf".to_string(),
        127 => "dvr".to_string(),
        128 => "nlsr".to_string(),
        129 => "prefix-ann".to_string(),
        255 => "static".to_string(),
        n => n.to_string(),
    }
}

fn route_flags_str(flags: u64) -> String {
    let mut parts = Vec::new();
    if flags & 0x01 != 0 {
        parts.push("child-inherit");
    }
    if flags & 0x02 != 0 {
        parts.push("capture");
    }
    if parts.is_empty() {
        "\u{2014}".to_string()
    } else {
        parts.join(",")
    }
}

fn fmt_bytes(n: u64) -> String {
    if n < 1024 {
        format!("{n} B")
    } else if n < 1_048_576 {
        format!("{:.1} KiB", n as f64 / 1024.0)
    } else if n < 1_073_741_824 {
        format!("{:.1} MiB", n as f64 / 1_048_576.0)
    } else {
        format!("{:.2} GiB", n as f64 / 1_073_741_824.0)
    }
}

// ─── Output ──────────────────────────────────────────────────────────────────

fn print_face_list(faces: &[ndn_config::FaceStatus]) {
    for (i, f) in faces.iter().enumerate() {
        if i > 0 {
            println!();
        }
        // Determine the kind label from whichever URI is non-empty.
        let kind = if !f.uri.is_empty() {
            face_kind(&f.uri)
        } else {
            face_kind(&f.local_uri)
        };
        // First line: faceid, kind, persistency, scope, link-type, optional mtu.
        let mtu_suffix = if let Some(mtu) = f.mtu {
            format!("  mtu={mtu}")
        } else {
            String::new()
        };
        println!(
            "faceid={}  {}  {}  {}  {}{}",
            f.face_id,
            kind,
            f.persistency_str(),
            f.scope_str(),
            link_type_str(f.link_type),
            mtu_suffix,
        );
        // Remote URI line (only when non-empty).
        if !f.uri.is_empty() {
            println!("  remote: {}", f.uri);
        }
        // Local URI line (only when non-empty).
        if !f.local_uri.is_empty() {
            println!("  local:  {}", f.local_uri);
        }
        // Counter lines.
        println!(
            "  in:  interests={}  data={}  nacks={}  bytes={}",
            f.n_in_interests,
            f.n_in_data,
            f.n_in_nacks,
            fmt_bytes(f.n_in_bytes),
        );
        println!(
            "  out: interests={}  data={}  nacks={}  bytes={}",
            f.n_out_interests,
            f.n_out_data,
            f.n_out_nacks,
            fmt_bytes(f.n_out_bytes),
        );
    }
}

fn print_fib_list(entries: &[ndn_config::FibEntry]) {
    // Compute column width for the prefix column.
    let prefix_w = entries
        .iter()
        .flat_map(|e| {
            let p = e.name.to_string();
            std::iter::repeat_n(p.len(), e.nexthops.len().max(1))
        })
        .max()
        .unwrap_or(0)
        .max(6);

    println!("{:<prefix_w$}  {:>6}  {:>6}", "Prefix", "FaceID", "Cost");
    println!("{}", "\u{2500}".repeat(prefix_w + 16));

    for entry in entries {
        let prefix = entry.name.to_string();
        for nh in &entry.nexthops {
            println!("{:<prefix_w$}  {:>6}  {:>6}", prefix, nh.face_id, nh.cost);
        }
    }
}

fn print_rib_list(entries: &[ndn_config::RibEntry]) {
    // Compute column width for the prefix column.
    let prefix_w = entries
        .iter()
        .flat_map(|e| {
            let p = e.name.to_string();
            std::iter::repeat_n(p.len(), e.routes.len().max(1))
        })
        .max()
        .unwrap_or(0)
        .max(6);

    println!(
        "{:<prefix_w$}  {:>6}  {:>8}  {:>6}  Flags",
        "Prefix", "FaceID", "Origin", "Cost"
    );
    println!("{}", "\u{2500}".repeat(prefix_w + 36));

    for entry in entries {
        let prefix = entry.name.to_string();
        for route in &entry.routes {
            let origin = origin_str(route.origin);
            let flags = route_flags_str(route.flags);
            let expiry = if let Some(ep) = route.expiration_period {
                format!("  expiry={}s", ep / 1000)
            } else {
                String::new()
            };
            println!(
                "{:<prefix_w$}  {:>6}  {:>8}  {:>6}  {}{}",
                prefix, route.face_id, origin, route.cost, flags, expiry,
            );
        }
    }
}

fn print_strategy_list(entries: &[ndn_config::StrategyChoice]) {
    // Compute column width for the prefix column.
    let prefix_w = entries
        .iter()
        .map(|e| e.name.to_string().len())
        .max()
        .unwrap_or(0)
        .max(6);

    println!("{:<prefix_w$}  Strategy", "Prefix");
    println!("{}", "\u{2500}".repeat(prefix_w + 2 + 32));

    for entry in entries {
        let prefix = entry.name.to_string();
        println!("{:<prefix_w$}  {}", prefix, entry.strategy);
    }
}

fn print_params(params: &ndn_config::ControlParameters) {
    println!("\u{2713} 200 OK");
    if let Some(ref name) = params.name {
        println!("  name:      {name}");
    }
    if let Some(id) = params.face_id {
        println!("  face-id:   {id}");
    }
    if let Some(ref uri) = params.uri {
        println!("  uri:       {uri}");
    }
    if let Some(ref local_uri) = params.local_uri {
        println!("  local-uri: {local_uri}");
    }
    if let Some(cost) = params.cost {
        println!("  cost:      {cost}");
    }
    if let Some(origin) = params.origin {
        println!("  origin:    {} ({origin})", origin_str(origin));
    }
    if let Some(flags) = params.flags {
        println!("  flags:     {} ({flags:#x})", route_flags_str(flags));
    }
    if let Some(ref strategy) = params.strategy {
        println!("  strategy:  {strategy}");
    }
    if let Some(capacity) = params.capacity {
        println!("  capacity:  {}", fmt_bytes(capacity));
    }
    if let Some(count) = params.count {
        println!("  count:     {count}");
    }
}

fn print_control_response(resp: &ControlResponse) {
    let symbol = if resp.is_ok() { "\u{2713}" } else { "\u{2717}" };
    println!("{symbol} {} {}", resp.status_code, resp.status_text);
    if let Some(ref body) = resp.body {
        print_params(body);
    }
}
