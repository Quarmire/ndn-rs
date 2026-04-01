/// ndn-ctl — send a management command to a running ndn-router.
///
/// Commands are expressed as NFD management Interests sent over the router's
/// face socket (`/tmp/ndn-faces.sock`).  The response is a Data packet whose
/// Content carries a ControlResponse TLV (type 0x65).
///
/// An optional `--bypass` flag falls back to the legacy transport: raw JSON
/// over a Unix socket.
///
/// # NFD protocol
///
/// - **Interest name**: `/localhost/nfd/<module>/<verb>/<ControlParameters>`
/// - **Data Content**: ControlResponse TLV (StatusCode, StatusText, optional body)
///
/// # Examples
///
/// ```sh
/// ndn-ctl add-route /ndn --face 1 --cost 10
/// ndn-ctl remove-route /ndn --face 1
/// ndn-ctl list-routes
/// ndn-ctl list-faces
/// ndn-ctl get-stats
/// ndn-ctl shutdown
///
/// # Custom face socket:
/// ndn-ctl --face-socket /var/run/ndn/faces.sock get-stats
///
/// # Bypass: Unix socket JSON:
/// ndn-ctl --bypass --socket /tmp/ndn-router.sock get-stats
/// ```
use bytes::Bytes;
use clap::{Parser, Subcommand};
use ndn_packet::Name;
use ndn_packet::encode::encode_interest;

use ndn_config::{
    ControlParameters, ControlResponse,
    nfd_command::{module, verb, command_name},
};

// Legacy JSON types (bypass path only).
#[cfg(unix)]
use ndn_config::{ManagementRequest, ManagementResponse};

// ─── CLI definition ───────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name    = "ndn-ctl",
    about   = "Send a management command to a running ndn-router",
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
    /// Add (or update) a FIB route.
    AddRoute {
        /// NDN name prefix (e.g. /ndn/test).
        prefix: String,
        /// Face ID.
        #[arg(long)]
        face: u32,
        /// Routing cost; lower is preferred (default: 10).
        #[arg(long, default_value = "10")]
        cost: u32,
    },
    /// Remove a FIB route.
    RemoveRoute {
        /// NDN name prefix.
        prefix: String,
        /// Face ID.
        #[arg(long)]
        face: u32,
    },
    /// List all FIB routes.
    ListRoutes,
    /// List all registered faces.
    ListFaces,
    /// Create a face.
    FaceCreate {
        /// Face URI (e.g. udp4://192.168.1.1:6363, tcp4://router.example.com:6363).
        uri: String,
    },
    /// Destroy a face.
    FaceDestroy {
        /// Face ID to destroy.
        #[arg(long)]
        face: u32,
    },
    /// Set the forwarding strategy for a name prefix.
    StrategySet {
        /// NDN name prefix (e.g. /ndn/test).
        prefix: String,
        /// Strategy name (e.g. /localhost/nfd/strategy/best-route).
        #[arg(long)]
        strategy: String,
    },
    /// Unset (remove) the forwarding strategy for a name prefix.
    StrategyUnset {
        /// NDN name prefix.
        prefix: String,
    },
    /// List all strategy choices.
    StrategyList,
    /// Display content store info (capacity, entries, memory).
    CsInfo,
    /// Display engine statistics (PIT size, etc.).
    GetStats,
    /// Request a graceful shutdown of the router.
    Shutdown,
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

// ─── NFD TLV transport (primary) ─────────────────────────────────────────────

/// Build the NFD command name and send it as an Interest.
#[cfg(unix)]
async fn run_nfd(cli: &Cli) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use ndn_face_local::UnixFace;
    use ndn_packet::Data;
    use ndn_transport::{Face, FaceId};

    let face = UnixFace::connect(FaceId(0), &cli.face_socket)
        .await
        .with_context(|| {
            format!("Cannot connect to '{}'. Is ndn-router running?", cli.face_socket)
        })?;

    let name = build_nfd_name(&cli.command);
    let interest_bytes = encode_interest(&name, None);

    face.send(interest_bytes).await
        .map_err(|e| anyhow::anyhow!("Failed to send Interest: {e}"))?;

    let data_bytes = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        face.recv(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Timed out waiting for response"))?
    .map_err(|e| anyhow::anyhow!("Failed to receive response: {e}"))?;

    let data = Data::decode(data_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to decode Data response: {e}"))?;

    let content = data.content()
        .ok_or_else(|| anyhow::anyhow!("Data response has no Content field"))?;

    let resp = ControlResponse::decode(Bytes::copy_from_slice(content))
        .map_err(|e| anyhow::anyhow!("Cannot parse ControlResponse: {e}"))?;

    print_control_response(&resp);

    if !resp.is_ok() {
        std::process::exit(1);
    }

    Ok(())
}

#[cfg(not(unix))]
async fn run_nfd(_cli: &Cli) -> anyhow::Result<()> {
    anyhow::bail!("NDN management transport requires Unix domain sockets")
}

// ─── NFD command name builder ────────────────────────────────────────────────

fn build_nfd_name(cmd: &Command) -> Name {
    match cmd {
        Command::AddRoute { prefix, face, cost } => {
            let params = ControlParameters {
                name: Some(prefix.parse().unwrap()),
                face_id: Some(*face as u64),
                cost: Some(*cost as u64),
                ..Default::default()
            };
            command_name(module::RIB, verb::REGISTER, &params)
        }
        Command::RemoveRoute { prefix, face } => {
            let params = ControlParameters {
                name: Some(prefix.parse().unwrap()),
                face_id: Some(*face as u64),
                ..Default::default()
            };
            command_name(module::RIB, verb::UNREGISTER, &params)
        }
        Command::ListRoutes => {
            ndn_config::nfd_command::dataset_name(module::FIB, verb::LIST)
        }
        Command::ListFaces => {
            ndn_config::nfd_command::dataset_name(module::FACES, verb::LIST)
        }
        Command::FaceCreate { uri } => {
            let params = ControlParameters {
                uri: Some(uri.clone()),
                ..Default::default()
            };
            command_name(module::FACES, verb::CREATE, &params)
        }
        Command::FaceDestroy { face } => {
            let params = ControlParameters {
                face_id: Some(*face as u64),
                ..Default::default()
            };
            command_name(module::FACES, verb::DESTROY, &params)
        }
        Command::StrategySet { prefix, strategy } => {
            let params = ControlParameters {
                name: Some(prefix.parse().unwrap()),
                strategy: Some(strategy.parse().unwrap()),
                ..Default::default()
            };
            command_name(module::STRATEGY, verb::SET, &params)
        }
        Command::StrategyUnset { prefix } => {
            let params = ControlParameters {
                name: Some(prefix.parse().unwrap()),
                ..Default::default()
            };
            command_name(module::STRATEGY, verb::UNSET, &params)
        }
        Command::StrategyList => {
            ndn_config::nfd_command::dataset_name(module::STRATEGY, verb::LIST)
        }
        Command::CsInfo => {
            ndn_config::nfd_command::dataset_name(module::CS, verb::INFO)
        }
        Command::GetStats => {
            ndn_config::nfd_command::dataset_name(module::STATUS, b"general")
        }
        Command::Shutdown => {
            ndn_config::nfd_command::dataset_name(module::STATUS, b"shutdown")
        }
    }
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
        format!("Could not connect to '{socket_path}'. Is ndn-router running with bypass transport?")
    })?;

    let (reader, mut writer) = stream.into_split();
    let mut json = serde_json::to_string(req)?;
    json.push('\n');
    writer.write_all(json.as_bytes()).await?;

    let mut lines = BufReader::new(reader).lines();
    let line = lines.next_line().await?.ok_or_else(|| {
        anyhow::anyhow!("Connection closed before a response was received.")
    })?;

    serde_json::from_str::<ManagementResponse>(&line)
        .with_context(|| format!("Unparseable response: {line}"))
}

#[cfg(unix)]
fn build_legacy_request(cmd: &Command) -> ManagementRequest {
    match cmd {
        Command::AddRoute { prefix, face, cost } => ManagementRequest::AddRoute {
            prefix: prefix.clone(),
            face:   *face,
            cost:   *cost,
        },
        Command::RemoveRoute { prefix, face } => ManagementRequest::RemoveRoute {
            prefix: prefix.clone(),
            face:   *face,
        },
        Command::ListRoutes  => ManagementRequest::ListRoutes,
        Command::ListFaces   => ManagementRequest::ListFaces,
        Command::GetStats    => ManagementRequest::GetStats,
        Command::Shutdown    => ManagementRequest::Shutdown,
        // These commands have no legacy equivalent — use NFD transport.
        Command::StrategySet { .. }
        | Command::StrategyUnset { .. }
        | Command::StrategyList
        | Command::CsInfo
        | Command::FaceCreate { .. }
        | Command::FaceDestroy { .. } => ManagementRequest::GetStats, // placeholder; bypass won't be used
    }
}

// ─── Output ──────────────────────────────────────────────────────────────────

fn print_control_response(resp: &ControlResponse) {
    println!("{} {}", resp.status_code, resp.status_text);
    if let Some(ref body) = resp.body {
        if let Some(ref name) = body.name {
            println!("  Name:    {}", name);
        }
        if let Some(id) = body.face_id {
            println!("  FaceId:  {id}");
        }
        if let Some(ref uri) = body.uri {
            println!("  Uri:     {uri}");
        }
        if let Some(ref local_uri) = body.local_uri {
            println!("  LocalUri: {local_uri}");
        }
        if let Some(cost) = body.cost {
            println!("  Cost:    {cost}");
        }
        if let Some(origin) = body.origin {
            println!("  Origin:  {origin}");
        }
        if let Some(flags) = body.flags {
            println!("  Flags:   {flags:#x}");
        }
        if let Some(ref strategy) = body.strategy {
            println!("  Strategy: {}", strategy);
        }
    }
}

#[cfg(unix)]
fn print_legacy_response(resp: ManagementResponse) {
    match resp {
        ManagementResponse::Ok => println!("ok"),
        ManagementResponse::OkData { data } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&data)
                    .unwrap_or_else(|_| data.to_string())
            );
        }
        ManagementResponse::Error { message } => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
    }
}

