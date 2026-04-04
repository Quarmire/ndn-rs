use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use ndn_config::{CsConfig, ForwarderConfig};
#[cfg(unix)]
use ndn_config::{ManagementRequest, ManagementResponse, ManagementServer};
use ndn_engine::{EngineBuilder, EngineConfig, ForwarderEngine};
use ndn_face_local::AppFace;
use ndn_packet::Name;
use ndn_security::{FilePib, SecurityManager};
use ndn_store::{ErasedContentStore, LruCs, NullCs, ShardedCs};

// Unix-socket bypass management I/O.
#[cfg(unix)]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::UnixListener;

// NDN-native management: face listener + Interest/Data handler.
mod mgmt_ndn;

// ─── Entry point ──────────────────────────────────────────────────────────────

/// Parsed CLI arguments.
struct CliArgs {
    config_path: Option<PathBuf>,
    log_level: Option<String>,
}

/// Parse `argv` into CLI arguments.
fn parse_args() -> CliArgs {
    let args: Vec<String> = std::env::args().collect();
    let mut config_path = None;
    let mut log_level = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-c" | "--config" => {
                i += 1;
                if let Some(p) = args.get(i) {
                    config_path = Some(PathBuf::from(p));
                }
            }
            "--log-level" => {
                i += 1;
                if let Some(l) = args.get(i) {
                    log_level = Some(l.clone());
                }
            }
            _ => {}
        }
        i += 1;
    }
    CliArgs {
        config_path,
        log_level,
    }
}

/// Initialise the tracing subscriber.
///
/// **Precedence** (highest wins):
/// 1. `RUST_LOG` environment variable
/// 2. `--log-level` CLI flag
/// 3. `[logging] level` from the config file
///
/// When `[logging] file` is set, logs are written to *both* stderr and the
/// file. The file appender is non-blocking so log writes never stall the
/// forwarder.
///
/// Returns an optional guard that must be held for the lifetime of the
/// process — dropping it flushes the file appender.
fn init_tracing(
    config: &ndn_config::LoggingConfig,
    cli_log_level: Option<&str>,
) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    // Resolve filter: RUST_LOG > --log-level > config level.
    let filter_str = if std::env::var("RUST_LOG").is_ok() {
        // EnvFilter::from_default_env() will pick up RUST_LOG automatically,
        // but we still need a string for the file layer's filter.
        std::env::var("RUST_LOG").unwrap()
    } else if let Some(cli) = cli_log_level {
        cli.to_owned()
    } else {
        config.level.clone()
    };

    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_thread_ids(true);

    // If a log file is configured, set up a non-blocking file appender.
    if let Some(ref path) = config.file {
        let log_path = std::path::Path::new(path);

        // Create parent directories if they don't exist.
        if let Some(parent) = log_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let file_appender = tracing_appender::rolling::never(
            log_path.parent().unwrap_or(std::path::Path::new(".")),
            log_path.file_name().unwrap_or(std::ffi::OsStr::new("ndn-router.log")),
        );
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

        let file_layer = tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_thread_ids(true)
            .with_ansi(false)
            .with_writer(non_blocking);

        tracing_subscriber::registry()
            .with(EnvFilter::new(&filter_str))
            .with(stderr_layer)
            .with(file_layer)
            .init();

        Some(guard)
    } else {
        tracing_subscriber::registry()
            .with(EnvFilter::new(&filter_str))
            .with(stderr_layer)
            .init();

        None
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = parse_args();

    // Load config or use defaults (before tracing init so we have the
    // logging section available).
    let fwd_config = if let Some(ref path) = cli.config_path {
        ForwarderConfig::from_file(path)?
    } else {
        ForwarderConfig::default()
    };

    // Initialise tracing — must hold the guard until shutdown.
    let _log_guard = init_tracing(&fwd_config.logging, cli.log_level.as_deref());

    if let Some(ref path) = cli.config_path {
        tracing::info!(path = %path.display(), "loading config");
    } else {
        tracing::info!("no config file specified, using defaults");
    }
    if let Some(ref file) = fwd_config.logging.file {
        tracing::info!(path = %file, "logging to file");
    }

    // Resolve CS capacity: prefer [cs] section, fall back to engine.cs_capacity_mb.
    let cs_cap_mb = if fwd_config.cs.capacity_mb != 0 {
        fwd_config.cs.capacity_mb
    } else {
        fwd_config.engine.cs_capacity_mb
    };

    let engine_config = EngineConfig {
        cs_capacity_bytes: cs_cap_mb * 1024 * 1024,
        pipeline_channel_cap: fwd_config.engine.pipeline_channel_cap,
        pipeline_threads: fwd_config.engine.pipeline_threads,
    };

    // ── NDN management: pre-register management AppFace ───────────────────────
    //
    // An AppFace is registered with the engine before build so it gets a
    // run_face_reader task.  After build, /localhost/ndn-ctl is added to the
    // FIB pointing at this face.  The NDN management handler reads Interests
    // from the AppHandle side and writes Data responses back.
    const MGMT_FACE_ID: u32 = 0xFFFF_0001;
    let (mgmt_app_face, mgmt_handle) = AppFace::new(ndn_transport::FaceId(MGMT_FACE_ID), 64);

    let security_mgr = load_security(&fwd_config);

    let cs = build_cs(&fwd_config.cs);
    let admission: Arc<dyn ndn_store::CsAdmissionPolicy> =
        match fwd_config.cs.admission_policy.as_str() {
            "admit-all" => Arc::new(ndn_store::AdmitAllPolicy),
            _ => Arc::new(ndn_store::DefaultAdmissionPolicy),
        };

    let security_profile = match fwd_config.security.profile.as_str() {
        "disabled" => ndn_security::SecurityProfile::Disabled,
        "accept-signed" => ndn_security::SecurityProfile::AcceptSigned,
        _ => ndn_security::SecurityProfile::Default,
    };

    let mut builder = EngineBuilder::new(engine_config)
        .face(mgmt_app_face)
        .content_store(cs)
        .admission_policy(admission)
        .security_profile(security_profile);
    if let Some(mgr) = security_mgr {
        builder = builder.security(mgr);
    }

    let (engine, shutdown) = builder.build().await?;

    // Apply static FIB routes from config.
    for route in &fwd_config.routes {
        let name = parse_name(&route.prefix);
        engine
            .fib()
            .add_nexthop(&name, ndn_transport::FaceId(route.face as u32), route.cost);
        tracing::info!(prefix = %route.prefix, face = route.face, cost = route.cost, "route added");
    }

    // Register the management prefix in the FIB so the pipeline routes
    // /localhost/ndn-ctl/... Interests to the management AppFace.
    engine.fib().add_nexthop(
        &mgmt_ndn::mgmt_prefix(),
        ndn_transport::FaceId(MGMT_FACE_ID),
        0,
    );

    // ── Startup face listeners from config ──────────────────────────────────
    //
    // If no [[face]] entries are configured, start default UDP and TCP
    // listeners on 0.0.0.0:6363 (matches NFD default behavior).

    let cancel = CancellationToken::new();

    let face_configs: std::borrow::Cow<'_, [ndn_config::FaceConfig]> =
        if fwd_config.faces.is_empty() {
            tracing::info!("no [[face]] in config, using defaults: udp+tcp on 0.0.0.0:6363");
            std::borrow::Cow::Owned(vec![
                ndn_config::FaceConfig::Udp {
                    bind: Some("0.0.0.0:6363".into()),
                    remote: None,
                },
                ndn_config::FaceConfig::Tcp {
                    bind: Some("0.0.0.0:6363".into()),
                    remote: None,
                },
            ])
        } else {
            std::borrow::Cow::Borrowed(&fwd_config.faces)
        };

    for face_cfg in face_configs.iter() {
        match face_cfg {
            ndn_config::FaceConfig::Udp { bind, .. } => {
                if let Some(addr) =
                    parse_bind_addr(bind.as_deref().unwrap_or("0.0.0.0:6363"), "UDP")
                {
                    let eng = engine.clone();
                    let c = cancel.clone();
                    tokio::spawn(async move {
                        mgmt_ndn::run_udp_listener(addr, eng, c).await;
                    });
                }
            }
            ndn_config::FaceConfig::Tcp { bind, .. } => {
                if let Some(addr) =
                    parse_bind_addr(bind.as_deref().unwrap_or("0.0.0.0:6363"), "TCP")
                {
                    let eng = engine.clone();
                    let c = cancel.clone();
                    tokio::spawn(async move {
                        mgmt_ndn::run_tcp_listener(addr, eng, c).await;
                    });
                }
            }
            ndn_config::FaceConfig::Multicast { .. } => {
                // TODO: multicast UDP face from config
                tracing::warn!("multicast face config not yet supported at startup");
            }
            ndn_config::FaceConfig::Unix { .. } => {
                // Unix faces are handled by the face listener below.
                tracing::warn!("unix face config ignored (use [management] face_socket)");
            }
            ndn_config::FaceConfig::WebSocket { bind, .. } => {
                let Some(bind_str) = bind.as_deref() else {
                    tracing::error!("websocket face requires 'bind' address");
                    continue;
                };
                if let Some(addr) = parse_bind_addr(bind_str, "WebSocket") {
                    let eng = engine.clone();
                    let c = cancel.clone();
                    tokio::spawn(async move {
                        run_ws_listener(addr, eng, c).await;
                    });
                }
            }
            ndn_config::FaceConfig::Serial { path, baud } => {
                #[cfg(feature = "serial")]
                {
                    let id = engine.faces().alloc_id();
                    match ndn_face_serial::serial_face_open(id, path, *baud) {
                        Ok(face) => {
                            let c = cancel.child_token();
                            engine.add_face(face, c);
                            tracing::info!(port=%path, baud=%baud, face=%id, "serial face opened");
                        }
                        Err(e) => {
                            tracing::error!(port=%path, error=%e, "failed to open serial face");
                        }
                    }
                }
                #[cfg(not(feature = "serial"))]
                {
                    let _ = (path, baud);
                    tracing::warn!("serial face support not compiled in");
                }
            }
            ndn_config::FaceConfig::EtherMulticast { interface } => {
                #[cfg(target_os = "linux")]
                {
                    let id = engine.faces().alloc_id();
                    match ndn_face_l2::MulticastEtherFace::new(id, interface) {
                        Ok(face) => {
                            let c = cancel.child_token();
                            engine.add_face_with_persistency(
                                face,
                                c,
                                ndn_transport::FacePersistency::Permanent,
                            );
                            tracing::info!(iface=%interface, face=%id, "multicast ethernet face opened");
                        }
                        Err(e) => {
                            tracing::error!(iface=%interface, error=%e, "failed to open multicast ethernet face");
                        }
                    }
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = interface;
                    tracing::warn!("ether-multicast face only supported on Linux");
                }
            }
        }
    }

    tracing::info!("engine running");

    // ── Management transport selection ────────────────────────────────────────
    //
    // [management]
    // transport = "ndn"    (default) — NDN Interest/Data over face socket
    // transport = "bypass"           — raw JSON over Unix socket
    //
    // Bypass transports are kept for emergency access when the pipeline is
    // broken or during bootstrapping.

    let use_ndn_mgmt = fwd_config.management.transport == "ndn";

    // ── NDN management ────────────────────────────────────────────────────────
    #[cfg(unix)]
    let (ndn_handler_task, ndn_listener_task) = if use_ndn_mgmt {
        let face_socket = PathBuf::from(&fwd_config.management.face_socket);
        tracing::info!(
            socket = %face_socket.display(),
            prefix = "/localhost/nfd",
            "NFD management active"
        );

        let handler = tokio::spawn(mgmt_ndn::run_ndn_mgmt_handler(
            mgmt_handle,
            engine.clone(),
            cancel.clone(),
        ));
        let listener_engine = engine.clone();
        let listener_cancel = cancel.clone();
        let listener = tokio::spawn(async move {
            mgmt_ndn::run_face_listener(&face_socket, listener_engine, listener_cancel).await;
        });
        (Some(handler), Some(listener))
    } else {
        (None, None)
    };

    // ── Bypass management ─────────────────────────────────────────────────────

    #[cfg(unix)]
    let bypass_task = if !use_ndn_mgmt {
        let bypass_path = PathBuf::from(&fwd_config.management.bypass_socket);
        let mgmt_engine = engine.clone();
        let cancel_clone = cancel.clone();
        tracing::info!(path = %bypass_path.display(), "bypass: Unix socket management");
        Some(tokio::spawn(run_unix_mgmt_server(
            bypass_path,
            mgmt_engine,
            cancel_clone,
        )))
    } else {
        None
    };

    #[cfg(not(unix))]
    if !use_ndn_mgmt {
        tracing::warn!("bypass management unavailable on non-Unix platforms");
    }

    // Wait for Ctrl-C.
    tokio::signal::ctrl_c().await?;

    tracing::info!("shutting down");
    cancel.cancel();

    #[cfg(unix)]
    {
        if let Some(t) = ndn_handler_task {
            let _ = t.await;
        }
        if let Some(t) = ndn_listener_task {
            let _ = t.await;
        }
    }

    #[cfg(unix)]
    if let Some(t) = bypass_task {
        let _ = t.await;
    }

    shutdown.shutdown().await;
    Ok(())
}

// ─── Legacy JSON management request dispatch (bypass only) ───────────────────

/// Dispatch a legacy JSON management request against the live engine.
///
/// Used only by the bypass Unix socket transport. The primary management
/// path uses NFD-compatible TLV protocol via `mgmt_ndn`.
#[cfg(unix)]
fn handle_request(
    req: ManagementRequest,
    engine: &ForwarderEngine,
    cancel: &CancellationToken,
) -> ManagementResponse {
    match req {
        ManagementRequest::AddRoute { prefix, face, cost } => {
            let name = parse_name(&prefix);
            engine
                .fib()
                .add_nexthop(&name, ndn_transport::FaceId(face), cost);
            tracing::info!(%prefix, face, cost, "management: route added");
            ManagementResponse::Ok
        }
        ManagementRequest::RemoveRoute { prefix, face } => {
            let name = parse_name(&prefix);
            engine
                .fib()
                .remove_nexthop(&name, ndn_transport::FaceId(face));
            tracing::info!(%prefix, face, "management: route removed");
            ManagementResponse::Ok
        }
        ManagementRequest::ListFaces => {
            let entries: Vec<serde_json::Value> = engine
                .faces()
                .face_entries()
                .into_iter()
                .filter(|(_, kind)| {
                    !matches!(
                        kind,
                        ndn_transport::FaceKind::App | ndn_transport::FaceKind::Internal
                    )
                })
                .map(|(id, kind)| {
                    serde_json::json!({
                        "id":   id.0,
                        "kind": kind.to_string(),
                    })
                })
                .collect();
            ManagementResponse::OkData {
                data: serde_json::json!({ "faces": entries }),
            }
        }
        ManagementRequest::ListRoutes => {
            let routes: Vec<serde_json::Value> = engine
                .fib()
                .dump()
                .into_iter()
                .map(|(name, entry)| {
                    let nexthops: Vec<serde_json::Value> = entry
                        .nexthops
                        .iter()
                        .map(|n| serde_json::json!({ "face": n.face_id.0, "cost": n.cost }))
                        .collect();
                    serde_json::json!({ "prefix": name.to_string(), "nexthops": nexthops })
                })
                .collect();
            ManagementResponse::OkData {
                data: serde_json::json!({ "routes": routes }),
            }
        }
        ManagementRequest::GetStats => {
            let pit_size = engine.pit().len();
            ManagementResponse::OkData {
                data: serde_json::json!({ "pit_size": pit_size }),
            }
        }
        ManagementRequest::Shutdown => {
            tracing::info!("management: shutdown requested");
            cancel.cancel();
            ManagementResponse::Ok
        }
    }
}

// ─── Unix socket management server ────────────────────────────────────────────

/// Accept bypass management connections on a Unix socket until `cancel` fires.
///
/// Uses the raw JSON protocol (newline-delimited).  Only active when
/// `[management] transport = "bypass"`.
#[cfg(unix)]
async fn run_unix_mgmt_server(path: PathBuf, engine: ForwarderEngine, cancel: CancellationToken) {
    // Remove stale socket file if it exists.
    let _ = std::fs::remove_file(&path);

    let listener = match UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, "failed to bind management socket");
            return;
        }
    };

    let engine = Arc::new(engine);

    loop {
        let conn = tokio::select! {
            _ = cancel.cancelled() => break,
            c = listener.accept() => match c {
                Ok((stream, _)) => stream,
                Err(e) => {
                    tracing::warn!(error = %e, "management accept error");
                    continue;
                }
            },
        };

        let eng = Arc::clone(&engine);
        let cancel = cancel.clone();
        tokio::spawn(async move {
            let (reader, mut writer) = conn.into_split();
            let mut lines = BufReader::new(reader).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let resp = match ManagementServer::decode_request(&line) {
                    Ok(req) => handle_request(req, &eng, &cancel),
                    Err(msg) => ManagementResponse::Error { message: msg },
                };
                let encoded = ManagementServer::encode_response(&resp);
                let _ = writer.write_all(encoded.as_bytes()).await;
                let _ = writer.write_all(b"\n").await;
            }
        });
    }

    let _ = std::fs::remove_file(&path);
}

// ─── WebSocket listener ──────────────────────────────────────────────────────

/// Accept WebSocket connections and create a `WebSocketFace` for each.
#[cfg(feature = "websocket")]
async fn run_ws_listener(
    bind_addr: std::net::SocketAddr,
    engine: ForwarderEngine,
    cancel: CancellationToken,
) {
    let listener = match tokio::net::TcpListener::bind(bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(addr=%bind_addr, error=%e, "ws-listener: bind failed");
            return;
        }
    };

    let local = listener.local_addr().unwrap_or(bind_addr);
    tracing::info!(addr=%local, "WebSocket listener ready");

    loop {
        let (stream, peer) = tokio::select! {
            _ = cancel.cancelled() => break,
            r = listener.accept() => match r {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error=%e, "ws-listener: accept error");
                    continue;
                }
            },
        };

        let ws =
            match tokio_tungstenite::accept_async(tokio_tungstenite::MaybeTlsStream::Plain(stream))
                .await
            {
                Ok(ws) => ws,
                Err(e) => {
                    tracing::warn!(peer=%peer, error=%e, "ws-listener: handshake failed");
                    continue;
                }
            };

        let face_id = engine.faces().alloc_id();
        let face = ndn_face_net::WebSocketFace::from_stream(
            face_id,
            ws,
            peer.to_string(),
            local.to_string(),
        );
        let conn_cancel = cancel.child_token();
        engine.add_face(face, conn_cancel);
        tracing::info!(face=%face_id, peer=%peer, "ws-listener: accepted connection");
    }

    tracing::info!("WebSocket listener stopped");
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Load the router's security identity from the PIB specified in `[security]`.
///
/// When `auto_init` is enabled and no keys exist, generates a new identity
/// with a self-signed certificate.  Returns `Some(SecurityManager)` on
/// success; `None` on failure or when no identity is configured.  Failures
/// are non-fatal: the router starts without a security identity and logs a
/// warning instead.
fn load_security(cfg: &ForwarderConfig) -> Option<SecurityManager> {
    let identity_uri = cfg.security.identity.as_ref()?;

    let pib_path = cfg
        .security
        .pib_path
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(default_pib_path);

    let identity = parse_name(identity_uri);

    if cfg.security.auto_init {
        match SecurityManager::auto_init(&identity, &pib_path) {
            Ok((mgr, generated)) => {
                if generated {
                    tracing::info!(
                        identity = %identity_uri,
                        pib = %pib_path.display(),
                        "auto-initialized new security identity"
                    );
                } else {
                    tracing::info!(
                        identity = %identity_uri,
                        pib = %pib_path.display(),
                        "loaded existing security identity from PIB"
                    );
                }
                return Some(mgr);
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    identity = %identity_uri,
                    "auto-init failed; starting without security identity"
                );
                return None;
            }
        }
    }

    let pib = match FilePib::open(&pib_path) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(
                error = %e,
                pib = %pib_path.display(),
                "PIB not found; starting without security identity"
            );
            return None;
        }
    };

    match SecurityManager::from_pib(&pib, &identity) {
        Ok(mgr) => {
            tracing::info!(
                identity = %identity_uri,
                pib = %pib_path.display(),
                "loaded security identity from PIB"
            );
            Some(mgr)
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                identity = %identity_uri,
                "failed to load security identity; starting without it"
            );
            None
        }
    }
}

/// Default PIB path: `$HOME/.ndn/pib`.
fn default_pib_path() -> PathBuf {
    let mut p = std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"));
    p.push(".ndn");
    p.push("pib");
    p
}

/// Parse a bind address string into a `SocketAddr`, logging errors on failure.
fn parse_bind_addr(bind: &str, label: &str) -> Option<std::net::SocketAddr> {
    match bind.parse() {
        Ok(a) => Some(a),
        Err(e) => {
            tracing::error!(bind=%bind, error=%e, "invalid {label} bind address");
            None
        }
    }
}

/// Parse a URI-style NDN name like `/ndn/test` into a `Name`.
fn parse_name(uri: &str) -> Name {
    uri.parse().unwrap_or_else(|_| Name::root())
}

/// Build a content store from config.
fn build_cs(cfg: &CsConfig) -> Arc<dyn ErasedContentStore> {
    let cap = cfg.capacity_mb * 1024 * 1024;
    match cfg.variant.as_str() {
        "null" => {
            tracing::info!("content store disabled (variant=null)");
            Arc::new(NullCs)
        }
        "sharded-lru" => {
            let n = cfg.shards.unwrap_or(4);
            tracing::info!(variant = "sharded-lru", shards = n, capacity_mb = cfg.capacity_mb, "content store");
            Arc::new(ShardedCs::new(
                (0..n).map(|_| LruCs::new(cap / n)).collect(),
            ))
        }
        _ => {
            tracing::info!(variant = "lru", capacity_mb = cfg.capacity_mb, "content store");
            Arc::new(LruCs::new(cap))
        }
    }
}
