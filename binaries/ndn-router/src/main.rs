use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

use ndn_config::ForwarderConfig;
#[cfg(unix)]
use ndn_config::{ManagementRequest, ManagementResponse, ManagementServer};
use ndn_engine::{EngineBuilder, EngineConfig, ForwarderEngine};
use ndn_packet::{Name, NameComponent};
use ndn_security::{FilePib, SecurityManager};
use ndn_face_local::AppFace;
use bytes::Bytes;

// Unix-socket bypass management I/O.
#[cfg(unix)]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::UnixListener;

// NDN-native management: face listener + Interest/Data handler.
mod mgmt_ndn;

// ─── Entry point ──────────────────────────────────────────────────────────────

/// Parse `argv` into a config file path.
fn parse_args() -> Option<PathBuf> {
    let args: Vec<String> = std::env::args().collect();
    let mut config_path = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-c" | "--config" => {
                i += 1;
                if let Some(p) = args.get(i) {
                    config_path = Some(PathBuf::from(p));
                }
            }
            _ => {}
        }
        i += 1;
    }
    config_path
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(true)
        .with_thread_ids(true)
        .init();

    let config_path = parse_args();

    // Load config or use defaults.
    let fwd_config = if let Some(path) = config_path {
        tracing::info!(path = %path.display(), "loading config");
        ForwarderConfig::from_file(&path)?
    } else {
        tracing::info!("no config file specified, using defaults");
        ForwarderConfig::default()
    };

    let engine_config = EngineConfig {
        cs_capacity_bytes:    fwd_config.engine.cs_capacity_mb * 1024 * 1024,
        pipeline_channel_cap: fwd_config.engine.pipeline_channel_cap,
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

    let mut builder = EngineBuilder::new(engine_config)
        .face(mgmt_app_face);
    if let Some(mgr) = security_mgr {
        builder = builder.security(mgr);
    }

    let (engine, shutdown) = builder.build().await?;

    // Apply static FIB routes from config.
    for route in &fwd_config.routes {
        let name = name_from_uri(&route.prefix);
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

    tracing::info!("engine running");

    let cancel = CancellationToken::new();

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
        let mgmt_engine  = engine.clone();
        let cancel_clone = cancel.clone();
        tracing::info!(path = %bypass_path.display(), "bypass: Unix socket management");
        Some(tokio::spawn(run_unix_mgmt_server(bypass_path, mgmt_engine, cancel_clone)))
    } else { None };

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
        if let Some(t) = ndn_handler_task { let _ = t.await; }
        if let Some(t) = ndn_listener_task { let _ = t.await; }
    }

    #[cfg(unix)]
    if let Some(t) = bypass_task { let _ = t.await; }

    shutdown.shutdown().await;
    Ok(())
}

// ─── Legacy JSON management request dispatch (bypass only) ───────────────────

/// Dispatch a legacy JSON management request against the live engine.
///
/// Used only by the bypass Unix socket transport. The primary management
/// path uses NFD-compatible TLV protocol via `mgmt_ndn`.
#[cfg(all(unix, not(feature = "iceoryx2-mgmt")))]
fn handle_request(
    req: ManagementRequest,
    engine: &ForwarderEngine,
    cancel: &CancellationToken,
) -> ManagementResponse {
    match req {
        ManagementRequest::AddRoute { prefix, face, cost } => {
            let name = name_from_uri(&prefix);
            engine.fib().add_nexthop(
                &name,
                ndn_transport::FaceId(face),
                cost,
            );
            tracing::info!(%prefix, face, cost, "management: route added");
            ManagementResponse::Ok
        }
        ManagementRequest::RemoveRoute { prefix, face } => {
            let name = name_from_uri(&prefix);
            engine.fib().remove_nexthop(&name, ndn_transport::FaceId(face));
            tracing::info!(%prefix, face, "management: route removed");
            ManagementResponse::Ok
        }
        ManagementRequest::ListFaces => {
            let entries: Vec<serde_json::Value> = engine
                .faces()
                .face_entries()
                .into_iter()
                .filter(|(_, kind)| !matches!(kind, ndn_transport::FaceKind::App | ndn_transport::FaceKind::Internal))
                .map(|(id, kind)| serde_json::json!({
                    "id":   id.0,
                    "kind": format!("{kind:?}").to_lowercase(),
                }))
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
/// `[management] transport = "bypass"` and the `iceoryx2-mgmt` feature is off.
#[cfg(all(unix, not(feature = "iceoryx2-mgmt")))]
async fn run_unix_mgmt_server(
    path: PathBuf,
    engine: ForwarderEngine,
    cancel: CancellationToken,
) {
    // Remove stale socket file if it exists.
    let _ = std::fs::remove_file(&path);

    let listener = match UnixListener::bind(&path) {
        Ok(l)  => l,
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

        let eng    = Arc::clone(&engine);
        let cancel = cancel.clone();
        tokio::spawn(async move {
            let (reader, mut writer) = conn.into_split();
            let mut lines = BufReader::new(reader).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let resp = match ManagementServer::decode_request(&line) {
                    Ok(req)  => handle_request(req, &eng, &cancel),
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

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Load the router's security identity from the PIB specified in `[security]`.
///
/// Returns `Some(SecurityManager)` on success; `None` on failure or when no
/// identity is configured.  Failures are non-fatal: the router starts without a
/// security identity and logs a warning instead.
fn load_security(cfg: &ForwarderConfig) -> Option<SecurityManager> {
    let identity_uri = cfg.security.identity.as_ref()?;

    let pib_path = cfg.security.pib_path
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(default_pib_path);

    let identity = name_from_uri(identity_uri);

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

/// Parse a URI-style NDN name like `/ndn/test` into a `Name`.
fn name_from_uri(uri: &str) -> Name {
    let comps: Vec<NameComponent> = uri
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| NameComponent::generic(Bytes::copy_from_slice(s.as_bytes())))
        .collect();
    Name::from_components(comps)
}
