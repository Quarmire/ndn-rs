use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

use ndn_config::{ForwarderConfig, ManagementRequest, ManagementResponse, ManagementServer};
use ndn_engine::{EngineBuilder, EngineConfig, ForwarderEngine};
use ndn_packet::{Name, NameComponent};
use bytes::Bytes;

/// Parse `argv` into (config_path, mgmt_socket_path).
fn parse_args() -> (Option<PathBuf>, PathBuf) {
    let args: Vec<String> = std::env::args().collect();
    let mut config_path = None;
    let mut mgmt_path = PathBuf::from("/tmp/ndn-router.sock");
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-c" | "--config" => {
                i += 1;
                if let Some(p) = args.get(i) {
                    config_path = Some(PathBuf::from(p));
                }
            }
            "-m" | "--mgmt" => {
                i += 1;
                if let Some(p) = args.get(i) {
                    mgmt_path = PathBuf::from(p);
                }
            }
            _ => {}
        }
        i += 1;
    }
    (config_path, mgmt_path)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(true)
        .with_thread_ids(true)
        .init();

    let (config_path, mgmt_path) = parse_args();

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

    let (engine, shutdown) = EngineBuilder::new(engine_config)
        .build()
        .await?;

    // Apply static FIB routes from config.
    for route in &fwd_config.routes {
        let name = name_from_uri(&route.prefix);
        engine
            .fib()
            .add_nexthop(&name, ndn_transport::FaceId(route.face as u32), route.cost);
        tracing::info!(prefix = %route.prefix, face = route.face, cost = route.cost, "route added");
    }

    tracing::info!("engine running");

    // Spawn the management server.
    let cancel = CancellationToken::new();
    let mgmt_engine = engine.clone();
    let cancel_clone = cancel.clone();
    let mgmt_task = tokio::spawn(run_mgmt_server(
        mgmt_path.clone(),
        mgmt_engine,
        cancel_clone,
    ));
    tracing::info!(path = %mgmt_path.display(), "management socket listening");

    // Wait for Ctrl-C.
    tokio::signal::ctrl_c().await?;

    tracing::info!("shutting down");
    cancel.cancel();
    let _ = mgmt_task.await;
    shutdown.shutdown().await;
    Ok(())
}

/// Parse a URI-style NDN name like `/ndn/test` into `Name`.
fn name_from_uri(uri: &str) -> Name {
    let comps: Vec<NameComponent> = uri
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| NameComponent::generic(Bytes::copy_from_slice(s.as_bytes())))
        .collect();
    Name::from_components(comps)
}

/// Dispatch a `ManagementRequest` against the live engine.
async fn handle_request(
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
            let face_ids: Vec<u32> = engine
                .faces()
                .face_ids()
                .iter()
                .map(|id| id.0)
                .collect();
            ManagementResponse::OkData {
                data: serde_json::json!({ "faces": face_ids }),
            }
        }
        ManagementRequest::ListRoutes => {
            ManagementResponse::OkData {
                data: serde_json::json!({ "note": "FIB dump not yet implemented" }),
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

/// Accept management connections on a Unix socket until `cancel` fires.
async fn run_mgmt_server(
    path: PathBuf,
    engine: ForwarderEngine,
    cancel: CancellationToken,
) {
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
                    Ok(req)  => handle_request(req, &eng, &cancel).await,
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
