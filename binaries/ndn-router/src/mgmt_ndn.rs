/// NFD-compatible management server.
///
/// Implements the NFD Management Protocol over NDN Interest/Data packets.
/// Management Interests use the name structure:
///
/// ```text
/// /localhost/nfd/<module>/<verb>/<ControlParameters>
/// ```
///
/// # Supported modules
///
/// - **rib**: `register`, `unregister`, `list`
/// - **faces**: `create`, `destroy`, `list`
/// - **fib**: `add-nexthop`, `remove-nexthop`, `list`
/// - **strategy-choice**: `set`, `unset`, `list`
/// - **cs**: `config`, `info`
/// - **status**: `general`, `shutdown`
///
/// # Source face propagation
///
/// When a command omits `FaceId`, the handler resolves the requesting face from
/// the PIT in-records via [`ForwarderEngine::source_face_id`].
use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use ndn_face_local::AppHandle;
use ndn_engine::ForwarderEngine;
use ndn_engine::stages::ErasedStrategy;
use ndn_packet::{Interest, Name, NameComponent, encode::encode_data_unsigned};
use ndn_store::ContentStore;
use ndn_strategy::{BestRouteStrategy, MulticastStrategy};
use ndn_transport::{Face, FaceId, FacePersistency};
use tokio_util::sync::CancellationToken;

use ndn_config::{
    ControlParameters, ControlResponse,
    control_parameters::{origin, route_flags},
    control_response::status,
    nfd_command::{module, verb, parse_command_name},
};

// ─── Socket helpers ──────────────────────────────────────────────────────────

/// Best-effort attempt to increase the socket receive buffer size.
///
/// Uses `SO_RCVBUF` via `libc::setsockopt`.  On Linux the effective maximum is
/// `net.core.rmem_max` (doubled by the kernel); on macOS it is `kern.ipc.maxsockbuf`.
/// Failure is logged but not fatal — the listener will still work, just with a
/// smaller buffer that may drop fragments under heavy load.
fn set_recv_buf_size(socket: &tokio::net::UdpSocket, size: usize) {
    use std::os::fd::AsRawFd;
    let fd = socket.as_raw_fd();
    let size = size as libc::c_int;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &size as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        tracing::warn!(
            error=%std::io::Error::last_os_error(),
            "udp-listener: failed to set SO_RCVBUF (continuing with default)"
        );
    }
}

// ─── Management prefix ────────────────────────────────────────────────────────

/// Build the `/localhost/nfd` name prefix registered in the FIB.
pub fn mgmt_prefix() -> Name {
    Name::from_components([
        NameComponent::generic(Bytes::from_static(b"localhost")),
        NameComponent::generic(Bytes::from_static(b"nfd")),
    ])
}

// ─── Face listener ────────────────────────────────────────────────────────────

/// Accept NDN face connections on `path` and register each as a dynamic face.
pub async fn run_face_listener(
    path:   &Path,
    engine: ForwarderEngine,
    cancel: CancellationToken,
) {
    let _ = std::fs::remove_file(path);

    let listener = match tokio::net::UnixListener::bind(path) {
        Ok(l)  => l,
        Err(e) => {
            tracing::error!(path = %path.display(), error = %e, "face-listener: bind failed");
            return;
        }
    };

    tracing::info!(path = %path.display(), "NDN face listener ready");

    loop {
        let (stream, _addr) = tokio::select! {
            _ = cancel.cancelled() => break,
            r = listener.accept() => match r {
                Ok(s)  => s,
                Err(e) => {
                    tracing::warn!(error = %e, "face-listener: accept error");
                    continue;
                }
            },
        };

        let face_id = engine.faces().alloc_id();
        let face    = ndn_face_local::UnixFace::from_stream(face_id, stream, path);
        tracing::debug!(face = %face_id, "face-listener: accepted connection");
        // Per-connection child token: cancelling it on disconnect only affects
        // this connection and its child faces (e.g. SHM), not the whole router.
        let conn_cancel = cancel.child_token();
        engine.add_face(face, conn_cancel);
    }

    let _ = std::fs::remove_file(path);
    tracing::info!("NDN face listener stopped");
}

// ─── UDP listener ────────────────────────────────────────────────────────────

/// Listen for incoming UDP datagrams on `bind_addr` and auto-create a `UdpFace`
/// for each new source address seen.
///
/// NFD calls this the "UDP channel".  A single unconnected socket receives from
/// all peers.  The first datagram from a new source creates a per-peer `UdpFace`
/// (unconnected, using `send_to`).  Subsequent datagrams from that peer are
/// forwarded into the pipeline via the existing face's channel.
///
/// The per-peer face shares the listener socket for sending (via `send_to`) but
/// receives packets only through the listener's demux — the face's own `recv()`
/// is never called (it would compete for the same socket).  Instead, the
/// listener pushes received bytes directly into the pipeline channel.
pub async fn run_udp_listener(
    bind_addr: std::net::SocketAddr,
    engine:    ForwarderEngine,
    cancel:    CancellationToken,
) {
    let socket = match tokio::net::UdpSocket::bind(bind_addr).await {
        Ok(s) => {
            // Increase the receive buffer to handle fragment bursts.  At high
            // window sizes a single peer can send hundreds of fragments (7 per
            // Data) before the pipeline drains them.  The default OS buffer
            // (~212 KB on Linux) is too small and causes silent drops.
            set_recv_buf_size(&s, 4 * 1024 * 1024);
            Arc::new(s)
        }
        Err(e) => {
            tracing::error!(addr=%bind_addr, error=%e, "udp-listener: bind failed");
            return;
        }
    };

    let local = socket.local_addr().unwrap_or(bind_addr);
    tracing::info!(addr=%local, "UDP listener ready");

    let mut peers = std::collections::HashMap::<std::net::SocketAddr, FaceId>::new();
    let mut buf = [0u8; 9000];

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            r = socket.recv_from(&mut buf) => {
                let (n, src) = match r {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::warn!(error=%e, "udp-listener: recv error");
                        continue;
                    }
                };

                tracing::debug!(src=%src, len=n, "udp-listener: recv packet");
                let raw = bytes::Bytes::copy_from_slice(&buf[..n]);

                let face_id = if let Some(&id) = peers.get(&src) {
                    id
                } else {
                    // New peer — create a send-only UdpFace sharing the listener socket.
                    // Replies go out from the listener's port (6363), so the
                    // remote peer's socket accepts them (it filters by source).
                    // No recv loop is spawned — the listener handles inbound
                    // packets and injects them via `inject_packet`.
                    let face_id = engine.faces().alloc_id();
                    let face = ndn_face_net::UdpFace::from_shared_socket(
                        face_id, Arc::clone(&socket), src,
                    );
                    let peer_cancel = cancel.child_token();
                    engine.add_face_send_only(face, peer_cancel);
                    peers.insert(src, face_id);
                    tracing::info!(face=%face_id, peer=%src, "udp-listener: new face");
                    face_id
                };

                // Inject the raw datagram into the pipeline. Fragment reassembly
                // is handled by the TlvDecode stage (per-face reassembly buffers),
                // not here — keeping the listener simple and avoiding duplication.
                let arrival = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;
                if engine.inject_packet(raw, face_id, arrival).await.is_err() {
                    break; // Pipeline channel closed.
                }
            }
        }
    }

    tracing::info!("UDP listener stopped");
}

// ─── TCP listener ────────────────────────────────────────────────────────────

/// Accept incoming TCP connections on `bind_addr` and create a `TcpFace` for
/// each.  TLV length-prefix framing is handled by `TcpFace` internally.
pub async fn run_tcp_listener(
    bind_addr: std::net::SocketAddr,
    engine:    ForwarderEngine,
    cancel:    CancellationToken,
) {
    let listener = match tokio::net::TcpListener::bind(bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(addr=%bind_addr, error=%e, "tcp-listener: bind failed");
            return;
        }
    };

    let local = listener.local_addr().unwrap_or(bind_addr);
    tracing::info!(addr=%local, "TCP listener ready");

    loop {
        let (stream, peer) = tokio::select! {
            _ = cancel.cancelled() => break,
            r = listener.accept() => match r {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error=%e, "tcp-listener: accept error");
                    continue;
                }
            },
        };

        let face_id = engine.faces().alloc_id();
        let face = ndn_face_net::TcpFace::from_stream(face_id, stream);
        let conn_cancel = cancel.child_token();
        engine.add_face(face, conn_cancel);
        tracing::info!(face=%face_id, peer=%peer, "tcp-listener: accepted connection");
    }

    tracing::info!("TCP listener stopped");
}

// ─── Management handler ───────────────────────────────────────────────────────

/// Read Interests from the management `AppHandle`, dispatch NFD commands,
/// and write Data responses back.
pub async fn run_ndn_mgmt_handler(
    mut handle: AppHandle,
    engine:     ForwarderEngine,
    cancel:     CancellationToken,
) {
    loop {
        let raw = tokio::select! {
            _ = cancel.cancelled() => break,
            r = handle.recv() => match r {
                Some(b) => b,
                None    => break,
            },
        };

        let interest = match Interest::decode(raw) {
            Ok(i)  => i,
            Err(e) => {
                tracing::warn!(error = %e, "nfd-mgmt: malformed Interest; skipping");
                continue;
            }
        };

        let source_face = engine.source_face_id(&interest);
        tracing::debug!(
            source_face = ?source_face,
            name = %interest.name,
            "nfd-mgmt: received command"
        );

        let parsed = match parse_command_name(&interest.name) {
            Some(p) => p,
            None => {
                let resp = ControlResponse::error(status::BAD_PARAMS, "invalid command name");
                send_response(&mut handle, &interest.name, &resp).await;
                continue;
            }
        };

        let params = parsed.params.unwrap_or_default();

        let resp = dispatch_command(
            parsed.module.as_ref(),
            parsed.verb.as_ref(),
            params,
            source_face,
            &engine,
            &cancel,
        ).await;

        send_response(&mut handle, &interest.name, &resp).await;
    }

    tracing::info!("NFD management handler stopped");
}

// ─── Command dispatch ─────────────────────────────────────────────────────────

async fn dispatch_command(
    module_name: &[u8],
    verb_name:   &[u8],
    params:      ControlParameters,
    source_face: Option<FaceId>,
    engine:      &ForwarderEngine,
    cancel:      &CancellationToken,
) -> ControlResponse {
    match module_name {
        m if m == module::RIB      => handle_rib(verb_name, params, source_face, engine),
        m if m == module::FACES    => handle_faces(verb_name, params, source_face, engine).await,
        m if m == module::FIB      => handle_fib(verb_name, params, source_face, engine),
        m if m == module::STRATEGY => handle_strategy(verb_name, params, engine),
        m if m == module::CS       => handle_cs(verb_name, engine),
        m if m == module::STATUS   => handle_status(verb_name, engine, cancel),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown module"),
    }
}

// ─── RIB module ───────────────────────────────────────────────────────────────

fn handle_rib(
    verb_name:   &[u8],
    params:      ControlParameters,
    source_face: Option<FaceId>,
    engine:      &ForwarderEngine,
) -> ControlResponse {
    match verb_name {
        v if v == verb::REGISTER   => rib_register(params, source_face, engine),
        v if v == verb::UNREGISTER => rib_unregister(params, source_face, engine),
        v if v == verb::LIST       => rib_list(engine),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown rib verb"),
    }
}

fn rib_register(
    params:      ControlParameters,
    source_face: Option<FaceId>,
    engine:      &ForwarderEngine,
) -> ControlResponse {
    let name = match &params.name {
        Some(n) => n.clone(),
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };

    let face_id = match resolve_face_id(&params, source_face) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let cost = params.cost.unwrap_or(0) as u32;

    engine.fib().add_nexthop(&name, face_id, cost);

    tracing::info!(prefix = %name, face = face_id.0, cost, "rib/register");

    let echo = ControlParameters {
        name: Some(name),
        face_id: Some(face_id.0 as u64),
        origin: Some(params.origin.unwrap_or(origin::APP)),
        cost: Some(cost as u64),
        flags: Some(params.flags.unwrap_or(route_flags::CHILD_INHERIT)),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn rib_unregister(
    params:      ControlParameters,
    source_face: Option<FaceId>,
    engine:      &ForwarderEngine,
) -> ControlResponse {
    let name = match &params.name {
        Some(n) => n.clone(),
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };

    let face_id = match resolve_face_id(&params, source_face) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    engine.fib().remove_nexthop(&name, face_id);
    tracing::info!(prefix = %name, face = face_id.0, "rib/unregister");

    let echo = ControlParameters {
        name: Some(name),
        face_id: Some(face_id.0 as u64),
        origin: Some(params.origin.unwrap_or(origin::APP)),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn rib_list(engine: &ForwarderEngine) -> ControlResponse {
    // RIB in ndn-rs maps directly to the FIB.
    fib_list(engine)
}

// ─── Faces module ─────────────────────────────────────────────────────────────

async fn handle_faces(
    verb_name:   &[u8],
    params:      ControlParameters,
    source_face: Option<FaceId>,
    engine:      &ForwarderEngine,
) -> ControlResponse {
    match verb_name {
        v if v == verb::CREATE  => faces_create(params, source_face, engine).await,
        v if v == verb::DESTROY => faces_destroy(params, engine),
        v if v == verb::LIST    => faces_list(engine),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown faces verb"),
    }
}

async fn faces_create(
    params:      ControlParameters,
    source_face: Option<FaceId>,
    engine:      &ForwarderEngine,
) -> ControlResponse {
    let uri = match &params.uri {
        Some(u) => u.clone(),
        None => return ControlResponse::error(status::BAD_PARAMS, "Uri is required"),
    };

    if let Some(shm_name) = uri.strip_prefix("shm://") {
        return faces_create_shm(shm_name, source_face, engine);
    }

    if let Some(addr_str) = uri.strip_prefix("udp4://") {
        return faces_create_udp(addr_str, engine).await;
    }

    if let Some(addr_str) = uri.strip_prefix("tcp4://") {
        return faces_create_tcp(addr_str, engine).await;
    }

    ControlResponse::error(status::BAD_PARAMS, format!("unsupported URI scheme: {uri}"))
}

async fn faces_create_udp(addr_str: &str, engine: &ForwarderEngine) -> ControlResponse {
    let peer: std::net::SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(e) => return ControlResponse::error(
            status::BAD_PARAMS,
            format!("invalid UDP address '{addr_str}': {e}"),
        ),
    };

    let face_id = engine.faces().alloc_id();
    let local: std::net::SocketAddr = if peer.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };

    match ndn_face_net::UdpFace::bind(local, peer, face_id).await {
        Ok(face) => {
            let local_uri = face.local_uri().unwrap_or_default();
            let cancel = CancellationToken::new();
            engine.add_face_with_persistency(face, cancel, FacePersistency::Persistent);
            tracing::info!(face = face_id.0, remote = %peer, "faces/create udp4");

            let echo = ControlParameters {
                face_id: Some(face_id.0 as u64),
                uri: Some(format!("udp4://{peer}")),
                local_uri: Some(local_uri),
                ..Default::default()
            };
            ControlResponse::ok("OK", echo)
        }
        Err(e) => {
            tracing::warn!(error = %e, remote = %peer, "faces/create udp4 failed");
            ControlResponse::error(status::SERVER_ERROR, format!("UDP face creation failed: {e}"))
        }
    }
}

async fn faces_create_tcp(addr_str: &str, engine: &ForwarderEngine) -> ControlResponse {
    let peer: std::net::SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(e) => return ControlResponse::error(
            status::BAD_PARAMS,
            format!("invalid TCP address '{addr_str}': {e}"),
        ),
    };

    let face_id = engine.faces().alloc_id();

    match ndn_face_net::TcpFace::connect(face_id, peer).await {
        Ok(face) => {
            let local_uri = face.local_uri().unwrap_or_default();
            let cancel = CancellationToken::new();
            engine.add_face_with_persistency(face, cancel, FacePersistency::Persistent);
            tracing::info!(face = face_id.0, remote = %peer, "faces/create tcp4");

            let echo = ControlParameters {
                face_id: Some(face_id.0 as u64),
                uri: Some(format!("tcp4://{peer}")),
                local_uri: Some(local_uri),
                ..Default::default()
            };
            ControlResponse::ok("OK", echo)
        }
        Err(e) => {
            tracing::warn!(error = %e, remote = %peer, "faces/create tcp4 failed");
            ControlResponse::error(status::SERVER_ERROR, format!("TCP face creation failed: {e}"))
        }
    }
}

#[cfg(all(unix, feature = "spsc-shm"))]
fn faces_create_shm(
    shm_name:    &str,
    source_face: Option<FaceId>,
    engine:      &ForwarderEngine,
) -> ControlResponse {
    let face_id = engine.faces().alloc_id();

    match ndn_face_local::ShmFace::create(face_id, shm_name) {
        Ok(face) => {
            // Use a child of the control face's cancel token so that when the
            // control face disconnects, this SHM face is also cancelled and
            // cleaned up (FIB routes removed, face removed from table).
            let cancel = source_face
                .and_then(|sf| engine.face_token(sf))
                .map(|t| t.child_token())
                .unwrap_or_else(CancellationToken::new);
            // SHM faces are on-demand: when the control face disconnects
            // (app exits), the child cancel token fires and the face is
            // fully cleaned up (SHM region unlinked, FIB routes removed).
            engine.add_face(face, cancel);
            tracing::info!(face = face_id.0, shm = shm_name, "faces/create shm");

            let echo = ControlParameters {
                face_id: Some(face_id.0 as u64),
                uri: Some(format!("shm://{shm_name}")),
                ..Default::default()
            };
            ControlResponse::ok("OK", echo)
        }
        Err(e) => {
            tracing::warn!(error = %e, shm = shm_name, "faces/create shm failed");
            ControlResponse::error(status::SERVER_ERROR, format!("SHM creation failed: {e}"))
        }
    }
}

#[cfg(not(all(unix, feature = "spsc-shm")))]
fn faces_create_shm(
    _shm_name:    &str,
    _source_face: Option<FaceId>,
    _engine:      &ForwarderEngine,
) -> ControlResponse {
    ControlResponse::error(status::SERVER_ERROR, "SHM faces not supported on this platform")
}

fn faces_destroy(params: ControlParameters, engine: &ForwarderEngine) -> ControlResponse {
    let face_id = match params.face_id {
        Some(id) => FaceId(id as u32),
        None => return ControlResponse::error(status::BAD_PARAMS, "FaceId is required"),
    };

    if engine.faces().get(face_id).is_none() {
        return ControlResponse::error(status::NOT_FOUND, format!("face {} does not exist", face_id.0));
    }

    // Cancel the face's token — this triggers run_face_reader cleanup which:
    // 1. Removes all FIB nexthops pointing to this face
    // 2. Propagates cancellation to child faces (e.g. SHM)
    // 3. Removes the face from the face table
    if let Some(token) = engine.face_token(face_id) {
        token.cancel();
    } else {
        // No token (shouldn't happen for dynamic faces) — fall back to manual cleanup.
        engine.fib().remove_face(face_id);
        engine.faces().remove(face_id);
    }

    tracing::info!(face = face_id.0, "faces/destroy");

    let echo = ControlParameters {
        face_id: Some(face_id.0 as u64),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn faces_list(engine: &ForwarderEngine) -> ControlResponse {
    let entries = engine.faces().face_info();
    let face_states = engine.face_states();
    let mut text = format!("{} faces\n", entries.len());
    for info in &entries {
        let persistency = face_states.get(&info.id)
            .map(|s| s.persistency)
            .unwrap_or(FacePersistency::OnDemand);
        let mut line = format!("  faceid={} remote={} local={} persistency={:?}",
            info.id.0,
            info.remote_uri.as_deref().unwrap_or("N/A"),
            info.local_uri.as_deref().unwrap_or("N/A"),
            persistency,
        );
        // Show kind if no URIs are available (e.g. App, Internal faces).
        if info.remote_uri.is_none() && info.local_uri.is_none() {
            line = format!("  faceid={} kind={:?} persistency={:?}",
                info.id.0, info.kind, persistency);
        }
        text.push_str(&line);
        text.push('\n');
    }
    ControlResponse::ok_empty(text)
}

// ─── FIB module ───────────────────────────────────────────────────────────────

fn handle_fib(
    verb_name:   &[u8],
    params:      ControlParameters,
    source_face: Option<FaceId>,
    engine:      &ForwarderEngine,
) -> ControlResponse {
    match verb_name {
        v if v == verb::ADD_NEXTHOP    => fib_add_nexthop(params, source_face, engine),
        v if v == verb::REMOVE_NEXTHOP => fib_remove_nexthop(params, source_face, engine),
        v if v == verb::LIST           => fib_list(engine),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown fib verb"),
    }
}

fn fib_add_nexthop(
    params:      ControlParameters,
    source_face: Option<FaceId>,
    engine:      &ForwarderEngine,
) -> ControlResponse {
    let name = match &params.name {
        Some(n) => n.clone(),
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };

    let face_id = match resolve_face_id(&params, source_face) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let cost = params.cost.unwrap_or(0) as u32;

    engine.fib().add_nexthop(&name, face_id, cost);
    tracing::info!(prefix = %name, face = face_id.0, cost, "fib/add-nexthop");

    let echo = ControlParameters {
        name: Some(name),
        face_id: Some(face_id.0 as u64),
        cost: Some(cost as u64),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn fib_remove_nexthop(
    params:      ControlParameters,
    source_face: Option<FaceId>,
    engine:      &ForwarderEngine,
) -> ControlResponse {
    let name = match &params.name {
        Some(n) => n.clone(),
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };

    let face_id = match resolve_face_id(&params, source_face) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    engine.fib().remove_nexthop(&name, face_id);
    tracing::info!(prefix = %name, face = face_id.0, "fib/remove-nexthop");

    let echo = ControlParameters {
        name: Some(name),
        face_id: Some(face_id.0 as u64),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn fib_list(engine: &ForwarderEngine) -> ControlResponse {
    let routes = engine.fib().dump();
    let mut text = format!("{} routes\n", routes.len());
    for (name, entry) in &routes {
        let nexthops: Vec<String> = entry.nexthops.iter()
            .map(|nh| format!("faceid={} cost={}", nh.face_id.0, nh.cost))
            .collect();
        text.push_str(&format!("  {name} nexthops=[{}]\n",
            nexthops.join(", ")));
    }
    ControlResponse::ok_empty(text)
}

// ─── Strategy-choice module ──────────────────────────────────────────────────

fn handle_strategy(
    verb_name: &[u8],
    params:    ControlParameters,
    engine:    &ForwarderEngine,
) -> ControlResponse {
    match verb_name {
        v if v == verb::SET    => strategy_set(params, engine),
        v if v == verb::UNSET  => strategy_unset(params, engine),
        v if v == verb::LIST   => strategy_list(engine),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown strategy-choice verb"),
    }
}

/// Instantiate a strategy by its NFD-style name.
///
/// Known strategies:
/// - `/localhost/nfd/strategy/best-route`
/// - `/localhost/nfd/strategy/multicast`
fn create_strategy_by_name(name: &Name) -> Option<Arc<dyn ErasedStrategy>> {
    let comps = name.components();
    // Expect /localhost/nfd/strategy/<name> — match on the last component.
    let short_name = if comps.len() >= 4
        && comps[0].value.as_ref() == b"localhost"
        && comps[1].value.as_ref() == b"nfd"
        && comps[2].value.as_ref() == b"strategy"
    {
        comps[3].value.as_ref()
    } else if comps.len() == 1 {
        // Allow bare name like just "best-route".
        comps[0].value.as_ref()
    } else {
        return None;
    };

    match short_name {
        b"best-route" => Some(Arc::new(BestRouteStrategy::new())),
        b"multicast"  => Some(Arc::new(MulticastStrategy::new())),
        _ => None,
    }
}

fn strategy_set(params: ControlParameters, engine: &ForwarderEngine) -> ControlResponse {
    let prefix = match &params.name {
        Some(n) => n.clone(),
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };

    let strategy_name = match &params.strategy {
        Some(n) => n.clone(),
        None => return ControlResponse::error(status::BAD_PARAMS, "Strategy is required"),
    };

    let strategy = match create_strategy_by_name(&strategy_name) {
        Some(s) => s,
        None => return ControlResponse::error(
            status::NOT_FOUND,
            format!("unknown strategy: {}", strategy_name),
        ),
    };

    engine.strategy_table().insert(&prefix, strategy);

    tracing::info!(
        prefix = %prefix,
        strategy = %strategy_name,
        "strategy-choice/set"
    );

    let echo = ControlParameters {
        name: Some(prefix),
        strategy: Some(strategy_name),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn strategy_unset(params: ControlParameters, engine: &ForwarderEngine) -> ControlResponse {
    let prefix = match &params.name {
        Some(n) => n.clone(),
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };

    // Prevent unsetting the root strategy.
    if prefix.is_empty() {
        return ControlResponse::error(
            status::BAD_PARAMS,
            "cannot unset strategy at root prefix"
        );
    }

    engine.strategy_table().remove(&prefix);

    tracing::info!(prefix = %prefix, "strategy-choice/unset");

    let echo = ControlParameters {
        name: Some(prefix),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn strategy_list(engine: &ForwarderEngine) -> ControlResponse {
    let entries = engine.strategy_table().dump();
    let mut text = format!("{} strategy entries\n", entries.len());
    for (prefix, strategy) in &entries {
        text.push_str(&format!("  prefix={prefix} strategy={}\n",
            strategy.name()));
    }
    ControlResponse::ok_empty(text)
}

// ─── CS module ───────────────────────────────────────────────────────────────

fn handle_cs(
    verb_name: &[u8],
    engine:    &ForwarderEngine,
) -> ControlResponse {
    match verb_name {
        v if v == verb::CONFIG => cs_config(engine),
        v if v == verb::INFO   => cs_info(engine),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown cs verb"),
    }
}

fn cs_config(engine: &ForwarderEngine) -> ControlResponse {
    let cs = engine.cs();
    let cap = cs.capacity();
    let echo = ControlParameters {
        // Repurpose capacity field for CS max bytes.
        // NFD uses a dedicated Capacity TLV (0x83) — we encode it here.
        cost: Some(cap.max_bytes as u64),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn cs_info(engine: &ForwarderEngine) -> ControlResponse {
    let cs = engine.cs();
    let cap = cs.capacity();
    let n_entries = cs.len();
    let current = cs.current_bytes();

    let text = format!(
        "capacity={}B entries={} used={}B",
        cap.max_bytes, n_entries, current,
    );
    ControlResponse::ok_empty(text)
}

// ─── Status module ────────────────────────────────────────────────────────────

fn handle_status(
    verb_name: &[u8],
    engine:    &ForwarderEngine,
    cancel:    &CancellationToken,
) -> ControlResponse {
    match verb_name {
        b"general" => {
            let n_faces = engine.faces().face_entries().len();
            let n_fib   = engine.fib().dump().len();
            let n_pit   = engine.pit().len();
            let n_cs    = engine.cs().len();

            let text = format!(
                "faces={n_faces} fib={n_fib} pit={n_pit} cs={n_cs}"
            );
            ControlResponse::ok_empty(text)
        }
        b"shutdown" => {
            tracing::info!("status/shutdown requested");
            cancel.cancel();
            ControlResponse::ok_empty("OK")
        }
        _ => ControlResponse::error(status::NOT_FOUND, "unknown status verb"),
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Resolve FaceId from params or source face.
///
/// Returns the error as a `ControlResponse` via the `?` operator on `Result`.
fn resolve_face_id(
    params: &ControlParameters,
    source_face: Option<FaceId>,
) -> Result<FaceId, ControlResponse> {
    match params.face_id {
        Some(id) => Ok(FaceId(id as u32)),
        None => source_face.ok_or_else(|| {
            ControlResponse::error(status::BAD_PARAMS, "cannot determine FaceId")
        }),
    }
}

async fn send_response(handle: &mut AppHandle, name: &Name, resp: &ControlResponse) {
    let content = resp.encode();
    let data = encode_data_unsigned(name, &content);
    if let Err(e) = handle.send(data).await {
        tracing::warn!(error = %e, "nfd-mgmt: failed to send Data response");
    }
}

