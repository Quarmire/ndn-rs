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
/// - **neighbors**: `list`
/// - **service**: `list`, `browse`, `announce`, `withdraw`
/// - **status**: `general`, `shutdown`
///
/// # Source face propagation
///
/// When a command omits `FaceId`, the handler resolves the requesting face from
/// the PIT in-records via [`ForwarderEngine::source_face_id`].
use std::str::FromStr;
use std::sync::Arc;

#[cfg(feature = "yubikey-piv")]
use base64::Engine as _;
use bytes::Bytes;
use ndn_discovery::{NeighborState, ServiceDiscoveryProtocol, ServiceRecord};
use ndn_engine::ForwarderEngine;
use ndn_engine::stages::ErasedStrategy;
use ndn_face_local::AppHandle;
use ndn_packet::{Interest, Name, NameComponent, encode::encode_data_unsigned};
use ndn_security::FilePib;
use ndn_strategy::{BestRouteStrategy, MulticastStrategy};
use ndn_transport::{Face, FaceId, FacePersistency};
use tokio_util::sync::CancellationToken;

use ndn_config::{
    ControlParameters, ControlResponse,
    control_parameters::{origin, route_flags},
    control_response::status,
    nfd_command::{module, parse_command_name, verb},
};

// ─── Socket helpers ──────────────────────────────────────────────────────────

/// Best-effort attempt to increase the socket receive buffer size.
///
/// Uses `SO_RCVBUF` via `libc::setsockopt`.  On Linux the effective maximum is
/// `net.core.rmem_max` (doubled by the kernel); on macOS it is `kern.ipc.maxsockbuf`.
/// Failure is logged but not fatal — the listener will still work, just with a
/// smaller buffer that may drop fragments under heavy load.
///
/// On Windows, tuning `SO_RCVBUF` via the `libc` crate is not supported; the
/// default OS buffer is used instead.
#[cfg(unix)]
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

#[cfg(not(unix))]
fn set_recv_buf_size(_socket: &tokio::net::UdpSocket, _size: usize) {
    // No-op on non-Unix platforms. The OS default receive buffer is used.
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
///
/// `path` is a Unix domain socket path on Unix (e.g. `/tmp/ndn-faces.sock`)
/// or a Named Pipe path on Windows (e.g. `\\.\pipe\ndn-faces`).
pub async fn run_face_listener(path: &str, engine: ForwarderEngine, cancel: CancellationToken) {
    let listener = match ndn_face_local::IpcListener::bind(path) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(path = %path, error = %e, "face-listener: bind failed");
            return;
        }
    };

    tracing::info!(path = %listener.uri(), "NDN face listener ready");

    loop {
        let face_id = engine.faces().alloc_id();
        let face = tokio::select! {
            _ = cancel.cancelled() => break,
            r = listener.accept(face_id) => match r {
                Ok(f)  => f,
                Err(e) => {
                    tracing::warn!(error = %e, "face-listener: accept error");
                    continue;
                }
            },
        };

        tracing::debug!(face = %face_id, "face-listener: accepted management connection");
        // Per-connection child token so that closing one connection only
        // cancels that connection's tasks, not the whole listener.
        let conn_cancel = cancel.child_token();
        engine.add_face(face, conn_cancel);
    }

    listener.cleanup();
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
    engine: ForwarderEngine,
    cancel: CancellationToken,
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

    // Deduplicate faces by remote IP address only (ignoring ephemeral source
    // port).  Peers often send from a different ephemeral port on each socket
    // creation (e.g. when the discovery protocol creates a new unicast face),
    // which would otherwise produce one listener face per port per peer.
    //
    // All replies go TO the peer's well-known NDN port (6363).  Any valid NDN
    // router listens on that port; apps that use a non-standard port connect
    // outbound rather than waiting for inbound, so they are unaffected.
    let mut peers = std::collections::HashMap::<std::net::IpAddr, FaceId>::new();
    let mut buf = [0u8; 9000];
    // The NDN well-known port (IANA assigned).
    const NDN_PORT: u16 = 6363;

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

                let src_ip = src.ip();
                let face_id = if let Some(&id) = peers.get(&src_ip) {
                    id
                } else {
                    // New peer (by IP) — create a send-only UdpFace sharing the
                    // listener socket.  Target the peer's well-known NDN port so
                    // reply traffic does not go to the ephemeral source port.
                    // Replies go out from the listener's bound port, so the remote
                    // peer's server socket (also on NDN_PORT) accepts them.
                    // No recv loop is spawned — the listener handles inbound
                    // packets and injects them via `inject_packet`.
                    let canonical_peer = std::net::SocketAddr::new(src_ip, NDN_PORT);
                    let face_id = engine.faces().alloc_id();
                    let face = ndn_face_net::UdpFace::from_shared_socket(
                        face_id, Arc::clone(&socket), canonical_peer,
                    );
                    let peer_cancel = cancel.child_token();
                    engine.add_face_send_only(face, peer_cancel);
                    peers.insert(src_ip, face_id);
                    tracing::info!(face=%face_id, peer=%canonical_peer, src=%src, "udp-listener: new face");
                    face_id
                };

                // Inject the raw datagram into the pipeline. Fragment reassembly
                // is handled by the TlvDecode stage (per-face reassembly buffers),
                // not here — keeping the listener simple and avoiding duplication.
                let arrival = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;
                let meta = ndn_discovery::InboundMeta::udp(src);
                if engine.inject_packet(raw, face_id, arrival, meta).await.is_err() {
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
    engine: ForwarderEngine,
    cancel: CancellationToken,
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
        let face = ndn_face_net::tcp_face_from_stream(face_id, stream);
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
    handle: AppHandle,
    engine: ForwarderEngine,
    cancel: CancellationToken,
    discovery_sd: Option<Arc<ServiceDiscoveryProtocol>>,
    discovery_claimed: Vec<Name>,
    config: Arc<ndn_config::ForwarderConfig>,
    pib: Option<Arc<FilePib>>,
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
            Ok(i) => i,
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
                send_response(&handle, &interest.name, &resp).await;
                continue;
            }
        };

        let params = parsed.params.unwrap_or_default();

        let resp = dispatch_command(
            parsed.module.as_ref(),
            parsed.verb.as_ref(),
            params,
            source_face,
            DispatchCtx {
                engine: &engine,
                cancel: &cancel,
                discovery_sd: discovery_sd.as_deref(),
                discovery_claimed: &discovery_claimed,
                config: &config,
                pib: pib.as_deref(),
            },
        )
        .await;

        send_response(&handle, &interest.name, &resp).await;
    }

    tracing::info!("NFD management handler stopped");
}

// ─── Command dispatch ─────────────────────────────────────────────────────────

struct DispatchCtx<'a> {
    engine: &'a ForwarderEngine,
    cancel: &'a CancellationToken,
    discovery_sd: Option<&'a ServiceDiscoveryProtocol>,
    discovery_claimed: &'a [Name],
    config: &'a ndn_config::ForwarderConfig,
    pib: Option<&'a FilePib>,
}

async fn dispatch_command(
    module_name: &[u8],
    verb_name: &[u8],
    params: ControlParameters,
    source_face: Option<FaceId>,
    ctx: DispatchCtx<'_>,
) -> ControlResponse {
    let DispatchCtx {
        engine,
        cancel,
        discovery_sd,
        discovery_claimed,
        config,
        pib,
    } = ctx;
    match module_name {
        m if m == module::RIB => handle_rib(verb_name, params, source_face, engine),
        m if m == module::FACES => handle_faces(verb_name, params, source_face, engine).await,
        m if m == module::FIB => handle_fib(verb_name, params, source_face, engine),
        m if m == module::STRATEGY => handle_strategy(verb_name, params, engine),
        m if m == module::CS => handle_cs(verb_name, params, engine).await,
        m if m == module::NEIGHBORS => handle_neighbors(verb_name, engine),
        m if m == module::SERVICE => handle_service(
            verb_name,
            params,
            engine,
            source_face,
            discovery_sd,
            discovery_claimed,
        ),
        m if m == module::STATUS => handle_status(verb_name, engine, cancel),
        m if m == module::MEASUREMENTS => handle_measurements(verb_name, engine),
        m if m == module::CONFIG => handle_config(verb_name, config),
        m if m == module::SECURITY => handle_security(verb_name, params, pib, engine, config).await,
        m if m == module::LOG => handle_log(verb_name, params),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown module"),
    }
}

// ─── RIB module ───────────────────────────────────────────────────────────────

fn handle_rib(
    verb_name: &[u8],
    params: ControlParameters,
    source_face: Option<FaceId>,
    engine: &ForwarderEngine,
) -> ControlResponse {
    match verb_name {
        v if v == verb::REGISTER => rib_register(params, source_face, engine),
        v if v == verb::UNREGISTER => rib_unregister(params, source_face, engine),
        v if v == verb::LIST => rib_list(engine),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown rib verb"),
    }
}

fn rib_register(
    params: ControlParameters,
    source_face: Option<FaceId>,
    engine: &ForwarderEngine,
) -> ControlResponse {
    let name = match &params.name {
        Some(n) => n.clone(),
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };

    // Block non-management faces from registering reserved prefixes.
    if is_reserved_name(&name) && !is_management_face(source_face, engine) {
        return ControlResponse::error(
            status::UNAUTHORIZED,
            format!("prefix {name} is reserved for operator use"),
        );
    }

    let face_id = match resolve_face_id(&params, source_face) {
        Ok(id) => id,
        Err(resp) => return *resp,
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
    params: ControlParameters,
    source_face: Option<FaceId>,
    engine: &ForwarderEngine,
) -> ControlResponse {
    let name = match &params.name {
        Some(n) => n.clone(),
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };

    let face_id = match resolve_face_id(&params, source_face) {
        Ok(id) => id,
        Err(resp) => return *resp,
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
    verb_name: &[u8],
    params: ControlParameters,
    source_face: Option<FaceId>,
    engine: &ForwarderEngine,
) -> ControlResponse {
    match verb_name {
        v if v == verb::CREATE => faces_create(params, source_face, engine).await,
        v if v == verb::DESTROY => faces_destroy(params, source_face, engine),
        v if v == verb::LIST => faces_list(engine),
        v if v == verb::COUNTERS => faces_counters(engine),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown faces verb"),
    }
}

async fn faces_create(
    params: ControlParameters,
    source_face: Option<FaceId>,
    engine: &ForwarderEngine,
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
        Err(e) => {
            return ControlResponse::error(
                status::BAD_PARAMS,
                format!("invalid UDP address '{addr_str}': {e}"),
            );
        }
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
            ControlResponse::error(
                status::SERVER_ERROR,
                format!("UDP face creation failed: {e}"),
            )
        }
    }
}

async fn faces_create_tcp(addr_str: &str, engine: &ForwarderEngine) -> ControlResponse {
    let peer: std::net::SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(e) => {
            return ControlResponse::error(
                status::BAD_PARAMS,
                format!("invalid TCP address '{addr_str}': {e}"),
            );
        }
    };

    let face_id = engine.faces().alloc_id();

    match ndn_face_net::tcp_face_connect(face_id, peer).await {
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
            ControlResponse::error(
                status::SERVER_ERROR,
                format!("TCP face creation failed: {e}"),
            )
        }
    }
}

#[cfg(all(unix, feature = "spsc-shm"))]
fn faces_create_shm(
    shm_name: &str,
    source_face: Option<FaceId>,
    engine: &ForwarderEngine,
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
                .unwrap_or_default();
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
    _shm_name: &str,
    _source_face: Option<FaceId>,
    _engine: &ForwarderEngine,
) -> ControlResponse {
    ControlResponse::error(
        status::SERVER_ERROR,
        "SHM faces not supported on this platform",
    )
}

fn faces_destroy(
    params: ControlParameters,
    source_face: Option<FaceId>,
    engine: &ForwarderEngine,
) -> ControlResponse {
    let face_id = match params.face_id {
        Some(id) => FaceId(id as u32),
        None => return ControlResponse::error(status::BAD_PARAMS, "FaceId is required"),
    };

    let target = match engine.faces().get(face_id) {
        Some(f) => f,
        None => {
            return ControlResponse::error(
                status::NOT_FOUND,
                format!("face {} does not exist", face_id.0),
            );
        }
    };

    // Non-management faces cannot destroy management faces.
    if target.kind().is_management() && !is_management_face(source_face, engine) {
        return ControlResponse::error(
            status::UNAUTHORIZED,
            "cannot destroy a management face from a non-management face",
        );
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
        let persistency = face_states
            .get(&info.id)
            .map(|s| s.persistency)
            .unwrap_or(FacePersistency::OnDemand);
        let mut line = format!(
            "  faceid={} remote={} local={} persistency={:?}",
            info.id.0,
            info.remote_uri.as_deref().unwrap_or("N/A"),
            info.local_uri.as_deref().unwrap_or("N/A"),
            persistency,
        );
        // Show kind if no URIs are available (e.g. App, Internal faces).
        if info.remote_uri.is_none() && info.local_uri.is_none() {
            line = format!(
                "  faceid={} kind={:?} persistency={:?}",
                info.id.0, info.kind, persistency
            );
        }
        text.push_str(&line);
        text.push('\n');
    }
    ControlResponse::ok_empty(text)
}

// ─── FIB module ───────────────────────────────────────────────────────────────

fn handle_fib(
    verb_name: &[u8],
    params: ControlParameters,
    source_face: Option<FaceId>,
    engine: &ForwarderEngine,
) -> ControlResponse {
    match verb_name {
        v if v == verb::ADD_NEXTHOP => fib_add_nexthop(params, source_face, engine),
        v if v == verb::REMOVE_NEXTHOP => fib_remove_nexthop(params, source_face, engine),
        v if v == verb::LIST => fib_list(engine),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown fib verb"),
    }
}

fn fib_add_nexthop(
    params: ControlParameters,
    source_face: Option<FaceId>,
    engine: &ForwarderEngine,
) -> ControlResponse {
    let name = match &params.name {
        Some(n) => n.clone(),
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };

    // Block non-management faces from injecting nexthops into reserved prefixes.
    if is_reserved_name(&name) && !is_management_face(source_face, engine) {
        return ControlResponse::error(
            status::UNAUTHORIZED,
            format!("prefix {name} is reserved for operator use"),
        );
    }

    let face_id = match resolve_face_id(&params, source_face) {
        Ok(id) => id,
        Err(resp) => return *resp,
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
    params: ControlParameters,
    source_face: Option<FaceId>,
    engine: &ForwarderEngine,
) -> ControlResponse {
    let name = match &params.name {
        Some(n) => n.clone(),
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };

    let face_id = match resolve_face_id(&params, source_face) {
        Ok(id) => id,
        Err(resp) => return *resp,
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
        let nexthops: Vec<String> = entry
            .nexthops
            .iter()
            .map(|nh| format!("faceid={} cost={}", nh.face_id.0, nh.cost))
            .collect();
        text.push_str(&format!("  {name} nexthops=[{}]\n", nexthops.join(", ")));
    }
    ControlResponse::ok_empty(text)
}

// ─── Strategy-choice module ──────────────────────────────────────────────────

fn handle_strategy(
    verb_name: &[u8],
    params: ControlParameters,
    engine: &ForwarderEngine,
) -> ControlResponse {
    match verb_name {
        v if v == verb::SET => strategy_set(params, engine),
        v if v == verb::UNSET => strategy_unset(params, engine),
        v if v == verb::LIST => strategy_list(engine),
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
        b"multicast" => Some(Arc::new(MulticastStrategy::new())),
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
        None => {
            return ControlResponse::error(
                status::NOT_FOUND,
                format!("unknown strategy: {}", strategy_name),
            );
        }
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
        return ControlResponse::error(status::BAD_PARAMS, "cannot unset strategy at root prefix");
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
        text.push_str(&format!("  prefix={prefix} strategy={}\n", strategy.name()));
    }
    ControlResponse::ok_empty(text)
}

// ─── CS module ───────────────────────────────────────────────────────────────

async fn handle_cs(
    verb_name: &[u8],
    params: ControlParameters,
    engine: &ForwarderEngine,
) -> ControlResponse {
    match verb_name {
        v if v == verb::CONFIG => cs_config(params, engine),
        v if v == verb::INFO => cs_info(engine),
        v if v == verb::ERASE => cs_erase(params, engine).await,
        _ => ControlResponse::error(status::NOT_FOUND, "unknown cs verb"),
    }
}

fn cs_config(params: ControlParameters, engine: &ForwarderEngine) -> ControlResponse {
    let cs = engine.cs();

    // If capacity is provided, update it at runtime.
    if let Some(new_cap) = params.capacity {
        cs.set_capacity(new_cap as usize);
        tracing::info!(capacity = new_cap, "cs capacity updated");
    }

    let cap = cs.capacity();
    let echo = ControlParameters {
        capacity: Some(cap.max_bytes as u64),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn cs_info(engine: &ForwarderEngine) -> ControlResponse {
    let cs = engine.cs();
    let cap = cs.capacity();
    let n_entries = cs.len();
    let current = cs.current_bytes();
    let stats = cs.stats();
    let variant = cs.variant_name();

    let text = format!(
        "capacity={}B entries={} used={}B hits={} misses={} variant={}",
        cap.max_bytes, n_entries, current, stats.hits, stats.misses, variant,
    );
    ControlResponse::ok_empty(text)
}

async fn cs_erase(params: ControlParameters, engine: &ForwarderEngine) -> ControlResponse {
    let Some(ref name) = params.name else {
        return ControlResponse::error(status::BAD_PARAMS, "missing Name parameter");
    };
    let cs = engine.cs();
    let limit = params.count.map(|c| c as usize);
    let erased = cs.evict_prefix_erased(name, limit).await;

    let echo = ControlParameters {
        name: params.name,
        count: Some(erased as u64),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

// ─── Status module ────────────────────────────────────────────────────────────

fn handle_status(
    verb_name: &[u8],
    engine: &ForwarderEngine,
    cancel: &CancellationToken,
) -> ControlResponse {
    match verb_name {
        b"general" => {
            let n_faces = engine.faces().face_entries().len();
            let n_fib = engine.fib().dump().len();
            let n_pit = engine.pit().len();
            let n_cs = engine.cs().len();

            let text = format!("faces={n_faces} fib={n_fib} pit={n_pit} cs={n_cs}");
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

// ─── Neighbors module ─────────────────────────────────────────────────────────

fn handle_neighbors(verb_name: &[u8], engine: &ForwarderEngine) -> ControlResponse {
    match verb_name {
        v if v == verb::LIST => neighbors_list(engine),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown neighbors verb"),
    }
}

fn neighbors_list(engine: &ForwarderEngine) -> ControlResponse {
    let entries = engine.neighbors().all();
    let mut text = format!("{} neighbors\n", entries.len());
    for e in &entries {
        let face_ids: Vec<String> = e.faces.iter().map(|(id, _, _)| id.0.to_string()).collect();
        let state_str = match &e.state {
            NeighborState::Established { last_seen } => {
                let age_s = last_seen.elapsed().as_secs_f64();
                format!("state=Established  last_seen={:.1}s ago", age_s)
            }
            NeighborState::Stale {
                miss_count,
                last_seen,
            } => {
                let age_s = last_seen.elapsed().as_secs_f64();
                format!(
                    "state=Stale  miss={}  last_seen={:.1}s ago",
                    miss_count, age_s
                )
            }
            NeighborState::Probing { attempts, .. } => {
                format!("state=Probing  attempts={}", attempts)
            }
            NeighborState::Absent => "state=Absent".to_string(),
        };
        let rtt_str = match e.rtt_us {
            Some(us) => format!("  rtt={}us", us),
            None => "  rtt=None".to_string(),
        };
        text.push_str(&format!(
            "  {}  {}{}  faces=[{}]\n",
            e.node_name,
            state_str,
            rtt_str,
            face_ids.join(","),
        ));
    }
    ControlResponse::ok_empty(text)
}

// ─── Service module ───────────────────────────────────────────────────────────

fn handle_service(
    verb_name: &[u8],
    params: ControlParameters,
    engine: &ForwarderEngine,
    source_face: Option<FaceId>,
    discovery_sd: Option<&ServiceDiscoveryProtocol>,
    discovery_claimed: &[Name],
) -> ControlResponse {
    let sd = match discovery_sd {
        Some(s) => s,
        None => {
            return ControlResponse::error(status::NOT_FOUND, "service discovery is not enabled");
        }
    };
    match verb_name {
        v if v == verb::LIST => service_list(sd),
        v if v == verb::BROWSE => service_browse(params, sd),
        v if v == verb::ANNOUNCE => {
            service_announce(params, sd, engine, source_face, discovery_claimed)
        }
        v if v == verb::WITHDRAW => service_withdraw(params, sd),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown service verb"),
    }
}

fn service_list(sd: &ServiceDiscoveryProtocol) -> ControlResponse {
    let records = sd.local_records();
    let mut text = format!("{} services\n", records.len());
    for r in &records {
        text.push_str(&format!(
            "  {}  node={}  freshness={}ms\n",
            r.announced_prefix, r.node_name, r.freshness_ms,
        ));
    }
    ControlResponse::ok_empty(text)
}

fn service_browse(params: ControlParameters, sd: &ServiceDiscoveryProtocol) -> ControlResponse {
    let filter = params.name;
    let records = sd.all_records();
    let filtered: Vec<_> = records
        .iter()
        .filter(|r| {
            filter
                .as_ref()
                .is_none_or(|p| r.announced_prefix.has_prefix(p))
        })
        .collect();
    let mut text = format!("{} services\n", filtered.len());
    for r in &filtered {
        text.push_str(&format!(
            "  {}  node={}  freshness={}ms\n",
            r.announced_prefix, r.node_name, r.freshness_ms,
        ));
    }
    ControlResponse::ok_empty(text)
}

fn service_announce(
    params: ControlParameters,
    sd: &ServiceDiscoveryProtocol,
    engine: &ForwarderEngine,
    source_face: Option<FaceId>,
    discovery_claimed: &[Name],
) -> ControlResponse {
    let prefix = match params.name {
        Some(n) => n,
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };

    // Block announcements that would shadow a discovery-owned prefix.
    // Non-management faces in particular cannot claim prefixes already owned by
    // the discovery layer (e.g. /ndn/local/nd/, /ndn/local/sd/services/).
    if !is_management_face(source_face, engine) {
        let shadows_discovery = discovery_claimed
            .iter()
            .any(|cp| prefix.has_prefix(cp) || cp.has_prefix(&prefix));
        if shadows_discovery {
            return ControlResponse::error(
                status::UNAUTHORIZED,
                format!("prefix {prefix} overlaps with a discovery-owned namespace"),
            );
        }
    }

    // Also block reserved namespaces from non-management faces.
    if is_reserved_name(&prefix) && !is_management_face(source_face, engine) {
        return ControlResponse::error(
            status::UNAUTHORIZED,
            format!("prefix {prefix} is reserved for operator use"),
        );
    }

    // Derive node name from any existing service record (first one available).
    // If no records exist yet, use the prefix itself as a placeholder node name.
    let node_name = sd
        .local_records()
        .into_iter()
        .next()
        .map(|r| r.node_name)
        .unwrap_or_else(|| prefix.clone());

    // Find the FIB nexthop face for this prefix — that is the app's data face.
    // Linking the service record to that face means it is automatically
    // withdrawn when the app's face goes down (app exit, crash, disconnect),
    // without requiring the app to call service/withdraw explicitly.
    //
    // If no FIB route exists for the prefix yet, publish permanently and let
    // the operator call service/withdraw manually.
    let record = ServiceRecord::new(prefix.clone(), node_name);
    let owner_face = engine.fib().lpm(&prefix).and_then(|e| {
        // Prefer a non-management nexthop (the app's data face).
        e.nexthops_excluding(source_face.unwrap_or(FaceId(u32::MAX)))
            .into_iter()
            .next()
            .map(|nh| nh.face_id)
    });

    if let Some(face) = owner_face {
        sd.publish_with_owner(record, face);
        tracing::info!(prefix = %prefix, owner_face = ?face, "service/announce (owned by face)");
    } else {
        sd.publish(record);
        tracing::info!(prefix = %prefix, "service/announce (permanent — no FIB route found)");
    }

    let echo = ControlParameters {
        name: Some(prefix),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn service_withdraw(params: ControlParameters, sd: &ServiceDiscoveryProtocol) -> ControlResponse {
    let prefix = match params.name {
        Some(n) => n,
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };

    sd.withdraw(&prefix);
    tracing::info!(prefix = %prefix, "service/withdraw");

    let echo = ControlParameters {
        name: Some(prefix),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

// ─── Security helpers ─────────────────────────────────────────────────────────

/// Reserved name prefixes that only management (operator) faces may register.
const RESERVED_PREFIXES: &[&str] = &["/ndn/local", "/localhost/nfd"];

/// Return `true` if `name` has a prefix that is reserved for the router.
fn is_reserved_name(name: &Name) -> bool {
    RESERVED_PREFIXES.iter().any(|r| {
        Name::from_str(r)
            .map(|p| name.has_prefix(&p) || *name == p)
            .unwrap_or(false)
    })
}

/// Return `true` if the source face has operator-level management trust.
///
/// A face is trusted if:
/// - It is `FaceKind::Management` (connected through the management socket), OR
/// - No source face is known (internally generated command).
fn is_management_face(source_face: Option<FaceId>, engine: &ForwarderEngine) -> bool {
    match source_face {
        None => true, // internal / no source
        Some(fid) => engine
            .faces()
            .get(fid)
            .map(|f| f.kind().is_management())
            .unwrap_or(false),
    }
}

// ─── Faces counters ───────────────────────────────────────────────────────────

fn faces_counters(engine: &ForwarderEngine) -> ControlResponse {
    use std::sync::atomic::Ordering;
    let face_states = engine.face_states();
    let entries = engine.faces().face_info();
    let mut text = format!("{} faces\n", entries.len());
    for info in &entries {
        if let Some(s) = face_states.get(&info.id) {
            text.push_str(&format!(
                "  faceid={} in_interests={} in_data={} out_interests={} out_data={} in_bytes={} out_bytes={}\n",
                info.id.0,
                s.counters.in_interests.load(Ordering::Relaxed),
                s.counters.in_data.load(Ordering::Relaxed),
                s.counters.out_interests.load(Ordering::Relaxed),
                s.counters.out_data.load(Ordering::Relaxed),
                s.counters.in_bytes.load(Ordering::Relaxed),
                s.counters.out_bytes.load(Ordering::Relaxed),
            ));
        }
    }
    ControlResponse::ok_empty(text)
}

// ─── Measurements module ──────────────────────────────────────────────────────

fn handle_measurements(verb_name: &[u8], engine: &ForwarderEngine) -> ControlResponse {
    match verb_name {
        v if v == verb::LIST => measurements_list(engine),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown measurements verb"),
    }
}

fn measurements_list(engine: &ForwarderEngine) -> ControlResponse {
    let entries = engine.measurements().dump();
    let mut text = format!("{} entries\n", entries.len());
    for (prefix, entry) in &entries {
        let face_rtts: Vec<String> = entry
            .rtt_per_face
            .iter()
            .map(|(fid, rtt)| format!("face{}={:.1}ms", fid.0, rtt.srtt_ns / 1_000_000.0))
            .collect();
        text.push_str(&format!(
            "  prefix={} sat_rate={:.3} rtt=[{}]\n",
            prefix,
            entry.satisfaction_rate,
            face_rtts.join(" "),
        ));
    }
    ControlResponse::ok_empty(text)
}

// ─── Security module ──────────────────────────────────────────────────────────

async fn handle_security(
    verb_name: &[u8],
    params: ControlParameters,
    pib: Option<&FilePib>,
    engine: &ForwarderEngine,
    config: &ndn_config::ForwarderConfig,
) -> ControlResponse {
    // Verbs that don't need the PIB first.
    match verb_name {
        v if v == verb::CA_INFO         => return security_ca_info(config),
        v if v == verb::CA_REQUESTS     => return security_ca_requests(),
        v if v == verb::CA_TOKEN_ADD    => return security_ca_token_add(params),
        v if v == verb::YUBIKEY_DETECT  => return security_yubikey_detect(),
        _ => {}
    }

    let pib = match pib {
        Some(p) => p,
        None => {
            return ControlResponse::error(
                status::NOT_FOUND,
                "security identity not configured (no [security] section in config)",
            );
        }
    };
    match verb_name {
        v if v == verb::IDENTITY_LIST     => security_identity_list(pib),
        v if v == verb::IDENTITY_GENERATE => security_identity_generate(params, pib),
        v if v == verb::IDENTITY_DID      => security_identity_did(params, pib),
        v if v == verb::ANCHOR_LIST       => security_anchor_list(pib),
        v if v == verb::KEY_DELETE        => security_key_delete(params, pib),
        v if v == verb::CA_ENROLL         => security_ca_enroll(params, pib, engine).await,
        v if v == verb::YUBIKEY_GENERATE  => security_yubikey_generate(params, pib).await,
        _ => ControlResponse::error(status::NOT_FOUND, "unknown security verb"),
    }
}

fn security_identity_list(pib: &FilePib) -> ControlResponse {
    let keys = match pib.list_keys() {
        Ok(k) => k,
        Err(e) => return ControlResponse::error(status::SERVER_ERROR, e.to_string()),
    };
    let mut text = format!("{} identities\n", keys.len());
    for key_name in &keys {
        let cert = pib.get_cert(key_name);
        let (has_cert, valid_until) = match cert {
            Ok(c) => {
                let exp = if c.valid_until == u64::MAX {
                    "never".to_string()
                } else {
                    format!("{}ns", c.valid_until)
                };
                (true, exp)
            }
            Err(_) => (false, "-".to_string()),
        };
        text.push_str(&format!(
            "  name={} has_cert={} valid_until={}\n",
            key_name, has_cert, valid_until,
        ));
    }
    ControlResponse::ok_empty(text)
}

fn security_identity_generate(params: ControlParameters, pib: &FilePib) -> ControlResponse {
    let name = match params.name {
        Some(n) => n,
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };
    match pib.generate_ed25519(&name) {
        Ok(_signer) => {
            tracing::info!(name = %name, "security/identity-generate: generated Ed25519 key");
            let echo = ControlParameters {
                name: Some(name),
                ..Default::default()
            };
            ControlResponse::ok("OK", echo)
        }
        Err(e) => ControlResponse::error(status::SERVER_ERROR, e.to_string()),
    }
}

fn security_anchor_list(pib: &FilePib) -> ControlResponse {
    let anchors = match pib.list_anchors() {
        Ok(a) => a,
        Err(e) => return ControlResponse::error(status::SERVER_ERROR, e.to_string()),
    };
    let mut text = format!("{} anchors\n", anchors.len());
    for anchor_name in &anchors {
        text.push_str(&format!("  name={}\n", anchor_name));
    }
    ControlResponse::ok_empty(text)
}

fn security_key_delete(params: ControlParameters, pib: &FilePib) -> ControlResponse {
    let name = match params.name {
        Some(n) => n,
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };
    match pib.delete_key(&name) {
        Ok(()) => {
            tracing::info!(name = %name, "security/key-delete");
            let echo = ControlParameters {
                name: Some(name),
                ..Default::default()
            };
            ControlResponse::ok("OK", echo)
        }
        Err(e) => ControlResponse::error(status::SERVER_ERROR, e.to_string()),
    }
}

fn security_identity_did(params: ControlParameters, pib: &FilePib) -> ControlResponse {
    let name = match params.name {
        Some(n) => n,
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };
    // Verify the key actually exists.
    match pib.list_keys() {
        Ok(keys) if keys.contains(&name) => {}
        Ok(_) => return ControlResponse::error(status::NOT_FOUND, "identity not found in PIB"),
        Err(e) => return ControlResponse::error(status::SERVER_ERROR, e.to_string()),
    }
    // Encode as did:ndn:<percent-encoded-name> per W3C DID spec.
    let encoded = name.to_string().replace('/', "%2F");
    let did = format!("did:ndn:{encoded}");
    ControlResponse::ok_empty(did)
}

fn security_ca_info(config: &ndn_config::ForwarderConfig) -> ControlResponse {
    let sec = &config.security;
    match &sec.ca_prefix {
        None => ControlResponse::error(
            status::NOT_FOUND,
            "no CA configured (set [security] ca_prefix in router TOML)",
        ),
        Some(prefix) => {
            let info = format!(
                "ca_prefix={}\nca_info={}\nmax_validity_days={}\nchallenges={}\n",
                prefix,
                sec.ca_info,
                sec.ca_max_validity_days,
                sec.ca_challenges.join(","),
            );
            ControlResponse::ok_empty(info)
        }
    }
}

fn security_ca_requests() -> ControlResponse {
    // CaState is not yet embedded in the router process; return empty list.
    // When ndn-cert's CaState is wired into the router, this will return the
    // in-flight pending DashMap entries.
    ControlResponse::ok_empty("0 pending requests\n".to_string())
}

fn security_ca_token_add(params: ControlParameters) -> ControlResponse {
    let description = params.uri.unwrap_or_default();
    // Generate a random hex token using OS randomness.
    let mut token_bytes = [0u8; 16];
    let _ = getrandom::getrandom(&mut token_bytes);
    let token: String = token_bytes.iter().map(|b| format!("{b:02x}")).collect();
    tracing::info!(token = %token, description = %description, "security/ca-token-add");
    let echo = ControlParameters {
        // Return the token in the `uri` field (repurposed as a generic string slot).
        uri: Some(format!("token={token} description={description}")),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

/// Start a background NDNCERT enrollment session.
///
/// Creates a temporary [`AppFace`] registered with the engine so that
/// NDN Interests can be expressed through the live forwarder, then runs
/// the PROBE → NEW → CHALLENGE exchange against the requested CA prefix.
/// When the CA issues a certificate it is stored in the PIB.
async fn security_ca_enroll(
    params: ControlParameters,
    pib: &FilePib,
    engine: &ForwarderEngine,
) -> ControlResponse {
    use ndn_face_local::AppFace;

    let ca_name = match params.name {
        Some(n) => n,
        None => return ControlResponse::error(status::BAD_PARAMS, "ca_prefix (Name) is required"),
    };

    // `uri` encodes "challenge_type:challenge_param".
    let (challenge_type, challenge_param) = match params.uri.as_deref() {
        Some(s) => match s.split_once(':') {
            Some((t, p)) => (t.to_owned(), p.to_owned()),
            None => (s.to_owned(), String::new()),
        },
        None => return ControlResponse::error(status::BAD_PARAMS, "challenge type:param required"),
    };

    // We need an identity key to enroll with.
    let identity_name = match pib.list_keys() {
        Ok(keys) => match keys.into_iter().next() {
            Some(n) => n,
            None => return ControlResponse::error(status::NOT_FOUND, "no identity keys in PIB"),
        },
        Err(e) => return ControlResponse::error(status::SERVER_ERROR, e.to_string()),
    };

    let public_key = match pib.get_signer(&identity_name) {
        Ok(s) => s.public_key_bytes().to_vec(),
        Err(e) => return ControlResponse::error(status::SERVER_ERROR, e.to_string()),
    };

    // Allocate a temporary face ID (high range to avoid collisions).
    let face_id = FaceId(0xFFFF_0100 + (rand_u32() & 0x0FFF));
    let (app_face, app_handle) = AppFace::new(face_id, 32);
    let face_cancel = CancellationToken::new();
    engine.add_face(app_face, face_cancel.clone());

    // Clone what we need for the background task.
    let engine_clone = engine.clone();
    let pib_path = pib.root().to_owned();
    let identity_name_echo = identity_name.clone();

    tokio::spawn(async move {
        let result = run_enrollment(
            app_handle,
            face_id,
            &ca_name,
            &identity_name,
            &public_key,
            &challenge_type,
            &challenge_param,
        )
        .await;

        face_cancel.cancel();

        match result {
            Ok(cert) => {
                // Store the issued certificate in the PIB.
                match ndn_security::FilePib::open(&pib_path) {
                    Ok(pib) => match pib.store_cert(&identity_name, &cert) {
                        Ok(()) => tracing::info!(
                            name = %identity_name,
                            "ca-enroll: certificate installed"
                        ),
                        Err(e) => tracing::error!(error = %e, "ca-enroll: failed to store cert"),
                    },
                    Err(e) => tracing::error!(error = %e, "ca-enroll: failed to open PIB"),
                }
            }
            Err(e) => {
                tracing::error!(
                    ca = %ca_name,
                    error = %e,
                    "ca-enroll: enrollment failed"
                );
            }
        }

        drop(engine_clone); // keep engine alive until task completes
    });

    let echo = ControlParameters {
        name: Some(identity_name_echo),
        ..Default::default()
    };
    ControlResponse::ok("started", echo)
}

/// Run the three-step NDNCERT enrollment exchange (PROBE → NEW → CHALLENGE)
/// using a temporary AppFace that routes Interests through the live forwarder.
async fn run_enrollment(
    handle: ndn_face_local::AppHandle,
    _face_id: ndn_transport::FaceId,
    ca_prefix: &Name,
    identity_name: &Name,
    public_key: &[u8],
    challenge_type: &str,
    challenge_param: &str,
) -> Result<ndn_security::Certificate, String> {
    use ndn_cert::client::EnrollmentSession;
    use ndn_packet::encode::encode_interest;

    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    // ── PROBE ────────────────────────────────────────────────────────────────
    let probe_name = ca_prefix.clone().append(b"CA").append(b"PROBE");
    let probe_interest = encode_interest(&probe_name, None);
    handle.send(probe_interest).await.map_err(|e| format!("PROBE send: {e}"))?;

    let probe_resp = tokio::time::timeout(TIMEOUT, handle.recv())
        .await
        .map_err(|_| "PROBE timeout")?
        .ok_or("PROBE: face closed")?;

    tracing::debug!(bytes = probe_resp.len(), "ca-enroll: PROBE response received");

    // ── NEW ──────────────────────────────────────────────────────────────────
    let mut session = EnrollmentSession::new(
        identity_name.clone(),
        public_key.to_vec(),
        86400, // 24h default; CA will cap to its max_validity
    );

    let new_body = session.new_request_body().map_err(|e| e.to_string())?;
    let new_name = ca_prefix.clone().append(b"CA").append(b"NEW");
    let new_interest = encode_interest(&new_name, Some(&new_body));
    handle.send(new_interest).await.map_err(|e| format!("NEW send: {e}"))?;

    let new_resp = tokio::time::timeout(TIMEOUT, handle.recv())
        .await
        .map_err(|_| "NEW timeout")?
        .ok_or("NEW: face closed")?;

    let new_body_content = extract_data_content(&new_resp).ok_or("NEW: malformed Data")?;
    session.handle_new_response(&new_body_content).map_err(|e| e.to_string())?;

    // ── CHALLENGE ────────────────────────────────────────────────────────────
    let mut challenge_params = serde_json::Map::new();
    challenge_params.insert("code".to_owned(), serde_json::Value::String(challenge_param.to_owned()));
    let chal_body = session
        .challenge_request_body(challenge_type, challenge_params)
        .map_err(|e| e.to_string())?;

    let request_id = session.request_id().unwrap_or("").to_owned();
    let chal_name = ca_prefix.clone().append(b"CA").append(b"CHALLENGE").append(request_id.as_bytes());
    let chal_interest = encode_interest(&chal_name, Some(&chal_body));
    handle.send(chal_interest).await.map_err(|e| format!("CHALLENGE send: {e}"))?;

    let chal_resp = tokio::time::timeout(TIMEOUT, handle.recv())
        .await
        .map_err(|_| "CHALLENGE timeout")?
        .ok_or("CHALLENGE: face closed")?;

    let chal_body_content = extract_data_content(&chal_resp).ok_or("CHALLENGE: malformed Data")?;
    session.handle_challenge_response(&chal_body_content).map_err(|e| e.to_string())?;

    if session.is_complete() {
        session.into_certificate().ok_or_else(|| "no cert after completion".to_owned())
    } else if session.needs_another_round() {
        let msg = session.challenge_status_message().unwrap_or("another round required");
        Err(format!("multi-round challenge not supported: {msg}"))
    } else {
        Err("enrollment did not complete".to_owned())
    }
}

/// Extract the Content TLV value from a Data packet (best-effort).
fn extract_data_content(data_bytes: &[u8]) -> Option<Vec<u8>> {
    use ndn_packet::Data;
    Data::decode(bytes::Bytes::copy_from_slice(data_bytes))
        .ok()
        .and_then(|d| d.content().map(|c| c.to_vec()))
}

/// Generate a pseudo-random u32 for face ID allocation.
fn rand_u32() -> u32 {
    let mut buf = [0u8; 4];
    let _ = getrandom::getrandom(&mut buf);
    u32::from_le_bytes(buf)
}

// ─── Config module ────────────────────────────────────────────────────────────

fn handle_config(verb_name: &[u8], config: &ndn_config::ForwarderConfig) -> ControlResponse {
    match verb_name {
        v if v == verb::GET => config_get(config),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown config verb"),
    }
}

fn config_get(config: &ndn_config::ForwarderConfig) -> ControlResponse {
    match config.to_toml_string() {
        Ok(toml) => ControlResponse::ok_empty(toml),
        Err(e) => ControlResponse::error(status::SERVER_ERROR, e.to_string()),
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Resolve FaceId from params or source face.
///
/// Returns the error as a `ControlResponse` via the `?` operator on `Result`.
fn resolve_face_id(
    params: &ControlParameters,
    source_face: Option<FaceId>,
) -> Result<FaceId, Box<ControlResponse>> {
    match params.face_id {
        // Face ID 0 is never valid (IDs are allocated from 1 upwards).
        // Treat it the same as omitted — fall back to the requesting face.
        // This matches NFD convention and fixes Unix-mode clients that pass 0.
        Some(0) | None => source_face.ok_or_else(|| {
            Box::new(ControlResponse::error(
                status::BAD_PARAMS,
                "cannot determine FaceId",
            ))
        }),
        Some(id) => Ok(FaceId(id as u32)),
    }
}

// ─── YubiKey commands ─────────────────────────────────────────────────────────

/// Detect whether a YubiKey is connected and accessible via PC/SC.
///
/// Returns `status_text = "present"` on success, or an error if no device is found.
/// Requires the `yubikey-piv` cargo feature; returns `NOT_FOUND` otherwise.
fn security_yubikey_detect() -> ControlResponse {
    #[cfg(feature = "yubikey-piv")]
    {
        match ndn_security::yubikey::YubikeyKeyStore::open() {
            Ok(_) => ControlResponse::ok_empty("present"),
            Err(e) => ControlResponse::error(
                status::NOT_FOUND,
                format!("YubiKey not found: {e}"),
            ),
        }
    }
    #[cfg(not(feature = "yubikey-piv"))]
    {
        ControlResponse::error(
            status::NOT_FOUND,
            "yubikey-piv feature is not compiled in; rebuild ndn-router with --features yubikey-piv",
        )
    }
}

/// Generate a P-256 key in YubiKey PIV slot 9a and register it under `params.name`.
///
/// The slot mapping is persisted to `{pib_root}/yubikey-slots.json` so that
/// subsequent operations can locate the key. The uncompressed 65-byte public key
/// is returned base64url-encoded in the `uri` field of the response.
///
/// Requires the `yubikey-piv` cargo feature.
async fn security_yubikey_generate(
    params: ControlParameters,
    pib: &FilePib,
) -> ControlResponse {
    let key_name = match params.name {
        Some(n) => n,
        None => return ControlResponse::error(status::BAD_PARAMS, "missing name parameter"),
    };

    #[cfg(feature = "yubikey-piv")]
    {
        use ndn_security::yubikey::{YubikeyKeyStore, YubikeySlot};

        let store = match YubikeyKeyStore::open() {
            Ok(s) => s,
            Err(e) => return ControlResponse::error(
                status::NOT_FOUND,
                format!("YubiKey not found: {e}"),
            ),
        };

        let pub_bytes = match store
            .generate_in_slot(key_name.clone(), YubikeySlot::Authentication)
            .await
        {
            Ok(b) => b,
            Err(e) => return ControlResponse::error(
                status::SERVER_ERROR,
                format!("YubiKey generate failed: {e}"),
            ),
        };

        // Persist the name→slot mapping alongside the PIB.
        let slot_file = pib.root().join("yubikey-slots.json");
        let entry = serde_json::json!({
            "name": key_name.to_string(),
            "slot": "9a"
        });
        let mut entries: Vec<serde_json::Value> = if slot_file.exists() {
            std::fs::read_to_string(&slot_file)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        // Remove any existing entry for this name, then append the new one.
        entries.retain(|e| e["name"].as_str() != Some(&key_name.to_string()));
        entries.push(entry);
        let _ = std::fs::write(
            &slot_file,
            serde_json::to_vec_pretty(&entries).unwrap_or_default(),
        );

        let pubkey_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&pub_bytes);
        tracing::info!(
            name = %key_name,
            pubkey_len = pub_bytes.len(),
            "security/yubikey-generate: P-256 key generated in PIV slot 9a"
        );
        ControlResponse::ok(
            "generated",
            ControlParameters {
                name: Some(key_name),
                uri: Some(pubkey_b64),
                ..Default::default()
            },
        )
    }
    #[cfg(not(feature = "yubikey-piv"))]
    {
        let _ = (key_name, pib);
        ControlResponse::error(
            status::NOT_FOUND,
            "yubikey-piv feature is not compiled in; rebuild ndn-router with --features yubikey-piv",
        )
    }
}

// ─── Log module ───────────────────────────────────────────────────────────────

fn handle_log(verb_name: &[u8], params: ControlParameters) -> ControlResponse {
    match verb_name {
        v if v == verb::GET_RECENT => {
            // `params.count` carries the last sequence number the client has seen.
            // We return only entries with seq > after_seq, plus the current max_seq
            // as the first line of the response body so the client can advance its cursor.
            let after_seq = params.count.unwrap_or(0);
            let body = crate::LOG_RING
                .get()
                .and_then(|r| r.lock().ok())
                .map(|g| {
                    let max_seq = g.back().map(|(s, _)| *s).unwrap_or(0);
                    let mut out = max_seq.to_string();
                    for (seq, line) in g.iter() {
                        if *seq > after_seq {
                            out.push('\n');
                            out.push_str(line);
                        }
                    }
                    out
                })
                .unwrap_or_else(|| "0".to_string());
            ControlResponse::ok_empty(body)
        }
        v if v == verb::GET_FILTER => {
            let filter = crate::LOG_FILTER
                .get()
                .and_then(|m| m.lock().ok())
                .map(|g| g.clone())
                .unwrap_or_default();
            ControlResponse::ok_empty(filter)
        }
        v if v == verb::SET_FILTER => {
            let filter_str = params.uri.unwrap_or_default();
            if filter_str.is_empty() {
                return ControlResponse::error(status::BAD_PARAMS, "uri field must contain the filter string");
            }
            if let Some(apply) = crate::APPLY_FILTER.get() {
                apply(&filter_str);
                tracing::info!(filter = %filter_str, "log/set-filter: filter updated");
                ControlResponse::ok_empty(filter_str)
            } else {
                ControlResponse::error(status::NOT_FOUND, "filter reload not initialised")
            }
        }
        _ => ControlResponse::error(status::NOT_FOUND, "unknown log verb"),
    }
}

async fn send_response(handle: &AppHandle, name: &Name, resp: &ControlResponse) {
    let content = resp.encode();
    let data = encode_data_unsigned(name, &content);
    if let Err(e) = handle.send(data).await {
        tracing::warn!(error = %e, "nfd-mgmt: failed to send Data response");
    }
}
