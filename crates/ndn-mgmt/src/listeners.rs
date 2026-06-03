//! Native-only listener loops — accept incoming face / udp / tcp
//! connections and add each new peer to the engine face table.

#![cfg(not(target_arch = "wasm32"))]

use std::sync::Arc;

use ndn_engine::ForwarderEngine;
use ndn_transport::{FaceId, FaceKind};
use tokio_util::sync::CancellationToken;

/// Best-effort `SO_RCVBUF` bump (Unix). Failure is logged but non-fatal.
/// Effective ceiling: `net.core.rmem_max` on Linux (doubled by the
/// kernel), `kern.ipc.maxsockbuf` on macOS. Not supported on Windows.
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
            target: "face.udp",
            error=%std::io::Error::last_os_error(),
            "udp-listener: failed to set SO_RCVBUF (continuing with default)"
        );
    }
}

#[cfg(not(unix))]
fn set_recv_buf_size(_socket: &tokio::net::UdpSocket, _size: usize) {}

/// Accept NDN face connections on `path` and register each as an
/// operator-trusted `FaceKind::Management` face (the NFD management socket;
/// trust is gated by `0600`/`0666` filesystem perms + signed-command auth).
///
/// `path` is a Unix domain socket path on Unix (e.g. `/run/nfd/nfd.sock`)
/// or a Named Pipe path on Windows (e.g. `\\.\pipe\ndn`).
pub async fn run_face_listener(path: &str, engine: ForwarderEngine, cancel: CancellationToken) {
    run_face_listener_as(path, FaceKind::Management, engine, cancel).await
}

/// Like [`run_face_listener`] but accepts each connection with an explicit
/// [`FaceKind`]. A mobile UI/app listener (iOS App-Group UDS) should pass
/// `FaceKind::App` so connecting clients do **not** inherit operator-level
/// management trust — privileged verbs then go through signed-command auth, not
/// face-kind. (`FaceKind::App` is `FaceScope::Local`, so `/localhost` prefixes
/// stay reachable and congestion uses the app-face backpressure policy.)
pub async fn run_face_listener_as(
    path: &str,
    kind: FaceKind,
    engine: ForwarderEngine,
    cancel: CancellationToken,
) {
    let listener = match ndn_face_native::local::IpcListener::bind(path) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(target: "face.system", path = %path, error = %e, "face-listener: bind failed");
            return;
        }
    };

    tracing::info!(target: "face.system", path = %listener.uri(), ?kind, "NDN face listener ready");

    loop {
        let face_id = engine.faces().alloc_id();
        let face = tokio::select! {
            _ = cancel.cancelled() => break,
            r = listener.accept_as(face_id, kind) => match r {
                Ok(f)  => f,
                Err(e) => {
                    tracing::warn!(target: "face.system", error = %e, "face-listener: accept error");
                    continue;
                }
            },
        };

        tracing::debug!(target: "face.system", face = %face_id, ?kind, "face-listener: accepted connection");
        // Per-connection child token isolates teardown to one peer.
        let conn_cancel = cancel.child_token();
        engine.add_face(face, conn_cancel);
    }

    listener.cleanup();
    tracing::info!(target: "face.system", "NDN face listener stopped");
}

/// Mount a single already-connected fd as a `FaceKind::App` face on `engine`,
/// returning the allocated [`FaceId`].
///
/// Android has no `listen()` rendezvous for the UI↔tunnel seam — the foreground
/// `VpnService` creates a `socketpair()` and hands one end to the UI Activity
/// across Binder as a `ParcelFileDescriptor`. This is the fd analogue of
/// [`run_face_listener_as`]'s accept loop: one pre-handed fd per bound client,
/// mounted as a local app face (no operator trust). Unix only.
#[cfg(unix)]
pub fn mount_app_face_from_fd(
    fd: std::os::fd::RawFd,
    engine: &ForwarderEngine,
    cancel: CancellationToken,
) -> std::io::Result<FaceId> {
    let face_id = engine.faces().alloc_id();
    let face = ndn_face_native::local::ipc_face_from_raw_fd(face_id, FaceKind::App, fd)?;
    engine.add_face(face, cancel);
    tracing::debug!(target: "face.system", face = %face_id, "mounted app face from fd");
    Ok(face_id)
}

/// Listen for incoming UDP datagrams on `bind_addr` and auto-create a
/// `UdpFace` per source address (NFD "UDP channel" pattern).
///
/// A single unconnected socket serves every peer. The per-peer face
/// shares the listener socket for sending via `send_to`; inbound bytes
/// are demuxed by the listener and injected directly into the pipeline,
/// since the face's own `recv()` would race the listener for the same
/// socket.
/// Resolve the configured `rx_sockets` knob to an actual socket count:
/// `0` → auto (min(num_cpus, 4)); otherwise the configured value. Clamped to
/// 1 on platforms without `SO_REUSEPORT` flow-balancing.
fn resolve_rx_sockets(rx_sockets: usize) -> usize {
    #[cfg(unix)]
    {
        if rx_sockets == 0 {
            let cpus = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1);
            cpus.clamp(1, 4)
        } else {
            rx_sockets
        }
    }
    #[cfg(not(unix))]
    {
        let _ = rx_sockets;
        1
    }
}

/// Run the UDP listener for `bind_addr`. With `rx_sockets > 1` (Linux/BSD),
/// opens that many `SO_REUSEPORT` sockets — each with its own reader task — so
/// the kernel spreads inbound flows across cores. Falls back to one socket
/// otherwise.
pub async fn run_udp_listener(
    bind_addr: std::net::SocketAddr,
    engine: ForwarderEngine,
    cancel: CancellationToken,
    rx_sockets: usize,
) {
    let n = resolve_rx_sockets(rx_sockets);

    if n > 1 {
        #[cfg(unix)]
        {
            let mut started = 0;
            for _ in 0..n {
                match ndn_face_native::net::sockopt::bind_reuseport_udp(bind_addr) {
                    Ok(std_sock) => {
                        if let Err(e) = std_sock.set_nonblocking(true) {
                            tracing::warn!(target: "face.udp", error=%e, "udp-listener: set_nonblocking failed");
                            continue;
                        }
                        match tokio::net::UdpSocket::from_std(std_sock) {
                            Ok(tok) => {
                                let eng = engine.clone();
                                let c = cancel.child_token();
                                tokio::spawn(
                                    async move { udp_rx_loop(Arc::new(tok), eng, c).await },
                                );
                                started += 1;
                            }
                            Err(e) => {
                                tracing::warn!(target: "face.udp", error=%e, "udp-listener: from_std failed")
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(target: "face.udp", addr=%bind_addr, error=%e, "udp-listener: SO_REUSEPORT bind failed")
                    }
                }
            }
            if started > 0 {
                tracing::info!(target: "face.udp", addr=%bind_addr, sockets=started, "UDP listener ready (SO_REUSEPORT RX sharding)");
                cancel.cancelled().await;
                return;
            }
            tracing::warn!(target: "face.udp", "udp-listener: no SO_REUSEPORT sockets opened, falling back to single socket");
        }
    }

    // Single-socket path.
    let socket = match tokio::net::UdpSocket::bind(bind_addr).await {
        Ok(s) => {
            // Default OS buffer (~212 KB on Linux) is too small for
            // fragment bursts at high window sizes and causes drops.
            set_recv_buf_size(&s, 4 * 1024 * 1024);
            Arc::new(s)
        }
        Err(e) => {
            tracing::error!(target: "face.udp", addr=%bind_addr, error=%e, "udp-listener: bind failed");
            return;
        }
    };
    tracing::info!(target: "face.udp", addr=%socket.local_addr().unwrap_or(bind_addr), "UDP listener ready");
    udp_rx_loop(socket, engine, cancel).await;
}

/// One UDP receive loop: demux datagrams by source address into send-only
/// faces and inject into the engine. One of these runs per listener socket.
async fn udp_rx_loop(
    socket: Arc<tokio::net::UdpSocket>,
    engine: ForwarderEngine,
    cancel: CancellationToken,
) {
    // Dedupe faces by (IP, port). Replies go to the datagram's source
    // address so consumer apps on ephemeral ports — not port 6363 —
    // still receive the Data.
    let mut peers = std::collections::HashMap::<std::net::SocketAddr, FaceId>::new();
    let mut buf = [0u8; 9000];

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            r = socket.recv_from(&mut buf) => {
                let (n, src) = match r {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::warn!(target: "face.udp", error=%e, "udp-listener: recv error");
                        continue;
                    }
                };

                tracing::debug!(target: "face.udp", src=%src, len=n, "udp-listener: recv packet");
                let raw = bytes::Bytes::copy_from_slice(&buf[..n]);

                let face_id = if let Some(&id) = peers.get(&src) {
                    id
                } else {
                    // New peer: send-only UdpFace sharing the listener
                    // socket. Inbound bytes come from the listener's
                    // demux via `inject_packet`, so no recv loop runs.
                    let face_id = engine.faces().alloc_id();
                    let face = ndn_face_native::net::UdpFace::from_shared_socket(
                        face_id, Arc::clone(&socket), src,
                    );
                    let peer_cancel = cancel.child_token();
                    engine.add_face_send_only(face, peer_cancel);
                    peers.insert(src, face_id);
                    tracing::info!(target: "face.udp", face=%face_id, peer=%src, "udp-listener: new face");
                    face_id
                };

                // TlvDecode handles per-face fragment reassembly downstream.
                let arrival = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;
                let meta = ndn_discovery::InboundMeta::udp(src);
                if engine.inject_packet(raw, face_id, arrival, meta).await.is_err() {
                    break;
                }
            }
        }
    }

    tracing::info!(target: "face.udp", "UDP listener stopped");
}

/// Accept incoming TCP connections on `bind_addr` and create a
/// `TcpFace` per connection. `TcpFace` owns TLV length-prefix framing.
pub async fn run_tcp_listener(
    bind_addr: std::net::SocketAddr,
    engine: ForwarderEngine,
    cancel: CancellationToken,
) {
    let listener = match tokio::net::TcpListener::bind(bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(target: "face.tcp", addr=%bind_addr, error=%e, "tcp-listener: bind failed");
            return;
        }
    };

    let local = listener.local_addr().unwrap_or(bind_addr);
    tracing::info!(target: "face.tcp", addr=%local, "TCP listener ready");

    loop {
        let (stream, peer) = tokio::select! {
            _ = cancel.cancelled() => break,
            r = listener.accept() => match r {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(target: "face.tcp", error=%e, "tcp-listener: accept error");
                    continue;
                }
            },
        };

        let face_id = engine.faces().alloc_id();
        let face = ndn_face_native::net::tcp_face_from_stream(face_id, stream);
        let conn_cancel = cancel.child_token();
        engine.add_face(face, conn_cancel);
        tracing::info!(target: "face.tcp", face=%face_id, peer=%peer, "tcp-listener: accepted connection");
    }

    tracing::info!(target: "face.tcp", "TCP listener stopped");
}
