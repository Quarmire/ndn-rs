//! Native-only listener loops — accept incoming face / udp / tcp
//! connections and add each new peer to the engine face table.

#![cfg(not(target_arch = "wasm32"))]

use std::sync::Arc;

use ndn_engine::ForwarderEngine;
use ndn_transport::{FaceId, FaceKind};
use tokio_util::sync::CancellationToken;

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
    let listener = match ndn_face::local::IpcListener::bind(path) {
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
    let face = ndn_face::local::ipc_face_from_raw_fd(face_id, FaceKind::App, fd)?;
    engine.add_face(face, cancel);
    tracing::debug!(target: "face.system", face = %face_id, "mounted app face from fd");
    Ok(face_id)
}

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

/// A bound UDP listener: its port is claimed and its RX sockets are open, but
/// nothing reads them until [`run_udp_listener`].
pub struct UdpListener {
    addr: std::net::SocketAddr,
    sockets: Vec<std::net::UdpSocket>,
}

impl UdpListener {
    /// The bound address, with the resolved port when bound to port `0`.
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.addr
    }
}

/// Bind the UDP listener for `bind_addr`, claiming its port for this process.
///
/// Fails with [`std::io::ErrorKind::AddrInUse`] while another process holds
/// the port (see [`ndn_face::net::sockopt::bind_listener_udp`]): two
/// forwarders on one port would otherwise share one `SO_REUSEPORT` group and
/// the kernel would split inbound datagrams between them, silently. Bind the
/// listeners before any peer face, which joins the claimed port
/// (`ConnectedPort::Listener`) and would otherwise hold it first.
///
/// With `rx_sockets > 1` (unix), that many sockets in total are opened on the
/// port, each read by its own task, so the kernel spreads inbound flows
/// across cores. An extra socket that fails to bind is logged and skipped.
pub fn bind_udp_listener(
    bind_addr: std::net::SocketAddr,
    rx_sockets: usize,
) -> std::io::Result<UdpListener> {
    let first = ndn_face::net::sockopt::bind_listener_udp(bind_addr)?;
    first.set_nonblocking(true)?;
    let addr = first.local_addr()?;
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut sockets = vec![first];
    for _ in 1..resolve_rx_sockets(rx_sockets) {
        #[cfg(unix)]
        match ndn_face::net::sockopt::bind_reuseport_udp(addr).and_then(|s| {
            s.set_nonblocking(true)?;
            Ok(s)
        }) {
            Ok(s) => sockets.push(s),
            Err(e) => {
                tracing::warn!(target: "face.udp", addr=%addr, error=%e, "udp-listener: extra RX socket bind failed")
            }
        }
    }
    Ok(UdpListener { addr, sockets })
}

/// Serve a bound UDP listener: auto-create a `UdpFace` per source address
/// (NFD "UDP channel" pattern) until `cancel` fires.
///
/// Each listener socket serves every peer that the kernel steers to it. The
/// per-peer face shares that socket for sending via `send_to`; inbound bytes
/// are demuxed by the listener and injected directly into the pipeline, since
/// the face's own `recv()` would race the listener for the same socket.
pub async fn run_udp_listener(
    listener: UdpListener,
    engine: ForwarderEngine,
    cancel: CancellationToken,
) {
    let UdpListener { addr, sockets } = listener;
    let mut readers = tokio::task::JoinSet::new();
    for std_sock in sockets {
        match tokio::net::UdpSocket::from_std(std_sock) {
            Ok(sock) => {
                readers.spawn(udp_rx_loop(
                    Arc::new(sock),
                    engine.clone(),
                    cancel.child_token(),
                ));
            }
            Err(e) => {
                tracing::warn!(target: "face.udp", addr=%addr, error=%e, "udp-listener: from_std failed")
            }
        }
    }
    if readers.is_empty() {
        tracing::error!(target: "face.udp", addr=%addr, "udp-listener: no socket could be served");
        return;
    }
    tracing::info!(target: "face.udp", addr=%addr, sockets=readers.len(), "UDP listener ready");
    while readers.join_next().await.is_some() {}
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

                // A cached mapping may point at a face the engine's idle
                // reaper has since removed — injecting under a dead FaceId is
                // a silent blackhole. Verify liveness and re-create if gone.
                let cached = peers
                    .get(&src)
                    .copied()
                    .filter(|id| engine.face_states().contains_key(id));
                let face_id = if let Some(id) = cached {
                    id
                } else {
                    if let Some(stale) = peers.remove(&src) {
                        tracing::info!(target: "face.udp", face=%stale, peer=%src, "udp-listener: cached face gone, re-creating");
                    }
                    // New peer: send-only UdpFace sharing the listener
                    // socket. Inbound bytes come from the listener's
                    // demux via `inject_packet`, so no recv loop runs.
                    let face_id = engine.faces().alloc_id();
                    let face = ndn_face::net::UdpFace::from_shared_socket(
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
                let meta = ndn_discovery_core::InboundMeta::udp(src);
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
        let face = ndn_face::net::tcp_face_from_stream(face_id, stream);
        let conn_cancel = cancel.child_token();
        engine.add_face(face, conn_cancel);
        tracing::info!(target: "face.tcp", face=%face_id, peer=%peer, "tcp-listener: accepted connection");
    }

    tracing::info!(target: "face.tcp", "TCP listener stopped");
}

#[cfg(test)]
mod tests {
    use super::bind_udp_listener;

    /// A UDP listener opens all its RX sockets on its port, and a second
    /// listener — another forwarder — is refused that port.
    #[test]
    fn a_udp_listener_port_is_not_shared_with_a_second_listener() {
        let first = bind_udp_listener("127.0.0.1:0".parse().unwrap(), 4).unwrap();
        #[cfg(unix)]
        assert_eq!(first.sockets.len(), 4);
        for rx_sockets in [1, 4] {
            let second = bind_udp_listener(first.local_addr(), rx_sockets);
            assert_eq!(
                second.err().map(|e| e.kind()),
                Some(std::io::ErrorKind::AddrInUse)
            );
        }
    }
}
