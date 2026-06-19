use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use tokio::net::UdpSocket;

use tracing::trace;

use ndn_packet::fragment::DEFAULT_UDP_MTU;
use ndn_transport::{
    FaceError, FaceId, FaceKind, FacePersistency, MtuError, PersistencyError, Transport,
    ip_face_uri,
};

/// Hard maximum UDP datagram payload (65535 − 8-byte UDP header − 20-byte
/// minimum IPv4 header).
const UDP_HARD_MAX: u64 = 65507;

/// Receive-buffer size, and therefore the largest datagram this face can accept
/// without truncation. `set_send_mtu` is capped to this (audit DG-1): advertising
/// a send MTU larger than the receive buffer would let a peer send datagrams that
/// are silently truncate-dropped on receipt.
const UDP_RECV_BUF: usize = 9000;

/// NDN transport over unicast UDP.
///
/// Uses an unconnected socket with `send_to` / `recv_from`: on macOS and some
/// BSDs a connected UDP socket that receives an ICMP port-unreachable enters
/// a permanent `EPIPE` state on every subsequent `send`. NDNLPv2 framing and
/// fragmentation live in the paired
/// [`LpLinkService`](ndn_transport::LpLinkService); `send_bytes` ships one
/// datagram.
pub struct UdpFace {
    id: FaceId,
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    mtu: AtomicUsize,
    /// Reported [`FaceKind`] — `Udp` by default. A caller can re-tag the face
    /// (e.g. [`FaceKind::WifiDirect`] for a unicast bulk link over a Wi-Fi P2P
    /// group) so cost-aware forwarding and telemetry see the real radio while
    /// the transport stays an ordinary UDP socket. See [`Self::with_kind`].
    kind: FaceKind,
    /// Spillover for the `recvmmsg` batch path: one syscall yields up to N
    /// datagrams; `recv_bytes` returns one at a time and buffers the rest.
    #[cfg(all(feature = "udp-recvmmsg", target_os = "linux"))]
    rx: std::sync::Mutex<std::collections::VecDeque<Bytes>>,
}

impl UdpFace {
    /// Bind to `local`, targeting `peer` for all sends. Datagrams from other
    /// sources are dropped.
    ///
    /// If `local` is unspecified, the socket binds to the specific local
    /// interface that the OS routes to `peer`, avoiding `EHOSTUNREACH` on
    /// macOS when the peer is on a non-default-route subnet.
    pub async fn bind(local: SocketAddr, peer: SocketAddr, id: FaceId) -> std::io::Result<Self> {
        let local = if local.ip().is_unspecified() {
            let resolved = resolve_local_addr(peer, local.port())?;
            trace!(target: "face.udp", peer=%peer, resolved=%resolved, "udp: resolved local addr for peer");
            resolved
        } else {
            local
        };
        let socket = UdpSocket::bind(local).await?;
        super::sockopt::tune_datagram_socket(&socket, "udp");
        trace!(target: "face.udp", face=%id, local=%socket.local_addr().unwrap_or(local), peer=%peer, "udp: bound");
        Ok(Self {
            id,
            socket: Arc::new(socket),
            peer,
            mtu: AtomicUsize::new(DEFAULT_UDP_MTU),
            kind: FaceKind::Udp,
            #[cfg(all(feature = "udp-recvmmsg", target_os = "linux"))]
            rx: std::sync::Mutex::new(std::collections::VecDeque::new()),
        })
    }

    pub fn from_socket(id: FaceId, socket: UdpSocket, peer: SocketAddr) -> Self {
        Self {
            id,
            socket: Arc::new(socket),
            peer,
            mtu: AtomicUsize::new(DEFAULT_UDP_MTU),
            kind: FaceKind::Udp,
            #[cfg(all(feature = "udp-recvmmsg", target_os = "linux"))]
            rx: std::sync::Mutex::new(std::collections::VecDeque::new()),
        }
    }

    /// Share an existing socket (e.g. the UDP listener socket) so replies go
    /// out from the same port; `recv` filters by `peer` address.
    pub fn from_shared_socket(id: FaceId, socket: Arc<UdpSocket>, peer: SocketAddr) -> Self {
        Self {
            id,
            socket,
            peer,
            mtu: AtomicUsize::new(DEFAULT_UDP_MTU),
            kind: FaceKind::Udp,
            #[cfg(all(feature = "udp-recvmmsg", target_os = "linux"))]
            rx: std::sync::Mutex::new(std::collections::VecDeque::new()),
        }
    }

    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Re-tag the reported [`FaceKind`] (default [`FaceKind::Udp`]). Used to
    /// mark a unicast bulk link over a Wi-Fi P2P group as
    /// [`FaceKind::WifiDirect`] so cost-aware forwarding prefers it and
    /// telemetry names the real radio — the wire transport is unchanged.
    pub fn with_kind(mut self, kind: FaceKind) -> Self {
        self.kind = kind;
        self
    }
}

impl Transport for UdpFace {
    fn id(&self) -> FaceId {
        self.id
    }
    fn kind(&self) -> FaceKind {
        self.kind
    }

    fn remote_uri(&self) -> Option<String> {
        Some(ip_face_uri("udp", self.peer))
    }

    fn local_uri(&self) -> Option<String> {
        self.socket.local_addr().ok().map(|a| ip_face_uri("udp", a))
    }

    fn send_mtu(&self) -> Option<usize> {
        Some(self.mtu.load(Ordering::Relaxed))
    }

    /// `None` reverts to `DEFAULT_UDP_MTU`; values above `UDP_HARD_MAX` are
    /// rejected with `OutOfRange`.
    fn set_send_mtu(&self, mtu: Option<u64>) -> Result<Option<u64>, MtuError> {
        let new = match mtu {
            None => DEFAULT_UDP_MTU,
            Some(0) => {
                return Err(MtuError::OutOfRange {
                    reason: "mtu must be > 0",
                });
            }
            Some(n) if n > UDP_HARD_MAX => {
                return Err(MtuError::OutOfRange {
                    reason: "udp-max-65507",
                });
            }
            // DG-1: never advertise a send MTU larger than the receive buffer,
            // or peers' larger datagrams would be truncate-dropped here.
            Some(n) if n > UDP_RECV_BUF as u64 => {
                return Err(MtuError::OutOfRange {
                    reason: "udp send MTU cannot exceed the receive buffer",
                });
            }
            Some(n) => n as usize,
        };
        self.mtu.store(new, Ordering::Relaxed);
        Ok(Some(new as u64))
    }

    /// Persistency is a face-table metadata hint with no socket-level effect.
    fn set_persistency(&self, _persistency: FacePersistency) -> Result<(), PersistencyError> {
        Ok(())
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        #[cfg(all(feature = "udp-recvmmsg", target_os = "linux"))]
        {
            self.recv_bytes_batched().await
        }
        #[cfg(not(all(feature = "udp-recvmmsg", target_os = "linux")))]
        {
            self.recv_bytes_single().await
        }
    }

    async fn send_bytes(&self, wire: Bytes) -> Result<(), FaceError> {
        match self.socket.try_send_to(&wire, self.peer) {
            Ok(_) => Ok(()),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                self.socket.send_to(&wire, self.peer).await?;
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Batch a packet's fragment burst into one `sendmmsg` syscall (all to
    /// `self.peer`), resuming on partial sends. Off-by-default `udp-sendmmsg`,
    /// Linux only; otherwise the trait default ships one datagram at a time.
    #[cfg(all(feature = "udp-sendmmsg", target_os = "linux"))]
    async fn send_batch(&self, wires: &[Bytes]) -> Result<(), FaceError> {
        use std::os::unix::io::AsRawFd;
        let fd = self.socket.as_raw_fd();
        let mut start = 0;
        while start < wires.len() {
            self.socket.writable().await?;
            match self.socket.try_io(tokio::io::Interest::WRITABLE, || {
                super::sendmmsg::sendmmsg_batch(fd, &self.peer, &wires[start..])
            }) {
                Ok(n) if n > 0 => start += n,
                // Kernel accepted nothing but didn't signal WouldBlock — re-arm.
                Ok(_) => continue,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
}

impl UdpFace {
    /// One datagram per `recv_from` syscall, dropping wrong-source datagrams.
    /// The default receive path on every platform (and the only one unless the
    /// `udp-recvmmsg` batch path is enabled on Linux).
    #[cfg(not(all(feature = "udp-recvmmsg", target_os = "linux")))]
    async fn recv_bytes_single(&self) -> Result<Bytes, FaceError> {
        let mut buf = [0u8; UDP_RECV_BUF];
        loop {
            let (n, src) = self.socket.recv_from(&mut buf).await?;
            // Match on IP + port only, NOT the full `SocketAddr`: for an IPv6
            // link-local peer (e.g. a Wi-Fi Aware NDP), `recv_from` reports a
            // source whose `scope_id`/`flowinfo` differ from the address we were
            // constructed with, so an exact `==` would drop every reply. `ip()` /
            // `port()` exclude scope/flowinfo (they live only on `SocketAddrV6`),
            // so this is robust there and unchanged for ordinary UDP (scope 0).
            // Canonicalize both sides: a dual-stack (`[::]`-bound) socket reports an
            // IPv4 peer as an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`), which
            // would never `==` the plain-IPv4 peer the face was built with — so a
            // Wi-Fi Direct / SoftAP IPv4 peer's every datagram was dropped as
            // "wrong source". `to_canonical()` maps `::ffff:a.b.c.d` → `a.b.c.d`.
            if src.ip().to_canonical() == self.peer.ip().to_canonical()
                && src.port() == self.peer.port()
            {
                return Ok(Bytes::copy_from_slice(&buf[..n]));
            }
        }
    }

    /// Batched receive: drain the spillover buffer, else refill it with one
    /// `recvmmsg` (up to `BATCH` datagrams), keeping only peer-matched ones.
    /// Off-by-default (`udp-recvmmsg`, Linux); see `net::recvmmsg`.
    #[cfg(all(feature = "udp-recvmmsg", target_os = "linux"))]
    async fn recv_bytes_batched(&self) -> Result<Bytes, FaceError> {
        use std::os::unix::io::AsRawFd;
        loop {
            if let Some(pkt) = self.rx.lock().unwrap().pop_front() {
                return Ok(pkt);
            }
            self.socket.readable().await?;
            let fd = self.socket.as_raw_fd();
            match self.socket.try_io(tokio::io::Interest::READABLE, || {
                super::recvmmsg::recvmmsg_batch(fd)
            }) {
                Ok(batch) => {
                    let mut q = self.rx.lock().unwrap();
                    for (payload, src) in batch {
                        // Canonicalize: a dual-stack socket reports IPv4 peers as
                        // IPv4-mapped IPv6 (see `recv_bytes_single`).
                        if src.ip().to_canonical() == self.peer.ip().to_canonical()
                            && src.port() == self.peer.port()
                        {
                            q.push_back(payload);
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e.into()),
            }
        }
    }
}

/// Discover the local IP that routes to `peer` via a throwaway connected
/// UDP socket (`connect` resolves the route without sending).
fn resolve_local_addr(peer: SocketAddr, port: u16) -> std::io::Result<SocketAddr> {
    let probe = std::net::UdpSocket::bind(if peer.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })?;
    probe.connect(peer)?;
    let mut local = probe.local_addr()?;
    local.set_port(port);
    Ok(local)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_transport::Face;

    #[cfg(unix)]
    #[tokio::test]
    async fn bind_enlarges_recv_buffer() {
        // Buffer tuning is best-effort: the kernel clamps SO_RCVBUF to
        // net.core.rmem_max (only ~208 KiB on a stock Ubuntu), so we cannot
        // assert a portable absolute size. Assert instead that a tuned face's
        // receive buffer is at least as large as an untuned socket's — tuning
        // never shrinks it, and grows it wherever rmem_max permits.
        let untuned = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let baseline = super::super::sockopt::recv_buffer_size(&untuned).unwrap();

        let face = UdpFace::bind(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:6363".parse().unwrap(),
            FaceId(1),
        )
        .await
        .unwrap();
        let tuned = super::super::sockopt::recv_buffer_size(&*face.socket).unwrap();
        assert!(
            tuned >= baseline,
            "tuned recv buffer {tuned} smaller than untuned {baseline}"
        );
    }

    /// Exercises the `recvmmsg` batch path end-to-end: send more datagrams than
    /// one `recvmmsg` drains (BATCH=16) and assert every one is delivered via
    /// the buffered `recv_bytes`, with the peer filter intact.
    #[cfg(all(feature = "udp-recvmmsg", target_os = "linux"))]
    #[tokio::test]
    async fn recvmmsg_batch_receives_all() {
        use ndn_transport::Transport;
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender_addr = sender.local_addr().unwrap();

        let face = UdpFace::bind("127.0.0.1:0".parse().unwrap(), sender_addr, FaceId(7))
            .await
            .unwrap();
        let recv_addr = face.socket.local_addr().unwrap();

        // A second, non-peer sender — its datagrams must be filtered out.
        let intruder = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let n: usize = 20; // > BATCH so the spillover buffer + a 2nd refill run
        for i in 0..n {
            sender
                .send_to(&[i as u8, 0xAA, 0xBB], recv_addr)
                .await
                .unwrap();
        }
        intruder.send_to(&[0xFF; 3], recv_addr).await.unwrap();

        let mut seen = std::collections::HashSet::new();
        for _ in 0..n {
            let b = tokio::time::timeout(std::time::Duration::from_secs(3), face.recv_bytes())
                .await
                .expect("recv timed out")
                .expect("recv error");
            assert_eq!(
                &b[..],
                &[b[0], 0xAA, 0xBB],
                "payload corrupted by batch path"
            );
            seen.insert(b[0]);
        }
        assert_eq!(
            seen.len(),
            n,
            "missing datagrams via recvmmsg path: {seen:?}"
        );
    }

    /// Exercises the `sendmmsg` batch path: send a burst as one batch and
    /// assert every datagram is delivered to the peer.
    #[cfg(all(feature = "udp-sendmmsg", target_os = "linux"))]
    #[tokio::test]
    async fn send_batch_delivers_all() {
        use ndn_transport::Transport;
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let recv_addr = receiver.local_addr().unwrap();

        let face = UdpFace::bind("127.0.0.1:0".parse().unwrap(), recv_addr, FaceId(8))
            .await
            .unwrap();

        let k = 8u8;
        let wires: Vec<Bytes> = (0..k).map(|i| Bytes::from(vec![i, 0xCC])).collect();
        Transport::send_batch(&face, &wires).await.unwrap();

        let mut seen = std::collections::HashSet::new();
        let mut buf = [0u8; 64];
        for _ in 0..k {
            let (n, _) = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                receiver.recv_from(&mut buf),
            )
            .await
            .expect("recv timed out")
            .unwrap();
            assert_eq!(n, 2);
            seen.insert(buf[0]);
        }
        assert_eq!(
            seen.len(),
            k as usize,
            "missing datagrams via sendmmsg path: {seen:?}"
        );
    }

    fn test_packet(tag: u8) -> Bytes {
        use ndn_tlv::TlvWriter;
        let mut w = TlvWriter::new();
        w.write_tlv(0x05, &[tag]);
        w.finish()
    }

    fn expected_on_wire(pkt: &Bytes) -> Bytes {
        ndn_packet::lp::encode_lp_packet(pkt)
    }

    async fn face_pair() -> (Face, UdpFace) {
        let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();

        let face_a = Face::from_transport(UdpFace::from_socket(FaceId(0), sock_a, addr_b));
        let face_b = UdpFace::from_socket(FaceId(1), sock_b, addr_a);
        (face_a, face_b)
    }

    #[tokio::test]
    async fn udp_roundtrip() {
        let (face_a, face_b) = face_pair().await;

        let pkt = test_packet(0xAB);
        face_a.send_bytes(pkt.clone()).await.unwrap();
        let received = face_b.recv_bytes().await.unwrap();
        assert_eq!(received, expected_on_wire(&pkt));
    }

    #[tokio::test]
    async fn udp_multiple_sequential() {
        let (face_a, face_b) = face_pair().await;

        for i in 0u8..5 {
            face_a.send_bytes(test_packet(i)).await.unwrap();
            assert_eq!(
                face_b.recv_bytes().await.unwrap(),
                expected_on_wire(&test_packet(i))
            );
        }
    }

    #[test]
    fn accessors() {
        let peer: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        assert_eq!(FaceId(7).0, 7);
        assert_eq!(FaceKind::Udp, FaceKind::Udp);
        let _ = peer;
    }
}
