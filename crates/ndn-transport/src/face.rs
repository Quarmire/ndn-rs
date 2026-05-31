use bytes::Bytes;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

use crate::link_service::{LinkService, default_link_service_for_kind};
use crate::transport::{ErasedTransport, Transport};

/// Format an IP-based FaceUri with the spec-correct family suffix:
/// `<scheme>4://` for IPv4, `<scheme>6://` for IPv6. NFD rejects the
/// family-less variants (`udp://`, `tcp://`).
pub fn ip_face_uri(scheme_base: &str, addr: std::net::SocketAddr) -> String {
    let suffix = if addr.is_ipv4() { '4' } else { '6' };
    format!("{scheme_base}{suffix}://{addr}")
}

/// Link-layer source address returned by multicast/broadcast faces.
#[derive(Clone, Debug)]
pub enum FaceAddr {
    Udp(std::net::SocketAddr),
    Ether([u8; 6]),
}

/// Opaque face identifier.
///
/// Monotonically allocated by [`crate::FaceTable::alloc_id`]; never recycled.
/// `u64` is wide enough that the counter cannot wrap in a realistic daemon
/// lifetime, closing the ABA hazard for stamped face-ids (e.g. NDNLPv2
/// `IncomingFaceId`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FaceId(pub u64);

impl FaceId {
    pub const INVALID: FaceId = FaceId(u64::MAX);

    /// Reserved id reported as NDNLPv2 `IncomingFaceId` on Data answered from
    /// the Content Store rather than a real ingress face. Mirrors NFD's
    /// `face::FACEID_CONTENT_STORE` (`NFD/daemon/face/face-common.hpp`), which
    /// `onContentStoreHit` stamps so a `LocalFields` consumer can tell a cache
    /// hit from a producer reply.
    pub const CONTENT_STORE: FaceId = FaceId(254);
}

impl core::fmt::Display for FaceId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "face#{}", self.0)
    }
}

/// Classifies a face by its transport type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum FaceKind {
    Udp,
    Tcp,
    Unix,
    Ethernet,
    EtherMulticast,
    App,
    Shm,
    Serial,
    Bluetooth,
    Wfb,
    /// Wi-Fi Aware (NAN) connectionless coordination bearer — AP-less,
    /// association-less follow-up messages. `link_type() == AdHoc`.
    WifiAware,
    Compute,
    Internal,
    Multicast,
    WebSocket,
    /// WebTransport face (HTTP/3 + QUIC datagrams). Oversized packets are
    /// NDNLPv2-fragmented to `maxDatagramSize` (interoperates with NDNts).
    /// Listens for browsers and dials peer forwarders.
    WebTransport,
    /// Raw QUIC face — forwarder-to-forwarder backbone link (TLS 1.3,
    /// connection migration, 0-RTT). One reliable bidirectional stream of
    /// length-delimited NDN TLV; no HTTP/3 layer (unlike WebTransport, it
    /// does not reach browsers).
    Quic,
    /// WebRTC datachannel (peer-to-peer SCTP/DTLS); browser-as-peer transport.
    /// Local-scope by classification (signaling typically loopback), trust
    /// boundary matches `WebTransport`.
    WebRtc,
    /// Management socket face (Unix domain). Filesystem permissions on the
    /// socket (`0600`, router user) gate operator-level access without
    /// requiring signed Interests.
    Management,
}

impl FaceKind {
    /// The locality policy for this kind (see [`resolve_scope`]).
    pub fn scope_policy(&self) -> ScopePolicy {
        match self {
            FaceKind::Unix
            | FaceKind::App
            | FaceKind::Shm
            | FaceKind::Internal
            | FaceKind::Compute
            | FaceKind::Management => ScopePolicy::AlwaysLocal,
            FaceKind::Ethernet
            | FaceKind::EtherMulticast
            | FaceKind::Serial
            | FaceKind::Bluetooth
            | FaceKind::Wfb
            | FaceKind::WifiAware
            | FaceKind::Multicast => ScopePolicy::AlwaysNonLocal,
            FaceKind::Udp
            | FaceKind::Tcp
            | FaceKind::WebSocket
            | FaceKind::WebTransport
            | FaceKind::WebRtc
            | FaceKind::Quic => ScopePolicy::ByRemoteAddress,
        }
    }

    /// Whether this kind frames packets with NDNLPv2 on the wire (the LP
    /// link-service) versus passing bare TLV (in-process / IPC kinds). This is
    /// the *transport-type* axis, independent of [`FaceScope`]: a loopback UDP
    /// face is `Local` scope but still LP-framed.
    pub fn uses_lp_framing(&self) -> bool {
        match self {
            FaceKind::Unix
            | FaceKind::App
            | FaceKind::Shm
            | FaceKind::Internal
            | FaceKind::Compute
            | FaceKind::Management => false,
            FaceKind::Udp
            | FaceKind::Tcp
            | FaceKind::Ethernet
            | FaceKind::EtherMulticast
            | FaceKind::Serial
            | FaceKind::Bluetooth
            | FaceKind::Wfb
            | FaceKind::WifiAware
            | FaceKind::Multicast
            | FaceKind::WebSocket
            | FaceKind::WebTransport
            | FaceKind::WebRtc
            | FaceKind::Quic => true,
        }
    }

    pub fn is_management(&self) -> bool {
        matches!(self, FaceKind::Management)
    }
}

impl core::fmt::Display for FaceKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Unix => "unix",
            Self::Ethernet => "ethernet",
            Self::EtherMulticast => "ether-multicast",
            Self::App => "app",
            Self::Shm => "shm",
            Self::Serial => "serial",
            Self::Bluetooth => "bluetooth",
            Self::Wfb => "wfb",
            Self::WifiAware => "wifi-aware",
            Self::Compute => "compute",
            Self::Internal => "internal",
            Self::Multicast => "multicast",
            Self::WebSocket => "web-socket",
            Self::WebTransport => "web-transport",
            Self::WebRtc => "web-rtc",
            Self::Quic => "quic",
            Self::Management => "management",
        })
    }
}

impl core::str::FromStr for FaceKind {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "udp" => Ok(Self::Udp),
            "tcp" => Ok(Self::Tcp),
            "unix" => Ok(Self::Unix),
            "ethernet" => Ok(Self::Ethernet),
            "ether-multicast" => Ok(Self::EtherMulticast),
            "app" => Ok(Self::App),
            "shm" => Ok(Self::Shm),
            "serial" => Ok(Self::Serial),
            "bluetooth" => Ok(Self::Bluetooth),
            "wfb" => Ok(Self::Wfb),
            "wifi-aware" => Ok(Self::WifiAware),
            "compute" => Ok(Self::Compute),
            "internal" => Ok(Self::Internal),
            "multicast" => Ok(Self::Multicast),
            "web-socket" => Ok(Self::WebSocket),
            "web-transport" => Ok(Self::WebTransport),
            "quic" => Ok(Self::Quic),
            "management" => Ok(Self::Management),
            _ => Err(()),
        }
    }
}

/// Whether a face is local (same-host IPC) or non-local (network). Used to
/// enforce that `/localhost` prefixes never cross non-local faces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaceScope {
    Local,
    NonLocal,
}

/// How a [`FaceKind`]'s [`FaceScope`] is determined. NFD keeps locality
/// (a property of the *remote endpoint*) separate from LP framing (a property
/// of the *transport type*); this enum is the locality axis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopePolicy {
    /// Always [`FaceScope::Local`] — same-host IPC (Unix, Shm, App, …).
    AlwaysLocal,
    /// Always [`FaceScope::NonLocal`] — L2 links / multicast with no IP
    /// loopback notion (Ethernet, multicast, serial, Bluetooth, WiFi-direct).
    AlwaysNonLocal,
    /// Local iff the remote address is loopback; else NonLocal. IP / overlay
    /// transports (UDP, TCP, WebSocket, WebTransport, WebRTC).
    ByRemoteAddress,
}

/// Resolve a face's [`FaceScope`] from its kind and remote FaceUri.
///
/// For [`ScopePolicy::ByRemoteAddress`] kinds the remote host decides: a
/// loopback (or `localhost`) remote is [`FaceScope::Local`], anything else —
/// including an unknown/absent remote — is [`FaceScope::NonLocal`] (the safe
/// default: never grant `/localhost` reach to an unidentified peer).
pub fn resolve_scope(kind: FaceKind, remote_uri: Option<&str>) -> FaceScope {
    match kind.scope_policy() {
        ScopePolicy::AlwaysLocal => FaceScope::Local,
        ScopePolicy::AlwaysNonLocal => FaceScope::NonLocal,
        ScopePolicy::ByRemoteAddress => match remote_uri.map(host_is_loopback) {
            Some(true) => FaceScope::Local,
            _ => FaceScope::NonLocal,
        },
    }
}

/// Whether a FaceUri authority resolves to a loopback host. Accepts schemes
/// like `udp4://127.0.0.1:6363`, `wts://[::1]:4443`, `tcp4://localhost:6363`.
fn host_is_loopback(uri: &str) -> bool {
    // Strip `scheme://`, then take the authority up to the next `/` or `?`.
    let after_scheme = uri.split("://").nth(1).unwrap_or(uri);
    let authority = after_scheme
        .split(['/', '?'])
        .next()
        .unwrap_or(after_scheme);
    // Split host from port, honoring `[v6]:port`.
    let host = if let Some(rest) = authority.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else {
        authority
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(authority)
    };
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

/// Per-face policy for handling a full outbound send queue.
///
/// `Drop` matches NFD's `GenericLinkService`: drop under congestion and let
/// transport-layer recovery handle it (network faces).
///
/// `Backpressure` blocks engine dispatch for up to `deadline`, then falls
/// back to Drop. Correct for App faces where there is no upstream transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionPolicy {
    Drop,
    Backpressure { deadline: Duration },
}

impl CongestionPolicy {
    /// Local faces → `Backpressure { 100ms }`; non-local → `Drop`.
    pub fn default_for_scope(scope: FaceScope) -> Self {
        match scope {
            FaceScope::Local => CongestionPolicy::Backpressure {
                deadline: Duration::from_millis(100),
            },
            FaceScope::NonLocal => CongestionPolicy::Drop,
        }
    }
}

/// Face persistence level (NFD semantics):
/// `OnDemand` (0) — destroyed on idle or I/O error;
/// `Persistent` (1) — survives I/O errors;
/// `Permanent` (2) — never destroyed (multicast, always-on links).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FacePersistency {
    OnDemand = 0,
    Persistent = 1,
    Permanent = 2,
}

/// Connectivity model of the underlying link. Forwarding strategies consult
/// this for multi-access suppression and partially-connected handling.
///
/// `PointToPoint`: unicast TCP/UDP, serial, Unix socket.
/// `MultiAccess`: every node receives every frame (Ethernet/UDP multicast).
/// `AdHoc`: partially-connected wireless (IBSS, MANET) — suppression off.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum LinkType {
    #[default]
    PointToPoint,
    MultiAccess,
    AdHoc,
}

impl core::fmt::Display for LinkType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::PointToPoint => "point-to-point",
            Self::MultiAccess => "multi-access",
            Self::AdHoc => "ad-hoc",
        })
    }
}

impl FacePersistency {
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0 => Some(Self::OnDemand),
            1 => Some(Self::Persistent),
            2 => Some(Self::Permanent),
            _ => None,
        }
    }
}

#[derive(Debug, Error)]
pub enum FaceError {
    #[error("face closed")]
    Closed,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("send buffer full")]
    Full,
}

/// A composed ([`Transport`](crate::transport::Transport) +
/// [`LinkService`](crate::link_service::LinkService)) pair. The Transport
/// owns wire-byte I/O; the LinkService owns NDNLPv2 framing, reliability,
/// IncomingFaceId tagging, and congestion-mark handling.
pub struct Face {
    pub transport: Arc<dyn ErasedTransport>,
    pub link_service: Arc<dyn LinkService>,
    /// Locality resolved once at construction from kind + remote address
    /// ([`resolve_scope`]); cached so hot-path scope checks avoid re-parsing
    /// the FaceUri.
    scope: FaceScope,
}

impl Face {
    pub fn new(transport: Arc<dyn ErasedTransport>, link_service: Arc<dyn LinkService>) -> Self {
        let scope = resolve_scope(transport.kind(), transport.remote_uri().as_deref());
        Self {
            transport,
            link_service,
            scope,
        }
    }

    /// Pair the transport with the default LinkService for its `FaceKind`
    /// (Passthrough for IPC kinds, LpLinkService for wire kinds).
    pub fn from_transport<T: Transport>(transport: T) -> Self {
        let link_service = default_link_service_for_kind(Transport::kind(&transport));
        Self::new(Arc::new(transport), link_service)
    }

    /// Build a face from a pre-wrapped erased transport plus an explicit
    /// LinkService (tests, mgmt mount, demo CA, internal faces).
    pub fn from_parts(
        transport: Arc<dyn ErasedTransport>,
        link_service: Arc<dyn LinkService>,
    ) -> Self {
        Self::new(transport, link_service)
    }

    pub fn id(&self) -> FaceId {
        self.transport.id()
    }

    pub fn kind(&self) -> FaceKind {
        self.transport.kind()
    }

    /// Per-face locality, resolved from kind + remote address at construction
    /// (honors a loopback remote, unlike a kind-only classification).
    pub fn scope(&self) -> FaceScope {
        self.scope
    }

    pub fn remote_uri(&self) -> Option<String> {
        self.transport.remote_uri()
    }

    pub fn local_uri(&self) -> Option<String> {
        self.transport.local_uri()
    }

    pub fn link_type(&self) -> LinkType {
        self.transport.link_type()
    }

    /// Send through the paired LinkService (applies NDNLPv2 framing for
    /// non-local transports).
    pub async fn send_bytes(&self, pkt: Bytes) -> Result<(), FaceError> {
        self.link_service.send(&*self.transport, pkt, None).await
    }

    /// Send tagged with its originating face id. Passthrough routes the tag
    /// through the in-process tag-bag; LpLinkService drops it for now.
    pub async fn send_bytes_with_source(
        &self,
        pkt: Bytes,
        source: FaceId,
    ) -> Result<(), FaceError> {
        self.link_service
            .send(&*self.transport, pkt, Some(source))
            .await
    }

    /// Send a packet's already-framed NDNLPv2 fragment burst (all to the same
    /// peer) through the link service, which batches the egress syscall where
    /// the transport supports it (`sendmmsg`).
    pub async fn send_batch(
        &self,
        wires: &[Bytes],
        source: Option<FaceId>,
    ) -> Result<(), FaceError> {
        self.link_service
            .send_batch(&*self.transport, wires, source)
            .await
    }

    /// Receive the next wire packet. For link-layer addr or LP-surfaced
    /// metadata use [`Face::recv_frame`].
    pub async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        Ok(self.link_service.recv(&*self.transport).await?.wire)
    }

    /// Receive payload + link-layer sender address (multicast/broadcast
    /// surface it; unicast returns `None`).
    pub async fn recv_bytes_with_addr(&self) -> Result<(Bytes, Option<FaceAddr>), FaceError> {
        let frame = self.link_service.recv(&*self.transport).await?;
        Ok((frame.wire, frame.addr))
    }

    /// Receive the full [`LinkServiceFrame`](crate::link_service::LinkServiceFrame)
    /// (wire payload plus LP-surfaced fields).
    pub async fn recv_frame(&self) -> Result<crate::link_service::LinkServiceFrame, FaceError> {
        self.link_service.recv(&*self.transport).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn f01_ip_face_uri_ipv4_uses_scheme4() {
        let addr: std::net::SocketAddr = "192.0.2.7:6363".parse().unwrap();
        assert_eq!(ip_face_uri("udp", addr), "udp4://192.0.2.7:6363");
        assert_eq!(ip_face_uri("tcp", addr), "tcp4://192.0.2.7:6363");
    }

    #[test]
    fn f01_ip_face_uri_ipv6_uses_scheme6_with_brackets() {
        let addr: std::net::SocketAddr = "[2001:db8::1]:6363".parse().unwrap();
        assert_eq!(ip_face_uri("udp", addr), "udp6://[2001:db8::1]:6363");
        assert_eq!(ip_face_uri("tcp", addr), "tcp6://[2001:db8::1]:6363");
    }

    #[test]
    fn scope_policy_partitions_kinds() {
        assert_eq!(FaceKind::Shm.scope_policy(), ScopePolicy::AlwaysLocal);
        assert_eq!(
            FaceKind::Management.scope_policy(),
            ScopePolicy::AlwaysLocal
        );
        assert_eq!(
            FaceKind::Ethernet.scope_policy(),
            ScopePolicy::AlwaysNonLocal
        );
        assert_eq!(
            FaceKind::Multicast.scope_policy(),
            ScopePolicy::AlwaysNonLocal
        );
        assert_eq!(FaceKind::Udp.scope_policy(), ScopePolicy::ByRemoteAddress);
        assert_eq!(
            FaceKind::WebTransport.scope_policy(),
            ScopePolicy::ByRemoteAddress
        );
    }

    #[test]
    fn lp_framing_splits_ipc_from_wire() {
        // IPC kinds carry bare TLV; wire kinds (incl. WS/WT/WebRTC) use NDNLPv2.
        assert!(!FaceKind::Unix.uses_lp_framing());
        assert!(!FaceKind::App.uses_lp_framing());
        assert!(!FaceKind::Management.uses_lp_framing());
        assert!(FaceKind::Udp.uses_lp_framing());
        assert!(FaceKind::WebSocket.uses_lp_framing());
        assert!(FaceKind::WebTransport.uses_lp_framing());
        assert!(FaceKind::WebRtc.uses_lp_framing());
    }

    #[test]
    fn resolve_scope_by_remote_loopback() {
        // IPC: always local regardless of (absent) remote.
        assert_eq!(resolve_scope(FaceKind::Shm, None), FaceScope::Local);
        // L2: always non-local.
        assert_eq!(resolve_scope(FaceKind::Ethernet, None), FaceScope::NonLocal);
        // ByRemote: loopback host → Local.
        assert_eq!(
            resolve_scope(FaceKind::Udp, Some("udp4://127.0.0.1:6363")),
            FaceScope::Local
        );
        assert_eq!(
            resolve_scope(FaceKind::WebTransport, Some("wts://localhost:4443")),
            FaceScope::Local
        );
        assert_eq!(
            resolve_scope(FaceKind::Tcp, Some("tcp6://[::1]:6363")),
            FaceScope::Local
        );
        // ByRemote: non-loopback or unknown → NonLocal (safe default).
        assert_eq!(
            resolve_scope(FaceKind::Udp, Some("udp4://192.0.2.7:6363")),
            FaceScope::NonLocal
        );
        assert_eq!(
            resolve_scope(FaceKind::WebTransport, Some("wts://peer.example:4443")),
            FaceScope::NonLocal
        );
        assert_eq!(resolve_scope(FaceKind::WebRtc, None), FaceScope::NonLocal);
    }
}
