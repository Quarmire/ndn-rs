//! Log-target taxonomy. Every `tracing` call site uses one of these targets
//! so operators can scope `RUST_LOG` (e.g. `info,fwd.pit=trace,face.tcp=debug`)
//! without recompiling. The target names what the event is about, not where
//! the code lives.
//!
//! # NFD `[log]` mapping
//!
//! | NFD module      | ndn-rs target  |
//! |-----------------|----------------|
//! | `Forwarder`     | `fwd.pipeline` |
//! | `Cs` / `Pit` / `Fib` / `Strategy` | `fwd.cs` / `fwd.pit` / `fwd.fib` / `fwd.strategy` |
//! | `Face`          | `face.system`  |
//! | `UdpFactory` / `TcpFactory` / `WebSocketFace` | `face.udp` / `face.tcp` / `face.ws` |
//! | `NfdcMain`      | `mgmt.*`       |

/// Forwarding pipeline — packet arrival, decode, pipeline routing decisions.
pub const FWD_PIPELINE: &str = "fwd.pipeline";

/// PIT operations — new entry, aggregation, satisfaction, expiry, drain.
pub const FWD_PIT: &str = "fwd.pit";

/// Content Store — lookup hits/misses and insertion decisions.
pub const FWD_CS: &str = "fwd.cs";

/// FIB — longest-prefix-match lookups during strategy dispatch.
pub const FWD_FIB: &str = "fwd.fib";

/// Strategy — forwarding decisions, Nack generation, delayed forward.
pub const FWD_STRATEGY: &str = "fwd.strategy";

/// TCP face — per-frame send/recv events for stream-oriented faces.
pub const FACE_TCP: &str = "face.tcp";

/// UDP face — per-datagram send/recv events, fragmentation, reassembly.
pub const FACE_UDP: &str = "face.udp";

/// WebSocket face — binary-frame send/recv events.
pub const FACE_WS: &str = "face.ws";

/// NDNLPv2 — LP header processing (fragmentation, congestion marks, PIT tokens).
pub const FACE_LP: &str = "face.lp";

/// Ethernet/L2 faces — raw frame I/O and neighbor discovery.
pub const FACE_ETH: &str = "face.eth";

/// Face system — face lifecycle: creation, removal, hotplug, idle timeout.
pub const FACE_SYSTEM: &str = "face.system";

/// RIB management commands — register/unregister/list.
pub const MGMT_RIB: &str = "mgmt.rib";

/// Face management commands — create/destroy/list.
pub const MGMT_FACE: &str = "mgmt.face";

/// FIB management commands — add-nexthop/remove-nexthop.
pub const MGMT_FIB: &str = "mgmt.fib";

/// CS management commands — config/info.
pub const MGMT_CS: &str = "mgmt.cs";

/// Strategy-choice management commands — set/unset/list.
pub const MGMT_STRATEGY: &str = "mgmt.strategy";

/// Log management commands — get-filter/set-filter/get-recent/modules.
pub const MGMT_LOG: &str = "mgmt.log";

/// Security management commands — identity, cert, schema operations.
pub const MGMT_SECURITY: &str = "mgmt.security";

/// Status and measurement queries.
pub const MGMT_STATUS: &str = "mgmt.status";

/// Static routing protocol (administrator-configured routes).
pub const ROUTING_STATIC: &str = "routing.static";

/// Spec-compliant ndn-dv distance-vector routing protocol (per
/// `ndnd/dv/SPEC.md`).
pub const ROUTING_DV: &str = "routing.dv";

/// NLSR link-state routing protocol.
pub const ROUTING_NLSR: &str = "routing.nlsr";

/// SVS state-vector sync protocol.
pub const SYNC_SVS: &str = "sync.svs";

/// PSync set-reconciliation sync protocol.
pub const SYNC_PSYNC: &str = "sync.psync";

/// Cryptographic validation — chain walks, cert fetches, key verification.
pub const SECURITY: &str = "security";

/// Engine internals — task lifecycle, shutdown, expiry workers.
pub const ENGINE: &str = "engine";

/// Neighbor discovery and service discovery protocols.
pub const DISCOVERY: &str = "discovery";

static ALL_TARGETS: &[&str] = &[
    ENGINE,
    FWD_PIPELINE,
    FWD_PIT,
    FWD_CS,
    FWD_FIB,
    FWD_STRATEGY,
    FACE_TCP,
    FACE_UDP,
    FACE_WS,
    FACE_LP,
    FACE_ETH,
    FACE_SYSTEM,
    MGMT_RIB,
    MGMT_FACE,
    MGMT_FIB,
    MGMT_CS,
    MGMT_STRATEGY,
    MGMT_LOG,
    MGMT_SECURITY,
    MGMT_STATUS,
    ROUTING_STATIC,
    ROUTING_DV,
    ROUTING_NLSR,
    SYNC_SVS,
    SYNC_PSYNC,
    SECURITY,
    DISCOVERY,
];

/// Every log target in the taxonomy, sorted alphabetically. Used by
/// `ndn-fwd --modules` and `/localhost/nfd/log/modules`.
pub fn enumerate() -> &'static [&'static str] {
    ALL_TARGETS
}
