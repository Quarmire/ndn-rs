use std::collections::BTreeMap;
use std::sync::Arc;

use dashmap::DashMap;
use ndn_discovery_core::NeighborTable;
use ndn_packet::Name;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use ndn_transport::FaceTable;

use crate::observability::targets as t;
use crate::{Fib, Rib};

/// Shared tables passed to [`RoutingProtocol::start`]: RIB (writes go here),
/// FIB (nexthop introspection), face table (live faces and kinds), and
/// neighbour table (peer state). The engine retains its own clones.
pub struct RoutingHandle {
    pub rib: Arc<Rib>,
    pub fib: Arc<Fib>,
    pub faces: Arc<FaceTable>,
    pub neighbors: Arc<NeighborTable>,
}

/// Operator-visible snapshot of a routing protocol's state. Mgmt verb
/// handlers render via the `render_*` helpers; the DV Status TLV codec
/// (`ndnd/dv/SPEC.md`) reads structured fields directly.
#[derive(Debug, Clone, Default)]
pub struct RoutingProtocolStatus {
    pub network: Option<Name>,
    pub router: Option<Name>,
    pub origin: u64,
    /// Numeric metrics keyed by NFD-style name (`nNeighbors`, `nRibEntries`).
    pub counters: BTreeMap<String, u64>,
    /// Non-numeric values (`boot`, `adv_seq`, `pfx_seq`).
    pub fields: BTreeMap<String, String>,
    pub neighbors: Vec<NeighborInfo>,
    pub lsdb: Vec<LsdbEntry>,
    /// Free-form extras for data that doesn't fit a typed slot. Prefer a
    /// typed field for anything downstream tools need to parse.
    pub extra: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct NeighborInfo {
    pub name: Name,
    /// FaceUri (e.g. `udp4://10.0.0.2:6363`); empty when the protocol
    /// binds by face id only.
    pub face_uri: String,
    /// Dijkstra (NLSR) / DV cost. `f64::NAN` when not tracked.
    pub link_cost: f64,
    pub state: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LsdbEntry {
    /// `adjacency`, `name`, or `coordinate`.
    pub lsa_type: String,
    pub originator: Name,
    pub sequence: u64,
    /// Pre-rendered body line(s) for the human-readable dump.
    pub summary: String,
}

impl RoutingProtocolStatus {
    pub fn empty(origin: u64) -> Self {
        Self {
            origin,
            ..Default::default()
        }
    }

    /// Render the status header (network / router / counters / fields).
    /// Used by the `*_STATUS` mgmt verbs.
    pub fn render_status(&self, label: &str) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(128);
        let _ = writeln!(s, "{label} status:");
        if let Some(n) = &self.network {
            let _ = writeln!(s, "  network={n}");
        }
        if let Some(r) = &self.router {
            let _ = writeln!(s, "  router={r}");
        }
        for (k, v) in &self.fields {
            let _ = writeln!(s, "  {k}={v}");
        }
        for (k, v) in &self.counters {
            let _ = writeln!(s, "  {k}={v}");
        }
        s
    }

    /// Render the per-neighbour list. Used by `verb::NLSR_NEIGHBORS`.
    pub fn render_neighbors(&self, label: &str) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(64);
        let _ = writeln!(s, "{label} neighbors: {} configured", self.neighbors.len());
        for n in &self.neighbors {
            let cost = if n.link_cost.is_nan() {
                String::from("-")
            } else {
                format!("{}", n.link_cost)
            };
            let state = n
                .state
                .as_deref()
                .map(|s| format!(" state={s}"))
                .unwrap_or_default();
            let _ = writeln!(
                s,
                "  name={} face_uri={} cost={cost}{state}",
                n.name, n.face_uri
            );
        }
        s
    }

    /// Render the LSDB. Used by `verb::NLSR_LSDB`.
    pub fn render_lsdb(&self, label: &str) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(64);
        let _ = writeln!(s, "{label} LSDB: {} entries", self.lsdb.len());
        for e in &self.lsdb {
            let _ = writeln!(s, "  {} {} seq={}", e.lsa_type, e.originator, e.sequence,);
            if !e.summary.is_empty() {
                for line in e.summary.lines() {
                    let _ = writeln!(s, "    {line}");
                }
            }
        }
        s
    }

    /// Render the runtime-config dump (used by `verb::DVR_CONFIG` GET).
    pub fn render_config(&self, label: &str) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(128);
        let _ = writeln!(s, "{label} runtime config:");
        if let Some(n) = &self.network {
            let _ = writeln!(s, "  network={n}");
        }
        if let Some(r) = &self.router {
            let _ = writeln!(s, "  router={r}");
        }
        for (k, v) in &self.fields {
            let _ = writeln!(s, "  {k}={v}");
        }
        for (k, v) in &self.counters {
            let _ = writeln!(s, "  {k}={v}");
        }
        s
    }
}

/// Typed input to [`RoutingProtocol::apply_config`]. The mgmt layer parses
/// the wire-level `key=value&key=value` URI into `fields` once.
#[derive(Debug, Clone, Default)]
pub struct ConfigUpdate {
    pub fields: BTreeMap<String, String>,
}

impl ConfigUpdate {
    /// Parse an NFD-style `key=value&key=value` string. Empty input is
    /// `Ok(empty)`; missing `=` returns `Err`.
    pub fn parse(params: &str) -> Result<Self, ConfigError> {
        let mut fields = BTreeMap::new();
        for pair in params.split('&').filter(|p| !p.is_empty()) {
            let Some((k, v)) = pair.split_once('=') else {
                return Err(ConfigError::Malformed(format!(
                    "missing `=` in key=value pair: {pair}"
                )));
            };
            fields.insert(k.to_owned(), v.to_owned());
        }
        Ok(Self { fields })
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ConfigError {
    #[error("this routing protocol has no runtime-mutable config")]
    NotSupported,
    #[error("malformed config update: {0}")]
    Malformed(String),
    #[error("unknown config key `{0}`")]
    UnknownKey(String),
    #[error("`{key}` value `{value}` rejected: {reason}")]
    BadValue {
        key: String,
        value: String,
        reason: String,
    },
}

/// A routing protocol that manages routes in the RIB. Each protocol
/// registers under a distinct `origin`; the RIB computes best nexthops
/// across all origins when building FIB entries.
pub trait RoutingProtocol: Send + Sync + 'static {
    /// Must be unique per instance. Standard values in
    /// `ndn_config::control_parameters::origin`.
    fn origin(&self) -> u64;

    /// Run until `cancel` is cancelled.
    fn start(&self, handle: RoutingHandle, cancel: CancellationToken) -> JoinHandle<()>;

    /// Operator-visible state. Default is an empty status with the origin.
    fn status(&self) -> RoutingProtocolStatus {
        RoutingProtocolStatus::empty(self.origin())
    }

    /// Apply a runtime-mutable config update atomically (all-or-nothing).
    /// Returns the number of fields applied. Default `Err(NotSupported)`.
    fn apply_config(&self, _update: &ConfigUpdate) -> Result<usize, ConfigError> {
        Err(ConfigError::NotSupported)
    }

    /// Downcast hook for protocol-specific mgmt verbs the trait can't
    /// unify. Implementations should be `fn as_any(&self) -> &dyn Any { self }`.
    fn as_any(&self) -> &dyn std::any::Any;
}

struct ProtocolHandle {
    cancel: CancellationToken,
    /// Awaited by `RoutingManager::disable` so any `Arc<…>` clones held by
    /// the protocol's task are released before the RIB flush runs.
    task: JoinHandle<()>,
    /// Reachable so mgmt verbs can call `status()` on the running protocol.
    proto: Arc<dyn RoutingProtocol>,
}

/// Manages a set of concurrently-running routing protocols.
pub struct RoutingManager {
    rib: Arc<Rib>,
    fib: Arc<Fib>,
    faces: Arc<FaceTable>,
    neighbors: Arc<NeighborTable>,
    handles: DashMap<u64, ProtocolHandle>,
    engine_cancel: CancellationToken,
}

impl RoutingManager {
    pub fn new(
        rib: Arc<Rib>,
        fib: Arc<Fib>,
        faces: Arc<FaceTable>,
        neighbors: Arc<NeighborTable>,
        engine_cancel: CancellationToken,
    ) -> Self {
        Self {
            rib,
            fib,
            faces,
            neighbors,
            handles: DashMap::new(),
            engine_cancel,
        }
    }

    pub async fn enable(&self, proto: Arc<dyn RoutingProtocol>) {
        let origin = proto.origin();
        if self.handles.contains_key(&origin) {
            self.stop_and_flush(origin).await;
        }
        let cancel = self.engine_cancel.child_token();
        let handle = RoutingHandle {
            rib: Arc::clone(&self.rib),
            fib: Arc::clone(&self.fib),
            faces: Arc::clone(&self.faces),
            neighbors: Arc::clone(&self.neighbors),
        };
        let task = proto.start(handle, cancel.clone());
        self.handles.insert(
            origin,
            ProtocolHandle {
                cancel,
                task,
                proto,
            },
        );
        tracing::info!(target: t::ENGINE, origin, "routing protocol enabled");
    }

    pub async fn disable(&self, origin: u64) -> bool {
        if self.handles.contains_key(&origin) {
            self.stop_and_flush(origin).await;
            tracing::info!(target: t::ENGINE, origin, "routing protocol disabled");
            true
        } else {
            false
        }
    }

    pub fn running_origins(&self) -> Vec<u64> {
        self.handles.iter().map(|e| *e.key()).collect()
    }

    pub fn running_count(&self) -> usize {
        self.handles.len()
    }

    /// Look up the running protocol for `origin`.
    pub fn protocol(&self, origin: u64) -> Option<Arc<dyn RoutingProtocol>> {
        self.handles.get(&origin).map(|h| Arc::clone(&h.proto))
    }

    /// Cancel the protocol's task and await its completion before flushing
    /// the RIB, ensuring any `Arc<…>` clones the task held are released
    /// before a subsequent `enable()` at the same origin runs.
    async fn stop_and_flush(&self, origin: u64) {
        if let Some((_, handle)) = self.handles.remove(&origin) {
            handle.cancel.cancel();
            // Cooperative cancel; discard a join error so the RIB flush
            // still runs after a panicked task.
            let _ = handle.task.await;
        }
        let affected = self.rib.flush_origin(origin);
        let n = affected.len();
        for prefix in &affected {
            self.rib.apply_to_fib(prefix, &self.fib);
        }
        if n > 0 {
            tracing::debug!(origin, prefixes = n, "RIB flushed for origin");
        }
    }
}

impl Drop for RoutingManager {
    /// Best-effort cancel; `Drop` cannot await, so tasks may briefly
    /// outlive the manager. For clean shutdown call
    /// `ShutdownHandle::shutdown().await`.
    fn drop(&mut self) {
        for entry in self.handles.iter() {
            entry.value().cancel.cancel();
        }
    }
}
