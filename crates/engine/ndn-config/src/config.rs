use crate::ConfigError;
use serde::{Deserialize, Serialize};

/// Top-level forwarder configuration (loaded from TOML).
///
/// Example `ndn-fwd.toml`:
///
/// ```toml
/// [engine]
/// cs_capacity_mb = 64
/// pipeline_channel_cap = 1024
///
/// [[face]]
/// kind = "udp"
/// bind = "0.0.0.0:6363"
///
/// [[face]]
/// kind = "multicast"
/// group = "224.0.23.170"
/// port = 56363
/// interface = "eth0"
///
/// [[route]]
/// prefix = "/ndn"
/// face = 0
/// cost = 10
///
/// [security]
/// trust_anchor = "/etc/ndn/trust-anchor.cert"
///
/// [[security.rule]]
/// data = "/sensor/<node>/<type>"
/// key  = "/sensor/<node>/KEY/<id>"
///
/// [logging]
/// level = "info"
/// file = "/var/log/ndn/router.log"
/// ```
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ForwarderConfig {
    #[serde(default)]
    pub engine: EngineConfig,

    #[serde(default, rename = "face")]
    pub faces: Vec<FaceConfig>,

    #[serde(default, rename = "route")]
    pub routes: Vec<RouteConfig>,

    #[serde(default)]
    pub management: ManagementConfig,

    #[serde(default)]
    pub security: SecurityConfig,

    #[serde(default)]
    pub cs: CsConfig,

    #[serde(default)]
    pub logging: LoggingConfig,

    #[serde(default)]
    pub discovery: DiscoveryTomlConfig,

    /// Face system auto-configuration — interface enumeration and hotplug.
    #[serde(default)]
    pub face_system: FaceSystemConfig,
}

impl std::str::FromStr for ForwarderConfig {
    type Err = ConfigError;

    /// Parse a `ForwarderConfig` from a TOML string.
    ///
    /// Expands `${VAR}` environment variable references in string values before
    /// deserializing. Unknown variables are replaced with an empty string and
    /// a `tracing::warn!` is emitted.
    fn from_str(s: &str) -> Result<Self, ConfigError> {
        let expanded = expand_env_vars(s);
        let cfg: ForwarderConfig = toml::from_str(&expanded)?;
        cfg.validate()?;
        Ok(cfg)
    }
}

impl ForwarderConfig {
    /// Load a `ForwarderConfig` from a TOML file.
    pub fn from_file(path: &std::path::Path) -> Result<Self, ConfigError> {
        let s = std::fs::read_to_string(path)?;
        s.parse()
    }

    /// Validate the parsed config for obvious errors.
    ///
    /// Called automatically from [`from_str`]. Returns [`ConfigError::Invalid`]
    /// describing the first problem found.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate face URIs and addresses.
        for face in &self.faces {
            validate_face_config(face)?;
        }

        // Validate route costs.
        for route in &self.routes {
            if route.prefix.is_empty() {
                return Err(ConfigError::Invalid(
                    "route prefix must not be empty".into(),
                ));
            }
        }

        // Validate CS capacity sanity (> 0 MB when not disabled).
        if self.engine.cs_capacity_mb > 65536 {
            return Err(ConfigError::Invalid(format!(
                "engine.cs_capacity_mb ({}) is unreasonably large (max 65536 MB)",
                self.engine.cs_capacity_mb
            )));
        }

        Ok(())
    }

    /// Serialize to a TOML string.
    pub fn to_toml_string(&self) -> Result<String, ConfigError> {
        toml::to_string_pretty(self).map_err(|e| ConfigError::Invalid(e.to_string()))
    }
}

/// Expand `${VAR}` environment variable references in a TOML string.
///
/// Each `${VAR}` is replaced with `std::env::var(VAR)`. If the variable is
/// not set, it is replaced with an empty string and a warning is logged.
fn expand_env_vars(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '$' && chars.peek() == Some(&'{') {
            chars.next(); // consume '{'
            let var_name: String = chars.by_ref().take_while(|&c| c != '}').collect();
            match std::env::var(&var_name) {
                Ok(val) => result.push_str(&val),
                Err(_) => {
                    // Unknown variable — replace with empty string and warn on stderr.
                    eprintln!(
                        "ndn-config: unknown env var ${{{var_name}}}, replacing with empty string"
                    );
                }
            }
        } else {
            result.push(ch);
        }
    }
    result
}

/// Validate a single `FaceConfig` for obviously invalid fields.
fn validate_face_config(face: &FaceConfig) -> Result<(), ConfigError> {
    match face {
        FaceConfig::Udp { bind, remote } | FaceConfig::Tcp { bind, remote } => {
            if let Some(addr) = bind {
                addr.parse::<std::net::SocketAddr>()
                    .map_err(|_| ConfigError::Invalid(format!("invalid bind address: {addr}")))?;
            }
            if let Some(addr) = remote {
                addr.parse::<std::net::SocketAddr>()
                    .map_err(|_| ConfigError::Invalid(format!("invalid remote address: {addr}")))?;
            }
        }
        FaceConfig::Multicast {
            group,
            port: _,
            interface: _,
        } => {
            let ip: std::net::IpAddr = group.parse().map_err(|_| {
                ConfigError::Invalid(format!("invalid multicast group address: {group}"))
            })?;
            if !ip.is_multicast() {
                return Err(ConfigError::Invalid(format!(
                    "multicast group address is not a multicast address: {group}"
                )));
            }
        }
        FaceConfig::WebSocket { bind, url } => {
            if let Some(addr) = bind {
                addr.parse::<std::net::SocketAddr>().map_err(|_| {
                    ConfigError::Invalid(format!("invalid WebSocket bind address: {addr}"))
                })?;
            }
            if let Some(u) = url
                && !u.starts_with("ws://")
                && !u.starts_with("wss://")
            {
                return Err(ConfigError::Invalid(format!(
                    "WebSocket URL must start with ws:// or wss://: {u}"
                )));
            }
        }
        FaceConfig::Serial { path, baud } => {
            if path.is_empty() {
                return Err(ConfigError::Invalid(
                    "serial face path must not be empty".into(),
                ));
            }
            if *baud == 0 {
                return Err(ConfigError::Invalid(
                    "serial face baud rate must be > 0".into(),
                ));
            }
        }
        FaceConfig::Unix { .. } | FaceConfig::EtherMulticast { .. } => {
            // No additional validation needed for these face types.
        }
    }
    Ok(())
}

/// Content store configuration.
///
/// ```toml
/// [cs]
/// variant = "lru"           # "lru" (default), "sharded-lru", "null"
/// capacity_mb = 64
/// shards = 4                # only for "sharded-lru"
/// admission_policy = "default"  # "default" or "admit-all"
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CsConfig {
    /// CS implementation variant.
    #[serde(default = "default_cs_variant")]
    pub variant: String,
    /// Capacity in megabytes (0 = disable).
    #[serde(default = "default_cs_capacity_mb")]
    pub capacity_mb: usize,
    /// Number of shards (only for "sharded-lru").
    #[serde(default)]
    pub shards: Option<usize>,
    /// Admission policy: "default" or "admit-all".
    #[serde(default = "default_admission_policy")]
    pub admission_policy: String,
}

fn default_cs_variant() -> String {
    "lru".to_string()
}
fn default_cs_capacity_mb() -> usize {
    64
}
fn default_admission_policy() -> String {
    "default".to_string()
}

impl Default for CsConfig {
    fn default() -> Self {
        Self {
            variant: default_cs_variant(),
            capacity_mb: default_cs_capacity_mb(),
            shards: None,
            admission_policy: default_admission_policy(),
        }
    }
}

/// Engine tuning parameters.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EngineConfig {
    /// Content store capacity in megabytes (0 = disable).
    /// Deprecated: use `[cs] capacity_mb` instead. Kept for backward compatibility.
    pub cs_capacity_mb: usize,
    /// Pipeline inter-task channel capacity (backpressure).
    pub pipeline_channel_cap: usize,
    /// Number of parallel pipeline processing threads.
    ///
    /// - `0` (default): auto-detect from available CPU parallelism.
    /// - `1`: single-threaded — all pipeline processing runs inline in the
    ///   pipeline runner task (lowest latency, no task spawn overhead).
    /// - `N`: spawn up to N concurrent tokio tasks per batch for pipeline
    ///   processing (highest throughput on multi-core systems).
    #[serde(default)]
    pub pipeline_threads: usize,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            cs_capacity_mb: 64,
            pipeline_channel_cap: 4096,
            pipeline_threads: 0,
        }
    }
}

/// Configuration for a single face.
///
/// Each variant carries only the fields relevant to that transport type,
/// making invalid combinations unrepresentable at parse time.
///
/// TOML syntax is unchanged — the `kind` field selects the variant:
///
/// ```toml
/// [[face]]
/// kind = "udp"
/// bind = "0.0.0.0:6363"
///
/// [[face]]
/// kind = "serial"
/// path = "/dev/ttyUSB0"
/// baud = 115200
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum FaceConfig {
    Udp {
        #[serde(default)]
        bind: Option<String>,
        #[serde(default)]
        remote: Option<String>,
    },
    Tcp {
        #[serde(default)]
        bind: Option<String>,
        #[serde(default)]
        remote: Option<String>,
    },
    Multicast {
        group: String,
        port: u16,
        #[serde(default)]
        interface: Option<String>,
    },
    Unix {
        #[serde(default)]
        path: Option<String>,
    },
    #[serde(rename = "web-socket")]
    WebSocket {
        #[serde(default)]
        bind: Option<String>,
        #[serde(default)]
        url: Option<String>,
    },
    Serial {
        path: String,
        #[serde(default = "default_baud")]
        baud: u32,
    },
    #[serde(rename = "ether-multicast")]
    EtherMulticast { interface: String },
}

fn default_baud() -> u32 {
    115200
}

/// Face system auto-configuration.
///
/// Controls automatic creation of multicast faces on startup and dynamic
/// interface monitoring.  When `auto_multicast` is enabled, the router
/// enumerates all eligible network interfaces at startup and creates one
/// multicast face per interface without requiring explicit `[[face]]` entries.
///
/// ```toml
/// [face_system.ether]
/// auto_multicast = true
/// whitelist = ["eth*", "enp*", "en*"]
/// blacklist = ["docker*", "virbr*", "lo"]
///
/// [face_system.udp]
/// auto_multicast = true
/// ad_hoc = false
/// whitelist = ["*"]
/// blacklist = ["lo"]
///
/// [face_system]
/// watch_interfaces = true  # Linux only; macOS/Windows: warning logged
/// ```
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct FaceSystemConfig {
    /// Ethernet (Layer-2) multicast face auto-configuration.
    #[serde(default)]
    pub ether: EtherFaceSystemConfig,
    /// UDP multicast face auto-configuration.
    #[serde(default)]
    pub udp: UdpFaceSystemConfig,
    /// Subscribe to OS interface add/remove events and automatically
    /// create or destroy multicast faces as interfaces appear and disappear.
    ///
    /// **Linux**: uses `RTMGRP_LINK` netlink.
    /// **macOS / Windows**: unsupported — logs a warning and ignored.
    #[serde(default)]
    pub watch_interfaces: bool,
}

/// Ethernet multicast face auto-configuration (`[face_system.ether]`).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EtherFaceSystemConfig {
    /// Create a `MulticastEtherFace` for every eligible interface at startup.
    ///
    /// An interface is eligible when it is UP, supports multicast, is not a
    /// loopback, and passes the `whitelist` / `blacklist` filters.
    #[serde(default)]
    pub auto_multicast: bool,
    /// Interface name glob patterns to include (default: `["*"]`).
    ///
    /// Supports `*` (any sequence) and `?` (one character).
    /// Examples: `"eth*"`, `"enp*"`, `"en0"`.
    #[serde(default = "default_iface_whitelist")]
    pub whitelist: Vec<String>,
    /// Interface name glob patterns to exclude (default: `["lo"]`).
    ///
    /// Applied after the whitelist.  Examples: `"docker*"`, `"virbr*"`.
    #[serde(default = "default_ether_iface_blacklist")]
    pub blacklist: Vec<String>,
}

impl Default for EtherFaceSystemConfig {
    fn default() -> Self {
        Self {
            auto_multicast: false,
            whitelist: default_iface_whitelist(),
            blacklist: default_ether_iface_blacklist(),
        }
    }
}

/// UDP multicast face auto-configuration (`[face_system.udp]`).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UdpFaceSystemConfig {
    /// Create a `MulticastUdpFace` for every eligible interface at startup.
    #[serde(default)]
    pub auto_multicast: bool,
    /// Advertise faces as `AdHoc` link type instead of `MultiAccess`.
    ///
    /// Set to `true` for Wi-Fi IBSS (ad-hoc) or MANET deployments where not
    /// all nodes hear every multicast frame.  Strategies use this to disable
    /// multi-access Interest suppression on partially-connected links.
    #[serde(default)]
    pub ad_hoc: bool,
    /// Interface name glob patterns to include (default: `["*"]`).
    #[serde(default = "default_iface_whitelist")]
    pub whitelist: Vec<String>,
    /// Interface name glob patterns to exclude (default: `["lo"]`).
    #[serde(default = "default_udp_iface_blacklist")]
    pub blacklist: Vec<String>,
}

impl Default for UdpFaceSystemConfig {
    fn default() -> Self {
        Self {
            auto_multicast: false,
            ad_hoc: false,
            whitelist: default_iface_whitelist(),
            blacklist: default_udp_iface_blacklist(),
        }
    }
}

fn default_iface_whitelist() -> Vec<String> {
    vec!["*".to_owned()]
}

fn default_ether_iface_blacklist() -> Vec<String> {
    vec![
        "lo".to_owned(),
        "lo0".to_owned(),
        "docker*".to_owned(),
        "virbr*".to_owned(),
    ]
}

fn default_udp_iface_blacklist() -> Vec<String> {
    vec!["lo".to_owned(), "lo0".to_owned()]
}

/// Re-export the canonical `FaceKind` from `ndn-transport` — single source of
/// truth for all face type classification.  Serde support is enabled via the
/// `serde` feature on `ndn-transport`.
pub use ndn_transport::FaceKind;

/// A static FIB route entry.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RouteConfig {
    /// NDN name prefix (e.g., `"/ndn"`).
    pub prefix: String,
    /// Zero-based face index (matches order in `faces`).
    pub face: usize,
    /// Routing cost (lower is preferred).
    #[serde(default = "default_cost")]
    pub cost: u32,
}

fn default_cost() -> u32 {
    10
}

/// Management interface configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ManagementConfig {
    /// Unix domain socket (or Named Pipe on Windows) that accepts NDN face
    /// connections from apps and tools.
    ///
    /// `ndn-ctl` and application processes connect here to exchange NDN packets
    /// with the forwarder.
    ///
    /// Default (Unix): `/run/nfd/nfd.sock`
    /// Default (Windows): `\\.\pipe\ndn`
    #[serde(default = "default_face_socket")]
    pub face_socket: String,
}

impl Default for ManagementConfig {
    fn default() -> Self {
        Self {
            face_socket: default_face_socket(),
        }
    }
}

fn default_face_socket() -> String {
    #[cfg(unix)]
    return "/run/nfd/nfd.sock".to_owned();
    #[cfg(windows)]
    return r"\\.\pipe\ndn".to_owned();
}

/// A single trust schema rule in the router configuration.
///
/// Rules are specified as `[[security.rule]]` entries in the TOML config:
///
/// ```toml
/// [[security.rule]]
/// data  = "/sensor/<node>/<type>"
/// key   = "/sensor/<node>/KEY/<id>"
///
/// [[security.rule]]
/// data  = "/admin/<**rest>"
/// key   = "/admin/KEY/<id>"
/// ```
///
/// Each rule consists of a data name pattern and a key name pattern. Variables
/// (e.g. `<node>`) captured in the data pattern must bind the same component
/// value in the key pattern — this prevents cross-identity signing.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct TrustRuleConfig {
    /// Data name pattern, e.g. `/sensor/<node>/<type>`.
    pub data: String,
    /// Key name pattern, e.g. `/sensor/<node>/KEY/<id>`.
    pub key: String,
}

/// Security settings.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SecurityConfig {
    /// NDN identity name for this router (e.g., `/ndn/router1`).
    ///
    /// The corresponding key and certificate must exist in the PIB
    /// (unless `auto_init` is enabled).
    #[serde(default)]
    pub identity: Option<String>,

    /// Path to the PIB directory (default: `~/.ndn/pib`).
    ///
    /// Create with `ndn-ctl security init` or enable `auto_init`.
    #[serde(default)]
    pub pib_path: Option<String>,

    /// Path to a trust-anchor certificate file to load at startup.
    ///
    /// Takes precedence over anchors already stored in the PIB.
    #[serde(default)]
    pub trust_anchor: Option<String>,

    /// Whether to require all Data packets to be signed and verified.
    #[serde(default)]
    pub require_signed: bool,

    /// Automatically generate an identity and self-signed certificate
    /// on first startup if no keys exist in the PIB.
    ///
    /// Requires `identity` to be set. Default: `false`.
    #[serde(default)]
    pub auto_init: bool,

    /// Security profile: `"default"`, `"accept-signed"`, or `"disabled"`.
    ///
    /// - `"default"` — full chain validation with hierarchical trust schema
    /// - `"accept-signed"` — verify signatures but skip chain walking
    /// - `"disabled"` — no validation (benchmarking/lab only)
    ///
    /// Default: `"default"`.
    #[serde(default = "default_security_profile")]
    pub profile: String,

    // ── NDNCERT CA (optional) ─────────────────────────────────────────────────
    /// NDN name prefix for the built-in NDNCERT CA, e.g. `/ndn/edu/example/CA`.
    ///
    /// When set, the router registers handlers under `<ca_prefix>/CA/INFO`,
    /// `<ca_prefix>/CA/PROBE`, `<ca_prefix>/CA/NEW`, and `<ca_prefix>/CA/CHALLENGE`.
    ///
    /// Leave unset to run in client-only mode (no CA hosted).
    #[serde(default)]
    pub ca_prefix: Option<String>,

    /// Human-readable description of this CA, returned in CA INFO responses.
    ///
    /// Example: `"NDN Test Network CA"`.
    #[serde(default)]
    pub ca_info: String,

    /// Maximum certificate lifetime (days) the CA will issue.
    ///
    /// Requests for longer validity are silently capped to this value.
    /// Default: `365`.
    #[serde(default = "default_ca_max_validity_days")]
    pub ca_max_validity_days: u32,

    /// Supported NDNCERT challenge types offered by the CA.
    ///
    /// Recognised values: `"token"`, `"pin"`, `"possession"`, `"email"`,
    /// `"yubikey-hotp"`.  Default: `["token"]`.
    #[serde(default = "default_ca_challenges")]
    pub ca_challenges: Vec<String>,

    /// Static trust schema rules loaded at startup.
    ///
    /// These are added to the active validator's schema on startup in
    /// addition to the rules implied by the `profile` setting.
    ///
    /// When `profile = "default"` the hierarchical rule is pre-loaded; additional
    /// `[[security.rule]]` entries extend it. When `profile = "accept-signed"` the
    /// accept-all rule is pre-loaded; additional rules are appended. When
    /// `profile = "disabled"` this field is ignored.
    ///
    /// Rules can also be added or removed at runtime via the management API:
    /// `/localhost/nfd/security/schema-rule-add` and `schema-rule-remove`.
    #[serde(default, rename = "rule")]
    pub rules: Vec<TrustRuleConfig>,

    // ── PIB backing store ─────────────────────────────────────────────────────
    /// Key backing store type.
    ///
    /// - `"file"` — file-based PIB at `pib_path` (default, persisted across restarts)
    /// - `"memory"` — ephemeral in-memory store; keys are lost on restart
    ///
    /// When `identity` is set and the PIB cannot be opened, the router falls
    /// back to an ephemeral identity and logs a warning (or shows an interactive
    /// recovery prompt when running in a terminal).
    ///
    /// Default: `"file"`.
    #[serde(default = "default_pib_type")]
    pub pib_type: String,

    /// NDN name prefix for the auto-generated ephemeral identity.
    ///
    /// When no `identity` is configured (or the PIB fails), an in-memory key is
    /// generated under `<ephemeral_prefix>/<hostname>`.  If not set, the router
    /// derives the name from the system hostname (e.g. `/ndn-fwd/router-host`).
    ///
    /// Set this to enforce a deterministic name for ephemeral identities, e.g.
    /// in test environments where the hostname varies.
    #[serde(default)]
    pub ephemeral_prefix: Option<String>,
}

fn default_pib_type() -> String {
    "file".to_owned()
}

fn default_security_profile() -> String {
    // Match NFD's default: forwarder does not validate Data at the network layer.
    // Validation is a consumer-side concern in NDN; enable "default" or "accept-signed"
    // explicitly if you want the forwarder to enforce signatures.
    "disabled".to_owned()
}

fn default_ca_max_validity_days() -> u32 {
    365
}

fn default_ca_challenges() -> Vec<String> {
    vec!["token".to_owned()]
}

/// Logging configuration.
///
/// ```toml
/// [logging]
/// level = "info"                          # default tracing filter
/// file = "/var/log/ndn/router.log"        # optional log file
/// ```
///
/// **Precedence** (highest to lowest):
/// 1. `RUST_LOG` environment variable
/// 2. `--log-level` CLI flag
/// 3. `level` field in this section
///
/// When `file` is set, logs are written to *both* stderr and the file so
/// interactive use always shows output while the file captures a persistent
/// record.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    /// Default tracing filter string (e.g. `"info"`, `"ndn_engine=debug,warn"`).
    ///
    /// Overridden by `--log-level` CLI flag or `RUST_LOG` env var.
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Optional file path for persistent log output.
    ///
    /// Parent directories are created automatically. When set, logs are
    /// written to both stderr and this file.
    #[serde(default)]
    pub file: Option<String>,
}

fn default_log_level() -> String {
    "info".to_owned()
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            file: None,
        }
    }
}

// ─── Discovery TOML config ────────────────────────────────────────────────────

/// `[discovery]` section — neighbor and service discovery configuration.
///
/// Discovery is disabled unless `node_name` is set.
///
/// ```toml
/// [discovery]
/// profile = "lan"
/// node_name = "/ndn/site/myrouter"
/// served_prefixes = ["/ndn/site/sensors"]
/// # optional per-field overrides:
/// hello_interval_base_ms = 5000
/// hello_interval_max_ms  = 60000
/// liveness_miss_count    = 3
/// gossip_fanout          = 3
/// relay_records          = false
/// auto_fib_cost          = 100
/// auto_fib_ttl_multiplier = 2.0
/// ```
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct DiscoveryTomlConfig {
    /// Deployment profile name: `static`, `lan`, `campus`, `mobile`,
    /// `high-mobility`, or `asymmetric`.  Defaults to `lan`.
    #[serde(default)]
    pub profile: Option<String>,

    /// This node's NDN name.  **Required** to enable discovery.
    ///
    /// If the value ends with `/`, the system hostname is appended
    /// automatically (e.g. `"/ndn/site/"` → `"/ndn/site/router1"`).
    #[serde(default)]
    pub node_name: Option<String>,

    /// Prefixes published as service records at startup via
    /// `ServiceDiscoveryProtocol::publish()`.
    #[serde(default)]
    pub served_prefixes: Vec<String>,

    // ── Per-field overrides (supplement the profile defaults) ─────────────
    /// Override `hello_interval_base` in milliseconds.
    #[serde(default)]
    pub hello_interval_base_ms: Option<u64>,

    /// Override `hello_interval_max` in milliseconds.
    #[serde(default)]
    pub hello_interval_max_ms: Option<u64>,

    /// Override `liveness_miss_count`.
    #[serde(default)]
    pub liveness_miss_count: Option<u32>,

    /// Override SWIM indirect-probe fanout K.
    #[serde(default)]
    pub swim_indirect_fanout: Option<u32>,

    /// Override gossip broadcast fanout.
    #[serde(default)]
    pub gossip_fanout: Option<u32>,

    /// Override `relay_records` in `ServiceDiscoveryConfig`.
    #[serde(default)]
    pub relay_records: Option<bool>,

    /// Override auto-FIB route cost.
    #[serde(default)]
    pub auto_fib_cost: Option<u32>,

    /// Override auto-FIB TTL multiplier.
    #[serde(default)]
    pub auto_fib_ttl_multiplier: Option<f32>,

    /// Optional PIB (public information base) path for persistent key storage.
    /// Defaults to `~/.ndn/pib.db`.
    #[serde(default)]
    pub pib_path: Option<String>,

    /// Key name for signing hello packets.  If absent, a deterministic
    /// ephemeral Ed25519 key is auto-generated from the node name.
    #[serde(default)]
    pub key_name: Option<String>,

    /// Which link-layer transports to run discovery on.
    ///
    /// Accepted values:
    /// - `"udp"` (default): UDP multicast only (`224.0.23.170:6363`).
    /// - `"ether"`: raw Ethernet multicast only (EtherType 0x8624).
    /// - `"both"`: UDP and Ethernet simultaneously.
    ///
    /// Ethernet discovery requires `CAP_NET_RAW` / root on Linux, or root on
    /// macOS (PF_NDRV).  The `ether` and `both` options also require at least
    /// one `[[face]]` entry with `kind = "ether-multicast"` (providing the
    /// `FaceId` and interface name).
    #[serde(default)]
    pub discovery_transport: Option<String>,

    /// Network interface name for Ethernet discovery (e.g. `"eth0"`, `"en0"`).
    ///
    /// Required when `discovery_transport` is `"ether"` or `"both"`.
    #[serde(default)]
    pub ether_iface: Option<String>,
}

impl DiscoveryTomlConfig {
    /// Returns `true` if discovery is enabled (i.e. `node_name` is set).
    pub fn enabled(&self) -> bool {
        self.node_name.is_some()
    }

    /// Resolve the effective node name, appending the system hostname if
    /// `node_name` ends with `/`.
    pub fn resolved_node_name(&self) -> Option<String> {
        let raw = self.node_name.as_deref()?;
        if raw.ends_with('/') {
            let host = Self::hostname();
            Some(format!("{}{}", raw.trim_end_matches('/'), host))
        } else {
            Some(raw.to_owned())
        }
    }

    fn hostname() -> String {
        std::env::var("HOSTNAME").unwrap_or_else(|_| {
            // Fallback: read from /etc/hostname or use "localhost".
            std::fs::read_to_string("/etc/hostname")
                .map(|s| s.trim().to_owned())
                .unwrap_or_else(|_| "localhost".to_owned())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    const SAMPLE_TOML: &str = r#"
[engine]
cs_capacity_mb = 32
pipeline_channel_cap = 512

[[face]]
kind = "udp"
bind = "0.0.0.0:6363"

[[face]]
kind = "multicast"
group = "224.0.23.170"
port = 56363
interface = "eth0"

[[route]]
prefix = "/ndn"
face = 0
cost = 10

[[route]]
prefix = "/local"
face = 1

[security]
trust_anchor = "/etc/ndn/ta.cert"
require_signed = true

[[security.rule]]
data = "/sensor/<node>/<type>"
key  = "/sensor/<node>/KEY/<id>"

[logging]
level = "debug"
file = "/var/log/ndn/router.log"
"#;

    #[test]
    fn parse_sample_config() {
        let cfg = ForwarderConfig::from_str(SAMPLE_TOML).unwrap();
        assert_eq!(cfg.engine.cs_capacity_mb, 32);
        assert_eq!(cfg.engine.pipeline_channel_cap, 512);
        assert_eq!(cfg.faces.len(), 2);
        assert!(matches!(cfg.faces[0], FaceConfig::Udp { .. }));
        assert!(matches!(cfg.faces[1], FaceConfig::Multicast { .. }));
        assert_eq!(cfg.routes.len(), 2);
        assert_eq!(cfg.routes[0].prefix, "/ndn");
        assert_eq!(cfg.routes[0].cost, 10);
        assert_eq!(cfg.routes[1].prefix, "/local");
        assert_eq!(cfg.routes[1].cost, 10); // default
        assert!(cfg.security.trust_anchor.is_some());
        assert!(cfg.security.require_signed);
        assert_eq!(cfg.security.rules.len(), 1);
        assert_eq!(cfg.security.rules[0].data, "/sensor/<node>/<type>");
        assert_eq!(cfg.security.rules[0].key, "/sensor/<node>/KEY/<id>");
        assert_eq!(cfg.logging.level, "debug");
        assert_eq!(cfg.logging.file.as_deref(), Some("/var/log/ndn/router.log"));
    }

    #[test]
    fn default_config_is_valid() {
        let cfg = ForwarderConfig::default();
        assert_eq!(cfg.engine.cs_capacity_mb, 64);
        assert!(cfg.faces.is_empty());
        assert!(cfg.routes.is_empty());
    }

    #[test]
    fn roundtrip_serialize_deserialize() {
        let cfg = ForwarderConfig::from_str(SAMPLE_TOML).unwrap();
        let toml_str = cfg.to_toml_string().unwrap();
        let cfg2 = ForwarderConfig::from_str(&toml_str).unwrap();
        assert_eq!(cfg2.engine.cs_capacity_mb, 32);
        assert_eq!(cfg2.faces.len(), 2);
    }

    #[test]
    fn empty_string_gives_defaults() {
        let cfg = ForwarderConfig::from_str("").unwrap();
        assert_eq!(cfg.engine.cs_capacity_mb, 64);
        assert!(cfg.faces.is_empty());
        assert_eq!(cfg.logging.level, "info");
        assert!(cfg.logging.file.is_none());
    }

    #[test]
    fn invalid_toml_returns_error() {
        let result = ForwarderConfig::from_str("[[[invalid");
        assert!(result.is_err());
    }

    #[test]
    fn route_default_cost() {
        let toml = "[[route]]\nprefix = \"/x\"\nface = 0\n";
        let cfg = ForwarderConfig::from_str(toml).unwrap();
        assert_eq!(cfg.routes[0].cost, 10);
    }

    #[test]
    fn example_file_parses() {
        let s = include_str!("../../../../ndn-fwd.example.toml");
        ForwarderConfig::from_str(s).expect("example config should parse");
    }
}
