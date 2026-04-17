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

    pub fn validate(&self) -> Result<(), ConfigError> {
        for face in &self.faces {
            validate_face_config(face)?;
        }

        for route in &self.routes {
            if route.prefix.is_empty() {
                return Err(ConfigError::Invalid(
                    "route prefix must not be empty".into(),
                ));
            }
        }

        if self.engine.cs_capacity_mb > 65536 {
            return Err(ConfigError::Invalid(format!(
                "engine.cs_capacity_mb ({}) is unreasonably large (max 65536 MB)",
                self.engine.cs_capacity_mb
            )));
        }

        Ok(())
    }

    pub fn to_toml_string(&self) -> Result<String, ConfigError> {
        toml::to_string_pretty(self).map_err(|e| ConfigError::Invalid(e.to_string()))
    }
}

/// Expand `${VAR}` environment variable references in a TOML string.
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
        FaceConfig::Unix { .. } | FaceConfig::EtherMulticast { .. } => {}
    }
    Ok(())
}

/// Content store configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CsConfig {
    #[serde(default = "default_cs_variant")]
    pub variant: String,
    #[serde(default = "default_cs_capacity_mb")]
    pub capacity_mb: usize,
    /// Only for "sharded-lru".
    #[serde(default)]
    pub shards: Option<usize>,
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
    /// Deprecated: use `[cs] capacity_mb` instead.
    pub cs_capacity_mb: usize,
    pub pipeline_channel_cap: usize,
    /// 0 = auto-detect, 1 = single-threaded inline, N = parallel tasks.
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

/// Configuration for a single face. The `kind` tag selects the variant.
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

pub use ndn_transport::FaceKind;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RouteConfig {
    pub prefix: String,
    /// Zero-based face index (matches order in `faces`).
    pub face: usize,
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

    /// NDN name prefix for the built-in NDNCERT CA. Unset = client-only mode.
    #[serde(default)]
    pub ca_prefix: Option<String>,

    #[serde(default)]
    pub ca_info: String,

    #[serde(default = "default_ca_max_validity_days")]
    pub ca_max_validity_days: u32,

    /// Recognised: `"token"`, `"pin"`, `"possession"`, `"email"`, `"yubikey-hotp"`.
    #[serde(default = "default_ca_challenges")]
    pub ca_challenges: Vec<String>,

    /// Trust schema rules loaded at startup (extend the profile's defaults).
    #[serde(default, rename = "rule")]
    pub rules: Vec<TrustRuleConfig>,

    /// `"file"` (default, persistent) or `"memory"` (ephemeral).
    #[serde(default = "default_pib_type")]
    pub pib_type: String,

    /// Prefix for auto-generated ephemeral identity (defaults to hostname).
    #[serde(default)]
    pub ephemeral_prefix: Option<String>,
}

fn default_pib_type() -> String {
    "file".to_owned()
}

fn default_security_profile() -> String {
    // Matches NFD: validation is a consumer-side concern in NDN.
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

/// `[discovery]` section. Discovery is disabled unless `node_name` is set.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct DiscoveryTomlConfig {
    #[serde(default)]
    pub profile: Option<String>,

    /// Required to enable discovery. Trailing `/` appends hostname automatically.
    #[serde(default)]
    pub node_name: Option<String>,

    #[serde(default)]
    pub served_prefixes: Vec<String>,

    #[serde(default)]
    pub hello_interval_base_ms: Option<u64>,
    #[serde(default)]
    pub hello_interval_max_ms: Option<u64>,
    #[serde(default)]
    pub liveness_miss_count: Option<u32>,
    #[serde(default)]
    pub swim_indirect_fanout: Option<u32>,
    #[serde(default)]
    pub gossip_fanout: Option<u32>,
    #[serde(default)]
    pub relay_records: Option<bool>,
    #[serde(default)]
    pub auto_fib_cost: Option<u32>,
    #[serde(default)]
    pub auto_fib_ttl_multiplier: Option<f32>,
    #[serde(default)]
    pub pib_path: Option<String>,

    /// If absent, an ephemeral Ed25519 key is auto-generated from node name.
    #[serde(default)]
    pub key_name: Option<String>,

    /// `"udp"` (default), `"ether"`, or `"both"`. Ethernet requires CAP_NET_RAW.
    #[serde(default)]
    pub discovery_transport: Option<String>,

    /// Required when `discovery_transport` is `"ether"` or `"both"`.
    #[serde(default)]
    pub ether_iface: Option<String>,
}

impl DiscoveryTomlConfig {
    pub fn enabled(&self) -> bool {
        self.node_name.is_some()
    }

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
