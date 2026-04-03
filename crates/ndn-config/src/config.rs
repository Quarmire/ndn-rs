use crate::ConfigError;
use serde::{Deserialize, Serialize};

/// Top-level forwarder configuration (loaded from TOML).
///
/// Example `ndn-router.toml`:
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
/// key_dir = "/etc/ndn/keys"
/// ```
#[derive(Debug, Default, Deserialize, Serialize)]
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
}

impl ForwarderConfig {
    /// Parse a `ForwarderConfig` from a TOML string.
    pub fn from_str(s: &str) -> Result<Self, ConfigError> {
        Ok(toml::from_str(s)?)
    }

    /// Load a `ForwarderConfig` from a TOML file.
    pub fn from_file(path: &std::path::Path) -> Result<Self, ConfigError> {
        let s = std::fs::read_to_string(path)?;
        Self::from_str(&s)
    }

    /// Serialize to a TOML string.
    pub fn to_toml_string(&self) -> Result<String, ConfigError> {
        toml::to_string_pretty(self).map_err(|e| ConfigError::Invalid(e.to_string()))
    }
}

/// Engine tuning parameters.
#[derive(Debug, Deserialize, Serialize)]
pub struct EngineConfig {
    /// Content store capacity in megabytes (0 = disable).
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
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FaceConfig {
    /// Transport kind: `"udp"`, `"tcp"`, `"multicast"`, `"unix"`.
    pub kind: FaceKind,

    /// Local bind address (e.g., `"0.0.0.0:6363"`) for UDP/TCP faces.
    #[serde(default)]
    pub bind: Option<String>,

    /// Remote peer address for unicast UDP/TCP faces.
    #[serde(default)]
    pub remote: Option<String>,

    /// Multicast group address.
    #[serde(default)]
    pub group: Option<String>,

    /// Multicast port.
    #[serde(default)]
    pub port: Option<u16>,

    /// Network interface name for multicast faces.
    #[serde(default)]
    pub interface: Option<String>,

    /// Unix socket path for local faces, or serial port path (e.g., `/dev/ttyUSB0`).
    #[serde(default)]
    pub path: Option<String>,

    /// Serial baud rate (only for `kind = "serial"`).
    #[serde(default)]
    pub baud: Option<u32>,

    /// WebSocket URL for client-mode connections (e.g., `ws://host:9696/ndn`).
    /// For server-mode, use `bind` instead.
    #[serde(default)]
    pub url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FaceKind {
    Udp,
    Tcp,
    Multicast,
    Unix,
    WebSocket,
    EtherMulticast,
    Serial,
}

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
#[derive(Debug, Deserialize, Serialize)]
pub struct ManagementConfig {
    /// Transport for the management interface.
    ///
    /// - `"ndn"` (default): NDN Interest/Data packets over the face socket.
    ///   Inherits NDN security and routing.  `ndn-ctl` connects via `UnixFace`.
    /// - `"bypass"`: raw JSON over a Unix socket (or iceoryx2 if the
    ///   `iceoryx2-mgmt` feature is enabled).  Useful when the forwarding
    ///   pipeline is unreachable.
    #[serde(default = "default_mgmt_transport")]
    pub transport: String,

    /// Unix socket path for the **bypass** JSON management interface.
    ///
    /// Only used when `transport = "bypass"`.
    /// Default: `/tmp/ndn-router.sock`.
    #[serde(default = "default_bypass_socket")]
    pub bypass_socket: String,

    /// Unix socket path that accepts **NDN face connections** from apps and tools.
    ///
    /// `ndn-ctl` and application processes connect here to exchange NDN packets
    /// with the forwarder.  Only used when `transport = "ndn"`.
    /// Default: `/tmp/ndn-faces.sock`.
    #[serde(default = "default_face_socket")]
    pub face_socket: String,
}

impl Default for ManagementConfig {
    fn default() -> Self {
        Self {
            transport: default_mgmt_transport(),
            bypass_socket: default_bypass_socket(),
            face_socket: default_face_socket(),
        }
    }
}

fn default_mgmt_transport() -> String {
    "ndn".to_owned()
}
fn default_bypass_socket() -> String {
    "/tmp/ndn-router.sock".to_owned()
}
fn default_face_socket() -> String {
    "/tmp/ndn-faces.sock".to_owned()
}

/// Security settings.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct SecurityConfig {
    /// NDN identity name for this router (e.g., `/ndn/router1`).
    ///
    /// The corresponding key and certificate must exist in the PIB.
    #[serde(default)]
    pub identity: Option<String>,

    /// Path to the PIB directory (default: `~/.ndn/pib`).
    ///
    /// Create with `ndn-sec keygen <identity>`.
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
"#;

    #[test]
    fn parse_sample_config() {
        let cfg = ForwarderConfig::from_str(SAMPLE_TOML).unwrap();
        assert_eq!(cfg.engine.cs_capacity_mb, 32);
        assert_eq!(cfg.engine.pipeline_channel_cap, 512);
        assert_eq!(cfg.faces.len(), 2);
        assert_eq!(cfg.faces[0].kind, FaceKind::Udp);
        assert_eq!(cfg.faces[1].kind, FaceKind::Multicast);
        assert_eq!(cfg.routes.len(), 2);
        assert_eq!(cfg.routes[0].prefix, "/ndn");
        assert_eq!(cfg.routes[0].cost, 10);
        assert_eq!(cfg.routes[1].prefix, "/local");
        assert_eq!(cfg.routes[1].cost, 10); // default
        assert!(cfg.security.trust_anchor.is_some());
        assert!(cfg.security.require_signed);
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
}
