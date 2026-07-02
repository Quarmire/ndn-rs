use crate::ConfigError;
use ndn_mgmt_wire::parse_cert_sha256_hex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Top-level forwarder configuration loaded from TOML. See
/// `examples/ndn-fwd.example.toml` for a fully-populated sample.
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

    /// Interface enumeration and hotplug for multicast faces.
    #[serde(default)]
    pub face_system: FaceSystemConfig,

    #[serde(default)]
    pub routing: RoutingTomlConfig,

    /// TLS-bearing listeners (WebTransport, WS-TLS) that accept many
    /// connections each — distinct from one-face-per-entry `[[face]]`.
    #[serde(default)]
    pub listeners: ListenersConfig,

    /// Opt-in in-process NDNCERT CA. Production deployments run a real
    /// CA out-of-process and configure
    /// `[security.mgmt] localhop_trust_anchor_pib` against its PIB.
    #[serde(default)]
    pub demo_ca: DemoCaConfig,

    /// NDN-native span publisher. Spans served under `ndn_prefix` as
    /// OTLP `Span` protobufs (OTLP wire format inside Data content).
    #[serde(default)]
    pub observability: ObservabilityTomlConfig,

    /// Reflexive-forwarding boot defaults; runtime-mutable via the
    /// `/localhost/nfd/reflexive` management module.
    #[serde(default)]
    pub reflexive: ReflexiveTomlConfig,

    /// CCLF (content-aware forwarding) boot config. CCLF is selected per-prefix
    /// via strategy-choice like any other strategy (requires the `cclf` build
    /// feature); this section only sets the network-layer **presence** this
    /// node advertises so neighbors count it for density (A-LAL).
    #[serde(default)]
    pub cclf: CclfTomlConfig,

    /// Generic config for EXTENSION subsystems that live outside the core
    /// schema (their own crates/repos). Each `[extensions.<name>]` table is
    /// handed to that extension verbatim; it deserializes its own slice via
    /// [`Self::extension`]. Keeps ndn-config a CLOSED core schema — it never
    /// needs to know a split-out subsystem's config shape.
    #[serde(default)]
    pub extensions: BTreeMap<String, toml::Value>,
}

/// CCLF presence configuration. See [`ForwarderConfig::cclf`].
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct CclfTomlConfig {
    /// NDN name this node advertises as its A-LAL presence — its network-layer
    /// neighbor identity (NOT a MAC/host address). Unset → this node observes
    /// neighbors but does not advertise itself, so peers won't count it.
    #[serde(default)]
    pub presence_name: Option<String>,
}

/// Opt-in span publisher; defaults are conservative (no publishing,
/// 1% head sampling, no peer propagation).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ObservabilityTomlConfig {
    #[serde(default)]
    pub publish_to_ndn: bool,

    /// Default `/localhost/nfd/observability`. Cross-router access
    /// requires explicit prefix announcement.
    #[serde(default = "default_observability_prefix")]
    pub ndn_prefix: String,

    /// Humantime duration (`"30m"`, `"1h"`); empty = publisher default.
    #[serde(default)]
    pub retention: String,

    /// 0 = use publisher default (8 MiB).
    #[serde(default)]
    pub max_bytes: u64,

    /// 0 = use publisher default (10_000).
    #[serde(default)]
    pub max_spans: usize,

    /// Head sampling ratio 0.0..1.0 (default 0.01).
    #[serde(default = "default_observability_sample")]
    pub sample: f64,

    /// Attach LP `TraceContext` to outbound packets. Privacy-bearing:
    /// trace IDs reveal usage patterns.
    #[serde(default)]
    pub propagate_to_peers: bool,

    /// Read by an out-of-process `ndn-otel-bridge` that pushes spans
    /// from the NDN substrate to this OTLP/gRPC endpoint.
    #[serde(default)]
    pub otlp_bridge_url: String,
}

impl Default for ObservabilityTomlConfig {
    fn default() -> Self {
        Self {
            publish_to_ndn: false,
            ndn_prefix: default_observability_prefix(),
            retention: String::new(),
            max_bytes: 0,
            max_spans: 0,
            sample: default_observability_sample(),
            propagate_to_peers: false,
            otlp_bridge_url: String::new(),
        }
    }
}

fn default_observability_prefix() -> String {
    "/localhost/nfd/observability".to_string()
}

fn default_observability_sample() -> f64 {
    0.01
}

/// Embedded NDNCERT CA for demo deployments. Mints a self-signed CA
/// cert and serves `/<prefix>/CA/{INFO,NEW,CHALLENGE/<id>}`. Only safe
/// behind a trusted local face.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DemoCaConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "DemoCaConfig::default_prefix")]
    pub prefix: String,
    /// CA's self-signed identity name; typically equals `prefix`.
    #[serde(default = "DemoCaConfig::default_identity")]
    pub identity: String,
    /// Pre-provisioned one-time invite tokens; non-empty switches the
    /// CA from `NopChallenge` (auto-approve) to `TokenChallenge`.
    /// Legacy shortcut; ignored when `challenge` is non-empty.
    #[serde(default)]
    pub tokens: Vec<String>,
    /// Explicit challenge set. When non-empty it overrides the
    /// `tokens`-driven nop/token selection — the CA offers exactly these
    /// challenges. Serialized as `[[demo_ca.challenge]]` array-of-tables.
    #[serde(default, rename = "challenge")]
    pub challenges: Vec<ChallengeConfig>,
    /// Embed a challenge attestation (how the challenge was satisfied) in each
    /// issued cert's `AdditionalDescription`.
    #[serde(default)]
    pub emit_attestations: bool,
    /// Optional post-challenge issuance gate: under `prefix`, require the
    /// satisfied challenge's attestation to carry a leaf of `kind` (and, if
    /// `require_signed`, an independently-signed one). Maps to
    /// `ndn_cert::RequireAttestationKind`. Plain data here; the policy object
    /// is constructed by the CA wiring (`ndn-config` stays free of `ndn-cert`).
    #[serde(default)]
    pub require_attestation: Option<RequireAttestationConfig>,
}

/// One NDNCERT challenge the CA offers. Flat (`kind` + per-kind fields) for
/// TOML friendliness; the CA wiring matches on `kind`. Recognised kinds:
/// `nop`, `token`, `pin`, `email`. (`possession`/`yubikey`/`device-approval`
/// need certs / secrets / the approve-feed, so they're wired in code.)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChallengeConfig {
    /// `nop` | `token` | `pin` | `email`.
    pub kind: String,
    /// `token`: one-time invite tokens.
    #[serde(default)]
    pub tokens: Vec<String>,
    /// `pin`: the shared PIN (hashed by the handler).
    #[serde(default)]
    pub pin: Option<String>,
    /// `pin` / `email`: max attempts before failure.
    #[serde(default)]
    pub max_tries: Option<u8>,
    /// `email`: code time-to-live in seconds.
    #[serde(default)]
    pub ttl_secs: Option<u32>,
    /// `email`: SMTP delivery settings.
    #[serde(default)]
    pub smtp: Option<SmtpConfig>,
}

/// SMTP delivery for the `email` challenge. With `log_only` (or no `host`),
/// the code is logged instead of sent — a dependency-free dev path.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SmtpConfig {
    /// SMTP relay host. Empty / unset ⇒ `log_only` behaviour.
    #[serde(default)]
    pub host: String,
    #[serde(default = "SmtpConfig::default_port")]
    pub port: u16,
    /// Envelope/from address.
    #[serde(default)]
    pub from: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    /// Use STARTTLS on the relay connection.
    #[serde(default)]
    pub starttls: bool,
    /// Log the code instead of sending it (dev / no real SMTP wired).
    #[serde(default)]
    pub log_only: bool,
}

impl SmtpConfig {
    fn default_port() -> u16 {
        587
    }
}

/// Declarative form of `ndn_cert::RequireAttestationKind` (see
/// [`DemoCaConfig::require_attestation`]).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RequireAttestationConfig {
    /// Subject-name prefix the rule applies to (e.g. `/high-trust`).
    pub prefix: String,
    /// Required challenge-attestation leaf kind (e.g. `device-approval`).
    pub kind: String,
    /// Require the matching leaf to be independently signed.
    #[serde(default)]
    pub require_signed: bool,
}

impl DemoCaConfig {
    fn default_prefix() -> String {
        "/demo/CA".to_string()
    }
    fn default_identity() -> String {
        "/demo/CA".to_string()
    }
}

impl Default for DemoCaConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            prefix: Self::default_prefix(),
            identity: Self::default_identity(),
            tokens: Vec::new(),
            challenges: Vec::new(),
            emit_attestations: false,
            require_attestation: None,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ListenersConfig {
    #[serde(default)]
    pub webtransport: Option<WebTransportListenerConfig>,
    #[serde(default)]
    pub quic: Option<QuicListenerConfig>,
    #[serde(default)]
    pub webrtc: Option<WebRtcListenerConfig>,
    #[serde(default)]
    pub ble: Option<BleListenerConfig>,
}

/// Raw-QUIC backbone listener (forwarder-to-forwarder).
///
/// Shares the [`CertSourceConfig`] cert-provisioning shape with the
/// WebTransport listener, so a QUIC backbone can equally serve a self-signed
/// (pin the logged leaf SHA-256), PEM, or ACME-provisioned certificate.
/// Defaults to a long-lived self-signed cert for `localhost`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct QuicListenerConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Bind address, e.g. `0.0.0.0:6367`.
    pub listen: String,
    /// TLS certificate source. Defaults to a self-signed cert for `localhost`
    /// (dialers pin the leaf SHA-256 logged at startup).
    #[serde(default)]
    pub cert_source: CertSourceConfig,
}

/// BLE GATT-server (peripheral) listener. When enabled, the forwarder binds
/// the local Bluetooth adapter as an NDN-BLE peripheral and advertises the NDN
/// service; connecting centrals are accepted as faces. This is the NFD-style
/// listener/channel model — the peripheral is *not* created via `faces/create`
/// (only the central `ble://<addr>` is).
///
/// Requires ndn-fwd built with `--features bluetooth` (Linux/macOS).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct BleListenerConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Adapter to bind (e.g. `hci0` on Linux); `None` selects the default.
    /// Ignored on macOS — CoreBluetooth uses the system adapter.
    #[serde(default)]
    pub adapter: Option<String>,
    /// Advertised local name; `None` uses the default `ndn-rs` name.
    #[serde(default)]
    pub local_name: Option<String>,
}

/// Peer-to-peer WebRTC datachannel listener. Polls an external
/// signaling relay (run `ndn-rtc-signaling-relay` separately) for
/// inbound SDP offers and registers each accepted face with the engine.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebRtcListenerConfig {
    #[serde(default)]
    pub enabled: bool,
    /// HTTP signaling-relay base URL.
    pub signaling_url: String,
    /// Session ids the listener accepts; one rendezvous slot each.
    #[serde(default)]
    pub session_ids: Vec<String>,
    /// STUN/TURN servers; `None` selects Google STUN.
    #[serde(default)]
    pub ice_servers: Option<WtIceServers>,
}

/// STUN / TURN configuration. Structurally mirrors `ndn_face_webrtc::IceServers`
/// (the forwarder round-trips this into it) so `ndn-config` need not depend on
/// the WebRTC stack and keeps building for wasm32.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WtIceServers {
    pub stun: Vec<String>,
    #[serde(default)]
    pub turn: Vec<WtTurnServer>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WtTurnServer {
    pub url: String,
    pub username: String,
    pub credential: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebTransportListenerConfig {
    #[serde(default)]
    pub enabled: bool,
    pub listen: String,
    /// TLS certificate source for the listener.
    pub cert_source: CertSourceConfig,
}

/// TLS certificate source for a cert-bearing face listener (WebTransport,
/// WS-TLS, raw QUIC).
///
/// Structurally mirrors `ndn_acme::CertSource` — the forwarder round-trips this
/// into it — so `ndn-config` stays decoupled from the ACME/QUIC stack and keeps
/// building for wasm32. Defaults are replicated to preserve behavior across the
/// round-trip.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CertSourceConfig {
    /// PEM cert chain + private key read from disk.
    Pem { cert_pem: String, key_pem: String },
    /// ACME (RFC 8555) DNS-01 provisioning with automatic renewal.
    Acme(AcmeTomlConfig),
    /// Ephemeral self-signed cert (dev / `serverCertificateHashes` workflow,
    /// or a pinned backbone link).
    SelfSignedDev(SelfSignedDevConfig),
}

/// A self-signed source defaults to a `localhost` cert — the zero-config path
/// for a loopback QUIC backbone or a dev WebTransport listener.
impl Default for CertSourceConfig {
    fn default() -> Self {
        CertSourceConfig::SelfSignedDev(SelfSignedDevConfig::default())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SelfSignedDevConfig {
    #[serde(default = "default_cert_hostnames")]
    pub hostnames: Vec<String>,
}

impl Default for SelfSignedDevConfig {
    fn default() -> Self {
        Self {
            hostnames: default_cert_hostnames(),
        }
    }
}

fn default_cert_hostnames() -> Vec<String> {
    vec!["localhost".into()]
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AcmeTomlConfig {
    /// e.g. `https://acme-v02.api.letsencrypt.org/directory`.
    pub directory_url: String,
    pub email: String,
    pub domain: String,
    /// Selects a registered DNS provider impl (e.g. `"cloudflare"`).
    pub dns_provider: String,
    /// Provider-specific params (API token, zone id, …).
    #[serde(default)]
    pub params: serde_json::Value,
    pub cache_dir: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RoutingTomlConfig {
    #[serde(default)]
    pub nlsr: NlsrTomlConfig,
    /// ndn-dv distance-vector, per `ndnd/dv/SPEC.md`.
    #[serde(default)]
    pub dv: DvTomlConfig,
}

/// Spec-compliant ndn-dv distance-vector routing. Default trust is
/// `InsecureTrust`, matching ndnd's `KeyChainUri = "insecure"` mode.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DvTomlConfig {
    #[serde(default)]
    pub enabled: bool,

    /// Default `"/ndn"`.
    #[serde(default = "default_dv_network")]
    pub network: String,

    /// Default `"/ndn/localhost/router"`.
    #[serde(default = "default_dv_router")]
    pub router: String,

    /// Spec default 30.
    #[serde(default = "default_dv_adv_sync_secs")]
    pub adv_sync_secs: u64,

    /// Spec default 30.
    #[serde(default = "default_dv_pfx_sync_secs")]
    pub pfx_sync_secs: u64,

    /// Drop a neighbour that hasn't sync'd for this many seconds.
    /// Spec default 60.
    #[serde(default = "default_dv_dead_secs")]
    pub router_dead_secs: u64,

    /// Each entry opens a UDP face to `face_uri` and seeds the engine's
    /// NeighborTable.
    #[serde(default, rename = "neighbor")]
    pub neighbors: Vec<DvNeighborConfig>,

    #[serde(default)]
    pub trust: DvTrustTomlConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DvNeighborConfig {
    /// Neighbour's router name (e.g. `/ndn/r2`).
    pub name: String,
    /// e.g. `udp4://10.0.0.2:6363`.
    pub face_uri: String,
}

/// DV trust policy. Modes:
///
/// - `insecure` (default): no signing or validation; wire-compat with
///   ndnd's `KeyChainUri = "insecure"`.
/// - `static`: pre-shared public keys (`[[trusted_key]]`) for verify,
///   paired with the security manager's signer for outgoing Data.
/// - `lvs`: schema-driven; `schema_file` is an LVS binary (python-ndn
///   / ndnts `@ndn/lvs` / ndnd `std/security/trust_schema` format).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DvTrustTomlConfig {
    /// `"insecure"` (default), `"static"`, or `"lvs"`.
    #[serde(default = "default_dv_trust_mode")]
    pub mode: String,

    #[serde(default, rename = "trusted_key")]
    pub trusted_keys: Vec<DvTrustedKey>,

    /// Required when `mode = "lvs"`; ignored otherwise.
    #[serde(default)]
    pub schema_file: Option<String>,
}

/// `public_key_file` holds raw public-key bytes per the algorithm —
/// e.g. 32 bytes for Ed25519.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DvTrustedKey {
    /// `KeyLocator` name this key matches against.
    pub name: String,
    pub public_key_file: String,
}

impl Default for DvTrustTomlConfig {
    fn default() -> Self {
        Self {
            mode: default_dv_trust_mode(),
            trusted_keys: Vec::new(),
            schema_file: None,
        }
    }
}

fn default_dv_trust_mode() -> String {
    "insecure".to_owned()
}

impl Default for DvTomlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            network: default_dv_network(),
            router: default_dv_router(),
            adv_sync_secs: default_dv_adv_sync_secs(),
            pfx_sync_secs: default_dv_pfx_sync_secs(),
            router_dead_secs: default_dv_dead_secs(),
            neighbors: Vec::new(),
            trust: DvTrustTomlConfig::default(),
        }
    }
}

fn default_dv_network() -> String {
    "/ndn".to_owned()
}
fn default_dv_router() -> String {
    "/ndn/localhost/router".to_owned()
}
fn default_dv_adv_sync_secs() -> u64 {
    30
}
fn default_dv_pfx_sync_secs() -> u64 {
    30
}
fn default_dv_dead_secs() -> u64 {
    60
}

/// Named-data Link State Routing. Timing defaults match
/// `NLSR/src/conf-parameter.hpp`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NlsrTomlConfig {
    #[serde(default)]
    pub enabled: bool,

    /// Default `"/ndn"`.
    #[serde(default = "default_nlsr_network")]
    pub network: String,

    /// Default `"/ndn/localhost/router"`.
    #[serde(default = "default_nlsr_router")]
    pub router: String,

    /// Prefixes originated by this router.
    #[serde(default)]
    pub name_prefixes: Vec<String>,

    #[serde(default, rename = "neighbor")]
    pub neighbors: Vec<NlsrNeighborConfig>,

    /// LSA lifetime seconds (default 1800).
    #[serde(default = "default_lsa_refresh_secs")]
    pub lsa_refresh_secs: u32,

    /// Default 10.
    #[serde(default = "default_adj_lsa_build_interval")]
    pub adj_lsa_build_interval_secs: u32,

    /// Default 15.
    #[serde(default = "default_routing_calc_interval")]
    pub routing_calc_interval_secs: u32,

    /// Default 60.
    #[serde(default = "default_hello_interval")]
    pub hello_interval_secs: u32,

    /// Hellos before declaring a neighbor Inactive (default 3).
    #[serde(default = "default_hello_retries")]
    pub hello_retries: u32,

    /// Default 1.
    #[serde(default = "default_hello_timeout")]
    pub hello_timeout_secs: u32,

    /// Default 60 000.
    #[serde(default = "default_sync_interest_lifetime_ms")]
    pub sync_interest_lifetime_ms: u64,

    /// Skip trust-chain validation of received LSAs. Bringup only.
    #[serde(default)]
    pub permissive_validation: bool,

    /// 0 = no limit.
    #[serde(default)]
    pub max_faces_per_prefix: usize,
}

fn default_nlsr_network() -> String {
    "/ndn".to_owned()
}
fn default_nlsr_router() -> String {
    "/ndn/localhost/router".to_owned()
}
fn default_lsa_refresh_secs() -> u32 {
    1800
}
fn default_adj_lsa_build_interval() -> u32 {
    10
}
fn default_routing_calc_interval() -> u32 {
    15
}
fn default_hello_interval() -> u32 {
    60
}
fn default_hello_retries() -> u32 {
    3
}
fn default_hello_timeout() -> u32 {
    1
}
fn default_sync_interest_lifetime_ms() -> u64 {
    60_000
}

impl Default for NlsrTomlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            network: default_nlsr_network(),
            router: default_nlsr_router(),
            name_prefixes: Vec::new(),
            neighbors: Vec::new(),
            lsa_refresh_secs: default_lsa_refresh_secs(),
            adj_lsa_build_interval_secs: default_adj_lsa_build_interval(),
            routing_calc_interval_secs: default_routing_calc_interval(),
            hello_interval_secs: default_hello_interval(),
            hello_retries: default_hello_retries(),
            hello_timeout_secs: default_hello_timeout(),
            sync_interest_lifetime_ms: default_sync_interest_lifetime_ms(),
            permissive_validation: false,
            max_faces_per_prefix: 0,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NlsrNeighborConfig {
    pub name: String,
    /// e.g. `udp4://10.0.0.2:6363`.
    pub face_uri: String,
    /// Default 10.0.
    #[serde(default = "default_link_cost")]
    pub link_cost: f64,
}

fn default_link_cost() -> f64 {
    10.0
}

impl std::str::FromStr for ForwarderConfig {
    type Err = ConfigError;

    /// `${VAR}` references are expanded before deserialization. An unset variable
    /// or an unterminated `${` is a hard error (audit CFG-3): a silent empty
    /// substitution could turn a security-relevant path (a cert/PIB path, a
    /// listen address) into `""`.
    fn from_str(s: &str) -> Result<Self, ConfigError> {
        let expanded = expand_env_vars(s)?;
        let cfg: ForwarderConfig = toml::from_str(&expanded)?;
        cfg.validate()?;
        Ok(cfg)
    }
}

impl ForwarderConfig {
    pub fn from_file(path: &std::path::Path) -> Result<Self, ConfigError> {
        let s = std::fs::read_to_string(path)?;
        s.parse()
    }

    /// Deserialize the `[extensions.<name>]` slice into an extension subsystem's
    /// own config type. `Ok(None)` when the section is absent. This is the seam
    /// that lets an out-of-core subsystem (its own crate/repo) own its config
    /// schema while ndn-config stays a closed core schema — ndn-config hands
    /// over the raw TOML and the extension parses it.
    pub fn extension<T: serde::de::DeserializeOwned>(
        &self,
        name: &str,
    ) -> Result<Option<T>, toml::de::Error> {
        self.extensions
            .get(name)
            .cloned()
            .map(toml::Value::try_into)
            .transpose()
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

fn expand_env_vars(s: &str) -> Result<String, ConfigError> {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '$' && chars.peek() == Some(&'{') {
            chars.next(); // consume '{'
            let mut var_name = String::new();
            let mut closed = false;
            for c in chars.by_ref() {
                if c == '}' {
                    closed = true;
                    break;
                }
                var_name.push(c);
            }
            // Reject an unterminated `${...` instead of consuming to end-of-input.
            if !closed {
                return Err(ConfigError::Invalid(format!(
                    "unterminated `${{` in config (variable `{var_name}` has no closing `}}`)"
                )));
            }
            // Reject an unset variable instead of silently substituting "".
            match std::env::var(&var_name) {
                Ok(val) => result.push_str(&val),
                Err(_) => {
                    return Err(ConfigError::Invalid(format!(
                        "config references unset environment variable `${{{var_name}}}`"
                    )));
                }
            }
        } else {
            result.push(ch);
        }
    }
    Ok(result)
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
        FaceConfig::WebTransport {
            remote,
            cert_sha256,
            webpki,
        } => {
            if !remote.starts_with("wts://") && !remote.starts_with("https://") {
                return Err(ConfigError::Invalid(format!(
                    "WebTransport remote must start with wts:// or https://: {remote}"
                )));
            }
            match (cert_sha256.as_deref(), webpki) {
                (Some(_), true) => {
                    return Err(ConfigError::Invalid(
                        "WebTransport face: set either cert_sha256 or webpki, not both".into(),
                    ));
                }
                (None, false) => {
                    return Err(ConfigError::Invalid(
                        "WebTransport face requires cert_sha256 (self-signed peer) or webpki = true"
                            .into(),
                    ));
                }
                (Some(hex), false) => {
                    if parse_cert_sha256_hex(hex).is_none() {
                        return Err(ConfigError::Invalid(format!(
                            "WebTransport cert_sha256 must be 64 hex chars (32 bytes): {hex}"
                        )));
                    }
                }
                (None, true) => {}
            }
        }
        FaceConfig::Quic {
            remote,
            cert_sha256,
            webpki,
        } => {
            if !remote.starts_with("quic://") {
                return Err(ConfigError::Invalid(format!(
                    "QUIC remote must start with quic://: {remote}"
                )));
            }
            match (cert_sha256.as_deref(), webpki) {
                (Some(_), true) => {
                    return Err(ConfigError::Invalid(
                        "QUIC face: set either cert_sha256 or webpki, not both".into(),
                    ));
                }
                (None, false) => {
                    return Err(ConfigError::Invalid(
                        "QUIC face requires cert_sha256 (self-signed peer) or webpki = true".into(),
                    ));
                }
                (Some(hex), false) => {
                    if parse_cert_sha256_hex(hex).is_none() {
                        return Err(ConfigError::Invalid(format!(
                            "QUIC cert_sha256 must be 64 hex chars (32 bytes): {hex}"
                        )));
                    }
                }
                (None, true) => {}
            }
        }
        FaceConfig::Ether {
            interface,
            peer_mac,
            io,
            bpf_object,
        } => {
            if interface.is_empty() {
                return Err(ConfigError::Invalid(
                    "ether face interface must not be empty".into(),
                ));
            }
            let octets: Vec<&str> = peer_mac.split(':').collect();
            let well_formed = octets.len() == 6
                && octets
                    .iter()
                    .all(|o| o.len() == 2 && o.bytes().all(|b| b.is_ascii_hexdigit()));
            if !well_formed {
                return Err(ConfigError::Invalid(format!(
                    "ether face peer-mac must be aa:bb:cc:dd:ee:ff: {peer_mac}"
                )));
            }
            // `io = "afxdp"` works with no `bpf-object` (the embedded redirect
            // program is used); a path, if given, just overrides it.
            let _ = (io, bpf_object);
        }
        FaceConfig::Unix { .. } | FaceConfig::EtherMulticast { .. } => {}
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CsConfig {
    #[serde(default = "default_cs_variant")]
    pub variant: String,
    #[serde(default = "default_cs_capacity_mb")]
    pub capacity_mb: usize,
    /// Used only by `"sharded-lru"`.
    #[serde(default)]
    pub shards: Option<usize>,
    #[serde(default = "default_admission_policy")]
    pub admission_policy: String,
    /// Caching of **unsolicited** Data (Data with no matching PIT entry).
    /// NFD-compatible tokens: `drop-all` (default), `admit-local`,
    /// `admit-network`, `admit-all`. `admit-network` is the choice for a
    /// broadcast/ad-hoc bearer where overhearing peers' Data is the point.
    #[serde(default = "default_unsolicited_policy")]
    pub unsolicited_policy: String,
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
fn default_unsolicited_policy() -> String {
    "drop-all".to_string()
}

impl Default for CsConfig {
    fn default() -> Self {
        Self {
            variant: default_cs_variant(),
            capacity_mb: default_cs_capacity_mb(),
            shards: None,
            admission_policy: default_admission_policy(),
            unsolicited_policy: default_unsolicited_policy(),
        }
    }
}

/// `[reflexive]` — reflexive-forwarding boot defaults. Runtime-mutable
/// afterwards via the `/localhost/nfd/reflexive` management module.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReflexiveTomlConfig {
    /// Whether reflexive forwarding is active at start-up.
    #[serde(default = "default_reflexive_enabled")]
    pub enabled: bool,
    /// Maximum live reverse routes per incoming face.
    #[serde(default = "default_reflexive_max_per_face")]
    pub max_per_face: usize,
    /// Route-lifetime ceiling in milliseconds.
    #[serde(default = "default_reflexive_max_lifetime_ms")]
    pub max_lifetime_ms: u64,
}

fn default_reflexive_enabled() -> bool {
    true
}
fn default_reflexive_max_per_face() -> usize {
    256
}
fn default_reflexive_max_lifetime_ms() -> u64 {
    8000
}

impl Default for ReflexiveTomlConfig {
    fn default() -> Self {
        Self {
            enabled: default_reflexive_enabled(),
            max_per_face: default_reflexive_max_per_face(),
            max_lifetime_ms: default_reflexive_max_lifetime_ms(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EngineConfig {
    /// Deprecated; use `[cs] capacity_mb`.
    #[serde(default = "default_cs_capacity_mb_engine")]
    pub cs_capacity_mb: usize,
    #[serde(default = "default_pipeline_channel_cap")]
    pub pipeline_channel_cap: usize,
    /// 0 = auto-detect, 1 = single-threaded inline, N = parallel tasks.
    #[serde(default)]
    pub pipeline_threads: usize,
    /// Data-plane runtime: `"shared"` (default) or `"partitioned"`. The
    /// partitioned (per-worker) runtime requires `ndn-fwd` built with the
    /// `partitioned-fwd` feature; otherwise it falls back to shared.
    #[serde(default = "default_data_plane")]
    pub data_plane: String,
    /// Worker count for the partitioned data plane. 0 = auto (physical cores).
    #[serde(default)]
    pub workers: usize,
    /// Require Data signature validation even on Local faces (IPC/SHM), which
    /// otherwise skip it. Default false. For multi-tenant hosts (or to stress
    /// the validation path under load).
    #[serde(default)]
    pub require_local_validation: bool,
}

fn default_cs_capacity_mb_engine() -> usize {
    64
}
fn default_pipeline_channel_cap() -> usize {
    4096
}
fn default_data_plane() -> String {
    "shared".to_string()
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            cs_capacity_mb: default_cs_capacity_mb_engine(),
            pipeline_channel_cap: default_pipeline_channel_cap(),
            pipeline_threads: 0,
            data_plane: default_data_plane(),
            workers: 0,
            require_local_validation: false,
        }
    }
}

/// The `kind` tag selects the variant.
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
    /// Outbound WebTransport dial (forwarder-to-forwarder over QUIC/HTTP3,
    /// NAT-traversing). The inbound side is `[listeners.webtransport]`.
    #[serde(rename = "web-transport")]
    WebTransport {
        /// Peer to dial as `wts://host:port[/path]` (or `https://…`).
        remote: String,
        /// Pin the peer's leaf cert by SHA-256 (hex) — for self-signed peers.
        /// Mutually exclusive with `webpki`.
        #[serde(default)]
        cert_sha256: Option<String>,
        /// Validate against the OS trust store (public-CA / ACME peers).
        #[serde(default)]
        webpki: bool,
    },
    /// Outbound raw-QUIC dial (forwarder-to-forwarder backbone link; TLS 1.3,
    /// connection migration). The inbound side is `[listeners.quic]`.
    Quic {
        /// Peer to dial as `quic://host:port`.
        remote: String,
        /// Pin the peer's leaf cert by SHA-256 (hex) — for self-signed peers.
        /// Mutually exclusive with `webpki`.
        #[serde(default)]
        cert_sha256: Option<String>,
        /// Validate the peer's chain against the bundled WebPKI roots (a
        /// publicly-trusted / ACME cert). Mutually exclusive with `cert_sha256`.
        #[serde(default)]
        webpki: bool,
    },
    Serial {
        path: String,
        #[serde(default = "default_baud")]
        baud: u32,
    },
    #[serde(rename = "ether-multicast")]
    EtherMulticast { interface: String },
    /// Unicast NDN-over-Ethernet link to a known peer MAC on `interface`
    /// (EtherType 0x8624). Linux/macOS/Windows; requires `CAP_NET_RAW`/root.
    /// Peer MAC must be supplied — neighbor discovery is not yet wired.
    Ether {
        interface: String,
        /// Peer MAC as `aa:bb:cc:dd:ee:ff`.
        #[serde(rename = "peer-mac")]
        peer_mac: String,
        /// I/O backend: `"af-packet"` (default) or `"afxdp"` (kernel-bypass,
        /// Linux; requires `ndn-fwd` built with the `af-xdp` feature).
        #[serde(default)]
        io: Option<String>,
        /// Path to the compiled XDP redirect object. Required when
        /// `io = "afxdp"`.
        #[serde(default, rename = "bpf-object")]
        bpf_object: Option<String>,
    },
}

fn default_baud() -> u32 {
    115200
}

/// Automatic multicast face creation and OS interface hotplug.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct FaceSystemConfig {
    #[serde(default)]
    pub ether: EtherFaceSystemConfig,
    #[serde(default)]
    pub udp: UdpFaceSystemConfig,
    /// Linux only (`RTMGRP_LINK` netlink); macOS/Windows log a warning
    /// and ignore.
    #[serde(default)]
    pub watch_interfaces: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EtherFaceSystemConfig {
    /// Eligibility: UP, multicast-capable, non-loopback, passes the
    /// whitelist/blacklist filters.
    #[serde(default)]
    pub auto_multicast: bool,
    /// Glob patterns to include (`*` / `?`); default `["*"]`.
    #[serde(default = "default_iface_whitelist")]
    pub whitelist: Vec<String>,
    /// Applied after `whitelist`; default `["lo"]`.
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UdpFaceSystemConfig {
    #[serde(default)]
    pub auto_multicast: bool,
    /// Advertise faces as `AdHoc` instead of `MultiAccess`. Required
    /// for Wi-Fi IBSS / MANET where not all nodes hear every multicast
    /// frame; disables multi-access Interest suppression in strategies.
    #[serde(default)]
    pub ad_hoc: bool,
    /// Default `["*"]`.
    #[serde(default = "default_iface_whitelist")]
    pub whitelist: Vec<String>,
    /// Default `["lo"]`.
    #[serde(default = "default_udp_iface_blacklist")]
    pub blacklist: Vec<String>,
    /// Number of `SO_REUSEPORT` listener sockets per UDP bind. Each gets its
    /// own reader task, and the kernel load-balances inbound flows across them
    /// (Linux per-4-tuple hash), so multi-flow wire RX scales across cores
    /// instead of serialising on one. `0` = auto (min(num_cpus, 4)); `1` =
    /// single socket (current behaviour). Linux/BSD only; elsewhere clamped
    /// to 1. See testbed/bench/multiflow_wire.sh.
    #[serde(default = "default_udp_rx_sockets")]
    pub rx_sockets: usize,
}

fn default_udp_rx_sockets() -> usize {
    1
}

impl Default for UdpFaceSystemConfig {
    fn default() -> Self {
        Self {
            auto_multicast: false,
            ad_hoc: false,
            whitelist: default_iface_whitelist(),
            blacklist: default_udp_iface_blacklist(),
            rx_sockets: default_udp_rx_sockets(),
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
    /// Zero-based index into `faces`.
    pub face: usize,
    #[serde(default = "default_cost")]
    pub cost: u32,
}

fn default_cost() -> u32 {
    10
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ManagementConfig {
    /// Unix domain socket (or Named Pipe on Windows) for app/tool faces.
    /// Default Unix: `/run/nfd/nfd.sock`; Windows: `\\.\pipe\ndn`.
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
    #[cfg(not(any(unix, windows)))]
    return String::new();
}

/// `[[security.rule]]` data/key pattern pair. Variables captured in
/// the data pattern must bind the same component value in the key
/// pattern — this prevents cross-identity signing.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct TrustRuleConfig {
    /// e.g. `/sensor/<node>/<type>`.
    pub data: String,
    /// e.g. `/sensor/<node>/KEY/<id>`.
    pub key: String,
}

/// Whether privileged management commands require key-backed signed
/// Interests. Default is on; opt out only for local dev without a
/// provisioned trust anchor.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MgmtSecurityConfig {
    /// When `true` (default), DigestSha256-only or unsigned command
    /// Interests are rejected 403; key-backed signatures must pass the
    /// validator loaded from `trust_anchor_pib`.
    #[serde(default = "default_require_signed_commands")]
    pub require_signed_commands: bool,

    /// Required when `require_signed_commands = true`; ndn-fwd aborts
    /// at startup if missing or empty.
    #[serde(default)]
    pub trust_anchor_pib: Option<String>,

    /// PIB whose anchors authorise `/localhop/nfd/rib/{register,
    /// unregister}` Interests. Mirrors NFD's `rib.localhop_security`
    /// (`daemon/mgmt/rib-manager.cpp:60`). Unset = reject all
    /// `/localhop/nfd/...` commands.
    #[serde(default)]
    pub localhop_trust_anchor_pib: Option<String>,
}

fn default_require_signed_commands() -> bool {
    true
}

impl Default for MgmtSecurityConfig {
    fn default() -> Self {
        Self {
            require_signed_commands: default_require_signed_commands(),
            trust_anchor_pib: None,
            localhop_trust_anchor_pib: None,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    /// Key and certificate must exist in the PIB unless `auto_init`.
    #[serde(default)]
    pub identity: Option<String>,

    /// Default `~/.ndn/pib`. Create with `ndn-ctl security init`.
    #[serde(default)]
    pub pib_path: Option<String>,

    /// Takes precedence over anchors stored in the PIB.
    #[serde(default)]
    pub trust_anchor: Option<String>,

    #[serde(default)]
    pub require_signed: bool,

    /// Auto-generate a self-signed identity on first startup if the PIB
    /// is empty. Requires `identity`.
    #[serde(default)]
    pub auto_init: bool,

    /// `"default"` (full chain validation), `"accept-signed"` (signature
    /// only, no chain walk), or `"disabled"` (no validation; implies
    /// `validator_enabled = false`). Default `"default"`; when the
    /// `[security]` block is absent entirely the router falls back to
    /// `AcceptSigned`.
    #[serde(default = "default_security_profile")]
    pub profile: String,

    /// When `false`, Data bypasses signature verification before CS
    /// admission. Removes the trust barrier between the network and
    /// the cache — lab use only.
    #[serde(default = "default_validator_enabled")]
    pub validator_enabled: bool,

    /// Unset = client-only mode (no built-in CA).
    #[serde(default)]
    pub ca_prefix: Option<String>,

    #[serde(default)]
    pub ca_info: String,

    #[serde(default = "default_ca_max_validity_days")]
    pub ca_max_validity_days: u32,

    /// Recognised: `"token"`, `"pin"`, `"possession"`, `"email"`,
    /// `"yubikey-hotp"`.
    #[serde(default = "default_ca_challenges")]
    pub ca_challenges: Vec<String>,

    /// Extends the profile's default rules.
    #[serde(default, rename = "rule")]
    pub rules: Vec<TrustRuleConfig>,

    /// `"file"` (persistent, default) or `"memory"` (ephemeral).
    #[serde(default = "default_pib_type")]
    pub pib_type: String,

    /// Default = hostname.
    #[serde(default)]
    pub ephemeral_prefix: Option<String>,

    #[serde(default)]
    pub mgmt: MgmtSecurityConfig,
}

fn default_pib_type() -> String {
    "file".to_owned()
}

fn default_security_profile() -> String {
    "default".to_owned()
}

fn default_validator_enabled() -> bool {
    true
}

fn default_ca_max_validity_days() -> u32 {
    365
}

fn default_ca_challenges() -> Vec<String> {
    vec!["token".to_owned()]
}

/// Precedence: `RUST_LOG` env > `--log-level` CLI > `level`. When
/// `file` is set, logs go to both stderr and the file.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    /// Tracing filter, e.g. `"info"`, `"ndn_engine=debug,warn"`.
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Parent directories are created automatically.
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

/// Discovery is disabled unless `node_name` is set.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct DiscoveryTomlConfig {
    #[serde(default)]
    pub profile: Option<String>,

    /// Trailing `/` appends the hostname automatically.
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
    pub relay_records: Option<bool>,
    #[serde(default)]
    pub auto_fib_cost: Option<u32>,
    #[serde(default)]
    pub auto_fib_ttl_multiplier: Option<f32>,
    #[serde(default)]
    pub pib_path: Option<String>,

    /// Absent = ephemeral Ed25519 auto-generated from node name.
    #[serde(default)]
    pub key_name: Option<String>,

    /// PIB of trust anchors for verifying *peer* service records. Absent
    /// ⇒ fail-closed: peer records are browseable but never auto-install
    /// FIB routes. Each trusted peer's identity cert (or a shared CA the
    /// peers chain to) goes here.
    #[serde(default)]
    pub trust_anchor_pib: Option<String>,

    /// `"udp"` (default), `"ether"`, or `"both"`. Ethernet needs
    /// CAP_NET_RAW.
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

    #[test]
    fn extensions_passthrough_round_trips_a_subsystem_slice() {
        #[derive(serde::Deserialize, PartialEq, Debug)]
        struct MyRoutingCfg {
            calc_interval_secs: u32,
            neighbors: Vec<String>,
        }
        let cfg: ForwarderConfig = r#"
            [extensions.my-routing]
            calc_interval_secs = 15
            neighbors = ["udp4://10.0.0.2:6363"]
        "#
        .parse()
        .expect("parse");
        // The core schema ignored the unknown subsystem; the extension reads its own slice.
        let mine: MyRoutingCfg = cfg
            .extension("my-routing")
            .expect("deserialize")
            .expect("present");
        assert_eq!(
            mine,
            MyRoutingCfg {
                calc_interval_secs: 15,
                neighbors: vec!["udp4://10.0.0.2:6363".to_owned()],
            }
        );
        // Absent extension → Ok(None).
        assert!(cfg.extension::<MyRoutingCfg>("absent").unwrap().is_none());
    }

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
        assert_eq!(cfg.routes[1].cost, 10);
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
    // `env::set_var` is unsafe in edition 2024; test-only exception to the
    // workspace `deny(unsafe_code)`.
    #[allow(unsafe_code)]
    fn example_file_parses() {
        // The example is a deployment template referencing env-var placeholders;
        // set them so expansion succeeds (unset vars now hard-error — CFG-3).
        // SAFETY: single-threaded test; no concurrent env access.
        unsafe {
            std::env::set_var("CLOUDFLARE_API_TOKEN", "test-token");
            std::env::set_var("CLOUDFLARE_ZONE_ID", "test-zone");
        }
        let s = include_str!("../../../../deploy/ndn-fwd.example.toml");
        ForwarderConfig::from_str(s).expect("example config should parse");
    }

    #[test]
    fn cfg3_unset_env_var_errors() {
        // An unset ${VAR} must hard-error, not silently expand to "".
        let toml = "listen = \"${DEFINITELY_UNSET_VAR_XYZ}\"\n";
        assert!(ForwarderConfig::from_str(toml).is_err());
    }

    #[test]
    fn cfg3_unterminated_env_var_errors() {
        let toml = "listen = \"${OPEN_BUT_NEVER_CLOSED\"\n";
        assert!(ForwarderConfig::from_str(toml).is_err());
    }

    #[test]
    fn misplaced_security_keys_are_rejected() {
        // A `[security.mgmt]` key placed under `[security]` is a common
        // footgun — without deny_unknown_fields serde silently drops it,
        // leaving the validator unconfigured. It must now error loudly.
        let bad = "[security]\ntrust_anchor_pib = \"/etc/ndn/mgmt-pib\"\n";
        let err = ForwarderConfig::from_str(bad).expect_err("misplaced key must error");
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("unknown field") || msg.contains("trust_anchor_pib"),
            "expected an unknown-field error, got: {msg}"
        );

        // The same key in its correct home parses.
        let good = "[security.mgmt]\ntrust_anchor_pib = \"/etc/ndn/mgmt-pib\"\n";
        let cfg = ForwarderConfig::from_str(good).expect("correct placement parses");
        assert_eq!(
            cfg.security.mgmt.trust_anchor_pib.as_deref(),
            Some("/etc/ndn/mgmt-pib")
        );
    }

    #[test]
    fn reflexive_config_parses_and_defaults() {
        // Explicit values.
        let cfg = ForwarderConfig::from_str(
            "[reflexive]\nenabled = false\nmax_per_face = 16\nmax_lifetime_ms = 2000\n",
        )
        .unwrap();
        assert!(!cfg.reflexive.enabled);
        assert_eq!(cfg.reflexive.max_per_face, 16);
        assert_eq!(cfg.reflexive.max_lifetime_ms, 2000);

        // Absent → sensible defaults.
        let d = ForwarderConfig::from_str("").unwrap();
        assert!(d.reflexive.enabled);
        assert_eq!(d.reflexive.max_per_face, 256);
        assert_eq!(d.reflexive.max_lifetime_ms, 8000);
    }
}
