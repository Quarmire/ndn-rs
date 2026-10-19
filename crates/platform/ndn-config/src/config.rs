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

    /// Devices this one links to over QUIC, or lets link in, identified by
    /// their key (`[[peer]]`). See [`PeerConfig`].
    #[serde(default, rename = "peer")]
    pub peers: Vec<PeerConfig>,

    /// Which relays this device links to and how (`[relays]`). See
    /// [`RelaysConfig`].
    #[serde(default)]
    pub relays: RelaysConfig,

    /// Relays the user adds: own server, community relay, hosted service
    /// (`[[relay]]`). See [`RelayConfig`].
    #[serde(default, rename = "relay")]
    pub user_relays: Vec<RelayConfig>,

    /// What this device does as a relay for others (`[relay_service]`).
    #[serde(default)]
    pub relay_service: RelayServiceConfig,

    /// Keep-alive and idle timeout of every link (`[links]`).
    #[serde(default)]
    pub links: LinksConfig,

    /// Direct paths with members met at a common relay (`[direct]`).
    #[serde(default)]
    pub direct: DirectConfig,

    /// Boot-time strategy choices. Strategy selection is otherwise only
    /// reachable over the management socket, so a forwarder restart silently
    /// reverts every prefix to the default strategy while `[[route]]` entries
    /// survive — a fleet that configures multicast out-of-band loses it on
    /// every restart with no error anywhere. Declaring them here keeps the
    /// strategy table part of the forwarder's own config, like routes.
    #[serde(default, rename = "strategy")]
    pub strategies: Vec<StrategyConfig>,

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

    /// Opt-in in-process NDNCERT CA for the namespace whose root this node's
    /// PIB holds (`[ca]`; `ndn-fwd init` writes its identity). A CA can also
    /// run out-of-process, with `[security.mgmt] localhop_trust_anchor_pib`
    /// pointing at its PIB.
    #[serde(default)]
    pub ca: CaTomlConfig,

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

/// Embedded NDNCERT CA. Serves `/<prefix>/CA/{INFO,NEW,CHALLENGE/<id>}`
/// plus cert-fetch for the certs it issued, and — with the
/// `device-approval` challenge — `/<prefix>/CA/APPROVAL` (an admin device's
/// signed decision) and `/<prefix>/CA/PENDING` (the pending requests, to an
/// admin key).
///
/// By default the CA signs with the identity `identity` loaded from the node's
/// PIB (`[security] pib_path`): its key and its `ca/ca-cert.data` certificate
/// (issued by the namespace root) are written by `ndn-fwd init --namespace <ns>`.
/// Issued certs and revocations persist under `<pib_path>/ca/`. With
/// `ephemeral = true` the CA instead mints a throwaway self-signed key at
/// every start (demo only: certs it issued stop verifying after a restart).
///
/// The CA refuses to start with no challenge configured: list them under
/// `[[ca.challenge]]` (or the legacy `tokens`). `nop` (auto-approve) is
/// only offered when listed explicitly.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CaTomlConfig {
    #[serde(default)]
    pub enabled: bool,
    /// CA namespace, e.g. `/home/bob`. The CA appends `/CA` itself and serves
    /// `/<prefix>/CA/...` (NDNCERT convention; clients append `/CA` too), so
    /// this must not end in `CA`.
    #[serde(default = "CaTomlConfig::default_prefix")]
    pub prefix: String,
    /// CA signing identity, conventionally `<prefix>/CA`. Loaded from the PIB
    /// unless `ephemeral`.
    #[serde(default = "CaTomlConfig::default_identity")]
    pub identity: String,
    /// Mint a throwaway self-signed CA key at startup instead of loading
    /// `identity` from the PIB. Demo only; logged as a warning.
    #[serde(default)]
    pub ephemeral: bool,
    /// Legacy shortcut for a single `token` challenge with these one-time
    /// invite tokens. Ignored when `challenge` is non-empty.
    #[serde(default)]
    pub tokens: Vec<String>,
    /// Explicit challenge set — the CA offers exactly these. Serialized as
    /// `[[ca.challenge]]` array-of-tables.
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
    /// Lifetime, in days, of the certificates this CA issues: one number for
    /// every role, or a `[ca.cert_validity_days]` table per role (`admin`,
    /// `member`, `node`, `guest`, plus `default` for the roles it does not
    /// list). The longest is the maximum the CA advertises in INFO. Default
    /// 90 for every role. Devices enrolling by invite or renewing name no
    /// lifetime, so they get exactly their role's; `ndn-fwd enroll` and
    /// `ndn-fwd renew` report the expiry the CA issued.
    #[serde(default)]
    pub cert_validity_days: CertValidityDays,
    /// Roles whose certificates the CA renews: a device holding a current,
    /// unrevoked certificate of such a role gets a new one for the same key
    /// without an invite (`ndn-fwd renew`, the renewal timer). Default
    /// `["admin", "member", "node"]`: guest certificates end at their
    /// expiry. Empty: the CA renews nothing.
    #[serde(default = "CaTomlConfig::default_renewable_roles")]
    pub renewable_roles: Vec<String>,
    /// Roles whose certificates the CA issues only on an admin's approval
    /// (`ndn-fwd enroll <anchor link> --role <role>`, then `ndn-fwd approvals
    /// approve <code>` on an admin device). Policy in data: `ndn-fwd init -c
    /// <config>` writes it into the namespace's trust context, and a
    /// namespace CA enforces what its context advertises — it refuses to
    /// start when this key disagrees with it. Unset: what the context says
    /// (default `["admin", "node"]`).
    #[serde(default)]
    pub approval_roles: Option<Vec<String>>,
    /// Whether a request for one of `approval_roles` must also redeem an
    /// invite token of this CA (`token AND device-approval`), redeemed once,
    /// when the request is made. Written into the trust context by `ndn-fwd
    /// init -c <config>` and checked against it like `approval_roles`.
    /// Unset: what the context says (default `false`).
    #[serde(default)]
    pub approval_requires_invite: Option<bool>,
    /// Roles whose devices may link to the namespace's devices (`[[peer]]`
    /// QUIC links). Policy in data: `ndn-fwd init -c <config>` writes the
    /// link policy into the namespace's trust context and `ndn-fwd schema
    /// update -c <config>` changes it (a narrowing only with
    /// `--accept-narrowing`); a namespace CA refuses to start when this key
    /// disagrees with the context. Empty list: every role. Unset: what the
    /// context says (default: every role).
    #[serde(default)]
    pub link_roles: Option<Vec<String>>,
    /// Roles a device may use as a relay (a link other devices are reached
    /// through); each must be one of `link_roles` when that is not empty.
    /// Written and checked like `link_roles`. Unset: what the context says
    /// (default `["node"]`).
    #[serde(default)]
    pub relay_roles: Option<Vec<String>>,
    /// Whether a relay of the namespace admits an unknown device on an
    /// enrollment link that carries only its enrollment (the CA endpoints
    /// and the trust context). Written and checked like `link_roles`.
    /// Unset: what the context says (default on when the namespace has a
    /// CA).
    #[serde(default)]
    pub enrollment_links: Option<bool>,
    /// Whether two devices of the namespace linked through a relay may try
    /// a direct path between them (NAT hole punching from the addresses
    /// each offers), keeping the relay when it does not open. Written and
    /// checked like `link_roles`; turning it off is a narrowing. Unset:
    /// what the context says (default on).
    #[serde(default)]
    pub direct_paths: Option<bool>,
    /// Which pairs of roles may make direct paths with each other, each
    /// `"<role>:<role>"` (unordered; `"member:member"` for two members),
    /// roles `admin`, `member`, `node` or `guest`. Written and checked like
    /// `link_roles`; removing a pair is a narrowing. Empty list: no pair.
    /// Unset: what the context says (default: every pair of admin, member
    /// and node; guests none).
    #[serde(default)]
    pub direct_pairs: Option<Vec<String>>,
    /// `[[ca.relay]]`: the relays the namespace advertises in its trust
    /// context, so every member learns them without local configuration
    /// (each device decides whether to use them). Their endpoints are
    /// visible to every device that holds the context. Written by `ndn-fwd
    /// init -c <config>` and `ndn-fwd schema update -c <config>` (dropping
    /// one, or changing its `key`, is a narrowing); a namespace CA refuses to
    /// start when they disagree with the context. `relay = []`: none.
    /// Unset: what the context says (default none).
    #[serde(default, rename = "relay", skip_serializing_if = "Option::is_none")]
    pub relays: Option<Vec<CaRelayConfig>>,
    /// How long a request for an admin's approval waits for a decision, in
    /// days, before it expires (the device is then told to ask again); a
    /// decision is kept as long for a device that was offline to learn it.
    /// Default 7.
    #[serde(default = "CaTomlConfig::default_approval_request_ttl_days")]
    pub approval_request_ttl_days: u32,
}

/// One `[[ca.relay]]` entry: a relay the namespace advertises.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaRelayConfig {
    /// The relay's device name, normally `/<namespace>/node/<device>`.
    pub device: String,
    /// Its expected fingerprint: 64 hex digits (the link key its `ndn-fwd`
    /// prints). Required when `device` is not a device of the namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Where devices dial it: `host:port`, or a list tried in order.
    #[serde(deserialize_with = "one_or_many")]
    pub endpoint: Vec<String>,
    /// Lower is preferred. Default 0.
    #[serde(default)]
    pub preference: u32,
}

/// `[ca] cert_validity_days`: one number of days for every role, or a table
/// with a number per role and an optional `default` for the rest:
///
/// ```toml
/// [ca.cert_validity_days]
/// default = 90
/// guest = 7
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertValidityDays {
    /// Days for every role the table does not list.
    pub default: u32,
    pub admin: Option<u32>,
    pub member: Option<u32>,
    pub node: Option<u32>,
    pub guest: Option<u32>,
}

impl CertValidityDays {
    /// The role names a table may list.
    pub const ROLES: [&'static str; 4] = ["admin", "member", "node", "guest"];

    /// `days` for every role.
    pub const fn uniform(days: u32) -> Self {
        Self {
            default: days,
            admin: None,
            member: None,
            node: None,
            guest: None,
        }
    }

    /// The table entry for `role` (one of [`ROLES`](Self::ROLES)), if listed.
    pub fn listed(&self, role: &str) -> Option<u32> {
        match role {
            "admin" => self.admin,
            "member" => self.member,
            "node" => self.node,
            "guest" => self.guest,
            _ => None,
        }
    }

    /// Days for `role`: its table entry, else the default.
    pub fn for_role(&self, role: &str) -> u32 {
        self.listed(role).unwrap_or(self.default)
    }

    /// The longest lifetime of any role (the default's included).
    pub fn max_days(&self) -> u32 {
        Self::ROLES
            .iter()
            .map(|r| self.for_role(r))
            .fold(self.default, u32::max)
    }

    fn slot(&mut self, role: &str) -> Option<&mut Option<u32>> {
        match role {
            "admin" => Some(&mut self.admin),
            "member" => Some(&mut self.member),
            "node" => Some(&mut self.node),
            "guest" => Some(&mut self.guest),
            _ => None,
        }
    }
}

impl Default for CertValidityDays {
    fn default() -> Self {
        Self::uniform(CaTomlConfig::DEFAULT_CERT_VALIDITY_DAYS)
    }
}

impl Serialize for CertValidityDays {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        if Self::ROLES.iter().all(|r| self.listed(r).is_none()) {
            return s.serialize_u32(self.default);
        }
        let mut map = s.serialize_map(None)?;
        map.serialize_entry("default", &self.default)?;
        for role in Self::ROLES {
            if let Some(days) = self.listed(role) {
                map.serialize_entry(role, &days)?;
            }
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for CertValidityDays {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Days;
        fn days<E: serde::de::Error>(v: i64) -> Result<u32, E> {
            u32::try_from(v).map_err(|_| E::custom(format!("{v} is not a number of days")))
        }
        impl<'de> serde::de::Visitor<'de> for Days {
            type Value = CertValidityDays;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str(
                    "a number of days, or a table of days per role (admin, member, node, guest, \
                     default)",
                )
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(CertValidityDays::uniform(days::<E>(v)?))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                self.visit_i64(i64::try_from(v).unwrap_or(i64::MAX))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                use serde::de::Error;
                let mut out = CertValidityDays::default();
                while let Some(key) = map.next_key::<String>()? {
                    let value = days::<A::Error>(map.next_value::<i64>()?)?;
                    if key == "default" {
                        out.default = value;
                    } else if let Some(slot) = out.slot(&key) {
                        *slot = Some(value);
                    } else {
                        return Err(A::Error::unknown_field(
                            &key,
                            &["default", "admin", "member", "node", "guest"],
                        ));
                    }
                }
                Ok(out)
            }
        }
        d.deserialize_any(Days)
    }
}

/// One NDNCERT challenge the CA offers. Flat (`kind` + per-kind fields) for
/// TOML friendliness; the CA wiring matches on `kind`. Recognised kinds:
/// `nop`, `token`, `pin`, `email`, `device-approval`. (`possession`/`yubikey`
/// need certs / secrets, so they're wired in code.)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChallengeConfig {
    /// `nop` | `token` | `pin` | `email` | `device-approval`.
    /// `device-approval` holds each request durably until an admin decides
    /// it: the CA host's local operator (`ndn-fwd approvals approve|deny`
    /// there), or an admin device's signed decision pushed to
    /// `/<prefix>/CA/APPROVAL` (`ndn-fwd approvals` on that device). A
    /// namespace CA offers it even when unlisted, for the roles its trust
    /// context certifies on approval.
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
/// [`CaTomlConfig::require_attestation`]).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RequireAttestationConfig {
    /// Subject-name prefix the rule applies to (e.g. `/high-trust`).
    pub prefix: String,
    /// Required challenge-attestation leaf kind (e.g. `device-approval`).
    pub kind: String,
    /// Require the matching leaf to be independently signed (an admin
    /// device's signed approval).
    #[serde(default)]
    pub require_signed: bool,
    /// With `require_signed`, also accept the CA host's local operator's
    /// approval, which carries no signature (the attestation names the
    /// operator instead).
    #[serde(default)]
    pub accept_local_operator: bool,
}

impl CaTomlConfig {
    fn default_prefix() -> String {
        "/demo".to_string()
    }
    fn default_identity() -> String {
        "/demo/CA".to_string()
    }
    /// See [`cert_validity_days`](Self::cert_validity_days).
    pub const DEFAULT_CERT_VALIDITY_DAYS: u32 = 90;
    /// See [`renewable_roles`](Self::renewable_roles).
    fn default_renewable_roles() -> Vec<String> {
        ["admin", "member", "node"].map(String::from).to_vec()
    }
    /// See [`approval_request_ttl_days`](Self::approval_request_ttl_days).
    pub const DEFAULT_APPROVAL_REQUEST_TTL_DAYS: u32 = 7;
    fn default_approval_request_ttl_days() -> u32 {
        Self::DEFAULT_APPROVAL_REQUEST_TTL_DAYS
    }

    /// Checks `direct_pairs` and each `[[ca.relay]]` entry on their own;
    /// whether a relay outside the namespace has its `key` is checked when
    /// the namespace is known (init, schema update, CA start).
    fn validate(&self) -> Result<(), ConfigError> {
        for pair in self.direct_pairs.iter().flatten() {
            let roles = pair.split_once(':');
            if !roles.is_some_and(|(a, b)| {
                CertValidityDays::ROLES.contains(&a) && CertValidityDays::ROLES.contains(&b)
            }) {
                return Err(ConfigError::Invalid(format!(
                    "[ca] direct_pairs: {pair:?} is not a pair of roles: write \"<role>:<role>\" \
                     with roles {}, such as \"member:member\"",
                    CertValidityDays::ROLES.join(", ")
                )));
            }
        }
        let relays = self.relays.as_deref().unwrap_or_default();
        for (i, relay) in relays.iter().enumerate() {
            let invalid = |why: String| {
                ConfigError::Invalid(format!("[[ca.relay]] {}: {why}", relay.device))
            };
            let parsed = relay.device.parse::<ndn_packet::Name>().ok();
            if !relay.device.starts_with('/') || parsed.is_none_or(|n| n.len() < 3) {
                return Err(ConfigError::Invalid(format!(
                    "[[ca.relay]] #{}: device must be a device name /<namespace>/<role>/<device>, \
                     not {:?}",
                    i + 1,
                    relay.device
                )));
            }
            if let Some(key) = &relay.key
                && (key.len() != 64 || !key.bytes().all(|b| b.is_ascii_hexdigit()))
            {
                return Err(invalid(format!(
                    "key must be the 64 hex digits of the relay's fingerprint, not {key:?}"
                )));
            }
            if relay.endpoint.is_empty() {
                return Err(invalid(
                    "no endpoint, so no device could reach it: set endpoint = \"host:port\"".into(),
                ));
            }
            for endpoint in &relay.endpoint {
                let port = endpoint.rsplit_once(':').map(|(_, p)| p.parse::<u16>());
                if !matches!(port, Some(Ok(p)) if p != 0) {
                    return Err(invalid(format!(
                        "endpoint must be host:port, such as \"relay.example.net:6367\", not \
                         {endpoint:?}"
                    )));
                }
            }
            if relays[..i].iter().any(|r| r.device == relay.device) {
                return Err(invalid("listed twice; merge the two entries".into()));
            }
        }
        Ok(())
    }
}

impl Default for CaTomlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            prefix: Self::default_prefix(),
            identity: Self::default_identity(),
            ephemeral: false,
            tokens: Vec::new(),
            challenges: Vec::new(),
            emit_attestations: false,
            require_attestation: None,
            cert_validity_days: CertValidityDays::default(),
            renewable_roles: Self::default_renewable_roles(),
            approval_roles: None,
            approval_requires_invite: None,
            link_roles: None,
            relay_roles: None,
            enrollment_links: None,
            direct_paths: None,
            direct_pairs: None,
            relays: None,
            approval_request_ttl_days: Self::DEFAULT_APPROVAL_REQUEST_TTL_DAYS,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListenersConfig {
    #[serde(default)]
    pub webtransport: Option<WebTransportListenerConfig>,
    #[serde(default)]
    pub webrtc: Option<WebRtcListenerConfig>,
    #[serde(default)]
    pub ble: Option<BleListenerConfig>,
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
/// WS-TLS). QUIC links need none: their TLS identity is the device's NDN key.
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
    /// Self-signed cert (dev / `serverCertificateHashes` workflow, or a pinned
    /// backbone link). The key + cert persist across restarts so the pinned
    /// leaf SHA-256 stays stable.
    SelfSignedDev(SelfSignedDevConfig),
}

/// A self-signed source defaults to a `localhost` cert — the zero-config path
/// for a loopback QUIC backbone or a dev WebTransport listener.
impl Default for CertSourceConfig {
    fn default() -> Self {
        CertSourceConfig::SelfSignedDev(SelfSignedDevConfig::default())
    }
}

/// Self-signed listener cert. The generated key (PKCS#8) and cert are
/// persisted under `cache_dir`, keyed by profile + hostnames, and reused on
/// restart, so dialers' `cert_sha256` / `?cert=` pins keep working. A QUIC
/// backbone reuses its 10-year cert as-is; a WebTransport (browser-pinnable,
/// 13-day) cert is re-issued from the same key near expiry. Changing
/// `hostnames` mints a new key and cert.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SelfSignedDevConfig {
    #[serde(default = "default_cert_hostnames")]
    pub hostnames: Vec<String>,
    /// Directory for the persisted key + cert (files written `0600`). Absent =
    /// `$XDG_STATE_HOME/ndn-fwd/tls`, else `~/.local/state/ndn-fwd/tls`. Give
    /// each node on a shared host its own directory to keep pins distinct.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_dir: Option<String>,
}

impl Default for SelfSignedDevConfig {
    fn default() -> Self {
        Self {
            hostnames: default_cert_hostnames(),
            cache_dir: None,
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
/// `DvInsecure`, matching ndnd's `KeyChainUri = "insecure"` mode.
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
        reject_legacy_sections(&expanded)?;
        let cfg: ForwarderConfig = toml::from_str(&expanded)?;
        cfg.validate()?;
        Ok(cfg)
    }
}

/// Refuse sections that were renamed, rather than silently ignoring them (an
/// unknown section deserializes to nothing, which would leave the CA off).
fn reject_legacy_sections(toml_src: &str) -> Result<(), ConfigError> {
    if !toml_src.contains("demo_ca") {
        return Ok(());
    }
    let table: toml::Table = toml::from_str(toml_src)?;
    if table.contains_key("demo_ca") {
        return Err(ConfigError::Invalid(
            "the `[demo_ca]` section was renamed to `[ca]` (it is the namespace's PIB-backed \
             CA, not a demo): rename `[demo_ca]` to `[ca]` and `[[demo_ca.challenge]]` / \
             `[demo_ca.require_attestation]` to `[[ca.challenge]]` / \
             `[ca.require_attestation]`; the keys are unchanged"
                .into(),
        ));
    }
    Ok(())
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
            if let Some(FaceConfig::Quic { .. }) = self.faces.get(route.face) {
                return Err(ConfigError::Invalid(format!(
                    "[[route]] {} names [[face]] #{} (kind \"quic\"), which is this device's \
                     link socket rather than a link: put routes over a link in its [[peer]] routes",
                    route.prefix, route.face
                )));
            }
        }

        let quic_sockets: Vec<bool> = self
            .faces
            .iter()
            .filter_map(|f| match f {
                FaceConfig::Quic { listen, .. } => Some(*listen),
                _ => None,
            })
            .collect();
        if quic_sockets.len() > 1 {
            return Err(ConfigError::Invalid(format!(
                "{} [[face]] entries of kind \"quic\": a device has one link socket, which \
                 listens and dials (bind \"[::]:6367\" to take both IPv4 and IPv6)",
                quic_sockets.len()
            )));
        }
        if quic_sockets == [false]
            && !self.peers.iter().any(|p| !p.endpoint.is_empty())
            && self.user_relays.is_empty()
            && !self.relays.namespace
        {
            return Err(ConfigError::Invalid(
                "[[face]] kind = \"quic\" with listen = false only dials, and nothing is there to \
                 dial: no [[peer]] has an endpoint, no [[relay]] is configured and [relays] \
                 namespace = false; give a [[peer]] an endpoint, add a [[relay]], set [relays] \
                 namespace = true, or set listen = true to accept links"
                    .into(),
            ));
        }
        validate_peers(&self.peers, &self.user_relays)?;
        validate_relays(&self.user_relays, &self.peers)?;
        self.relays.validate()?;
        self.relay_service.validate()?;
        self.links.validate()?;
        self.direct.validate()?;
        self.ca.validate()?;

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
        FaceConfig::Quic { bind, advertise, .. } => {
            bind.parse::<std::net::SocketAddr>().map_err(|_| {
                ConfigError::Invalid(format!(
                    "[[face]] kind = \"quic\": bind must be an address and port such as \
                     \"0.0.0.0:6367\", not {bind:?}"
                ))
            })?;
            for addr in advertise {
                let port = addr.rsplit_once(':').map(|(host, p)| (host, p.parse::<u16>()));
                if !matches!(port, Some((host, Ok(p))) if p != 0 && !host.is_empty()) {
                    return Err(ConfigError::Invalid(format!(
                        "[[face]] kind = \"quic\": advertise entries must be the public host:port \
                         that reaches this socket, such as \"203.0.113.7:6367\", not {addr:?}"
                    )));
                }
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
        FaceConfig::Radio { radios } => {
            if radios.is_empty() {
                return Err(ConfigError::Invalid(
                    "radio face must declare at least one radio capability".into(),
                ));
            }
            for r in radios {
                if r.driver.is_empty() {
                    return Err(ConfigError::Invalid(
                        "radio capability driver must not be empty".into(),
                    ));
                }
                if matches!(r.driver.as_str(), "af-packet" | "halow") && r.interface.is_none() {
                    return Err(ConfigError::Invalid(format!(
                        "radio driver {:?} requires an interface",
                        r.driver
                    )));
                }
            }
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
    /// Cache Data that no validator ever checked, i.e. when `[security]
    /// profile = "disabled"` leaves nothing to validate with.
    ///
    /// Default `false` preserves ndn-rs's fail-secure invariant, which is
    /// deliberately stricter than NFD: with no validator, network Data is
    /// forwarded but never cached (ARCHITECTURE.md, test D.12).
    ///
    /// Set `true` ONLY where trust is enforced above the forwarder. The cost
    /// of leaving it false in that situation is a Content Store that admits
    /// nothing: measured 0.17% hit rate and 37 retained entries against NFD's
    /// 7.33% and 12033 on the same workload. Data that a validator ran and
    /// REJECTED is never cached at either setting.
    #[serde(default)]
    pub admit_unverified: bool,
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
            admit_unverified: false,
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
    /// This device's QUIC link socket: it listens for links from other
    /// devices, and `[[peer]]` links are dialled from it, so the other
    /// device sees this one at `bind`. Who may link is decided by the
    /// devices' keys, not by this entry: see [`PeerConfig`].
    Quic {
        /// Address and UDP port, e.g. `0.0.0.0:6367`. A dial-only device
        /// (`listen = false`) picks its source address here; port `0` lets
        /// the system choose the port.
        bind: String,
        /// Accept links from other devices. `false`: the socket only dials
        /// the `[[peer]]` endpoints, from `bind`. Without any quic
        /// `[[face]]`, a device dials from an address the system picks.
        #[serde(default = "default_true")]
        listen: bool,
        /// Public `host:port` addresses that reach this socket (port
        /// forwards), offered to linked devices as direct-path candidates
        /// besides the addresses the device learns by itself.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        advertise: Vec<String>,
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
    /// **The wireless medium as one face.** Unlike every other kind — each a link
    /// to one peer — a radio face is the shared broadcast neighbourhood, and a node
    /// reaches it through one or more *radio capabilities* (`radios`). Adding a
    /// second radio is an added capability on the *same* face, never a new face:
    /// RX unions across all radios and TX fans out (diversity on a broadcast
    /// medium); the cognitive control plane decides per-frame rate/power and, with
    /// >1 radio, which carry each transmission. Requires `ndn-fwd` built with the
    /// > `radio` feature; USB Wi-Fi drivers additionally need `radio-libusb` (Linux).
    Radio {
        /// The radio capabilities bound into this medium (≥1).
        radios: Vec<RadioDeviceConfig>,
    },
}

/// One radio capability bound into a [`FaceConfig::Radio`] medium.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RadioDeviceConfig {
    /// Driver backend selecting how frames reach the air:
    /// - `"rtl8822e"` / `"rtl8812au"` — userspace USB Wi-Fi (needs `radio-libusb`, Linux),
    /// - `"af-packet"` — a kernel monitor-mode interface (Linux; set `interface`),
    /// - `"halow"` — an 802.11ah/S1G monitor interface (Linux; set `interface`).
    pub driver: String,
    /// Channel to tune (driver-interpreted; e.g. `149` for 5 GHz Wi-Fi). Optional
    /// for `af-packet`, where the interface is pre-tuned out of band.
    #[serde(default)]
    pub channel: Option<u8>,
    /// Monitor-mode interface name for `af-packet` / `halow` (e.g. `"halow0"`).
    #[serde(default)]
    pub interface: Option<String>,
    /// Optional initial TX-power index (driver-specific; 0..=0x3f for Realtek).
    #[serde(default, rename = "tx-power")]
    pub tx_power: Option<u8>,
    /// **Which physical device**, when the driver could bind several — a backend-agnostic selector
    /// each driver interprets in its own terms, so the config schema bakes in no one bus. The radio
    /// is just a backend behind this string:
    /// - Realtek USB (`rtl8822e` / `rtl8812au`): a USB selector — `"1-1.4"` (a stable bus\:port,
    ///   matching the Linux sysfs device path and surviving reboots), or `"#<n>"` (enumeration index,
    ///   simpler but not stable across reboots/hotplug).
    /// - serial backends: a device path (e.g. `"/dev/ttyACM0"`).
    ///
    /// `af-packet` / `halow` select by netdev name via [`interface`](Self::interface) instead. Unset
    /// ⇒ the driver's default (the first device it finds). The main use: a host with two identical
    /// dongles pins the spare here and leaves the kernel link on the other.
    #[serde(default)]
    pub address: Option<String>,
    /// Optional **static** Wi-Fi rate ceilings for this radio, clamping the driver's own capability
    /// (they can only *lower* it). `max-mcs` caps the HT/VHT MCS index (0..=9), `max-nss` the spatial
    /// stream count (1 or 2). Cognition reads these as the radio's ceiling, so they cap the *transmit*
    /// rate declaratively — e.g. pin an `af-packet` TX to single-stream ≤ MCS 7 for a peer known to
    /// have one RX chain, independent of (and before) that peer's advertised reception report. Unset
    /// ⇒ the driver default. (The dynamic worst-overheard-receiver cap still applies on top.)
    #[serde(default, rename = "max-mcs")]
    pub max_mcs: Option<u8>,
    #[serde(default, rename = "max-nss")]
    pub max_nss: Option<u8>,
}

fn default_baud() -> u32 {
    115200
}

/// One `[[peer]]`: a device this one links to over QUIC, or lets link in,
/// identified by its key — never by an address or a TLS certificate.
///
/// A peer is named by its device name (`device`, resolved to a key by the
/// certificate it presents, valid in a namespace this device holds), by its
/// expected fingerprint (`key`, for a device of another namespace or before
/// adoption), or both. With an `endpoint` this device dials it; without one
/// it is reached through `relay`, or it dials in.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    /// Expected fingerprint of the peer's key: 64 hex digits, the SHA-256
    /// of its public key (what `ndn-fwd` prints as this device's link key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// The peer's device name, `/<namespace>/<role>/<device>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// Where to dial it: `host:port`, or a list of them tried in order.
    #[serde(
        default,
        deserialize_with = "one_or_many",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub endpoint: Vec<String>,
    /// Reach this peer through the link to another `[[peer]]` (its `device`
    /// or `key`): the relay forwards between the two links.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
    /// Prefixes routed to this peer. Unset: the peer's namespace when it is a
    /// relay (a `node` device), else its device name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routes: Option<Vec<String>>,
    /// Keep the link up: dial again, with backoff, whenever it drops.
    #[serde(default = "default_true")]
    pub persistent: bool,
    /// NDNLPv2 reliability (retransmission of lost frames) on this link.
    #[serde(default)]
    pub reliability: bool,
    /// Try a direct path to this peer when it is reached through a relay
    /// (and the namespace's link policy allows direct paths). `false`:
    /// always go through the relay.
    #[serde(default = "default_true")]
    pub direct: bool,
    /// When the link is up: `always`, `on-demand` or `off`. See
    /// [`LinkModeConfig`].
    #[serde(default)]
    pub mode: LinkModeConfig,
    /// With `mode = "on-demand"`: close the link after this many seconds
    /// without traffic (10..=86400).
    #[serde(default = "default_idle_secs")]
    pub idle_secs: u64,
    /// Ask this peer (a relay) to hold Interests for this device while its
    /// link is asleep, and deliver them when it is back.
    #[serde(default)]
    pub hold: bool,
    /// Opaque token (UTF-8, at most 1024 bytes) registered with this peer
    /// (a relay) to wake this device when Interests arrive while it is
    /// asleep, e.g. a platform push token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wake_token: Option<String>,
}

impl PeerConfig {
    /// How the config refers to this peer in messages and in `relay`.
    pub fn label(&self) -> String {
        self.device
            .clone()
            .or_else(|| self.key.clone())
            .unwrap_or_default()
    }

    /// Whether `reference` (a `relay` value) names this peer.
    pub fn is_named(&self, reference: &str) -> bool {
        self.device.as_deref() == Some(reference)
            || self
                .key
                .as_deref()
                .is_some_and(|k| k.eq_ignore_ascii_case(reference))
    }
}

fn default_true() -> bool {
    true
}

fn one_or_many<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    Ok(match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(s) => vec![s],
        OneOrMany::Many(v) => v,
    })
}

fn validate_peers(peers: &[PeerConfig], relays: &[RelayConfig]) -> Result<(), ConfigError> {
    let invalid = |peer: &PeerConfig, why: String| {
        ConfigError::Invalid(format!("[[peer]] {}: {why}", peer.label()))
    };
    for (i, peer) in peers.iter().enumerate() {
        if peer.key.is_none() && peer.device.is_none() {
            return Err(ConfigError::Invalid(format!(
                "[[peer]] #{}: name the device (device = \"/<namespace>/<role>/<device>\") or its \
                 expected fingerprint (key = \"<64 hex digits>\")",
                i + 1
            )));
        }
        check_identity(peer.key.as_deref(), peer.device.as_deref())
            .and_then(|()| check_endpoints(&peer.endpoint))
            .and_then(|()| check_mode(peer.mode, peer.idle_secs, peer.wake_token.as_deref()))
            .map_err(|why| invalid(peer, why))?;
        for route in peer.routes.iter().flatten() {
            if route.parse::<ndn_packet::Name>().is_err() || !route.starts_with('/') {
                return Err(invalid(peer, format!("route {route:?} is not an NDN name")));
            }
        }
        if let Some(relay) = &peer.relay {
            match peers.iter().find(|p| !std::ptr::eq(*p, peer) && p.is_named(relay)) {
                Some(r) if r.endpoint.is_empty() => {
                    return Err(invalid(
                        peer,
                        format!("relay {relay:?} has no endpoint, so this device cannot reach it"),
                    ));
                }
                Some(_) => {}
                None if relays.iter().any(|r| r.is_named(relay)) => {}
                None => {
                    return Err(invalid(
                        peer,
                        format!(
                            "relay {relay:?} is not the device or key of another [[peer]] or of a \
                             [[relay]]; add it as one of those, or fix the reference"
                        ),
                    ));
                }
            }
        }
        if let Some(other) = peers[..i]
            .iter()
            .find(|p| same_device(p.key.as_deref(), p.device.as_deref(), peer.key.as_deref(), peer.device.as_deref()))
        {
            return Err(invalid(
                peer,
                format!("names the same device as [[peer]] {}; merge the two", other.label()),
            ));
        }
    }
    Ok(())
}

/// `[[relay]]` entries: each identified, reachable, and distinct from every
/// other `[[relay]]` and `[[peer]]` (one device is one link).
fn validate_relays(relays: &[RelayConfig], peers: &[PeerConfig]) -> Result<(), ConfigError> {
    for (i, relay) in relays.iter().enumerate() {
        let invalid = |why: String| ConfigError::Invalid(format!("[[relay]] {}: {why}", relay.label()));
        if relay.key.is_none() && relay.device.is_none() {
            return Err(ConfigError::Invalid(format!(
                "[[relay]] #{}: give the relay's expected fingerprint (key = \"<64 hex digits>\"); \
                 device = \"/<namespace>/node/<device>\" alone is enough only for a relay of a \
                 namespace this device holds",
                i + 1
            )));
        }
        if relay.endpoint.is_empty() {
            return Err(invalid(
                "has no endpoint, so this device cannot reach it: add endpoint = \"host:port\" \
                 (or a list tried in order)"
                    .into(),
            ));
        }
        check_identity(relay.key.as_deref(), relay.device.as_deref())
            .and_then(|()| check_endpoints(&relay.endpoint))
            .and_then(|()| check_mode(relay.mode, relay.idle_secs, relay.wake_token.as_deref()))
            .map_err(invalid)?;
        let same = |key: Option<&str>, device: Option<&str>| {
            same_device(key, device, relay.key.as_deref(), relay.device.as_deref())
        };
        if let Some(other) = relays[..i].iter().find(|r| same(r.key.as_deref(), r.device.as_deref())) {
            return Err(invalid(format!(
                "names the same device as [[relay]] {}; merge the two",
                other.label()
            )));
        }
        if let Some(peer) = peers.iter().find(|p| same(p.key.as_deref(), p.device.as_deref())) {
            return Err(invalid(format!(
                "names the same device as [[peer]] {}: one device is one link; keep the \
                 [[relay]] (and move that peer's routes and options to it) or the [[peer]], not both",
                peer.label()
            )));
        }
    }
    Ok(())
}

/// Whether two (key, device) identifications name the same device.
fn same_device(a_key: Option<&str>, a_device: Option<&str>, b_key: Option<&str>, b_device: Option<&str>) -> bool {
    (a_device.is_some() && a_device == b_device)
        || a_key.zip(b_key).is_some_and(|(a, b)| a.eq_ignore_ascii_case(b))
}

fn check_identity(key: Option<&str>, device: Option<&str>) -> Result<(), String> {
    if let Some(key) = key
        && !is_fingerprint(key)
    {
        return Err(format!(
            "key must be the 64 hex digits of the device's fingerprint, not {key:?}"
        ));
    }
    if let Some(device) = device {
        let parsed = device.parse::<ndn_packet::Name>().ok();
        if !device.starts_with('/') || parsed.is_none_or(|n| n.len() < 3) {
            return Err(format!(
                "device must be a device name /<namespace>/<role>/<device>, not {device:?}"
            ));
        }
    }
    Ok(())
}

fn is_fingerprint(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn check_endpoints(endpoints: &[String]) -> Result<(), String> {
    for endpoint in endpoints {
        let port = endpoint.rsplit_once(':').map(|(_, p)| p.parse::<u16>());
        if !matches!(port, Some(Ok(p)) if p != 0) {
            return Err(format!(
                "endpoint must be host:port, such as \"relay.example.net:6367\", not {endpoint:?}"
            ));
        }
    }
    Ok(())
}

fn check_mode(mode: LinkModeConfig, idle_secs: u64, wake_token: Option<&str>) -> Result<(), String> {
    if mode == LinkModeConfig::OnDemand && !IDLE_SECS.contains(&idle_secs) {
        return Err(format!(
            "idle_secs = {idle_secs} is outside {}..={}: below that an on-demand link closes \
             between the packets of one exchange, above it stays open for a day; pick a value in range",
            IDLE_SECS.start(),
            IDLE_SECS.end()
        ));
    }
    if let Some(token) = wake_token
        && !(1..=MAX_WAKE_TOKEN).contains(&token.len())
    {
        return Err(format!(
            "wake_token is {} bytes; a relay keeps 1..={MAX_WAKE_TOKEN} bytes: remove the key \
             to register none, or shorten the token",
            token.len()
        ));
    }
    Ok(())
}

/// Bounds of an on-demand link's idle close, in seconds.
const IDLE_SECS: std::ops::RangeInclusive<u64> = 10..=86_400;
/// Longest wake token a relay keeps, in bytes.
const MAX_WAKE_TOKEN: usize = 1024;

fn default_idle_secs() -> u64 {
    60
}

/// When a link is up.
///
/// - `always`: linked all the time; a keep-alive every
///   `[links] keep_alive_secs` keeps NAT bindings — and the radio — awake.
/// - `on-demand`: closed until there is traffic for it (or the host says it
///   is active); closed again after `idle_secs` without traffic. The first
///   Interest waits for the handshake.
/// - `off`: configured but closed until asked (`ndn-ctl link connect`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LinkModeConfig {
    #[default]
    Always,
    OnDemand,
    Off,
}

/// `[relays]`: how this device uses relays.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelaysConfig {
    /// Relays linked at once, preferred first (1..=8); the rest stand by
    /// and take over when one is lost.
    #[serde(default = "default_relay_count")]
    pub count: usize,
    /// Use the relays the namespace advertises in its trust context.
    #[serde(default = "default_true")]
    pub namespace: bool,
    /// Link mode of the namespace's relays.
    #[serde(default)]
    pub mode: LinkModeConfig,
    /// With `mode = "on-demand"`: idle close, in seconds (10..=86400).
    #[serde(default = "default_idle_secs")]
    pub idle_secs: u64,
    /// Ask the namespace's relays to hold Interests while this device is
    /// asleep.
    #[serde(default)]
    pub hold: bool,
}

fn default_relay_count() -> usize {
    1
}

impl Default for RelaysConfig {
    fn default() -> Self {
        Self {
            count: default_relay_count(),
            namespace: true,
            mode: LinkModeConfig::default(),
            idle_secs: default_idle_secs(),
            hold: false,
        }
    }
}

impl RelaysConfig {
    /// Most relays linked at once.
    pub const MAX_COUNT: usize = 8;

    fn validate(&self) -> Result<(), ConfigError> {
        let invalid = |why: String| ConfigError::Invalid(format!("[relays] {why}"));
        if !(1..=Self::MAX_COUNT).contains(&self.count) {
            return Err(invalid(format!(
                "count = {} is outside 1..={}: at least one relay is linked when any is known \
                 (set namespace = false and add no [[relay]] for none), and more than {} only \
                 costs keep-alives",
                self.count,
                Self::MAX_COUNT,
                Self::MAX_COUNT
            )));
        }
        check_mode(self.mode, self.idle_secs, None).map_err(invalid)
    }
}

/// One `[[relay]]`: a relay the user adds (own server, community relay,
/// hosted service), identified by its key and dialled at its endpoints.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    /// Expected fingerprint of the relay's key (64 hex digits). Required
    /// unless `device` is a device of a namespace this device holds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// The relay's device name, `/<namespace>/node/<device>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// Where to dial it: `host:port`, or a list tried in order.
    #[serde(default, deserialize_with = "one_or_many")]
    pub endpoint: Vec<String>,
    /// Lower is preferred; on a tie user relays come before the
    /// namespace's.
    #[serde(default)]
    pub preference: u32,
    /// Link mode; see [`LinkModeConfig`].
    #[serde(default)]
    pub mode: LinkModeConfig,
    /// With `mode = "on-demand"`: idle close, in seconds (10..=86400).
    #[serde(default = "default_idle_secs")]
    pub idle_secs: u64,
    /// Ask this relay to hold Interests while this device is asleep.
    #[serde(default)]
    pub hold: bool,
    /// Opaque wake token (UTF-8, at most 1024 bytes) registered with this
    /// relay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wake_token: Option<String>,
}

impl RelayConfig {
    /// How the config refers to this relay in messages and in `[[peer]] relay`.
    pub fn label(&self) -> String {
        self.device
            .clone()
            .or_else(|| self.key.clone())
            .unwrap_or_default()
    }

    /// Whether `reference` (a `[[peer]] relay` value) names this relay.
    pub fn is_named(&self, reference: &str) -> bool {
        self.device.as_deref() == Some(reference)
            || self
                .key
                .as_deref()
                .is_some_and(|k| k.eq_ignore_ascii_case(reference))
    }
}

/// Which namespaces a relay serves (`[relay_service] serve`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServeConfig {
    /// Devices of namespaces this device holds a certificate in.
    #[default]
    Own,
    /// Those, plus namespaces whose root key fingerprint is in `roots`.
    Listed,
    /// Any namespace whose certificate chain validates to its root, within
    /// the quotas.
    Open,
}

/// Per-relay quotas for devices of other namespaces (rates per second,
/// burst twice that).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotasConfig {
    pub links_total: usize,
    pub links_per_namespace: usize,
    pub interests_per_key: u32,
    pub interests_per_namespace: u32,
}

impl Default for QuotasConfig {
    fn default() -> Self {
        Self {
            links_total: 256,
            links_per_namespace: 32,
            interests_per_key: 100,
            interests_per_namespace: 400,
        }
    }
}

/// `[relay_service]`: what this device does as a relay for others.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelayServiceConfig {
    /// `own` (default), `listed` or `open`; see [`ServeConfig`].
    #[serde(default)]
    pub serve: ServeConfig,
    /// With `serve = "listed"`: root key fingerprints (64 hex digits) of the
    /// namespaces served besides this device's own.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roots: Vec<String>,
    /// Quotas: always in force for `open` (defaults 256, 32, 100, 400);
    /// for `listed` only when one is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub links_total: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub links_per_namespace: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interests_per_key: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interests_per_namespace: Option<u32>,
    /// Hold Interests for sleeping devices that ask (within the bounds
    /// below).
    #[serde(default)]
    pub hold: bool,
    #[serde(default = "default_hold_per_device")]
    pub hold_per_device: usize,
    #[serde(default = "default_hold_total")]
    pub hold_total: usize,
    /// Longest an Interest is held, in seconds (never past its lifetime).
    #[serde(default = "default_hold_secs")]
    pub hold_secs: u64,
    /// How long a device that went asleep counts as asleep (held for,
    /// woken), in seconds.
    #[serde(default = "default_asleep_secs")]
    pub asleep_secs: u64,
    /// Program (and arguments) run once per wake, with env
    /// `NDN_WAKE_TOKEN` (hex), `NDN_WAKE_DEVICE` (name, or empty),
    /// `NDN_WAKE_KEY` (fingerprint hex), `NDN_WAKE_HELD` (count).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wake_command: Option<Vec<String>>,
}

fn default_hold_per_device() -> usize {
    64
}
fn default_hold_total() -> usize {
    4096
}
fn default_hold_secs() -> u64 {
    60
}
fn default_asleep_secs() -> u64 {
    86_400
}

impl Default for RelayServiceConfig {
    fn default() -> Self {
        Self {
            serve: ServeConfig::default(),
            roots: Vec::new(),
            links_total: None,
            links_per_namespace: None,
            interests_per_key: None,
            interests_per_namespace: None,
            hold: false,
            hold_per_device: default_hold_per_device(),
            hold_total: default_hold_total(),
            hold_secs: default_hold_secs(),
            asleep_secs: default_asleep_secs(),
            wake_command: None,
        }
    }
}

impl RelayServiceConfig {
    fn any_quota(&self) -> bool {
        self.links_total.is_some()
            || self.links_per_namespace.is_some()
            || self.interests_per_key.is_some()
            || self.interests_per_namespace.is_some()
    }

    /// The quotas in force: `open` always, `listed` when any is set (unset
    /// ones take the default), `own` never.
    pub fn quotas(&self) -> Option<QuotasConfig> {
        let on = match self.serve {
            ServeConfig::Own => false,
            ServeConfig::Listed => self.any_quota(),
            ServeConfig::Open => true,
        };
        on.then(|| {
            let d = QuotasConfig::default();
            let links_total = self.links_total.unwrap_or(d.links_total);
            QuotasConfig {
                links_total,
                // An unset share never exceeds a smaller total that was set.
                links_per_namespace: self
                    .links_per_namespace
                    .unwrap_or(d.links_per_namespace.min(links_total)),
                interests_per_key: self.interests_per_key.unwrap_or(d.interests_per_key),
                interests_per_namespace: self
                    .interests_per_namespace
                    .unwrap_or(d.interests_per_namespace),
            }
        })
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let invalid = |why: String| ConfigError::Invalid(format!("[relay_service] {why}"));
        match self.serve {
            ServeConfig::Listed if self.roots.is_empty() => {
                return Err(invalid(
                    "serve = \"listed\" serves the namespaces in roots, and roots is empty: list \
                     their root key fingerprints, or use serve = \"own\""
                        .into(),
                ));
            }
            ServeConfig::Own | ServeConfig::Open if !self.roots.is_empty() => {
                return Err(invalid(
                    "roots is used only with serve = \"listed\" (\"own\" serves this device's \
                     namespaces, \"open\" every namespace): set serve = \"listed\" or remove roots"
                        .into(),
                ));
            }
            ServeConfig::Own if self.any_quota() => {
                return Err(invalid(
                    "quotas limit devices of other namespaces, and serve = \"own\" serves none: \
                     remove them, or set serve = \"listed\" or \"open\""
                        .into(),
                ));
            }
            _ => {}
        }
        if let Some(root) = self.roots.iter().find(|r| !is_fingerprint(r)) {
            return Err(invalid(format!(
                "roots entries must be the 64 hex digits of a namespace's root key fingerprint, \
                 not {root:?}"
            )));
        }
        if let Some(q) = self.quotas() {
            if q.links_total == 0 || q.links_per_namespace == 0 || q.links_per_namespace > q.links_total {
                return Err(invalid(format!(
                    "links_per_namespace = {} with links_total = {}: both must be at least 1 and \
                     one namespace cannot have more links than the total",
                    q.links_per_namespace, q.links_total
                )));
            }
            if q.interests_per_key == 0 || q.interests_per_namespace == 0 {
                return Err(invalid(
                    "interests_per_key and interests_per_namespace must be at least 1 Interest \
                     per second: 0 would admit links that can send nothing; to serve no other \
                     namespace use serve = \"own\""
                        .into(),
                ));
            }
        }
        if self.hold_per_device == 0 || self.hold_total < self.hold_per_device {
            return Err(invalid(format!(
                "hold_per_device = {} with hold_total = {}: a device needs room for at least one \
                 Interest, and the total must fit one device's share",
                self.hold_per_device, self.hold_total
            )));
        }
        if !(1..=3600).contains(&self.hold_secs) {
            return Err(invalid(format!(
                "hold_secs = {} is outside 1..=3600: an Interest is never held past its lifetime, \
                 and Interests live far less than an hour",
                self.hold_secs
            )));
        }
        if !(60..=604_800).contains(&self.asleep_secs) {
            return Err(invalid(format!(
                "asleep_secs = {} is outside 60..=604800 (one minute to one week): a device asleep \
                 longer is treated as gone",
                self.asleep_secs
            )));
        }
        if let Some(command) = &self.wake_command
            && command.first().is_none_or(|program| program.trim().is_empty())
        {
            return Err(invalid(
                "wake_command must start with the program to run, as in wake_command = \
                 [\"/usr/local/bin/notify\", \"arg\"]; remove the key to wake no one"
                    .into(),
            ));
        }
        Ok(())
    }
}

/// `[links]`: timing of every link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinksConfig {
    /// Seconds between keep-alives on an idle link (2..=60).
    #[serde(default = "default_keep_alive_secs")]
    pub keep_alive_secs: u64,
    /// Seconds of silence after which a link counts as lost
    /// (≥ 3 × keep_alive_secs, ≤ 600).
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
}

fn default_keep_alive_secs() -> u64 {
    10
}
fn default_idle_timeout_secs() -> u64 {
    30
}

impl Default for LinksConfig {
    fn default() -> Self {
        Self {
            keep_alive_secs: default_keep_alive_secs(),
            idle_timeout_secs: default_idle_timeout_secs(),
        }
    }
}

impl LinksConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        let k = self.keep_alive_secs;
        let t = self.idle_timeout_secs;
        if !(2..=60).contains(&k) {
            return Err(ConfigError::Invalid(format!(
                "[links] keep_alive_secs = {k} is outside 2..=60: faster wastes battery and data, \
                 slower lets NAT bindings (often 30–120 s) expire so the peer can no longer reach \
                 this device"
            )));
        }
        if t < 3 * k || t > 600 {
            return Err(ConfigError::Invalid(format!(
                "[links] idle_timeout_secs = {t} must be at least 3 × keep_alive_secs ({}) so \
                 two lost keep-alives do not drop the link, and at most 600 so a dead link is \
                 noticed",
                3 * k
            )));
        }
        Ok(())
    }
}

/// `[direct]`: direct paths made by membership.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DirectConfig {
    /// Try direct paths with devices of this device's namespace met at a
    /// common relay, where the trust context's role matrix allows them.
    #[serde(default = "default_true")]
    pub membership: bool,
    /// Most direct paths kept at once (1..=64).
    #[serde(default = "default_max_paths")]
    pub max_paths: usize,
}

fn default_max_paths() -> usize {
    8
}

impl Default for DirectConfig {
    fn default() -> Self {
        Self { membership: true, max_paths: default_max_paths() }
    }
}

impl DirectConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if !(1..=64).contains(&self.max_paths) {
            return Err(ConfigError::Invalid(format!(
                "[direct] max_paths = {} is outside 1..=64: each path costs keep-alives; for no \
                 direct paths by membership set membership = false",
                self.max_paths
            )));
        }
        Ok(())
    }
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

/// One `[[strategy]]` entry: the forwarding strategy to install for a name
/// prefix at startup, equivalent to a `strategy-choice/set` command.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StrategyConfig {
    pub prefix: String,
    /// NFD-style strategy name, either fully qualified
    /// (`/localhost/nfd/strategy/multicast`, optionally with a `/v=N`
    /// version) or the bare registry short name (`multicast`).
    pub strategy: String,
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

/// How management commands are authenticated. On the local Unix socket the
/// kernel's peer credentials authenticate the caller: the daemon's user,
/// root, and members of `[security] trust_admin_groups` are accepted
/// without a signature. Every other caller must sign.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MgmtSecurityConfig {
    /// When `true` (default), a command from anyone but a local operator
    /// (see above) must carry a key-backed signature that passes the
    /// validator loaded from `trust_anchor_pib`; DigestSha256-only or
    /// unsigned commands are rejected 403. `false` accepts unsigned
    /// commands of the standard NFD modules (`faces`, `fib`, `rib`, `cs`,
    /// `strategy-choice`, `status`) from any caller; the ndn-rs extension
    /// modules (e.g. `security`) still need a local operator or a signature.
    #[serde(default = "default_require_signed_commands")]
    pub require_signed_commands: bool,

    /// PIB whose anchors verify signed commands. Unset: only local
    /// operators can issue commands. ndn-fwd aborts at startup if it is set
    /// but unreadable or empty.
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    /// Identity name (e.g. `/home/bob/router`); its signing key is the one
    /// stored under `<identity>/KEY/` in the PIB, which must exist unless
    /// `auto_init`.
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

    /// Auto-generate a key `<identity>/KEY/<random key-id>` with a signed
    /// self-signed certificate `<key>/self/<version>` on startup if the PIB
    /// holds no key for `identity`. Requires `identity`.
    #[serde(default)]
    pub auto_init: bool,

    /// `"default"` (full chain validation), `"accept-signed"` (signature
    /// only, no chain walk), or `"disabled"` (no validation; implies
    /// `validator_enabled = false`). Default `"default"` when the `[security]`
    /// table is present. When it is absent entirely, `SecurityConfig::default()`
    /// applies, whose `validator_enabled` is `false`: Data is NOT validated.
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

    /// Publish every trust context stored in `<pib_path>/contexts/` (the
    /// node's own namespace context included) by name over RDR:
    /// `/<ns>/32=trust-context/32=metadata` → the newest version's name,
    /// `/<ns>/32=trust-context/v=<N>` → the stored signed Data verbatim.
    /// Contexts are public (anchors, schema, CA endpoints); default `true`.
    #[serde(default = "default_serve_contexts")]
    pub serve_contexts: bool,

    /// Unix groups whose members are local operators on the management
    /// socket, in addition to the daemon's own user and root: they may
    /// change this node's trust (e.g. `security/context-adopt`) and issue
    /// any other command without a signature. Empty (default) = only the
    /// daemon's user and root.
    #[serde(default)]
    pub trust_admin_groups: Vec<String>,

    /// How often, in seconds, the daemon checks each trust context it holds
    /// for a newer version (`/<ns>/32=trust-context/32=metadata`, fetched
    /// upstream) and adopts one signed by the held version's root — how a
    /// revocation reaches this node. `0` disables the periodic check
    /// (`ndn-fwd context refresh` still works). A missed check only delays
    /// an update; it never weakens what is accepted. Default 300.
    #[serde(default = "default_context_refresh_secs")]
    pub context_refresh_secs: u64,

    /// Also join each held namespace's trust-context sync group
    /// (`/<ns>/32=trust-context/32=sync`, SVS), so a new version reaches
    /// this node as soon as the root device makes it instead of at the next
    /// refresh; the root device puts every new version into the group. An
    /// update arriving this way is adopted under the same rule as a
    /// refreshed one. The refresh keeps running beside it. Default `false`.
    #[serde(default)]
    pub context_sync: bool,

    /// When this node renews its certificates: once the remaining validity
    /// falls below this. A number between 0 and 1 is a fraction of the
    /// certificate's lifetime (default `0.333`: a 90-day certificate renews
    /// with 30 days left); a string `"<n>d"`, `"<n>h"`, `"<n>m"` or `"<n>s"`
    /// is a fixed time before expiry; `0` turns the automatic renewal off
    /// (`ndn-fwd renew` still works). Failed attempts are retried with a
    /// growing backoff and logged with the days remaining.
    #[serde(default)]
    pub renew_before: RenewBeforeConfig,
}

fn default_serve_contexts() -> bool {
    true
}

fn default_context_refresh_secs() -> u64 {
    300
}

/// [`SecurityConfig::renew_before`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RenewBeforeConfig {
    /// No automatic renewal.
    Off,
    /// A fraction (`0 < f < 1`) of the certificate's lifetime.
    Fraction(f64),
    /// A fixed time before expiry.
    Before(std::time::Duration),
}

impl Default for RenewBeforeConfig {
    fn default() -> Self {
        Self::Fraction(1.0 / 3.0)
    }
}

impl RenewBeforeConfig {
    /// Parse `"<n>d"`, `"<n>h"`, `"<n>m"` or `"<n>s"`.
    fn parse_duration(s: &str) -> Option<std::time::Duration> {
        let s = s.trim();
        let unit = s.chars().last()?;
        let n: u64 = s[..s.len() - unit.len_utf8()].trim().parse().ok()?;
        let secs = match unit {
            'd' => n.checked_mul(86_400)?,
            'h' => n.checked_mul(3_600)?,
            'm' => n.checked_mul(60)?,
            's' => n,
            _ => return None,
        };
        (secs > 0).then(|| std::time::Duration::from_secs(secs))
    }
}

impl Serialize for RenewBeforeConfig {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Off => s.serialize_u8(0),
            Self::Fraction(f) => s.serialize_f64(*f),
            Self::Before(d) => s.serialize_str(&format!("{}s", d.as_secs())),
        }
    }
}

impl<'de> Deserialize<'de> for RenewBeforeConfig {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = RenewBeforeConfig;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str(
                    "a fraction of the certificate lifetime between 0 and 1 (e.g. 0.333), a time \
                     before expiry such as \"30d\", \"12h\", \"10m\" or \"90s\", or 0 (off)",
                )
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Self::Value, E> {
                if v == 0.0 {
                    Ok(RenewBeforeConfig::Off)
                } else if v > 0.0 && v < 1.0 {
                    Ok(RenewBeforeConfig::Fraction(v))
                } else {
                    Err(E::invalid_value(serde::de::Unexpected::Float(v), &self))
                }
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                if v == 0 {
                    Ok(RenewBeforeConfig::Off)
                } else {
                    Err(E::invalid_value(serde::de::Unexpected::Signed(v), &self))
                }
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                self.visit_i64(i64::try_from(v).unwrap_or(i64::MAX))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                RenewBeforeConfig::parse_duration(v)
                    .map(RenewBeforeConfig::Before)
                    .ok_or_else(|| E::invalid_value(serde::de::Unexpected::Str(v), &self))
            }
        }
        d.deserialize_any(Visitor)
    }
}

/// An absent `[security]` block: zero values, except `serve_contexts`,
/// `context_refresh_secs` and `renew_before`, which default as they do in
/// TOML.
impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            identity: None,
            pib_path: None,
            trust_anchor: None,
            require_signed: false,
            auto_init: false,
            profile: String::new(),
            validator_enabled: false,
            ca_prefix: None,
            ca_info: String::new(),
            ca_max_validity_days: 0,
            ca_challenges: Vec::new(),
            rules: Vec::new(),
            pib_type: String::new(),
            ephemeral_prefix: None,
            mgmt: MgmtSecurityConfig::default(),
            serve_contexts: default_serve_contexts(),
            trust_admin_groups: Vec::new(),
            context_refresh_secs: default_context_refresh_secs(),
            context_sync: false,
            renew_before: RenewBeforeConfig::default(),
        }
    }
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

    #[test]
    fn legacy_demo_ca_section_is_refused_with_rename_hint() {
        for src in ["[demo_ca]\nenabled = true\n", "[[demo_ca.challenge]]\nkind = \"nop\"\n"] {
            let err = src.parse::<ForwarderConfig>().unwrap_err().to_string();
            assert!(err.contains("renamed to `[ca]`"), "{err}");
        }
        let cfg: ForwarderConfig = "[ca]\nenabled = true\n".parse().unwrap();
        assert!(cfg.ca.enabled);
    }

    use super::*;
    use std::str::FromStr;

    /// `[ca] cert_validity_days` is one number for every role or a per-role
    /// table whose unlisted roles take `default` (90 when absent); both
    /// survive a round trip, and an unknown role is refused.
    #[test]
    fn cert_validity_days_is_a_number_or_a_per_role_table() {
        let cfg: ForwarderConfig = "[ca]\ncert_validity_days = 30\n".parse().unwrap();
        assert_eq!(cfg.ca.cert_validity_days, CertValidityDays::uniform(30));
        assert_eq!(cfg.ca.cert_validity_days.for_role("guest"), 30);

        let src = "[ca.cert_validity_days]\nmember = 1\nguest = 7\n";
        let cfg: ForwarderConfig = src.parse().unwrap();
        let days = cfg.ca.cert_validity_days;
        assert_eq!(days.for_role("member"), 1);
        assert_eq!(days.for_role("guest"), 7);
        assert_eq!(days.for_role("admin"), CaTomlConfig::DEFAULT_CERT_VALIDITY_DAYS);
        assert_eq!(days.max_days(), CaTomlConfig::DEFAULT_CERT_VALIDITY_DAYS);
        let again: ForwarderConfig = cfg.to_toml_string().unwrap().parse().unwrap();
        assert_eq!(again.ca.cert_validity_days, days);

        let cfg: ForwarderConfig = "[ca.cert_validity_days]\ndefault = 10\nnode = 20\n"
            .parse()
            .unwrap();
        assert_eq!(cfg.ca.cert_validity_days.for_role("member"), 10);
        assert_eq!(cfg.ca.cert_validity_days.max_days(), 20);

        assert!("[ca.cert_validity_days]\nfriend = 7\n".parse::<ForwarderConfig>().is_err());
        assert!("[ca]\ncert_validity_days = -1\n".parse::<ForwarderConfig>().is_err());
        let cfg: ForwarderConfig = "[ca]\n".parse().unwrap();
        assert_eq!(cfg.ca.renewable_roles, ["admin", "member", "node"]);
    }

    /// `[security] renew_before` is a lifetime fraction, a time before
    /// expiry, or 0 (off); anything else is refused.
    #[test]
    fn renew_before_is_a_fraction_a_duration_or_off() {
        let parse = |v: &str| {
            format!("[security]\nrenew_before = {v}\n")
                .parse::<ForwarderConfig>()
                .map(|c| c.security.renew_before)
        };
        assert_eq!(parse("0.25").unwrap(), RenewBeforeConfig::Fraction(0.25));
        assert_eq!(
            parse("\"2d\"").unwrap(),
            RenewBeforeConfig::Before(std::time::Duration::from_secs(2 * 86_400))
        );
        assert_eq!(
            parse("\"90s\"").unwrap(),
            RenewBeforeConfig::Before(std::time::Duration::from_secs(90))
        );
        assert_eq!(parse("0").unwrap(), RenewBeforeConfig::Off);
        for bad in ["1.5", "3", "\"soon\"", "\"0d\"", "\"5w\""] {
            assert!(parse(bad).is_err(), "accepted {bad}");
        }
        let cfg: ForwarderConfig = "[security]\n".parse().unwrap();
        assert_eq!(cfg.security.renew_before, RenewBeforeConfig::default());
    }

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
    fn parse_radio_medium_face_with_multiple_capabilities() {
        // One `kind="radio"` medium face reached through TWO radio capabilities —
        // a 5 GHz USB Wi-Fi radio and a sub-GHz HaLow monitor — on the *same* face.
        let toml = r#"
[[face]]
kind = "radio"

[[face.radios]]
driver = "rtl8822e"
channel = 149
tx-power = 40

[[face.radios]]
driver = "halow"
interface = "halow0"
channel = 161
"#;
        let cfg = ForwarderConfig::from_str(toml).unwrap();
        assert_eq!(cfg.faces.len(), 1, "one medium face");
        match &cfg.faces[0] {
            FaceConfig::Radio { radios } => {
                assert_eq!(radios.len(), 2, "two capabilities on the one medium face");
                assert_eq!(radios[0].driver, "rtl8822e");
                assert_eq!(radios[0].channel, Some(149));
                assert_eq!(radios[0].tx_power, Some(40));
                assert_eq!(radios[1].driver, "halow");
                assert_eq!(radios[1].interface.as_deref(), Some("halow0"));
            }
            other => panic!("expected a radio face, got {other:?}"),
        }
    }

    #[test]
    fn radio_face_validation_rejects_empty_and_interfaceless() {
        // A medium with no radios is meaningless.
        assert!(validate_face_config(&FaceConfig::Radio { radios: vec![] }).is_err());
        // af-packet / halow bearers need an interface.
        let no_iface = FaceConfig::Radio {
            radios: vec![RadioDeviceConfig {
                driver: "af-packet".into(),
                channel: Some(149),
                interface: None,
                tx_power: None,
                address: None,
                max_mcs: None,
                max_nss: None,
            }],
        };
        assert!(validate_face_config(&no_iface).is_err());
        // A USB radio needs no interface — valid.
        let usb = FaceConfig::Radio {
            radios: vec![RadioDeviceConfig {
                driver: "rtl8822e".into(),
                channel: Some(149),
                interface: None,
                tx_power: None,
                address: None,
                max_mcs: None,
                max_nss: None,
            }],
        };
        assert!(validate_face_config(&usb).is_ok());
    }

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
    fn strategy_choices_parse() {
        // Boot-time strategy choices must round-trip from TOML; the fleet
        // regression they exist to prevent is a restart silently dropping
        // /muas back to best-route while [[route]] entries survive.
        let toml = concat!(
            "[[strategy]]\nprefix = \"/muas\"\n",
            "strategy = \"/localhost/nfd/strategy/multicast\"\n",
            "[[strategy]]\nprefix = \"/x\"\nstrategy = \"multicast\"\n",
        );
        let cfg = ForwarderConfig::from_str(toml).unwrap();
        assert_eq!(cfg.strategies.len(), 2);
        assert_eq!(cfg.strategies[0].prefix, "/muas");
        assert_eq!(
            cfg.strategies[0].strategy,
            "/localhost/nfd/strategy/multicast"
        );
        assert_eq!(cfg.strategies[1].strategy, "multicast");
    }

    #[test]
    fn strategy_section_is_optional() {
        let cfg = ForwarderConfig::from_str("[[route]]\nprefix = \"/x\"\nface = 0\n").unwrap();
        assert!(cfg.strategies.is_empty());
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

    #[test]
    fn self_signed_cache_dir_parses_and_round_trips() {
        let cfg = ForwarderConfig::from_str(
            "[listeners.webtransport]\nenabled = true\nlisten = \"0.0.0.0:6367\"\n\
             cert_source = { type = \"self_signed_dev\", cache_dir = \"/var/lib/ndn-fwd/tls\" }\n",
        )
        .unwrap();
        let src = cfg.listeners.webtransport.unwrap().cert_source;
        let CertSourceConfig::SelfSignedDev(s) = &src else {
            panic!("expected self_signed_dev, got {src:?}");
        };
        assert_eq!(s.cache_dir.as_deref(), Some("/var/lib/ndn-fwd/tls"));
        assert_eq!(s.hostnames, vec!["localhost".to_string()]);
        // The forwarder hands this to `ndn_acme::CertSource` via JSON.
        let json = serde_json::to_value(&src).unwrap();
        assert_eq!(json["cache_dir"], "/var/lib/ndn-fwd/tls");
        // Unset stays absent rather than `null`.
        let json = serde_json::to_value(CertSourceConfig::default()).unwrap();
        assert!(json.get("cache_dir").is_none());
    }

    #[test]
    fn peers_parse_with_one_or_many_endpoints() {
        let fp = "ab".repeat(32);
        let cfg = ForwarderConfig::from_str(&format!(
            "[[face]]\nkind = \"quic\"\nbind = \"0.0.0.0:6367\"\n\
             [[peer]]\ndevice = \"/home/node/relay\"\nendpoint = \"relay.example.net:6367\"\n\
             [[peer]]\nkey = \"{fp}\"\nendpoint = [\"10.0.0.1:6367\", \"[::1]:6367\"]\n\
             persistent = false\n\
             [[peer]]\ndevice = \"/home/member/phone\"\nrelay = \"/home/node/relay\"\n"
        ))
        .unwrap();
        assert!(matches!(&cfg.faces[0], FaceConfig::Quic { bind, listen: true, .. } if bind == "0.0.0.0:6367"));
        assert_eq!(cfg.peers[0].endpoint, vec!["relay.example.net:6367"]);
        assert!(cfg.peers[0].persistent);
        assert_eq!(cfg.peers[1].endpoint.len(), 2);
        assert!(!cfg.peers[1].persistent);
        assert!(cfg.peers[2].endpoint.is_empty());
        assert_eq!(cfg.peers[2].relay.as_deref(), Some("/home/node/relay"));
    }

    #[test]
    fn a_dial_only_socket_picks_the_source_address_and_needs_something_to_dial() {
        let cfg = ForwarderConfig::from_str(
            "[[face]]\nkind = \"quic\"\nbind = \"192.0.2.7:0\"\nlisten = false\n\
             [[peer]]\ndevice = \"/home/node/relay\"\nendpoint = \"relay.example.net:6367\"\n",
        )
        .unwrap();
        assert!(matches!(&cfg.faces[0], FaceConfig::Quic { bind, listen: false, .. } if bind == "192.0.2.7:0"));
        let err = ForwarderConfig::from_str(
            "[[face]]\nkind = \"quic\"\nbind = \"192.0.2.7:0\"\nlisten = false\n\
             [relays]\nnamespace = false\n",
        )
        .err()
        .expect("a socket that neither listens nor dials is refused");
        assert!(err.to_string().contains("no [[peer]] has an endpoint"), "{err}");
        // The namespace's relays (on by default) are something to dial.
        assert!(
            ForwarderConfig::from_str("[[face]]\nkind = \"quic\"\nbind = \"192.0.2.7:0\"\nlisten = false\n")
                .is_ok()
        );
    }

    /// `[[ca.relay]]` and `direct_pairs` parse, unset stays unset (the
    /// context's), `relay = []` states none, and a bad entry is refused.
    #[test]
    fn ca_relays_and_direct_pairs_are_checked() {
        let cfg = ForwarderConfig::from_str(&format!(
            "[ca]\ndirect_pairs = [\"member:member\", \"admin:member\"]\n\
             [[ca.relay]]\ndevice = \"/home/node/vps\"\nendpoint = \"vps.example.net:6367\"\n\
             [[ca.relay]]\ndevice = \"/club/node/r\"\nkey = \"{}\"\n\
             endpoint = [\"club.example.org:6367\", \"192.0.2.9:6367\"]\npreference = 2\n",
            "ab".repeat(32)
        ))
        .unwrap();
        let relays = cfg.ca.relays.as_deref().unwrap();
        assert_eq!(relays.len(), 2);
        assert_eq!((relays[1].endpoint.len(), relays[1].preference), (2, 2));
        assert_eq!(ForwarderConfig::from_str("").unwrap().ca.relays, None);
        assert_eq!(ForwarderConfig::from_str("[ca]\nrelay = []\n").unwrap().ca.relays, Some(Vec::new()));
        for (bad, why) in [
            ("[ca]\ndirect_pairs = [\"member\"]\n", "is not a pair of roles"),
            ("[ca]\ndirect_pairs = [\"member:robot\"]\n", "is not a pair of roles"),
            ("[[ca.relay]]\ndevice = \"vps\"\nendpoint = \"v:1\"\n", "device must be a device name"),
            ("[[ca.relay]]\ndevice = \"/h/node/v\"\nkey = \"ab\"\nendpoint = \"v:1\"\n", "key must be"),
            ("[[ca.relay]]\ndevice = \"/h/node/v\"\nendpoint = []\n", "no endpoint"),
            ("[[ca.relay]]\ndevice = \"/h/node/v\"\nendpoint = \"v\"\n", "endpoint must be host:port"),
            (
                "[[ca.relay]]\ndevice = \"/h/node/v\"\nendpoint = \"v:1\"\n\
                 [[ca.relay]]\ndevice = \"/h/node/v\"\nendpoint = \"w:1\"\n",
                "listed twice",
            ),
        ] {
            let err = ForwarderConfig::from_str(bad).unwrap_err().to_string();
            assert!(err.contains(why), "{bad}: {err}");
        }
    }

    #[test]
    fn direct_paths_default_on_and_advertised_addresses_must_be_host_port() {
        let cfg = ForwarderConfig::from_str(
            "[[face]]\nkind = \"quic\"\nbind = \"0.0.0.0:6367\"\n\
             advertise = [\"203.0.113.7:6367\", \"home.example.net:16367\"]\n\
             [[peer]]\ndevice = \"/home/node/relay\"\nendpoint = \"relay.example.net:6367\"\n\
             [[peer]]\ndevice = \"/home/member/phone\"\nrelay = \"/home/node/relay\"\ndirect = false\n",
        )
        .unwrap();
        assert!(matches!(&cfg.faces[0], FaceConfig::Quic { advertise, .. } if advertise.len() == 2));
        assert!(cfg.peers[0].direct);
        assert!(!cfg.peers[1].direct);
        for bad in ["\"203.0.113.7\"", "\":6367\"", "\"h:0\""] {
            let err = ForwarderConfig::from_str(&format!(
                "[[face]]\nkind = \"quic\"\nbind = \"0.0.0.0:6367\"\nadvertise = [{bad}]\n"
            ))
            .err()
            .expect("a malformed advertise entry is refused");
            assert!(err.to_string().contains("advertise entries must be"), "{err}");
        }
    }

    #[test]
    fn a_peer_that_cannot_be_identified_or_reached_is_refused() {
        for bad in [
            "[[peer]]\nendpoint = \"h:1\"\n",
            "[[peer]]\nkey = \"abc\"\n",
            "[[peer]]\ndevice = \"/home\"\n",
            "[[peer]]\ndevice = \"/home/node/r\"\nendpoint = \"nohost\"\n",
            "[[peer]]\ndevice = \"/home/member/a\"\nrelay = \"/home/node/r\"\n",
            "[[peer]]\ndevice = \"/home/node/r\"\n\
             [[peer]]\ndevice = \"/home/member/a\"\nrelay = \"/home/node/r\"\n",
            "[[peer]]\ndevice = \"/home/node/r\"\nendpoint = \"h:1\"\n\
             [[peer]]\ndevice = \"/home/node/r\"\nendpoint = \"h:2\"\n",
            "[[peer]]\ndevice = \"/home/node/r\"\ncert_sha256 = \"00\"\n",
            "[listeners.quic]\nenabled = true\nlisten = \"0.0.0.0:6367\"\n",
            "[[face]]\nkind = \"quic\"\nremote = \"quic://h:1\"\n",
        ] {
            assert!(ForwarderConfig::from_str(bad).is_err(), "accepted: {bad}");
        }
    }

    #[test]
    fn relays_link_modes_and_relay_service_parse() {
        let fp = "ab".repeat(32);
        let root = "cd".repeat(32);
        let cfg = ForwarderConfig::from_str(&format!(
            "[relays]\ncount = 2\nnamespace = true\nmode = \"on-demand\"\nidle_secs = 120\nhold = true\n\
             [[relay]]\nkey = \"{fp}\"\nendpoint = \"relay.example.net:6367\"\npreference = 5\n\
             mode = \"off\"\nwake_token = \"push-token\"\n\
             [[peer]]\ndevice = \"/home/member/phone\"\nrelay = \"{fp}\"\nmode = \"on-demand\"\n\
             idle_secs = 30\nhold = true\n\
             [relay_service]\nserve = \"listed\"\nroots = [\"{root}\"]\nlinks_total = 10\n\
             hold = true\nhold_secs = 30\nwake_command = [\"/usr/bin/notify\", \"-q\"]\n\
             [links]\nkeep_alive_secs = 20\nidle_timeout_secs = 60\n\
             [direct]\nmembership = false\nmax_paths = 2\n"
        ))
        .unwrap();
        assert_eq!(cfg.relays.count, 2);
        assert_eq!(cfg.relays.mode, LinkModeConfig::OnDemand);
        assert!(cfg.relays.hold);
        let relay = &cfg.user_relays[0];
        assert_eq!((relay.preference, relay.mode), (5, LinkModeConfig::Off));
        assert_eq!(relay.wake_token.as_deref(), Some("push-token"));
        assert_eq!(cfg.peers[0].mode, LinkModeConfig::OnDemand);
        assert_eq!(cfg.peers[0].idle_secs, 30);
        assert_eq!(cfg.relay_service.serve, ServeConfig::Listed);
        let quotas = cfg.relay_service.quotas().expect("a set quota turns listed quotas on");
        assert_eq!((quotas.links_total, quotas.links_per_namespace), (10, 10));
        assert_eq!(cfg.links.idle_timeout_secs, 60);
        assert_eq!(cfg.direct, DirectConfig { membership: false, max_paths: 2 });

        let cfg = ForwarderConfig::default();
        assert!(cfg.relays.namespace && cfg.direct.membership);
        assert_eq!(cfg.relay_service.quotas(), None);
        let open: ForwarderConfig = "[relay_service]\nserve = \"open\"\n".parse().unwrap();
        assert_eq!(open.relay_service.quotas(), Some(QuotasConfig::default()));
    }

    #[test]
    fn reach_options_out_of_bounds_are_refused_with_the_reason() {
        let fp = "ab".repeat(32);
        let twice = format!("[[relay]]\nkey = \"{fp}\"\nendpoint = \"h:1\"\n[[peer]]\nkey = \"{fp}\"\n");
        let roots_unlisted = format!("[relay_service]\nroots = [\"{fp}\"]\n");
        for (bad, why) in [
            ("[relays]\ncount = 9\n", "count = 9"),
            ("[relays]\nmode = \"on-demand\"\nidle_secs = 5\n", "idle_secs = 5"),
            ("[relays]\nmode = \"sometimes\"\n", "sometimes"),
            ("[relays]\nnope = 1\n", "nope"),
            ("[[relay]]\ndevice = \"/home/node/r\"\n", "has no endpoint"),
            ("[[relay]]\nendpoint = \"h:1\"\n", "expected fingerprint"),
            ("[[relay]]\nkey = \"abc\"\nendpoint = \"h:1\"\n", "64 hex digits"),
            (twice.as_str(), "one device is one link"),
            ("[[peer]]\ndevice = \"/home/node/r\"\nwake_token = \"\"\n", "wake_token"),
            ("[relay_service]\nserve = \"listed\"\n", "roots is empty"),
            (roots_unlisted.as_str(), "only with serve = \"listed\""),
            ("[relay_service]\nwake_command = [\"\"]\n", "start with the program"),
            ("[links]\nkeep_alive_secs = 90\n", "NAT bindings"),
            ("[links]\nkeep_alive_secs = 10\nidle_timeout_secs = 20\n", "3 × keep_alive_secs"),
            ("[direct]\nmax_paths = 0\n", "max_paths = 0"),
        ] {
            let err = ForwarderConfig::from_str(bad).err().unwrap_or_else(|| panic!("accepted: {bad}"));
            assert!(err.to_string().contains(why), "{bad}: {err}");
        }
    }
}
