//! [`SignedTrustContext`] — an anchor-rooted namespace relationship.
//!
//! A node does not "join a network"; it adopts a *set* of trust contexts (a
//! [`Keyring`](crate::Keyring)). Each context binds a `namespace` to the
//! anchor(s) and trust schema that govern it. Validation dispatches to the
//! context selected by the *data/command name's* namespace, so trust held for
//! one namespace never bleeds into another.
//!
//! A context is also a signed, versioned NDN object: its fields encode to the
//! `Content` of `/<namespace>/32=trust-context/v=N` (TLV block
//! `0x0410–0x041F`, see [`tlv`]). The schema travels as stock LightVerSec
//! binary for cross-implementation interop; native ndn-rs text rules are a
//! local authoring convenience. See
//! `docs/wiki/src/reference/trust-policies.md`.

pub mod tlv;

use std::sync::{Arc, RwLock};

use bytes::Bytes;
use dashmap::DashMap;
use ndn_packet::{Data, Name};
use ndn_tlv::{TlvWriter, read_varu64};

use crate::cert_cache::Certificate;
use crate::trust_schema::{SchemaRule, TrustSchema};

/// Errors from encoding/decoding a [`SignedTrustContext`] wire object.
#[derive(Debug, thiserror::Error)]
pub enum SignedTrustContextError {
    #[error("truncated TLV: {0}")]
    Truncated(&'static str),
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    #[error("no schema blob in a format this node understands (format code {0})")]
    UnsupportedSchemaFormat(u8),
    #[error("malformed anchor certificate: {0}")]
    BadAnchor(String),
    #[error("malformed name: {0}")]
    BadName(String),
    #[error("schema import: {0}")]
    Schema(#[from] crate::lvs::LvsError),
    #[error("schema parse: {0}")]
    SchemaParse(#[from] crate::trust_schema::PatternParseError),
    #[error("not a SignedTrustContext (TLV-TYPE {0:#06x})")]
    NotSignedTrustContext(u64),
    #[error("signing into Data failed: {0}")]
    Sign(String),
    #[error("more than one LVS schema blob (a context carries at most one)")]
    MultipleLvsSchemas,
    #[error("{0} appears more than once (a context carries at most one)")]
    DuplicateField(&'static str),
    #[error("unknown critical TLV-TYPE {0:#06x}")]
    UnknownCritical(u64),
    #[error("malformed {0}")]
    BadField(&'static str),
}

/// The RDR keyword component naming a published context: `/<ns>/32=trust-context`.
/// Canonical home; `ndn-cert`'s onboarding re-exports this.
pub const TRUST_CONTEXT_KEYWORD: &[u8] = b"trust-context";

/// Which encoding the schema bytes use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchemaFormat {
    /// ndn-rs native text grammar (`/d => /k` per line); local authoring only.
    NativeText,
    /// Stock LightVerSec binary — the portable, published form.
    Lvs,
    /// A format code this node does not understand. The blob authorizes
    /// nothing here (the schema is the OR of the blobs understood, so fewer
    /// blobs authorize less, never more) and is re-emitted verbatim; a
    /// context none of whose blobs is understood is refused.
    Unknown(u8),
}

impl SchemaFormat {
    fn code(self) -> u8 {
        match self {
            SchemaFormat::NativeText => tlv::SCHEMA_FORMAT_NATIVE,
            SchemaFormat::Lvs => tlv::SCHEMA_FORMAT_LVS,
            SchemaFormat::Unknown(c) => c,
        }
    }
    fn from_code(c: u8) -> Self {
        match c {
            tlv::SCHEMA_FORMAT_NATIVE => SchemaFormat::NativeText,
            tlv::SCHEMA_FORMAT_LVS => SchemaFormat::Lvs,
            other => SchemaFormat::Unknown(other),
        }
    }
}

/// A schema in its wire form: a format tag plus opaque bytes.
#[derive(Clone, Debug)]
pub struct SchemaBlob {
    pub format: SchemaFormat,
    pub body: Bytes,
}

impl SchemaBlob {
    pub fn lvs(body: impl Into<Bytes>) -> Self {
        Self {
            format: SchemaFormat::Lvs,
            body: body.into(),
        }
    }

    /// Native-text rules, one `<data pattern> => <key pattern>` per line.
    pub fn native_text(text: impl Into<String>) -> Self {
        Self {
            format: SchemaFormat::NativeText,
            body: Bytes::from(text.into().into_bytes()),
        }
    }

    /// Build the runtime [`TrustSchema`] this blob describes.
    fn to_schema(&self) -> Result<TrustSchema, SignedTrustContextError> {
        match self.format {
            SchemaFormat::Unknown(c) => Err(SignedTrustContextError::UnsupportedSchemaFormat(c)),
            SchemaFormat::Lvs => Ok(TrustSchema::from_lvs_binary(&self.body)?),
            SchemaFormat::NativeText => {
                let mut schema = TrustSchema::new();
                for line in std::str::from_utf8(&self.body)
                    .map_err(|_| SignedTrustContextError::Truncated("schema body utf-8"))?
                    .lines()
                {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    schema.add_rule(SchemaRule::parse(line)?);
                }
                Ok(schema)
            }
        }
    }
}

/// The runtime schema for a set of blobs: the OR of those in a format this
/// node understands. Blobs in an unknown format are skipped (they can only
/// add grants); a non-empty set with none understood is refused.
fn schema_of(blobs: &[SchemaBlob]) -> Result<TrustSchema, SignedTrustContextError> {
    let mut schema = TrustSchema::new();
    let mut unknown = None;
    let mut understood = false;
    for blob in blobs {
        if let SchemaFormat::Unknown(c) = blob.format {
            unknown.get_or_insert(c);
            continue;
        }
        understood = true;
        if !schema.merge(blob.to_schema()?) {
            return Err(SignedTrustContextError::MultipleLvsSchemas);
        }
    }
    match unknown {
        Some(c) if !understood => Err(SignedTrustContextError::UnsupportedSchemaFormat(c)),
        _ => Ok(schema),
    }
}

/// What [`SignedTrustContext::explain`] found for a `(data, key)` pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContextExplanation {
    /// The hierarchy floor's verdict (the key's identity is a prefix of the
    /// data name), or `None` when the context does not enforce one.
    pub hierarchy_floor: Option<bool>,
    /// The schema rule that admits the pair (rendered), or `None` if none does.
    pub rule: Option<String>,
}

impl ContextExplanation {
    /// Whether the context authorizes the pair — always equal to
    /// [`SignedTrustContext::authorizes`].
    pub fn allowed(&self) -> bool {
        self.hierarchy_floor != Some(false) && self.rule.is_some()
    }
}

/// How devices enroll under a context: which NDNCERT challenges the
/// namespace's CA offers, which roles it certifies only on an admin's
/// approval, and whether those roles need every challenge (an invite AND an
/// approval) or the approval alone. Other roles enroll with an invite token.
/// Policy in data: a namespace CA enforces what its context advertises.
///
/// Strings are NDNCERT challenge identifiers — `"token"`, `"pin"`, `"email"`,
/// `"proof-of-possession"`, `"device-approval"`, `"yubikey"` — and role names
/// (`"admin"`, `"node"`, …). ndn-cert maps them to its handlers and roles,
/// keeping ndn-security free of an ndn-cert dependency.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EnrollmentHint {
    pub challenges: Vec<String>,
    /// For the roles in [`approval_roles`](Self::approval_roles): every
    /// challenge is required (`token AND device-approval`), not the
    /// approval alone.
    pub require_all: bool,
    /// Roles whose certificates are issued only on an admin's approval.
    /// Empty in contexts made before the hint carried them.
    pub approval_roles: Vec<String>,
}

/// [`EnrollmentHint`] wire flag: every challenge is required.
const HINT_REQUIRE_ALL: u8 = 0x01;
/// [`EnrollmentHint`] wire flag: a `;`-separated approval-role list follows
/// the challenge list.
const HINT_HAS_ROLES: u8 = 0x02;

impl EnrollmentHint {
    /// The default enrollment policy `ndn-fwd init` puts on a namespace:
    /// members and guests by invite token, admins and nodes by an admin's
    /// approval alone.
    pub fn namespace_default() -> Self {
        Self {
            challenges: vec!["token".into(), "device-approval".into()],
            require_all: false,
            approval_roles: vec!["admin".into(), "node".into()],
        }
    }

    fn encode(&self) -> Bytes {
        let mut flags = 0u8;
        if self.require_all {
            flags |= HINT_REQUIRE_ALL;
        }
        if !self.approval_roles.is_empty() {
            flags |= HINT_HAS_ROLES;
        }
        let mut v = vec![flags];
        v.extend_from_slice(self.challenges.join(",").as_bytes());
        if !self.approval_roles.is_empty() {
            v.push(b';');
            v.extend_from_slice(self.approval_roles.join(",").as_bytes());
        }
        Bytes::from(v)
    }

    fn decode(value: &[u8]) -> Self {
        let flags = value.first().copied().unwrap_or(0);
        let rest = if value.is_empty() {
            &[][..]
        } else {
            &value[1..]
        };
        let s = String::from_utf8_lossy(rest);
        let (challenges, roles) = if flags & HINT_HAS_ROLES != 0 {
            s.split_once(';').unwrap_or((&s, ""))
        } else {
            (&s[..], "")
        };
        let list = |text: &str| -> Vec<String> {
            if text.is_empty() {
                Vec::new()
            } else {
                text.split(',').map(|x| x.to_string()).collect()
            }
        };
        Self {
            challenges: list(challenges),
            // Before the flags, any non-zero first byte meant "all required".
            require_all: if flags & HINT_HAS_ROLES != 0 {
                flags & HINT_REQUIRE_ALL != 0
            } else {
                flags != 0
            },
            approval_roles: list(roles),
        }
    }
}

/// What a key a context names is for ([`tlv::KEY_ROLE`]), beyond what the
/// anchor set and the schema already say. Policy in data: it is signed with
/// the context and carried to every version made from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeyRole(pub u8);

impl KeyRole {
    /// An anchor that is a **recovery key**: generated for a recovery kit,
    /// kept offline, root-equivalent (as every anchor, it can sign the next
    /// version of the context) and used only to replace a lost root device.
    pub const RECOVERY_ANCHOR: KeyRole = KeyRole(1);
    /// A key that lives on the root device beside the root: its CA key and
    /// its admin device key. A recovery after a compromise revokes them.
    pub const ROOT_DEVICE: KeyRole = KeyRole(2);

    pub fn as_str(self) -> &'static str {
        match self {
            Self::RECOVERY_ANCHOR => "recovery-anchor",
            Self::ROOT_DEVICE => "root-device",
            _ => "unknown",
        }
    }
}

/// Which devices of a namespace may link to its devices, by the role in
/// their certificate's name (`/<ns>/<role>/<device>`), which roles may act
/// as a relay for other devices, whether a relay admits enrollment links,
/// and which pairs of roles may make direct paths ([`tlv::LINK_POLICY`]).
/// Policy in data: signed with the context, so every device of the
/// namespace admits links by the same rule, and carried to every version
/// made from it. A context without one has the default
/// ([`LinkPolicy::default`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkPolicy {
    /// Roles whose devices may link. Empty: every device role.
    pub roles: Vec<String>,
    /// Roles a device may use as a relay (a link other devices are reached
    /// through).
    pub relay_roles: Vec<String>,
    /// Whether a relay of the namespace admits a link from a device it does
    /// not know yet as an *enrollment link*: one that carries only Interests
    /// for the namespace's CA endpoints and its trust context, and their
    /// answers, so a device reachable only over QUIC can enroll. Takes
    /// effect only when the context names a CA endpoint
    /// ([`SignedTrustContext::admits_enrollment_links`]).
    pub enrollment_links: bool,
    /// Whether two devices linked through a relay may try a direct path
    /// between them (NAT hole punching from the addresses each one offers),
    /// falling back to the relay when it does not open.
    pub direct_paths: bool,
    /// Unordered pairs of roles whose devices may make a direct path with
    /// each other when `direct_paths` is on: `(a, b)` also allows `(b, a)`,
    /// `(r, r)` two devices of role `r`. Default:
    /// [`default_direct_pairs`](Self::default_direct_pairs).
    pub direct_pairs: Vec<(String, String)>,
}

impl Default for LinkPolicy {
    /// Any enrolled device of the namespace may link; relays are `node`
    /// devices; relays admit enrollment links; admins, members and nodes
    /// may make direct paths with each other, guests with nobody.
    fn default() -> Self {
        Self {
            roles: Vec::new(),
            relay_roles: vec!["node".into()],
            enrollment_links: true,
            direct_paths: true,
            direct_pairs: Self::default_direct_pairs(),
        }
    }
}

/// [`LinkPolicy`] wire words for `enrollment_links`.
const ENROLLMENT_LINKS_ON: &str = "enrollment";
const ENROLLMENT_LINKS_OFF: &str = "no-enrollment";
/// [`LinkPolicy`] wire words for `direct_paths`.
const DIRECT_PATHS_ON: &str = "direct";
const DIRECT_PATHS_OFF: &str = "no-direct";
/// The roles whose devices make direct paths with each other by default.
const DEFAULT_DIRECT_ROLES: [&str; 3] = ["admin", "member", "node"];

impl LinkPolicy {
    /// Whether a device with `role` may link.
    pub fn allows_link(&self, role: &str) -> bool {
        self.roles.is_empty() || self.roles.iter().any(|r| r == role)
    }

    /// Whether a device with `role` may be a relay.
    pub fn allows_relay(&self, role: &str) -> bool {
        self.allows_link(role) && self.relay_roles.iter().any(|r| r == role)
    }

    /// Whether linked devices may try a direct path instead of the relay
    /// at all; [`allows_direct_path`](Self::allows_direct_path) says between
    /// which roles.
    pub fn allows_direct_paths(&self) -> bool {
        self.direct_paths
    }

    /// Whether a device with role `a` and one with role `b` may make a
    /// direct path with each other: direct paths are on and `{a, b}` is one
    /// of [`direct_pairs`](Self::direct_pairs).
    pub fn allows_direct_path(&self, a: &str, b: &str) -> bool {
        self.direct_paths
            && self
                .direct_pairs
                .iter()
                .any(|(x, y)| (x == a && y == b) || (x == b && y == a))
    }

    /// Every pair of `admin`, `member` and `node` (each role with itself
    /// too); `guest` in none. In canonical form
    /// ([`canonical_direct_pairs`](Self::canonical_direct_pairs)).
    pub fn default_direct_pairs() -> Vec<(String, String)> {
        let mut pairs = Vec::new();
        for (i, a) in DEFAULT_DIRECT_ROLES.iter().enumerate() {
            for b in &DEFAULT_DIRECT_ROLES[i..] {
                pairs.push((a.to_string(), b.to_string()));
            }
        }
        pairs
    }

    /// [`direct_pairs`](Self::direct_pairs) as a set: each pair's roles in
    /// order, the pairs sorted, duplicates dropped. Two policies allow the
    /// same direct paths iff these are equal.
    pub fn canonical_direct_pairs(&self) -> Vec<(String, String)> {
        let mut pairs: Vec<(String, String)> = self
            .direct_pairs
            .iter()
            .map(|(a, b)| {
                if a <= b {
                    (a.clone(), b.clone())
                } else {
                    (b.clone(), a.clone())
                }
            })
            .collect();
        pairs.sort();
        pairs.dedup();
        pairs
    }

    /// One line for a person: `links: any role; relays: node; enrollment
    /// links: on`, plus `; direct paths: off` when they are off, or `;
    /// direct paths: admin:member, …` when they are on between other role
    /// pairs than the default.
    pub fn describe(&self) -> String {
        let list = |roles: &[String], empty: &str| {
            if roles.is_empty() {
                empty.to_string()
            } else {
                roles.join(", ")
            }
        };
        let pairs = self.canonical_direct_pairs();
        let direct = if !self.direct_paths {
            "; direct paths: off".to_string()
        } else if pairs == Self::default_direct_pairs() {
            String::new()
        } else if pairs.is_empty() {
            "; direct paths: no role pair".to_string()
        } else {
            format!("; direct paths: {}", pairs_text(&pairs, ", "))
        };
        format!(
            "links: {}; relays: {}; enrollment links: {}{direct}",
            list(&self.roles, "any role"),
            list(&self.relay_roles, "none"),
            if self.enrollment_links { "on" } else { "off" },
        )
    }

    /// `<roles>;<relay roles>;<enrollment|no-enrollment>[;<direct|no-direct>
    /// [;<pairs>]]`, roles comma-separated, pairs `a:b` comma-separated in
    /// canonical order. The fifth field is written only when the pairs are
    /// not the default (and then the fourth explicitly); otherwise the
    /// fourth only when direct paths are off. So a policy that states
    /// nothing new encodes as before either field existed.
    fn encode(&self) -> Vec<u8> {
        let mut text = format!(
            "{};{};{}",
            self.roles.join(","),
            self.relay_roles.join(","),
            if self.enrollment_links {
                ENROLLMENT_LINKS_ON
            } else {
                ENROLLMENT_LINKS_OFF
            },
        );
        let direct = if self.direct_paths {
            DIRECT_PATHS_ON
        } else {
            DIRECT_PATHS_OFF
        };
        let pairs = self.canonical_direct_pairs();
        if pairs != Self::default_direct_pairs() {
            text = format!("{text};{direct};{}", pairs_text(&pairs, ","));
        } else if !self.direct_paths {
            text = format!("{text};{direct}");
        }
        text.into_bytes()
    }

    /// Decode the value; `None` when it is malformed (the default applies).
    /// The fourth field is `direct` or `no-direct`; absent or any other word
    /// means direct paths on. The fifth lists the role pairs; absent, or
    /// not a list of `a:b` (a later form of the field), means the default
    /// pairs. Fields after the fifth are reserved for extension and
    /// ignored, so an older node keeps the ones it knows instead of
    /// falling back to the broader default.
    fn decode(value: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(value).ok()?;
        let mut fields = text.split(';');
        let list = |s: &str| -> Vec<String> {
            s.split(',')
                .filter(|r| !r.is_empty())
                .map(str::to_string)
                .collect()
        };
        let roles = list(fields.next()?);
        let relay_roles = list(fields.next()?);
        let enrollment_links = match fields.next() {
            Some(ENROLLMENT_LINKS_OFF) => false,
            Some(ENROLLMENT_LINKS_ON) | None => true,
            Some(_) => return None,
        };
        // Unknown words are a later extension of this field: keep the default.
        let direct_paths = match fields.next() {
            Some(DIRECT_PATHS_OFF) => false,
            Some(DIRECT_PATHS_ON) | Some(_) | None => true,
        };
        let direct_pairs = fields
            .next()
            .and_then(parse_pairs)
            .unwrap_or_else(Self::default_direct_pairs);
        let mut policy = Self {
            roles,
            relay_roles,
            enrollment_links,
            direct_paths,
            direct_pairs,
        };
        policy.direct_pairs = policy.canonical_direct_pairs();
        Some(policy)
    }
}

/// `a:b` per pair, joined by `sep`.
fn pairs_text(pairs: &[(String, String)], sep: &str) -> String {
    pairs
        .iter()
        .map(|(a, b)| format!("{a}:{b}"))
        .collect::<Vec<_>>()
        .join(sep)
}

/// The LinkPolicy pair list `a:b,c:d` (empty: no pair); `None` when an
/// entry is not `<role>:<role>`.
fn parse_pairs(field: &str) -> Option<Vec<(String, String)>> {
    field
        .split(',')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (a, b) = p.split_once(':')?;
            (!a.is_empty() && !b.is_empty() && !b.contains(':'))
                .then(|| (a.to_string(), b.to_string()))
        })
        .collect()
}

/// A relay the namespace advertises ([`tlv::ADVERTISED_RELAY`]). Signed
/// with the context, so every member learns it without local
/// configuration; each device decides whether it uses namespace relays.
/// Every device that holds the context sees its endpoints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdvertisedRelay {
    /// The relay's device name, normally `/<ns>/node/<device>`.
    pub device: Name,
    /// The relay's expected fingerprint: SHA-256 of its public key as its
    /// certificate carries it. Required when `device` is not under the
    /// namespace (a device of the namespace is admitted by its certificate).
    pub key: Option<[u8; 32]>,
    /// Where to dial it, `host:port`, in the order a device tries them (at
    /// least one).
    pub endpoints: Vec<String>,
    /// Lower is preferred.
    pub preference: u32,
}

impl AdvertisedRelay {
    /// The canonical order: by preference, then device, key, endpoints.
    fn canonical_cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.preference, &self.device, &self.key, &self.endpoints).cmp(&(
            other.preference,
            &other.device,
            &other.key,
            &other.endpoints,
        ))
    }

    /// The [`tlv::ADVERTISED_RELAY`] value: device Name, then
    /// [`tlv::RELAY_KEY`], each [`tlv::RELAY_ENDPOINT`], [`tlv::RELAY_PREFERENCE`].
    fn encode(&self) -> Vec<u8> {
        let mut w = TlvWriter::new();
        w.write_raw(&self.device.encode_to_tlv());
        if let Some(key) = &self.key {
            w.write_tlv(tlv::RELAY_KEY, key);
        }
        for endpoint in &self.endpoints {
            w.write_tlv(tlv::RELAY_ENDPOINT, endpoint.as_bytes());
        }
        w.write_tlv(tlv::RELAY_PREFERENCE, &nni(u64::from(self.preference)));
        w.finish().to_vec()
    }

    /// Decode the value; `None` when it is malformed: no device Name, or a
    /// second one, a key that is not 32 octets or a second key, no
    /// endpoint or an empty / non-UTF-8 one, a preference that is not a
    /// NonNegativeInteger of at most 32 bits or a second one, an unknown
    /// critical sub-TLV. Unknown non-critical sub-TLVs are skipped. A
    /// missing preference is 0.
    fn decode(value: &[u8]) -> Option<Self> {
        let mut device = None;
        let mut key = None;
        let mut endpoints = Vec::new();
        let mut preference = None;
        let mut cur = value;
        while !cur.is_empty() {
            let (t, v, rest) = read_tlv(cur).ok()?;
            cur = rest;
            match t {
                ndn_packet::tlv_type::NAME if device.is_none() => {
                    device = Some(Name::decode(Bytes::copy_from_slice(v)).ok()?);
                }
                tlv::RELAY_KEY if key.is_none() => key = Some(<[u8; 32]>::try_from(v).ok()?),
                tlv::RELAY_ENDPOINT => {
                    let endpoint = std::str::from_utf8(v).ok().filter(|e| !e.is_empty())?;
                    endpoints.push(endpoint.to_string());
                }
                tlv::RELAY_PREFERENCE if preference.is_none() => {
                    let p = ndn_packet::decode_nni(v).ok()?;
                    preference = Some(u32::try_from(p).ok()?);
                }
                ndn_packet::tlv_type::NAME | tlv::RELAY_KEY | tlv::RELAY_PREFERENCE => return None,
                other if is_critical(other) => return None,
                _ => {}
            }
        }
        if endpoints.is_empty() {
            return None;
        }
        Some(Self {
            device: device?,
            key,
            endpoints,
            preference: preference.unwrap_or(0),
        })
    }
}

impl std::fmt::Display for AdvertisedRelay {
    /// `<device> [key <64 hex>] at <endpoint>, … (preference <n>)`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.device)?;
        if let Some(key) = &self.key {
            f.write_str(" key ")?;
            for b in key {
                write!(f, "{b:02x}")?;
            }
        }
        write!(
            f,
            " at {} (preference {})",
            self.endpoints.join(", "),
            self.preference
        )
    }
}

/// NDN NonNegativeInteger: 1, 2, 4 or 8 big-endian octets by magnitude.
fn nni(v: u64) -> Vec<u8> {
    let b = v.to_be_bytes();
    match v {
        0..=0xFF => b[7..].to_vec(),
        0x100..=0xFFFF => b[6..].to_vec(),
        0x1_0000..=0xFFFF_FFFF => b[4..].to_vec(),
        _ => b.to_vec(),
    }
}

/// One anchor-rooted namespace relationship in a [`Keyring`](crate::Keyring).
///
/// A context owns the anchor set and schema for its `namespace`. Hierarchical
/// contexts additionally enforce the `keyLocator.isPrefixOf(name)` floor — the
/// signing key's identity must be a prefix of the signed name — which is the
/// authorization binding NFD never shipped (issue #2856), closing the
/// skeleton-key gap by construction.
pub struct SignedTrustContext {
    namespace: Name,
    anchors: Arc<DashMap<Arc<Name>, Certificate>>,
    schema: RwLock<TrustSchema>,
    /// When set, [`authorizes`](Self::authorizes) requires the signing key's
    /// identity to be a prefix of the data name, on top of the schema.
    enforce_hierarchy: bool,
    /// Monotonic, signed version (from the RDR name `…/v=N`). Anti-rollback:
    /// the keyring refuses to replace a context with a lower version.
    version: u64,
    /// Where to enroll to become a recognized producer. Repeatable.
    ca_endpoints: Vec<Name>,
    /// Which challenge(s) gate issuance.
    enrollment_hint: Option<EnrollmentHint>,
    /// Dead keys and certificates, by name. An entry covers that name and
    /// every name under it ([`is_revoked`](Self::is_revoked)): a revoked key
    /// name `/<id>/KEY/<k>` covers each certificate of that key
    /// (`/<id>/KEY/<k>/<issuer>/<version>`), including ones issued later.
    revocations: Vec<Name>,
    /// Schema blobs to re-emit verbatim on encode (preserves a published LVS
    /// blob exactly), OR'd into the runtime schema; empty means derive a
    /// native-text blob from the runtime schema.
    schema_blobs: Vec<SchemaBlob>,
    /// Emit [`tlv::SCHEMA_AUTHORITATIVE`]: the schema governs alone, without
    /// the hierarchy floor (see [`schema_authoritative`](Self::schema_authoritative)).
    schema_authoritative: bool,
    /// Provenance hint: SHA-256 implicit digest of the source trust **bundle**
    /// (Block) this context was projected from, for wire-level traceability
    /// back to the root of authority. Non-critical; `None` when unprojected
    /// (locally authored). See [`tlv::SOURCE_BUNDLE_HASH`].
    source_bundle_hash: Option<[u8; 32]>,
    /// Roles of keys the context names ([`tlv::KEY_ROLE`]), in wire order.
    key_roles: Vec<(KeyRole, Name)>,
    /// Which devices may link ([`tlv::LINK_POLICY`]); `None` is the default.
    link_policy: Option<LinkPolicy>,
    /// Relays the namespace advertises ([`tlv::ADVERTISED_RELAY`]), in
    /// canonical order (preference, then device).
    relays: Vec<AdvertisedRelay>,
}

impl SignedTrustContext {
    fn base(namespace: Name, schema: TrustSchema, enforce_hierarchy: bool) -> Self {
        Self {
            namespace,
            anchors: Arc::new(DashMap::new()),
            schema: RwLock::new(schema),
            enforce_hierarchy,
            version: 0,
            ca_endpoints: Vec::new(),
            enrollment_hint: None,
            revocations: Vec::new(),
            schema_blobs: Vec::new(),
            schema_authoritative: false,
            source_bundle_hash: None,
            key_roles: Vec::new(),
            link_policy: None,
            relays: Vec::new(),
        }
    }

    /// A hierarchical context: the default. Signing is authorized only when
    /// the key's identity is a prefix of the data/command name *and* the
    /// schema permits the pair. This is the spec-canonical NDN hierarchical
    /// trust model and the skeleton-key enforcer.
    pub fn hierarchical(namespace: Name) -> Self {
        Self::base(namespace, TrustSchema::hierarchical(), true)
    }

    /// An accept-all context: schema-only, **no** hierarchy floor. An
    /// explicit, logged opt-in — prefer [`hierarchical`](Self::hierarchical).
    /// Certificate hops are not judged either: any key chaining to an anchor
    /// may certify any key ([`authorizes_certification`](Self::authorizes_certification)).
    pub fn accept_all(namespace: Name) -> Self {
        tracing::warn!(
            target: "ndn::security",
            namespace = %namespace,
            "SignedTrustContext::accept_all — hierarchical authorization floor disabled \
             (any cert under an adopted anchor may sign any name in this context)"
        );
        Self::base(namespace, TrustSchema::accept_all(), false)
    }

    /// The ambient (root-namespace) context backing a [`Validator`]'s
    /// flat-anchor API for backward compatibility. The hierarchy floor is
    /// **off** so existing single-anchor callers keep their prior semantics,
    /// and so are certificate-hop rules ([`authorizes_certification`](Self::authorizes_certification)).
    pub(crate) fn ambient(
        schema: TrustSchema,
        anchors: Arc<DashMap<Arc<Name>, Certificate>>,
    ) -> Self {
        let mut c = Self::base(Name::root(), schema, false);
        c.anchors = anchors;
        c
    }

    // ── builder setters (by-move; contexts are immutable once adopted) ──────

    pub fn with_version(mut self, version: u64) -> Self {
        self.version = version;
        self
    }
    pub fn with_ca_endpoint(mut self, ca: Name) -> Self {
        self.ca_endpoints.push(ca);
        self
    }
    pub fn with_enrollment_hint(mut self, hint: EnrollmentHint) -> Self {
        self.enrollment_hint = Some(hint);
        self
    }
    pub fn with_revocation(mut self, name: Name) -> Self {
        self.revocations.push(name);
        self
    }
    /// Attach a schema blob to re-emit verbatim on `encode_content`
    /// (e.g. a published LVS binary), and adopt it as the runtime schema.
    pub fn with_schema_blob(self, blob: SchemaBlob) -> Result<Self, SignedTrustContextError> {
        self.with_schema_blobs(vec![blob])
    }
    /// As [`with_schema_blob`](Self::with_schema_blob) for several blobs whose
    /// OR is the runtime schema — at most one LVS binary, plus native-text
    /// rules for what LVS cannot express.
    pub fn with_schema_blobs(
        mut self,
        blobs: Vec<SchemaBlob>,
    ) -> Result<Self, SignedTrustContextError> {
        *self.schema.write().expect("schema RwLock poisoned") = schema_of(&blobs)?;
        self.schema_blobs = blobs;
        Ok(self)
    }
    /// Make the schema authoritative: drop the hierarchy floor, evaluate the
    /// schema on every certificate hop of a chain walk (not only the first
    /// signature), and say so on the wire ([`tlv::SCHEMA_AUTHORITATIVE`]) so
    /// adopters do the same. Only for schemas that bind every signer to the
    /// names it may sign, certificates included (the generated
    /// namespace schema): its cross-identity grants (admins approving
    /// enrollments, members writing a shared namespace) are exactly what the
    /// floor forbids.
    pub fn schema_authoritative(mut self) -> Self {
        self.enforce_hierarchy = false;
        self.schema_authoritative = true;
        self
    }
    /// Record the source trust-bundle the context was projected from (its
    /// SHA-256 implicit digest), emitted as a non-critical provenance hint so
    /// auditors can walk the wire object back to its Block root of authority.
    pub fn with_source_bundle_hash(mut self, digest: [u8; 32]) -> Self {
        self.source_bundle_hash = Some(digest);
        self
    }
    /// Give `key` (a key name) the role `role` (no duplicate entries).
    pub fn with_key_role(mut self, role: KeyRole, key: Name) -> Self {
        if !self.key_roles.iter().any(|(r, k)| *r == role && *k == key) {
            self.key_roles.push((role, key));
        }
        self
    }
    /// Drop every role entry `drop` selects.
    pub fn without_key_roles(mut self, drop: impl Fn(KeyRole, &Name) -> bool) -> Self {
        self.key_roles.retain(|(r, k)| !drop(*r, k));
        self
    }
    /// Set which devices of the namespace may link and relay.
    pub fn with_link_policy(mut self, policy: LinkPolicy) -> Self {
        self.link_policy = Some(policy);
        self
    }
    /// Set the relays the namespace advertises (replacing any), kept and
    /// encoded in canonical order — by preference, then device — so the
    /// same set encodes identically. The caller checks each entry (an
    /// endpoint, a `key` for a device outside the namespace): a decoder
    /// drops an entry without them.
    pub fn with_relays(mut self, mut relays: Vec<AdvertisedRelay>) -> Self {
        relays.sort_by(AdvertisedRelay::canonical_cmp);
        self.relays = relays;
        self
    }

    // ── accessors ───────────────────────────────────────────────────────────

    pub fn namespace(&self) -> &Name {
        &self.namespace
    }
    pub fn version(&self) -> u64 {
        self.version
    }
    pub fn enforces_hierarchy(&self) -> bool {
        self.enforce_hierarchy
    }
    /// Whether the schema is authoritative (see
    /// [`schema_authoritative`](Self::schema_authoritative)): no floor, and
    /// every certificate hop is checked against it.
    pub fn schema_is_authoritative(&self) -> bool {
        self.schema_authoritative
    }
    pub fn ca_endpoints(&self) -> &[Name] {
        &self.ca_endpoints
    }
    pub fn enrollment_hint(&self) -> Option<&EnrollmentHint> {
        self.enrollment_hint.as_ref()
    }
    pub fn revocations(&self) -> &[Name] {
        &self.revocations
    }
    /// The source trust-bundle's SHA-256 implicit digest, if this context was
    /// projected from one (the F9 provenance hint).
    pub fn source_bundle_hash(&self) -> Option<&[u8; 32]> {
        self.source_bundle_hash.as_ref()
    }
    /// Every role entry ([`KeyRole`], key name), in wire order.
    pub fn key_roles(&self) -> &[(KeyRole, Name)] {
        &self.key_roles
    }
    /// The keys that have `role`.
    pub fn keys_with_role(&self, role: KeyRole) -> impl Iterator<Item = &Name> {
        self.key_roles
            .iter()
            .filter(move |(r, _)| *r == role)
            .map(|(_, k)| k)
    }
    /// Whether `key` has `role`.
    pub fn has_key_role(&self, key: &Name, role: KeyRole) -> bool {
        self.key_roles.iter().any(|(r, k)| *r == role && k == key)
    }
    /// Which devices of the namespace may link and relay: the context's
    /// policy, else the default.
    pub fn link_policy(&self) -> LinkPolicy {
        self.link_policy.clone().unwrap_or_default()
    }
    /// The link policy the context carries, `None` when it carries none (and
    /// [`link_policy`](Self::link_policy) is the default).
    pub fn stated_link_policy(&self) -> Option<&LinkPolicy> {
        self.link_policy.as_ref()
    }
    /// The relays the namespace advertises, in canonical order.
    pub fn relays(&self) -> &[AdvertisedRelay] {
        &self.relays
    }
    /// Whether a relay of this namespace admits enrollment links: its link
    /// policy allows them and the context names a CA endpoint to enroll at.
    pub fn admits_enrollment_links(&self) -> bool {
        self.link_policy().enrollment_links && !self.ca_endpoints.is_empty()
    }

    /// Shared handle to this context's anchor set. The chain walk terminates
    /// only at an anchor *in this set* — anchors from other contexts cannot
    /// terminate a chain selected for this namespace.
    pub fn anchors(&self) -> &Arc<DashMap<Arc<Name>, Certificate>> {
        &self.anchors
    }

    pub fn add_anchor(&self, cert: Certificate) -> bool {
        if !cert.is_valid_now() {
            return false;
        }
        self.anchors.insert(Arc::clone(&cert.name), cert);
        true
    }

    /// Whether `name` (a key name or a certificate name) names an anchor of
    /// this context — see [`anchor_for`](Self::anchor_for).
    pub fn is_anchor(&self, name: &Name) -> bool {
        self.anchor_for(name).is_some()
    }

    /// The anchor `name` refers to. Anchors match by key: a KeyLocator naming
    /// the anchor's key (`/<id>/KEY/<k>`), the anchor certificate itself
    /// (`/<id>/KEY/<k>/self/<v>`) or another certificate of that key all
    /// resolve to the anchor, which is trusted for its key. An anchor
    /// stored under exactly `name` wins; among several of one key, the newest
    /// valid one.
    pub fn anchor_for(&self, name: &Name) -> Option<Certificate> {
        if let Some(exact) = self.anchors.get(name) {
            return Some(exact.value().clone());
        }
        let key = crate::cert_name::key_name_of(name);
        let now = crate::validator::now_ns();
        self.anchors
            .iter()
            // Same key, or (for a key named outside the `…/KEY/<id>` layout)
            // a certificate `<name>/<issuer>/<version>` of it.
            .filter(|r| {
                crate::cert_name::key_name_of(r.key()) == key
                    || (r.key().len() == name.len() + 2 && r.key().has_prefix(name))
            })
            .map(|r| r.value().clone())
            .max_by_key(|c| (c.is_valid_at(now), c.valid_from, Arc::clone(&c.name)))
    }

    /// Whether `name` is revoked by this context: equal to a revocation
    /// entry or under one. A chain walk checks every key/certificate name it
    /// passes, so revoking a key name refuses every certificate of that key —
    /// whichever form a KeyLocator names it in (key name or certificate
    /// name), and certificates issued after the revocation too.
    pub fn is_revoked(&self, name: &Name) -> bool {
        self.revocations.iter().any(|r| name.has_prefix(r))
    }

    pub fn set_schema(&self, schema: TrustSchema) {
        *self.schema.write().expect("schema RwLock poisoned") = schema;
    }

    pub fn schema_snapshot(&self) -> TrustSchema {
        self.schema.read().expect("schema RwLock poisoned").clone()
    }

    /// The schema in the form it will publish on the wire — the retained
    /// blobs (e.g. a stock-LVS binary) verbatim, else a native-text rendering
    /// of the current rules.
    pub fn published_schemas(&self) -> Vec<SchemaBlob> {
        self.schema_blobs_or_derive()
    }

    pub(crate) fn with_schema_mut<R>(&self, f: impl FnOnce(&mut TrustSchema) -> R) -> R {
        f(&mut self.schema.write().expect("schema RwLock poisoned"))
    }

    /// Authorization decision for a `(data_name, key_name)` pair: the
    /// hierarchy floor (when enabled) AND the schema must both permit it.
    pub fn authorizes(&self, data_name: &Name, key_name: &Name) -> bool {
        if self.enforce_hierarchy {
            let identity = key_identity(key_name);
            if !data_name.has_prefix(&identity) {
                return false;
            }
        }
        self.schema
            .read()
            .expect("schema RwLock poisoned")
            .allows(data_name, key_name)
    }

    /// Authorization of one signing hop as a chain walk decides it: `signed`
    /// (a packet name, or a certificate name at a certificate hop) signed by
    /// the key its KeyLocator `locator` names, whose certificate the walk
    /// resolved to `signer_cert` (when it has).
    ///
    /// NDN Certificate Format v2 gives a key several names — `…/KEY/<k>` and
    /// each certificate `…/KEY/<k>/<issuer>/<v>` — and schemas are written
    /// for either: python-ndn / NDNts LVS rules match certificate names,
    /// ndn-rs's key names, and earlier ndn-rs releases named certificates
    /// after their key. So the pair is authorized when
    /// [`authorizes`](Self::authorizes) admits any of: the signer as its
    /// KeyLocator names it, as its resolved certificate, or as its key; for a
    /// certificate `signed`, the certificate's own name or its key name. Every
    /// form names the same key, so no form grants authority another one lacks.
    pub fn authorizes_hop(&self, signed: &Name, locator: &Name, signer_cert: Option<&Name>) -> bool {
        if self.authorizes(signed, locator) {
            return true;
        }
        use crate::cert_name::{is_cert_name, key_name_of};
        let signed_key = is_cert_name(signed).then(|| key_name_of(signed));
        let locator_key = is_cert_name(locator).then(|| key_name_of(locator));
        let signers = [Some(locator), signer_cert, locator_key.as_ref()];
        [Some(signed), signed_key.as_ref()]
            .into_iter()
            .flatten()
            .any(|s| signers.iter().flatten().any(|k| self.authorizes(s, k)))
    }

    /// Whether the key `issuer` (a KeyLocator: key or certificate name) may
    /// certify the certificate `cert` under this context. In a hierarchical
    /// (floor) or schema-authoritative context — every context received on
    /// the wire — it may when:
    ///
    /// 1. `issuer` is a key of an anchor of this context; or
    /// 2. the issuer's identity (its name before `KEY`) is a prefix of the
    ///    subject's identity (the classic NDN hierarchical rule); or
    /// 3. the issuer's identity is a CA this context names
    ///    ([`ca_endpoints`](Self::ca_endpoints), e.g. `<ns>/CA`) and the
    ///    subject lies under the context's namespace.
    ///
    /// So an enrolled device cannot certify another device's key. An
    /// authoritative schema also judges every certificate hop, on top
    /// ([`authorizes_hop`](Self::authorizes_hop)). [`accept_all`](Self::accept_all)
    /// and the ambient flat-anchor context judge no certificate hop.
    pub fn authorizes_certification(&self, cert: &Name, issuer: &Name) -> bool {
        use crate::cert_name::key_name_of;
        if !self.enforce_hierarchy && !self.schema_authoritative {
            return true;
        }
        if self.anchor_for(issuer).is_some() {
            return true;
        }
        let subject = key_identity(&key_name_of(cert));
        let issuer_id = key_identity(&key_name_of(issuer));
        subject.has_prefix(&issuer_id)
            || (self.ca_endpoints.contains(&issuer_id) && subject.has_prefix(&self.namespace))
    }

    /// Why [`authorizes`](Self::authorizes) decides as it does for
    /// `(data_name, key_name)`: the hierarchy floor's verdict (if enforced)
    /// and the schema rule that admits the pair. For inspection tooling;
    /// [`ContextExplanation::allowed`] equals `authorizes`.
    pub fn explain(&self, data_name: &Name, key_name: &Name) -> ContextExplanation {
        let hierarchy_floor = self
            .enforce_hierarchy
            .then(|| data_name.has_prefix(&key_identity(key_name)));
        let schema = self.schema.read().expect("schema RwLock poisoned");
        ContextExplanation {
            hierarchy_floor,
            rule: schema.explain(data_name, key_name).map(|m| m.to_string()),
        }
    }

    // ── wire codec ────────────────────────────────────────────────────────

    /// Encode this context as the `Content` of its NDN object: a single
    /// `SignedTrustContext` (`0x0410`) TLV. The version lives in the *name* (RDR),
    /// not here. Anchors with no retained wire (test-only structs) are
    /// skipped. Anchors (by certificate name) and Revocation entries are
    /// written in canonical NDN name order, so the same context always
    /// encodes to the same bytes.
    pub fn encode_content(&self) -> Bytes {
        let blobs = self.schema_blobs_or_derive();
        let mut anchors: Vec<(Arc<Name>, Bytes)> = self
            .anchors
            .iter()
            .filter_map(|r| Some((Arc::clone(r.key()), r.value().data_wire()?)))
            .collect();
        anchors.sort_by(|a, b| a.0.cmp(&b.0));
        let mut revocations: Vec<&Name> = self.revocations.iter().collect();
        revocations.sort();
        let mut w = TlvWriter::new();
        w.write_nested(tlv::TRUST_CONTEXT, |w| {
            // namespace — a plain Name (0x07), no dedicated code.
            w.write_raw(&self.namespace.encode_to_tlv());
            // AnchorSet — concatenated Data (0x06) certs.
            w.write_nested(tlv::ANCHOR_SET, |w| {
                for (_, wire) in &anchors {
                    w.write_raw(wire);
                }
            });
            // TrustSchemaBlob(s) — format + body; their OR is the schema.
            for blob in &blobs {
                w.write_nested(tlv::TRUST_SCHEMA_BLOB, |w| {
                    w.write_tlv(tlv::SCHEMA_FORMAT, &[blob.format.code()]);
                    w.write_tlv(tlv::SCHEMA_BODY, &blob.body);
                });
            }
            if self.schema_authoritative {
                w.write_tlv(tlv::SCHEMA_AUTHORITATIVE, &[]);
            }
            for ca in &self.ca_endpoints {
                w.write_tlv(tlv::CA_ENDPOINT, &ca.encode_to_tlv());
            }
            if let Some(hint) = &self.enrollment_hint {
                w.write_tlv(tlv::ENROLLMENT_HINT, &hint.encode());
            }
            for rev in revocations {
                w.write_tlv(tlv::REVOCATION, &rev.encode_to_tlv());
            }
            // SourceBundleHash — non-critical provenance hint (F9).
            if let Some(digest) = &self.source_bundle_hash {
                w.write_tlv(tlv::SOURCE_BUNDLE_HASH, digest);
            }
            for (role, key) in &self.key_roles {
                let mut value = vec![role.0];
                value.extend_from_slice(&key.encode_to_tlv());
                w.write_tlv(tlv::KEY_ROLE, &value);
            }
            if let Some(policy) = &self.link_policy {
                w.write_tlv(tlv::LINK_POLICY, &policy.encode());
            }
            // AdvertisedRelay entries, in canonical order (`with_relays`).
            for relay in &self.relays {
                w.write_tlv(tlv::ADVERTISED_RELAY, &relay.encode());
            }
        });
        w.finish()
    }

    /// The canonical versioned RDR name this context publishes at:
    /// `/<namespace>/32=trust-context/v=<version>`.
    pub fn rdr_name(&self) -> Name {
        self.namespace
            .clone()
            .append_component(ndn_packet::NameComponent::keyword(Bytes::from_static(
                TRUST_CONTEXT_KEYWORD,
            )))
            .append_version(self.version)
    }

    /// Construct → sign → serialize in one in-process step (NDF F10): wrap this
    /// context's encoded Content into its signed NDN Data object at
    /// [`rdr_name`](Self::rdr_name), ready to publish and to adopt remotely. No
    /// subprocess. The remote consumer decodes with
    /// [`decode_content`](Self::decode_content) (version from the RDR name) and
    /// adopts via [`Keyring::adopt`](crate::Keyring::adopt) (anti-rollback).
    ///
    /// `signer` is any [`Signer`](crate::signer::Signer) whose key signs
    /// synchronously (an in-memory Ed25519/ECDSA key). A signer that signs
    /// only asynchronously — a hardware token, a custodian, a remote signer —
    /// is refused with an error, never turned into an empty signature: use
    /// [`sign_into_data_async`](Self::sign_into_data_async) for those.
    pub fn sign_into_data(
        &self,
        signer: &dyn crate::signer::Signer,
    ) -> Result<Data, SignedTrustContextError> {
        let content = self.encode_content();
        let mut failure = None;
        let wire = ndn_packet::encode::DataBuilder::new(self.rdr_name(), &content).sign_sync(
            signer.sig_type(),
            Some(signer.key_name()),
            |region| match signer.sign_sync(region) {
                Ok(sig) => sig,
                Err(e) => {
                    failure = Some(e);
                    Bytes::new()
                }
            },
        );
        if let Some(e) = failure {
            return Err(SignedTrustContextError::Sign(format!(
                "{} cannot sign synchronously ({e}); sign with sign_into_data_async",
                signer.key_name()
            )));
        }
        signed_context_data(wire, signer)
    }

    /// [`sign_into_data`](Self::sign_into_data) through the signer's async
    /// [`sign`](crate::signer::Signer::sign): works with every signer,
    /// including hardware tokens and custodians whose key sits behind an I/O
    /// boundary. A failed signature is an error, never an empty one.
    pub async fn sign_into_data_async(
        &self,
        signer: &dyn crate::signer::Signer,
    ) -> Result<Data, SignedTrustContextError> {
        let content = self.encode_content();
        let wire = ndn_packet::encode::DataBuilder::new(self.rdr_name(), &content)
            .sign_fallible(signer.sig_type(), Some(signer.key_name()), |region| {
                let region = region.to_vec();
                async move { signer.sign(&region).await }
            })
            .await
            .map_err(|e| {
                SignedTrustContextError::Sign(format!("{} did not sign: {e}", signer.key_name()))
            })?;
        signed_context_data(wire, signer)
    }

    /// Decode a context from the `Content` bytes of its NDN object. The
    /// `version` must be supplied by the caller (it lives in the RDR name).
    /// Decoded contexts keep the hierarchical floor (N1) unless they carry
    /// [`tlv::SCHEMA_AUTHORITATIVE`].
    ///
    /// A single-valued field (Name, AnchorSet, SchemaAuthoritative,
    /// EnrollmentHint, SourceBundleHash, LinkPolicy; SchemaFormat and
    /// SchemaBody inside a blob) that appears twice rejects the context: no
    /// producer emits one twice, and which one counts would be a guess.
    pub fn decode_content(content: &[u8], version: u64) -> Result<Self, SignedTrustContextError> {
        let (t, value, _rest) = read_tlv(content)?;
        if t != tlv::TRUST_CONTEXT {
            return Err(SignedTrustContextError::NotSignedTrustContext(t));
        }

        let mut namespace: Option<Name> = None;
        let mut anchors: Vec<Certificate> = Vec::new();
        let mut schema_blobs: Vec<SchemaBlob> = Vec::new();
        let mut schema_authoritative = false;
        let mut ca_endpoints: Vec<Name> = Vec::new();
        let mut enrollment_hint: Option<EnrollmentHint> = None;
        let mut revocations: Vec<Name> = Vec::new();
        let mut source_bundle_hash: Option<[u8; 32]> = None;
        let mut key_roles: Vec<(KeyRole, Name)> = Vec::new();
        let mut link_policy: Option<LinkPolicy> = None;
        let mut relays: Vec<AdvertisedRelay> = Vec::new();

        let mut seen: Vec<u64> = Vec::new();
        let mut once = |t: u64, field: &'static str| {
            if seen.contains(&t) {
                return Err(SignedTrustContextError::DuplicateField(field));
            }
            seen.push(t);
            Ok(())
        };

        let mut cur = value;
        while !cur.is_empty() {
            let (ft, fval, rest) = read_tlv(cur)?;
            cur = rest;
            match ft {
                ndn_packet::tlv_type::NAME => {
                    once(ft, "Name")?;
                    namespace = Some(
                        Name::decode(Bytes::copy_from_slice(fval))
                            .map_err(|e| SignedTrustContextError::BadName(e.to_string()))?,
                    );
                }
                tlv::ANCHOR_SET => {
                    once(ft, "AnchorSet")?;
                    let mut acur = fval;
                    while !acur.is_empty() {
                        let (at, aval, arest) = read_tlv(acur)?;
                        acur = arest;
                        if at != ndn_packet::tlv_type::DATA {
                            continue;
                        }
                        let mut dw = TlvWriter::new();
                        dw.write_tlv(ndn_packet::tlv_type::DATA, aval);
                        let data = Data::decode(dw.finish())
                            .map_err(|e| SignedTrustContextError::BadAnchor(e.to_string()))?;
                        let cert = Certificate::decode(&data)
                            .map_err(|e| SignedTrustContextError::BadAnchor(e.to_string()))?;
                        anchors.push(cert);
                    }
                }
                tlv::TRUST_SCHEMA_BLOB => {
                    let mut format: Option<SchemaFormat> = None;
                    let mut body: Option<Bytes> = None;
                    let mut scur = fval;
                    while !scur.is_empty() {
                        let (st, sval, srest) = read_tlv(scur)?;
                        scur = srest;
                        match st {
                            tlv::SCHEMA_FORMAT => {
                                let [code] = sval else {
                                    return Err(SignedTrustContextError::BadField(
                                        "SchemaFormat (one octet)",
                                    ));
                                };
                                if format.replace(SchemaFormat::from_code(*code)).is_some() {
                                    return Err(SignedTrustContextError::DuplicateField(
                                        "SchemaFormat",
                                    ));
                                }
                            }
                            tlv::SCHEMA_BODY => {
                                if body.replace(Bytes::copy_from_slice(sval)).is_some() {
                                    return Err(SignedTrustContextError::DuplicateField(
                                        "SchemaBody",
                                    ));
                                }
                            }
                            // Same evolvability rule as the outer fields.
                            other if is_critical(other) => {
                                return Err(SignedTrustContextError::UnknownCritical(other));
                            }
                            _ => {}
                        }
                    }
                    schema_blobs.push(SchemaBlob {
                        format: format
                            .ok_or(SignedTrustContextError::MissingField("SchemaFormat"))?,
                        body: body.ok_or(SignedTrustContextError::MissingField("SchemaBody"))?,
                    });
                }
                tlv::SCHEMA_AUTHORITATIVE => {
                    once(ft, "SchemaAuthoritative")?;
                    schema_authoritative = true;
                }
                tlv::CA_ENDPOINT => {
                    ca_endpoints.push(
                        Name::decode_from_tlv(Bytes::copy_from_slice(fval))
                            .map_err(|e| SignedTrustContextError::BadName(e.to_string()))?,
                    );
                }
                tlv::ENROLLMENT_HINT => {
                    once(ft, "EnrollmentHint")?;
                    enrollment_hint = Some(EnrollmentHint::decode(fval));
                }
                // Non-critical provenance hint (F9): a 32-byte SHA-256 digest.
                // A malformed length is ignored — a hint, not a rule — but
                // still counts as the one SourceBundleHash.
                tlv::SOURCE_BUNDLE_HASH => {
                    once(ft, "SourceBundleHash")?;
                    source_bundle_hash = <[u8; 32]>::try_from(fval).ok();
                }
                tlv::REVOCATION => {
                    revocations.push(
                        Name::decode_from_tlv(Bytes::copy_from_slice(fval))
                            .map_err(|e| SignedTrustContextError::BadName(e.to_string()))?,
                    );
                }
                // A role byte, then the key's Name. A malformed entry is a
                // hint lost, not a rejected context (non-critical).
                tlv::KEY_ROLE if fval.len() > 1 => {
                    if let Ok(key) = Name::decode_from_tlv(Bytes::copy_from_slice(&fval[1..])) {
                        key_roles.push((KeyRole(fval[0]), key));
                    }
                }
                // A malformed policy is a field lost (the default applies),
                // not a rejected context (non-critical).
                tlv::LINK_POLICY => {
                    once(ft, "LinkPolicy")?;
                    link_policy = LinkPolicy::decode(fval);
                }
                // A malformed entry is a relay lost, not a rejected context
                // (non-critical).
                tlv::ADVERTISED_RELAY => relays.extend(AdvertisedRelay::decode(fval)),
                // Unknown critical sub-TLV → reject; unknown non-critical → skip.
                other if is_critical(other) => {
                    return Err(SignedTrustContextError::UnknownCritical(other));
                }
                _ => {}
            }
        }

        let namespace = namespace.ok_or(SignedTrustContextError::MissingField("namespace"))?;
        // A relay outside the namespace is admitted only by its expected
        // fingerprint: an entry without one cannot be used, so it is dropped.
        relays.retain(|r| r.key.is_some() || r.device.has_prefix(&namespace));
        relays.sort_by(AdvertisedRelay::canonical_cmp);
        if schema_blobs.is_empty() {
            return Err(SignedTrustContextError::MissingField("TrustSchemaBlob"));
        }
        let schema = schema_of(&schema_blobs)?;

        let anchor_map: DashMap<Arc<Name>, Certificate> = DashMap::new();
        for cert in anchors {
            anchor_map.insert(Arc::clone(&cert.name), cert);
        }

        Ok(Self {
            namespace,
            anchors: Arc::new(anchor_map),
            schema: RwLock::new(schema),
            enforce_hierarchy: !schema_authoritative,
            version,
            ca_endpoints,
            enrollment_hint,
            revocations,
            schema_blobs,
            schema_authoritative,
            source_bundle_hash,
            key_roles,
            link_policy,
            relays,
        })
    }

    /// The schema blobs to emit: the retained ones, else a native-text
    /// rendering of the current rules.
    fn schema_blobs_or_derive(&self) -> Vec<SchemaBlob> {
        if !self.schema_blobs.is_empty() {
            return self.schema_blobs.clone();
        }
        let schema = self.schema.read().expect("schema RwLock poisoned");
        let text = schema
            .rules()
            .iter()
            .map(|r| r.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        vec![SchemaBlob::native_text(text)]
    }
}

/// SHA-256 over an anchor certificate's public key: the fingerprint an anchor
/// link (`ndn-trust://anchor`, a QR code) carries and a device expects. Over
/// the key, not the whole certificate, so a re-issued anchor certificate for
/// the same key keeps its fingerprint.
pub fn anchor_fingerprint(cert: &Certificate) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(&cert.public_key).into()
}

/// The namespace `<ns>` of a context Data name `<ns>/32=trust-context/v=<N>`,
/// or `None` for any other name shape. Name-only: says nothing about content.
pub fn context_namespace_of(name: &Name) -> Option<Name> {
    let comps = name.components();
    let [.., keyword, version] = comps else {
        return None;
    };
    version.as_version()?;
    if *keyword
        != ndn_packet::NameComponent::keyword(Bytes::from_static(TRUST_CONTEXT_KEYWORD))
    {
        return None;
    }
    Some(Name::from_components(
        comps[..comps.len() - 2].iter().cloned(),
    ))
}

/// Why a Data is not a self-consistent signed trust context
/// ([`SignedTrustContext::open_signed`]).
#[derive(Debug, thiserror::Error)]
pub enum OpenContextError {
    #[error("context Data name {0} is not /<namespace>/32=trust-context/v=<version>")]
    BadName(String),
    #[error("context Data carries no Content")]
    MissingContent,
    #[error("malformed trust context: {0}")]
    Malformed(#[from] SignedTrustContextError),
    #[error("context Data carries no KeyLocator naming its signer")]
    MissingKeyLocator,
    #[error("context signer {0} is not one of the context's own anchors")]
    SignerNotAnchor(String),
    #[error("context signature type {0} is not a public-key signature")]
    UnsupportedSignature(u64),
    #[error("context signature does not verify under anchor {0}")]
    BadSignature(String),
    #[error(
        "context signer {0} is outside its certificate's ValidityPeriod now (expired, or not \
         yet valid: check this device's clock)"
    )]
    SignerNotValid(String),
}

impl SignedTrustContext {
    /// Decode and authenticate a signed trust-context Data: it must be named
    /// at its own context's RDR name (`/<ns>/32=trust-context/v=<version>`) and
    /// carry a public-key signature that verifies under one of the anchors the
    /// context itself lists. Returns the context and the anchor that signed it.
    ///
    /// This proves only *self-consistency* (the context is exactly what its
    /// anchor signed). Whether that anchor is trusted is the caller's decision:
    /// it compares [`anchor_fingerprint`] of the returned anchor with the
    /// fingerprint it expects from an out-of-band link.
    pub async fn open_signed(data: &Data) -> Result<(Self, Certificate), OpenContextError> {
        use ndn_packet::SignatureType;
        let version = data
            .name
            .components()
            .last()
            .and_then(ndn_packet::NameComponent::as_version)
            .ok_or_else(|| OpenContextError::BadName(data.name.to_string()))?;
        let content = data.content().ok_or(OpenContextError::MissingContent)?;
        let ctx = Self::decode_content(content, version)?;
        if *data.name != ctx.rdr_name() {
            return Err(OpenContextError::BadName(data.name.to_string()));
        }

        let sig_info = data.sig_info().ok_or(OpenContextError::MissingKeyLocator)?;
        let signer = sig_info
            .key_locator_name()
            .ok_or(OpenContextError::MissingKeyLocator)?;
        // The anchor of the signer's key, whether the KeyLocator names the key
        // or one of its certificates.
        let anchor = ctx
            .anchor_for(&signer)
            .ok_or_else(|| OpenContextError::SignerNotAnchor(signer.to_string()))?;

        // Only public-key signatures authenticate a signer; a digest or
        // shared-key MAC would let anyone re-sign a tampered context.
        match sig_info.sig_type {
            SignatureType::SignatureEd25519
            | SignatureType::SignatureSha256WithEcdsa
            | SignatureType::SignatureSha256WithRsa => {}
            other => return Err(OpenContextError::UnsupportedSignature(other.code())),
        }
        match crate::verifier::verify_by_sig_type(
            sig_info.sig_type,
            data.signed_region(),
            data.sig_value(),
            &anchor.public_key,
        )
        .await
        {
            Ok(crate::VerifyOutcome::Valid) => Ok((ctx, anchor)),
            _ => Err(OpenContextError::BadSignature(anchor.name.to_string())),
        }
    }

    /// [`open_signed`](Self::open_signed) for a context received from
    /// elsewhere — a first adoption, or an update and each version a
    /// catch-up walk goes through: its signing anchor must also be valid now
    /// (its ValidityPeriod), as a chain walk requires of an anchor it
    /// terminates at. Only the signing anchor of the version received is
    /// checked: the continuity rule matches the held version's anchors by
    /// public key, so a root whose held certificate expired signs the next
    /// version listing a re-issued certificate of the same key. A node's own
    /// stored copy is opened with [`open_signed`](Self::open_signed), so an
    /// expired anchor never stops a root device from making that version.
    pub async fn open_received(data: &Data) -> Result<(Self, Certificate), OpenContextError> {
        let (ctx, anchor) = Self::open_signed(data).await?;
        if !anchor.is_valid_now() {
            return Err(OpenContextError::SignerNotValid(anchor.name.to_string()));
        }
        Ok((ctx, anchor))
    }
}

impl std::fmt::Debug for SignedTrustContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedTrustContext")
            .field("namespace", &self.namespace.to_string())
            .field("version", &self.version)
            .field("anchors", &self.anchors.len())
            .field("enforce_hierarchy", &self.enforce_hierarchy)
            .finish()
    }
}

/// One signing relationship observed in the live cert set: a `(data/command
/// name, signing key name)` pair.
pub type SigningPair = (Name, Name);

/// Schema-tightening dry-run (§8): report which live signing relationships a
/// `candidate` context would **stop** authorizing, *before* applying it. Run
/// the candidate against the current set of `(data_name, key_name)` pairs and
/// return the orphans, so a tighten can show "these identities would stop
/// validating" and apply with a grace window instead of silently breaking
/// working nodes.
pub fn dryrun_orphans(candidate: &SignedTrustContext, live: &[SigningPair]) -> Vec<SigningPair> {
    live.iter()
        .filter(|(data, key)| !candidate.authorizes(data, key))
        .cloned()
        .collect()
}

/// Decode the signed context Data `wire`; a missing signature value is an
/// error (a signer that produced none never yields a "signed" context).
fn signed_context_data(
    wire: Bytes,
    signer: &dyn crate::signer::Signer,
) -> Result<Data, SignedTrustContextError> {
    let data = Data::decode(wire).map_err(|e| SignedTrustContextError::Sign(e.to_string()))?;
    if data.sig_value().is_empty() {
        return Err(SignedTrustContextError::Sign(format!(
            "{} produced an empty signature",
            signer.key_name()
        )));
    }
    Ok(data)
}

/// ndn-cxx evolvability rule: `type <= 31 || (type & 1)`.
fn is_critical(t: u64) -> bool {
    t <= 31 || (t & 1) == 1
}

/// Read one TLV; returns `(type, value, rest)`.
fn read_tlv(input: &[u8]) -> Result<(u64, &[u8], &[u8]), SignedTrustContextError> {
    let (t, tn) = read_varu64(input).map_err(|_| SignedTrustContextError::Truncated("TLV type"))?;
    let (l, ln) =
        read_varu64(&input[tn..]).map_err(|_| SignedTrustContextError::Truncated("TLV length"))?;
    let header = tn + ln;
    let total = header
        .checked_add(l as usize)
        .ok_or(SignedTrustContextError::Truncated("length overflow"))?;
    if total > input.len() {
        return Err(SignedTrustContextError::Truncated("value"));
    }
    Ok((t, &input[header..total], &input[total..]))
}

/// Recover the signing identity from a key/cert name by dropping a trailing
/// `KEY/<keyid>/...` tail. `/home/bob/alice/KEY/k1/self/v=0` → `/home/bob/alice`.
/// Only the GenericNameComponent `KEY` counts (as in
/// [`is_cert_name`](crate::cert_name::is_cert_name)); names without one are
/// returned unchanged.
pub(crate) fn key_identity(key_name: &Name) -> Name {
    let comps = key_name.components();
    match comps.iter().position(crate::cert_name::is_key_component) {
        Some(pos) => Name::from_components(comps[..pos].iter().cloned()),
        None => key_name.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust_schema::{NamePattern, PatternComponent};

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn key_identity_strips_key_tail() {
        assert_eq!(
            key_identity(&n("/home/bob/alice/KEY/k1/self/v=0")),
            n("/home/bob/alice")
        );
        assert_eq!(key_identity(&n("/home/bob/KEY/root")), n("/home/bob"));
        assert_eq!(key_identity(&n("/home/bob")), n("/home/bob"));
    }

    #[test]
    fn hierarchical_floor_blocks_outside_subtree() {
        let ctx = SignedTrustContext::hierarchical(n("/home/bob"));
        let key = n("/home/bob/alice/KEY/k1");
        assert!(ctx.authorizes(&n("/home/bob/alice/doc"), &key));
        assert!(ctx.authorizes(&n("/home/bob/alice/sub/deep/doc"), &key));
        assert!(!ctx.authorizes(&n("/home/bob/charlie/doc"), &key));
    }

    #[test]
    fn accept_all_ignores_floor() {
        let ctx = SignedTrustContext::accept_all(n("/home/bob"));
        let key = n("/home/bob/alice/KEY/k1");
        assert!(ctx.authorizes(&n("/home/bob/charlie/doc"), &key));
    }

    /// An authoritative context carrying an LVS blob and a native-text blob
    /// round-trips both blobs and the floor-off flag; the runtime schema is
    /// their OR; `explain` agrees with `authorizes`. Without the flag the
    /// decoded context keeps the floor.
    #[test]
    fn authoritative_multi_blob_schema_roundtrips() {
        let lvs = crate::lvs_compile::compile_to_binary(
            "#root: /\"home\"/\"bob\"/\"KEY\"/_k\n\
             #ca: /\"home\"/\"bob\"/\"CA\"/\"KEY\"/_k <= #root",
        )
        .unwrap();
        let native = "/home/bob/shared/<**d> => /home/bob/admin/<dev>/KEY/<**k>";
        let blobs = vec![SchemaBlob::lvs(lvs.clone()), SchemaBlob::native_text(native)];
        let ctx = SignedTrustContext::hierarchical(n("/home/bob"))
            .with_schema_blobs(blobs.clone())
            .unwrap()
            .schema_authoritative();
        let back = SignedTrustContext::decode_content(&ctx.encode_content(), 1).unwrap();
        assert!(!back.enforces_hierarchy());
        let published = back.published_schemas();
        assert_eq!(published.len(), 2);
        assert_eq!(published[0].body, lvs);
        assert_eq!(published[1].body.as_ref(), native.as_bytes());

        let admin = n("/home/bob/admin/laptop/KEY/k1");
        let cases = [
            (n("/home/bob/CA/KEY/ca"), n("/home/bob/KEY/root"), true),
            (n("/home/bob/shared/notes"), admin.clone(), true),
            (n("/home/bob/CA/KEY/ca"), admin.clone(), false),
        ];
        for (data, key, allowed) in &cases {
            assert_eq!(back.authorizes(data, key), *allowed, "{data} by {key}");
            let why = back.explain(data, key);
            assert_eq!(why.allowed(), *allowed, "{data} by {key}");
            assert_eq!(why.hierarchy_floor, None);
        }
        assert!(
            back.explain(&cases[1].0, &admin)
                .rule
                .unwrap()
                .starts_with("native rule 0:")
        );

        // The same blobs without the flag: the floor is back and blocks the
        // cross-identity grant.
        let plain = SignedTrustContext::hierarchical(n("/home/bob"))
            .with_schema_blobs(blobs)
            .unwrap();
        let back = SignedTrustContext::decode_content(&plain.encode_content(), 1).unwrap();
        assert!(back.enforces_hierarchy());
        assert!(!back.authorizes(&n("/home/bob/shared/notes"), &admin));
        assert_eq!(
            back.explain(&n("/home/bob/shared/notes"), &admin).hierarchy_floor,
            Some(false)
        );

        // Two LVS blobs are refused.
        let two = SignedTrustContext::hierarchical(n("/home/bob"))
            .with_schema_blobs(vec![SchemaBlob::lvs(lvs.clone()), SchemaBlob::lvs(lvs)]);
        assert!(matches!(two, Err(SignedTrustContextError::MultipleLvsSchemas)));
    }

    #[test]
    fn ambient_preserves_passed_schema_without_floor() {
        let mut schema = TrustSchema::new();
        schema.add_rule(SchemaRule {
            data_pattern: NamePattern(vec![PatternComponent::MultiCapture("_".into())]),
            key_pattern: NamePattern(vec![PatternComponent::MultiCapture("_".into())]),
        });
        let ctx = SignedTrustContext::ambient(schema, Arc::new(DashMap::new()));
        assert!(!ctx.enforces_hierarchy());
        assert!(ctx.authorizes(&n("/anything/at/all"), &n("/totally/unrelated/KEY/k")));
    }

    #[test]
    fn enrollment_hint_roundtrips() {
        let h = EnrollmentHint::namespace_default();
        let decoded = EnrollmentHint::decode(&h.encode());
        assert_eq!(decoded, h);
        // Admins and nodes by an admin's approval alone; members, guests by invite.
        assert!(!decoded.require_all);
        assert_eq!(decoded.challenges, vec!["token", "device-approval"]);
        assert_eq!(decoded.approval_roles, vec!["admin", "node"]);
    }

    #[test]
    fn a_link_policy_survives_the_wire_and_its_absence_is_the_default() {
        let policy = LinkPolicy {
            roles: vec!["admin".into(), "node".into()],
            relay_roles: vec!["node".into()],
            enrollment_links: false,
            direct_paths: false,
            direct_pairs: LinkPolicy::default_direct_pairs(),
        };
        let ctx = SignedTrustContext::hierarchical(n("/home"))
            .with_version(3)
            .with_ca_endpoint(n("/home/CA"))
            .with_link_policy(policy.clone());
        let decoded = SignedTrustContext::decode_content(&ctx.encode_content(), 3).unwrap();
        assert_eq!(decoded.link_policy(), policy);
        assert_eq!(decoded.stated_link_policy(), Some(&policy));
        assert!(!decoded.link_policy().allows_link("member"));
        assert!(decoded.link_policy().allows_relay("node"));
        assert!(!decoded.admits_enrollment_links(), "the policy turned them off");

        let bare = SignedTrustContext::hierarchical(n("/home")).with_version(1);
        let decoded = SignedTrustContext::decode_content(&bare.encode_content(), 1).unwrap();
        let default = decoded.link_policy();
        assert_eq!(decoded.stated_link_policy(), None);
        assert!(["admin", "member", "node", "guest"].iter().all(|r| default.allows_link(r)));
        assert!(default.allows_relay("node") && !default.allows_relay("member"));
        assert!(default.enrollment_links);
        assert!(!decoded.admits_enrollment_links(), "no CA endpoint to enroll at");
        let with_ca = SignedTrustContext::hierarchical(n("/home"))
            .with_version(1)
            .with_ca_endpoint(n("/home/CA"));
        assert!(with_ca.admits_enrollment_links(), "default on for a namespace with a CA");
        assert_eq!(tlv::LINK_POLICY % 2, 0, "an old node must be able to skip it");
    }

    // ── F9: source-bundle provenance hint ──────────────────────────────────

    #[test]
    fn source_bundle_hash_roundtrips() {
        let digest = [0x5au8; 32];
        let ctx = SignedTrustContext::hierarchical(n("/home/bob"))
            .with_version(7)
            .with_source_bundle_hash(digest);
        let wire = ctx.encode_content();
        let decoded = SignedTrustContext::decode_content(&wire, 7).expect("decode");
        assert_eq!(decoded.source_bundle_hash(), Some(&digest));
    }

    #[test]
    fn source_bundle_hash_absent_is_none() {
        // Old/unprojected contexts carry no hint; the field stays None and the
        // object still decodes (the hint is additive, not required).
        let ctx = SignedTrustContext::hierarchical(n("/home/bob")).with_version(1);
        let wire = ctx.encode_content();
        let decoded = SignedTrustContext::decode_content(&wire, 1).expect("decode");
        assert_eq!(decoded.source_bundle_hash(), None);
    }

    #[test]
    fn source_bundle_hash_is_non_critical() {
        // The TLV code is even, so an old node that doesn't understand it skips
        // it rather than rejecting the whole context (NDN evolvability rule).
        assert_eq!(tlv::SOURCE_BUNDLE_HASH % 2, 0);
    }

    /// Key roles survive a re-encode (so every version made from a context
    /// keeps them), unknown role codes included, and the TLV is non-critical.
    #[test]
    fn key_roles_roundtrip_and_are_non_critical() {
        let ctx = SignedTrustContext::hierarchical(n("/home/bob"))
            .with_version(3)
            .with_key_role(KeyRole::RECOVERY_ANCHOR, n("/home/bob/KEY/r0011223344556677"))
            .with_key_role(KeyRole::ROOT_DEVICE, n("/home/bob/CA/KEY/ca"))
            .with_key_role(KeyRole(9), n("/home/bob/x/KEY/k"));
        let decoded = SignedTrustContext::decode_content(&ctx.encode_content(), 3).unwrap();
        assert_eq!(decoded.key_roles(), ctx.key_roles());
        assert!(decoded.has_key_role(&n("/home/bob/CA/KEY/ca"), KeyRole::ROOT_DEVICE));
        assert_eq!(
            decoded.keys_with_role(KeyRole::RECOVERY_ANCHOR).collect::<Vec<_>>(),
            [&n("/home/bob/KEY/r0011223344556677")]
        );
        assert_eq!(tlv::KEY_ROLE % 2, 0);
    }

    // ── F10: in-process authoring (construct → sign → serialize → adopt) ────

    #[test]
    fn sign_into_data_round_trips_and_adopts() {
        use crate::Keyring;
        use crate::signer::Ed25519Signer;

        // Construct a context with the typed builder (no subprocess).
        let ctx = SignedTrustContext::hierarchical(n("/home/bob")).with_version(3);

        // Sign it into its wire Data with the publishing identity's signer.
        let signer = Ed25519Signer::from_seed(&[9u8; 32], n("/home/bob/KEY/k1"));
        let data = ctx.sign_into_data(&signer).expect("sign into data");

        // The Data is named at the canonical RDR name:
        // /home/bob/32=trust-context/v=3 (keyword component + version).
        assert_eq!(*data.name, ctx.rdr_name());
        let comps = ctx.rdr_name();
        let comps = comps.components();
        assert!(ctx.rdr_name().has_prefix(ctx.namespace()));
        assert_eq!(comps[comps.len() - 2].typ, 0x20, "keyword component");
        assert_eq!(comps[comps.len() - 2].value.as_ref(), TRUST_CONTEXT_KEYWORD);
        assert_eq!(comps.last().unwrap().typ, 0x36, "version component");

        // A remote consumer decodes the Content (version from the RDR name) and
        // adopts it with anti-rollback.
        let content = data.content().expect("has content");
        let decoded = SignedTrustContext::decode_content(content, ctx.version()).expect("decode");
        assert_eq!(decoded.version(), 3);
        assert_eq!(decoded.namespace(), ctx.namespace());

        let keyring = Keyring::new();
        assert!(keyring.adopt(Arc::new(decoded)), "first adoption succeeds");
        // Anti-rollback: a lower version is refused.
        let older = SignedTrustContext::hierarchical(n("/home/bob")).with_version(2);
        assert!(!keyring.adopt(Arc::new(older)), "older version refused");
    }

    /// A signer with only an async `sign` (a hardware token, a custodian):
    /// signs through `inner`, or fails when `inner` is `None`.
    struct AsyncOnly {
        inner: Option<crate::signer::Ed25519Signer>,
        key: Name,
    }

    impl crate::signer::Signer for AsyncOnly {
        fn sig_type(&self) -> ndn_packet::SignatureType {
            ndn_packet::SignatureType::SignatureEd25519
        }
        fn key_name(&self) -> &Name {
            &self.key
        }
        fn sign<'a>(
            &'a self,
            region: &'a [u8],
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<Bytes, crate::TrustError>> + Send + 'a>>
        {
            Box::pin(async move {
                match &self.inner {
                    Some(s) => s.sign(region).await,
                    None => Err(crate::TrustError::KeyStore("token unplugged".into())),
                }
            })
        }
    }

    /// An async-only signer never yields a context with an empty signature:
    /// the sync path refuses it, the async path signs for real (verifiable
    /// under the key), and a failing signer is an error.
    #[tokio::test]
    async fn async_only_signers_never_produce_empty_signatures() {
        use crate::signer::{Ed25519Signer, Signer};
        let key = n("/home/bob/KEY/root");
        let ed = Ed25519Signer::from_seed(&[4u8; 32], key.clone());
        let pk = ed.public_key().unwrap();
        let ctx = SignedTrustContext::hierarchical(n("/home/bob")).with_version(2);

        let signer = AsyncOnly {
            inner: Some(ed),
            key: key.clone(),
        };
        assert!(matches!(
            ctx.sign_into_data(&signer),
            Err(SignedTrustContextError::Sign(_))
        ));
        let data = ctx.sign_into_data_async(&signer).await.unwrap();
        assert!(!data.sig_value().is_empty());
        let outcome = crate::verifier::verify_by_sig_type(
            ndn_packet::SignatureType::SignatureEd25519,
            data.signed_region(),
            data.sig_value(),
            &pk,
        )
        .await
        .unwrap();
        assert_eq!(outcome, crate::VerifyOutcome::Valid);

        let unplugged = AsyncOnly { inner: None, key };
        assert!(matches!(
            ctx.sign_into_data_async(&unplugged).await,
            Err(SignedTrustContextError::Sign(_))
        ));
    }

    /// A context "signed" with a MAC keyed with its anchor's public key
    /// (KeyLocator the anchor) — anyone can make one, e.g. to drop a
    /// revocation or add an anchor — never opens; the anchor's real
    /// signature does.
    #[tokio::test]
    async fn a_context_maced_with_its_anchor_public_key_does_not_open() {
        use crate::signer::{Blake3KeyedSigner, Ed25519Signer, HmacSha256Signer, Signer};

        let key = n("/home/bob/KEY/root");
        let root = Ed25519Signer::from_seed(&[5u8; 32], key.clone());
        let pk = root.public_key_bytes();
        let ctx = SignedTrustContext::hierarchical(n("/home/bob")).with_version(2);
        let anchor_wire =
            crate::manager::encode_cert_data(&n("/home/bob/KEY/root/self/v=1"), &pk, &root, 0, u64::MAX)
                .await
                .unwrap();
        let anchor = Certificate::decode(&Data::decode(anchor_wire).unwrap()).unwrap();
        assert!(ctx.add_anchor(anchor));

        let forgers: [Box<dyn Signer>; 2] = [
            Box::new(HmacSha256Signer::new(&pk, key.clone())),
            Box::new(Blake3KeyedSigner::new(pk, key.clone())),
        ];
        for forger in forgers {
            let data = ctx.sign_into_data(forger.as_ref()).expect("MAC into data");
            let opened = SignedTrustContext::open_signed(&data).await;
            assert!(
                matches!(opened, Err(OpenContextError::UnsupportedSignature(_))),
                "a context MACed with its anchor's public key must not open: {opened:?}"
            );
        }
        let data = ctx.sign_into_data(&root).unwrap();
        let (_, anchor) = SignedTrustContext::open_signed(&data).await.unwrap();
        assert!(anchor.name.has_prefix(&key), "{}", anchor.name);
    }

    // ── decoder rules (spec trust-context.md §3.4, Decisions) ──────────────

    fn tlv_bytes(t: u64, v: &[u8]) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_tlv(t, v);
        w.finish()
    }

    /// `content` with the complete TLVs `extra` appended inside TrustContext.
    fn with_fields(content: &[u8], extra: &[Bytes]) -> Bytes {
        let (_, value, _) = read_tlv(content).unwrap();
        let mut w = TlvWriter::new();
        w.write_nested(tlv::TRUST_CONTEXT, |w| {
            w.write_raw(value);
            for field in extra {
                w.write_raw(field);
            }
        });
        w.finish()
    }

    fn blob(sub: &[Bytes]) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(tlv::TRUST_SCHEMA_BLOB, |w| {
            for s in sub {
                w.write_raw(s);
            }
        });
        w.finish()
    }

    /// A later malformed LinkPolicy used to reset an earlier valid one to
    /// the (broader) default. A second copy of any single-valued field now
    /// rejects the context; one malformed LinkPolicy alone is a field lost.
    #[test]
    fn a_repeated_single_valued_field_rejects_the_context() {
        let policy = LinkPolicy {
            roles: vec!["admin".into()],
            relay_roles: vec![],
            enrollment_links: false,
            direct_paths: true,
            direct_pairs: LinkPolicy::default_direct_pairs(),
        };
        let ctx = SignedTrustContext::hierarchical(n("/home")).with_link_policy(policy);
        let content = ctx.encode_content();
        let malformed_policy = tlv_bytes(tlv::LINK_POLICY, b"no separators");
        let twice = with_fields(&content, &[malformed_policy.clone()]);
        assert!(matches!(
            SignedTrustContext::decode_content(&twice, 1),
            Err(SignedTrustContextError::DuplicateField("LinkPolicy"))
        ));

        let bare = SignedTrustContext::hierarchical(n("/home")).encode_content();
        let lost = SignedTrustContext::decode_content(&with_fields(&bare, &[malformed_policy]), 1)
            .unwrap();
        assert_eq!(lost.stated_link_policy(), None);

        for (extra, field) in [
            (n("/other").encode_to_tlv(), "Name"),
            (tlv_bytes(tlv::ANCHOR_SET, &[]), "AnchorSet"),
        ] {
            assert!(
                matches!(
                    SignedTrustContext::decode_content(&with_fields(&bare, &[extra]), 1),
                    Err(SignedTrustContextError::DuplicateField(f)) if f == field
                ),
                "{field}"
            );
        }
        for (t, v, field) in [
            (tlv::ENROLLMENT_HINT, &b"\x00token"[..], "EnrollmentHint"),
            (tlv::SOURCE_BUNDLE_HASH, &[0u8; 3][..], "SourceBundleHash"),
            (tlv::SCHEMA_AUTHORITATIVE, &[][..], "SchemaAuthoritative"),
        ] {
            let once = with_fields(&bare, &[tlv_bytes(t, v)]);
            assert!(SignedTrustContext::decode_content(&once, 1).is_ok(), "{field} once");
            let twice = with_fields(&bare, &[tlv_bytes(t, v), tlv_bytes(t, v)]);
            assert!(
                matches!(
                    SignedTrustContext::decode_content(&twice, 1),
                    Err(SignedTrustContextError::DuplicateField(f)) if f == field
                ),
                "{field} twice"
            );
        }
    }

    /// The fourth field of a LinkPolicy is the direct-path word: absent or
    /// unknown means on. The fifth lists the role pairs: absent or not a
    /// pair list means the default pairs; fields after it are ignored.
    #[test]
    fn link_policy_direct_paths_field_and_later_fields() {
        let unknown = LinkPolicy::decode(b"admin;node;no-enrollment;future,words").unwrap();
        assert_eq!(unknown.roles, ["admin"]);
        assert_eq!(unknown.relay_roles, ["node"]);
        assert!(!unknown.enrollment_links);
        assert!(unknown.allows_direct_paths(), "an unknown word keeps the default");

        let absent = LinkPolicy::decode(b";node;enrollment").unwrap();
        assert_eq!(absent, LinkPolicy::default());
        assert_eq!(LinkPolicy::default().encode(), b";node;enrollment");

        let off = LinkPolicy::decode(b";node;enrollment;no-direct;later").unwrap();
        assert!(!off.allows_direct_paths());
        assert_eq!(off.direct_pairs, LinkPolicy::default_direct_pairs());
        assert_eq!(off.encode(), b";node;enrollment;no-direct");
        assert_eq!(LinkPolicy::decode(&off.encode()).unwrap(), off);
        assert!(off.describe().ends_with("; direct paths: off"));

        let on = LinkPolicy::decode(b";node;enrollment;direct").unwrap();
        assert_eq!(on, LinkPolicy::default());
    }

    /// The direct-path role matrix: default pairs (no guest) when the fifth
    /// field is absent, so an encoding made before the field decodes as it
    /// did; the default writes nothing new; other pairs round-trip in
    /// canonical order, after an explicit fourth field.
    #[test]
    fn link_policy_direct_pairs_round_trip_and_default_is_unchanged() {
        let default = LinkPolicy::default();
        for (a, b) in [("admin", "member"), ("member", "member"), ("node", "admin")] {
            assert!(default.allows_direct_path(a, b), "{a}-{b} by default");
        }
        for other in ["admin", "member", "node", "guest"] {
            assert!(!default.allows_direct_path("guest", other), "guest-{other}");
        }
        // Four fields (an encoding from before the matrix): default pairs.
        let old = LinkPolicy::decode(b"admin,member;node;no-enrollment;direct").unwrap();
        assert_eq!(old.direct_pairs, LinkPolicy::default_direct_pairs());
        assert_eq!(old.encode(), b"admin,member;node;no-enrollment");
        // Stating the default pairs, in any order, writes nothing new.
        let mut reordered = LinkPolicy::default_direct_pairs();
        reordered.reverse();
        reordered.push(("member".into(), "admin".into()));
        let stated = LinkPolicy {
            direct_pairs: reordered,
            ..LinkPolicy::default()
        };
        assert_eq!(stated.encode(), b";node;enrollment");
        assert_eq!(stated.describe(), LinkPolicy::default().describe());

        let members = LinkPolicy {
            direct_pairs: vec![("member".into(), "member".into())],
            ..LinkPolicy::default()
        };
        assert_eq!(members.encode(), b";node;enrollment;direct;member:member");
        assert_eq!(LinkPolicy::decode(&members.encode()).unwrap(), members);
        assert!(members.allows_direct_path("member", "member"));
        assert!(!members.allows_direct_path("admin", "member"));
        assert!(members.describe().ends_with("; direct paths: member:member"));

        let with_guest = LinkPolicy {
            direct_pairs: vec![("member".into(), "guest".into()), ("node".into(), "admin".into())],
            direct_paths: false,
            ..LinkPolicy::default()
        };
        assert_eq!(with_guest.encode(), b";node;enrollment;no-direct;admin:node,guest:member");
        let decoded = LinkPolicy::decode(&with_guest.encode()).unwrap();
        assert_eq!(decoded.direct_pairs, with_guest.canonical_direct_pairs());
        assert!(!decoded.allows_direct_path("guest", "member"), "direct paths are off");

        let none = LinkPolicy {
            direct_pairs: Vec::new(),
            ..LinkPolicy::default()
        };
        assert_eq!(none.encode(), b";node;enrollment;direct;");
        assert_eq!(LinkPolicy::decode(&none.encode()).unwrap(), none);
        assert!(none.describe().ends_with("; direct paths: no role pair"));
    }

    fn relay(device: &str, key: Option<[u8; 32]>, endpoints: &[&str], preference: u32) -> AdvertisedRelay {
        AdvertisedRelay {
            device: n(device),
            key,
            endpoints: endpoints.iter().map(|e| e.to_string()).collect(),
            preference,
        }
    }

    /// Advertised relays survive a re-encode (so every version made from a
    /// context carries them) and encode in canonical order whatever order
    /// they were set in; the TLV is non-critical.
    #[test]
    fn advertised_relays_round_trip_in_canonical_order() {
        let far = relay("/club/node/r", Some([7; 32]), &["club.example.org:6367"], 5);
        let near = relay("/home/node/b", None, &["b.example.net:6367", "192.0.2.1:6367"], 0);
        let tie = relay("/home/node/a", None, &["a.example.net:6367"], 0);
        let ctx = SignedTrustContext::hierarchical(n("/home"))
            .with_version(2)
            .with_relays(vec![far.clone(), near.clone(), tie.clone()]);
        assert_eq!(ctx.relays(), [tie.clone(), near.clone(), far.clone()]);
        let decoded = SignedTrustContext::decode_content(&ctx.encode_content(), 2).unwrap();
        assert_eq!(decoded.relays(), ctx.relays());
        let again = SignedTrustContext::hierarchical(n("/home"))
            .with_version(2)
            .with_relays(vec![near, tie, far]);
        assert_eq!(again.encode_content(), ctx.encode_content());
        assert_eq!(tlv::ADVERTISED_RELAY % 2, 0, "an old node must be able to skip it");
        let bare = SignedTrustContext::hierarchical(n("/home")).with_version(1);
        assert!(SignedTrustContext::decode_content(&bare.encode_content(), 1).unwrap().relays().is_empty());
    }

    /// A malformed relay entry is dropped, not the context; an unknown
    /// non-critical sub-TLV is skipped.
    #[test]
    fn a_malformed_relay_entry_is_skipped() {
        let name = |s: &str| n(s).encode_to_tlv().to_vec();
        let endpoint = tlv_bytes(tlv::RELAY_ENDPOINT, b"r.example.net:6367").to_vec();
        let entry = |parts: &[&[u8]]| tlv_bytes(tlv::ADVERTISED_RELAY, &parts.concat());
        let ok = entry(&[&name("/h/node/ok"), &endpoint, &tlv_bytes(0x0428, b"x")]);
        let malformed = [
            entry(&[&name("/h/node/a")]),                                   // no endpoint
            entry(&[&name("/h/node/b"), &endpoint, &tlv_bytes(0x0429, b"x")]), // unknown critical
            entry(&[&name("/h/node/c"), &tlv_bytes(tlv::RELAY_KEY, &[1; 31]), &endpoint]),
            entry(&[&name("/h/node/d"), &tlv_bytes(tlv::RELAY_ENDPOINT, b"")]),
            entry(&[&name("/h/node/e"), &endpoint, &tlv_bytes(tlv::RELAY_PREFERENCE, &[1; 5])]),
            entry(&[&name("/h/node/f"), &name("/h/node/g"), &endpoint]),
            entry(&[&endpoint]),                                            // no device
            entry(&[&name("/other/node/r"), &endpoint]),                    // outside, no key
        ];
        let mut body = n("/h").encode_to_tlv().to_vec();
        body.extend_from_slice(&tlv_bytes(
            tlv::TRUST_SCHEMA_BLOB,
            &[
                tlv_bytes(tlv::SCHEMA_FORMAT, &[tlv::SCHEMA_FORMAT_NATIVE]),
                tlv_bytes(tlv::SCHEMA_BODY, b""),
            ]
            .concat(),
        ));
        for e in malformed.iter().chain([&ok]) {
            body.extend_from_slice(e);
        }
        let ctx = SignedTrustContext::decode_content(&tlv_bytes(tlv::TRUST_CONTEXT, &body), 1)
            .expect("a malformed relay does not reject the context");
        assert_eq!(ctx.relays(), [relay("/h/node/ok", None, &["r.example.net:6367"], 0)]);
    }

    /// The LinkPolicy and AdvertisedRelay vectors of trust-context.md §11 T5.
    #[test]
    fn spec_vectors_t5_direct_pairs_and_relays() {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let mut w = TlvWriter::new();
        let members = LinkPolicy {
            direct_pairs: vec![("member".into(), "member".into())],
            ..LinkPolicy::default()
        };
        w.write_tlv(tlv::LINK_POLICY, &members.encode());
        assert_eq!(
            hex(&w.finish()),
            "fd0412253b6e6f64653b656e726f6c6c6d656e743b6469726563743b6d656d6265723a6d656d626572"
        );
        let mut w = TlvWriter::new();
        let none = LinkPolicy {
            direct_pairs: Vec::new(),
            ..LinkPolicy::default()
        };
        w.write_tlv(tlv::LINK_POLICY, &none.encode());
        assert_eq!(hex(&w.finish()), "fd0412183b6e6f64653b656e726f6c6c6d656e743b6469726563743b");

        let fingerprint: [u8; 32] = [
            0x56, 0x47, 0x5a, 0xa7, 0x54, 0x63, 0x47, 0x4c, 0x02, 0x85, 0xdf, 0x5d, 0xbf, 0x2b,
            0xca, 0xb7, 0x3d, 0xa6, 0x51, 0x35, 0x88, 0x39, 0xe9, 0xb7, 0x74, 0x81, 0xb2, 0xea,
            0xb1, 0x07, 0x70, 0x8c,
        ];
        let r1 = relay("/home/bob/node/relay", Some(fingerprint), &["relay.example.net:6367"], 0);
        let r2 = relay("/home/bob/node/r2", None, &["192.0.2.7:6367", "[2001:db8::7]:6367"], 300);
        let mut w = TlvWriter::new();
        w.write_tlv(tlv::ADVERTISED_RELAY, &r1.encode());
        assert_eq!(
            hex(&w.finish()),
            "fd04205d07180804686f6d650803626f6208046e6f6465080572656c6179fd0422205647\
             5aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708cfd04241672656c\
             61792e6578616d706c652e6e65743a36333637fd04260100"
        );
        let mut w = TlvWriter::new();
        w.write_tlv(tlv::ADVERTISED_RELAY, &r2.encode());
        assert_eq!(
            hex(&w.finish()),
            "fd04204507150804686f6d650803626f6208046e6f646508027232fd04240e3139322e30\
             2e322e373a36333637fd0424125b323030313a6462383a3a375d3a36333637fd042602012c"
        );
    }

    /// AnchorSet (by certificate name) and Revocation entries are written in
    /// canonical name order whatever order they were added in.
    #[tokio::test]
    async fn anchors_and_revocations_encode_in_canonical_order() {
        use crate::signer::Ed25519Signer;
        let ctx = SignedTrustContext::hierarchical(n("/home/bob"))
            .with_revocation(n("/home/bob/member/z/KEY/k"))
            .with_revocation(n("/home/bob/guest/a/KEY/k"))
            .with_revocation(n("/home/bob/member/b/KEY/k"));
        for (i, id) in ["d", "a", "c", "b"].into_iter().enumerate() {
            let key = n(&format!("/home/bob/KEY/{id}"));
            let signer = Ed25519Signer::from_seed(&[i as u8 + 1; 32], key.clone());
            let cert_name = key.append("self").append_version(1);
            let wire = crate::manager::encode_cert_data(
                &cert_name,
                &signer.public_key_bytes(),
                &signer,
                0,
                u64::MAX,
            )
            .await
            .unwrap();
            assert!(ctx.add_anchor(Certificate::decode(&Data::decode(wire).unwrap()).unwrap()));
        }
        let content = ctx.encode_content();
        assert_eq!(content, ctx.encode_content());

        let (_, value, _) = read_tlv(&content).unwrap();
        let (mut cur, mut anchor_names) = (value, Vec::new());
        while !cur.is_empty() {
            let (t, v, rest) = read_tlv(cur).unwrap();
            cur = rest;
            let mut a = v;
            while t == tlv::ANCHOR_SET && !a.is_empty() {
                let (_, data, more) = read_tlv(a).unwrap();
                a = more;
                let mut dw = TlvWriter::new();
                dw.write_tlv(ndn_packet::tlv_type::DATA, data);
                anchor_names.push(Name::clone(&Data::decode(dw.finish()).unwrap().name));
            }
        }
        let mut sorted = anchor_names.clone();
        sorted.sort();
        assert_eq!(anchor_names.len(), 4);
        assert_eq!(anchor_names, sorted);

        let decoded = SignedTrustContext::decode_content(&content, 1).unwrap();
        assert_eq!(
            decoded.revocations(),
            [
                n("/home/bob/guest/a/KEY/k"),
                n("/home/bob/member/b/KEY/k"),
                n("/home/bob/member/z/KEY/k"),
            ]
        );
    }

    /// A blob in an unknown format authorizes nothing and is kept (and
    /// re-emitted); a context with no blob this node understands is refused.
    #[test]
    fn an_unknown_schema_format_is_skipped_unless_nothing_is_understood() {
        let native = SchemaBlob::native_text("/home/a/<**d> => /home/a/KEY/<k>");
        let ctx = SignedTrustContext::hierarchical(n("/home"))
            .with_schema_blob(native)
            .unwrap();
        let unknown = blob(&[
            tlv_bytes(tlv::SCHEMA_FORMAT, &[9]),
            tlv_bytes(tlv::SCHEMA_BODY, b"/<**d> => /<**k>"),
        ]);
        let content = with_fields(&ctx.encode_content(), &[unknown.clone()]);
        let decoded = SignedTrustContext::decode_content(&content, 1).unwrap();
        let formats: Vec<_> = decoded.published_schemas().iter().map(|b| b.format).collect();
        assert_eq!(formats, [SchemaFormat::NativeText, SchemaFormat::Unknown(9)]);
        assert!(decoded.authorizes(&n("/home/a/x"), &n("/home/a/KEY/k")));
        assert!(!decoded.authorizes(&n("/home/b/x"), &n("/home/b/KEY/k")));
        let again = SignedTrustContext::decode_content(&decoded.encode_content(), 1).unwrap();
        assert_eq!(again.published_schemas()[1].format, SchemaFormat::Unknown(9));

        let mut w = TlvWriter::new();
        w.write_nested(tlv::TRUST_CONTEXT, |w| {
            w.write_raw(&n("/home").encode_to_tlv());
            w.write_tlv(tlv::ANCHOR_SET, &[]);
            w.write_raw(&unknown);
        });
        assert!(matches!(
            SignedTrustContext::decode_content(&w.finish(), 1),
            Err(SignedTrustContextError::UnsupportedSchemaFormat(9))
        ));
    }

    /// Inside a TrustSchemaBlob: an unknown critical (odd) sub-TLV rejects,
    /// an unknown even one is skipped, SchemaFormat is exactly one octet and
    /// neither SchemaFormat nor SchemaBody may repeat.
    #[test]
    fn schema_blob_sub_tlvs_follow_the_critical_bit_rule() {
        let bare = {
            let mut w = TlvWriter::new();
            w.write_nested(tlv::TRUST_CONTEXT, |w| {
                w.write_raw(&n("/home").encode_to_tlv());
                w.write_tlv(tlv::ANCHOR_SET, &[]);
            });
            w.finish()
        };
        let format = tlv_bytes(tlv::SCHEMA_FORMAT, &[tlv::SCHEMA_FORMAT_NATIVE]);
        let body = tlv_bytes(tlv::SCHEMA_BODY, b"/home/<**d> => /home/KEY/<k>");
        let decode = |sub: &[Bytes]| SignedTrustContext::decode_content(&with_fields(&bare, &[blob(sub)]), 1);

        assert!(decode(&[format.clone(), body.clone()]).is_ok());
        assert!(decode(&[format.clone(), tlv_bytes(0x0420, b"x"), body.clone()]).is_ok());
        assert!(matches!(
            decode(&[format.clone(), tlv_bytes(0x0421, b"x"), body.clone()]),
            Err(SignedTrustContextError::UnknownCritical(0x0421))
        ));
        assert!(matches!(
            decode(&[tlv_bytes(tlv::SCHEMA_FORMAT, &[1, 1]), body.clone()]),
            Err(SignedTrustContextError::BadField(_))
        ));
        assert!(matches!(
            decode(&[tlv_bytes(tlv::SCHEMA_FORMAT, &[]), body.clone()]),
            Err(SignedTrustContextError::BadField(_))
        ));
        assert!(matches!(
            decode(&[format.clone(), format.clone(), body.clone()]),
            Err(SignedTrustContextError::DuplicateField("SchemaFormat"))
        ));
        assert!(matches!(
            decode(&[format, body.clone(), body]),
            Err(SignedTrustContextError::DuplicateField("SchemaBody"))
        ));
    }

    /// A context received from elsewhere is refused when its signing anchor
    /// is outside its ValidityPeriod; the holder's own copy still opens.
    #[tokio::test]
    async fn a_context_signed_by_an_expired_anchor_is_not_received() {
        use crate::signer::Ed25519Signer;
        let root = Ed25519Signer::from_seed(&[6u8; 32], n("/home/bob/KEY/root"));
        let pk = root.public_key_bytes();
        let signer = &root;
        let cert = |until: u64| async move {
            let wire = crate::manager::encode_cert_data(
                &n("/home/bob/KEY/root/self/v=1"),
                &pk,
                signer,
                0,
                until,
            )
            .await
            .unwrap();
            Certificate::decode(&Data::decode(wire).unwrap()).unwrap()
        };

        let expired = cert(1).await;
        assert!(!expired.is_valid_now());
        let ctx = SignedTrustContext::hierarchical(n("/home/bob")).with_version(2);
        // `add_anchor` refuses an invalid certificate; a decoded context
        // keeps whatever its producer listed.
        ctx.anchors().insert(Arc::clone(&expired.name), expired);
        let data = ctx.sign_into_data(&root).unwrap();
        assert!(SignedTrustContext::open_signed(&data).await.is_ok());
        assert!(matches!(
            SignedTrustContext::open_received(&data).await,
            Err(OpenContextError::SignerNotValid(_))
        ));

        let valid = SignedTrustContext::hierarchical(n("/home/bob")).with_version(3);
        assert!(valid.add_anchor(cert(u64::MAX).await));
        let data = valid.sign_into_data(&root).unwrap();
        assert!(SignedTrustContext::open_received(&data).await.is_ok());
    }

    /// Only the GenericNameComponent `KEY` ends a signer's identity.
    #[test]
    fn key_identity_ignores_a_typed_key_component() {
        let typed = n("/home/bob").append_component(ndn_packet::NameComponent::keyword(
            Bytes::from_static(b"KEY"),
        ));
        let key = typed.clone().append("k1");
        assert_eq!(key_identity(&key), key);
    }
}
