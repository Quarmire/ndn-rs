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
use ndn_packet::{Data, Name, NameComponent};
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

/// The keyword component naming a namespace's sync group: `/<ns>/32=sync`.
pub const SYNC_GROUP_KEYWORD: &[u8] = b"sync";

/// The sync group of `namespace`: `<namespace>/32=sync`, the State Vector
/// Sync group in which the namespace's devices say they wrote
/// (`docs/specs/data-layer.md` §12). `namespace` is the context's whole
/// namespace name, however many components it has. A forwarder holding the
/// namespace's context runs the group with the multicast strategy and
/// routes it over each link that carries the namespace; a member registers
/// it for its own sync face, beside those routes.
pub fn sync_group(namespace: &Name) -> Name {
    namespace
        .clone()
        .append_component(NameComponent::keyword(Bytes::from_static(
            SYNC_GROUP_KEYWORD,
        )))
}

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
    /// data name) — in the ambient context, for a data name under the
    /// shared `/user`, the shared-`/user` floor's (the key's identity lies
    /// under the same `/user/<x>`) — or `None` when the context enforces
    /// neither for the pair.
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

/// One prefix of a [`RevocationCut`]: Data named `prefix` plus exactly one
/// SequenceNumNameComponent whose value lies in one of `runs` is accepted.
///
/// In a cut, `runs` are inclusive `(first, last)` pairs, ascending, disjoint
/// and non-adjacent (merged), never empty — the canonical form
/// [`RevocationCut::add_run`] keeps and the wire carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CutRange {
    /// The prefix `P` (e.g. a data-layer collection log `<D>/32=log/<C>`).
    pub prefix: Name,
    /// Inclusive runs of accepted sequence numbers.
    pub runs: Vec<(u64, u64)>,
}

impl CutRange {
    /// Whether `seq` lies in one of the runs.
    pub fn contains(&self, seq: u64) -> bool {
        let i = self.runs.partition_point(|&(_, last)| last < seq);
        self.runs.get(i).is_some_and(|&(first, _)| first <= seq)
    }
}

/// Where a revoked key's authority over Data stopped ([`tlv::REVOCATION_CUT`]):
/// the packets the key signed that stay accepted although a Revocation
/// entry covers the key. Everything else the key signed is refused.
///
/// A cut names Data `N` with implicit digest `d` iff some [`CutRange`] has
/// a prefix `P` with `N` = `P` + one SequenceNumNameComponent (minimally
/// encoded) whose value lies in a run ([`range_seq`](Self::range_seq)), or
/// some exact entry equals `N` + `d` (an ImplicitSha256DigestComponent).
/// Two optional bindings narrow that:
///
/// - a key digest ([`tlv::CUT_KEY_DIGEST`], [`key_digest`](Self::key_digest)):
///   only Data verified under the public key whose digest it is
///   ([`public_key_digest`]) is excused — another public key certified
///   under the key's name later (a mis-issued or re-certified one) is not;
/// - a manifest ([`tlv::CUT_MANIFEST`], [`manifest`](Self::manifest)): an
///   in-range packet is accepted only when the manifest
///   ([`cut_manifest`](crate::cut_manifest)) lists exactly its sequence
///   number and implicit digest, so a range binds bytes, not names.
///
/// The producer (the namespace root) adds a cut in the version that
/// revokes its key; later versions carry it verbatim and may only add
/// exact entries ([`readmit`](Self::readmit)). Adopters do not enforce that
/// rule: the anchor that signs the context is the authority over it (an
/// adoption whose cut accepts less than before is revoking, see
/// [`Keyring`](crate::Keyring)).
///
/// Kept canonical: ranges by prefix (NDN canonical order), one per prefix,
/// runs merged; exact entries in canonical order without duplicates. The
/// same cut therefore always encodes to the same bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationCut {
    key: Name,
    key_digest: Option<[u8; 32]>,
    manifest: Option<Name>,
    ranges: Vec<CutRange>,
    exact: Vec<Name>,
}

/// The SHA-256 of a public key as a certificate carries it
/// ([`Certificate::public_key`](crate::Certificate::public_key): the raw
/// 32-octet key for Ed25519, the SubjectPublicKeyInfo DER otherwise) — the
/// value of a cut's [`tlv::CUT_KEY_DIGEST`].
pub fn public_key_digest(public_key: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(public_key).into()
}

impl RevocationCut {
    /// An empty cut for the revoked key `key` (`<id>/KEY/<k>`): it accepts
    /// nothing until runs or exact names are added.
    pub fn new(key: Name) -> Self {
        Self {
            key,
            key_digest: None,
            manifest: None,
            ranges: Vec::new(),
            exact: Vec::new(),
        }
    }

    /// Bind the cut to the revoked key's public key: `digest` is
    /// [`public_key_digest`] of the certificate that verified the entries
    /// the cut lists. Replaces a digest set before.
    pub fn set_key_digest(&mut self, digest: [u8; 32]) {
        self.key_digest = Some(digest);
    }

    /// The digest of the public key the cut is bound to, if it is bound.
    pub fn key_digest(&self) -> Option<&[u8; 32]> {
        self.key_digest.as_ref()
    }

    /// Bind the ranges to bytes: `full_name` is the full name (ending in
    /// its 32-octet ImplicitSha256DigestComponent) of the root packet of
    /// the cut's manifest ([`cut_manifest::build`](crate::cut_manifest::build)).
    /// Replaces a manifest set before. A name without the digest is refused:
    /// the manifest is trusted only by its digest.
    pub fn set_manifest(&mut self, full_name: Name) -> Result<(), SignedTrustContextError> {
        if !ends_in_implicit_digest(&full_name) {
            return Err(SignedTrustContextError::BadField(
                "CutManifest name (it must end in the ImplicitSha256DigestComponent of the \
                 manifest's root packet, 32 octets: give its full name)",
            ));
        }
        self.manifest = Some(full_name);
        Ok(())
    }

    /// The full name of the cut's manifest root packet, if the ranges are
    /// bound to bytes.
    pub fn manifest(&self) -> Option<&Name> {
        self.manifest.as_ref()
    }

    /// Accept `prefix` + SequenceNum `seq`, merged into the runs of `prefix`.
    pub fn add_seq(&mut self, prefix: &Name, seq: u64) {
        self.add_run(prefix, seq, seq);
    }

    /// Accept `prefix` + SequenceNum `first..=last`, merged into the runs of
    /// `prefix`. An inverted run (`first > last`) holds no sequence number
    /// and adds nothing.
    pub fn add_run(&mut self, prefix: &Name, first: u64, last: u64) {
        if first > last {
            return;
        }
        let i = match self.ranges.binary_search_by(|r| r.prefix.cmp(prefix)) {
            Ok(i) => i,
            Err(i) => {
                self.ranges.insert(
                    i,
                    CutRange {
                        prefix: prefix.clone(),
                        runs: Vec::new(),
                    },
                );
                i
            }
        };
        let runs = &mut self.ranges[i].runs;
        // Runs `lo..hi` overlap or touch `first..=last`; they merge into one.
        let lo = runs.partition_point(|&(_, l)| l.saturating_add(1) < first);
        let hi = runs.partition_point(|&(f, _)| f <= last.saturating_add(1));
        if lo == hi {
            runs.insert(lo, (first, last));
        } else {
            let merged = (first.min(runs[lo].0), last.max(runs[hi - 1].1));
            runs.splice(lo..hi, std::iter::once(merged));
        }
    }

    /// Accept exactly the Data `full_name` names: its name followed by its
    /// ImplicitSha256DigestComponent (re-admission of one version). `Ok(false)`
    /// when the cut already holds it. A name that does not end in a 32-octet
    /// digest component is refused: a re-admission binds the bytes, never a
    /// name alone.
    pub fn readmit(&mut self, full_name: Name) -> Result<bool, SignedTrustContextError> {
        if !ends_in_implicit_digest(&full_name) {
            return Err(SignedTrustContextError::BadField(
                "CutExact name (it must end in the ImplicitSha256DigestComponent of the Data, \
                 32 octets: give the full name with its digest)",
            ));
        }
        match self.exact.binary_search(&full_name) {
            Ok(_) => Ok(false),
            Err(i) => {
                self.exact.insert(i, full_name);
                Ok(true)
            }
        }
    }

    /// The revoked key this cut is for.
    pub fn key(&self) -> &Name {
        &self.key
    }

    /// The accepted ranges, by prefix in canonical order.
    pub fn ranges(&self) -> &[CutRange] {
        &self.ranges
    }

    /// The exactly re-admitted Data, full names in canonical order.
    pub fn exact(&self) -> &[Name] {
        &self.exact
    }

    /// The range naming the Data `name` and its sequence number: `name` is
    /// a range's prefix plus one minimally encoded SequenceNumNameComponent
    /// whose value lies in a run. By name only: with a
    /// [`manifest`](Self::manifest), the bytes must also be listed there.
    pub fn range_seq(&self, name: &Name) -> Option<(&CutRange, u64)> {
        let (last, prefix) = name.components().split_last()?;
        let seq = last.as_sequence_num()?;
        // A non-minimal encoding names other Data than the one the producer
        // counted.
        if *last != NameComponent::sequence_num(seq) {
            return None;
        }
        let i = self
            .ranges
            .binary_search_by(|r| r.prefix.components().iter().cmp(prefix.iter()))
            .ok()?;
        let range = &self.ranges[i];
        range.contains(seq).then_some((range, seq))
    }

    /// Whether an exact entry re-admits the Data named `name` whose implicit
    /// digest is `digest` (its name plus digest is listed).
    pub fn accepts_exactly(&self, name: &Name, digest: &[u8; 32]) -> bool {
        !self.exact.is_empty()
            && self
                .exact
                .binary_search(&name.clone().append_implicit_digest(*digest))
                .is_ok()
    }

    /// Whether the cut accepts the Data named `name` whose implicit digest
    /// (SHA-256 of its whole wire) is `digest`, as far as the cut alone can
    /// tell: an exact entry lists it, or a range names it and the cut has
    /// no [`manifest`](Self::manifest) (with one, only the manifest can say;
    /// this answers `false`). The [`key_digest`](Self::key_digest) is not
    /// checked here: it needs the verifying public key. The durable walk
    /// applies every binding ([`Validator::validate_durable`](crate::Validator::validate_durable)).
    pub fn accepts(&self, name: &Name, digest: &[u8; 32]) -> bool {
        self.accepts_exactly(name, digest)
            || (self.manifest.is_none() && self.range_seq(name).is_some())
    }

    /// Whether this cut accepts everything `earlier` (a cut of the same key
    /// in an earlier version) accepts: the same key digest and manifest,
    /// every run of `earlier` inside a run of the same prefix here, and
    /// every exact entry of `earlier` here. A version whose cut does not is
    /// revoking ([`Keyring`](crate::Keyring)).
    pub fn covers(&self, earlier: &RevocationCut) -> bool {
        self.key == earlier.key
            && self.key_digest == earlier.key_digest
            && self.manifest == earlier.manifest
            && earlier.ranges.iter().all(|old| {
                self.ranges
                    .binary_search_by(|r| r.prefix.cmp(&old.prefix))
                    .is_ok_and(|i| {
                        let new = &self.ranges[i];
                        old.runs.iter().all(|&(first, last)| {
                            let j = new.runs.partition_point(|&(_, l)| l < first);
                            new.runs
                                .get(j)
                                .is_some_and(|&(f, l)| f <= first && last <= l)
                        })
                    })
            })
            && earlier
                .exact
                .iter()
                .all(|name| self.exact.binary_search(name).is_ok())
    }

    /// The cut as its [`tlv::REVOCATION_CUT`] TLV.
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(tlv::REVOCATION_CUT, |w| self.write_value(w));
        w.finish()
    }

    fn write_value(&self, w: &mut TlvWriter) {
        w.write_raw(&self.key.encode_to_tlv());
        if let Some(digest) = &self.key_digest {
            w.write_tlv(tlv::CUT_KEY_DIGEST, digest);
        }
        if let Some(manifest) = &self.manifest {
            w.write_tlv(tlv::CUT_MANIFEST, &manifest.encode_to_tlv());
        }
        for range in &self.ranges {
            w.write_nested(tlv::CUT_RANGE, |w| {
                w.write_raw(&range.prefix.encode_to_tlv());
                for &(first, last) in &range.runs {
                    w.write_nested(tlv::CUT_RUN, |w| {
                        w.write_tlv(ndn_packet::tlv_type::SEQUENCE_NUM, &nni(first));
                        w.write_tlv(ndn_packet::tlv_type::SEQUENCE_NUM, &nni(last));
                    });
                }
            });
        }
        for name in &self.exact {
            w.write_tlv(tlv::CUT_EXACT, &name.encode_to_tlv());
        }
    }

    /// Decode one [`tlv::REVOCATION_CUT`] TLV (and nothing after it). Entries
    /// may come in any order; overlapping or adjacent runs and repeated
    /// prefixes or exact names are merged. Refused: a key or prefix that is
    /// not a Name, a range without runs, a run that is not two
    /// SequenceNumNameComponents with first <= last, an exact name not ending
    /// in a 32-octet ImplicitSha256DigestComponent, a key digest that is not
    /// 32 octets, a manifest that is not one Name ending in a 32-octet
    /// ImplicitSha256DigestComponent, a second key digest or manifest, an
    /// unknown critical element. Unknown non-critical elements are skipped.
    pub fn decode(wire: &[u8]) -> Result<Self, SignedTrustContextError> {
        let (t, value, rest) = read_tlv(wire)?;
        if t != tlv::REVOCATION_CUT {
            return Err(SignedTrustContextError::BadField(
                "RevocationCut (TLV-TYPE must be 0x0428)",
            ));
        }
        if !rest.is_empty() {
            return Err(SignedTrustContextError::BadField(
                "RevocationCut (octets follow the TLV)",
            ));
        }
        Self::decode_value(value)
    }

    fn decode_value(value: &[u8]) -> Result<Self, SignedTrustContextError> {
        let (t, key, mut cur) = read_tlv(value)?;
        if t != ndn_packet::tlv_type::NAME {
            return Err(SignedTrustContextError::BadField(
                "RevocationCut (it must start with the revoked key's Name)",
            ));
        }
        let mut cut = Self::new(decode_name(key)?);
        while !cur.is_empty() {
            let (t, v, rest) = read_tlv(cur)?;
            cur = rest;
            match t {
                tlv::CUT_RANGE => {
                    let (pt, prefix, mut runs) = read_tlv(v)?;
                    if pt != ndn_packet::tlv_type::NAME {
                        return Err(SignedTrustContextError::BadField(
                            "CutRange (it must start with its prefix Name)",
                        ));
                    }
                    let prefix = decode_name(prefix)?;
                    let mut any = false;
                    while !runs.is_empty() {
                        let (rt, rv, rest) = read_tlv(runs)?;
                        runs = rest;
                        match rt {
                            tlv::CUT_RUN => {
                                let (first, last) = decode_run(rv)?;
                                cut.add_run(&prefix, first, last);
                                any = true;
                            }
                            other if is_critical(other) => {
                                return Err(SignedTrustContextError::UnknownCritical(other));
                            }
                            _ => {}
                        }
                    }
                    if !any {
                        return Err(SignedTrustContextError::BadField(
                            "CutRange (it holds no CutRun)",
                        ));
                    }
                }
                tlv::CUT_EXACT => {
                    let name = Name::decode_from_tlv(Bytes::copy_from_slice(v))
                        .map_err(|e| SignedTrustContextError::BadName(e.to_string()))?;
                    cut.readmit(name)?;
                }
                tlv::CUT_KEY_DIGEST => {
                    let digest = <[u8; 32]>::try_from(v).map_err(|_| {
                        SignedTrustContextError::BadField("CutKeyDigest (exactly 32 octets)")
                    })?;
                    if cut.key_digest.replace(digest).is_some() {
                        return Err(SignedTrustContextError::DuplicateField("CutKeyDigest"));
                    }
                }
                tlv::CUT_MANIFEST => {
                    let (nt, name, rest) = read_tlv(v)?;
                    if nt != ndn_packet::tlv_type::NAME || !rest.is_empty() {
                        return Err(SignedTrustContextError::BadField(
                            "CutManifest (it must be exactly one Name)",
                        ));
                    }
                    if cut.manifest.is_some() {
                        return Err(SignedTrustContextError::DuplicateField("CutManifest"));
                    }
                    cut.set_manifest(decode_name(name)?)?;
                }
                other if is_critical(other) => {
                    return Err(SignedTrustContextError::UnknownCritical(other));
                }
                _ => {}
            }
        }
        Ok(cut)
    }
}

/// The components of a Name TLV's value.
fn decode_name(value: &[u8]) -> Result<Name, SignedTrustContextError> {
    Name::decode(Bytes::copy_from_slice(value))
        .map_err(|e| SignedTrustContextError::BadName(e.to_string()))
}

/// A [`tlv::CUT_RUN`] value: exactly two SequenceNumNameComponents, each a
/// NonNegativeInteger (1, 2, 4 or 8 octets), first <= last.
fn decode_run(value: &[u8]) -> Result<(u64, u64), SignedTrustContextError> {
    let bad = || {
        SignedTrustContextError::BadField(
            "CutRun (it must be two SequenceNumNameComponents, first <= last)",
        )
    };
    let mut seqs = [0u64; 2];
    let mut cur = value;
    for seq in &mut seqs {
        let (t, v, rest) = read_tlv(cur).map_err(|_| bad())?;
        cur = rest;
        *seq = NameComponent::new(t, Bytes::copy_from_slice(v))
            .as_sequence_num()
            .ok_or_else(bad)?;
    }
    let [first, last] = seqs;
    if !cur.is_empty() || first > last {
        return Err(bad());
    }
    Ok((first, last))
}

/// Whether `name` ends in an ImplicitSha256DigestComponent of 32 octets.
fn ends_in_implicit_digest(name: &Name) -> bool {
    name.components()
        .last()
        .is_some_and(|c| c.typ == ndn_packet::tlv_type::IMPLICIT_SHA256 && c.value.len() == 32)
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
    /// The ambient context's floor under the shared `/user`
    /// ([`user_floor_allows`]): one `/user/<x>`'s keys neither sign nor
    /// certify for another `/user/<y>`. Local, never on the wire.
    shared_user_floor: bool,
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
    /// Where revoked keys' authority over Data stopped
    /// ([`tlv::REVOCATION_CUT`]), at most one per key, sorted by key name.
    revocation_cuts: Vec<RevocationCut>,
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
    /// Device roles whose keys' Data needs a cut once their certificate
    /// lapsed ([`tlv::DATA_REQUIRES_CUT`]), sorted, without duplicates.
    data_requires_cut: Vec<String>,
}

impl SignedTrustContext {
    fn base(namespace: Name, schema: TrustSchema, enforce_hierarchy: bool) -> Self {
        Self {
            namespace,
            anchors: Arc::new(DashMap::new()),
            schema: RwLock::new(schema),
            enforce_hierarchy,
            shared_user_floor: false,
            version: 0,
            ca_endpoints: Vec::new(),
            enrollment_hint: None,
            revocations: Vec::new(),
            revocation_cuts: Vec::new(),
            schema_blobs: Vec::new(),
            schema_authoritative: false,
            source_bundle_hash: None,
            key_roles: Vec::new(),
            link_policy: None,
            relays: Vec::new(),
            data_requires_cut: Vec::new(),
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

    /// The ambient (root-namespace) context backing a [`Validator`](crate::Validator)'s
    /// flat-anchor API for backward compatibility: `schema` over `anchors`
    /// (the handle is shared as-is). The hierarchy floor is **off** so
    /// existing single-anchor callers keep their prior semantics, and so are
    /// the certificate-hop rules of a named context
    /// ([`authorizes_certification`](Self::authorizes_certification)) —
    /// except under the shared `/user`: there one `/user/<x>`'s keys
    /// neither sign nor certify for another `/user/<y>` (see
    /// [`authorizes`](Self::authorizes)). A person's self-certifying names
    /// are never judged by it ([`Keyring::context_for`](crate::Keyring::context_for)).
    pub fn ambient(schema: TrustSchema, anchors: Arc<DashMap<Arc<Name>, Certificate>>) -> Self {
        let mut c = Self::base(Name::root(), schema, false);
        c.anchors = anchors;
        c.shared_user_floor = true;
        c
    }

    /// A context that accepts nothing: no anchors, an empty schema, the
    /// hierarchy floor on. Judges a person's names whose namespace is not
    /// held ([`Keyring::context_for`](crate::Keyring::context_for)); its
    /// namespace is `/`, as the ambient's, since it is no namespace's.
    pub(crate) fn deny_all() -> Self {
        Self::base(Name::root(), TrustSchema::new(), true)
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
    /// Add `cut` (where the revoked key `cut.key()` stopped), replacing a
    /// cut this context holds for the same key. The key's Revocation entry
    /// is added separately ([`with_revocation`](Self::with_revocation)): a
    /// cut without one has no effect.
    pub fn with_revocation_cut(mut self, cut: RevocationCut) -> Self {
        match self
            .revocation_cuts
            .binary_search_by(|c| c.key.cmp(&cut.key))
        {
            Ok(i) => self.revocation_cuts[i] = cut,
            Err(i) => self.revocation_cuts.insert(i, cut),
        }
        self
    }
    /// Drop every cut `drop` selects (e.g. a cut whose key no Revocation
    /// entry names any more).
    pub fn without_revocation_cuts(mut self, drop: impl Fn(&RevocationCut) -> bool) -> Self {
        self.revocation_cuts.retain(|cut| !drop(cut));
        self
    }
    /// List the device role `role` in [`tlv::DATA_REQUIRES_CUT`]: Data a
    /// key of a device of that role signs is accepted by the durable rule
    /// only while a certificate of the key that verifies it is valid by the
    /// reader's clock, or once the key is revoked with a cut
    /// ([`requires_cut_for`](Self::requires_cut_for)). Kept sorted, once.
    pub fn with_data_requires_cut(mut self, role: impl Into<String>) -> Self {
        let role = role.into();
        if let Err(i) = self.data_requires_cut.binary_search(&role) {
            self.data_requires_cut.insert(i, role);
        }
        self
    }
    /// Remove the device role `role` from [`tlv::DATA_REQUIRES_CUT`].
    pub fn without_data_requires_cut(mut self, role: &str) -> Self {
        self.data_requires_cut.retain(|r| r != role);
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
    /// Every revocation cut, by key name in canonical order.
    pub fn revocation_cuts(&self) -> &[RevocationCut] {
        &self.revocation_cuts
    }
    /// The cut for exactly the key `key` (a key name, not a certificate
    /// name), if the context holds one.
    pub fn revocation_cut(&self, key: &Name) -> Option<&RevocationCut> {
        self.revocation_cuts
            .binary_search_by(|c| c.key.cmp(key))
            .ok()
            .map(|i| &self.revocation_cuts[i])
    }
    /// Durable rule for Data named `name` with implicit digest `digest`
    /// signed by `key` (a key or certificate name), as far as the context
    /// alone can tell: `false` when no Revocation entry covers `key`;
    /// otherwise `true` unless the cut of its key
    /// ([`key_name_of`](crate::cert_name::key_name_of)) accepts the Data
    /// ([`RevocationCut::accepts`]: a cut with a manifest accepts an
    /// in-range packet only through the manifest, so it is refused here).
    /// Says nothing about the issuers above `key`, the signature, the cut's
    /// key digest or [`DataRequiresCut`](Self::data_requires_cut): the
    /// durable walk ([`Validator::validate_durable`](crate::Validator::validate_durable))
    /// applies them all.
    pub fn refuses_data(&self, key: &Name, name: &Name, digest: &[u8; 32]) -> bool {
        self.is_revoked(key)
            && !self
                .revocation_cut(&crate::cert_name::key_name_of(key))
                .is_some_and(|cut| cut.accepts(name, digest))
    }
    /// The device roles listed in [`tlv::DATA_REQUIRES_CUT`], sorted.
    pub fn data_requires_cut(&self) -> &[String] {
        &self.data_requires_cut
    }
    /// The device role of `key` (a key or certificate name) under this
    /// context: the name component right after the namespace, for a key of
    /// an identity at least `/<ns>/<role>/<device>`. `None` for the
    /// namespace's own keys (`/<ns>/KEY/..`, `/<ns>/<x>/KEY/..`) and for
    /// names outside the namespace.
    pub fn role_of<'a>(&self, key: &'a Name) -> Option<&'a [u8]> {
        let identity = key_identity(&crate::cert_name::key_name_of(key));
        let ns = self.namespace.len();
        // The identity is a prefix of `key` (a key or certificate name).
        (identity.has_prefix(&self.namespace) && identity.len() >= ns + 2)
            .then(|| key.components()[ns].value.as_ref())
    }
    /// Whether Data signed by `key` (a key or certificate name) needs a cut
    /// once its certificate lapsed: its device role
    /// ([`role_of`](Self::role_of)) is listed in
    /// [`data_requires_cut`](Self::data_requires_cut).
    pub fn requires_cut_for(&self, key: &Name) -> bool {
        !self.data_requires_cut.is_empty()
            && self.role_of(key).is_some_and(|role| {
                self.data_requires_cut
                    .iter()
                    .any(|listed| listed.as_bytes() == role)
            })
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
    /// hierarchy floor (when enabled) — in the ambient context, the
    /// shared-`/user` floor (a name under `/user/<x>` only by a key under
    /// the same `/user/<x>`) — AND the schema must both permit it.
    pub fn authorizes(&self, data_name: &Name, key_name: &Name) -> bool {
        if self.enforce_hierarchy {
            let identity = key_identity(key_name);
            if !data_name.has_prefix(&identity) {
                return false;
            }
        }
        if self.shared_user_floor && !user_floor_allows(data_name, key_name) {
            return false;
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
    pub fn authorizes_hop(
        &self,
        signed: &Name,
        locator: &Name,
        signer_cert: Option<&Name>,
    ) -> bool {
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
    /// and the ambient flat-anchor context judge no certificate hop, except
    /// that in the ambient context a key under one `/user/<x>` certifies no
    /// key under another `/user/<y>`: `/user` is shared by every person, so
    /// it is no authority of its own.
    pub fn authorizes_certification(&self, cert: &Name, issuer: &Name) -> bool {
        use crate::cert_name::key_name_of;
        if self.shared_user_floor && !user_floor_allows(cert, issuer) {
            return false;
        }
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

    /// Whether this is an ambient context judging `/user/<x>` names by the
    /// shared-`/user` floor ([`user_floor_allows`]).
    pub(crate) fn has_shared_user_floor(&self) -> bool {
        self.shared_user_floor
    }

    /// Why [`authorizes`](Self::authorizes) decides as it does for
    /// `(data_name, key_name)`: the hierarchy floor's verdict (if enforced)
    /// and the schema rule that admits the pair. For inspection tooling;
    /// [`ContextExplanation::allowed`] equals `authorizes`.
    pub fn explain(&self, data_name: &Name, key_name: &Name) -> ContextExplanation {
        let floor = self
            .enforce_hierarchy
            .then(|| data_name.has_prefix(&key_identity(key_name)));
        let user_floor = (self.shared_user_floor && under_shared_user(data_name))
            .then(|| user_floor_allows(data_name, key_name));
        let hierarchy_floor = match (floor, user_floor) {
            (None, None) => None,
            (floor, user_floor) => Some(floor != Some(false) && user_floor != Some(false)),
        };
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
    /// skipped. Anchors (by certificate name), Revocation entries and
    /// RevocationCut entries (by key name, each in its canonical form, see
    /// [`RevocationCut`]) are written in canonical NDN name order, so the
    /// same context always encodes to the same bytes.
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
            // RevocationCut entries, by key (`with_revocation_cut`).
            for cut in &self.revocation_cuts {
                w.write_nested(tlv::REVOCATION_CUT, |w| cut.write_value(w));
            }
            // DataRequiresCut roles, sorted (`with_data_requires_cut`).
            for role in &self.data_requires_cut {
                w.write_tlv(tlv::DATA_REQUIRES_CUT, role.as_bytes());
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
        let mut revocation_cuts: Vec<RevocationCut> = Vec::new();
        let mut source_bundle_hash: Option<[u8; 32]> = None;
        let mut key_roles: Vec<(KeyRole, Name)> = Vec::new();
        let mut link_policy: Option<LinkPolicy> = None;
        let mut relays: Vec<AdvertisedRelay> = Vec::new();
        let mut data_requires_cut: Vec<String> = Vec::new();

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
                // A malformed role rejects the context: skipping it would
                // accept Data of a lapsed key the root said needs a cut.
                tlv::DATA_REQUIRES_CUT => {
                    let role = std::str::from_utf8(fval)
                        .ok()
                        .filter(|r| !r.is_empty())
                        .ok_or(SignedTrustContextError::BadField(
                            "DataRequiresCut (a non-empty UTF-8 role name)",
                        ))?;
                    if let Err(i) = data_requires_cut.binary_search_by(|r| r.as_str().cmp(role)) {
                        data_requires_cut.insert(i, role.to_string());
                    }
                }
                // A malformed cut rejects the context: skipping it would
                // refuse what the root kept accepted, and guessing at it
                // could accept what the root cut off.
                tlv::REVOCATION_CUT => {
                    let cut = RevocationCut::decode_value(fval)?;
                    match revocation_cuts.binary_search_by(|c| c.key.cmp(&cut.key)) {
                        Ok(_) => {
                            return Err(SignedTrustContextError::DuplicateField(
                                "RevocationCut for one key",
                            ));
                        }
                        Err(i) => revocation_cuts.insert(i, cut),
                    }
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
            shared_user_floor: false,
            version,
            ca_endpoints,
            enrollment_hint,
            revocations,
            revocation_cuts,
            schema_blobs,
            schema_authoritative,
            source_bundle_hash,
            key_roles,
            link_policy,
            relays,
            data_requires_cut,
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
    if *keyword != ndn_packet::NameComponent::keyword(Bytes::from_static(TRUST_CONTEXT_KEYWORD)) {
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

/// Whether `name` lies under the shared `/user` as `/user/<x>/…` — its
/// second component is no `KEY` component (`/user/KEY/…` is a key of
/// `/user` itself).
fn under_shared_user(name: &Name) -> bool {
    let comps = name.components();
    comps.len() >= 2
        && comps[0].typ == ndn_packet::tlv_type::NAME_COMPONENT
        && comps[0].value.as_ref() == crate::self_certifying::PERSONAL_PREFIX
        && !crate::cert_name::is_key_component(&comps[1])
}

/// The ambient context's shared-`/user` floor: `signer` (a key or
/// certificate name) may sign or certify `signed` (a data, key or
/// certificate name) when `signed` is not under the shared `/user`, or when
/// both lie under the same `/user/<x>`. `/user` is every person's prefix,
/// so it is no authority of its own: the keys of one `/user/<x>` neither
/// sign nor certify for another `/user/<y>` (trust-context.md §6.1).
fn user_floor_allows(signed: &Name, signer: &Name) -> bool {
    !under_shared_user(signed)
        || (under_shared_user(signer) && signer.components()[1] == signed.components()[1])
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
    fn sync_group_is_the_whole_namespace_then_keyword_sync() {
        for ns in ["/alice", "/home/bob"] {
            let group = sync_group(&n(ns));
            let comps = group.components();
            assert_eq!(
                Name::from_components(comps[..comps.len() - 1].to_vec()),
                n(ns)
            );
            let last = comps.last().unwrap();
            assert_eq!(last.typ, ndn_packet::tlv_type::KEYWORD);
            assert_eq!(last.value.as_ref(), SYNC_GROUP_KEYWORD);
        }
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
        let blobs = vec![
            SchemaBlob::lvs(lvs.clone()),
            SchemaBlob::native_text(native),
        ];
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
            back.explain(&n("/home/bob/shared/notes"), &admin)
                .hierarchy_floor,
            Some(false)
        );

        // Two LVS blobs are refused.
        let two = SignedTrustContext::hierarchical(n("/home/bob"))
            .with_schema_blobs(vec![SchemaBlob::lvs(lvs.clone()), SchemaBlob::lvs(lvs)]);
        assert!(matches!(
            two,
            Err(SignedTrustContextError::MultipleLvsSchemas)
        ));
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
        assert!(
            !decoded.admits_enrollment_links(),
            "the policy turned them off"
        );

        let bare = SignedTrustContext::hierarchical(n("/home")).with_version(1);
        let decoded = SignedTrustContext::decode_content(&bare.encode_content(), 1).unwrap();
        let default = decoded.link_policy();
        assert_eq!(decoded.stated_link_policy(), None);
        assert!(
            ["admin", "member", "node", "guest"]
                .iter()
                .all(|r| default.allows_link(r))
        );
        assert!(default.allows_relay("node") && !default.allows_relay("member"));
        assert!(default.enrollment_links);
        assert!(
            !decoded.admits_enrollment_links(),
            "no CA endpoint to enroll at"
        );
        let with_ca = SignedTrustContext::hierarchical(n("/home"))
            .with_version(1)
            .with_ca_endpoint(n("/home/CA"));
        assert!(
            with_ca.admits_enrollment_links(),
            "default on for a namespace with a CA"
        );
        assert_eq!(
            tlv::LINK_POLICY % 2,
            0,
            "an old node must be able to skip it"
        );
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
            .with_key_role(
                KeyRole::RECOVERY_ANCHOR,
                n("/home/bob/KEY/r0011223344556677"),
            )
            .with_key_role(KeyRole::ROOT_DEVICE, n("/home/bob/CA/KEY/ca"))
            .with_key_role(KeyRole(9), n("/home/bob/x/KEY/k"));
        let decoded = SignedTrustContext::decode_content(&ctx.encode_content(), 3).unwrap();
        assert_eq!(decoded.key_roles(), ctx.key_roles());
        assert!(decoded.has_key_role(&n("/home/bob/CA/KEY/ca"), KeyRole::ROOT_DEVICE));
        assert_eq!(
            decoded
                .keys_with_role(KeyRole::RECOVERY_ANCHOR)
                .collect::<Vec<_>>(),
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
        keyring
            .adopt(Arc::new(decoded))
            .expect("first adoption succeeds");
        // Anti-rollback: a lower version is refused.
        let older = SignedTrustContext::hierarchical(n("/home/bob")).with_version(2);
        assert!(
            keyring.adopt(Arc::new(older)).is_err(),
            "older version refused"
        );
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
        let anchor_wire = crate::manager::encode_cert_data(
            &n("/home/bob/KEY/root/self/v=1"),
            &pk,
            &root,
            0,
            u64::MAX,
        )
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
        let twice = with_fields(&content, std::slice::from_ref(&malformed_policy));
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
            assert!(
                SignedTrustContext::decode_content(&once, 1).is_ok(),
                "{field} once"
            );
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
        assert!(
            unknown.allows_direct_paths(),
            "an unknown word keeps the default"
        );

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
        assert!(
            members
                .describe()
                .ends_with("; direct paths: member:member")
        );

        let with_guest = LinkPolicy {
            direct_pairs: vec![
                ("member".into(), "guest".into()),
                ("node".into(), "admin".into()),
            ],
            direct_paths: false,
            ..LinkPolicy::default()
        };
        assert_eq!(
            with_guest.encode(),
            b";node;enrollment;no-direct;admin:node,guest:member"
        );
        let decoded = LinkPolicy::decode(&with_guest.encode()).unwrap();
        assert_eq!(decoded.direct_pairs, with_guest.canonical_direct_pairs());
        assert!(
            !decoded.allows_direct_path("guest", "member"),
            "direct paths are off"
        );

        let none = LinkPolicy {
            direct_pairs: Vec::new(),
            ..LinkPolicy::default()
        };
        assert_eq!(none.encode(), b";node;enrollment;direct;");
        assert_eq!(LinkPolicy::decode(&none.encode()).unwrap(), none);
        assert!(none.describe().ends_with("; direct paths: no role pair"));
    }

    fn relay(
        device: &str,
        key: Option<[u8; 32]>,
        endpoints: &[&str],
        preference: u32,
    ) -> AdvertisedRelay {
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
        let near = relay(
            "/home/node/b",
            None,
            &["b.example.net:6367", "192.0.2.1:6367"],
            0,
        );
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
        assert_eq!(
            tlv::ADVERTISED_RELAY % 2,
            0,
            "an old node must be able to skip it"
        );
        let bare = SignedTrustContext::hierarchical(n("/home")).with_version(1);
        assert!(
            SignedTrustContext::decode_content(&bare.encode_content(), 1)
                .unwrap()
                .relays()
                .is_empty()
        );
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
            entry(&[&name("/h/node/a")]), // no endpoint
            entry(&[&name("/h/node/b"), &endpoint, &tlv_bytes(0x0429, b"x")]), // unknown critical
            entry(&[
                &name("/h/node/c"),
                &tlv_bytes(tlv::RELAY_KEY, &[1; 31]),
                &endpoint,
            ]),
            entry(&[&name("/h/node/d"), &tlv_bytes(tlv::RELAY_ENDPOINT, b"")]),
            entry(&[
                &name("/h/node/e"),
                &endpoint,
                &tlv_bytes(tlv::RELAY_PREFERENCE, &[1; 5]),
            ]),
            entry(&[&name("/h/node/f"), &name("/h/node/g"), &endpoint]),
            entry(&[&endpoint]),                         // no device
            entry(&[&name("/other/node/r"), &endpoint]), // outside, no key
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
        assert_eq!(
            ctx.relays(),
            [relay("/h/node/ok", None, &["r.example.net:6367"], 0)]
        );
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
        assert_eq!(
            hex(&w.finish()),
            "fd0412183b6e6f64653b656e726f6c6c6d656e743b6469726563743b"
        );

        let fingerprint: [u8; 32] = [
            0x56, 0x47, 0x5a, 0xa7, 0x54, 0x63, 0x47, 0x4c, 0x02, 0x85, 0xdf, 0x5d, 0xbf, 0x2b,
            0xca, 0xb7, 0x3d, 0xa6, 0x51, 0x35, 0x88, 0x39, 0xe9, 0xb7, 0x74, 0x81, 0xb2, 0xea,
            0xb1, 0x07, 0x70, 0x8c,
        ];
        let r1 = relay(
            "/home/bob/node/relay",
            Some(fingerprint),
            &["relay.example.net:6367"],
            0,
        );
        let r2 = relay(
            "/home/bob/node/r2",
            None,
            &["192.0.2.7:6367", "[2001:db8::7]:6367"],
            300,
        );
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
        let content = with_fields(&ctx.encode_content(), std::slice::from_ref(&unknown));
        let decoded = SignedTrustContext::decode_content(&content, 1).unwrap();
        let formats: Vec<_> = decoded
            .published_schemas()
            .iter()
            .map(|b| b.format)
            .collect();
        assert_eq!(
            formats,
            [SchemaFormat::NativeText, SchemaFormat::Unknown(9)]
        );
        assert!(decoded.authorizes(&n("/home/a/x"), &n("/home/a/KEY/k")));
        assert!(!decoded.authorizes(&n("/home/b/x"), &n("/home/b/KEY/k")));
        let again = SignedTrustContext::decode_content(&decoded.encode_content(), 1).unwrap();
        assert_eq!(
            again.published_schemas()[1].format,
            SchemaFormat::Unknown(9)
        );

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
        let decode = |sub: &[Bytes]| {
            SignedTrustContext::decode_content(&with_fields(&bare, &[blob(sub)]), 1)
        };

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

    // ── RevocationCut ───────────────────────────────────────────────────────

    const PHONE_KEY: &str = "/home/bob/member/phone/KEY/k1";

    /// `/home/bob/member/phone/32=log`, then `extra` generic components.
    fn log_prefix(extra: &[&str]) -> Name {
        let mut name = n("/home/bob/member/phone")
            .append_component(NameComponent::keyword(Bytes::from_static(b"log")));
        for c in extra {
            name = name.append(c);
        }
        name
    }

    fn digest(first: u8) -> [u8; 32] {
        std::array::from_fn(|i| first.wrapping_add(i as u8))
    }

    /// The cut of trust-context.md §11 T8.
    fn t8_cut() -> RevocationCut {
        let mut cut = RevocationCut::new(n(PHONE_KEY));
        let notes = log_prefix(&["notes"]);
        cut.add_seq(&notes, 7);
        cut.add_run(&notes, 1, 3);
        cut.add_seq(&log_prefix(&[]), 1);
        cut.readmit(
            notes
                .append_sequence_num(9)
                .append_implicit_digest(digest(0)),
        )
        .unwrap();
        cut
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn revocation_cut_tlv_types_are_non_critical() {
        for t in [
            tlv::REVOCATION_CUT,
            tlv::CUT_RANGE,
            tlv::CUT_RUN,
            tlv::CUT_EXACT,
            tlv::CUT_KEY_DIGEST,
            tlv::CUT_MANIFEST,
            tlv::DATA_REQUIRES_CUT,
            tlv::MANIFEST_NODE,
            tlv::MANIFEST_RANGE,
            tlv::MANIFEST_ENTRY,
            tlv::MANIFEST_CHILD,
            tlv::MANIFEST_BOUND,
        ] {
            assert!(!is_critical(t), "{t:#06x} must be even (non-critical)");
        }
    }

    #[test]
    fn revocation_cuts_round_trip_and_carry_into_the_next_version() {
        let cut = t8_cut();
        assert_eq!(RevocationCut::decode(&cut.encode()).unwrap(), cut);

        let other = {
            let mut c = RevocationCut::new(n("/home/bob/member/tablet/KEY/t"));
            c.add_run(&n("/home/bob/member/tablet/x"), 0, u64::MAX);
            c
        };
        let ctx = SignedTrustContext::hierarchical(n("/home/bob"))
            .with_revocation(n(PHONE_KEY))
            .with_revocation(other.key().clone())
            .with_revocation_cut(cut.clone())
            .with_revocation_cut(other.clone());
        let content = ctx.encode_content();
        let next = SignedTrustContext::decode_content(&content, 2).unwrap();
        assert_eq!(next.revocation_cuts(), [cut.clone(), other.clone()]);
        assert_eq!(next.revocation_cut(&n(PHONE_KEY)), Some(&cut));
        assert_eq!(
            next.revocation_cut(&n("/home/bob/member/laptop/KEY/l")),
            None
        );
        // Version N+1 made from N's content carries the cuts verbatim.
        assert_eq!(next.with_version(3).encode_content(), content);

        // A cut for the same key replaces the held one.
        let replaced = SignedTrustContext::hierarchical(n("/home/bob"))
            .with_revocation_cut(cut)
            .with_revocation_cut(RevocationCut::new(n(PHONE_KEY)));
        assert_eq!(
            replaced.revocation_cuts(),
            [RevocationCut::new(n(PHONE_KEY))]
        );
    }

    #[test]
    fn cut_bytes_do_not_depend_on_insertion_order() {
        let notes = log_prefix(&["notes"]);
        let photos = log_prefix(&["photos"]);
        let full = |seq: u64, d: u8| {
            notes
                .clone()
                .append_sequence_num(seq)
                .append_implicit_digest(digest(d))
        };
        let mut a = RevocationCut::new(n(PHONE_KEY));
        for s in [1, 2, 3, 4, 9, 10] {
            a.add_seq(&notes, s);
        }
        a.add_run(&photos, 5, 6);
        a.readmit(full(20, 1)).unwrap();
        a.readmit(full(21, 2)).unwrap();

        let mut b = RevocationCut::new(n(PHONE_KEY));
        b.add_seq(&photos, 6);
        b.readmit(full(21, 2)).unwrap();
        b.add_seq(&notes, 10);
        b.add_run(&notes, 2, 3);
        b.add_seq(&photos, 5);
        b.add_seq(&notes, 9);
        b.add_run(&notes, 1, 4);
        assert!(b.readmit(full(20, 1)).unwrap());
        assert!(!b.readmit(full(20, 1)).unwrap(), "already re-admitted");
        assert_eq!(a.encode(), b.encode());
        // Canonical form: one range per prefix, runs merged when they touch.
        assert_eq!(b.ranges()[0].runs, [(1, 4), (9, 10)]);
        assert_eq!(b.ranges()[1].runs, [(5, 6)]);

        let tablet = RevocationCut::new(n("/home/bob/member/tablet/KEY/t"));
        let one = SignedTrustContext::hierarchical(n("/home/bob"))
            .with_revocation_cut(tablet.clone())
            .with_revocation_cut(a);
        let two = SignedTrustContext::hierarchical(n("/home/bob"))
            .with_revocation_cut(b)
            .with_revocation_cut(tablet);
        assert_eq!(one.encode_content(), two.encode_content());

        // A decoder accepts any order and overlapping runs, and keeps the
        // canonical form.
        let run = |a: u64, b: u64| {
            let mut v = NameComponent::sequence_num(a).value.to_vec();
            v.insert(0, v.len() as u8);
            v.insert(0, 0x3A);
            let mut last = NameComponent::sequence_num(b).value.to_vec();
            last.insert(0, last.len() as u8);
            last.insert(0, 0x3A);
            v.extend(last);
            tlv_bytes(tlv::CUT_RUN, &v).to_vec()
        };
        let range = |prefix: &Name, runs: &[Vec<u8>]| {
            let mut v = prefix.encode_to_tlv().to_vec();
            for r in runs {
                v.extend_from_slice(r);
            }
            tlv_bytes(tlv::CUT_RANGE, &v).to_vec()
        };
        let mut value = n(PHONE_KEY).encode_to_tlv().to_vec();
        value.extend(tlv_bytes(tlv::CUT_EXACT, &full(21, 2).encode_to_tlv()));
        value.extend(range(&photos, &[run(5, 6)]));
        value.extend(range(&notes, &[run(9, 10), run(2, 4), run(1, 3)]));
        value.extend(tlv_bytes(tlv::CUT_EXACT, &full(20, 1).encode_to_tlv()));
        let shuffled = RevocationCut::decode(&tlv_bytes(tlv::REVOCATION_CUT, &value)).unwrap();
        assert_eq!(shuffled.encode(), one.revocation_cuts()[0].encode());
    }

    /// A context without cuts encodes as before: trust-context.md §11 T2,
    /// byte for byte.
    #[tokio::test]
    async fn spec_vector_t2_is_unchanged() {
        use crate::signer::Ed25519Signer;
        let seed: [u8; 32] = std::array::from_fn(|i| i as u8);
        let root = Ed25519Signer::from_seed(&seed, n("/home/bob/KEY/root"));
        let wire = crate::manager::encode_cert_data(
            &n("/home/bob/KEY/root/self").append_version(1),
            &root.public_key_bytes(),
            &root,
            1_700_000_000_000_000_000,
            u64::MAX,
        )
        .await
        .unwrap();
        let ctx = SignedTrustContext::hierarchical(n("/home/bob"))
            .with_version(1)
            .with_schema_blob(SchemaBlob::native_text(
                "/home/bob/shared/<**d> => /home/bob/admin/<dev>/KEY/<**k>",
            ))
            .unwrap()
            .schema_authoritative()
            .with_ca_endpoint(n("/home/bob/CA"))
            .with_enrollment_hint(EnrollmentHint::namespace_default())
            .with_revocation(n(PHONE_KEY))
            .with_key_role(KeyRole::ROOT_DEVICE, n("/home/bob/CA/KEY/ca"))
            .with_link_policy(LinkPolicy::default());
        assert!(ctx.add_anchor(Certificate::decode(&Data::decode(wire).unwrap()).unwrap()));
        let t2 = "fd0410fd01e3070b0804686f6d650803626f62fd0411f206f0071f0804686f6d\
                  650803626f6208034b45590804726f6f74080473656c66360101141418080000\
                  0000000000021908000000000036ee80152c302a300506032b657003210003a1\
                  07bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b81647\
                  1b01051c1807160804686f6d650803626f6208034b45590804726f6f74fd00fd\
                  26fd00fe0f323032333131313454323231333230fd00ff0f3235353430373231\
                  5432333334333317408179b8add1e2b0da55cc806f3d59c67e107814cde57b2a\
                  253521216d52304e36229491d3b6c84ac5c5cd75e45c47c8a503576d7fba17b7\
                  23f9cbfd20c7345b09fd041342fd04150101fd0417392f686f6d652f626f622f\
                  7368617265642f3c2a2a643e203d3e202f686f6d652f626f622f61646d696e2f\
                  3c6465763e2f4b45592f3c2a2a6b3efd041c00fd041411070f0804686f6d6508\
                  03626f6208024341fd04162102746f6b656e2c6465766963652d617070726f76\
                  616c3b61646d696e2c6e6f6465fd04182507230804686f6d650803626f620806\
                  6d656d626572080570686f6e6508034b455908026b31fd041e1b020718080468\
                  6f6d650803626f620802434108034b455908026361fd0412103b6e6f64653b65\
                  6e726f6c6c6d656e74";
        assert_eq!(hex(&ctx.encode_content()), t2);
        let decoded = SignedTrustContext::decode_content(&ctx.encode_content(), 1).unwrap();
        assert!(decoded.revocation_cuts().is_empty());
        assert_eq!(hex(&decoded.encode_content()), t2);

        // The same context with the T8 cut: the cut sits right after the
        // Revocation entry, and nothing else moves.
        let with_cut = decoded.with_revocation_cut(t8_cut());
        let content = with_cut.encode_content();
        let revocation = "fd04182507230804686f6d650803626f6208066d656d626572080570686f6e65\
                          08034b455908026b31";
        let at = t2.find(revocation).unwrap() + revocation.len();
        let body = hex(&content);
        assert_eq!(&body[body.len() - (t2.len() - at)..], &t2[at..]);
        assert!(body.contains(&format!("{revocation}{}", hex(&t8_cut().encode()))));
    }

    /// The RevocationCut vector of trust-context.md §11 T8: key
    /// `/home/bob/member/phone/KEY/k1`; CutRange `/home/bob/member/phone/32=log`
    /// run 1–1; CutRange `/home/bob/member/phone/32=log/notes` runs 1–3 and
    /// 7–7; CutExact `/home/bob/member/phone/32=log/notes/seq=9` with the
    /// digest `000102…1f`.
    #[test]
    fn spec_vector_t8_revocation_cut() {
        assert_eq!(
            hex(&t8_cut().encode()),
            "fd0428e507230804686f6d650803626f6208066d656d626572080570686f6e65\
             08034b455908026b31fd042a2b071f0804686f6d650803626f6208066d656d62\
             6572080570686f6e6520036c6f67fd042c063a01013a0101fd042a3c07260804\
             686f6d650803626f6208066d656d626572080570686f6e6520036c6f6708056e\
             6f746573fd042c063a01013a0103fd042c063a01073a0107fd042e4d074b0804\
             686f6d650803626f6208066d656d626572080570686f6e6520036c6f6708056e\
             6f7465733a01090120000102030405060708090a0b0c0d0e0f10111213141516\
             1718191a1b1c1d1e1f"
        );
    }

    /// A full name standing for a manifest root in decoder tests.
    fn manifest_name() -> Name {
        n("/home/bob/m/seg=0").append_implicit_digest(digest(0x20))
    }

    /// The manifest of trust-context.md §11 T10: the entries the T8 cut's
    /// ranges accept, each with the digest `digest(seq)`.
    fn t10_manifest() -> crate::cut_manifest::BuiltManifest {
        let notes = log_prefix(&["notes"]);
        let entries: Vec<(Name, u64, [u8; 32])> = [1, 2, 3, 7]
            .into_iter()
            .map(|s| (notes.clone(), s, digest(s as u8)))
            .chain([(log_prefix(&[]), 1, digest(1))])
            .collect();
        crate::cut_manifest::build(&n("/home/bob"), &n(PHONE_KEY), &entries).unwrap()
    }

    /// The cut of trust-context.md §11 T9: T8 bound to the public key
    /// whose digest is `404142…5f` and to the T10 manifest.
    fn t9_cut() -> RevocationCut {
        let mut cut = t8_cut();
        cut.set_key_digest(digest(0x40));
        cut.set_manifest(t10_manifest().root).unwrap();
        cut
    }

    /// T8's bytes stay a valid cut of the old form: no key digest, no
    /// manifest, ranges by name.
    #[test]
    fn t8_bytes_decode_as_an_old_form_cut() {
        let cut = RevocationCut::decode(&t8_cut().encode()).unwrap();
        assert_eq!(cut.key_digest(), None);
        assert_eq!(cut.manifest(), None);
        let in_range = log_prefix(&["notes"]).append_sequence_num(2);
        assert!(cut.accepts(&in_range, &digest(0x77)));
    }

    /// T9: the key digest and the manifest come right after the key Name,
    /// before the ranges; they round-trip, and a range of a cut with a
    /// manifest accepts nothing by name alone.
    #[test]
    fn spec_vector_t9_cut_with_key_digest_and_manifest() {
        let cut = t9_cut();
        let wire = cut.encode();
        assert_eq!(
            hex(&wire),
            "fd0428fd017507230804686f6d650803626f6208066d656d626572080570686f\
             6e6508034b455908026b31fd043020404142434445464748494a4b4c4d4e4f50\
             5152535455565758595a5b5c5d5e5ffd04326807660804686f6d650803626f62\
             200d74727573742d636f6e7465787420036375740820b016d8ea2979c8cb799a\
             1819b433608c13e16299ae0a35e53c87f659c2490a60320100012094f6b9944d\
             ec675aec156eded41ba373d407e9f35ea6ac4168e8618a9357710afd042a2b07\
             1f0804686f6d650803626f6208066d656d626572080570686f6e6520036c6f67\
             fd042c063a01013a0101fd042a3c07260804686f6d650803626f6208066d656d\
             626572080570686f6e6520036c6f6708056e6f746573fd042c063a01013a0103\
             fd042c063a01073a0107fd042e4d074b0804686f6d650803626f6208066d656d\
             626572080570686f6e6520036c6f6708056e6f7465733a010901200001020304\
             05060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        );
        let back = RevocationCut::decode(&wire).unwrap();
        assert_eq!(back, cut);
        assert_eq!(back.key_digest(), Some(&digest(0x40)));
        assert_eq!(back.manifest(), Some(&t10_manifest().root));
        let in_range = log_prefix(&["notes"]).append_sequence_num(2);
        assert!(back.range_seq(&in_range).is_some());
        assert!(
            !back.accepts(&in_range, &digest(2)),
            "only the manifest decides"
        );
        let exact = log_prefix(&["notes"]).append_sequence_num(9);
        assert!(
            back.accepts(&exact, &digest(0)),
            "an exact entry binds bytes itself"
        );
        // Encoded inside a context, the cut keeps its bytes.
        let ctx = SignedTrustContext::hierarchical(n("/home/bob"))
            .with_revocation(n(PHONE_KEY))
            .with_revocation_cut(cut.clone());
        let decoded = SignedTrustContext::decode_content(&ctx.encode_content(), 1).unwrap();
        assert_eq!(decoded.revocation_cut(&n(PHONE_KEY)), Some(&cut));
    }

    /// T10: the one manifest packet of the T9 cut (name, DigestSha256,
    /// FreshnessPeriod, CutManifestNode content).
    #[test]
    fn spec_vector_t10_manifest_packet() {
        let built = t10_manifest();
        assert_eq!(built.packets.len(), 1);
        assert_eq!(
            hex(&built.packets[0]),
            "06fd019d07440804686f6d650803626f62200d74727573742d636f6e74657874\
             20036375740820b016d8ea2979c8cb799a1819b433608c13e16299ae0a35e53c\
             87f659c2490a60320100140619040036ee8015fd0124fd0436fd011efd04384a\
             071f0804686f6d650803626f6208066d656d626572080570686f6e6520036c6f\
             67fd043a253a010101200102030405060708090a0b0c0d0e0f10111213141516\
             1718191a1b1c1d1e1f20fd0438cc07260804686f6d650803626f6208066d656d\
             626572080570686f6e6520036c6f6708056e6f746573fd043a253a0101012001\
             02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20fd\
             043a253a0102012002030405060708090a0b0c0d0e0f10111213141516171819\
             1a1b1c1d1e1f2021fd043a253a01030120030405060708090a0b0c0d0e0f1011\
             12131415161718191a1b1c1d1e1f202122fd043a253a010701200708090a0b0c\
             0d0e0f101112131415161718191a1b1c1d1e1f2021222324252616031b010017\
             208b88bc33ba60b31453c9457f2a9561713450540ef8c118be605d8b755f8009\
             05"
        );
        assert_eq!(
            hex(&built.root.encode_to_tlv()),
            "07660804686f6d650803626f62200d74727573742d636f6e7465787420036375\
             740820b016d8ea2979c8cb799a1819b433608c13e16299ae0a35e53c87f659c2\
             490a60320100012094f6b9944dec675aec156eded41ba373d407e9f35ea6ac41\
             68e8618a9357710a"
        );
    }

    /// DataRequiresCut: sorted, once, right after the RevocationCut
    /// entries; carried through decode and encode.
    #[test]
    fn data_requires_cut_round_trips_in_canonical_order() {
        assert!(!is_critical(tlv::DATA_REQUIRES_CUT));
        let ctx = SignedTrustContext::hierarchical(n("/home/bob"))
            .with_revocation(n(PHONE_KEY))
            .with_revocation_cut(t8_cut())
            .with_data_requires_cut("relay")
            .with_data_requires_cut("guest")
            .with_data_requires_cut("guest");
        assert_eq!(ctx.data_requires_cut(), ["guest", "relay"]);
        let content = ctx.encode_content();
        let element = hex(&tlv_bytes(tlv::DATA_REQUIRES_CUT, b"guest"));
        assert_eq!(element, "fd0434056775657374");
        let wire = hex(&content);
        let cut_at = wire.find(&hex(&t8_cut().encode())).unwrap();
        let guest_at = wire.find(&element).unwrap();
        assert!(cut_at < guest_at, "after the cuts");
        assert!(
            guest_at
                < wire
                    .find(&hex(&tlv_bytes(tlv::DATA_REQUIRES_CUT, b"relay")))
                    .unwrap()
        );
        let back = SignedTrustContext::decode_content(&content, 1).unwrap();
        assert_eq!(back.data_requires_cut(), ["guest", "relay"]);
        assert_eq!(back.encode_content(), content);
        let without = back.without_data_requires_cut("relay");
        assert_eq!(without.data_requires_cut(), ["guest"]);

        // The role is the component after the namespace, of a device key.
        let guest =
            SignedTrustContext::hierarchical(n("/home/bob")).with_data_requires_cut("guest");
        assert!(guest.requires_cut_for(&n("/home/bob/guest/ann/KEY/1")));
        assert!(guest.requires_cut_for(&n("/home/bob/guest/ann/KEY/1/CA/v=1")));
        assert!(!guest.requires_cut_for(&n("/home/bob/member/ann/KEY/1")));
        assert!(
            !guest.requires_cut_for(&n("/home/bob/guest/KEY/1")),
            "no device"
        );
        assert!(!guest.requires_cut_for(&n("/home/alice/guest/ann/KEY/1")));
    }

    /// `covers`: a later cut that only adds accepts everything the earlier
    /// one did; one that drops or rebinds anything does not.
    #[test]
    fn a_cut_covers_an_earlier_one_only_when_it_accepts_all_of_it() {
        let earlier = t8_cut();
        let notes = log_prefix(&["notes"]);
        let mut grown = earlier.clone();
        grown.add_run(&notes, 4, 6);
        grown
            .readmit(
                notes
                    .clone()
                    .append_sequence_num(11)
                    .append_implicit_digest(digest(3)),
            )
            .unwrap();
        assert!(grown.covers(&earlier));
        assert!(earlier.covers(&earlier));
        assert!(!earlier.covers(&grown));

        let mut shrunk = RevocationCut::new(n(PHONE_KEY));
        shrunk.add_run(&notes, 1, 2);
        shrunk.add_seq(&notes, 7);
        shrunk.add_seq(&log_prefix(&[]), 1);
        shrunk
            .readmit(
                notes
                    .clone()
                    .append_sequence_num(9)
                    .append_implicit_digest(digest(0)),
            )
            .unwrap();
        assert!(!shrunk.covers(&earlier), "a run shrunk");
        let mut bound = earlier.clone();
        bound.set_key_digest(digest(1));
        assert!(!bound.covers(&earlier), "a key digest added");
        let mut manifested = earlier.clone();
        manifested.set_manifest(manifest_name()).unwrap();
        assert!(!manifested.covers(&earlier), "a manifest added");
        assert!(!earlier.covers(&manifested), "a manifest removed");
    }

    #[test]
    fn malformed_revocation_cuts_reject_the_context() {
        let base = SignedTrustContext::hierarchical(n("/home/bob"))
            .with_revocation(n(PHONE_KEY))
            .encode_content();
        let key = n(PHONE_KEY).encode_to_tlv().to_vec();
        let notes = log_prefix(&["notes"]).encode_to_tlv().to_vec();
        let seq = |v: &[u8]| tlv_bytes(0x3A, v).to_vec();
        let run = |parts: &[Vec<u8>]| tlv_bytes(tlv::CUT_RUN, &parts.concat()).to_vec();
        let range = |parts: &[Vec<u8>]| tlv_bytes(tlv::CUT_RANGE, &parts.concat()).to_vec();
        let exact = |name: Name| tlv_bytes(tlv::CUT_EXACT, &name.encode_to_tlv()).to_vec();
        let cut = |parts: &[Vec<u8>]| tlv_bytes(tlv::REVOCATION_CUT, &parts.concat());
        let good_run = run(&[seq(&[1]), seq(&[2])]);
        let in_notes = |s: u64| log_prefix(&["notes"]).append_sequence_num(s);

        let malformed: Vec<(&str, Vec<Bytes>)> = vec![
            (
                "run with first > last",
                vec![cut(&[
                    key.clone(),
                    range(&[notes.clone(), run(&[seq(&[3]), seq(&[2])])]),
                ])],
            ),
            (
                "run with one component",
                vec![cut(&[
                    key.clone(),
                    range(&[notes.clone(), run(&[seq(&[3])])]),
                ])],
            ),
            (
                "run with three components",
                vec![cut(&[
                    key.clone(),
                    range(&[notes.clone(), run(&[seq(&[1]), seq(&[2]), seq(&[3])])]),
                ])],
            ),
            (
                "run of non-sequence components",
                vec![cut(&[
                    key.clone(),
                    range(&[
                        notes.clone(),
                        run(&[tlv_bytes(0x32, &[1]).to_vec(), seq(&[2])]),
                    ]),
                ])],
            ),
            (
                "sequence number not a NonNegativeInteger",
                vec![cut(&[
                    key.clone(),
                    range(&[notes.clone(), run(&[seq(&[0, 0, 1]), seq(&[2])])]),
                ])],
            ),
            (
                "range without runs",
                vec![cut(&[key.clone(), range(std::slice::from_ref(&notes))])],
            ),
            (
                "range without a prefix Name",
                vec![cut(&[key.clone(), range(std::slice::from_ref(&good_run))])],
            ),
            (
                "exact name without a digest",
                vec![cut(&[key.clone(), exact(in_notes(9))])],
            ),
            (
                "exact name with a short digest",
                vec![cut(&[
                    key.clone(),
                    exact(in_notes(9).append_component(NameComponent::new(
                        ndn_packet::tlv_type::IMPLICIT_SHA256,
                        Bytes::from_static(&[0; 31]),
                    ))),
                ])],
            ),
            (
                "no key Name",
                vec![cut(&[range(&[notes.clone(), good_run.clone()])])],
            ),
            ("empty cut", vec![cut(&[])]),
            (
                "malformed key Name",
                vec![cut(&[tlv_bytes(0x07, &[0x08, 0x05, b'a']).to_vec()])],
            ),
            (
                "unknown critical element",
                vec![cut(&[key.clone(), tlv_bytes(0x0431, &[]).to_vec()])],
            ),
            (
                "two cuts for one key",
                vec![
                    cut(std::slice::from_ref(&key)),
                    cut(std::slice::from_ref(&key)),
                ],
            ),
            (
                "key digest of 31 octets",
                vec![cut(&[
                    key.clone(),
                    tlv_bytes(tlv::CUT_KEY_DIGEST, &[0; 31]).to_vec(),
                ])],
            ),
            (
                "two key digests",
                vec![cut(&[
                    key.clone(),
                    tlv_bytes(tlv::CUT_KEY_DIGEST, &[0; 32]).to_vec(),
                    tlv_bytes(tlv::CUT_KEY_DIGEST, &[1; 32]).to_vec(),
                ])],
            ),
            (
                "manifest name without a digest",
                vec![cut(&[
                    key.clone(),
                    tlv_bytes(tlv::CUT_MANIFEST, &n("/home/bob/m").encode_to_tlv()).to_vec(),
                ])],
            ),
            (
                "manifest that is not one Name",
                vec![cut(&[
                    key.clone(),
                    tlv_bytes(
                        tlv::CUT_MANIFEST,
                        &[
                            manifest_name().encode_to_tlv().to_vec(),
                            tlv_bytes(0x08, b"x").to_vec(),
                        ]
                        .concat(),
                    )
                    .to_vec(),
                ])],
            ),
            (
                "two manifests",
                vec![cut(&[
                    key.clone(),
                    tlv_bytes(tlv::CUT_MANIFEST, &manifest_name().encode_to_tlv()).to_vec(),
                    tlv_bytes(tlv::CUT_MANIFEST, &manifest_name().encode_to_tlv()).to_vec(),
                ])],
            ),
            (
                "empty DataRequiresCut role",
                vec![tlv_bytes(tlv::DATA_REQUIRES_CUT, &[])],
            ),
            (
                "DataRequiresCut role not UTF-8",
                vec![tlv_bytes(tlv::DATA_REQUIRES_CUT, &[0xFF, 0xFE])],
            ),
        ];
        for (why, fields) in malformed {
            assert!(
                SignedTrustContext::decode_content(&with_fields(&base, &fields), 1).is_err(),
                "{why}: the context must be refused"
            );
        }

        // Well-formed, with an unknown non-critical element skipped.
        let fine = cut(&[
            key.clone(),
            tlv_bytes(0x0440, b"later").to_vec(),
            range(&[notes.clone(), good_run.clone()]),
        ]);
        let ctx = SignedTrustContext::decode_content(&with_fields(&base, &[fine]), 1).unwrap();
        assert!(ctx.revocation_cut(&n(PHONE_KEY)).is_some());

        // `readmit` refuses a name that does not end in a full digest.
        let mut cut = RevocationCut::new(n(PHONE_KEY));
        assert!(cut.readmit(in_notes(9)).is_err());
        assert!(cut.exact().is_empty());
    }

    #[test]
    fn a_cut_accepts_its_prefix_plus_one_sequence_number_in_a_run() {
        let cut = t8_cut();
        let notes = log_prefix(&["notes"]);
        let d = digest(0x40);
        let at = |prefix: &Name, seq: u64| prefix.clone().append_sequence_num(seq);

        for seq in [1, 2, 3, 7] {
            assert!(
                cut.accepts(&at(&notes, seq), &d),
                "notes seq {seq} is in a run"
            );
        }
        assert!(cut.accepts(&at(&log_prefix(&[]), 1), &d), "snapshot 1");
        for seq in [0, 4, 6, 8] {
            assert!(
                !cut.accepts(&at(&notes, seq), &d),
                "notes seq {seq} is in a gap"
            );
        }
        assert!(!cut.accepts(&at(&log_prefix(&[]), 2), &d));
        // The same sequence number under another prefix.
        assert!(!cut.accepts(&at(&log_prefix(&["photos"]), 2), &d));
        assert!(!cut.accepts(&at(&n("/home/bob/member/laptop/x"), 2), &d));
        // An extra component after (or before) the sequence number.
        assert!(!cut.accepts(&at(&notes, 2).append("x"), &d));
        assert!(!cut.accepts(&at(&notes.clone().append("x"), 2), &d));
        assert!(!cut.accepts(&at(&notes, 2).append_segment(0), &d));
        // The prefix itself, and another component type with the value.
        assert!(!cut.accepts(&notes, &d));
        assert!(!cut.accepts(&notes.clone().append_version(2), &d));
        // A non-minimal encoding of an accepted number names other Data.
        let padded = notes.clone().append_component(NameComponent::new(
            ndn_packet::tlv_type::SEQUENCE_NUM,
            Bytes::from_static(&[0, 2]),
        ));
        assert!(!cut.accepts(&padded, &d));

        // CutExact: that name with exactly that digest.
        assert!(cut.accepts(&at(&notes, 9), &digest(0)));
        assert!(!cut.accepts(&at(&notes, 9), &digest(1)));
        assert!(!cut.accepts(&at(&notes, 10), &digest(0)));
        assert!(!cut.accepts(&at(&log_prefix(&["photos"]), 9), &digest(0)));
    }

    #[test]
    fn refuses_data_is_the_revocation_minus_the_cut() {
        let notes = log_prefix(&["notes"]);
        let inside = notes.clone().append_sequence_num(2);
        let outside = notes.clone().append_sequence_num(5);
        let d = digest(9);
        let cert = n(PHONE_KEY).append("NA").append_version(3);

        let unrevoked = SignedTrustContext::hierarchical(n("/home/bob"));
        assert!(!unrevoked.refuses_data(&n(PHONE_KEY), &outside, &d));

        let uncut = SignedTrustContext::hierarchical(n("/home/bob")).with_revocation(n(PHONE_KEY));
        for key in [n(PHONE_KEY), cert.clone()] {
            assert!(uncut.refuses_data(&key, &inside, &d));
        }

        let cut = uncut.with_revocation_cut(t8_cut());
        for key in [n(PHONE_KEY), cert.clone()] {
            assert!(
                !cut.refuses_data(&key, &inside, &d),
                "{key}: inside the cut"
            );
            assert!(
                cut.refuses_data(&key, &outside, &d),
                "{key}: outside the cut"
            );
        }
        // A cut of another key excuses nothing.
        let tablet = SignedTrustContext::hierarchical(n("/home/bob"))
            .with_revocation(n("/home/bob/member/tablet/KEY/t"))
            .with_revocation_cut(t8_cut());
        assert!(tablet.refuses_data(&n("/home/bob/member/tablet/KEY/t"), &inside, &d));
        // A cut without a revocation changes nothing.
        let alone = SignedTrustContext::hierarchical(n("/home/bob")).with_revocation_cut(t8_cut());
        assert!(!alone.refuses_data(&n(PHONE_KEY), &outside, &d));
    }
}
