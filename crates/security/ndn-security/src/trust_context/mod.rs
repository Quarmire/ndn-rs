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
    #[error("unsupported schema format: {0}")]
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
}

impl SchemaFormat {
    fn code(self) -> u8 {
        match self {
            SchemaFormat::NativeText => tlv::SCHEMA_FORMAT_NATIVE,
            SchemaFormat::Lvs => tlv::SCHEMA_FORMAT_LVS,
        }
    }
    fn from_code(c: u8) -> Result<Self, SignedTrustContextError> {
        match c {
            tlv::SCHEMA_FORMAT_NATIVE => Ok(SchemaFormat::NativeText),
            tlv::SCHEMA_FORMAT_LVS => Ok(SchemaFormat::Lvs),
            other => Err(SignedTrustContextError::UnsupportedSchemaFormat(other)),
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

/// The runtime schema for a set of blobs: their OR.
fn schema_of(blobs: &[SchemaBlob]) -> Result<TrustSchema, SignedTrustContextError> {
    let mut schema = TrustSchema::new();
    for blob in blobs {
        if !schema.merge(blob.to_schema()?) {
            return Err(SignedTrustContextError::MultipleLvsSchemas);
        }
    }
    Ok(schema)
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
/// as a relay for other devices, and whether a relay admits enrollment
/// links ([`tlv::LINK_POLICY`]). Policy in data: signed with the context, so
/// every device of the namespace admits links by the same rule, and carried
/// to every version made from it. A context without one has the default
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
}

impl Default for LinkPolicy {
    /// Any enrolled device of the namespace may link; relays are `node`
    /// devices; relays admit enrollment links.
    fn default() -> Self {
        Self {
            roles: Vec::new(),
            relay_roles: vec!["node".into()],
            enrollment_links: true,
        }
    }
}

/// [`LinkPolicy`] wire words for `enrollment_links`.
const ENROLLMENT_LINKS_ON: &str = "enrollment";
const ENROLLMENT_LINKS_OFF: &str = "no-enrollment";

impl LinkPolicy {
    /// Whether a device with `role` may link.
    pub fn allows_link(&self, role: &str) -> bool {
        self.roles.is_empty() || self.roles.iter().any(|r| r == role)
    }

    /// Whether a device with `role` may be a relay.
    pub fn allows_relay(&self, role: &str) -> bool {
        self.allows_link(role) && self.relay_roles.iter().any(|r| r == role)
    }

    /// One line for a person: `links: any role; relays: node; enrollment
    /// links: on`.
    pub fn describe(&self) -> String {
        let list = |roles: &[String], empty: &str| {
            if roles.is_empty() {
                empty.to_string()
            } else {
                roles.join(", ")
            }
        };
        format!(
            "links: {}; relays: {}; enrollment links: {}",
            list(&self.roles, "any role"),
            list(&self.relay_roles, "none"),
            if self.enrollment_links { "on" } else { "off" }
        )
    }

    /// `<roles>;<relay roles>;<enrollment|no-enrollment>`, roles
    /// comma-separated.
    fn encode(&self) -> Vec<u8> {
        format!(
            "{};{};{}",
            self.roles.join(","),
            self.relay_roles.join(","),
            if self.enrollment_links {
                ENROLLMENT_LINKS_ON
            } else {
                ENROLLMENT_LINKS_OFF
            }
        )
        .into_bytes()
    }

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
        Some(Self {
            roles,
            relay_roles,
            enrollment_links,
        })
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
    /// skipped.
    pub fn encode_content(&self) -> Bytes {
        let blobs = self.schema_blobs_or_derive();
        let mut w = TlvWriter::new();
        w.write_nested(tlv::TRUST_CONTEXT, |w| {
            // namespace — a plain Name (0x07), no dedicated code.
            w.write_raw(&self.namespace.encode_to_tlv());
            // AnchorSet — concatenated Data (0x06) certs.
            w.write_nested(tlv::ANCHOR_SET, |w| {
                for r in self.anchors.iter() {
                    if let Some(wire) = r.value().data_wire() {
                        w.write_raw(&wire);
                    }
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
            for rev in &self.revocations {
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

        let mut cur = value;
        while !cur.is_empty() {
            let (ft, fval, rest) = read_tlv(cur)?;
            cur = rest;
            match ft {
                ndn_packet::tlv_type::NAME => {
                    namespace = Some(
                        Name::decode(Bytes::copy_from_slice(fval))
                            .map_err(|e| SignedTrustContextError::BadName(e.to_string()))?,
                    );
                }
                tlv::ANCHOR_SET => {
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
                                format = Some(SchemaFormat::from_code(
                                    sval.first().copied().unwrap_or(0),
                                )?);
                            }
                            tlv::SCHEMA_BODY => body = Some(Bytes::copy_from_slice(sval)),
                            _ => {}
                        }
                    }
                    schema_blobs.push(SchemaBlob {
                        format: format
                            .ok_or(SignedTrustContextError::MissingField("SchemaFormat"))?,
                        body: body.ok_or(SignedTrustContextError::MissingField("SchemaBody"))?,
                    });
                }
                tlv::SCHEMA_AUTHORITATIVE => schema_authoritative = true,
                tlv::CA_ENDPOINT => {
                    ca_endpoints.push(
                        Name::decode_from_tlv(Bytes::copy_from_slice(fval))
                            .map_err(|e| SignedTrustContextError::BadName(e.to_string()))?,
                    );
                }
                tlv::ENROLLMENT_HINT => enrollment_hint = Some(EnrollmentHint::decode(fval)),
                // Non-critical provenance hint (F9): a 32-byte SHA-256 digest.
                // A malformed length fails the guard and falls through to the
                // non-critical skip arm below — tolerate, don't reject; it is a
                // hint, not a rule.
                tlv::SOURCE_BUNDLE_HASH if fval.len() == 32 => {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(fval);
                    source_bundle_hash = Some(h);
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
                tlv::LINK_POLICY => link_policy = LinkPolicy::decode(fval),
                // Unknown critical sub-TLV → reject; unknown non-critical → skip.
                other if is_critical(other) => {
                    return Err(SignedTrustContextError::Truncated(
                        "unknown critical sub-TLV",
                    ));
                }
                _ => {}
            }
        }

        let namespace = namespace.ok_or(SignedTrustContextError::MissingField("namespace"))?;
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
/// Names without a `KEY` component are returned unchanged.
pub(crate) fn key_identity(key_name: &Name) -> Name {
    let comps = key_name.components();
    match comps.iter().position(|c| c.value.as_ref() == b"KEY") {
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
}
