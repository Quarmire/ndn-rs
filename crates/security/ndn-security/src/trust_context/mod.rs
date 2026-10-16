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

/// Which NDNCERT challenges gate enrollment under a context, and whether all
/// are required (combinator-AND) or any one suffices.
///
/// Strings are NDNCERT challenge identifiers — `"token"`, `"pin"`, `"email"`,
/// `"proof-of-possession"`, `"device-approval"`, `"yubikey"`. ndn-cert maps
/// them to its handlers, keeping ndn-security free of an ndn-cert dependency.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EnrollmentHint {
    pub challenges: Vec<String>,
    pub require_all: bool,
}

impl EnrollmentHint {
    /// The hub default: `token AND device-approval` — a leaked QR token alone
    /// yields no cert without an admin tap.
    pub fn hub_default() -> Self {
        Self {
            challenges: vec!["token".into(), "device-approval".into()],
            require_all: true,
        }
    }

    fn encode(&self) -> Bytes {
        let mut v = Vec::new();
        v.push(self.require_all as u8);
        v.extend_from_slice(self.challenges.join(",").as_bytes());
        Bytes::from(v)
    }

    fn decode(value: &[u8]) -> Self {
        let require_all = value.first().copied().unwrap_or(0) != 0;
        let rest = if value.is_empty() {
            &[][..]
        } else {
            &value[1..]
        };
        let s = String::from_utf8_lossy(rest);
        let challenges = if s.is_empty() {
            Vec::new()
        } else {
            s.split(',').map(|x| x.to_string()).collect()
        };
        Self {
            challenges,
            require_all,
        }
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
    /// Dead anchors/intermediates by cert name or key digest.
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
    /// **off** so existing single-anchor callers keep their prior semantics.
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
    /// personal-network schema): its cross-identity grants (admins approving
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

    pub fn is_anchor(&self, name: &Name) -> bool {
        self.anchors.iter().any(|r| r.key().as_ref() == name)
    }

    /// Whether `name` is listed as revoked in this context.
    pub fn is_revoked(&self, name: &Name) -> bool {
        self.revocations.iter().any(|r| r == name)
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
                    if let Some(wire) = cert_to_data_wire(r.value()) {
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
    /// `signer` is any [`Signer`](crate::signer::Signer) — typically obtained
    /// from a `SecurityManager`/`KeyChain` for the publishing identity.
    pub fn sign_into_data(
        &self,
        signer: &dyn crate::signer::Signer,
    ) -> Result<Data, SignedTrustContextError> {
        let content = self.encode_content();
        let wire = ndn_packet::encode::DataBuilder::new(self.rdr_name(), &content).sign_sync(
            signer.sig_type(),
            Some(signer.key_name()),
            |region| signer.sign_sync(region).unwrap_or_default(),
        );
        Data::decode(wire).map_err(|e| SignedTrustContextError::Sign(e.to_string()))
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
        // Exact anchor (cert) name first, else the anchor cert under the
        // signer's key name (`/<id>/KEY/<k>` locating `/<id>/KEY/<k>/<issuer>/<v>`).
        let anchor = ctx
            .anchors()
            .get(&signer)
            .map(|r| r.value().clone())
            .or_else(|| {
                ctx.anchors()
                    .iter()
                    .find(|r| r.key().has_prefix(&signer))
                    .map(|r| r.value().clone())
            })
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

/// Reconstruct an anchor's `Data` wire from its retained signed region and
/// signature value. `None` for test-only certs that carry neither.
fn cert_to_data_wire(cert: &Certificate) -> Option<Bytes> {
    let sr = cert.signed_region.as_ref()?;
    let sv = cert.sig_value.as_ref()?;
    let mut w = TlvWriter::new();
    w.write_nested(ndn_packet::tlv_type::DATA, |w| {
        w.write_raw(sr);
        w.write_tlv(ndn_packet::tlv_type::SIGNATURE_VALUE, sv);
    });
    Some(w.finish())
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
        let h = EnrollmentHint::hub_default();
        let decoded = EnrollmentHint::decode(&h.encode());
        assert_eq!(decoded, h);
        assert!(decoded.require_all);
        assert_eq!(decoded.challenges, vec!["token", "device-approval"]);
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
}
