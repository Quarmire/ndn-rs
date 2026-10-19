//! The `ndn-trust://` onboarding/pairing envelope — one source of truth shared by
//! the issuer side (CLIs, dashboard) and the mobile consumers (via boltffi).
//!
//! Every onboarding flow is a *transfer of authority over a namespace, expressed
//! as named signed Data*. They differ only by **kind** (what is transferred) and
//! **direction** (in = you gain authority; out = you grant bounded authority):
//!
//! | kind | dir | flow |
//! |------|-----|------|
//! | [`anchor`](TrustKind::Anchor) | in | adopt a trust context |
//! | [`invite`](TrustKind::Invite) | in | get certified (NDNCERT token) |
//! | [`delegation`](TrustKind::Delegation) | in/out | be sponsored / sponsor a device |
//! | [`recovery`](TrustKind::Recovery) | in | restore from a recovery bundle |
//! | [`bag`](TrustKind::Bag) | in | migrate a SafeBag (custody layer) |
//! | [`capability`](TrustKind::Capability) | out | grant ephemeral scoped authority (pairing) |
//!
//! This crate is the *authority layer*: it never names a host, link, session, or
//! address. It only carries names (as strings), anchor fingerprints, and
//! signed-Data wire blobs.
//!
//! An [`Anchor`](TrustEnvelope::Anchor) is either *inline* (the context's
//! **signed** NDN Data, `context_data`) or *by reference* (namespace + the
//! 32-byte SHA-256 fingerprint of the root anchor's public key, the expected
//! fingerprint), or both. `ndn_cert::adopt_anchor_link` fetches a by-reference
//! context by name and, like the inline path, verifies its signature under an
//! anchor with the expected fingerprint before anything is trusted. The older unsigned
//! inline form (`context_content`, the bare `SignedTrustContext` Content —
//! also what `ndn-ctx:1:` carries) still decodes, but nothing adopts it unless
//! the caller explicitly opts in to unverified legacy adoption.
//!
//! ## Carriage
//!
//! ```text
//! ndn-trust://<kind>/<base64url(TLV)>        QR / NFC / clipboard / deep-link / file
//! https://<domain>/t/<kind>#<base64url(TLV)> universal-link mirror (payload in the fragment)
//! ndn-ctx:1:<ver>:<b64url>                    legacy inline-anchor form, parse-only
//! ```
//!
//! A file carries the text form (one URI). The `<kind>` in a URI must name the
//! kind of the TLV it carries; the TLV is authoritative. [`qr`] holds the QR
//! parameters every producer renders with, and [`TrustEnvelope::qr_uri`] the
//! URI to show as a QR code.
//!
//! ## Decoding rules
//!
//! The decoder is strict where a lenient reading could hide a forged or
//! damaged envelope: no bytes after the envelope, one-byte FormatVersion /
//! Kind / Direction, no repeated field (ScopePattern excepted), and the NDN
//! evolvability rule for anything it does not recognize in its place
//! (an unknown child, or a field another kind uses): ignored when its type
//! is non-critical (even and above 31), refused when it is critical.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use bytes::Bytes;
use ndn_tlv::{TlvReader, TlvWriter};
use thiserror::Error;

pub mod qr;

// ── TLV codes (fresh range, clear of SignedTrustContext's 0x0410–0x041F) ─────
const T_ENVELOPE: u64 = 0x0470;
const T_FORMAT_VERSION: u64 = 0x0471;
const T_KIND: u64 = 0x0472;
const T_BODY: u64 = 0x0473;

const T_U64_VERSION: u64 = 0x0481; // anchor: context version
const T_WIRE: u64 = 0x0482; // primary signed-Data blob (delegation / bundle / safebag); anchor: legacy unsigned context Content
const T_CA_PREFIX: u64 = 0x0483;
const T_ID_NAMESPACE: u64 = 0x0484;
const T_TOKEN: u64 = 0x0485;
const T_TTL_SECS: u64 = 0x0486;
const T_PRINCIPAL_PUBKEY: u64 = 0x0487;
const T_KEY_NAME: u64 = 0x0488;
const T_NAMESPACE: u64 = 0x0489;
const T_SCOPE_PATTERN: u64 = 0x048A; // repeatable
const T_NONCE: u64 = 0x048B;
const T_GRANT: u64 = 0x048C;
const T_DIRECTION: u64 = 0x048D;
const T_ANCHOR_FINGERPRINT: u64 = 0x048E; // anchor / invite: SHA-256 of the root anchor pubkey
const T_CONTEXT_DATA: u64 = 0x048F; // anchor: the signed trust-context Data (full wire)

/// Length of an anchor fingerprint (SHA-256 of the anchor's public key).
pub const ANCHOR_FINGERPRINT_LEN: usize = 32;

/// The envelope format version this crate emits and accepts.
pub const FORMAT_VERSION: u8 = 1;

/// Length of the nonce a capability request carries: fresh random bytes per
/// request (trust-envelope.md §4.4). Producers draw it from the system RNG.
pub const CAPABILITY_NONCE_LEN: usize = 16;

const SCHEME: &str = "ndn-trust://";
const MIRROR_SCHEME: &str = "https://";
const LEGACY_ANCHOR_TAG: &str = "ndn-ctx:1:";

/// What kind of authority transfer an envelope carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustKind {
    /// Adopt a trust context (a named anchor set).
    Anchor,
    /// An NDNCERT enrollment invitation (CA + namespace + token).
    Invite,
    /// A signed delegation (sponsor a device / be sponsored).
    Delegation,
    /// A recovery bundle (restore an identity on a fresh device).
    Recovery,
    /// A password-encrypted SafeBag (key migration — custody layer).
    Bag,
    /// An ephemeral, scoped, expiring capability (pairing).
    Capability,
}

impl TrustKind {
    fn code(self) -> u8 {
        match self {
            TrustKind::Anchor => 1,
            TrustKind::Invite => 2,
            TrustKind::Delegation => 3,
            TrustKind::Recovery => 4,
            TrustKind::Bag => 5,
            TrustKind::Capability => 6,
        }
    }

    fn from_code(c: u8) -> Result<Self, EnvelopeError> {
        Ok(match c {
            1 => TrustKind::Anchor,
            2 => TrustKind::Invite,
            3 => TrustKind::Delegation,
            4 => TrustKind::Recovery,
            5 => TrustKind::Bag,
            6 => TrustKind::Capability,
            other => return Err(EnvelopeError::UnknownKind(other)),
        })
    }

    /// The URI host token (`ndn-trust://<as_str>/…`).
    pub fn as_str(self) -> &'static str {
        match self {
            TrustKind::Anchor => "anchor",
            TrustKind::Invite => "invite",
            TrustKind::Delegation => "delegation",
            TrustKind::Recovery => "recovery",
            TrustKind::Bag => "bag",
            TrustKind::Capability => "capability",
        }
    }

    /// The body fields this kind defines (any order on the wire). Any other
    /// field is unrecognized here and falls under the evolvability rule.
    fn body_fields(self) -> &'static [u64] {
        match self {
            TrustKind::Anchor => &[
                T_NAMESPACE,
                T_ANCHOR_FINGERPRINT,
                T_U64_VERSION,
                T_CONTEXT_DATA,
                T_WIRE,
            ],
            TrustKind::Invite => &[
                T_CA_PREFIX,
                T_ID_NAMESPACE,
                T_TOKEN,
                T_TTL_SECS,
                T_ANCHOR_FINGERPRINT,
            ],
            TrustKind::Delegation => &[T_WIRE, T_PRINCIPAL_PUBKEY],
            TrustKind::Recovery => &[T_WIRE],
            TrustKind::Bag => &[T_KEY_NAME, T_WIRE, T_NAMESPACE, T_ANCHOR_FINGERPRINT],
            TrustKind::Capability => &[
                T_DIRECTION,
                T_NAMESPACE,
                T_SCOPE_PATTERN,
                T_TTL_SECS,
                T_NONCE,
                T_GRANT,
            ],
        }
    }
}

/// Direction of a [`Capability`] payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapDirection {
    /// A peer asking this device to grant a capability.
    Request,
    /// A capability this device has granted to a bearer.
    Grant,
}

impl CapDirection {
    fn code(self) -> u8 {
        match self {
            CapDirection::Request => 0,
            CapDirection::Grant => 1,
        }
    }
    fn from_code(c: u8) -> Result<Self, EnvelopeError> {
        match c {
            0 => Ok(CapDirection::Request),
            1 => Ok(CapDirection::Grant),
            _ => Err(EnvelopeError::Malformed("capability direction")),
        }
    }
}

/// An ephemeral, scoped, expiring capability — the pairing payload. A `Request`
/// (peer → this device) carries the asked-for scope; a `Grant` (this device →
/// bearer) additionally carries the granting operator's certificate in
/// [`grant`](Self::grant).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub direction: CapDirection,
    /// The namespace the capability is scoped to.
    pub namespace: String,
    /// Trust-schema patterns further narrowing the grant.
    pub scope_patterns: Vec<String>,
    /// Lifetime in seconds (a hard ceiling; never "forever").
    pub ttl_secs: u64,
    /// Anti-replay nonce chosen by the requester.
    pub nonce: Bytes,
    /// The granting operator's certificate, as signed NDN Data wire (present
    /// on a `Grant`). The bearer decodes it as a `Certificate` to learn and
    /// verify the operator's key.
    pub grant: Option<Bytes>,
}

/// A decoded `ndn-trust://` envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustEnvelope {
    /// Adopt a trust context. At least one of `context_data` /
    /// `context_content` (inline) or `fingerprint` (by reference) is present;
    /// see the crate docs.
    Anchor {
        /// The context namespace, as an NDN URI (e.g. `/home/bob`).
        namespace: Option<String>,
        /// SHA-256 of the root anchor's public key — the expected
        /// fingerprint the adopted context's signer must have.
        fingerprint: Option<[u8; ANCHOR_FINGERPRINT_LEN]>,
        /// The context version (the RDR `v=` component). A context fetched by
        /// name must be at least this version.
        version: Option<u64>,
        /// The **signed** context: the full NDN Data wire of
        /// `SignedTrustContext::sign_into_data` (named
        /// `/<ns>/32=trust-context/v=<version>`, signed by a context anchor).
        context_data: Option<Bytes>,
        /// Legacy **unsigned** `SignedTrustContext::encode_content()`. Decoded
        /// for old payloads (and `ndn-ctx:1:`); never adopted by default.
        context_content: Option<Bytes>,
    },
    /// NDNCERT enrollment invitation.
    Invite {
        ca_prefix: String,
        identity_namespace: String,
        token: String,
        ttl_secs: Option<u64>,
        /// SHA-256 of the CA's root anchor public key: the expected fingerprint.
        anchor_fingerprint: Option<[u8; ANCHOR_FINGERPRINT_LEN]>,
    },
    /// A signed delegation plus the principal's public key needed to verify it.
    Delegation {
        signed_delegation: Bytes,
        principal_pubkey: Bytes,
    },
    /// A recovery bundle (public history; carries no private keys).
    Recovery { bundle: Bytes },
    /// A password-encrypted SafeBag and the key name it carries. A recovery
    /// kit also names the namespace the key recovers and the namespace's
    /// expected fingerprint when the kit was made (the root that signed the
    /// context then), so a device that holds no context of the namespace can
    /// adopt the right one before recovering. Both are optional on the wire:
    /// a plain key-migration bag carries neither.
    Bag {
        key_name: String,
        safebag: Bytes,
        namespace: Option<String>,
        fingerprint: Option<[u8; ANCHOR_FINGERPRINT_LEN]>,
    },
    /// An ephemeral scoped capability (pairing).
    Capability(Capability),
}

impl TrustEnvelope {
    /// The kind discriminator for this envelope.
    pub fn kind(&self) -> TrustKind {
        match self {
            TrustEnvelope::Anchor { .. } => TrustKind::Anchor,
            TrustEnvelope::Invite { .. } => TrustKind::Invite,
            TrustEnvelope::Delegation { .. } => TrustKind::Delegation,
            TrustEnvelope::Recovery { .. } => TrustKind::Recovery,
            TrustEnvelope::Bag { .. } => TrustKind::Bag,
            TrustEnvelope::Capability(_) => TrustKind::Capability,
        }
    }

    /// Encode to the canonical TLV container (the bytes base64url'd into a
    /// URI).
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(T_ENVELOPE, |w| {
            w.write_tlv(T_FORMAT_VERSION, &[FORMAT_VERSION]);
            w.write_tlv(T_KIND, &[self.kind().code()]);
            w.write_nested(T_BODY, |w| self.encode_body(w));
        });
        w.finish()
    }

    fn encode_body(&self, w: &mut TlvWriter) {
        match self {
            TrustEnvelope::Anchor {
                namespace,
                fingerprint,
                version,
                context_data,
                context_content,
            } => {
                if let Some(ns) = namespace {
                    w.write_tlv(T_NAMESPACE, ns.as_bytes());
                }
                if let Some(fp) = fingerprint {
                    w.write_tlv(T_ANCHOR_FINGERPRINT, fp);
                }
                if let Some(v) = version {
                    w.write_tlv(T_U64_VERSION, &v.to_be_bytes());
                }
                if let Some(d) = context_data {
                    w.write_tlv(T_CONTEXT_DATA, d);
                }
                if let Some(c) = context_content {
                    w.write_tlv(T_WIRE, c);
                }
            }
            TrustEnvelope::Invite {
                ca_prefix,
                identity_namespace,
                token,
                ttl_secs,
                anchor_fingerprint,
            } => {
                w.write_tlv(T_CA_PREFIX, ca_prefix.as_bytes());
                w.write_tlv(T_ID_NAMESPACE, identity_namespace.as_bytes());
                w.write_tlv(T_TOKEN, token.as_bytes());
                if let Some(ttl) = ttl_secs {
                    w.write_tlv(T_TTL_SECS, &ttl.to_be_bytes());
                }
                if let Some(fp) = anchor_fingerprint {
                    w.write_tlv(T_ANCHOR_FINGERPRINT, fp);
                }
            }
            TrustEnvelope::Delegation {
                signed_delegation,
                principal_pubkey,
            } => {
                w.write_tlv(T_WIRE, signed_delegation);
                w.write_tlv(T_PRINCIPAL_PUBKEY, principal_pubkey);
            }
            TrustEnvelope::Recovery { bundle } => {
                w.write_tlv(T_WIRE, bundle);
            }
            TrustEnvelope::Bag {
                key_name,
                safebag,
                namespace,
                fingerprint,
            } => {
                w.write_tlv(T_KEY_NAME, key_name.as_bytes());
                w.write_tlv(T_WIRE, safebag);
                if let Some(ns) = namespace {
                    w.write_tlv(T_NAMESPACE, ns.as_bytes());
                }
                if let Some(fp) = fingerprint {
                    w.write_tlv(T_ANCHOR_FINGERPRINT, fp);
                }
            }
            TrustEnvelope::Capability(c) => {
                w.write_tlv(T_DIRECTION, &[c.direction.code()]);
                w.write_tlv(T_NAMESPACE, c.namespace.as_bytes());
                for p in &c.scope_patterns {
                    w.write_tlv(T_SCOPE_PATTERN, p.as_bytes());
                }
                w.write_tlv(T_TTL_SECS, &c.ttl_secs.to_be_bytes());
                if !c.nonce.is_empty() {
                    w.write_tlv(T_NONCE, &c.nonce);
                }
                if let Some(g) = &c.grant {
                    w.write_tlv(T_GRANT, g);
                }
            }
        }
    }

    /// Decode the TLV container (trust-envelope.md §6).
    pub fn decode(wire: &[u8]) -> Result<Self, EnvelopeError> {
        let mut outer = TlvReader::new(Bytes::copy_from_slice(wire));
        let (typ, body) = outer.read_tlv().map_err(|_| EnvelopeError::Truncated)?;
        if typ != T_ENVELOPE {
            return Err(EnvelopeError::BadTag(typ));
        }
        if !outer.is_empty() {
            return Err(EnvelopeError::Malformed("bytes after the envelope"));
        }

        let mut fmt: Option<u8> = None;
        let mut kind: Option<u8> = None;
        let mut body_bytes: Option<Bytes> = None;
        // Reported after the format version, so a newer format is refused as
        // such rather than by one of its new children.
        let mut unknown_critical: Option<u64> = None;
        let mut inner = TlvReader::new(body);
        while !inner.is_empty() {
            let (t, v) = inner.read_tlv().map_err(|_| EnvelopeError::Truncated)?;
            match t {
                T_FORMAT_VERSION => set_once(&mut fmt, one_byte(&v, "format version length")?)?,
                T_KIND => set_once(&mut kind, one_byte(&v, "kind length")?)?,
                T_BODY => set_once(&mut body_bytes, v)?,
                t if is_critical(t) => {
                    unknown_critical.get_or_insert(t);
                }
                _ => {} // non-critical: ignored (evolvability)
            }
        }

        let fmt = fmt.ok_or(EnvelopeError::MissingField("format version"))?;
        if fmt != FORMAT_VERSION {
            return Err(EnvelopeError::UnsupportedVersion(fmt));
        }
        if let Some(t) = unknown_critical {
            return Err(EnvelopeError::UnknownCritical(t));
        }
        let kind = TrustKind::from_code(kind.ok_or(EnvelopeError::MissingField("kind"))?)?;
        let body = body_bytes.ok_or(EnvelopeError::MissingField("body"))?;
        Self::decode_body(kind, body)
    }

    fn decode_body(kind: TrustKind, body: Bytes) -> Result<Self, EnvelopeError> {
        let mut version: Option<u64> = None;
        let mut wire: Option<Bytes> = None;
        let mut ca_prefix: Option<String> = None;
        let mut id_namespace: Option<String> = None;
        let mut token: Option<String> = None;
        let mut ttl_secs: Option<u64> = None;
        let mut principal_pubkey: Option<Bytes> = None;
        let mut key_name: Option<String> = None;
        let mut namespace: Option<String> = None;
        let mut scope_patterns: Vec<String> = Vec::new();
        let mut nonce: Option<Bytes> = None;
        let mut grant: Option<Bytes> = None;
        let mut direction: Option<u8> = None;
        let mut fingerprint: Option<[u8; ANCHOR_FINGERPRINT_LEN]> = None;
        let mut context_data: Option<Bytes> = None;

        let fields = kind.body_fields();
        let mut r = TlvReader::new(body);
        while !r.is_empty() {
            let (t, v) = r.read_tlv().map_err(|_| EnvelopeError::Truncated)?;
            if !fields.contains(&t) {
                // Unknown here (a future field, or one another kind uses):
                // skipped unread if non-critical, refused if critical.
                if is_critical(t) {
                    return Err(EnvelopeError::UnknownCritical(t));
                }
                continue;
            }
            match t {
                T_U64_VERSION => set_once(&mut version, read_u64(&v)?)?,
                T_WIRE => set_once(&mut wire, v)?,
                T_CONTEXT_DATA => set_once(&mut context_data, v)?,
                T_CA_PREFIX => set_once(&mut ca_prefix, read_str(&v)?)?,
                T_ID_NAMESPACE => set_once(&mut id_namespace, read_str(&v)?)?,
                T_TOKEN => set_once(&mut token, read_str(&v)?)?,
                T_TTL_SECS => set_once(&mut ttl_secs, read_u64(&v)?)?,
                T_PRINCIPAL_PUBKEY => set_once(&mut principal_pubkey, v)?,
                T_KEY_NAME => set_once(&mut key_name, read_str(&v)?)?,
                T_NAMESPACE => set_once(&mut namespace, read_str(&v)?)?,
                T_SCOPE_PATTERN => scope_patterns.push(read_str(&v)?),
                T_NONCE => set_once(&mut nonce, v)?,
                T_GRANT => set_once(&mut grant, v)?,
                T_DIRECTION => {
                    set_once(&mut direction, one_byte(&v, "capability direction length")?)?
                }
                T_ANCHOR_FINGERPRINT => set_once(
                    &mut fingerprint,
                    v.as_ref()
                        .try_into()
                        .map_err(|_| EnvelopeError::Malformed("anchor fingerprint length"))?,
                )?,
                _ => unreachable!("every type in body_fields() has an arm"),
            }
        }

        let need = EnvelopeError::MissingField;
        Ok(match kind {
            TrustKind::Anchor => {
                if wire.is_none() && context_data.is_none() && fingerprint.is_none() {
                    return Err(need("anchor content or fingerprint"));
                }
                TrustEnvelope::Anchor {
                    namespace,
                    fingerprint,
                    version,
                    context_data,
                    context_content: wire,
                }
            }
            TrustKind::Invite => TrustEnvelope::Invite {
                ca_prefix: ca_prefix.ok_or(need("ca prefix"))?,
                identity_namespace: id_namespace.ok_or(need("identity namespace"))?,
                token: token.ok_or(need("token"))?,
                ttl_secs,
                anchor_fingerprint: fingerprint,
            },
            TrustKind::Delegation => TrustEnvelope::Delegation {
                signed_delegation: wire.ok_or(need("delegation wire"))?,
                principal_pubkey: principal_pubkey.ok_or(need("principal pubkey"))?,
            },
            TrustKind::Recovery => TrustEnvelope::Recovery {
                bundle: wire.ok_or(need("recovery bundle"))?,
            },
            TrustKind::Bag => TrustEnvelope::Bag {
                key_name: key_name.ok_or(need("key name"))?,
                safebag: wire.ok_or(need("safebag"))?,
                namespace,
                fingerprint,
            },
            TrustKind::Capability => TrustEnvelope::Capability(Capability {
                direction: CapDirection::from_code(direction.ok_or(need("direction"))?)?,
                namespace: namespace.ok_or(need("capability namespace"))?,
                scope_patterns,
                ttl_secs: ttl_secs.ok_or(need("capability ttl"))?,
                nonce: nonce.unwrap_or_default(),
                grant,
            }),
        })
    }

    /// The canonical scannable URI: `ndn-trust://<kind>/<base64url(TLV)>`.
    pub fn to_uri(&self) -> String {
        format!(
            "{SCHEME}{}/{}",
            self.kind().as_str(),
            B64.encode(self.encode())
        )
    }

    /// The universal-link mirror: `https://<domain>/t/<kind>#<base64url(TLV)>`.
    /// The payload rides in the fragment, so it never reaches the web server.
    pub fn to_https_url(&self, domain: &str) -> String {
        format!(
            "{MIRROR_SCHEME}{domain}/t/{}#{}",
            self.kind().as_str(),
            B64.encode(self.encode())
        )
    }

    /// The URI to show as one QR code ([`qr::encode`]): [`to_uri`](Self::to_uri)
    /// when it fits [`qr::MAX_TEXT_LEN`]; for an inline anchor that does not,
    /// the same anchor by reference (namespace, expected fingerprint and
    /// version, no context: the adopting device fetches the context by name).
    /// `None` when neither fits.
    pub fn qr_uri(&self) -> Option<String> {
        let uri = self.to_uri();
        if uri.len() <= qr::MAX_TEXT_LEN {
            return Some(uri);
        }
        let TrustEnvelope::Anchor {
            namespace: Some(namespace),
            fingerprint: Some(fingerprint),
            version,
            ..
        } = self
        else {
            return None;
        };
        let by_reference = TrustEnvelope::Anchor {
            namespace: Some(namespace.clone()),
            fingerprint: Some(*fingerprint),
            version: *version,
            context_data: None,
            context_content: None,
        }
        .to_uri();
        (by_reference.len() <= qr::MAX_TEXT_LEN).then_some(by_reference)
    }

    /// Parse any supported carriage: the `ndn-trust://<kind>/` scheme, the
    /// `https://<domain>/t/<kind>#` universal-link mirror, or the legacy
    /// `ndn-ctx:1:` inline-anchor form (parse-only; nothing emits it any
    /// more). The `<kind>` must be the kind of the TLV the URI carries.
    pub fn from_uri(s: &str) -> Result<Self, EnvelopeError> {
        let s = s.trim();

        if let Some(rest) = s.strip_prefix(LEGACY_ANCHOR_TAG) {
            let (ver, b64) = rest.split_once(':').ok_or(EnvelopeError::MalformedUri)?;
            // Decimal digits only (`u64::from_str` alone would take a `+`).
            if ver.is_empty() || !ver.bytes().all(|b| b.is_ascii_digit()) {
                return Err(EnvelopeError::MalformedUri);
            }
            let version = ver.parse().map_err(|_| EnvelopeError::MalformedUri)?;
            let content = B64
                .decode(b64.trim())
                .map_err(|_| EnvelopeError::BadBase64)?;
            return Ok(TrustEnvelope::Anchor {
                namespace: None,
                fingerprint: None,
                version: Some(version),
                context_data: None,
                context_content: Some(Bytes::from(content)),
            });
        }

        let (token, b64) = if let Some(rest) = s.strip_prefix(SCHEME) {
            // <kind>/<b64>
            rest.split_once('/').ok_or(EnvelopeError::MalformedUri)?
        } else if let Some(rest) = s.strip_prefix(MIRROR_SCHEME) {
            // <domain>/t/<kind>#<b64>: an https URL with another path is not a
            // trust link at all.
            let (url, fragment) = match rest.split_once('#') {
                Some((url, fragment)) => (url, Some(fragment)),
                None => (rest, None),
            };
            let (domain, path) = url.split_once('/').unwrap_or((url, ""));
            let Some(token) = path.strip_prefix("t/").filter(|t| !t.contains(['/', '?'])) else {
                return Err(EnvelopeError::UnknownScheme);
            };
            if domain.is_empty() || domain.contains('?') {
                return Err(EnvelopeError::MalformedUri);
            }
            (token, fragment.ok_or(EnvelopeError::MalformedUri)?)
        } else {
            return Err(EnvelopeError::UnknownScheme);
        };

        let wire = B64
            .decode(b64.trim())
            .map_err(|_| EnvelopeError::BadBase64)?;
        let envelope = Self::decode(&wire)?;
        if token != envelope.kind().as_str() {
            return Err(EnvelopeError::KindMismatch {
                uri: token.to_owned(),
                envelope: envelope.kind().as_str(),
            });
        }
        Ok(envelope)
    }
}

/// The NDN evolvability rule (Packet Format v0.3, TLV-TYPE): an unrecognized
/// type is critical when it is 31 or below, or odd.
fn is_critical(t: u64) -> bool {
    t <= 31 || t % 2 == 1
}

/// Store a field read once; a second occurrence is refused.
fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), EnvelopeError> {
    if slot.is_some() {
        return Err(EnvelopeError::Malformed("repeated field"));
    }
    *slot = Some(value);
    Ok(())
}

/// A one-byte field value; any other length is refused.
fn one_byte(v: &[u8], what: &'static str) -> Result<u8, EnvelopeError> {
    match v {
        [b] => Ok(*b),
        _ => Err(EnvelopeError::Malformed(what)),
    }
}

fn read_str(b: &[u8]) -> Result<String, EnvelopeError> {
    String::from_utf8(b.to_vec()).map_err(|_| EnvelopeError::Malformed("non-utf8 string field"))
}

fn read_u64(b: &[u8]) -> Result<u64, EnvelopeError> {
    if b.is_empty() || b.len() > 8 {
        return Err(EnvelopeError::Malformed("u64 field length"));
    }
    let mut buf = [0u8; 8];
    buf[8 - b.len()..].copy_from_slice(b);
    Ok(u64::from_be_bytes(buf))
}

/// Errors decoding a trust envelope.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EnvelopeError {
    #[error("not a recognized trust-envelope URI scheme")]
    UnknownScheme,
    #[error("malformed trust-envelope URI")]
    MalformedUri,
    #[error("invalid base64url payload")]
    BadBase64,
    #[error("truncated TLV")]
    Truncated,
    #[error("unexpected outer TLV tag {0:#x}")]
    BadTag(u64),
    #[error("unsupported envelope format version {0}")]
    UnsupportedVersion(u8),
    #[error("unknown kind code {0}")]
    UnknownKind(u8),
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    #[error("malformed field: {0}")]
    Malformed(&'static str),
    #[error("unrecognized critical TLV type {0:#x}")]
    UnknownCritical(u64),
    #[error("the link says it is a {uri:?} link, but it carries a {envelope} envelope")]
    KindMismatch { uri: String, envelope: &'static str },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(e: &TrustEnvelope) {
        let bytes = e.encode();
        assert_eq!(&TrustEnvelope::decode(&bytes).unwrap(), e, "TLV round-trip");
        let uri = e.to_uri();
        assert!(uri.starts_with(SCHEME));
        assert_eq!(&TrustEnvelope::from_uri(&uri).unwrap(), e, "URI round-trip");
    }

    #[test]
    fn anchor_round_trips_and_matches_kind() {
        let e = TrustEnvelope::Anchor {
            namespace: None,
            fingerprint: None,
            version: Some(7),
            context_data: None,
            context_content: Some(Bytes::from_static(b"\x07\x14ctx-wire-bytes")),
        };
        assert_eq!(e.kind(), TrustKind::Anchor);
        round_trip(&e);
        // By reference (namespace + expected fingerprint), and both forms at once.
        round_trip(&TrustEnvelope::Anchor {
            namespace: Some("/home/bob".into()),
            fingerprint: Some([0xAB; ANCHOR_FINGERPRINT_LEN]),
            version: None,
            context_data: None,
            context_content: None,
        });
        round_trip(&TrustEnvelope::Anchor {
            namespace: Some("/home/bob".into()),
            fingerprint: Some([0xAB; ANCHOR_FINGERPRINT_LEN]),
            version: Some(1),
            context_data: None,
            context_content: Some(Bytes::from_static(b"ctx")),
        });
    }

    #[test]
    fn signed_context_data_round_trips_alone() {
        // The signed form carries the Data wire in its own TLV and needs no
        // legacy content alongside it.
        let e = TrustEnvelope::Anchor {
            namespace: Some("/home/bob".into()),
            fingerprint: Some([0xCD; ANCHOR_FINGERPRINT_LEN]),
            version: Some(1),
            context_data: Some(Bytes::from_static(b"\x06\x03abc")),
            context_content: None,
        };
        round_trip(&e);
        let TrustEnvelope::Anchor {
            context_data,
            context_content,
            ..
        } = TrustEnvelope::decode(&e.encode()).unwrap()
        else {
            unreachable!()
        };
        assert_eq!(context_data.as_deref(), Some(&b"\x06\x03abc"[..]));
        assert_eq!(
            context_content, None,
            "signed Data is not decoded as legacy content"
        );
    }

    #[test]
    fn anchor_needs_content_or_fingerprint() {
        let e = TrustEnvelope::Anchor {
            namespace: Some("/home/bob".into()),
            fingerprint: None,
            version: Some(1),
            context_data: None,
            context_content: None,
        };
        assert_eq!(
            TrustEnvelope::decode(&e.encode()),
            Err(EnvelopeError::MissingField("anchor content or fingerprint"))
        );
    }

    #[test]
    fn short_fingerprint_is_malformed() {
        let mut w = TlvWriter::new();
        w.write_nested(T_ENVELOPE, |w| {
            w.write_tlv(T_FORMAT_VERSION, &[FORMAT_VERSION]);
            w.write_tlv(T_KIND, &[TrustKind::Anchor.code()]);
            w.write_nested(T_BODY, |w| w.write_tlv(T_ANCHOR_FINGERPRINT, &[1, 2, 3]));
        });
        assert_eq!(
            TrustEnvelope::decode(&w.finish()),
            Err(EnvelopeError::Malformed("anchor fingerprint length"))
        );
    }

    #[test]
    fn invite_round_trips_with_and_without_optionals() {
        round_trip(&TrustEnvelope::Invite {
            ca_prefix: "/ndn".into(),
            identity_namespace: "/ndn/mobile".into(),
            token: "a1b2c3d4e5f6".into(),
            ttl_secs: Some(3600),
            anchor_fingerprint: Some([0x11; ANCHOR_FINGERPRINT_LEN]),
        });
        round_trip(&TrustEnvelope::Invite {
            ca_prefix: "/ndn".into(),
            identity_namespace: "/ndn/mobile".into(),
            token: "tok".into(),
            ttl_secs: None,
            anchor_fingerprint: None,
        });
    }

    #[test]
    fn delegation_recovery_bag_round_trip() {
        round_trip(&TrustEnvelope::Delegation {
            signed_delegation: Bytes::from_static(b"signed-delegation-wire"),
            principal_pubkey: Bytes::from_static(&[1, 2, 3, 4]),
        });
        round_trip(&TrustEnvelope::Recovery {
            bundle: Bytes::from_static(b"recovery-bundle-history"),
        });
        round_trip(&TrustEnvelope::Bag {
            key_name: "/ndn/mobile/alice/KEY/18b5e7d515966f90".into(),
            safebag: Bytes::from_static(b"\x80\x10encrypted-safebag"),
            namespace: None,
            fingerprint: None,
        });
        round_trip(&TrustEnvelope::Bag {
            key_name: "/home/bob/KEY/r0011223344556677".into(),
            safebag: Bytes::from_static(b"\x80\x10encrypted-safebag"),
            namespace: Some("/home/bob".into()),
            fingerprint: Some([7; ANCHOR_FINGERPRINT_LEN]),
        });
    }

    #[test]
    fn capability_request_and_grant_round_trip() {
        round_trip(&TrustEnvelope::Capability(Capability {
            direction: CapDirection::Request,
            namespace: "/work/acme/dashboard".into(),
            scope_patterns: vec!["/work/acme/<**rest>".into()],
            ttl_secs: 300,
            nonce: Bytes::from_static(&[9, 9, 9, 9]),
            grant: None,
        }));
        round_trip(&TrustEnvelope::Capability(Capability {
            direction: CapDirection::Grant,
            namespace: "/work/acme/dashboard".into(),
            scope_patterns: vec![],
            ttl_secs: 300,
            nonce: Bytes::new(),
            grant: Some(Bytes::from_static(b"operator-certificate-data-wire")),
        }));
    }

    #[test]
    fn legacy_ndn_ctx_parses_as_anchor() {
        // ndn-ctx:1:<ver>:<b64url(content)>
        let content = b"\x07\x10legacy-context!!";
        let b64 = B64.encode(content);
        let s = format!("ndn-ctx:1:42:{b64}");
        let e = TrustEnvelope::from_uri(&s).unwrap();
        assert_eq!(
            e,
            TrustEnvelope::Anchor {
                namespace: None,
                fingerprint: None,
                version: Some(42),
                context_data: None,
                context_content: Some(Bytes::from_static(content)),
            }
        );
    }

    #[test]
    fn https_mirror_uses_the_fragment() {
        let e = TrustEnvelope::Invite {
            ca_prefix: "/ndn".into(),
            identity_namespace: "/ndn/mobile".into(),
            token: "tok123".into(),
            ttl_secs: Some(900),
            anchor_fingerprint: None,
        };
        let b64 = B64.encode(e.encode());
        let mirror = e.to_https_url("join.example");
        assert_eq!(mirror, format!("https://join.example/t/invite#{b64}"));
        assert_eq!(TrustEnvelope::from_uri(&mirror).unwrap(), e);
    }

    #[test]
    fn unknown_scheme_and_bad_payload_are_errors() {
        assert_eq!(
            TrustEnvelope::from_uri("https://example.com/login"),
            Err(EnvelopeError::UnknownScheme)
        );
        assert_eq!(
            TrustEnvelope::from_uri("ndn-trust://invite/!!!not-base64!!!"),
            Err(EnvelopeError::BadBase64)
        );
    }

    /// An envelope from hand-written children.
    fn raw(children: impl FnOnce(&mut TlvWriter)) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(T_ENVELOPE, children);
        w.finish()
    }

    /// A fingerprint-only anchor whose body also carries `extra`.
    fn anchor_with(extra: impl FnOnce(&mut TlvWriter)) -> Bytes {
        raw(|w| {
            w.write_tlv(T_FORMAT_VERSION, &[FORMAT_VERSION]);
            w.write_tlv(T_KIND, &[TrustKind::Anchor.code()]);
            w.write_nested(T_BODY, |w| {
                w.write_tlv(T_ANCHOR_FINGERPRINT, &[1; ANCHOR_FINGERPRINT_LEN]);
                extra(w);
            });
        })
    }

    fn recovery_uri(token: &str) -> String {
        let wire = TrustEnvelope::Recovery {
            bundle: Bytes::from_static(b"\xb0\x0b"),
        }
        .encode();
        format!("ndn-trust://{token}/{}", B64.encode(wire))
    }

    #[test]
    fn bytes_after_the_envelope_are_refused() {
        let mut wire = anchor_with(|_| {}).to_vec();
        assert!(TrustEnvelope::decode(&wire).is_ok());
        wire.extend_from_slice(&[0xaa, 0xbb]);
        assert_eq!(
            TrustEnvelope::decode(&wire),
            Err(EnvelopeError::Malformed("bytes after the envelope"))
        );
    }

    /// Unknown types follow the NDN critical rule, in the envelope and in the
    /// body, and a field of another kind counts as unknown.
    #[test]
    fn unknown_types_follow_the_critical_rule() {
        assert!(TrustEnvelope::decode(&anchor_with(|w| w.write_tlv(0x0490, b"x"))).is_ok());
        assert_eq!(
            TrustEnvelope::decode(&anchor_with(|w| w.write_tlv(0x0491, b"x"))),
            Err(EnvelopeError::UnknownCritical(0x0491))
        );
        // Token (0x0485, odd) belongs to invites: critical inside an anchor.
        assert_eq!(
            TrustEnvelope::decode(&anchor_with(|w| w.write_tlv(T_TOKEN, b"t"))),
            Err(EnvelopeError::UnknownCritical(T_TOKEN))
        );
        // Envelope children.
        let child = |t: u64| {
            raw(|w| {
                w.write_tlv(T_FORMAT_VERSION, &[FORMAT_VERSION]);
                w.write_tlv(T_KIND, &[TrustKind::Recovery.code()]);
                w.write_tlv(t, b"x");
                w.write_nested(T_BODY, |w| w.write_tlv(T_WIRE, b"b"));
            })
        };
        assert!(TrustEnvelope::decode(&child(0x0476)).is_ok());
        assert_eq!(
            TrustEnvelope::decode(&child(0x0477)),
            Err(EnvelopeError::UnknownCritical(0x0477))
        );
        assert_eq!(
            TrustEnvelope::decode(&child(0x07)),
            Err(EnvelopeError::UnknownCritical(0x07))
        );
        // A non-critical field of another kind is skipped unread: a 31-byte
        // AnchorFingerprint (0x048E) inside a delegation.
        let delegation = raw(|w| {
            w.write_tlv(T_FORMAT_VERSION, &[FORMAT_VERSION]);
            w.write_tlv(T_KIND, &[TrustKind::Delegation.code()]);
            w.write_nested(T_BODY, |w| {
                w.write_tlv(T_WIRE, b"d");
                w.write_tlv(T_PRINCIPAL_PUBKEY, b"k");
                w.write_tlv(T_ANCHOR_FINGERPRINT, &[0; 31]);
            });
        });
        assert!(TrustEnvelope::decode(&delegation).is_ok());
    }

    /// A newer format is refused as such, whatever its new children.
    #[test]
    fn newer_format_is_refused_before_its_children() {
        let wire = raw(|w| {
            w.write_tlv(T_FORMAT_VERSION, &[2]);
            w.write_tlv(T_KIND, &[TrustKind::Anchor.code()]);
            w.write_tlv(0x0479, b"new");
        });
        assert_eq!(
            TrustEnvelope::decode(&wire),
            Err(EnvelopeError::UnsupportedVersion(2))
        );
    }

    #[test]
    fn one_byte_fields_must_be_one_byte() {
        for (value, error) in [
            (&[1u8, 0][..], "format version length"),
            (&[][..], "format version length"),
        ] {
            let wire = raw(|w| {
                w.write_tlv(T_FORMAT_VERSION, value);
                w.write_tlv(T_KIND, &[TrustKind::Recovery.code()]);
                w.write_nested(T_BODY, |w| w.write_tlv(T_WIRE, b"b"));
            });
            assert_eq!(
                TrustEnvelope::decode(&wire),
                Err(EnvelopeError::Malformed(error))
            );
        }
        let wire = raw(|w| {
            w.write_tlv(T_FORMAT_VERSION, &[FORMAT_VERSION]);
            w.write_tlv(T_KIND, &[TrustKind::Recovery.code(), 0]);
            w.write_nested(T_BODY, |w| w.write_tlv(T_WIRE, b"b"));
        });
        assert_eq!(
            TrustEnvelope::decode(&wire),
            Err(EnvelopeError::Malformed("kind length"))
        );
        let capability = |direction: &[u8]| {
            raw(|w| {
                w.write_tlv(T_FORMAT_VERSION, &[FORMAT_VERSION]);
                w.write_tlv(T_KIND, &[TrustKind::Capability.code()]);
                w.write_nested(T_BODY, |w| {
                    w.write_tlv(T_DIRECTION, direction);
                    w.write_tlv(T_NAMESPACE, b"/work");
                    w.write_tlv(T_TTL_SECS, &300u64.to_be_bytes());
                });
            })
        };
        assert!(TrustEnvelope::decode(&capability(&[1])).is_ok());
        assert_eq!(
            TrustEnvelope::decode(&capability(&[1, 5])),
            Err(EnvelopeError::Malformed("capability direction length"))
        );
    }

    #[test]
    fn repeated_fields_are_refused_except_scope_patterns() {
        let twice = anchor_with(|w| {
            w.write_tlv(T_NAMESPACE, b"/a");
            w.write_tlv(T_NAMESPACE, b"/b");
        });
        assert_eq!(
            TrustEnvelope::decode(&twice),
            Err(EnvelopeError::Malformed("repeated field"))
        );
        let kind_twice = raw(|w| {
            w.write_tlv(T_FORMAT_VERSION, &[FORMAT_VERSION]);
            w.write_tlv(T_KIND, &[TrustKind::Recovery.code()]);
            w.write_tlv(T_KIND, &[TrustKind::Recovery.code()]);
            w.write_nested(T_BODY, |w| w.write_tlv(T_WIRE, b"b"));
        });
        assert_eq!(
            TrustEnvelope::decode(&kind_twice),
            Err(EnvelopeError::Malformed("repeated field"))
        );
        let c = Capability {
            direction: CapDirection::Request,
            namespace: "/work/acme".into(),
            scope_patterns: vec!["/work/acme/a".into(), "/work/acme/b".into()],
            ttl_secs: 60,
            nonce: Bytes::from_static(&[3; CAPABILITY_NONCE_LEN]),
            grant: None,
        };
        round_trip(&TrustEnvelope::Capability(c));
    }

    #[test]
    fn uri_kind_must_match_the_envelope() {
        assert!(TrustEnvelope::from_uri(&recovery_uri("recovery")).is_ok());
        for token in ["anchor", "", "Recovery"] {
            assert_eq!(
                TrustEnvelope::from_uri(&recovery_uri(token)),
                Err(EnvelopeError::KindMismatch {
                    uri: token.into(),
                    envelope: "recovery",
                }),
                "{token:?}"
            );
        }
        let payload = recovery_uri("recovery")
            .rsplit('/')
            .next()
            .unwrap()
            .to_owned();
        assert!(matches!(
            TrustEnvelope::from_uri(&format!("https://x.example/t/bag#{payload}")),
            Err(EnvelopeError::KindMismatch { .. })
        ));
    }

    /// The mirror is `https://<domain>/t/<kind>#<payload>`, nothing looser.
    #[test]
    fn mirror_is_https_with_the_t_kind_path() {
        let payload = recovery_uri("recovery")
            .rsplit('/')
            .next()
            .unwrap()
            .to_owned();
        let ok = |s: String| assert!(TrustEnvelope::from_uri(&s).is_ok(), "{s}");
        ok(format!("https://join.example/t/recovery#{payload}"));
        ok(format!("https://join.example:8443/t/recovery#{payload}"));
        let err =
            |s: String, e: EnvelopeError| assert_eq!(TrustEnvelope::from_uri(&s), Err(e), "{s}");
        err(
            format!("http://x/t/recovery#{payload}"),
            EnvelopeError::UnknownScheme,
        );
        err(
            format!("https://x/recovery#{payload}"),
            EnvelopeError::UnknownScheme,
        );
        err(
            format!("https://x/a/t/recovery#{payload}"),
            EnvelopeError::UnknownScheme,
        );
        err(
            format!("https://x/t/recovery/y#{payload}"),
            EnvelopeError::UnknownScheme,
        );
        err(
            format!("https://x/t/recovery?q=1#{payload}"),
            EnvelopeError::UnknownScheme,
        );
        err(
            format!("https://x/y#/t/recovery{payload}"),
            EnvelopeError::UnknownScheme,
        );
        err("https://x/t/recovery".into(), EnvelopeError::MalformedUri);
        err(
            format!("https:///t/recovery#{payload}"),
            EnvelopeError::MalformedUri,
        );
    }

    #[test]
    fn legacy_version_is_decimal_digits_only() {
        assert!(TrustEnvelope::from_uri("ndn-ctx:1:42:Y3R4").is_ok());
        for bad in [
            "ndn-ctx:1:+42:Y3R4",
            "ndn-ctx:1::Y3R4",
            "ndn-ctx:1:-1:Y3R4",
            "ndn-ctx:1: 42:Y3R4",
        ] {
            assert_eq!(
                TrustEnvelope::from_uri(bad),
                Err(EnvelopeError::MalformedUri),
                "{bad}"
            );
        }
    }
}
