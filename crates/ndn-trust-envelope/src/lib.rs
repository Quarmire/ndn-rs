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
//! address. It only carries names (as strings) and signed-Data wire blobs.
//!
//! ## Carriage
//!
//! ```text
//! ndn-trust://<kind>/<base64url(TLV)>        QR / NFC / clipboard / deep-link
//! https://<domain>/t/<kind>#<base64url(TLV)> universal-link mirror (payload in the fragment)
//! <file>.ndntrust                            raw TLV — file / share-sheet
//! ndn-ctx:1:<ver>:<b64url>                    legacy anchor form, still parsed
//! ```
//!
//! The `<kind>` in a URI is a routing hint; the TLV is authoritative.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use bytes::Bytes;
use ndn_tlv::{TlvReader, TlvWriter};
use thiserror::Error;

// ── TLV codes (fresh range, clear of TrustContext's 0x0410–0x041F) ───────────
const T_ENVELOPE: u64 = 0x0470;
const T_FORMAT_VERSION: u64 = 0x0471;
const T_KIND: u64 = 0x0472;
const T_BODY: u64 = 0x0473;

const T_U64_VERSION: u64 = 0x0481; // anchor: context version
const T_WIRE: u64 = 0x0482; // primary signed-Data blob (context / delegation / bundle / safebag)
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

/// The envelope format version this crate emits and accepts.
pub const FORMAT_VERSION: u8 = 1;

const SCHEME: &str = "ndn-trust://";
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
/// bearer) additionally carries the signed capability wire in [`grant`](Self::grant).
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
    /// The signed capability wire (present on a `Grant`).
    pub grant: Option<Bytes>,
}

/// A decoded `ndn-trust://` envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustEnvelope {
    /// Adopt a trust context: `context_content` is `SignedTrustContext::encode_content()`.
    Anchor { version: u64, context_content: Bytes },
    /// NDNCERT enrollment invitation.
    Invite {
        ca_prefix: String,
        identity_namespace: String,
        token: String,
        ttl_secs: Option<u64>,
    },
    /// A signed delegation plus the principal's public key needed to verify it.
    Delegation {
        signed_delegation: Bytes,
        principal_pubkey: Bytes,
    },
    /// A recovery bundle (public history; carries no private keys).
    Recovery { bundle: Bytes },
    /// A password-encrypted SafeBag and the key name it carries.
    Bag { key_name: String, safebag: Bytes },
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

    /// Encode to the canonical TLV container (the `.ndntrust` file form, and the
    /// bytes base64url'd into a URI).
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
                version,
                context_content,
            } => {
                w.write_tlv(T_U64_VERSION, &version.to_be_bytes());
                w.write_tlv(T_WIRE, context_content);
            }
            TrustEnvelope::Invite {
                ca_prefix,
                identity_namespace,
                token,
                ttl_secs,
            } => {
                w.write_tlv(T_CA_PREFIX, ca_prefix.as_bytes());
                w.write_tlv(T_ID_NAMESPACE, identity_namespace.as_bytes());
                w.write_tlv(T_TOKEN, token.as_bytes());
                if let Some(ttl) = ttl_secs {
                    w.write_tlv(T_TTL_SECS, &ttl.to_be_bytes());
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
            TrustEnvelope::Bag { key_name, safebag } => {
                w.write_tlv(T_KEY_NAME, key_name.as_bytes());
                w.write_tlv(T_WIRE, safebag);
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

    /// Decode the canonical TLV container.
    pub fn decode(wire: &[u8]) -> Result<Self, EnvelopeError> {
        let mut outer = TlvReader::new(Bytes::copy_from_slice(wire));
        let (typ, body) = outer.read_tlv().map_err(|_| EnvelopeError::Truncated)?;
        if typ != T_ENVELOPE {
            return Err(EnvelopeError::BadTag(typ));
        }

        let mut fmt: Option<u8> = None;
        let mut kind: Option<u8> = None;
        let mut body_bytes: Option<Bytes> = None;
        let mut inner = TlvReader::new(body);
        while !inner.is_empty() {
            let (t, v) = inner.read_tlv().map_err(|_| EnvelopeError::Truncated)?;
            match t {
                T_FORMAT_VERSION => fmt = v.first().copied(),
                T_KIND => kind = v.first().copied(),
                T_BODY => body_bytes = Some(v),
                _ => {} // forward-compatible: ignore unknown fields
            }
        }

        let fmt = fmt.ok_or(EnvelopeError::MissingField("format version"))?;
        if fmt != FORMAT_VERSION {
            return Err(EnvelopeError::UnsupportedVersion(fmt));
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

        let mut r = TlvReader::new(body);
        while !r.is_empty() {
            let (t, v) = r.read_tlv().map_err(|_| EnvelopeError::Truncated)?;
            match t {
                T_U64_VERSION => version = Some(read_u64(&v)?),
                T_WIRE => wire = Some(v),
                T_CA_PREFIX => ca_prefix = Some(read_str(&v)?),
                T_ID_NAMESPACE => id_namespace = Some(read_str(&v)?),
                T_TOKEN => token = Some(read_str(&v)?),
                T_TTL_SECS => ttl_secs = Some(read_u64(&v)?),
                T_PRINCIPAL_PUBKEY => principal_pubkey = Some(v),
                T_KEY_NAME => key_name = Some(read_str(&v)?),
                T_NAMESPACE => namespace = Some(read_str(&v)?),
                T_SCOPE_PATTERN => scope_patterns.push(read_str(&v)?),
                T_NONCE => nonce = Some(v),
                T_GRANT => grant = Some(v),
                T_DIRECTION => direction = v.first().copied(),
                _ => {}
            }
        }

        let need = EnvelopeError::MissingField;
        Ok(match kind {
            TrustKind::Anchor => TrustEnvelope::Anchor {
                version: version.ok_or(need("anchor version"))?,
                context_content: wire.ok_or(need("anchor content"))?,
            },
            TrustKind::Invite => TrustEnvelope::Invite {
                ca_prefix: ca_prefix.ok_or(need("ca prefix"))?,
                identity_namespace: id_namespace.ok_or(need("identity namespace"))?,
                token: token.ok_or(need("token"))?,
                ttl_secs,
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
        format!("{SCHEME}{}/{}", self.kind().as_str(), B64.encode(self.encode()))
    }

    /// Parse any supported carriage: the `ndn-trust://` scheme, the `https://…#`
    /// universal-link mirror, or the legacy `ndn-ctx:1:` anchor form.
    pub fn from_uri(s: &str) -> Result<Self, EnvelopeError> {
        let s = s.trim();

        if let Some(rest) = s.strip_prefix(LEGACY_ANCHOR_TAG) {
            let (ver, b64) = rest.split_once(':').ok_or(EnvelopeError::MalformedUri)?;
            let version = ver.parse().map_err(|_| EnvelopeError::MalformedUri)?;
            let content = B64.decode(b64.trim()).map_err(|_| EnvelopeError::BadBase64)?;
            return Ok(TrustEnvelope::Anchor {
                version,
                context_content: Bytes::from(content),
            });
        }

        let b64 = if let Some(rest) = s.strip_prefix(SCHEME) {
            // <kind>/<b64> — the kind is a hint; the TLV is authoritative.
            rest.split_once('/')
                .map(|(_, b)| b)
                .ok_or(EnvelopeError::MalformedUri)?
        } else if (s.starts_with("https://") || s.starts_with("http://")) && s.contains("/t/") {
            s.split_once('#').ok_or(EnvelopeError::MalformedUri)?.1
        } else {
            return Err(EnvelopeError::UnknownScheme);
        };

        let wire = B64.decode(b64.trim()).map_err(|_| EnvelopeError::BadBase64)?;
        Self::decode(&wire)
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
            version: 7,
            context_content: Bytes::from_static(b"\x07\x14ctx-wire-bytes"),
        };
        assert_eq!(e.kind(), TrustKind::Anchor);
        round_trip(&e);
    }

    #[test]
    fn invite_round_trips_with_and_without_ttl() {
        round_trip(&TrustEnvelope::Invite {
            ca_prefix: "/ndn".into(),
            identity_namespace: "/ndn/mobile".into(),
            token: "a1b2c3d4e5f6".into(),
            ttl_secs: Some(3600),
        });
        round_trip(&TrustEnvelope::Invite {
            ca_prefix: "/ndn".into(),
            identity_namespace: "/ndn/mobile".into(),
            token: "tok".into(),
            ttl_secs: None,
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
            grant: Some(Bytes::from_static(b"signed-capability-wire")),
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
                version: 42,
                context_content: Bytes::from_static(content),
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
        };
        let b64 = B64.encode(e.encode());
        let mirror = format!("https://join.example/t/invite#{b64}");
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
}
