//! Namespace role layout and its generated trust schema
//! (`docs/specs/personal-namespace.md` §2, §4).
//!
//! Every device of a namespace rooted at `/<ns>` is named
//! `/<ns>/<role>/<device>` with keys `/<ns>/<role>/<device>/KEY/<id>`, where
//! the role is one of `admin`, `member`, `node` (relay) or `guest`.
//! Authorization lives in these names, so [`namespace_schema`] can derive the
//! whole trust schema from the namespace:
//!
//! ```text
//! /<ns>/KEY/<k>/self/<v>, /<ns>/32=trust-context/<v>  signed by  the root key    (root)
//! /<ns>/CA/KEY/<k>/<issuer>/<v>               signed by  the root key
//! /<ns>/<role>/<dev>/KEY/<k>/NDNCERT/<v>      signed by  /<ns>/CA/KEY/<k>
//! <requested device key>/ndncert-approve/<id> signed by /<ns>/admin/<dev>/KEY/<k>
//! <requested device key>/ndncert-deny/<id>    signed by /<ns>/admin/<dev>/KEY/<k>
//! /<ns>/CA/PENDING/<digest> (signed Interest) signed by /<ns>/admin/<dev>/KEY/<k>
//! /<ns>/<role>/<dev>/<**data>                 signed by  /<ns>/<role>/<dev>/KEY/<k>
//! /<ns>/CA/<**data>                           signed by  /<ns>/CA/KEY/<k>
//! /<ns>/shared/<**data>                       signed by  /<ns>/{admin,member}/<dev>/KEY/<k>
//! ```
//!
//! Certificates follow NDN Certificate Format v2: a certificate of the key
//! `…/KEY/<k>` is `…/KEY/<k>/<issuer-id>/<version>` — the root's
//! self-signed `/<ns>/KEY/<k>/self/<v>`, a device's CA-issued
//! `…/KEY/<k>/NDNCERT/<v>` (the issuer id also keeps a certificate apart from
//! an approval `…/KEY/<k>/ndncert-approve/<id>`). The LVS rules match
//! certificate names, signers included, as python-ndn / NDNts schemas do; the
//! native rules name signers by key. A signer may be named either way in a
//! KeyLocator: ndn-rs's chain walk judges each hop by the KeyLocator, by the
//! certificate it resolves to and by the key name
//! ([`SignedTrustContext::authorizes_hop`](ndn_security::SignedTrustContext::authorizes_hop)).
//! Contexts published by earlier releases carry their key-name schema; the
//! same walk judges a cert-v2 certificate there by its key name, so they keep
//! working.
//!
//! The fixed-shape rules (root, context, CA and device certificates,
//! approvals) are LightVerSec, compiled in-tree to the portable binary. Two
//! kinds of rule are beyond the in-tree LVS compiler and evaluator, and are
//! native-text rules OR'd with it instead:
//!
//! - **variable-depth data** (`<**data>`): LVS patterns have a fixed number of
//!   components;
//! - **"the device's own key"**: the data name's `<dev>` must equal the key
//!   name's, which needs cross-pattern tag equality (not lowered by the
//!   compiler, not checked by the evaluator), and the device's `KEY` subtree
//!   must stay excluded (`<!KEY>`) so only the CA certifies device keys — no
//!   device can self-sign a sub-key or an approval of its own re-key.
//!
//! The context carrying the schema is authoritative
//! ([`SignedTrustContext::schema_authoritative`](ndn_security::SignedTrustContext::schema_authoritative)):
//! no hierarchy floor (the approval and shared rules are cross-identity on
//! purpose) and the schema is checked on every certificate hop, so a key is
//! only as good as its issuer's right to certify it.
//!
//! The schema travels in the anchor envelope, which is kept small so it fits
//! one QR code for short namespaces (a larger one is shown by reference): the
//! approval rule therefore covers every role's request with one pattern.

use std::fmt;
use std::str::FromStr;

use ndn_packet::{Name, NameComponent};
use ndn_security::cert_name::NDNCERT_ISSUER;
use ndn_security::{LvsCompileError, SchemaBlob, compile_lvs_to_binary};

/// One of the four roles a device holds in a namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    /// The owner's devices allowed to approve enrollments.
    Admin,
    /// Every other device of the owner's.
    Member,
    /// A relay (VPS / home server, QUIC listener, relay).
    Node,
    /// A friend's device, short-lived.
    Guest,
}

impl Role {
    pub const ALL: [Role; 4] = [Role::Admin, Role::Member, Role::Node, Role::Guest];

    /// The name component naming this role (`admin`, `member`, …).
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Member => "member",
            Role::Node => "node",
            Role::Guest => "guest",
        }
    }

    fn from_bytes(b: &[u8]) -> Option<Role> {
        Role::ALL.into_iter().find(|r| r.as_str().as_bytes() == b)
    }

    /// The role a generic name component names, if any.
    pub fn from_component(c: &NameComponent) -> Option<Role> {
        if c.typ != ndn_packet::tlv_type::NAME_COMPONENT {
            return None;
        }
        Role::from_bytes(&c.value)
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Role {
    type Err = RoleError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Role::from_bytes(s.as_bytes()).ok_or_else(|| RoleError::UnknownRole(s.to_string()))
    }
}

/// `/<ns>/shared`: data any admin or member device may write.
pub const SHARED: &str = "shared";
/// Longest device name accepted (a DNS label).
pub const MAX_DEVICE_NAME_LEN: usize = 63;

/// Why a role-layout name or namespace was refused.
#[derive(Debug, thiserror::Error)]
pub enum RoleError {
    #[error("unknown role {0:?}: expected admin, member, node or guest")]
    UnknownRole(String),
    #[error("invalid device name {name:?}: {reason}")]
    InvalidDevice { name: String, reason: &'static str },
    #[error("namespace {namespace} cannot root a namespace: {reason}")]
    InvalidNamespace {
        namespace: String,
        reason: &'static str,
    },
    /// The generated LVS did not compile — a generator bug.
    #[error("generated schema does not compile: {0}")]
    SchemaCompile(#[from] LvsCompileError),
}

fn device_err(name: &str, reason: &'static str) -> RoleError {
    RoleError::InvalidDevice {
        name: name.to_string(),
        reason,
    }
}

/// Check that `device` can be the `<device>` component of
/// `/<ns>/<role>/<device>`: 1–63 bytes of ASCII letters, digits, `-`, `_` and
/// `.`, starting with a letter or digit, and not a word the layout reserves
/// (`KEY`, `CA`, a role keyword) in any letter case.
pub fn validate_device_name(device: &str) -> Result<(), RoleError> {
    if device.is_empty() {
        return Err(device_err(device, "it is empty"));
    }
    if device.len() > MAX_DEVICE_NAME_LEN {
        return Err(device_err(device, "it is longer than 63 bytes"));
    }
    if !device
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(device_err(
            device,
            "only ASCII letters, digits, '-', '_' and '.' are allowed",
        ));
    }
    if !device.as_bytes()[0].is_ascii_alphanumeric() {
        return Err(device_err(device, "it must start with a letter or digit"));
    }
    let reserved = ["KEY", "CA"]
        .into_iter()
        .chain(Role::ALL.iter().map(|r| r.as_str()));
    if reserved.into_iter().any(|w| w.eq_ignore_ascii_case(device)) {
        return Err(device_err(
            device,
            "it is reserved by the role layout (KEY, CA, admin, member, node, guest)",
        ));
    }
    Ok(())
}

/// A device name derived from a host name: the first DNS label, lowercased,
/// with every disallowed character replaced by `-` (runs collapsed, ends
/// trimmed), cut to 63 bytes. `None` when nothing valid remains (e.g. the
/// label is reserved).
pub fn sanitize_device_name(host: &str) -> Option<String> {
    let label = host.trim().split('.').next().unwrap_or("");
    let mut out = String::with_capacity(label.len());
    for c in label.chars() {
        let c = c.to_ascii_lowercase();
        if c.is_ascii_alphanumeric() || c == '_' {
            out.push(c);
        } else if !out.is_empty() && !out.ends_with('-') {
            out.push('-');
        }
    }
    out.truncate(MAX_DEVICE_NAME_LEN);
    let out = out.trim_end_matches('-').to_string();
    validate_device_name(&out).is_ok().then_some(out)
}

/// Check that `namespace` can root a namespace and its generated
/// schema: at least one component, each a generic component of URI-unreserved
/// ASCII (so it reads the same in LVS and native rule text) and not `KEY`.
pub fn validate_namespace(namespace: &Name) -> Result<(), RoleError> {
    let err = |reason| RoleError::InvalidNamespace {
        namespace: namespace.to_string(),
        reason,
    };
    if namespace.is_empty() {
        return Err(err("it is the root name"));
    }
    for c in namespace.components() {
        if c.typ != ndn_packet::tlv_type::NAME_COMPONENT {
            return Err(err("every component must be a generic name component"));
        }
        if c.value.is_empty()
            || c.value.iter().all(|&b| b == b'.')
            || !c
                .value
                .iter()
                .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~'))
        {
            return Err(err(
                "components may only use ASCII letters, digits, '-', '_', '.' and '~'",
            ));
        }
        if c.value.as_ref() == b"KEY" {
            return Err(err("a component named KEY would read as a key name"));
        }
    }
    Ok(())
}

/// `/<ns>/<role>`, the prefix every device of `role` is named under (and the
/// scope of a role's invite tokens).
pub fn role_prefix(namespace: &Name, role: Role) -> Name {
    namespace.clone().append(role.as_str())
}

/// `/<ns>/shared`.
pub fn shared_prefix(namespace: &Name) -> Name {
    namespace.clone().append(SHARED)
}

/// The device identity `/<ns>/<role>/<device>`, after
/// [`validate_device_name`].
pub fn device_identity(namespace: &Name, role: Role, device: &str) -> Result<Name, RoleError> {
    validate_device_name(device)?;
    Ok(role_prefix(namespace, role).append(device))
}

/// A device identity under the role layout, parsed from a name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceName {
    pub role: Role,
    pub device: String,
}

/// Parse `/<ns>/<role>/<device>` followed by `tail` more components.
fn parse_device_prefix(namespace: &Name, name: &Name) -> Option<(DeviceName, usize)> {
    if !name.has_prefix(namespace) {
        return None;
    }
    let rest = &name.components()[namespace.len()..];
    let [role, device, ..] = rest else {
        return None;
    };
    let role = Role::from_component(role)?;
    if device.typ != ndn_packet::tlv_type::NAME_COMPONENT {
        return None;
    }
    let device = std::str::from_utf8(&device.value).ok()?;
    validate_device_name(device).ok()?;
    Some((
        DeviceName {
            role,
            device: device.to_string(),
        },
        rest.len() - 2,
    ))
}

/// The device a name names exactly: `/<ns>/<role>/<device>`.
pub fn parse_device_identity(namespace: &Name, name: &Name) -> Option<DeviceName> {
    match parse_device_prefix(namespace, name)? {
        (device, 0) => Some(device),
        _ => None,
    }
}

/// The device a key (or certificate) name belongs to:
/// `/<ns>/<role>/<device>/KEY/<id>[/…]`.
pub fn parse_device_key(namespace: &Name, key_name: &Name) -> Option<DeviceName> {
    let (device, tail) = parse_device_prefix(namespace, key_name)?;
    if tail < 2 {
        return None;
    }
    let key = &key_name.components()[namespace.len() + 2];
    (key.typ == ndn_packet::tlv_type::NAME_COMPONENT && key.value.as_ref() == b"KEY")
        .then_some(device)
}

/// An invite token that carries its role: `<role>-<secret>`. The CA scopes
/// such a token to `/<ns>/<role>` ([`token_role`]), so it can only certify
/// devices of that role.
pub fn role_token(role: Role, secret: &str) -> String {
    format!("{role}-{secret}")
}

/// The role an invite token names (`member-…`, `guest-…`), if any. Tokens
/// without a role prefix are unscoped.
pub fn token_role(token: &str) -> Option<Role> {
    let (role, secret) = token.split_once('-')?;
    if secret.is_empty() {
        return None;
    }
    Role::from_str(role).ok()
}

/// The separator between a token and the expiry it carries.
const TOKEN_EXPIRY_MARK: &str = "-until";

/// `token` with an absolute expiry (Unix seconds) appended:
/// `<token>-until<secs>`. The expiry travels inside the token, so the CA
/// (which reads tokens from its config) and the invitee (which reads the
/// invite) both see the same deadline, however long the token sat in a
/// config file or a message.
pub fn token_with_expiry(token: &str, expires_at_secs: u64) -> String {
    format!("{token}{TOKEN_EXPIRY_MARK}{expires_at_secs}")
}

/// The expiry (Unix seconds) a token carries ([`token_with_expiry`]):
/// `Ok(None)` for a token without one, which does not expire. A `-until`
/// suffix that is not a decimal u64 (empty, non-digits, overflow) is an
/// error: such a token is refused, never read as non-expiring.
pub fn token_expiry(token: &str) -> Result<Option<u64>, MalformedTokenExpiry> {
    let Some((_, secs)) = token.rsplit_once(TOKEN_EXPIRY_MARK) else {
        return Ok(None);
    };
    if !secs.is_empty()
        && secs.bytes().all(|b| b.is_ascii_digit())
        && let Ok(at) = secs.parse()
    {
        return Ok(Some(at));
    }
    Err(MalformedTokenExpiry(secs.to_string()))
}

/// A token's `-until` suffix is not a number of Unix seconds.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the token's expiry `-until{0}` is not a number of Unix seconds")]
pub struct MalformedTokenExpiry(pub String);

/// Whether a token expiring at `expires_at` has expired at `now` (same
/// unit). A token is valid while `now < expires_at`, on the CA and on the
/// invitee alike.
pub fn token_expired(expires_at: u64, now: u64) -> bool {
    now >= expires_at
}

/// The generated namespace schema for one namespace (see the module
/// docs): LVS for the fixed-shape rules, native text for the rest; the trust
/// context carries both, OR'd.
#[derive(Clone, Debug)]
pub struct NamespaceSchema {
    /// LVS source in the in-tree compiler's syntax.
    pub lvs_source: String,
    /// [`lvs_source`](Self::lvs_source) compiled to the LVS binary.
    pub lvs_binary: Vec<u8>,
    /// Native-text rules (`<data> => <key>`, one per line) for what the
    /// in-tree LVS cannot express.
    pub native_rules: String,
}

impl NamespaceSchema {
    /// The context's schema blobs: the LVS binary, then the native rules.
    pub fn blobs(&self) -> Vec<SchemaBlob> {
        vec![
            SchemaBlob::lvs(self.lvs_binary.clone()),
            SchemaBlob::native_text(self.native_rules.clone()),
        ]
    }
}

/// Generate the namespace trust schema for `namespace` (§4).
pub fn namespace_schema(namespace: &Name) -> Result<NamespaceSchema, RoleError> {
    validate_namespace(namespace)?;
    let lvs_ns: String = namespace
        .components()
        .iter()
        .map(|c| format!("/\"{}\"", String::from_utf8_lossy(&c.value)))
        .collect();
    // `validate_namespace` keeps every component URI-unreserved, so the raw
    // value is also its URI form.
    let ns = namespace.to_string();

    // Only `_device` is a named pattern: the key id, issuer id, version and
    // request id stay anonymous (`_`), which spares the envelope a tag symbol
    // for each. Certificates and their signers are cert-v2 certificate names,
    // as in python-ndn / NDNts schemas (a device certificate is the CA's
    // `…/KEY/<k>/NDNCERT/<v>`); a chain walk matches a signer named by its key
    // through the certificate that key resolves to.
    let mut lvs = format!(
        "// Generated namespace trust schema for {ns}. Signers are certificate names.\n\
         #root: {lvs_ns}/\"KEY\"/_/_/_ <= #root\n\
         #context: {lvs_ns}/\"32=trust-context\"/_ <= #root\n\
         #ca: {lvs_ns}/\"CA\"/\"KEY\"/_/_/_ <= #root\n"
    );
    for role in Role::ALL {
        lvs.push_str(&format!(
            "#{role}: {lvs_ns}/\"{role}\"/_device/\"KEY\"/_/\"{NDNCERT_ISSUER}\"/_ <= #ca\n"
        ));
    }
    // Enrollment decisions for any device key (whatever its role), signed by
    // an admin device: approvals and denials, one rule each (the envelope
    // carrying the schema must stay QR-sized). The CA's pending list is
    // answered only to an Interest an admin device signed.
    lvs.push_str(&format!(
        "#approve: {lvs_ns}/_/_device/\"KEY\"/_/\"ndncert-approve\"/_ <= #admin\n\
         #deny: {lvs_ns}/_/_device/\"KEY\"/_/\"ndncert-deny\"/_ <= #admin\n\
         #pending: {lvs_ns}/\"CA\"/\"PENDING\"/_ <= #admin\n"
    ));

    // Signers by key name; the validator also accepts a signer named by one
    // of its certificates (it judges a certificate name by its key's).
    let mut native = format!("{ns}/CA/<!KEY>/<**data> => {ns}/CA/KEY/<key>\n");
    for role in Role::ALL {
        native.push_str(&format!(
            "{ns}/{role}/<device>/<!KEY>/<**data> => {ns}/{role}/<device>/KEY/<key>\n"
        ));
    }
    for role in [Role::Admin, Role::Member] {
        native.push_str(&format!(
            "{ns}/{SHARED}/<**data> => {ns}/{role}/<device>/KEY/<key>\n"
        ));
    }

    let lvs_binary = compile_lvs_to_binary(&lvs)?;
    Ok(NamespaceSchema {
        lvs_source: lvs,
        lvs_binary,
        native_rules: native,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_security::SignedTrustContext;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    /// A malformed `-until` suffix is refused, never read as "no expiry".
    #[test]
    fn malformed_token_expiry_fails_closed() {
        assert_eq!(token_expiry("member-ab"), Ok(None));
        assert_eq!(token_expiry(&token_with_expiry("member-ab", 1700000000)), Ok(Some(1700000000)));
        for bad in [
            "member-ab-until",
            "member-ab-untilsoon",
            "member-ab-until12x",
            "member-ab-until+12",
            "member-ab-until99999999999999999999",
        ] {
            assert!(token_expiry(bad).is_err(), "{bad}");
        }
    }

    /// One boundary everywhere: valid while `now < until`.
    #[test]
    fn a_token_expires_at_its_until() {
        assert!(!token_expired(100, 99));
        assert!(token_expired(100, 100));
        assert!(token_expired(100, 101));
    }

    #[test]
    fn roles_round_trip_and_name_builders() {
        for role in Role::ALL {
            assert_eq!(role.as_str().parse::<Role>().unwrap(), role);
        }
        assert!(matches!(
            "owner".parse::<Role>(),
            Err(RoleError::UnknownRole(_))
        ));
        let ns = n("/home/bob");
        assert_eq!(role_prefix(&ns, Role::Guest), n("/home/bob/guest"));
        assert_eq!(shared_prefix(&ns), n("/home/bob/shared"));
        assert_eq!(
            device_identity(&ns, Role::Admin, "laptop").unwrap(),
            n("/home/bob/admin/laptop")
        );
    }

    #[test]
    fn device_names_are_single_unreserved_components() {
        for ok in ["laptop", "pixel-7", "a", "host_2.lan", &"x".repeat(63)] {
            validate_device_name(ok).unwrap_or_else(|e| panic!("{ok:?}: {e}"));
        }
        for bad in [
            "",
            "a/b",
            "KEY",
            "key",
            "CA",
            "admin",
            "Member",
            "node",
            "guest",
            "-x",
            ".x",
            "with space",
            "ü",
            &"x".repeat(64),
        ] {
            assert!(
                matches!(
                    validate_device_name(bad),
                    Err(RoleError::InvalidDevice { .. })
                ),
                "{bad:?} must be refused"
            );
        }
        assert!(device_identity(&n("/home/bob"), Role::Member, "a/b").is_err());
    }

    #[test]
    fn host_names_sanitize_to_device_names() {
        assert_eq!(
            sanitize_device_name("Bobs-MacBook.local").as_deref(),
            Some("bobs-macbook")
        );
        assert_eq!(
            sanitize_device_name("my host!!name\n").as_deref(),
            Some("my-host-name")
        );
        assert_eq!(
            sanitize_device_name("raspberrypi").as_deref(),
            Some("raspberrypi")
        );
        assert_eq!(sanitize_device_name(&"a".repeat(80)).unwrap().len(), 63);
        for unusable in ["", "...", "admin", "KEY.example.org", "-"] {
            assert_eq!(sanitize_device_name(unusable), None, "{unusable:?}");
        }
    }

    #[test]
    fn parses_device_identities_and_keys() {
        let ns = n("/home/bob");
        let phone = DeviceName {
            role: Role::Member,
            device: "phone".into(),
        };
        assert_eq!(
            parse_device_identity(&ns, &n("/home/bob/member/phone")),
            Some(phone.clone())
        );
        assert_eq!(
            parse_device_identity(&ns, &n("/home/bob/member/phone/x")),
            None
        );
        assert_eq!(
            parse_device_key(&ns, &n("/home/bob/member/phone/KEY/k1")),
            Some(phone.clone())
        );
        assert_eq!(
            parse_device_key(&ns, &n("/home/bob/member/phone/KEY/k1/NDNCERT/v=1")),
            Some(phone)
        );
        for not_a_device_key in [
            "/home/bob/member/phone/KEY",
            "/home/bob/member/phone/data/x",
            "/home/bob/owner/phone/KEY/k1",
            "/home/bob/member/KEY/KEY/k1",
            "/home/bob/CA/KEY/ca",
            "/home/alice/member/phone/KEY/k1",
            "/home/bob/phone/KEY/k1",
        ] {
            assert_eq!(
                parse_device_key(&ns, &n(not_a_device_key)),
                None,
                "{not_a_device_key}"
            );
        }
    }

    #[test]
    fn invite_tokens_carry_their_role() {
        let t = role_token(Role::Guest, "3fa2");
        assert_eq!(t, "guest-3fa2");
        assert_eq!(token_role(&t), Some(Role::Guest));
        assert_eq!(token_role("member-ab"), Some(Role::Member));
        assert_eq!(token_role("3fa2"), None);
        assert_eq!(token_role("invite-1"), None);
        assert_eq!(token_role("member-"), None);
    }

    #[test]
    fn namespaces_must_be_plain() {
        validate_namespace(&n("/home/bob")).unwrap();
        for bad in ["/", "/home/KEY", "/home/a%20b", "/home/v=1"] {
            assert!(
                matches!(
                    validate_namespace(&n(bad)),
                    Err(RoleError::InvalidNamespace { .. })
                ),
                "{bad}"
            );
        }
    }

    /// The schema, as adopters evaluate it: the generated blobs in an
    /// authoritative context.
    fn context() -> SignedTrustContext {
        let schema = namespace_schema(&n("/home/bob")).unwrap();
        SignedTrustContext::hierarchical(n("/home/bob"))
            .with_schema_blobs(schema.blobs())
            .unwrap()
            .schema_authoritative()
    }

    /// The certificate a signer's key name resolves to, named as this
    /// namespace names it (NDN Certificate Format v2): the root's
    /// self-signed `…/self/<v>`, the CA's root-issued `…/NA/<v>`, a device's
    /// CA-issued `…/NDNCERT/<v>`.
    fn cert_of(key: &Name) -> Name {
        let issuer = if key.has_prefix(&n("/home/bob/KEY")) {
            "self"
        } else if key.has_prefix(&n("/home/bob/CA/KEY")) {
            "NA"
        } else {
            "NDNCERT"
        };
        ndn_security::cert_name::cert_name(key, issuer, 9)
    }

    /// Whether a chain walk authorizes `data` signed by `key` — with the
    /// KeyLocator naming the key (ndn-rs) and naming its certificate (other
    /// stacks); both forms must give the same verdict.
    fn hop(ctx: &SignedTrustContext, data: &str, key: &str) -> bool {
        let (data, key) = (n(data), n(key));
        let cert = cert_of(&key);
        let by_key = ctx.authorizes_hop(&data, &key, Some(&cert));
        let by_cert = ctx.authorizes_hop(&data, &cert, Some(&cert));
        assert_eq!(by_key, by_cert, "{data} by {key}: the KeyLocator form changed the verdict");
        by_key
    }

    #[test]
    fn generated_schema_allows_the_role_layout() {
        let ctx = context();
        let root = "/home/bob/KEY/root";
        let ca = "/home/bob/CA/KEY/ca";
        let admin = "/home/bob/admin/laptop/KEY/k1";
        let member = "/home/bob/member/phone/KEY/k1";
        let allowed = [
            // root, context and CA certificates (cert-v2 names)
            ("/home/bob/KEY/root/self/v=1", root),
            ("/home/bob/32=trust-context/v=3", root),
            ("/home/bob/CA/KEY/ca/NA/v=1", root),
            // every role's device certificates, issued by the CA
            ("/home/bob/admin/laptop/KEY/k1/NDNCERT/v=1", ca),
            ("/home/bob/member/phone/KEY/k1/NDNCERT/v=2", ca),
            ("/home/bob/node/vps/KEY/k1/NDNCERT/v=3", ca),
            ("/home/bob/guest/alice/KEY/k1/NDNCERT/v=4", ca),
            // CA service data under its own name
            ("/home/bob/CA/INFO/v=1", ca),
            // device data under the device's own name, by its own key
            ("/home/bob/admin/laptop/photos/1", admin),
            ("/home/bob/member/phone/notes/a/b/c", member),
            (
                "/home/bob/guest/alice/hello",
                "/home/bob/guest/alice/KEY/k9",
            ),
            // approvals by an admin device, for any role's request
            (
                "/home/bob/member/tablet/KEY/k1/ndncert-approve/req-1",
                admin,
            ),
            ("/home/bob/admin/desk/KEY/k1/ndncert-approve/req-2", admin),
            ("/home/bob/node/vps/KEY/k1/ndncert-approve/req-3", admin),
            // the shared namespace, by admins and members
            ("/home/bob/shared/calendar/2026", admin),
            ("/home/bob/shared/calendar/2026", member),
        ];
        for (data, key) in allowed {
            assert!(hop(&ctx, data, key), "{data} by {key} must be allowed");
        }
        // The certificate hops, as LVS (python-ndn, NDNts) reads them: the
        // published LVS alone admits them with certificate-name signers.
        let lvs = SignedTrustContext::hierarchical(n("/home/bob"))
            .with_schema_blob(SchemaBlob::lvs(namespace_schema(&n("/home/bob")).unwrap().lvs_binary))
            .unwrap()
            .schema_authoritative();
        for (data, key) in [
            ("/home/bob/CA/KEY/ca/NA/v=1", "/home/bob/KEY/root/self/v=1"),
            ("/home/bob/member/phone/KEY/k1/NDNCERT/v=2", "/home/bob/CA/KEY/ca/NA/v=1"),
            ("/home/bob/32=trust-context/v=3", "/home/bob/KEY/root/self/v=1"),
        ] {
            assert!(lvs.authorizes(&n(data), &n(key)), "LVS: {data} by {key}");
        }
    }

    #[test]
    fn generated_schema_denies_what_the_roles_forbid() {
        let ctx = context();
        let denied = [
            // a member (or the device itself) signs an approval
            (
                "/home/bob/member/tablet/KEY/k1/ndncert-approve/req-1",
                "/home/bob/member/phone/KEY/k1",
            ),
            (
                "/home/bob/member/tablet/KEY/k2/ndncert-approve/req-1",
                "/home/bob/member/tablet/KEY/k1",
            ),
            (
                "/home/bob/admin/tablet/KEY/k1/ndncert-approve/req-1",
                "/home/bob/node/vps/KEY/k1",
            ),
            // an approval is no certificate: the CA does not sign one, and an
            // admin does not issue a device certificate
            (
                "/home/bob/member/tablet/KEY/k1/ndncert-approve/req-1",
                "/home/bob/CA/KEY/ca",
            ),
            (
                "/home/bob/member/tablet/KEY/k1/NDNCERT/v=1",
                "/home/bob/admin/laptop/KEY/k1",
            ),
            // a member signs another device's data, or another role's
            (
                "/home/bob/member/laptop/notes",
                "/home/bob/member/phone/KEY/k1",
            ),
            (
                "/home/bob/admin/phone/notes",
                "/home/bob/member/phone/KEY/k1",
            ),
            // guests and nodes do not write the shared namespace
            ("/home/bob/shared/calendar", "/home/bob/guest/alice/KEY/k1"),
            ("/home/bob/shared/calendar", "/home/bob/node/vps/KEY/k1"),
            // device keys not issued by the CA: self-signed, by the root, by a
            // device, or by an admin — in either certificate naming
            (
                "/home/bob/member/phone/KEY/k2",
                "/home/bob/member/phone/KEY/k1",
            ),
            (
                "/home/bob/member/phone/KEY/k1/self/v=1",
                "/home/bob/member/phone/KEY/k1",
            ),
            (
                "/home/bob/member/phone/KEY/k2/NDNCERT/v=1",
                "/home/bob/member/phone/KEY/k1",
            ),
            ("/home/bob/member/phone/KEY/k1", "/home/bob/KEY/root"),
            ("/home/bob/member/phone/KEY/k1/NDNCERT/v=1", "/home/bob/KEY/root"),
            (
                "/home/bob/admin/laptop/KEY/k1",
                "/home/bob/admin/desk/KEY/k1",
            ),
            // the CA key is certified by the root only; the CA cannot sign the
            // context; the root does not sign device data
            ("/home/bob/CA/KEY/ca2", "/home/bob/CA/KEY/ca"),
            ("/home/bob/CA/KEY/ca2/NA/v=1", "/home/bob/CA/KEY/ca"),
            ("/home/bob/KEY/root2/self/v=1", "/home/bob/CA/KEY/ca"),
            ("/home/bob/32=trust-context/v=4", "/home/bob/CA/KEY/ca"),
            ("/home/bob/member/phone/notes", "/home/bob/KEY/root"),
            // names outside the layout
            ("/home/bob/phone/notes", "/home/bob/phone/KEY/k1"),
            (
                "/home/alice/member/phone/x",
                "/home/alice/member/phone/KEY/k1",
            ),
        ];
        for (data, key) in denied {
            // Under either KeyLocator form (checked equal by `hop`).
            assert!(!hop(&ctx, data, key), "{data} by {key} must be denied");
        }
    }

    /// A context published by an earlier release carries the schema it
    /// generated then, over key names (`…/KEY/<k>` certificates, key-name
    /// signers). Its namespaces keep working once their CA issues cert-v2
    /// certificates: a chain walk judges a certificate by its key name too,
    /// and the old denials still hold.
    #[test]
    fn earlier_releases_schema_accepts_cert_v2_names() {
        let ns = "/\"home\"/\"bob\"";
        let mut lvs = format!(
            "#root: {ns}/\"KEY\"/_ <= #root\n#context: {ns}/\"32=trust-context\"/_ <= #root\n\
             #ca: {ns}/\"CA\"/\"KEY\"/_ <= #root\n"
        );
        for role in Role::ALL {
            lvs.push_str(&format!("#{role}: {ns}/\"{role}\"/_device/\"KEY\"/_ <= #ca\n"));
            lvs.push_str(&format!(
                "#approve_{role}: {ns}/\"{role}\"/_device/\"KEY\"/_/\"ndncert-approve\"/_ <= #admin\n"
            ));
        }
        let mut native = String::from("/home/bob/CA/<!KEY>/<**data> => /home/bob/CA/KEY/<key>\n");
        for role in Role::ALL {
            native.push_str(&format!(
                "/home/bob/{role}/<device>/<!KEY>/<**data> => /home/bob/{role}/<device>/KEY/<key>\n"
            ));
        }
        let old = SignedTrustContext::hierarchical(n("/home/bob"))
            .with_schema_blobs(vec![
                SchemaBlob::lvs(compile_lvs_to_binary(&lvs).unwrap()),
                SchemaBlob::native_text(native),
            ])
            .unwrap()
            .schema_authoritative();
        let ca_key = n("/home/bob/CA/KEY/ca");
        let ca_cert = n("/home/bob/CA/KEY/ca"); // key-named, as the old CA's certificate is
        let member = n("/home/bob/member/phone/KEY/k1");
        let renewed = n("/home/bob/member/phone/KEY/k1/NDNCERT/v=5");
        // The CA's cert-v2 certificate of a device, by the CA's key.
        assert!(old.authorizes_hop(&renewed, &ca_key, Some(&ca_cert)));
        // Device data signed under either KeyLocator form.
        let notes = n("/home/bob/member/phone/notes");
        assert!(old.authorizes_hop(&notes, &member, Some(&renewed)));
        assert!(old.authorizes_hop(&notes, &renewed, Some(&renewed)));
        // Still denied: a device certifying itself, or another device's data.
        let self_issued = n("/home/bob/member/phone/KEY/k2/NDNCERT/v=1");
        assert!(!old.authorizes_hop(&self_issued, &member, Some(&renewed)));
        assert!(!old.authorizes_hop(&n("/home/bob/member/laptop/x"), &renewed, Some(&renewed)));
    }

    #[test]
    fn generated_schema_is_lvs_plus_native_and_round_trips() {
        let schema = namespace_schema(&n("/home/bob")).unwrap();
        let model = ndn_security::LvsModel::decode(&schema.lvs_binary).unwrap();
        // The rendered binary names every rule of the source.
        let text = model.to_text();
        for rule in ["#root:", "#context:", "#ca:", "#guest:", "#approve:"] {
            assert!(text.contains(rule), "{rule} missing from:\n{text}");
        }
        assert!(namespace_schema(&n("/")).is_err());

        // Published and re-decoded, the context keeps both blobs and the verdicts.
        let ctx = context();
        let back = SignedTrustContext::decode_content(&ctx.encode_content(), 1).unwrap();
        assert!(!back.enforces_hierarchy());
        assert_eq!(back.published_schemas().len(), 2);
        let admin = n("/home/bob/admin/laptop/KEY/k1");
        assert!(back.authorizes(&n("/home/bob/shared/x"), &admin));
        assert!(!back.authorizes(&n("/home/bob/shared/x"), &n("/home/bob/guest/a/KEY/k")));
    }
}
