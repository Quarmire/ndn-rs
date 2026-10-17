//! Enrolling a device key with an `ndn-trust://invite` link: the one step
//! that takes a device from "holds nothing" to "holds a certificate for
//! `/<ns>/<role>/<device>` issued by the namespace's CA".
//!
//! An invite (`ndn-fwd-tokens new --role member|guest`) carries the CA prefix,
//! the identity namespace `/<ns>/<role>`, a one-time token scoped by the CA to
//! that role, and — when minted with `--anchor-fp` — the fingerprint of the
//! namespace's root anchor. [`enroll_with_invite`]:
//!
//! 1. reads the invite ([`InviteLink`]): only `member` and `guest` are ever
//!    admitted by a token, and a role-carrying token must name the invite's
//!    role;
//! 2. makes sure the trust context for `/<ns>` is held: an already held
//!    context must be signed by the root the invite expects; otherwise it is
//!    adopted from the namespace + expected fingerprint exactly as a
//!    fingerprint-only anchor link would be ([`adopt_anchor_link`]). An invite
//!    names no context version, so no version floor applies to that first
//!    adoption (the keyring's anti-rollback still does);
//! 3. runs NDNCERT 0.3 ([`crate::client::enroll`]) for the caller's device key
//!    with the `token` challenge, fetches the issued certificate, and checks
//!    it: it certifies that key, is valid now, and chains to the root of the
//!    namespace's trust context under its schema (the issuer certificates
//!    are fetched for the walk; each hop's signature is verified). The
//!    request names no lifetime: the CA's policy (`[ca] cert_validity_days`
//!    on a namespace CA) decides it.
//!
//! A token minted with an expiry (`ndn-fwd-tokens new --ttl`) carries it
//! ([`crate::roles::token_expiry`]); an expired invite is refused before
//! anything is sent, and the CA refuses the token after it too.
//!
//! The device key is the caller's: it is generated and kept wherever the
//! caller keeps keys (the `ndn-fwd` daemon's PIB, a phone's key store); only
//! its public half and signatures cross the wire. Storing the certificate and
//! selecting the identity are the caller's too. The CA may later answer
//! "pending" (admin approval); that path is not taken by a token and is
//! reported as [`InviteEnrollError::ChallengeIncomplete`].

use std::sync::Arc;

use ndn_packet::encode::InterestBuilder;
use ndn_packet::{Data, Name};
use ndn_security::{
    CertCache, Certificate, Keyring, SignedTrustContext, Signer, ValidationResult, Validator,
    VerifyOutcome, verifier::verify_by_sig_type,
};
use ndn_trust_envelope::TrustEnvelope;

use crate::client::CaExchange;
use crate::error::CertError;
use crate::onboarding::{AdoptError, AnchorLink, LinkAdoption, adopt_anchor_link, anchor_fingerprint};
use crate::roles::{
    Role, RoleError, token_expiry, token_role, validate_device_name, validate_namespace,
};

/// What an `ndn-trust://invite` link asks a device to do: enroll a key under
/// [`identity_prefix`](Self::identity_prefix) with the CA at
/// [`ca_prefix`](Self::ca_prefix), redeeming [`token`](Self::token).
#[derive(Clone, Debug)]
pub struct InviteLink {
    /// The CA's prefix: its NDNCERT names are `<ca_prefix>/CA/…`.
    pub ca_prefix: Name,
    /// The namespace `/<ns>` whose trust context and CA certify the device.
    pub namespace: Name,
    /// `member` or `guest`.
    pub role: Role,
    /// `/<ns>/<role>`: the device's identity is `<identity_prefix>/<device>`.
    pub identity_prefix: Name,
    /// The one-time token the CA's `token` challenge redeems.
    pub token: String,
    /// SHA-256 of the namespace's root anchor public key, when the invite
    /// carries it (`ndn-fwd-tokens new --anchor-fp`).
    pub expected_fingerprint: Option<[u8; 32]>,
    /// When the token stops being redeemable (Unix seconds), if it expires.
    pub expires_at_secs: Option<u64>,
}

impl InviteLink {
    /// Parse an `ndn-trust://invite/…` URI (or its https mirror).
    pub fn from_uri(uri: &str) -> Result<Self, InviteEnrollError> {
        let envelope = TrustEnvelope::from_uri(uri.trim())
            .map_err(|e| InviteEnrollError::BadInvite(e.to_string()))?;
        Self::from_envelope(&envelope)
    }

    /// Read an invite envelope. Refuses anything a token can never certify:
    /// an identity namespace that is not `/<ns>/member` or `/<ns>/guest`, and
    /// a token whose role differs from it (a token without a role prefix is
    /// scoped by a namespace CA to members).
    pub fn from_envelope(envelope: &TrustEnvelope) -> Result<Self, InviteEnrollError> {
        let TrustEnvelope::Invite {
            ca_prefix,
            identity_namespace,
            token,
            anchor_fingerprint,
            ..
        } = envelope
        else {
            return Err(InviteEnrollError::NotInvite(envelope.kind().as_str()));
        };
        let bad = |field: &'static str, value: &str| InviteEnrollError::InviteField {
            field,
            value: value.to_string(),
        };
        let ca: Name = ca_prefix.parse().map_err(|_| bad("CA prefix", ca_prefix))?;
        if ca.is_empty() {
            return Err(bad("CA prefix", ca_prefix));
        }
        let identity_prefix: Name = identity_namespace
            .parse()
            .map_err(|_| bad("identity namespace", identity_namespace))?;
        let comps = identity_prefix.components();
        let role = comps.last().and_then(Role::from_component);
        let (namespace, role) = match (role, comps.len()) {
            (Some(role @ (Role::Member | Role::Guest)), n) if n >= 2 => {
                (Name::from_components(comps[..n - 1].iter().cloned()), role)
            }
            _ => return Err(InviteEnrollError::InviteRole(identity_namespace.clone())),
        };
        validate_namespace(&namespace).map_err(|_| bad("identity namespace", identity_namespace))?;
        if token.is_empty() {
            return Err(bad("token", token));
        }
        let token_admits = token_role(token).unwrap_or(Role::Member);
        let expires_at_secs = token_expiry(token);
        if let Some(at) = expires_at_secs {
            let now = web_time::SystemTime::now()
                .duration_since(web_time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if now >= at {
                return Err(InviteEnrollError::TokenExpired {
                    expired_at: iso_secs(at),
                });
            }
        }
        if token_admits != role {
            return Err(InviteEnrollError::TokenRole {
                token_role: token_admits,
                invite_role: role,
                identity_prefix: identity_prefix.to_string(),
            });
        }
        Ok(Self {
            ca_prefix: ca,
            namespace,
            role,
            identity_prefix,
            token: token.clone(),
            expected_fingerprint: *anchor_fingerprint,
            expires_at_secs,
        })
    }

    /// The identity `<identity_prefix>/<device>` after checking `device` is a
    /// valid device name.
    pub fn device_identity(&self, device: &str) -> Result<Name, InviteEnrollError> {
        validate_device_name(device).map_err(InviteEnrollError::Device)?;
        Ok(self.identity_prefix.clone().append(device))
    }

    /// The device named by `key_name` if it is a key of
    /// `<identity_prefix>/<device>` (`…/<device>/KEY/<id>`).
    fn device_of_key(&self, key_name: &Name) -> Result<(), InviteEnrollError> {
        let comps = key_name.components();
        let base = self.identity_prefix.len();
        let ok = key_name.has_prefix(&self.identity_prefix)
            && comps.len() == base + 3
            && comps[base + 1].value.as_ref() == b"KEY"
            && std::str::from_utf8(&comps[base].value)
                .is_ok_and(|d| validate_device_name(d).is_ok());
        if ok {
            Ok(())
        } else {
            Err(InviteEnrollError::KeyOutsideInvite {
                key: key_name.to_string(),
                identity_prefix: self.identity_prefix.to_string(),
            })
        }
    }
}

/// A fresh key name for `identity`: `<identity>/KEY/<16 hex digits>`, the key
/// id random so a re-enrollment never collides with an earlier key
/// ([`ndn_security::cert_name::new_key_name`]).
pub fn new_device_key_name(identity: &Name) -> Name {
    ndn_security::cert_name::new_key_name(identity)
}

/// Why enrollment with an invite did not produce a certificate. Every message
/// says what is wrong and what to do instead.
#[derive(Debug, thiserror::Error)]
pub enum InviteEnrollError {
    #[error("not a readable invite link: {0}")]
    BadInvite(String),
    #[error("expected an invite link (ndn-trust://invite/…), got a {0} link")]
    NotInvite(&'static str),
    #[error("the invite carries an invalid {field} {value:?}; ask for a new invite")]
    InviteField { field: &'static str, value: String },
    #[error(
        "the invite names {0} as the identity namespace, but an invite token only certifies \
         /<namespace>/member or /<namespace>/guest devices; admin and node certificates need an \
         admin's approval"
    )]
    InviteRole(String),
    #[error(
        "the invite's token admits only {token_role} certificates, but the invite asks for a \
         {invite_role} certificate under {identity_prefix}: the invite was altered or minted \
         wrongly; ask for a new one (`ndn-fwd-tokens new --role {invite_role}`)"
    )]
    TokenRole {
        token_role: Role,
        invite_role: Role,
        identity_prefix: String,
    },
    #[error("{0}; choose another device name (--device)")]
    Device(RoleError),
    #[error("key {key} is not a device key under {identity_prefix} (<device>/KEY/<id>)")]
    KeyOutsideInvite { key: String, identity_prefix: String },
    #[error(
        "this node holds no trust context for {namespace}, and the invite carries no root \
         fingerprint to check one against: ask for an invite minted with --anchor-fp, or adopt \
         the context first (`ndn-fwd adopt <anchor link>`)"
    )]
    NoExpectedFingerprint { namespace: String },
    #[error(
        "the trust context this node holds for {namespace} is signed by a different root \
         (fingerprint {held}) than the invite expects ({expected}): check where the invite \
         came from; this node keeps the context it holds"
    )]
    DifferentRoot {
        namespace: String,
        held: String,
        expected: String,
    },
    #[error(
        "could not fetch the trust context for {namespace} ({detail}): this device needs a face \
         and a route for {namespace} toward a forwarder that serves it (`ndn-ctl face create \
         udp4://<host>:6363`, then `ndn-ctl route add {namespace} <face-id>`), then enroll again"
    )]
    ContextUnreachable { namespace: String, detail: String },
    #[error(
        "the trust context served for {namespace} was refused ({reason}): it is not signed by \
         the root the invite expects. This node's route for {namespace} leads to a forwarder \
         serving another root; check the route (`ndn-ctl route list`) and the invite"
    )]
    ContextFromDifferentRoot { namespace: String, reason: String },
    #[error("trust context for {namespace} not adopted: {source}")]
    Adopt {
        namespace: String,
        #[source]
        source: AdoptError,
    },
    #[error(
        "could not reach the CA {ca_prefix}/CA ({detail}): this device needs a face and a route \
         for {namespace} toward a forwarder that serves it (`ndn-ctl face create \
         udp4://<host>:6363`, then `ndn-ctl route add {namespace} <face-id>`), then enroll \
         again. A CA that refuses a request outright also leaves it unanswered"
    )]
    CaUnreachable {
        ca_prefix: String,
        namespace: String,
        detail: String,
    },
    #[error(
        "the CA refused the invite token: {0}. A token is redeemed once, only for its role, \
         and only before it expires; ask for a new invite"
    )]
    TokenRefused(String),
    #[error("the invite expired at {expired_at}; ask for a new invite")]
    TokenExpired { expired_at: String },
    #[error("the CA refused the request: {0}")]
    CaRefused(String),
    #[error(
        "the CA refused this device name: {0}. Enroll under another device name (--device), \
         revoke that certificate first, or have an admin approve this device"
    )]
    NameRefused(String),
    #[error("the CA did not complete the token challenge: {0}")]
    ChallengeIncomplete(String),
    #[error("signing the request with the device key failed: {0}")]
    Signing(String),
    #[error(
        "the certificate the CA issued was refused ({0}); nothing was kept. The token is spent: \
         ask for a new invite"
    )]
    IssuedCertificate(String),
}

impl InviteEnrollError {
    /// Classify a CA exchange failure.
    fn from_cert(e: CertError, invite: &InviteLink) -> Self {
        match e {
            CertError::Transport(detail) => Self::CaUnreachable {
                ca_prefix: invite.ca_prefix.to_string(),
                namespace: invite.namespace.to_string(),
                detail,
            },
            CertError::ChallengeFailed(reason) => Self::TokenRefused(reason),
            CertError::PolicyDenied(reason) => Self::NameRefused(reason),
            CertError::ChallengePending(status) => Self::ChallengeIncomplete(status),
            CertError::Security(e) => Self::Signing(e.to_string()),
            other => Self::CaRefused(other.to_string()),
        }
    }

    /// Restate an adoption failure in terms of the invite.
    fn from_adopt(e: AdoptError, namespace: &Name) -> Self {
        let namespace = namespace.to_string();
        match e {
            AdoptError::Fetch { source, .. } => Self::ContextUnreachable {
                namespace,
                detail: source.to_string(),
            },
            AdoptError::WrongContext { reason, .. } => {
                Self::ContextFromDifferentRoot { namespace, reason }
            }
            e @ (AdoptError::FingerprintMismatch(_) | AdoptError::NoExpectedAnchor) => {
                Self::ContextFromDifferentRoot {
                    namespace,
                    reason: e.to_string(),
                }
            }
            source => Self::Adopt { namespace, source },
        }
    }
}

/// An enrollment that did not complete. When the trust context was adopted
/// on the way (`adopted`), it stays adopted in the keyring — it passed the
/// fingerprint check independently of the certificate — so the caller should
/// persist it as it would after `ndn-fwd adopt`.
#[derive(Debug, thiserror::Error)]
#[error("{error}")]
pub struct InviteEnrollFailure {
    pub adopted: Option<LinkAdoption>,
    #[source]
    pub error: InviteEnrollError,
}

impl From<InviteEnrollError> for InviteEnrollFailure {
    fn from(error: InviteEnrollError) -> Self {
        Self {
            adopted: None,
            error,
        }
    }
}

/// A certificate issued for the device key.
#[derive(Debug)]
pub struct IssuedCertificate {
    /// The certificate Data exactly as the CA served it.
    pub data: Data,
    pub cert: Certificate,
    /// The key that signed it (the CA's, `/<ns>/CA/KEY/<k>`).
    pub issuer: Option<Name>,
    /// The issuer certificates of its chain, in walk order, as they were
    /// fetched to check it (an anchor is never fetched, so it is never
    /// here). A node keeps them ([`crate::issuers`]): they prove the
    /// certificate's chain at a renewal, at a later CA of the namespace that
    /// did not issue it, once nobody else serves its CA's certificate.
    pub issuers: Vec<Data>,
}

/// The outcome of [`enroll_with_invite`].
#[derive(Debug)]
pub struct InviteEnrollment {
    /// The trust context adopted on the way, `None` when it was already held.
    pub adopted: Option<LinkAdoption>,
    pub issued: IssuedCertificate,
}

/// Make sure `keyring` holds the trust context the invite's namespace needs.
/// Already held: it must have an anchor with the invite's expected
/// fingerprint (when the invite carries one). Not held: adopt it by
/// namespace + expected fingerprint ([`adopt_anchor_link`], no version
/// floor). Returns the adoption, `None` when nothing was adopted.
pub async fn ensure_invite_context<E>(
    keyring: &Keyring,
    forwarder: Option<&Validator>,
    exchange: &mut E,
    invite: &InviteLink,
) -> Result<Option<LinkAdoption>, InviteEnrollError>
where
    E: CaExchange + ?Sized,
{
    if let Some(held) = held_context(keyring, &invite.namespace) {
        let Some(expected) = invite.expected_fingerprint else {
            return Ok(None);
        };
        let fingerprints: Vec<[u8; 32]> = held
            .anchors()
            .iter()
            .map(|a| anchor_fingerprint(a.value()))
            .collect();
        if fingerprints.contains(&expected) {
            return Ok(None);
        }
        return Err(InviteEnrollError::DifferentRoot {
            namespace: invite.namespace.to_string(),
            held: fingerprints.first().map(|f| hex(f)).unwrap_or_default(),
            expected: hex(&expected),
        });
    }
    let expected_fingerprint =
        invite
            .expected_fingerprint
            .ok_or_else(|| InviteEnrollError::NoExpectedFingerprint {
                namespace: invite.namespace.to_string(),
            })?;
    let link = AnchorLink {
        namespace: invite.namespace.clone(),
        expected_fingerprint,
        min_version: None,
        context_data: None,
    };
    adopt_anchor_link(keyring, forwarder, exchange, &link)
        .await
        .map(Some)
        .map_err(|e| InviteEnrollError::from_adopt(e, &invite.namespace))
}

/// Enroll `device_key` with the CA the invite names (see the module docs):
/// adopt the namespace's trust context into `keyring` if it is not held, run
/// NDNCERT with the invite's token, fetch the issued certificate and check it
/// — including its chain to the namespace's root under the context's schema,
/// fetching the issuer certificates it needs through `exchange`.
/// `forwarder` is the validator of the forwarder `exchange`'s Interests go
/// through, if any: it admits the expected context during adoption. Nothing
/// is stored; `device_key` must be named `<identity_prefix>/<device>/KEY/<id>`
/// ([`new_device_key_name`]). The certificate's lifetime is the CA's to
/// decide: the request names none.
pub async fn enroll_with_invite<E>(
    keyring: &Arc<Keyring>,
    forwarder: Option<&Validator>,
    exchange: &mut E,
    invite: &InviteLink,
    device_key: Arc<dyn Signer>,
) -> Result<InviteEnrollment, InviteEnrollFailure>
where
    E: CaExchange + ?Sized,
{
    invite.device_of_key(device_key.key_name())?;
    let adopted = ensure_invite_context(keyring, forwarder, exchange, invite).await?;
    match issue(exchange, keyring, invite, device_key).await {
        Ok(issued) => Ok(InviteEnrollment { adopted, issued }),
        Err(error) => Err(InviteEnrollFailure { adopted, error }),
    }
}

async fn issue<E>(
    exchange: &mut E,
    keyring: &Arc<Keyring>,
    invite: &InviteLink,
    device_key: Arc<dyn Signer>,
) -> Result<IssuedCertificate, InviteEnrollError>
where
    E: CaExchange + ?Sized,
{
    let mut params = serde_json::Map::new();
    params.insert(
        "token".to_owned(),
        serde_json::Value::String(invite.token.clone()),
    );
    let mut params = Some(params);
    let cert_name = crate::client::enroll(
        exchange,
        &invite.ca_prefix,
        Arc::clone(&device_key),
        // An empty validity window: the CA issues what its policy allows.
        0,
        "token",
        |_| std::future::ready(Ok(params.take())),
    )
    .await
    .map_err(|e| InviteEnrollError::from_cert(e, invite))?;
    let data = crate::client::fetch_issued_cert_via(exchange, &invite.ca_prefix, &cert_name)
        .await
        .map_err(|e| InviteEnrollError::from_cert(e, invite))?;
    let mut issued = check_issued(&data, device_key.as_ref())
        .await
        .map_err(|e| e.into_invite(invite))?;
    issued.issuers = check_chain(&data, keyring, exchange, &invite.namespace)
        .await
        .map_err(|e| e.into_invite(invite))?;
    Ok(issued)
}

/// Why [`check_issued`] or [`check_chain`] did not accept an issued
/// certificate.
pub(crate) enum IssuedCheckError {
    /// The certificate itself is wrong; the reason says how.
    Refused(String),
    /// The device key could not sign the key check.
    Signing(String),
    /// Fetching an issuer certificate failed.
    Exchange(CertError),
}

impl IssuedCheckError {
    fn into_invite(self, invite: &InviteLink) -> InviteEnrollError {
        match self {
            Self::Refused(why) => InviteEnrollError::IssuedCertificate(why),
            Self::Signing(e) => InviteEnrollError::Signing(e),
            Self::Exchange(e) => InviteEnrollError::from_cert(e, invite),
        }
    }
}

/// Issuer certificates [`enroll_with_invite`] fetches at most to walk the
/// issued certificate's chain.
pub(crate) const MAX_ISSUER_FETCHES: usize = 5;

/// Exchanges (Interest → Data) [`enroll_with_invite`] makes at most: the
/// context's metadata and the context, NEW, CHALLENGE, the issued
/// certificate, and the issuer certificates. Times the per-Interest timeout,
/// it bounds how long an enrollment can take.
pub const INVITE_ENROLL_MAX_EXCHANGES: u32 = 5 + MAX_ISSUER_FETCHES as u32;

/// The issued certificate must chain to the root of the namespace's trust
/// context under its schema. Checked by a validator over `keyring` alone (not
/// the forwarder's, whose keyring may differ), fetching each missing issuer
/// certificate through `exchange`; each hop's signature is verified by the
/// chain walk, so a fetched certificate is never trusted by itself. Returns
/// the issuer certificate Data fetched for the walk, in walk order.
pub(crate) async fn check_chain<E>(
    data: &Data,
    keyring: &Arc<Keyring>,
    exchange: &mut E,
    namespace: &Name,
) -> Result<Vec<Data>, IssuedCheckError>
where
    E: CaExchange + ?Sized,
{
    const MAX_FETCHES: usize = MAX_ISSUER_FETCHES - 1;
    let refused = IssuedCheckError::Refused;
    let validator = Validator::with_keyring(
        Arc::clone(keyring),
        Arc::new(CertCache::new()),
        None,
        MAX_FETCHES + 1,
    );
    let mut fetched = Vec::new();
    for _ in 0..=MAX_FETCHES {
        match validator.validate_chain_cached(data).await {
            (ValidationResult::Valid(_), _) => return Ok(fetched),
            (ValidationResult::Invalid(e), _) => {
                return Err(refused(format!(
                    "it does not chain to the root of {namespace} under its schema: {e}"
                )));
            }
            (ValidationResult::Pending, missing) => {
                let Some(missing) = missing else { break };
                // `missing` is a KeyLocator, normally a key name: ask for its
                // newest certificate (`CanBePrefix`), never a stale cached one.
                let interest = InterestBuilder::new((*missing).clone())
                    .can_be_prefix()
                    .must_be_fresh()
                    .build();
                let reply = exchange
                    .express(interest)
                    .await
                    .map_err(IssuedCheckError::Exchange)?;
                let cert = Certificate::decode(&reply).map_err(|e| {
                    refused(format!("its issuer certificate {missing} is malformed: {e}"))
                })?;
                validator.cert_cache().insert(cert);
                fetched.push(reply);
            }
        }
    }
    Err(refused(format!(
        "its chain to the root of {namespace} is longer than {MAX_FETCHES} certificates"
    )))
}

/// The issued certificate must certify `device_key` (its public key verifies
/// a fresh signature by that key) and be valid now.
pub(crate) async fn check_issued(
    data: &Data,
    device_key: &dyn Signer,
) -> Result<IssuedCertificate, IssuedCheckError> {
    let refused = IssuedCheckError::Refused;
    let cert = Certificate::decode(data).map_err(|e| refused(format!("not a certificate: {e}")))?;
    let device_key_name = ndn_security::cert_name::key_name_of(device_key.key_name());
    if !cert.name.has_prefix(&device_key_name) {
        return Err(refused(format!(
            "it names {}, not the device key {}",
            cert.name,
            device_key.key_name()
        )));
    }
    const PROBE: &[u8] = b"ndn-cert invite enrollment key check";
    let probe = device_key
        .sign(PROBE)
        .await
        .map_err(|e| IssuedCheckError::Signing(e.to_string()))?;
    match verify_by_sig_type(device_key.sig_type(), PROBE, &probe, &cert.public_key).await {
        Ok(VerifyOutcome::Valid) => {}
        _ => return Err(refused("it certifies a different public key".into())),
    }
    if !cert.is_valid_now() {
        return Err(refused("it is not valid now".into()));
    }
    let issuer = data
        .sig_info()
        .and_then(|s| s.key_locator_name())
        .map(|n| (*n).clone());
    Ok(IssuedCertificate {
        data: Data::decode(data.raw().clone())
            .map_err(|e| refused(format!("not a Data packet: {e}")))?,
        cert,
        issuer,
        issuers: Vec::new(),
    })
}

fn held_context(keyring: &Keyring, namespace: &Name) -> Option<Arc<SignedTrustContext>> {
    keyring
        .contexts()
        .into_iter()
        .find(|c| c.namespace() == namespace)
}

fn iso_secs(secs: u64) -> String {
    let basic = ndn_security::iso8601::format_iso_basic(secs.saturating_mul(1_000_000_000));
    format!("{}Z", String::from_utf8_lossy(&basic))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
