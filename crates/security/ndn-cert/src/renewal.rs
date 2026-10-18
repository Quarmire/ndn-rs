//! Certificate renewal: a device that holds a current certificate from a CA
//! gets a fresh one for the **same key** before the old one expires, without
//! a new invite.
//!
//! Renewal is an NDNCERT 0.3 exchange (NEW → CHALLENGE) whose challenge is
//! the CA's built-in [`RENEWAL_CHALLENGE`]. The device proves it
//! holds the private key of the certificate it renews by signing
//! [`renewal_proof_message`] — the CA-chosen request id of this very
//! exchange plus the certificate's name — with that key. The proof travels
//! inside the CHALLENGE envelope, which is encrypted under the exchange's
//! ECDH session key, and the request id is fresh for every NEW, so a proof
//! cannot be replayed into another exchange.
//!
//! The CA ([`CaState`](crate::ca::CaState)) re-certifies the key when:
//!
//! - the certificate named is one it issued (it serves it on cert-fetch),
//!   **or** — when the CA accepts earlier CAs' certificates
//!   ([`CaState::accept_earlier_ca_certificates`](crate::ca::CaState::accept_earlier_ca_certificates))
//!   — a current certificate of the namespace issued by an earlier CA of the
//!   same CA identity (`<prefix>/CA/KEY/<other id>`: the CA of a root device
//!   that was replaced through a recovery kit) that chains to an anchor of
//!   the trust context the CA holds, under its schema, through no revoked
//!   key. Nobody may serve the earlier CA's certificate any more, so the
//!   device sends its certificate ([`CERTIFICATE_PARAM`]) and the issuer
//!   certificates of its chain ([`ISSUERS_PARAM`]); once the proof holds,
//!   the CA serves the earlier CA's certificates of that chain itself;
//! - the certificate is for the key the request certifies, with the same
//!   public key — renewal never certifies a new key; a new key is a new
//!   enrollment;
//! - the certificate is valid now: an **expired** device needs a new invite;
//! - no certificate it issued for that key is **revoked** (nor, for an
//!   earlier CA's certificate, does the trust context revoke it);
//! - the proof verifies under the certificate's key;
//! - its [`IssuancePolicy`](crate::IssuancePolicy) issues on a renewal (for
//!   [`RolePolicy`](crate::RolePolicy): the role is renewable — guests are
//!   not by default) and sets the new lifetime.
//!
//! The CA names every certificate `<key>/NDNCERT/<version>` (NDN Certificate
//! Format v2), so the renewed certificate has a name of its own: the device
//! fetches it by the name the CHALLENGE response reports, and no cache can
//! answer that fetch with the certificate it replaces. Old and new
//! certificate coexist until the old one expires.
//!
//! [`renew_certificate`] is the device side. Renewal goes to the namespace's
//! CA — the `<prefix>/CA` the certificate's KeyLocator names
//! ([`issuing_ca_prefix`]); after a recovery that is a later CA key of the
//! same CA identity, not the CA key that issued the certificate. It walks the
//! current certificate's chain to send it with the proof, answering the
//! walk's certificate Interests from the issuer certificates the device kept
//! ([`IssuedCertificate::issuers`], [`crate::issuers`]) before the network,
//! runs the exchange and checks that the new certificate certifies the
//! device key, is valid now, and chains to the root of the namespace's trust
//! context.

use std::sync::Arc;

use base64::Engine;
use bytes::Bytes;
use ndn_packet::{Data, Interest, Name};
use ndn_security::{Certificate, Keyring, Signer};

use crate::client::CaExchange;
use crate::error::CertError;
use crate::invite::{IssuedCertificate, IssuedCheckError, check_chain, check_issued};

/// The challenge type of a renewal. Built into the CA (it needs the CA's
/// record of issued and revoked certificates), offered when its issuance
/// policy [renews](crate::IssuancePolicy::offers_renewal).
pub const RENEWAL_CHALLENGE: &str = "renewal";

/// CHALLENGE parameter: the URI of the certificate being renewed.
pub const CERT_NAME_PARAM: &str = "cert_name";
/// CHALLENGE parameter: base64url (no padding) signature, by the
/// certificate's key, over [`renewal_proof_message`].
pub const PROOF_PARAM: &str = "signature";
/// CHALLENGE parameter: base64url (no padding) wire of the certificate being
/// renewed, for a CA that did not issue it.
pub const CERTIFICATE_PARAM: &str = "certificate";
/// CHALLENGE parameter: JSON array of the base64url (no padding) wires of
/// the issuer certificates of the renewed certificate's chain, in walk
/// order, for a CA that did not issue it.
pub const ISSUERS_PARAM: &str = "issuers";

/// Exchanges (Interest → Data) [`renew_certificate`] makes at most: the
/// issuer certificates of the current certificate's chain, NEW, CHALLENGE,
/// the renewed certificate, and the issuer certificates of its chain. Times
/// the per-Interest timeout, it bounds how long a renewal can take.
pub const RENEWAL_MAX_EXCHANGES: u32 = 3 + 2 * crate::invite::MAX_ISSUER_FETCHES as u32;

/// What the device signs to prove it holds the key of `cert_name` in the
/// exchange with request id `request_id_hex` (the CA's NEW response,
/// lowercase hex).
pub fn renewal_proof_message(request_id_hex: &str, cert_name: &Name) -> Vec<u8> {
    format!("ndncert-renewal\n{request_id_hex}\n{cert_name}").into_bytes()
}

/// The prefix of the namespace's CA that `cert` names (its NDNCERT names are
/// `<prefix>/CA/…`): the certificate's KeyLocator `/<prefix>/CA/KEY/<id>…`
/// minus `/CA/KEY/…`. Renewal goes there: after a recovery the CA at that
/// prefix signs with a later key of the same CA identity than the one that
/// issued `cert`. `None` when the issuer is not named that way.
pub fn issuing_ca_prefix(cert: &Certificate) -> Option<Name> {
    let issuer = cert.issuer.as_deref()?;
    let comps = issuer.components();
    let key = comps
        .iter()
        .position(|c| c.typ == ndn_packet::tlv_type::NAME_COMPONENT && c.value.as_ref() == b"KEY")?;
    let ca = comps.get(key.checked_sub(1)?)?;
    (ca.typ == ndn_packet::tlv_type::NAME_COMPONENT && ca.value.as_ref() == b"CA" && key >= 2)
        .then(|| Name::from_components(comps[..key - 1].iter().cloned()))
}

/// Why a renewal produced no certificate. The current certificate is left as
/// it was in every case.
#[derive(Debug, thiserror::Error)]
pub enum RenewalError {
    #[error("the current certificate cannot be read: {0}")]
    BadCertificate(String),
    #[error("certificate {cert} does not certify the key {key}")]
    OtherKey { cert: String, key: String },
    #[error(
        "certificate {cert} does not name its namespace's CA (its issuer is {issuer}, not \
         /<prefix>/CA/KEY/<id>); renewal goes to the namespace's CA, /<prefix>/CA"
    )]
    NoIssuingCa { cert: String, issuer: String },
    #[error(
        "certificate {cert} expired at {expired_at}; renewal needs a current certificate, so \
         this device needs a new invite to enroll again"
    )]
    Expired { cert: String, expired_at: String },
    #[error(
        "could not reach the CA {ca_prefix}/CA ({detail}): this device needs a face and a route \
         for {ca_prefix} toward a forwarder that serves it"
    )]
    CaUnreachable { ca_prefix: String, detail: String },
    #[error("the CA refused to renew {cert}: {reason}")]
    Refused { cert: String, reason: String },
    #[error("signing the renewal with the device key failed: {0}")]
    Signing(String),
    #[error(
        "the certificate the CA issued on renewal was refused ({0}); the current certificate \
         stays in use"
    )]
    IssuedCertificate(String),
}

impl RenewalError {
    /// Whether trying again cannot help until something changes (the CA's
    /// answer, an expired or unusable certificate) — as opposed to a network
    /// or local failure worth retrying soon.
    pub fn is_final(&self) -> bool {
        !matches!(self, Self::CaUnreachable { .. } | Self::Signing(_))
    }

    fn from_check(e: IssuedCheckError, ca_prefix: &Name, cert: &Name) -> Self {
        match e {
            IssuedCheckError::Refused(why) => Self::IssuedCertificate(why),
            IssuedCheckError::Signing(e) => Self::Signing(e),
            IssuedCheckError::Exchange(e) => Self::from_cert(e, ca_prefix, cert),
        }
    }

    fn from_cert(e: CertError, ca_prefix: &Name, cert: &Name) -> Self {
        match e {
            CertError::Transport(detail) => Self::CaUnreachable {
                ca_prefix: ca_prefix.to_string(),
                detail,
            },
            CertError::Security(e) => Self::Signing(e.to_string()),
            CertError::ChallengeFailed(reason)
            | CertError::PolicyDenied(reason)
            | CertError::ChallengePending(reason)
            | CertError::InvalidRequest(reason) => Self::Refused {
                cert: cert.to_string(),
                reason,
            },
            // The CA's answer could not be verified yet (its signer's
            // certificate was not to be had): as if it had not arrived.
            CertError::Refused { name, reason } if !reason.is_final() => Self::CaUnreachable {
                ca_prefix: ca_prefix.to_string(),
                detail: format!(
                    "this node's forwarder refused the Data answering {name} for now \
                     ({reason}: {})",
                    reason.next_step()
                ),
            },
            other => Self::Refused {
                cert: cert.to_string(),
                reason: other.to_string(),
            },
        }
    }
}

fn iso(ns: u64) -> String {
    let basic = ndn_security::iso8601::format_iso_basic(ns);
    format!("{}Z", String::from_utf8_lossy(&basic))
}

/// Renew `current` — a certificate Data for `device_key`, issued by a CA of
/// its namespace — at the namespace's CA ([`issuing_ca_prefix`]), through
/// `exchange`. After a recovery that CA signs with a later key of the same CA
/// identity, which accepts `current` with its chain. The renewal carries
/// `current` and the issuer certificates of its chain, as walked to the root
/// of a trust context in `keyring` (when the walk fails, it carries none: the
/// CA key that issued `current` needs none). The walk takes each issuer
/// certificate from `issuers` — the ones the device kept from its enrollment
/// or an earlier renewal ([`IssuedCertificate::issuers`]) — before fetching it
/// through `exchange`; a kept certificate is never trusted by itself, the
/// walk verifies every hop. Returns the new certificate for the same key,
/// checked: it certifies `device_key`, is valid now and chains to the root of
/// a trust context in `keyring` (issuer certificates are fetched for the
/// walk, from the network only, and returned in
/// [`IssuedCertificate::issuers`] for the caller to keep). Nothing is stored;
/// keeping the new certificate is the caller's. An expired `current` is
/// refused before anything is sent.
pub async fn renew_certificate<E>(
    keyring: &Arc<Keyring>,
    exchange: &mut E,
    current: &Data,
    issuers: &[Data],
    device_key: Arc<dyn Signer>,
) -> Result<IssuedCertificate, RenewalError>
where
    E: CaExchange + ?Sized,
{
    let cert =
        Certificate::decode(current).map_err(|e| RenewalError::BadCertificate(e.to_string()))?;
    let cert_name = (*cert.name).clone();
    if !cert_name.has_prefix(&ndn_security::cert_name::key_name_of(device_key.key_name())) {
        return Err(RenewalError::OtherKey {
            cert: cert_name.to_string(),
            key: device_key.key_name().to_string(),
        });
    }
    let ca_prefix = issuing_ca_prefix(&cert).ok_or_else(|| RenewalError::NoIssuingCa {
        cert: cert_name.to_string(),
        issuer: cert
            .issuer
            .as_deref()
            .map(Name::to_string)
            .unwrap_or_else(|| "unnamed".into()),
    })?;
    if !cert.is_valid_now() {
        return Err(RenewalError::Expired {
            cert: cert_name.to_string(),
            expired_at: iso(cert.valid_until),
        });
    }

    // The current certificate's chain travels with the proof: a later CA of
    // the namespace that did not issue it (its root device was replaced)
    // verifies the chain with these issuer certificates, which nobody but
    // this device may serve any more — so the walk takes them from the ones
    // it kept first. A failed walk does not stop the renewal: the CA key that
    // issued the certificate needs none of them.
    let b64 = &base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let certificate = b64.encode(current.raw());
    let mut walk = KeptIssuersFirst::new(issuers, exchange);
    let issuers: Vec<serde_json::Value> = check_chain(current, keyring, &mut walk, &ca_prefix)
        .await
        .unwrap_or_default()
        .iter()
        .map(|issuer| b64.encode(issuer.raw()).into())
        .collect();

    let signer = Arc::clone(&device_key);
    let proven = cert_name.clone();
    let session = crate::client::run_session(
        exchange,
        &ca_prefix,
        Arc::clone(&device_key),
        // An empty validity window: the CA's policy decides the lifetime.
        0,
        RENEWAL_CHALLENGE,
        move |round| {
            let signer = Arc::clone(&signer);
            let proven = proven.clone();
            let certificate = certificate.clone();
            let issuers = issuers.clone();
            async move {
                if round.round > 0 {
                    // The CA decides in one round; it never asks again.
                    return Ok(None);
                }
                let proof = signer
                    .sign(&renewal_proof_message(&round.request_id, &proven))
                    .await
                    .map_err(CertError::Security)?;
                let mut params = serde_json::Map::new();
                params.insert(CERT_NAME_PARAM.into(), proven.to_string().into());
                params.insert(
                    PROOF_PARAM.into(),
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(&proof)
                        .into(),
                );
                params.insert(CERTIFICATE_PARAM.into(), certificate.into());
                params.insert(ISSUERS_PARAM.into(), serde_json::Value::Array(issuers));
                Ok(Some(params))
            }
        },
    )
    .await
    .map_err(|e| RenewalError::from_cert(e, &ca_prefix, &cert_name))?;
    let issued_name = session.issued_cert_name().cloned().ok_or_else(|| {
        RenewalError::IssuedCertificate("the CA reported no issued certificate".into())
    })?;
    // A CA of an earlier release names a renewed certificate like the one it
    // replaces; fetched by that name, a cache could answer with the old
    // certificate, so such a renewal is not taken.
    if issued_name == cert_name {
        return Err(RenewalError::IssuedCertificate(format!(
            "the CA reissued {cert_name} under the same name (a CA of an earlier release that \
             names certificates after their key); upgrade the CA to renew"
        )));
    }
    let data = crate::client::fetch_issued_cert_via(exchange, &ca_prefix, &issued_name)
        .await
        .map_err(|e| RenewalError::from_cert(e, &ca_prefix, &cert_name))?;
    if *data.name != issued_name {
        return Err(RenewalError::IssuedCertificate(format!(
            "fetching {issued_name} returned {}",
            data.name
        )));
    }
    let mut issued = check_issued(&data, device_key.as_ref())
        .await
        .map_err(|e| RenewalError::from_check(e, &ca_prefix, &cert_name))?;
    issued.issuers = check_chain(&data, keyring, exchange, &ca_prefix)
        .await
        .map_err(|e| RenewalError::from_check(e, &ca_prefix, &cert_name))?;
    Ok(issued)
}

/// The exchange of the walk of the current certificate's chain: a
/// certificate Interest is answered from the issuer certificates the device
/// kept — by exact name, or with CanBePrefix the newest valid one under it
/// (else the newest) — and anything they do not answer goes through the
/// network. A kept certificate is only an answer: the chain walk verifies
/// every hop, exactly as for a fetched one.
struct KeptIssuersFirst<'a, E: ?Sized> {
    kept: Vec<(Certificate, &'a Data)>,
    network: &'a mut E,
}

impl<'a, E: ?Sized> KeptIssuersFirst<'a, E> {
    /// Kept Data that is not a certificate is skipped.
    fn new(kept: &'a [Data], network: &'a mut E) -> Self {
        let kept = kept
            .iter()
            .filter_map(|data| Certificate::decode(data).ok().map(|cert| (cert, data)))
            .collect();
        Self { kept, network }
    }

    fn answer(&self, interest: &Bytes) -> Option<Data> {
        let interest = Interest::decode(interest.clone()).ok()?;
        let can_be_prefix = interest.selectors().can_be_prefix;
        self.kept
            .iter()
            .filter(|(cert, _)| {
                if can_be_prefix {
                    cert.name.has_prefix(&interest.name)
                } else {
                    *cert.name == *interest.name
                }
            })
            .max_by_key(|(cert, _)| (cert.is_valid_now(), cert.valid_from))
            .and_then(|(_, data)| Data::decode(data.raw().clone()).ok())
    }
}

impl<E: CaExchange + ?Sized> CaExchange for KeptIssuersFirst<'_, E> {
    fn express(&mut self, interest: Bytes) -> impl Future<Output = Result<Data, CertError>> + Send {
        use futures::future::{Either, ready};
        match self.answer(&interest) {
            Some(kept) => Either::Left(ready(Ok(kept))),
            None => Either::Right(self.network.express(interest)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert_issued_by(issuer: &str) -> Certificate {
        Certificate {
            name: Arc::new("/home/bob/member/phone/KEY/k/i/v".parse().unwrap()),
            public_key: bytes::Bytes::new(),
            valid_from: 0,
            valid_until: 0,
            issuer: Some(Arc::new(issuer.parse().unwrap())),
            signed_region: None,
            sig_value: None,
            sig_type: ndn_packet::SignatureType::SignatureEd25519,
        }
    }

    #[test]
    fn issuing_ca_is_the_issuer_minus_ca_key() {
        let prefix = |issuer| issuing_ca_prefix(&cert_issued_by(issuer));
        assert_eq!(prefix("/home/bob/CA/KEY/k1"), Some("/home/bob".parse().unwrap()));
        assert_eq!(
            prefix("/home/bob/CA/KEY/k1/root/v=1"),
            Some("/home/bob".parse().unwrap())
        );
        // Signed by the root key itself, not by a CA.
        assert_eq!(prefix("/home/bob/KEY/k1"), None);
        assert_eq!(prefix("/CA/KEY/k1"), None);
    }

    #[test]
    fn the_proof_binds_the_exchange_and_the_certificate() {
        let a: Name = "/home/bob/member/phone/KEY/k/i/v1".parse().unwrap();
        let b: Name = "/home/bob/member/phone/KEY/k/i/v2".parse().unwrap();
        assert_ne!(renewal_proof_message("00", &a), renewal_proof_message("01", &a));
        assert_ne!(renewal_proof_message("00", &a), renewal_proof_message("00", &b));
    }

    /// A CA answer this node's forwarder refused for now (`unverifiable`)
    /// leaves the renewal to be tried again soon; a final refusal does not.
    #[test]
    fn a_refusal_for_now_does_not_end_the_renewal() {
        let (ca, cert): (Name, Name) =
            ("/home/bob".parse().unwrap(), "/home/bob/c".parse().unwrap());
        let refused = |reason| CertError::Refused {
            name: "/home/bob/CA/RENEW".to_string(),
            reason,
        };
        let for_now =
            RenewalError::from_cert(refused(ndn_packet::Refusal::Unverifiable), &ca, &cert);
        assert!(!for_now.is_final(), "{for_now}");
        let revoked = RenewalError::from_cert(refused(ndn_packet::Refusal::Revoked), &ca, &cert);
        assert!(revoked.is_final(), "{revoked}");
    }
}
