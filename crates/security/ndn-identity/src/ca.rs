//! [`NdncertCa`] wraps [`CaState`] with an
//! `ndn-app::Producer` registered under `/<prefix>/CA/*`, plus — with
//! [`NdncertCa::approvals`] — enrollment by an admin's approval
//! (`/<prefix>/CA/APPROVAL`, `/<prefix>/CA/PENDING`; [`ndn_cert::approval`]).

use std::sync::Arc;
use std::time::Duration;

use ndn_cert::{
    AcceptAllIssuance, ApprovalService, ApprovalStore, CaConfig, CaState, CaStore,
    ChallengeHandler, HierarchicalPolicy, IssuancePolicy, NamespacePolicy,
};
use ndn_packet::encode::DataBuilder;
use ndn_packet::{NackReason, Name, NameComponent, SignatureType};
use ndn_security::{Keyring, SecurityManager, Signer};
use tracing::{debug, warn};

use crate::{error::IdentityError, facade::Identity};

pub struct NdncertCaBuilder {
    prefix: Option<Name>,
    info: String,
    identity: Option<Arc<SecurityManager>>,
    signing_key: Option<Name>,
    store: Option<Arc<dyn CaStore>>,
    challenges: Vec<Box<dyn ChallengeHandler>>,
    policy: Box<dyn NamespacePolicy>,
    issuance: Option<Box<dyn IssuancePolicy>>,
    emit_attestations: bool,
    default_validity: Duration,
    max_validity: Duration,
}

impl NdncertCaBuilder {
    fn new() -> Self {
        Self {
            prefix: None,
            info: "NDN Certificate Authority".to_string(),
            identity: None,
            signing_key: None,
            store: None,
            challenges: Vec::new(),
            policy: Box::new(HierarchicalPolicy),
            issuance: None,
            emit_attestations: false,
            default_validity: Duration::from_secs(86400),
            max_validity: Duration::from_secs(365 * 86400),
        }
    }

    pub fn name(mut self, prefix: impl AsRef<str>) -> Result<Self, IdentityError> {
        let name: Name = prefix
            .as_ref()
            .parse()
            .map_err(|_| IdentityError::Name(prefix.as_ref().to_string()))?;
        self.prefix = Some(name);
        Ok(self)
    }

    pub fn info(mut self, info: impl Into<String>) -> Self {
        self.info = info.into();
        self
    }

    /// Sign issued certs and CA responses with `identity`'s active key (its
    /// certificate must be in the identity's cert cache or trust anchors).
    pub fn signing_identity(mut self, identity: &Identity) -> Self {
        self.identity = Some(identity.manager_arc());
        self.signing_key = Some(identity.key_name().clone());
        self
    }

    /// Persist issued certs and revocations in `store` and reload them at
    /// [`build`](Self::build) (see [`CaState::with_store`]). Without one the
    /// CA forgets both on restart.
    pub fn store(mut self, store: Arc<dyn CaStore>) -> Self {
        self.store = Some(store);
        self
    }

    pub fn challenge(mut self, handler: impl ChallengeHandler + 'static) -> Self {
        self.challenges.push(Box::new(handler));
        self
    }

    /// Boxed variant of [`challenge`](Self::challenge) for runtime dispatch.
    pub fn challenge_box(mut self, handler: Box<dyn ChallengeHandler>) -> Self {
        self.challenges.push(handler);
        self
    }

    pub fn policy(mut self, policy: impl NamespacePolicy + 'static) -> Self {
        self.policy = Box::new(policy);
        self
    }

    /// Post-challenge issuance gate (the last stage before signing). Defaults
    /// to [`AcceptAllIssuance`] when unset. Use e.g. `RequireAttestationKind`
    /// to gate high-trust namespaces on a signed device-approval.
    pub fn issuance(mut self, issuance: Box<dyn IssuancePolicy>) -> Self {
        self.issuance = Some(issuance);
        self
    }

    /// Embed a challenge attestation (how the challenge was satisfied) in each
    /// issued cert's `AdditionalDescription`. Default `false`.
    pub fn emit_attestations(mut self, yes: bool) -> Self {
        self.emit_attestations = yes;
        self
    }

    pub fn cert_lifetime(mut self, d: Duration) -> Self {
        self.default_validity = d;
        self
    }

    pub fn max_cert_lifetime(mut self, d: Duration) -> Self {
        self.max_validity = d;
        self
    }

    pub fn build(self) -> Result<NdncertCa, IdentityError> {
        let prefix = self
            .prefix
            .ok_or_else(|| IdentityError::Name("CA prefix not set".to_string()))?;
        let manager = self.identity.ok_or(IdentityError::NotEnrolled)?;

        if self.challenges.is_empty() {
            return Err(IdentityError::Enrollment(
                "at least one challenge handler is required".to_string(),
            ));
        }

        let config = CaConfig {
            prefix: prefix.clone(),
            info: self.info,
            default_validity: self.default_validity,
            max_validity: self.max_validity,
            challenges: self.challenges,
            policy: self.policy,
            issuance: self.issuance.unwrap_or_else(|| Box::new(AcceptAllIssuance)),
            emit_attestations: self.emit_attestations,
            signing_key: self.signing_key,
        };

        let state = match self.store {
            Some(store) => CaState::with_store(config, manager, store)?,
            None => CaState::new(config, manager),
        };
        if state.response_signer().is_none() {
            return Err(IdentityError::Enrollment(format!(
                "CA signing key {} has no signer or certificate in the signing identity",
                state
                    .signing_key_name()
                    .map(|k| k.to_string())
                    .unwrap_or_else(|| "<none>".to_string())
            )));
        }

        Ok(NdncertCa {
            state: Arc::new(state),
            prefix,
            approvals: None,
        })
    }
}

pub struct NdncertCa {
    state: Arc<CaState>,
    prefix: Name,
    approvals: Option<ApprovalService>,
}

impl NdncertCa {
    pub fn builder() -> NdncertCaBuilder {
        NdncertCaBuilder::new()
    }

    pub fn prefix(&self) -> &Name {
        &self.prefix
    }

    /// The CA's state, shared with the running service: its host
    /// administers it directly (e.g. [`CaState::revoke_issued_under`]).
    pub fn state(&self) -> Arc<CaState> {
        Arc::clone(&self.state)
    }

    /// Serve enrollment by an admin's approval: decisions pushed to
    /// `/<prefix>/CA/APPROVAL`, the pending list at `/<prefix>/CA/PENDING`
    /// and each request's held status at `/<prefix>/CA/STATUS/<request id>`
    /// act on `store` — the same store the CA's `device-approval` challenge
    /// reads — and are validated under the trust contexts in `keyring` (the
    /// node's own, holding the namespace's).
    pub fn approvals(mut self, store: ApprovalStore, keyring: Arc<Keyring>) -> Self {
        self.approvals = Some(ApprovalService::new(store, keyring, Arc::clone(&self.state)));
        self
    }

    /// The approval service [`approvals`](Self::approvals) set up (shared
    /// with the running CA): its host calls
    /// [`ApprovalService::release_held`] when it stops, so devices waiting on
    /// a held status ask the restarted CA instead of waiting out their
    /// Interests.
    pub fn approval_service(&self) -> Option<ApprovalService> {
        self.approvals.clone()
    }

    /// Runs until the Producer is dropped or errors. A held status Interest
    /// is answered from its own task, so holding it delays no other.
    pub async fn serve(self, producer: ndn_app::Producer) -> Result<(), IdentityError> {
        let state = self.state.clone();
        let ca_prefix = self.prefix.clone();
        let approvals = self.approvals.clone();

        producer
            .serve(move |interest, responder| {
                let state = state.clone();
                let ca_prefix = ca_prefix.clone();
                let approvals = approvals.clone();
                async move {
                    let interest_name = (*interest.name).clone();
                    let Some(reply) =
                        handle_interest(&state, &ca_prefix, approvals.as_ref(), interest).await
                    else {
                        return;
                    };
                    let wire = match reply {
                        CaReply::Body(body) => {
                            let Some((signer, cert_name)) = state.response_signer() else {
                                warn!("NDNCERT: CA has no response signer; dropping reply");
                                return;
                            };
                            build_signed_response(interest_name, body, signer.as_ref(), &cert_name)
                                .await
                        }
                        // Pre-signed Data wire (issued certs) is forwarded
                        // verbatim; wrapping would discard the signature.
                        CaReply::Wire(wire) => wire,
                        CaReply::NoSuchData => {
                            responder.nack(NackReason::NoRoute).await.ok();
                            return;
                        }
                        CaReply::Held {
                            service,
                            held,
                            hold,
                        } => {
                            tokio::spawn(async move {
                                let body = service.answer_status(&held, hold).await;
                                let Some((signer, cert_name)) = state.response_signer() else {
                                    warn!("NDNCERT: CA has no response signer; dropping a status answer");
                                    return;
                                };
                                let wire = build_signed_response(
                                    interest_name,
                                    body,
                                    signer.as_ref(),
                                    &cert_name,
                                )
                                .await;
                                responder.respond_bytes(wire).await.ok();
                                // The slot is given back once the answer is
                                // out (`release_held` waits for that).
                                drop(held);
                            });
                            return;
                        }
                        CaReply::Busy => {
                            responder.nack(NackReason::Congestion).await.ok();
                            return;
                        }
                    };
                    responder.respond_bytes(wire).await.ok();
                }
            })
            .await?;

        Ok(())
    }
}

enum CaReply {
    /// NDNCERT TLV body to wrap in a fresh CA-signed Data.
    Body(Vec<u8>),
    /// Complete pre-signed Data wire bytes (cert-fetch path).
    Wire(bytes::Bytes),
    /// Nothing under the CA prefix answers this Interest (e.g. a routed
    /// certificate fetch for a key the CA never certified): Nacked with
    /// `NoRoute`, so the requester moves on at once instead of waiting out
    /// the Interest lifetime.
    NoSuchData,
    /// A request's status (`<prefix>/CA/STATUS/<request id>`), held until
    /// the request changes or `hold` ends, then answered CA-signed.
    Held {
        service: ApprovalService,
        held: ndn_cert::HeldStatus,
        hold: Duration,
    },
    /// A status Interest beyond the CA's limits (per request, in all):
    /// Nacked with `Congestion`, so the requester backs off and asks again.
    Busy,
}

/// NDNCERT v0.3 §4.1: every CA→requester Data is signed with the CA's
/// identity key. The signer's `sig_type()` selects the algorithm.
async fn build_signed_response(
    name: Name,
    body: Vec<u8>,
    signer: &dyn Signer,
    key_locator: &Name,
) -> bytes::Bytes {
    let sig_type: SignatureType = signer.sig_type();
    DataBuilder::new(name, &body)
        .sign(sig_type, Some(key_locator), move |region| {
            let region = region.to_vec();
            async move {
                signer.sign(&region).await.unwrap_or_else(|e| {
                    warn!(error = %e, "NDNCERT: response signing failed");
                    bytes::Bytes::new()
                })
            }
        })
        .await
}

async fn handle_interest(
    state: &CaState,
    ca_prefix: &Name,
    approvals: Option<&ApprovalService>,
    interest: ndn_packet::Interest,
) -> Option<CaReply> {
    let name = &*interest.name;

    debug!(%name, "NDNCERT: received Interest");

    // Cert-fetch: ship the pre-signed Data wire verbatim. A CanBePrefix
    // Interest for a key name gets the newest valid certificate of the key.
    if let Some(wire) = state.cert_for_interest(name, interest.selectors().can_be_prefix) {
        debug!(%name, "NDNCERT: serving issued cert");
        return Some(CaReply::Wire(bytes::Bytes::from(wire)));
    }

    // `<ca>/CA/<endpoint>/…`: the endpoint is the one component after `CA`,
    // matched exactly (so `<ca>/CA/APPROVALX` reaches nothing).
    let Some((endpoint, tail)) = ca_endpoint(ca_prefix, name) else {
        debug!(%name, "NDNCERT: not a CA endpoint; Nacking");
        return Some(CaReply::NoSuchData);
    };

    match endpoint {
        // INFO may name a version and segment of the CA profile.
        b"INFO" => return Some(CaReply::Body(state.handle_info())),
        // A failed NEW or CHALLENGE is answered, as in NDNCERT v0.3, with an
        // unencrypted ErrorCode + ErrorInfo, never left to time out.
        b"NEW" => {
            let answer = if only_params_digest(tail) {
                let body = interest.app_parameters().cloned().unwrap_or_default();
                state.handle_new(&body).await
            } else {
                Err(bad_interest_format("NEW"))
            };
            return Some(CaReply::Body(answer_or_failure(answer, "NEW")));
        }
        // `<ca>/CA/CHALLENGE/<request id>`, then the
        // ParametersSha256DigestComponent of a signed Interest.
        b"CHALLENGE" => {
            // The request id is a GenericNameComponent: a lone digest
            // component is not one.
            let request_id = match tail {
                [request_id] => Some(request_id),
                [request_id, digest] if digest.typ == PARAMETERS_SHA256 => Some(request_id),
                _ => None,
            }
            .filter(|id| id.typ == ndn_packet::tlv_type::NAME_COMPONENT);
            let answer = match request_id {
                Some(request_id) => {
                    let request_id_hex: String = request_id
                        .value
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect();
                    let body = interest.app_parameters().cloned().unwrap_or_default();
                    state.handle_challenge(&request_id_hex, &body).await
                }
                None => Err(bad_interest_format("CHALLENGE")),
            };
            return Some(CaReply::Body(answer_or_failure(answer, "CHALLENGE")));
        }
        // NDNCERT 0.3 `<ca-prefix>/CA/REVOKE`: the possession-proof request
        // rides in ApplicationParameters; the outcome is a status, never an
        // error.
        b"REVOKE" if only_params_digest(tail) => {
            let body = interest.app_parameters().cloned().unwrap_or_default();
            return Some(CaReply::Body(state.handle_revoke(&body).await));
        }
        _ => {}
    }

    // Enrollment by approval: an admin device's signed decision, the
    // pending list (answered only to an admin-signed Interest), and a
    // request's held status.
    if let Some(approvals) = approvals {
        let is = |e: &str| endpoint == e.as_bytes() && only_params_digest(tail);
        if is(ndn_cert::approval::APPROVAL_ENDPOINT) {
            let body = interest.app_parameters().cloned().unwrap_or_default();
            return Some(CaReply::Body(approvals.handle_decision(&body).await));
        }
        if is(ndn_cert::approval::PENDING_ENDPOINT) {
            return Some(CaReply::Body(approvals.handle_listing(&interest).await));
        }
        if let Some(request_id) = ndn_cert::approval::status_request_id(ca_prefix, name) {
            let hold = ndn_cert::approval::status_hold(interest.lifetime());
            // A check asked to be answered at once takes no held slot.
            if hold.is_zero() {
                return Some(CaReply::Body(approvals.status_now(&request_id)));
            }
            return Some(match approvals.hold_status(&request_id) {
                Ok(held) => CaReply::Held {
                    service: approvals.clone(),
                    held,
                    hold,
                },
                Err(reason) => {
                    warn!(request = %request_id, %reason, "NDNCERT: status Interest refused (Nack Congestion)");
                    CaReply::Busy
                }
            });
        }
    }

    debug!(%name, "NDNCERT: no CA service or issued certificate answers this Interest; Nacking");
    Some(CaReply::NoSuchData)
}

/// NDN Packet Format §3.4: a signed Interest with ApplicationParameters
/// ends with a `ParametersSha256DigestComponent`.
const PARAMETERS_SHA256: u64 = ndn_packet::tlv_type::PARAMETERS_SHA256;

/// The endpoint `name` addresses — the component after `<ca>/CA` — and the
/// components after it. `None` unless `name` is `<ca>/CA/<endpoint>[/…]`
/// with `CA` and the endpoint GenericNameComponents.
fn ca_endpoint<'a>(ca_prefix: &Name, name: &'a Name) -> Option<(&'a [u8], &'a [NameComponent])> {
    const GENERIC: u64 = ndn_packet::tlv_type::NAME_COMPONENT;
    if !name.has_prefix(ca_prefix) {
        return None;
    }
    let [ca, endpoint, tail @ ..] = name.components().get(ca_prefix.len()..)? else {
        return None;
    };
    (ca.typ == GENERIC && ca.value.as_ref() == b"CA" && endpoint.typ == GENERIC)
        .then_some((endpoint.value.as_ref(), tail))
}

/// Nothing follows the endpoint but, for a signed Interest, its
/// ParametersSha256DigestComponent.
fn only_params_digest(tail: &[NameComponent]) -> bool {
    match tail {
        [] => true,
        [digest] => digest.typ == PARAMETERS_SHA256,
        _ => false,
    }
}

fn bad_interest_format(step: &str) -> ndn_cert::CertError {
    ndn_cert::CertError::CaFailure {
        code: ndn_cert::ErrorCode::BadInterestFormat.into(),
        info: format!("the {step} Interest name is not <ca>/CA/{step} in NDNCERT form"),
    }
}

/// The CA's answer to a NEW or CHALLENGE, or its failure answer.
fn answer_or_failure(answer: Result<Vec<u8>, ndn_cert::CertError>, step: &str) -> Vec<u8> {
    answer.unwrap_or_else(|e| {
        warn!(error = %e, "NDNCERT {step} failed; answering ErrorCode {}", e.ndncert_error_code());
        ndn_cert::tlv::ErrorTlv::from_error(&e).encode().to_vec()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_cert::approval::{ApprovalStore, DEFAULT_REQUEST_TTL};
    use ndn_cert::challenge::device_approval::DeviceApprovalChallenge;

    /// An Interest under the CA prefix that no CA service or issued
    /// certificate answers (a routed certificate fetch for a key the CA never
    /// certified) is refused with a Nack, never left unanswered.
    #[tokio::test]
    async fn an_interest_nothing_answers_is_nacked() {
        let identity = Identity::ephemeral("/lab/ca").unwrap();
        let ca = NdncertCa::builder()
            .name("/lab/ca")
            .unwrap()
            .signing_identity(&identity)
            .challenge(DeviceApprovalChallenge::new(ApprovalStore::new(
                "/lab/ca".parse().unwrap(),
                None,
                DEFAULT_REQUEST_TTL,
            )))
            .build()
            .unwrap();
        let interest = ndn_packet::Interest::new("/lab/ca/CA/KEY/unknown".parse().unwrap());
        assert!(matches!(
            handle_interest(&ca.state, &ca.prefix, None, interest).await,
            Some(CaReply::NoSuchData)
        ));
    }

    fn lab_ca() -> (Identity, NdncertCa) {
        let identity = Identity::ephemeral("/lab/ca").unwrap();
        let store = || ApprovalStore::new("/lab/ca".parse().unwrap(), None, DEFAULT_REQUEST_TTL);
        let ca = NdncertCa::builder()
            .name("/lab/ca")
            .unwrap()
            .signing_identity(&identity)
            .challenge(DeviceApprovalChallenge::new(store()))
            .build()
            .unwrap()
            .approvals(store(), Arc::new(Keyring::new()));
        (identity, ca)
    }

    async fn ask(ca: &NdncertCa, name: &str, body: Vec<u8>) -> Option<CaReply> {
        let wire = ndn_packet::encode::InterestBuilder::new(name.parse::<Name>().unwrap())
            .app_parameters(body)
            .build();
        let interest = ndn_packet::Interest::decode(wire).unwrap();
        let approvals = ca.approval_service();
        handle_interest(&ca.state, &ca.prefix, approvals.as_ref(), interest).await
    }

    fn failure(reply: Option<CaReply>) -> ndn_cert::tlv::ErrorTlv {
        let Some(CaReply::Body(body)) = reply else {
            panic!("expected an answer Data");
        };
        ndn_cert::tlv::ErrorTlv::decode_if_error(&body)
            .unwrap()
            .expect("a failure answer (ErrorCode + ErrorInfo)")
    }

    /// A NEW for a name the CA's policy refuses is answered with ErrorCode
    /// NameNotAllowed (not left to time out), and the requester reads it as
    /// a refusal of the name.
    #[tokio::test]
    async fn a_new_for_a_refused_name_answers_name_not_allowed() {
        let (_identity, ca) = lab_ca();
        let key: Name = "/elsewhere/alice/KEY/k1".parse().unwrap();
        let signer = Arc::new(ndn_security::Ed25519Signer::from_seed(&[7u8; 32], key.clone()));
        let mut session = ndn_cert::EnrollmentSession::new(key, signer, 3600);
        let body = session.new_request_body().await.unwrap();
        let answer = failure(ask(&ca, "/lab/ca/CA/NEW", body).await);
        assert_eq!(answer.code, u8::from(ndn_cert::ErrorCode::NameNotAllowed));
        assert!(answer.info.contains("/elsewhere/alice"), "{}", answer.info);
        assert!(matches!(
            session.handle_new_response(&answer.encode()),
            Err(ndn_cert::CertError::PolicyDenied(_))
        ));
    }

    /// A malformed NEW and a CHALLENGE for an unknown request are answered
    /// with their v0.3 ErrorCodes.
    #[tokio::test]
    async fn malformed_new_and_unknown_challenge_are_answered() {
        let (_identity, ca) = lab_ca();
        let answer = failure(ask(&ca, "/lab/ca/CA/NEW", vec![0x01, 0x05, 0x00]).await);
        assert_eq!(answer.code, u8::from(ndn_cert::ErrorCode::BadParameterFormat));
        let answer = failure(
            ask(&ca, "/lab/ca/CA/CHALLENGE/%01%02%03%04%05%06%07%08", vec![0x01]).await,
        );
        assert_eq!(answer.code, u8::from(ndn_cert::ErrorCode::InvalidParameters));
        // No request id component.
        let answer = failure(ask(&ca, "/lab/ca/CA/CHALLENGE", vec![0x01]).await);
        assert_eq!(answer.code, u8::from(ndn_cert::ErrorCode::BadInterestFormat));
    }

    /// Endpoints are the exact component after `<ca>/CA`: a longer
    /// component, or `CA` deeper in the name, reaches no handler.
    #[tokio::test]
    async fn endpoints_match_exact_components() {
        let (_identity, ca) = lab_ca();
        for name in [
            "/lab/ca/CA/APPROVALX",
            "/lab/ca/CA/PENDINGX",
            "/lab/ca/CA/NEWX",
            "/lab/ca/CA/CHALLENGEX/%01",
            "/lab/ca/CA/REVOKEX",
            "/lab/ca/x/CA/NEW",
            "/lab/ca/CA/APPROVAL/extra",
        ] {
            assert!(
                matches!(ask(&ca, name, vec![0x01]).await, Some(CaReply::NoSuchData)),
                "{name} must reach no handler"
            );
        }
        // The exact endpoint still reaches its handler.
        assert!(matches!(
            ask(&ca, "/lab/ca/CA/APPROVAL", vec![0x01]).await,
            Some(CaReply::Body(_))
        ));
    }

    /// A status check asked to be answered at once takes no held slot: it
    /// is answered even while the request's held slots are all taken, when
    /// a held status Interest is refused.
    #[tokio::test]
    async fn an_immediate_status_check_takes_no_held_slot() {
        let (_identity, ca) = lab_ca();
        let approvals = ca.approval_service().unwrap();
        let _held: Vec<_> = (0..ndn_cert::approval::MAX_HELD_PER_REQUEST)
            .map(|_| approvals.hold_status("0123456789abcdef").unwrap())
            .collect();
        let status = |lifetime: Duration| {
            let wire = ndn_packet::encode::InterestBuilder::new(
                "/lab/ca/CA/STATUS/0123456789abcdef".parse::<Name>().unwrap(),
            )
            .must_be_fresh()
            .lifetime(lifetime)
            .build();
            ndn_packet::Interest::decode(wire).unwrap()
        };
        let now = handle_interest(
            &ca.state,
            &ca.prefix,
            Some(&approvals),
            status(ndn_cert::approval::STATUS_ANSWER_MARGIN),
        )
        .await;
        let Some(CaReply::Body(body)) = now else {
            panic!("an immediate check is answered");
        };
        let answer: ndn_cert::approval::RequestStatus = serde_json::from_slice(&body).unwrap();
        assert!(matches!(answer, ndn_cert::approval::RequestStatus::Expired { .. }));
        let held = handle_interest(
            &ca.state,
            &ca.prefix,
            Some(&approvals),
            status(ndn_cert::approval::STATUS_LIFETIME),
        )
        .await;
        assert!(matches!(held, Some(CaReply::Busy)));
    }
}
