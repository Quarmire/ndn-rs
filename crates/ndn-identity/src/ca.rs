//! [`NdncertCa`] wraps [`CaState`](ndn_cert::CaState) with an
//! `ndn-app::Producer` registered under `/<prefix>/CA/*`.

use std::sync::Arc;
use std::time::Duration;

use ndn_cert::{
    AcceptAllIssuance, CaConfig, CaState, ChallengeHandler, HierarchicalPolicy, IssuancePolicy,
    NamespacePolicy,
};
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Name, SignatureType};
use ndn_security::{SecurityManager, Signer};
use tracing::{debug, warn};

use crate::{error::IdentityError, identity::NdnIdentity};

pub struct NdncertCaBuilder {
    prefix: Option<Name>,
    info: String,
    identity: Option<Arc<SecurityManager>>,
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

    pub fn signing_identity(mut self, identity: &NdnIdentity) -> Self {
        self.identity = Some(identity.manager_arc());
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
        };

        Ok(NdncertCa {
            state: Arc::new(CaState::new(config, manager)),
            prefix,
        })
    }
}

pub struct NdncertCa {
    state: Arc<CaState>,
    prefix: Name,
}

/// Configuration for an APPROVE-FEED running alongside the CA's `/CA/*`
/// service — the cross-process device-approval transport
/// ([`crate::device_approval_net`]).
///
/// `store` **must** be the same [`PendingApprovalStore`] the CA's
/// `DeviceApprovalChallenge` reads (so a networked approval flips the request
/// the CHALLENGE round is polling). `producer` is registered for
/// `/<prefix>/CA/APPROVE-FEED` on its own face — a longer prefix than the
/// main `/<prefix>/CA`, so the forwarder routes feed Interests to it — and
/// `side` is a separate consumer for the reverse pull.
pub struct CaApproveFeed {
    pub producer: ndn_app::Producer,
    pub side: ndn_app::Consumer,
    pub store: ndn_cert::challenge::device_approval::PendingApprovalStore,
    pub resolver: Arc<ndn_security::did::UniversalResolver>,
    pub authorizer: Arc<dyn crate::device_approval_net::ApproverAuthorizer>,
    pub timeout: Duration,
}

impl NdncertCa {
    pub fn builder() -> NdncertCaBuilder {
        NdncertCaBuilder::new()
    }

    pub fn prefix(&self) -> &Name {
        &self.prefix
    }

    /// Run the `/CA/*` service and an [`CaApproveFeed`] concurrently, each until
    /// its connection closes. Use this instead of [`serve`](Self::serve) when
    /// the CA offers cross-process device-approval.
    pub async fn serve_with_feed(
        self,
        ca_producer: ndn_app::Producer,
        feed: CaApproveFeed,
    ) -> Result<(), IdentityError> {
        let main = self.serve(ca_producer);
        let feed_loop = crate::device_approval_net::serve_approve_feed(
            feed.producer,
            feed.side,
            feed.store,
            feed.resolver,
            feed.authorizer,
            feed.timeout,
        );
        let (main_res, feed_res) = tokio::join!(main, feed_loop);
        main_res?;
        feed_res?;
        Ok(())
    }

    /// Runs until the Producer is dropped or errors.
    pub async fn serve(self, producer: ndn_app::Producer) -> Result<(), IdentityError> {
        let state = self.state.clone();
        let ca_prefix = self.prefix.clone();

        producer
            .serve(move |interest, responder| {
                let state = state.clone();
                let ca_prefix = ca_prefix.clone();
                async move {
                    let interest_name = (*interest.name).clone();
                    let Some(reply) = handle_interest(&state, &ca_prefix, interest).await else {
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
    interest: ndn_packet::Interest,
) -> Option<CaReply> {
    let name = &*interest.name;
    let name_str = name.to_string();
    let ca_prefix_str = ca_prefix.to_string();

    debug!(name = %name_str, "NDNCERT: received Interest");

    // Cert-fetch: ship the pre-signed Data wire verbatim.
    if let Some(wire) = state.get_served_cert(&name_str) {
        debug!(name = %name_str, "NDNCERT: serving issued cert");
        return Some(CaReply::Wire(bytes::Bytes::from(wire)));
    }

    let suffix = name_str.strip_prefix(&ca_prefix_str).unwrap_or(&name_str);

    if suffix == "/CA/INFO" || suffix.ends_with("/CA/INFO") {
        return Some(CaReply::Body(state.handle_info()));
    }

    if suffix.contains("/CA/NEW") {
        let body = interest.app_parameters().cloned().unwrap_or_default();
        match state.handle_new(&body).await {
            Ok(resp) => return Some(CaReply::Body(resp)),
            Err(e) => {
                warn!(error = %e, "NDNCERT NEW failed");
                return None;
            }
        }
    }

    if suffix.contains("/CA/CHALLENGE/") {
        // NDN Packet Format §3.4: a signed Interest with
        // ApplicationParameters carries `ParametersSha256Digest` (0x02)
        // as the last name component, so request-id sits at index N-2.
        const PARAMETERS_SHA256: u64 = 0x02;
        let comps = name.components();
        let request_id_comp = match comps.last() {
            Some(last) if last.typ == PARAMETERS_SHA256 => comps.get(comps.len() - 2)?,
            Some(last) => last,
            None => return None,
        };
        let request_id_hex: String = request_id_comp
            .value
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

        let body = interest.app_parameters().cloned().unwrap_or_default();
        match state.handle_challenge(&request_id_hex, &body).await {
            Ok(resp) => return Some(CaReply::Body(resp)),
            Err(e) => {
                warn!(error = %e, "NDNCERT CHALLENGE failed");
                return None;
            }
        }
    }

    warn!(name = %name_str, "NDNCERT: unrecognised Interest");
    None
}
