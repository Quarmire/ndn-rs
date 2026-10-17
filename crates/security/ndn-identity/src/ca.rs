//! [`NdncertCa`] wraps [`CaState`] with an
//! `ndn-app::Producer` registered under `/<prefix>/CA/*`.

use std::sync::Arc;
use std::time::Duration;

use ndn_cert::{
    AcceptAllIssuance, CaConfig, CaState, CaStore, ChallengeHandler, HierarchicalPolicy,
    IssuancePolicy, NamespacePolicy,
};
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Name, SignatureType};
use ndn_security::{SecurityManager, Signer};
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
        })
    }
}

pub struct NdncertCa {
    state: Arc<CaState>,
    prefix: Name,
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

    /// Run the `/CA/*` service and a canonical (validator-checked)
    /// [`ApprovalFeed`](crate::ApprovalFeed) concurrently, each until its
    /// connection closes. Use this instead of [`serve`](Self::serve) when the
    /// CA offers cross-process device-approval
    /// ([`crate::device_approval_net`]).
    ///
    /// The feed's sink **must** be the same `PendingApprovalStore` the CA's
    /// `DeviceApprovalChallenge` reads, so a networked approval flips the
    /// request the CHALLENGE round is polling. `feed_producer` serves
    /// `/<prefix>/CA/APPROVE-FEED` on its own face — a longer prefix than the
    /// main `/<prefix>/CA`, so the forwarder routes feed Interests to it — and
    /// `feed_side` is a separate consumer for the reverse pull.
    pub async fn serve_with_feed<S>(
        self,
        ca_producer: ndn_app::Producer,
        feed: crate::ApprovalFeed<S>,
        feed_producer: ndn_app::Producer,
        feed_side: ndn_app::Consumer,
    ) -> Result<(), IdentityError>
    where
        S: crate::ApprovalSink + Clone + Send + Sync + 'static,
    {
        let (main_res, feed_res) =
            tokio::join!(self.serve(ca_producer), feed.serve(feed_producer, feed_side));
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

    // Cert-fetch: ship the pre-signed Data wire verbatim. A CanBePrefix
    // Interest for a key name gets the newest valid certificate of the key.
    if let Some(wire) = state.cert_for_interest(name, interest.selectors().can_be_prefix) {
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

    // NDNCERT 0.3 `<ca-prefix>/CA/REVOKE/...`: the possession-proof request
    // rides in ApplicationParameters; the outcome is a status, never an error.
    if suffix.contains("/CA/REVOKE") {
        let body = interest.app_parameters().cloned().unwrap_or_default();
        return Some(CaReply::Body(state.handle_revoke(&body).await));
    }

    warn!(name = %name_str, "NDNCERT: unrecognised Interest");
    None
}
