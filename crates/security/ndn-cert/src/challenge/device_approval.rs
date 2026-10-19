//! The `device-approval` challenge: a key is certified once an admin
//! approved it — a local operator of the CA host, or a current admin device
//! through its signed decision (see [`crate::approval`]). The challenge
//! opens or resumes the key's durable [`ApprovalRecord`]
//! in the CA's [`ApprovalStore`] and answers pending (with the request id and
//! verification code), approved (with the approval as attestation) or
//! denied / expired (with the reason and what to do).

use std::{future::Future, pin::Pin};

use base64::Engine as _;
use ndn_packet::Name;

use crate::{
    approval::{
        ApprovalRecord, ApprovalState, ApprovalStore, Approver, CODE_PARAM, DEVICE_APPROVAL,
        EXPIRES_PARAM, OpenRefusal, POLL_SESSION_SECS, REQUEST_PARAM, Redeem, TOKEN_PARAM,
    },
    attestation::{AttestationSet, ChallengeAttestation},
    challenge::{ChallengeHandler, ChallengeOutcome, ChallengeState, token::TokenStore},
    error::CertError,
    protocol::CertRequest,
    roles::Role,
};

/// Attestation evidence: the approver kind (`local-operator` | `admin-key`).
pub const APPROVER_KIND_EVIDENCE: &str = "approver_kind";
/// Attestation evidence: who approved (operator or admin key name).
pub const APPROVED_BY_EVIDENCE: &str = "approved_by";
/// Attestation evidence: an invite token was redeemed with the request.
pub const INVITE_EVIDENCE: &str = "invite";

pub struct DeviceApprovalChallenge {
    store: ApprovalStore,
    invite: Option<InviteRequirement>,
}

/// Roles whose requests must also redeem an invite token.
struct InviteRequirement {
    namespace: Name,
    roles: Vec<Role>,
    tokens: TokenStore,
}

impl DeviceApprovalChallenge {
    pub fn new(store: ApprovalStore) -> Self {
        Self {
            store,
            invite: None,
        }
    }

    /// A request for a role in `roles` (keys `/<namespace>/<role>/…`) must
    /// also redeem one of `tokens` — an invite of this CA, whatever role it
    /// names: the admin's approval decides the role. The token is redeemed
    /// once, when the request is opened, and recorded with it.
    pub fn requiring_invite(
        mut self,
        namespace: Name,
        roles: Vec<Role>,
        tokens: TokenStore,
    ) -> Self {
        self.invite = Some(InviteRequirement {
            namespace,
            roles,
            tokens,
        });
        self
    }

    pub fn store(&self) -> &ApprovalStore {
        &self.store
    }

    /// The invite a new request for `key` needs, if it needs one: checked
    /// now, consumed by the returned [`Redeem`] once the request is saved.
    fn redeem_invite<'a>(
        &'a self,
        key: &Name,
        params: &'a serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<Redeem<'a>>, String> {
        let Some(req) = &self.invite else {
            return Ok(None);
        };
        let Some(device) = crate::roles::parse_device_key(&req.namespace, key) else {
            return Ok(None);
        };
        if !req.roles.contains(&device.role) {
            return Ok(None);
        }
        let role = device.role;
        let Some(token) = params.get(TOKEN_PARAM).and_then(|v| v.as_str()) else {
            return Err(format!(
                "this CA approves a {role} device only together with an invite: ask as {role} \
                 with an invite link of this namespace"
            ));
        };
        let refused = move || {
            format!(
                "the invite token was not accepted (already redeemed, expired, or not this \
                 CA's); a {role} device needs a valid invite beside an admin's approval: ask \
                 for a new invite"
            )
        };
        if !req.tokens.is_live(token) {
            return Err(refused());
        }
        Ok(Some(Box::new(move || match req.tokens.redeem(token) {
            crate::challenge::token::TokenCheck::Ok => Ok(()),
            crate::challenge::token::TokenCheck::NotRecorded(e) => Err(format!(
                "the CA could not record the invite's redemption durably ({e}); nothing is \
                 pending and the invite was not used: ask again once the CA operator has fixed \
                 its storage"
            )),
            _ => Err(refused()),
        })))
    }
}

fn state_of(key: &str, public_key: &str, request: Option<&str>) -> ChallengeState {
    let mut data = serde_json::json!({ "key": key, "public_key": public_key });
    if let Some(id) = request {
        data["request"] = id.into();
    }
    ChallengeState {
        challenge_type: DEVICE_APPROVAL.to_string(),
        data,
    }
}

impl ChallengeHandler for DeviceApprovalChallenge {
    fn challenge_type(&self) -> &'static str {
        DEVICE_APPROVAL
    }

    fn begin<'a>(
        &'a self,
        req: &'a CertRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ChallengeState, CertError>> + Send + 'a>> {
        Box::pin(async move { Ok(state_of(&req.name, &req.public_key, None)) })
    }

    fn verify<'a>(
        &'a self,
        state: &'a ChallengeState,
        parameters: &'a serde_json::Map<String, serde_json::Value>,
    ) -> Pin<Box<dyn Future<Output = Result<ChallengeOutcome, CertError>> + Send + 'a>> {
        Box::pin(async move {
            let field = |k: &str| state.data.get(k).and_then(|v| v.as_str());
            let (Some(key_uri), Some(public_b64)) = (field("key"), field("public_key")) else {
                return Ok(ChallengeOutcome::Denied(
                    "the request carries no key to approve".into(),
                ));
            };
            let key: Name = key_uri
                .parse()
                .map_err(|_| CertError::Name(key_uri.to_string()))?;
            let public_key = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(public_b64)
                .map_err(|_| CertError::InvalidRequest("invalid public key base64".into()))?;
            let resume = parameters
                .get(REQUEST_PARAM)
                .and_then(|v| v.as_str())
                .or_else(|| field("request"));
            let record = match self.store.open_request(&key, &public_key, resume, || {
                self.redeem_invite(&key, parameters)
            }) {
                Ok(record) => record,
                Err(OpenRefusal::Expired(reason)) => return Ok(ChallengeOutcome::Expired(reason)),
                Err(OpenRefusal::Refused(reason)) => return Ok(ChallengeOutcome::Denied(reason)),
            };
            Ok(match &record.state {
                ApprovalState::Pending => ChallengeOutcome::Pending {
                    status_message: format!(
                        "waiting for an admin's approval of request {} (verification code {}); \
                         on an admin device, check it shows the same code, then approve it",
                        record.request_id, record.code
                    ),
                    remaining_tries: 1,
                    remaining_time_secs: POLL_SESSION_SECS,
                    next_state: state_of(key_uri, public_b64, Some(&record.request_id)),
                },
                ApprovalState::Approved { by, .. } => ChallengeOutcome::Approved {
                    attestation: Some(attestation(&record, by)),
                },
                ApprovalState::Denied { by, reason, .. } => ChallengeOutcome::Denied(
                    crate::approval::denial_reason(&record.request_id, by, reason),
                ),
            })
        })
    }

    fn pending_parameters(
        &self,
        state: &ChallengeState,
    ) -> serde_json::Map<String, serde_json::Value> {
        let mut out = serde_json::Map::new();
        let Some(record) = state
            .data
            .get("request")
            .and_then(|v| v.as_str())
            .and_then(|id| self.store.get(id))
        else {
            return out;
        };
        out.insert(REQUEST_PARAM.into(), record.request_id.into());
        out.insert(CODE_PARAM.into(), record.code.into());
        out.insert(EXPIRES_PARAM.into(), record.expires_secs.to_string().into());
        out
    }
}

/// The attestation of an approved request: who approved it and how. An
/// admin key's approval carries its signed decision Data as the leaf's
/// signature; a local operator's carries none (none exists).
fn attestation(record: &ApprovalRecord, by: &Approver) -> AttestationSet {
    let mut leaf = ChallengeAttestation::of_kind(DEVICE_APPROVAL)
        .with_evidence("request_id", serde_json::json!(record.request_id))
        .with_evidence("code", serde_json::json!(record.code))
        .with_evidence(APPROVER_KIND_EVIDENCE, serde_json::json!(by.kind()));
    leaf.handler_name = Some(DEVICE_APPROVAL.to_string());
    leaf = match by {
        Approver::LocalOperator { who } => {
            leaf.with_evidence(APPROVED_BY_EVIDENCE, serde_json::json!(who))
        }
        Approver::AdminKey { key, evidence } => {
            let mut leaf = leaf.with_evidence(APPROVED_BY_EVIDENCE, serde_json::json!(key));
            leaf.signature = Some(evidence.clone());
            leaf
        }
    };
    if record.invite {
        leaf = leaf.with_evidence(INVITE_EVIDENCE, serde_json::json!(true));
    }
    AttestationSet::single(leaf)
}
