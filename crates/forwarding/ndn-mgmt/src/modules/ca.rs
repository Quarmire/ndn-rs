//! `/localhost/nfd/ca/{list-approvals,approve,deny}` — enrollment by an
//! admin's approval, through the node's [`ApprovalMgmtBackend`]: its own
//! CA's requests on a CA host; on an admin device also its namespaces' CAs'
//! pending requests, decided with its admin key.
//!
//! Every verb is a trust change: it reaches this module only from a local
//! operator on the management socket (kernel peer credentials), never over
//! `/localhop` or another face (see `auth::TRUST_ADMIN_VERBS`). The operator
//! the kernel attests (`uid 1000 (alice)`) is handed to the backend, which
//! records it as the approver of a decision made on the CA host.
//!
//! `list-approvals` answers a dataset of `PendingApproval` rows plus a note
//! per namespace whose CA could not be asked
//! ([`ndn_mgmt_wire::ApprovalListing`]); `approve` takes the request id or
//! verification code in `Uri`, `deny` takes `<id or code>[:<reason>]`. Both
//! answer a sentence saying what was recorded.

use std::sync::Arc;

use async_trait::async_trait;

use ndn_mgmt_wire::{
    ControlParameters, ControlResponse, PendingApproval,
    control_response::status,
    nfd_command::{module, verb},
};

use crate::module::{MgmtContext, MgmtModule};
use crate::{ApprovalMgmtBackend, MgmtResponse};

fn handle_ca(
    verb_name: &[u8],
    params: ControlParameters,
    handler: Option<&Arc<dyn ApprovalMgmtBackend>>,
    operator: String,
) -> MgmtResponse {
    let Some(handler) = handler else {
        return ControlResponse::error(
            status::NOT_FOUND,
            "this node neither runs a CA that takes approval requests nor is an admin device \
             of a namespace: there is nothing to approve here",
        )
        .into();
    };
    let handler = Arc::clone(handler);
    match verb_name {
        v if v == verb::LIST_APPROVALS => MgmtResponse::DeferredDataset(Box::pin(async move {
            handler
                .list()
                .await
                .map(|listing| listing.encode())
                .map_err(|r| ControlResponse::error(r.status_code, r.reason))
        })),
        v if v == verb::APPROVE || v == verb::DENY => {
            let Some((target, decision)) = decision_of(v == verb::APPROVE, params.uri.as_deref())
            else {
                return ControlResponse::error(
                    status::BAD_PARAMS,
                    "give the request id or the six-digit code (`ndn-fwd approvals list` shows \
                     them) in Uri; a denial may add `:<reason>`",
                )
                .into();
            };
            MgmtResponse::Deferred(Box::pin(async move {
                match handler.decide(target, decision, operator).await {
                    Ok(row) => ControlResponse::ok_empty(decided(&row)),
                    Err(r) => ControlResponse::error(r.status_code, r.reason),
                }
            }))
        }
        _ => ControlResponse::error(
            status::NOT_FOUND,
            "unknown ca verb (try `list-approvals`, `approve`, or `deny`)",
        )
        .into(),
    }
}

/// `(target, decision)` of an approve (`<id or code>`) or deny
/// (`<id or code>[:<reason>]`) Uri.
fn decision_of(approve: bool, uri: Option<&str>) -> Option<(String, ndn_cert::Decision)> {
    let raw = uri.map(str::trim).filter(|s| !s.is_empty())?;
    if approve {
        return Some((raw.to_owned(), ndn_cert::Decision::Approve));
    }
    let (target, reason) = match raw.split_once(':') {
        Some((target, reason)) => (target.trim(), reason.trim()),
        None => (raw, ""),
    };
    let reason = if reason.is_empty() {
        "no reason given".to_owned()
    } else {
        reason.to_owned()
    };
    (!target.is_empty()).then(|| (target.to_owned(), ndn_cert::Decision::Deny { reason }))
}

/// What a decision recorded, in one sentence.
fn decided(row: &PendingApproval) -> String {
    let subject = if row.role.is_empty() {
        row.key_name.clone()
    } else {
        format!("{} device {:?} ({})", row.role, row.device, row.key_name)
    };
    let outcome = if row.state == "approved" {
        "the device's next request gets its certificate".to_owned()
    } else {
        format!("reason: {}; the device is told so at its next request", row.reason)
    };
    format!(
        "{} request {} for {subject} at {} (code {}), recorded as decided by {}; {outcome}",
        row.state, row.request_id, row.namespace, row.code, row.approver
    )
}

pub(crate) struct CaModule;

#[async_trait]
impl MgmtModule for CaModule {
    fn name(&self) -> &'static [u8] {
        module::CA
    }

    async fn dispatch(
        &self,
        verb: &[u8],
        params: ControlParameters,
        ctx: &MgmtContext<'_>,
    ) -> MgmtResponse {
        let operator = crate::auth::caller_label(ctx.source_face, ctx.engine);
        handle_ca(verb, params, ctx.approval_handler, operator)
    }
}

#[cfg(test)]
mod ca_tests {
    use super::*;
    use ndn_mgmt_wire::ApprovalListing;
    use parking_lot::Mutex;

    /// Records what reached the backend.
    #[derive(Default)]
    struct Recording {
        decided: Mutex<Vec<(String, ndn_cert::Decision, String)>>,
    }

    #[async_trait]
    impl ApprovalMgmtBackend for Recording {
        async fn list(&self) -> Result<ApprovalListing, crate::TrustRefusal> {
            Ok(ApprovalListing::default())
        }
        async fn decide(
            &self,
            target: String,
            decision: ndn_cert::Decision,
            operator: String,
        ) -> Result<PendingApproval, crate::TrustRefusal> {
            self.decided
                .lock()
                .push((target.clone(), decision, operator.clone()));
            Ok(PendingApproval {
                request_id: target,
                key_name: "/home/bob/admin/phone/KEY/k".into(),
                state: "approved".into(),
                approver: operator,
                ..Default::default()
            })
        }
    }

    async fn answer(resp: MgmtResponse) -> ControlResponse {
        match resp {
            MgmtResponse::Control(cr) => *cr,
            MgmtResponse::Deferred(pending) => pending.await,
            _ => panic!("expected a control response"),
        }
    }

    /// The approver a decision records is the operator the kernel attested,
    /// never a fixed label; a denial carries its reason.
    #[tokio::test]
    async fn decisions_carry_the_attested_operator_and_reason() {
        let backend = Arc::new(Recording::default());
        let dyn_backend: Arc<dyn ApprovalMgmtBackend> = backend.clone();
        let uri = |s: &str| ControlParameters {
            uri: Some(s.into()),
            ..Default::default()
        };
        let op = || "uid 1000 (alice)".to_owned();
        assert!(
            answer(handle_ca(verb::APPROVE, uri("482 913"), Some(&dyn_backend), op()))
                .await
                .is_ok()
        );
        assert!(
            answer(handle_ca(verb::DENY, uri("1a2b:not mine"), Some(&dyn_backend), op()))
                .await
                .is_ok()
        );
        let decided = backend.decided.lock();
        assert_eq!(
            decided[0],
            ("482 913".into(), ndn_cert::Decision::Approve, op())
        );
        assert_eq!(
            decided[1],
            (
                "1a2b".into(),
                ndn_cert::Decision::Deny {
                    reason: "not mine".into()
                },
                op()
            )
        );
    }

    #[tokio::test]
    async fn without_a_backend_or_target_nothing_is_decided() {
        let none = handle_ca(verb::APPROVE, ControlParameters::default(), None, String::new());
        assert_eq!(answer(none).await.status_code, status::NOT_FOUND);
        let backend: Arc<dyn ApprovalMgmtBackend> = Arc::new(Recording::default());
        let no_target =
            handle_ca(verb::APPROVE, ControlParameters::default(), Some(&backend), String::new());
        assert_eq!(answer(no_target).await.status_code, status::BAD_PARAMS);
    }
}
