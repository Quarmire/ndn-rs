//! `/localhost/nfd/ca/list-approvals` — read-only introspection of the
//! NDNCERT CA's pending device-approval requests. Backend is a
//! [`PendingApprovalStore`](ndn_cert::challenge::device_approval::PendingApprovalStore)
//! via the [`ApprovalMgmtBackend`] trait.
//!
//! List-only, like `compute`: approvals are created by the CHALLENGE flow and
//! resolved by the approval transport, never mutated over this verb. The
//! dataset is a concatenation of `PendingApproval` TLVs:
//!
//! ```text
//! PendingApproval = PENDING-APPROVAL-TYPE TLV-LENGTH
//!                     RequestId    ; text, the per-request nonce
//!                     CertName     ; text, the subject awaiting approval
//!                     [Description]; text, optional requester note
//! ```

use std::sync::Arc;

use async_trait::async_trait;

use ndn_mgmt_wire::{
    ControlParameters, ControlResponse,
    control_response::status,
    nfd_command::{module, verb},
};

use crate::module::{MgmtContext, MgmtModule};
use crate::{ApprovalMgmtBackend, MgmtResponse, PendingApprovalInfo};
use ndn_mgmt_wire::PendingApproval;

fn handle_ca(
    verb_name: &[u8],
    params: ControlParameters,
    handler: Option<&Arc<dyn ApprovalMgmtBackend>>,
) -> MgmtResponse {
    let Some(handler) = handler else {
        return ControlResponse::error(
            status::NOT_FOUND,
            "ca module not wired (no ApprovalMgmtBackend installed)",
        )
        .into();
    };
    match verb_name {
        v if v == verb::LIST_APPROVALS => {
            MgmtResponse::Dataset(approvals_dataset(&handler.pending()))
        }
        v if v == verb::APPROVE => approve_handler(params, handler.as_ref()).into(),
        v if v == verb::DENY => deny_handler(params, handler.as_ref()).into(),
        _ => ControlResponse::error(
            status::NOT_FOUND,
            "unknown ca verb (try `list-approvals`, `approve`, or `deny`)",
        )
        .into(),
    }
}

/// Approve a pending request. Params: `uri` carries the request id.
/// The signed-command gate authenticates the operator; the recorded
/// approver label is the conventional `"approved-via-mgmt"` until
/// the v2 canonical signed-Data approval path lands.
fn approve_handler(
    params: ControlParameters,
    handler: &dyn ApprovalMgmtBackend,
) -> ControlResponse {
    let Some(id) = params.uri.as_deref() else {
        return ControlResponse::error(status::BAD_PARAMS, "request id required in `uri`");
    };
    if handler.approve(id, "approved-via-mgmt") {
        ControlResponse::ok_empty(format!("approved {id}"))
    } else {
        ControlResponse::error(
            status::NOT_FOUND,
            format!("no pending request with id {id:?} (already resolved or never existed)"),
        )
    }
}

/// Deny a pending request. Params: `uri` carries `<request_id>:<reason>`
/// (reason optional). Mirrors the `safebag-import` two-half hex
/// convention so callers don't need a new TLV field.
fn deny_handler(params: ControlParameters, handler: &dyn ApprovalMgmtBackend) -> ControlResponse {
    let Some(raw) = params.uri.as_deref() else {
        return ControlResponse::error(
            status::BAD_PARAMS,
            "request id required in `uri` (format: `<id>` or `<id>:<reason>`)",
        );
    };
    let (id, reason) = match raw.split_once(':') {
        Some((id, reason)) => (id, reason),
        None => (raw, "denied"),
    };
    if handler.deny(id, reason) {
        ControlResponse::ok_empty(format!("denied {id}"))
    } else {
        ControlResponse::error(
            status::NOT_FOUND,
            format!("no pending request with id {id:?} (already resolved or never existed)"),
        )
    }
}

fn approvals_dataset(rows: &[PendingApprovalInfo]) -> bytes::Bytes {
    // Encode through the shared `ndn-mgmt-wire` codec so the engine and every
    // client decode the same bytes by construction.
    let wire: Vec<PendingApproval> = rows
        .iter()
        .map(|info| PendingApproval {
            request_id: info.id.clone(),
            cert_name: info.cert_name.clone(),
            description: info.description.clone(),
        })
        .collect();
    PendingApproval::encode_all(&wire)
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
        handle_ca(verb, params, ctx.approval_handler)
    }
}

#[cfg(test)]
mod ca_tests {
    use super::*;
    use std::sync::Mutex;

    struct StubBackend {
        rows: Mutex<Vec<PendingApprovalInfo>>,
        approved: Mutex<Vec<(String, String)>>,
        denied: Mutex<Vec<(String, String)>>,
    }
    impl ApprovalMgmtBackend for StubBackend {
        fn pending(&self) -> Vec<PendingApprovalInfo> {
            self.rows.lock().unwrap().clone()
        }
        fn approve(&self, id: &str, approver: &str) -> bool {
            // Mirror PendingApprovalStore semantics: only flip if the
            // request is still in the pending list.
            let mut rows = self.rows.lock().unwrap();
            let Some(pos) = rows.iter().position(|r| r.id == id) else {
                return false;
            };
            rows.remove(pos);
            self.approved
                .lock()
                .unwrap()
                .push((id.to_string(), approver.to_string()));
            true
        }
        fn deny(&self, id: &str, reason: &str) -> bool {
            let mut rows = self.rows.lock().unwrap();
            let Some(pos) = rows.iter().position(|r| r.id == id) else {
                return false;
            };
            rows.remove(pos);
            self.denied
                .lock()
                .unwrap()
                .push((id.to_string(), reason.to_string()));
            true
        }
    }

    fn backend(rows: Vec<PendingApprovalInfo>) -> Arc<StubBackend> {
        Arc::new(StubBackend {
            rows: Mutex::new(rows),
            approved: Mutex::new(Vec::new()),
            denied: Mutex::new(Vec::new()),
        })
    }

    fn as_dyn(b: &Arc<StubBackend>) -> Arc<dyn ApprovalMgmtBackend> {
        b.clone()
    }

    fn info(id: &str, cert: &str, desc: &str) -> PendingApprovalInfo {
        PendingApprovalInfo {
            id: id.to_string(),
            cert_name: cert.to_string(),
            description: desc.to_string(),
        }
    }

    fn cp_uri(s: &str) -> ControlParameters {
        ControlParameters {
            uri: Some(s.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn returns_404_when_no_backend() {
        match handle_ca(verb::LIST_APPROVALS, ControlParameters::default(), None) {
            MgmtResponse::Control(cr) => assert_eq!(cr.status_code, status::NOT_FOUND),
            _ => panic!("expected ControlResponse"),
        }
    }

    #[test]
    fn unknown_verb_returns_404() {
        let h = backend(vec![]);
        match handle_ca(b"nope", ControlParameters::default(), Some(&as_dyn(&h))) {
            MgmtResponse::Control(cr) => assert_eq!(cr.status_code, status::NOT_FOUND),
            _ => panic!("expected ControlResponse"),
        }
    }

    #[test]
    fn list_encodes_each_pending_approval() {
        let h = backend(vec![
            info("req-1", "/lab/alice/devices/laptop", "laptop"),
            info("req-2", "/lab/bob/devices/watch", ""),
        ]);
        let bytes = match handle_ca(
            verb::LIST_APPROVALS,
            ControlParameters::default(),
            Some(&as_dyn(&h)),
        ) {
            MgmtResponse::Dataset(b) => b,
            _ => panic!("expected dataset"),
        };
        // Decode through the shared codec — proves the engine's output is
        // round-trippable by the same decoder every client uses.
        let rows = PendingApproval::decode_all(&bytes);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].request_id, "req-1");
        assert_eq!(rows[0].cert_name, "/lab/alice/devices/laptop");
        assert_eq!(rows[1].request_id, "req-2");
        assert_eq!(rows[1].description, ""); // empty omitted on the wire
    }

    #[test]
    fn approve_succeeds_on_pending_request() {
        let h = backend(vec![info("req-1", "/lab/alice", "")]);
        let resp = match handle_ca(verb::APPROVE, cp_uri("req-1"), Some(&as_dyn(&h))) {
            MgmtResponse::Control(cr) => cr,
            _ => panic!("expected ControlResponse"),
        };
        assert!(resp.is_ok(), "expected 2xx; got {}", resp.status_code);
        let approved = h.approved.lock().unwrap();
        assert_eq!(approved.len(), 1);
        assert_eq!(approved[0].0, "req-1");
        assert_eq!(approved[0].1, "approved-via-mgmt");
    }

    #[test]
    fn approve_requires_request_id() {
        let h = backend(vec![info("req-1", "/lab/alice", "")]);
        match handle_ca(
            verb::APPROVE,
            ControlParameters::default(),
            Some(&as_dyn(&h)),
        ) {
            MgmtResponse::Control(cr) => assert_eq!(cr.status_code, status::BAD_PARAMS),
            _ => panic!("expected ControlResponse"),
        }
    }

    #[test]
    fn approve_unknown_id_returns_404() {
        let h = backend(vec![info("req-1", "/lab/alice", "")]);
        match handle_ca(verb::APPROVE, cp_uri("req-missing"), Some(&as_dyn(&h))) {
            MgmtResponse::Control(cr) => assert_eq!(cr.status_code, status::NOT_FOUND),
            _ => panic!("expected ControlResponse"),
        }
    }

    #[test]
    fn deny_with_reason_records_reason() {
        let h = backend(vec![info("req-1", "/lab/alice", "")]);
        match handle_ca(verb::DENY, cp_uri("req-1:not on team"), Some(&as_dyn(&h))) {
            MgmtResponse::Control(cr) => assert!(cr.is_ok()),
            _ => panic!("expected ControlResponse"),
        }
        let denied = h.denied.lock().unwrap();
        assert_eq!(denied.len(), 1);
        assert_eq!(denied[0].1, "not on team");
    }

    #[test]
    fn deny_without_reason_defaults_to_denied() {
        let h = backend(vec![info("req-1", "/lab/alice", "")]);
        match handle_ca(verb::DENY, cp_uri("req-1"), Some(&as_dyn(&h))) {
            MgmtResponse::Control(cr) => assert!(cr.is_ok()),
            _ => panic!("expected ControlResponse"),
        }
        assert_eq!(h.denied.lock().unwrap()[0].1, "denied");
    }
}
