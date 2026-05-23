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

use ndn_config::{
    ControlParameters, ControlResponse, control_response::status,
    nfd_command::{module, verb},
};

use crate::module::{MgmtContext, MgmtModule};
use crate::{ApprovalMgmtBackend, MgmtResponse, PendingApprovalInfo};

// Dataset TLV codes (ndn-rs application range; scoped to this Data content).
const TYPE_PENDING_APPROVAL: u64 = 0xCA;
const TYPE_REQUEST_ID: u64 = 0xCC;
const TYPE_CERT_NAME: u64 = 0xCE;
const TYPE_DESCRIPTION: u64 = 0xD0;

fn handle_ca(verb_name: &[u8], handler: Option<&Arc<dyn ApprovalMgmtBackend>>) -> MgmtResponse {
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
        _ => ControlResponse::error(status::NOT_FOUND, "unknown ca verb (only `list-approvals`)")
            .into(),
    }
}

fn approvals_dataset(rows: &[PendingApprovalInfo]) -> bytes::Bytes {
    let mut w = ndn_tlv::TlvWriter::new();
    for info in rows {
        w.write_nested(TYPE_PENDING_APPROVAL, |inner| {
            inner.write_tlv(TYPE_REQUEST_ID, info.id.as_bytes());
            inner.write_tlv(TYPE_CERT_NAME, info.cert_name.as_bytes());
            if !info.description.is_empty() {
                inner.write_tlv(TYPE_DESCRIPTION, info.description.as_bytes());
            }
        });
    }
    w.finish()
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
        _params: ControlParameters,
        ctx: &MgmtContext<'_>,
    ) -> MgmtResponse {
        handle_ca(verb, ctx.approval_handler)
    }
}

#[cfg(test)]
mod ca_tests {
    use super::*;
    use std::sync::Mutex;

    struct StubBackend {
        rows: Mutex<Vec<PendingApprovalInfo>>,
    }
    impl ApprovalMgmtBackend for StubBackend {
        fn pending(&self) -> Vec<PendingApprovalInfo> {
            self.rows.lock().unwrap().clone()
        }
    }

    fn backend(rows: Vec<PendingApprovalInfo>) -> Arc<dyn ApprovalMgmtBackend> {
        Arc::new(StubBackend {
            rows: Mutex::new(rows),
        })
    }

    fn info(id: &str, cert: &str, desc: &str) -> PendingApprovalInfo {
        PendingApprovalInfo {
            id: id.to_string(),
            cert_name: cert.to_string(),
            description: desc.to_string(),
        }
    }

    #[test]
    fn returns_404_when_no_backend() {
        match handle_ca(verb::LIST_APPROVALS, None) {
            MgmtResponse::Control(cr) => assert_eq!(cr.status_code, status::NOT_FOUND),
            _ => panic!("expected ControlResponse"),
        }
    }

    #[test]
    fn unknown_verb_returns_404() {
        let h = backend(vec![]);
        match handle_ca(b"approve", Some(&h)) {
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
        let bytes = match handle_ca(verb::LIST_APPROVALS, Some(&h)) {
            MgmtResponse::Dataset(b) => b,
            _ => panic!("expected dataset"),
        };
        let mut r = ndn_tlv::TlvReader::new(bytes);
        let (t0, v0) = r.read_tlv().expect("first approval");
        assert_eq!(t0, TYPE_PENDING_APPROVAL);
        let mut ir = ndn_tlv::TlvReader::new(v0);
        let (idt, idv) = ir.read_tlv().expect("request id");
        assert_eq!(idt, TYPE_REQUEST_ID);
        assert_eq!(idv.as_ref(), b"req-1");
        let (t1, _) = r.read_tlv().expect("second approval");
        assert_eq!(t1, TYPE_PENDING_APPROVAL);
        assert!(r.is_empty());
    }
}
