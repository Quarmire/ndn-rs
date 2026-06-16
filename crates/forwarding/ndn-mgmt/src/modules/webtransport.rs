//! `/localhost/nfd/webtransport/cert-status` — read-only introspection of the
//! WebTransport listeners' TLS certificate status. Backend is the host
//! (`ndn-fwd`) via the [`WtCertStatusBackend`] trait.
//!
//! List-only, like `compute`: the cert state is owned by the running listeners,
//! not mutated over the wire. The dataset is a concatenation of `WtCertStatus`
//! TLVs:
//!
//! ```text
//! WtCertStatus = WT-CERT-STATUS-TYPE TLV-LENGTH
//!                  Listen          ; bind address, UTF-8 (TLV 0xCC)
//!                  NotAfterUnix    ; NonNegativeInteger seconds (TLV 0xCE)
//!                  NeedsRenewal    ; 1 byte 0/1 (TLV 0xD0)
//! ```
//! `days_remaining` is derivable client-side from `NotAfterUnix`.

use std::sync::Arc;

use async_trait::async_trait;

use ndn_mgmt_wire::{
    ControlParameters, ControlResponse, control_response::status, nfd_command::module,
};

use crate::module::{MgmtContext, MgmtModule};
use crate::{MgmtResponse, WtCertStatusBackend, WtCertStatusInfo};

// Dataset TLV codes (ndn-rs application range; scoped to this Data content).
const TYPE_WT_CERT_STATUS: u64 = 0xCA;
const TYPE_WT_LISTEN: u64 = 0xCC;
const TYPE_WT_NOT_AFTER: u64 = 0xCE;
const TYPE_WT_NEEDS_RENEWAL: u64 = 0xD0;

// `cert-status` read verb (no mutation verbs on this module).
const VERB_CERT_STATUS: &[u8] = b"cert-status";

fn handle_webtransport(
    verb_name: &[u8],
    handler: Option<&Arc<dyn WtCertStatusBackend>>,
) -> MgmtResponse {
    let Some(handler) = handler else {
        return ControlResponse::error(
            status::NOT_FOUND,
            "webtransport module not wired (no WtCertStatusBackend installed)",
        )
        .into();
    };
    match verb_name {
        v if v == VERB_CERT_STATUS => {
            MgmtResponse::Dataset(cert_status_dataset(&handler.cert_status()))
        }
        _ => ControlResponse::error(
            status::NOT_FOUND,
            "unknown webtransport verb (only `cert-status`)",
        )
        .into(),
    }
}

/// Big-endian, leading zeros trimmed — NDN NonNegativeInteger convention.
fn nni_be(v: u64) -> Vec<u8> {
    if v == 0 {
        return vec![0];
    }
    let bytes = v.to_be_bytes();
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    bytes[first..].to_vec()
}

fn cert_status_dataset(rows: &[WtCertStatusInfo]) -> bytes::Bytes {
    let mut w = ndn_tlv::TlvWriter::new();
    for info in rows {
        w.write_nested(TYPE_WT_CERT_STATUS, |inner| {
            inner.write_tlv(TYPE_WT_LISTEN, info.listen.as_bytes());
            // notAfter is always in the future-or-past but a positive epoch
            // second; clamp a (theoretically impossible) negative to 0.
            inner.write_tlv(
                TYPE_WT_NOT_AFTER,
                &nni_be(info.not_after_unix.max(0) as u64),
            );
            inner.write_tlv(TYPE_WT_NEEDS_RENEWAL, &[u8::from(info.needs_renewal)]);
        });
    }
    w.finish()
}

pub(crate) struct WebTransportModule;

#[async_trait]
impl MgmtModule for WebTransportModule {
    fn name(&self) -> &'static [u8] {
        module::WEBTRANSPORT
    }

    async fn dispatch(
        &self,
        verb: &[u8],
        _params: ControlParameters,
        ctx: &MgmtContext<'_>,
    ) -> MgmtResponse {
        handle_webtransport(verb, ctx.webtransport_status_handler)
    }
}

#[cfg(test)]
mod webtransport_tests {
    use super::*;

    struct StubBackend(Vec<WtCertStatusInfo>);
    impl WtCertStatusBackend for StubBackend {
        fn cert_status(&self) -> Vec<WtCertStatusInfo> {
            self.0.clone()
        }
    }

    fn backend(rows: Vec<WtCertStatusInfo>) -> Arc<dyn WtCertStatusBackend> {
        Arc::new(StubBackend(rows))
    }

    #[test]
    fn returns_404_when_no_backend() {
        match handle_webtransport(VERB_CERT_STATUS, None) {
            MgmtResponse::Control(cr) => assert_eq!(cr.status_code, status::NOT_FOUND),
            _ => panic!("expected ControlResponse"),
        }
    }

    #[test]
    fn unknown_verb_returns_404() {
        let h = backend(vec![]);
        match handle_webtransport(b"list", Some(&h)) {
            MgmtResponse::Control(cr) => assert_eq!(cr.status_code, status::NOT_FOUND),
            _ => panic!("expected ControlResponse"),
        }
    }

    #[test]
    fn cert_status_encodes_each_listener() {
        let rows = vec![
            WtCertStatusInfo {
                listen: "0.0.0.0:4443".into(),
                not_after_unix: 1_900_000_000,
                days_remaining: 120,
                needs_renewal: false,
            },
            WtCertStatusInfo {
                listen: "[::]:4444".into(),
                not_after_unix: 1_800_000_000,
                days_remaining: 5,
                needs_renewal: true,
            },
        ];
        let h = backend(rows);
        let bytes = match handle_webtransport(VERB_CERT_STATUS, Some(&h)) {
            MgmtResponse::Dataset(b) => b,
            _ => panic!("expected dataset"),
        };
        let mut r = ndn_tlv::TlvReader::new(bytes);
        let (t0, v0) = r.read_tlv().expect("first row");
        assert_eq!(t0, TYPE_WT_CERT_STATUS);
        let mut ir = ndn_tlv::TlvReader::new(v0);
        let (lt, lv) = ir.read_tlv().expect("listen tlv");
        assert_eq!(lt, TYPE_WT_LISTEN);
        assert_eq!(&lv[..], b"0.0.0.0:4443");
        let (t1, _) = r.read_tlv().expect("second row");
        assert_eq!(t1, TYPE_WT_CERT_STATUS);
        assert!(r.is_empty());
    }
}
