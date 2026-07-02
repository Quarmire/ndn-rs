//! `/localhost/nfd/coding/{set, unset, list}` — coding-policy table
//! pluggable backend.

use std::sync::Arc;

use async_trait::async_trait;

use ndn_mgmt_wire::{
    ControlParameters, ControlResponse,
    control_response::status,
    nfd_command::{module, verb},
};
#[cfg(test)]
use ndn_packet::Name;

use crate::module::{MgmtContext, MgmtModule};
use crate::{CodingEntry, CodingFieldId, CodingHandler, CodingRole, MgmtResponse};

fn handle_coding(
    verb_name: &[u8],
    params: ControlParameters,
    handler: Option<&Arc<dyn CodingHandler>>,
) -> MgmtResponse {
    let Some(handler) = handler else {
        return ControlResponse::error(
            status::NOT_FOUND,
            "coding module not wired (no CodingHandler installed)",
        )
        .into();
    };
    match verb_name {
        v if v == verb::SET => coding_set(params, handler.as_ref()).into(),
        v if v == verb::UNSET => coding_unset(params, handler.as_ref()).into(),
        v if v == verb::LIST => MgmtResponse::Dataset(coding_list_dataset(handler.as_ref())),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown coding verb").into(),
    }
}

fn parse_role(code: Option<u8>) -> Option<CodingRole> {
    match code? {
        c if c == ndn_mgmt_wire::control_parameters::fec_role::PRODUCED => {
            Some(CodingRole::Produced)
        }
        c if c == ndn_mgmt_wire::control_parameters::fec_role::CONSUMED => {
            Some(CodingRole::Consumed)
        }
        _ => None,
    }
}

fn parse_field(code: Option<u8>) -> Option<CodingFieldId> {
    match code.unwrap_or(ndn_mgmt_wire::control_parameters::fec_field::GF8) {
        c if c == ndn_mgmt_wire::control_parameters::fec_field::GF8 => Some(CodingFieldId::Gf8),
        _ => None,
    }
}

fn coding_set(params: ControlParameters, handler: &dyn CodingHandler) -> ControlResponse {
    let prefix = match &params.name {
        Some(n) => n.clone(),
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };
    let Some(role) = parse_role(params.fec_role) else {
        return ControlResponse::error(status::BAD_PARAMS, "valid FecRole is required");
    };
    let Some(field) = parse_field(params.fec_field) else {
        return ControlResponse::error(status::BAD_PARAMS, "unsupported FecField");
    };
    let k = match params.fec_k {
        Some(k) if k > 0 => k,
        _ => return ControlResponse::error(status::BAD_PARAMS, "FecK must be > 0"),
    };
    let n = match params.fec_n {
        Some(n) if n >= k && n <= 255 => n,
        _ => return ControlResponse::error(status::BAD_PARAMS, "FecN must satisfy K <= N <= 255"),
    };
    let entry = CodingEntry { role, k, n, field };
    if let Err(msg) = handler.set(&prefix, entry) {
        return ControlResponse::error(status::SERVER_ERROR, msg);
    }
    tracing::info!(
        target: "mgmt.coding",
        prefix = %prefix,
        role = ?role,
        k, n,
        "coding/set"
    );
    let echo = ControlParameters {
        name: Some(prefix),
        fec_k: Some(k),
        fec_n: Some(n),
        fec_field: Some(ndn_mgmt_wire::control_parameters::fec_field::GF8),
        fec_role: params.fec_role,
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn coding_unset(params: ControlParameters, handler: &dyn CodingHandler) -> ControlResponse {
    let prefix = match &params.name {
        Some(n) => n.clone(),
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };
    let Some(role) = parse_role(params.fec_role) else {
        return ControlResponse::error(status::BAD_PARAMS, "valid FecRole is required");
    };
    if let Err(msg) = handler.unset(&prefix, role) {
        return ControlResponse::error(status::SERVER_ERROR, msg);
    }
    tracing::info!(target: "mgmt.coding", prefix = %prefix, role = ?role, "coding/unset");
    let echo = ControlParameters {
        name: Some(prefix),
        fec_role: params.fec_role,
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn coding_list_dataset(handler: &dyn CodingHandler) -> bytes::Bytes {
    let mut buf = bytes::BytesMut::new();
    for (prefix, entry) in handler.list() {
        let role_code = match entry.role {
            CodingRole::Produced => ndn_mgmt_wire::control_parameters::fec_role::PRODUCED,
            CodingRole::Consumed => ndn_mgmt_wire::control_parameters::fec_role::CONSUMED,
        };
        let field_code = match entry.field {
            CodingFieldId::Gf8 => ndn_mgmt_wire::control_parameters::fec_field::GF8,
        };
        let cp = ControlParameters {
            name: Some(prefix),
            fec_k: Some(entry.k),
            fec_n: Some(entry.n),
            fec_field: Some(field_code),
            fec_role: Some(role_code),
            ..Default::default()
        };
        buf.extend_from_slice(&cp.encode());
    }
    buf.freeze()
}

pub(crate) struct CodingModule;

#[async_trait]
impl MgmtModule for CodingModule {
    fn name(&self) -> &'static [u8] {
        module::CODING
    }

    async fn dispatch(
        &self,
        verb: &[u8],
        params: ControlParameters,
        ctx: &MgmtContext<'_>,
    ) -> MgmtResponse {
        handle_coding(verb, params, ctx.coding_handler)
    }
}
#[cfg(test)]
mod coding_tests {
    use super::*;
    use ndn_mgmt_wire::control_parameters::{fec_field as fr_fld, fec_role as fr_role};
    use std::sync::Mutex;

    struct StubHandler {
        entries: Mutex<Vec<(Name, CodingEntry)>>,
    }

    impl StubHandler {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                entries: Mutex::new(Vec::new()),
            })
        }
    }

    impl CodingHandler for StubHandler {
        fn set(&self, prefix: &Name, entry: CodingEntry) -> Result<(), String> {
            if entry.k == 0 || entry.n < entry.k {
                return Err("bad k/n".into());
            }
            let mut g = self.entries.lock().unwrap();
            g.retain(|(p, e)| !(p == prefix && e.role == entry.role));
            g.push((prefix.clone(), entry));
            Ok(())
        }
        fn unset(&self, prefix: &Name, role: CodingRole) -> Result<(), String> {
            let mut g = self.entries.lock().unwrap();
            g.retain(|(p, e)| !(p == prefix && e.role == role));
            Ok(())
        }
        fn list(&self) -> Vec<(Name, CodingEntry)> {
            self.entries.lock().unwrap().clone()
        }
    }

    fn set_params(prefix: &Name, k: u16, n: u16, role: u8) -> ControlParameters {
        ControlParameters {
            name: Some(prefix.clone()),
            fec_k: Some(k),
            fec_n: Some(n),
            fec_field: Some(fr_fld::GF8),
            fec_role: Some(role),
            ..Default::default()
        }
    }

    #[test]
    fn coding_module_returns_404_when_no_handler_installed() {
        let resp = handle_coding(verb::SET, ControlParameters::default(), None);
        match resp {
            MgmtResponse::Control(cr) => assert_eq!(cr.status_code, status::NOT_FOUND),
            _ => panic!("expected ControlResponse"),
        }
    }

    #[test]
    fn coding_set_rejects_missing_name() {
        let handler: Arc<dyn CodingHandler> = StubHandler::new();
        let params = ControlParameters {
            fec_k: Some(16),
            fec_n: Some(20),
            fec_role: Some(fr_role::PRODUCED),
            ..Default::default()
        };
        let resp = handle_coding(verb::SET, params, Some(&handler));
        match resp {
            MgmtResponse::Control(cr) => assert_eq!(cr.status_code, status::BAD_PARAMS),
            _ => panic!("expected ControlResponse"),
        }
    }

    #[test]
    fn coding_set_rejects_missing_role() {
        let handler: Arc<dyn CodingHandler> = StubHandler::new();
        let prefix: Name = "/a".parse().unwrap();
        let params = ControlParameters {
            name: Some(prefix),
            fec_k: Some(8),
            fec_n: Some(10),
            ..Default::default()
        };
        let resp = handle_coding(verb::SET, params, Some(&handler));
        match resp {
            MgmtResponse::Control(cr) => assert_eq!(cr.status_code, status::BAD_PARAMS),
            _ => panic!(),
        }
    }

    #[test]
    fn coding_set_rejects_bad_kn() {
        let handler: Arc<dyn CodingHandler> = StubHandler::new();
        let prefix: Name = "/a".parse().unwrap();
        let params = set_params(&prefix, 10, 5, fr_role::PRODUCED);
        let resp = handle_coding(verb::SET, params, Some(&handler));
        match resp {
            MgmtResponse::Control(cr) => assert_eq!(cr.status_code, status::BAD_PARAMS),
            _ => panic!(),
        }
    }

    #[test]
    fn coding_set_then_list_roundtrip() {
        let stub = StubHandler::new();
        let handler: Arc<dyn CodingHandler> = stub.clone();
        let prefix: Name = "/alice/video".parse().unwrap();
        let params = set_params(&prefix, 16, 20, fr_role::PRODUCED);
        let resp = handle_coding(verb::SET, params, Some(&handler));
        match resp {
            MgmtResponse::Control(cr) => assert_eq!(cr.status_code, status::OK),
            _ => panic!(),
        }
        let resp = handle_coding(verb::LIST, ControlParameters::default(), Some(&handler));
        let bytes = match resp {
            MgmtResponse::Dataset(b) => b,
            _ => panic!("expected dataset"),
        };
        let cp = ControlParameters::decode(bytes).expect("decode listed entry");
        assert_eq!(cp.name.as_ref(), Some(&prefix));
        assert_eq!(cp.fec_k, Some(16));
        assert_eq!(cp.fec_n, Some(20));
        assert_eq!(cp.fec_role, Some(fr_role::PRODUCED));
    }

    #[test]
    fn coding_unset_removes_entry() {
        let stub = StubHandler::new();
        let handler: Arc<dyn CodingHandler> = stub.clone();
        let prefix: Name = "/x".parse().unwrap();
        handle_coding(
            verb::SET,
            set_params(&prefix, 4, 6, fr_role::PRODUCED),
            Some(&handler),
        );
        assert_eq!(stub.list().len(), 1);
        let unset = ControlParameters {
            name: Some(prefix.clone()),
            fec_role: Some(fr_role::PRODUCED),
            ..Default::default()
        };
        handle_coding(verb::UNSET, unset, Some(&handler));
        assert_eq!(stub.list().len(), 0);
    }

    #[test]
    fn coding_unknown_verb_returns_404() {
        let handler: Arc<dyn CodingHandler> = StubHandler::new();
        let resp = handle_coding(b"frobnicate", ControlParameters::default(), Some(&handler));
        match resp {
            MgmtResponse::Control(cr) => assert_eq!(cr.status_code, status::NOT_FOUND),
            _ => panic!(),
        }
    }

    /// A wire-form command name parses back to the coding module/verb.
    #[test]
    fn coding_command_name_parses_into_module_coding() {
        use ndn_mgmt_wire::nfd_command::{command_name, module, parse_command_name};
        let prefix: Name = "/alice/video".parse().unwrap();
        let params = set_params(&prefix, 16, 20, fr_role::PRODUCED);
        let cmd_name = command_name(module::CODING, verb::SET, &params);
        let parsed = parse_command_name(&cmd_name).expect("parses");
        assert_eq!(parsed.module.as_ref(), b"coding");
        assert_eq!(parsed.verb.as_ref(), b"set");
        let p = parsed.params.expect("params present");
        assert_eq!(p.fec_k, Some(16));
        assert_eq!(p.fec_n, Some(20));
        assert_eq!(p.fec_role, Some(fr_role::PRODUCED));
    }
}
