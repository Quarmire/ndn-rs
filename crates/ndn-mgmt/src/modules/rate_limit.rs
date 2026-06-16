//! `/localhost/nfd/rate-limit/{set, unset, list}` — token-bucket
//! limiter table; backend is `ndn-ratelimit::RateLimitMgmtHandler`.

use std::sync::Arc;

use async_trait::async_trait;

use ndn_config::{
    ControlParameters, ControlResponse,
    control_response::status,
    nfd_command::{module, verb},
};
#[cfg(test)]
use ndn_packet::Name;

#[cfg(test)]
use crate::RateLimitWireListed;
use crate::module::{MgmtContext, MgmtModule};
use crate::{
    MgmtResponse, RateLimitDirection, RateLimitMgmtBackend, RateLimitOverflow, RateLimitWireEntry,
    RateLimitWireKey,
};

fn handle_rate_limit(
    verb_name: &[u8],
    params: ControlParameters,
    handler: Option<&Arc<dyn RateLimitMgmtBackend>>,
) -> MgmtResponse {
    let Some(handler) = handler else {
        return ControlResponse::error(
            status::NOT_FOUND,
            "rate-limit module not wired (no backend installed)",
        )
        .into();
    };
    match verb_name {
        v if v == verb::SET => rate_limit_set(params, handler.as_ref()).into(),
        v if v == verb::UNSET => rate_limit_unset(params, handler.as_ref()).into(),
        v if v == verb::LIST => MgmtResponse::Dataset(rate_limit_list_dataset(handler.as_ref())),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown rate-limit verb").into(),
    }
}

fn parse_rl_direction(code: Option<u8>) -> Option<RateLimitDirection> {
    match code? {
        c if c == ndn_mgmt_wire::control_parameters::rl_direction::INBOUND => {
            Some(RateLimitDirection::Inbound)
        }
        c if c == ndn_mgmt_wire::control_parameters::rl_direction::OUTBOUND => {
            Some(RateLimitDirection::Outbound)
        }
        _ => None,
    }
}

fn parse_rl_overflow(code: Option<u8>) -> Option<RateLimitOverflow> {
    match code? {
        c if c == ndn_mgmt_wire::control_parameters::rl_overflow::NACK => {
            Some(RateLimitOverflow::Nack)
        }
        c if c == ndn_mgmt_wire::control_parameters::rl_overflow::DROP => {
            Some(RateLimitOverflow::Drop)
        }
        c if c == ndn_mgmt_wire::control_parameters::rl_overflow::QUEUE => {
            Some(RateLimitOverflow::Queue)
        }
        _ => None,
    }
}

fn rl_direction_to_wire(d: RateLimitDirection) -> u8 {
    match d {
        RateLimitDirection::Inbound => ndn_mgmt_wire::control_parameters::rl_direction::INBOUND,
        RateLimitDirection::Outbound => ndn_mgmt_wire::control_parameters::rl_direction::OUTBOUND,
    }
}

fn rl_overflow_to_wire(o: RateLimitOverflow) -> u8 {
    match o {
        RateLimitOverflow::Nack => ndn_mgmt_wire::control_parameters::rl_overflow::NACK,
        RateLimitOverflow::Drop => ndn_mgmt_wire::control_parameters::rl_overflow::DROP,
        RateLimitOverflow::Queue => ndn_mgmt_wire::control_parameters::rl_overflow::QUEUE,
    }
}

fn rate_limit_set(
    params: ControlParameters,
    handler: &dyn RateLimitMgmtBackend,
) -> ControlResponse {
    let Some(direction) = parse_rl_direction(params.rl_direction) else {
        return ControlResponse::error(status::BAD_PARAMS, "valid RlDirection is required");
    };
    let Some(overflow) = parse_rl_overflow(params.rl_overflow) else {
        return ControlResponse::error(status::BAD_PARAMS, "valid RlOverflow is required");
    };
    if params.rl_interest_pps.is_none() && params.rl_data_bps.is_none() {
        return ControlResponse::error(
            status::BAD_PARAMS,
            "at least one of RlInterestPps / RlDataBps must be set",
        );
    }
    if matches!(overflow, RateLimitOverflow::Queue) && params.rl_queue_max.is_none() {
        return ControlResponse::error(
            status::BAD_PARAMS,
            "RlQueueMax is required when overflow = queue",
        );
    }
    let entry = RateLimitWireEntry {
        face_id: params.face_id,
        direction,
        interest_pps: params.rl_interest_pps,
        interest_burst: params.rl_interest_burst,
        data_bps: params.rl_data_bps,
        data_burst_bytes: params.rl_data_burst_bytes,
        overflow,
        queue_max: params.rl_queue_max,
    };
    if let Err(msg) = handler.set(params.name.as_ref(), entry.clone()) {
        return ControlResponse::error(status::SERVER_ERROR, msg);
    }
    tracing::info!(
        target: "mgmt.rate_limit",
        prefix = ?params.name,
        face = ?entry.face_id,
        direction = ?direction,
        overflow = ?overflow,
        "rate-limit/set"
    );
    let echo = ControlParameters {
        name: params.name,
        face_id: params.face_id,
        rl_direction: Some(rl_direction_to_wire(direction)),
        rl_interest_pps: entry.interest_pps,
        rl_interest_burst: entry.interest_burst,
        rl_data_bps: entry.data_bps,
        rl_data_burst_bytes: entry.data_burst_bytes,
        rl_overflow: Some(rl_overflow_to_wire(overflow)),
        rl_queue_max: entry.queue_max,
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn rate_limit_unset(
    params: ControlParameters,
    handler: &dyn RateLimitMgmtBackend,
) -> ControlResponse {
    let Some(direction) = parse_rl_direction(params.rl_direction) else {
        return ControlResponse::error(status::BAD_PARAMS, "valid RlDirection is required");
    };
    let key = RateLimitWireKey {
        face_id: params.face_id,
        direction,
    };
    if let Err(msg) = handler.unset(params.name.as_ref(), key) {
        return ControlResponse::error(status::SERVER_ERROR, msg);
    }
    tracing::info!(
        target: "mgmt.rate_limit",
        prefix = ?params.name,
        face = ?params.face_id,
        direction = ?direction,
        "rate-limit/unset"
    );
    let echo = ControlParameters {
        name: params.name,
        face_id: params.face_id,
        rl_direction: Some(rl_direction_to_wire(direction)),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn rate_limit_list_dataset(handler: &dyn RateLimitMgmtBackend) -> bytes::Bytes {
    let mut buf = bytes::BytesMut::new();
    for row in handler.list() {
        let cp = ControlParameters {
            name: row.prefix,
            face_id: row.entry.face_id,
            rl_direction: Some(rl_direction_to_wire(row.entry.direction)),
            rl_interest_pps: row.entry.interest_pps,
            rl_interest_burst: row.entry.interest_burst,
            rl_data_bps: row.entry.data_bps,
            rl_data_burst_bytes: row.entry.data_burst_bytes,
            rl_overflow: Some(rl_overflow_to_wire(row.entry.overflow)),
            rl_queue_max: row.entry.queue_max,
            count: Some(row.overflow_events),
            ..Default::default()
        };
        buf.extend_from_slice(&cp.encode());
    }
    buf.freeze()
}

pub(crate) struct RateLimitModule;

#[async_trait]
impl MgmtModule for RateLimitModule {
    fn name(&self) -> &'static [u8] {
        module::RATE_LIMIT
    }

    async fn dispatch(
        &self,
        verb: &[u8],
        params: ControlParameters,
        ctx: &MgmtContext<'_>,
    ) -> MgmtResponse {
        handle_rate_limit(verb, params, ctx.rate_limit_handler)
    }
}
#[cfg(test)]
mod rate_limit_tests {
    use super::*;
    use ndn_mgmt_wire::control_parameters::{rl_direction as rd, rl_overflow as ro};
    use std::sync::Mutex;

    struct StubBackend {
        entries: Mutex<Vec<(Option<Name>, RateLimitWireEntry)>>,
    }

    impl StubBackend {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                entries: Mutex::new(Vec::new()),
            })
        }
    }

    impl RateLimitMgmtBackend for StubBackend {
        fn set(&self, prefix: Option<&Name>, entry: RateLimitWireEntry) -> Result<(), String> {
            if entry.interest_pps.is_none() && entry.data_bps.is_none() {
                return Err("empty bucket".into());
            }
            let mut g = self.entries.lock().unwrap();
            let prefix = prefix.cloned();
            g.retain(|(p, e)| {
                !(p == &prefix && e.face_id == entry.face_id && e.direction == entry.direction)
            });
            g.push((prefix, entry));
            Ok(())
        }
        fn unset(&self, prefix: Option<&Name>, key: RateLimitWireKey) -> Result<(), String> {
            let mut g = self.entries.lock().unwrap();
            let prefix = prefix.cloned();
            g.retain(|(p, e)| {
                !(p == &prefix && e.face_id == key.face_id && e.direction == key.direction)
            });
            Ok(())
        }
        fn list(&self) -> Vec<RateLimitWireListed> {
            self.entries
                .lock()
                .unwrap()
                .iter()
                .cloned()
                .map(|(prefix, entry)| RateLimitWireListed {
                    prefix,
                    entry,
                    overflow_events: 0,
                })
                .collect()
        }
    }

    fn set_params(face_id: Option<u64>, prefix: Option<Name>) -> ControlParameters {
        ControlParameters {
            name: prefix,
            face_id,
            rl_direction: Some(rd::INBOUND),
            rl_interest_pps: Some(100),
            rl_interest_burst: Some(200),
            rl_overflow: Some(ro::NACK),
            ..Default::default()
        }
    }

    #[test]
    fn rate_limit_returns_404_when_no_backend() {
        let resp = handle_rate_limit(verb::SET, ControlParameters::default(), None);
        match resp {
            MgmtResponse::Control(cr) => assert_eq!(cr.status_code, status::NOT_FOUND),
            _ => panic!(),
        }
    }

    #[test]
    fn rate_limit_set_requires_direction() {
        let backend: Arc<dyn RateLimitMgmtBackend> = StubBackend::new();
        let params = ControlParameters {
            rl_interest_pps: Some(10),
            rl_overflow: Some(ro::NACK),
            ..Default::default()
        };
        let resp = handle_rate_limit(verb::SET, params, Some(&backend));
        match resp {
            MgmtResponse::Control(cr) => assert_eq!(cr.status_code, status::BAD_PARAMS),
            _ => panic!(),
        }
    }

    #[test]
    fn rate_limit_set_requires_at_least_one_limit() {
        let backend: Arc<dyn RateLimitMgmtBackend> = StubBackend::new();
        let params = ControlParameters {
            rl_direction: Some(rd::INBOUND),
            rl_overflow: Some(ro::NACK),
            ..Default::default()
        };
        let resp = handle_rate_limit(verb::SET, params, Some(&backend));
        match resp {
            MgmtResponse::Control(cr) => assert_eq!(cr.status_code, status::BAD_PARAMS),
            _ => panic!(),
        }
    }

    #[test]
    fn rate_limit_set_then_list_roundtrip() {
        let stub = StubBackend::new();
        let backend: Arc<dyn RateLimitMgmtBackend> = stub.clone();
        let prefix: Name = "/alice/video".parse().unwrap();
        let params = set_params(Some(7), Some(prefix.clone()));
        let resp = handle_rate_limit(verb::SET, params, Some(&backend));
        match resp {
            MgmtResponse::Control(cr) => assert_eq!(cr.status_code, status::OK),
            _ => panic!(),
        }
        let resp = handle_rate_limit(verb::LIST, ControlParameters::default(), Some(&backend));
        let bytes = match resp {
            MgmtResponse::Dataset(b) => b,
            _ => panic!(),
        };
        let cp = ControlParameters::decode(bytes).unwrap();
        assert_eq!(cp.name, Some(prefix));
        assert_eq!(cp.face_id, Some(7));
        assert_eq!(cp.rl_direction, Some(rd::INBOUND));
        assert_eq!(cp.rl_interest_pps, Some(100));
        assert_eq!(cp.rl_overflow, Some(ro::NACK));
    }

    #[test]
    fn rate_limit_unset_removes_entry() {
        let stub = StubBackend::new();
        let backend: Arc<dyn RateLimitMgmtBackend> = stub.clone();
        let prefix: Name = "/x".parse().unwrap();
        handle_rate_limit(
            verb::SET,
            set_params(Some(1), Some(prefix.clone())),
            Some(&backend),
        );
        assert_eq!(stub.list().len(), 1);
        let unset = ControlParameters {
            face_id: Some(1),
            name: Some(prefix),
            rl_direction: Some(rd::INBOUND),
            ..Default::default()
        };
        handle_rate_limit(verb::UNSET, unset, Some(&backend));
        assert_eq!(stub.list().len(), 0);
    }

    #[test]
    fn rate_limit_command_name_parses() {
        use ndn_mgmt_wire::nfd_command::{command_name, module, parse_command_name};
        let prefix: Name = "/alice".parse().unwrap();
        let params = set_params(Some(7), Some(prefix.clone()));
        let cmd_name = command_name(module::RATE_LIMIT, verb::SET, &params);
        let parsed = parse_command_name(&cmd_name).expect("parses");
        assert_eq!(parsed.module.as_ref(), b"rate-limit");
        assert_eq!(parsed.verb.as_ref(), b"set");
        let p = parsed.params.expect("params");
        assert_eq!(p.face_id, Some(7));
        assert_eq!(p.rl_direction, Some(rd::INBOUND));
        assert_eq!(p.rl_interest_pps, Some(100));
    }
}
