//! `/localhost/nfd/log/*` — tracing module discovery, recent log
//! tail, and filter get/set.

use async_trait::async_trait;
use ndn_mgmt_wire::{
    ControlParameters, ControlResponse,
    control_response::status,
    nfd_command::{module, verb},
};

use crate::module::{MgmtContext, MgmtModule};
use crate::{LogInspector, MgmtResponse};

fn handle_log(
    verb_name: &[u8],
    params: ControlParameters,
    log_inspector: Option<&LogInspector>,
) -> ControlResponse {
    match verb_name {
        v if v == verb::MODULES => {
            let body = ndn_engine::observability::targets::enumerate().join("\n");
            ControlResponse::ok_empty(body)
        }
        v if v == verb::GET_RECENT => {
            let after_seq = params.count.unwrap_or(0);
            let body = log_inspector
                .and_then(|li| li.ring.lock().ok())
                .map(|g| {
                    let max_seq = g.back().map(|(s, _)| *s).unwrap_or(0);
                    let mut out = max_seq.to_string();
                    for (seq, line) in g.iter() {
                        if *seq > after_seq {
                            out.push('\n');
                            out.push_str(line);
                        }
                    }
                    out
                })
                .unwrap_or_else(|| "0".to_string());
            ControlResponse::ok_empty(body)
        }
        v if v == verb::GET_FILTER => {
            let filter = log_inspector
                .and_then(|li| li.filter.lock().ok())
                .map(|g| g.clone())
                .unwrap_or_default();
            ControlResponse::ok_empty(filter)
        }
        v if v == verb::SET_FILTER => {
            let filter_str = params.uri.clone().unwrap_or_default();
            if filter_str.is_empty() {
                return ControlResponse::error(
                    status::BAD_PARAMS,
                    "uri field must contain the filter string",
                );
            }
            if let Some(li) = log_inspector {
                (li.apply_filter)(&filter_str);
                tracing::info!(target: "mgmt.log", filter = %filter_str, "log/set-filter: filter updated");
                ControlResponse::ok_empty(filter_str)
            } else {
                ControlResponse::error(status::NOT_FOUND, "filter reload not initialised")
            }
        }
        _ => ControlResponse::error(status::NOT_FOUND, "unknown log verb"),
    }
}

pub(crate) struct LogModule;

#[async_trait]
impl MgmtModule for LogModule {
    fn name(&self) -> &'static [u8] {
        module::LOG
    }

    async fn dispatch(
        &self,
        verb: &[u8],
        params: ControlParameters,
        ctx: &MgmtContext<'_>,
    ) -> MgmtResponse {
        handle_log(verb, params, ctx.log_inspector).into()
    }
}
