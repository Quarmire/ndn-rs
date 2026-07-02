//! `/localhost/nfd/routing/{list, disable, nlsr-*, dvr-*}` — running
//! routing-protocol status + runtime config (native only).

use async_trait::async_trait;

use ndn_engine::ForwarderEngine;
use ndn_mgmt_wire::{
    ControlParameters, ControlResponse,
    control_response::status,
    nfd_command::{module, verb},
};

use crate::MgmtResponse;
use crate::module::{MgmtContext, MgmtModule};

async fn handle_routing(
    verb_name: &[u8],
    params: ControlParameters,
    engine: &ForwarderEngine,
) -> ControlResponse {
    match verb_name {
        v if v == verb::LIST => routing_list(engine),
        v if v == b"disable" => routing_disable(params, engine).await,
        v if v == verb::DVR_STATUS => routing_render(
            engine,
            ndn_mgmt_wire::control_parameters::origin::DVR,
            "ndn-dv routing not running",
            |s| s.render_status("ndn-dv"),
        ),
        v if v == verb::NLSR_STATUS => routing_render(
            engine,
            ndn_mgmt_wire::control_parameters::origin::NLSR,
            "NLSR routing not running",
            |s| s.render_status("nlsr"),
        ),
        v if v == verb::NLSR_NEIGHBORS => routing_render(
            engine,
            ndn_mgmt_wire::control_parameters::origin::NLSR,
            "NLSR routing not running",
            |s| s.render_neighbors("nlsr"),
        ),
        v if v == verb::NLSR_LSDB => routing_render(
            engine,
            ndn_mgmt_wire::control_parameters::origin::NLSR,
            "NLSR routing not running",
            |s| s.render_lsdb("nlsr"),
        ),
        v if v == verb::DVR_CONFIG => routing_dvr_config(engine, &params),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown routing verb"),
    }
}

/// `routing/dvr-config`: empty `params.uri` dumps current config; non-empty
/// parses `key=value&...` via `ConfigUpdate::parse` and applies atomically.
fn routing_dvr_config(engine: &ForwarderEngine, params: &ControlParameters) -> ControlResponse {
    use ndn_engine::ConfigUpdate;

    let origin = ndn_mgmt_wire::control_parameters::origin::DVR;
    let Some(proto) = engine.routing().protocol(origin) else {
        return ControlResponse::error(status::NOT_FOUND, "DV routing not running");
    };
    let uri = params.uri.as_deref().unwrap_or("");
    if uri.is_empty() {
        return ControlResponse::ok_empty(proto.status().render_config("ndn-dv"));
    }
    let update = match ConfigUpdate::parse(uri) {
        Ok(u) => u,
        Err(e) => {
            return ControlResponse::error(
                status::BAD_PARAMS,
                format!("invalid dvr-config write: {e}"),
            );
        }
    };
    match proto.apply_config(&update) {
        Ok(n) => ControlResponse::ok_empty(format!(
            "applied {n} field(s); current config:\n{}",
            proto.status().render_config("ndn-dv"),
        )),
        Err(e) => {
            ControlResponse::error(status::BAD_PARAMS, format!("invalid dvr-config write: {e}"))
        }
    }
}

fn routing_render<F>(
    engine: &ForwarderEngine,
    origin: u64,
    not_running_msg: &str,
    render: F,
) -> ControlResponse
where
    F: Fn(&ndn_engine::RoutingProtocolStatus) -> String,
{
    match engine.routing().protocol(origin) {
        Some(proto) => {
            let snapshot = proto.status();
            let text = render(&snapshot);
            if text.trim().is_empty() {
                ControlResponse::ok_empty(format!(
                    "routing protocol origin={origin} is running but does not implement this verb\n",
                ))
            } else {
                ControlResponse::ok_empty(text)
            }
        }
        None => ControlResponse::error(status::NOT_FOUND, not_running_msg),
    }
}

fn routing_list(engine: &ForwarderEngine) -> ControlResponse {
    let origins = engine.routing().running_origins();
    let mut text = format!("{} routing protocol(s)\n", origins.len());
    let mut sorted = origins;
    sorted.sort_unstable();
    for origin in &sorted {
        let name = match *origin {
            ndn_mgmt_wire::control_parameters::origin::DVR => "dvr",
            ndn_mgmt_wire::control_parameters::origin::AUTOCONF => "autoconf",
            ndn_mgmt_wire::control_parameters::origin::NLSR => "nlsr",
            ndn_mgmt_wire::control_parameters::origin::PREFIX_ANN => "prefix-ann",
            ndn_mgmt_wire::control_parameters::origin::STATIC => "static",
            _ => "custom",
        };
        text.push_str(&format!("  origin={origin} ({name})\n"));
    }
    ControlResponse::ok_empty(text)
}

async fn routing_disable(params: ControlParameters, engine: &ForwarderEngine) -> ControlResponse {
    let origin = match params.origin {
        Some(o) => o,
        None => return ControlResponse::error(status::BAD_PARAMS, "Origin is required"),
    };
    if engine.routing().disable(origin).await {
        tracing::info!(target: "mgmt.rib", origin, "routing/disable");
        let echo = ControlParameters {
            origin: Some(origin),
            ..Default::default()
        };
        ControlResponse::ok("OK", echo)
    } else {
        ControlResponse::error(
            status::NOT_FOUND,
            format!("no protocol running with origin {origin}"),
        )
    }
}

pub(crate) struct RoutingModule;

#[async_trait]
impl MgmtModule for RoutingModule {
    fn name(&self) -> &'static [u8] {
        module::ROUTING
    }

    async fn dispatch(
        &self,
        verb: &[u8],
        params: ControlParameters,
        ctx: &MgmtContext<'_>,
    ) -> MgmtResponse {
        handle_routing(verb, params, ctx.engine).await.into()
    }
}
