//! `/localhost/nfd/measurements/list` — per-prefix RTT + satisfaction.

use async_trait::async_trait;
use ndn_mgmt_wire::{
    ControlParameters, ControlResponse,
    control_response::status,
    nfd_command::{module, verb},
};
use ndn_engine::ForwarderEngine;

use crate::MgmtResponse;
use crate::module::{MgmtContext, MgmtModule};

fn handle_measurements(verb_name: &[u8], engine: &ForwarderEngine) -> ControlResponse {
    match verb_name {
        v if v == verb::LIST => measurements_list(engine),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown measurements verb"),
    }
}

fn measurements_list(engine: &ForwarderEngine) -> ControlResponse {
    let entries = engine.measurements().dump();
    let mut text = format!("{} entries\n", entries.len());
    for (prefix, entry) in &entries {
        let face_rtts: Vec<String> = entry
            .rtt_per_face
            .iter()
            .map(|(fid, rtt)| format!("face{}={:.1}ms", fid.0, rtt.srtt_ns / 1_000_000.0))
            .collect();
        text.push_str(&format!(
            "  prefix={} sat_rate={:.3} rtt=[{}]\n",
            prefix,
            entry.satisfaction_rate,
            face_rtts.join(" "),
        ));
    }
    ControlResponse::ok_empty(text)
}

pub(crate) struct MeasurementsModule;

#[async_trait]
impl MgmtModule for MeasurementsModule {
    fn name(&self) -> &'static [u8] {
        module::MEASUREMENTS
    }

    async fn dispatch(
        &self,
        verb: &[u8],
        _params: ControlParameters,
        ctx: &MgmtContext<'_>,
    ) -> MgmtResponse {
        handle_measurements(verb, ctx.engine).into()
    }
}
