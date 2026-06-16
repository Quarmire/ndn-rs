//! `/localhost/nfd/status/*` — NFD ForwarderStatus dataset + shutdown.

use async_trait::async_trait;
use ndn_mgmt_wire::{
    ControlParameters, ControlResponse, control_response::status, nfd_command::module,
};
use ndn_engine::ForwarderEngine;
use ndn_mgmt_wire::GeneralStatus;

use crate::MgmtResponse;
use crate::module::{MgmtContext, MgmtModule};

/// Build the spec NFD ForwarderStatus (GeneralStatus) dataset from live engine
/// state. Table counts are real; forwarder-wide packet counters are not yet
/// aggregated and are reported as 0 (the wire format is now spec-correct
/// regardless — see `ndn-mgmt-wire`).
fn general_status_dataset(engine: &ForwarderEngine) -> bytes::Bytes {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let status = GeneralStatus {
        nfd_version: format!("ndn-rs {}", env!("CARGO_PKG_VERSION")),
        start_timestamp_ms: engine.start_timestamp_ms(),
        current_timestamp_ms: now_ms,
        n_fib_entries: engine.fib().dump().len() as u64,
        n_pit_entries: engine.pit().len() as u64,
        n_cs_entries: engine.cs().len() as u64,
        ..Default::default()
    };
    status.encode()
}

pub(crate) struct StatusModule;

#[async_trait]
impl MgmtModule for StatusModule {
    fn name(&self) -> &'static [u8] {
        module::STATUS
    }

    async fn dispatch(
        &self,
        verb: &[u8],
        _params: ControlParameters,
        ctx: &MgmtContext<'_>,
    ) -> MgmtResponse {
        match verb {
            b"general" => MgmtResponse::Dataset(general_status_dataset(ctx.engine)),
            b"shutdown" => {
                tracing::info!(target: "engine", "status/shutdown requested");
                ctx.cancel.cancel();
                ControlResponse::ok_empty("OK").into()
            }
            _ => ControlResponse::error(status::NOT_FOUND, "unknown status verb").into(),
        }
    }
}
