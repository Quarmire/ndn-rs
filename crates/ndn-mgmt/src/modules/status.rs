//! `/localhost/nfd/status/*` — general counters + shutdown.

use async_trait::async_trait;
use ndn_config::{
    ControlParameters, ControlResponse, control_response::status, nfd_command::module,
};
use ndn_engine::ForwarderEngine;
use tokio_util::sync::CancellationToken;

use crate::MgmtResponse;
use crate::module::{MgmtContext, MgmtModule};

fn handle_status(
    verb_name: &[u8],
    engine: &ForwarderEngine,
    cancel: &CancellationToken,
) -> ControlResponse {
    match verb_name {
        b"general" => {
            let n_faces = engine.faces().face_entries().len();
            let n_fib = engine.fib().dump().len();
            let n_pit = engine.pit().len();
            let n_cs = engine.cs().len();

            let text = format!("faces={n_faces} fib={n_fib} pit={n_pit} cs={n_cs}");
            ControlResponse::ok_empty(text)
        }
        b"shutdown" => {
            tracing::info!(target: "engine", "status/shutdown requested");
            cancel.cancel();
            ControlResponse::ok_empty("OK")
        }
        _ => ControlResponse::error(status::NOT_FOUND, "unknown status verb"),
    }
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
        handle_status(verb, ctx.engine, ctx.cancel).into()
    }
}
