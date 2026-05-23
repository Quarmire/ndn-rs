//! `/localhost/nfd/ble/{list, start, stop}` — BLE peripheral listener control
//! and status. Backend is the host's [`crate::BleMgmtBackend`] (in `ndn-fwd`,
//! over [`ndn_faces::l2::BleListener`]). The central role is reached via
//! `faces/create ble://<addr>`, not this module.

use std::sync::Arc;

use async_trait::async_trait;

use ndn_config::{
    ControlParameters, ControlResponse,
    control_response::status,
    nfd_command::{module, verb},
};

use crate::module::{MgmtContext, MgmtModule};
use crate::{BleMgmtBackend, MgmtResponse};

async fn handle_ble(verb_name: &[u8], handler: Option<&Arc<dyn BleMgmtBackend>>) -> MgmtResponse {
    let Some(handler) = handler else {
        return ControlResponse::error(
            status::NOT_FOUND,
            "ble module not wired (build the forwarder with --features bluetooth)",
        )
        .into();
    };
    match verb_name {
        v if v == verb::LIST => {
            let s = handler.status().await;
            let text = format!(
                "supported={} advertising={} adapter={} centrals={}",
                s.supported,
                s.advertising,
                s.adapter.as_deref().unwrap_or("-"),
                s.connected_centrals,
            );
            ControlResponse::ok(text, ControlParameters::default()).into()
        }
        v if v == verb::START => match handler.start().await {
            Ok(()) => ControlResponse::ok("advertising", ControlParameters::default()).into(),
            Err(e) => ControlResponse::error(status::SERVER_ERROR, e).into(),
        },
        v if v == verb::STOP => match handler.stop().await {
            Ok(()) => ControlResponse::ok("stopped", ControlParameters::default()).into(),
            Err(e) => ControlResponse::error(status::SERVER_ERROR, e).into(),
        },
        _ => ControlResponse::error(status::NOT_FOUND, "unknown ble verb").into(),
    }
}

pub(crate) struct BleModule;

#[async_trait]
impl MgmtModule for BleModule {
    fn name(&self) -> &'static [u8] {
        module::BLE
    }

    async fn dispatch(
        &self,
        verb: &[u8],
        _params: ControlParameters,
        ctx: &MgmtContext<'_>,
    ) -> MgmtResponse {
        handle_ble(verb, ctx.ble_handler).await
    }
}
