//! `/localhost/nfd/config/get` — TOML config dump.

use async_trait::async_trait;
use ndn_config::{
    ControlParameters, ControlResponse,
    control_response::status,
    nfd_command::{module, verb},
};

use crate::MgmtResponse;
use crate::module::{MgmtContext, MgmtModule};

fn handle_config(verb_name: &[u8], config: &ndn_config::ForwarderConfig) -> ControlResponse {
    match verb_name {
        v if v == verb::GET => config_get(config),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown config verb"),
    }
}

fn config_get(config: &ndn_config::ForwarderConfig) -> ControlResponse {
    match config.to_toml_string() {
        Ok(toml) => ControlResponse::ok_empty(toml),
        Err(e) => ControlResponse::error(status::SERVER_ERROR, e.to_string()),
    }
}

pub(crate) struct ConfigModule;

#[async_trait]
impl MgmtModule for ConfigModule {
    fn name(&self) -> &'static [u8] {
        module::CONFIG
    }

    async fn dispatch(
        &self,
        verb: &[u8],
        _params: ControlParameters,
        ctx: &MgmtContext<'_>,
    ) -> MgmtResponse {
        handle_config(verb, ctx.config).into()
    }
}
