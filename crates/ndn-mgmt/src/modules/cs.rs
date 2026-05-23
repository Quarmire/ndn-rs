//! `/localhost/nfd/cs/{config, info, erase}` — content store.

use async_trait::async_trait;
use ndn_config::{
    ControlParameters, ControlResponse,
    control_response::status,
    nfd_command::{module, verb},
};
use ndn_engine::ForwarderEngine;

use crate::MgmtResponse;
use crate::module::{MgmtContext, MgmtModule};

async fn handle_cs(
    verb_name: &[u8],
    params: ControlParameters,
    engine: &ForwarderEngine,
) -> ControlResponse {
    match verb_name {
        v if v == verb::CONFIG => cs_config(params, engine),
        v if v == verb::INFO => cs_info(engine),
        v if v == verb::ERASE => cs_erase(params, engine).await,
        _ => ControlResponse::error(status::NOT_FOUND, "unknown cs verb"),
    }
}

fn cs_config(params: ControlParameters, engine: &ForwarderEngine) -> ControlResponse {
    let cs = engine.cs();

    if let Some(new_cap) = params.capacity {
        cs.set_capacity(new_cap as usize);
        tracing::info!(target: "mgmt.cs", capacity = new_cap, "cs capacity updated");
    }

    let cap = cs.capacity();
    let echo = ControlParameters {
        capacity: Some(cap.max_bytes as u64),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn cs_info(engine: &ForwarderEngine) -> ControlResponse {
    let cs = engine.cs();
    let cap = cs.capacity();
    let n_entries = cs.len();
    let current = cs.current_bytes();
    let stats = cs.stats();
    let variant = cs.variant_name();

    let text = format!(
        "capacity={}B entries={} used={}B hits={} misses={} variant={}",
        cap.max_bytes, n_entries, current, stats.hits, stats.misses, variant,
    );
    ControlResponse::ok_empty(text)
}

async fn cs_erase(params: ControlParameters, engine: &ForwarderEngine) -> ControlResponse {
    let Some(ref name) = params.name else {
        return ControlResponse::error(status::BAD_PARAMS, "missing Name parameter");
    };
    let cs = engine.cs();
    let limit = params.count.map(|c| c as usize);
    let erased = cs.evict_prefix_erased(name, limit).await;

    let echo = ControlParameters {
        name: params.name,
        count: Some(erased as u64),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

pub(crate) struct CsModule;

#[async_trait]
impl MgmtModule for CsModule {
    fn name(&self) -> &'static [u8] {
        module::CS
    }

    async fn dispatch(
        &self,
        verb: &[u8],
        params: ControlParameters,
        ctx: &MgmtContext<'_>,
    ) -> MgmtResponse {
        handle_cs(verb, params, ctx.engine).await.into()
    }
}
