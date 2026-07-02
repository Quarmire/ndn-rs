//! `/localhost/nfd/cs/{config, info, erase}` — content store.

use async_trait::async_trait;
use ndn_engine::ForwarderEngine;
use ndn_mgmt_wire::{
    ControlParameters, ControlResponse,
    control_response::status,
    nfd_command::{module, verb},
};

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

// NFD `CsFlagBit` (ndn-cxx nfd-constants.hpp): admit gates insertion, serve
// gates satisfying Interests from cache.
const BIT_CS_ENABLE_ADMIT: u64 = 1 << 0;
const BIT_CS_ENABLE_SERVE: u64 = 1 << 1;

fn cs_config(params: ControlParameters, engine: &ForwarderEngine) -> ControlResponse {
    let cs = engine.cs();

    if let Some(new_cap) = params.capacity {
        cs.set_capacity(new_cap as usize);
        tracing::info!(target: "mgmt.cs", capacity = new_cap, "cs capacity updated");
    }

    // Admit/Serve flags, Flags+Mask shaped like faces/update (NFD CsManager).
    if let (Some(flags), Some(mask)) = (params.flags, params.mask) {
        if mask & BIT_CS_ENABLE_ADMIT != 0 {
            cs.set_admit(flags & BIT_CS_ENABLE_ADMIT != 0);
        }
        if mask & BIT_CS_ENABLE_SERVE != 0 {
            cs.set_serve(flags & BIT_CS_ENABLE_SERVE != 0);
        }
    }

    let cap = cs.capacity();
    let mut flags = 0u64;
    if cs.admit_enabled() {
        flags |= BIT_CS_ENABLE_ADMIT;
    }
    if cs.serve_enabled() {
        flags |= BIT_CS_ENABLE_SERVE;
    }
    let echo = ControlParameters {
        capacity: Some(cap.max_bytes as u64),
        flags: Some(flags),
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
