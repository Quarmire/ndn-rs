//! `/localhost/nfd/neighbors/list` — discovered-neighbour table dump.
//!
//! Native-only — pulls in `ndn-discovery::NeighborState`.

use async_trait::async_trait;
use ndn_config::{
    ControlParameters, ControlResponse,
    control_response::status,
    nfd_command::{module, verb},
};
use ndn_discovery::NeighborState;
use ndn_engine::ForwarderEngine;

use crate::MgmtResponse;
use crate::module::{MgmtContext, MgmtModule};

fn handle_neighbors(verb_name: &[u8], engine: &ForwarderEngine) -> ControlResponse {
    match verb_name {
        v if v == verb::LIST => neighbors_list(engine),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown neighbors verb"),
    }
}

fn neighbors_list(engine: &ForwarderEngine) -> ControlResponse {
    let entries = engine.neighbors().all();
    let mut text = format!("{} neighbors\n", entries.len());
    for e in &entries {
        let face_ids: Vec<String> = e.faces.iter().map(|(id, _, _)| id.0.to_string()).collect();
        let state_str = match &e.state {
            NeighborState::Established { last_seen } => {
                let age_s = last_seen.elapsed().as_secs_f64();
                format!("state=Established  last_seen={:.1}s ago", age_s)
            }
            NeighborState::Stale {
                miss_count,
                last_seen,
            } => {
                let age_s = last_seen.elapsed().as_secs_f64();
                format!(
                    "state=Stale  miss={}  last_seen={:.1}s ago",
                    miss_count, age_s
                )
            }
            NeighborState::Probing { attempts, .. } => {
                format!("state=Probing  attempts={}", attempts)
            }
            NeighborState::Absent => "state=Absent".to_string(),
        };
        let rtt_str = match e.rtt_us {
            Some(us) => format!("  rtt={}us", us),
            None => "  rtt=None".to_string(),
        };
        text.push_str(&format!(
            "  {}  {}{}  faces=[{}]\n",
            e.node_name,
            state_str,
            rtt_str,
            face_ids.join(","),
        ));
    }
    ControlResponse::ok_empty(text)
}

pub(crate) struct NeighborsModule;

#[async_trait]
impl MgmtModule for NeighborsModule {
    fn name(&self) -> &'static [u8] {
        module::NEIGHBORS
    }

    async fn dispatch(
        &self,
        verb: &[u8],
        _params: ControlParameters,
        ctx: &MgmtContext<'_>,
    ) -> MgmtResponse {
        handle_neighbors(verb, ctx.engine).into()
    }
}
