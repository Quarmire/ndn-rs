//! `/localhost/nfd/service/{list, browse, announce, withdraw}` —
//! ndn-rs ANNOUNCE/WITHDRAW/BROWSE surface (native only).

use async_trait::async_trait;

use ndn_config::{
    ControlParameters, ControlResponse,
    control_response::status,
    nfd_command::{module, verb},
};
use ndn_discovery::{ServiceDiscoveryProtocol, ServiceRecord};
use ndn_engine::ForwarderEngine;
use ndn_packet::Name;
use ndn_transport::FaceId;

use super::common::{is_management_face, is_reserved_name};
use crate::MgmtResponse;
use crate::module::{MgmtContext, MgmtModule};

fn handle_service(
    verb_name: &[u8],
    params: ControlParameters,
    engine: &ForwarderEngine,
    source_face: Option<FaceId>,
    discovery_sd: Option<&ServiceDiscoveryProtocol>,
    discovery_claimed: &[Name],
) -> ControlResponse {
    let sd = match discovery_sd {
        Some(s) => s,
        None => {
            return ControlResponse::error(status::NOT_FOUND, "service discovery is not enabled");
        }
    };
    match verb_name {
        v if v == verb::LIST => service_list(sd),
        v if v == verb::BROWSE => service_browse(params, sd),
        v if v == verb::ANNOUNCE => {
            service_announce(params, sd, engine, source_face, discovery_claimed)
        }
        v if v == verb::WITHDRAW => service_withdraw(params, sd),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown service verb"),
    }
}

fn service_list(sd: &ServiceDiscoveryProtocol) -> ControlResponse {
    let records = sd.local_records();
    let mut text = format!("{} services\n", records.len());
    for r in &records {
        text.push_str(&format!(
            "  {}  node={}  freshness={}ms\n",
            r.announced_prefix, r.node_name, r.freshness_ms,
        ));
    }
    ControlResponse::ok_empty(text)
}

fn service_browse(params: ControlParameters, sd: &ServiceDiscoveryProtocol) -> ControlResponse {
    let filter = params.name;
    let records = sd.all_records();
    let filtered: Vec<_> = records
        .iter()
        .filter(|r| {
            filter
                .as_ref()
                .is_none_or(|p| r.announced_prefix.has_prefix(p))
        })
        .collect();
    let mut text = format!("{} services\n", filtered.len());
    for r in &filtered {
        text.push_str(&format!(
            "  {}  node={}  freshness={}ms\n",
            r.announced_prefix, r.node_name, r.freshness_ms,
        ));
    }
    ControlResponse::ok_empty(text)
}

fn service_announce(
    params: ControlParameters,
    sd: &ServiceDiscoveryProtocol,
    engine: &ForwarderEngine,
    source_face: Option<FaceId>,
    discovery_claimed: &[Name],
) -> ControlResponse {
    let prefix = match params.name {
        Some(n) => n,
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };

    if !is_management_face(source_face, engine) {
        let shadows_discovery = discovery_claimed
            .iter()
            .any(|cp| prefix.has_prefix(cp) || cp.has_prefix(&prefix));
        if shadows_discovery {
            return ControlResponse::error(
                status::UNAUTHORIZED,
                format!("prefix {prefix} overlaps with a discovery-owned namespace"),
            );
        }
    }

    if is_reserved_name(&prefix) && !is_management_face(source_face, engine) {
        return ControlResponse::error(
            status::UNAUTHORIZED,
            format!("prefix {prefix} is reserved for operator use"),
        );
    }

    let node_name = sd
        .local_records()
        .into_iter()
        .next()
        .map(|r| r.node_name)
        .unwrap_or_else(|| prefix.clone());

    let record = ServiceRecord::new(prefix.clone(), node_name);
    let owner_face = engine.fib().lpm(&prefix).and_then(|e| {
        e.nexthops_excluding(source_face.unwrap_or(FaceId::INVALID))
            .into_iter()
            .next()
            .map(|nh| nh.face_id)
    });

    if let Some(face) = owner_face {
        sd.publish_with_owner(record, face);
        tracing::info!(target: "discovery", prefix = %prefix, owner_face = ?face, "service/announce (owned by face)");
    } else {
        sd.publish(record);
        tracing::info!(target: "discovery", prefix = %prefix, "service/announce (permanent — no FIB route found)");
    }

    let echo = ControlParameters {
        name: Some(prefix),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn service_withdraw(params: ControlParameters, sd: &ServiceDiscoveryProtocol) -> ControlResponse {
    let prefix = match params.name {
        Some(n) => n,
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };

    sd.withdraw(&prefix);
    tracing::info!(target: "discovery", prefix = %prefix, "service/withdraw");

    let echo = ControlParameters {
        name: Some(prefix),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

pub(crate) struct ServiceModule;

#[async_trait]
impl MgmtModule for ServiceModule {
    fn name(&self) -> &'static [u8] {
        module::SERVICE
    }

    async fn dispatch(
        &self,
        verb: &[u8],
        params: ControlParameters,
        ctx: &MgmtContext<'_>,
    ) -> MgmtResponse {
        handle_service(
            verb,
            params,
            ctx.engine,
            ctx.source_face,
            ctx.discovery_sd,
            ctx.discovery_claimed,
        )
        .into()
    }
}
