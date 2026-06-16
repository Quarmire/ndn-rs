//! `/localhost/nfd/fib/{add-nexthop, remove-nexthop, list}` — direct
//! FIB manipulation (bypasses the RIB).

use async_trait::async_trait;
use ndn_mgmt_wire::{
    ControlParameters, ControlResponse,
    control_response::status,
    nfd_command::{module, verb},
    nfd_dataset,
};
use ndn_engine::ForwarderEngine;
use ndn_transport::FaceId;

use super::common::{is_management_face, is_reserved_name, resolve_face_id};
use crate::MgmtResponse;
use crate::module::{MgmtContext, MgmtModule};

fn handle_fib(
    verb_name: &[u8],
    params: ControlParameters,
    source_face: Option<FaceId>,
    engine: &ForwarderEngine,
) -> MgmtResponse {
    match verb_name {
        v if v == verb::ADD_NEXTHOP => fib_add_nexthop(params, source_face, engine).into(),
        v if v == verb::REMOVE_NEXTHOP => fib_remove_nexthop(params, source_face, engine).into(),
        v if v == verb::LIST => MgmtResponse::Dataset(fib_list_dataset(engine)),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown fib verb").into(),
    }
}

fn fib_add_nexthop(
    params: ControlParameters,
    source_face: Option<FaceId>,
    engine: &ForwarderEngine,
) -> ControlResponse {
    let name = match &params.name {
        Some(n) => n.clone(),
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };

    if is_reserved_name(&name) && !is_management_face(source_face, engine) {
        return ControlResponse::error(
            status::UNAUTHORIZED,
            format!("prefix {name} is reserved for operator use"),
        );
    }

    let face_id = match resolve_face_id(&params, source_face) {
        Ok(id) => id,
        Err(resp) => return *resp,
    };
    let cost = params.cost.unwrap_or(0) as u32;

    engine.fib().add_nexthop(&name, face_id, cost);
    tracing::info!(target: "mgmt.fib", prefix = %name, face = face_id.0, cost, "fib/add-nexthop");

    let echo = ControlParameters {
        name: Some(name),
        face_id: Some(face_id.0),
        cost: Some(cost as u64),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn fib_remove_nexthop(
    params: ControlParameters,
    source_face: Option<FaceId>,
    engine: &ForwarderEngine,
) -> ControlResponse {
    let name = match &params.name {
        Some(n) => n.clone(),
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };

    let face_id = match resolve_face_id(&params, source_face) {
        Ok(id) => id,
        Err(resp) => return *resp,
    };

    engine.fib().remove_nexthop(&name, face_id);
    tracing::info!(target: "mgmt.fib", prefix = %name, face = face_id.0, "fib/remove-nexthop");

    let echo = ControlParameters {
        name: Some(name),
        face_id: Some(face_id.0),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn fib_list_dataset(engine: &ForwarderEngine) -> bytes::Bytes {
    let routes = engine.fib().dump();
    let mut buf = bytes::BytesMut::new();
    for (name, entry) in &routes {
        let fib_entry = nfd_dataset::FibEntry {
            name: name.clone(),
            nexthops: entry
                .nexthops
                .iter()
                .map(|nh| nfd_dataset::NextHopRecord {
                    face_id: nh.face_id.0,
                    cost: nh.cost as u64,
                })
                .collect(),
        };
        buf.extend_from_slice(&fib_entry.encode());
    }
    buf.freeze()
}

pub(crate) struct FibModule;

#[async_trait]
impl MgmtModule for FibModule {
    fn name(&self) -> &'static [u8] {
        module::FIB
    }

    async fn dispatch(
        &self,
        verb: &[u8],
        params: ControlParameters,
        ctx: &MgmtContext<'_>,
    ) -> MgmtResponse {
        handle_fib(verb, params, ctx.source_face, ctx.engine)
    }
}
