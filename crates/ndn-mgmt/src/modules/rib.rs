//! `/localhost/nfd/rib/{register, unregister, list}` — application
//! route registration onto the engine RIB. Publishes `RouteEvent`s on
//! `/localhost/nfd/rib/notifications`.

use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use web_time::Instant;

use ndn_config::{
    ControlParameters, ControlResponse,
    control_parameters::{origin, route_flags},
    control_response::status,
    nfd_command::{module, verb},
    nfd_dataset,
};
use ndn_engine::{ForwarderEngine, RibRoute};
use ndn_packet::Name;
use ndn_transport::FaceId;

use super::common::{is_management_face, is_reserved_name, resolve_face_id};
use crate::MgmtResponse;
use crate::module::{MgmtContext, MgmtModule};
use crate::notification::NotificationEvent;

/// RIB add/remove event.
#[derive(Debug, Clone)]
pub struct RouteEvent {
    pub kind: RouteEventKind,
    pub prefix: Name,
    pub face_id: FaceId,
    pub origin: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RouteEventKind {
    Register = 1,
    Unregister = 2,
}

impl NotificationEvent for RouteEvent {
    fn encode(&self) -> Bytes {
        // v1 wire shape: `kind face_id=<id> origin=<o> name=<n>` text
        // line. NFD-canonical `RibEntryChange` TLV is a follow-up.
        let kind = match self.kind {
            RouteEventKind::Register => "register",
            RouteEventKind::Unregister => "unregister",
        };
        Bytes::from(format!(
            "{kind} face_id={} origin={} name={}",
            self.face_id.0, self.origin, self.prefix
        ))
    }
}

fn handle_rib(
    verb_name: &[u8],
    params: ControlParameters,
    source_face: Option<FaceId>,
    engine: &ForwarderEngine,
) -> MgmtResponse {
    match verb_name {
        v if v == verb::REGISTER => rib_register(params, source_face, engine).into(),
        v if v == verb::UNREGISTER => rib_unregister(params, source_face, engine).into(),
        v if v == verb::LIST => MgmtResponse::Dataset(rib_list_dataset(engine)),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown rib verb").into(),
    }
}

fn rib_register(
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
    let orig = params.origin.unwrap_or(origin::APP);
    let flags = params.flags.unwrap_or(route_flags::CHILD_INHERIT);
    let expires_at = params
        .expiration_period
        .map(|ms| Instant::now() + Duration::from_millis(ms));

    engine.rib().add(
        &name,
        RibRoute {
            face_id,
            origin: orig,
            cost,
            flags,
            expires_at,
        },
    );
    engine.rib().apply_to_fib(&name, &engine.fib());
    // Readvertise locally-originated registrations into the routing plane so
    // remote nodes can reach this prefix (NFD rib/readvertise; no-op unless a
    // routing protocol installed a destination and `orig` is a local origin).
    engine.rib().readvertise_announce(&name, orig);

    tracing::info!(target: "mgmt.rib", prefix = %name, face = face_id.0, cost, origin = orig, "rib/register");

    let echo = ControlParameters {
        name: Some(name),
        face_id: Some(face_id.0),
        origin: Some(orig),
        cost: Some(cost as u64),
        flags: Some(flags),
        expiration_period: params.expiration_period,
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn rib_unregister(
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

    let orig = params.origin;
    if let Some(o) = orig {
        engine.rib().remove(&name, face_id, o);
    } else {
        engine.rib().remove_nexthop(&name, face_id);
    }
    engine.rib().apply_to_fib(&name, &engine.fib());
    // Withdraw from the routing plane once no local route for the prefix
    // remains (the RIB checks; no-op if other local faces still serve it).
    engine.rib().readvertise_withdraw(&name);

    tracing::info!(target: "mgmt.rib", prefix = %name, face = face_id.0, "rib/unregister");

    let echo = ControlParameters {
        name: Some(name),
        face_id: Some(face_id.0),
        origin: Some(orig.unwrap_or(origin::APP)),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn rib_list_dataset(engine: &ForwarderEngine) -> bytes::Bytes {
    let entries = engine.rib().dump();
    let mut buf = bytes::BytesMut::new();
    for (name, routes) in &entries {
        let rib_entry = nfd_dataset::RibEntry {
            name: name.clone(),
            routes: routes
                .iter()
                .map(|r| {
                    let expiration_period = r.expires_at.map(|exp| {
                        exp.saturating_duration_since(Instant::now()).as_millis() as u64
                    });
                    nfd_dataset::Route {
                        face_id: r.face_id.0,
                        origin: r.origin,
                        cost: r.cost as u64,
                        flags: r.flags,
                        expiration_period,
                    }
                })
                .collect(),
        };
        buf.extend_from_slice(&rib_entry.encode());
    }
    buf.freeze()
}

pub(crate) struct RibModule;

#[async_trait]
impl MgmtModule for RibModule {
    fn name(&self) -> &'static [u8] {
        module::RIB
    }

    async fn dispatch(
        &self,
        verb: &[u8],
        params: ControlParameters,
        ctx: &MgmtContext<'_>,
    ) -> MgmtResponse {
        let resp = handle_rib(verb, params, ctx.source_face, ctx.engine);
        if let (Some(stream), MgmtResponse::Control(cr)) = (ctx.route_events, &resp)
            && cr.status_code == status::OK
            && let Some(body) = cr.body.as_ref()
            && let (Some(prefix), Some(face_id)) = (body.name.clone(), body.face_id)
        {
            let kind = if verb == verb::REGISTER {
                Some(RouteEventKind::Register)
            } else if verb == verb::UNREGISTER {
                Some(RouteEventKind::Unregister)
            } else {
                None
            };
            if let Some(kind) = kind {
                stream.publish(RouteEvent {
                    kind,
                    prefix,
                    face_id: FaceId(face_id),
                    origin: body.origin.unwrap_or(origin::APP),
                });
            }
        }
        resp
    }
}
