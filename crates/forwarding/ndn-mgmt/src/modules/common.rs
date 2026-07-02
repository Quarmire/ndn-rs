//! Helpers shared across multiple per-module dispatchers.

use std::str::FromStr;

use ndn_engine::ForwarderEngine;
use ndn_mgmt_wire::{ControlParameters, ControlResponse, control_response::status};
use ndn_packet::Name;
use ndn_transport::FaceId;

/// Prefixes only operator (management) faces may register under.
const RESERVED_PREFIXES: &[&str] = &["/ndn/local", "/localhost/nfd"];

pub fn is_reserved_name(name: &Name) -> bool {
    RESERVED_PREFIXES.iter().any(|r| {
        Name::from_str(r)
            .map(|p| name.has_prefix(&p) || *name == p)
            .unwrap_or(false)
    })
}

/// True for `FaceKind::Management` (operator socket) and for
/// internally-generated commands (`source_face = None`).
pub fn is_management_face(source_face: Option<FaceId>, engine: &ForwarderEngine) -> bool {
    match source_face {
        None => true,
        Some(fid) => engine
            .faces()
            .get(fid)
            .map(|f| f.kind().is_management())
            .unwrap_or(false),
    }
}

/// Resolve FaceId from `params`, falling back to the requesting face.
/// Treats `face_id = 0` as omitted (IDs are allocated from 1 upwards).
pub(crate) fn resolve_face_id(
    params: &ControlParameters,
    source_face: Option<FaceId>,
) -> Result<FaceId, Box<ControlResponse>> {
    match params.face_id {
        Some(0) | None => source_face.ok_or_else(|| {
            Box::new(ControlResponse::error(
                status::BAD_PARAMS,
                "cannot determine FaceId",
            ))
        }),
        Some(id) => Ok(FaceId(id)),
    }
}
