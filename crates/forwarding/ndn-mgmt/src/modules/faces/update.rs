//! `faces/update` — apply runtime-mutable face options (flag bits, MTU,
//! persistency) and the refusal-reason / refused-response helpers shared
//! with `faces/create`'s idempotent re-attach path.

use ndn_engine::ForwarderEngine;
use ndn_mgmt_wire::{ControlParameters, ControlResponse, control_response::status};
use ndn_transport::{
    BIT_CONGESTION_MARKING, BIT_LOCAL_FIELDS, BIT_LP_RELIABILITY, FaceId, FaceKind, FaceOption,
    FaceOptionError, FacePersistency, MtuError, PersistencyError,
};

use super::super::common::is_management_face;
use super::events::FaceEvent;

/// `faces/update`.
///
/// - NFD flag bits decompose into `FaceOption::{LocalFields,
///   LpReliability, CongestionMarking}` through `LinkService::apply()`.
/// - `Mtu` / `FacePersistency` route to `Transport::set_send_mtu` /
///   `Transport::set_persistency`.
///
/// Failures surface as `field=<option> reason=<machine-readable>` in
/// `status_text` (greppable without decoding bitmaps).
pub(super) fn faces_update(
    params: ControlParameters,
    source_face: Option<FaceId>,
    engine: &ForwarderEngine,
) -> (ControlResponse, Vec<FaceEvent>) {
    let mut events = Vec::new();
    let face_id = match params.face_id {
        Some(id) => FaceId(id),
        None => match source_face {
            Some(f) => f,
            None => {
                return (
                    ControlResponse::error(
                        status::BAD_PARAMS,
                        "FaceId is required (no source face on this request)",
                    ),
                    events,
                );
            }
        },
    };

    let target = match engine.faces().get(face_id) {
        Some(f) => f,
        None => {
            return (
                ControlResponse::error(
                    status::NOT_FOUND,
                    format!("face {} does not exist", face_id.0),
                ),
                events,
            );
        }
    };

    if target.kind().is_management() && !is_management_face(source_face, engine) {
        return (
            ControlResponse::error(
                status::LOCKED,
                "field=management-face reason=management-face-protected",
            ),
            events,
        );
    }

    // Flags+Mask → per-bit typed options through `LinkService::apply`.
    // Any refused bit short-circuits without mutating FaceState.
    if let (Some(flags), Some(mask)) = (params.flags, params.mask) {
        #[allow(clippy::type_complexity)]
        let bit_opts: [(u64, fn(bool) -> FaceOption); 3] = [
            (BIT_LOCAL_FIELDS, FaceOption::LocalFields),
            (BIT_LP_RELIABILITY, FaceOption::LpReliability),
            (BIT_CONGESTION_MARKING, FaceOption::CongestionMarking),
        ];
        for (bit, ctor) in bit_opts {
            if mask & bit == 0 {
                continue;
            }
            let on = (flags & bit) != 0;
            if let Err(err) = target.link_service.apply(ctor(on)) {
                events.push(FaceEvent::OptionRefused {
                    face_id,
                    option: format!("flags:{}", err.option()),
                    reason: refusal_reason_text(&err).to_owned(),
                });
                return (refused_flag_response(&err), events);
            }
        }
    }

    // CongestionMarking value parameters (runtime-mutable, like NFD's
    // BaseCongestionMarkingInterval / DefaultCongestionThreshold). Surfaced on
    // faces/list; ignored by transports without a congestion-marking feature.
    if let Some(us) = params.base_cong_interval {
        let _ = target
            .link_service
            .apply(FaceOption::BaseCongestionMarkingInterval(
                std::time::Duration::from_micros(us),
            ));
    }
    if let Some(threshold) = params.def_cong_threshold {
        let _ = target
            .link_service
            .apply(FaceOption::DefaultCongestionThreshold(threshold));
    }

    let mut applied_mtu: Option<u64> = None;
    let old_mtu_hint = target.transport.send_mtu().map(|n| n as u64);
    if let Some(mtu) = params.mtu {
        let arg = if mtu == 0 { None } else { Some(mtu) };
        match target.transport.set_send_mtu(arg) {
            Ok(eff) => {
                applied_mtu = eff;
                if let (Some(old), Some(new)) = (old_mtu_hint, eff)
                    && old != new
                {
                    events.push(FaceEvent::MtuChanged { face_id, old, new });
                }
            }
            Err(err) => {
                events.push(FaceEvent::OptionRefused {
                    face_id,
                    option: "mtu".to_owned(),
                    reason: mtu_refusal_reason(&err, target.kind()),
                });
                return (refused_mtu_response(&err, target.kind()), events);
            }
        }
    }

    let mut applied_persistency: Option<u64> = None;
    if let Some(p) = params.face_persistency {
        match FacePersistency::from_u64(p) {
            Some(persistency) => match target.transport.set_persistency(persistency) {
                Ok(()) => {
                    applied_persistency = Some(p);
                    // No pre-update snapshot; emit only the new value.
                    events.push(FaceEvent::PersistencyChanged {
                        face_id,
                        old: 0,
                        new: p,
                    });
                }
                Err(err) => {
                    events.push(FaceEvent::OptionRefused {
                        face_id,
                        option: "persistency".to_owned(),
                        reason: persistency_refusal_reason(&err, target.kind()),
                    });
                    return (refused_persistency_response(&err, target.kind()), events);
                }
            },
            None => {
                events.push(FaceEvent::OptionRefused {
                    face_id,
                    option: "persistency".to_owned(),
                    reason: "invalid-value".to_owned(),
                });
                return (
                    ControlResponse::error(
                        status::BAD_PARAMS,
                        "field=persistency reason=invalid-value",
                    ),
                    events,
                );
            }
        }
    }

    // All options accepted — commit Flag bits to FaceState in one
    // store to avoid torn writes against in-flight reads.
    let new_flags = match (params.flags, params.mask) {
        (Some(flags), Some(mask)) => engine
            .face_states()
            .get(&face_id)
            .map(|state| state.apply_face_flags_mask(flags, mask))
            .or(Some(0)),
        _ => None,
    };

    tracing::info!(
        target: "mgmt.face",
        face = face_id.0,
        flags = ?new_flags,
        mtu = ?applied_mtu,
        persistency = ?applied_persistency,
        "faces/update",
    );

    let echo = ControlParameters {
        face_id: Some(face_id.0),
        flags: new_flags,
        mtu: applied_mtu,
        face_persistency: applied_persistency,
        ..Default::default()
    };
    (ControlResponse::ok("OK", echo), events)
}

pub(super) fn refusal_reason_text(err: &FaceOptionError) -> &'static str {
    match err {
        FaceOptionError::NotSupportedByTransport { .. } => "transport-not-eligible",
        FaceOptionError::Immutable { .. } => "immutable",
        FaceOptionError::OutOfRange { reason, .. } => reason,
    }
}

pub(super) fn mtu_refusal_reason(err: &MtuError, kind: FaceKind) -> String {
    match err {
        MtuError::NotSupported => "transport-not-eligible".to_owned(),
        MtuError::Immutable => format!("immutable-on-{kind}"),
        MtuError::OutOfRange { reason } => (*reason).to_owned(),
    }
}

pub(super) fn persistency_refusal_reason(err: &PersistencyError, kind: FaceKind) -> String {
    match err {
        PersistencyError::NotSupported => "transport-not-eligible".to_owned(),
        PersistencyError::Immutable => format!("immutable-on-{kind}"),
        PersistencyError::OutOfRange { reason } => (*reason).to_owned(),
    }
}

fn refused_flag_response(err: &FaceOptionError) -> ControlResponse {
    let opt = err.option();
    match err {
        FaceOptionError::NotSupportedByTransport { .. } => ControlResponse::error(
            status::SERVICE_UNAVAILABLE,
            format!("field=flags:{opt} reason=transport-not-eligible"),
        ),
        FaceOptionError::Immutable { .. } => ControlResponse::error(
            status::CONFLICT,
            format!("field=flags:{opt} reason=immutable"),
        ),
        FaceOptionError::OutOfRange { reason, .. } => ControlResponse::error(
            status::BAD_PARAMS,
            format!("field=flags:{opt} reason={reason}"),
        ),
    }
}

fn refused_mtu_response(err: &MtuError, kind: FaceKind) -> ControlResponse {
    match err {
        MtuError::NotSupported => ControlResponse::error(
            status::SERVICE_UNAVAILABLE,
            "field=mtu reason=transport-not-eligible",
        ),
        MtuError::Immutable => ControlResponse::error(
            status::CONFLICT,
            format!("field=mtu reason=immutable-on-{kind}"),
        ),
        MtuError::OutOfRange { reason } => {
            ControlResponse::error(status::BAD_PARAMS, format!("field=mtu reason={reason}"))
        }
    }
}

fn refused_persistency_response(err: &PersistencyError, kind: FaceKind) -> ControlResponse {
    match err {
        PersistencyError::NotSupported => ControlResponse::error(
            status::SERVICE_UNAVAILABLE,
            "field=persistency reason=transport-not-eligible",
        ),
        PersistencyError::Immutable => ControlResponse::error(
            status::CONFLICT,
            format!("field=persistency reason=immutable-on-{kind}"),
        ),
        PersistencyError::OutOfRange { reason } => ControlResponse::error(
            status::BAD_PARAMS,
            format!("field=persistency reason={reason}"),
        ),
    }
}
