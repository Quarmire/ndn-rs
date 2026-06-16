//! `/localhost/nfd/faces/{create, update, destroy, list, counters}` —
//! face table management. Publishes `FaceEvent`s on
//! `/localhost/nfd/faces/notifications`.

mod create;
mod datasets;
mod events;
mod update;
pub mod provision;

use async_trait::async_trait;

use ndn_mgmt_wire::{
    ControlParameters, ControlResponse,
    control_response::status,
    nfd_command::{module, verb},
};
use ndn_engine::ForwarderEngine;
use ndn_transport::FaceId;

use super::common::is_management_face;
use crate::MgmtResponse;
use crate::module::{MgmtContext, MgmtModule};

// Public API: `lib.rs` re-exports `FaceEvent`/`FaceEventKind` at
// `ndn_mgmt::modules::faces::{FaceEvent, FaceEventKind}`.
pub use events::{FaceEvent, FaceEventKind};

use create::faces_create;
use datasets::{faces_counters, faces_link_quality_dataset, faces_list_dataset};
use update::faces_update;

/// Verb handler output. `events` is non-empty when the verb produces
/// ndn-rs semantic events (e.g. `faces/update`); lifecycle Created /
/// Destroyed kinds are emitted by the dispatch wrapper from the
/// response status to keep the NFD wire shape unchanged.
struct VerbOutcome {
    response: MgmtResponse,
    events: Vec<FaceEvent>,
}

impl From<ControlResponse> for VerbOutcome {
    fn from(response: ControlResponse) -> Self {
        Self {
            response: response.into(),
            events: Vec::new(),
        }
    }
}

async fn handle_faces(
    verb_name: &[u8],
    params: ControlParameters,
    source_face: Option<FaceId>,
    engine: &ForwarderEngine,
    provisioners: &[std::sync::Arc<dyn crate::FaceProvisioner>],
) -> VerbOutcome {
    match verb_name {
        v if v == verb::CREATE => faces_create(params, source_face, engine, provisioners).await.into(),
        v if v == verb::UPDATE => {
            let (response, events) = faces_update(params, source_face, engine);
            VerbOutcome {
                response: response.into(),
                events,
            }
        }
        v if v == verb::DESTROY => faces_destroy(params, source_face, engine).into(),
        v if v == verb::LIST => VerbOutcome {
            response: MgmtResponse::Dataset(faces_list_dataset(engine)),
            events: Vec::new(),
        },
        v if v == verb::COUNTERS => faces_counters(engine).into(),
        v if v == verb::LINK_QUALITY => VerbOutcome {
            response: MgmtResponse::Dataset(faces_link_quality_dataset(engine)),
            events: Vec::new(),
        },
        _ => ControlResponse::error(status::NOT_FOUND, "unknown faces verb").into(),
    }
}

fn faces_destroy(
    params: ControlParameters,
    source_face: Option<FaceId>,
    engine: &ForwarderEngine,
) -> ControlResponse {
    let face_id = match params.face_id {
        Some(id) => FaceId(id),
        None => return ControlResponse::error(status::BAD_PARAMS, "FaceId is required"),
    };

    let target = match engine.faces().get(face_id) {
        Some(f) => f,
        None => {
            return ControlResponse::error(
                status::NOT_FOUND,
                format!("face {} does not exist", face_id.0),
            );
        }
    };

    if target.kind().is_management() && !is_management_face(source_face, engine) {
        return ControlResponse::error(
            status::UNAUTHORIZED,
            "cannot destroy a management face from a non-management face",
        );
    }

    if let Some(token) = engine.face_token(face_id) {
        token.cancel();
    } else {
        engine.fib().remove_face(face_id);
        engine.faces().remove(face_id);
    }

    tracing::info!(target: "mgmt.face", face = face_id.0, "faces/destroy");

    let echo = ControlParameters {
        face_id: Some(face_id.0),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

pub(crate) struct FacesModule;

#[async_trait]
impl MgmtModule for FacesModule {
    fn name(&self) -> &'static [u8] {
        module::FACES
    }

    async fn dispatch(
        &self,
        verb: &[u8],
        params: ControlParameters,
        ctx: &MgmtContext<'_>,
    ) -> MgmtResponse {
        let outcome =
            handle_faces(verb, params, ctx.source_face, ctx.engine, ctx.face_provisioners).await;
        let VerbOutcome { response, events } = outcome;

        if let Some(stream) = ctx.face_events {
            if let MgmtResponse::Control(cr) = &response
                && cr.status_code == status::OK
                && let Some(fid) = cr.body.as_ref().and_then(|b| b.face_id)
            {
                let face_id = FaceId(fid);
                if verb == verb::CREATE {
                    stream.publish(FaceEvent::Created { face_id });
                } else if verb == verb::DESTROY {
                    stream.publish(FaceEvent::Destroyed { face_id });
                }
            }
            for event in events {
                stream.publish(event);
            }
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notification::NotificationEvent;
    use datasets::{encode_link_quality, link_quality_tlv};
    use events::MarkDirection;

    #[cfg(all(
        feature = "l2",
        any(target_os = "linux", target_os = "macos", target_os = "windows")
    ))]
    #[test]
    fn ether_uri_parses_mac_and_iface() {
        use super::create::parse_ether_uri;
        let (mac, iface) = parse_ether_uri("ether://[aa:bb:cc:dd:ee:ff]/eth0").unwrap();
        assert_eq!(mac.as_bytes(), &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(iface, "eth0");

        // Round-trips against the URI a NamedEtherFace emits.
        assert!(parse_ether_uri("ether://[01:00:5e:00:17:aa]/en1").is_ok());

        // Malformed inputs are rejected before any socket is opened.
        assert!(parse_ether_uri("ether://aa:bb:cc:dd:ee:ff/eth0").is_err()); // no brackets
        assert!(parse_ether_uri("ether://[aa:bb:cc:dd:ee:ff]/").is_err()); // empty iface
        assert!(parse_ether_uri("ether://[zz:zz:zz:zz:zz:zz]/eth0").is_err()); // bad MAC
    }

    #[test]
    fn link_quality_dataset_round_trips() {
        use link_quality_tlv as t;
        use ndn_strategy::{CongestionLevel, LinkSignals};

        let entries = vec![
            (
                5u64,
                LinkSignals {
                    rssi_dbm: Some(-67),
                    snr_db: Some(9),
                    congestion: Some(CongestionLevel::High),
                    updated_ms: 12345,
                    ..Default::default()
                },
            ),
            (
                9u64,
                LinkSignals {
                    rssi_dbm: Some(-50),
                    updated_ms: 7,
                    ..Default::default()
                },
            ),
        ];
        let wire = encode_link_quality(&entries);

        // Walk the TLV entries back out.
        let b = wire.as_ref();
        let mut pos = 0;
        let mut decoded: Vec<(u64, Option<i8>, Option<u8>, u32)> = Vec::new();
        while pos < b.len() {
            assert_eq!(b[pos], t::ENTRY);
            let len = b[pos + 1] as usize;
            let body = &b[pos + 2..pos + 2 + len];
            pos += 2 + len;

            let (mut fid, mut rssi, mut cong, mut updated) = (0u64, None, None, 0u32);
            let mut p = 0;
            while p < body.len() {
                let (ty, l) = (body[p], body[p + 1] as usize);
                let v = &body[p + 2..p + 2 + l];
                match ty {
                    x if x == t::FACE_ID => fid = u64::from_be_bytes(v.try_into().unwrap()),
                    x if x == t::RSSI => rssi = Some(v[0] as i8),
                    x if x == t::CONGESTION => cong = Some(v[0]),
                    x if x == t::UPDATED_MS => updated = u32::from_be_bytes(v.try_into().unwrap()),
                    _ => {}
                }
                p += 2 + l;
            }
            decoded.push((fid, rssi, cong, updated));
        }

        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0], (5, Some(-67), Some(2), 12345)); // High=2
        assert_eq!(decoded[1], (9, Some(-50), None, 7)); // no congestion field
    }

    fn round_trip(event: FaceEvent) -> FaceEvent {
        let wire = event.encode();
        FaceEvent::decode(&wire).expect("FaceEvent decode")
    }

    /// Every extended FaceEventKind round-trips wire encode/decode.
    #[test]
    fn face_event_extended_round_trips_mtu_changed() {
        let event = FaceEvent::MtuChanged {
            face_id: FaceId(7),
            old: 1500,
            new: 8800,
        };
        match round_trip(event) {
            FaceEvent::MtuChanged { face_id, old, new } => {
                assert_eq!(face_id, FaceId(7));
                assert_eq!(old, 1500);
                assert_eq!(new, 8800);
            }
            other => panic!("expected MtuChanged, got {other:?}"),
        }
    }

    #[test]
    fn face_event_extended_round_trips_persistency_changed() {
        let event = FaceEvent::PersistencyChanged {
            face_id: FaceId(11),
            old: 0,
            new: 2,
        };
        match round_trip(event) {
            FaceEvent::PersistencyChanged { face_id, old, new } => {
                assert_eq!(face_id, FaceId(11));
                assert_eq!(old, 0);
                assert_eq!(new, 2);
            }
            other => panic!("expected PersistencyChanged, got {other:?}"),
        }
    }

    #[test]
    fn face_event_extended_round_trips_reliability_backoff() {
        let event = FaceEvent::ReliabilityBackoff {
            face_id: FaceId(23),
            attempt: 3,
            rto_us: 250_000,
        };
        match round_trip(event) {
            FaceEvent::ReliabilityBackoff {
                face_id,
                attempt,
                rto_us,
            } => {
                assert_eq!(face_id, FaceId(23));
                assert_eq!(attempt, 3);
                assert_eq!(rto_us, 250_000);
            }
            other => panic!("expected ReliabilityBackoff, got {other:?}"),
        }
    }

    #[test]
    fn face_event_extended_round_trips_congestion_mark() {
        for direction in [MarkDirection::Egress, MarkDirection::Ingress] {
            let event = FaceEvent::CongestionMark {
                face_id: FaceId(31),
                direction,
                mark: 1,
            };
            match round_trip(event) {
                FaceEvent::CongestionMark {
                    face_id,
                    direction: d,
                    mark,
                } => {
                    assert_eq!(face_id, FaceId(31));
                    assert_eq!(d, direction);
                    assert_eq!(mark, 1);
                }
                other => panic!("expected CongestionMark, got {other:?}"),
            }
        }
    }

    #[test]
    fn face_event_extended_round_trips_option_refused() {
        let event = FaceEvent::OptionRefused {
            face_id: FaceId(41),
            option: "flags:lp-reliability".to_owned(),
            reason: "transport-not-eligible".to_owned(),
        };
        match round_trip(event) {
            FaceEvent::OptionRefused {
                face_id,
                option,
                reason,
            } => {
                assert_eq!(face_id, FaceId(41));
                assert_eq!(option, "flags:lp-reliability");
                assert_eq!(reason, "transport-not-eligible");
            }
            other => panic!("expected OptionRefused, got {other:?}"),
        }
    }

    /// NFD-canonical lifecycle kinds encode to the bare NFD wire shape.
    #[test]
    fn face_event_extended_lifecycle_wire_unchanged() {
        let event = FaceEvent::Created {
            face_id: FaceId(257),
        };
        let wire = event.encode();
        assert_eq!(
            wire.as_ref(),
            &[0xC0, 0x07, 0xC1, 0x01, 0x01, 0x69, 0x02, 0x01, 0x01]
        );
    }
}
