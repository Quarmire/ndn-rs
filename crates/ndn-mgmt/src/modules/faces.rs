//! `/localhost/nfd/faces/{create, update, destroy, list, counters}` —
//! face table management. Publishes `FaceEvent`s on
//! `/localhost/nfd/faces/notifications`.

use async_trait::async_trait;
use bytes::Bytes;

use ndn_config::{
    ControlParameters, ControlResponse,
    control_response::status,
    nfd_command::{module, verb},
    nfd_dataset,
};
use ndn_engine::ForwarderEngine;
#[cfg(not(target_arch = "wasm32"))]
use ndn_transport::Transport;
use ndn_transport::{
    BIT_CONGESTION_MARKING, BIT_LOCAL_FIELDS, BIT_LP_RELIABILITY, FaceId, FaceKind, FaceOption,
    FaceOptionError, FacePersistency, FaceScope, MtuError, PersistencyError,
};
use tokio_util::sync::CancellationToken;

use super::common::is_management_face;
use crate::MgmtResponse;
use crate::module::{MgmtContext, MgmtModule};
use crate::notification::NotificationEvent;

/// Face lifecycle and semantic-event notifications.
///
/// Wire shape: NFD-canonical `FaceEventNotification` TLV (type `0xC0`,
/// see ndn-cxx `mgmt/nfd/face-event-notification.hpp`) carrying
/// `FaceEventKind` (`0xC1`, NNI) and `FaceId` (`0x69`). NFD reserves
/// kinds 1..=4 for lifecycle (Created / Destroyed / Up / Down); ndn-rs
/// adds kinds 5..=9 (MtuChanged, PersistencyChanged,
/// ReliabilityBackoff, CongestionMark, OptionRefused) — NFD clients
/// ignore kinds > 4.
#[derive(Debug, Clone)]
pub enum FaceEvent {
    Created {
        face_id: FaceId,
    },
    Destroyed {
        face_id: FaceId,
    },
    Up {
        face_id: FaceId,
    },
    Down {
        face_id: FaceId,
    },
    MtuChanged {
        face_id: FaceId,
        old: u64,
        new: u64,
    },
    PersistencyChanged {
        face_id: FaceId,
        old: u64,
        new: u64,
    },
    ReliabilityBackoff {
        face_id: FaceId,
        attempt: u32,
        rto_us: u64,
    },
    CongestionMark {
        face_id: FaceId,
        direction: MarkDirection,
        mark: u64,
    },
    OptionRefused {
        face_id: FaceId,
        option: String,
        reason: String,
    },
}

impl FaceEvent {
    pub fn face_id(&self) -> FaceId {
        match self {
            FaceEvent::Created { face_id }
            | FaceEvent::Destroyed { face_id }
            | FaceEvent::Up { face_id }
            | FaceEvent::Down { face_id }
            | FaceEvent::MtuChanged { face_id, .. }
            | FaceEvent::PersistencyChanged { face_id, .. }
            | FaceEvent::ReliabilityBackoff { face_id, .. }
            | FaceEvent::CongestionMark { face_id, .. }
            | FaceEvent::OptionRefused { face_id, .. } => *face_id,
        }
    }

    pub fn kind(&self) -> FaceEventKind {
        match self {
            FaceEvent::Created { .. } => FaceEventKind::Created,
            FaceEvent::Destroyed { .. } => FaceEventKind::Destroyed,
            FaceEvent::Up { .. } => FaceEventKind::Up,
            FaceEvent::Down { .. } => FaceEventKind::Down,
            FaceEvent::MtuChanged { .. } => FaceEventKind::MtuChanged,
            FaceEvent::PersistencyChanged { .. } => FaceEventKind::PersistencyChanged,
            FaceEvent::ReliabilityBackoff { .. } => FaceEventKind::ReliabilityBackoff,
            FaceEvent::CongestionMark { .. } => FaceEventKind::CongestionMark,
            FaceEvent::OptionRefused { .. } => FaceEventKind::OptionRefused,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FaceEventKind {
    Created = 1,
    Destroyed = 2,
    Up = 3,
    Down = 4,
    // ndn-rs semantic-event extensions.
    MtuChanged = 5,
    PersistencyChanged = 6,
    ReliabilityBackoff = 7,
    CongestionMark = 8,
    OptionRefused = 9,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MarkDirection {
    Egress = 0,
    Ingress = 1,
}

/// ndn-cxx `mgmt/nfd/face-event-notification.hpp:62`.
const TLV_FACE_EVENT_NOTIFICATION: u8 = 0xC0;
const TLV_FACE_EVENT_KIND: u8 = 0xC1;
/// Shared with management `FaceStatus`.
const TLV_FACE_ID: u8 = 0x69;

// Extended-event payload TLVs, project-private range 0xD0..=0xD9.
const TLV_OLD_MTU: u8 = 0xD0;
const TLV_NEW_MTU: u8 = 0xD1;
const TLV_OLD_PERSISTENCY: u8 = 0xD2;
const TLV_NEW_PERSISTENCY: u8 = 0xD3;
const TLV_RELIABILITY_ATTEMPT: u8 = 0xD4;
const TLV_RTO: u8 = 0xD5;
const TLV_MARK_DIRECTION: u8 = 0xD6;
const TLV_MARK: u8 = 0xD7;
const TLV_OPTION_NAME: u8 = 0xD8;
const TLV_REFUSAL_REASON: u8 = 0xD9;

impl NotificationEvent for FaceEvent {
    fn encode(&self) -> Bytes {
        let face_id = self.face_id();
        let kind = self.kind();

        let kind_v = encode_non_neg_int(kind as u64);
        let face_id_v = encode_non_neg_int(face_id.0);

        // Inner length must be known before the outer length-prefix.
        let mut payload = Vec::new();
        match self {
            FaceEvent::MtuChanged { old, new, .. } => {
                write_one_byte_tlv_nni(&mut payload, TLV_OLD_MTU, *old);
                write_one_byte_tlv_nni(&mut payload, TLV_NEW_MTU, *new);
            }
            FaceEvent::PersistencyChanged { old, new, .. } => {
                write_one_byte_tlv_nni(&mut payload, TLV_OLD_PERSISTENCY, *old);
                write_one_byte_tlv_nni(&mut payload, TLV_NEW_PERSISTENCY, *new);
            }
            FaceEvent::ReliabilityBackoff {
                attempt, rto_us, ..
            } => {
                write_one_byte_tlv_nni(&mut payload, TLV_RELIABILITY_ATTEMPT, *attempt as u64);
                write_one_byte_tlv_nni(&mut payload, TLV_RTO, *rto_us);
            }
            FaceEvent::CongestionMark {
                direction, mark, ..
            } => {
                payload.push(TLV_MARK_DIRECTION);
                payload.push(1);
                payload.push(*direction as u8);
                write_one_byte_tlv_nni(&mut payload, TLV_MARK, *mark);
            }
            FaceEvent::OptionRefused { option, reason, .. } => {
                write_one_byte_tlv_str(&mut payload, TLV_OPTION_NAME, option);
                write_one_byte_tlv_str(&mut payload, TLV_REFUSAL_REASON, reason);
            }
            _ => {}
        }

        let inner_len = 2 + kind_v.len() + 2 + face_id_v.len() + payload.len();
        // One-byte varu64 budget — promote to multi-byte if payloads grow.
        debug_assert!(
            inner_len <= 252,
            "FaceEvent inner length {inner_len} exceeds one-byte varu64 budget",
        );
        let mut buf = Vec::with_capacity(2 + inner_len);
        buf.push(TLV_FACE_EVENT_NOTIFICATION);
        buf.push(inner_len as u8);
        buf.push(TLV_FACE_EVENT_KIND);
        buf.push(kind_v.len() as u8);
        buf.extend_from_slice(&kind_v);
        buf.push(TLV_FACE_ID);
        buf.push(face_id_v.len() as u8);
        buf.extend_from_slice(&face_id_v);
        buf.extend_from_slice(&payload);
        Bytes::from(buf)
    }
}

fn write_one_byte_tlv_nni(buf: &mut Vec<u8>, typ: u8, v: u64) {
    let bytes = encode_non_neg_int(v);
    buf.push(typ);
    buf.push(bytes.len() as u8);
    buf.extend_from_slice(&bytes);
}

fn write_one_byte_tlv_str(buf: &mut Vec<u8>, typ: u8, s: &str) {
    debug_assert!(
        s.len() <= 252,
        "FaceEvent string field {typ:#x} length {} exceeds one-byte varu64 budget",
        s.len(),
    );
    buf.push(typ);
    buf.push(s.len() as u8);
    buf.extend_from_slice(s.as_bytes());
}

impl FaceEvent {
    /// Decode a wire-format [`FaceEvent`]. Mirrors the encoder's
    /// one-byte-length assumption; events with inner length > 252 are
    /// rejected as malformed.
    pub fn decode(wire: &[u8]) -> Option<Self> {
        if wire.len() < 4 || wire[0] != TLV_FACE_EVENT_NOTIFICATION {
            return None;
        }
        let inner_len = wire[1] as usize;
        let inner = wire.get(2..2 + inner_len)?;

        let mut pos = 0;
        let mut kind: Option<FaceEventKind> = None;
        let mut face_id: Option<FaceId> = None;
        let mut old_mtu: Option<u64> = None;
        let mut new_mtu: Option<u64> = None;
        let mut old_persistency: Option<u64> = None;
        let mut new_persistency: Option<u64> = None;
        let mut attempt: Option<u32> = None;
        let mut rto_us: Option<u64> = None;
        let mut mark_direction: Option<MarkDirection> = None;
        let mut mark: Option<u64> = None;
        let mut option_name: Option<String> = None;
        let mut refusal_reason: Option<String> = None;

        while pos < inner.len() {
            let typ = *inner.get(pos)?;
            let len = *inner.get(pos + 1)? as usize;
            let val = inner.get(pos + 2..pos + 2 + len)?;
            pos += 2 + len;
            match typ {
                TLV_FACE_EVENT_KIND => {
                    kind = Some(match decode_nni(val)? {
                        1 => FaceEventKind::Created,
                        2 => FaceEventKind::Destroyed,
                        3 => FaceEventKind::Up,
                        4 => FaceEventKind::Down,
                        5 => FaceEventKind::MtuChanged,
                        6 => FaceEventKind::PersistencyChanged,
                        7 => FaceEventKind::ReliabilityBackoff,
                        8 => FaceEventKind::CongestionMark,
                        9 => FaceEventKind::OptionRefused,
                        _ => return None,
                    });
                }
                TLV_FACE_ID => face_id = Some(FaceId(decode_nni(val)?)),
                TLV_OLD_MTU => old_mtu = Some(decode_nni(val)?),
                TLV_NEW_MTU => new_mtu = Some(decode_nni(val)?),
                TLV_OLD_PERSISTENCY => old_persistency = Some(decode_nni(val)?),
                TLV_NEW_PERSISTENCY => new_persistency = Some(decode_nni(val)?),
                TLV_RELIABILITY_ATTEMPT => attempt = Some(decode_nni(val)? as u32),
                TLV_RTO => rto_us = Some(decode_nni(val)?),
                TLV_MARK_DIRECTION => {
                    mark_direction = match val.first()? {
                        0 => Some(MarkDirection::Egress),
                        1 => Some(MarkDirection::Ingress),
                        _ => return None,
                    };
                }
                TLV_MARK => mark = Some(decode_nni(val)?),
                TLV_OPTION_NAME => {
                    option_name = Some(std::str::from_utf8(val).ok()?.to_owned());
                }
                TLV_REFUSAL_REASON => {
                    refusal_reason = Some(std::str::from_utf8(val).ok()?.to_owned());
                }
                _ => {}
            }
        }

        let face_id = face_id?;
        Some(match kind? {
            FaceEventKind::Created => FaceEvent::Created { face_id },
            FaceEventKind::Destroyed => FaceEvent::Destroyed { face_id },
            FaceEventKind::Up => FaceEvent::Up { face_id },
            FaceEventKind::Down => FaceEvent::Down { face_id },
            FaceEventKind::MtuChanged => FaceEvent::MtuChanged {
                face_id,
                old: old_mtu?,
                new: new_mtu?,
            },
            FaceEventKind::PersistencyChanged => FaceEvent::PersistencyChanged {
                face_id,
                old: old_persistency?,
                new: new_persistency?,
            },
            FaceEventKind::ReliabilityBackoff => FaceEvent::ReliabilityBackoff {
                face_id,
                attempt: attempt?,
                rto_us: rto_us?,
            },
            FaceEventKind::CongestionMark => FaceEvent::CongestionMark {
                face_id,
                direction: mark_direction?,
                mark: mark?,
            },
            FaceEventKind::OptionRefused => FaceEvent::OptionRefused {
                face_id,
                option: option_name?,
                reason: refusal_reason?,
            },
        })
    }
}

fn decode_nni(buf: &[u8]) -> Option<u64> {
    match buf.len() {
        1 => Some(buf[0] as u64),
        2 => Some(u16::from_be_bytes([buf[0], buf[1]]) as u64),
        4 => Some(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as u64),
        8 => Some(u64::from_be_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ])),
        _ => None,
    }
}

/// NDN NonNegativeInteger: 1, 2, 4, or 8 bytes BE, shortest form.
fn encode_non_neg_int(v: u64) -> Vec<u8> {
    if v <= 0xFF {
        vec![v as u8]
    } else if v <= 0xFFFF {
        (v as u16).to_be_bytes().to_vec()
    } else if v <= 0xFFFF_FFFF {
        (v as u32).to_be_bytes().to_vec()
    } else {
        v.to_be_bytes().to_vec()
    }
}

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
) -> VerbOutcome {
    match verb_name {
        v if v == verb::CREATE => faces_create(params, source_face, engine).await.into(),
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
        _ => ControlResponse::error(status::NOT_FOUND, "unknown faces verb").into(),
    }
}

async fn faces_create(
    params: ControlParameters,
    source_face: Option<FaceId>,
    engine: &ForwarderEngine,
) -> ControlResponse {
    let uri = match &params.uri {
        Some(u) => u.clone(),
        None => return ControlResponse::error(status::BAD_PARAMS, "Uri is required"),
    };

    // Idempotent create: when the URI already attaches to a face,
    // return `200 OK` with that face_id and best-effort apply the
    // remaining options. Refusals collect into `partial_failures` on
    // the response body — NFD clients ignore the extra field.
    if let Some(existing_id) = existing_face_id_for_uri(engine, &uri) {
        return faces_create_idempotent(existing_id, uri, &params, engine);
    }

    if let Some(shm_name) = uri.strip_prefix("shm://") {
        return faces_create_shm(shm_name, params.mtu, source_face, engine);
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        if let Some(addr_str) = uri.strip_prefix("udp4://") {
            return faces_create_udp(addr_str, engine).await;
        }
        if let Some(addr_str) = uri.strip_prefix("tcp4://") {
            return faces_create_tcp(addr_str, engine).await;
        }
    }

    // `wts://host:port[?cert=<sha256hex>]` dials a WebTransport peer
    // (forwarder-to-forwarder over QUIC/HTTP3). `?cert=` pins a self-signed
    // peer's leaf cert; without it the OS trust store (WebPKI) is used.
    #[cfg(all(not(target_arch = "wasm32"), feature = "webtransport"))]
    {
        if uri.starts_with("wts://") {
            return faces_create_webtransport(&uri, engine).await;
        }
    }

    // `ble://<name-or-address>[?opts]` dials a peripheral as a GATT central
    // (Linux/macOS/Windows). The peripheral (GATT server) is NOT created here —
    // it is an NFD-style listener configured via `[listeners.ble]` (see
    // `ndn_faces::l2::BleListener`). Any `?query` is split off the target; the
    // params are a reserved extension point (e.g. `?adapter=hci0`).
    #[cfg(all(not(target_arch = "wasm32"), feature = "bluetooth"))]
    {
        if let Some(rest) = uri.strip_prefix("ble://") {
            let (target, query) = match rest.split_once('?') {
                Some((t, q)) => (t, Some(q)),
                None => (rest, None),
            };
            let framing = query.and_then(parse_ble_framing);
            let adapter = query.and_then(|q| parse_ble_query(q, "adapter"));
            return faces_create_ble_central(target, framing, adapter.as_deref(), engine).await;
        }
    }

    ControlResponse::error(status::BAD_PARAMS, format!("unsupported URI scheme: {uri}"))
}

fn existing_face_id_for_uri(engine: &ForwarderEngine, uri: &str) -> Option<FaceId> {
    engine
        .faces()
        .face_info()
        .into_iter()
        .find(|info| info.remote_uri.as_deref() == Some(uri))
        .map(|info| info.id)
}

/// Re-attach an existing face and best-effort apply mtu / flags /
/// persistency from `params`. Returns `200 OK` with the existing
/// face_id even when some options refuse; refusals surface in
/// `body.partial_failures`.
fn faces_create_idempotent(
    face_id: FaceId,
    uri: String,
    params: &ControlParameters,
    engine: &ForwarderEngine,
) -> ControlResponse {
    let target = match engine.faces().get(face_id) {
        Some(f) => f,
        None => {
            // Face went away between lookup and re-attach.
            return ControlResponse::error(
                status::NOT_FOUND,
                format!("face {} disappeared mid-request", face_id.0),
            );
        }
    };

    let mut partial_failures = Vec::new();
    let mut applied_mtu = None;
    let mut applied_persistency = None;
    let mut applied_flags = None;

    // Flags+Mask: refused bits collect into `partial_failures`
    // instead of short-circuiting (mirrors faces/update layout).
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
                partial_failures.push((
                    format!("flags:{}", err.option()),
                    refusal_reason_text(&err).to_owned(),
                ));
            }
        }
        if let Some(state) = engine.face_states().get(&face_id) {
            applied_flags = Some(state.apply_face_flags_mask(flags, mask));
        }
    }

    if let Some(mtu) = params.mtu {
        let arg = if mtu == 0 { None } else { Some(mtu) };
        match target.transport.set_send_mtu(arg) {
            Ok(eff) => applied_mtu = eff,
            Err(err) => {
                partial_failures.push(("mtu".to_owned(), mtu_refusal_reason(&err, target.kind())))
            }
        }
    }

    if let Some(p) = params.face_persistency {
        if let Some(persistency) = FacePersistency::from_u64(p) {
            match target.transport.set_persistency(persistency) {
                Ok(()) => applied_persistency = Some(p),
                Err(err) => partial_failures.push((
                    "persistency".to_owned(),
                    persistency_refusal_reason(&err, target.kind()),
                )),
            }
        } else {
            partial_failures.push(("persistency".to_owned(), "invalid-value".to_owned()));
        }
    }

    tracing::info!(
        target: "mgmt.face",
        face = face_id.0,
        uri = %uri,
        partial = partial_failures.len(),
        "faces/create (idempotent re-attach)",
    );

    let echo = ControlParameters {
        face_id: Some(face_id.0),
        uri: Some(uri),
        local_uri: target.local_uri(),
        flags: applied_flags,
        mtu: applied_mtu,
        face_persistency: applied_persistency,
        partial_failures,
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

#[cfg(not(target_arch = "wasm32"))]
async fn faces_create_udp(addr_str: &str, engine: &ForwarderEngine) -> ControlResponse {
    let peer: std::net::SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(e) => {
            return ControlResponse::error(
                status::BAD_PARAMS,
                format!("invalid UDP address '{addr_str}': {e}"),
            );
        }
    };

    let face_id = engine.faces().alloc_id();
    let local: std::net::SocketAddr = if peer.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };

    match ndn_faces::net::UdpFace::bind(local, peer, face_id).await {
        Ok(face) => {
            let local_uri = face.local_uri().unwrap_or_default();
            let cancel = CancellationToken::new();
            engine.add_face_with_persistency(face, cancel, FacePersistency::Persistent);
            tracing::info!(target: "mgmt.face", face = face_id.0, remote = %peer, "faces/create udp4");

            let echo = ControlParameters {
                face_id: Some(face_id.0),
                uri: Some(format!("udp4://{peer}")),
                local_uri: Some(local_uri),
                ..Default::default()
            };
            ControlResponse::ok("OK", echo)
        }
        Err(e) => {
            tracing::warn!(target: "mgmt.face", error = %e, remote = %peer, "faces/create udp4 failed");
            ControlResponse::error(
                status::SERVER_ERROR,
                format!("UDP face creation failed: {e}"),
            )
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn faces_create_tcp(addr_str: &str, engine: &ForwarderEngine) -> ControlResponse {
    let peer: std::net::SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(e) => {
            return ControlResponse::error(
                status::BAD_PARAMS,
                format!("invalid TCP address '{addr_str}': {e}"),
            );
        }
    };

    let face_id = engine.faces().alloc_id();

    match ndn_faces::net::tcp_face_connect(face_id, peer).await {
        Ok(face) => {
            let local_uri = face.local_uri().unwrap_or_default();
            let cancel = CancellationToken::new();
            engine.add_face_with_persistency(face, cancel, FacePersistency::Persistent);
            tracing::info!(target: "mgmt.face", face = face_id.0, remote = %peer, "faces/create tcp4");

            let echo = ControlParameters {
                face_id: Some(face_id.0),
                uri: Some(format!("tcp4://{peer}")),
                local_uri: Some(local_uri),
                ..Default::default()
            };
            ControlResponse::ok("OK", echo)
        }
        Err(e) => {
            tracing::warn!(target: "mgmt.face", error = %e, remote = %peer, "faces/create tcp4 failed");
            ControlResponse::error(
                status::SERVER_ERROR,
                format!("TCP face creation failed: {e}"),
            )
        }
    }
}

/// Dial a `wts://host:port[?cert=<sha256hex>]` WebTransport peer.
#[cfg(all(not(target_arch = "wasm32"), feature = "webtransport"))]
async fn faces_create_webtransport(uri: &str, engine: &ForwarderEngine) -> ControlResponse {
    use ndn_face_webtransport::{WebTransportFace, WtClientTls};

    let rest = uri.strip_prefix("wts://").unwrap_or(uri);
    let (authority, query) = match rest.split_once('?') {
        Some((a, q)) => (a, Some(q)),
        None => (rest, None),
    };

    // `?cert=<sha256hex>` pins a self-signed peer; absence falls back to WebPKI.
    let cert_hex = query.and_then(|q| {
        q.split('&')
            .find_map(|kv| kv.strip_prefix("cert="))
            .map(str::to_owned)
    });
    let tls = match cert_hex {
        Some(hex) => match ndn_config::parse_cert_sha256_hex(&hex) {
            Some(h) => WtClientTls::CertHashes(vec![h]),
            None => {
                return ControlResponse::error(
                    status::BAD_PARAMS,
                    format!("invalid cert hash (need 64 hex chars): {hex}"),
                );
            }
        },
        None => WtClientTls::WebPki,
    };

    let face_id = engine.faces().alloc_id();
    let url = format!("https://{authority}");
    match WebTransportFace::connect(face_id, &url, tls).await {
        Ok(face) => {
            let local_uri = face.local_uri().unwrap_or_default();
            let cancel = CancellationToken::new();
            engine.add_face_with_persistency(face, cancel, FacePersistency::Persistent);
            tracing::info!(target: "mgmt.face", face = face_id.0, remote = %authority, "faces/create wts");
            let echo = ControlParameters {
                face_id: Some(face_id.0),
                uri: Some(format!("wts://{authority}")),
                local_uri: Some(local_uri),
                ..Default::default()
            };
            ControlResponse::ok("OK", echo)
        }
        Err(e) => {
            tracing::warn!(target: "mgmt.face", error = %e, remote = %authority, "faces/create wts failed");
            ControlResponse::error(
                status::SERVER_ERROR,
                format!("WebTransport face creation failed: {e}"),
            )
        }
    }
}

/// Parse `framing=ndnts|ndnlpv2` out of a `ble://` URI query string.
#[cfg(all(not(target_arch = "wasm32"), feature = "bluetooth"))]
fn parse_ble_framing(query: &str) -> Option<ndn_faces::l2::BleFraming> {
    let v = parse_ble_query(query, "framing")?;
    match v.to_ascii_lowercase().as_str() {
        "ndnts" => Some(ndn_faces::l2::BleFraming::Ndnts),
        "ndnlpv2" => Some(ndn_faces::l2::BleFraming::Ndnlpv2),
        _ => None,
    }
}

/// Extract `key=value` from a `&`-separated query string.
#[cfg(all(not(target_arch = "wasm32"), feature = "bluetooth"))]
fn parse_ble_query(query: &str, key: &str) -> Option<String> {
    query
        .split('&')
        .find_map(|kv| kv.strip_prefix(&format!("{key}=")))
        .map(str::to_owned)
}

#[cfg(all(not(target_arch = "wasm32"), feature = "bluetooth"))]
async fn faces_create_ble_central(
    target: &str,
    framing: Option<ndn_faces::l2::BleFraming>,
    adapter: Option<&str>,
    engine: &ForwarderEngine,
) -> ControlResponse {
    let face_id = engine.faces().alloc_id();
    match ndn_faces::l2::BleCentralFace::connect(face_id, target, framing, adapter).await {
        Ok(face) => {
            let remote_uri = face.remote_uri().unwrap_or_else(|| format!("ble://{target}"));
            engine.add_face_with_persistency(
                face,
                CancellationToken::new(),
                FacePersistency::Persistent,
            );
            tracing::info!(target: "mgmt.face", face = face_id.0, %target, "faces/create ble central");
            let echo = ControlParameters {
                face_id: Some(face_id.0),
                uri: Some(remote_uri.clone()),
                local_uri: Some(remote_uri),
                ..Default::default()
            };
            ControlResponse::ok("OK", echo)
        }
        Err(e) => {
            tracing::warn!(target: "mgmt.face", error = %e, %target, "faces/create ble central failed");
            ControlResponse::error(status::SERVER_ERROR, format!("BLE central failed: {e}"))
        }
    }
}

#[cfg(all(unix, feature = "spsc-shm"))]
fn faces_create_shm(
    shm_name: &str,
    mtu: Option<u64>,
    source_face: Option<FaceId>,
    engine: &ForwarderEngine,
) -> ControlResponse {
    let face_id = engine.faces().alloc_id();

    let face_result = match mtu {
        Some(m) => {
            ndn_faces::local::shm::spsc::SpscFace::create_for_mtu(face_id, shm_name, m as usize)
        }
        None => ndn_faces::local::ShmFace::create(face_id, shm_name),
    };
    match face_result {
        Ok(face) => {
            let cancel = source_face
                .and_then(|sf| engine.face_token(sf))
                .map(|t| t.child_token())
                .unwrap_or_default();
            engine.add_face(face, cancel);
            tracing::info!(target: "mgmt.face", face = face_id.0, shm = shm_name, mtu = ?mtu, "faces/create shm");

            let echo = ControlParameters {
                face_id: Some(face_id.0),
                uri: Some(format!("shm://{shm_name}")),
                mtu,
                ..Default::default()
            };
            ControlResponse::ok("OK", echo)
        }
        Err(e) => {
            tracing::warn!(target: "mgmt.face", error = %e, shm = shm_name, "faces/create shm failed");
            ControlResponse::error(status::SERVER_ERROR, format!("SHM creation failed: {e}"))
        }
    }
}

#[cfg(not(all(unix, feature = "spsc-shm")))]
fn faces_create_shm(
    _shm_name: &str,
    _mtu: Option<u64>,
    _source_face: Option<FaceId>,
    _engine: &ForwarderEngine,
) -> ControlResponse {
    ControlResponse::error(
        status::SERVER_ERROR,
        "SHM faces not supported on this platform",
    )
}

/// `faces/update`.
///
/// - NFD flag bits decompose into `FaceOption::{LocalFields,
///   LpReliability, CongestionMarking}` through `LinkService::apply()`.
/// - `Mtu` / `FacePersistency` route to `Transport::set_send_mtu` /
///   `Transport::set_persistency`.
///
/// Failures surface as `field=<option> reason=<machine-readable>` in
/// `status_text` (greppable without decoding bitmaps).
fn faces_update(
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

fn refusal_reason_text(err: &FaceOptionError) -> &'static str {
    match err {
        FaceOptionError::NotSupportedByTransport { .. } => "transport-not-eligible",
        FaceOptionError::Immutable { .. } => "immutable",
        FaceOptionError::OutOfRange { reason, .. } => reason,
    }
}

fn mtu_refusal_reason(err: &MtuError, kind: FaceKind) -> String {
    match err {
        MtuError::NotSupported => "transport-not-eligible".to_owned(),
        MtuError::Immutable => format!("immutable-on-{kind}"),
        MtuError::OutOfRange { reason } => (*reason).to_owned(),
    }
}

fn persistency_refusal_reason(err: &PersistencyError, kind: FaceKind) -> String {
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

fn faces_list_dataset(engine: &ForwarderEngine) -> bytes::Bytes {
    use std::sync::atomic::Ordering;
    let entries = engine.faces().face_info();
    let face_states = engine.face_states();
    let mut buf = bytes::BytesMut::new();
    for info in &entries {
        let state = face_states.get(&info.id);
        let persistency = state
            .as_ref()
            .map(|s| s.persistency)
            .unwrap_or(FacePersistency::OnDemand);
        let face_persistency = match persistency {
            FacePersistency::Persistent => 0,
            FacePersistency::OnDemand => 1,
            FacePersistency::Permanent => 2,
        };
        let (
            n_in_interests,
            n_in_data,
            n_out_interests,
            n_out_data,
            n_in_bytes,
            n_out_bytes,
            n_satisfied_interests,
            n_unsatisfied_interests,
            face_flags,
        ) = state
            .as_ref()
            .map(|s| {
                (
                    s.counters.in_interests.load(Ordering::Relaxed),
                    s.counters.in_data.load(Ordering::Relaxed),
                    s.counters.out_interests.load(Ordering::Relaxed),
                    s.counters.out_data.load(Ordering::Relaxed),
                    s.counters.in_bytes.load(Ordering::Relaxed),
                    s.counters.out_bytes.load(Ordering::Relaxed),
                    s.counters.in_satisfied_interests.load(Ordering::Relaxed),
                    s.counters.in_unsatisfied_interests.load(Ordering::Relaxed),
                    s.face_flags_raw(),
                )
            })
            .unwrap_or_default();
        let face_scope =
            if ndn_transport::face::resolve_scope(info.kind, info.remote_uri.as_deref())
                == FaceScope::Local
            {
                1
            } else {
                0
            };
        let link_type = match info.kind {
            FaceKind::EtherMulticast | FaceKind::Multicast => 1,
            _ => 0,
        };
        let uri = info
            .remote_uri
            .clone()
            .unwrap_or_else(|| format!("internal://{}", info.kind));

        // ndn-rs extension fields from the face's LinkService snapshot
        // + feature counters. Bare NFD shape when the face has no
        // Lp-side (Passthrough: empty feature_set, None counters).
        let mut effective_mtu = None;
        let mut base_cong_interval = None;
        let mut def_cong_threshold = None;
        let mut feature_set = Vec::new();
        let mut reliability_counters = None;
        let mut congestion_counters = None;
        if let Some(face) = engine.faces().get(info.id) {
            let snap = face.link_service.snapshot();
            effective_mtu = snap.effective_mtu;
            base_cong_interval = snap.base_congestion_marking_interval.map(duration_to_us);
            def_cong_threshold = snap.default_congestion_threshold;
            feature_set = face
                .link_service
                .feature_names()
                .into_iter()
                .map(String::from)
                .collect();
            reliability_counters = face.link_service.reliability_counters();
            congestion_counters = face.link_service.congestion_counters();
        }
        let (n_lp_resent_packets, rto_micros) = match reliability_counters {
            Some((resent, rto)) => (Some(resent), Some(rto)),
            None => (None, None),
        };
        let (n_congestion_marks_sent, n_congestion_marks_received) = match congestion_counters {
            Some((sent, recv)) => (Some(sent), Some(recv)),
            None => (None, None),
        };

        let fs = nfd_dataset::FaceStatus {
            face_id: info.id.0,
            uri,
            local_uri: info.local_uri.clone().unwrap_or_default(),
            face_scope,
            face_persistency,
            link_type,
            mtu: None,
            base_congestion_marking_interval: base_cong_interval,
            default_congestion_threshold: def_cong_threshold,
            n_in_interests,
            n_in_data,
            n_in_nacks: 0,
            n_out_interests,
            n_out_data,
            n_out_nacks: 0,
            n_in_bytes,
            n_out_bytes,
            n_satisfied_interests,
            n_unsatisfied_interests,
            flags: face_flags,
            n_lp_acks_received: None,
            n_lp_resent_packets,
            n_lp_rto_expirations: None,
            n_congestion_marks_sent,
            n_congestion_marks_received,
            effective_mtu,
            feature_set,
            rto_micros,
        };
        buf.extend_from_slice(&fs.encode());
    }
    buf.freeze()
}

fn duration_to_us(d: std::time::Duration) -> u64 {
    d.as_micros().min(u64::MAX as u128) as u64
}

fn faces_counters(engine: &ForwarderEngine) -> ControlResponse {
    use std::sync::atomic::Ordering;
    let face_states = engine.face_states();
    let entries = engine.faces().face_info();
    let mut text = format!("{} faces\n", entries.len());
    for info in &entries {
        if let Some(s) = face_states.get(&info.id) {
            text.push_str(&format!(
                "  faceid={} in_interests={} in_data={} out_interests={} out_data={} in_bytes={} out_bytes={}\n",
                info.id.0,
                s.counters.in_interests.load(Ordering::Relaxed),
                s.counters.in_data.load(Ordering::Relaxed),
                s.counters.out_interests.load(Ordering::Relaxed),
                s.counters.out_data.load(Ordering::Relaxed),
                s.counters.in_bytes.load(Ordering::Relaxed),
                s.counters.out_bytes.load(Ordering::Relaxed),
            ));
        }
    }
    ControlResponse::ok_empty(text)
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
        let outcome = handle_faces(verb, params, ctx.source_face, ctx.engine).await;
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
