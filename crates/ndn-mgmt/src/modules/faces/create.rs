//! `faces/create` — URI-scheme dispatch and per-transport face dialing,
//! plus idempotent re-attach of an existing face.

use ndn_config::{ControlParameters, ControlResponse, control_response::status};
use ndn_engine::ForwarderEngine;
use ndn_transport::{
    BIT_CONGESTION_MARKING, BIT_LOCAL_FIELDS, BIT_LP_RELIABILITY, FaceId, FaceOption,
    FacePersistency,
};
// Only the native face-creation paths (UDP/TCP/… dialing) spawn faces with a
// cancel token; wasm32 has no such transports here.
#[cfg(not(target_arch = "wasm32"))]
use ndn_transport::Transport;
#[cfg(not(target_arch = "wasm32"))]
use tokio_util::sync::CancellationToken;

use super::update::{mtu_refusal_reason, persistency_refusal_reason, refusal_reason_text};

pub(super) async fn faces_create(
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

    // `ether://[<peer-mac>]/<iface>` opens a unicast NDN-over-Ethernet link
    // (EtherType 0x8624) to a known peer MAC. Linux/macOS/Windows; requires
    // CAP_NET_RAW/root. The peer MAC must be supplied — neighbor discovery is
    // not yet wired into runtime creation.
    #[cfg(all(
        feature = "l2",
        not(target_arch = "wasm32"),
        any(target_os = "linux", target_os = "macos", target_os = "windows")
    ))]
    {
        if uri.starts_with("ether://") {
            return faces_create_ether(&uri, engine);
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

    // `quic://host:port?cert=<sha256hex>` dials a raw-QUIC backbone peer. The
    // `?cert=` pin is required (no WebPKI path for the raw-QUIC dialer).
    #[cfg(all(not(target_arch = "wasm32"), feature = "quic"))]
    {
        if uri.starts_with("quic://") {
            return faces_create_quic(&uri, engine).await;
        }
    }

    // `ble://<name-or-address>[?opts]` dials a peripheral as a GATT central
    // (Linux/macOS/Windows). The peripheral (GATT server) is NOT created here —
    // it is an NFD-style listener configured via `[listeners.ble]` (see
    // `ndn_face_native::l2::BleListener`). Any `?query` is split off the target; the
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

fn face_persistency_code(persistency: FacePersistency) -> u64 {
    match persistency {
        FacePersistency::Persistent => 0,
        FacePersistency::OnDemand => 1,
        FacePersistency::Permanent => 2,
    }
}

fn face_flags(engine: &ForwarderEngine, face_id: FaceId) -> Option<u64> {
    engine
        .face_states()
        .get(&face_id)
        .map(|state| state.face_flags_raw())
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
    let mut applied_persistency = engine
        .face_states()
        .get(&face_id)
        .map(|s| face_persistency_code(s.persistency));
    let mut applied_flags = engine
        .face_states()
        .get(&face_id)
        .map(|s| s.face_flags_raw());

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

    match ndn_face_native::net::UdpFace::bind(local, peer, face_id).await {
        Ok(face) => {
            let local_uri = face.local_uri().unwrap_or_default();
            let cancel = CancellationToken::new();
            engine.add_face_with_persistency(face, cancel, FacePersistency::Persistent);
            tracing::info!(target: "mgmt.face", face = face_id.0, remote = %peer, "faces/create udp4");

            let echo = ControlParameters {
                face_id: Some(face_id.0),
                uri: Some(format!("udp4://{peer}")),
                local_uri: Some(local_uri),
                face_persistency: Some(face_persistency_code(FacePersistency::Persistent)),
                flags: face_flags(engine, face_id),
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

    match ndn_face_native::net::tcp_face_connect(face_id, peer).await {
        Ok(face) => {
            let local_uri = face.local_uri().unwrap_or_default();
            let cancel = CancellationToken::new();
            engine.add_face_with_persistency(face, cancel, FacePersistency::Persistent);
            tracing::info!(target: "mgmt.face", face = face_id.0, remote = %peer, "faces/create tcp4");

            let echo = ControlParameters {
                face_id: Some(face_id.0),
                uri: Some(format!("tcp4://{peer}")),
                local_uri: Some(local_uri),
                face_persistency: Some(face_persistency_code(FacePersistency::Persistent)),
                flags: face_flags(engine, face_id),
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

/// Open a unicast Ethernet face from `ether://[<peer-mac>]/<iface>`.
#[cfg(all(
    feature = "l2",
    not(target_arch = "wasm32"),
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
fn faces_create_ether(uri: &str, engine: &ForwarderEngine) -> ControlResponse {
    let (peer_mac, iface) = match parse_ether_uri(uri) {
        Ok(parsed) => parsed,
        Err(msg) => return ControlResponse::error(status::BAD_PARAMS, msg),
    };

    let face_id = engine.faces().alloc_id();
    match ndn_face_native::l2::NamedEtherFace::new(
        face_id,
        ndn_packet::Name::root(),
        peer_mac,
        &iface,
        ndn_face_native::l2::RadioFaceMetadata::default(),
    ) {
        Ok(face) => {
            let remote_uri = face.remote_uri();
            let local_uri = face.local_uri().unwrap_or_default();
            let cancel = CancellationToken::new();
            engine.add_face_with_persistency(face, cancel, FacePersistency::Persistent);
            tracing::info!(target: "mgmt.face", face = face_id.0, uri = %uri, "faces/create ether");
            let echo = ControlParameters {
                face_id: Some(face_id.0),
                uri: remote_uri,
                local_uri: Some(local_uri),
                face_persistency: Some(face_persistency_code(FacePersistency::Persistent)),
                flags: face_flags(engine, face_id),
                ..Default::default()
            };
            ControlResponse::ok("OK", echo)
        }
        Err(e) => {
            tracing::warn!(target: "mgmt.face", error = %e, uri = %uri, "faces/create ether failed");
            ControlResponse::error(
                status::SERVER_ERROR,
                format!("Ethernet face creation failed: {e}"),
            )
        }
    }
}

/// Parse `ether://[<peer-mac>]/<iface>` into `(peer_mac, iface)`. Pure (no I/O
/// or privileges) so it is unit-testable. Returns a user-facing error string
/// on malformed input.
#[cfg(all(
    feature = "l2",
    not(target_arch = "wasm32"),
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
pub(super) fn parse_ether_uri(uri: &str) -> Result<(ndn_transport::MacAddr, String), String> {
    let rest = uri.strip_prefix("ether://").unwrap_or(uri);
    let (mac_str, iface) = rest
        .strip_prefix('[')
        .and_then(|r| r.split_once(']'))
        .and_then(|(mac, tail)| tail.strip_prefix('/').map(|iface| (mac, iface)))
        .filter(|(_, iface)| !iface.is_empty())
        .ok_or_else(|| format!("ether URI must be ether://[<peer-mac>]/<iface>: {uri}"))?;
    let peer_mac: ndn_transport::MacAddr = mac_str
        .parse()
        .map_err(|_| format!("invalid peer MAC '{mac_str}'"))?;
    Ok((peer_mac, iface.to_owned()))
}

/// Dial a `wts://host:port[?cert=<sha256hex>]` WebTransport peer.
#[cfg(all(not(target_arch = "wasm32"), feature = "webtransport"))]
async fn faces_create_webtransport(uri: &str, engine: &ForwarderEngine) -> ControlResponse {
    use ndn_face_webtransport::WebTransportFace;
    use ndn_transport::ClientTls;

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
            Some(h) => ClientTls::CertHashes(vec![h]),
            None => {
                return ControlResponse::error(
                    status::BAD_PARAMS,
                    format!("invalid cert hash (need 64 hex chars): {hex}"),
                );
            }
        },
        None => ClientTls::WebPki,
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
                face_persistency: Some(face_persistency_code(FacePersistency::Persistent)),
                flags: face_flags(engine, face_id),
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

/// Dial a `quic://host:port?cert=<sha256hex>` (pin) or `quic://host:port?webpki`
/// (validate against WebPKI roots) raw-QUIC peer.
#[cfg(all(not(target_arch = "wasm32"), feature = "quic"))]
async fn faces_create_quic(uri: &str, engine: &ForwarderEngine) -> ControlResponse {
    use ndn_face_quic::QuicConnector;
    use ndn_transport::ClientTls;

    let rest = uri.strip_prefix("quic://").unwrap_or(uri);
    let (authority, query) = match rest.split_once('?') {
        Some((a, q)) => (a, Some(q)),
        None => (rest, None),
    };
    let params: Vec<&str> = query.map(|q| q.split('&').collect()).unwrap_or_default();
    let cert_hex = params.iter().find_map(|kv| kv.strip_prefix("cert="));
    let webpki = params
        .iter()
        .any(|kv| *kv == "webpki" || *kv == "webpki=true");

    let tls = if let Some(hex) = cert_hex {
        match ndn_config::parse_cert_sha256_hex(hex) {
            Some(h) => ClientTls::CertHashes(vec![h]),
            None => {
                return ControlResponse::error(
                    status::BAD_PARAMS,
                    format!("invalid cert hash (need 64 hex chars): {hex}"),
                );
            }
        }
    } else if webpki {
        ClientTls::WebPki
    } else {
        return ControlResponse::error(
            status::BAD_PARAMS,
            "quic:// requires ?cert=<64 hex chars> (pin) or ?webpki",
        );
    };

    let connector = match QuicConnector::new(tls) {
        Ok(c) => c,
        Err(e) => {
            return ControlResponse::error(status::SERVER_ERROR, format!("QUIC connector: {e}"));
        }
    };
    let face_id = engine.faces().alloc_id();
    // The connector (endpoint) may drop after connect; the face's streams keep
    // the connection and its I/O driver alive.
    match connector.connect_authority(face_id, authority).await {
        Ok(face) => {
            let local_uri = face.local_uri().unwrap_or_default();
            engine.add_face_with_persistency(
                face,
                CancellationToken::new(),
                FacePersistency::Persistent,
            );
            tracing::info!(target: "mgmt.face", face = face_id.0, remote = %authority, "faces/create quic");
            let echo = ControlParameters {
                face_id: Some(face_id.0),
                uri: Some(format!("quic://{authority}")),
                local_uri: Some(local_uri),
                face_persistency: Some(face_persistency_code(FacePersistency::Persistent)),
                flags: face_flags(engine, face_id),
                ..Default::default()
            };
            ControlResponse::ok("OK", echo)
        }
        Err(e) => {
            tracing::warn!(target: "mgmt.face", error = %e, remote = %authority, "faces/create quic failed");
            ControlResponse::error(
                status::SERVER_ERROR,
                format!("QUIC face creation failed: {e}"),
            )
        }
    }
}

/// Parse `framing=ndnts|ndnlpv2` out of a `ble://` URI query string.
#[cfg(all(not(target_arch = "wasm32"), feature = "bluetooth"))]
fn parse_ble_framing(query: &str) -> Option<ndn_face_native::l2::BleFraming> {
    let v = parse_ble_query(query, "framing")?;
    match v.to_ascii_lowercase().as_str() {
        "ndnts" => Some(ndn_face_native::l2::BleFraming::Ndnts),
        "ndnlpv2" => Some(ndn_face_native::l2::BleFraming::Ndnlpv2),
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
    framing: Option<ndn_face_native::l2::BleFraming>,
    adapter: Option<&str>,
    engine: &ForwarderEngine,
) -> ControlResponse {
    let face_id = engine.faces().alloc_id();
    match ndn_face_native::l2::BleCentralFace::connect(face_id, target, framing, adapter).await {
        Ok(face) => {
            let remote_uri = face
                .remote_uri()
                .unwrap_or_else(|| format!("ble://{target}"));
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
                face_persistency: Some(face_persistency_code(FacePersistency::Persistent)),
                flags: face_flags(engine, face_id),
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
        Some(m) => ndn_face_native::local::shm::spsc::SpscFace::create_for_mtu(
            face_id, shm_name, m as usize,
        ),
        None => ndn_face_native::local::ShmFace::create(face_id, shm_name),
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
                face_persistency: Some(face_persistency_code(FacePersistency::OnDemand)),
                flags: face_flags(engine, face_id),
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
