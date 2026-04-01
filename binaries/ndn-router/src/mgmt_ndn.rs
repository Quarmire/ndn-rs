/// NFD-compatible management server.
///
/// Implements the NFD Management Protocol over NDN Interest/Data packets.
/// Management Interests use the name structure:
///
/// ```text
/// /localhost/nfd/<module>/<verb>/<ControlParameters>
/// ```
///
/// # Supported modules
///
/// - **rib**: `register`, `unregister`, `list`
/// - **faces**: `create`, `destroy`, `list`
/// - **fib**: `add-nexthop`, `remove-nexthop`, `list`
/// - **strategy-choice**: `set`, `unset`, `list`
/// - **cs**: `config`, `info`
/// - **status**: `general`, `shutdown`
///
/// # Source face propagation
///
/// When a command omits `FaceId`, the handler resolves the requesting face from
/// the PIT in-records via [`ForwarderEngine::source_face_id`].
use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use ndn_face_local::AppHandle;
use ndn_engine::ForwarderEngine;
use ndn_engine::stages::ErasedStrategy;
use ndn_packet::{Interest, Name, NameComponent, encode::encode_data_unsigned};
use ndn_store::ContentStore;
use ndn_strategy::{BestRouteStrategy, MulticastStrategy};
use ndn_transport::FaceId;
use tokio_util::sync::CancellationToken;

use ndn_config::{
    ControlParameters, ControlResponse,
    control_parameters::{origin, route_flags},
    control_response::status,
    nfd_command::{module, verb, parse_command_name},
};

// ─── Management prefix ────────────────────────────────────────────────────────

/// Build the `/localhost/nfd` name prefix registered in the FIB.
pub fn mgmt_prefix() -> Name {
    Name::from_components([
        NameComponent::generic(Bytes::from_static(b"localhost")),
        NameComponent::generic(Bytes::from_static(b"nfd")),
    ])
}

// ─── Face listener ────────────────────────────────────────────────────────────

/// Accept NDN face connections on `path` and register each as a dynamic face.
pub async fn run_face_listener(
    path:   &Path,
    engine: ForwarderEngine,
    cancel: CancellationToken,
) {
    let _ = std::fs::remove_file(path);

    let listener = match tokio::net::UnixListener::bind(path) {
        Ok(l)  => l,
        Err(e) => {
            tracing::error!(path = %path.display(), error = %e, "face-listener: bind failed");
            return;
        }
    };

    tracing::info!(path = %path.display(), "NDN face listener ready");

    loop {
        let (stream, _addr) = tokio::select! {
            _ = cancel.cancelled() => break,
            r = listener.accept() => match r {
                Ok(s)  => s,
                Err(e) => {
                    tracing::warn!(error = %e, "face-listener: accept error");
                    continue;
                }
            },
        };

        let face_id = engine.faces().alloc_id();
        let face    = ndn_face_local::UnixFace::from_stream(face_id, stream, path);
        tracing::debug!(face = %face_id, "face-listener: accepted connection");
        engine.add_face(face, cancel.clone());
    }

    let _ = std::fs::remove_file(path);
    tracing::info!("NDN face listener stopped");
}

// ─── Management handler ───────────────────────────────────────────────────────

/// Read Interests from the management `AppHandle`, dispatch NFD commands,
/// and write Data responses back.
pub async fn run_ndn_mgmt_handler(
    mut handle: AppHandle,
    engine:     ForwarderEngine,
    cancel:     CancellationToken,
) {
    loop {
        let raw = tokio::select! {
            _ = cancel.cancelled() => break,
            r = handle.recv() => match r {
                Some(b) => b,
                None    => break,
            },
        };

        let interest = match Interest::decode(raw) {
            Ok(i)  => i,
            Err(e) => {
                tracing::warn!(error = %e, "nfd-mgmt: malformed Interest; skipping");
                continue;
            }
        };

        let source_face = engine.source_face_id(&interest);

        let parsed = match parse_command_name(&interest.name) {
            Some(p) => p,
            None => {
                let resp = ControlResponse::error(status::BAD_PARAMS, "invalid command name");
                send_response(&mut handle, &interest.name, &resp).await;
                continue;
            }
        };

        let params = parsed.params.unwrap_or_default();

        let resp = dispatch_command(
            parsed.module.as_ref(),
            parsed.verb.as_ref(),
            params,
            source_face,
            &engine,
            &cancel,
        );

        send_response(&mut handle, &interest.name, &resp).await;
    }

    tracing::info!("NFD management handler stopped");
}

// ─── Command dispatch ─────────────────────────────────────────────────────────

fn dispatch_command(
    module_name: &[u8],
    verb_name:   &[u8],
    params:      ControlParameters,
    source_face: Option<FaceId>,
    engine:      &ForwarderEngine,
    cancel:      &CancellationToken,
) -> ControlResponse {
    match module_name {
        m if m == module::RIB      => handle_rib(verb_name, params, source_face, engine),
        m if m == module::FACES    => handle_faces(verb_name, params, engine),
        m if m == module::FIB      => handle_fib(verb_name, params, source_face, engine),
        m if m == module::STRATEGY => handle_strategy(verb_name, params, engine),
        m if m == module::CS       => handle_cs(verb_name, engine),
        m if m == module::STATUS   => handle_status(verb_name, engine, cancel),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown module"),
    }
}

// ─── RIB module ───────────────────────────────────────────────────────────────

fn handle_rib(
    verb_name:   &[u8],
    params:      ControlParameters,
    source_face: Option<FaceId>,
    engine:      &ForwarderEngine,
) -> ControlResponse {
    match verb_name {
        v if v == verb::REGISTER   => rib_register(params, source_face, engine),
        v if v == verb::UNREGISTER => rib_unregister(params, source_face, engine),
        v if v == verb::LIST       => rib_list(engine),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown rib verb"),
    }
}

fn rib_register(
    params:      ControlParameters,
    source_face: Option<FaceId>,
    engine:      &ForwarderEngine,
) -> ControlResponse {
    let name = match &params.name {
        Some(n) => n.clone(),
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };

    let face_id = match resolve_face_id(&params, source_face) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let cost = params.cost.unwrap_or(0) as u32;

    engine.fib().add_nexthop(&name, face_id, cost);

    tracing::info!(prefix = %format_name(&name), face = face_id.0, cost, "rib/register");

    let echo = ControlParameters {
        name: Some(name),
        face_id: Some(face_id.0 as u64),
        origin: Some(params.origin.unwrap_or(origin::APP)),
        cost: Some(cost as u64),
        flags: Some(params.flags.unwrap_or(route_flags::CHILD_INHERIT)),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn rib_unregister(
    params:      ControlParameters,
    source_face: Option<FaceId>,
    engine:      &ForwarderEngine,
) -> ControlResponse {
    let name = match &params.name {
        Some(n) => n.clone(),
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };

    let face_id = match resolve_face_id(&params, source_face) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    engine.fib().remove_nexthop(&name, face_id);
    tracing::info!(prefix = %format_name(&name), face = face_id.0, "rib/unregister");

    let echo = ControlParameters {
        name: Some(name),
        face_id: Some(face_id.0 as u64),
        origin: Some(params.origin.unwrap_or(origin::APP)),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn rib_list(engine: &ForwarderEngine) -> ControlResponse {
    // RIB in ndn-rs maps directly to the FIB.
    fib_list(engine)
}

// ─── Faces module ─────────────────────────────────────────────────────────────

fn handle_faces(
    verb_name: &[u8],
    params:    ControlParameters,
    engine:    &ForwarderEngine,
) -> ControlResponse {
    match verb_name {
        v if v == verb::CREATE  => faces_create(params, engine),
        v if v == verb::DESTROY => faces_destroy(params, engine),
        v if v == verb::LIST    => faces_list(engine),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown faces verb"),
    }
}

fn faces_create(params: ControlParameters, engine: &ForwarderEngine) -> ControlResponse {
    let uri = match &params.uri {
        Some(u) => u.clone(),
        None => return ControlResponse::error(status::BAD_PARAMS, "Uri is required"),
    };

    if let Some(shm_name) = uri.strip_prefix("shm://") {
        return faces_create_shm(shm_name, engine);
    }

    ControlResponse::error(status::BAD_PARAMS, format!("unsupported URI scheme: {uri}"))
}

#[cfg(all(unix, feature = "spsc-shm"))]
fn faces_create_shm(shm_name: &str, engine: &ForwarderEngine) -> ControlResponse {
    let face_id = engine.faces().alloc_id();

    match ndn_face_local::ShmFace::create(face_id, shm_name) {
        Ok(face) => {
            let cancel = CancellationToken::new();
            engine.add_face(face, cancel);
            tracing::info!(face = face_id.0, shm = shm_name, "faces/create shm");

            let echo = ControlParameters {
                face_id: Some(face_id.0 as u64),
                uri: Some(format!("shm://{shm_name}")),
                ..Default::default()
            };
            ControlResponse::ok("OK", echo)
        }
        Err(e) => {
            tracing::warn!(error = %e, shm = shm_name, "faces/create shm failed");
            ControlResponse::error(status::SERVER_ERROR, format!("SHM creation failed: {e}"))
        }
    }
}

#[cfg(not(all(unix, feature = "spsc-shm")))]
fn faces_create_shm(_shm_name: &str, _engine: &ForwarderEngine) -> ControlResponse {
    ControlResponse::error(status::SERVER_ERROR, "SHM faces not supported on this platform")
}

fn faces_destroy(params: ControlParameters, engine: &ForwarderEngine) -> ControlResponse {
    let face_id = match params.face_id {
        Some(id) => FaceId(id as u32),
        None => return ControlResponse::error(status::BAD_PARAMS, "FaceId is required"),
    };

    engine.faces().remove(face_id);
    tracing::info!(face = face_id.0, "faces/destroy");

    let echo = ControlParameters {
        face_id: Some(face_id.0 as u64),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn faces_list(engine: &ForwarderEngine) -> ControlResponse {
    let entries = engine.faces().face_entries();
    // Encode face list as a multi-line status text (pragmatic approach).
    // Full NFD dataset encoding (segmented Data with FaceStatus TLV) can be
    // added later.
    let mut text = format!("{} faces\n", entries.len());
    for (id, kind) in &entries {
        text.push_str(&format!("  faceid={} kind={:?}\n", id.0, kind));
    }
    ControlResponse::ok_empty(text)
}

// ─── FIB module ───────────────────────────────────────────────────────────────

fn handle_fib(
    verb_name:   &[u8],
    params:      ControlParameters,
    source_face: Option<FaceId>,
    engine:      &ForwarderEngine,
) -> ControlResponse {
    match verb_name {
        v if v == verb::ADD_NEXTHOP    => fib_add_nexthop(params, source_face, engine),
        v if v == verb::REMOVE_NEXTHOP => fib_remove_nexthop(params, source_face, engine),
        v if v == verb::LIST           => fib_list(engine),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown fib verb"),
    }
}

fn fib_add_nexthop(
    params:      ControlParameters,
    source_face: Option<FaceId>,
    engine:      &ForwarderEngine,
) -> ControlResponse {
    let name = match &params.name {
        Some(n) => n.clone(),
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };

    let face_id = match resolve_face_id(&params, source_face) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let cost = params.cost.unwrap_or(0) as u32;

    engine.fib().add_nexthop(&name, face_id, cost);
    tracing::info!(prefix = %format_name(&name), face = face_id.0, cost, "fib/add-nexthop");

    let echo = ControlParameters {
        name: Some(name),
        face_id: Some(face_id.0 as u64),
        cost: Some(cost as u64),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn fib_remove_nexthop(
    params:      ControlParameters,
    source_face: Option<FaceId>,
    engine:      &ForwarderEngine,
) -> ControlResponse {
    let name = match &params.name {
        Some(n) => n.clone(),
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };

    let face_id = match resolve_face_id(&params, source_face) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    engine.fib().remove_nexthop(&name, face_id);
    tracing::info!(prefix = %format_name(&name), face = face_id.0, "fib/remove-nexthop");

    let echo = ControlParameters {
        name: Some(name),
        face_id: Some(face_id.0 as u64),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn fib_list(engine: &ForwarderEngine) -> ControlResponse {
    let routes = engine.fib().dump();
    let mut text = format!("{} routes\n", routes.len());
    for (name, entry) in &routes {
        let nexthops: Vec<String> = entry.nexthops.iter()
            .map(|nh| format!("faceid={} cost={}", nh.face_id.0, nh.cost))
            .collect();
        text.push_str(&format!("  {} nexthops=[{}]\n",
            format_name(name), nexthops.join(", ")));
    }
    ControlResponse::ok_empty(text)
}

// ─── Strategy-choice module ──────────────────────────────────────────────────

fn handle_strategy(
    verb_name: &[u8],
    params:    ControlParameters,
    engine:    &ForwarderEngine,
) -> ControlResponse {
    match verb_name {
        v if v == verb::SET    => strategy_set(params, engine),
        v if v == verb::UNSET  => strategy_unset(params, engine),
        v if v == verb::LIST   => strategy_list(engine),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown strategy-choice verb"),
    }
}

/// Instantiate a strategy by its NFD-style name.
///
/// Known strategies:
/// - `/localhost/nfd/strategy/best-route`
/// - `/localhost/nfd/strategy/multicast`
fn create_strategy_by_name(name: &Name) -> Option<Arc<dyn ErasedStrategy>> {
    let comps = name.components();
    // Expect /localhost/nfd/strategy/<name> — match on the last component.
    let short_name = if comps.len() >= 4
        && comps[0].value.as_ref() == b"localhost"
        && comps[1].value.as_ref() == b"nfd"
        && comps[2].value.as_ref() == b"strategy"
    {
        comps[3].value.as_ref()
    } else if comps.len() == 1 {
        // Allow bare name like just "best-route".
        comps[0].value.as_ref()
    } else {
        return None;
    };

    match short_name {
        b"best-route" => Some(Arc::new(BestRouteStrategy::new())),
        b"multicast"  => Some(Arc::new(MulticastStrategy::new())),
        _ => None,
    }
}

fn strategy_set(params: ControlParameters, engine: &ForwarderEngine) -> ControlResponse {
    let prefix = match &params.name {
        Some(n) => n.clone(),
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };

    let strategy_name = match &params.strategy {
        Some(n) => n.clone(),
        None => return ControlResponse::error(status::BAD_PARAMS, "Strategy is required"),
    };

    let strategy = match create_strategy_by_name(&strategy_name) {
        Some(s) => s,
        None => return ControlResponse::error(
            status::NOT_FOUND,
            format!("unknown strategy: {}", format_name(&strategy_name)),
        ),
    };

    engine.strategy_table().insert(&prefix, strategy);

    tracing::info!(
        prefix = %format_name(&prefix),
        strategy = %format_name(&strategy_name),
        "strategy-choice/set"
    );

    let echo = ControlParameters {
        name: Some(prefix),
        strategy: Some(strategy_name),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn strategy_unset(params: ControlParameters, engine: &ForwarderEngine) -> ControlResponse {
    let prefix = match &params.name {
        Some(n) => n.clone(),
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };

    // Prevent unsetting the root strategy.
    if prefix.is_empty() {
        return ControlResponse::error(
            status::BAD_PARAMS,
            "cannot unset strategy at root prefix"
        );
    }

    engine.strategy_table().remove(&prefix);

    tracing::info!(prefix = %format_name(&prefix), "strategy-choice/unset");

    let echo = ControlParameters {
        name: Some(prefix),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn strategy_list(engine: &ForwarderEngine) -> ControlResponse {
    let entries = engine.strategy_table().dump();
    let mut text = format!("{} strategy entries\n", entries.len());
    for (prefix, strategy) in &entries {
        text.push_str(&format!("  prefix={} strategy={}\n",
            format_name(prefix), format_name(strategy.name())));
    }
    ControlResponse::ok_empty(text)
}

// ─── CS module ───────────────────────────────────────────────────────────────

fn handle_cs(
    verb_name: &[u8],
    engine:    &ForwarderEngine,
) -> ControlResponse {
    match verb_name {
        v if v == verb::CONFIG => cs_config(engine),
        v if v == verb::INFO   => cs_info(engine),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown cs verb"),
    }
}

fn cs_config(engine: &ForwarderEngine) -> ControlResponse {
    let cs = engine.cs();
    let cap = cs.capacity();
    let echo = ControlParameters {
        // Repurpose capacity field for CS max bytes.
        // NFD uses a dedicated Capacity TLV (0x83) — we encode it here.
        cost: Some(cap.max_bytes as u64),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn cs_info(engine: &ForwarderEngine) -> ControlResponse {
    let cs = engine.cs();
    let cap = cs.capacity();
    let n_entries = cs.len();
    let current = cs.current_bytes();

    let text = format!(
        "capacity={}B entries={} used={}B",
        cap.max_bytes, n_entries, current,
    );
    ControlResponse::ok_empty(text)
}

// ─── Status module ────────────────────────────────────────────────────────────

fn handle_status(
    verb_name: &[u8],
    engine:    &ForwarderEngine,
    cancel:    &CancellationToken,
) -> ControlResponse {
    match verb_name {
        b"general" => {
            let n_faces = engine.faces().face_entries().len();
            let n_fib   = engine.fib().dump().len();
            let n_pit   = engine.pit().len();
            let n_cs    = engine.cs().len();

            let text = format!(
                "faces={n_faces} fib={n_fib} pit={n_pit} cs={n_cs}"
            );
            ControlResponse::ok_empty(text)
        }
        b"shutdown" => {
            tracing::info!("status/shutdown requested");
            cancel.cancel();
            ControlResponse::ok_empty("OK")
        }
        _ => ControlResponse::error(status::NOT_FOUND, "unknown status verb"),
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Resolve FaceId from params or source face.
///
/// Returns the error as a `ControlResponse` via the `?` operator on `Result`.
fn resolve_face_id(
    params: &ControlParameters,
    source_face: Option<FaceId>,
) -> Result<FaceId, ControlResponse> {
    match params.face_id {
        Some(id) => Ok(FaceId(id as u32)),
        None => source_face.ok_or_else(|| {
            ControlResponse::error(status::BAD_PARAMS, "cannot determine FaceId")
        }),
    }
}

async fn send_response(handle: &mut AppHandle, name: &Name, resp: &ControlResponse) {
    let content = resp.encode();
    let data = encode_data_unsigned(name, &content);
    if let Err(e) = handle.send(data).await {
        tracing::warn!(error = %e, "nfd-mgmt: failed to send Data response");
    }
}

fn format_name(name: &Name) -> String {
    let mut s = String::new();
    for comp in name.components() {
        s.push('/');
        for &b in comp.value.iter() {
            if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' {
                s.push(b as char);
            } else {
                s.push_str(&format!("%{b:02X}"));
            }
        }
    }
    if s.is_empty() { s.push('/'); }
    s
}
