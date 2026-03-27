/// iceoryx2-based management server.
///
/// Provides the same `ManagementRequest` / `ManagementResponse` protocol as
/// the Unix-socket transport but over iceoryx2 shared-memory IPC, which works
/// on Linux, macOS, and Windows.
///
/// # Service layout
///
/// A single iceoryx2 `request_response` service is created under the name
/// supplied by the caller (default `"ndn/router/mgmt"`).  Requests and
/// responses are encoded as null-padded JSON in a fixed 4 KiB shared-memory
/// buffer — no serialization copy; the data lands directly in the slot.
///
/// # Wire types
///
/// Both [`MgmtReq`] and [`MgmtResp`] carry a `data: [u8; 4096]` field that
/// holds a null-terminated JSON string.  They must be `#[repr(C)]` and derive
/// [`ZeroCopySend`] so iceoryx2 can transfer them through shared memory
/// without any heap allocation.
///
/// # Client example (Rust)
///
/// ```ignore
/// use iceoryx2::prelude::*;
///
/// let node   = NodeBuilder::new().create::<ipc::Service>()?;
/// let service = node
///     .service_builder(&"ndn/router/mgmt".try_into()?)
///     .request_response::<MgmtReq, MgmtResp>()
///     .open_or_create()?;
/// let client = service.client_builder().create()?;
///
/// // Borrow a request slot from shared memory and fill it.
/// let mut request = client.loan_uninit()?;
/// let json = br#"{"type":"GetStats"}"#;
/// request.payload_mut().data[..json.len()].copy_from_slice(json);
/// let pending = request.assume_init().send()?;
///
/// // Wait for the server's response.
/// while let Some(response) = pending.receive()? {
///     let end = response.data.iter().position(|&b| b == 0).unwrap_or(4096);
///     println!("{}", std::str::from_utf8(&response.data[..end]).unwrap());
/// }
/// ```
use std::sync::Arc;
use std::time::Duration;

use iceoryx2::node::NodeWaitFailure;
use iceoryx2::prelude::*;
use tokio_util::sync::CancellationToken;

use ndn_config::{ManagementResponse, ManagementServer};
use ndn_engine::ForwarderEngine;

// ─── Wire types ───────────────────────────────────────────────────────────────

/// Management request payload: null-padded JSON in a fixed 4 KiB buffer.
///
/// `#[repr(C)]` and `ZeroCopySend` are required by iceoryx2 so the value can
/// be mapped into a shared-memory slot without any copy or pointer fixup.
#[derive(Debug, Clone, Copy, ZeroCopySend)]
#[repr(C)]
pub struct MgmtReq {
    pub data: [u8; 4096],
}

impl Default for MgmtReq {
    fn default() -> Self {
        Self { data: [0u8; 4096] }
    }
}

/// Management response payload (same layout as [`MgmtReq`]).
#[derive(Debug, Clone, Copy, ZeroCopySend)]
#[repr(C)]
pub struct MgmtResp {
    pub data: [u8; 4096],
}

impl Default for MgmtResp {
    fn default() -> Self {
        Self { data: [0u8; 4096] }
    }
}

// ─── Server ───────────────────────────────────────────────────────────────────

/// How long each `node.wait()` call blocks before returning to check the
/// cancellation token.  Keeps the management loop responsive while avoiding
/// a busy-spin.
const CYCLE_TIME: Duration = Duration::from_millis(5);

/// Run the iceoryx2 management server.
///
/// **Blocking** — intended to run inside `tokio::task::spawn_blocking`.
/// Returns when `cancel` is fired, when iceoryx2 signals a termination
/// request, or on an unrecoverable error.
pub fn run_blocking(service_name: &str, engine: ForwarderEngine, cancel: CancellationToken) {
    let engine = Arc::new(engine);

    let node = match NodeBuilder::new().create::<ipc::Service>() {
        Ok(n)  => n,
        Err(e) => {
            tracing::error!(error = %e, "iceoryx2-mgmt: failed to create node");
            return;
        }
    };

    let svc_name: ServiceName = match service_name.try_into() {
        Ok(s)  => s,
        Err(e) => {
            tracing::error!(
                error = %e,
                service = service_name,
                "iceoryx2-mgmt: invalid service name"
            );
            return;
        }
    };

    let service = match node
        .service_builder(&svc_name)
        .request_response::<MgmtReq, MgmtResp>()
        .open_or_create()
    {
        Ok(s)  => s,
        Err(e) => {
            tracing::error!(error = %e, "iceoryx2-mgmt: failed to open/create service");
            return;
        }
    };

    let server = match service.server_builder().create() {
        Ok(s)  => s,
        Err(e) => {
            tracing::error!(error = %e, "iceoryx2-mgmt: failed to create server");
            return;
        }
    };

    tracing::info!(service = service_name, "iceoryx2 management server ready");

    // ── Event loop ─────────────────────────────────────────────────────────
    //
    // `node.wait(CYCLE_TIME)` blocks until either:
    //   • a CYCLE_TIME timeout elapses  → Ok(())
    //   • the OS sends SIGTERM/CTRL-C   → Err(NodeWaitFailure::TerminationRequest)
    //   • a spurious signal interrupts  → Err(NodeWaitFailure::Interrupt)
    //
    // We also check `cancel` after each wake to honour Tokio shutdown.
    loop {
        match node.wait(CYCLE_TIME) {
            Ok(()) => {}
            Err(NodeWaitFailure::TerminationRequest) => {
                tracing::info!("iceoryx2-mgmt: OS termination request received");
                break;
            }
            Err(NodeWaitFailure::Interrupt) => {
                // Spurious wakeup — continue so we still check `cancel`.
            }
            #[allow(unreachable_patterns)]
            Err(e) => {
                tracing::warn!(error = %e, "iceoryx2-mgmt: wait error; stopping");
                break;
            }
        }

        if cancel.is_cancelled() {
            break;
        }

        // Drain all pending requests that arrived during this tick.
        loop {
            match server.receive() {
                Ok(Some(active_request)) => {
                    // Compute the JSON response from the shared-memory payload.
                    let resp = dispatch(&*active_request, &engine, &cancel);

                    // Loan a zero-copy response slot, write our value, send it.
                    match active_request.loan_uninit() {
                        Ok(loan) => {
                            if let Err(e) = loan.write_payload(resp).send() {
                                tracing::warn!(error = %e, "iceoryx2-mgmt: send failed");
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "iceoryx2-mgmt: loan failed");
                        }
                    }
                }
                Ok(None) => break,  // no more pending requests this tick
                Err(e)   => {
                    tracing::warn!(error = %e, "iceoryx2-mgmt: receive error");
                    break;
                }
            }
        }
    }

    tracing::info!("iceoryx2 management server stopped");
}

// ─── Dispatch helper ──────────────────────────────────────────────────────────

/// Decode a [`MgmtReq`] payload, dispatch to the engine, and return the
/// encoded [`MgmtResp`] ready to write into the shared-memory response slot.
fn dispatch(req: &MgmtReq, engine: &ForwarderEngine, cancel: &CancellationToken) -> MgmtResp {
    // Find the null terminator so we don't pass padding zeros to the JSON parser.
    let end  = req.data.iter().position(|&b| b == 0).unwrap_or(req.data.len());
    let json = std::str::from_utf8(&req.data[..end]).unwrap_or("");

    let resp = match ManagementServer::decode_request(json) {
        Ok(req) => super::handle_request(req, engine, cancel),
        Err(msg) => ManagementResponse::Error { message: msg },
    };

    let resp_json = ManagementServer::encode_response(&resp);
    let mut out = MgmtResp::default();
    let bytes = resp_json.as_bytes();
    let len   = bytes.len().min(out.data.len() - 1); // leave one byte for the null terminator
    out.data[..len].copy_from_slice(&bytes[..len]);
    out
}
