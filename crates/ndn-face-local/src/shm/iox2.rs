//! iceoryx2-backed SHM face (`iceoryx2-shm` feature).
//!
//! Uses two iceoryx2 publish-subscribe services (one per direction) to carry
//! NDN packets between the engine and applications over true zero-copy shared
//! memory.
//!
//! # Service naming
//!
//! For a face named `"sensor-0"`:
//! - `ndn-shm/sensor-0/a2e` — app publishes, engine subscribes
//! - `ndn-shm/sensor-0/e2a` — engine publishes, app subscribes
//!
//! # Threading model
//!
//! iceoryx2 uses a blocking poll loop that cannot live inside a Tokio async
//! task without blocking the executor thread.  Each face therefore spawns a
//! dedicated OS thread that runs the iceoryx2 event loop and bridges results
//! to Tokio via `tokio::sync::mpsc` channels.
use bytes::Bytes;
use tokio::sync::mpsc;

use ndn_transport::{Face, FaceError, FaceId, FaceKind};

use crate::shm::ShmError;

// ─── Wire type ───────────────────────────────────────────────────────────────

/// Maximum NDN packet size carried over iceoryx2 shared memory.
pub const MAX_PACKET_SIZE: usize = 65520;

/// Fixed-size SHM-friendly NDN packet carrier.
///
/// `ZeroCopySend` is required by iceoryx2; `#[repr(C)]` ensures no padding
/// surprises when the struct is mapped into shared memory by another process.
#[derive(Debug, Clone, Copy, iceoryx2::prelude::ZeroCopySend)]
#[repr(C)]
pub struct NdnPacket {
    pub len:  u32,
    pub data: [u8; MAX_PACKET_SIZE],
}

impl Default for NdnPacket {
    fn default() -> Self { Self { len: 0, data: [0u8; MAX_PACKET_SIZE] } }
}

// ─── Service names ────────────────────────────────────────────────────────────

fn a2e_service(name: &str) -> String { format!("ndn-shm/{name}/a2e") }
fn e2a_service(name: &str) -> String { format!("ndn-shm/{name}/e2a") }

// ─── Background bridge thread ─────────────────────────────────────────────────

/// Run the iceoryx2 event loop for the **engine** side.
///
/// - Subscribes on the a2e service (receives from app).
/// - Publishes on the e2a service (sends to app).
fn engine_bridge(
    name:    String,
    a2e_tx:  mpsc::Sender<Bytes>,      // a2e received → face.recv()
    mut e2a_rx: mpsc::Receiver<Bytes>, // face.send() → e2a published
) {
    use iceoryx2::node::NodeWaitFailure;
    use iceoryx2::prelude::*;
    use std::time::Duration;

    let node = match NodeBuilder::new().create::<ipc::Service>() {
        Ok(n) => n,
        Err(e) => { tracing::error!(error=%e, "iox2-shm engine: node creation failed"); return; }
    };

    let a2e_name: ServiceName = match a2e_service(&name).try_into() {
        Ok(n) => n,
        Err(e) => { tracing::error!(error=%e, "iox2-shm: invalid a2e service name"); return; }
    };
    let e2a_name: ServiceName = match e2a_service(&name).try_into() {
        Ok(n) => n,
        Err(e) => { tracing::error!(error=%e, "iox2-shm: invalid e2a service name"); return; }
    };

    let a2e_svc = match node.service_builder(&a2e_name)
        .publish_subscribe::<NdnPacket>()
        .open_or_create()
    {
        Ok(s) => s,
        Err(e) => { tracing::error!(error=%e, "iox2-shm engine: a2e service failed"); return; }
    };
    let e2a_svc = match node.service_builder(&e2a_name)
        .publish_subscribe::<NdnPacket>()
        .open_or_create()
    {
        Ok(s) => s,
        Err(e) => { tracing::error!(error=%e, "iox2-shm engine: e2a service failed"); return; }
    };

    let subscriber = match a2e_svc.subscriber_builder().create() {
        Ok(s) => s,
        Err(e) => { tracing::error!(error=%e, "iox2-shm engine: subscriber failed"); return; }
    };
    let publisher  = match e2a_svc.publisher_builder().create() {
        Ok(p) => p,
        Err(e) => { tracing::error!(error=%e, "iox2-shm engine: publisher failed"); return; }
    };

    tracing::debug!(name=%name, "iox2-shm engine bridge running");

    loop {
        match node.wait(Duration::from_millis(1)) {
            Ok(()) | Err(NodeWaitFailure::Interrupt) => {}
            Err(NodeWaitFailure::TerminationRequest) => break,
            #[allow(unreachable_patterns)]
            Err(e) => { tracing::warn!(error=%e, "iox2-shm engine: wait error"); break; }
        }

        // Drain packets received from app (a2e direction).
        loop {
            match subscriber.receive() {
                Ok(Some(sample)) => {
                    let p   = &*sample;
                    let len = p.len as usize;
                    let pkt = Bytes::copy_from_slice(&p.data[..len.min(MAX_PACKET_SIZE)]);
                    if a2e_tx.blocking_send(pkt).is_err() { return; }
                }
                Ok(None) => break,
                Err(e)   => { tracing::warn!(error=%e, "iox2-shm engine: receive error"); break; }
            }
        }

        // Drain packets to send to app (e2a direction).
        loop {
            match e2a_rx.try_recv() {
                Ok(pkt) => {
                    let mut wire = NdnPacket::default();
                    let len = pkt.len().min(MAX_PACKET_SIZE);
                    wire.len = len as u32;
                    wire.data[..len].copy_from_slice(&pkt[..len]);
                    if let Ok(loan) = publisher.loan_uninit() {
                        let _ = loan.write_payload(wire).send();
                    }
                }
                Err(mpsc::error::TryRecvError::Empty)        => break,
                Err(mpsc::error::TryRecvError::Disconnected) => return,
            }
        }
    }

    tracing::debug!(name=%name, "iox2-shm engine bridge stopped");
}

/// Run the iceoryx2 event loop for the **application** side.
///
/// - Publishes on the a2e service (sends to engine).
/// - Subscribes on the e2a service (receives from engine).
fn app_bridge(
    name:    String,
    mut a2e_rx: mpsc::Receiver<Bytes>,  // handle.send() → a2e published
    e2a_tx:  mpsc::Sender<Bytes>,       // e2a received → handle.recv()
) {
    use iceoryx2::node::NodeWaitFailure;
    use iceoryx2::prelude::*;
    use std::time::Duration;

    let node = match NodeBuilder::new().create::<ipc::Service>() {
        Ok(n) => n,
        Err(e) => { tracing::error!(error=%e, "iox2-shm app: node creation failed"); return; }
    };

    let a2e_name: ServiceName = match a2e_service(&name).try_into() {
        Ok(n) => n,
        Err(e) => { tracing::error!(error=%e, "iox2-shm: invalid a2e service name"); return; }
    };
    let e2a_name: ServiceName = match e2a_service(&name).try_into() {
        Ok(n) => n,
        Err(e) => { tracing::error!(error=%e, "iox2-shm: invalid e2a service name"); return; }
    };

    let a2e_svc = match node.service_builder(&a2e_name)
        .publish_subscribe::<NdnPacket>()
        .open_or_create()
    {
        Ok(s) => s,
        Err(e) => { tracing::error!(error=%e, "iox2-shm app: a2e service failed"); return; }
    };
    let e2a_svc = match node.service_builder(&e2a_name)
        .publish_subscribe::<NdnPacket>()
        .open_or_create()
    {
        Ok(s) => s,
        Err(e) => { tracing::error!(error=%e, "iox2-shm app: e2a service failed"); return; }
    };

    let publisher  = match a2e_svc.publisher_builder().create() {
        Ok(p) => p,
        Err(e) => { tracing::error!(error=%e, "iox2-shm app: publisher failed"); return; }
    };
    let subscriber = match e2a_svc.subscriber_builder().create() {
        Ok(s) => s,
        Err(e) => { tracing::error!(error=%e, "iox2-shm app: subscriber failed"); return; }
    };

    tracing::debug!(name=%name, "iox2-shm app bridge running");

    loop {
        match node.wait(Duration::from_millis(1)) {
            Ok(()) | Err(NodeWaitFailure::Interrupt) => {}
            Err(NodeWaitFailure::TerminationRequest) => break,
            #[allow(unreachable_patterns)]
            Err(e) => { tracing::warn!(error=%e, "iox2-shm app: wait error"); break; }
        }

        // Drain outgoing packets (a2e).
        loop {
            match a2e_rx.try_recv() {
                Ok(pkt) => {
                    let mut wire = NdnPacket::default();
                    let len = pkt.len().min(MAX_PACKET_SIZE);
                    wire.len = len as u32;
                    wire.data[..len].copy_from_slice(&pkt[..len]);
                    if let Ok(loan) = publisher.loan_uninit() {
                        let _ = loan.write_payload(wire).send();
                    }
                }
                Err(mpsc::error::TryRecvError::Empty)        => break,
                Err(mpsc::error::TryRecvError::Disconnected) => return,
            }
        }

        // Drain incoming packets (e2a).
        loop {
            match subscriber.receive() {
                Ok(Some(sample)) => {
                    let p   = &*sample;
                    let len = p.len as usize;
                    let pkt = Bytes::copy_from_slice(&p.data[..len.min(MAX_PACKET_SIZE)]);
                    if e2a_tx.blocking_send(pkt).is_err() { return; }
                }
                Ok(None) => break,
                Err(e)   => { tracing::warn!(error=%e, "iox2-shm app: receive error"); break; }
            }
        }
    }

    tracing::debug!(name=%name, "iox2-shm app bridge stopped");
}

// ─── Iox2Face (engine side) ───────────────────────────────────────────────────

/// Engine-side iceoryx2 SHM face.
pub struct Iox2Face {
    id:  FaceId,
    /// Packets received from the app (a2e direction).
    rx:  tokio::sync::Mutex<mpsc::Receiver<Bytes>>,
    /// Packets to send to the app (e2a direction).
    tx:  mpsc::Sender<Bytes>,
    /// Keep the background thread alive.
    _bg: std::thread::JoinHandle<()>,
}

impl Iox2Face {
    /// Create the engine-side face and launch the iceoryx2 bridge thread.
    pub fn create(id: FaceId, name: &str) -> Result<Self, ShmError> {
        let (a2e_tx, a2e_rx) = mpsc::channel::<Bytes>(128);
        let (e2a_tx, e2a_rx) = mpsc::channel::<Bytes>(128);

        let n  = name.to_owned();
        let bg = std::thread::Builder::new()
            .name(format!("iox2-shm-engine-{name}"))
            .spawn(move || engine_bridge(n, a2e_tx, e2a_rx))
            .map_err(ShmError::Io)?;

        Ok(Iox2Face {
            id,
            rx:  tokio::sync::Mutex::new(a2e_rx),
            tx:  e2a_tx,
            _bg: bg,
        })
    }
}

impl Face for Iox2Face {
    fn id(&self)   -> FaceId   { self.id }
    fn kind(&self) -> FaceKind { FaceKind::Shm }

    async fn recv(&self) -> Result<Bytes, FaceError> {
        self.rx.lock().await.recv().await.ok_or(FaceError::Closed)
    }

    async fn send(&self, pkt: Bytes) -> Result<(), FaceError> {
        self.tx.send(pkt).await.map_err(|_| FaceError::Closed)
    }
}

// ─── Iox2Handle (application side) ───────────────────────────────────────────

/// Application-side iceoryx2 SHM handle.
pub struct Iox2Handle {
    /// Packets to send to the engine (a2e direction).
    tx:  mpsc::Sender<Bytes>,
    /// Packets received from the engine (e2a direction).
    rx:  tokio::sync::Mutex<mpsc::Receiver<Bytes>>,
    /// Keep the background thread alive.
    _bg: std::thread::JoinHandle<()>,
}

impl Iox2Handle {
    /// Connect to the engine-side iceoryx2 services.
    ///
    /// This may be called before or after `Iox2Face::create`; iceoryx2 retries
    /// the service open until the peer appears.
    pub fn connect(name: &str) -> Result<Self, ShmError> {
        let (a2e_tx, a2e_rx) = mpsc::channel::<Bytes>(128);
        let (e2a_tx, e2a_rx) = mpsc::channel::<Bytes>(128);

        let n  = name.to_owned();
        let bg = std::thread::Builder::new()
            .name(format!("iox2-shm-app-{name}"))
            .spawn(move || app_bridge(n, a2e_rx, e2a_tx))
            .map_err(ShmError::Io)?;

        Ok(Iox2Handle {
            tx:  a2e_tx,
            rx:  tokio::sync::Mutex::new(e2a_rx),
            _bg: bg,
        })
    }

    /// Send a packet to the engine.
    pub async fn send(&self, pkt: Bytes) -> Result<(), ShmError> {
        self.tx.send(pkt).await.map_err(|_| ShmError::Io(
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "bridge thread exited")
        ))
    }

    /// Receive a packet from the engine. Returns `None` when the bridge exits.
    pub async fn recv(&self) -> Option<Bytes> {
        self.rx.lock().await.recv().await
    }
}
