//! App-side client for a running `ndn-fwd`: opens the face socket
//! (UnixFace) for control, optionally creates an SHM face for the
//! data plane, registers prefixes via NFD `rib/{register,unregister}`,
//! and shuttles packets. On Android / iOS use
//! `ndn_engine::ForwarderEngine` with `ndn_face::local::AppFace`
//! instead — there's no separate forwarder daemon to connect to.
use std::path::Path;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use ndn_face::local::IpcFace;
use ndn_packet::Name;
use ndn_packet::lp::encode_lp_packet;
use ndn_transport::{FaceId, Transport};

#[derive(Debug, thiserror::Error)]
pub enum ForwarderError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("face error: {0}")]
    Face(#[from] ndn_transport::FaceError),
    #[error("management command failed: {code} {text}")]
    Command { code: u64, text: String },
    #[error("malformed management response")]
    MalformedResponse,
    #[error("signing failed: {0}")]
    SigningFailed(String),
    /// An externally-registered data plane (e.g. the SHM ring in `ndn-ipc-shm`)
    /// failed to set up or move bytes. Carries the impl's own error rendered as
    /// text so this core crate need not know the data plane's error type.
    #[error("data-plane error: {0}")]
    DataPlane(String),
}

/// A pluggable client-side data plane for a [`ForwarderClient`].
///
/// The core crate ships only the Unix-socket data plane. Faster, non-standard
/// data planes (the SHM ring in `ndn-ipc-shm`) live in their own crates and plug
/// in here via [`register_data_plane_factory`] — that inversion keeps `ndn-ipc`
/// (a spec crate) from ever depending on an extension face crate, so the two can
/// live in independent repos. Object-safe + sans-io over the wire bytes.
#[async_trait]
pub trait DataPlane: Send + Sync {
    /// Send one packet (already a bare NDN TLV; the data plane owns its framing).
    async fn send(&self, pkt: Bytes) -> Result<(), ForwarderError>;
    /// Send a batch; impls may coalesce wakeups. Default loops over [`send`].
    async fn send_batch(&self, pkts: &[Bytes]) -> Result<(), ForwarderError> {
        for pkt in pkts {
            self.send(pkt.clone()).await?;
        }
        Ok(())
    }
    /// Receive the next packet, or `None` when the channel is closed.
    async fn recv(&self) -> Option<Bytes>;
    /// Router-side face id for this data plane — used for `rib/register` routing
    /// and `faces/destroy` on close.
    fn face_id(&self) -> u64;
}

/// Builds a [`DataPlane`] on demand during [`ForwarderClient::connect`].
///
/// Register the SHM factory once at process start with
/// `ndn_ipc_shm::install()`; thereafter the standard `connect` paths attach the
/// external data plane automatically, falling back to the Unix socket if it
/// can't be set up. With no factory registered, every client is Unix-only.
#[async_trait]
pub trait DataPlaneFactory: Send + Sync {
    /// Create the router-side face (via `mgmt`) and connect a data plane to it.
    /// `cancel` is a child token fired on control-face disconnect.
    async fn connect(
        &self,
        mgmt: &crate::mgmt_client::MgmtClient,
        name: &str,
        mtu: Option<usize>,
        cancel: CancellationToken,
    ) -> Result<Box<dyn DataPlane>, ForwarderError>;
}

static DATA_PLANE_FACTORY: OnceLock<Box<dyn DataPlaneFactory>> = OnceLock::new();

/// Install the process-wide data-plane factory. Idempotent: the first call wins,
/// later calls return `false` and are ignored. Called by `ndn_ipc_shm::install`.
pub fn register_data_plane_factory(factory: Box<dyn DataPlaneFactory>) -> bool {
    DATA_PLANE_FACTORY.set(factory).is_ok()
}

fn data_plane_factory() -> Option<&'static dyn DataPlaneFactory> {
    DATA_PLANE_FACTORY.get().map(Box::as_ref)
}

enum DataTransport {
    /// An externally-registered fast data plane (e.g. SHM).
    External(Box<dyn DataPlane>),
    Unix,
}

pub struct ForwarderClient {
    control: Arc<IpcFace>,
    pub mgmt: crate::mgmt_client::MgmtClient,
    /// Single-reader demux over `control` for the management+data seam
    /// (`from_raw_fd`): `recv()` drains its data plane and `mgmt` reads through
    /// it, so they don't race on the one fd. `None` for the connect paths, where
    /// the data plane is a separate SHM face (or sequential Unix usage).
    mux: Option<Arc<crate::face_mux::FaceMux>>,
    recv_lock: Mutex<()>,
    transport: DataTransport,
    /// Cancelled on control-face disconnect; propagates to SHM so
    /// recv/send abort promptly.
    cancel: CancellationToken,
    dead: Arc<AtomicBool>,
    monitor_started: AtomicU8,
}

impl ForwarderClient {
    /// Attempts SHM data plane; falls back to Unix socket on failure.
    pub async fn connect(face_socket: impl AsRef<Path>) -> Result<Self, ForwarderError> {
        Self::connect_with_mtu(face_socket, None).await
    }

    /// `mtu_hint` only affects the SHM data plane.
    ///
    /// `mtu` is passed to the router's `faces/create` so the SHM ring
    /// is sized to carry Data packets whose content body can be up
    /// to `mtu` bytes. Pass `None` to use the default slot size
    /// (enough for ~256 KiB content bodies). Producers that plan to
    /// emit larger segments — e.g. chunked transfers at 1 MiB per
    /// segment — should pass `Some(chunk_size)` here.
    pub async fn connect_with_mtu(
        face_socket: impl AsRef<Path>,
        mtu: Option<usize>,
    ) -> Result<Self, ForwarderError> {
        let auto_name = format!("app-{}-{}", std::process::id(), next_shm_id());
        Self::connect_with_name(face_socket, Some(&auto_name), mtu).await
    }

    /// Connect using only the Unix socket for data (no SHM attempt).
    pub async fn connect_unix_only(face_socket: impl AsRef<Path>) -> Result<Self, ForwarderError> {
        Self::connect_with_name(face_socket, None, None).await
    }

    /// Connect with an explicit SHM name for the data plane.
    ///
    /// If `shm_name` is `Some`, creates an SHM face with that name.
    /// If `None` or SHM creation fails, falls back to Unix-only mode.
    /// `mtu` sizes the SHM ring slot for the expected max Data body.
    pub async fn connect_with_name(
        face_socket: impl AsRef<Path>,
        shm_name: Option<&str>,
        mtu: Option<usize>,
    ) -> Result<Self, ForwarderError> {
        let path = face_socket.as_ref().to_str().unwrap_or_default().to_owned();
        let control = Arc::new(ndn_face::local::ipc_face_connect(FaceId(0), &path).await?);
        let cancel = CancellationToken::new();
        let dead = Arc::new(AtomicBool::new(false));

        if let (Some(name), Some(factory)) = (shm_name, data_plane_factory()) {
            let mgmt = crate::mgmt_client::MgmtClient::from_face(Arc::clone(&control));
            match factory
                .connect(&mgmt, name, mtu, cancel.child_token())
                .await
            {
                Ok(dp) => {
                    return Ok(Self {
                        control,
                        mgmt,
                        mux: None,
                        recv_lock: Mutex::new(()),
                        transport: DataTransport::External(dp),
                        cancel,
                        dead,
                        monitor_started: AtomicU8::new(0),
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "data-plane setup failed, falling back to Unix");
                }
            }
        }

        let mgmt = crate::mgmt_client::MgmtClient::from_face(Arc::clone(&control));
        Ok(Self {
            control,
            mgmt,
            mux: None,
            recv_lock: Mutex::new(()),
            transport: DataTransport::Unix,
            cancel,
            dead,
            monitor_started: AtomicU8::new(0),
        })
    }

    /// Build a client over an already-connected `SOCK_STREAM` fd instead of
    /// dialing a socket path — the mobile counterpart to [`Self::connect`].
    /// Android hands the UI one half of a `socketpair()` across Binder; the UI
    /// adopts it here. Unix-only, and Unix data plane only (no SHM negotiation
    /// over a handed fd — SHM is excluded on the mobile targets anyway).
    #[cfg(unix)]
    pub fn from_raw_fd(fd: std::os::fd::RawFd) -> Result<Self, ForwarderError> {
        let control = Arc::new(ndn_face::local::ipc_face_from_raw_fd(
            FaceId(0),
            ndn_transport::FaceKind::Unix,
            fd,
        )?);
        let cancel = CancellationToken::new();
        // The seam multiplexes management + data over this one fd; a single-reader
        // demux routes management responses to `mgmt` and the rest to `recv()` so
        // they don't race. (Must be built in a runtime — callers adopt the fd
        // inside `block_on`.)
        let mux = crate::face_mux::FaceMux::new(Arc::clone(&control), cancel.child_token());
        let mgmt = crate::mgmt_client::MgmtClient::from_mux(Arc::clone(&control), Arc::clone(&mux));
        Ok(Self {
            control,
            mgmt,
            mux: Some(mux),
            recv_lock: Mutex::new(()),
            transport: DataTransport::Unix,
            cancel,
            dead: Arc::new(AtomicBool::new(false)),
            monitor_started: AtomicU8::new(0),
        })
    }

    /// `rib/register`. Routes to the SHM face when in SHM mode; in
    /// Unix mode `face_id = None` lets the router default to the
    /// requesting face (passing 0 would silently black-hole).
    pub async fn register_prefix(&self, prefix: &Name) -> Result<(), ForwarderError> {
        let face_id = self.shm_face_id();
        let resp = self.mgmt.route_add(prefix, face_id, 0).await?;
        tracing::debug!(
            face_id = ?resp.face_id,
            cost = ?resp.cost,
            "rib/register succeeded"
        );
        Ok(())
    }

    pub async fn unregister_prefix(&self, prefix: &Name) -> Result<(), ForwarderError> {
        let face_id = self.shm_face_id();
        self.mgmt.route_remove(prefix, face_id).await?;
        Ok(())
    }

    /// Destroys the SHM face (if any) so the router cleans up
    /// immediately rather than waiting for GC.
    pub async fn close(self) {
        self.cancel.cancel();
        if let DataTransport::External(dp) = &self.transport {
            let _ = self.mgmt.face_destroy(dp.face_id()).await;
        }
    }

    fn shm_face_id(&self) -> Option<u64> {
        match &self.transport {
            DataTransport::External(dp) => Some(dp.face_id()),
            DataTransport::Unix => None,
        }
    }

    /// Unix transport wraps `pkt` in a minimal NDNLPv2 LpPacket
    /// (NFD/yanfd/ndnd reject bare TLV on Unix faces);
    /// `encode_lp_packet` is idempotent. SHM transport does not use
    /// LP — the engine handles framing.
    pub async fn send(&self, pkt: Bytes) -> Result<(), ForwarderError> {
        match &self.transport {
            DataTransport::External(dp) => dp.send(pkt).await,
            DataTransport::Unix => {
                let wire = encode_lp_packet(&pkt);
                self.control
                    .send_bytes(wire)
                    .await
                    .map_err(ForwarderError::Face)
            }
        }
    }

    /// SHM: single atomic tail advance + one wakeup. Unix: plain loop.
    pub async fn send_batch(&self, pkts: &[Bytes]) -> Result<(), ForwarderError> {
        if pkts.is_empty() {
            return Ok(());
        }
        match &self.transport {
            DataTransport::External(dp) => dp.send_batch(pkts).await,
            DataTransport::Unix => {
                for pkt in pkts {
                    let wire = encode_lp_packet(pkt);
                    self.control
                        .send_bytes(wire)
                        .await
                        .map_err(ForwarderError::Face)?;
                }
                Ok(())
            }
        }
    }

    /// Returns `None` if the data channel is closed.
    pub async fn recv(&self) -> Option<Bytes> {
        // Seam: the demux owns the single `control` reader and has already split
        // management responses off; drain its data plane (LP already stripped).
        if let Some(mux) = &self.mux {
            return mux.recv().await;
        }
        self.start_monitor_once();
        match &self.transport {
            DataTransport::External(dp) => dp.recv().await,
            DataTransport::Unix => {
                let _guard = self.recv_lock.lock().await;
                self.control.recv_bytes().await.ok().map(strip_lp)
            }
        }
    }

    /// SHM mode only: watches the control socket and cancels the
    /// token on close so SHM recv/send abort. No-op for Unix.
    fn start_monitor_once(&self) {
        if self
            .monitor_started
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        if matches!(&self.transport, DataTransport::External(_)) {
            let control = Arc::clone(&self.control);
            let cancel = self.cancel.clone();
            let dead = Arc::clone(&self.dead);
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        result = control.recv_bytes() => {
                            match result {
                                Ok(_) => {}
                                Err(_) => {
                                    dead.store(true, Ordering::Relaxed);
                                    cancel.cancel();
                                    break;
                                }
                            }
                        }
                    }
                }
            });
        }
    }

    /// True when an external fast data plane (e.g. SHM) is attached, rather than
    /// the plain Unix-socket data plane.
    pub fn is_shm(&self) -> bool {
        matches!(&self.transport, DataTransport::External(_))
    }

    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Relaxed)
    }

    /// Started automatically on first `recv`; call explicitly to
    /// front-load it.
    pub fn spawn_disconnect_monitor(&self) {
        self.start_monitor_once();
    }

    pub async fn probe_alive(&self) -> bool {
        if self.dead.load(Ordering::Relaxed) {
            return false;
        }
        let probe = ndn_packet::encode::InterestBuilder::new("/localhost/nfd/status/general")
            .sign_digest_sha256();
        match self.control.send_bytes(probe).await {
            Ok(_) => true,
            Err(_) => {
                self.dead.store(true, Ordering::Relaxed);
                self.cancel.cancel();
                false
            }
        }
    }
}

impl Drop for ForwarderClient {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

fn next_shm_id() -> u32 {
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Unwraps an LPv2 `Fragment` and discards LP headers; passes
/// non-LP bytes through unchanged. Nack LP packets are returned
/// as-is so callers see the recognisable LP type (0x64) instead of
/// mistaking the nacked Interest fragment for a Data packet.
pub(crate) fn strip_lp(raw: Bytes) -> Bytes {
    use ndn_packet::lp::{LpPacket, is_lp_packet};
    if is_lp_packet(&raw)
        && let Ok(lp) = LpPacket::decode(raw.clone())
    {
        if lp.nack.is_some() {
            return raw;
        }
        if let Some(fragment) = lp.fragment {
            return fragment;
        }
    }
    raw
}
