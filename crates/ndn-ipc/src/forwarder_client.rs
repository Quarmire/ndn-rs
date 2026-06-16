//! App-side client for a running `ndn-fwd`: opens the face socket
//! (UnixFace) for control, optionally creates an SHM face for the
//! data plane, registers prefixes via NFD `rib/{register,unregister}`,
//! and shuttles packets. On Android / iOS use
//! `ndn_engine::ForwarderEngine` with `ndn_face::local::AppFace`
//! instead — there's no separate forwarder daemon to connect to.
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

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
    #[cfg(all(
        unix,
        not(any(target_os = "android", target_os = "ios")),
        feature = "spsc-shm"
    ))]
    #[error("SHM error: {0}")]
    Shm(#[from] ndn_face_shm::ShmError),
}

enum DataTransport {
    #[cfg(all(
        unix,
        not(any(target_os = "android", target_os = "ios")),
        feature = "spsc-shm"
    ))]
    Shm {
        handle: ndn_face_shm::spsc::SpscHandle,
        face_id: u64,
    },
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

        #[cfg(all(
            unix,
            not(any(target_os = "android", target_os = "ios")),
            feature = "spsc-shm"
        ))]
        if let Some(name) = shm_name {
            match Self::setup_shm(&control, name, mtu, cancel.child_token()).await {
                Ok(transport) => {
                    let mgmt = crate::mgmt_client::MgmtClient::from_face(Arc::clone(&control));
                    return Ok(Self {
                        control,
                        mgmt,
                        mux: None,
                        recv_lock: Mutex::new(()),
                        transport,
                        cancel,
                        dead,
                        monitor_started: AtomicU8::new(0),
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "SHM setup failed, falling back to Unix");
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
        let mgmt =
            crate::mgmt_client::MgmtClient::from_mux(Arc::clone(&control), Arc::clone(&mux));
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

    #[cfg(all(
        unix,
        not(any(target_os = "android", target_os = "ios")),
        feature = "spsc-shm"
    ))]
    async fn setup_shm(
        control: &Arc<IpcFace>,
        shm_name: &str,
        mtu: Option<usize>,
        cancel: CancellationToken,
    ) -> Result<DataTransport, ForwarderError> {
        let mgmt = crate::mgmt_client::MgmtClient::from_face(Arc::clone(control));
        let resp = mgmt
            .face_create_with_mtu(&format!("shm://{shm_name}"), mtu.map(|m| m as u64))
            .await?;
        let face_id = resp.face_id.ok_or(ForwarderError::MalformedResponse)?;

        let mut handle = ndn_face_shm::spsc::SpscHandle::connect(shm_name)?;
        handle.set_cancel(cancel);

        Ok(DataTransport::Shm { handle, face_id })
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
        #[cfg(all(
            unix,
            not(any(target_os = "android", target_os = "ios")),
            feature = "spsc-shm"
        ))]
        if let DataTransport::Shm { face_id, .. } = &self.transport {
            let _ = self.mgmt.face_destroy(*face_id).await;
        }
    }

    fn shm_face_id(&self) -> Option<u64> {
        #[cfg(all(
            unix,
            not(any(target_os = "android", target_os = "ios")),
            feature = "spsc-shm"
        ))]
        if let DataTransport::Shm { face_id, .. } = &self.transport {
            return Some(*face_id);
        }
        None
    }

    /// Unix transport wraps `pkt` in a minimal NDNLPv2 LpPacket
    /// (NFD/yanfd/ndnd reject bare TLV on Unix faces);
    /// `encode_lp_packet` is idempotent. SHM transport does not use
    /// LP — the engine handles framing.
    pub async fn send(&self, pkt: Bytes) -> Result<(), ForwarderError> {
        match &self.transport {
            #[cfg(all(
                unix,
                not(any(target_os = "android", target_os = "ios")),
                feature = "spsc-shm"
            ))]
            DataTransport::Shm { handle, .. } => {
                handle.send_bytes(pkt).await.map_err(ForwarderError::Shm)
            }
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
            #[cfg(all(
                unix,
                not(any(target_os = "android", target_os = "ios")),
                feature = "spsc-shm"
            ))]
            DataTransport::Shm { handle, .. } => {
                handle.send_batch(pkts).await.map_err(ForwarderError::Shm)
            }
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
            #[cfg(all(
                unix,
                not(any(target_os = "android", target_os = "ios")),
                feature = "spsc-shm"
            ))]
            DataTransport::Shm { handle, .. } => handle.recv_bytes().await,
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

        #[cfg(all(
            unix,
            not(any(target_os = "android", target_os = "ios")),
            feature = "spsc-shm"
        ))]
        if matches!(&self.transport, DataTransport::Shm { .. }) {
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

    pub fn is_shm(&self) -> bool {
        #[cfg(all(
            unix,
            not(any(target_os = "android", target_os = "ios")),
            feature = "spsc-shm"
        ))]
        if matches!(&self.transport, DataTransport::Shm { .. }) {
            return true;
        }
        false
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
