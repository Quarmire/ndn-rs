/// App-side client for connecting to a running `ndn-fwd` forwarder.
///
/// `ForwarderClient` handles:
/// - Connecting to the forwarder's face socket (UnixFace)
/// - Optionally creating an SHM face for high-performance data plane
/// - Registering/unregistering prefixes via NFD `rib/register`/`rib/unregister`
/// - Sending and receiving NDN packets on the data plane
///
/// # Mobile (Android / iOS)
///
/// On mobile the forwarder runs in-process; there is no separate forwarder daemon
/// to connect to.  Use [`ndn_engine::ForwarderEngine`] in embedded mode with
/// an [`ndn_faces::local::AppFace`] instead of `ForwarderClient`.
///
/// # Connection flow (SHM preferred)
///
/// ```text
/// 1. Connect to /run/nfd/nfd.sock → UnixFace (control channel)
/// 2. Send faces/create {Uri:"shm://myapp"} → get FaceId
/// 3. ShmHandle::connect("myapp") → data plane ready
/// 4. Send rib/register {Name:"/prefix", FaceId} → route installed
/// 5. Send/recv packets over SHM
/// ```
///
/// # Connection flow (Unix fallback)
///
/// ```text
/// 1. Connect to /run/nfd/nfd.sock → UnixFace (control + data)
/// 2. Send rib/register {Name:"/prefix"} → FaceId defaults to requesting face
/// 3. Send/recv packets over same UnixFace
/// ```
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use bytes::Bytes;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use ndn_faces::local::IpcFace;
use ndn_packet::Name;
use ndn_packet::lp::encode_lp_packet;
use ndn_transport::{Face, FaceId};

/// Error type for `ForwarderClient` operations.
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
    #[cfg(all(
        unix,
        not(any(target_os = "android", target_os = "ios")),
        feature = "spsc-shm"
    ))]
    #[error("SHM error: {0}")]
    Shm(#[from] ndn_faces::local::ShmError),
}

enum DataTransport {
    #[cfg(all(
        unix,
        not(any(target_os = "android", target_os = "ios")),
        feature = "spsc-shm"
    ))]
    Shm {
        handle: ndn_faces::local::shm::spsc::SpscHandle,
        face_id: u64,
    },
    Unix,
}

pub struct ForwarderClient {
    control: Arc<IpcFace>,
    pub mgmt: crate::mgmt_client::MgmtClient,
    recv_lock: Mutex<()>,
    transport: DataTransport,
    /// Cancelled when the router control face disconnects.
    /// Propagates to SHM handle so recv/send abort promptly.
    cancel: CancellationToken,
    dead: Arc<AtomicBool>,
    monitor_started: AtomicU8,
}

impl ForwarderClient {
    /// Connect to the router's face socket.
    ///
    /// Attempts SHM data plane; falls back to Unix socket on failure.
    pub async fn connect(face_socket: impl AsRef<Path>) -> Result<Self, ForwarderError> {
        Self::connect_with_mtu(face_socket, None).await
    }

    /// Connect with an explicit MTU hint for the SHM data plane.
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
        let control = Arc::new(ndn_faces::local::ipc_face_connect(FaceId(0), &path).await?);
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
            recv_lock: Mutex::new(()),
            transport: DataTransport::Unix,
            cancel,
            dead,
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

        let mut handle = ndn_faces::local::shm::spsc::SpscHandle::connect(shm_name)?;
        handle.set_cancel(cancel);

        Ok(DataTransport::Shm { handle, face_id })
    }

    /// Register a prefix with the router via `rib/register`.
    pub async fn register_prefix(&self, prefix: &Name) -> Result<(), ForwarderError> {
        // SHM mode: route to the SHM face. Unix mode: None lets the router
        // default to the requesting face (passing 0 would silently black-hole).
        let face_id = self.shm_face_id();
        let resp = self.mgmt.route_add(prefix, face_id, 0).await?;
        tracing::debug!(
            face_id = ?resp.face_id,
            cost = ?resp.cost,
            "rib/register succeeded"
        );
        Ok(())
    }

    /// Unregister a prefix from the router via `rib/unregister`.
    pub async fn unregister_prefix(&self, prefix: &Name) -> Result<(), ForwarderError> {
        let face_id = self.shm_face_id();
        self.mgmt.route_remove(prefix, face_id).await?;
        Ok(())
    }

    /// Gracefully tear down: destroy the SHM face (if any) so the router
    /// cleans up immediately rather than waiting for GC.
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

    /// Send a packet on the data plane.
    ///
    /// On the Unix transport, packets are wrapped in a minimal NDNLPv2 LpPacket
    /// before sending.  External forwarders (yanfd/ndnd, NFD) always use LP
    /// framing on their Unix socket faces and reject bare TLV packets;
    /// `encode_lp_packet` is idempotent so already-wrapped packets pass through
    /// unchanged.  SHM transport does not use LP — the engine handles framing
    /// internally.
    pub async fn send(&self, pkt: Bytes) -> Result<(), ForwarderError> {
        match &self.transport {
            #[cfg(all(
                unix,
                not(any(target_os = "android", target_os = "ios")),
                feature = "spsc-shm"
            ))]
            DataTransport::Shm { handle, .. } => {
                handle.send(pkt).await.map_err(ForwarderError::Shm)
            }
            DataTransport::Unix => {
                let wire = encode_lp_packet(&pkt);
                self.control.send(wire).await.map_err(ForwarderError::Face)
            }
        }
    }

    /// Send multiple packets in one synchronisation.
    ///
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
                        .send(wire)
                        .await
                        .map_err(ForwarderError::Face)?;
                }
                Ok(())
            }
        }
    }

    /// Returns `None` if the data channel is closed.
    pub async fn recv(&self) -> Option<Bytes> {
        self.start_monitor_once();
        match &self.transport {
            #[cfg(all(
                unix,
                not(any(target_os = "android", target_os = "ios")),
                feature = "spsc-shm"
            ))]
            DataTransport::Shm { handle, .. } => handle.recv().await,
            DataTransport::Unix => {
                let _guard = self.recv_lock.lock().await;
                self.control.recv().await.ok().map(strip_lp)
            }
        }
    }

    /// In SHM mode, watches the control socket for closure and cancels
    /// the token so SHM recv/send abort. No-op in Unix mode.
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
                        result = control.recv() => {
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

    /// Explicitly start the disconnect monitor (called automatically on first `recv`).
    pub fn spawn_disconnect_monitor(&self) {
        self.start_monitor_once();
    }

    /// Probe whether the router is still alive via a management Interest.
    pub async fn probe_alive(&self) -> bool {
        if self.dead.load(Ordering::Relaxed) {
            return false;
        }
        let probe = ndn_packet::encode::InterestBuilder::new("/localhost/nfd/status/general")
            .sign_digest_sha256();
        match self.control.send(probe).await {
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

/// Process-local counter for auto-generated SHM names.
fn next_shm_id() -> u32 {
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Strip NDNLPv2 wrapper (type 0x64) if present.
///
/// External forwarders (yanfd, NFD) always wrap packets in LP framing on Unix
/// socket faces.  Unwrap the `Fragment` field and discard LP headers (PIT
/// tokens, face IDs, congestion marks, etc.).
///
/// Nack LP packets (LP with a Nack header) are returned as-is — the caller
/// will see the raw LP bytes (type 0x64) and handle them gracefully rather
/// than mistaking the nacked Interest fragment (type 0x05) for a Data packet.
///
/// Returns the original bytes unchanged if the packet is not LP-wrapped.
pub(crate) fn strip_lp(raw: Bytes) -> Bytes {
    use ndn_packet::lp::{LpPacket, is_lp_packet};
    if is_lp_packet(&raw)
        && let Ok(lp) = LpPacket::decode(raw.clone())
    {
        // Do NOT strip Nack packets: the fragment is the nacked Interest
        // (type 0x05), not Data.  Return the raw LP bytes so callers
        // receive a recognisable LP type (0x64) instead of an Interest.
        if lp.nack.is_some() {
            return raw;
        }
        if let Some(fragment) = lp.fragment {
            return fragment;
        }
    }
    raw
}
