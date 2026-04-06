/// App-side client for connecting to a running ndn-router.
///
/// `RouterClient` handles:
/// - Connecting to the router's face socket (UnixFace)
/// - Optionally creating an SHM face for high-performance data plane
/// - Registering/unregistering prefixes via NFD `rib/register`/`rib/unregister`
/// - Sending and receiving NDN packets on the data plane
///
/// # Connection flow (SHM preferred)
///
/// ```text
/// 1. Connect to /tmp/ndn-faces.sock → UnixFace (control channel)
/// 2. Send faces/create {Uri:"shm://myapp"} → get FaceId
/// 3. ShmHandle::connect("myapp") → data plane ready
/// 4. Send rib/register {Name:"/prefix", FaceId} → route installed
/// 5. Send/recv packets over SHM
/// ```
///
/// # Connection flow (Unix fallback)
///
/// ```text
/// 1. Connect to /tmp/ndn-faces.sock → UnixFace (control + data)
/// 2. Send rib/register {Name:"/prefix"} → FaceId defaults to requesting face
/// 3. Send/recv packets over same UnixFace
/// ```
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use bytes::Bytes;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use ndn_face_local::IpcFace;
use ndn_packet::Name;
use ndn_transport::{Face, FaceId};

/// Error type for `RouterClient` operations.
#[derive(Debug, thiserror::Error)]
pub enum RouterError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("face error: {0}")]
    Face(#[from] ndn_transport::FaceError),
    #[error("management command failed: {code} {text}")]
    Command { code: u64, text: String },
    #[error("malformed management response")]
    MalformedResponse,
    #[cfg(all(unix, feature = "spsc-shm"))]
    #[error("SHM error: {0}")]
    Shm(#[from] ndn_face_local::ShmError),
}

/// Data plane transport — either SHM (preferred) or reuse the control UnixFace.
enum DataTransport {
    /// High-performance shared-memory data plane.
    #[cfg(all(unix, feature = "spsc-shm"))]
    Shm {
        handle: ndn_face_local::shm::spsc::SpscHandle,
        face_id: u64,
    },
    /// Fallback: reuse the control UnixFace for data.
    Unix,
}

/// Client for connecting to and communicating with a running ndn-router.
pub struct RouterClient {
    /// Control channel (Unix domain socket on Unix, Named Pipe on Windows).
    control: Arc<IpcFace>,
    /// Typed management API — shares the control face.
    pub mgmt: crate::mgmt_client::MgmtClient,
    /// Mutex for serialising recv on the control face (Unix data path).
    recv_lock: Mutex<()>,
    /// Data transport — SHM or reuse control face.
    transport: DataTransport,
    /// Cancelled when the router control face disconnects.
    /// Propagates to SHM handle so recv/send abort promptly.
    cancel: CancellationToken,
    /// Set when the control face health monitor detects disconnection.
    dead: Arc<AtomicBool>,
    /// Guards single-start of the disconnect monitor (0 = not started, 1 = started).
    monitor_started: AtomicU8,
}

impl RouterClient {
    /// Connect to the router's face socket.
    ///
    /// Automatically attempts SHM data plane with an auto-generated name;
    /// falls back to Unix socket if SHM is unavailable or fails.
    pub async fn connect(face_socket: impl AsRef<Path>) -> Result<Self, RouterError> {
        let auto_name = format!("app-{}-{}", std::process::id(), next_shm_id());
        Self::connect_with_name(face_socket, Some(&auto_name)).await
    }

    /// Connect using only the Unix socket for data (no SHM attempt).
    pub async fn connect_unix_only(face_socket: impl AsRef<Path>) -> Result<Self, RouterError> {
        Self::connect_with_name(face_socket, None).await
    }

    /// Connect with an explicit SHM name for the data plane.
    ///
    /// If `shm_name` is `Some`, creates an SHM face with that name.
    /// If `None` or SHM creation fails, falls back to Unix-only mode.
    pub async fn connect_with_name(
        face_socket: impl AsRef<Path>,
        shm_name: Option<&str>,
    ) -> Result<Self, RouterError> {
        let path = face_socket.as_ref().to_str().unwrap_or_default().to_owned();
        let control = Arc::new(ndn_face_local::ipc_face_connect(FaceId(0), &path).await?);
        let cancel = CancellationToken::new();
        let dead = Arc::new(AtomicBool::new(false));

        // Try SHM data plane if a name is provided.
        #[cfg(all(unix, feature = "spsc-shm"))]
        if let Some(name) = shm_name {
            match Self::setup_shm(&control, name, cancel.child_token()).await {
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

    /// Set up SHM data plane by sending `faces/create` to the router.
    #[cfg(all(unix, feature = "spsc-shm"))]
    async fn setup_shm(
        control: &Arc<IpcFace>,
        shm_name: &str,
        cancel: CancellationToken,
    ) -> Result<DataTransport, RouterError> {
        let mgmt = crate::mgmt_client::MgmtClient::from_face(Arc::clone(control));
        let resp = mgmt.face_create(&format!("shm://{shm_name}")).await?;
        let face_id = resp.face_id.ok_or(RouterError::MalformedResponse)?;

        // Connect the app-side SHM handle with cancellation from control face.
        let mut handle = ndn_face_local::shm::spsc::SpscHandle::connect(shm_name)?;
        handle.set_cancel(cancel);

        Ok(DataTransport::Shm { handle, face_id })
    }

    /// Register a prefix with the router via `rib/register`.
    pub async fn register_prefix(&self, prefix: &Name) -> Result<(), RouterError> {
        let face_id = self.shm_face_id().unwrap_or(0);
        let resp = self.mgmt.route_add(prefix, face_id, 0).await?;
        tracing::debug!(
            face_id = ?resp.face_id,
            cost = ?resp.cost,
            "rib/register succeeded"
        );
        Ok(())
    }

    /// Unregister a prefix from the router via `rib/unregister`.
    pub async fn unregister_prefix(&self, prefix: &Name) -> Result<(), RouterError> {
        let face_id = self.shm_face_id().unwrap_or(0);
        self.mgmt.route_remove(prefix, face_id).await?;
        Ok(())
    }

    /// Get the SHM face ID if using SHM transport.
    fn shm_face_id(&self) -> Option<u64> {
        #[cfg(all(unix, feature = "spsc-shm"))]
        if let DataTransport::Shm { face_id, .. } = &self.transport {
            return Some(*face_id);
        }
        None
    }

    /// Send a packet on the data plane.
    pub async fn send(&self, pkt: Bytes) -> Result<(), RouterError> {
        match &self.transport {
            #[cfg(all(unix, feature = "spsc-shm"))]
            DataTransport::Shm { handle, .. } => handle.send(pkt).await.map_err(RouterError::Shm),
            DataTransport::Unix => self.control.send(pkt).await.map_err(RouterError::Face),
        }
    }

    /// Receive a packet from the data plane.
    ///
    /// Returns `None` if the data channel is closed or the router has
    /// disconnected.  On the first call, automatically starts the disconnect
    /// monitor (see [`RouterClient::spawn_disconnect_monitor`]) so that callers
    /// do not need to start it explicitly.
    pub async fn recv(&self) -> Option<Bytes> {
        self.start_monitor_once();
        match &self.transport {
            #[cfg(all(unix, feature = "spsc-shm"))]
            DataTransport::Shm { handle, .. } => handle.recv().await,
            DataTransport::Unix => {
                let _guard = self.recv_lock.lock().await;
                self.control.recv().await.ok()
            }
        }
    }

    /// Start the disconnect monitor the first time it is needed.
    ///
    /// In **SHM mode** the data plane reads from shared memory and does not
    /// observe socket closure directly.  This starts a background task that
    /// drains the control socket (which is otherwise idle after setup) and
    /// fires the internal [`CancellationToken`] when the socket closes.
    ///
    /// In **Unix mode** the data `recv()` already returns `None` on socket
    /// closure, so no additional monitor is needed.
    ///
    /// Safe to call multiple times — only one monitor is ever started.
    fn start_monitor_once(&self) {
        if self
            .monitor_started
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return; // already started
        }

        #[cfg(all(unix, feature = "spsc-shm"))]
        if matches!(&self.transport, DataTransport::Shm { .. }) {
            let control = Arc::clone(&self.control);
            let cancel = self.cancel.clone();
            let dead = Arc::clone(&self.dead);
            tokio::spawn(async move {
                // In SHM mode the control socket is used only for management
                // commands.  After setup, no traffic is expected on it.  Any
                // recv error means the socket was closed (router died).
                // Stray successful reads (e.g. unsolicited router messages) are
                // drained harmlessly; only errors trigger cancellation.
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        result = control.recv() => {
                            match result {
                                Ok(_) => {
                                    // Stray data on control socket — drain it.
                                }
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

    /// Whether this client is using SHM for data transport.
    pub fn is_shm(&self) -> bool {
        #[cfg(all(unix, feature = "spsc-shm"))]
        if matches!(&self.transport, DataTransport::Shm { .. }) {
            return true;
        }
        false
    }

    /// Whether the router connection has been lost.
    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Relaxed)
    }

    /// Explicitly start the disconnect monitor.
    ///
    /// This is called automatically on the first [`RouterClient::recv`] call,
    /// so most applications do not need to call this directly.
    ///
    /// In **SHM mode** the monitor watches the control socket for closure
    /// (no probes are sent; the control socket is idle after setup).  In
    /// **Unix mode** the data `recv()` already returns `None` on closure, so
    /// this is a no-op.
    ///
    /// Safe to call multiple times — only one monitor is ever started.
    pub fn spawn_disconnect_monitor(&self) {
        self.start_monitor_once();
    }

    /// Check if the control face is still connected by attempting a
    /// non-blocking management probe.  Returns `true` if the router is alive.
    ///
    /// Called lazily by applications that detect SHM stalls.
    pub async fn probe_alive(&self) -> bool {
        if self.dead.load(Ordering::Relaxed) {
            return false;
        }
        // Try sending a trivial Interest on the control face.
        // If the socket is closed, send will fail immediately.
        let probe = ndn_packet::encode::encode_interest(
            &"/localhost/nfd/status/general"
                .parse()
                .expect("valid probe name"),
            None,
        );
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

/// Process-local counter for auto-generated SHM names.
fn next_shm_id() -> u32 {
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}
