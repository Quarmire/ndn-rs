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

use bytes::Bytes;
use tokio::sync::Mutex;

use ndn_config::{
    ControlParameters, ControlResponse,
    nfd_command::{module, verb, command_name},
};
use ndn_face_local::UnixFace;
use ndn_packet::{Name, encode::encode_interest};
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
        handle:  ndn_face_local::shm::spsc::SpscHandle,
        face_id: u64,
    },
    /// Fallback: reuse the control UnixFace for data.
    Unix,
}

/// Client for connecting to and communicating with a running ndn-router.
pub struct RouterClient {
    /// Control channel (always a UnixFace).
    control: Arc<UnixFace>,
    /// Mutex for serialising recv on the control face.
    recv_lock: Mutex<()>,
    /// Data transport — SHM or reuse control face.
    transport: DataTransport,
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
        let control = Arc::new(
            UnixFace::connect(FaceId(0), face_socket.as_ref()).await?
        );

        // Try SHM data plane if a name is provided.
        #[cfg(all(unix, feature = "spsc-shm"))]
        if let Some(name) = shm_name {
            match Self::setup_shm(&control, name).await {
                Ok(transport) => {
                    return Ok(Self {
                        control,
                        recv_lock: Mutex::new(()),
                        transport,
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "SHM setup failed, falling back to Unix");
                }
            }
        }

        Ok(Self {
            control,
            recv_lock: Mutex::new(()),
            transport: DataTransport::Unix,
        })
    }

    /// Set up SHM data plane by sending `faces/create` to the router.
    #[cfg(all(unix, feature = "spsc-shm"))]
    async fn setup_shm(
        control: &UnixFace,
        shm_name: &str,
    ) -> Result<DataTransport, RouterError> {
        let params = ControlParameters {
            uri: Some(format!("shm://{shm_name}")),
            ..Default::default()
        };

        let resp = send_command(control, module::FACES, verb::CREATE, &params).await?;
        let face_id = resp.face_id
            .ok_or(RouterError::MalformedResponse)?;

        // Connect the app-side SHM handle.
        let handle = ndn_face_local::shm::spsc::SpscHandle::connect(shm_name)?;

        Ok(DataTransport::Shm { handle, face_id })
    }

    /// Register a prefix with the router via `rib/register`.
    pub async fn register_prefix(&self, prefix: &Name) -> Result<(), RouterError> {
        let mut params = ControlParameters {
            name: Some(prefix.clone()),
            ..Default::default()
        };

        // If using SHM, specify the SHM face ID so the route points to it.
        #[cfg(all(unix, feature = "spsc-shm"))]
        if let DataTransport::Shm { face_id, .. } = &self.transport {
            params.face_id = Some(*face_id);
        }

        let resp = send_command(&self.control, module::RIB, verb::REGISTER, &params).await?;
        tracing::debug!(
            face_id = ?resp.face_id,
            cost = ?resp.cost,
            "rib/register succeeded"
        );
        Ok(())
    }

    /// Unregister a prefix from the router via `rib/unregister`.
    pub async fn unregister_prefix(&self, prefix: &Name) -> Result<(), RouterError> {
        let mut params = ControlParameters {
            name: Some(prefix.clone()),
            ..Default::default()
        };

        #[cfg(all(unix, feature = "spsc-shm"))]
        if let DataTransport::Shm { face_id, .. } = &self.transport {
            params.face_id = Some(*face_id);
        }

        let _resp = send_command(&self.control, module::RIB, verb::UNREGISTER, &params).await?;
        Ok(())
    }

    /// Send a packet on the data plane.
    pub async fn send(&self, pkt: Bytes) -> Result<(), RouterError> {
        match &self.transport {
            #[cfg(all(unix, feature = "spsc-shm"))]
            DataTransport::Shm { handle, .. } => {
                handle.send(pkt).await.map_err(RouterError::Shm)
            }
            DataTransport::Unix => {
                self.control.send(pkt).await.map_err(RouterError::Face)
            }
        }
    }

    /// Receive a packet from the data plane.
    ///
    /// Returns `None` if the data channel is closed.
    pub async fn recv(&self) -> Option<Bytes> {
        match &self.transport {
            #[cfg(all(unix, feature = "spsc-shm"))]
            DataTransport::Shm { handle, .. } => {
                handle.recv().await
            }
            DataTransport::Unix => {
                let _guard = self.recv_lock.lock().await;
                self.control.recv().await.ok()
            }
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
}

// ─── Command helper ──────────────────────────────────────────────────────────

/// Send a management command Interest and wait for the ControlResponse.
async fn send_command(
    face:   &UnixFace,
    module_name: &[u8],
    verb_name:   &[u8],
    params: &ControlParameters,
) -> Result<ControlParameters, RouterError> {
    let name = command_name(module_name, verb_name, params);
    let interest_wire = encode_interest(&name, None);

    face.send(interest_wire).await?;

    // Wait for the Data response.
    let data_wire = face.recv().await?;
    let data = ndn_packet::Data::decode(data_wire)
        .map_err(|_| RouterError::MalformedResponse)?;

    // Decode ControlResponse from Data content.
    let content = data.content()
        .ok_or(RouterError::MalformedResponse)?;
    let resp = ControlResponse::decode(Bytes::copy_from_slice(content))
        .map_err(|_| RouterError::MalformedResponse)?;

    if !resp.is_ok() {
        return Err(RouterError::Command {
            code: resp.status_code,
            text: resp.status_text,
        });
    }

    Ok(resp.body.unwrap_or_default())
}

/// Process-local counter for auto-generated SHM names.
fn next_shm_id() -> u32 {
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}
