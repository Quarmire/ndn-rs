/// Programmatic management client for NDN router control.
///
/// `MgmtClient` provides typed methods for every NFD management command,
/// making it easy for control applications (routing daemons, CLI tools, etc.)
/// to interact with a running ndn-router without hand-building Interest names.
///
/// # Example
///
/// ```rust,no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use ndn_ipc::MgmtClient;
///
/// let mgmt = MgmtClient::connect("/tmp/ndn-faces.sock").await?;
/// mgmt.route_add(&"/ndn".parse()?, 1, 10).await?;
/// let status = mgmt.status().await?;
/// println!("{} {}", status.status_code, status.status_text);
/// # Ok(())
/// # }
/// ```
use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::Mutex;

use ndn_config::{
    ControlParameters, ControlResponse,
    nfd_command::{module, verb, command_name, dataset_name},
};
use ndn_face_local::UnixFace;
use ndn_packet::{Name, encode::encode_interest};
use ndn_transport::{Face, FaceId};

use crate::router_client::RouterError;

/// Management client for a running ndn-router.
///
/// Sends NFD management Interests over a UnixFace and decodes the
/// ControlResponse from the returned Data packet.
pub struct MgmtClient {
    face: Arc<UnixFace>,
    recv_lock: Mutex<()>,
}

impl MgmtClient {
    /// Connect to the router's face socket.
    pub async fn connect(face_socket: impl AsRef<Path>) -> Result<Self, RouterError> {
        let face = Arc::new(
            ndn_face_local::unix_face_connect(FaceId(0), face_socket.as_ref()).await?
        );
        Ok(Self { face, recv_lock: Mutex::new(()) })
    }

    /// Wrap an existing UnixFace (e.g. from a `RouterClient`).
    pub fn from_face(face: Arc<UnixFace>) -> Self {
        Self { face, recv_lock: Mutex::new(()) }
    }

    // ─── Route management ───────────────────────────────────────────────

    /// Add (or update) a route: `rib/register`.
    pub async fn route_add(
        &self,
        prefix: &Name,
        face_id: u64,
        cost: u64,
    ) -> Result<ControlParameters, RouterError> {
        let params = ControlParameters {
            name: Some(prefix.clone()),
            face_id: Some(face_id),
            cost: Some(cost),
            ..Default::default()
        };
        self.command(module::RIB, verb::REGISTER, &params).await
    }

    /// Remove a route: `rib/unregister`.
    pub async fn route_remove(
        &self,
        prefix: &Name,
        face_id: u64,
    ) -> Result<ControlParameters, RouterError> {
        let params = ControlParameters {
            name: Some(prefix.clone()),
            face_id: Some(face_id),
            ..Default::default()
        };
        self.command(module::RIB, verb::UNREGISTER, &params).await
    }

    /// List all FIB routes: `fib/list`.
    pub async fn route_list(&self) -> Result<ControlResponse, RouterError> {
        self.dataset(module::FIB, verb::LIST).await
    }

    // ─── Face management ────────────────────────────────────────────────

    /// Create a face: `faces/create`.
    pub async fn face_create(&self, uri: &str) -> Result<ControlParameters, RouterError> {
        let params = ControlParameters {
            uri: Some(uri.to_owned()),
            ..Default::default()
        };
        self.command(module::FACES, verb::CREATE, &params).await
    }

    /// Destroy a face: `faces/destroy`.
    pub async fn face_destroy(&self, face_id: u64) -> Result<ControlParameters, RouterError> {
        let params = ControlParameters {
            face_id: Some(face_id),
            ..Default::default()
        };
        self.command(module::FACES, verb::DESTROY, &params).await
    }

    /// List all faces: `faces/list`.
    pub async fn face_list(&self) -> Result<ControlResponse, RouterError> {
        self.dataset(module::FACES, verb::LIST).await
    }

    // ─── Strategy management ────────────────────────────────────────────

    /// Set forwarding strategy for a prefix: `strategy-choice/set`.
    pub async fn strategy_set(
        &self,
        prefix: &Name,
        strategy: &Name,
    ) -> Result<ControlParameters, RouterError> {
        let params = ControlParameters {
            name: Some(prefix.clone()),
            strategy: Some(strategy.clone()),
            ..Default::default()
        };
        self.command(module::STRATEGY, verb::SET, &params).await
    }

    /// Unset forwarding strategy for a prefix: `strategy-choice/unset`.
    pub async fn strategy_unset(
        &self,
        prefix: &Name,
    ) -> Result<ControlParameters, RouterError> {
        let params = ControlParameters {
            name: Some(prefix.clone()),
            ..Default::default()
        };
        self.command(module::STRATEGY, verb::UNSET, &params).await
    }

    /// List all strategy choices: `strategy-choice/list`.
    pub async fn strategy_list(&self) -> Result<ControlResponse, RouterError> {
        self.dataset(module::STRATEGY, verb::LIST).await
    }

    // ─── Content store ──────────────────────────────────────────────────

    /// Content store info: `cs/info`.
    pub async fn cs_info(&self) -> Result<ControlResponse, RouterError> {
        self.dataset(module::CS, verb::INFO).await
    }

    // ─── Status ─────────────────────────────────────────────────────────

    /// General forwarder status: `status/general`.
    pub async fn status(&self) -> Result<ControlResponse, RouterError> {
        self.dataset(module::STATUS, b"general").await
    }

    /// Request graceful shutdown: `status/shutdown`.
    pub async fn shutdown(&self) -> Result<ControlResponse, RouterError> {
        self.dataset(module::STATUS, b"shutdown").await
    }

    // ─── Core transport ─────────────────────────────────────────────────

    /// Send a command Interest with ControlParameters and decode the response.
    async fn command(
        &self,
        module_name: &[u8],
        verb_name: &[u8],
        params: &ControlParameters,
    ) -> Result<ControlParameters, RouterError> {
        let name = command_name(module_name, verb_name, params);
        let resp = self.send_interest(name).await?;

        if !resp.is_ok() {
            return Err(RouterError::Command {
                code: resp.status_code,
                text: resp.status_text,
            });
        }

        Ok(resp.body.unwrap_or_default())
    }

    /// Send a dataset Interest (no ControlParameters) and return the full response.
    async fn dataset(
        &self,
        module_name: &[u8],
        verb_name: &[u8],
    ) -> Result<ControlResponse, RouterError> {
        let name = dataset_name(module_name, verb_name);
        self.send_interest(name).await
    }

    /// Send an Interest and decode the ControlResponse from the Data reply.
    async fn send_interest(&self, name: Name) -> Result<ControlResponse, RouterError> {
        let interest_wire = encode_interest(&name, None);

        // Serialise send+recv so concurrent callers don't interleave.
        let _guard = self.recv_lock.lock().await;

        self.face.send(interest_wire).await?;

        let data_wire = self.face.recv().await?;
        let data = ndn_packet::Data::decode(data_wire)
            .map_err(|_| RouterError::MalformedResponse)?;

        let content = data.content()
            .ok_or(RouterError::MalformedResponse)?;

        ControlResponse::decode(Bytes::copy_from_slice(content))
            .map_err(|_| RouterError::MalformedResponse)
    }
}
