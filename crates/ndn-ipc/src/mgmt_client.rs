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
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::Mutex;

use ndn_config::{
    ControlParameters, ControlResponse,
    nfd_command::{command_name, dataset_name, module, verb},
};
use ndn_face_local::IpcFace;
use ndn_packet::{Name, encode::encode_interest};
use ndn_transport::{Face, FaceId};

use crate::router_client::RouterError;

/// Management client for a running ndn-router.
///
/// Sends NFD management Interests over an [`IpcFace`] and decodes the
/// `ControlResponse` from the returned Data packet.
///
/// On Unix the transport is a Unix domain socket; on Windows it is a
/// Named Pipe.  Both are accessed through the same `MgmtClient` API.
pub struct MgmtClient {
    face: Arc<IpcFace>,
    recv_lock: Mutex<()>,
}

impl MgmtClient {
    /// Connect to the router's IPC socket.
    ///
    /// `face_socket` is a Unix domain socket path on Unix (e.g.
    /// `/tmp/ndn-faces.sock`) or a Named Pipe path on Windows (e.g.
    /// `\\.\pipe\ndn-faces`).
    pub async fn connect(face_socket: impl AsRef<str>) -> Result<Self, RouterError> {
        let face =
            Arc::new(ndn_face_local::ipc_face_connect(FaceId(0), face_socket.as_ref()).await?);
        Ok(Self {
            face,
            recv_lock: Mutex::new(()),
        })
    }

    /// Wrap an existing [`IpcFace`] (e.g. from a `RouterClient`).
    pub fn from_face(face: Arc<IpcFace>) -> Self {
        Self {
            face,
            recv_lock: Mutex::new(()),
        }
    }

    // ─── Route management ───────────────────────────────────────────────

    /// Add (or update) a route: `rib/register`.
    ///
    /// Pass `face_id: None` to let the router use the requesting face (the
    /// default NFD behaviour when no FaceId is supplied).  This is the correct
    /// value to use when connecting over a Unix socket without SHM, because
    /// there is no separate SHM face ID to reference.
    pub async fn route_add(
        &self,
        prefix: &Name,
        face_id: Option<u64>,
        cost: u64,
    ) -> Result<ControlParameters, RouterError> {
        let params = ControlParameters {
            name: Some(prefix.clone()),
            face_id,
            cost: Some(cost),
            ..Default::default()
        };
        self.command(module::RIB, verb::REGISTER, &params).await
    }

    /// Remove a route: `rib/unregister`.
    ///
    /// Pass `face_id: None` to remove the route on the requesting face.
    pub async fn route_remove(
        &self,
        prefix: &Name,
        face_id: Option<u64>,
    ) -> Result<ControlParameters, RouterError> {
        let params = ControlParameters {
            name: Some(prefix.clone()),
            face_id,
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
    pub async fn strategy_unset(&self, prefix: &Name) -> Result<ControlParameters, RouterError> {
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

    /// Configure CS capacity: `cs/config`.
    ///
    /// If `capacity` is `Some`, sets the new max capacity in bytes.
    /// Always returns the current capacity.
    pub async fn cs_config(&self, capacity: Option<u64>) -> Result<ControlParameters, RouterError> {
        let params = ControlParameters {
            capacity,
            ..Default::default()
        };
        self.command(module::CS, verb::CONFIG, &params).await
    }

    /// Erase CS entries by prefix: `cs/erase`.
    ///
    /// Returns the number of entries erased (in the `count` field of the
    /// response ControlParameters).
    pub async fn cs_erase(
        &self,
        prefix: &ndn_packet::Name,
        count: Option<u64>,
    ) -> Result<ControlParameters, RouterError> {
        let params = ControlParameters {
            name: Some(prefix.clone()),
            count,
            ..Default::default()
        };
        self.command(module::CS, verb::ERASE, &params).await
    }

    // ─── Neighbors ──────────────────────────────────────────────────────

    /// List discovered neighbors: `neighbors/list`.
    pub async fn neighbors_list(&self) -> Result<ControlResponse, RouterError> {
        self.dataset(module::NEIGHBORS, verb::LIST).await
    }

    // ─── Service discovery ──────────────────────────────────────────────

    /// List locally announced services: `service/list`.
    pub async fn service_list(&self) -> Result<ControlResponse, RouterError> {
        self.dataset(module::SERVICE, verb::LIST).await
    }

    /// Announce a service prefix at runtime: `service/announce`.
    pub async fn service_announce(&self, prefix: &Name) -> Result<ControlParameters, RouterError> {
        let params = ControlParameters {
            name: Some(prefix.clone()),
            ..Default::default()
        };
        self.command(module::SERVICE, verb::ANNOUNCE, &params).await
    }

    /// Withdraw a previously announced service prefix: `service/withdraw`.
    pub async fn service_withdraw(&self, prefix: &Name) -> Result<ControlParameters, RouterError> {
        let params = ControlParameters {
            name: Some(prefix.clone()),
            ..Default::default()
        };
        self.command(module::SERVICE, verb::WITHDRAW, &params).await
    }

    /// Browse all known service records (local + received from peers): `service/browse`.
    ///
    /// When `prefix` is `Some`, the router returns only records whose
    /// `announced_prefix` has `prefix` as a prefix (server-side filter).
    pub async fn service_browse(
        &self,
        prefix: Option<&Name>,
    ) -> Result<ControlResponse, RouterError> {
        let name = match prefix {
            None => dataset_name(module::SERVICE, verb::BROWSE),
            Some(p) => {
                let params = ControlParameters {
                    name: Some(p.clone()),
                    ..Default::default()
                };
                command_name(module::SERVICE, verb::BROWSE, &params)
            }
        };
        self.send_interest(name).await
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

    // ─── Config ──────────────────────────────────────────────────────────────

    /// Retrieve the running router configuration as TOML: `config/get`.
    pub async fn config_get(&self) -> Result<ControlResponse, RouterError> {
        self.dataset(module::CONFIG, verb::GET).await
    }

    // ─── Faces counters ─────────────────────────────────────────────────

    /// Per-face packet/byte counters: `faces/counters`.
    pub async fn face_counters(&self) -> Result<ControlResponse, RouterError> {
        self.dataset(module::FACES, verb::COUNTERS).await
    }

    // ─── Measurements ───────────────────────────────────────────────────

    /// Per-prefix measurements (satisfaction rate, RTTs): `measurements/list`.
    pub async fn measurements_list(&self) -> Result<ControlResponse, RouterError> {
        self.dataset(module::MEASUREMENTS, verb::LIST).await
    }

    // ─── Security ────────────────────────────────────────────────────────

    /// List all identity keys in the PIB: `security/identity-list`.
    pub async fn security_identity_list(&self) -> Result<ControlResponse, RouterError> {
        self.dataset(module::SECURITY, verb::IDENTITY_LIST).await
    }

    /// Generate a new Ed25519 identity key: `security/identity-generate`.
    pub async fn security_identity_generate(&self, name: &Name) -> Result<ControlParameters, RouterError> {
        let params = ControlParameters {
            name: Some(name.clone()),
            ..Default::default()
        };
        self.command(module::SECURITY, verb::IDENTITY_GENERATE, &params).await
    }

    /// List all trust anchors in the PIB: `security/anchor-list`.
    pub async fn security_anchor_list(&self) -> Result<ControlResponse, RouterError> {
        self.dataset(module::SECURITY, verb::ANCHOR_LIST).await
    }

    /// Delete a key from the PIB: `security/key-delete`.
    pub async fn security_key_delete(&self, name: &Name) -> Result<ControlParameters, RouterError> {
        let params = ControlParameters {
            name: Some(name.clone()),
            ..Default::default()
        };
        self.command(module::SECURITY, verb::KEY_DELETE, &params).await
    }

    /// Get the `did:ndn:` DID for a named identity: `security/identity-did`.
    ///
    /// The response `status_text` contains the DID string.
    pub async fn security_identity_did(&self, name: &Name) -> Result<ControlResponse, RouterError> {
        let params = ControlParameters {
            name: Some(name.clone()),
            ..Default::default()
        };
        let name = command_name(module::SECURITY, verb::IDENTITY_DID, &params);
        self.send_interest(name).await
    }

    /// Retrieve the router's NDNCERT CA profile: `security/ca-info`.
    ///
    /// Returns `NOT_FOUND` if no `ca_prefix` is configured.
    pub async fn security_ca_info(&self) -> Result<ControlResponse, RouterError> {
        self.dataset(module::SECURITY, verb::CA_INFO).await
    }

    /// Initiate NDNCERT enrollment with a CA: `security/ca-enroll`.
    ///
    /// Parameters:
    /// - `ca_prefix` — NDN name of the CA (e.g. `/ndn/edu/example/CA`)
    /// - `challenge_type` — `"token"`, `"pin"`, `"possession"`, or `"yubikey-hotp"`
    /// - `challenge_param` — the challenge secret/code
    ///
    /// The router starts a background enrollment session and returns immediately
    /// with `status_text = "started"`.  Poll `security/identity-list` to detect
    /// when the certificate has been installed.
    pub async fn security_ca_enroll(
        &self,
        ca_prefix: &Name,
        challenge_type: &str,
        challenge_param: &str,
    ) -> Result<ControlParameters, RouterError> {
        let params = ControlParameters {
            name: Some(ca_prefix.clone()),
            uri: Some(format!("{challenge_type}:{challenge_param}")),
            ..Default::default()
        };
        self.command(module::SECURITY, verb::CA_ENROLL, &params).await
    }

    /// Add a Zero-Touch-Provisioning token to the CA: `security/ca-token-add`.
    ///
    /// Returns the generated token in `ControlParameters::uri`.
    pub async fn security_ca_token_add(&self, description: &str) -> Result<ControlParameters, RouterError> {
        let params = ControlParameters {
            uri: Some(description.to_owned()),
            ..Default::default()
        };
        self.command(module::SECURITY, verb::CA_TOKEN_ADD, &params).await
    }

    /// List pending NDNCERT CA enrollment requests: `security/ca-requests`.
    pub async fn security_ca_requests(&self) -> Result<ControlResponse, RouterError> {
        self.dataset(module::SECURITY, verb::CA_REQUESTS).await
    }

    /// Detect whether a YubiKey is connected: `security/yubikey-detect`.
    ///
    /// Returns `Ok` with `status_text = "present"` if a YubiKey is found,
    /// or an error if not present or the `yubikey-piv` feature is not compiled in.
    pub async fn security_yubikey_detect(&self) -> Result<ControlResponse, RouterError> {
        self.dataset(module::SECURITY, verb::YUBIKEY_DETECT).await
    }

    /// Generate a P-256 key in YubiKey PIV slot 9a: `security/yubikey-generate`.
    ///
    /// On success the response `body.uri` contains the base64url-encoded 65-byte
    /// uncompressed public key.
    pub async fn security_yubikey_generate(&self, name: &Name) -> Result<ControlParameters, RouterError> {
        let params = ControlParameters {
            name: Some(name.clone()),
            ..Default::default()
        };
        self.command(module::SECURITY, verb::YUBIKEY_GENERATE, &params).await
    }

    // ─── Log filter ─────────────────────────────────────────────────────

    /// Get the current runtime log filter string: `log/get-filter`.
    pub async fn log_get_filter(&self) -> Result<ControlResponse, RouterError> {
        self.dataset(module::LOG, verb::GET_FILTER).await
    }

    /// Get new log lines from the router's in-memory ring buffer: `log/get-recent`.
    ///
    /// Pass the last sequence number received (0 on first call) in `after_seq`.
    /// The router returns only entries with a higher sequence number, so repeated
    /// polls never replay old lines.
    ///
    /// Response format: first line is the new max sequence number, followed by
    /// zero or more log lines.
    pub async fn log_get_recent(&self, after_seq: u64) -> Result<ControlResponse, RouterError> {
        let params = ControlParameters {
            count: Some(after_seq),
            ..Default::default()
        };
        let name = command_name(module::LOG, verb::GET_RECENT, &params);
        self.send_interest(name).await
    }

    /// Set the runtime log filter: `log/set-filter`.
    ///
    /// The `filter` string is an `EnvFilter`-compatible directive
    /// (e.g. `"info"`, `"debug,ndn_engine=trace"`).
    pub async fn log_set_filter(&self, filter: &str) -> Result<ControlResponse, RouterError> {
        let params = ControlParameters {
            uri: Some(filter.to_owned()),
            ..Default::default()
        };
        let name = command_name(module::LOG, verb::SET_FILTER, &params);
        self.send_interest(name).await
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
        let data =
            ndn_packet::Data::decode(data_wire).map_err(|_| RouterError::MalformedResponse)?;

        let content = data.content().ok_or(RouterError::MalformedResponse)?;

        ControlResponse::decode(Bytes::copy_from_slice(content))
            .map_err(|_| RouterError::MalformedResponse)
    }
}
