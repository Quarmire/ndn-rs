//! Typed NFD management commands for control applications (routing
//! daemons, CLI tools). Sends command Interests over an [`IpcFace`]
//! and decodes the `ControlResponse` from the returned Data.
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::Mutex;

use ndn_face::local::IpcFace;
use ndn_mgmt_wire::{
    ControlParameters, ControlResponse,
    nfd_command::{command_name, dataset_name, module, verb},
};
use ndn_packet::{Name, encode::InterestBuilder};
use ndn_security::Signer;
use ndn_transport::{FaceId, Transport};

use crate::forwarder_client::ForwarderError;

/// `DigestSha256` is sufficient for ndn-fwd and localhost NFD; testbed
/// NFD enforces `rib.localhop_security` and requires a key-backed
/// signature (NFD `daemon/mgmt/command-authenticator.cpp:154-202`).
enum SigningPolicy {
    DigestSha256,
    Key(Arc<dyn Signer>),
}

/// Default signing is `DigestSha256`; call [`Self::with_signer`] for
/// the key-backed path required by testbed NFD.
pub struct MgmtClient {
    face: Arc<IpcFace>,
    recv: MgmtRecv,
    recv_lock: Mutex<()>,
    signing: SigningPolicy,
}

/// How `MgmtClient` reads command responses. `Face` reads the face directly (a
/// dedicated management connection). `Mux` registers the expected response with
/// a [`FaceMux`](crate::face_mux::FaceMux) — used on the management+data seam,
/// so a response is never swallowed by the data `recv`.
enum MgmtRecv {
    Face,
    Mux(Arc<crate::face_mux::FaceMux>),
}

/// The response to a command Interest is a Data named under the command name;
/// extract it so the demux can match the reply.
fn expected_response_name(interest_wire: &Bytes) -> Result<Name, ForwarderError> {
    ndn_packet::Interest::decode(interest_wire.clone())
        .map(|i| (*i.name).clone())
        .map_err(|_| ForwarderError::MalformedResponse)
}

impl MgmtClient {
    pub async fn connect(face_socket: impl AsRef<str>) -> Result<Self, ForwarderError> {
        let face =
            Arc::new(ndn_face::local::ipc_face_connect(FaceId(0), face_socket.as_ref()).await?);
        Ok(Self {
            face,
            recv: MgmtRecv::Face,
            recv_lock: Mutex::new(()),
            signing: SigningPolicy::DigestSha256,
        })
    }

    pub fn from_face(face: Arc<IpcFace>) -> Self {
        Self {
            face,
            recv: MgmtRecv::Face,
            recv_lock: Mutex::new(()),
            signing: SigningPolicy::DigestSha256,
        }
    }

    /// Read responses through `mux` (the seam demux) instead of the face
    /// directly, so they don't race the data plane on a shared fd.
    pub(crate) fn from_mux(face: Arc<IpcFace>, mux: Arc<crate::face_mux::FaceMux>) -> Self {
        Self {
            face,
            recv: MgmtRecv::Mux(mux),
            recv_lock: Mutex::new(()),
            signing: SigningPolicy::DigestSha256,
        }
    }

    /// Send a raw (unwrapped) command Interest and return the LP-stripped
    /// response Data wire. On the seam this registers the expected response with
    /// the demux *before* sending, so the demux loop routes it back here.
    async fn exchange(&self, interest_wire: &Bytes) -> Result<Bytes, ForwarderError> {
        let lp = ndn_packet::lp::encode_lp_packet(interest_wire);
        match &self.recv {
            MgmtRecv::Face => {
                self.face.send_bytes(lp).await?;
                Ok(crate::forwarder_client::strip_lp(
                    self.face.recv_bytes().await?,
                ))
            }
            MgmtRecv::Mux(mux) => {
                let rx = mux.expect(expected_response_name(interest_wire)?);
                self.face.send_bytes(lp).await?;
                rx.await.map_err(|_| ForwarderError::MalformedResponse)
            }
        }
    }

    /// As [`exchange`](Self::exchange) but `Ok(None)` when `timeout` elapses with
    /// no response (the notification long-poll).
    async fn exchange_timeout(
        &self,
        interest_wire: &Bytes,
        timeout: std::time::Duration,
    ) -> Result<Option<Bytes>, ForwarderError> {
        let lp = ndn_packet::lp::encode_lp_packet(interest_wire);
        match &self.recv {
            MgmtRecv::Face => {
                self.face.send_bytes(lp).await?;
                match tokio::time::timeout(timeout, self.face.recv_bytes()).await {
                    Err(_) => Ok(None),
                    Ok(r) => Ok(Some(crate::forwarder_client::strip_lp(r?))),
                }
            }
            MgmtRecv::Mux(mux) => {
                let rx = mux.expect(expected_response_name(interest_wire)?);
                self.face.send_bytes(lp).await?;
                match tokio::time::timeout(timeout, rx).await {
                    Err(_) => Ok(None),
                    Ok(Ok(d)) => Ok(Some(d)),
                    Ok(Err(_)) => Ok(None),
                }
            }
        }
    }

    /// Required when the forwarder enforces certificate-based command
    /// Interest authentication (NFD with `rib.localhop_security`).
    pub fn with_signer(self, signer: Arc<dyn Signer>) -> Self {
        Self {
            signing: SigningPolicy::Key(signer),
            ..self
        }
    }

    /// `rib/register`. `face_id: None` falls back to the requesting
    /// face (default NFD behaviour), which is correct for Unix-socket
    /// connections without a separate SHM face.
    pub async fn route_add(
        &self,
        prefix: &Name,
        face_id: Option<u64>,
        cost: u64,
    ) -> Result<ControlParameters, ForwarderError> {
        let params = ControlParameters {
            name: Some(prefix.clone()),
            face_id,
            cost: Some(cost),
            ..Default::default()
        };
        self.command(module::RIB, verb::REGISTER, &params).await
    }

    /// `rib/unregister`. `face_id: None` removes the route on the
    /// requesting face.
    pub async fn route_remove(
        &self,
        prefix: &Name,
        face_id: Option<u64>,
    ) -> Result<ControlParameters, ForwarderError> {
        let params = ControlParameters {
            name: Some(prefix.clone()),
            face_id,
            ..Default::default()
        };
        self.command(module::RIB, verb::UNREGISTER, &params).await
    }

    /// List all FIB routes: `fib/list`.
    ///
    /// Returns NFD TLV `FibEntry` dataset entries (per-spec wire format).
    pub async fn route_list(&self) -> Result<Vec<ndn_mgmt_wire::FibEntry>, ForwarderError> {
        let bytes = self.dataset_raw(module::FIB, verb::LIST).await?;
        Ok(ndn_mgmt_wire::FibEntry::decode_all(&bytes))
    }

    /// List all RIB routes: `rib/list`.
    ///
    /// Returns NFD TLV `RibEntry` dataset entries (per-spec wire format).
    pub async fn rib_list(&self) -> Result<Vec<ndn_mgmt_wire::RibEntry>, ForwarderError> {
        let bytes = self.dataset_raw(module::RIB, verb::LIST).await?;
        Ok(ndn_mgmt_wire::RibEntry::decode_all(&bytes))
    }

    /// Create a face: `faces/create`.
    pub async fn face_create(&self, uri: &str) -> Result<ControlParameters, ForwarderError> {
        self.face_create_with_mtu(uri, None).await
    }

    /// Create a face with an optional `mtu` hint: `faces/create`.
    ///
    /// For SHM faces the router uses `mtu` to size the ring slot so
    /// it can carry Data packets whose content body is up to `mtu`
    /// bytes. For Unix and network faces `mtu` is currently ignored.
    pub async fn face_create_with_mtu(
        &self,
        uri: &str,
        mtu: Option<u64>,
    ) -> Result<ControlParameters, ForwarderError> {
        let params = ControlParameters {
            uri: Some(uri.to_owned()),
            mtu,
            ..Default::default()
        };
        self.command(module::FACES, verb::CREATE, &params).await
    }

    /// Create a capability-scoped SHM face: `faces/create` carrying a client-
    /// minted control token (ndn-rs `shm://` Option-A bootstrap). The router
    /// uses the token to gate the fd handoff on the derived control socket; the
    /// caller then connects to `control_socket_path(token)` to receive the fds.
    pub async fn face_create_shm(
        &self,
        uri: &str,
        mtu: Option<u64>,
        token: bytes::Bytes,
    ) -> Result<ControlParameters, ForwarderError> {
        let params = ControlParameters {
            uri: Some(uri.to_owned()),
            mtu,
            shm_control_token: Some(token),
            ..Default::default()
        };
        self.command(module::FACES, verb::CREATE, &params).await
    }

    /// Destroy a face: `faces/destroy`.
    pub async fn face_destroy(&self, face_id: u64) -> Result<ControlParameters, ForwarderError> {
        let params = ControlParameters {
            face_id: Some(face_id),
            ..Default::default()
        };
        self.command(module::FACES, verb::DESTROY, &params).await
    }

    /// Update per-face flags: `faces/update`. `flags` carries the desired bit
    /// values, `mask` selects which bits to write (bit 0 = LocalFields,
    /// 1 = LpReliability, 2 = CongestionMarking); bits outside the mask are
    /// preserved.
    pub async fn face_update(
        &self,
        face_id: u64,
        flags: u64,
        mask: u64,
    ) -> Result<ControlParameters, ForwarderError> {
        let params = ControlParameters {
            face_id: Some(face_id),
            flags: Some(flags),
            mask: Some(mask),
            ..Default::default()
        };
        self.command(module::FACES, verb::UPDATE, &params).await
    }

    /// `faces/list` decoded as NFD `FaceStatus` entries.
    pub async fn face_list(&self) -> Result<Vec<ndn_mgmt_wire::FaceStatus>, ForwarderError> {
        let bytes = self.dataset_raw(module::FACES, verb::LIST).await?;
        Ok(ndn_mgmt_wire::FaceStatus::decode_all(&bytes))
    }

    /// Set forwarding strategy for a prefix: `strategy-choice/set`.
    pub async fn strategy_set(
        &self,
        prefix: &Name,
        strategy: &Name,
    ) -> Result<ControlParameters, ForwarderError> {
        let params = ControlParameters {
            name: Some(prefix.clone()),
            strategy: Some(strategy.clone()),
            ..Default::default()
        };
        self.command(module::STRATEGY, verb::SET, &params).await
    }

    /// Unset forwarding strategy for a prefix: `strategy-choice/unset`.
    pub async fn strategy_unset(&self, prefix: &Name) -> Result<ControlParameters, ForwarderError> {
        let params = ControlParameters {
            name: Some(prefix.clone()),
            ..Default::default()
        };
        self.command(module::STRATEGY, verb::UNSET, &params).await
    }

    /// `strategy-choice/list` decoded as NFD `StrategyChoice` entries.
    pub async fn strategy_list(
        &self,
    ) -> Result<Vec<ndn_mgmt_wire::StrategyChoice>, ForwarderError> {
        let bytes = self.dataset_raw(module::STRATEGY, verb::LIST).await?;
        Ok(ndn_mgmt_wire::StrategyChoice::decode_all(&bytes))
    }

    /// Content store info: `cs/info`.
    pub async fn cs_info(&self) -> Result<ControlResponse, ForwarderError> {
        self.dataset(module::CS, verb::INFO).await
    }

    /// `coding/list`. Entry fields: `name`, `fec_k`, `fec_n`,
    /// `fec_field`, `fec_role`. Empty when no policies are installed
    /// or the `fec` feature is off (status 404).
    pub async fn coding_list(&self) -> Result<Vec<ControlParameters>, ForwarderError> {
        let bytes = self.dataset_raw(module::CODING, verb::LIST).await?;
        Ok(ControlParameters::decode_all(&bytes))
    }

    /// `rate-limit/list`. Entry fields: `name`, `face_id`,
    /// `rl_direction`, the limit fields, `rl_overflow`, and `count`
    /// (per-cell overflow event counter).
    pub async fn rate_limit_list(&self) -> Result<Vec<ControlParameters>, ForwarderError> {
        let bytes = self.dataset_raw(module::RATE_LIMIT, verb::LIST).await?;
        Ok(ControlParameters::decode_all(&bytes))
    }

    /// `ca/list-approvals`: the requests for an admin's approval this node
    /// can decide (its CA's, or as an admin device its namespaces' CAs'
    /// pending ones). Local operators only (trust-admin verb). On an admin
    /// device the daemon asks the CAs over the network: the Interest lives
    /// `timeout`, and so does the wait. A CA that could not be asked is a
    /// note in the listing beside the rows that could be; a refusal (nothing
    /// to approve on this node, or nothing could be listed) is
    /// [`ForwarderError::Command`] with its reason.
    pub async fn ca_list_approvals(
        &self,
        timeout: std::time::Duration,
    ) -> Result<ndn_mgmt_wire::ApprovalListing, ForwarderError> {
        let interest_wire = InterestBuilder::new(dataset_name(module::CA, verb::LIST_APPROVALS))
            .can_be_prefix()
            .must_be_fresh()
            .lifetime(timeout)
            .build();
        let _guard = self.recv_lock.lock().await;
        let data_wire = self
            .exchange_timeout(&interest_wire, timeout)
            .await?
            .ok_or_else(|| no_answer_within(timeout))?;
        let data =
            ndn_packet::Data::decode(data_wire).map_err(|_| ForwarderError::MalformedResponse)?;
        let content = data.content().map(|c| c.as_ref()).unwrap_or_default();
        // A refusal is a ControlResponse; the dataset is the listing.
        if content.first() == Some(&(ndn_mgmt_wire::control_response::tlv::CONTROL_RESPONSE as u8))
        {
            let resp = ControlResponse::decode(Bytes::copy_from_slice(content))
                .map_err(|_| ForwarderError::MalformedResponse)?;
            return Err(ForwarderError::Command {
                code: resp.status_code,
                text: resp.status_text,
            });
        }
        Ok(ndn_mgmt_wire::ApprovalListing::decode(content))
    }

    /// `links/list`: this device's QUIC links and the paths that reach each
    /// linked device. Local operators only. A daemon that runs no links
    /// answers with a refusal: [`ForwarderError::Command`] with its reason.
    pub async fn link_list(
        &self,
        timeout: std::time::Duration,
    ) -> Result<ndn_mgmt_wire::LinkListing, ForwarderError> {
        let interest_wire = InterestBuilder::new(dataset_name(module::LINKS, verb::LIST))
            .can_be_prefix()
            .must_be_fresh()
            .lifetime(timeout)
            .build();
        let _guard = self.recv_lock.lock().await;
        let data_wire = self
            .exchange_timeout(&interest_wire, timeout)
            .await?
            .ok_or_else(|| no_answer_within(timeout))?;
        let data =
            ndn_packet::Data::decode(data_wire).map_err(|_| ForwarderError::MalformedResponse)?;
        let content = data.content().cloned().unwrap_or_default();
        // A refusal is a ControlResponse; the dataset is the listing.
        if content.first() == Some(&(ndn_mgmt_wire::control_response::tlv::CONTROL_RESPONSE as u8))
        {
            let resp =
                ControlResponse::decode(content).map_err(|_| ForwarderError::MalformedResponse)?;
            return Err(ForwarderError::Command {
                code: resp.status_code,
                text: resp.status_text,
            });
        }
        ndn_mgmt_wire::LinkListing::decode(content).map_err(|_| ForwarderError::MalformedResponse)
    }

    /// `links/connect`: link now to the configured device labelled `label`
    /// (as `link list` shows it), whatever its mode. The answer's
    /// `status_text` says what was done, or why nothing was.
    pub async fn link_connect(&self, label: &str) -> Result<ControlResponse, ForwarderError> {
        let params = ndn_mgmt_wire::link_command(label, None);
        self.send_interest(command_name(module::LINKS, verb::CONNECT, &params))
            .await
    }

    /// `links/disconnect`: close the link labelled `label` and keep it closed
    /// until connected again or its mode is set. Answered like
    /// [`link_connect`](Self::link_connect).
    pub async fn link_disconnect(&self, label: &str) -> Result<ControlResponse, ForwarderError> {
        let params = ndn_mgmt_wire::link_command(label, None);
        self.send_interest(command_name(module::LINKS, verb::DISCONNECT, &params))
            .await
    }

    /// `links/mode`: set the mode of the link labelled `label` until the
    /// daemon restarts (the config's mode applies again then). Answered like
    /// [`link_connect`](Self::link_connect).
    pub async fn link_mode(
        &self,
        label: &str,
        mode: ndn_mgmt_wire::LinkModeArg,
    ) -> Result<ControlResponse, ForwarderError> {
        let params = ndn_mgmt_wire::link_command(label, Some(mode));
        self.send_interest(command_name(module::LINKS, verb::MODE, &params))
            .await
    }

    /// `ca/approve`: approve the pending request `target` names (its request
    /// id or its six-digit verification code). On the CA host the daemon
    /// records the local operator as the approver; on an admin device it
    /// signs the approval with its admin key and pushes it to the CA, so the
    /// Interest lives `timeout`, and so does the wait. The answer's
    /// `status_text` says what was recorded, or why nothing was.
    pub async fn ca_approve(
        &self,
        target: &str,
        timeout: std::time::Duration,
    ) -> Result<ControlResponse, ForwarderError> {
        let params = ControlParameters {
            uri: Some(target.to_owned()),
            ..Default::default()
        };
        self.deferred_command(module::CA, verb::APPROVE, &params, timeout)
            .await
    }

    /// `ca/deny`: deny the pending request `target` names, with `reason`
    /// (told to the device; empty: "no reason given"). Decided and answered
    /// like [`ca_approve`](Self::ca_approve).
    pub async fn ca_deny(
        &self,
        target: &str,
        reason: &str,
        timeout: std::time::Duration,
    ) -> Result<ControlResponse, ForwarderError> {
        let uri = if reason.is_empty() {
            target.to_owned()
        } else {
            format!("{target}:{reason}")
        };
        let params = ControlParameters {
            uri: Some(uri),
            ..Default::default()
        };
        self.deferred_command(module::CA, verb::DENY, &params, timeout)
            .await
    }

    /// `cs/config`. `Some(capacity)` sets the new bytes cap; always
    /// returns the current capacity.
    pub async fn cs_config(
        &self,
        capacity: Option<u64>,
    ) -> Result<ControlParameters, ForwarderError> {
        let params = ControlParameters {
            capacity,
            ..Default::default()
        };
        self.command(module::CS, verb::CONFIG, &params).await
    }

    /// `cs/erase`. Erased entry count returned in the response
    /// `count` field.
    pub async fn cs_erase(
        &self,
        prefix: &ndn_packet::Name,
        count: Option<u64>,
    ) -> Result<ControlParameters, ForwarderError> {
        let params = ControlParameters {
            name: Some(prefix.clone()),
            count,
            ..Default::default()
        };
        self.command(module::CS, verb::ERASE, &params).await
    }

    /// List discovered neighbors: `neighbors/list`.
    pub async fn neighbors_list(&self) -> Result<ControlResponse, ForwarderError> {
        self.dataset(module::NEIGHBORS, verb::LIST).await
    }

    /// List locally announced services: `service/list`.
    pub async fn service_list(&self) -> Result<ControlResponse, ForwarderError> {
        self.dataset(module::SERVICE, verb::LIST).await
    }

    /// Announce a service prefix at runtime: `service/announce`.
    pub async fn service_announce(
        &self,
        prefix: &Name,
    ) -> Result<ControlParameters, ForwarderError> {
        let params = ControlParameters {
            name: Some(prefix.clone()),
            ..Default::default()
        };
        self.command(module::SERVICE, verb::ANNOUNCE, &params).await
    }

    /// Withdraw a previously announced service prefix: `service/withdraw`.
    pub async fn service_withdraw(
        &self,
        prefix: &Name,
    ) -> Result<ControlParameters, ForwarderError> {
        let params = ControlParameters {
            name: Some(prefix.clone()),
            ..Default::default()
        };
        self.command(module::SERVICE, verb::WITHDRAW, &params).await
    }

    /// `service/browse`. `Some(prefix)` is a server-side filter on
    /// `announced_prefix`.
    pub async fn service_browse(
        &self,
        prefix: Option<&Name>,
    ) -> Result<ControlResponse, ForwarderError> {
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

    /// General forwarder status: `status/general` — the NFD ForwarderStatus
    /// (GeneralStatus) dataset.
    pub async fn status(&self) -> Result<ndn_mgmt_wire::GeneralStatus, ForwarderError> {
        let bytes = self.dataset_raw(module::STATUS, b"general").await?;
        ndn_mgmt_wire::GeneralStatus::decode(bytes).map_err(|_| ForwarderError::MalformedResponse)
    }

    /// Request graceful shutdown: `status/shutdown`.
    pub async fn shutdown(&self) -> Result<ControlResponse, ForwarderError> {
        self.dataset(module::STATUS, b"shutdown").await
    }

    /// Fetch one NFD-style notification event from
    /// `/localhost/nfd/<module>/notifications`. With `seq = None` it requests
    /// the latest event (`CanBePrefix`); with `Some(n)` it long-polls sequence
    /// `n` — the producer holds the Interest until that event publishes (up to
    /// its own budget). Returns `Ok(Some((seq, content)))` for an event,
    /// `Ok(None)` if `timeout` elapsed with no event (re-issue the same seq),
    /// or `Err` on a transport/decode failure. Mirrors
    /// `daemon/mgmt/notification-stream.hpp` subscribers.
    pub async fn notification(
        &self,
        module: &str,
        seq: Option<u64>,
        timeout: std::time::Duration,
    ) -> Result<Option<(u64, Bytes)>, ForwarderError> {
        let mut name = Name::from_components([
            ndn_packet::NameComponent::generic(Bytes::from_static(b"localhost")),
            ndn_packet::NameComponent::generic(Bytes::from_static(b"nfd")),
            ndn_packet::NameComponent::generic(Bytes::copy_from_slice(module.as_bytes())),
            ndn_packet::NameComponent::generic(Bytes::from_static(b"notifications")),
        ]);
        if let Some(s) = seq {
            name = name.append_sequence_num(s);
        }
        let mut builder = InterestBuilder::new(name).must_be_fresh().lifetime(timeout);
        if seq.is_none() {
            builder = builder.can_be_prefix();
        }
        let interest_wire = builder.build();

        let _guard = self.recv_lock.lock().await;
        let data_wire = match self.exchange_timeout(&interest_wire, timeout).await? {
            None => return Ok(None),
            Some(w) => w,
        };
        let data =
            ndn_packet::Data::decode(data_wire).map_err(|_| ForwarderError::MalformedResponse)?;
        let got = data
            .name
            .components()
            .last()
            .filter(|c| c.typ == ndn_packet::tlv_type::SEQUENCE_NUM)
            .map(|c| {
                c.value
                    .as_ref()
                    .iter()
                    .fold(0u64, |n, b| (n << 8) | u64::from(*b))
            })
            .ok_or(ForwarderError::MalformedResponse)?;
        Ok(Some((got, data.content().cloned().unwrap_or_default())))
    }

    /// Retrieve the running router configuration as TOML: `config/get`.
    pub async fn config_get(&self) -> Result<ControlResponse, ForwarderError> {
        self.dataset(module::CONFIG, verb::GET).await
    }

    /// Per-face packet/byte counters: `faces/counters`.
    pub async fn face_counters(&self) -> Result<ControlResponse, ForwarderError> {
        self.dataset(module::FACES, verb::COUNTERS).await
    }

    /// Per-prefix measurements (satisfaction rate, RTTs): `measurements/list`.
    pub async fn measurements_list(&self) -> Result<ControlResponse, ForwarderError> {
        self.dataset(module::MEASUREMENTS, verb::LIST).await
    }

    /// List all identity keys in the PIB: `security/identity-list`.
    pub async fn security_identity_list(&self) -> Result<ControlResponse, ForwarderError> {
        self.dataset(module::SECURITY, verb::IDENTITY_LIST).await
    }

    /// `security/identity-status`. `status_text` is a space-separated
    /// key=value line: `identity=<name> is_ephemeral=<bool>
    /// pib_path=<path>`, then — for the key the daemon signs with —
    /// `key=<key>` and, when it holds a certificate for it,
    /// `valid_until=<ISO 8601> days_left=<n.n>`. Works without a configured
    /// PIB.
    pub async fn security_identity_status(&self) -> Result<ControlResponse, ForwarderError> {
        self.dataset(module::SECURITY, verb::IDENTITY_STATUS).await
    }

    /// Generate a new Ed25519 identity key: `security/identity-generate`.
    pub async fn security_identity_generate(
        &self,
        name: &Name,
    ) -> Result<ControlParameters, ForwarderError> {
        let params = ControlParameters {
            name: Some(name.clone()),
            ..Default::default()
        };
        self.command(module::SECURITY, verb::IDENTITY_GENERATE, &params)
            .await
    }

    /// List all trust anchors in the PIB: `security/anchor-list`.
    pub async fn security_anchor_list(&self) -> Result<ControlResponse, ForwarderError> {
        self.dataset(module::SECURITY, verb::ANCHOR_LIST).await
    }

    /// `security/anchor-add`. `key_name` is the cert key name,
    /// `cert_wire_hex` the hex-encoded NDN Data wire. Signed-command
    /// gated.
    pub async fn security_anchor_add(
        &self,
        key_name: &Name,
        cert_wire_hex: &str,
    ) -> Result<ControlParameters, ForwarderError> {
        let params = ControlParameters {
            name: Some(key_name.clone()),
            uri: Some(cert_wire_hex.to_owned()),
            ..Default::default()
        };
        self.command(module::SECURITY, verb::ANCHOR_ADD, &params)
            .await
    }

    /// Import an ndn-cxx-compatible SafeBag: `security/safebag-import`.
    /// `key_name` is the embedded cert's key name; `safebag_wire`
    /// is the SafeBag TLV (0x80) bytes; `passphrase` decrypts the
    /// wrapped PKCS#8. Signed-command gated. Powers the dashboard's
    /// §5.1 drag-drop import. Both halves of the URI body are hex
    /// so the `:` delimiter is unambiguous; the passphrase never
    /// appears in logs.
    pub async fn security_safebag_import(
        &self,
        key_name: &Name,
        safebag_wire: &[u8],
        passphrase: &[u8],
    ) -> Result<ControlParameters, ForwarderError> {
        let mut uri = String::with_capacity(safebag_wire.len() * 2 + passphrase.len() * 2 + 1);
        for b in safebag_wire {
            uri.push_str(&format!("{:02x}", b));
        }
        uri.push(':');
        for b in passphrase {
            uri.push_str(&format!("{:02x}", b));
        }
        let params = ControlParameters {
            name: Some(key_name.clone()),
            uri: Some(uri),
            ..Default::default()
        };
        self.command(module::SECURITY, verb::SAFEBAG_IMPORT, &params)
            .await
    }

    /// `security/anchor-remove` on the cert's key name; signed-command gated.
    pub async fn security_anchor_remove(
        &self,
        key_name: &Name,
    ) -> Result<ControlParameters, ForwarderError> {
        let params = ControlParameters {
            name: Some(key_name.clone()),
            ..Default::default()
        };
        self.command(module::SECURITY, verb::ANCHOR_REMOVE, &params)
            .await
    }

    /// Delete a key from the PIB: `security/key-delete`.
    pub async fn security_key_delete(
        &self,
        name: &Name,
    ) -> Result<ControlParameters, ForwarderError> {
        let params = ControlParameters {
            name: Some(name.clone()),
            ..Default::default()
        };
        self.command(module::SECURITY, verb::KEY_DELETE, &params)
            .await
    }

    /// `security/identity-did`. DID string in `status_text`.
    pub async fn security_identity_did(
        &self,
        name: &Name,
    ) -> Result<ControlResponse, ForwarderError> {
        let params = ControlParameters {
            name: Some(name.clone()),
            ..Default::default()
        };
        let name = command_name(module::SECURITY, verb::IDENTITY_DID, &params);
        self.send_interest(name).await
    }

    /// `security/ca-info`; `NOT_FOUND` when no `ca_prefix` is configured.
    pub async fn security_ca_info(&self) -> Result<ControlResponse, ForwarderError> {
        self.dataset(module::SECURITY, verb::CA_INFO).await
    }

    /// `security/ca-enroll`. `challenge_type` is `"token"`, `"pin"`,
    /// `"possession"`, or `"yubikey-hotp"`. Returns immediately with
    /// `status_text = "started"`; poll `security/identity-list` for
    /// completion.
    pub async fn security_ca_enroll(
        &self,
        ca_prefix: &Name,
        challenge_type: &str,
        challenge_param: &str,
    ) -> Result<ControlParameters, ForwarderError> {
        let params = ControlParameters {
            name: Some(ca_prefix.clone()),
            uri: Some(format!("{challenge_type}:{challenge_param}")),
            ..Default::default()
        };
        self.command(module::SECURITY, verb::CA_ENROLL, &params)
            .await
    }

    /// `security/ca-token-add`. Generated token returned in
    /// `ControlParameters::uri`.
    pub async fn security_ca_token_add(
        &self,
        description: &str,
    ) -> Result<ControlParameters, ForwarderError> {
        let params = ControlParameters {
            uri: Some(description.to_owned()),
            ..Default::default()
        };
        self.command(module::SECURITY, verb::CA_TOKEN_ADD, &params)
            .await
    }

    /// List pending NDNCERT CA enrollment requests: `security/ca-requests`.
    pub async fn security_ca_requests(&self) -> Result<ControlResponse, ForwarderError> {
        self.dataset(module::SECURITY, verb::CA_REQUESTS).await
    }

    /// `security/context-adopt`: ask the daemon to adopt the trust context
    /// the `ndn-trust://anchor` link names (it may fetch the context by
    /// name). The command Interest lives `timeout`, and so does the wait;
    /// the daemon answers within it. Success carries
    /// `ndn_mgmt::AdoptedContextInfo` as JSON in `status_text`; a refusal's
    /// `status_text` says why and what to do instead.
    pub async fn security_context_adopt(
        &self,
        link_uri: &str,
        timeout: std::time::Duration,
    ) -> Result<ControlResponse, ForwarderError> {
        let params = ControlParameters {
            uri: Some(link_uri.to_owned()),
            ..Default::default()
        };
        self.deferred_command(module::SECURITY, verb::CONTEXT_ADOPT, &params, timeout)
            .await
    }

    /// `security/enroll`: ask the daemon to enroll `identity`
    /// (`/<ns>/<role>/<device>`) with the CA `link_uri` names — an
    /// `ndn-trust://invite` link (the token is redeemed), or an
    /// `ndn-trust://anchor` link for a role the namespace certifies on an
    /// admin's approval. The daemon generates the key in its PIB, adopts the
    /// trust context if needed and, once certified, makes the identity its
    /// default. `force`: enroll although this node already holds a
    /// certificate in the namespace. The command Interest lives `timeout`,
    /// and so does the wait. Success carries `ndn_mgmt::EnrollOutcome` as
    /// JSON in `status_text` (`enrolled`, or `pending` an admin's approval,
    /// which the daemon then completes on its own); a refusal's
    /// `status_text` says why and what to do instead.
    pub async fn security_enroll(
        &self,
        link_uri: &str,
        identity: &ndn_packet::Name,
        force: bool,
        timeout: std::time::Duration,
    ) -> Result<ControlResponse, ForwarderError> {
        let params = ControlParameters {
            uri: Some(link_uri.to_owned()),
            name: Some(identity.clone()),
            flags: force.then_some(verb::ENROLL_FORCE),
            ..Default::default()
        };
        self.deferred_command(module::SECURITY, verb::ENROLL, &params, timeout)
            .await
    }

    /// `security/enroll-status`: the requests for an admin's approval this
    /// node made, oldest first, as a JSON list of `ndn_cert::OutgoingRequest`
    /// in `status_text`.
    pub async fn security_enroll_status(
        &self,
        timeout: std::time::Duration,
    ) -> Result<ControlResponse, ForwarderError> {
        self.deferred_command(
            module::SECURITY,
            verb::ENROLL_STATUS,
            &ControlParameters::default(),
            timeout,
        )
        .await
    }

    /// `security/context-refresh`: ask the daemon to check the held trust
    /// context of `namespace` (every held one when `None`) for a newer
    /// version now, rather than at its next periodic check. The command
    /// Interest lives `timeout`, and so does the wait. Success carries a JSON
    /// list of `ndn_mgmt::ContextRefreshInfo` in `status_text`.
    pub async fn security_context_refresh(
        &self,
        namespace: Option<&ndn_packet::Name>,
        timeout: std::time::Duration,
    ) -> Result<ControlResponse, ForwarderError> {
        let params = ControlParameters {
            name: namespace.cloned(),
            ..Default::default()
        };
        self.deferred_command(module::SECURITY, verb::CONTEXT_REFRESH, &params, timeout)
            .await
    }

    /// `security/context-update`: hand the daemon `context_data`, a signed
    /// trust-context Data made on this device (by `ndn-fwd revoke`,
    /// `ndn-fwd recovery-kit` or `ndn-fwd recover`), to adopt as the next
    /// version of the context it holds — only if strictly newer and signed by
    /// an anchor of the held version — then store and publish. The Data
    /// travels in the command's ApplicationParameters. Success carries one
    /// `ndn_mgmt::ContextRefreshInfo` as JSON in `status_text`.
    pub async fn security_context_update(
        &self,
        context_data: bytes::Bytes,
        timeout: std::time::Duration,
    ) -> Result<ControlResponse, ForwarderError> {
        let params = ControlParameters {
            context_data: Some(context_data),
            ..Default::default()
        };
        self.deferred_command(module::SECURITY, verb::CONTEXT_UPDATE, &params, timeout)
            .await
    }

    /// `security/renew`: ask the daemon to renew, now, every certificate a
    /// namespace CA issued to its keys (same key, no invite), rather than when
    /// its renewal timer would. The command Interest lives `timeout`, and so
    /// does the wait. Success carries a JSON list of `ndn_mgmt::RenewalInfo`
    /// in `status_text`.
    pub async fn security_renew(
        &self,
        timeout: std::time::Duration,
    ) -> Result<ControlResponse, ForwarderError> {
        self.deferred_command(
            module::SECURITY,
            verb::RENEW,
            &ControlParameters::default(),
            timeout,
        )
        .await
    }

    /// A `<module>/<verb>` command the daemon answers only after network
    /// round trips: the Interest lives `timeout` and the wait is as long.
    async fn deferred_command(
        &self,
        module_name: &[u8],
        verb: &[u8],
        params: &ControlParameters,
        timeout: std::time::Duration,
    ) -> Result<ControlResponse, ForwarderError> {
        // A context Data travels in ApplicationParameters (kilobytes, too
        // long for a Name component).
        let (name, app_params) = if params.context_data.is_some() {
            (dataset_name(module_name, verb), Some(params.encode()))
        } else {
            (command_name(module_name, verb, params), None)
        };
        let interest_wire =
            build_signed_interest_with_lifetime(&self.signing, name, Some(timeout), app_params)
                .await?;
        let _guard = self.recv_lock.lock().await;
        let data_wire = self
            .exchange_timeout(&interest_wire, timeout)
            .await?
            .ok_or_else(|| no_answer_within(timeout))?;
        let data =
            ndn_packet::Data::decode(data_wire).map_err(|_| ForwarderError::MalformedResponse)?;
        let content = data.content().ok_or(ForwarderError::MalformedResponse)?;
        ControlResponse::decode(Bytes::copy_from_slice(content))
            .map_err(|_| ForwarderError::MalformedResponse)
    }

    /// `security/policy-get`. JSON `MgmtAccessPolicy` in `status_text`;
    /// auth-exempt read.
    pub async fn security_policy_get(&self) -> Result<ControlResponse, ForwarderError> {
        self.dataset(module::SECURITY, verb::POLICY_GET).await
    }

    /// `security/validate`. Response body is JSON
    /// `TrustValidationResult { verdict, chain, schema_rules_applied,
    /// failure_diagnosis, challenge_attestations }`. v1 only checks
    /// anchor-set membership; full chain walk + schema match list
    /// comes online when `ndn_security::Validator` exposes a trace
    /// API. Auth-exempt read.
    pub async fn security_validate(
        &self,
        target: &Name,
    ) -> Result<ControlResponse, ForwarderError> {
        let params = ControlParameters {
            name: Some(target.clone()),
            ..Default::default()
        };
        let name = command_name(module::SECURITY, verb::VALIDATE, &params);
        self.send_interest(name).await
    }

    /// `security/validation-stats`. Body is three `key=value` lines:
    /// `validator_present=<bool>`, `verified_per_sec=<u64>`,
    /// `rejected_per_sec=<u64>`. v1 returns zeros for the counters.
    /// Auth-exempt read.
    pub async fn security_validation_stats(&self) -> Result<ControlResponse, ForwarderError> {
        self.dataset(module::SECURITY, verb::VALIDATION_STATS).await
    }

    /// `security/policy-set`. `body_json` matches `policy-get`'s
    /// shape; three booleans (`require_signed_commands`,
    /// `localhop_disabled`, `ephemeral_allowed`) apply immediately
    /// when `MgmtHandles::runtime_policy` is wired, while
    /// `validator_anchor` and `replay_window_secs` always come back
    /// as `pending_restart`. Response body: two `key=value` lines —
    /// `runtime_applied=…`, `pending_restart=…`. Signed-command gated.
    pub async fn security_policy_set(
        &self,
        body_json: &str,
    ) -> Result<ControlResponse, ForwarderError> {
        let params = ControlParameters {
            uri: Some(body_json.to_owned()),
            ..Default::default()
        };
        let name = command_name(module::SECURITY, verb::POLICY_SET, &params);
        self.send_interest(name).await
    }

    /// `security/yubikey-detect`. `status_text = "present"` on hit;
    /// error when absent or the `yubikey-piv` feature is off.
    pub async fn security_yubikey_detect(&self) -> Result<ControlResponse, ForwarderError> {
        self.dataset(module::SECURITY, verb::YUBIKEY_DETECT).await
    }

    /// `security/yubikey-generate` (P-256 in PIV slot 9a). On success
    /// `body.uri` is the base64url-encoded 65-byte uncompressed pubkey.
    pub async fn security_yubikey_generate(
        &self,
        name: &Name,
    ) -> Result<ControlParameters, ForwarderError> {
        let params = ControlParameters {
            name: Some(name.clone()),
            ..Default::default()
        };
        self.command(module::SECURITY, verb::YUBIKEY_GENERATE, &params)
            .await
    }

    /// `security/schema-list`. `status_text` contains one rule per
    /// line: `[0] /data_pattern => /key_pattern`.
    pub async fn security_schema_list(&self) -> Result<ControlResponse, ForwarderError> {
        self.dataset(module::SECURITY, verb::SCHEMA_LIST).await
    }

    /// `security/schema-rule-add`. `rule` is
    /// `"<data_pattern> => <key_pattern>"`.
    pub async fn security_schema_rule_add(
        &self,
        rule: &str,
    ) -> Result<ControlResponse, ForwarderError> {
        let params = ControlParameters {
            uri: Some(rule.to_owned()),
            ..Default::default()
        };
        let name = ndn_mgmt_wire::command_name(module::SECURITY, verb::SCHEMA_RULE_ADD, &params);
        self.send_interest(name).await
    }

    /// `security/schema-rule-remove`. `index` is the 0-based position
    /// from `security_schema_list()`.
    pub async fn security_schema_rule_remove(
        &self,
        index: u64,
    ) -> Result<ControlResponse, ForwarderError> {
        let params = ControlParameters {
            count: Some(index),
            ..Default::default()
        };
        let name = ndn_mgmt_wire::command_name(module::SECURITY, verb::SCHEMA_RULE_REMOVE, &params);
        self.send_interest(name).await
    }

    /// `security/schema-set`. `rules` is newline-separated
    /// `<data_pattern> => <key_pattern>` lines; empty string clears
    /// all rules (schema rejects everything).
    pub async fn security_schema_set(
        &self,
        rules: &str,
    ) -> Result<ControlResponse, ForwarderError> {
        let params = ControlParameters {
            uri: Some(rules.to_owned()),
            ..Default::default()
        };
        let name = ndn_mgmt_wire::command_name(module::SECURITY, verb::SCHEMA_SET, &params);
        self.send_interest(name).await
    }

    /// Get discovery protocol status and current config: `discovery/status`.
    pub async fn discovery_status(&self) -> Result<ControlResponse, ForwarderError> {
        self.dataset(module::DISCOVERY, b"status").await
    }

    /// `discovery/config`. `params` is a URL query string. Keys:
    /// `hello_interval_base_ms`, `hello_interval_max_ms`,
    /// `hello_jitter`, `liveness_timeout_ms`, `liveness_miss_count`,
    /// `probe_timeout_ms`, `auto_create_faces`.
    pub async fn discovery_config_set(
        &self,
        params: &str,
    ) -> Result<ControlResponse, ForwarderError> {
        let cp = ControlParameters {
            uri: Some(params.to_owned()),
            ..Default::default()
        };
        let name = command_name(module::DISCOVERY, verb::CONFIG, &cp);
        self.send_interest(name).await
    }

    /// `routing/dvr-status`. Maps to the `experimental-pvr`-gated
    /// `PrefixVectorProtocol`; the v0.2 spec-compliant ndn-dv will
    /// respond on the same verb.
    pub async fn routing_dvr_status(&self) -> Result<ControlResponse, ForwarderError> {
        self.dataset(module::ROUTING, verb::DVR_STATUS).await
    }

    /// `routing/dvr-config`. `params` is a URL query string, e.g.
    /// `"update_interval_ms=30000&route_ttl_ms=90000"`.
    pub async fn routing_dvr_config_set(
        &self,
        params: &str,
    ) -> Result<ControlResponse, ForwarderError> {
        let cp = ControlParameters {
            uri: Some(params.to_owned()),
            ..Default::default()
        };
        let name = command_name(module::ROUTING, verb::DVR_CONFIG, &cp);
        self.send_interest(name).await
    }

    /// `routing/nlsr-status` wraps `RoutingProtocol::status_text()`;
    /// `NOT_FOUND` when NLSR isn't configured.
    pub async fn routing_nlsr_status(&self) -> Result<ControlResponse, ForwarderError> {
        self.dataset(module::ROUTING, verb::NLSR_STATUS).await
    }

    /// `routing/nlsr-neighbors`. Lists configured peers as
    /// `name=<router> face_uri=<uri> cost=<f64>`.
    pub async fn routing_nlsr_neighbors(&self) -> Result<ControlResponse, ForwarderError> {
        self.dataset(module::ROUTING, verb::NLSR_NEIGHBORS).await
    }

    /// `routing/nlsr-lsdb`. Body is `LsdbSnapshot`'s `Display`:
    /// adjacency / name / coordinate LSAs with originator + seq.
    pub async fn routing_nlsr_lsdb(&self) -> Result<ControlResponse, ForwarderError> {
        self.dataset(module::ROUTING, verb::NLSR_LSDB).await
    }

    /// Get the current runtime log filter string: `log/get-filter`.
    pub async fn log_get_filter(&self) -> Result<ControlResponse, ForwarderError> {
        self.dataset(module::LOG, verb::GET_FILTER).await
    }

    /// `log/get-recent`. `after_seq` is the last seq the caller has;
    /// only higher-seq lines come back. Response: first line is the
    /// new max seq, then the new log lines.
    pub async fn log_get_recent(&self, after_seq: u64) -> Result<ControlResponse, ForwarderError> {
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
    pub async fn log_set_filter(&self, filter: &str) -> Result<ControlResponse, ForwarderError> {
        let params = ControlParameters {
            uri: Some(filter.to_owned()),
            ..Default::default()
        };
        let name = command_name(module::LOG, verb::SET_FILTER, &params);
        self.send_interest(name).await
    }

    /// Generic management exchange — the transport-agnostic seam a UI/engine
    /// drives. Sends one `/localhost/nfd/<module>/<verb>` Interest and returns
    /// the reply's `(status_code, status_text, raw_content)`.
    ///
    /// With `params` it's a **signed command** (ControlParameters in the name,
    /// per the NFD signed-command convention the typed mutators use); without,
    /// an **unsigned dataset** read. The control-vs-dataset distinction is
    /// inferred from `params` because every dashboard mutation carries
    /// parameters and every read does not. Status is read from a `ControlResponse`
    /// when the content decodes as one, else synthesised as `200 OK` (datasets
    /// whose content is concatenated TLV entries).
    pub async fn send_cmd_raw(
        &self,
        module: &str,
        verb: &str,
        params: Option<&ControlParameters>,
    ) -> Result<(u64, String, Bytes), ForwarderError> {
        let interest_wire = match params {
            Some(cp) => {
                let name = command_name(module.as_bytes(), verb.as_bytes(), cp);
                build_signed_interest_with_policy(&self.signing, name).await?
            }
            None => {
                let name = dataset_name(module.as_bytes(), verb.as_bytes());
                build_dataset_interest(name)
            }
        };
        let content = self.send_content_bytes(interest_wire).await?;
        match ControlResponse::decode(content.clone()) {
            Ok(cr) => Ok((cr.status_code, cr.status_text, content)),
            Err(_) => Ok((200, "OK".to_string(), content)),
        }
    }

    /// Send a command Interest with ControlParameters and decode the response.
    async fn command(
        &self,
        module_name: &[u8],
        verb_name: &[u8],
        params: &ControlParameters,
    ) -> Result<ControlParameters, ForwarderError> {
        let name = command_name(module_name, verb_name, params);
        let resp = self.send_interest(name).await?;

        if !resp.is_ok() {
            return Err(ForwarderError::Command {
                code: resp.status_code,
                text: resp.status_text,
            });
        }

        Ok(resp.body.unwrap_or_default())
    }

    /// Send a dataset Interest and return raw content bytes.
    ///
    /// Used for the four NFD-standard list datasets (`faces/list`, `fib/list`,
    /// `rib/list`, `strategy-choice/list`) whose content is concatenated TLV
    /// entries rather than a ControlResponse.
    async fn dataset_raw(
        &self,
        module_name: &[u8],
        verb_name: &[u8],
    ) -> Result<Bytes, ForwarderError> {
        let name = dataset_name(module_name, verb_name);
        // CanBePrefix: dataset responses are versioned+segmented Data names
        // (e.g. /localhost/nfd/faces/list/v=N/seg=0) that are longer than
        // the Interest name. MustBeFresh avoids satisfying management reads
        // from an older cached dataset segment after a mutating command.
        let interest_wire = build_dataset_interest(name);
        self.send_content_bytes(interest_wire).await
    }

    async fn send_content_bytes(&self, interest_wire: Bytes) -> Result<Bytes, ForwarderError> {
        let _guard = self.recv_lock.lock().await;
        let data_wire = self.exchange(&interest_wire).await?;
        let data =
            ndn_packet::Data::decode(data_wire).map_err(|_| ForwarderError::MalformedResponse)?;
        let content = data.content().ok_or(ForwarderError::MalformedResponse)?;
        Ok(Bytes::copy_from_slice(content))
    }

    /// Dataset queries go out unsigned because NFD/yanfd/ndnd require
    /// it; ndn-fwd accepts either.
    async fn dataset(
        &self,
        module_name: &[u8],
        verb_name: &[u8],
    ) -> Result<ControlResponse, ForwarderError> {
        let name = dataset_name(module_name, verb_name);
        self.send_unsigned_interest(name).await
    }

    /// `CanBePrefix` is set so the PIT matches dataset responses
    /// whose names carry version+segment suffixes (e.g. `/.../v=N/seg=0`).
    /// `MustBeFresh` prevents a previous dataset segment from hiding a recent
    /// management change, such as a route registered immediately before a RIB
    /// list query.
    async fn send_unsigned_interest(&self, name: Name) -> Result<ControlResponse, ForwarderError> {
        let interest_wire = build_dataset_interest(name);
        self.send_raw(interest_wire).await
    }

    /// Signs per the active [`SigningPolicy`] and LP-wraps the
    /// Interest (NFD/yanfd/ndnd require NDNLPv2 on Unix faces).
    async fn send_interest(&self, name: Name) -> Result<ControlResponse, ForwarderError> {
        let interest_wire = build_signed_interest_with_policy(&self.signing, name).await?;
        self.send_raw(interest_wire).await
    }

    async fn send_raw(&self, interest_wire: Bytes) -> Result<ControlResponse, ForwarderError> {
        let _guard = self.recv_lock.lock().await;
        let data_wire = self.exchange(&interest_wire).await?;
        let data =
            ndn_packet::Data::decode(data_wire).map_err(|_| ForwarderError::MalformedResponse)?;
        let content = data.content().ok_or(ForwarderError::MalformedResponse)?;
        ControlResponse::decode(Bytes::copy_from_slice(content))
            .map_err(|_| ForwarderError::MalformedResponse)
    }
}

/// The error of a deferred management command the daemon left unanswered.
fn no_answer_within(timeout: std::time::Duration) -> ForwarderError {
    ForwarderError::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("the daemon did not answer within {}s", timeout.as_secs()),
    ))
}

fn build_dataset_interest(name: Name) -> Bytes {
    InterestBuilder::new(name)
        .can_be_prefix()
        .must_be_fresh()
        .build()
}

async fn build_signed_interest_with_policy(
    signing: &SigningPolicy,
    name: Name,
) -> Result<Bytes, ForwarderError> {
    build_signed_interest_with_lifetime(signing, name, None, None).await
}

/// As [`build_signed_interest_with_policy`] with an explicit Interest
/// lifetime (`None`: the default), for commands the daemon answers only after
/// network round trips, and optional ApplicationParameters (the command's
/// ControlParameters when they must stay out of the Name).
async fn build_signed_interest_with_lifetime(
    signing: &SigningPolicy,
    name: Name,
    lifetime: Option<std::time::Duration>,
    app_params: Option<Bytes>,
) -> Result<Bytes, ForwarderError> {
    let mut builder = match lifetime {
        Some(d) => InterestBuilder::new(name).lifetime(d),
        None => InterestBuilder::new(name),
    };
    if let Some(params) = app_params {
        builder = builder.app_parameters(params.to_vec());
    }
    match signing {
        SigningPolicy::DigestSha256 => Ok(builder.sign_digest_sha256()),
        SigningPolicy::Key(signer) => {
            let signer = Arc::clone(signer);
            let sig_type = signer.sig_type();
            let key_loc = signer
                .cert_name()
                .or_else(|| Some(signer.key_name()))
                .cloned();
            builder
                .sign_fallible(sig_type, key_loc.as_ref(), |region: &[u8]| {
                    let region = bytes::Bytes::copy_from_slice(region);
                    let signer = Arc::clone(&signer);
                    async move {
                        signer
                            .sign(&region)
                            .await
                            .map_err(|e| ForwarderError::SigningFailed(e.to_string()))
                    }
                })
                .await
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bytes::Bytes;
    use ndn_mgmt_wire::nfd_command::{command_name, dataset_name, module, verb};
    use ndn_packet::{SignatureType, encode::InterestBuilder};
    use ndn_security::{Ed25519Signer, Signer};

    use super::{SigningPolicy, build_dataset_interest, build_signed_interest_with_policy};

    fn rib_register_name() -> ndn_packet::Name {
        let params = ndn_mgmt_wire::ControlParameters {
            name: Some("/test/prefix".parse().unwrap()),
            face_id: Some(1),
            cost: Some(10),
            ..Default::default()
        };
        command_name(module::RIB, verb::REGISTER, &params)
    }

    async fn sign_with_policy(signing: SigningPolicy) -> Bytes {
        build_signed_interest_with_policy(&signing, rib_register_name())
            .await
            .expect("signing must not fail in test")
    }

    #[test]
    fn dataset_interest_uses_can_be_prefix_and_must_be_fresh() {
        let wire = build_dataset_interest(dataset_name(module::RIB, verb::LIST));
        let interest = ndn_packet::Interest::decode(wire).unwrap();
        let selectors = interest.selectors();

        assert!(
            selectors.can_be_prefix,
            "management datasets need CanBePrefix for versioned segments"
        );
        assert!(
            selectors.must_be_fresh,
            "management datasets must bypass stale cached status segments"
        );
    }

    /// DigestSha256 sig_value must equal `SHA-256(signed_region)` per
    /// ndn-cxx `command-interest-signer.cpp:sendCommandInterest`.
    #[test]
    fn c12_digest_sha256_signed_region_verifies() {
        use sha2::{Digest as _, Sha256};
        let wire = InterestBuilder::new(rib_register_name()).sign_digest_sha256();
        let interest = ndn_packet::Interest::decode(wire).unwrap();
        let region = interest
            .signed_region()
            .expect("signed_region must be present");
        let sig = interest.sig_value().expect("sig_value must be present");
        let expected: [u8; 32] = Sha256::digest(&region).into();
        assert_eq!(
            sig.as_ref(),
            expected.as_slice(),
            "DigestSha256 sig_value must equal SHA-256(signed_region)"
        );
    }

    #[tokio::test]
    async fn c12_digest_sha256_policy_produces_signed_interest() {
        let wire = sign_with_policy(SigningPolicy::DigestSha256).await;
        let interest = ndn_packet::Interest::decode(wire).unwrap();
        assert_eq!(
            interest.sig_info().map(|s| s.sig_type),
            Some(SignatureType::DigestSha256)
        );
        assert!(
            interest.signed_region().is_some(),
            "signed region must be present when InterestSignatureInfo is present"
        );
    }

    #[tokio::test]
    async fn c12_key_signer_produces_verifiable_ed25519_interest() {
        use ndn_security::{
            Ed25519Verifier,
            verifier::{Verifier, VerifyOutcome},
        };

        let signer = Arc::new(Ed25519Signer::from_seed(
            &[0xABu8; 32],
            "/ndn/test/router1/KEY/1".parse().unwrap(),
        ));
        let pk = signer.public_key_bytes();

        let wire =
            sign_with_policy(SigningPolicy::Key(Arc::clone(&signer) as Arc<dyn Signer>)).await;

        let interest = ndn_packet::Interest::decode(wire).unwrap();
        assert_eq!(
            interest.sig_info().map(|s| s.sig_type),
            Some(SignatureType::SignatureEd25519)
        );

        let region = interest
            .signed_region()
            .expect("signed region must be present");
        let sig_value = interest.sig_value().expect("sig_value must be present");
        let outcome = Ed25519Verifier
            .verify(&region, sig_value, &pk)
            .await
            .unwrap();
        assert_eq!(outcome, VerifyOutcome::Valid);
    }

    #[tokio::test]
    async fn c12_key_signer_key_name_in_sig_info() {
        let key_name: ndn_packet::Name = "/ndn/test/router1/KEY/1".parse().unwrap();
        let signer = Arc::new(Ed25519Signer::from_seed(&[0xABu8; 32], key_name.clone()));
        let wire =
            sign_with_policy(SigningPolicy::Key(Arc::clone(&signer) as Arc<dyn Signer>)).await;

        let interest = ndn_packet::Interest::decode(wire).unwrap();
        let locator = interest
            .sig_info()
            .and_then(|s| s.key_locator.as_ref())
            .and_then(|kl| match kl {
                ndn_packet::KeyLocator::Name(n) => Some((**n).clone()),
                _ => None,
            });
        assert_eq!(locator.as_ref(), Some(&key_name));
    }
}
