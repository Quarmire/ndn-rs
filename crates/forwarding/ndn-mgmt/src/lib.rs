//! NFD-compatible management dispatcher over `/localhost/nfd/<module>/<verb>/<ControlParameters>`.
//!
//! Per-module handlers live in [`modules`]; [`module::MgmtRouter`] dispatches
//! by module name. Hosts embed the dispatcher via [`run_ndn_mgmt_handler`]
//! with a populated [`MgmtHandles`].

use std::sync::Arc;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::RwLock;

use bytes::Bytes;
use ndn_engine::ForwarderEngine;
use ndn_face_local::InProcHandle;
use ndn_packet::{Interest, Name, NameComponent};
#[cfg(not(target_arch = "wasm32"))]
use ndn_security::FilePib;
use tokio_util::sync::CancellationToken;

use ndn_mgmt_wire::{
    ControlParameters, ControlResponse, control_response::status, nfd_command::parse_command_name,
};

pub mod auth;
pub mod module;
pub mod modules;
#[cfg(not(target_arch = "wasm32"))]
pub mod ndnsd_adapter;
pub mod notification;
#[cfg(not(target_arch = "wasm32"))]
pub mod status_bridge;
pub mod wire;

#[cfg(not(target_arch = "wasm32"))]
pub mod listeners;

#[cfg(all(unix, not(target_arch = "wasm32")))]
pub use listeners::mount_app_face_from_fd;
#[cfg(not(target_arch = "wasm32"))]
pub use listeners::{
    UdpListener, bind_udp_listener, run_face_listener, run_face_listener_as, run_tcp_listener,
    run_udp_listener,
};
#[cfg(not(target_arch = "wasm32"))]
pub use modules::MgmtAccessPolicy;
#[cfg(not(target_arch = "wasm32"))]
pub use ndnsd_adapter::{
    NdnsdServiceInfo, encode_service_info, encode_service_list, mount_ndnsd_discovery,
    mount_ndnsd_service_info,
};
#[cfg(not(target_arch = "wasm32"))]
pub use status_bridge::mount_routing_status;

pub use auth::{COMMAND_SIG_TIME_TOLERANCE_MS, CommandReplayCache};
pub use module::{CaInfo, MgmtConfig, MgmtContext, MgmtModule, MgmtRouter};
// Re-exported for out-of-core mgmt modules (e.g. ndn-discovery's service module)
// that enforce the same operator/reserved-name policy as the built-ins.
pub use modules::common::{is_management_face, is_reserved_name};
pub use modules::faces::provision::{
    FaceProvisioner, ProvisionError, ProvisionRequest, ProvisionedFace,
};
pub use modules::faces::{FaceEvent, FaceEventKind};
pub use modules::rib::{RouteEvent, RouteEventKind};
pub use modules::strategy::{StrategyEvent, StrategyEventKind, create_strategy_by_name};
pub use ndn_mgmt_wire::{ControlInfo, ControlStats, ControlSurface};
pub use notification::{NotificationEvent, NotificationStream};

use auth::{
    CommandAuth, authorize_command, authorize_trust_admin, effective_require_signed,
    is_public_dataset_verb, is_trust_admin_verb, local_command_auth, resolve_control_parameters,
};
use wire::{send_dataset, send_response};

/// Response from a management command dispatch.
///
/// - `Control` — standard ControlResponse (TLV 0x65) wrapped in Data content.
/// - `Dataset` — raw NFD status dataset bytes (concatenated TLV 0x80 entries)
///   used for `*/list` verbs.
/// - `Deferred` — a ControlResponse that needs network round trips (e.g.
///   `security/context-adopt` fetching a context). The handler loop answers it
///   from a task of its own, so one slow command does not stall every other
///   management client; the command Interest's lifetime must cover it.
/// - `DeferredDataset` — a dataset that may need network round trips (e.g.
///   `ca/list-approvals` on an admin device asking its namespace's CA),
///   answered like `Deferred`; a refusal is a ControlResponse instead.
pub enum MgmtResponse {
    Control(Box<ControlResponse>),
    Dataset(bytes::Bytes),
    Deferred(std::pin::Pin<Box<dyn Future<Output = ControlResponse> + Send>>),
    DeferredDataset(
        std::pin::Pin<Box<dyn Future<Output = Result<bytes::Bytes, ControlResponse>> + Send>>,
    ),
}

impl From<ControlResponse> for MgmtResponse {
    fn from(r: ControlResponse) -> Self {
        MgmtResponse::Control(Box::new(r))
    }
}

/// Build the `/localhost/nfd` name prefix registered in the FIB.
pub fn mgmt_prefix() -> Name {
    Name::from_components([
        NameComponent::generic(Bytes::from_static(b"localhost")),
        NameComponent::generic(Bytes::from_static(b"nfd")),
    ])
}

/// Build the `/localhop/nfd` name prefix.
///
/// Per NFD `daemon/mgmt/rib-manager.cpp:60-89`, rib commands are registered
/// under both `/localhost/nfd` and `/localhop/nfd`; the latter validates
/// against the localhop trust anchor set so remote signers with appropriate
/// certs can register prefixes. Without this FIB entry the pipeline NACKs
/// with NoRoute before the handler runs.
pub fn mgmt_localhop_prefix() -> Name {
    Name::from_components([
        NameComponent::generic(Bytes::from_static(b"localhop")),
        NameComponent::generic(Bytes::from_static(b"nfd")),
    ])
}

/// Bridges `ndn_transport::FaceLifecycleSink` to the face-events
/// notification stream so per-face `Up` / `Down` transitions reach
/// subscribers on `/localhost/nfd/faces/notifications`.
struct NotificationFaceLifecycleSink {
    stream: Arc<NotificationStream<FaceEvent>>,
}

impl ndn_transport::FaceLifecycleSink for NotificationFaceLifecycleSink {
    fn on_up(&self, face_id: ndn_transport::FaceId) {
        self.stream.publish(FaceEvent::Up { face_id });
    }

    fn on_down(&self, face_id: ndn_transport::FaceId) {
        self.stream.publish(FaceEvent::Down { face_id });
    }
}

/// Wire NFD-compatible management onto `engine` and return the handler
/// future. The caller spawns it on whatever runtime is in scope
/// (`tokio::spawn` on native, `ndn_runtime::Runtime::spawn` on wasm).
pub fn mount_management(
    engine: &ForwarderEngine,
    cancel: CancellationToken,
    config: Arc<dyn crate::module::MgmtConfig>,
    #[cfg(not(target_arch = "wasm32"))] pib: Option<Arc<FilePib>>,
    handles: MgmtHandles,
) -> impl std::future::Future<Output = ()> + 'static {
    use ndn_engine::FibNexthop;

    let face_id = engine.faces().alloc_id();
    let (face, handle) =
        ndn_face_local::InProcFace::new_kind(face_id, 64, ndn_transport::face::FaceKind::Internal);
    engine.add_face(face, cancel.child_token());

    engine
        .fib()
        .set_nexthops(&mgmt_prefix(), vec![FibNexthop { face_id, cost: 0 }]);
    engine.fib().set_nexthops(
        &mgmt_localhop_prefix(),
        vec![FibNexthop { face_id, cost: 0 }],
    );

    let face_events = NotificationStream::<FaceEvent>::new(notifications_prefix(b"faces"));
    let route_events = NotificationStream::<RouteEvent>::new(notifications_prefix(b"rib"));
    let strategy_events =
        NotificationStream::<StrategyEvent>::new(notifications_prefix(b"strategy-choice"));
    Arc::clone(&face_events).install(engine, cancel.clone());
    Arc::clone(&route_events).install(engine, cancel.clone());
    Arc::clone(&strategy_events).install(engine, cancel.clone());
    install_membership_events(engine, &handles, &cancel);

    engine.set_face_lifecycle_sink(Arc::new(NotificationFaceLifecycleSink {
        stream: Arc::clone(&face_events),
    }));

    let engine = engine.clone();
    async move {
        run_ndn_mgmt_handler(
            handle,
            engine,
            cancel,
            config,
            #[cfg(not(target_arch = "wasm32"))]
            pib,
            handles,
            face_events,
            route_events,
            strategy_events,
        )
        .await;
    }
}

/// Build the mgmt router: the NFD-compatible built-in modules plus any
/// host-supplied extension modules (e.g. `ndn_pipes::PipesModule`). Exposed so
/// the wiring is testable without standing up the whole handler loop.
pub fn build_mgmt_router(extra_modules: &[Arc<dyn MgmtModule>]) -> MgmtRouter {
    let mut router = MgmtRouter::new();
    modules::register_builtins(&mut router);
    for m in extra_modules {
        router.register(Arc::clone(m));
    }
    router
}

/// Build the `/localhost/nfd/<module>/notifications` prefix for a
/// module name like `b"faces"` or `b"rib"`.
pub fn notifications_prefix(module_name: &'static [u8]) -> Name {
    Name::from_components([
        NameComponent::generic(Bytes::from_static(b"localhost")),
        NameComponent::generic(Bytes::from_static(b"nfd")),
        NameComponent::generic(Bytes::from_static(module_name)),
        NameComponent::generic(Bytes::from_static(b"notifications")),
    ])
}

/// `/localhost/nfd/security/notifications`: the trust-admin backend's
/// [`MembershipEvent`]s, JSON-encoded, one Data per event — when the
/// backend publishes them ([`TrustAdminMgmtBackend::membership_events`]).
fn install_membership_events(
    engine: &ForwarderEngine,
    handles: &MgmtHandles,
    cancel: &CancellationToken,
) {
    let Some(mut events) = handles
        .trust_context_handler
        .as_ref()
        .and_then(|backend| backend.membership_events())
    else {
        return;
    };
    let stream = NotificationStream::<MembershipEvent>::new(notifications_prefix(b"security"));
    Arc::clone(&stream).install(engine, cancel.clone());
    let cancel = cancel.clone();
    engine.runtime().spawn(Box::pin(async move {
        use tokio::sync::broadcast::error::RecvError;
        loop {
            let event = tokio::select! {
                _ = cancel.cancelled() => return,
                event = events.recv() => event,
            };
            match event {
                Ok(event) => stream.publish(event),
                Err(RecvError::Lagged(missed)) => tracing::warn!(
                    target: "mgmt.security",
                    missed,
                    "membership notifications fell behind; {missed} events were not published \
                     (security/memberships has the current state)"
                ),
                Err(RecvError::Closed) => return,
            }
        }
    }));
}

impl NotificationEvent for MembershipEvent {
    fn encode(&self) -> Bytes {
        Bytes::from(serde_json::to_vec(self).unwrap_or_default())
    }
}

/// Runtime handles for management of pluggable protocol components.
#[derive(Default)]
pub struct MgmtHandles {
    /// Whether the active signing identity is ephemeral (in-memory, not persisted).
    pub security_is_ephemeral: bool,
    /// Validator for signed command Interests.
    pub command_validator: Option<Arc<ndn_security::Validator>>,
    /// Validator for `/localhop/nfd/...` commands.
    pub localhop_command_validator: Option<Arc<ndn_security::Validator>>,
    /// When `true`, an unsigned or invalid command Interest is rejected.
    pub require_signed_commands: bool,
    /// Sliding `SignatureTime` window per signer for replay defence.
    pub command_replay_cache: Option<CommandReplayCache>,
    /// Signer for control-response Data packets: the node's current key,
    /// which may change while it runs. Each response is signed with one
    /// snapshot ([`response_signer`](Self::response_signer)).
    pub command_response_signer: Option<Arc<ndn_security::ActiveSigner>>,
    /// Host-owned log ring + filter reload hook for the `log` module.
    pub log_inspector: Option<Arc<LogInspector>>,
    pub coding_handler: Option<Arc<dyn CodingHandler>>,
    pub rate_limit_handler: Option<Arc<dyn RateLimitMgmtBackend>>,
    /// Read-only `compute` introspection backend (function table).
    pub compute_handler: Option<Arc<dyn ComputeMgmtBackend>>,
    /// BLE peripheral listener control + status backend (`ble` module).
    pub ble_handler: Option<Arc<dyn BleMgmtBackend>>,
    /// Read-only pending device-approval backend (`ca` module).
    pub approval_handler: Option<Arc<dyn ApprovalMgmtBackend>>,
    /// Trust-admin backend (`security/context-adopt`, `security/enroll`, and
    /// the live signing identity `security/identity-status` reports). None:
    /// those verbs answer that this host does not change its trust at runtime.
    pub trust_context_handler: Option<Arc<dyn TrustAdminMgmtBackend>>,
    /// Read-only WebTransport TLS cert-status backend (`webtransport` module).
    pub webtransport_status_handler: Option<Arc<dyn WtCertStatusBackend>>,
    /// Runtime-mutable mgmt-access policy.
    #[cfg(not(target_arch = "wasm32"))]
    pub runtime_policy: Option<Arc<RwLock<MgmtAccessPolicy>>>,
    /// Extra, self-contained management modules to register alongside the
    /// built-ins — e.g. an extension's read-only introspection module like
    /// `ndn_pipes::PipesModule` (`/localhost/nfd/pipes/list`). Each carries its
    /// own state and is registered as-is into the router.
    pub extra_modules: Vec<Arc<dyn MgmtModule>>,
    /// Per-scheme builders for the **extension** transports (quic://, wts://,
    /// …). `ndn-mgmt` links no extension face crate; the forwarder registers
    /// these so `faces/create` can dial them. Empty = standard transports only.
    pub face_provisioners: Vec<Arc<dyn FaceProvisioner>>,
    /// Pluggable introspection/control surfaces for out-of-core subsystems
    /// (routing, discovery, custom strategies, ext faces). Served generically at
    /// `/localhost/nfd/ext/…`. Empty = no extensions registered.
    pub control_surfaces: Vec<Arc<dyn ndn_mgmt_wire::ControlSurface>>,
}

impl MgmtHandles {
    pub fn effective_require_signed_commands(&self) -> bool {
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(lock) = &self.runtime_policy
            && let Ok(g) = lock.read()
        {
            return g.require_signed_commands;
        }
        self.require_signed_commands
    }

    pub fn effective_localhop_disabled(&self) -> bool {
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(lock) = &self.runtime_policy
            && let Ok(g) = lock.read()
        {
            return g.localhop_disabled;
        }
        self.localhop_command_validator.is_none()
    }

    /// One snapshot of the response signer, for signing one response.
    pub fn response_signer(&self) -> Option<Arc<dyn ndn_security::Signer>> {
        self.command_response_signer.as_ref().map(|s| s.current())
    }
}

/// Pluggable backend for the `coding` management module. The spec crate
/// owns the trait so it stays independent of the draft crate that ships
/// the policy table (`ndn-coding::mgmt::CodingMgmtHandler`).
pub trait CodingHandler: Send + Sync {
    fn set(&self, prefix: &Name, entry: CodingEntry) -> Result<(), String>;
    fn unset(&self, prefix: &Name, role: CodingRole) -> Result<(), String>;
    fn list(&self) -> Vec<(Name, CodingEntry)>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodingRole {
    Produced,
    Consumed,
}

/// Read-only backend for the `compute` introspection module. The spec
/// crate owns the trait so it stays independent of `ndn-compute`, which
/// implements it over its `ComputeService` function table.
pub trait ComputeMgmtBackend: Send + Sync {
    /// The currently-registered compute functions.
    fn list(&self) -> Vec<ComputeFunctionInfo>;
}

/// Read-only TLS cert status of a WebTransport listener, for the
/// `webtransport/cert-status` introspection module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WtCertStatusInfo {
    /// Listener bind address (e.g. `0.0.0.0:4443`).
    pub listen: String,
    /// Leaf cert `notAfter`, seconds since the Unix epoch.
    pub not_after_unix: i64,
    /// Whole days until `notAfter` (negative if already expired).
    pub days_remaining: i64,
    /// Whether the cert is within the renewal window.
    pub needs_renewal: bool,
}

/// Read-only backend for the `webtransport` introspection module. The spec
/// crate owns the trait; the host (`ndn-fwd`) implements it over the live
/// listener cert state.
pub trait WtCertStatusBackend: Send + Sync {
    /// One row per active WebTransport listener.
    fn cert_status(&self) -> Vec<WtCertStatusInfo>;
}

/// Snapshot of the BLE peripheral listener for the `ble` module's `list` verb.
#[derive(Debug, Clone, Default)]
pub struct BleStatus {
    /// Whether this build supports BLE (feature `bluetooth`, supported OS).
    pub supported: bool,
    /// Whether the peripheral listener is currently advertising.
    pub advertising: bool,
    /// Local adapter identifier/address, when known.
    pub adapter: Option<String>,
    /// Number of currently connected centrals (BLE faces).
    pub connected_centrals: u64,
}

/// Backend for the `ble` management module: controls the BLE peripheral
/// listener and reports status. The spec crate owns the trait; the host
/// (`ndn-fwd`) implements it over `ndn_face::l2::BleListener`.
#[async_trait::async_trait]
pub trait BleMgmtBackend: Send + Sync {
    async fn status(&self) -> BleStatus;
    /// Start advertising the NDN service (idempotent).
    async fn start(&self) -> Result<(), String>;
    /// Stop advertising and tear down the listener (idempotent).
    async fn stop(&self) -> Result<(), String>;
}

/// Backend of the `ca` module: the requests for an admin's approval this
/// node can decide. On a CA host that is its CA's records
/// ([`ndn_cert::ApprovalStore`] implements it); a forwarder that is also an
/// admin device of other namespaces adds their CAs' pending requests and
/// decides them with its admin key. The spec crate owns the trait; the
/// verbs reach it only from a local operator (the trust-admin
/// peer-credential gate), never over `/localhop`.
#[async_trait::async_trait]
pub trait ApprovalMgmtBackend: Send + Sync {
    /// Every request this node can see, plus a note for each namespace whose
    /// requests could not be listed (its CA unreachable). Refuse only when
    /// nothing at all could be listed.
    async fn list(&self) -> Result<ndn_mgmt_wire::ApprovalListing, TrustRefusal>;
    /// Decide the pending request `target` names (its request id or its
    /// verification code). `operator` is the local operator the kernel
    /// attests (`uid 1000 (alice)`): the approver a CA host records.
    /// Returns the request as decided.
    async fn decide(
        &self,
        target: String,
        decision: ndn_cert::Decision,
        operator: String,
    ) -> Result<ndn_mgmt_wire::PendingApproval, TrustRefusal>;
}

/// The `ca/list-approvals` row of a CA's approval record.
pub fn approval_row(record: &ndn_cert::ApprovalRecord) -> ndn_mgmt_wire::PendingApproval {
    use ndn_cert::ApprovalState;
    let (approver, reason) = match &record.state {
        ApprovalState::Pending => (String::new(), String::new()),
        ApprovalState::Approved { by, .. } => (by.describe(), String::new()),
        ApprovalState::Denied { by, reason, .. } => (by.describe(), reason.clone()),
    };
    ndn_mgmt_wire::PendingApproval {
        request_id: record.request_id.clone(),
        key_name: record.key_name.clone(),
        namespace: record.ca_prefix.clone(),
        role: record.role.clone().unwrap_or_default(),
        device: record.device.clone().unwrap_or_default(),
        code: record.code.clone(),
        state: record.state.as_str().to_owned(),
        created_secs: record.created_secs,
        expires_secs: record.expires_secs,
        approver,
        reason,
    }
}

#[async_trait::async_trait]
impl ApprovalMgmtBackend for ndn_cert::ApprovalStore {
    async fn list(&self) -> Result<ndn_mgmt_wire::ApprovalListing, TrustRefusal> {
        Ok(ndn_mgmt_wire::ApprovalListing {
            rows: self.records().iter().map(approval_row).collect(),
            notes: Vec::new(),
        })
    }

    async fn decide(
        &self,
        target: String,
        decision: ndn_cert::Decision,
        operator: String,
    ) -> Result<ndn_mgmt_wire::PendingApproval, TrustRefusal> {
        self.decide_locally(&target, decision, &operator)
            .map(|record| approval_row(&record))
            .map_err(TrustRefusal::from)
    }
}

// What the trust-admin verbs answer: owned by `ndn-cert` (any host of a
// personal namespace produces them, see the `ndn-namespace` crate).
pub use ndn_cert::NodeIdentitySource;
pub use ndn_cert::report::{
    AdoptedContextInfo, ContextRefreshInfo, EnrollOutcome, EnrollRequest, EnrolledInfo,
    MembershipChange, MembershipEvent, MembershipInfo, MembershipRelation, PendingEnrollInfo,
    RefreshState, RenewalInfo, RenewalState, TrustRefusal,
};

/// Where this node keeps the root key of a namespace it is the root device
/// of (`security/identity-status` reports each as `root_store=<kind>
/// root_key=<key>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootStoreInfo {
    /// The namespace whose root it is.
    pub namespace: Name,
    /// The store kind: `os-keyring`, `sealed-file`, `yubikey-piv`, `file`.
    pub kind: String,
    /// The root key, `<ns>/KEY/root`.
    pub key: Name,
}

/// The identities the node signs as: its node identity — the key of its
/// own packets (management responses, discovery records, links) — and why,
/// and every identity it signs Data as (each trusted prefix's Data with its
/// own key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningIdentityInfo {
    /// The node key.
    pub key: Name,
    /// An in-memory key minted at startup (not persisted).
    pub ephemeral: bool,
    /// When the node key's certificate expires (ns since the Unix epoch),
    /// if the node holds one for it.
    pub valid_until: Option<u64>,
    /// Which rule chose the node identity.
    pub source: NodeIdentitySource,
    /// Every identity the node signs Data as, with its key, sorted by
    /// identity.
    pub signing: Vec<(Name, Name)>,
}

/// Backend for the trust-admin verbs: adopt a trust context
/// (`security/context-adopt`), enroll with an invite (`security/enroll`),
/// refresh held contexts (`security/context-refresh`), take a newer version
/// of a held context made on this device (`security/context-update`), renew
/// this node's certificates (`security/renew`), and report the identity the
/// node signs with now. The
/// spec crate owns the trait; the forwarder (`ndn-fwd`)
/// implements it over its engine, keyring, PIB, CA, context store and
/// publisher. Authorization happens before a verb reaches the backend (the
/// trust-admin peer-credential gate).
#[async_trait::async_trait]
pub trait TrustAdminMgmtBackend: Send + Sync {
    async fn adopt(&self, link_uri: String) -> Result<AdoptedContextInfo, TrustRefusal>;

    async fn enroll(&self, request: EnrollRequest) -> Result<EnrollOutcome, TrustRefusal> {
        let _ = request;
        Err(TrustRefusal {
            status_code: ndn_mgmt_wire::control_response::status::NOT_FOUND,
            reason: "this node does not enroll at runtime".to_owned(),
        })
    }

    /// Check the held context of `namespace` (every held one when `None`)
    /// for a newer version.
    async fn refresh_contexts(
        &self,
        namespace: Option<Name>,
    ) -> Result<Vec<ContextRefreshInfo>, TrustRefusal> {
        let _ = namespace;
        Err(TrustRefusal {
            status_code: ndn_mgmt_wire::control_response::status::NOT_FOUND,
            reason: "this node does not refresh trust contexts at runtime".to_owned(),
        })
    }

    /// Adopt `context_data` (a signed trust-context Data) as the next version
    /// of a held context, under the continuity rule a refresh applies, then
    /// store and publish it.
    async fn update_context(
        &self,
        context_data: bytes::Bytes,
    ) -> Result<ContextRefreshInfo, TrustRefusal> {
        let _ = context_data;
        Err(TrustRefusal {
            status_code: ndn_mgmt_wire::control_response::status::NOT_FOUND,
            reason: "this node does not take trust-context updates at runtime".to_owned(),
        })
    }

    /// Renew, now, every certificate a namespace CA issued to this node's
    /// keys.
    async fn renew(&self) -> Result<Vec<RenewalInfo>, TrustRefusal> {
        Err(TrustRefusal {
            status_code: ndn_mgmt_wire::control_response::status::NOT_FOUND,
            reason: "this node does not renew certificates at runtime".to_owned(),
        })
    }

    /// The requests for an admin's approval this node made
    /// (`security/enroll-status`), oldest first.
    async fn enroll_status(&self) -> Result<Vec<ndn_cert::OutgoingRequest>, TrustRefusal> {
        Err(TrustRefusal {
            status_code: ndn_mgmt_wire::control_response::status::NOT_FOUND,
            reason: "this node does not enroll at runtime".to_owned(),
        })
    }

    /// The node identity and every identity the node signs as, if the
    /// backend tracks them (they change at runtime through
    /// `security/enroll`).
    fn signing_identity(&self) -> Option<SigningIdentityInfo> {
        None
    }

    /// How the node takes part in each namespace it holds
    /// (`security/memberships`): following, member (role) or owner.
    async fn memberships(&self) -> Result<Vec<MembershipInfo>, TrustRefusal> {
        Err(TrustRefusal {
            status_code: ndn_mgmt_wire::control_response::status::NOT_FOUND,
            reason: "this node does not report its trusted prefixes".to_owned(),
        })
    }

    /// A receiver of the node's membership changes, served at
    /// `/localhost/nfd/security/notifications`; `None`: none are published.
    /// Called once, when management is mounted.
    fn membership_events(&self) -> Option<tokio::sync::broadcast::Receiver<MembershipEvent>> {
        None
    }

    /// Where this node keeps the root keys of the namespaces it is the root
    /// device of, sorted by namespace; empty on every other node.
    fn root_stores(&self) -> Vec<RootStoreInfo> {
        Vec::new()
    }
}

/// Whether a function's result is determined solely by its invocation
/// name (mirrors `ndn_compute::Determinism`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComputeDeterminism {
    /// Cacheable, PIT-aggregatable.
    Transparent,
    /// Carries a per-call nonce; never aliases.
    Opaque,
}

/// How a registered compute function is backed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComputeFnKind {
    /// Raw [`ComputeHandler`](https://docs.rs/ndn-compute) (Tier 0).
    Raw,
    /// Typed function (Tier 1).
    Typed,
    /// Sandboxed/native executor (Tier 2).
    Executor,
    /// Reflexive-pull function (Tier 3, RICE §8).
    Reflexive,
    /// Long-running thunk job (Tier 3).
    Job,
}

/// One row of the compute function table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputeFunctionInfo {
    /// Function name prefix routed to the compute face.
    pub prefix: Name,
    /// Determinism class.
    pub determinism: ComputeDeterminism,
    /// Backing kind.
    pub kind: ComputeFnKind,
    /// Per-invocation fuel budget, for sandboxed executors that meter it.
    pub fuel: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodingFieldId {
    Gf8,
}

/// One row of policy table for both `set` (input) and `list` (output).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodingEntry {
    pub role: CodingRole,
    pub k: u16,
    pub n: u16,
    pub field: CodingFieldId,
}

/// Pluggable backend for the `rate-limit` management module.
pub trait RateLimitMgmtBackend: Send + Sync {
    fn set(&self, prefix: Option<&Name>, entry: RateLimitWireEntry) -> Result<(), String>;
    fn unset(&self, prefix: Option<&Name>, key: RateLimitWireKey) -> Result<(), String>;
    fn list(&self) -> Vec<RateLimitWireListed>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitWireKey {
    pub face_id: Option<u64>,
    pub direction: RateLimitDirection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitWireEntry {
    pub face_id: Option<u64>,
    pub direction: RateLimitDirection,
    pub interest_pps: Option<u32>,
    pub interest_burst: Option<u32>,
    pub data_bps: Option<u64>,
    pub data_burst_bytes: Option<u64>,
    pub overflow: RateLimitOverflow,
    pub queue_max: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct RateLimitWireListed {
    pub prefix: Option<Name>,
    pub entry: RateLimitWireEntry,
    pub overflow_events: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitOverflow {
    Nack,
    Drop,
    Queue,
}

/// Host-supplied plumbing for the `log` management module. The dispatcher
/// owns no log state — `tracing_subscriber` lives in the binary, which
/// shares its ring buffer, current filter string, and reload callback here.
pub struct LogInspector {
    pub ring: Arc<std::sync::Mutex<std::collections::VecDeque<(u64, String)>>>,
    pub filter: Arc<std::sync::Mutex<String>>,
    pub apply_filter: Arc<dyn Fn(&str) + Send + Sync + 'static>,
}

/// Pull a `/localhop` registrant's certificate back over the reverse path
/// (reflexive forwarding) and insert it into `validator`'s cache, so the
/// subsequent signature chain-walk resolves without a network cert-fetch. The
/// registrant serves its certificate as the *content* of the reverse-pull Data
/// (named under the reflexive name `R`); we decode that content into a
/// [`Certificate`](ndn_security::Certificate). Best-effort — every failure path
/// leaves the cache untouched, so the validator falls back to its FIB fetcher.
#[cfg(not(target_arch = "wasm32"))]
async fn reflexive_prefetch_localhop_cert(
    consumer: &mut ndn_app::Consumer,
    interest: &Interest,
    validator: &ndn_security::Validator,
) {
    use std::time::Duration;
    let wrapper = match consumer
        .pull_reflexive(interest, "cert", Duration::from_secs(3))
        .await
    {
        Ok(d) => d,
        Err(e) => {
            tracing::debug!(target: "security", error = %e,
                "localhop: reflexive cert pull failed; falling back to FIB fetch");
            return;
        }
    };
    let Some(content) = wrapper.content() else {
        return;
    };
    let cert_data = match ndn_packet::Data::decode(content.clone()) {
        Ok(d) => d,
        Err(e) => {
            tracing::debug!(target: "security", error = %e,
                "localhop: reflexive cert wrapper content is not a Data");
            return;
        }
    };
    match ndn_security::Certificate::decode(&cert_data) {
        Ok(cert) => {
            tracing::debug!(target: "security", name = %cert.name,
                "localhop: cached registrant cert via reflexive pull");
            validator.cert_cache_arc().insert(cert);
        }
        Err(e) => tracing::debug!(target: "security", error = %e,
            "localhop: reflexive-pulled cert did not decode"),
    }
}

/// Read Interests from the management `InProcHandle`, dispatch NFD
/// commands through the [`MgmtRouter`], and write Data responses back.
#[allow(clippy::too_many_arguments)]
pub async fn run_ndn_mgmt_handler(
    handle: InProcHandle,
    engine: ForwarderEngine,
    cancel: CancellationToken,
    config: Arc<dyn crate::module::MgmtConfig>,
    #[cfg(not(target_arch = "wasm32"))] pib: Option<Arc<FilePib>>,
    mgmt_handles: MgmtHandles,
    face_events: Arc<NotificationStream<FaceEvent>>,
    route_events: Arc<NotificationStream<RouteEvent>>,
    strategy_events: Arc<NotificationStream<StrategyEvent>>,
) {
    let router = build_mgmt_router(&mgmt_handles.extra_modules);
    // Shared with the tasks that answer deferred responses.
    let handle = Arc::new(handle);

    // Side consumer for reflexive certificate pulls during `/localhop`
    // authorization: when a remote node registers a prefix, it carries a
    // reflexive name so we can pull its certificate back along the reverse path
    // (rather than FIB-fetching it — which routes the requester's identity at the
    // CA, not the requester, and times out). Created lazily on first use. Native
    // only (localhop registration is a forwarder/gateway concern).
    #[cfg(not(target_arch = "wasm32"))]
    let mut reflexive_consumer: Option<ndn_app::Consumer> = None;

    loop {
        let tagged = tokio::select! {
            _ = cancel.cancelled() => break,
            r = handle.recv_tagged() => match r {
                Some(t) => t,
                None    => break,
            },
        };

        let interest = match Interest::decode(tagged.wire) {
            Ok(i) => i,
            Err(e) => {
                tracing::warn!(target: "engine", error = %e, "nfd-mgmt: malformed Interest; skipping");
                continue;
            }
        };
        let source_face = tagged
            .source_face
            .or_else(|| engine.source_face_id(&interest));
        tracing::debug!(
            target: "engine",
            source_face = ?source_face,
            name = %interest.name,
            "nfd-mgmt: received command"
        );

        let parsed = match parse_command_name(&interest.name) {
            Some(p) => p,
            None => {
                let resp = ControlResponse::error(status::BAD_PARAMS, "invalid command name");
                send_response(
                    &handle,
                    &interest.name,
                    &resp,
                    mgmt_handles.response_signer().as_deref(),
                )
                .await;
                continue;
            }
        };

        // Per NFD `daemon/mgmt/rib-manager.cpp:340-355`, `/localhop/...`
        // commands always require a signed Interest validated against the
        // localhop trust anchors.
        let is_localhop_command = interest
            .name
            .components()
            .first()
            .is_some_and(|c| c.value.as_ref() == b"localhop");
        // Public read-only dataset queries (the canonical NFD status datasets
        // — `*/list`, `status/general`, `cs/info` — plus the security
        // inspection verbs and `compute/list`) are served unsigned by design.
        // Skip authorization for them entirely: they need no signature, and
        // routing them through `authorize_command` made every poll emit an
        // "unsigned command accepted" warning. localhop commands are never
        // public. See `is_public_dataset_verb`.
        let is_public_read =
            !is_localhop_command && is_public_dataset_verb(&parsed.module, &parsed.verb);
        // Trust-changing verbs (adopting a trust context, enrolling) are
        // authorized by who is on the other end of the local management
        // socket — its peer credentials — instead of by a command signature:
        // a device that has no identity yet must still be able to adopt its
        // first trust context. Over `/localhop` they are refused outright: a
        // neighbour must never change this node's trust. See
        // `auth::authorize_trust_admin`.
        let is_trust_admin_command = is_trust_admin_verb(&parsed.module, &parsed.verb);
        if is_localhop_command && is_trust_admin_command {
            tracing::warn!(
                target: "mgmt.security",
                name = %interest.name,
                "nfd-mgmt: trust change over /localhop refused"
            );
            let resp = ControlResponse::error(
                status::UNAUTHORIZED,
                "trust changes — adopting, enrolling, revoking, refreshing, and listing or \
                 deciding approval requests — are accepted only on this node's local \
                 management socket; run `ndn-fwd adopt` / `enroll` / `revoke` / `context \
                 refresh` / `approvals` on the node itself (an admin device decides another \
                 node's requests with `ndn-fwd approvals` on its own node)",
            );
            send_response(
                &handle,
                &interest.name,
                &resp,
                mgmt_handles.response_signer().as_deref(),
            )
            .await;
            continue;
        }
        let is_trust_admin = is_trust_admin_command;
        if is_trust_admin {
            if let Err(reason) = authorize_trust_admin(source_face, &engine, config.as_ref()) {
                tracing::warn!(
                    target: "mgmt.security",
                    name = %interest.name,
                    %reason,
                    "nfd-mgmt: trust change refused"
                );
                let resp = ControlResponse::error(status::UNAUTHORIZED, reason);
                send_response(
                    &handle,
                    &interest.name,
                    &resp,
                    mgmt_handles.response_signer().as_deref(),
                )
                .await;
                continue;
            }
        } else if !is_public_read {
            // `None`: the caller is already authenticated by its credentials.
            let signature_check = if is_localhop_command {
                match mgmt_handles.localhop_command_validator.as_deref() {
                    Some(v) => Some((Some(v), true)),
                    None => {
                        let resp = ControlResponse::error(
                            status::UNAUTHORIZED,
                            "localhop registration disabled (no trust anchor configured)",
                        );
                        send_response(
                            &handle,
                            &interest.name,
                            &resp,
                            mgmt_handles.response_signer().as_deref(),
                        )
                        .await;
                        continue;
                    }
                }
            } else {
                let required = effective_require_signed(
                    &parsed.module,
                    mgmt_handles.effective_require_signed_commands(),
                );
                let validator = mgmt_handles.command_validator.as_deref();
                // On the local management socket the kernel's peer
                // credentials authenticate the caller, as for trust changes:
                // a local operator's command needs no signature. Any other
                // face (and any other local user) is decided by the
                // signature. See `auth::local_command_auth`.
                match local_command_auth(
                    source_face,
                    &engine,
                    config.as_ref(),
                    &interest,
                    required,
                    validator.is_some(),
                ) {
                    CommandAuth::LocalOperator => None,
                    CommandAuth::Signature => Some((validator, required)),
                    CommandAuth::Refused(reason) => {
                        tracing::warn!(
                            target: "mgmt.security",
                            name = %interest.name,
                            %reason,
                            "nfd-mgmt: unsigned local command refused"
                        );
                        let resp = ControlResponse::error(status::UNAUTHORIZED, reason);
                        send_response(
                            &handle,
                            &interest.name,
                            &resp,
                            mgmt_handles.response_signer().as_deref(),
                        )
                        .await;
                        continue;
                    }
                }
            };
            // Reflexive cert distribution: a `/localhop` registrant attaches a
            // reflexive name so we can pull its certificate back along the reverse
            // path of the command Interest. Pre-cache it so the validator's
            // chain-walk resolves locally — fast, and crucially it works *before*
            // any route to the requester exists (the chicken-and-egg of remote
            // registration: validating the registrant needs its cert, but routing
            // to its cert would need the registration). Best-effort; on failure
            // the validator falls back to its FIB-backed CertFetcher.
            #[cfg(not(target_arch = "wasm32"))]
            if is_localhop_command
                && interest.reflexive_name().is_some()
                && let Some(validator) = mgmt_handles.localhop_command_validator.as_deref()
            {
                let consumer = reflexive_consumer.get_or_insert_with(|| {
                    use ndn_app::EngineAppExt;
                    engine.app_consumer(cancel.child_token())
                });
                reflexive_prefetch_localhop_cert(consumer, &interest, validator).await;
            }
            if let Some((active_validator, effective_required)) = signature_check
                && let Err(reason) = authorize_command(
                    &interest,
                    active_validator,
                    effective_required,
                    mgmt_handles.command_replay_cache.as_ref(),
                )
                .await
            {
                let resp = ControlResponse::error(status::UNAUTHORIZED, reason);
                send_response(
                    &handle,
                    &interest.name,
                    &resp,
                    mgmt_handles.response_signer().as_deref(),
                )
                .await;
                continue;
            }
        }

        // ControlParameters MUST appear in exactly one location (name
        // component or AppParameters), never both.
        let params_in_app = interest
            .app_parameters()
            .and_then(|app| ControlParameters::decode(app.clone()).ok());
        let resolved = resolve_control_parameters(parsed.params.clone(), params_in_app);
        let params = match resolved {
            Ok(opt) => opt.unwrap_or_default(),
            Err(reason) => {
                tracing::warn!(target: "engine", name = %interest.name, %reason, "nfd-mgmt: rejecting");
                let resp = ControlResponse::error(status::BAD_PARAMS, reason);
                send_response(
                    &handle,
                    &interest.name,
                    &resp,
                    mgmt_handles.response_signer().as_deref(),
                )
                .await;
                continue;
            }
        };

        let ctx = MgmtContext {
            engine: &engine,
            cancel: &cancel,
            source_face,
            face_provisioners: &mgmt_handles.face_provisioners,
            control_surfaces: &mgmt_handles.control_surfaces,
            config: config.as_ref(),
            #[cfg(not(target_arch = "wasm32"))]
            pib: pib.as_deref(),
            security_is_ephemeral: mgmt_handles.security_is_ephemeral,
            log_inspector: mgmt_handles.log_inspector.as_deref(),
            coding_handler: mgmt_handles.coding_handler.as_ref(),
            rate_limit_handler: mgmt_handles.rate_limit_handler.as_ref(),
            compute_handler: mgmt_handles.compute_handler.as_ref(),
            ble_handler: mgmt_handles.ble_handler.as_ref(),
            approval_handler: mgmt_handles.approval_handler.as_ref(),
            trust_context_handler: mgmt_handles.trust_context_handler.as_ref(),
            webtransport_status_handler: mgmt_handles.webtransport_status_handler.as_ref(),
            #[cfg(not(target_arch = "wasm32"))]
            runtime_policy: mgmt_handles.runtime_policy.as_ref(),
            face_events: Some(&face_events),
            route_events: Some(&route_events),
            strategy_events: Some(&strategy_events),
        };

        let resp = router
            .dispatch(parsed.module.as_ref(), parsed.verb.as_ref(), params, &ctx)
            .await;

        match resp {
            MgmtResponse::Control(cr) => {
                send_response(
                    &handle,
                    &interest.name,
                    &cr,
                    mgmt_handles.response_signer().as_deref(),
                )
                .await
            }
            MgmtResponse::Dataset(bytes) => {
                send_dataset(
                    &handle,
                    &interest.name,
                    bytes,
                    mgmt_handles.response_signer().as_deref(),
                )
                .await;
            }
            MgmtResponse::Deferred(pending) => {
                let handle = Arc::clone(&handle);
                let name = Arc::clone(&interest.name);
                let signer = mgmt_handles.command_response_signer.clone();
                let answer = async move {
                    let cr = pending.await;
                    // Signed by the key current when the answer is ready
                    // (an enrollment may have just switched it).
                    let signer = signer.map(|s| s.current());
                    send_response(&handle, &name, &cr, signer.as_deref()).await;
                };
                #[cfg(not(target_arch = "wasm32"))]
                tokio::spawn(answer);
                // No ambient multi-task runtime on wasm: answer in line.
                #[cfg(target_arch = "wasm32")]
                answer.await;
            }
            MgmtResponse::DeferredDataset(pending) => {
                let handle = Arc::clone(&handle);
                let name = Arc::clone(&interest.name);
                let signer = mgmt_handles.command_response_signer.clone();
                let answer = async move {
                    let result = pending.await;
                    let signer = signer.map(|s| s.current());
                    match result {
                        Ok(bytes) => send_dataset(&handle, &name, bytes, signer.as_deref()).await,
                        Err(cr) => send_response(&handle, &name, &cr, signer.as_deref()).await,
                    }
                };
                #[cfg(not(target_arch = "wasm32"))]
                tokio::spawn(answer);
                #[cfg(target_arch = "wasm32")]
                answer.await;
            }
        }
    }

    tracing::info!(target: "engine", "NFD management handler stopped");
}
