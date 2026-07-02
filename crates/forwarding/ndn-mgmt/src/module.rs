//! Module-trait surface for the mgmt dispatcher.
//!
//! Each NFD-compatible management module is a [`MgmtModule`] registered
//! in the [`MgmtRouter`], dispatched by the second name component
//! (`b"rib"`, `b"faces"`, …) with a borrowed [`MgmtContext`] carrying
//! the engine, optional discovery/PIB handles, and the source-face id.

use std::collections::HashMap;
use std::sync::Arc;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::RwLock;

use async_trait::async_trait;
use ndn_engine::ForwarderEngine;
use ndn_mgmt_wire::ControlParameters;
use ndn_transport::FaceId;
use tokio_util::sync::CancellationToken;

#[cfg(not(target_arch = "wasm32"))]
use ndn_security::FilePib;

#[cfg(not(target_arch = "wasm32"))]
use crate::MgmtAccessPolicy;
use crate::{
    ApprovalMgmtBackend, BleMgmtBackend, CodingHandler, ComputeMgmtBackend, FaceEvent,
    LogInspector, MgmtResponse, NotificationStream, RateLimitMgmtBackend, RouteEvent,
    StrategyEvent, WtCertStatusBackend,
};

/// The forwarder-config read surface the management handlers depend on.
///
/// `ndn-mgmt` is the spec-layer NFD management protocol; the forwarder TOML
/// schema (`ndn_config::ForwarderConfig`) is an extension. Threading the
/// concrete config through the handlers made the spec crate depend on the
/// extension. This trait inverts that: the handlers read only what they need
/// through `&dyn MgmtConfig`, and `ForwarderConfig` implements it downstream in
/// `ndn-config`. The forwarder hands the engine an `Arc<dyn MgmtConfig>` when it
/// mounts management.
pub trait MgmtConfig: Send + Sync {
    /// Serialize the running config to **redacted** TOML — backs
    /// `/localhost/nfd/config/get`. Implementations MUST replace secret-bearing
    /// fields (passwords, CA invite tokens, challenge PINs, SMTP/TURN
    /// credentials, ACME API tokens, …) with a placeholder (audit CFG-1): the
    /// response Data can be logged or cached, and those secrets authorise
    /// issuance/impersonation for *other* parties, so a read verb must not
    /// disclose them even to an authenticated operator.
    fn redacted_toml(&self) -> Result<String, String>;

    /// `[security] identity` — the configured engine identity name, if any.
    fn security_identity(&self) -> Option<&str>;
    /// `[security] pib_path` — the engine identity PIB path, if configured.
    fn pib_path(&self) -> Option<&str>;

    /// `[security.mgmt] require_signed_commands`.
    fn require_signed_commands(&self) -> bool;
    /// `[security.mgmt] trust_anchor_pib` — the operator command anchor PIB path.
    fn mgmt_trust_anchor_pib(&self) -> Option<&str>;
    /// `[security.mgmt] localhop_trust_anchor_pib` — the localhop registration anchor PIB path.
    fn localhop_trust_anchor_pib(&self) -> Option<&str>;

    /// NDNCERT CA posture for `security/ca-info`; `None` when no CA is configured.
    fn ca_info(&self) -> Option<CaInfo<'_>>;
}

/// NDNCERT CA configuration surfaced by `security/ca-info`. Borrows from the
/// underlying [`MgmtConfig`].
pub struct CaInfo<'a> {
    pub prefix: &'a str,
    pub info: &'a str,
    pub max_validity_days: u32,
    pub challenges: &'a [String],
}

/// Minimal [`MgmtConfig`] for the in-crate unit tests. The production
/// implementor is `ndn_config::ForwarderConfig` (downstream, behind its `mgmt`
/// feature), which the *integration* tests in `tests/` use. Unit tests can't:
/// `ndn-config` is only a dev-dependency here and depends back on this crate, so
/// its impl is for the lib build's trait, not the test-cfg build's — a stub
/// avoids that mismatch.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct TestMgmtConfig {
    pub require_signed_commands: bool,
    pub mgmt_trust_anchor_pib: Option<String>,
    pub localhop_trust_anchor_pib: Option<String>,
    pub identity: Option<String>,
    pub pib_path: Option<String>,
}

#[cfg(test)]
impl MgmtConfig for TestMgmtConfig {
    fn redacted_toml(&self) -> Result<String, String> {
        Ok(String::new())
    }
    fn security_identity(&self) -> Option<&str> {
        self.identity.as_deref()
    }
    fn pib_path(&self) -> Option<&str> {
        self.pib_path.as_deref()
    }
    fn require_signed_commands(&self) -> bool {
        self.require_signed_commands
    }
    fn mgmt_trust_anchor_pib(&self) -> Option<&str> {
        self.mgmt_trust_anchor_pib.as_deref()
    }
    fn localhop_trust_anchor_pib(&self) -> Option<&str> {
        self.localhop_trust_anchor_pib.as_deref()
    }
    fn ca_info(&self) -> Option<CaInfo<'_>> {
        None
    }
}

/// Per-Interest dispatch context. Threaded by the router into each
/// [`MgmtModule::dispatch`] call; modules pull the fields they need.
pub struct MgmtContext<'a> {
    pub engine: &'a ForwarderEngine,
    pub cancel: &'a CancellationToken,
    pub source_face: Option<FaceId>,
    /// Extension-transport face builders the forwarder registered (quic://,
    /// wts://, …). Empty in hosts that mount only the standard transports.
    pub face_provisioners: &'a [Arc<dyn crate::FaceProvisioner>],
    /// Out-of-core subsystem introspection/control surfaces (served at `ext/…`).
    pub control_surfaces: &'a [Arc<dyn ndn_mgmt_wire::ControlSurface>],
    pub config: &'a dyn MgmtConfig,
    #[cfg(not(target_arch = "wasm32"))]
    pub pib: Option<&'a FilePib>,
    pub security_is_ephemeral: bool,
    pub log_inspector: Option<&'a LogInspector>,
    pub coding_handler: Option<&'a Arc<dyn CodingHandler>>,
    pub rate_limit_handler: Option<&'a Arc<dyn RateLimitMgmtBackend>>,
    pub compute_handler: Option<&'a Arc<dyn ComputeMgmtBackend>>,
    pub ble_handler: Option<&'a Arc<dyn BleMgmtBackend>>,
    pub approval_handler: Option<&'a Arc<dyn ApprovalMgmtBackend>>,
    pub webtransport_status_handler: Option<&'a Arc<dyn WtCertStatusBackend>>,
    #[cfg(not(target_arch = "wasm32"))]
    pub runtime_policy: Option<&'a Arc<RwLock<MgmtAccessPolicy>>>,
    /// Notification streams mounted by [`crate::mount_management`].
    /// `None` in tests that bypass `mount_management`.
    pub face_events: Option<&'a Arc<NotificationStream<FaceEvent>>>,
    pub route_events: Option<&'a Arc<NotificationStream<RouteEvent>>>,
    pub strategy_events: Option<&'a Arc<NotificationStream<StrategyEvent>>>,
}

/// A single NFD-compatible management module. Built-in modules are
/// stateless unit structs; stateful modules carry state on the struct
/// (the router holds them as `Arc<dyn MgmtModule>`).
#[async_trait]
pub trait MgmtModule: Send + Sync + 'static {
    /// Module name as it appears on the wire, e.g. `b"rib"`.
    fn name(&self) -> &'static [u8];

    /// Dispatch a verb. The router has already validated the command
    /// name and authorisation; the module produces the response payload.
    async fn dispatch(
        &self,
        verb: &[u8],
        params: ControlParameters,
        ctx: &MgmtContext<'_>,
    ) -> MgmtResponse;
}

/// Registered modules keyed by exact byte-string name. Unknown module
/// yields `NOT_FOUND`.
#[derive(Default)]
pub struct MgmtRouter {
    modules: HashMap<&'static [u8], Arc<dyn MgmtModule>>,
}

impl MgmtRouter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, m: Arc<dyn MgmtModule>) {
        self.modules.insert(m.name(), m);
    }

    pub async fn dispatch(
        &self,
        module: &[u8],
        verb: &[u8],
        params: ControlParameters,
        ctx: &MgmtContext<'_>,
    ) -> MgmtResponse {
        match self.modules.get(module) {
            Some(m) => m.dispatch(verb, params, ctx).await,
            None => ndn_mgmt_wire::ControlResponse::error(
                ndn_mgmt_wire::control_response::status::NOT_FOUND,
                "unknown module",
            )
            .into(),
        }
    }
}
