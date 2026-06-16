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
use ndn_mgmt_wire::ControlParameters;
use ndn_engine::ForwarderEngine;
#[cfg(not(target_arch = "wasm32"))]
use ndn_packet::Name;
use ndn_transport::FaceId;
use tokio_util::sync::CancellationToken;

#[cfg(not(target_arch = "wasm32"))]
use ndn_discovery::{DiscoveryConfig, ServiceDiscoveryProtocol};
#[cfg(not(target_arch = "wasm32"))]
use ndn_security::FilePib;

#[cfg(not(target_arch = "wasm32"))]
use crate::MgmtAccessPolicy;
use crate::{
    ApprovalMgmtBackend, BleMgmtBackend, CodingHandler, ComputeMgmtBackend, FaceEvent,
    LogInspector, MgmtResponse, NotificationStream, RateLimitMgmtBackend, RouteEvent,
    StrategyEvent, WtCertStatusBackend,
};

/// Per-Interest dispatch context. Threaded by the router into each
/// [`MgmtModule::dispatch`] call; modules pull the fields they need.
pub struct MgmtContext<'a> {
    pub engine: &'a ForwarderEngine,
    pub cancel: &'a CancellationToken,
    pub source_face: Option<FaceId>,
    pub config: &'a ndn_config::ForwarderConfig,
    #[cfg(not(target_arch = "wasm32"))]
    pub discovery_sd: Option<&'a ServiceDiscoveryProtocol>,
    #[cfg(not(target_arch = "wasm32"))]
    pub discovery_claimed: &'a [Name],
    #[cfg(not(target_arch = "wasm32"))]
    pub pib: Option<&'a FilePib>,
    #[cfg(not(target_arch = "wasm32"))]
    pub discovery_cfg: Option<&'a Arc<RwLock<DiscoveryConfig>>>,
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
