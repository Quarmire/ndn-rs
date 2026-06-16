//! Witness for the `extra_modules` seam: a host-supplied [`MgmtModule`] passed
//! through `MgmtHandles::extra_modules` (e.g. `ndn_pipes::PipesModule`) is
//! registered by `build_mgmt_router` alongside the built-ins and routes to.

use std::sync::Arc;

use async_trait::async_trait;
use ndn_config::{ControlParameters, ControlResponse, control_response::status};
use ndn_engine::{EngineBuilder, EngineConfig, ForwarderEngine};
use ndn_mgmt::MgmtResponse;
use ndn_mgmt::build_mgmt_router;
use ndn_mgmt::module::{MgmtContext, MgmtModule};
use tokio_util::sync::CancellationToken;

/// A trivial extension module: answers `ping` with `pong`.
struct StubModule;

#[async_trait]
impl MgmtModule for StubModule {
    fn name(&self) -> &'static [u8] {
        b"teststub"
    }
    async fn dispatch(
        &self,
        verb: &[u8],
        _params: ControlParameters,
        _ctx: &MgmtContext<'_>,
    ) -> MgmtResponse {
        match verb {
            b"ping" => ControlResponse::ok_empty("pong").into(),
            _ => ControlResponse::error(status::NOT_FOUND, "unknown stub verb").into(),
        }
    }
}

fn ctx<'a>(
    engine: &'a ForwarderEngine,
    cancel: &'a CancellationToken,
    config: &'a ndn_config::ForwarderConfig,
) -> MgmtContext<'a> {
    MgmtContext {
        engine,
        cancel,
        source_face: None,
        face_provisioners: &[],
        control_surfaces: &[],
        config,
        pib: None,
        security_is_ephemeral: false,
        log_inspector: None,
        coding_handler: None,
        rate_limit_handler: None,
        compute_handler: None,
        webtransport_status_handler: None,
        ble_handler: None,
        approval_handler: None,
        runtime_policy: None,
        face_events: None,
        route_events: None,
        strategy_events: None,
    }
}

#[tokio::test]
async fn extra_module_is_registered_and_routes() {
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .build()
        .await
        .unwrap();
    let cancel = CancellationToken::new();
    let config = ndn_config::ForwarderConfig::default();

    let extra: Vec<Arc<dyn MgmtModule>> = vec![Arc::new(StubModule)];
    let router = build_mgmt_router(&extra);

    // The extra module routes...
    let resp = router
        .dispatch(b"teststub", b"ping", ControlParameters::default(), &ctx(&engine, &cancel, &config))
        .await;
    match resp {
        MgmtResponse::Control(cr) => assert_eq!(cr.status_text, "pong", "extra module answered"),
        _ => panic!("expected a Control response"),
    }

    // ...and a built-in still routes (extras are additive, not a replacement).
    // `*/list` verbs answer with a Dataset, not a Control response.
    let faces = router
        .dispatch(b"faces", b"list", ControlParameters::default(), &ctx(&engine, &cancel, &config))
        .await;
    assert!(matches!(faces, MgmtResponse::Dataset(_)), "built-in faces/list still routes");

    // An unregistered module is NOT_FOUND.
    let missing = router
        .dispatch(b"nope", b"x", ControlParameters::default(), &ctx(&engine, &cancel, &config))
        .await;
    match missing {
        MgmtResponse::Control(cr) => assert_eq!(cr.status_code, status::NOT_FOUND),
        _ => panic!("expected a Control response"),
    }

    cancel.cancel();
    shutdown.shutdown().await;
}
