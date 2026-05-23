//! `/localhost/nfd/reflexive/{enable,disable,config,flush,info}` — reflexive
//! forwarding control (ndn-rs extension, not an NFD module).
//!
//! Verbs:
//! - `enable` / `disable` — toggle installing new reverse routes. `disable` is a
//!   graceful drain: existing routes keep being served until they expire.
//! - `config` — set `Capacity` (per-face route cap) and/or `ExpirationPeriod`
//!   (route-lifetime ceiling, ms); echoes the current settings.
//! - `flush` — immediately drop all reverse routes (breaks in-flight handshakes).
//! - `info` — status text (settings + live routes + counters).
//!
//! Being an ndn-rs-only module, every verb requires a signed command Interest
//! (the dispatcher enforces this for non-NFD-canonical modules).

use std::time::Duration;

use async_trait::async_trait;
use ndn_config::{ControlParameters, ControlResponse, control_response::status};
use ndn_engine::ForwarderEngine;

use crate::MgmtResponse;
use crate::module::{MgmtContext, MgmtModule};

fn reflexive_config(params: ControlParameters, engine: &ForwarderEngine) -> ControlResponse {
    let table = engine.reflexive();
    if let Some(cap) = params.capacity {
        table.set_max_per_face(cap as usize);
    }
    if let Some(ms) = params.expiration_period {
        table.set_max_lifetime(Duration::from_millis(ms));
    }
    let s = table.status();
    let echo = ControlParameters {
        capacity: Some(s.max_per_face as u64),
        expiration_period: Some(s.max_lifetime_ms),
        flags: Some(u64::from(s.enabled)),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn reflexive_info(engine: &ForwarderEngine) -> ControlResponse {
    let s = engine.reflexive().status();
    let text = format!(
        "enabled={} max_per_face={} max_lifetime_ms={} live={} installs={} \
         refused={} expired={} lookup_hits={}",
        s.enabled,
        s.max_per_face,
        s.max_lifetime_ms,
        s.live_routes,
        s.installs,
        s.refused,
        s.expired,
        s.lookup_hits,
    );
    ControlResponse::ok_empty(text)
}

pub(crate) struct ReflexiveModule;

#[async_trait]
impl MgmtModule for ReflexiveModule {
    fn name(&self) -> &'static [u8] {
        b"reflexive"
    }

    async fn dispatch(
        &self,
        verb: &[u8],
        params: ControlParameters,
        ctx: &MgmtContext<'_>,
    ) -> MgmtResponse {
        let engine = ctx.engine;
        let resp = match verb {
            b"enable" => {
                engine.reflexive().set_enabled(true);
                tracing::info!(target: "mgmt.reflexive", "reflexive forwarding enabled");
                ControlResponse::ok_empty("reflexive forwarding enabled")
            }
            b"disable" => {
                engine.reflexive().set_enabled(false);
                tracing::info!(target: "mgmt.reflexive", "reflexive forwarding disabled (graceful drain)");
                ControlResponse::ok_empty("reflexive forwarding disabled (graceful drain)")
            }
            b"flush" => {
                let n = engine.reflexive().flush();
                tracing::info!(target: "mgmt.reflexive", routes = n, "reflexive routes flushed");
                ControlResponse::ok(
                    "OK",
                    ControlParameters {
                        count: Some(n as u64),
                        ..Default::default()
                    },
                )
            }
            b"config" => reflexive_config(params, engine),
            b"info" => reflexive_info(engine),
            _ => ControlResponse::error(status::NOT_FOUND, "unknown reflexive verb"),
        };
        resp.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_engine::{EngineBuilder, EngineConfig};
    use tokio_util::sync::CancellationToken;

    fn ctx<'a>(
        engine: &'a ForwarderEngine,
        cancel: &'a CancellationToken,
        config: &'a ndn_config::ForwarderConfig,
    ) -> MgmtContext<'a> {
        MgmtContext {
            engine,
            cancel,
            source_face: None,
            config,
            #[cfg(not(target_arch = "wasm32"))]
            discovery_sd: None,
            #[cfg(not(target_arch = "wasm32"))]
            discovery_claimed: &[],
            #[cfg(not(target_arch = "wasm32"))]
            pib: None,
            #[cfg(not(target_arch = "wasm32"))]
            discovery_cfg: None,
            security_is_ephemeral: false,
            log_inspector: None,
            coding_handler: None,
            rate_limit_handler: None,
            compute_handler: None,
            webtransport_status_handler: None,
            ble_handler: None,
            approval_handler: None,
            #[cfg(not(target_arch = "wasm32"))]
            runtime_policy: None,
            face_events: None,
            route_events: None,
            strategy_events: None,
        }
    }

    #[tokio::test]
    async fn enable_disable_flush_info_round_trip() {
        let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
            .build()
            .await
            .unwrap();
        let cancel = CancellationToken::new();
        let config = ndn_config::ForwarderConfig::default();
        let m = ReflexiveModule;

        // disable → table reports disabled and refuses new routes.
        m.dispatch(b"disable", ControlParameters::default(), &ctx(&engine, &cancel, &config))
            .await;
        assert!(!engine.reflexive().is_enabled());

        // enable → back on.
        m.dispatch(b"enable", ControlParameters::default(), &ctx(&engine, &cancel, &config))
            .await;
        assert!(engine.reflexive().is_enabled());

        // config → caps applied and echoed.
        let params = ControlParameters {
            capacity: Some(7),
            expiration_period: Some(3000),
            ..Default::default()
        };
        m.dispatch(b"config", params, &ctx(&engine, &cancel, &config))
            .await;
        let s = engine.reflexive().status();
        assert_eq!(s.max_per_face, 7);
        assert_eq!(s.max_lifetime_ms, 3000);

        // flush → install a route, then flush it away.
        engine
            .reflexive()
            .install(&"/rfx/q".parse().unwrap(), ndn_transport::FaceId(1), Duration::from_secs(4));
        assert!(!engine.reflexive().is_empty());
        m.dispatch(b"flush", ControlParameters::default(), &ctx(&engine, &cancel, &config))
            .await;
        assert!(engine.reflexive().is_empty());

        // info → returns a Control response (text), not an error.
        let resp = m
            .dispatch(b"info", ControlParameters::default(), &ctx(&engine, &cancel, &config))
            .await;
        assert!(matches!(resp, MgmtResponse::Control(_)));

        // unknown verb → NOT_FOUND.
        let resp = m
            .dispatch(b"bogus", ControlParameters::default(), &ctx(&engine, &cancel, &config))
            .await;
        match resp {
            MgmtResponse::Control(cr) => assert_eq!(cr.status_code, status::NOT_FOUND),
            _ => panic!("expected control response"),
        }

        shutdown.shutdown().await;
    }
}
