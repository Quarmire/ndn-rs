//! `/localhost/nfd/discovery/{status, config}` — runtime-mutable
//! Hello-strategy config (native only).

use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;

use ndn_config::{
    ControlParameters, ControlResponse,
    control_response::status,
    nfd_command::{module, verb},
};
use ndn_discovery::{DiscoveryConfig, HelloStrategyKind, PrefixAnnouncementMode};

use crate::MgmtResponse;
use crate::module::{MgmtContext, MgmtModule};

fn handle_discovery(
    verb_name: &[u8],
    params: ControlParameters,
    discovery_cfg: Option<&Arc<RwLock<DiscoveryConfig>>>,
) -> ControlResponse {
    match verb_name {
        v if v == b"status" => discovery_status(discovery_cfg),
        v if v == verb::CONFIG => discovery_config_set(params, discovery_cfg),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown discovery verb"),
    }
}

fn discovery_status(discovery_cfg: Option<&Arc<RwLock<DiscoveryConfig>>>) -> ControlResponse {
    let Some(cfg_lock) = discovery_cfg else {
        return ControlResponse::error(status::NOT_FOUND, "discovery not enabled");
    };
    let cfg = cfg_lock.read().unwrap();
    let strategy_str = match cfg.hello_strategy {
        HelloStrategyKind::Backoff => "backoff",
        HelloStrategyKind::Reactive => "reactive",
        HelloStrategyKind::Passive => "passive",
    };
    let prefix_ann_str = match cfg.prefix_announcement {
        PrefixAnnouncementMode::Static => "static",
        PrefixAnnouncementMode::InHello => "in-hello",
        PrefixAnnouncementMode::NlsrLsa => "nlsr-lsa",
    };
    let text = format!(
        "discovery: enabled\n\
         hello_strategy: {strategy_str}\n\
         hello_interval_base_ms: {}\n\
         hello_interval_max_ms: {}\n\
         hello_jitter: {:.2}\n\
         liveness_timeout_ms: {}\n\
         liveness_miss_count: {}\n\
         probe_timeout_ms: {}\n\
         prefix_announcement: {prefix_ann_str}\n\
         auto_create_faces: {}\n\
         tick_interval_ms: {}\n",
        cfg.hello_interval_base.as_millis(),
        cfg.hello_interval_max.as_millis(),
        cfg.hello_jitter,
        cfg.liveness_timeout.as_millis(),
        cfg.liveness_miss_count,
        cfg.probe_timeout.as_millis(),
        cfg.auto_create_faces,
        cfg.tick_interval.as_millis(),
    );
    ControlResponse::ok_empty(text)
}

fn discovery_config_set(
    params: ControlParameters,
    discovery_cfg: Option<&Arc<RwLock<DiscoveryConfig>>>,
) -> ControlResponse {
    let Some(cfg_lock) = discovery_cfg else {
        return ControlResponse::error(status::NOT_FOUND, "discovery not enabled");
    };
    let Some(query) = &params.uri else {
        return discovery_status(discovery_cfg);
    };
    {
        let mut cfg = cfg_lock.write().unwrap();
        for pair in query.split('&') {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next().unwrap_or("").trim();
            let val = parts.next().unwrap_or("").trim();
            match key {
                "hello_interval_base_ms" => {
                    if let Ok(ms) = val.parse::<u64>() {
                        cfg.hello_interval_base = Duration::from_millis(ms);
                    }
                }
                "hello_interval_max_ms" => {
                    if let Ok(ms) = val.parse::<u64>() {
                        cfg.hello_interval_max = Duration::from_millis(ms);
                    }
                }
                "hello_jitter" => {
                    if let Ok(v) = val.parse::<f32>() {
                        cfg.hello_jitter = v.clamp(0.0, 0.5);
                    }
                }
                "liveness_timeout_ms" => {
                    if let Ok(ms) = val.parse::<u64>() {
                        cfg.liveness_timeout = Duration::from_millis(ms);
                    }
                }
                "liveness_miss_count" => {
                    if let Ok(v) = val.parse::<u32>() {
                        cfg.liveness_miss_count = v;
                    }
                }
                "probe_timeout_ms" => {
                    if let Ok(ms) = val.parse::<u64>() {
                        cfg.probe_timeout = Duration::from_millis(ms);
                    }
                }
                "auto_create_faces" => {
                    cfg.auto_create_faces = val == "true" || val == "1";
                }
                _ => {}
            }
        }
        tracing::info!(target: "discovery", params = %query, "discovery/config updated");
    }
    discovery_status(discovery_cfg)
}

pub(crate) struct DiscoveryModule;

#[async_trait]
impl MgmtModule for DiscoveryModule {
    fn name(&self) -> &'static [u8] {
        module::DISCOVERY
    }

    async fn dispatch(
        &self,
        verb: &[u8],
        params: ControlParameters,
        ctx: &MgmtContext<'_>,
    ) -> MgmtResponse {
        handle_discovery(verb, params, ctx.discovery_cfg).into()
    }
}
