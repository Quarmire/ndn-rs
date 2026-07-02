//! `/localhost/nfd/strategy-choice/{set, unset, list}` — strategy
//! table management. Publishes `StrategyEvent`s on
//! `/localhost/nfd/strategy-choice/notifications`.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;

use ndn_engine::{ForwarderEngine, stages::ErasedStrategy};
use ndn_mgmt_wire::{
    ControlParameters, ControlResponse,
    control_response::status,
    nfd_command::{module, verb},
    nfd_dataset,
};
use ndn_packet::Name;

use crate::MgmtResponse;
use crate::module::{MgmtContext, MgmtModule};
use crate::notification::NotificationEvent;

/// Strategy set / unset event.
#[derive(Debug, Clone)]
pub struct StrategyEvent {
    pub kind: StrategyEventKind,
    pub prefix: Name,
    pub strategy: Option<Name>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StrategyEventKind {
    Set = 1,
    Unset = 2,
}

impl NotificationEvent for StrategyEvent {
    fn encode(&self) -> Bytes {
        let kind = match self.kind {
            StrategyEventKind::Set => "set",
            StrategyEventKind::Unset => "unset",
        };
        let strategy = self
            .strategy
            .as_ref()
            .map(|n| n.to_string())
            .unwrap_or_default();
        Bytes::from(format!(
            "{kind} prefix={} strategy={}",
            self.prefix, strategy
        ))
    }
}

fn handle_strategy(
    verb_name: &[u8],
    params: ControlParameters,
    engine: &ForwarderEngine,
) -> MgmtResponse {
    match verb_name {
        v if v == verb::SET => strategy_set(params, engine).into(),
        v if v == verb::UNSET => strategy_unset(params, engine).into(),
        v if v == verb::LIST => MgmtResponse::Dataset(strategy_list_dataset(engine)),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown strategy-choice verb").into(),
    }
}

/// Instantiate a strategy by its NFD-style name via
/// [`ndn_strategy::registry`]. Built-ins register at static-init time;
/// external crates plug in via `ndn_strategy::register_strategy!`.
fn create_strategy_by_name(name: &Name) -> Option<Arc<dyn ErasedStrategy>> {
    let comps = name.components();
    let (short_name, version) = if comps.len() >= 4
        && comps[0].value.as_ref() == b"localhost"
        && comps[1].value.as_ref() == b"nfd"
        && comps[2].value.as_ref() == b"strategy"
    {
        let short = comps[3].value.as_ref();
        let v = comps.get(4).and_then(|c| {
            if c.typ == ndn_packet::tlv_type::VERSION {
                let mut n: u64 = 0;
                for b in c.value.as_ref() {
                    n = (n << 8) | u64::from(*b);
                }
                Some(n)
            } else {
                None
            }
        });
        (short, v)
    } else if comps.len() == 1 {
        (comps[0].value.as_ref(), None)
    } else {
        return None;
    };

    match version {
        Some(v) => ndn_strategy::registry::create_by_name_version(short_name, v),
        None => ndn_strategy::registry::create_by_name(short_name),
    }
}

fn strategy_set(params: ControlParameters, engine: &ForwarderEngine) -> ControlResponse {
    let prefix = match &params.name {
        Some(n) => n.clone(),
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };

    let strategy_name = match &params.strategy {
        Some(n) => n.clone(),
        None => return ControlResponse::error(status::BAD_PARAMS, "Strategy is required"),
    };

    let strategy = match create_strategy_by_name(&strategy_name) {
        Some(s) => s,
        None => {
            return ControlResponse::error(
                status::NOT_FOUND,
                format!("unknown strategy: {}", strategy_name),
            );
        }
    };

    engine.strategy_table().insert(&prefix, strategy);

    tracing::info!(
        target: "mgmt.strategy",
        prefix = %prefix,
        strategy = %strategy_name,
        "strategy-choice/set"
    );

    let echo = ControlParameters {
        name: Some(prefix),
        strategy: Some(strategy_name),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn strategy_unset(params: ControlParameters, engine: &ForwarderEngine) -> ControlResponse {
    let prefix = match &params.name {
        Some(n) => n.clone(),
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };

    if prefix.is_empty() {
        return ControlResponse::error(status::BAD_PARAMS, "cannot unset strategy at root prefix");
    }

    engine.strategy_table().remove(&prefix);

    tracing::info!(target: "mgmt.strategy", prefix = %prefix, "strategy-choice/unset");

    let echo = ControlParameters {
        name: Some(prefix),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn strategy_list_dataset(engine: &ForwarderEngine) -> bytes::Bytes {
    let entries = engine.strategy_table().dump();
    let mut buf = bytes::BytesMut::new();
    for (prefix, strategy) in &entries {
        let sc = nfd_dataset::StrategyChoice {
            name: prefix.clone(),
            strategy: strategy.name().clone(),
        };
        buf.extend_from_slice(&sc.encode());
    }
    buf.freeze()
}

pub(crate) struct StrategyModule;

#[async_trait]
impl MgmtModule for StrategyModule {
    fn name(&self) -> &'static [u8] {
        module::STRATEGY
    }

    async fn dispatch(
        &self,
        verb: &[u8],
        params: ControlParameters,
        ctx: &MgmtContext<'_>,
    ) -> MgmtResponse {
        let resp = handle_strategy(verb, params, ctx.engine);
        if let (Some(stream), MgmtResponse::Control(cr)) = (ctx.strategy_events, &resp)
            && cr.status_code == status::OK
            && let Some(body) = cr.body.as_ref()
            && let Some(prefix) = body.name.clone()
        {
            let kind = if verb == verb::SET {
                Some(StrategyEventKind::Set)
            } else if verb == verb::UNSET {
                Some(StrategyEventKind::Unset)
            } else {
                None
            };
            if let Some(kind) = kind {
                stream.publish(StrategyEvent {
                    kind,
                    prefix,
                    strategy: body.strategy.clone(),
                });
            }
        }
        resp
    }
}
