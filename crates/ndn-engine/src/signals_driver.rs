//! Background driver for cross-layer [`SignalSource`]s.
//!
//! Sources are push-based: this task polls each registered source on a cadence
//! and lets it push the latest readings into the engine's [`SignalsTable`].
//! Strategies then read cached values via `StrategyContext::signals` — the
//! forwarding hot path never blocks on a driver. Registered via
//! [`crate::EngineBuilder::signal_source`].

use std::sync::Arc;
use std::time::Duration;

use ndn_runtime::Runtime;
use ndn_signals_core::SignalSource;
use ndn_strategy::SignalsTable;
use ndn_transport::FaceId;
use tokio_util::sync::CancellationToken;

/// Poll every registered source at the smallest requested interval (clamped to
/// a sane floor) until cancelled. `now_ms` is monotonic from task start.
#[tracing::instrument(level = "info", target = "engine", name = "signal_sources", skip_all)]
pub async fn run_signal_sources(
    mut sources: Vec<Box<dyn SignalSource<FaceId>>>,
    store: Arc<SignalsTable>,
    cancel: CancellationToken,
    runtime: Arc<dyn Runtime>,
) {
    let tick = sources
        .iter()
        .map(|s| s.interval())
        .min()
        .unwrap_or(Duration::from_secs(1))
        .max(Duration::from_millis(50));

    let start = runtime.now();
    loop {
        let sleep = runtime.sleep(tick);
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            _ = sleep => {
                let now_ms = runtime.now().duration_since(start).as_millis() as u32;
                for source in sources.iter_mut() {
                    source.poll(store.as_ref(), now_ms);
                }
            }
        }
    }
}
