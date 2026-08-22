//! # Strategy Composition with Filters
//!
//! This example shows how to compose an existing strategy with filters
//! using [`ComposedStrategy`], without modifying the base strategy code.
//!
//! ## What this does
//!
//! Wraps `BestRouteStrategy` with two filters:
//! 1. **`RssiFilter`** — removes faces with RSSI below -60 dBm
//! 2. **`LatencyFilter`** (custom) — removes faces with RTT above a threshold
//!
//! The result is "best-route, but only over faces with acceptable radio
//! signal and latency." The base strategy doesn't know about RSSI or RTT
//! filtering — that's entirely handled by the filter chain.
//!
//! ## Key concepts
//!
//! - [`StrategyFilter`] trait: post-processes forwarding actions
//! - [`ComposedStrategy`]: wraps an inner strategy + filter chain
//! - Filters read [`StrategyContext::signals`] for cross-layer data (RSSI, RTT)
//! - If a filter removes all faces from a `Forward`, the action is dropped
//!   and the strategy falls through to the next action (e.g. `Nack`)

use std::sync::Arc;

use anyhow::Result;
use smallvec::SmallVec;

use ndn::engine::ComposedStrategy;
use ndn::engine::pipeline::ForwardingAction;
use ndn::engine::stages::ErasedStrategy;
use ndn::strategy::{BestRouteStrategy, RssiFilter, StrategyContext, StrategyFilter};
use ndn::{EngineBuilder, EngineConfig, FaceId, Name};

// ─── Custom filter: LatencyFilter ────────────────────────────────────────────

/// Removes faces with observed RTT above a threshold from `Forward` actions.
struct LatencyFilter {
    max_rtt_ms: f64,
}

impl StrategyFilter for LatencyFilter {
    fn name(&self) -> &str {
        "latency-filter"
    }

    fn filter(
        &self,
        ctx: &StrategyContext,
        actions: SmallVec<[ForwardingAction; 2]>,
    ) -> SmallVec<[ForwardingAction; 2]> {
        actions
            .into_iter()
            .filter_map(|action| match action {
                ForwardingAction::Forward(faces) => {
                    let filtered: SmallVec<[FaceId; 4]> = faces
                        .into_iter()
                        .filter(|fid| {
                            // Unknown RTT passes; otherwise keep faces within budget.
                            ctx.signals
                                .link(*fid)
                                .and_then(|l| l.observed_rtt_ms)
                                .is_none_or(|rtt| f64::from(rtt) <= self.max_rtt_ms)
                        })
                        .collect();
                    if filtered.is_empty() {
                        None // all faces exceeded latency threshold
                    } else {
                        Some(ForwardingAction::Forward(filtered))
                    }
                }
                other => Some(other),
            })
            .collect()
    }
}

// ─── Compose and register ────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // Build the composed strategy:
    //   BestRouteStrategy → RssiFilter(-60 dBm) → LatencyFilter(100 ms)
    let inner: Arc<dyn ErasedStrategy> = Arc::new(BestRouteStrategy::new());
    let composed = ComposedStrategy::new(
        // Strategy name (used for per-prefix strategy table lookups)
        Name::from_str("/localhost/nfd/strategy/best-route-filtered")?,
        inner,
        vec![
            Arc::new(RssiFilter::new(-60)), // drop faces below -60 dBm
            Arc::new(LatencyFilter { max_rtt_ms: 100.0 }), // drop faces above 100 ms RTT
        ],
    );

    tracing::info!(
        strategy = "/localhost/nfd/strategy/best-route-filtered",
        "Composed strategy: BestRoute + RssiFilter + LatencyFilter"
    );

    // Register with the engine.
    let (_engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .strategy(composed) // <-- composed strategy as default
        .build()
        .await?;

    tracing::info!("Engine started with composed strategy");

    // The composed strategy will:
    // 1. Ask BestRouteStrategy for a forwarding decision
    // 2. Pass the result through RssiFilter (removes low-signal faces)
    // 3. Pass the result through LatencyFilter (removes high-latency faces)
    // 4. If all faces are filtered out, fall through to Nack
    //
    // Cross-layer data (RSSI, RTT) is pushed by signal sources registered
    // via EngineBuilder::signal_source() and read through ctx.signals.
    // See `ndn-signal-sources` and docs/signals.md.

    shutdown.shutdown().await;
    Ok(())
}

use std::str::FromStr;
