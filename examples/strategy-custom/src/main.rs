//! # Writing a Custom Strategy
//!
//! This example demonstrates how to implement a custom forwarding strategy
//! from scratch and register it with the engine.
//!
//! ## What this strategy does
//!
//! `RandomStrategy` picks a random nexthop from the FIB entry for each
//! Interest — unlike `BestRouteStrategy` which always picks the lowest-cost
//! nexthop. This is useful for load balancing across equal-cost paths.
//!
//! ## Key concepts
//!
//! - Implement the [`Strategy`] trait from `ndn-strategy`
//! - Override `decide()` for synchronous fast-path decisions (avoids async overhead)
//! - Register with `EngineBuilder::strategy()` before building
//! - The strategy receives an immutable [`StrategyContext`] and returns
//!   [`ForwardingAction`] values — it cannot mutate forwarding tables directly

use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use smallvec::{SmallVec, smallvec};

use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_packet::Name;
use ndn_pipeline::{ForwardingAction, NackReason};
use ndn_strategy::{Strategy, StrategyContext};

// ─── Custom strategy implementation ──────────────────────────────────────────

/// A strategy that picks a pseudo-random nexthop from the FIB entry.
///
/// Uses a simple counter-based selection (round-robin) rather than true
/// randomness to avoid pulling in a PRNG dependency.
struct RandomStrategy {
    name: Name,
    counter: AtomicU64,
}

impl RandomStrategy {
    fn new() -> Self {
        Self {
            name: Name::from_components(vec![
                ndn_packet::NameComponent::generic(bytes::Bytes::from_static(b"localhost")),
                ndn_packet::NameComponent::generic(bytes::Bytes::from_static(b"nfd")),
                ndn_packet::NameComponent::generic(bytes::Bytes::from_static(b"strategy")),
                ndn_packet::NameComponent::generic(bytes::Bytes::from_static(b"random")),
            ]),
            counter: AtomicU64::new(0),
        }
    }
}

impl Strategy for RandomStrategy {
    fn name(&self) -> &Name {
        &self.name
    }

    // The synchronous fast path. Returning `Some(actions)` here avoids the
    // overhead of boxing an async future. Most strategies can be fully
    // synchronous — only use the async path if you need to await something
    // (e.g., a remote lookup or timer).
    fn decide(&self, ctx: &StrategyContext) -> Option<SmallVec<[ForwardingAction; 2]>> {
        let Some(fib) = ctx.fib_entry else {
            return Some(smallvec![ForwardingAction::Nack(NackReason::NoRoute)]);
        };

        // Exclude the face the Interest arrived on (split horizon).
        let nexthops = fib.nexthops_excluding(ctx.in_face);
        if nexthops.is_empty() {
            return Some(smallvec![ForwardingAction::Nack(NackReason::NoRoute)]);
        }

        // Pick a nexthop using round-robin.
        let idx = self.counter.fetch_add(1, Ordering::Relaxed) as usize % nexthops.len();
        let chosen = nexthops[idx].face_id;

        tracing::info!(
            name = %ctx.name,
            in_face = %ctx.in_face,
            chosen_face = %chosen,
            nexthop_count = nexthops.len(),
            "RandomStrategy: forwarding"
        );

        Some(smallvec![ForwardingAction::Forward(smallvec![chosen])])
    }

    // Required by the trait but unreachable when `decide()` always returns Some.
    async fn after_receive_interest(
        &self,
        _ctx: &StrategyContext<'_>,
    ) -> SmallVec<[ForwardingAction; 2]> {
        unreachable!("decide() always returns Some")
    }

    async fn after_receive_data(
        &self,
        _ctx: &StrategyContext<'_>,
    ) -> SmallVec<[ForwardingAction; 2]> {
        SmallVec::new()
    }
}

// ─── Wire it up ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // Create an in-process engine with our custom strategy.
    let (_engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .strategy(RandomStrategy::new()) // <-- register custom strategy
        .build()
        .await?;

    tracing::info!("Engine started with RandomStrategy");

    // In a real application you would:
    // 1. Add faces (UDP, TCP, AppFace, etc.)
    // 2. Add FIB routes pointing to those faces
    // 3. Run the engine until shutdown
    //
    // For this example, we just demonstrate the wiring.
    // See the `ndn-app` crate docs for Consumer/Producer examples.

    tracing::info!("Engine ready — no faces registered (demo only)");

    shutdown.shutdown().await;
    tracing::info!("Engine shut down cleanly");
    Ok(())
}
