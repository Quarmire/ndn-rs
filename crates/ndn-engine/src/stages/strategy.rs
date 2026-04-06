use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use smallvec::SmallVec;
use tracing::trace;

use crate::Fib;
use crate::enricher::ContextEnricher;
use ndn_discovery::scope::is_link_local;
use ndn_packet::Name;
use ndn_pipeline::{
    Action, AnyMap, DecodedPacket, DropReason, ForwardingAction, NackReason, PacketContext,
};
use ndn_store::{Pit, StrategyTable};
use ndn_strategy::{MeasurementsTable, Strategy, StrategyContext};
use ndn_transport::face::FaceScope;

/// Object-safe version of `Strategy` that boxes its futures.
pub trait ErasedStrategy: Send + Sync + 'static {
    /// Canonical name identifying this strategy (e.g. `/localhost/nfd/strategy/best-route`).
    fn name(&self) -> &Name;

    /// Synchronous fast path — avoids the `Box::pin` heap allocation.
    /// Returns `None` to fall through to the async path.
    fn decide_sync(&self, ctx: &StrategyContext<'_>) -> Option<SmallVec<[ForwardingAction; 2]>>;

    /// Async path for Interest forwarding decisions (boxed future).
    fn after_receive_interest_erased<'a>(
        &'a self,
        ctx: &'a StrategyContext<'a>,
    ) -> Pin<Box<dyn Future<Output = SmallVec<[ForwardingAction; 2]>> + Send + 'a>>;

    /// Handle an incoming Nack and decide whether to retry or propagate.
    fn on_nack_erased<'a>(
        &'a self,
        ctx: &'a StrategyContext<'a>,
        reason: NackReason,
    ) -> Pin<Box<dyn Future<Output = ForwardingAction> + Send + 'a>>;
}

impl<S: Strategy> ErasedStrategy for S {
    fn name(&self) -> &Name {
        Strategy::name(self)
    }

    fn decide_sync(&self, ctx: &StrategyContext<'_>) -> Option<SmallVec<[ForwardingAction; 2]>> {
        self.decide(ctx)
    }

    fn after_receive_interest_erased<'a>(
        &'a self,
        ctx: &'a StrategyContext<'a>,
    ) -> Pin<Box<dyn Future<Output = SmallVec<[ForwardingAction; 2]>> + Send + 'a>> {
        Box::pin(self.after_receive_interest(ctx))
    }

    fn on_nack_erased<'a>(
        &'a self,
        ctx: &'a StrategyContext<'a>,
        reason: NackReason,
    ) -> Pin<Box<dyn Future<Output = ForwardingAction> + Send + 'a>> {
        let strategy_reason = match reason {
            NackReason::NoRoute => ndn_pipeline::NackReason::NoRoute,
            NackReason::Duplicate => ndn_pipeline::NackReason::Duplicate,
            NackReason::Congestion => ndn_pipeline::NackReason::Congestion,
            NackReason::NotYet => ndn_pipeline::NackReason::NotYet,
        };
        Box::pin(self.on_nack(ctx, strategy_reason))
    }
}

/// Calls the strategy to produce a forwarding decision for Interests.
///
/// Performs LPM on the strategy table to find the per-prefix strategy.
/// Falls back to `default_strategy` if no entry matches (should not happen
/// if root is populated).
pub struct StrategyStage {
    pub strategy_table: Arc<StrategyTable<dyn ErasedStrategy>>,
    pub default_strategy: Arc<dyn ErasedStrategy>,
    pub fib: Arc<Fib>,
    pub measurements: Arc<MeasurementsTable>,
    pub pit: Arc<Pit>,
    pub face_table: Arc<ndn_transport::FaceTable>,
    /// Cross-layer enrichers run before the strategy to populate `StrategyContext::extensions`.
    pub enrichers: Vec<Arc<dyn ContextEnricher>>,
}

impl StrategyStage {
    /// Run the per-prefix strategy for an Interest and return a pipeline action.
    pub async fn process(&self, mut ctx: PacketContext) -> Action {
        match &ctx.packet {
            DecodedPacket::Interest(_) => {}
            // Strategy only runs for Interests in the forward path.
            _ => return Action::Continue(ctx),
        };

        let name = match &ctx.name {
            Some(n) => n.clone(),
            None => return Action::Drop(DropReason::MalformedPacket),
        };

        let fib_entry_arc = self.fib.lpm(&name);
        let fib_entry_ref = fib_entry_arc.as_deref();

        if let Some(ref e) = fib_entry_ref {
            trace!(face=%ctx.face_id, name=%name, nexthops=?e.nexthops.iter().map(|nh| (nh.face_id, nh.cost)).collect::<Vec<_>>(), "strategy: FIB LPM hit");
        } else {
            trace!(face=%ctx.face_id, name=%name, "strategy: FIB LPM miss (no route)");
        }

        // Convert engine FibEntry → strategy FibEntry.
        let strategy_fib: Option<ndn_strategy::FibEntry> =
            fib_entry_ref.map(|e| ndn_strategy::FibEntry {
                nexthops: e
                    .nexthops
                    .iter()
                    .map(|nh| ndn_strategy::FibNexthop {
                        face_id: nh.face_id,
                        cost: nh.cost,
                    })
                    .collect(),
            });

        // Build cross-layer extensions via registered enrichers.
        let mut extensions = AnyMap::new();
        for enricher in &self.enrichers {
            enricher.enrich(strategy_fib.as_ref(), &mut extensions);
        }

        let sctx = StrategyContext {
            name: &name,
            in_face: ctx.face_id,
            fib_entry: strategy_fib.as_ref(),
            pit_token: ctx.pit_token,
            measurements: &self.measurements,
            extensions: &extensions,
        };

        // Per-prefix strategy lookup (LPM on strategy table).
        let strategy = self
            .strategy_table
            .lpm(&name)
            .unwrap_or_else(|| Arc::clone(&self.default_strategy));
        trace!(face=%ctx.face_id, name=%name, strategy=%strategy.name(), "strategy: selected");

        // Sync fast path: avoids Box::pin heap allocation for strategies
        // like BestRoute / Multicast whose decisions are fully synchronous.
        let actions = if let Some(a) = strategy.decide_sync(&sctx) {
            a
        } else {
            strategy.after_receive_interest_erased(&sctx).await
        };

        // Use the first actionable ForwardingAction.
        for action in actions {
            match action {
                ForwardingAction::Forward(faces) => {
                    trace!(face=%ctx.face_id, name=%name, out_faces=?faces, "strategy: Forward");
                    // Link-local scope enforcement: /ndn/local/ packets must
                    // not be forwarded to non-local (network) faces, mirroring
                    // IPv6 fe80::/10 link-local semantics.
                    let effective_faces: SmallVec<[ndn_transport::FaceId; 4]> = if is_link_local(&name) {
                        faces.iter().copied().filter(|fid| {
                            let keep = self.face_table.get(*fid)
                                .map(|f| f.kind().scope() == FaceScope::Local)
                                .unwrap_or(false);
                            if !keep {
                                trace!(face=%ctx.face_id, name=%name, out_face=%fid, "strategy: dropping link-local packet on non-local face");
                            }
                            keep
                        }).collect()
                    } else {
                        faces.iter().copied().collect()
                    };
                    if effective_faces.is_empty() {
                        // All nexthops filtered out — Nack.
                        return Action::Nack(ctx, NackReason::NoRoute);
                    }
                    ctx.out_faces.extend_from_slice(&effective_faces);
                    let out = ctx.out_faces.clone();
                    return Action::Send(ctx, out);
                }
                ForwardingAction::ForwardAfter { faces, delay } => {
                    trace!(face=%ctx.face_id, name=%name, out_faces=?faces, delay_ms=%delay.as_millis(), "strategy: ForwardAfter");
                    // Spawn a delayed send: sleep, re-check PIT, then forward.
                    let pit = Arc::clone(&self.pit);
                    let face_table = Arc::clone(&self.face_table);
                    let raw_bytes = ctx.raw_bytes.clone();
                    let pit_token = ctx.pit_token;
                    tokio::spawn(async move {
                        tokio::time::sleep(delay).await;
                        // Re-check PIT — if the entry was already satisfied or
                        // expired, do not send (the Interest is no longer pending).
                        if let Some(token) = pit_token {
                            if pit.get(&token).is_none() {
                                return; // PIT entry gone — already satisfied/expired.
                            }
                        }
                        for face_id in &faces {
                            if let Some(face) = face_table.get(*face_id) {
                                let _ = face.send_bytes(raw_bytes.clone()).await;
                            }
                        }
                    });
                    return Action::Drop(DropReason::Other); // consumed by delayed task
                }
                ForwardingAction::Nack(reason) => {
                    trace!(face=%ctx.face_id, name=%name, reason=?reason, "strategy: Nack");
                    let nr = match reason {
                        NackReason::NoRoute => NackReason::NoRoute,
                        NackReason::Duplicate => NackReason::Duplicate,
                        NackReason::Congestion => NackReason::Congestion,
                        NackReason::NotYet => NackReason::NotYet,
                    };
                    return Action::Nack(ctx, nr);
                }
                ForwardingAction::Suppress => {
                    trace!(face=%ctx.face_id, name=%name, "strategy: Suppress");
                    return Action::Drop(DropReason::Suppressed);
                }
            }
        }

        // No actionable forwarding decision → no route.
        trace!(face=%ctx.face_id, name=%name, "strategy: no actionable decision, Nack NoRoute");
        Action::Nack(ctx, NackReason::NoRoute)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_local_scope_check_is_accurate() {
        use std::str::FromStr;
        let link_local = ndn_packet::Name::from_str("/ndn/local/nd/hello/1").unwrap();
        let global = ndn_packet::Name::from_str("/ndn/edu/test").unwrap();
        assert!(is_link_local(&link_local), "/ndn/local/ must be link-local");
        assert!(!is_link_local(&global), "/ndn/edu/ must not be link-local");
    }
}
