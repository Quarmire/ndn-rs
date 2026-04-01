use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use smallvec::SmallVec;

use ndn_packet::Name;
use ndn_pipeline::{Action, DecodedPacket, DropReason, ForwardingAction, NackReason, PacketContext};
use ndn_store::{Pit, StrategyTable};
use ndn_strategy::{MeasurementsTable, Strategy, StrategyContext};
use crate::Fib;

/// Object-safe version of `Strategy` that boxes its futures.
pub trait ErasedStrategy: Send + Sync + 'static {
    /// Canonical name identifying this strategy (e.g. `/localhost/nfd/strategy/best-route`).
    fn name(&self) -> &Name;

    fn after_receive_interest_erased<'a>(
        &'a self,
        ctx: &'a StrategyContext<'a>,
    ) -> Pin<Box<dyn Future<Output = SmallVec<[ForwardingAction; 2]>> + Send + 'a>>;

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
            NackReason::NoRoute    => ndn_pipeline::NackReason::NoRoute,
            NackReason::Duplicate  => ndn_pipeline::NackReason::Duplicate,
            NackReason::Congestion => ndn_pipeline::NackReason::Congestion,
            NackReason::NotYet     => ndn_pipeline::NackReason::NotYet,
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
    pub strategy_table:   Arc<StrategyTable<dyn ErasedStrategy>>,
    pub default_strategy: Arc<dyn ErasedStrategy>,
    pub fib:              Arc<Fib>,
    pub measurements:     Arc<MeasurementsTable>,
    pub pit:              Arc<Pit>,
    pub face_table:       Arc<ndn_transport::FaceTable>,
}

impl StrategyStage {
    pub async fn process(&self, mut ctx: PacketContext) -> Action {
        match &ctx.packet {
            DecodedPacket::Interest(_) => {}
            // Strategy only runs for Interests in the forward path.
            _ => return Action::Continue(ctx),
        };

        let name = match &ctx.name {
            Some(n) => n.clone(),
            None    => return Action::Drop(DropReason::MalformedPacket),
        };

        let fib_entry_arc = self.fib.lpm(&name);
        let fib_entry_ref = fib_entry_arc.as_deref();

        // Convert engine FibEntry → strategy FibEntry.
        let strategy_fib: Option<ndn_strategy::FibEntry> = fib_entry_ref.map(|e| {
            ndn_strategy::FibEntry {
                nexthops: e.nexthops.iter().map(|nh| ndn_strategy::FibNexthop {
                    face_id: nh.face_id,
                    cost:    nh.cost,
                }).collect(),
            }
        });

        let sctx = StrategyContext {
            name:         &name,
            in_face:      ctx.face_id,
            fib_entry:    strategy_fib.as_ref(),
            pit_token:    ctx.pit_token,
            measurements: &self.measurements,
        };

        // Per-prefix strategy lookup (LPM on strategy table).
        let strategy = self.strategy_table.lpm(&name)
            .unwrap_or_else(|| Arc::clone(&self.default_strategy));

        let actions = strategy.after_receive_interest_erased(&sctx).await;

        // Use the first actionable ForwardingAction.
        for action in actions {
            match action {
                ForwardingAction::Forward(faces) => {
                    ctx.out_faces.extend_from_slice(&faces);
                    let out = ctx.out_faces.clone();
                    return Action::Send(ctx, out);
                }
                ForwardingAction::ForwardAfter { faces, delay } => {
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
                    let nr = match reason {
                        NackReason::NoRoute    => NackReason::NoRoute,
                        NackReason::Duplicate  => NackReason::Duplicate,
                        NackReason::Congestion => NackReason::Congestion,
                        NackReason::NotYet     => NackReason::NotYet,
                    };
                    return Action::Nack(ctx, nr);
                }
                ForwardingAction::Suppress => {
                    return Action::Drop(DropReason::Suppressed);
                }
            }
        }

        // No actionable forwarding decision → no route.
        Action::Nack(ctx, NackReason::NoRoute)
    }
}
