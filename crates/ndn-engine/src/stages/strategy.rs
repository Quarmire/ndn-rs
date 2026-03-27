use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use smallvec::SmallVec;

use ndn_pipeline::{Action, DecodedPacket, DropReason, ForwardingAction, NackReason, PacketContext};
use ndn_strategy::{MeasurementsTable, Strategy, StrategyContext};
use crate::Fib;

/// Object-safe version of `Strategy` that boxes its futures.
pub trait ErasedStrategy: Send + Sync + 'static {
    fn after_receive_interest_erased<'a>(
        &'a self,
        ctx: &'a StrategyContext<'a>,
    ) -> Pin<Box<dyn Future<Output = SmallVec<[ForwardingAction; 2]>> + Send + 'a>>;
}

impl<S: Strategy> ErasedStrategy for S {
    fn after_receive_interest_erased<'a>(
        &'a self,
        ctx: &'a StrategyContext<'a>,
    ) -> Pin<Box<dyn Future<Output = SmallVec<[ForwardingAction; 2]>> + Send + 'a>> {
        Box::pin(self.after_receive_interest(ctx))
    }
}

/// Calls the strategy to produce a forwarding decision for Interests.
pub struct StrategyStage {
    pub strategy:     Arc<dyn ErasedStrategy>,
    pub fib:          Arc<Fib>,
    pub measurements: Arc<MeasurementsTable>,
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

        let actions = self.strategy.after_receive_interest_erased(&sctx).await;

        // Use the first actionable ForwardingAction.
        for action in actions {
            match action {
                ForwardingAction::Forward(faces) => {
                    ctx.out_faces.extend_from_slice(&faces);
                    let out = ctx.out_faces.clone();
                    return Action::Send(ctx, out);
                }
                ForwardingAction::ForwardAfter { faces, delay: _ } => {
                    // Forward immediately (delay scheduling not yet implemented).
                    ctx.out_faces.extend_from_slice(&faces);
                    let out = ctx.out_faces.clone();
                    return Action::Send(ctx, out);
                }
                ForwardingAction::Nack(_reason) => {
                    return Action::Nack(NackReason::NoRoute);
                }
                ForwardingAction::Suppress => {
                    return Action::Drop(DropReason::Suppressed);
                }
            }
        }

        // No actionable forwarding decision → no route.
        Action::Nack(NackReason::NoRoute)
    }
}
