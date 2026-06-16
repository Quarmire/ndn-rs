use crate::context::StrategyContext;
use crate::filter::StrategyFilter;
use ndn_transport::ForwardingAction;
use smallvec::SmallVec;

/// Removes faces with RSSI below a threshold from `Forward` actions.
/// A face with no RSSI signal passes (unknown is not a reason to drop).
pub struct RssiFilter {
    pub min_rssi_dbm: i8,
}

impl RssiFilter {
    pub fn new(min_rssi_dbm: i8) -> Self {
        Self { min_rssi_dbm }
    }
}

impl StrategyFilter for RssiFilter {
    fn name(&self) -> &str {
        "rssi-filter"
    }

    fn filter(
        &self,
        ctx: &StrategyContext,
        actions: SmallVec<[ForwardingAction; 2]>,
    ) -> SmallVec<[ForwardingAction; 2]> {
        // RSSI from the cross-layer SignalView (pushed by signal sources).
        let rssi_for = |face_id: ndn_transport::FaceId| -> Option<i8> {
            ctx.signals.link(face_id).and_then(|l| l.rssi_dbm)
        };

        actions
            .into_iter()
            .filter_map(|action| match action {
                ForwardingAction::Forward(faces) => {
                    let filtered: SmallVec<[_; 4]> = faces
                        .into_iter()
                        .filter(|face_id| {
                            rssi_for(*face_id).is_none_or(|rssi| rssi >= self.min_rssi_dbm)
                        })
                        .collect();
                    if filtered.is_empty() {
                        None
                    } else {
                        Some(ForwardingAction::Forward(filtered))
                    }
                }
                other => Some(other),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MeasurementsTable, SignalStore, SignalsTable};
    use ndn_packet::Name;
    use ndn_signals_core::LinkSignals;
    use ndn_transport::{AnyMap, FaceId};
    use smallvec::smallvec;
    use std::sync::Arc;

    fn rssi(dbm: i8) -> LinkSignals {
        LinkSignals {
            rssi_dbm: Some(dbm),
            ..Default::default()
        }
    }

    fn make_ctx<'a>(
        name: &'a Arc<Name>,
        measurements: &'a MeasurementsTable,
        signals: &'a (dyn crate::SignalView<FaceId> + Send + Sync),
        extensions: &'a AnyMap,
    ) -> StrategyContext<'a> {
        static RUNTIME: std::sync::LazyLock<Arc<dyn ndn_runtime::Runtime>> =
            std::sync::LazyLock::new(|| Arc::new(ndn_runtime::TokioRuntime));
        StrategyContext {
            name,
            in_face: FaceId(0),
            fib_entry: None,
            pit_token: None,
            tried_faces: &[],
            measurements,
            signals,
            extensions,
            runtime: &RUNTIME,
        }
    }

    #[test]
    fn passes_through_when_no_signal() {
        // No SignalView entries -> unknown RSSI -> every face passes.
        let name = Arc::new(Name::root());
        let m = MeasurementsTable::new();
        let ext = AnyMap::new();
        let ctx = make_ctx(&name, &m, &crate::NoSignals, &ext);

        let filter = RssiFilter::new(-60);
        let actions = smallvec![ForwardingAction::Forward(smallvec![FaceId(1), FaceId(2)])];
        let result = filter.filter(&ctx, actions);
        assert_eq!(result.len(), 1);
        match &result[0] {
            ForwardingAction::Forward(faces) => assert_eq!(faces.len(), 2),
            _ => panic!("expected Forward"),
        }
    }

    #[test]
    fn filters_low_rssi_faces() {
        // RSSI from the SignalsTable: f1 passes (-50>=-60), f2 fails (-70<-60),
        // f3 has no signal so it passes (unknown = pass).
        let name = Arc::new(Name::root());
        let m = MeasurementsTable::new();
        let ext = AnyMap::new();
        let signals = SignalsTable::new();
        signals.set_link(FaceId(1), rssi(-50));
        signals.set_link(FaceId(2), rssi(-70));
        let ctx = make_ctx(&name, &m, &signals, &ext);

        let filter = RssiFilter::new(-60);
        let actions = smallvec![ForwardingAction::Forward(smallvec![
            FaceId(1),
            FaceId(2),
            FaceId(3)
        ])];
        let result = filter.filter(&ctx, actions);
        assert_eq!(result.len(), 1);
        match &result[0] {
            ForwardingAction::Forward(faces) => {
                assert_eq!(faces.as_slice(), &[FaceId(1), FaceId(3)])
            }
            _ => panic!("expected Forward"),
        }
    }

    #[test]
    fn all_filtered_drops_forward_action() {
        let name = Arc::new(Name::root());
        let m = MeasurementsTable::new();
        let ext = AnyMap::new();
        let signals = SignalsTable::new();
        signals.set_link(FaceId(1), rssi(-80)); // below threshold -> dropped
        let ctx = make_ctx(&name, &m, &signals, &ext);

        let filter = RssiFilter::new(-60);
        let actions = smallvec![
            ForwardingAction::Forward(smallvec![FaceId(1)]),
            ForwardingAction::Nack(ndn_transport::NackReason::NoRoute),
        ];
        let result = filter.filter(&ctx, actions);
        assert_eq!(result.len(), 1);
        assert!(matches!(result[0], ForwardingAction::Nack(_)));
    }
}
