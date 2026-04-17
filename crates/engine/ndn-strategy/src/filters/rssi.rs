use crate::context::StrategyContext;
use crate::cross_layer::LinkQualitySnapshot;
use crate::filter::StrategyFilter;
use ndn_transport::ForwardingAction;
use smallvec::SmallVec;

/// Removes faces with RSSI below a threshold from `Forward` actions.
/// No-op when no `LinkQualitySnapshot` is present in extensions.
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
        let snapshot = match ctx.extensions.get::<LinkQualitySnapshot>() {
            Some(s) => s,
            None => return actions,
        };

        actions
            .into_iter()
            .filter_map(|action| {
                match action {
                    ForwardingAction::Forward(faces) => {
                        let filtered: SmallVec<[_; 4]> = faces
                            .into_iter()
                            .filter(|face_id| {
                                snapshot
                                    .for_face(*face_id)
                                    .and_then(|lq| lq.rssi_dbm)
                                    .is_none_or(|rssi| rssi >= self.min_rssi_dbm)
                            })
                            .collect();
                        if filtered.is_empty() {
                            None
                        } else {
                            Some(ForwardingAction::Forward(filtered))
                        }
                    }
                    other => Some(other),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MeasurementsTable;
    use crate::cross_layer::FaceLinkQuality;
    use ndn_packet::Name;
    use ndn_transport::{AnyMap, FaceId};
    use smallvec::smallvec;
    use std::sync::Arc;

    fn make_ctx_with_snapshot<'a>(
        name: &'a Arc<Name>,
        measurements: &'a MeasurementsTable,
        extensions: &'a AnyMap,
    ) -> StrategyContext<'a> {
        StrategyContext {
            name,
            in_face: FaceId(0),
            fib_entry: None,
            pit_token: None,
            measurements,
            extensions,
        }
    }

    #[test]
    fn passes_through_when_no_snapshot() {
        let name = Arc::new(Name::root());
        let m = MeasurementsTable::new();
        let ext = AnyMap::new();
        let ctx = make_ctx_with_snapshot(&name, &m, &ext);

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
        let name = Arc::new(Name::root());
        let m = MeasurementsTable::new();
        let mut ext = AnyMap::new();
        ext.insert(LinkQualitySnapshot {
            per_face: smallvec![
                FaceLinkQuality {
                    face_id: FaceId(1),
                    rssi_dbm: Some(-50),
                    retransmit_rate: None,
                    observed_rtt_ms: None,
                    observed_tput: None
                },
                FaceLinkQuality {
                    face_id: FaceId(2),
                    rssi_dbm: Some(-70),
                    retransmit_rate: None,
                    observed_rtt_ms: None,
                    observed_tput: None
                },
                FaceLinkQuality {
                    face_id: FaceId(3),
                    rssi_dbm: None,
                    retransmit_rate: None,
                    observed_rtt_ms: None,
                    observed_tput: None
                },
            ],
        });
        let ctx = make_ctx_with_snapshot(&name, &m, &ext);

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
                // FaceId(1) passes (-50 >= -60), FaceId(2) fails (-70 < -60), FaceId(3) passes (no RSSI = pass)
                assert_eq!(faces.as_slice(), &[FaceId(1), FaceId(3)]);
            }
            _ => panic!("expected Forward"),
        }
    }

    #[test]
    fn all_filtered_drops_forward_action() {
        let name = Arc::new(Name::root());
        let m = MeasurementsTable::new();
        let mut ext = AnyMap::new();
        ext.insert(LinkQualitySnapshot {
            per_face: smallvec![FaceLinkQuality {
                face_id: FaceId(1),
                rssi_dbm: Some(-80),
                retransmit_rate: None,
                observed_rtt_ms: None,
                observed_tput: None
            },],
        });
        let ctx = make_ctx_with_snapshot(&name, &m, &ext);

        let filter = RssiFilter::new(-60);
        let actions = smallvec![
            ForwardingAction::Forward(smallvec![FaceId(1)]),
            ForwardingAction::Nack(ndn_transport::NackReason::NoRoute),
        ];
        let result = filter.filter(&ctx, actions);
        // Forward removed, Nack passes through
        assert_eq!(result.len(), 1);
        assert!(matches!(result[0], ForwardingAction::Nack(_)));
    }
}
