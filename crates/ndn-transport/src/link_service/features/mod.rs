//! Built-in [`super::LinkServiceFeature`] implementations.
//!
//! Default order from [`default_features_for_network_face`]:
//! Fragmentation, Reassembly, LocalFields, IncomingFaceId, Nack,
//! TraceContext, Reliability, CongestionMarking. Features run in the
//! listed order; see each module for behaviour.

use std::sync::Arc;

use super::LinkServiceFeature;

pub mod al_lal;
pub mod congestion_marking;
pub mod fragmentation;
pub mod incoming_face_id;
pub mod local_fields;
pub mod nack;
pub mod reassembly;
pub mod reliability;
pub mod trace_context;

pub use al_lal::{
    AlalFeature, PresenceSink, PresenceSource, install_global_presence_sink,
    install_global_presence_source,
};
pub use congestion_marking::CongestionMarkingFeature;
pub use fragmentation::FragmentationFeature;
pub use incoming_face_id::IncomingFaceIdFeature;
pub use local_fields::LocalFieldsFeature;
pub use nack::NackFeature;
pub use reassembly::ReassemblyFeature;
pub use reliability::ReliabilityFeature;
pub use trace_context::{
    InboundSink, OutboundSource, TraceContextFeature, install_global_egress_source,
    install_global_ingress_sink,
};

/// Feature bundle for one network face. The trait-erased `features` vec
/// drives the per-frame pipeline; the typed `Arc`s let `apply()` flip
/// runtime switches directly.
pub struct NetworkFeatureSet {
    pub features: Vec<Arc<dyn LinkServiceFeature>>,
    pub reliability: Arc<ReliabilityFeature>,
    pub congestion_marking: Arc<CongestionMarkingFeature>,
    /// A-LAL (CCLF presence piggyback / neighbor observation). Disabled until
    /// the app sets a presence + sink and enables it.
    pub a_lal: Arc<AlalFeature>,
}

/// Fresh per-face bundle. Order is significant (see module docs).
pub fn default_features_for_network_face() -> NetworkFeatureSet {
    let reliability = Arc::new(ReliabilityFeature::new());
    let congestion_marking = Arc::new(CongestionMarkingFeature::new());
    let a_lal = Arc::new(AlalFeature::new());
    let features: Vec<Arc<dyn LinkServiceFeature>> = vec![
        Arc::new(FragmentationFeature::new()),
        Arc::new(ReassemblyFeature::new()),
        Arc::new(LocalFieldsFeature::new()),
        Arc::new(IncomingFaceIdFeature::new()),
        Arc::new(NackFeature::new()),
        Arc::new(TraceContextFeature::new()),
        Arc::clone(&reliability) as Arc<dyn LinkServiceFeature>,
        Arc::clone(&congestion_marking) as Arc<dyn LinkServiceFeature>,
        // A-LAL last: it splices presence onto the fully framed egress wire and
        // is inert (early-return) until enabled, so it adds nothing by default.
        Arc::clone(&a_lal) as Arc<dyn LinkServiceFeature>,
    ];
    NetworkFeatureSet {
        features,
        reliability,
        congestion_marking,
        a_lal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_pipeline_has_features_in_order() {
        let set = default_features_for_network_face();
        let names: Vec<&'static str> = set.features.iter().map(|f| f.name()).collect();
        assert_eq!(
            names,
            vec![
                "fragmentation",
                "reassembly",
                "local-fields",
                "incoming-face-id",
                "nack",
                "trace-context",
                "reliability",
                "congestion-marking",
                "a-lal",
            ]
        );
    }
}
