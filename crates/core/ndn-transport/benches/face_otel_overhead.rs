//! Face-system Tier 4 §9.9 — TraceContextFeature overhead benchmark.
//!
//! Today's Tier 4 deliverable is the **scaffold + OFF baseline**.
//! Phase-3 OTel (separate prompt) flips the sampler to 0.01 and
//! populates the "feature ON" datapoint; the
//! `testbed/tests/audit/face_otel_overhead.sh` wrapper then asserts
//! the p99 delta is within 5% of OFF.
//!
//! ## What this bench measures
//!
//! - **OFF baseline:** drive the default `LpLinkService` pipeline
//!   (six inert Tier-1 features + the two Tier-3 features in their
//!   default OFF state) through `on_egress` against a fixed-size
//!   LP frame.  Establishes the per-frame floor.
//!
//! - **ON datapoint** (Phase-3): flip the TraceContextFeature into
//!   "sample at 0.01, emit span on hit" mode and re-run the same
//!   workload.  Compare p99.
//!
//! The bench deliberately exercises `on_egress` only — the codec
//! cost dominates per-frame, and we want a hot path that mirrors
//! production frame rates.  Reassembly / acks live in `on_ingress`
//! and have their own follow-up bench.

use std::time::Duration;

use bytes::Bytes;
use criterion::{Criterion, criterion_group, criterion_main};
use ndn_transport::FaceId;
use ndn_transport::link_service::{EgressCtx, LpLinkService, OutboundLpFrame};

fn bench_egress_off_baseline(c: &mut Criterion) {
    let svc = LpLinkService::new();
    // Realistic LP-wrapped frame size — 256 bytes covers a small
    // Interest (Name + Nonce + PIT token).
    let lp_wire = Bytes::from(vec![0x64u8; 256]);
    let ctx = EgressCtx::new(FaceId(1), None);

    c.bench_function("egress_off_baseline_256b", |b| {
        b.iter(|| {
            let mut frame = OutboundLpFrame::new(lp_wire.clone(), true);
            // The composer iterates features by Vec ref; here we
            // exercise that path through the public API to keep the
            // bench representative.
            for feat in svc.features() {
                feat.on_egress(&mut frame, &ctx);
            }
            criterion::black_box(&frame);
        });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(3));
    targets = bench_egress_off_baseline
}
criterion_main!(benches);
