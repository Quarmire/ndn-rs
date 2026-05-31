//! Partitioned forwarding data-plane runtime (`partitioned-fwd` feature).
//!
//! The path toward NDN-DPDK-style per-core state partitioning: decode happens
//! in an RX front-end, and forwarding runs in N worker tasks dispatched by a
//! Name Dispatch Table (NDT). Staging:
//!
//! - **Phase 1** — single-worker seam (decode-in-RX → worker → `forward_decoded`).
//! - **Phase 2a** (this file) — N workers + NDT dispatch over the **shared**
//!   PIT. The NDT keys each packet on a hash of its first `start_depth` name
//!   components, so an Interest and the Data that satisfies it (its name is a
//!   prefix) land on the same worker — giving cache affinity and the same-name
//!   → same-worker property aggregation relies on. Because the PIT is still
//!   shared, dispatch is pure load distribution: every worker can match any
//!   entry, so this is correct without the wire owner-tag. The win is
//!   parallelism — forwarding and (for NonLocal Data) per-packet signature
//!   verification spread across cores.
//! - **Phase 2b** — per-worker **private** PITs + a `PitToken` owner-tag echoed
//!   on the wire so Data/Nack return to the owning partition (needed only once
//!   PITs are private; short CanBePrefix discovery relies on the tag).
//!
//! Design: `.claude/notes/partitioned-fwd-design-2026-05-24.md`.

use std::sync::Arc;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;

use ndn_discovery_core::InboundMeta;
use ndn_packet::Name;

use crate::engine::TaskTracker;
use crate::observability::targets as t;
use crate::pipeline::{Action, PacketContext};

use super::{InboundPacket, PacketDispatcher};

/// NDT dispatch depth: hash the first 2 name components (NDN-DPDK default).
const NDT_START_DEPTH: usize = 2;

/// A decoded packet handed from the RX/decode front-end to a forwarding worker.
struct WorkerMsg {
    ctx: PacketContext,
    meta: InboundMeta,
}

/// Name Dispatch Table: maps a packet to a forwarding worker by a hash of its
/// first `start_depth` name components. A Data and the (prefix-)Interest it
/// satisfies share those components (when both have ≥ `start_depth`), so they
/// map to the same worker. Phase 2a runs over the shared PIT, so this is load
/// distribution + cache affinity; Phase 2b makes it the per-partition router.
struct Ndt {
    workers: usize,
    start_depth: usize,
}

impl Ndt {
    fn worker_for(&self, name: &Name) -> usize {
        use std::hash::{Hash, Hasher};
        if self.workers <= 1 {
            return 0;
        }
        let mut h = std::collections::hash_map::DefaultHasher::new();
        let k = name.components().len().min(self.start_depth);
        for comp in name.components().iter().take(k) {
            comp.hash(&mut h);
        }
        (h.finish() % self.workers as u64) as usize
    }
}

impl PacketDispatcher {
    /// Spawn the partitioned data-plane: an RX front-end that decodes inbound
    /// packets and dispatches each to a forwarding worker via the NDT. Phase 2a
    /// runs `workers` worker tasks over the shared PIT.
    pub(super) fn spawn_partitioned(
        self: &Arc<Self>,
        rx: mpsc::Receiver<InboundPacket>,
        cancel: CancellationToken,
        tasks: &mut TaskTracker,
        workers: usize,
    ) {
        let workers = workers.max(1);
        let ndt = Ndt {
            workers,
            start_depth: NDT_START_DEPTH,
        };

        // One inbox per worker; the router fans packets in by NDT.
        let mut worker_txs = Vec::with_capacity(workers);
        for id in 0..workers {
            let (wtx, wrx) = mpsc::channel::<WorkerMsg>(self.channel_cap);
            worker_txs.push(wtx);
            let w = Arc::clone(self);
            let wc = cancel.clone();
            tasks.spawn(async move { w.run_worker(wrx, wc).await }.instrument(
                tracing::info_span!(
                    target: t::FWD_PIPELINE,
                    "fwd_worker",
                    id = id as u32,
                ),
            ));
        }

        let r = Arc::clone(self);
        tasks.spawn(
            async move { r.run_partitioned_router(rx, worker_txs, ndt, cancel).await }.instrument(
                tracing::info_span!(target: t::FWD_PIPELINE, "fwd_router", workers = workers as u32),
            ),
        );
    }

    /// Decode inbound packets (fragment fast-path + TLV/LP decode) and dispatch
    /// each decoded packet to its NDT-assigned worker. Drops and buffered
    /// fragments are terminal here (decode never yields a forwarding action).
    async fn run_partitioned_router(
        &self,
        mut rx: mpsc::Receiver<InboundPacket>,
        worker_txs: Vec<mpsc::Sender<WorkerMsg>>,
        ndt: Ndt,
        cancel: CancellationToken,
    ) {
        loop {
            let pkt = tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                pkt = rx.recv() => match pkt {
                    Some(p) => p,
                    None => break,
                },
            };
            let InboundPacket {
                raw,
                face_id,
                arrival,
                meta,
            } = pkt;
            let endpoint_id = meta.endpoint_id();
            if let Action::Continue(ctx) =
                self.decode
                    .decode_inbound(raw, face_id, arrival, endpoint_id)
            {
                let worker = ctx.name.as_deref().map_or(0, |n| ndt.worker_for(n));
                // Backpressure on the chosen worker; an error means it stopped
                // (shutdown), so the router winds down too.
                if worker_txs[worker]
                    .send(WorkerMsg { ctx, meta })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }

    /// Forwarding worker: drain decoded packets and run the forwarding path.
    async fn run_worker(&self, mut rx: mpsc::Receiver<WorkerMsg>, cancel: CancellationToken) {
        loop {
            let msg = tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                msg = rx.recv() => match msg {
                    Some(m) => m,
                    None => break,
                },
            };
            self.forward_decoded(msg.ctx, msg.meta).await;
        }
    }
}
