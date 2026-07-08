//! [`HistoryServer`] — a durable, publisher-independent history replica (D-42).
//!
//! The substrate enabler for cooperative offline history serving: a peer can
//! reach a chain's verifiable history even while the writer is **down**. It is
//! **composition of already-shipped [`crate::svsync`] pieces**, not new
//! architecture — a long-lived [`SvSync`] node with a durable store that
//! *ingests everything advertised* and *serves it from the demux*:
//!
//! * [`SvSync`] joined with `auto_ack: false` — advance a slot only on a
//!   verified+stored ack (D-44 two-phase), so a rejected item never marks the
//!   server caught-up.
//! * [`SvSync::ingest_publication`] — fetch + (optionally) validate + store the
//!   raw signed wire, so it re-serves byte-for-byte.
//! * [`IngestValidator`] — fail-closed **resource protection** (don't store what
//!   won't validate). It is *not* trust vouching (C1): the fetcher re-verifies
//!   through its own gate (D-44 reject-without-poison); nothing the server does
//!   places it in the trust path.
//! * `serve_all_stored` — the demux answers fetches for *any* stored name, not
//!   just the server's own prefix (a replica holds other publishers' Data).
//! * N-13 durable store + seq recovery — history survives the server's own boots.
//!
//! **The one behavioural difference from a normal consumer:** a `HistoryServer`
//! ingests the **full advertised range** for every publisher in the group, not
//! just the gaps it personally needs — it is a durable replica.
//!
//! **Backfill from peers (redundancy):** because it ingests over the advertised
//! range and every server advertises its full vector + serves from its store, a
//! *new* server catches the whole history up from an *existing* server via the
//! ordinary gap→ingest path — no live writer required. That is what lets
//! redundancy across cooperative members work.
//!
//! **Topology-neutral (C3):** this type knows nothing about cooperatives,
//! replication factor, or redistribution — it is one node's role. The same type
//! runs as a dedicated repo (the D-42 fallback) or as a cooperative member; the
//! orchestration is an NDF policy layer above it. No new Block Kind, no new wire
//! path (C4).

use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use ndn_packet::Name;

use crate::rt;
use crate::svsync::{DataStore, IngestValidator, SvSync, SvSyncConfig, svs_data_name};

/// Configuration for a [`HistoryServer`]. The store and (optional) trust gate
/// are the durability + resource-protection knobs; the SVS tunables ride
/// `svsync` (its `auto_ack` and `serve_all_stored` are forced to the server
/// posture regardless of what is passed).
#[derive(Default)]
pub struct HistoryServerConfig {
    /// Layer-1 tunables. [`HistoryServer::join`] forces `svs.auto_ack = false`
    /// (two-phase) and `serve_all_stored = true` (repo serving) on top.
    pub svsync: SvSyncConfig,
    /// Fail-closed ingest gate (resource protection, **not** trust vouching).
    /// `None` accepts all fetched wire for storage (open / testbed). A real
    /// deployment wraps its verifier here so the server never stores garbage.
    pub ingest_validator: Option<IngestValidator>,
}

/// A durable history replica for one sync `group` (see the module docs). Serve
/// multiple groups by running one `HistoryServer` per group. Drop or
/// [`leave`](Self::leave) to stop; the durable store outlives it.
pub struct HistoryServer {
    svs: Arc<SvSync>,
    cancel: CancellationToken,
}

impl HistoryServer {
    /// Join `group` as `local_name`, ingesting-and-serving through the
    /// `net_out`/`net_in` channel pair. `store` is the durable backing (e.g.
    /// `BackendStore` over fjall/redb); it holds every ingested publication and
    /// the demux re-serves from it. The background task ingests the full
    /// advertised range for every publisher and acks the contiguous
    /// verified+stored prefix (a hole stays visible and re-derives next round).
    pub fn join(
        group: Name,
        local_name: Name,
        store: Arc<dyn DataStore>,
        net_out: mpsc::Sender<Bytes>,
        net_in: mpsc::Receiver<Bytes>,
        config: HistoryServerConfig,
    ) -> Self {
        let mut svsync = config.svsync;
        // Server posture: two-phase (advance only on verified+stored) + repo serving.
        svsync.svs.auto_ack = false;
        svsync.serve_all_stored = true;

        let mut svs = SvSync::join(group.clone(), local_name, store, net_out, net_in, svsync);
        if let Some(validator) = config.ingest_validator {
            svs.set_ingest_validator(validator);
        }
        // Own the update stream; the ingest loop drives it.
        let mut updates = svs.take_updates();
        let svs = Arc::new(svs);
        let cancel = CancellationToken::new();

        let ingest_svs = Arc::clone(&svs);
        let ingest_cancel = cancel.clone();
        rt::spawn(async move {
            loop {
                let update = tokio::select! {
                    _ = ingest_cancel.cancelled() => break,
                    u = updates.recv() => match u {
                        Some(u) => u,
                        None => break,
                    },
                };
                // Durable-replica ingest: fetch+verify+store the WHOLE advertised
                // range (not just personally-needed gaps). Ack only the contiguous
                // verified+stored prefix — stop at the first Block that did not land
                // so its gap stays visible and re-derives, never acking past a hole.
                for seq in update.low_seq..=update.high_seq {
                    ingest_svs.ingest_publication(&update.name, seq).await;
                    let present = ingest_svs
                        .store()
                        .find_under(&svs_data_name(&update.name, &group, seq))
                        .is_some();
                    if present {
                        let _ = ingest_svs.sync_handle().ack(&update.publisher, seq).await;
                    } else {
                        break;
                    }
                }
            }
        });

        Self { svs, cancel }
    }

    /// The underlying [`SvSync`] (its store, data prefix, and — via
    /// [`SvSync::sync_handle`] — the observed high-water). Read-only use; the
    /// ingest loop owns the update stream.
    pub fn svs(&self) -> &Arc<SvSync> {
        &self.svs
    }

    /// The durable store this replica ingests into and serves from.
    pub fn store(&self) -> &Arc<dyn DataStore> {
        self.svs.store()
    }

    /// Stop the ingest loop (the store — durable — outlives it).
    pub fn leave(self) {
        self.cancel.cancel();
    }
}

impl Drop for HistoryServer {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use crate::SvsConfig;
    use crate::svsync::{MemoryStore, SvSync, SvSyncConfig};

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn fast() -> SvSyncConfig {
        SvSyncConfig {
            svs: SvsConfig {
                sync_interval: Duration::from_millis(40),
                jitter_ms: 0,
                ..Default::default()
            },
            fetch_timeout: Duration::from_secs(2),
            ..Default::default()
        }
    }

    /// Forward one node's outbound onto a set of inbound channels, until cancelled.
    fn pipe(
        mut out: mpsc::Receiver<Bytes>,
        ins: Vec<mpsc::Sender<Bytes>>,
        cancel: CancellationToken,
    ) {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    p = out.recv() => match p {
                        Some(p) => { for i in &ins { let _ = i.send(p.clone()).await; } }
                        None => break,
                    },
                }
            }
        });
    }

    async fn wait_until(mut pred: impl FnMut() -> bool, ms: u64) -> bool {
        for _ in 0..(ms / 10) {
            if pred() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        pred()
    }

    /// D-42 acceptance (lib level): a `HistoryServer` ingests a writer's history,
    /// the writer goes fully OFFLINE, and a reader still fetches that history —
    /// byte-identical — served by the server. Topology W <-> H <-> R (writer and
    /// reader never directly connected), so the reader can only be served by H.
    #[tokio::test]
    async fn history_server_serves_offline_writer() {
        let group = n("/coop/grp");
        let w = n("/coop/grp/writer");
        let h = n("/coop/grp/repo");
        let r = n("/coop/grp/reader");

        let (w_out_tx, w_out_rx) = mpsc::channel::<Bytes>(256);
        let (w_in_tx, w_in_rx) = mpsc::channel::<Bytes>(256);
        let (h_out_tx, h_out_rx) = mpsc::channel::<Bytes>(256);
        let (h_in_tx, h_in_rx) = mpsc::channel::<Bytes>(256);
        let (r_out_tx, r_out_rx) = mpsc::channel::<Bytes>(256);
        let (r_in_tx, r_in_rx) = mpsc::channel::<Bytes>(256);

        // W <-> H <-> R. The writer's pipe is separately cancellable so we can take
        // it fully offline; H fans its outbound to both W and R.
        let writer_link = CancellationToken::new();
        let live = CancellationToken::new();
        pipe(w_out_rx, vec![h_in_tx.clone()], writer_link.clone());
        pipe(h_out_rx, vec![w_in_tx, r_in_tx], live.clone());
        pipe(r_out_rx, vec![h_in_tx], live.clone());

        // Writer publishes three Blocks.
        let store_w: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let svs_w = SvSync::join(group.clone(), w.clone(), store_w, w_out_tx, w_in_rx, fast());

        // HistoryServer ingests everything, durable + serving.
        let store_h: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let server = HistoryServer::join(
            group.clone(),
            h,
            Arc::clone(&store_h),
            h_out_tx,
            h_in_rx,
            HistoryServerConfig::default(),
        );

        let mut svs_w = Some(svs_w);
        for i in 1..=3u64 {
            svs_w
                .as_ref()
                .unwrap()
                .publish_data(format!("blk-{i}").as_bytes())
                .await
                .unwrap();
        }

        // H durably ingests the full range (stored under the WRITER's name).
        let ingested = wait_until(
            || (1..=3).all(|s| store_h.find_under(&svs_data_name(&w, &group, s)).is_some()),
            5000,
        )
        .await;
        assert!(ingested, "HistoryServer must ingest the writer's full history");

        // Writer goes fully offline: cut its link and drop it. Only H can serve now.
        writer_link.cancel();
        drop(svs_w.take());

        // Reader fetches the writer's history — served by H, writer gone.
        let store_r: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let svs_r = SvSync::join(group.clone(), r, store_r, r_out_tx, r_in_rx, fast());
        for i in 1..=3u64 {
            let got = tokio::time::timeout(Duration::from_secs(5), svs_r.fetch(&w, i))
                .await
                .expect("fetch timed out");
            assert_eq!(
                got.as_deref(),
                Some(format!("blk-{i}").as_bytes()),
                "Block {i} served by the HistoryServer, byte-identical, writer offline"
            );
        }

        server.leave();
        live.cancel();
    }

    /// C1 — untrusted serving is RESOURCE PROTECTION: a reject-all `IngestValidator`
    /// makes the server store nothing (it never vouches for or holds unvalidated
    /// bytes). Trust stays with the fetcher; the server only ever carries.
    #[tokio::test]
    async fn reject_all_ingest_validator_stores_nothing() {
        let group = n("/coop/grp");
        let w = n("/coop/grp/writer");
        let h = n("/coop/grp/repo");

        let (w_out_tx, w_out_rx) = mpsc::channel::<Bytes>(256);
        let (w_in_tx, w_in_rx) = mpsc::channel::<Bytes>(256);
        let (h_out_tx, h_out_rx) = mpsc::channel::<Bytes>(256);
        let (h_in_tx, h_in_rx) = mpsc::channel::<Bytes>(256);

        let live = CancellationToken::new();
        pipe(w_out_rx, vec![h_in_tx], live.clone());
        pipe(h_out_rx, vec![w_in_tx], live.clone());

        let store_w: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let svs_w = SvSync::join(group.clone(), w.clone(), store_w, w_out_tx, w_in_rx, fast());

        let store_h: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let config = HistoryServerConfig {
            ingest_validator: Some(Arc::new(|_wire: Bytes| {
                Box::pin(async { false })
                    as std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>>
            })),
            ..Default::default()
        };
        let server = HistoryServer::join(
            group.clone(),
            h,
            Arc::clone(&store_h),
            h_out_tx,
            h_in_rx,
            config,
        );

        svs_w.publish_data(b"secret").await.unwrap();
        svs_w.publish_data(b"secret-2").await.unwrap();

        // Give several sync rounds + ingest attempts time to happen and be refused.
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(
            store_h.find_under(&svs_data_name(&w, &group, 1)).is_none()
                && store_h.find_under(&svs_data_name(&w, &group, 2)).is_none(),
            "a reject-all ingest gate must store nothing (resource protection, not vouching)"
        );

        server.leave();
        drop(svs_w);
        live.cancel();
    }
}
