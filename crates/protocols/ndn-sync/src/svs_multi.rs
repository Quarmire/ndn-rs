//! Multiplexed SVS driver (the AD-10 demux; skyfall FIELD-REPORT-2 §6.3 WIDTH axis).
//!
//! [`join_svs_group`](crate::svs_sync::join_svs_group) spawns **one task, one
//! face, one timer per group** — fine for a handful of chains, but a node
//! following 100 chains then runs hundreds of timers and tasks. This driver
//! collapses that to **O(1) infrastructure**: a single task over a single
//! `mpsc<Bytes>` face pair, with a single shared timer that services every
//! group by its own cadence, plus **O(chains) lightweight [`GroupCore`] state**.
//!
//! Each group is driven through the exact same [`GroupCore`] operations the
//! single-group task uses — so convergence, two-phase reject-without-poison
//! (D-44), N-9 observation, and N-11 coalescing are **identical per group**, and
//! **no group's state touches another's** (each has its own `SvsNode`, pending
//! buffer, and update/ack channels). A poison in group A can never stall group B.
//!
//! **AD-10 invariant.** This lives *below* an app's follow/publisher API: a
//! consumer that joins N groups gets N ordinary [`SyncHandle`]s and drives each
//! exactly as before — the multiplexing is transparent. The FIB axis (one
//! namespace route covering many groups) is a **separable** follow-on: this
//! collapses tasks/timers, not the O(chains) FIB entries.
//!
//! What is NOT collapsed here (deliberately): each group still routes its own
//! prefix to the shared face (the FIB axis), and each group keeps its own state
//! vector (that is the irreducible O(chains) data).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_packet::{Interest, Name};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;

use crate::protocol::{ObservedState, SyncHandle};
use crate::rt::{self, Instant};
use crate::svs_sync::{GroupCore, PENDING_RETRY, SvsConfig};

/// Handle to a running multiplexed SVS driver: join/leave groups at runtime;
/// each join returns an ordinary [`SyncHandle`] for that group.
pub struct MultiSvs {
    control_tx: mpsc::Sender<MultiControl>,
    cancel: CancellationToken,
}

enum MultiControl {
    Join {
        group: Name,
        config: Box<SvsConfig>,
        reply: oneshot::Sender<Option<SyncHandle>>,
    },
    Leave(Name),
}

/// Spawn a multiplexed SVS driver over one shared face (`send`/`recv`). All
/// groups joined via [`MultiSvs::join`] share this one task, face, and timer.
pub fn spawn_multi_svs(
    local_name: Name,
    send: mpsc::Sender<Bytes>,
    recv: mpsc::Receiver<Bytes>,
) -> MultiSvs {
    let cancel = CancellationToken::new();
    let (control_tx, control_rx) = mpsc::channel(64);
    let task_cancel = cancel.clone();
    rt::spawn(async move {
        multi_task(local_name, send, recv, control_rx, task_cancel).await;
    });
    MultiSvs { control_tx, cancel }
}

impl MultiSvs {
    /// Join `group` on the shared driver, returning its [`SyncHandle`] (the same
    /// type [`join_svs_group`](crate::svs_sync::join_svs_group) returns). `None`
    /// if the driver is gone or `group` is already joined. `config` may differ
    /// per group — the shared timer tracks each group's own cadence.
    pub async fn join(&self, group: Name, config: SvsConfig) -> Option<SyncHandle> {
        let (reply, rx) = oneshot::channel();
        self.control_tx
            .send(MultiControl::Join { group, config: Box::new(config), reply })
            .await
            .ok()?;
        rx.await.ok().flatten()
    }

    /// Stop carrying `group` (its `SyncHandle` also stops when dropped).
    pub async fn leave(&self, group: Name) {
        let _ = self.control_tx.send(MultiControl::Leave(group)).await;
    }

    /// Stop the driver and every group it carries.
    pub fn shutdown(&self) {
        self.cancel.cancel();
    }
}

impl Drop for MultiSvs {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Route an inbound Sync Interest to the group it belongs to. Its name is
/// `<group>/v=N[/params]`; find the trailing version component whose prefix is a
/// joined group (scanning from the end handles a group prefix that itself
/// contains a version component).
fn demux_group(raw: &Bytes, groups: &HashMap<Name, GroupCore>) -> Option<Name> {
    let interest = Interest::decode(raw.clone()).ok()?;
    let comps = interest.name.components();
    for i in (0..comps.len()).rev() {
        if comps[i].as_version().is_some() {
            let cand = Name::from_components(comps[..i].iter().cloned());
            if groups.contains_key(&cand) {
                return Some(cand);
            }
        }
    }
    None
}

async fn multi_task(
    local_name: Name,
    send: mpsc::Sender<Bytes>,
    mut recv: mpsc::Receiver<Bytes>,
    mut control_rx: mpsc::Receiver<MultiControl>,
    cancel: CancellationToken,
) {
    let mut groups: HashMap<Name, GroupCore> = HashMap::new();
    // N dynamic publish/ack receivers merged into the one task, keyed by group.
    let mut publish_map: tokio_stream::StreamMap<Name, ReceiverStream<(Name, Option<Bytes>)>> =
        tokio_stream::StreamMap::new();
    let mut ack_map: tokio_stream::StreamMap<Name, ReceiverStream<(String, u64)>> =
        tokio_stream::StreamMap::new();

    loop {
        // Per-group maintenance: deliver buffered gaps (non-blocking), and reap
        // any group whose consumer dropped its handle (update channel closed).
        let mut any_pending = false;
        let mut closed: Vec<Name> = Vec::new();
        for (g, gc) in groups.iter_mut() {
            if gc.update_tx.is_closed() {
                closed.push(g.clone());
                continue;
            }
            if gc.drain_pending_try() {
                any_pending = true;
            }
        }
        for g in closed {
            groups.remove(&g);
            publish_map.remove(&g);
            ack_map.remove(&g);
        }

        // One shared timer: the earliest group deadline, capped by a pending
        // retry. `wake == now` when a group is already due.
        let now = Instant::now();
        let mut wake = now + Duration::from_secs(3600);
        for gc in groups.values() {
            wake = wake.min(gc.next_send);
        }
        if any_pending {
            wake = wake.min(now + PENDING_RETRY);
        }

        tokio::select! {
            _ = cancel.cancelled() => break,

            _ = rt::sleep(wake.saturating_duration_since(now)) => {
                let now = Instant::now();
                // Service every group whose periodic deadline came due.
                for gc in groups.values_mut() {
                    if gc.next_send <= now {
                        gc.on_timer(&send).await;
                    }
                }
            }

            // Inbound Sync Interest off the shared face → demux to its group.
            Some(raw) = recv.recv() => {
                if let Some(group) = demux_group(&raw, &groups)
                    && let Some(gc) = groups.get_mut(&group)
                {
                    gc.on_inbound(&raw, &send).await;
                }
            }

            // A group's publish, tagged by group via the StreamMap key.
            Some((group, (pub_name, mapping))) = publish_map.next(), if !publish_map.is_empty() => {
                let _ = pub_name;
                if let Some(gc) = groups.get_mut(&group) {
                    gc.on_publish(mapping, &send).await;
                }
            }

            // A group's two-phase ack.
            Some((group, (key, seq))) = ack_map.next(), if !ack_map.is_empty() => {
                if let Some(gc) = groups.get_mut(&group) {
                    gc.on_ack(&key, seq).await;
                }
            }

            Some(ctl) = control_rx.recv() => match ctl {
                MultiControl::Join { group, config, reply } => {
                    if groups.contains_key(&group) {
                        let _ = reply.send(None);
                    } else {
                        let config = *config;
                        let (update_tx, update_rx) = mpsc::channel(config.channel_capacity);
                        let (publish_tx, publish_rx) = mpsc::channel(64);
                        let (ack_tx, ack_rx) = mpsc::channel(64);
                        let observed = Arc::new(ObservedState::default());
                        let gc = GroupCore::new(
                            group.clone(),
                            &local_name,
                            config,
                            update_tx,
                            Arc::clone(&observed),
                        );
                        groups.insert(group.clone(), gc);
                        publish_map.insert(group.clone(), ReceiverStream::new(publish_rx));
                        ack_map.insert(group.clone(), ReceiverStream::new(ack_rx));
                        // Per-group handle: a dropped/left handle closes `update_rx`,
                        // which the maintenance pass above reaps. The token is the
                        // handle's own (leave/drop consumes the handle → closes the
                        // channel → reaped); the driver watches the channel, not it.
                        let handle = SyncHandle::new(update_rx, publish_tx, CancellationToken::new())
                            .with_ack_channel(ack_tx)
                            .with_observed(observed);
                        let _ = reply.send(Some(handle));
                    }
                }
                MultiControl::Leave(group) => {
                    groups.remove(&group);
                    publish_map.remove(&group);
                    ack_map.remove(&group);
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SvsConfig;

    fn cfg() -> SvsConfig {
        SvsConfig { sync_interval: Duration::from_millis(30), jitter_ms: 0, ..Default::default() }
    }

    fn cfg_two_phase(cap: usize) -> SvsConfig {
        SvsConfig {
            sync_interval: Duration::from_millis(30),
            jitter_ms: 0,
            auto_ack: false,
            channel_capacity: cap,
            ..Default::default()
        }
    }

    /// Bridge two multiplexed drivers A<->B over in-memory channels.
    fn brokered() -> (mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>, mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>)
    {
        let (a_send, mut a_send_rx) = mpsc::channel::<Bytes>(4096);
        let (a_in, a_recv) = mpsc::channel::<Bytes>(4096);
        let (b_send, mut b_send_rx) = mpsc::channel::<Bytes>(4096);
        let (b_in, b_recv) = mpsc::channel::<Bytes>(4096);
        let a_in2 = a_in.clone();
        tokio::spawn(async move { while let Some(p) = b_send_rx.recv().await { let _ = a_in2.send(p).await; } });
        let b_in2 = b_in.clone();
        tokio::spawn(async move { while let Some(p) = a_send_rx.recv().await { let _ = b_in2.send(p).await; } });
        (a_send, a_recv, b_send, b_recv)
    }

    /// One driver on each node carries N groups; a publish in each group converges on the peer —
    /// proving the multiplexed core handles N groups over ONE task/face/timer.
    #[tokio::test]
    async fn multiplexed_driver_converges_across_many_groups() {
        let (a_send, a_recv, b_send, b_recv) = brokered();
        let a = spawn_multi_svs("/node/a".parse().unwrap(), a_send, a_recv);
        let b = spawn_multi_svs("/node/b".parse().unwrap(), b_send, b_recv);

        let n = 6;
        let mut a_handles = Vec::new();
        let mut b_handles = Vec::new();
        for i in 0..n {
            let g: Name = format!("/g{i}").parse().unwrap();
            let ha = a.join(g.clone(), cfg()).await.expect("A join");
            let hb = b.join(g.clone(), cfg()).await.expect("B join");
            ha.publish("/node/a".parse().unwrap()).await.unwrap();
            a_handles.push(ha);
            b_handles.push((g, hb));
        }
        for (g, hb) in b_handles.iter_mut() {
            let upd = tokio::time::timeout(Duration::from_secs(5), hb.recv())
                .await
                .unwrap_or_else(|_| panic!("group {g} never converged on the multiplexed driver"))
                .expect("update");
            assert_eq!(upd.publisher, "/node/a", "group {g}");
            assert_eq!(upd.high_seq, 1, "group {g}");
        }
        drop(a_handles);
    }

    /// A stalled group (its two-phase consumer never drains, so its update channel jams) must NOT
    /// wedge the shared driver — a healthy group on the same driver still converges. This is the
    /// per-group isolation AD-10 requires: a poison in group A never touches group B.
    #[tokio::test]
    async fn stalled_group_does_not_wedge_the_shared_driver() {
        let (a_send, a_recv, b_send, b_recv) = brokered();
        let a = spawn_multi_svs("/node/a".parse().unwrap(), a_send, a_recv);
        let b = spawn_multi_svs("/node/b".parse().unwrap(), b_send, b_recv);

        let g_stuck: Name = "/stuck".parse().unwrap();
        let g_ok: Name = "/ok".parse().unwrap();

        // g_stuck: capacity-1 two-phase channel that B will NEVER drain or ack.
        let a_stuck = a.join(g_stuck.clone(), cfg_two_phase(1)).await.unwrap();
        let _b_stuck = b.join(g_stuck.clone(), cfg_two_phase(1)).await.unwrap(); // held, never recv'd
        // g_ok: a healthy group.
        let a_ok = a.join(g_ok.clone(), cfg()).await.unwrap();
        let mut b_ok = b.join(g_ok.clone(), cfg()).await.unwrap();

        // Jam g_stuck: publish several times so its (undrained, cap-1) channel stays full and its
        // pending buffer keeps failing to deliver.
        for _ in 0..5 {
            a_stuck.publish("/node/a".parse().unwrap()).await.unwrap();
        }
        // The healthy group must still converge on the SAME driver.
        a_ok.publish("/node/a".parse().unwrap()).await.unwrap();
        let upd = tokio::time::timeout(Duration::from_secs(5), b_ok.recv())
            .await
            .expect("healthy group wedged by the stalled group — driver is not isolating")
            .expect("update");
        assert_eq!(upd.publisher, "/node/a");
        assert_eq!(upd.high_seq, 1);
    }
}
