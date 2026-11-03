//! Multiplexed SVS driver (the AD-10 demux; skyfall FIELD-REPORT-2 §6.3 WIDTH axis).
//!
//! [`join_svs_group`](crate::svs_sync::join_svs_group) spawns **one task, one
//! face, one timer per group** — fine for a handful of chains, but a node
//! following 100 chains then runs hundreds of timers and tasks. This driver
//! collapses that to **O(1) infrastructure**: a single task over a single
//! `mpsc<Bytes>` face pair, with a single shared timer that services every
//! group by its own cadence, plus **O(chains) lightweight `GroupCore` state**.
//!
//! Each group is driven through the exact same `GroupCore` operations the
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
//!
//! **Order.** Nothing here is served in hash or random order: groups by name,
//! their publish and ack channels round-robin by name, and the driver's
//! sources (timer, inbound, publishes, acks, control) round-robin from the
//! one after the source served last. When several are ready at one instant,
//! the order their Sync Interests leave in, and so the order they draw their
//! jitter in, is the same every run (a seeded virtual-time simulation replays
//! exactly).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use ndn_packet::{Interest, Name};
use tokio::sync::{mpsc, oneshot};
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
            .send(MultiControl::Join {
                group,
                config: Box::new(config),
                reply,
            })
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
fn demux_group(raw: &Bytes, groups: &BTreeMap<Name, GroupCore>) -> Option<Name> {
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

/// One channel per group, merged: the next message is taken round-robin by
/// group name, starting after the group served last, so no group starves and
/// the order is the same every run.
struct Inboxes<T> {
    /// Sorted by group name.
    rx: Vec<(Name, mpsc::Receiver<T>)>,
    /// Index the next poll starts at.
    next: usize,
}

impl<T> Inboxes<T> {
    fn new() -> Self {
        Self {
            rx: Vec::new(),
            next: 0,
        }
    }

    fn insert(&mut self, group: Name, rx: mpsc::Receiver<T>) {
        match self.rx.binary_search_by(|(g, _)| g.cmp(&group)) {
            Ok(at) => self.rx[at].1 = rx,
            Err(at) => {
                if at < self.next {
                    self.next += 1;
                }
                self.rx.insert(at, (group, rx));
            }
        }
    }

    fn remove(&mut self, group: &Name) {
        if let Ok(at) = self.rx.binary_search_by(|(g, _)| g.cmp(group)) {
            self.rx.remove(at);
            if at < self.next {
                self.next -= 1;
            }
        }
    }

    /// The next message of any group, with its group. A group whose sender is
    /// gone is dropped; `None` once no group is left.
    fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Option<(Name, T)>> {
        let mut k = 0;
        while k < self.rx.len() {
            let at = (self.next + k) % self.rx.len();
            match self.rx[at].1.poll_recv(cx) {
                Poll::Ready(Some(msg)) => {
                    self.next = at + 1;
                    return Poll::Ready(Some((self.rx[at].0.clone(), msg)));
                }
                Poll::Ready(None) => {
                    // Restart the pass from the same position over what is left.
                    self.rx.remove(at);
                    self.next = at;
                    k = 0;
                }
                Poll::Pending => k += 1,
            }
        }
        if self.rx.is_empty() {
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    }
}

/// What wakes the driver.
enum Event {
    Cancelled,
    /// The shared timer: some group's deadline (or a pending retry) came due.
    Due,
    /// An inbound Sync Interest off the shared face.
    Inbound(Bytes),
    /// A group's publish, with its mapping.
    Publish(Name, Option<Bytes>),
    /// A group's two-phase ack.
    Ack(Name, String, u64),
    Control(MultiControl),
}

/// The driver's sources besides cancellation: timer, inbound, publishes, acks,
/// control.
const SOURCES: usize = 5;

async fn multi_task(
    local_name: Name,
    send: mpsc::Sender<Bytes>,
    mut recv: mpsc::Receiver<Bytes>,
    mut control_rx: mpsc::Receiver<MultiControl>,
    cancel: CancellationToken,
) {
    let mut groups: BTreeMap<Name, GroupCore> = BTreeMap::new();
    // N dynamic publish/ack receivers merged into the one task, keyed by group.
    let mut publishes: Inboxes<(Name, Option<Bytes>)> = Inboxes::new();
    let mut acks: Inboxes<(String, u64)> = Inboxes::new();
    // The source polled first for the next event: the one after the source
    // served last.
    let mut turn = 0;

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
            publishes.remove(&g);
            acks.remove(&g);
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

        // The next event. Cancellation first; then the sources round-robin from
        // `turn`, so each ready source gets its turn and several ready at one
        // instant are taken in the same order every run (`tokio::select!` would
        // pick among them at random).
        let event = {
            let cancelled = cancel.cancelled();
            let sleep = rt::sleep(wake.saturating_duration_since(now));
            tokio::pin!(cancelled, sleep);
            std::future::poll_fn(|cx| {
                if cancelled.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Event::Cancelled);
                }
                for k in 0..SOURCES {
                    let source = (turn + k) % SOURCES;
                    // `Ready(None)`: a closed channel, or no group joined yet.
                    let polled = match source {
                        0 => sleep.as_mut().poll(cx).map(|()| Some(Event::Due)),
                        1 => recv.poll_recv(cx).map(|m| m.map(Event::Inbound)),
                        2 => publishes
                            .poll_next(cx)
                            .map(|m| m.map(|(g, (_, mapping))| Event::Publish(g, mapping))),
                        3 => acks
                            .poll_next(cx)
                            .map(|m| m.map(|(g, (key, seq))| Event::Ack(g, key, seq))),
                        _ => control_rx.poll_recv(cx).map(|m| m.map(Event::Control)),
                    };
                    if let Poll::Ready(Some(event)) = polled {
                        turn = (source + 1) % SOURCES;
                        return Poll::Ready(event);
                    }
                }
                Poll::Pending
            })
            .await
        };

        match event {
            Event::Cancelled => break,

            Event::Due => {
                let now = Instant::now();
                // Service every group whose periodic deadline came due.
                for gc in groups.values_mut() {
                    if gc.next_send <= now {
                        gc.on_timer(&send).await;
                    }
                }
            }

            // Inbound Sync Interest off the shared face → demux to its group.
            Event::Inbound(raw) => {
                if let Some(group) = demux_group(&raw, &groups)
                    && let Some(gc) = groups.get_mut(&group)
                {
                    gc.on_inbound(&raw, &send).await;
                }
            }

            Event::Publish(group, mapping) => {
                if let Some(gc) = groups.get_mut(&group) {
                    gc.on_publish(mapping, &send).await;
                }
            }

            Event::Ack(group, key, seq) => {
                if let Some(gc) = groups.get_mut(&group) {
                    gc.on_ack(&key, seq).await;
                }
            }

            Event::Control(MultiControl::Join {
                group,
                config,
                reply,
            }) => {
                if groups.contains_key(&group) {
                    let _ = reply.send(None);
                } else {
                    let config = *config;
                    let (update_tx, update_rx) = mpsc::channel(config.channel_capacity);
                    let (publish_tx, publish_rx) = mpsc::channel(64);
                    let (ack_tx, ack_rx) = mpsc::channel(64);
                    let observed = Arc::new(ObservedState::default());
                    let mut gc = GroupCore::new(
                        group.clone(),
                        &local_name,
                        config,
                        update_tx,
                        Arc::clone(&observed),
                    );
                    gc.announce(&send).await;
                    groups.insert(group.clone(), gc);
                    publishes.insert(group.clone(), publish_rx);
                    acks.insert(group.clone(), ack_rx);
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

            Event::Control(MultiControl::Leave(group)) => {
                groups.remove(&group);
                publishes.remove(&group);
                acks.remove(&group);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SvsConfig;

    fn cfg() -> SvsConfig {
        SvsConfig {
            sync_interval: Duration::from_millis(30),
            jitter_ms: 0,
            ..Default::default()
        }
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
    fn brokered() -> (
        mpsc::Sender<Bytes>,
        mpsc::Receiver<Bytes>,
        mpsc::Sender<Bytes>,
        mpsc::Receiver<Bytes>,
    ) {
        let (a_send, mut a_send_rx) = mpsc::channel::<Bytes>(4096);
        let (a_in, a_recv) = mpsc::channel::<Bytes>(4096);
        let (b_send, mut b_send_rx) = mpsc::channel::<Bytes>(4096);
        let (b_in, b_recv) = mpsc::channel::<Bytes>(4096);
        let a_in2 = a_in.clone();
        tokio::spawn(async move {
            while let Some(p) = b_send_rx.recv().await {
                let _ = a_in2.send(p).await;
            }
        });
        let b_in2 = b_in.clone();
        tokio::spawn(async move {
            while let Some(p) = a_send_rx.recv().await {
                let _ = b_in2.send(p).await;
            }
        });
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

    /// Each group joined on the shared driver announces itself at once, as a
    /// single-group task does: with a 60 s period the first Sync Interest of
    /// the new group still goes out immediately.
    #[tokio::test]
    async fn a_joined_group_announces_without_waiting_a_period() {
        let (send, mut send_rx) = mpsc::channel::<Bytes>(16);
        let (_in, recv) = mpsc::channel::<Bytes>(16);
        let driver = spawn_multi_svs("/node/a".parse().unwrap(), send, recv);
        let group: Name = "/g".parse().unwrap();
        let config = SvsConfig {
            sync_interval: Duration::from_secs(60),
            jitter_ms: 0,
            ..Default::default()
        };
        let _handle = driver.join(group.clone(), config).await.expect("join");
        let raw = tokio::time::timeout(Duration::from_secs(1), send_rx.recv())
            .await
            .expect("no Sync Interest at join")
            .expect("channel open");
        let interest = Interest::decode(raw).expect("decode");
        assert_eq!(interest.name.components()[..1], group.components()[..]);
    }

    /// Messages waiting in several groups' channels come out round-robin by
    /// group name, whatever order the groups were joined in; a group whose
    /// sender is gone leaves the rotation.
    #[tokio::test]
    async fn inboxes_take_groups_round_robin_by_name() {
        let mut inboxes: Inboxes<u32> = Inboxes::new();
        let mut senders = Vec::new();
        for g in ["/c", "/a", "/b"] {
            let (tx, rx) = mpsc::channel(8);
            inboxes.insert(g.parse().unwrap(), rx);
            senders.push((g, tx));
        }
        for (g, tx) in &senders {
            let base = if *g == "/a" {
                10
            } else if *g == "/b" {
                20
            } else {
                30
            };
            tx.send(base + 1).await.unwrap();
            tx.send(base + 2).await.unwrap();
        }
        drop(senders.remove(2)); // "/b"'s sender: its two messages still come out
        let mut got = Vec::new();
        while got.len() < 6 {
            let (g, m) = std::future::poll_fn(|cx| inboxes.poll_next(cx))
                .await
                .expect("messages left");
            got.push((g.to_string(), m));
        }
        let got: Vec<(&str, u32)> = got.iter().map(|(g, m)| (g.as_str(), *m)).collect();
        assert_eq!(
            got,
            [
                ("/a", 11),
                ("/b", 21),
                ("/c", 31),
                ("/a", 12),
                ("/b", 22),
                ("/c", 32)
            ]
        );
        drop(senders);
        let left = std::future::poll_fn(|cx| inboxes.poll_next(cx)).await;
        assert!(left.is_none(), "every sender is gone");
        assert!(inboxes.rx.is_empty());
    }
}
