//! The network half of a heap node: sync groups, the notice, direct fetch,
//! catch-up, serving and the grant pull (spec §7).
//!
//! Everything this half needs of the node it asks of [`NodeInner`]
//! (`take`, `missing`, `served`, …); nothing in `sync`, `fetch` or `serve`
//! reaches a [`Log`](crate::log::Log) or the store itself. The node
//! validates and admits what arrives (`NodeInner::take`: the judge, then
//! `Log::admit` under the space's lock, the flush ticket, watchers, re-check);
//! this half asks for what the log says is missing (`NodeInner::missing`), and
//! answers what the log says it may serve.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use bytes::Bytes;
use futures::FutureExt;
use ndn_app::Connection;
use ndn_foundation_types::Name;
use ndn_packet::Interest;
use ndn_sync::{
    MultiSvs, ObservedState, ProducerVouch, SvsConfig, SyncHandle, SyncUpdate, spawn_multi_svs,
};
use parking_lot::Mutex;
use tokio::sync::{Notify, mpsc};
use tokio_util::sync::CancellationToken;

use crate::error::HeapError;
use crate::face_up::FaceUp;
use crate::fetch::{self, Asks, Fetcher};
use crate::heard::{HEARD_MAX, Heard};
use crate::herald::Herald;
use crate::host::Extensions;
use crate::log::{Blob, Outcome};
use crate::node::Config;
use crate::register::EntryId;
use crate::reserve::FlushSink;
use crate::rt::Tasks;
use crate::serve::Granting;
use crate::trust::Waiting;
use crate::wire::{EpochId, parse_space_name, sync_group_of};

/// The `tracing` target of the timeline events (level `trace`): the few
/// seams a put crosses on its way to another device's watch, each named by
/// its message so a recorder can lay one put's journey out in time:
/// `put_returns`, `flush_begin`, `flush_end` (the node), `announce`,
/// `sync_update`, `fetch_out`, `fetch_in`, `fetch_miss`, `verify_begin`,
/// `verify_end` (this half) and `watch_send` (the node). Disabled, each
/// costs the callsite check and nothing else; none changes what a node does.
pub(crate) const TIMELINE: &str = "ndn_heap::timeline";

/// What the node made of a packet it was handed to take.
#[derive(Debug)]
pub(crate) enum Taken {
    /// The judge decided and the log took it (or refused it, or knew it).
    /// `blobs` are the entries whose pieces are now to be fetched.
    Decided {
        /// What the log did, or the refusal the judge gave: a refused
        /// packet is not held, and what it was fetched for stays wanted.
        outcome: Outcome,
        /// Entries that carry a value in pieces and were applied.
        blobs: Vec<Blob>,
    },
    /// The judgement waits for something that is not here yet (a context
    /// to adopt, a certificate): the packet is not held, and is fetched
    /// again later.
    Pending(Waiting),
}

/// What the network half holds of the node: the node itself. Tests put the
/// toy host of [`net_kit`] in its place behind a trait object.
#[cfg(not(test))]
pub(crate) type HostRef = Arc<crate::node::NodeInner>;
#[cfg(test)]
pub(crate) type HostRef = Arc<dyn net_kit::Host>;

// -- What the half shares ----------------------------------------------------------------------------

/// What every group and the server share: the node, its tuning, its fetching
/// and what a granter keeps.
pub(crate) struct Shared {
    pub(crate) host: HostRef,
    pub(crate) cfg: Config,
    pub(crate) fetcher: Fetcher,
    pub(crate) grants: Granting,
    /// What the host registered to answer keywords of its own
    /// ([`crate::host::Extension`]).
    pub(crate) extensions: Extensions,
    /// The tasks of the half: the groups', the pumps', the announcement's and the server's
    /// (one per Interest answered). Stopped with the half.
    pub(crate) tasks: Arc<Tasks>,
}

// -- The node's one network half ------------------------------------------------------------------------

/// The network half of a node: one SVS driver over the node's sync face, one
/// group per space joined, the fetching, serving and face-up announcement
/// around them.
pub(crate) struct Net {
    pub(crate) shared: Arc<Shared>,
    svs: Arc<MultiSvs>,
    sync: Arc<dyn Connection>,
    /// The groups joined, by space; the face-up announcement lists their
    /// names.
    groups: Arc<Mutex<BTreeMap<Name, Arc<Group>>>>,
    owners: Mutex<BTreeSet<Name>>,
    stop: CancellationToken,
    face_up: FaceUp,
    /// The driver's end ([`MultiSvs::ended`]).
    svs_ended: CancellationToken,
}

/// What waits for the network half to have ended once it is stopped: every task of it
/// dropped, the SVS driver ended. It holds neither the half nor the node.
pub(crate) struct NetEnd {
    tasks: Arc<Tasks>,
    svs: CancellationToken,
}

impl NetEnd {
    /// Wait until the half's tasks and its driver have ended: nothing of it keeps the node, or
    /// the store the node holds, any more. Call it after [`Net::shutdown`].
    pub(crate) async fn ended(self) {
        self.tasks.ended().await;
        self.svs.cancelled().await;
    }
}

impl Net {
    /// Start the half for the node `host` runs: `fetch` is the node's face
    /// for Interest and Data, `sync` its face for the groups' Sync Interests.
    /// The one SVS driver, the packet pumps between it and `sync`, and the
    /// announcement of a group when a link comes up are started here.
    pub(crate) fn start(
        host: HostRef,
        cfg: Config,
        fetch: Arc<dyn Connection>,
        sync: Arc<dyn Connection>,
    ) -> Arc<Net> {
        let (out_tx, mut out_rx) = mpsc::channel::<Bytes>(256);
        let (in_tx, in_rx) = mpsc::channel::<Bytes>(256);
        let svs = Arc::new(spawn_multi_svs(host.device().clone(), out_tx, in_rx));
        let svs_ended = svs.ended();
        let tasks = Tasks::new();
        let stop = CancellationToken::new();
        {
            let sync = Arc::clone(&sync);
            tasks.spawn(async move {
                while let Some(packet) = out_rx.recv().await {
                    if sync.send(packet).await.is_err() {
                        break;
                    }
                }
            });
        }
        {
            let sync = Arc::clone(&sync);
            tasks.spawn(async move {
                while let Some(packet) = sync.recv().await {
                    if Interest::decode(packet.clone()).is_ok() && in_tx.send(packet).await.is_err()
                    {
                        break;
                    }
                }
            });
        }
        let groups: Arc<Mutex<BTreeMap<Name, Arc<Group>>>> = Arc::default();
        let face_up = FaceUp::spawn(
            Arc::clone(&sync),
            Arc::clone(&tasks),
            {
                let groups = Arc::clone(&groups);
                move || groups.lock().values().map(|g| g.group.clone()).collect()
            },
            {
                let svs = Arc::clone(&svs);
                move |group| {
                    let svs = Arc::clone(&svs);
                    async move {
                        tracing::trace!(target: TIMELINE, %group, "announce");
                        svs.announce(group).await;
                    }
                    .boxed()
                }
            },
        );
        let shared = Arc::new(Shared {
            fetcher: Fetcher::new(
                fetch,
                cfg.lifetime,
                cfg.in_flight.max(cfg.window),
                cfg.window,
            ),
            host,
            cfg,
            grants: Granting::default(),
            extensions: Extensions::default(),
            tasks,
        });
        Arc::new(Net {
            shared,
            svs,
            sync,
            groups,
            owners: Mutex::new(BTreeSet::new()),
            stop,
            face_up,
            svs_ended,
        })
    }

    /// Join the sync group of `space` as a producer named by this device,
    /// whose counter is `counter` now: pass the own head, `Log::head()`, the
    /// highest seq of an entry this device holds. A publication sets the
    /// counter to the seq of its entry ([`Group::sink`]), so a seq that was
    /// never signed is never announced. The sync face registers the owner's
    /// `<O>/32=sync` once, however many of its spaces are joined. Starts the
    /// group's notice loop and fetching; the node calls
    /// [`Group::recover`] before its first publication.
    ///
    /// # Errors
    ///
    /// [`HeapError::BadName`] for a name that is not a space,
    /// [`HeapError::Local`] when the face or the driver refuses.
    pub(crate) async fn join(
        self: &Arc<Self>,
        space: &Name,
        counter: u64,
    ) -> Result<Arc<Group>, HeapError> {
        let (Some(group_name), Some(parsed)) = (sync_group_of(space), parse_space_name(space))
        else {
            return Err(HeapError::not_a_space(space));
        };
        let owner = parsed.owner;
        if self.owners.lock().insert(owner.clone()) {
            let prefix = ndn_security::sync_group(&owner);
            if let Err(e) = self.sync.register_prefix(&prefix).await {
                self.owners.lock().remove(&owner);
                return Err(HeapError::local(format!("cannot receive {prefix}: {e}")));
            }
        }
        // The group's state vector keeps the devices heard: at most
        // `HEARD_MAX` besides this one, a device an admitted entry vouches
        // for never displaced by a name a Sync Interest carried.
        let vouch = {
            let (host, space) = (Arc::clone(&self.shared.host), space.clone());
            ProducerVouch(Arc::new(move |device: &Name| host.vouched(&space, device)))
        };
        let cfg = SvsConfig {
            local_seq: counter,
            max_producers: HEARD_MAX,
            vouch: Some(vouch),
            ..self.shared.cfg.svs.clone()
        };
        let Some(handle) = self.svs.join(group_name.clone(), cfg).await else {
            return Err(HeapError::local(format!(
                "the sync driver did not join {group_name}: it is joined already, or it has stopped"
            )));
        };
        let Some(observed) = handle.observed_shared() else {
            return Err(HeapError::local(format!(
                "the sync driver keeps no observed state for {group_name}; it needs a multi-SVS group"
            )));
        };
        let stop = self.stop.child_token();
        let heard_any = Arc::new(AtomicBool::new(false));
        let herald = Herald::new(
            Arc::clone(&self.svs),
            group_name.clone(),
            self.shared.host.device().clone(),
            Arc::clone(&observed),
            Arc::clone(&heard_any),
            stop.clone(),
            Arc::clone(&self.shared.tasks),
        );
        let group = Arc::new(Group {
            space: space.clone(),
            group: group_name,
            shared: Arc::clone(&self.shared),
            heard: Mutex::new(Heard::default()),
            asks: Mutex::new(Asks::default()),
            certs: Mutex::new(fetch::CertAsks::default()),
            assembling: Mutex::new(HashSet::new()),
            asking: Mutex::new(BTreeSet::new()),
            wake: Notify::new(),
            progress: Notify::new(),
            first_vector: Notify::new(),
            heard_any,
            relist: AtomicBool::new(true),
            own_seen: AtomicU64::new(0),
            stop,
            svs: Arc::clone(&self.svs),
            observed,
            herald,
        });
        self.groups.lock().insert(space.clone(), Arc::clone(&group));
        self.shared.tasks.spawn(notices(Arc::clone(&group), handle));
        self.shared.tasks.spawn(fetch::run(Arc::clone(&group)));
        group.herald.hail();
        Ok(group)
    }

    /// Leave the group of `space`: its tasks end and its driver state goes.
    pub(crate) async fn leave(&self, space: &Name) {
        let group = self.groups.lock().remove(space);
        if let Some(group) = group {
            group.stop.cancel();
            self.svs.leave(group.group.clone()).await;
        }
    }

    /// The group of `space`, if joined.
    pub(crate) fn group(&self, space: &Name) -> Option<Arc<Group>> {
        self.groups.lock().get(space).cloned()
    }

    /// Something changed what `space` wants (a person adopted, a key
    /// arrived, a flush): look again at once.
    pub(crate) fn nudge(&self, space: &Name) {
        if let Some(group) = self.group(space) {
            group.nudge();
        }
    }

    /// Stop the driver, every group, every task and the announcement at once. Idempotent.
    /// The tasks end at their next poll, not before this returns: [`Self::end`] is what
    /// waits for them.
    pub(crate) fn shutdown(&self) {
        self.stop.cancel();
        self.shared.tasks.stop();
        self.face_up.stop();
        self.svs.shutdown();
    }

    /// What waits for this half to have ended, once [`Self::shutdown`] was called.
    pub(crate) fn end(&self) -> NetEnd {
        NetEnd {
            tasks: Arc::clone(&self.shared.tasks),
            svs: self.svs_ended.clone(),
        }
    }
}

impl Drop for Net {
    fn drop(&mut self) {
        self.shutdown();
    }
}

// -- One space's group ----------------------------------------------------------------------------------

/// One joined sync group, and everything asked and heard in it.
pub(crate) struct Group {
    pub(crate) space: Name,
    group: Name,
    pub(crate) shared: Arc<Shared>,
    /// The devices heard, bounded ([`Heard`]).
    pub(crate) heard: Mutex<Heard>,
    /// The asks in flight or pausing.
    pub(crate) asks: Mutex<Asks>,
    /// The certificates a judgement waits for that are being asked of holders and relays.
    pub(crate) certs: Mutex<fetch::CertAsks>,
    /// The values whose pieces are being gathered.
    pub(crate) assembling: Mutex<HashSet<EntryId>>,
    /// The epochs whose key is being asked for.
    pub(crate) asking: Mutex<BTreeSet<EpochId>>,
    /// Look again at what is wanted.
    pub(crate) wake: Notify,
    /// An ask ended.
    pub(crate) progress: Notify,
    /// The first notice arrived.
    pub(crate) first_vector: Notify,
    pub(crate) heard_any: Arc<AtomicBool>,
    /// List the values owed their pieces again.
    pub(crate) relist: AtomicBool,
    pub(crate) stop: CancellationToken,
    svs: Arc<MultiSvs>,
    /// The driver's observed state, to read the own counter from.
    pub(crate) observed: Arc<ObservedState>,
    /// The highest counter of this device's own name the group's carriage
    /// showed, as far as the log was told.
    pub(crate) own_seen: AtomicU64,
    /// Announces this device's own newest entry again while no peer took it.
    pub(crate) herald: Arc<Herald>,
}

/// What the group carries of this device's own name is not a notice: the
/// SVS driver is authoritative for the local name and merges no remote
/// counter into it, so a peer's counter for this device (entries it holds
/// that this device lost) is read from the observed state.
impl Group {
    /// Read the counter of this device's own name the group carries and, when
    /// it rose, take it ([`Self::own_counter`]). Whether it rose.
    pub(crate) fn note_own(&self) -> bool {
        let seen = self.observed.seq_for(self.shared.host.device());
        seen.filter(|seen| *seen > 0)
            .is_some_and(|seen| self.own_counter(seen))
    }

    /// The counter of this device's own name rose to `seen`: the log hears
    /// it (`NodeInner::note_own_counter`: an alert if above the head, the
    /// entries within its reservation wanted), the fetch notes it to probe
    /// the entry it names, and the pump wakes. Whether it rose.
    fn own_counter(&self, seen: u64) -> bool {
        if self.own_seen.fetch_max(seen, Ordering::Relaxed) >= seen {
            return false;
        }
        let host = &self.shared.host;
        host.note_own_counter(&self.space, seen);
        self.heard_any.store(true, Ordering::Relaxed);
        self.first_vector.notify_waiters();
        self.wake.notify_one();
        true
    }

    /// A notice: `update.name` says its counter in this group is
    /// `update.high_seq`. It decides nothing: it is noted, bounded, and the
    /// fetch probes the entry it names. A device at counter 0 has written
    /// nothing and is ignored; a name nothing vouches for never displaces one
    /// that is vouched for; this device's own counter is the log's to alert
    /// on (`NodeInner::note_own_counter`).
    pub(crate) fn on_update(&self, update: SyncUpdate) {
        let host = &self.shared.host;
        let (device, high) = (update.name, update.high_seq);
        tracing::trace!(target: TIMELINE, %device, high, "sync_update");
        self.note_own();
        self.heard_any.store(true, Ordering::Relaxed);
        self.first_vector.notify_waiters();
        if device == *host.device() {
            if high > 0 {
                self.own_counter(high);
            }
            return;
        }
        let hearing = self
            .heard
            .lock()
            .hear(device.clone(), high, |d| host.vouched(&self.space, d));
        if let Some(dropped) = &hearing.dropped {
            self.asks.lock().forget(dropped);
        }
        if !hearing.kept {
            tracing::debug!(%device, high, "not walked: it names no entry, or as many devices are heard in the group already, each vouched for by an admitted entry, and nothing held vouches for this one");
            return;
        }
        self.wake.notify_one();
    }

    /// Look again at what is wanted, and at the values and keys owed.
    pub(crate) fn nudge(&self) {
        self.relist.store(true, Ordering::Relaxed);
        self.wake.notify_one();
    }

    /// The sink that publishes this device's own entries into the group, one
    /// call per seq in order (`reserve::Publisher::spawn`): the counter the
    /// group advertises is then the seq of the entry, never a count of
    /// publications.
    pub(crate) fn sink(&self) -> Arc<dyn FlushSink> {
        Arc::new(Sink {
            group: self.group.clone(),
            svs: Arc::clone(&self.svs),
            herald: Arc::clone(&self.herald),
        })
    }
}

/// Publishes an own entry into the group: the counter becomes its seq.
struct Sink {
    group: Name,
    svs: Arc<MultiSvs>,
    herald: Arc<Herald>,
}

#[async_trait::async_trait]
impl FlushSink for Sink {
    async fn publish(&self, seq: u64) {
        tracing::trace!(target: TIMELINE, seq, "announce");
        self.svs.publish_at(self.group.clone(), seq).await;
        self.herald.announced(seq);
    }
}

/// The notices of a group, until it is left or the driver stops.
async fn notices(group: Arc<Group>, mut handle: SyncHandle) {
    while let Some(Some(update)) = group.stop.run_until_cancelled(handle.recv()).await {
        group.on_update(update);
    }
}

#[cfg(test)]
#[path = "net_kit.rs"]
pub(crate) mod net_kit;

#[cfg(test)]
#[path = "sync_tests.rs"]
mod tests;
