//! The network half of a heap node: sync groups, the notice, direct fetch,
//! catch-up, serving and the grant pull (spec §7).
//!
//! Everything this half needs of the node it asks through [`Host`], a narrow
//! trait the node implements over its spaces; nothing in `sync`, `fetch` or
//! `serve` reaches a [`Log`](crate::log::Log) or the store itself. The node
//! validates and admits what arrives (`Host::take`: the judge, then
//! `Log::admit` under the space's lock, the flush ticket, watchers, re-check);
//! this half asks for what the log says is missing (`Host::missing`), and
//! answers what the log says it may serve.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use futures::FutureExt;
use futures::future::{Either, select};
use ndn_app::Connection;
use ndn_foundation_types::Name;
use ndn_packet::{Data, Interest};
use ndn_sync::{
    MultiSvs, ObservedState, ProducerVouch, StoreOp, SvsConfig, SyncHandle, SyncUpdate,
    spawn_multi_svs,
};
use parking_lot::Mutex;
use tokio::sync::{Notify, mpsc};

use crate::error::HeapError;
use crate::face_up::FaceUp;
use crate::fetch::{self, Asks, Fetcher, Noticed, Recovered};
use crate::heard::{HEARD_MAX, Heard};
use crate::log::{Blob, Outcome, Want};
use crate::register::EntryId;
use crate::reserve::FlushSink;
use crate::rt;
use crate::seal::GrantRefusal;
use crate::serve::Granting;
use crate::trust::{Judged, Waiting};
use crate::wire::{EpochId, parse_space_name, sync_group_of};

/// The `tracing` target of the timeline events (level `trace`): the few
/// seams a put crosses on its way to another device's watch, each named by
/// its message so a recorder can lay one put's journey out in time:
/// `put_returns`, `flush_begin`, `flush_end` (the node), `announce`,
/// `sync_update`, `fetch_out`, `fetch_in`, `fetch_miss`, `verify_begin`,
/// `verify_end` (this half) and `watch_send` (the node). Disabled, each
/// costs the callsite check and nothing else; none changes what a node does.
pub(crate) const TIMELINE: &str = "ndn_heap::timeline";

/// What the network half is tuned by; the node derives it from its `Config`.
#[derive(Clone, Debug)]
pub(crate) struct NetConfig {
    /// The SVS group configuration every group starts from (`local_seq`,
    /// `max_producers` and `vouch` are set per group).
    pub svs: SvsConfig,
    /// How long one Interest lives (default 2 s).
    pub lifetime: Duration,
    /// The most entries of one device asked for at once (default 32).
    pub window: usize,
    /// The most asks of every kind in flight at once on the node (default
    /// 256).
    pub in_flight: usize,
    /// How long a restarting device waits for the first group vector before
    /// it fetches its own entries from its peers (default 1 s).
    pub settle: Duration,
    /// `Config.reserve_block`: own entries are fetched back at most four
    /// blocks above the head.
    pub reserve_block: u64,
}

impl Default for NetConfig {
    fn default() -> Self {
        NetConfig {
            svs: SvsConfig::default(),
            lifetime: Duration::from_secs(2),
            window: 32,
            in_flight: 256,
            settle: Duration::from_secs(1),
            reserve_block: 1024,
        }
    }
}

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

/// Everything the network half needs of the node, and nothing else. `space`
/// is always a space name (`<O>/32=data/…`) the node has open; for a space it
/// does not hold, each method answers with nothing (no wants, no packet, no
/// vouching).
///
/// Methods are synchronous unless they validate, which may fetch
/// certificates. None holds a lock across an `.await`.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub(crate) trait Host: Send + Sync + 'static {
    /// This device.
    fn device(&self) -> &Name;

    // -- admission --------------------------------------------------------------

    /// Take a packet fetched as an entry of `space`: decode it, judge it
    /// (`Judge::validate`), admit it (`Log::admit`) under the space's lock
    /// with everything that follows (flush ticket, publication routing,
    /// watchers, re-check of what it changed). Nothing is applied for a
    /// packet that does not verify.
    async fn take(&self, space: &Name, wire: Bytes) -> Taken;

    // -- what the log wants and knows --------------------------------------------

    /// Everything wanted of `space`: `Log::missing`. It shrinks only by
    /// holding, so a replayed notice never ends an ask.
    fn missing(&self, space: &Name) -> Vec<Want>;

    /// The highest seq heard of `device` in `space` (`Log::high`).
    fn high(&self, space: &Name, device: &Name) -> u64;

    /// This device's own head in `space` (`Log::head`).
    fn head(&self, space: &Name) -> u64;

    /// A notice or vector named `device` at `seen` in `space`
    /// (`Log::note_counter`): it raises what is wanted and nothing else. For
    /// this device's own name above its head the node raises
    /// `Alert::UnbackedCounter`; the head moves only when a verified entry
    /// is taken (D17).
    fn note_counter(&self, space: &Name, device: &Name, seen: u64);

    /// Whether an admitted entry of `device` is held in `space`: what keeps
    /// a device among the devices heard whatever a Sync Interest names.
    fn vouched(&self, space: &Name, device: &Name) -> bool;

    /// How `device` stands as a source for another device's packets
    /// (`Heard::relays`): `None` when it is not vouched for or has ended,
    /// `Some(true)` when its entries were held first.
    fn standing(&self, space: &Name, device: &Name) -> Option<bool>;

    // -- serving ----------------------------------------------------------------

    /// The packet of the entry `<device>/32=log/<space>/seq=<seq>` as this
    /// device may serve it: its own entry at or below its head and not held
    /// back (a structural entry not yet durable), or another device's entry
    /// only if it is held and admitted. `None` otherwise.
    fn served(&self, space: &Name, device: &Name, seq: u64) -> Option<Bytes>;

    /// The piece `piece` (a name under that entry's) of an entry
    /// [`Self::served`] would serve, from the store.
    fn served_piece(&self, space: &Name, device: &Name, seq: u64, piece: &Name) -> Option<Bytes>;

    /// This device's seal key packet when `name` is its name
    /// (`<device>/32=seal/<public key>`).
    fn seal_key_packet(&self, name: &Name) -> Option<Bytes>;

    // -- values in pieces -------------------------------------------------------

    /// The entries of `space` that carry a value in pieces and whose pieces
    /// are not all held: what is fetched at open and asked again while owed.
    fn blobs(&self, space: &Name) -> Vec<Blob>;

    /// All the pieces of `blob`'s entry arrived and proved: write them as one
    /// batch and make the value readable. `payload` is the (sealed, if
    /// sealed) value the proven chunks carry, so that telling the watchers
    /// reads nothing back from the store.
    fn assembled(&self, space: &Name, blob: &Blob, ops: Vec<StoreOp>, payload: Vec<u8>);

    // -- grants, reader side ----------------------------------------------------

    /// The epochs of `space` whose key is owed: a held owner-signed Epoch
    /// entry names it, this device may hold it, it does not, and an entry
    /// waits for it or it is the epoch in force.
    fn owed_keys(&self, space: &Name) -> Vec<EpochId>;

    /// The public half of this device's recipient key: the seal key its
    /// grant asks name.
    fn seal_public(&self) -> [u8; 32];

    /// Judge a packet signed by a device key that is not an entry (a seal
    /// key packet, a grant) for `space`, valid only if the key is
    /// `device`'s (`Judge::validate_device_packet`).
    async fn validate_device_packet(&self, space: &Name, data: &Data, device: &Name) -> Judged;

    /// A grant arrived: unwrap `content` (wrapped under the grant's `name`)
    /// with the recipient key and hold the key for `epoch` if it matches the
    /// check of a held owner-signed Epoch entry (`Log::key_arrived`), which
    /// opens what it unlocks. Whether the key was taken.
    fn key_arrived(&self, space: &Name, epoch: &EpochId, name: &Name, content: Bytes) -> bool;

    // -- grants, granter side ---------------------------------------------------

    /// Whether the key of `epoch` of `space` may be granted to a device
    /// `asker`: all four conditions of `seal::may_grant` for the asker's
    /// person, and an epoch this device made only once its entry is durable.
    fn may_grant(&self, space: &Name, epoch: &EpochId, asker: &Name) -> Result<(), GrantRefusal>;

    /// The grant packet named `name`, wrapping the key of `epoch` to the seal
    /// key `to` of device `asker` and signed by this device: decided again
    /// as [`Self::may_grant`]. `None` when it is refused now or cannot be
    /// signed.
    fn grant_packet(
        &self,
        space: &Name,
        epoch: &EpochId,
        asker: &Name,
        to: &[u8; 32],
        name: &Name,
    ) -> Option<Bytes>;
}

// -- Stopping --------------------------------------------------------------------------------------

/// A flag tasks watch, and a way to wake them to see it.
#[derive(Default)]
pub(crate) struct Stop {
    flag: AtomicBool,
    wake: Notify,
}

impl Stop {
    /// Stop, now and for good.
    pub(crate) fn stop(&self) {
        self.flag.store(true, Ordering::Relaxed);
        self.wake.notify_waiters();
        self.wake.notify_one();
    }

    /// Whether it was stopped.
    pub(crate) fn is_stopped(&self) -> bool {
        self.flag.load(Ordering::Relaxed)
    }

    /// Return once stopped.
    pub(crate) async fn stopped(&self) {
        loop {
            let woken = self.wake.notified();
            if self.is_stopped() {
                return;
            }
            woken.await;
        }
    }
}

// -- What the half shares ----------------------------------------------------------------------------

/// What every group and the server share: the node, its tuning, its fetching
/// and what a granter keeps.
pub(crate) struct Shared {
    pub(crate) host: Arc<dyn Host>,
    pub(crate) cfg: NetConfig,
    pub(crate) fetcher: Fetcher,
    pub(crate) grants: Granting,
}

// -- The node's one network half ------------------------------------------------------------------------

/// The network half of a node: one SVS driver over the node's sync face, one
/// group per space joined, the fetching, serving and face-up announcement
/// around them.
pub(crate) struct Net {
    pub(crate) shared: Arc<Shared>,
    svs: Arc<MultiSvs>,
    sync: Arc<dyn Connection>,
    groups: Mutex<BTreeMap<Name, Arc<Group>>>,
    owners: Mutex<BTreeSet<Name>>,
    /// The names of the sync groups joined, what the face-up announcement
    /// lists.
    names: Arc<Mutex<BTreeSet<Name>>>,
    stop: Arc<Stop>,
    face_up: FaceUp,
}

impl Net {
    /// Start the half for the node `host` runs: `fetch` is the node's face
    /// for Interest and Data, `sync` its face for the groups' Sync Interests.
    /// The one SVS driver, the packet pumps between it and `sync`, and the
    /// announcement of a group when a link comes up are started here.
    pub(crate) fn start(
        host: Arc<dyn Host>,
        cfg: NetConfig,
        fetch: Arc<dyn Connection>,
        sync: Arc<dyn Connection>,
    ) -> Arc<Net> {
        let (out_tx, mut out_rx) = mpsc::channel::<Bytes>(256);
        let (in_tx, in_rx) = mpsc::channel::<Bytes>(256);
        let svs = Arc::new(spawn_multi_svs(host.device().clone(), out_tx, in_rx));
        let stop = Arc::new(Stop::default());
        {
            let (sync, stop) = (Arc::clone(&sync), Arc::clone(&stop));
            rt::spawn(async move {
                while let Either::Left((Some(packet), _)) =
                    select(pin!(out_rx.recv()), pin!(stop.stopped())).await
                {
                    if sync.send(packet).await.is_err() {
                        break;
                    }
                }
            });
        }
        {
            let (sync, stop) = (Arc::clone(&sync), Arc::clone(&stop));
            rt::spawn(async move {
                while let Either::Left((Some(packet), _)) =
                    select(pin!(sync.recv()), pin!(stop.stopped())).await
                {
                    if Interest::decode(packet.clone()).is_ok() && in_tx.send(packet).await.is_err()
                    {
                        break;
                    }
                }
            });
        }
        let names: Arc<Mutex<BTreeSet<Name>>> = Arc::default();
        let face_up = FaceUp::spawn(
            Arc::clone(&sync),
            {
                let names = Arc::clone(&names);
                move || names.lock().iter().cloned().collect()
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
            fetcher: Fetcher::new(fetch, cfg.lifetime, cfg.in_flight),
            host,
            cfg,
            grants: Granting::default(),
        });
        Arc::new(Net {
            shared,
            svs,
            sync,
            groups: Mutex::new(BTreeMap::new()),
            owners: Mutex::new(BTreeSet::new()),
            names,
            stop,
            face_up,
        })
    }

    /// Join the sync group of `space` as a producer named by this device,
    /// whose counter is `counter` now: the first publication is `counter + 1`,
    /// so pass `Log::next_seq() - 1`. The sync face registers the owner's
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
        let bad = |why: &str| HeapError::BadName {
            name: space.clone(),
            why: why.into(),
        };
        let group_name =
            sync_group_of(space).ok_or_else(|| bad("a space is `<owner>/32=data/<path>`"))?;
        let owner = parse_space_name(space)
            .ok_or_else(|| bad("a space is `<owner>/32=data/<path>`"))?
            .owner;
        if self.owners.lock().insert(owner.clone()) {
            let prefix = ndn_security::sync_group(&owner);
            if let Err(e) = self.sync.register_prefix(&prefix).await {
                self.owners.lock().remove(&owner);
                return Err(HeapError::Local {
                    reason: format!("cannot receive {prefix}: {e}"),
                });
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
            return Err(HeapError::Local {
                reason: format!(
                    "the sync driver did not join {group_name}: it is joined already, or it has stopped"
                ),
            });
        };
        let group = Arc::new(Group {
            space: space.clone(),
            group: group_name.clone(),
            shared: Arc::clone(&self.shared),
            heard: Mutex::new(Heard::default()),
            noticed: Mutex::new(BTreeMap::new()),
            asks: Mutex::new(Asks::default()),
            assembling: Mutex::new(HashSet::new()),
            asking: Mutex::new(BTreeSet::new()),
            wake: Notify::new(),
            progress: Notify::new(),
            first_vector: Notify::new(),
            heard_any: AtomicBool::new(false),
            relist: AtomicBool::new(true),
            own_seen: AtomicU64::new(0),
            stop: Stop::default(),
            tx: handle.tx.clone(),
            observed: handle.observed_shared(),
        });
        self.groups.lock().insert(space.clone(), Arc::clone(&group));
        self.names.lock().insert(group_name);
        rt::spawn(notices(Arc::clone(&group), handle));
        rt::spawn(fetch::run(Arc::clone(&group)));
        Ok(group)
    }

    /// Leave the group of `space`: its tasks end and its driver state goes.
    pub(crate) async fn leave(&self, space: &Name) {
        let group = self.groups.lock().remove(space);
        if let Some(group) = group {
            group.stop.stop();
            self.names.lock().remove(&group.group);
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

    /// Stop the driver, every group and the announcement at once. Idempotent.
    pub(crate) fn shutdown(&self) {
        self.stop.stop();
        for group in self.groups.lock().values() {
            group.stop.stop();
        }
        self.face_up.stop();
        self.svs.shutdown();
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
    /// What a notice said of each device heard.
    pub(crate) noticed: Mutex<BTreeMap<Name, Noticed>>,
    /// The asks in flight or pausing.
    pub(crate) asks: Mutex<Asks>,
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
    pub(crate) heard_any: AtomicBool,
    /// List the values owed their pieces again.
    pub(crate) relist: AtomicBool,
    pub(crate) stop: Stop,
    tx: mpsc::Sender<(Name, Option<Bytes>)>,
    observed: Option<Arc<ObservedState>>,
    /// The highest counter of this device's own name the group's carriage
    /// showed, as far as the log was told.
    own_seen: AtomicU64,
}

/// What the group carries of this device's own name is not a notice: the
/// SVS driver is authoritative for the local name and merges no remote
/// counter into it, so a peer's counter for this device (entries it holds
/// that this device lost) is read from the observed state.
impl Group {
    /// Read the counter of this device's own name the group carries and, when
    /// it rose, tell the log ([`Host::note_counter`]: an alert if above the
    /// head, and the entries wanted) and wake the pump. Whether it rose.
    pub(crate) fn note_own(&self) -> bool {
        let Some(observed) = &self.observed else {
            return false;
        };
        let host = &self.shared.host;
        let me = host.device();
        let Some(seen) = observed.seq_for(me).filter(|s| *s > 0) else {
            return false;
        };
        if self.own_seen.fetch_max(seen, Ordering::Relaxed) >= seen {
            return false;
        }
        host.note_counter(&self.space, me, seen);
        self.heard_any.store(true, Ordering::Relaxed);
        self.first_vector.notify_waiters();
        self.wake.notify_one();
        true
    }

    /// Whether the driver keeps observed state to read the own counter from.
    pub(crate) fn observes(&self) -> bool {
        self.observed.is_some()
    }
}
impl Group {
    /// A notice: `update.name` says its counter in this group is
    /// `update.high_seq`. It decides nothing: it is noted, bounded, and the
    /// log's own wants do the rest. A device at counter 0 has written nothing
    /// and is ignored; a name nothing vouches for never displaces one that is
    /// vouched for; this device's own counter is the log's to alert on
    /// ([`Host::note_counter`]).
    pub(crate) fn on_update(&self, update: SyncUpdate) {
        let host = &self.shared.host;
        let (device, high) = (update.name, update.high_seq);
        tracing::trace!(target: TIMELINE, %device, high, "sync_update");
        self.note_own();
        self.heard_any.store(true, Ordering::Relaxed);
        self.first_vector.notify_waiters();
        if device == *host.device() {
            if high > 0 {
                host.note_counter(&self.space, &device, high);
                self.wake.notify_one();
            }
            return;
        }
        let hearing = self
            .heard
            .lock()
            .hear(device.clone(), high, |d| host.vouched(&self.space, d));
        if let Some(dropped) = &hearing.dropped {
            self.noticed.lock().remove(dropped);
            self.asks.lock().forget(dropped);
        }
        if !hearing.kept {
            tracing::debug!(%device, high, "not walked: it names no entry, or as many devices are heard in the group already, each vouched for by an admitted entry, and nothing held vouches for this one");
            return;
        }
        self.noticed.lock().entry(device).or_default().raise(high);
        self.wake.notify_one();
    }

    /// Look again at what is wanted, and at the values and keys owed.
    pub(crate) fn nudge(&self) {
        self.relist.store(true, Ordering::Relaxed);
        self.wake.notify_one();
    }

    /// The sink that publishes this device's own entries into the group, one
    /// call per seq in order (`reserve::Publisher::spawn`).
    pub(crate) fn sink(&self) -> Arc<dyn FlushSink> {
        Arc::new(Sink {
            group: self.group.clone(),
            tx: self.tx.clone(),
        })
    }

    /// Whether the group's state vector holds no device but this one (or the
    /// driver keeps no observed state): nobody to recover from or wait for.
    pub(crate) fn no_peers(&self) -> bool {
        let me = self.shared.host.device();
        self.observed
            .as_ref()
            .is_none_or(|o| o.snapshot().iter().all(|(name, _, _)| name == me))
    }
}

/// Publishes an own entry as one counter step of the group.
struct Sink {
    group: Name,
    tx: mpsc::Sender<(Name, Option<Bytes>)>,
}

#[async_trait::async_trait]
impl FlushSink for Sink {
    async fn publish(&self, seq: u64) {
        tracing::trace!(target: TIMELINE, seq, "announce");
        if self.tx.send((self.group.clone(), None)).await.is_err() {
            tracing::debug!(group = %self.group, seq, "not announced: the group's driver has stopped");
        }
    }
}

/// The notices of a group, until it is left or the driver stops.
async fn notices(group: Arc<Group>, mut handle: SyncHandle) {
    while let Either::Left((Some(update), _)) =
        select(pin!(handle.recv()), pin!(group.stop.stopped())).await
    {
        group.on_update(update);
    }
}

#[cfg(test)]
#[path = "net_kit.rs"]
pub(crate) mod net_kit;

#[cfg(test)]
#[path = "sync_tests.rs"]
mod tests;
