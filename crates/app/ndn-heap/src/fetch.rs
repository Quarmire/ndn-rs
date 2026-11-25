//! Direct fetch of the entry a notice names, catch-up, pieces, and the
//! reader's half of the grant pull (spec §7).
//!
//! **Level-triggered.** This half asks for whatever `NodeInner::missing` lists
//! and stops asking only when the log holds it. A replayed, stale or lower
//! notice therefore never ends an ask, and a device that comes back asks only
//! for what changed.
//!
//! **A notice is a probe, not a want.** The counters of a Sync Interest are
//! unsigned: they raise nothing the log wants. The entry a counter names,
//! `<D>/32=log/<S>/seq=<high>`, is asked for directly and alone while the log
//! holds nothing at or above it (and, for this device, asks nothing up to it
//! within its reservation): its own gap statement may declare everything
//! below it absent, and only once it is held and verified are the holes below
//! it wanted, asked for in a window ([`Window`]: one per device, node-wide, starting small
//! and following what the device answers, whose places an ask that missed keeps while it
//! pauses), in seq order, the first [`hole_reach`] seqs of each hole at a time,
//! minus what a gap statement declared void. A counter nothing signs
//! therefore costs [`FETCH_TRIES`] asks, then asks after a pause that climbs
//! from 4 s to a minute ([`probe_pause`]), so a forger's steady cost is one ask
//! a minute however often the counter rises (the ladder is the device's: a higher counter
//! changes the entry asked, nothing else), and wants nothing of the log. The counter of a
//! device signed data vouches for is paced as a want is ([`retry_pause`]), since it is the
//! one ask that finds the device's newest entry. The node's slots
//! are shared by kind ([`Kind`], [`Slots`]), so probes and a flooded walk leave a grant
//! pull a slot.
//!
//! **Sources.** The writer first, then the heard members vouched for
//! ([`Heard::relays`]) through `<H>/32=held/<name>`, one after another as the
//! asks miss. A miss decides nothing: the ask is made again after a capped
//! backoff ([`retry_pause`]) for as long as the log wants the entry, which is
//! how a forged copy, a lost packet and a silent writer all end. An answer
//! that resolved nothing (a packet the log already knew while it still wants
//! the entry, evidence, or for an entry a removal cut names, other bytes than
//! the cut's) is a miss too.
//!
//! **Own entries.** The entries this device lost are fetched back the same
//! way, from heard members only (never from itself): those within what it
//! reserved as its own counter names them, and above that the one entry the
//! counter names, probed; once that is held, the holes below it, at most four
//! reservation blocks above the head.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::Bytes;
use futures::future::join_all;
use ndn_app::{AppError, Connection, Consumer};
use ndn_foundation_types::{Name, tlv_type};
use ndn_packet::encode::InterestBuilder;
use ndn_packet::{Data, NackReason};
use parking_lot::Mutex;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, SemaphorePermit};

use crate::error::HeapError;
use crate::heard::holders_after;
use crate::log::{Blob, Outcome, Pin};
use crate::pieces::{self, Assembler, Offered};
use crate::register::EntryId;
use crate::rt::{self, Instant};
use crate::sync::{Group, TIMELINE, Taken};
use crate::trust::Waiting;
use crate::wire::{
    ChunksBody, EpochId, GrantAsk, LogName, WireError, grant_name, held_name, log_name,
    parse_log_name, seal_key_name, signed_digest_of,
};

/// The pause before asking again for something after `misses` asks for it
/// missed in a row: this long, doubled each time, at most [`REFRESH_PAUSE_MAX`].
const REFRESH_PAUSE: Duration = Duration::from_millis(250);

/// The longest pause between two asks for the same thing while it is owed.
const REFRESH_PAUSE_MAX: Duration = Duration::from_secs(4);

/// How many asks in a row may miss before the pause becomes [`REFRESH_IDLE`].
const REFRESH_TRIES: u32 = 16;

/// The pause between two asks for what is still owed once [`REFRESH_TRIES`]
/// asks in a row missed: a source away for long costs one ask a minute, until
/// what is owed comes or is no longer owed.
const REFRESH_IDLE: Duration = Duration::from_secs(64);

/// The most asks one thing is asked for in a row where asking again is
/// optional (the first asks of an entry a counter names): each of at most
/// `1 + REEXPRESS_MAX` Interests.
pub(crate) const FETCH_TRIES: u32 = 3;

/// The most times an Interest is expressed again under a fresh nonce within
/// its lifetime when nothing answers it.
const REEXPRESS_MAX: u32 = 3;

/// The least of an Interest's lifetime that must be left for it to be
/// expressed again: a forwarder holds back a fresh-nonce Interest from the same
/// face for up to 250 ms (NFD `RetxSuppressionExponential`), so a shorter gap
/// would be aggregated at the first hop and cost an Interest for nothing.
const RTO_MIN: Duration = Duration::from_millis(250);

/// The retransmission timeout before the node has measured a round trip
/// (RFC 6298 §2.1): a lost first Interest is expressed again after a second,
/// within a lifetime of two, not after it.
const RTO_INITIAL: Duration = Duration::from_secs(1);

/// How many seqs above its own head a device fetches its own entries back,
/// in reservation blocks.
const OWN_BLOCKS: u64 = 4;

/// The most turns [`Group::fetch_entry`] takes: two asks of the writer and two
/// of the heard members that vouch for its log.
const ENTRY_TURNS: u32 = 4;

/// How often the group's observed state is read for a peer's counter of this
/// device's own name while nothing else wakes the pump (a notice for it never
/// comes: the driver merges no remote counter into the local name), and how
/// often a restarting device looks for it within its wait.
const OWN_POLL: Duration = Duration::from_millis(50);

/// The pause before asking again for something after `misses` asks for it
/// missed in a row: [`REFRESH_PAUSE`] · 2^`misses`, at most
/// [`REFRESH_PAUSE_MAX`]; [`REFRESH_IDLE`] from [`REFRESH_TRIES`] misses on.
pub(crate) fn retry_pause(misses: u32) -> Duration {
    if misses >= REFRESH_TRIES {
        return REFRESH_IDLE;
    }
    REFRESH_PAUSE
        .saturating_mul(1 << misses.min(8))
        .min(REFRESH_PAUSE_MAX)
}

/// The longest pause between two asks for the counter of a stranger: a forger costs one ask
/// this often per name, however often its counter rises, and a device that was away and
/// speaks again is asked within it.
const PROBE_PAUSE_MAX: Duration = Duration::from_secs(16);

/// The pause before a probe of a stranger is asked again once [`FETCH_TRIES`] asks missed:
/// [`REFRESH_PAUSE_MAX`] after the last of them, doubled for each further miss, at most
/// [`PROBE_PAUSE_MAX`].
pub(crate) fn probe_pause(misses: u32) -> Duration {
    REFRESH_PAUSE_MAX
        .saturating_mul(1 << misses.saturating_sub(FETCH_TRIES).min(8))
        .min(PROBE_PAUSE_MAX)
}

/// The pause before a counter of a device signed data vouches for is asked again after `misses`
/// asks of its counters missed in a row: a quarter second, since a writer that never pauses
/// names a new entry every few milliseconds and the entry a notice names is often not to be
/// had when it is asked; [`REFRESH_IDLE`] from [`REFRESH_TRIES`] misses on, as a want's asks
/// are. A forged counter for such a device costs [`REFRESH_TRIES`] asks and then one a minute,
/// however often it rises: the run of misses is the device's, not the counter's, and one ask
/// of any counter of it that takes something ends the run.
pub(crate) fn vouched_pause(misses: u32) -> Duration {
    if misses >= REFRESH_TRIES {
        REFRESH_IDLE
    } else {
        REFRESH_PAUSE
    }
}

/// The round-trip estimate from which an unanswered Interest is expressed
/// again (RFC 6298): the smoothed round trip and its variation over the asks
/// answered by their first Interest, and how many asks since the last such
/// answer needed a re-expression or missed. An ask answered after a
/// re-expression gives no sample (Karn: which Interest was answered is not
/// known). Before any sample the timeout is [`RTO_INITIAL`], as RFC 6298 §2.1
/// has it.
#[derive(Debug, Default)]
pub(crate) struct Rtt {
    srtt: Option<Duration>,
    rttvar: Duration,
    backoff: u32,
}

impl Rtt {
    /// Take the round trip of an ask answered by its first Interest.
    pub(crate) fn sample(&mut self, r: Duration) {
        match self.srtt {
            None => {
                self.srtt = Some(r);
                self.rttvar = r / 2;
            }
            Some(srtt) => {
                self.rttvar = (self.rttvar * 3 + srtt.abs_diff(r)) / 4;
                self.srtt = Some((srtt * 7 + r) / 8);
            }
        }
        self.backoff = 0;
    }

    /// An ask needed a re-expression, or nothing answered it: the next
    /// waits twice as long, until an ask gives a sample again.
    pub(crate) fn missed(&mut self) {
        self.backoff = (self.backoff + 1).min(16);
    }

    /// The wait before expressing an unanswered Interest again: srtt +
    /// 4·rttvar ([`RTO_INITIAL`] before any sample), doubled per
    /// [`Self::missed`] since the last sample, at least [`RTO_MIN`] and at
    /// most `lifetime`.
    pub(crate) fn rto(&self, lifetime: Duration) -> Duration {
        self.srtt
            .map_or(RTO_INITIAL, |srtt| srtt + self.rttvar * 4)
            .saturating_mul(1 << self.backoff)
            .clamp(RTO_MIN, lifetime.max(RTO_MIN))
    }
}

/// The most devices a node keeps a round-trip estimate or a window of: the devices it asks are
/// the ones it heard, bounded per group, so this is a bound on memory, not a limit anyone
/// meets.
const RTTS_MAX: usize = 256;

/// Per-device state of a node, at most [`RTTS_MAX`] devices. A device not in the table is
/// made when it is first used; when the table is full that drops the device used least
/// recently, so names that others invent never reset what was measured of a device in use.
#[derive(Debug)]
struct Recent<V> {
    by: BTreeMap<Name, (u64, V)>,
    tick: u64,
}

impl<V> Default for Recent<V> {
    fn default() -> Self {
        Recent {
            by: BTreeMap::new(),
            tick: 0,
        }
    }
}

impl<V: Default> Recent<V> {
    /// The state of `device` if there is one, which is then the one used last.
    fn used(&mut self, device: &Name) -> Option<&mut V> {
        self.tick += 1;
        let tick = self.tick;
        self.by.get_mut(device).map(|(at, v)| {
            *at = tick;
            v
        })
    }

    /// The state of `device`, made if there is none, and the one used last.
    fn of(&mut self, device: &Name) -> &mut V {
        self.tick += 1;
        let tick = self.tick;
        if !self.by.contains_key(device) && self.by.len() >= RTTS_MAX {
            let oldest = self
                .by
                .iter()
                .min_by_key(|(_, (at, _))| *at)
                .map(|(device, _)| device.clone());
            if let Some(oldest) = oldest {
                self.by.remove(&oldest);
            }
        }
        let (at, v) = self.by.entry(device.clone()).or_default();
        *at = tick;
        v
    }

    /// The state of `device` without counting it as used.
    fn peek(&self, device: &Name) -> Option<&V> {
        self.by.get(device).map(|(_, v)| v)
    }
}

/// The round-trip estimates of a node, one per device it asks (the writer of an entry, or the
/// holder that is asked for a copy): a device that is away answers nothing and its asks, timing
/// out one after another, double the wait before an Interest is expressed again — that
/// is no reason to wait longer for another device that answers.
#[derive(Debug, Default)]
pub(crate) struct Rtts {
    by: Recent<Rtt>,
}

impl Rtts {
    /// The device `name` is asked of: the name before its first keyword (`<D>/32=log/…`,
    /// `<H>/32=held/…`, `<G>/32=grant/…`, `<D>/32=seal/…` all name their device first).
    fn device(name: &Name) -> Name {
        Name::from_components(
            name.components()
                .iter()
                .take_while(|c| c.typ != tlv_type::KEYWORD)
                .cloned(),
        )
    }

    /// The wait before an Interest for `name` is expressed again ([`Rtt::rto`] of its device).
    pub(crate) fn rto(&mut self, name: &Name, lifetime: Duration) -> Duration {
        self.by
            .used(&Self::device(name))
            .map_or(RTO_INITIAL, |rtt| rtt.rto(lifetime))
            .clamp(RTO_MIN, lifetime.max(RTO_MIN))
    }

    /// Take the round trip of an ask for `name` answered by its first Interest.
    pub(crate) fn sample(&mut self, name: &Name, r: Duration) {
        self.by.of(&Self::device(name)).sample(r);
    }

    /// An ask for `name` needed a re-expression, or nothing answered it.
    pub(crate) fn missed(&mut self, name: &Name) {
        self.by.of(&Self::device(name)).missed();
    }
}

/// The asks of one device that a node has in flight at once, as far as the device has answered
/// them: it starts at [`WINDOW_INITIAL`], grows by one with each ask answered (so it doubles
/// each round), and halves, at least to [`WINDOW_MIN`], after a round in which more asks timed
/// out than were answered. A round is as many answered or timed-out asks as the window is
/// wide. Loss is not silence: a path that loses a third of its asks answers more than it
/// misses and keeps its window; a device that answers nothing is down to the minimum after a
/// few rounds, however many seqs lie below its newest entry. A reply that is not genuine says
/// nothing of the device's reach and counts neither way.
///
/// A Congestion Nack is the path saying it is over a rate (a link's quota of what one key may
/// ask or be answered): the window halves, at least to [`WINDOW_MIN`], at once, **once for
/// all the asks that were in flight** (an ask carries the number of cuts the window had when
/// it began, and a Nack of an ask that began before the last cut says what the cut already
/// answered). From then on the window grows by one a round, not one an ask answered, until it
/// is cut again: a window that doubled back every round would meet the rate again and again,
/// each time with a Nack for every ask over it, and a link Nacks only so many a second.
#[derive(Debug)]
struct Window {
    size: usize,
    answered: usize,
    missed: usize,
    /// How many times a Congestion Nack cut the window.
    cuts: u64,
    /// After a cut: the size from which the window grows by one a round.
    threshold: Option<usize>,
    /// The asks answered since the window last grew by a round's step.
    credit: usize,
}

/// The first window of a device: sized for a hole of some hundreds of entries, not a cold start
/// of one.
const WINDOW_INITIAL: usize = 16;

/// The least window of a device that answers nothing: its asks, one after another, are what
/// tells that it answers again.
const WINDOW_MIN: usize = 2;

impl Default for Window {
    fn default() -> Self {
        Window {
            size: WINDOW_INITIAL,
            answered: 0,
            missed: 0,
            cuts: 0,
            threshold: None,
            credit: 0,
        }
    }
}

impl Window {
    /// The window, at most `cap`.
    fn size(&self, cap: usize) -> usize {
        self.size.min(cap).max(1)
    }

    /// An ask was answered.
    fn answer(&mut self, cap: usize) {
        if self.threshold.is_some_and(|t| self.size >= t) {
            self.credit += 1;
            if self.credit >= self.size {
                self.credit = 0;
                self.size = (self.size + 1).min(cap);
            }
        } else {
            self.size = (self.size + 1).min(cap);
        }
        self.answered += 1;
        self.round(cap);
    }

    /// An ask timed out.
    fn miss(&mut self, cap: usize) {
        self.missed += 1;
        self.round(cap);
    }

    /// How many times the window was cut by a Congestion Nack: what an ask carries from its
    /// start to tell [`Self::congested`] which cut it began after.
    fn cuts(&self) -> u64 {
        self.cuts
    }

    /// An ask that began when the window had been cut `began_after` times was Nacked
    /// Congestion.
    fn congested(&mut self, cap: usize, began_after: u64) {
        if began_after != self.cuts {
            return;
        }
        self.cuts += 1;
        self.size = (self.size(cap) / 2).max(WINDOW_MIN);
        self.threshold = Some(self.size);
        self.credit = 0;
        (self.answered, self.missed) = (0, 0);
    }

    /// End the round when it is as long as the window.
    fn round(&mut self, cap: usize) {
        if self.answered + self.missed < self.size(cap) {
            return;
        }
        if self.missed > self.answered {
            self.size = (self.size / 2).max(WINDOW_MIN).min(cap);
        }
        (self.answered, self.missed) = (0, 0);
    }
}

/// What an ask is for: which of the node's slots it may take.
#[derive(Clone, Debug)]
pub(crate) enum Kind {
    /// An entry or a piece of `device` that the log or an assembly wants: its asks share the
    /// device's window and its share of the node's slots, whatever space or value they are for.
    Walk(Name),
    /// The entry a counter names: a few at once per group and per node, so that counters
    /// anyone can send never fill the slots wants and grants wait for.
    Probe,
    /// A key pulled or granted, a seal key fetched: it takes from the slots the walks and the
    /// probes leave.
    Pull,
}

/// The node's slots, by what they are for. Walks take at most three quarters of them, one
/// device's walks at most half, probes an eighth: a grant pull, a seal key and the first
/// probe of a new device always find a slot, whoever floods the walks.
struct Slots {
    all: Semaphore,
    walks: Semaphore,
    probes: Semaphore,
    /// The slots of each device being walked now; a device is dropped from the table when it
    /// holds none.
    devices: Mutex<BTreeMap<Name, Arc<Semaphore>>>,
    per_device: usize,
}

/// A slot taken: given back when dropped.
struct Slot<'a> {
    _device: Option<OwnedSemaphorePermit>,
    _class: Option<SemaphorePermit<'a>>,
    _all: SemaphorePermit<'a>,
}

impl Slots {
    /// The slots of a node with `in_flight`, and a device's window of at most `window`.
    fn new(in_flight: usize, window: usize) -> Slots {
        let all = in_flight.max(1);
        Slots {
            all: Semaphore::new(all),
            walks: Semaphore::new((all - all / 4).max(1)),
            probes: Semaphore::new((all / 8).max(1)),
            devices: Mutex::new(BTreeMap::new()),
            per_device: window.min(all / 2).max(1),
        }
    }

    /// The most asks of one device in flight at once.
    fn per_device(&self) -> usize {
        self.per_device
    }

    /// The semaphore of `device`'s slots.
    fn device(&self, device: &Name) -> Arc<Semaphore> {
        let mut devices = self.devices.lock();
        if let Some(semaphore) = devices.get(device) {
            return Arc::clone(semaphore);
        }
        if devices.len() >= RTTS_MAX {
            devices.retain(|_, semaphore| Arc::strong_count(semaphore) > 1);
        }
        let semaphore = Arc::new(Semaphore::new(self.per_device));
        devices.insert(device.clone(), Arc::clone(&semaphore));
        semaphore
    }

    /// The slots `kind` may take, waiting for each: `None` when the node's slots are closed.
    async fn take(&self, kind: &Kind) -> Option<Slot<'_>> {
        let device = match kind {
            Kind::Walk(device) => Some(self.device(device).acquire_owned().await.ok()?),
            Kind::Probe | Kind::Pull => None,
        };
        let class = match kind {
            Kind::Walk(_) => Some(self.walks.acquire().await.ok()?),
            Kind::Probe => Some(self.probes.acquire().await.ok()?),
            Kind::Pull => None,
        };
        let all = self.all.acquire().await.ok()?;
        Some(Slot {
            _device: device,
            _class: class,
            _all: all,
        })
    }
}

/// Why an ask brought no packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Miss {
    /// Asking again may get it: nothing answered in time, the Interest was
    /// dropped for rate, the node was busy.
    Again,
    /// The answer was "not here": a Nack other than for rate, or the
    /// connection ended. Asking another holder may still get it.
    Gone,
}

/// The most values whose pieces the node gathers at once.
pub(crate) const ASSEMBLIES_MAX: usize = 4;

/// How a turn of an assembly ended.
enum Gathered {
    /// Every piece is held and the value is recorded whole.
    Whole,
    /// The value cannot be gathered (a size no entry may declare), or the
    /// group stopped: no turn comes again.
    Refused,
    /// A round brought nothing, or nobody is known to ask; whether any
    /// piece was proved in the turn.
    Stuck { progressed: bool },
}

/// The node's Interests: its slots, its round-trip estimates and windows, its face.
pub(crate) struct Fetcher {
    conn: Arc<dyn Connection>,
    lifetime: Duration,
    slots: Slots,
    assemblies: Semaphore,
    rtt: Mutex<Rtts>,
    windows: Mutex<Recent<Window>>,
}

impl Fetcher {
    /// A fetcher over `conn` with `in_flight` slots, expressing Interests of
    /// `lifetime`; one device's window is at most `window` and half of the slots.
    pub(crate) fn new(
        conn: Arc<dyn Connection>,
        lifetime: Duration,
        in_flight: usize,
        window: usize,
    ) -> Fetcher {
        Fetcher {
            conn,
            lifetime,
            slots: Slots::new(in_flight, window),
            assemblies: Semaphore::new(ASSEMBLIES_MAX),
            rtt: Mutex::new(Rtts::default()),
            windows: Mutex::new(Recent::default()),
        }
    }

    /// How many asks of `device` the node has in flight at once now ([`Window`]).
    pub(crate) fn window(&self, device: &Name) -> usize {
        let cap = self.slots.per_device();
        self.windows
            .lock()
            .peek(device)
            .map_or_else(|| WINDOW_INITIAL.min(cap).max(1), |w| w.size(cap))
    }

    /// The slots `kind` may take, waiting at most one Interest lifetime for all of them: a
    /// queue of fetches others made never holds a slot longer than the Interest it waits to
    /// send would have lived. [`Miss::Again`]: the slots stayed taken, so the node is busy,
    /// not the packet absent.
    async fn slot(&self, kind: &Kind) -> Result<Slot<'_>, Miss> {
        match rt::timeout(self.lifetime, self.slots.take(kind)).await {
            Ok(Some(slot)) => Ok(slot),
            Ok(None) => Err(Miss::Gone),
            Err(_) => {
                tracing::debug!(
                    ?kind,
                    "fetch not sent: the fetch slots it may take stayed taken for an Interest lifetime ({:?}); it is asked again after its pause, or raise Config::in_flight",
                    self.lifetime
                );
                Err(Miss::Again)
            }
        }
    }

    /// A turn at gathering the pieces of one value: at most
    /// [`ASSEMBLIES_MAX`] are held at once on the node, so what is in
    /// flight for pieces never grows with the values owed. Waits for as long
    /// as it takes: a value waiting has nothing in memory.
    async fn assembly_turn(&self) -> tokio::sync::SemaphorePermit<'_> {
        self.assemblies
            .acquire()
            .await
            .expect("the assembly semaphore is never closed")
    }

    /// An ask of the walk of `kind`'s device was answered or timed out: its window learns.
    fn learn(&self, kind: &Kind, answered: bool) {
        let Kind::Walk(device) = kind else { return };
        let cap = self.slots.per_device();
        let mut windows = self.windows.lock();
        let window = windows.of(device);
        if answered {
            window.answer(cap);
        } else {
            window.miss(cap);
        }
    }

    /// How many times the window of `kind`'s device was cut by a Congestion Nack so far
    /// (zero for asks that have no window): taken when an ask begins.
    fn cuts(&self, kind: &Kind) -> u64 {
        let Kind::Walk(device) = kind else { return 0 };
        self.windows.lock().peek(device).map_or(0, Window::cuts)
    }

    /// An ask of `kind` that began after `cuts` cuts was Nacked Congestion: the window of its
    /// device is cut, once for the asks in flight ([`Window`]).
    fn congested(&self, kind: &Kind, cuts: u64) {
        let Kind::Walk(device) = kind else { return };
        let cap = self.slots.per_device();
        self.windows.lock().of(device).congested(cap, cuts);
    }

    /// One ask within one Interest lifetime: an Interest nothing answered
    /// within the retransmission timeout ([`Rtt::rto`]) is expressed again
    /// under a fresh nonce, the timeout doubling each time, at most
    /// [`REEXPRESS_MAX`] times. A Nack with reason Congestion is asked again
    /// by the consumer after a short jittered pause
    /// ([`Consumer::fetch_reexpressing_noting`]), and the window of the
    /// device is cut at it when the ask went `direct`ly to the device (the writer's own
    /// path). An ask through a heard member's copy (`<H>/32=held/..`) says nothing of the
    /// path to the writer, and a holder that Nacks must not hold a good writer's window
    /// down. The packet is unverified: the caller hands it to the node.
    pub(crate) async fn once(&self, name: Name, kind: &Kind, direct: bool) -> Result<Data, Miss> {
        let _slot = self.slot(kind).await?;
        let rto = self.rtt.lock().rto(&name, self.lifetime);
        let cuts = self.cuts(kind);
        tracing::trace!(target: TIMELINE, %name, "fetch_out");
        let asked = Instant::now();
        let nacked = std::sync::atomic::AtomicU32::new(0);
        let fetched = Consumer::new(Arc::clone(&self.conn))
            .fetch_reexpressing_noting(
                || InterestBuilder::new(name.clone()),
                self.lifetime,
                RTO_MIN,
                (0..REEXPRESS_MAX).map(|k| rto.saturating_mul(1 << k)),
                || {
                    nacked.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if direct {
                        self.congested(kind, cuts);
                    }
                },
            )
            .await;
        match fetched {
            Ok((data, expressed)) => {
                tracing::trace!(target: TIMELINE, %name, expressed, "fetch_in");
                self.learn(kind, true);
                let mut rtt = self.rtt.lock();
                // Only the first Interest's round trip is a sample, and only the timer's
                // re-expressions are the path being slow or lossy: the ones a Nack made
                // say the path is over a rate, which the window answers.
                if expressed == 1 {
                    rtt.sample(&name, asked.elapsed());
                } else if expressed > 1 + nacked.load(std::sync::atomic::Ordering::Relaxed) {
                    rtt.missed(&name);
                }
                Ok(data)
            }
            Err(e) => {
                tracing::trace!(target: TIMELINE, %name, "fetch_miss");
                tracing::trace!(%name, "fetch missed: {e}");
                Err(match e {
                    AppError::Timeout => {
                        self.learn(kind, false);
                        self.rtt.lock().missed(&name);
                        Miss::Again
                    }
                    // A reply that does not verify was forged or altered on the
                    // way: final for that packet, not for the name, whose
                    // genuine packet asking again may get.
                    AppError::Refused { reason } => {
                        if reason == ndn_packet::Refusal::BadSignature || !reason.is_final() {
                            Miss::Again
                        } else {
                            Miss::Gone
                        }
                    }
                    // Dropped for rate and asking again soon already failed: not an
                    // answer, and the path's word that the window is too wide.
                    AppError::Nacked {
                        reason: Some(NackReason::Congestion),
                    } => {
                        if direct {
                            self.congested(kind, cuts);
                        }
                        Miss::Again
                    }
                    _ => Miss::Gone,
                })
            }
        }
    }
}

// -- What is asked for ---------------------------------------------------------------------------

/// Whom an ask goes to.
#[derive(Clone, Debug)]
pub(crate) enum Source {
    /// The device that wrote the packet, by its own name.
    Writer,
    /// A heard member, vouched for, through `<H>/32=held/<name>`.
    Relay(Name),
}

/// One ask: how many asks of it missed in a row, and when it may be made
/// again (`None`: one is in flight).
struct Ask {
    misses: u32,
    until: Option<Instant>,
}

/// The probe of one device: the entry its counter names, asked alone. The ladder of misses
/// and pauses belongs to the device, not to the counter: a higher counter changes the entry
/// asked ([`Self::seq`]) and nothing else, so counters that rise without end (an unsigned
/// vector costs nothing to send) cost the one ladder, never an ask each.
struct Probe {
    /// The newest counter named: the entry the next ask is for.
    seq: u64,
    /// How many asks of the device's counters missed in a row.
    misses: u32,
    /// Before this no ask is made: the pause after a miss.
    until: Instant,
    /// The counters asked now.
    flying: BTreeSet<u64>,
}

/// The most counters of one vouched device asked at once ([`Asks::probe`]).
const PROBE_FLIGHTS: usize = 4;

/// The most hole tops of one device asked at once, beside its window ([`Asks::walk`]).
const HOLE_TOPS: usize = 4;

/// What of the undeclared holes of one device is asked now.
struct Holes {
    /// The first seqs of each hole, a window deep or a block ([`reach`]).
    reach: Vec<(u64, u64)>,
    /// The highest seq of each hole, ascending: the entry the chain of the held entry above
    /// it names (§7.4).
    tops: Vec<u64>,
}

impl Holes {
    /// The tops asked first and beside the window: those of the lowest [`HOLE_TOPS`] holes.
    /// A pure function of the holes, so the lane never holds a place the window needs and
    /// the tops of the other holes are asked as the window gets to them.
    fn lane(&self) -> &[u64] {
        &self.tops[..self.tops.len().min(HOLE_TOPS)]
    }
}

/// The most hops of a signer's chain asked for as held copies in one pass (the validator's
/// chain is at most five deep).
const CHAIN_HOPS: usize = 6;

/// The most certificate names asked of holders and relays at once or pausing on a group.
const CERT_ASKS_MAX: usize = 64;

/// The certificates a judgement waits for that are asked as held copies ([`Group::complete_chain`]),
/// by name: one ask of a name at a time however many entries wait for it, and after a miss a
/// pause that doubles like any ask's ([`retry_pause`]), so that a name nobody serves costs one
/// round of asks per pause and not one per entry. The names come from entries fetched and not
/// yet judged, which anyone who is asked may have forged: at most [`CERT_ASKS_MAX`] are kept.
#[derive(Default)]
pub(crate) struct CertAsks {
    by: BTreeMap<Name, CertAsk>,
}

/// Where the ask of one certificate stands: how many rounds missed in a row, and when it may
/// be made again (`None`: a round is in flight).
struct CertAsk {
    misses: u32,
    until: Option<Instant>,
}

impl CertAsks {
    /// Whether the caller may ask for `name` now; it then owns the round until [`Self::end`].
    fn claim(&mut self, name: &Name, now: Instant) -> bool {
        if let Some(ask) = self.by.get_mut(name) {
            return match ask.until {
                Some(until) if until <= now => {
                    ask.until = None;
                    true
                }
                _ => false,
            };
        }
        self.by
            .retain(|_, ask| ask.until.is_none() || ask.until.is_some_and(|u| u > now));
        if self.by.len() >= CERT_ASKS_MAX {
            return false;
        }
        self.by.insert(
            name.clone(),
            CertAsk {
                misses: 0,
                until: None,
            },
        );
        true
    }

    /// The round for `name` ended; `taken`: it brought a certificate that moved the chain on.
    fn end(&mut self, name: &Name, taken: bool, now: Instant) {
        if taken {
            self.by.remove(name);
            return;
        }
        if let Some(ask) = self.by.get_mut(name) {
            ask.until = Some(now + retry_pause(ask.misses));
            ask.misses = ask.misses.saturating_add(1);
        }
    }
}

/// The most probes of one group in flight at once: a group has at most
/// [`HEARD_MAX`](crate::heard::HEARD_MAX) devices heard, and the probes of devices nothing
/// vouches for are for names anyone can send, so the others wait their turn (the devices
/// with the fewest misses first, vouched ones before the rest).
pub(crate) const PROBES_MAX: usize = 8;

/// Where the ask of a seq stands.
enum Standing {
    /// Never asked, or forgotten.
    New,
    /// In flight.
    Flying,
    /// Pausing for this much longer.
    Waiting(Duration),
    /// Its pause is over; it missed this many times in a row.
    Due(u32),
}

/// Every ask that is in flight or pausing, by `(device, seq)`, and the probe of each device
/// whose counter names an entry the log neither holds nor asks for. Entries are dropped once
/// the log no longer wants what they are for.
#[derive(Default)]
pub(crate) struct Asks {
    by: BTreeMap<(Name, u64), Ask>,
    probes: BTreeMap<Name, Probe>,
}

/// The keys of `device` among the asks.
fn span(device: &Name) -> std::ops::RangeInclusive<(Name, u64)> {
    (device.clone(), 0)..=(device.clone(), u64::MAX)
}

/// Lower `next`, the time to look again, to `left`.
fn look_again(next: &mut Option<Duration>, left: Duration) {
    *next = Some(next.map_or(left, |n| n.min(left)));
}

impl Asks {
    /// Where the ask of `key` stands at `now`.
    fn standing(&self, key: &(Name, u64), now: Instant) -> Standing {
        match self.by.get(key) {
            None => Standing::New,
            Some(Ask { until: None, .. }) => Standing::Flying,
            Some(Ask {
                until: Some(until), ..
            }) if *until > now => Standing::Waiting(*until - now),
            Some(ask) => Standing::Due(ask.misses),
        }
    }

    /// The asks of `device` in flight, and those that hold a place in its window: in flight, or
    /// pausing before they have missed [`REFRESH_TRIES`] times in a row (one that has waits
    /// idle, a minute at a time, and holds a place only while it is asked). The asks of the
    /// hole tops `tops` are the lane's, not the window's ([`Self::walk`]).
    fn busy(&self, device: &Name, tops: &[u64]) -> (usize, usize) {
        let (mut flying, mut busy) = (0, 0);
        let asks = self.by.range(span(device));
        for ask in asks.filter(|((_, s), _)| tops.binary_search(s).is_err()) {
            let ask = ask.1;
            if ask.until.is_none() {
                flying += 1;
                busy += 1;
            } else if ask.misses < REFRESH_TRIES {
                busy += 1;
            }
        }
        (flying, busy)
    }

    /// Enter the ask of `(device, seq)` as in flight.
    fn launch(&mut self, device: &Name, seq: u64, misses: u32, digest: Option<Pin>) -> Launch {
        self.by.insert(
            (device.clone(), seq),
            Ask {
                misses,
                until: None,
            },
        );
        Launch {
            device: device.clone(),
            seq,
            misses,
            probe: false,
            vouched: true,
            digest,
        }
    }

    /// The asks of the holes of `device` in `holes`, in seq order, at most `window` of them
    /// in flight or pausing at once: an ask that missed holds its place while it pauses, so the
    /// walk does not slide over the seqs nothing answers. Those due again go first.
    ///
    /// The tops of the lowest [`HOLE_TOPS`] holes ([`Holes::lane`]), the entries a held
    /// entry's chain names (§7.4), are asked **first** and **beside** the window: whatever
    /// the window holds, a window of asks from the bottom that nothing answers never keeps the
    /// one entry that may declare a hole void from being asked. The other tops are seqs of the
    /// window like any.
    fn walk(
        &mut self,
        device: &Name,
        holes: &Holes,
        window: usize,
        now: Instant,
        next: &mut Option<Duration>,
        out: &mut Vec<Launch>,
    ) {
        let (ranges, tops) = (&holes.reach[..], holes.lane());
        for &seq in tops {
            match self.standing(&(device.clone(), seq), now) {
                Standing::Flying => {}
                Standing::Waiting(left) => look_again(next, left),
                Standing::Due(misses) => out.push(self.launch(device, seq, misses, None)),
                Standing::New => out.push(self.launch(device, seq, 0, None)),
            }
        }
        let (mut flying, busy) = self.busy(device, tops);
        let mut budget = window.saturating_sub(busy);
        let known: Vec<u64> = self.by.range(span(device)).map(|((_, s), _)| *s).collect();
        let bottom = |s: &u64| tops.binary_search(s).is_err();
        for &seq in known.iter().filter(|s| bottom(s) && within(ranges, **s)) {
            match self.standing(&(device.clone(), seq), now) {
                Standing::Waiting(left) => look_again(next, left),
                Standing::Due(misses) if flying < window => {
                    if misses >= REFRESH_TRIES {
                        if budget == 0 {
                            continue;
                        }
                        budget -= 1;
                    }
                    flying += 1;
                    out.push(self.launch(device, seq, misses, None));
                }
                _ => {}
            }
        }
        for seq in ranges.iter().flat_map(|&(a, b)| a..=b).filter(bottom) {
            if budget == 0 {
                break;
            }
            if known.binary_search(&seq).is_ok() {
                continue;
            }
            budget -= 1;
            out.push(self.launch(device, seq, 0, None));
        }
    }

    /// The asks of the entries a cut names for `device` (`exact`, in seq order, each with the
    /// bytes it must have), within the device's `window` as a walk's asks are: at most `window`
    /// in flight or pausing at once, those that missed keeping their place, those due again
    /// first. A cut that names thousands holds the window of one device and no more.
    fn walk_exact(
        &mut self,
        device: &Name,
        exact: &[(u64, Pin)],
        window: usize,
        now: Instant,
        next: &mut Option<Duration>,
        out: &mut Vec<Launch>,
    ) {
        let (mut flying, busy) = self.busy(device, &[]);
        let mut budget = window.saturating_sub(busy);
        let mut fresh = Vec::new();
        for &(seq, pin) in exact {
            match self.standing(&(device.clone(), seq), now) {
                Standing::Flying => {}
                Standing::Waiting(left) => look_again(next, left),
                Standing::Due(misses) if flying < window => {
                    if misses >= REFRESH_TRIES {
                        if budget == 0 {
                            continue;
                        }
                        budget -= 1;
                    }
                    flying += 1;
                    out.push(self.launch(device, seq, misses, Some(pin)));
                }
                Standing::Due(_) => {}
                Standing::New => fresh.push((seq, pin)),
            }
        }
        for (seq, pin) in fresh {
            if budget == 0 {
                break;
            }
            budget -= 1;
            out.push(self.launch(device, seq, 0, Some(pin)));
        }
    }

    /// The probes to make now, for the entries `named` (a device and the entry its counter
    /// names): the probe of a device not named any more is dropped unless one is in flight,
    /// the entry a probe asks is the counter's as it stands, at most [`PROBES_MAX`] are in
    /// flight, and of one device a stranger's one at a time and a vouched device's at most
    /// [`PROBE_FLIGHTS`] (its counter rises as it writes, and the entry the notice names is
    /// often not to be had yet when it is asked: a reader that follows a writer that never
    /// pauses learns where the writer is by many asks of its counters, not by one). Asks of
    /// a device whose last asks missed wait out their pause ([`Self::end`]). `vouched` says
    /// whether signed data vouches for a device.
    fn probe(
        &mut self,
        named: &[(Name, u64)],
        vouched: impl Fn(&Name) -> bool,
        now: Instant,
        next: &mut Option<Duration>,
        out: &mut Vec<Launch>,
    ) {
        self.probes
            .retain(|d, p| !p.flying.is_empty() || named.iter().any(|(n, _)| n == d));
        for (device, high) in named {
            self.probes
                .entry(device.clone())
                .or_insert(Probe {
                    seq: *high,
                    misses: 0,
                    until: now,
                    flying: BTreeSet::new(),
                })
                .seq = *high;
        }
        let mut flying: usize = self.probes.values().map(|p| p.flying.len()).sum();
        let mut due: Vec<(u32, bool, Name)> = Vec::new();
        for (device, probe) in &self.probes {
            let stranger = !vouched(device);
            let flights = if stranger { 1 } else { PROBE_FLIGHTS };
            if probe.flying.len() >= flights || probe.flying.contains(&probe.seq) {
                continue;
            }
            if probe.until > now {
                look_again(next, probe.until - now);
            } else {
                due.push((probe.misses, stranger, device.clone()));
            }
        }
        due.sort();
        for (_, stranger, device) in due {
            if flying >= PROBES_MAX {
                break;
            }
            flying += 1;
            if let Some(probe) = self.probes.get_mut(&device) {
                probe.flying.insert(probe.seq);
                out.push(Launch {
                    seq: probe.seq,
                    misses: probe.misses,
                    device,
                    probe: true,
                    vouched: !stranger,
                    digest: None,
                });
            }
        }
    }

    /// The ask of `launch` ended, `resolved` or not (`answered`: a packet came, whatever the
    /// node made of it): how many asks of it missed in a row now, and how long it pauses. A
    /// walk's ask pauses by [`retry_pause`] after a miss and [`REFRESH_PAUSE`] after what
    /// resolved it. The asks of the counters of a device signed data vouches for miss in a row
    /// as the device's, not the counter's: any ask of it that took something ends the run. A
    /// silent miss (nothing came: the path lost it, or the entry is not to be had yet) pauses a
    /// quarter second ([`vouched_pause`]); a packet that took nothing (a forgery, a copy that
    /// does not verify) pauses as a want's does, growing. The probe of a stranger, which decides
    /// nothing and is never given up, climbs from [`REFRESH_PAUSE_MAX`] to [`PROBE_PAUSE_MAX`]
    /// by doubling ([`probe_pause`]) once [`FETCH_TRIES`] asks missed: a forger costs one ask
    /// per [`PROBE_PAUSE_MAX`] in the end. A probe that resolved ends the run: the next counter
    /// of the device is asked at once.
    fn end(
        &mut self,
        launch: &Launch,
        resolved: bool,
        answered: bool,
        now: Instant,
    ) -> (u32, Duration) {
        if launch.probe {
            let probe = self.probes.entry(launch.device.clone()).or_insert(Probe {
                seq: launch.seq,
                misses: 0,
                until: now,
                flying: BTreeSet::new(),
            });
            probe.flying.remove(&launch.seq);
            if resolved {
                (probe.misses, probe.until) = (0, now);
                return (0, REFRESH_PAUSE);
            }
            let missed = probe.misses;
            let pause = if launch.vouched && !answered {
                vouched_pause(missed)
            } else if !launch.vouched && missed >= FETCH_TRIES {
                probe_pause(missed)
            } else {
                retry_pause(missed)
            };
            (probe.misses, probe.until) = (missed + 1, now + pause);
            return (missed + 1, pause);
        }
        let (misses, pause) = if resolved {
            (0, REFRESH_PAUSE)
        } else {
            (launch.misses + 1, retry_pause(launch.misses))
        };
        self.by.insert(
            (launch.device.clone(), launch.seq),
            Ask {
                misses,
                until: Some(now + pause),
            },
        );
        (misses, pause)
    }

    /// Forget every ask of `device`.
    pub(crate) fn forget(&mut self, device: &Name) {
        self.by.retain(|(d, _), _| d != device);
        self.probes.remove(device);
    }
}

/// An ask to make.
struct Launch {
    device: Name,
    seq: u64,
    misses: u32,
    /// An ask of the entry a counter named that the log neither holds nor
    /// asks for: never given up.
    probe: bool,
    /// Whether signed data vouches for the device ([`Asks::probe`]): the ask of such a device's
    /// counter is paced as a want of the log is ([`retry_pause`]), not as a stranger's is
    /// ([`probe_pause`]).
    vouched: bool,
    /// The signed digest the bytes must have (a removal cut names its
    /// entries by it): other bytes are not handed to the log.
    digest: Option<Pin>,
}

/// What a restarting device's wait for its own entries came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Recovered {
    /// A group vector was heard within the wait.
    pub heard: bool,
    /// Every own entry within the bound that the log wants was fetched, and
    /// none is left that has not been asked for [`FETCH_TRIES`] times in vain.
    pub complete: bool,
}

/// Whether `seq` lies in one of `ranges`.
fn within(ranges: &[(u64, u64)], seq: u64) -> bool {
    ranges.iter().any(|&(a, b)| a <= seq && seq <= b)
}

/// How many windows deep above what it holds a hole of another device is asked ([`hole_reach`]).
const REACH_WINDOWS: u64 = 8;

/// How many seqs above the first one missing a hole of another device is asked: a reservation
/// block (a writer reserved no more than that at once, and what an entry far above names
/// proves of the seqs below it is only that they were signed, not that they can be had), and
/// never less than [`REACH_WINDOWS`] windows, so that a block tuned small (the conformance
/// suite's is 8) does not hold the walk of a device to a few asks in flight while the holes of
/// an honest writer's log are many.
fn hole_reach(reserve_block: u64, window: usize) -> u64 {
    reserve_block
        .max(REACH_WINDOWS.saturating_mul(window as u64))
        .max(1)
}

/// What of `ranges` is asked now: the first `block` seqs of each range. A range is a maximal
/// run of seqs neither held nor declared void, so the seq below it is held or void (or none):
/// the seqs asked are at most `block` above what is held, and move up as it is.
fn reach(ranges: &[(u64, u64)], block: u64) -> Vec<(u64, u64)> {
    ranges
        .iter()
        .map(|&(a, b)| (a, b.min(a.saturating_add(block - 1))))
        .collect()
}

impl Group {
    /// The entries notices named that the log neither holds nor asks for: a
    /// device's noticed counter above everything the log asks for without
    /// proof (`NodeInner::high`). Each is probed alone, until it is held.
    pub(crate) fn probes(&self) -> Vec<(Name, u64)> {
        let host = &self.shared.host;
        let own = (host.device(), self.own_seen.load(Ordering::Relaxed));
        let heard = self.heard.lock();
        let named = heard.noticed().chain(std::iter::once(own));
        let unheld = named.filter(|&(d, high)| high > host.high(&self.space, d));
        unheld
            .map(|(device, high)| (device.clone(), high))
            .collect()
    }

    /// The source for a packet of `device` on turn `turn`: the writer (unless it is this
    /// device) on every even turn, the heard members the log vouches for one after another
    /// on the odd ones, and after them the holders the host configured (`Config.holders`),
    /// within the same [`RELAYS_ASKED`] in all; this device's own packets are asked of those
    /// alone. The writer holds what it signed; a heard member holds it only if it got it, and
    /// the members missing a hole are as many as the devices that heard of it, so a ring
    /// that gave the writer one turn in nine left a hole only it held for minutes.
    fn source(&self, device: &Name, turn: u32) -> Option<Source> {
        let host = &self.shared.host;
        let me = host.device();
        let mut relays =
            (self.heard.lock()).relays(me, device, &[], |d| host.standing(&self.space, d));
        let holders = holders_after(&self.shared.cfg.holders, me, device, &relays);
        relays.extend(holders);
        let turn = turn as usize;
        if device == me {
            let pick = turn.checked_rem(relays.len())?;
            return Some(Source::Relay(relays.swap_remove(pick)));
        }
        if turn.is_multiple_of(2) || relays.is_empty() {
            return Some(Source::Writer);
        }
        let pick = (turn / 2) % relays.len();
        Some(Source::Relay(relays.swap_remove(pick)))
    }

    /// The packet `name` (an entry or a piece) as `source` gives it: the
    /// original packet, which must be named `name`. Nothing is verified.
    async fn fetch_original(
        &self,
        source: &Source,
        name: &Name,
        kind: &Kind,
    ) -> Result<Bytes, Miss> {
        let fetcher = &self.shared.fetcher;
        let wire = match source {
            Source::Writer => fetcher.once(name.clone(), kind, true).await?.raw().clone(),
            Source::Relay(holder) => {
                let wrapper = fetcher.once(held_name(holder, name), kind, false).await?;
                wrapper.content().cloned().ok_or(Miss::Again)?
            }
        };
        match Data::decode(wire.clone()) {
            Ok(data) if *data.name == *name => Ok(wire),
            _ => Err(Miss::Again),
        }
    }

    /// Hand `wire`, an entry fetched, to the node. When its judgement waits for a certificate
    /// of its signer's chain that nobody answered ([`Waiting::Chain`]: the validator asked for
    /// it by name, and its only route may be the writer's dead link), the certificates owed
    /// are asked of the heard members that vouch and the holders the host configured, as a
    /// held copy ([`Self::complete_chain`]), and the entry is handed over again.
    async fn take_completing(&self, wire: Bytes, probe: bool, kind: &Kind) -> Taken {
        let host = &self.shared.host;
        let taken = host.take(&self.space, wire.clone(), probe).await;
        if matches!(taken, Taken::Pending(Waiting::Chain)) && self.complete_chain(&wire, kind).await
        {
            return host.take(&self.space, wire, probe).await;
        }
        taken
    }

    /// Ask for the certificates `wire`'s judgement waits for, one hop of the chain at a time
    /// (at most [`CHAIN_HOPS`]), each of the sources of [`Self::ask_certificate`]. One ask of
    /// a name at a time on the group, with the back-off of any ask after a miss
    /// ([`CertAsks`]). Whether the judgement can be tried again: a certificate was taken,
    /// or none is missing now (another ask brought it).
    async fn complete_chain(&self, wire: &Bytes, kind: &Kind) -> bool {
        let host = &self.shared.host;
        let mut asked: Vec<Name> = Vec::new();
        for hop in 0..CHAIN_HOPS {
            let Some(missing) = host.missing_certificate(&self.space, wire).await else {
                return true;
            };
            if asked.contains(&missing) || !self.certs.lock().claim(&missing, Instant::now()) {
                return hop > 0;
            }
            asked.push(missing.clone());
            let taken = self.ask_certificate(wire, &missing, kind).await;
            self.certs.lock().end(&missing, taken, Instant::now());
            if !taken {
                return hop > 0;
            }
        }
        true
    }

    /// Ask for the certificate `missing` as a held copy (`<H>/32=held/<missing>`) of each of
    /// the heard members that vouch (those of which this node holds an unbroken prefix of their
    /// log leading), then of the configured holders, within `RELAYS_ASKED` in all, then of the
    /// writer, which answers for its own chain (a relay that is away costs it nothing), as an
    /// entry is ([`Self::source`]), until one gives a packet the node takes as a certificate
    /// of that key. What is taken is only held unverified: the judgement vouches for it by
    /// reaching a trust anchor through it and drops it when it cannot, so a copy that does not
    /// stand (a forgery) is not the end of the asking: the next source is asked. Whether a
    /// certificate was taken that moved the chain on.
    async fn ask_certificate(&self, wire: &Bytes, missing: &Name, kind: &Kind) -> bool {
        let host = &self.shared.host;
        let me = host.device();
        let writer = Data::decode(wire.clone())
            .ok()
            .and_then(|data| parse_log_name(&data.name))
            .map_or_else(|| me.clone(), |log| log.device);
        let mut sources =
            (self.heard.lock()).relays(me, &writer, &[], |d| host.standing(&self.space, d));
        let holders = holders_after(&self.shared.cfg.holders, me, &writer, &sources);
        sources.extend(holders);
        // The writer answers for its own chain as a held copy (a node serves the certificates
        // of its signing key and its issuers, [`crate::trust::Judge::own_certificate`]): asked
        // last, so that a writer that is away costs the relays nothing.
        if writer != *me {
            sources.push(writer.clone());
        }
        for holder in sources {
            let held = held_name(&holder, missing);
            let Ok(wrapper) = self.shared.fetcher.once(held, kind, false).await else {
                continue;
            };
            let Some(cert) = wrapper.content().cloned() else {
                continue;
            };
            if !host.take_certificate(&self.space, wire, missing, cert) {
                tracing::debug!(%holder, %missing, "not a certificate of that key: the next source is asked");
                continue;
            }
            if host.missing_certificate(&self.space, wire).await.as_ref() != Some(missing) {
                return true;
            }
            tracing::debug!(%holder, %missing, "a copy that does not stand in the chain: the next source is asked");
        }
        false
    }

    /// Fetch the entry `entry` of this space by its log name and admit it as
    /// any entry that arrives is: the node judges it by the durable rule and
    /// the log takes or refuses it ([`crate::node::NodeInner::take`]); there is
    /// no other way in. The writer is asked on the even turns and the heard
    /// members that vouch for its log on the odd ones ([`Self::source`]), at
    /// most [`ENTRY_TURNS`] turns, each within one Interest lifetime. The id of
    /// the entry, held now (applied or not: [`Heap::applied`] says), or why not:
    /// the judge's refusal, a judgement still waiting for a context or a
    /// certificate, or no answer.
    pub(crate) async fn fetch_entry(
        self: &Arc<Self>,
        entry: &LogName,
    ) -> Result<EntryId, HeapError> {
        let name = log_name(&entry.device, &self.space, entry.seq);
        let mut waiting = None;
        for turn in 0..ENTRY_TURNS {
            let Some(source) = self.source(&entry.device, turn) else {
                continue;
            };
            let Ok(wire) = self.fetch_original(&source, &name, &Kind::Pull).await else {
                continue;
            };
            let Ok(data) = Data::decode(wire.clone()) else {
                continue;
            };
            let id = EntryId {
                device: entry.device.clone(),
                seq: entry.seq,
                digest: signed_digest_of(&data),
            };
            match self.take_completing(wire, false, &Kind::Pull).await {
                Taken::Pending(why) => waiting = Some(why),
                Taken::Decided { outcome, blobs } => match outcome {
                    Outcome::Applied | Outcome::Closed | Outcome::Waiting | Outcome::Duplicate => {
                        self.assemble(blobs);
                        return Ok(id);
                    }
                    Outcome::Refused(why) => return Err(HeapError::Refused { name, why }),
                    Outcome::Evidence => {
                        return Err(HeapError::BadRequest {
                            why: format!(
                                "{name} holds another packet here already: its writer signed two \
                                 entries at one name, which is recorded as evidence (an alert) and \
                                 applies nothing; ask the owner to remove the writer"
                            ),
                        });
                    }
                    Outcome::Unreadable => {
                        return Err(HeapError::BadRequest {
                            why: format!(
                                "{name} verifies as its writer's but does not decode as an \
                                 entry; it is recorded and never fetched again, so ask for the \
                                 entry another name names"
                            ),
                        });
                    }
                },
            }
        }
        Err(match waiting {
            Some(waiting) => HeapError::NotReady {
                name,
                why: waiting.to_string(),
            },
            None => HeapError::Unavailable { name },
        })
    }

    /// Everything wanted of the own device and the bound it is fetched
    /// within.
    fn own_wants(&self, wants: &[crate::log::Want]) -> Vec<(u64, u64)> {
        let host = &self.shared.host;
        let cap = host
            .head(&self.space)
            .saturating_add(OWN_BLOCKS * self.shared.cfg.reserve_block);
        wants
            .iter()
            .filter(|w| w.digest.is_none() && w.device == *host.device())
            .map(|w| (w.first, w.last.min(cap)))
            .filter(|(a, b)| a <= b)
            .collect()
    }

    /// Plan the asks of one pass and make them; when to look again if an ask
    /// is pausing. Asks what the log wants, probes the entry each counter
    /// names that the log neither holds nor asks for, lists the pieces and
    /// epoch keys owed.
    pub(crate) fn pump(self: &Arc<Self>) -> Option<Duration> {
        let host = &self.shared.host;
        let space = &self.space;
        let me = host.device().clone();
        let block = hole_reach(self.shared.cfg.reserve_block, self.shared.cfg.window);
        let now = Instant::now();

        // What a notice named is unsigned: it wants nothing of the log. The
        // entry it names, when the log holds nothing at or above it and asks
        // for nothing up to it, is asked for alone; once it is held and
        // verified, the holes below it are the log's to want.
        let probes = self.probes();

        let mut raw: BTreeMap<Name, Vec<(u64, u64)>> = BTreeMap::new();
        let mut exact: BTreeMap<(Name, u64), Pin> = BTreeMap::new();
        let wants = host.missing(space);
        for want in &wants {
            match want.digest {
                Some(digest) => {
                    exact.insert((want.device.clone(), want.first), digest);
                }
                None => raw
                    .entry(want.device.clone())
                    .or_default()
                    .push((want.first, want.last)),
            }
        }
        raw.remove(&me);
        // An undeclared hole of another device is asked a reservation block at a time: its
        // writer reserved no more seqs than that at once, and what an entry far above names
        // proves of the seqs below it is only that they were signed, not that they can be
        // had. The next block is asked once this one is held (the hole's start moves up) or
        // a later entry declares it void. The top of each hole is asked besides, first: the
        // entry above it, held and verified, names it by its chain, and it is the one entry
        // that may declare the rest of the hole void (§7.4).
        let mut per: BTreeMap<Name, Holes> = raw
            .into_iter()
            .map(|(device, ranges)| {
                let mut tops: Vec<u64> = ranges.iter().map(|&(_, last)| last).collect();
                tops.sort_unstable();
                tops.dedup();
                let reach = reach(&ranges, block);
                (device, Holes { reach, tops })
            })
            .collect();
        let own = self.own_wants(&wants);
        if !own.is_empty() {
            per.insert(
                me.clone(),
                Holes {
                    reach: own,
                    tops: Vec::new(),
                },
            );
        }

        let mut launches: Vec<Launch> = Vec::new();
        let mut next: Option<Duration> = None;
        {
            let mut asks = self.asks.lock();
            asks.by.retain(|(d, s), a| {
                a.until.is_none()
                    || per
                        .get(d)
                        .is_some_and(|h| within(&h.reach, *s) || h.lane().binary_search(s).is_ok())
                    || exact.contains_key(&(d.clone(), *s))
            });
            for (device, holes) in &per {
                let window = self.shared.fetcher.window(device);
                asks.walk(device, holes, window, now, &mut next, &mut launches);
            }
            let mut by_device: BTreeMap<&Name, Vec<(u64, Pin)>> = BTreeMap::new();
            for ((device, seq), digest) in &exact {
                by_device.entry(device).or_default().push((*seq, *digest));
            }
            for (device, named) in &by_device {
                let window = self.shared.fetcher.window(device);
                asks.walk_exact(device, named, window, now, &mut next, &mut launches);
            }
            asks.probe(
                &probes,
                |d| *d != me && host.vouched(space, d),
                now,
                &mut next,
                &mut launches,
            );
        }
        for launch in launches {
            rt::spawn(Arc::clone(self).ask_entry(launch));
        }

        if self.relist.swap(false, Ordering::Relaxed) {
            self.assemble(host.blobs(space));
        }
        for epoch in host.owed_keys(space) {
            if self.asking.lock().insert(epoch.clone()) {
                rt::spawn(Arc::clone(self).pull_key(epoch));
            }
        }
        next
    }

    /// One ask for an entry: from the source its misses so far choose, taken
    /// by the node when it came. Whatever happens, the next pass sees the
    /// log's answer: held, or still wanted.
    async fn ask_entry(self: Arc<Self>, launch: Launch) {
        let name = log_name(&launch.device, &self.space, launch.seq);
        let kind = if launch.probe {
            Kind::Probe
        } else {
            Kind::Walk(launch.device.clone())
        };
        let wire = match self.source(&launch.device, launch.misses) {
            Some(source) => self.fetch_original(&source, &name, &kind).await.ok(),
            None => {
                tracing::debug!(%name, "no one to ask for it: this device is the writer and no heard member vouches for the log yet");
                None
            }
        };
        // A node that stopped while the entry was on its way (a clean close, a
        // restart over the same store) takes nothing: what it wrote now would
        // be unknown to the log that opens the store next. A cut names its
        // bytes: others are not handed to the log, and the next source is
        // asked.
        let wire = wire.filter(|_| !self.stop.is_cancelled()).filter(|wire| {
            let right = launch.digest.is_none_or(|pin| pin.accepts(wire));
            if !right {
                tracing::debug!(%name, "not the bytes the cut keeps: the next source is asked");
            }
            right
        });
        let answered = wire.is_some();
        let mut resolved = false;
        if let Some(wire) = wire {
            tracing::trace!(target: TIMELINE, %name, "verify_begin");
            let taken = self.take_completing(wire, launch.probe, &kind).await;
            tracing::trace!(target: TIMELINE, %name, "verify_end");
            match taken {
                Taken::Decided { outcome, blobs } => {
                    // Held now: the next pass sees what is still wanted. Not
                    // newly held (a refusal, a duplicate, evidence): if the
                    // log still wants this entry, this answer resolved
                    // nothing, and the next ask goes to another source.
                    resolved = matches!(
                        outcome,
                        Outcome::Applied | Outcome::Closed | Outcome::Waiting | Outcome::Unreadable
                    );
                    if !resolved {
                        tracing::debug!(%name, "not taken: {outcome:?}");
                    }
                    self.assemble(blobs);
                }
                Taken::Pending(waiting) => tracing::debug!(%name, "not judged yet: {waiting}"),
            }
        }
        let ended = Instant::now();
        let (misses, pause) = self.asks.lock().end(&launch, resolved, answered, ended);
        tracing::trace!(
            target: TIMELINE,
            device = %self.shared.host.device(),
            %name,
            probe = launch.probe,
            turn = launch.misses,
            resolved,
            misses,
            pause_ms = pause.as_millis() as u64,
            "ask_end"
        );
        self.progress.notify_waiters();
        self.wake.notify_one();
    }

    // -- Pieces ---------------------------------------------------------------------------------

    /// Fetch the pieces of the entries `blobs` name, one task each, unless one
    /// is under way for them already. At most [`ASSEMBLIES_MAX`] values
    /// gather at once on the node (a value is up to 64 MiB, a space may owe
    /// thousands): the others wait for a turn.
    pub(crate) fn assemble(self: &Arc<Self>, blobs: Vec<Blob>) {
        for blob in blobs {
            if self.assembling.lock().insert(blob.id.clone()) {
                rt::spawn(Arc::clone(self).assemble_one(blob));
            }
        }
    }

    /// Gather every piece of one value, each proved by the digest its parent
    /// lists, from the writer and then the heard members, storing the pieces
    /// as they are proved and the value whole when the last is held. A turn
    /// ends when the value is whole or a round brought nothing: the next turn
    /// is waited for after a pause, so a value whose holders are away never
    /// keeps the others from theirs. Asked again while the node lists the
    /// value as owed.
    async fn assemble_one(self: Arc<Self>, blob: Blob) {
        let host = &self.shared.host;
        // Turns taken (each is asked of the next source) and turns in a row
        // that proved nothing (the pause grows with them).
        let (mut turns, mut idle) = (0u32, 0u32);
        loop {
            if self.stop.is_cancelled() {
                break;
            }
            let turn = self.shared.fetcher.assembly_turn().await;
            let gathered = self.gather(&blob, turns).await;
            drop(turn);
            match gathered {
                Gathered::Whole | Gathered::Refused => break,
                Gathered::Stuck { progressed } => {
                    turns += 1;
                    idle = if progressed { 0 } else { idle + 1 };
                }
            }
            rt::sleep(retry_pause(idle)).await;
            if !host.blobs(&self.space).iter().any(|b| b.id == blob.id) {
                break;
            }
        }
        self.assembling.lock().remove(&blob.id);
    }

    /// One turn of an assembly: ask for the pieces the plan names, in
    /// rounds, keeping each round's proved pieces in one batch. A piece the
    /// store holds already (an assembly an earlier run began) counts once it
    /// proves; nothing but the plan is held here.
    async fn gather(&self, blob: &Blob, turns: u32) -> Gathered {
        let host = &self.shared.host;
        let entry = log_name(&blob.id.device, &self.space, blob.id.seq);
        let mut assembler = match Assembler::new(
            entry.clone(),
            ChunksBody {
                size: blob.size,
                root: blob.root,
            },
        ) {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(%entry, "pieces not fetched: {e}");
                return Gathered::Refused;
            }
        };
        let mut progressed = false;
        loop {
            if self.stop.is_cancelled() {
                return Gathered::Refused;
            }
            if assembler.is_complete() {
                host.assembled(&self.space, blob);
                return Gathered::Whole;
            }
            let (mut held, mut absent) = (false, Vec::new());
            let window = self.shared.fetcher.window(&blob.id.device);
            for piece in assembler.next_wanted(window) {
                match host
                    .held_piece(&self.space, &piece)
                    .map(|wire| assembler.offer(wire))
                {
                    Some(Ok(Offered::Accepted)) => held = true,
                    _ => absent.push(piece),
                }
            }
            if held {
                progressed = true;
                continue;
            }
            let Some(source) = self.source(&blob.id.device, turns) else {
                return Gathered::Stuck { progressed };
            };
            let kind = Kind::Walk(blob.id.device.clone());
            let arrived = join_all(
                absent
                    .iter()
                    .map(|piece| self.fetch_original(&source, piece, &kind)),
            )
            .await;
            let mut keep = Vec::new();
            for got in arrived.into_iter().flatten() {
                match assembler.offer(got.clone()) {
                    Ok(Offered::Accepted) => keep.extend(pieces::keep_op(got)),
                    Ok(Offered::Duplicate | Offered::NotYet) => {}
                    Err(e) => tracing::debug!(%entry, "a copy of a piece was not taken: {e}"),
                }
            }
            if keep.is_empty() {
                return Gathered::Stuck { progressed };
            }
            progressed = true;
            host.keep_pieces(&self.space, keep);
        }
    }

    // -- The grant pull, reader side ------------------------------------------------------------

    /// Ask for the key of `epoch` while it is owed (spec §6.5): round after
    /// round, each of the epoch's creator and then the heard members that
    /// vouch ([`Heard::granters`]), with a capped backoff between rounds. The
    /// ask carries this device's seal key packet, so a granter answers it in
    /// the one exchange. A granted key is taken only if the log accepts it (it
    /// matches the check of the Epoch entry naming the epoch); one that does
    /// not is dropped and the ask goes on.
    async fn pull_key(self: Arc<Self>, epoch: EpochId) {
        self.pull_rounds(&epoch).await;
        self.asking.lock().remove(&epoch);
        self.progress.notify_waiters();
        self.wake.notify_one();
    }

    /// The rounds of [`Self::pull_key`], until the key is held, no longer owed, or the group
    /// stops.
    async fn pull_rounds(&self, epoch: &EpochId) {
        let host = &self.shared.host;
        let own = seal_key_name(host.device(), &host.seal_public());
        let mut misses = 0u32;
        loop {
            if self.stop.is_cancelled() || !host.owed_keys(&self.space).contains(epoch) {
                return;
            }
            // Built each round: a certificate renewed meanwhile is carried as soon as it is
            // held. The ask carries this device's signer chain, so that a granter that
            // fetches nothing can judge the seal key packet (spec §6.5).
            let ask = match host
                .seal_key_packet(&own)
                .ok_or(WireError::Malformed("this device holds no seal key packet"))
                .and_then(|packet| GrantAsk::new(self.space.clone(), epoch.clone(), packet))
            {
                Ok(ask) => ask,
                Err(e) => {
                    tracing::warn!(space = %self.space, "the key of {epoch:?} is not asked for: this device's seal key packet cannot be carried in a grant ask ({e}); sign it with a device key whose signature is smaller");
                    return;
                }
            };
            let chain = host.signer_chain();
            if chain.is_empty() && misses == 0 {
                tracing::warn!(space = %self.space, "this device's validator holds no certificate of its signing key, so its grant asks carry no chain: a granter that does not hold the chain refuses them; enrol the device (or load its certificate) before it asks");
            }
            let ask = match ask.clone().with_chain(chain) {
                Ok(carrying) => carrying,
                Err(e) => {
                    tracing::warn!(space = %self.space, "this device's certificate chain cannot be carried in a grant ask ({e}): asking without it");
                    ask
                }
            };
            let granters = self
                .heard
                .lock()
                .granters(host.device(), &epoch.creator, |d| {
                    host.standing(&self.space, d)
                });
            for granter in granters {
                let name = grant_name(&granter, &ask);
                let Ok(data) = self
                    .shared
                    .fetcher
                    .once(name.clone(), &Kind::Pull, true)
                    .await
                else {
                    continue;
                };
                if *data.name != name {
                    continue;
                }
                let judged = host
                    .validate_device_packet(&self.space, &data, &granter)
                    .await;
                if !matches!(judged, crate::trust::Judged::Valid(_)) {
                    tracing::debug!(%granter, "a grant that does not verify as the granter's is dropped");
                    continue;
                }
                let Some(content) = data.content().cloned() else {
                    continue;
                };
                if host.key_arrived(&self.space, epoch, &name, content) {
                    return;
                }
                tracing::debug!(%granter, ?epoch, "refused: a granted key that does not match its epoch's key check");
            }
            rt::sleep(retry_pause(misses)).await;
            misses += 1;
        }
    }

    // -- Recovery -------------------------------------------------------------------------------

    /// Wait up to `settle` for the first group vector, then until the own
    /// entries the log wants (up to four reservation blocks above the head)
    /// are fetched or asked for in vain ([`FETCH_TRIES`] times each). What
    /// the log does with them (adoption, rollback evidence) is its own: this
    /// only fetches and hands over.
    pub(crate) async fn recover(&self, settle: Duration) -> Recovered {
        // The first vector: any notice, or a peer's counter for this device's
        // own name (which is no notice, `Group::note_own`), within `settle`.
        let began = Instant::now();
        loop {
            let first = self.first_vector.notified();
            if self.heard_any.load(Ordering::Relaxed) || self.note_own() {
                break;
            }
            let left = settle.saturating_sub(began.elapsed());
            if left.is_zero() {
                break;
            }
            let _ = rt::timeout(left.min(OWN_POLL), first).await;
        }
        let heard = self.heard_any.load(Ordering::Relaxed);
        loop {
            let progress = self.progress.notified();
            self.note_own();
            if let Some(complete) = self.own_complete() {
                return Recovered { heard, complete };
            }
            let _ = rt::timeout(Duration::from_millis(100), progress).await;
        }
    }

    /// Whether the own entries are done: `Some(true)` when none is wanted,
    /// `Some(false)` when every one wanted (or the entry the own counter
    /// names) was asked for in vain, `None` while one can still be asked for.
    fn own_complete(&self) -> Option<bool> {
        let host = &self.shared.host;
        let me = host.device();
        let seqs: Vec<u64> = self
            .own_wants(&host.missing(&self.space))
            .iter()
            .flat_map(|&(a, b)| a..=b)
            .collect();
        let probed = self.probes().iter().any(|(d, _)| d == me);
        if seqs.is_empty() && !probed {
            return Some(true);
        }
        let asks = self.asks.lock();
        let owed = seqs.iter().any(|&seq| {
            asks.by
                .get(&(me.clone(), seq))
                .is_none_or(|ask| ask.misses < FETCH_TRIES)
        }) || (probed
            && asks
                .probes
                .get(me)
                .is_none_or(|probe| probe.misses < FETCH_TRIES));
        (!owed).then_some(false)
    }
}

/// The pump of one group: look at what the log wants whenever woken, and when
/// an ask pauses, when its pause ends.
pub(crate) async fn run(group: Arc<Group>) {
    while !group.stop.is_cancelled() {
        group.note_own();
        // The own counter is read from the observed state: nothing wakes the
        // pump for it, so it looks again at least every `OWN_POLL * 20`.
        let wait = group.pump().map_or(OWN_POLL * 20, |w| w.min(OWN_POLL * 20));
        let woken = rt::timeout(wait, group.wake.notified());
        if group.stop.run_until_cancelled(woken).await.is_none() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Before the first sample (RFC 6298 §2.1) the timeout is a second: the first Interest a
    /// node expresses, lost, is expressed again within its lifetime, not after it.
    #[test]
    fn before_any_sample_a_lost_interest_is_expressed_again_within_the_lifetime() {
        let rtt = Rtt::default();
        let lifetime = Duration::from_secs(2);
        assert_eq!(rtt.rto(lifetime), Duration::from_secs(1));
        // The lifetime still bounds it.
        assert_eq!(
            rtt.rto(Duration::from_millis(600)),
            Duration::from_millis(600)
        );
    }

    /// An unreachable device is not a slow network: the asks to a writer that is away, one
    /// after another timing out, do not stretch the wait before an Interest to another device
    /// that answers is expressed again.
    #[test]
    fn a_device_that_never_answers_does_not_slow_the_asks_of_another() {
        let space: Name = "/alice/32=data/notes".parse().expect("a name");
        let name = |device: &str, seq: u64| {
            crate::wire::log_name(&device.parse().expect("a name"), &space, seq)
        };
        let lifetime = Duration::from_secs(2);
        let mut rtts = Rtts::default();
        for seq in 1..=6 {
            rtts.missed(&name("/alice/phone", seq));
        }
        // Nothing was ever measured toward the laptop: its first Interest waits the initial
        // timeout, not what six lost asks of the phone doubled it to.
        assert_eq!(rtts.rto(&name("/alice/laptop", 1), lifetime), RTO_INITIAL);
        // And what the laptop answers fast shortens its own wait, not the phone's.
        let laptop = name("/alice/laptop", 1);
        rtts.sample(&laptop, Duration::from_millis(40));
        assert!(rtts.rto(&laptop, lifetime) < RTO_INITIAL);
        assert_eq!(rtts.rto(&name("/alice/phone", 7), lifetime), lifetime);
    }

    /// Stage-4 review FB5. The table of round-trip estimates is capped; what it drops is the
    /// device asked least recently, not the one whose name sorts first: forged names that
    /// sort after an honest device's never reset what was measured of it.
    #[test]
    fn forged_names_do_not_reset_the_estimate_of_a_device_in_use() {
        let space: Name = "/alice/32=data/notes".parse().expect("a name");
        let name = |device: &str, seq: u64| {
            crate::wire::log_name(&device.parse().expect("a name"), &space, seq)
        };
        let lifetime = Duration::from_secs(2);
        let mut rtts = Rtts::default();
        let laptop = name("/alice/laptop", 1);
        rtts.sample(&laptop, Duration::from_millis(40));
        let measured = rtts.rto(&laptop, lifetime);
        assert!(measured < RTO_INITIAL);
        for i in 0..(3 * RTTS_MAX) {
            // Names that sort after the honest device's (a longer component sorts later).
            rtts.missed(&name(&format!("/alice/forged-{i}"), 1));
            // The honest device keeps being asked.
            assert_eq!(
                rtts.rto(&laptop, lifetime),
                measured,
                "after {i} forged names"
            );
        }
    }

    /// Stage-4 review M3. A device's window starts small, doubles each round the device
    /// answers, never passes its cap, keeps what a lossy path allows (a third of the asks
    /// missed answers more than it misses) and falls to the minimum for a device that answers
    /// nothing, from where an answer brings it up again.
    #[test]
    fn a_window_follows_what_a_device_answers() {
        let cap = 128;
        let mut w = Window::default();
        assert_eq!(w.size(cap), WINDOW_INITIAL);
        for _ in 0..WINDOW_INITIAL {
            w.answer(cap);
        }
        assert_eq!(
            w.size(cap),
            2 * WINDOW_INITIAL,
            "doubled by one round of answers"
        );
        for _ in 0..1000 {
            w.answer(cap);
        }
        assert_eq!(w.size(cap), cap, "never past its cap");

        let mut lossy = Window::default();
        for i in 0..600 {
            if i % 3 == 0 {
                lossy.miss(cap);
            } else {
                lossy.answer(cap);
            }
        }
        assert_eq!(
            lossy.size(cap),
            cap,
            "a path that loses a third keeps its window"
        );

        let mut silent = Window::default();
        for _ in 0..200 {
            silent.miss(cap);
        }
        assert_eq!(
            silent.size(cap),
            WINDOW_MIN,
            "a device that answers nothing"
        );
        for _ in 0..32 {
            silent.answer(cap);
        }
        assert!(
            silent.size(cap) >= 32,
            "and answers bring it back: {}",
            silent.size(cap)
        );
    }

    /// Round 12, the ladder. A Congestion Nack halves a device's window once for all the asks
    /// that were in flight, however many of them are Nacked; a later ask that is Nacked halves
    /// it again, down to the minimum; and after a cut the window grows by one a round, where
    /// before it doubled each round and met the link's rate again at every transfer.
    #[test]
    fn a_congestion_nack_cuts_the_window_once_and_it_grows_back_by_a_round() {
        let cap = 128;
        let mut w = Window::default();
        for _ in 0..1000 {
            w.answer(cap);
        }
        assert_eq!(w.size(cap), cap);
        let in_flight = w.cuts();
        w.congested(cap, in_flight);
        assert_eq!(w.size(cap), cap / 2, "halved by the first Nack");
        for _ in 0..127 {
            w.congested(cap, in_flight);
        }
        assert_eq!(
            w.size(cap),
            cap / 2,
            "the other asks that were in flight say what the cut already answered"
        );
        // A round of answers is one step, not a doubling.
        for _ in 0..(cap / 2) {
            w.answer(cap);
        }
        assert_eq!(w.size(cap), cap / 2 + 1, "one step for a round of answers");
        for _ in 0..(cap / 2 + 1) {
            w.answer(cap);
        }
        assert_eq!(w.size(cap), cap / 2 + 2);
        // An ask that began after the cut and is Nacked cuts again, to the least window.
        for _ in 0..20 {
            let began = w.cuts();
            w.congested(cap, began);
        }
        assert_eq!(w.size(cap), WINDOW_MIN);
        // Answers bring it back, slowly: no doubling a round.
        for _ in 0..(8 * WINDOW_MIN) {
            w.answer(cap);
        }
        assert!(w.size(cap) <= 2 * WINDOW_MIN + 4, "{}", w.size(cap));
        assert!(w.size(cap) > WINDOW_MIN);
    }

    /// Stage-4 review M3. One device holds at most half of the node's slots, walks at most
    /// three quarters, probes an eighth; a grant pull and a probe find a slot whoever floods.
    #[tokio::test(start_paused = true)]
    async fn walks_of_one_device_leave_slots_for_other_devices_probes_and_pulls() {
        let slots = Slots::new(16, 128);
        let walk = |device: &str| Kind::Walk(device.parse().expect("a name"));
        let wait = Duration::from_secs(1);
        let mut held = Vec::new();
        for _ in 0..8 {
            held.push(slots.take(&walk("/alice/phone")).await.expect("open"));
        }
        assert!(
            tokio::time::timeout(wait, slots.take(&walk("/alice/phone")))
                .await
                .is_err(),
            "one device holds at most half the slots"
        );
        for _ in 0..4 {
            held.push(slots.take(&walk("/alice/tablet")).await.expect("open"));
        }
        assert!(
            tokio::time::timeout(wait, slots.take(&walk("/alice/watch")))
                .await
                .is_err(),
            "walks hold at most three quarters of the slots"
        );
        for _ in 0..2 {
            held.push(slots.take(&Kind::Probe).await.expect("open"));
        }
        assert!(
            tokio::time::timeout(wait, slots.take(&Kind::Probe))
                .await
                .is_err(),
            "probes hold at most an eighth"
        );
        for _ in 0..2 {
            let pull = tokio::time::timeout(wait, slots.take(&Kind::Pull)).await;
            assert!(
                pull.is_ok(),
                "a pull finds a slot while walks and probes are full"
            );
            held.push(pull.expect("in time").expect("open"));
        }
        drop(held);
        assert!(
            tokio::time::timeout(wait, slots.take(&walk("/alice/phone")))
                .await
                .is_ok(),
            "slots come back when dropped"
        );
    }

    /// Stage-4 review M3. A hole no entry declares void is asked a reservation block at a
    /// time above what is held.
    #[test]
    fn an_undeclared_hole_is_asked_one_block_at_a_time() {
        assert_eq!(
            reach(&[(1, 999_999_999), (5000, 5002), (7000, 7100)], 1024),
            vec![(1, 1024), (5000, 5002), (7000, 7100)]
        );
    }

    /// Stage-4 review M3. An ask that missed holds its place in the device's window while it
    /// pauses: the walk does not slide on to new seqs over the ones nothing answers; once the
    /// pause is over the same seqs are asked again.
    #[test]
    fn asks_that_missed_keep_their_place_in_the_window() {
        let device: Name = "/alice/phone".parse().expect("a name");
        let mut asks = Asks::default();
        let (mut next, mut launches) = (None, Vec::new());
        let began = Instant::now();
        let holes = Holes {
            reach: vec![(1, 1000)],
            tops: Vec::new(),
        };
        asks.walk(&device, &holes, 4, began, &mut next, &mut launches);
        let seqs = |l: &[Launch]| l.iter().map(|l| l.seq).collect::<Vec<_>>();
        assert_eq!(seqs(&launches), vec![1, 2, 3, 4]);
        for launch in &launches {
            asks.end(launch, false, false, began);
        }
        launches.clear();
        asks.walk(&device, &holes, 4, began, &mut next, &mut launches);
        assert!(
            launches.is_empty(),
            "the missed asks hold the window: {:?}",
            seqs(&launches)
        );
        assert!(
            next.is_some(),
            "and the walk looks again when their pause ends"
        );
        let later = began + REFRESH_PAUSE_MAX;
        asks.walk(&device, &holes, 4, later, &mut next, &mut launches);
        assert_eq!(
            seqs(&launches),
            vec![1, 2, 3, 4],
            "the same seqs are asked again"
        );
    }

    /// The top of a hole (the entry a held entry's chain names) is asked besides the window,
    /// even when the window is full of asks that missed and are pausing: it is one of at most
    /// [`HOLE_TOPS`] asked at once beside it, the lowest holes first.
    #[test]
    fn the_top_of_a_hole_is_asked_beside_a_window_full_of_missed_asks() {
        let device: Name = "/alice/phone".parse().expect("a name");
        let mut asks = Asks::default();
        let (mut next, mut launches) = (None, Vec::new());
        let began = Instant::now();
        let seqs = |l: &[Launch]| l.iter().map(|l| l.seq).collect::<Vec<_>>();
        let below = Holes {
            reach: vec![(1, 1000)],
            tops: Vec::new(),
        };
        asks.walk(&device, &below, 4, began, &mut next, &mut launches);
        for launch in &launches {
            asks.end(launch, false, false, began);
        }
        launches.clear();
        let holes = Holes {
            reach: vec![
                (1, 1000),
                (3000, 3000),
                (4000, 4000),
                (5000, 5000),
                (6000, 6000),
            ],
            tops: vec![1000, 3000, 4000, 5000, 6000],
        };
        asks.walk(&device, &holes, 4, began, &mut next, &mut launches);
        assert_eq!(
            seqs(&launches),
            vec![1000, 3000, 4000, 5000],
            "the tops of the four lowest holes, though the window is full of missed asks, and no ask from the bottom"
        );
        launches.clear();
        asks.walk(&device, &holes, 4, began, &mut next, &mut launches);
        assert!(
            launches.is_empty(),
            "what is in the lane is not asked again, and the lane is full: {:?}",
            seqs(&launches)
        );
    }

    /// Many one-seq holes (a reader of a writer that never pauses, over a lossy path: o4) are
    /// asked by the window, not four at a time by the lane: the tops of the holes past the
    /// lowest [`HOLE_TOPS`] are seqs of the window like any other.
    #[test]
    fn the_tops_of_holes_past_the_lane_are_asked_by_the_window() {
        let device: Name = "/alice/phone".parse().expect("a name");
        let mut asks = Asks::default();
        let (mut next, mut launches) = (None, Vec::new());
        let seqs = |l: &[Launch]| l.iter().map(|l| l.seq).collect::<Vec<_>>();
        let tops: Vec<u64> = (1..=10).map(|i| i * 10).collect();
        let holes = Holes {
            reach: tops.iter().map(|&s| (s, s)).collect(),
            tops,
        };
        asks.walk(&device, &holes, 4, Instant::now(), &mut next, &mut launches);
        assert_eq!(
            seqs(&launches),
            vec![10, 20, 30, 40, 50, 60, 70, 80],
            "the lane of four, and then a window of four"
        );
    }

    /// Stage-4 review L2. The entries a cut re-admits one by one are asked within the window of
    /// their device as a walk's asks are: a cut that names thousands holds the device's window
    /// and no more, and the asks that missed keep their place while they pause.
    #[test]
    fn the_exact_asks_of_a_cut_are_asked_within_the_window_of_their_device() {
        let device: Name = "/alice/phone".parse().expect("a name");
        let named: Vec<(u64, Pin)> = (1..=1000)
            .map(|seq| (seq, Pin::Implicit([7; 32])))
            .collect();
        let mut asks = Asks::default();
        let (mut next, mut launches) = (None, Vec::new());
        let began = Instant::now();
        asks.walk_exact(&device, &named, 4, began, &mut next, &mut launches);
        let seqs = |l: &[Launch]| l.iter().map(|l| l.seq).collect::<Vec<_>>();
        assert_eq!(seqs(&launches), vec![1, 2, 3, 4], "a window of them");
        assert!(
            launches
                .iter()
                .all(|l| l.digest == Some(Pin::Implicit([7; 32])))
        );
        for launch in &launches {
            asks.end(launch, false, false, began);
        }
        launches.clear();
        asks.walk_exact(&device, &named, 4, began, &mut next, &mut launches);
        assert!(
            launches.is_empty(),
            "the missed asks hold the window: {:?}",
            seqs(&launches)
        );
        assert!(next.is_some(), "and it looks again when their pause ends");
        let later = began + REFRESH_PAUSE_MAX;
        asks.walk_exact(&device, &named, 4, later, &mut next, &mut launches);
        assert_eq!(seqs(&launches), vec![1, 2, 3, 4], "the same ones again");
    }

    /// Stage-4 review M2. The pauses of a probe belong to the device: counters that rise at
    /// every Sync Interest for 100 s cost the ladder of one entry (asks at 0, 0.25, 0.75,
    /// 1.75, 5.75 s, …), not an ask per counter.
    #[test]
    fn a_probes_ladder_belongs_to_the_device_not_to_the_counter() {
        let device: Name = "/alice/fake".parse().expect("a name");
        let mut asks = Asks::default();
        let began = Instant::now();
        let (mut count, mut last_misses) = (0, 0);
        for step in 0..400u64 {
            let now = began + Duration::from_millis(250 * step);
            let (mut next, mut launches) = (None, Vec::new());
            asks.probe(
                &[(device.clone(), step + 1)],
                |_| false,
                now,
                &mut next,
                &mut launches,
            );
            for launch in launches {
                assert_eq!(
                    launch.seq,
                    step + 1,
                    "the entry asked is the counter's as it stands"
                );
                last_misses = launch.misses;
                count += 1;
                asks.end(&launch, false, false, now);
            }
        }
        // Asks at 0, 0.25, 0.75, 1.75 s, then every pause of 4, 8, 16, 16 … s ([`probe_pause`]).
        assert!(count <= 11, "{count} probes in 100 s of rising counters");
        assert!(last_misses >= 7, "the ladder climbed: {last_misses}");
    }

    /// A device signed data vouches for is a device of the group: the asks for its newest
    /// entries that nothing answered (the path lost them, or the entry is not to be had yet)
    /// follow each other a quarter second apart, for [`REFRESH_TRIES`] of them in a row, however
    /// the counter rises, and then wait a minute; asks that were answered with packets that
    /// took nothing (forgeries) pause longer each time, as a want's do. A reader that follows a
    /// writer that never pauses (conformance o4, faulty seeds 1, 4, 6, 9) learned where the
    /// writer was a minute late otherwise.
    #[test]
    fn a_vouched_devices_silent_misses_pause_a_quarter_second_and_forgeries_pause_longer() {
        let device: Name = "/alice/phone".parse().expect("a name");
        let times = |answered: bool| {
            let mut asks = Asks::default();
            let began = Instant::now();
            let mut asked = Vec::new();
            for step in 0..400u64 {
                let now = began + Duration::from_millis(250 * step);
                let (mut next, mut launches) = (None, Vec::new());
                asks.probe(
                    &[(device.clone(), step + 1)],
                    |_| true,
                    now,
                    &mut next,
                    &mut launches,
                );
                for launch in launches {
                    asked.push(now - began);
                    asks.end(&launch, false, answered, now);
                }
            }
            asked
        };
        let silent = times(false);
        assert!(
            silent[..REFRESH_TRIES as usize]
                .windows(2)
                .all(|w| w[1] - w[0] <= Duration::from_millis(500)),
            "{} silent misses pause a quarter second each: {silent:?}",
            REFRESH_TRIES
        );
        let idle = REFRESH_TRIES as usize + 1;
        assert!(
            silent[idle] - silent[idle - 1] >= REFRESH_IDLE,
            "then a minute: {silent:?}"
        );
        let forged = times(true);
        let gaps: Vec<Duration> = forged.windows(2).map(|w| w[1] - w[0]).collect();
        assert!(
            gaps.windows(2).all(|g| g[1] >= g[0]) && gaps[3] > gaps[0],
            "forgeries pause longer each time: {gaps:?}"
        );
    }

    /// A writer that never pauses names a higher counter every few milliseconds, and the entry
    /// a notice names is often not to be had when it is asked: a vouched device's counters are
    /// asked several at once ([`PROBE_FLIGHTS`], so the reader learns where the writer is by many
    /// asks, not one at a time: o4 under loss, faulty seeds 1, 4, 6, 9), a stranger's one at a
    /// time, and a run of asks that missed holds back both.
    #[test]
    fn a_vouched_devices_counters_are_asked_several_at_once_and_a_strangers_one() {
        let device: Name = "/alice/phone".parse().expect("a name");
        let now = Instant::now();
        let asked = |vouched: bool| {
            let mut asks = Asks::default();
            let mut all = Vec::new();
            for counter in 1..=20u64 {
                let (mut next, mut launches) = (None, Vec::new());
                asks.probe(
                    &[(device.clone(), counter)],
                    |_| vouched,
                    now,
                    &mut next,
                    &mut launches,
                );
                all.extend(launches.iter().map(|l| l.seq));
            }
            all
        };
        assert_eq!(asked(true), vec![1, 2, 3, 4], "four counters at once");
        assert_eq!(asked(false), vec![1]);

        // Asks that missed in a row hold back the next counter, for either.
        let mut asks = Asks::default();
        let mut launches = Vec::new();
        asks.probe(
            &[(device.clone(), 1)],
            |_| true,
            now,
            &mut None,
            &mut launches,
        );
        asks.end(&launches[0], false, false, now);
        launches.clear();
        asks.probe(
            &[(device.clone(), 2)],
            |_| true,
            now,
            &mut None,
            &mut launches,
        );
        assert!(launches.is_empty(), "the pause after a miss is not over");
        asks.probe(
            &[(device.clone(), 2)],
            |_| true,
            now + Duration::from_millis(300),
            &mut None,
            &mut launches,
        );
        assert_eq!(launches.len(), 1, "and then the next counter is asked");
    }

    /// Stage-4 review M2. At most [`PROBES_MAX`] probes of a group are in flight; of the
    /// devices waiting, a vouched one is asked before the strangers, and a device not asked
    /// yet before one that missed.
    #[test]
    fn probes_in_flight_are_capped_and_the_vouched_come_first() {
        let real: Name = "/alice/zzz-real".parse().expect("a name");
        let named: Vec<(Name, u64)> = (0..64)
            .map(|i| (format!("/alice/fake{i:02}").parse().expect("a name"), 1))
            .chain([(real.clone(), 1)])
            .collect();
        let mut asks = Asks::default();
        let now = Instant::now();
        let (mut next, mut launches) = (None, Vec::new());
        asks.probe(&named, |d| *d == real, now, &mut next, &mut launches);
        assert_eq!(launches.len(), PROBES_MAX);
        assert_eq!(launches[0].device, real, "the vouched device first");
        launches.clear();
        asks.probe(&named, |d| *d == real, now, &mut next, &mut launches);
        assert!(
            launches.is_empty(),
            "no more while {PROBES_MAX} are in flight"
        );
        // One ends unanswered: the next asked is a device never asked, not the one that missed.
        asks.end(
            &Launch {
                device: real.clone(),
                seq: 1,
                misses: 0,
                probe: true,
                vouched: true,
                digest: None,
            },
            false,
            false,
            now,
        );
        asks.probe(
            &named,
            |d| *d == real,
            now + Duration::from_secs(1),
            &mut next,
            &mut launches,
        );
        assert_eq!(launches.len(), 1);
        assert_eq!(launches[0].misses, 0);
        assert_ne!(launches[0].device, real);
    }
}
