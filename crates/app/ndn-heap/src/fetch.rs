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
//! it wanted, asked for in a window ([`NetConfig::window`]), in seq order,
//! minus what a gap statement declared void. A counter nothing signs
//! therefore costs [`FETCH_TRIES`] asks and then one ask a minute
//! ([`probe_pause`]), and wants nothing of the log.
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

use std::collections::BTreeMap;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::future::{Either, join_all, select};
use ndn_app::{AppError, Connection, Consumer};
use ndn_foundation_types::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_packet::{Data, NackReason};
use parking_lot::Mutex;
use tokio::sync::Semaphore;

use crate::log::{Blob, Outcome};
use crate::pieces::{self, Assembler, Offered};
use crate::rt::{self, Instant};
use crate::sync::{Group, TIMELINE, Taken};
use crate::wire::{
    ChunksBody, EpochId, GrantAsk, grant_name, held_name, log_name, seal_key_name, signed_digest,
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
/// optional (a seal key learned in the background, the first asks of an
/// entry a counter names): each of at most `1 + REEXPRESS_MAX` Interests.
pub(crate) const FETCH_TRIES: u32 = 3;

/// The pause before an entry that only an unsigned counter names is asked for
/// again: [`retry_pause`] for the first [`FETCH_TRIES`] misses, then
/// [`REFRESH_IDLE`]. The counter decides nothing, so the probe is never given
/// up (an honest writer away for a while still comes, after a minute at the
/// latest), and costs a forger one ask a minute.
fn probe_pause(misses: u32) -> Duration {
    if misses >= FETCH_TRIES {
        REFRESH_IDLE
    } else {
        retry_pause(misses)
    }
}

/// The most times an Interest is expressed again under a fresh nonce within
/// its lifetime when nothing answers it.
const REEXPRESS_MAX: u32 = 3;

/// The least of an Interest's lifetime that must be left for it to be
/// expressed again: a forwarder holds back a fresh-nonce Interest from the same
/// face for up to 250 ms (NFD `RetxSuppressionExponential`), so a shorter gap
/// would be aggregated at the first hop and cost an Interest for nothing.
const RTO_MIN: Duration = Duration::from_millis(250);

/// How many seqs above its own head a device fetches its own entries back,
/// in reservation blocks.
const OWN_BLOCKS: u64 = 4;

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

/// The round-trip estimate from which an unanswered Interest is expressed
/// again (RFC 6298): the smoothed round trip and its variation over the asks
/// answered by their first Interest, and how many asks since the last such
/// answer needed a re-expression or missed. An ask answered after a
/// re-expression gives no sample (Karn: which Interest was answered is not
/// known). Before any sample nothing is re-expressed: the timeout is the
/// lifetime.
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
    /// 4·rttvar (the lifetime before any sample), doubled per
    /// [`Self::missed`] since the last sample, at least [`RTO_MIN`] and at
    /// most `lifetime`.
    pub(crate) fn rto(&self, lifetime: Duration) -> Duration {
        self.srtt
            .map_or(lifetime, |srtt| srtt + self.rttvar * 4)
            .saturating_mul(1 << self.backoff)
            .clamp(RTO_MIN, lifetime.max(RTO_MIN))
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

/// The node's Interests: its slots, its round-trip estimate, its face.
pub(crate) struct Fetcher {
    conn: Arc<dyn Connection>,
    lifetime: Duration,
    slots: Semaphore,
    assemblies: Semaphore,
    rtt: Mutex<Rtt>,
}

impl Fetcher {
    /// A fetcher over `conn` with `in_flight` slots, expressing Interests of
    /// `lifetime`.
    pub(crate) fn new(conn: Arc<dyn Connection>, lifetime: Duration, in_flight: usize) -> Fetcher {
        Fetcher {
            conn,
            lifetime,
            slots: Semaphore::new(in_flight.max(1)),
            assemblies: Semaphore::new(ASSEMBLIES_MAX),
            rtt: Mutex::new(Rtt::default()),
        }
    }

    /// One of the node's fetch slots, waiting at most one Interest lifetime:
    /// a queue of fetches others made never holds a slot longer than the
    /// Interest it waits to send would have lived. [`Miss::Again`]: every
    /// slot stayed taken, so the node is busy, not the packet absent.
    async fn slot(&self) -> Result<tokio::sync::SemaphorePermit<'_>, Miss> {
        match rt::timeout(self.lifetime, self.slots.acquire()).await {
            Ok(Ok(slot)) => Ok(slot),
            Ok(Err(_)) => Err(Miss::Gone),
            Err(_) => {
                tracing::debug!(
                    "fetch not sent: every fetch slot stayed taken for an Interest lifetime ({:?}); it is asked again after its pause, or raise Config::in_flight",
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

    /// One ask within one Interest lifetime: an Interest nothing answered
    /// within the retransmission timeout ([`Rtt::rto`]) is expressed again
    /// under a fresh nonce, the timeout doubling each time, at most `most`
    /// times. A Nack with reason Congestion is asked again by the consumer
    /// after a short jittered pause ([`Consumer::fetch_reexpressing`]). The
    /// packet is unverified: the caller hands it to the node.
    pub(crate) async fn expressed(&self, name: Name, most: u32) -> Result<Data, Miss> {
        let _slot = self.slot().await?;
        let rto = self.rtt.lock().rto(self.lifetime);
        tracing::trace!(target: TIMELINE, %name, "fetch_out");
        let asked = Instant::now();
        let fetched = Consumer::new(Arc::clone(&self.conn))
            .fetch_reexpressing(
                || InterestBuilder::new(name.clone()),
                self.lifetime,
                RTO_MIN,
                (0..most).map(|k| rto.saturating_mul(1 << k)),
            )
            .await;
        match fetched {
            Ok((data, expressed)) => {
                tracing::trace!(target: TIMELINE, %name, expressed, "fetch_in");
                let mut rtt = self.rtt.lock();
                if expressed == 1 {
                    rtt.sample(asked.elapsed());
                } else {
                    rtt.missed();
                }
                Ok(data)
            }
            Err(e) => {
                tracing::trace!(target: TIMELINE, %name, "fetch_miss");
                tracing::trace!(%name, "fetch missed: {e}");
                Err(match e {
                    AppError::Timeout => {
                        self.rtt.lock().missed();
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
                    // Dropped for rate and asking again soon already failed:
                    // not an answer.
                    AppError::Nacked {
                        reason: Some(NackReason::Congestion),
                    } => Miss::Again,
                    _ => Miss::Gone,
                })
            }
        }
    }

    /// [`Self::expressed`], re-expressed up to [`REEXPRESS_MAX`] times.
    pub(crate) async fn once(&self, name: Name) -> Result<Data, Miss> {
        self.expressed(name, REEXPRESS_MAX).await
    }

    /// A packet asked for in place up to [`FETCH_TRIES`] times with pauses
    /// between: the asks a caller makes where nothing else asks again for it.
    pub(crate) async fn owed(&self, name: Name) -> Option<Data> {
        for tries in 0..FETCH_TRIES {
            if tries > 0 {
                rt::sleep(retry_pause(tries - 1)).await;
            }
            match self.once(name.clone()).await {
                Ok(d) => return Some(d),
                Err(Miss::Again) => {}
                Err(Miss::Gone) => return None,
            }
        }
        None
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

/// What a notice made of a device: the counter it named. Unsigned: it wants
/// nothing of the log, and the entry it names is probed while the log holds
/// nothing at or above it.
#[derive(Default)]
pub(crate) struct Noticed {
    pub(crate) high: u64,
}

impl Noticed {
    /// A notice named the device at `high`.
    pub(crate) fn raise(&mut self, high: u64) {
        self.high = self.high.max(high);
    }
}

enum Phase {
    Flying,
    Pause(Instant),
}

struct Ask {
    misses: u32,
    phase: Phase,
}

/// Every ask that is in flight or pausing, by `(device, seq)`. Entries are
/// dropped once the log no longer wants what they are for.
#[derive(Default)]
pub(crate) struct Asks {
    by: BTreeMap<(Name, u64), Ask>,
}

impl Asks {
    fn flying(&self, device: &Name) -> usize {
        self.by
            .iter()
            .filter(|((d, _), a)| d == device && matches!(a.phase, Phase::Flying))
            .count()
    }

    /// Whether `key` is to be asked for now, and after how many misses; when
    /// it pauses, `next` is lowered to the time to look again.
    fn due(&self, key: &(Name, u64), now: Instant, next: &mut Option<Duration>) -> Option<u32> {
        let Some(ask) = self.by.get(key) else {
            return Some(0);
        };
        match ask.phase {
            Phase::Flying => None,
            Phase::Pause(until) if until <= now => Some(ask.misses),
            Phase::Pause(until) => {
                let left = until - now;
                *next = Some(next.map_or(left, |n| n.min(left)));
                None
            }
        }
    }

    fn launch(&mut self, key: (Name, u64), misses: u32) {
        self.by.insert(
            key,
            Ask {
                misses,
                phase: Phase::Flying,
            },
        );
    }

    /// Forget every ask of `device`.
    pub(crate) fn forget(&mut self, device: &Name) {
        self.by.retain(|(d, _), _| d != device);
    }
}

/// An ask to make.
struct Launch {
    device: Name,
    seq: u64,
    misses: u32,
    /// An ask of the entry a counter named that the log neither holds nor
    /// asks for: paced after [`FETCH_TRIES`] misses, never given up.
    probe: bool,
    /// The signed digest the bytes must have (a removal cut names its
    /// entries by it): other bytes are not handed to the log.
    digest: Option<[u8; 32]>,
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

impl Group {
    /// The sources for a packet of `device`, in the order they are tried: the
    /// writer (unless it is this device), then the heard members the log
    /// vouches for.
    fn sources(&self, device: &Name) -> Vec<Source> {
        let host = &self.shared.host;
        let me = host.device();
        let mut out = Vec::new();
        if device != me {
            out.push(Source::Writer);
        }
        let relays = self
            .heard
            .lock()
            .relays(me, device, &[], |d| host.standing(&self.space, d));
        out.extend(relays.into_iter().map(Source::Relay));
        out
    }

    /// The packet `name` (an entry or a piece) as `source` gives it: the
    /// original packet, which must be named `name`. Nothing is verified.
    async fn fetch_original(&self, source: &Source, name: &Name) -> Result<Bytes, Miss> {
        let fetcher = &self.shared.fetcher;
        let wire = match source {
            Source::Writer => fetcher.once(name.clone()).await?.raw().clone(),
            Source::Relay(holder) => {
                let wrapper = fetcher.once(held_name(holder, name)).await?;
                wrapper.content().cloned().ok_or(Miss::Again)?
            }
        };
        match Data::decode(wire.clone()) {
            Ok(data) if *data.name == *name => Ok(wire),
            _ => Err(Miss::Again),
        }
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
        let window = self.shared.cfg.window.max(1);
        let now = Instant::now();

        // What a notice named is unsigned: it wants nothing of the log. The
        // entry it names, when the log holds nothing at or above it and asks
        // for nothing up to it, is asked for alone; once it is held and
        // verified, the holes below it are the log's to want.
        let probes: Vec<(Name, u64)> = self
            .noticed
            .lock()
            .iter()
            .filter(|(device, notice)| notice.high > host.high(space, device))
            .map(|(device, notice)| (device.clone(), notice.high))
            .collect();

        let mut per: BTreeMap<Name, Vec<(u64, u64)>> = BTreeMap::new();
        let mut exact: BTreeMap<(Name, u64), [u8; 32]> = BTreeMap::new();
        let wants = host.missing(space);
        for want in &wants {
            match want.digest {
                Some(digest) => {
                    exact.insert((want.device.clone(), want.first), digest);
                }
                None => per
                    .entry(want.device.clone())
                    .or_default()
                    .push((want.first, want.last)),
            }
        }
        per.remove(&me);
        let own = self.own_wants(&wants);
        if !own.is_empty() {
            per.insert(me.clone(), own);
        }

        let mut launches: Vec<Launch> = Vec::new();
        let mut next: Option<Duration> = None;
        {
            let mut asks = self.asks.lock();
            asks.by.retain(|(d, s), a| {
                matches!(a.phase, Phase::Flying)
                    || per.get(d).is_some_and(|rs| within(rs, *s))
                    || exact.contains_key(&(d.clone(), *s))
                    || probes.iter().any(|(pd, ph)| pd == d && ph == s)
            });
            for (device, ranges) in &per {
                let mut budget = window.saturating_sub(asks.flying(device));
                for seq in ranges.iter().flat_map(|&(a, b)| a..=b) {
                    if budget == 0 {
                        break;
                    }
                    let key = (device.clone(), seq);
                    if let Some(misses) = asks.due(&key, now, &mut next) {
                        asks.launch(key, misses);
                        launches.push(Launch {
                            device: device.clone(),
                            seq,
                            misses,
                            probe: false,
                            digest: None,
                        });
                        budget -= 1;
                    }
                }
            }
            for ((device, seq), digest) in &exact {
                let key = (device.clone(), *seq);
                if let Some(misses) = asks.due(&key, now, &mut next) {
                    asks.launch(key, misses);
                    launches.push(Launch {
                        device: device.clone(),
                        seq: *seq,
                        misses,
                        probe: false,
                        digest: Some(*digest),
                    });
                }
            }
            for (device, seq) in &probes {
                let key = (device.clone(), *seq);
                if let Some(misses) = asks.due(&key, now, &mut next) {
                    asks.launch(key, misses);
                    launches.push(Launch {
                        device: device.clone(),
                        seq: *seq,
                        misses,
                        probe: true,
                        digest: None,
                    });
                }
            }
        }
        for launch in launches {
            rt::spawn(Arc::clone(self).ask_entry(launch));
        }

        if self
            .relist
            .swap(false, std::sync::atomic::Ordering::Relaxed)
        {
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
        let host = &self.shared.host;
        let name = log_name(&launch.device, &self.space, launch.seq);
        let sources = self.sources(&launch.device);
        let taken = match sources.get(launch.misses as usize % sources.len().max(1)) {
            None => {
                tracing::debug!(%name, "no one to ask for it: this device is the writer and no heard member vouches for the log yet");
                None
            }
            Some(source) => match self.fetch_original(source, &name).await {
                // A node that stopped while the entry was on its way (a clean
                // close, a restart over the same store) takes nothing: what
                // it wrote now would be unknown to the log that opens the
                // store next.
                Ok(_) if self.stop.is_stopped() => None,
                Ok(wire) => {
                    // A cut names its bytes: others are not handed to the
                    // log, and the next source is asked.
                    if launch
                        .digest
                        .is_some_and(|want| signed_digest(&wire) != want)
                    {
                        tracing::debug!(%name, "not the bytes the cut keeps: the next source is asked");
                        None
                    } else {
                        tracing::trace!(target: TIMELINE, %name, "verify_begin");
                        let taken = host.take(&self.space, wire, launch.probe).await;
                        tracing::trace!(target: TIMELINE, %name, "verify_end");
                        Some(taken)
                    }
                }
                Err(_) => None,
            },
        };
        let mut resolved = false;
        match taken {
            Some(Taken::Decided { outcome, blobs }) => {
                match &outcome {
                    Outcome::Refused(why) => tracing::debug!(%name, "refused: {why}"),
                    // Held now: the next pass sees what is still wanted.
                    Outcome::Applied | Outcome::Closed | Outcome::Waiting | Outcome::Unreadable => {
                        resolved = true
                    }
                    // Not newly held: if the log still wants this entry, this
                    // answer resolved nothing, and the next ask goes to
                    // another source.
                    Outcome::Duplicate | Outcome::Evidence => {
                        tracing::debug!(%name, "already held, or kept as evidence: {outcome:?}");
                    }
                }
                if !blobs.is_empty() {
                    self.assemble(blobs);
                }
            }
            Some(Taken::Pending(waiting)) => {
                tracing::debug!(%name, "not judged yet: {waiting}");
            }
            None => {}
        }
        {
            let now = Instant::now();
            let mut asks = self.asks.lock();
            let key = (launch.device.clone(), launch.seq);
            let ask = asks.by.entry(key).or_insert(Ask {
                misses: 0,
                phase: Phase::Flying,
            });
            if resolved {
                ask.misses = 0;
                ask.phase = Phase::Pause(now + REFRESH_PAUSE);
            } else {
                ask.misses = launch.misses + 1;
                let pause = if launch.probe {
                    probe_pause(launch.misses)
                } else {
                    retry_pause(launch.misses)
                };
                ask.phase = Phase::Pause(now + pause);
            }
        }
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
            if self.stop.is_stopped() {
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
            if self.stop.is_stopped() {
                return Gathered::Refused;
            }
            if assembler.is_complete() {
                host.assembled(&self.space, blob);
                return Gathered::Whole;
            }
            let (mut held, mut absent) = (false, Vec::new());
            for piece in assembler.next_wanted(self.shared.cfg.window.max(1)) {
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
            let sources = self.sources(&blob.id.device);
            let Some(source) = sources.get(turns as usize % sources.len().max(1)) else {
                return Gathered::Stuck { progressed };
            };
            let arrived = join_all(
                absent
                    .iter()
                    .map(|piece| self.fetch_original(source, piece)),
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
    /// vouch ([`Heard::granters`]), with a capped backoff between rounds. A
    /// granted key is taken only if the log accepts it (it matches the check
    /// of the Epoch entry naming the epoch); one that does not is dropped and
    /// the ask goes on.
    async fn pull_key(self: Arc<Self>, epoch: EpochId) {
        let host = &self.shared.host;
        let ask = GrantAsk {
            seal_key: seal_key_name(host.device(), &host.seal_public()),
            space: self.space.clone(),
            epoch: epoch.clone(),
        };
        let mut misses = 0u32;
        'rounds: loop {
            if self.stop.is_stopped() || !host.owed_keys(&self.space).contains(&epoch) {
                break;
            }
            let granters = self
                .heard
                .lock()
                .granters(host.device(), &epoch.creator, |d| {
                    host.standing(&self.space, d)
                });
            for granter in granters {
                let name = grant_name(&granter, &ask);
                let Ok(data) = self.shared.fetcher.once(name.clone()).await else {
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
                if host.key_arrived(&self.space, &epoch, &name, content) {
                    break 'rounds;
                }
                tracing::debug!(%granter, ?epoch, "refused: a granted key that does not match its epoch's key check");
            }
            rt::sleep(retry_pause(misses)).await;
            misses += 1;
        }
        self.asking.lock().remove(&epoch);
        self.progress.notify_waiters();
        self.wake.notify_one();
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
            if self.heard_any.load(std::sync::atomic::Ordering::Relaxed) || self.note_own() {
                break;
            }
            let left = settle.saturating_sub(began.elapsed());
            if left.is_zero() {
                break;
            }
            let _ = rt::timeout(left.min(OWN_POLL), first).await;
        }
        let heard = self.heard_any.load(std::sync::atomic::Ordering::Relaxed);
        loop {
            let progress = self.progress.notified();
            self.note_own();
            match self.own_state() {
                OwnState::Done => {
                    return Recovered {
                        heard,
                        complete: true,
                    };
                }
                OwnState::GaveUp => {
                    return Recovered {
                        heard,
                        complete: false,
                    };
                }
                OwnState::Owed => {
                    let _ = rt::timeout(Duration::from_millis(100), progress).await;
                }
            }
        }
    }

    /// The counter a notice named of `device`, when it is above everything
    /// the log asks for without proof (`NodeInner::high`): the one entry that is
    /// probed alone, until it is held.
    fn unconfirmed(&self, device: &Name) -> Option<u64> {
        let named = self.noticed.lock().get(device).map_or(0, |n| n.high);
        (named > self.shared.host.high(&self.space, device)).then_some(named)
    }

    /// Where the own entries stand: none wanted, some wanted (or the entry
    /// the own counter names, not yet probed in vain) that can still be asked
    /// for, or every one asked for in vain.
    fn own_state(&self) -> OwnState {
        let host = &self.shared.host;
        let me = host.device();
        let mut seqs: Vec<u64> = self
            .own_wants(&host.missing(&self.space))
            .iter()
            .flat_map(|&(a, b)| a..=b)
            .collect();
        seqs.extend(self.unconfirmed(me));
        if seqs.is_empty() {
            return OwnState::Done;
        }
        let asks = self.asks.lock();
        for seq in seqs {
            match asks.by.get(&(me.clone(), seq)) {
                Some(ask) if ask.misses >= FETCH_TRIES => {}
                _ => return OwnState::Owed,
            }
        }
        OwnState::GaveUp
    }
}

enum OwnState {
    Done,
    Owed,
    GaveUp,
}

/// The pump of one group: look at what the log wants whenever woken, and when
/// an ask pauses, when its pause ends.
pub(crate) async fn run(group: Arc<Group>) {
    loop {
        if group.stop.is_stopped() {
            return;
        }
        group.note_own();
        let mut wait = group.pump();
        if group.observes() {
            wait = Some(wait.map_or(OWN_POLL * 20, |w| w.min(OWN_POLL * 20)));
        }
        let woken = pin!(group.wake.notified());
        let timer = pin!(async {
            match wait {
                Some(d) => rt::sleep(d).await,
                None => futures::future::pending().await,
            }
        });
        let stopped = pin!(group.stop.stopped());
        match select(woken, select(timer, stopped)).await {
            Either::Left(_) | Either::Right((Either::Left(_), _)) => {}
            Either::Right((Either::Right(_), _)) => return,
        }
    }
}
