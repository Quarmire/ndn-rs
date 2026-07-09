//! ndnSVS-compatible State Vector Sync. Background task multicasts
//! Sync Interests carrying the local state vector, merges received
//! vectors, and emits [`SyncUpdate`]s for detected gaps.
//!
//! Wire shape — Sync Interest name `/<group-prefix>/v=2` (a typed
//! VERSION component, TLV-TYPE `0x36`, value 2), matching ndn-svs
//! `core.cpp:351` `Interest(Name(m_syncPrefix).appendVersion(2))`. This
//! is the v2 dialect; ndnd's v3 uses `v=3`. (Earlier revisions of this
//! file appended a *generic* `"svs"` component, which no C++/Go peer
//! recognises — see `testbed/fixtures/svs/README.md`, gap #9.) State
//! vector in ApplicationParameters (0x24):
//!
//! ```text
//! AppParameters    ::= StateVector [MappingData]
//! StateVector      ::= 0xC9 LEN StateVectorEntry*
//! StateVectorEntry ::= 0xCA LEN NodeID SeqNo
//! NodeID           ::= Name (0x07)
//! SeqNo            ::= 0xCC LEN NonNegativeInteger
//! MappingData      ::= 0xCD LEN MappingEntry*
//! MappingEntry     ::= 0xCE LEN NodeID SeqNo AppData
//! ```
//!
//! Timer model — the driver is a two-state machine (ndn-svs
//! `SVSyncCore`):
//!
//! * **Steady state.** A jittered periodic timer fires every
//!   `[sync_interval ± jitter_ms]`, emitting one Sync Interest. When a
//!   peer's Interest *covers* the local vector, this timer is reset to a
//!   fresh window — Interest-storm suppression, so a large group emits
//!   ≈ one Interest per interval rather than one per member.
//! * **Suppression (reply-to-stale).** When an incoming Interest is
//!   *behind* local state (a peer is missing data we hold), the node
//!   does **not** wait for the next periodic tick. It schedules a
//!   catch-up Interest after a short, exponentially-jittered
//!   [`SvsConfig::suppression_period`] (~200 ms) and, while that timer
//!   runs, records every peer vector it sees. When the timer fires it
//!   sends *only if* the union of recorded vectors still does not cover
//!   us — i.e. no other member already corrected the laggard. This is
//!   what gives a partitioned/rejoining node sub-second recovery instead
//!   of a full periodic wait, and what keeps the group to a single
//!   corrective Interest.
//!
//! **Authoritative-for-self (deliberate behaviour change, gap #3).**
//! [`SvsNode::merge`](crate::svs::SvsNode::merge) ignores any received
//! entry naming the local node: a remote peer can never raise our own
//! sequence number, only [`advance`](crate::svs::SvsNode::advance) can.
//! This closes a state-injection / seq-hijack hole. The one legitimate
//! case it used to (accidentally) serve — a node that restarted with no
//! persistence relearning its own seq from peers — is instead solved
//! correctly by the SVS v3 boot-timestamp dialect in
//! [`svs_local`](crate::svs_local), which disambiguates pre- and
//! post-restart sequence spaces.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::rt::{self, Instant};

use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;

use crate::dialect::WireDialect;
use crate::protocol::{ObservedState, SyncHandle, SyncUpdate};
use crate::security::{SyncSigner, SyncValidator};
use crate::svs::{StateEntry, SvsNode};

// MappingData TLV codes per ndn-svs/ndn-svs/tlv.hpp (the piggyback
// codec; the state-vector codec now lives in `crate::dialect`).
/// Outer TLV-TYPE shared by both dialects' state vectors (v2
/// `StateVector` 201, v3 `SvsData` 0xC9 — the same code).
const TLV_STATE_VECTOR_OUTER: u64 = 201;
const TLV_SV_SEQ_NO: u64 = 204;
const TLV_MAPPING_DATA: u64 = 205;
const TLV_MAPPING_ENTRY: u64 = 206;
const TLV_NDN_NAME: u64 = 7;

/// Exponential back-off for gap-fetch Interests. Defaults to the
/// ndnSVS reference: 4 retries, 1 s base, 2× factor.
#[derive(Clone, Debug)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub base_delay: Duration,
    pub backoff_factor: f64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 4,
            base_delay: Duration::from_secs(1),
            backoff_factor: 2.0,
        }
    }
}

/// On each failure the delay doubles (capped at 60 s). The closure
/// receives the 0-based attempt index.
pub async fn fetch_with_retry<F, Fut, T, E>(policy: RetryPolicy, mut fetch: F) -> Result<T, E>
where
    F: FnMut(u32) -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let mut delay = policy.base_delay;
    for attempt in 0..=policy.max_retries {
        match fetch(attempt).await {
            Ok(v) => return Ok(v),
            Err(e) => {
                if attempt == policy.max_retries {
                    return Err(e);
                }
                rt::sleep(delay).await;
                delay = Duration::from_secs_f64(
                    (delay.as_secs_f64() * policy.backoff_factor).min(60.0),
                );
            }
        }
    }
    unreachable!()
}

#[derive(Clone, Debug)]
pub struct SvsConfig {
    /// Default 30 s (ndnSVS reference).
    pub sync_interval: Duration,
    /// Default 3000 ms (≈±10 %).
    pub jitter_ms: u64,
    /// Reply-to-stale suppression window. When an incoming Sync Interest
    /// is *behind* local state (a peer is missing data we have), the
    /// node schedules its catch-up reply after an exponentially-jittered
    /// delay with this mean, then sends only if no other member has
    /// already corrected the laggard. This is half of the SVS protocol
    /// (ndn-svs `SVSyncCore`): in steady state the group emits ≈ one
    /// Sync Interest per [`Self::sync_interval`] rather than one per
    /// member, and a rejoining/partitioned node recovers in
    /// sub-`suppression_period` time instead of a full periodic wait.
    /// Default 200 ms.
    pub suppression_period: Duration,
    pub channel_capacity: usize,
    /// Not consumed by the SVS task itself; passed to [`fetch_with_retry`]
    /// by application-side gap fetchers.
    pub retry_policy: RetryPolicy,
    /// Wire dialect: [`WireDialect::V2`] (ndn-svs, default) or
    /// [`WireDialect::V3`] (ndnd, boot-timestamped). Selects the Sync
    /// Interest name version and the state-vector codec.
    pub dialect: WireDialect,
    /// Bootstrap timestamp for this node (SVS v3): the startup time in ms
    /// since the Unix epoch. Ignored by V2 (always 0). Set it for V3 so a
    /// restart is distinguishable from the pre-restart sequence space.
    pub local_boot: u64,
    /// Initial local sequence number (default 0). Set on restart so the node's
    /// advertised state vector resumes after its last durable publication
    /// instead of restarting at 0 (NS-8). [`crate::svsync::SvSync::join`]
    /// derives it from the [`DataStore`](crate::svsync::DataStore); a bare
    /// Layer-0 core normally leaves it 0.
    pub local_seq: u64,
    /// Signs every outgoing Sync Interest. Defaults to
    /// [`Insecure`](crate::security::Insecure) (unsigned), the
    /// closed-link posture; set an
    /// [`HmacKey`](crate::security::HmacKey) for authenticated groups.
    pub signer: Arc<dyn SyncSigner>,
    /// Gates every inbound Sync Interest before merge. Defaults to
    /// [`Insecure`](crate::security::Insecure) (accept-all); pair it with
    /// the same key as [`Self::signer`] for an HMAC group.
    pub validator: Arc<dyn SyncValidator>,
    /// **Two-phase commit (D-44 / N-3).** When `true` (**default**), a merged peer vector advances the
    /// local state vector eagerly — the classic SVS behaviour. When `false`, merges are *deferred*:
    /// gaps are emitted but the local seq is not advanced until the app calls [`SyncHandle::ack`] for
    /// each `(publisher, seq)` it has validated and stored. Off is the posture for a validating
    /// consumer (a chain-replication gate) that must be able to reject a delivered item without
    /// poisoning convergence — a rejected item is simply never acked, and its gap stays visible.
    pub auto_ack: bool,
}

impl Default for SvsConfig {
    fn default() -> Self {
        Self {
            sync_interval: Duration::from_secs(30),
            jitter_ms: 3000,
            suppression_period: Duration::from_millis(200),
            channel_capacity: 256,
            retry_policy: RetryPolicy::default(),
            dialect: WireDialect::default(),
            local_boot: 0,
            local_seq: 0,
            signer: crate::security::default_signer(),
            validator: crate::security::default_validator(),
            auto_ack: true,
        }
    }
}

/// Named-environment presets. [`Default`] carries the ndnSVS reference tuning (30 s interval,
/// ±3 s jitter) — lab values that every deployed app ends up discovering and overriding by
/// hand. Pick the environment instead of reverse-engineering the constants; every other field
/// stays at the default, and struct-update syntax layers app-specific overrides on top:
///
/// ```
/// # use ndn_sync::SvsConfig;
/// let cfg = SvsConfig { auto_ack: false, ..SvsConfig::lan() };
/// ```
impl SvsConfig {
    /// Local network / localhost: sub-millisecond RTT, loss is rare, convergence should feel
    /// immediate. Tight periodic (1 s ± 100 ms) and a short suppression window (50 ms) — a
    /// laggard is corrected in tens of milliseconds, and the steady-state cost (≈ one Sync
    /// Interest per second per group) is nothing on a LAN.
    pub fn lan() -> Self {
        Self {
            sync_interval: Duration::from_secs(1),
            jitter_ms: 100,
            suppression_period: Duration::from_millis(50),
            ..Self::default()
        }
    }

    /// Internet paths: tens-to-hundreds of ms RTT, transient loss, links worth not chattering
    /// on. Slower periodic (15 s ± 2 s) and a wide suppression window (500 ms) so one member's
    /// catch-up reply has time to silence the rest of the group across real latency spreads.
    pub fn wan() -> Self {
        Self {
            sync_interval: Duration::from_secs(15),
            jitter_ms: 2000,
            suppression_period: Duration::from_millis(500),
            ..Self::default()
        }
    }

    /// Deterministic simulation (ndn-sim's `VirtualKernel` and friends): fast periodic
    /// (500 ms) with **zero** interval jitter, so runs replay identically and tests converge
    /// in a few virtual seconds. The suppression delay keeps its default mean — it is
    /// exponentially drawn from the thread-local `fastrand` RNG, so a test that wants full
    /// schedule reproducibility seeds that (`fastrand::seed(..)`), as the ndn-sim harnesses
    /// do. Virtual time makes the tight cadence free.
    pub fn sim() -> Self {
        Self {
            sync_interval: Duration::from_millis(500),
            jitter_ms: 0,
            ..Self::default()
        }
    }
}

/// Spawn the SVS background task: periodic Sync Interests, merge of
/// incoming vectors, and gap [`SyncUpdate`]s on the returned handle.
pub fn join_svs_group(
    group: Name,
    local_name: Name,
    send: mpsc::Sender<Bytes>,
    recv: mpsc::Receiver<Bytes>,
    config: SvsConfig,
) -> SyncHandle {
    let cancel = CancellationToken::new();
    let (update_tx, update_rx) = mpsc::channel(config.channel_capacity);
    let (publish_tx, publish_rx) = mpsc::channel(64);
    // Two-phase-commit acks (D-44 / N-3): the app's validated `(publisher, seq)` flow back to the task.
    let (ack_tx, ack_rx) = mpsc::channel(64);
    // Observed per-name high-water (N-9): the task records inbound advertisements
    // into this; the handle exposes it read-only. A depth on the data, not a peer roster.
    let observed = Arc::new(ObservedState::default());

    let task_cancel = cancel.clone();
    let task_observed = Arc::clone(&observed);
    rt::spawn(async move {
        svs_task(
            group,
            local_name,
            send,
            recv,
            publish_rx,
            ack_rx,
            update_tx,
            task_observed,
            config,
            task_cancel,
        )
        .await;
    });

    SyncHandle::new(update_rx, publish_tx, cancel)
        .with_ack_channel(ack_tx)
        .with_observed(observed)
}

/// Per-group SVS state + the operations one Sync Interest / publish / ack / timer
/// tick performs on it. This is the **single source of truth** for per-group SVS
/// behaviour: both the single-group [`svs_task`] and the multiplexed driver
/// ([`crate::svs_multi`]) drive their groups through these methods, so
/// convergence, two-phase reject-without-poison, N-9 observation, and N-11
/// coalescing behave identically whether a group runs on its own task or shares
/// one with N others (the AD-10 invariant: multiplexing changes only *where* the
/// work runs, never *what* a group does).
pub(crate) struct GroupCore {
    pub(crate) group: Name,
    pub(crate) node: SvsNode,
    pub(crate) local_key: String,
    pub(crate) config: SvsConfig,
    pub(crate) current_mapping: Option<Bytes>,
    /// Suppression state (ndn-svs `SVSyncCore`). When set, `next_send` is a short
    /// reply-to-stale deadline; `recorded` accumulates peer vectors seen in the
    /// window so the timer can check whether someone else already corrected us.
    pub(crate) suppressing: bool,
    pub(crate) recorded: HashMap<String, (u64, u64)>,
    /// When this group next wants to emit a Sync Interest (periodic or suppressed).
    pub(crate) next_send: Instant,
    /// Gap updates awaiting delivery, coalesced per publisher (N-11 / NS-7): a
    /// re-advertised range widens the buffered `[low, high]` rather than queueing
    /// a second entry, and delivery never blocks the driver.
    pub(crate) pending: HashMap<String, SyncUpdate>,
    pub(crate) update_tx: mpsc::Sender<SyncUpdate>,
    /// Observed per-name high-water (N-9) — a read-only depth on the data.
    pub(crate) observed: Arc<ObservedState>,
}

impl GroupCore {
    pub(crate) fn new(
        group: Name,
        local_name: &Name,
        config: SvsConfig,
        update_tx: mpsc::Sender<SyncUpdate>,
        observed: Arc<ObservedState>,
    ) -> Self {
        let node = SvsNode::with_boot_seq(local_name, config.local_boot, config.local_seq);
        let local_key = node.local_key().to_string();
        let next_send = Instant::now() + jitter_interval(&config);
        Self {
            group,
            node,
            local_key,
            config,
            current_mapping: None,
            suppressing: false,
            recorded: HashMap::new(),
            next_send,
            pending: HashMap::new(),
            update_tx,
            observed,
        }
    }

    /// The group's `next_send` timer fired: emit the periodic or suppressed
    /// catch-up Sync Interest and reschedule.
    pub(crate) async fn on_timer(&mut self, send: &mpsc::Sender<Bytes>) {
        if self.suppressing {
            // Reply-to-stale: only emit if the union of vectors recorded during
            // the window still does not cover us (nobody else corrected us).
            self.suppressing = false;
            let snapshot = self.node.snapshot().await;
            let recorded_sv: Vec<StateEntry> = self
                .recorded
                .iter()
                .filter_map(|(k, (b, s))| {
                    k.parse::<Name>().ok().map(|name| StateEntry { name, boot: *b, seq: *s })
                })
                .collect();
            self.recorded.clear();
            if !remote_covers_local(&snapshot, &recorded_sv) {
                self.emit(send).await;
            }
        } else {
            self.emit(send).await;
        }
        self.next_send = Instant::now() + jitter_interval(&self.config);
    }

    async fn emit(&self, send: &mpsc::Sender<Bytes>) {
        send_sync_interest(
            &self.group,
            &self.node,
            send,
            self.current_mapping.clone(),
            &self.config.signer,
            self.config.dialect,
        )
        .await;
    }

    /// An inbound Sync Interest addressed to THIS group: authenticate, record the
    /// N-9 observation, merge (eager or deferred), buffer gaps, run the
    /// suppression FSM. No cross-group state is touched — a poison here stays here.
    pub(crate) async fn on_inbound(&mut self, raw: &Bytes, _send: &mpsc::Sender<Bytes>) {
        // Authenticate before touching the state vector (gap #2). `Insecure` accepts all.
        if let Err(reason) = self.config.validator.validate(raw) {
            tracing::trace!(?reason, "svs: rejected inbound sync interest");
            return;
        }
        let Some((remote_sv, peer_mappings)) =
            parse_sync_interest(&self.group, raw, self.config.dialect)
        else {
            return;
        };
        // N-9: record observed per-name high-water from every authenticated entry
        // (incl. one naming us, which the merge below drops). Strictly observational.
        for e in &remote_sv {
            self.observed.record(&e.name, e.boot, e.seq);
        }
        let snapshot = self.node.snapshot().await;
        let covers_local = remote_covers_local(&snapshot, &remote_sv);
        let local_ahead = local_ahead_of_remote(&snapshot, &remote_sv);
        // D-44 / N-3: eager merge advances now; deferred holds until `ack` (a
        // rejected item can't poison — and it can't poison ANOTHER group either,
        // since each group has its own `node`/`pending`).
        let gaps = if self.config.auto_ack {
            self.node.merge(&remote_sv).await
        } else {
            self.node.merge_deferred(&remote_sv).await
        };
        for (peer_key, low, high) in gaps {
            if peer_key == self.local_key {
                continue;
            }
            let mapping = peer_mappings.get(&peer_key).cloned();
            let fetch_name = peer_key
                .parse::<Name>()
                .unwrap_or_else(|_| self.group.clone().append(&peer_key));
            let update = SyncUpdate {
                publisher: peer_key.clone(),
                name: fetch_name,
                low_seq: low,
                high_seq: high,
                mapping,
                serving_party: None,
            };
            coalesce_pending(&mut self.pending, update);
        }
        if local_ahead {
            record_vector(&mut self.recorded, &remote_sv);
            if !self.suppressing {
                self.suppressing = true;
                self.next_send = Instant::now() + suppression_delay(&self.config);
            }
        } else if covers_local {
            self.suppressing = false;
            self.recorded.clear();
            self.next_send = Instant::now() + jitter_interval(&self.config);
        }
    }

    /// A local publication: advance, drop suppression, announce immediately.
    pub(crate) async fn on_publish(&mut self, mapping: Option<Bytes>, send: &mpsc::Sender<Bytes>) {
        self.current_mapping = mapping;
        self.node.advance().await;
        self.suppressing = false;
        self.recorded.clear();
        self.emit(send).await;
        self.next_send = Instant::now() + jitter_interval(&self.config);
    }

    /// Two-phase commit (D-44 / N-3): advance the deferred vector for a
    /// validated+stored `(publisher, seq)`.
    pub(crate) async fn on_ack(&mut self, key: &str, seq: u64) {
        self.node.ack(key, seq).await;
    }

    /// Deliver buffered gaps without ever blocking (the multiplexed driver can't
    /// afford a blocking send — it would stall every other group). `try_send`
    /// keeps an undeliverable (full channel) entry in `pending` for the next
    /// retry; a closed channel drops it (the consumer is gone). Returns `true`
    /// while anything remains undelivered (so the driver can schedule a retry).
    pub(crate) fn drain_pending_try(&mut self) -> bool {
        use tokio::sync::mpsc::error::TrySendError;
        let keys: Vec<String> = self.pending.keys().cloned().collect();
        for k in keys {
            let Some(update) = self.pending.get(&k).cloned() else { continue };
            match self.update_tx.try_send(update) {
                Ok(()) | Err(TrySendError::Closed(_)) => {
                    self.pending.remove(&k);
                }
                Err(TrySendError::Full(_)) => {}
            }
        }
        !self.pending.is_empty()
    }
}

#[allow(clippy::too_many_arguments)]
async fn svs_task(
    group: Name,
    local_name: Name,
    send: mpsc::Sender<Bytes>,
    mut recv: mpsc::Receiver<Bytes>,
    mut publish_rx: mpsc::Receiver<(Name, Option<Bytes>)>,
    mut ack_rx: mpsc::Receiver<(String, u64)>,
    update_tx: mpsc::Sender<SyncUpdate>,
    observed: Arc<ObservedState>,
    config: SvsConfig,
    cancel: CancellationToken,
) {
    let mut gc = GroupCore::new(group, &local_name, config, update_tx, observed);

    loop {
        // Deliver buffered gaps without blocking (N-11): a blocking send here
        // would wedge the loop against a two-phase consumer. Anything the full
        // channel refuses stays in `pending`; a short retry cap on the sleep
        // re-attempts it promptly without a busy-loop.
        let more = gc.drain_pending_try();
        let now = Instant::now();
        let mut wake = gc.next_send;
        if more {
            wake = wake.min(now + PENDING_RETRY);
        }

        tokio::select! {
            _ = cancel.cancelled() => break,

            // Portable `sleep_until(wake)`. On wake, emit only if the *periodic*
            // deadline is actually due — a shorter pending-retry wake just loops
            // back to re-drain.
            _ = rt::sleep(wake.saturating_duration_since(now)) => {
                if gc.next_send <= Instant::now() {
                    gc.on_timer(&send).await;
                }
            }

            Some(raw) = recv.recv() => { gc.on_inbound(&raw, &send).await; }

            Some((pub_name, mapping)) = publish_rx.recv() => {
                let _ = pub_name;
                gc.on_publish(mapping, &send).await;
            }

            Some((key, seq)) = ack_rx.recv() => { gc.on_ack(&key, seq).await; }
        }
    }
}

/// How long the driver waits before re-attempting a gap update the consumer's
/// (full) channel refused — short enough to feel prompt, long enough not to spin.
pub(crate) const PENDING_RETRY: Duration = Duration::from_millis(5);

/// Merge `update` into the per-publisher pending-delivery buffer (N-11 /
/// NS-7). At most one entry per publisher: a re-advertised or widened range
/// just extends the buffered `[low, high]` rather than queueing a second
/// entry, so the buffer is bounded by the tracked-producer count no matter how
/// often a burst re-advertises. `low` takes the smaller bound (never
/// under-cover: an already-fetched seq is re-derived as an idempotent re-fetch,
/// a missed one is a permanent hole); `high` takes the larger; the newest
/// mapping / serving party wins.
fn coalesce_pending(pending: &mut HashMap<String, SyncUpdate>, update: SyncUpdate) {
    match pending.get_mut(&update.publisher) {
        Some(existing) => {
            existing.low_seq = existing.low_seq.min(update.low_seq);
            existing.high_seq = existing.high_seq.max(update.high_seq);
            existing.name = update.name;
            if update.mapping.is_some() {
                existing.mapping = update.mapping;
            }
            if update.serving_party.is_some() {
                existing.serving_party = update.serving_party;
            }
        }
        None => {
            pending.insert(update.publisher.clone(), update);
        }
    }
}

/// Exponentially-jittered suppression delay with mean
/// [`SvsConfig::suppression_period`], capped at 4× the mean. The
/// exponential shape makes one member of a large group statistically
/// fire well before the others, who then observe its reply and stay
/// quiet (ndn-svs suppression timer).
fn suppression_delay(config: &SvsConfig) -> Duration {
    let mean = config.suppression_period.as_secs_f64();
    if mean <= 0.0 {
        return Duration::ZERO;
    }
    let u = fastrand::f64().clamp(f64::MIN_POSITIVE, 1.0);
    let sampled = (-mean * u.ln()).min(mean * 4.0);
    Duration::from_secs_f64(sampled)
}

/// Map a remote state vector to `node_uri → (boot, seq)`.
fn remote_map(remote_sv: &[StateEntry]) -> HashMap<String, (u64, u64)> {
    remote_sv
        .iter()
        .map(|e| (e.name.to_string(), (e.boot, e.seq)))
        .collect()
}

/// True if local state is strictly ahead of `remote_sv` on at least one
/// node — i.e. the peer is missing a publication we already hold.
/// Comparison is `(boot, seq)` lexicographic so a peer that hasn't seen
/// our reboot counts as behind.
fn local_ahead_of_remote(
    local_snapshot: &[crate::svs::StateVectorEntry],
    remote_sv: &[StateEntry],
) -> bool {
    let remote = remote_map(remote_sv);
    local_snapshot.iter().any(|e| {
        let (rb, rs) = remote.get(&e.node).copied().unwrap_or((0, 0));
        (e.boot, e.seq) > (rb, rs)
    })
}

/// Merge a received vector into the suppression record, keeping the
/// highest `(boot, seq)` seen per node across the window.
fn record_vector(recorded: &mut HashMap<String, (u64, u64)>, remote_sv: &[StateEntry]) {
    for e in remote_sv {
        let slot = recorded.entry(e.name.to_string()).or_insert((0, 0));
        if (e.boot, e.seq) > *slot {
            *slot = (e.boot, e.seq);
        }
    }
}

/// `mapping` adds a `MappingData` (0xCD) TLV after the `StateVector`.
/// The Interest is signed by `signer` ([`Insecure`](crate::security::Insecure)
/// leaves it unsigned).
async fn send_sync_interest(
    group: &Name,
    node: &SvsNode,
    send: &mpsc::Sender<Bytes>,
    mapping: Option<Bytes>,
    signer: &Arc<dyn SyncSigner>,
    dialect: WireDialect,
) {
    let entries = node.state_entries().await;
    let mut app_params = dialect.encode_state_vector(&entries).to_vec();

    if let Some(mapping_bytes) = mapping {
        let local_key = node.local_key();
        let local_name: Name = local_key.parse().unwrap_or_else(|_| Name::root());
        let seq = node.local_seq().await;
        let mapping_tlv = encode_mapping_data(&local_name, seq, &mapping_bytes);
        app_params.extend_from_slice(&mapping_tlv);
    }

    let sync_name = group.clone().append_version(dialect.sync_version());
    let builder = InterestBuilder::new(sync_name)
        .lifetime(Duration::from_millis(1000))
        .app_parameters(app_params);
    let wire = signer.sign(builder);
    let _ = send.send(wire).await;
}

fn jitter_interval(config: &SvsConfig) -> Duration {
    let jitter = Duration::from_millis(fastrand::u64(0..=config.jitter_ms));
    config.sync_interval + jitter
}

use crate::tlv::{encode_nni, read_tlv, write_tlv};

fn remote_covers_local(
    local_snapshot: &[crate::svs::StateVectorEntry],
    remote_sv: &[StateEntry],
) -> bool {
    let remote = remote_map(remote_sv);
    local_snapshot.iter().all(|e| {
        let (rb, rs) = remote.get(&e.node).copied().unwrap_or((0, 0));
        (rb, rs) >= (e.boot, e.seq)
    })
}

fn encode_name_tlv(name: &Name) -> Vec<u8> {
    let mut inner = BytesMut::new();
    for comp in name.components() {
        write_tlv(&mut inner, comp.typ, &comp.value);
    }
    let mut outer = BytesMut::new();
    write_tlv(&mut outer, TLV_NDN_NAME, &inner);
    outer.to_vec()
}

/// Single `MappingData` (0xCD) wrapping one `MappingEntry` (0xCE)
/// with NodeID, SeqNo, and application-defined `app_data`.
fn encode_mapping_data(node_name: &Name, seq: u64, app_data: &[u8]) -> Vec<u8> {
    let name_bytes = encode_name_tlv(node_name);
    let seq_bytes = encode_nni(seq);

    let mut entry_inner = BytesMut::new();
    entry_inner.put_slice(&name_bytes);
    write_tlv(&mut entry_inner, TLV_SV_SEQ_NO, &seq_bytes);
    entry_inner.put_slice(app_data);

    let mut mapping_inner = BytesMut::new();
    write_tlv(&mut mapping_inner, TLV_MAPPING_ENTRY, &entry_inner);

    let mut buf = BytesMut::new();
    write_tlv(&mut buf, TLV_MAPPING_DATA, &mapping_inner);
    buf.to_vec()
}

fn decode_name_key(name_tlv: &[u8]) -> Option<String> {
    let (typ, value, _) = read_tlv(name_tlv)?;
    if typ != TLV_NDN_NAME {
        return None;
    }
    let name = Name::decode(Bytes::copy_from_slice(value)).ok()?;
    Some(name.to_string())
}

/// `MappingData` (0xCD) → `node_key → app_data`. `app_data` is
/// everything after `NodeID` and `SeqNo` inside each `MappingEntry`.
fn decode_mapping_data(md_tlv: &[u8]) -> HashMap<String, Bytes> {
    let mut result = HashMap::new();
    let Some((typ, mut body, _)) = read_tlv(md_tlv) else {
        return result;
    };
    if typ != TLV_MAPPING_DATA {
        return result;
    }

    while !body.is_empty() {
        let Some((entry_typ, mut entry_body, rest)) = read_tlv(body) else {
            break;
        };
        body = rest;
        if entry_typ != TLV_MAPPING_ENTRY {
            continue;
        }

        // NodeID.
        let Some((name_typ, name_val, after_name)) = read_tlv(entry_body) else {
            continue;
        };
        if name_typ != TLV_NDN_NAME {
            continue;
        }
        let mut name_bytes = BytesMut::new();
        write_tlv(&mut name_bytes, name_typ, name_val);
        let Some(node_key) = decode_name_key(&name_bytes) else {
            continue;
        };

        entry_body = after_name;

        // SeqNo — read and discard (we match by node_key, not seq).
        let Some((seq_typ, _, after_seq)) = read_tlv(entry_body) else {
            continue;
        };
        if seq_typ != TLV_SV_SEQ_NO {
            continue;
        }

        // Remaining bytes are the application-defined AppData.
        let app_data = Bytes::copy_from_slice(after_seq);
        result.insert(node_key, app_data);
    }

    result
}

/// `(state_vector, mapping_map)` where `mapping_map` is empty when no
/// MappingData TLV is present.
type ParsedSyncInterest = (Vec<StateEntry>, HashMap<String, Bytes>);

fn parse_sync_interest(
    group: &Name,
    raw: &[u8],
    dialect: WireDialect,
) -> Option<ParsedSyncInterest> {
    let interest = ndn_packet::Interest::decode(Bytes::copy_from_slice(raw)).ok()?;
    let components = interest.name.components();

    let group_len = group.components().len();
    if components.len() < group_len + 1 {
        return None;
    }
    // The component after the group prefix must be the typed version for
    // this dialect (`v=2` for ndn-svs, `v=3` for ndnd), not a generic
    // component — this is also what keeps the two dialects from
    // mis-parsing each other's Interests.
    if components[group_len].as_version() != Some(dialect.sync_version()) {
        return None;
    }

    let app_params = interest.app_parameters()?;

    let mut sv: Option<Vec<StateEntry>> = None;
    let mut mappings: HashMap<String, Bytes> = HashMap::new();
    let mut cursor: &[u8] = app_params;

    while !cursor.is_empty() {
        let Some((typ, _value, rest)) = read_tlv(cursor) else {
            break;
        };
        let consumed = cursor.len() - rest.len();
        let full_tlv = &cursor[..consumed];

        match typ {
            TLV_MAPPING_DATA => {
                mappings = decode_mapping_data(full_tlv);
            }
            // The state-vector outer type 0xC9 (201) is shared by both
            // dialects (v2 StateVector / v3 SvsData); the dialect codec
            // handles the differing inner shape.
            TLV_STATE_VECTOR_OUTER => {
                sv = dialect.decode_state_vector(&Bytes::copy_from_slice(full_tlv));
            }
            _ => {}
        }

        cursor = rest;
    }

    sv.map(|v| (v, mappings))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::svs::StateVectorEntry;

    /// Default test dialect.
    const V2: WireDialect = WireDialect::V2;

    /// The named-environment presets carry sensible per-environment tunings and change
    /// nothing else — an app picks an environment instead of reverse-engineering the
    /// reference constants.
    #[test]
    fn environment_presets_carry_sane_tunings() {
        let (lan, wan, sim) = (SvsConfig::lan(), SvsConfig::wan(), SvsConfig::sim());
        let dflt = SvsConfig::default();

        // The orderings that define the environments.
        assert!(lan.sync_interval < wan.sync_interval, "lan is tighter than wan");
        assert!(sim.sync_interval <= lan.sync_interval, "sim is at least as tight as lan");
        assert!(wan.sync_interval <= dflt.sync_interval, "wan stays under the lab default");
        assert!(
            lan.suppression_period < wan.suppression_period,
            "wan gives catch-up replies room across real latency spreads"
        );
        assert_eq!(sim.jitter_ms, 0, "sim is deterministic: no interval jitter");

        // Internal coherence: jitter and suppression stay well inside the periodic interval.
        for (tag, c) in [("lan", &lan), ("wan", &wan), ("sim", &sim), ("default", &dflt)] {
            assert!(
                Duration::from_millis(c.jitter_ms) < c.sync_interval,
                "{tag}: jitter must not swamp the interval"
            );
            assert!(
                c.suppression_period < c.sync_interval,
                "{tag}: suppression must resolve before the next periodic round"
            );
        }

        // Presets are tuning-only: posture and plumbing stay at the defaults.
        for c in [&lan, &wan, &sim] {
            assert!(c.auto_ack, "presets do not flip the commit posture");
            assert_eq!(c.channel_capacity, dflt.channel_capacity);
            assert_eq!(c.local_boot, 0);
            assert_eq!(c.local_seq, 0);
        }
    }

    /// Build a remote state vector (boot = 0) from `(node, seq)` pairs.
    fn sv(entries: &[(&str, u64)]) -> Vec<StateEntry> {
        entries
            .iter()
            .map(|(n, s)| StateEntry {
                name: n.parse().unwrap(),
                boot: 0,
                seq: *s,
            })
            .collect()
    }

    /// Build a local snapshot entry (boot = 0).
    fn local(node: &str, seq: u64) -> StateVectorEntry {
        StateVectorEntry {
            node: node.to_string(),
            boot: 0,
            seq,
        }
    }

    #[test]
    fn mapping_data_roundtrip() {
        let name: Name = "/alice".parse().unwrap();
        let app_data = Bytes::from_static(b"hello-mapping");
        let encoded = encode_mapping_data(&name, 42, &app_data);

        assert_eq!(encoded[0], 0xCD, "MappingData type must be 205 (0xCD)");

        let decoded = decode_mapping_data(&encoded);
        let got = decoded.get("/alice").cloned().expect("entry for /alice");
        assert_eq!(got, app_data);
    }

    #[test]
    fn mapping_data_multiple_entries_roundtrip() {
        let a = encode_mapping_data(&"/a".parse().unwrap(), 1, b"data-a");
        let b = encode_mapping_data(&"/b".parse().unwrap(), 2, b"data-b");

        let da = decode_mapping_data(&a);
        let db = decode_mapping_data(&b);
        assert_eq!(da["/a"].as_ref(), b"data-a");
        assert_eq!(db["/b"].as_ref(), b"data-b");
    }

    #[test]
    fn remote_covers_local_true() {
        let snap = vec![local("/a", 3), local("/b", 1)];
        assert!(remote_covers_local(&snap, &sv(&[("/a", 3), ("/b", 5)])));
    }

    #[test]
    fn remote_covers_local_false_when_behind() {
        let snap = vec![local("/a", 5)];
        assert!(!remote_covers_local(&snap, &sv(&[("/a", 3)])));
    }

    #[test]
    fn remote_covers_local_false_when_missing_node() {
        let snap = vec![local("/a", 1)];
        assert!(!remote_covers_local(&snap, &sv(&[])));
    }

    #[tokio::test]
    async fn fetch_with_retry_succeeds_on_first_try() {
        let result = fetch_with_retry(RetryPolicy::default(), |_attempt| async {
            Ok::<_, &str>("ok")
        })
        .await;
        assert_eq!(result, Ok("ok"));
    }

    #[tokio::test]
    async fn fetch_with_retry_retries_on_failure() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        let calls = Arc::new(AtomicU32::new(0));
        let calls2 = calls.clone();

        let policy = RetryPolicy {
            max_retries: 3,
            base_delay: Duration::from_millis(1),
            backoff_factor: 1.0,
        };

        let result: Result<(), &str> = fetch_with_retry(policy, move |_| {
            let c = calls2.clone();
            async move {
                let n = c.fetch_add(1, Ordering::SeqCst);
                if n < 2 { Err("fail") } else { Ok(()) }
            }
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn fetch_with_retry_exhausts_retries() {
        let policy = RetryPolicy {
            max_retries: 2,
            base_delay: Duration::from_millis(1),
            backoff_factor: 1.0,
        };

        let result: Result<(), &str> =
            fetch_with_retry(policy, |_| async { Err("always fail") }).await;
        assert_eq!(result, Err("always fail"));
    }

    #[tokio::test]
    async fn join_and_leave() {
        let (send_tx, _send_rx) = mpsc::channel(16);
        let (_recv_tx, recv_rx) = mpsc::channel(16);

        let group: Name = "/test/svs".parse().unwrap();
        let local: Name = "/test/svs/node-a".parse().unwrap();

        let handle = join_svs_group(group, local, send_tx, recv_rx, SvsConfig::default());
        handle.leave();
    }

    #[tokio::test]
    async fn sync_interest_carries_app_params() {
        let (send_tx, mut send_rx) = mpsc::channel(16);
        let (_recv_tx, recv_rx) = mpsc::channel(16);

        let group: Name = "/test/svs".parse().unwrap();
        let local: Name = "/node-a".parse().unwrap();

        let config = SvsConfig {
            sync_interval: Duration::from_millis(10),
            jitter_ms: 0,
            ..Default::default()
        };

        let _handle = join_svs_group(group.clone(), local.clone(), send_tx, recv_rx, config);

        let raw = tokio::time::timeout(Duration::from_secs(2), send_rx.recv())
            .await
            .expect("timed out")
            .expect("channel closed");

        let interest = ndn_packet::Interest::decode(raw).expect("decode interest");
        let ap = interest.app_parameters().expect("must have AppParameters");
        let decoded = V2
            .decode_state_vector(&Bytes::copy_from_slice(ap))
            .expect("must decode StateVector");
        assert!(
            !decoded.is_empty(),
            "state vector should contain local node"
        );
    }

    /// Build a raw Sync Interest carrying `entries` as its state vector,
    /// as a v2 peer on the wire would send it.
    fn peer_sync_interest(group: &Name, entries: &[(&str, u64)]) -> Bytes {
        let app_params = V2.encode_state_vector(&sv(entries)).to_vec();
        InterestBuilder::new(group.clone().append_version(V2.sync_version()))
            .lifetime(Duration::from_millis(1000))
            .app_parameters(app_params)
            .build()
    }

    /// gap #9 golden: the v2 Sync Interest name appends a typed VERSION
    /// component (`0x36`) = 2, matching ndn-svs `core.cpp:351`
    /// `appendVersion(2)` — byte-for-byte against
    /// `testbed/fixtures/svs/sync_interest_v2_name.hex`.
    #[test]
    fn sync_interest_name_matches_ndn_svs_v2() {
        let group: Name = "/ndn/svs".parse().unwrap();
        let name = group.clone().append_version(V2.sync_version());

        // Reconstruct the NAME TLV inner bytes and compare to the fixture.
        let mut inner = BytesMut::new();
        for comp in name.components() {
            write_tlv(&mut inner, comp.typ, &comp.value);
        }
        let mut name_tlv = BytesMut::new();
        write_tlv(&mut name_tlv, TLV_NDN_NAME, &inner);

        let fixture = "070d08036e646e0803737673360102";
        let actual: String = name_tlv.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            actual, fixture,
            "v2 Sync Interest name must match ndn-svs appendVersion(2)"
        );

        // And the structural accessor agrees.
        assert_eq!(
            name.components().last().unwrap().as_version(),
            Some(2),
            "trailing component must be VERSION=2"
        );
    }

    #[tokio::test]
    async fn v3_dialect_drives_name_and_codec() {
        // A node configured for V3 must emit `<group>/v=3` carrying a v3
        // (boot-timestamped) state vector, parseable by a V3 peer and
        // rejected by a V2 peer (version mismatch).
        let (send_tx, mut send_rx) = mpsc::channel(16);
        let (_recv_tx, recv_rx) = mpsc::channel(16);

        let group: Name = "/app/v3".parse().unwrap();
        let local: Name = "/app/v3/node".parse().unwrap();
        let config = SvsConfig {
            sync_interval: Duration::from_millis(10),
            jitter_ms: 0,
            dialect: WireDialect::V3,
            local_boot: 1_700_000_000_000,
            ..Default::default()
        };

        let _handle = join_svs_group(group.clone(), local, send_tx, recv_rx, config);

        let raw = tokio::time::timeout(Duration::from_secs(2), send_rx.recv())
            .await
            .expect("timed out")
            .expect("channel closed");

        let interest = ndn_packet::Interest::decode(raw.clone()).expect("decode");
        // Name version is v=3.
        let gl = group.components().len();
        assert_eq!(interest.name.components()[gl].as_version(), Some(3));

        // A V3 peer parses it; the local entry carries our boot.
        let (entries, _) = parse_sync_interest(&group, &raw, WireDialect::V3).expect("v3 parse");
        let me = entries
            .iter()
            .find(|e| e.name.to_string() == "/app/v3/node");
        assert_eq!(me.map(|e| e.boot), Some(1_700_000_000_000));

        // A V2 peer rejects it on the version component.
        assert!(
            parse_sync_interest(&group, &raw, WireDialect::V2).is_none(),
            "v2 must not accept a v=3 Sync Interest"
        );
    }

    #[test]
    fn parser_rejects_legacy_generic_svs_component() {
        // A peer (or our own old code) appending a generic "svs"
        // component must no longer be accepted as a v2 Sync Interest.
        let group: Name = "/ndn/svs".parse().unwrap();
        let legacy = InterestBuilder::new(group.clone().append("svs"))
            .app_parameters(V2.encode_state_vector(&sv(&[("/ndn/svs/a", 1)])).to_vec())
            .build();
        assert!(
            parse_sync_interest(&group, &legacy, V2).is_none(),
            "generic 'svs' component must be rejected"
        );

        let good = peer_sync_interest(&group, &[("/ndn/svs/a", 1)]);
        assert!(
            parse_sync_interest(&group, &good, V2).is_some(),
            "v=2 component must parse"
        );
    }

    #[tokio::test]
    async fn reply_to_stale_fires_within_suppression_window() {
        // A node that is *ahead* of an incoming (stale) peer vector must
        // reply well before the steady periodic interval — this is the
        // sub-second partition/rejoin recovery the suppression FSM exists
        // for. We set the periodic interval to 60 s so any reply we see
        // can only come from the suppression path.
        let (send_tx, mut send_rx) = mpsc::channel(16);
        let (recv_tx, recv_rx) = mpsc::channel(16);

        let group: Name = "/test/svs".parse().unwrap();
        let local: Name = "/test/svs/node-ahead".parse().unwrap();

        let config = SvsConfig {
            sync_interval: Duration::from_secs(60),
            jitter_ms: 0,
            suppression_period: Duration::from_millis(40),
            ..Default::default()
        };

        let handle = join_svs_group(group.clone(), local.clone(), send_tx, recv_rx, config);

        // Publish so we advance to seq 1 (now ahead of any peer at 0).
        handle.publish(local.clone()).await.expect("publish");
        // Drain the immediate post-publish announcement.
        let _ = tokio::time::timeout(Duration::from_secs(1), send_rx.recv())
            .await
            .expect("post-publish interest")
            .expect("channel open");

        // Feed a stale peer vector that does not know our seq=1.
        let stale = peer_sync_interest(&group, &[("/test/svs/node-behind", 0)]);
        recv_tx.send(stale).await.expect("send stale");

        // The suppressed reply must arrive far sooner than 60 s.
        let replied = tokio::time::timeout(Duration::from_secs(2), send_rx.recv()).await;
        assert!(
            replied.is_ok() && replied.unwrap().is_some(),
            "node should emit a suppressed catch-up Interest for the stale peer"
        );
    }

    #[tokio::test]
    async fn steady_state_suppression_defers_periodic_interest() {
        // When a peer's vector already covers us, our next periodic
        // Interest is pushed out (interest-storm suppression). With a
        // short interval but a covering peer arriving each round, the
        // node should stay quiet rather than emit back-to-back.
        let (send_tx, mut send_rx) = mpsc::channel(16);
        let (recv_tx, recv_rx) = mpsc::channel(16);

        let group: Name = "/test/svs".parse().unwrap();
        let local: Name = "/test/svs/node-q".parse().unwrap();

        let config = SvsConfig {
            sync_interval: Duration::from_millis(120),
            jitter_ms: 0,
            suppression_period: Duration::from_millis(40),
            ..Default::default()
        };

        let _handle = join_svs_group(group.clone(), local.clone(), send_tx, recv_rx, config);

        // Drain the first periodic Interest.
        let _ = tokio::time::timeout(Duration::from_secs(1), send_rx.recv())
            .await
            .expect("first interest")
            .expect("channel open");

        // A peer that already covers us (knows our seq=0) arrives — should
        // reset our periodic timer, so no Interest in the next ~80 ms.
        let covering = peer_sync_interest(&group, &[("/test/svs/node-q", 0)]);
        recv_tx.send(covering).await.expect("send covering");

        let quiet = tokio::time::timeout(Duration::from_millis(80), send_rx.recv()).await;
        assert!(
            quiet.is_err(),
            "covering peer should defer our periodic Interest"
        );
    }

    #[tokio::test]
    async fn sync_update_name_is_publisher_components() {
        // Regression for the `group.append(peer_key)` smell: the fetch
        // prefix handed to consumers must be the publisher's real
        // component-wise Name, not one opaque component holding the URI.
        let (send_tx, _send_rx) = mpsc::channel(16);
        let (recv_tx, recv_rx) = mpsc::channel(16);

        let group: Name = "/test/svs".parse().unwrap();
        let local: Name = "/test/svs/me".parse().unwrap();

        let mut handle = join_svs_group(
            group.clone(),
            local.clone(),
            send_tx,
            recv_rx,
            SvsConfig::default(),
        );

        let peer = "/test/svs/peer-x";
        recv_tx
            .send(peer_sync_interest(&group, &[(peer, 3)]))
            .await
            .expect("send peer interest");

        let update = tokio::time::timeout(Duration::from_secs(2), handle.recv())
            .await
            .expect("timed out")
            .expect("update");

        let expected: Name = peer.parse().unwrap();
        assert_eq!(
            update.name, expected,
            "fetch name must be the publisher Name"
        );
        assert_eq!(
            update.name.components().len(),
            expected.components().len(),
            "publisher name must not collapse into one opaque component"
        );
    }

    #[tokio::test]
    async fn validator_drops_unsigned_then_accepts_signed() {
        use crate::security::HmacKey;
        let group: Name = "/ndn/svs".parse().unwrap();
        let local: Name = "/ndn/svs/me".parse().unwrap();
        let key = HmacKey::new(b"group-key".to_vec(), "/keys/g".parse::<Name>().unwrap());

        let config = SvsConfig {
            sync_interval: Duration::from_secs(60),
            jitter_ms: 0,
            signer: Arc::new(key.clone()),
            validator: Arc::new(key.clone()),
            ..Default::default()
        };
        let (send_tx, _send_rx) = mpsc::channel(16);
        let (recv_tx, recv_rx) = mpsc::channel(16);
        let mut handle = join_svs_group(group.clone(), local, send_tx, recv_rx, config);

        // Unsigned peer Interest → validator drops it, no SyncUpdate.
        let unsigned = peer_sync_interest(&group, &[("/ndn/svs/peer", 4)]);
        recv_tx.send(unsigned).await.unwrap();
        let none = tokio::time::timeout(Duration::from_millis(300), handle.recv()).await;
        assert!(
            none.is_err(),
            "unsigned interest must not produce an update"
        );

        // Correctly HMAC-signed peer Interest → accepted, update emitted.
        let signed = key.sign(
            InterestBuilder::new(group.clone().append_version(V2.sync_version()))
                .lifetime(Duration::from_millis(1000))
                .app_parameters(
                    V2.encode_state_vector(&sv(&[("/ndn/svs/peer", 4)]))
                        .to_vec(),
                ),
        );
        recv_tx.send(signed).await.unwrap();
        let upd = tokio::time::timeout(Duration::from_secs(2), handle.recv())
            .await
            .expect("timed out")
            .expect("update");
        assert_eq!(upd.publisher, "/ndn/svs/peer");
        assert_eq!(upd.high_seq, 4);
    }

    #[tokio::test]
    async fn sync_interest_carries_mapping_after_publish_with_mapping() {
        let (send_tx, mut send_rx) = mpsc::channel(16);
        let (_recv_tx, recv_rx) = mpsc::channel(16);

        let group: Name = "/test/svs".parse().unwrap();
        let local: Name = "/node-m".parse().unwrap();

        let config = SvsConfig {
            sync_interval: Duration::from_secs(60),
            jitter_ms: 0,
            ..Default::default()
        };

        let handle = join_svs_group(group.clone(), local.clone(), send_tx, recv_rx, config);

        handle
            .publish_with_mapping(local.clone(), Bytes::from_static(b"test-mapping"))
            .await
            .expect("publish_with_mapping");

        let raw = tokio::time::timeout(Duration::from_secs(2), send_rx.recv())
            .await
            .expect("timed out")
            .expect("channel closed");

        let interest = ndn_packet::Interest::decode(raw).expect("decode interest");
        let ap = interest.app_parameters().expect("AppParameters present");

        let mut found_mapping = false;
        let mut cursor: &[u8] = ap;
        while !cursor.is_empty() {
            let Some((typ, _val, rest)) = read_tlv(cursor) else {
                break;
            };
            let consumed = cursor.len() - rest.len();
            if typ == TLV_MAPPING_DATA {
                let mappings = decode_mapping_data(&cursor[..consumed]);
                let key = local.to_string();
                if let Some(data) = mappings.get(&key) {
                    assert_eq!(data.as_ref(), b"test-mapping");
                    found_mapping = true;
                }
            }
            cursor = rest;
        }
        assert!(found_mapping, "MappingData TLV not found in AppParameters");
    }

    #[tokio::test]
    async fn burst_does_not_wedge_the_select_loop() {
        // N-11 / NS-7 regression. The old code delivered gaps with
        // `update_tx.send(update).await` *inside* the select loop; once the
        // bounded update channel filled, that await parked the whole loop, so
        // the timer, `recv`, and `ack_rx` arms all went unreachable — and a
        // two-phase consumer blocked sending an ack deadlocked against it
        // (~44 Blocks into a 400-Block catch-up in the field).
        //
        // With a capacity-1 update channel that we deliberately never drain, a
        // burst of gap-producing Sync Interests must NOT freeze the task: it
        // has to keep emitting periodic Sync Interests AND keep servicing acks
        // while the update backlog is saturated.
        let (send_tx, mut send_rx) = mpsc::channel(64);
        let (recv_tx, recv_rx) = mpsc::channel(64);

        let group: Name = "/test/svs".parse().unwrap();
        let local: Name = "/test/svs/me".parse().unwrap();

        let config = SvsConfig {
            sync_interval: Duration::from_millis(30),
            jitter_ms: 0,
            channel_capacity: 1, // saturates after a single undrained update
            auto_ack: false,     // deferred: the two-phase path that deadlocked
            ..Default::default()
        };

        let handle = join_svs_group(group.clone(), local, send_tx, recv_rx, config);

        // Drain the first (post-join) periodic interest so we start clean.
        let _ = tokio::time::timeout(Duration::from_secs(1), send_rx.recv())
            .await
            .expect("first periodic interest")
            .expect("channel open");

        // Saturate the capacity-1 update channel without draining it: feed
        // several distinct-publisher gaps. The first fills the channel, the
        // rest coalesce into the pending buffer. Under the old blocking send,
        // the second gap parked the select loop here forever.
        for i in 0..8 {
            let peer = format!("/test/svs/peer-{i}");
            recv_tx
                .send(peer_sync_interest(&group, &[(&peer, 5)]))
                .await
                .expect("feed peer interest");
        }

        // Liveness probe #1: periodic Sync Interests keep flowing even though
        // the update backlog is full and undrained.
        for _ in 0..3 {
            let tick = tokio::time::timeout(Duration::from_millis(500), send_rx.recv()).await;
            assert!(
                matches!(tick, Ok(Some(_))),
                "task wedged: no periodic Sync Interest while the update backlog is saturated"
            );
        }

        // Liveness probe #2: the ack arm is still serviced under that same
        // saturation. In deferred mode only `ack` advances the vector, so once
        // peer-0 is acked to seq 5 the next periodic Sync Interest must
        // advertise peer-0 at 5 — proving the task processed the ack rather
        // than being frozen mid-`update_tx.send`.
        handle
            .ack("/test/svs/peer-0", 5)
            .await
            .expect("ack channel open");

        let advertised = loop {
            let raw = tokio::time::timeout(Duration::from_secs(1), send_rx.recv())
                .await
                .expect("periodic interest after ack (loop wedged?)")
                .expect("channel open");
            let (sv, _) = parse_sync_interest(&group, &raw, V2).expect("parse sync interest");
            if let Some(e) = sv.iter().find(|e| e.name.to_string() == "/test/svs/peer-0")
                && e.seq == 5
            {
                break e.seq;
            }
        };
        assert_eq!(advertised, 5, "acked seq must be advertised (ack arm serviced)");
    }

    /// Poll the observed high-water for `name` until it reaches `want` (recording
    /// is asynchronous in the task) or fail after a bounded wait.
    async fn wait_observed(obs: &ObservedState, name: &Name, want: u64) {
        for _ in 0..200 {
            if obs.seq_for(name) == Some(want) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("observed {name} never reached {want}; got {:?}", obs.seq_for(name));
    }

    #[tokio::test]
    async fn observed_records_high_water_by_name() {
        // N-9: the observed accessor reports a per-NAME depth — highest seq any
        // peer advertised — never regressing, and absent for a name never seen.
        let (send_tx, _send_rx) = mpsc::channel(64);
        let (recv_tx, recv_rx) = mpsc::channel(64);

        let group: Name = "/test/svs".parse().unwrap();
        let local: Name = "/test/svs/me".parse().unwrap();
        let config = SvsConfig {
            sync_interval: Duration::from_secs(60),
            jitter_ms: 0,
            auto_ack: false,
            ..Default::default()
        };
        let handle = join_svs_group(group.clone(), local, send_tx, recv_rx, config);
        let obs = handle.observed().expect("svs records observed high-water");

        let pubn: Name = "/test/svs/pub".parse().unwrap();
        recv_tx.send(peer_sync_interest(&group, &[("/test/svs/pub", 5)])).await.unwrap();
        wait_observed(obs, &pubn, 5).await;
        assert_eq!(obs.seq_for(&"/test/svs/never".parse().unwrap()), None, "unseen name absent");

        // A lower advert then a higher one, in order: reaching 8 proves the
        // interleaved 3 was processed and did NOT regress the high-water.
        recv_tx.send(peer_sync_interest(&group, &[("/test/svs/pub", 3)])).await.unwrap();
        recv_tx.send(peer_sync_interest(&group, &[("/test/svs/pub", 8)])).await.unwrap();
        wait_observed(obs, &pubn, 8).await;
    }

    #[tokio::test]
    async fn observed_captures_carriage_of_our_own_name() {
        // N-9's load-bearing case: a peer advertising OUR OWN name means it has
        // verified+stored our data — the "carried" signal. The authoritative
        // merge drops self (authoritative-for-self), so `observed` is the only
        // place it surfaces; and it must stay OUT of the authoritative advertised
        // vector (a depth, never our real publish count).
        let (send_tx, mut send_rx) = mpsc::channel(64);
        let (recv_tx, recv_rx) = mpsc::channel(64);

        let group: Name = "/test/svs".parse().unwrap();
        let local: Name = "/test/svs/me".parse().unwrap();
        let config = SvsConfig {
            sync_interval: Duration::from_secs(60),
            jitter_ms: 0,
            auto_ack: false,
            ..Default::default()
        };
        let handle = join_svs_group(group.clone(), local.clone(), send_tx, recv_rx, config);
        let obs = handle.observed().expect("observed present");

        // (60 s interval → no immediate periodic; the only send is the forced
        // post-publish announce captured below.)
        // Peer claims it has stored our data to seq 7.
        recv_tx.send(peer_sync_interest(&group, &["/test/svs/me"].map(|n| (n, 7)))).await.unwrap();
        wait_observed(obs, &local, 7).await;

        // Our OWN authoritative publish count is independent: one publish
        // advertises me@1 (our real count), NOT me@7 (the observation).
        handle.publish(local.clone()).await.expect("publish");
        let raw = tokio::time::timeout(Duration::from_secs(1), send_rx.recv())
            .await
            .expect("post-publish interest")
            .expect("open");
        let (sv, _) = parse_sync_interest(&group, &raw, V2).expect("parse");
        let me_seq = sv.iter().find(|e| e.name == local).map(|e| e.seq);
        assert_eq!(me_seq, Some(1), "authoritative advertised seq is our real publish count");
        assert_eq!(obs.seq_for(&local), Some(7), "observation is a separate 'carried to 7' depth");
    }
}
