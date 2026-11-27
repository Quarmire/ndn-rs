//! The asker's half: a query on `get`, its targets, its pending set and its deadline
//! (docs/specs/query.md, Several servers).
//!
//! `get` does no I/O in the caller's task: [`NodeInner::query_prepare`] judges the request and
//! makes the [`Run`], the `Items` takes the answer queue, and [`NodeInner::query_spawn`] runs the
//! query on the node's tasks. The run resolves who is asked ([`NodeInner::query_targets`]), asks
//! each server once (one signed Interest each, [`NodeInner::ask_server`]), tells each answer as
//! it is judged and ends with exactly one `AnswersDone` ([`drive`]). Dropping `Items` cancels the
//! run: its Interests are dropped, a late answer is discarded and the pending set is released.
//!
//! **An answer is judged as a signed Data** (docs/specs/query.md, How the server judges): the name
//! is the Interest's, it verifies as the server device's from the certificates held and the at most
//! four it carries (nothing is fetched), the signer is a **writer now**, the query id is the one
//! asked, an answer is at most `answer_max` octets, and in a sealed space it opens under the pair
//! key. Anything else is `QueryFailed { BadAnswer }`.
//!
//! **Sealed spaces.** The asker learns the server's recipient key from the `<server>/32=seal`
//! packet the server's device signed, derives one pair key per (space, server, epoch) from one
//! X25519 agreement and seals every query of the epoch under it with a counter of its own. Both
//! caches are memory, bounded, and dropped when the epoch, the trust generation or the members
//! fold moves.

use std::collections::HashMap;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::Bytes;
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use ndn_app::{AppError, Consumer};
use ndn_foundation_types::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_packet::{Data, Interest, NackReason};
use ndn_security::{PairKeys, pair_keys_to};
use parking_lot::Mutex;

use super::answers::AnswerSink;
use super::types::{
    ANSWER_MAX_DEFAULT, Answered, AppRefusal, Ask, DEADLINE_MAX, QUERY_MAX, QueryError, QueryId,
    QueryPath, TARGETS_MAX, Targets, Via,
};
use super::{answer_aad, open_answer, pair_context, query_aad, seal_query};
use crate::chan::ask::is_reserved;
use crate::chan::standing::{Who, gate, standing};
use crate::chan::verbs::{GetNotice, Got, Kind, Select};
use crate::error::HeapError;
use crate::node::NodeInner;
use crate::rt::Instant;
use crate::space::SpaceInner;
use crate::trust::Judged;
use crate::wire::{
    AnswerBody, AskSeal, DEADLINE_MAX_MS, EpochId, QUERY_PATH_MAX, QueryAnswer, QueryAsk, Status,
    is_device_name, parse_seal_key_name, query_prefix, seal_prefix,
};

/// The most queries one node has outstanding, over all servers.
pub(crate) const PENDING_TOTAL: usize = 64;

/// The most queries one node has outstanding to one server.
pub(crate) const PENDING_PER_SERVER: usize = 16;

/// The most server seal keys, and the most pair keys, one node caches.
pub(crate) const KEYS_MAX: usize = 64;

/// What the asker keeps: its pending queries and its pair keys.
#[derive(Default)]
pub(crate) struct AskState {
    pending: Mutex<Pending>,
    keys: Mutex<Keys>,
}

// -- The pending set ------------------------------------------------------------------------------

/// The queries outstanding: in all, and to each server.
#[derive(Default)]
pub(crate) struct Pending {
    total: usize,
    per_server: HashMap<Name, usize>,
}

impl Pending {
    /// Count one more query to `server`, if neither limit is reached.
    pub(crate) fn acquire(&mut self, server: &Name, total: usize, per_server: usize) -> bool {
        let held = self.per_server.get(server).copied().unwrap_or(0);
        if self.total >= total || held >= per_server {
            return false;
        }
        self.total += 1;
        *self.per_server.entry(server.clone()).or_insert(0) += 1;
        true
    }

    /// One query to `server` ended.
    pub(crate) fn release(&mut self, server: &Name) {
        self.total = self.total.saturating_sub(1);
        if let Some(held) = self.per_server.get_mut(server) {
            *held -= 1;
            if *held == 0 {
                self.per_server.remove(server);
            }
        }
    }

    /// Queries outstanding in all.
    #[cfg(test)]
    pub(crate) fn total(&self) -> usize {
        self.total
    }
}

/// A slot of the pending set, released when dropped: the query resolved, or `Items` was dropped.
struct Slot {
    node: Arc<NodeInner>,
    server: Name,
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.node.query.ask.pending.lock().release(&self.server);
    }
}

// -- The keys of a sealed space -------------------------------------------------------------------

/// A server's seal key as the asker judged it.
struct SealKey {
    public: [u8; 32],
    /// The trust generation it was judged at.
    generation: u64,
    used: u64,
}

/// The pair keys of one (space, server) for one epoch, and the counter the asker seals with.
struct Pair {
    epoch: EpochId,
    public: [u8; 32],
    ephemeral: [u8; 32],
    keys: Arc<PairKeys>,
    /// The next sealing counter: never used twice under these keys.
    next: u64,
    /// The trust generation and members-fold version it was derived at.
    judged_at: (u64, u64),
    used: u64,
}

#[derive(Default)]
pub(super) struct Keys {
    clock: u64,
    /// X25519 agreements made: what the tests count.
    #[cfg(test)]
    pub(super) agreements: u64,
    seals: HashMap<Name, SealKey>,
    pairs: HashMap<(Name, Name), Pair>,
}

/// What a sealed query is sealed with: the keys, the ephemeral key the server derives them from,
/// the epoch and the counter of this query.
pub(super) struct SealUse {
    pub(super) keys: Arc<PairKeys>,
    pub(super) ephemeral: [u8; 32],
    pub(super) epoch: EpochId,
    pub(super) seq: u64,
}

impl Keys {
    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    /// The seal key of `server` judged at `generation`, if one is held.
    pub(super) fn seal_public(&mut self, server: &Name, generation: u64) -> Option<[u8; 32]> {
        let used = self.tick();
        let held = self.seals.get_mut(server)?;
        if held.generation != generation {
            self.seals.remove(server);
            return None;
        }
        held.used = used;
        Some(held.public)
    }

    pub(super) fn put_seal(&mut self, server: &Name, public: [u8; 32], generation: u64) {
        self.seals.retain(|_, s| s.generation == generation);
        if self.seals.len() >= KEYS_MAX
            && !self.seals.contains_key(server)
            && let Some(oldest) = self
                .seals
                .iter()
                .min_by_key(|(_, s)| s.used)
                .map(|(n, _)| n.clone())
        {
            self.seals.remove(&oldest);
        }
        let used = self.tick();
        self.seals.insert(
            server.clone(),
            SealKey {
                public,
                generation,
                used,
            },
        );
    }

    /// The keys of `space` to `server` for `epoch`, derived once and then reused: the counter of
    /// the next query. A key of another epoch or public key, or judged before the trust
    /// generation or the members fold moved, is replaced.
    pub(super) fn pair(
        &mut self,
        space: &Name,
        asker: &Name,
        server: &Name,
        epoch: &EpochId,
        public: [u8; 32],
        judged_at: (u64, u64),
    ) -> Result<SealUse, ndn_security::confidentiality::ConfidentialityError> {
        self.pairs.retain(|(sp, _), p| {
            p.judged_at.0 == judged_at.0 && (sp != space || p.judged_at.1 == judged_at.1)
        });
        let used = self.tick();
        let key = (space.clone(), server.clone());
        if let Some(pair) = self.pairs.get_mut(&key)
            && pair.epoch == *epoch
            && pair.public == public
        {
            let seq = pair.next;
            pair.next += 1;
            pair.used = used;
            return Ok(SealUse {
                keys: Arc::clone(&pair.keys),
                ephemeral: pair.ephemeral,
                epoch: pair.epoch.clone(),
                seq,
            });
        }
        let context = pair_context(space, asker, server, epoch);
        #[cfg(test)]
        {
            self.agreements += 1;
        }
        let (ephemeral, keys) = pair_keys_to(&public, &context)?;
        let keys = Arc::new(keys);
        if self.pairs.len() >= KEYS_MAX
            && !self.pairs.contains_key(&key)
            && let Some(oldest) = self
                .pairs
                .iter()
                .min_by_key(|(_, p)| p.used)
                .map(|(k, _)| k.clone())
        {
            self.pairs.remove(&oldest);
        }
        self.pairs.insert(
            key,
            Pair {
                epoch: epoch.clone(),
                public,
                ephemeral,
                keys: Arc::clone(&keys),
                next: 1,
                judged_at,
                used,
            },
        );
        Ok(SealUse {
            keys,
            ephemeral,
            epoch: epoch.clone(),
            seq: 0,
        })
    }

    /// Forget everything held of `server`: it is no writer any more.
    pub(super) fn forget(&mut self, server: &Name) {
        self.seals.remove(server);
        self.pairs.retain(|(_, s), _| s != server);
    }

    #[cfg(test)]
    pub(super) fn counts(&self) -> (usize, usize) {
        (self.seals.len(), self.pairs.len())
    }
}

// -- Outcomes and the run -------------------------------------------------------------------------

/// How one asked server resolved. Each is exactly one bucket of `AnswersDone`.
pub(crate) enum Outcome {
    /// The server gave bytes.
    Answered(Got),
    /// The server's handler refused: the application's word, told as an answer.
    Refused(Got),
    /// A `QueryFailed` is told.
    Failed(QueryError),
    /// Nothing by the deadline.
    Silent,
}

/// Why asking one server stopped before an answer was judged.
pub(super) enum Stop {
    Silent,
    Failed(QueryError),
}

impl From<QueryError> for Stop {
    fn from(why: QueryError) -> Stop {
        Stop::Failed(why)
    }
}

/// The servers of one query and how each resolved.
#[derive(Default)]
struct Tally {
    asked: u32,
    answered: u32,
    refused: u32,
    failed: u32,
    silent: u32,
}

impl Tally {
    /// Tell one server's outcome to the stream and count it in its one bucket.
    fn take(&mut self, sink: &AnswerSink, server: Name, outcome: Outcome) {
        match outcome {
            Outcome::Answered(got) => {
                self.answered += 1;
                sink.push(got);
            }
            Outcome::Refused(got) => {
                self.refused += 1;
                sink.push(got);
            }
            Outcome::Failed(why) => {
                self.failed += 1;
                sink.notice(GetNotice::QueryFailed { server, why });
            }
            Outcome::Silent => self.silent += 1,
        }
    }
}

/// Ask every server of `servers` with `ask` and tell each outcome to `sink` as it comes; the
/// servers that have not resolved by `deadline` are `silent` (their futures are dropped, so
/// their Interests are). Ends with the one [`GetNotice::AnswersDone`], in which
/// `asked == answered + refused + failed + silent`.
pub(crate) async fn drive<F, Fut>(
    sink: &AnswerSink,
    servers: Vec<Name>,
    not_asked: u32,
    deadline: Instant,
    ask: F,
) where
    F: Fn(Name) -> Fut,
    Fut: Future<Output = Outcome>,
{
    let mut tally = Tally {
        asked: u32::try_from(servers.len()).unwrap_or(u32::MAX),
        ..Tally::default()
    };
    let mut pending: FuturesUnordered<_> = servers
        .into_iter()
        .map(|server| {
            let answer = ask(server.clone());
            async move { (server, answer.await) }
        })
        .collect();
    {
        let collect = async {
            while let Some((server, outcome)) = pending.next().await {
                tally.take(sink, server, outcome);
            }
        };
        let wait = deadline.saturating_duration_since(Instant::now());
        // Whether it ended at the deadline or because every server resolved, what is left is
        // counted below.
        let _ = crate::rt::timeout(wait, collect).await;
    }
    tally.silent += u32::try_from(pending.len()).unwrap_or(u32::MAX);
    drop(pending);
    sink.notice(GetNotice::AnswersDone {
        asked: tally.asked,
        answered: tally.answered,
        refused: tally.refused,
        failed: tally.failed,
        silent: tally.silent,
        not_asked,
    });
}

/// A query judged at creation, ready to run.
pub(crate) struct Run {
    pub(crate) sink: Arc<AnswerSink>,
    held: Arc<SpaceInner>,
    path: Name,
    ask: Ask,
    id: QueryId,
    deadline: Instant,
}

#[cfg(test)]
impl Run {
    /// The query id a test judges answers against.
    pub(super) fn set_id(&mut self, id: QueryId) {
        self.id = id;
    }
}

/// The servers a query asks and how many more were known.
pub(super) struct Targeted {
    pub(super) servers: Vec<Name>,
    pub(super) not_asked: u32,
}

fn bad(why: String) -> HeapError {
    HeapError::BadRequest { why }
}

/// Keep the first [`TARGETS_MAX`] of `found`; the rest are counted.
fn capped(mut found: Vec<Name>) -> Targeted {
    let not_asked = u32::try_from(found.len().saturating_sub(TARGETS_MAX)).unwrap_or(u32::MAX);
    found.truncate(TARGETS_MAX);
    Targeted {
        servers: found,
        not_asked,
    }
}

fn nack_to_error(reason: Option<NackReason>) -> QueryError {
    match reason {
        Some(NackReason::NoRoute) => QueryError::NotListed,
        Some(NackReason::Congestion | NackReason::Duplicate) => QueryError::Busy,
        Some(NackReason::NotYet) => QueryError::NotYet,
        _ => QueryError::Unreachable,
    }
}

/// What a failed fetch says of the server.
fn fetch_stop(e: AppError) -> Stop {
    match e {
        AppError::Timeout => Stop::Silent,
        AppError::Nacked { reason } => Stop::Failed(nack_to_error(reason)),
        AppError::Closed => Stop::Failed(QueryError::Unreachable),
        other => Stop::Failed(QueryError::BadAnswer {
            why: other.to_string(),
        }),
    }
}

fn bad_answer(why: impl Into<String>) -> Stop {
    Stop::Failed(QueryError::BadAnswer { why: why.into() })
}

fn not_ready(why: impl Into<String>) -> Stop {
    Stop::Failed(QueryError::NotReady { why: why.into() })
}

/// The milliseconds of `remaining`, rounded up, within what the wire carries.
fn deadline_ms(remaining: Duration) -> u32 {
    let ms = remaining.as_micros().div_ceil(1000);
    u32::try_from(ms)
        .unwrap_or(DEADLINE_MAX_MS)
        .clamp(1, DEADLINE_MAX_MS)
}

impl NodeInner {
    /// Judge a request to ask (`GetOptions::ask`) of `held` and make the run, or refuse it with the
    /// reason and what to do. Registers nothing and does no I/O: nothing is asked until
    /// [`Self::query_spawn`].
    pub(crate) fn query_prepare(
        &self,
        held: &Arc<SpaceInner>,
        what: &Select,
        ask: Ask,
    ) -> Result<Run, HeapError> {
        let space = &held.name;
        if held.follower {
            return Err(HeapError::NotAllowed {
                space: space.clone(),
                why: "this device only follows the space and takes no part in queries: open it \
                      as a member (a listed writer or reader asks)"
                    .into(),
            });
        }
        if ask.via == QueryPath::Channel {
            return Err(bad(
                "QueryPath::Channel is not built in this version of the layer: ask \
                 QueryPath::Signed, or QueryPath::Auto (which is the signed path until the \
                 channel path exists)"
                    .into(),
            ));
        }
        if ask.query.len() > QUERY_MAX {
            return Err(bad(format!(
                "the query is {} octets, over the limit of {QUERY_MAX} on the signed path: send \
                 less, or put the data and send its path",
                ask.query.len()
            )));
        }
        if ask.deadline.is_zero() || ask.deadline > DEADLINE_MAX {
            return Err(bad(format!(
                "the deadline is {:?}: a query lives for at least 1 ms and at most {:?}; ask for \
                 a deadline in that range (the default is 3 s)",
                ask.deadline, DEADLINE_MAX
            )));
        }
        if ask.answer_max == 0 || ask.answer_max > ANSWER_MAX_DEFAULT {
            return Err(bad(format!(
                "answer_max is {}: the signed path carries answers of 1 to {ANSWER_MAX_DEFAULT} \
                 octets; ask for a size in that range, or have the handler put the data and \
                 answer its path",
                ask.answer_max
            )));
        }
        let path = match what {
            Select::Path(p) | Select::Prefix(p) => p.clone(),
        };
        let path_octets = crate::wire::name_value_len(&path);
        if path_octets > QUERY_PATH_MAX {
            return Err(bad(format!(
                "the asked path is {path_octets} octets, over the limit of {QUERY_PATH_MAX}: ask a \
                 shorter path"
            )));
        }
        if let Targets::Devices(devices) = &ask.targets {
            if devices.is_empty() {
                return Err(bad(
                    "Targets::Devices names no device: name at least one, or use \
                     Targets::Serving"
                        .into(),
                ));
            }
            if devices.len() > TARGETS_MAX {
                return Err(bad(format!(
                    "{} devices are named, over the limit of {TARGETS_MAX} servers per query: \
                     name at most {TARGETS_MAX}, or use Targets::Serving",
                    devices.len()
                )));
            }
            for device in devices {
                if !is_device_name(device) || is_reserved(device) {
                    return Err(bad(format!(
                        "{device} is no device name of the network (a device name has no keyword \
                         or digest component and does not lie under /localhost or /localhop): \
                         name devices as the announces and the record do"
                    )));
                }
                if *device == self.device {
                    return Err(bad(format!(
                        "{device} is this device: a device does not ask itself; serve and ask \
                         from different devices"
                    )));
                }
            }
        }
        {
            let log = held.log.lock();
            gate(&log, &self.judge, Who::Listed, "queries")?;
        }
        let mut id = [0u8; 8];
        getrandom::getrandom(&mut id).expect("the operating system provides randomness");
        Ok(Run {
            sink: Arc::new(AnswerSink::default()),
            held: Arc::clone(held),
            path,
            id: QueryId(u64::from_be_bytes(id)),
            deadline: Instant::now() + ask.deadline,
            ask,
        })
    }

    /// Run `run` on the node's tasks until it ends or its `Items` is dropped.
    pub(crate) fn query_spawn(&self, run: Run) {
        let node = self.arc();
        let cancel = run.sink.cancel_token().clone();
        self.tasks.spawn(async move {
            // A dropped `Items` cancels the run: what it holds (Interests in flight, pending
            // slots) is dropped with it.
            let _ = cancel.run_until_cancelled(node.query_run(&run)).await;
        });
    }

    async fn query_run(self: &Arc<Self>, run: &Run) {
        let Targeted { servers, not_asked } = self.query_targets(run).await;
        if servers.is_empty() {
            run.sink.notice(GetNotice::QueryFailed {
                server: run.held.name.clone(),
                why: QueryError::NoServer {
                    path: run.path.clone(),
                },
            });
            run.sink.notice(GetNotice::AnswersDone {
                asked: 0,
                answered: 0,
                refused: 0,
                failed: 0,
                silent: 0,
                not_asked,
            });
            return;
        }
        drive(&run.sink, servers, not_asked, run.deadline, |server| {
            let node = Arc::clone(self);
            async move { node.ask_server(run, server).await }
        })
        .await;
    }

    /// The devices of `found` that are writers now, and not this one.
    fn writers_of(&self, held: &SpaceInner, found: Vec<Name>) -> Vec<Name> {
        let log = held.log.lock();
        found
            .into_iter()
            .filter(|d| *d != self.device && log.fold.is_writer(&self.person_of(d)))
            .collect()
    }

    /// Who `run` asks (docs/specs/query.md, Several servers): the devices it names, the writer
    /// devices of a person, or the devices announced to serve the path, waiting for an announce
    /// until the deadline when none is known.
    pub(super) async fn query_targets(&self, run: &Run) -> Targeted {
        let space = &run.held.name;
        match &run.ask.targets {
            Targets::Devices(devices) => {
                let mut seen = Vec::new();
                for device in devices {
                    if !seen.contains(device) {
                        seen.push(device.clone());
                    }
                }
                Targeted {
                    servers: seen,
                    not_asked: 0,
                }
            }
            Targets::Person(person) => {
                let mut found = run.held.log.lock().devices_of(person);
                let now = Instant::now();
                for device in self.query.hints.devices(space, now) {
                    if self.person_of(&device) == *person && !found.contains(&device) {
                        found.push(device);
                    }
                }
                found.sort();
                capped(self.writers_of(&run.held, found))
            }
            Targets::Serving => loop {
                let hints = &self.query.hints;
                let mut notified = pin!(hints.heard().notified());
                notified.as_mut().enable();
                let found = hints.serving(space, &run.path, Instant::now());
                let found = self.writers_of(&run.held, found);
                if !found.is_empty() {
                    break capped(found);
                }
                let wait = run.deadline.saturating_duration_since(Instant::now());
                if wait.is_zero() || crate::rt::timeout(wait, notified).await.is_err() {
                    break Targeted {
                        servers: Vec::new(),
                        not_asked: 0,
                    };
                }
            },
        }
    }

    /// Ask `server` once and judge what comes back.
    async fn ask_server(self: &Arc<Self>, run: &Run, server: Name) -> Outcome {
        match self.ask_server_inner(run, &server).await {
            Ok(outcome) => outcome,
            Err(Stop::Silent) => Outcome::Silent,
            Err(Stop::Failed(why)) => Outcome::Failed(why),
        }
    }

    async fn ask_server_inner(self: &Arc<Self>, run: &Run, server: &Name) -> Result<Outcome, Stop> {
        let space = &run.held.name;
        // Judged now, from the record held: a query goes to a writer's device and to no other.
        let (writer, sealed, judged_at) = {
            let person = self.person_of(server);
            let log = run.held.log.lock();
            (
                log.fold.is_writer(&person),
                log.sealed().then(|| log.fold.in_force()),
                (
                    self.judge.generation(),
                    log.fold.version().load(Ordering::SeqCst),
                ),
            )
        };
        if !writer {
            self.query.ask.keys.lock().forget(server);
            return Err(QueryError::NotWriter {
                device: server.clone(),
            }
            .into());
        }
        let _slot = {
            let acquired =
                self.query
                    .ask
                    .pending
                    .lock()
                    .acquire(server, PENDING_TOTAL, PENDING_PER_SERVER);
            if !acquired {
                return Err(QueryError::TooManyOutstanding.into());
            }
            Slot {
                node: Arc::clone(self),
                server: server.clone(),
            }
        };
        // A sealed space seals the query to the server's recipient key for the epoch in force.
        let seal = match sealed {
            None => None,
            Some(None) => {
                return Err(not_ready(
                    "the sealed space has no epoch in force here yet: wait for its record, then \
                     ask again",
                ));
            }
            Some(Some(epoch)) => {
                let public = self.server_seal_key(run, server).await?;
                let used = self
                    .query
                    .ask
                    .keys
                    .lock()
                    .pair(space, &self.device, server, &epoch, public, judged_at)
                    .map_err(|e| bad_answer(format!("its seal key is unusable ({e})")))?;
                Some(used)
            }
        };
        let remaining = run.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Stop::Silent);
        }
        let id = run.id.0.to_be_bytes();
        let ask = match &seal {
            None => QueryAsk {
                space: space.clone(),
                path: Some(run.path.clone()),
                id,
                deadline_ms: deadline_ms(remaining),
                bytes: run.ask.query.clone(),
                seal: None,
                chain: self.signer_chain(),
            },
            Some(used) => {
                let aad = query_aad(
                    server,
                    &self.device,
                    space,
                    &used.epoch,
                    &used.ephemeral,
                    used.seq,
                    &id,
                );
                let inner = QueryAsk::seal_inner(&run.path, &run.ask.query);
                QueryAsk {
                    space: space.clone(),
                    path: None,
                    id,
                    deadline_ms: deadline_ms(remaining),
                    bytes: seal_query(&used.keys, used.seq, &aad, &inner),
                    seal: Some(AskSeal {
                        ephemeral: used.ephemeral,
                        epoch: used.epoch.clone(),
                        seq: used.seq,
                    }),
                    chain: self.signer_chain(),
                }
            }
        };
        let params = ask
            .encode()
            .map_err(|e| not_ready(format!("the query cannot be written ({e})")))?;
        let wire = self
            .sign_query(server, &params)
            .map_err(|e| not_ready(e.to_string()))?;
        let interest = Interest::decode(wire.clone())
            .map_err(|e| not_ready(format!("the signed query does not decode ({e})")))?;
        let name = (*interest.name).clone();
        let data = Consumer::new(Arc::clone(&self.conn))
            .fetch_wire(wire, remaining)
            .await
            .map_err(fetch_stop)?;
        self.query_take_answer(run, server, &name, data, seal.as_ref())
            .await
    }

    /// Judge the answer `data` to the query named `name` (the module docs list the steps) and
    /// turn it into the outcome of `server`.
    pub(super) async fn query_take_answer(
        &self,
        run: &Run,
        server: &Name,
        name: &Name,
        data: Data,
        seal: Option<&SealUse>,
    ) -> Result<Outcome, Stop> {
        let space = &run.held.name;
        // 1. The name.
        if *data.name != *name {
            return Err(bad_answer(format!(
                "it is named {}, not the query's {name}",
                data.name
            )));
        }
        let content = data
            .content()
            .cloned()
            .ok_or_else(|| bad_answer("it has no content"))?;
        let answer = QueryAnswer::decode(content).map_err(|e| bad_answer(e.to_string()))?;
        // 2. The signature: the server's, from the certificates held and carried.
        let key = match self
            .judge
            .validate_asker_packet(&data, server, space, &answer.certs)
            .await
        {
            Judged::Valid(v) => v.key,
            Judged::Refused(why) => {
                return Err(bad_answer(format!(
                    "its signature is refused ({why}): it is not the server's"
                )));
            }
            Judged::Pending(waiting) => {
                return Err(bad_answer(format!(
                    "it cannot be verified from the certificates held and carried ({waiting}); \
                     nothing is fetched for a query"
                )));
            }
        };
        // 3. The signer is a writer now.
        let person = {
            let log = run.held.log.lock();
            standing(&log, &self.judge, &key, Who::Writer)
        }
        .map_err(|why| {
            bad_answer(format!(
                "the signer is no writer of the space now ({why:?})"
            ))
        })?;
        // 4. It answers this query.
        if answer.id != run.id.0.to_be_bytes() {
            return Err(bad_answer("it answers another query (Q_ID differs)"));
        }
        // 5. The status, opened if it was sealed.
        let status = match (seal, answer.body) {
            (None, AnswerBody::Plain(status)) => status,
            (Some(used), AnswerBody::Sealed { seq, cipher }) => {
                if seq != used.seq {
                    return Err(bad_answer(
                        "its sealing counter is not the query's: it answers another exchange",
                    ));
                }
                let aad = answer_aad(
                    server,
                    &self.device,
                    space,
                    &used.epoch,
                    &used.ephemeral,
                    used.seq,
                    &answer.id,
                );
                let inner = open_answer(&used.keys, seq, &aad, &cipher)
                    .ok_or_else(|| bad_answer("it does not open under the pair key"))?;
                Status::decode_inner(Bytes::from(inner)).map_err(|e| bad_answer(e.to_string()))?
            }
            (None, AnswerBody::Sealed { .. }) => {
                return Err(bad_answer(
                    "it is sealed, and this space is public: nothing here is sealed to a pair",
                ));
            }
            (Some(_), AnswerBody::Plain(_)) => {
                return Err(bad_answer(
                    "it is in the clear in a sealed space: every answer there is sealed",
                ));
            }
        };
        let proof = run.ask.proof.then(|| data.raw().clone());
        let got = |bytes: Bytes, refusal: Option<AppRefusal>| Got {
            path: run.path.clone(),
            bytes,
            by: person.clone(),
            writer: server.clone(),
            kind: Kind::Answered(Answered {
                query: run.id,
                via: Via::Signed,
                refusal,
                proof: proof.clone(),
            }),
        };
        match status {
            Status::Answered(bytes) => {
                if bytes.len() > run.ask.answer_max {
                    return Err(Stop::Failed(QueryError::AnswerTooLarge {
                        size: bytes.len(),
                        max: run.ask.answer_max,
                    }));
                }
                Ok(Outcome::Answered(got(bytes, None)))
            }
            Status::Refused { code, text } => Ok(Outcome::Refused(got(
                Bytes::new(),
                Some(AppRefusal::new(code, text)),
            ))),
            Status::NotServed => Err(Stop::Failed(QueryError::NotServed {
                path: run.path.clone(),
            })),
            Status::TooLarge { max } => Err(Stop::Failed(QueryError::TooLarge {
                what: "the server's answer does not fit its limit",
                max,
            })),
        }
    }

    /// The recipient key of `server`, from its signed seal key packet `<server>/32=seal/<key>`
    /// (asked for by `<server>/32=seal` with CanBePrefix): the packet is the server device's, and
    /// the device is a writer now. Cached until the trust generation moves.
    async fn server_seal_key(&self, run: &Run, server: &Name) -> Result<[u8; 32], Stop> {
        let space = &run.held.name;
        let generation = self.judge.generation();
        if let Some(public) = self.query.ask.keys.lock().seal_public(server, generation) {
            return Ok(public);
        }
        let remaining = run.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Stop::Silent);
        }
        let wire = InterestBuilder::new(seal_prefix(server))
            .can_be_prefix()
            .lifetime(remaining)
            .build();
        let data = Consumer::new(Arc::clone(&self.conn))
            .fetch_wire(wire, remaining)
            .await
            .map_err(fetch_stop)?;
        let public = match parse_seal_key_name(&data.name) {
            Some((device, public))
                if device == *server && crate::seal::seal_key_matches(&data, server, &public) =>
            {
                public
            }
            _ => {
                return Err(bad_answer(
                    "what it gave for its seal key is not its key packet",
                ));
            }
        };
        let key = match self
            .judge
            .validate_device_packet(&data, server, space)
            .await
        {
            Judged::Valid(v) => v.key,
            Judged::Refused(why) => {
                return Err(bad_answer(format!(
                    "its seal key packet is refused ({why}): it is not the server's"
                )));
            }
            Judged::Pending(waiting) => {
                return Err(bad_answer(format!(
                    "its seal key packet cannot be verified yet ({waiting})"
                )));
            }
        };
        {
            let log = run.held.log.lock();
            standing(&log, &self.judge, &key, Who::Writer).map_err(|why| {
                bad_answer(format!(
                    "the signer of its seal key is no writer now ({why:?})"
                ))
            })?;
        }
        self.query
            .ask
            .keys
            .lock()
            .put_seal(server, public, generation);
        Ok(public)
    }

    /// Sign the query `<device>/32=query/<digest>` whose ApplicationParameters are `params`: an
    /// InterestSignatureInfo with this device's key as the KeyLocator, a SignatureNonce and a
    /// SignatureTime, MustBeFresh, and an InterestLifetime of the query's own deadline
    /// (`Q_DEADLINE`). The name is the only one this signs besides the channel ask's: a signed
    /// Interest of this device's key is a command anywhere that trusts the key, so `params` must
    /// decode as a `QUERY_ASK` and `device` must be no reserved prefix (`/localhost`,
    /// `/localhop`): whatever else a caller hands in is refused, never signed.
    pub(crate) fn sign_query(&self, device: &Name, params: &[u8]) -> Result<Bytes, HeapError> {
        if is_reserved(device) {
            return Err(HeapError::BadRequest {
                why: format!(
                    "{device} lies under a reserved prefix (/localhost, /localhop): this node \
                     signs a query only for a device of the network"
                ),
            });
        }
        let ask = QueryAsk::decode(Bytes::copy_from_slice(params)).map_err(|e| {
            HeapError::BadRequest {
                why: format!(
                    "the {} octets given are no QUERY_ASK ({e}): this node signs the query of a \
                     space and the ask of a channel and nothing else, since a signed Interest of \
                     the device's key is a command wherever the key is trusted",
                    params.len()
                ),
            }
        })?;
        let key = self.signer.key_name();
        let mut failed = None;
        let wire = InterestBuilder::new(query_prefix(device))
            .must_be_fresh()
            .lifetime(Duration::from_millis(u64::from(ask.deadline_ms)))
            .app_parameters(params.to_vec())
            .signature_time(self.now())
            .sign_sync(self.signer.sig_type(), Some(key), |region| {
                self.signer.sign_sync(region).unwrap_or_else(|e| {
                    failed = Some(e);
                    Bytes::new()
                })
            });
        if let Some(e) = failed {
            return Err(HeapError::local(format!(
                "the device key {key} did not sign the query ({e}); the layer needs a key that \
                 signs synchronously"
            )));
        }
        self.signatures.fetch_add(1, Ordering::Relaxed);
        Ok(wire)
    }
}

#[cfg(test)]
impl NodeInner {
    /// How many server seal keys and pair keys the asker caches.
    pub(crate) fn query_key_counts(&self) -> (usize, usize) {
        self.query.ask.keys.lock().counts()
    }

    /// Queries outstanding in all.
    pub(crate) fn query_pending(&self) -> usize {
        self.query.ask.pending.lock().total()
    }

    /// How many X25519 agreements the asker has made for sealed queries.
    pub(crate) fn query_agreements(&self) -> u64 {
        self.query.ask.keys.lock().agreements
    }
}
