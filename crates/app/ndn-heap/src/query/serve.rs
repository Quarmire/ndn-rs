//! The server's half of the signed path: judging a query cheapest first and answering it
//! (docs/specs/query.md, How the server judges).
//!
//! A query is the Interest `<this device>/32=query/<digest>`, signed by the asker's device key,
//! its ApplicationParameters a `QUERY_ASK`. The steps run cheapest first, so a stranger costs a
//! lookup and no signature, and each step that refuses without a word answers a Nack and signs
//! nothing:
//!
//! 1. the name is `<this device>/32=query/<digest>`, the ApplicationParameters are at most 8 KiB
//!    and hash to the digest, parse as a `QUERY_ASK`, and the Interest names a device key and
//!    carries a `SignatureNonce` and a `SignatureTime`: else `NoRoute`;
//! 2. the lookup budget (per ingress face and for the node, shared with channel asks), then the
//!    space is open here as a member and the key **stands** as a listed person: else `NoRoute`
//!    (`Congestion` over the budget);
//! 3. `SignatureTime` is within 120 s of this device's clock **and not before the moment `serve`
//!    began**: else `NoRoute`;
//! 4. the verification budget: else `Congestion`;
//! 5. the signature verifies from the certificates held and the at most four carried, fetching
//!    nothing: `Pending` is `NotYet`, a refusal `NoRoute`;
//! 6. the query is no replay (key, nonce, time): `Duplicate`; then the asker person's rate
//!    (charged only now that the key is the asker's): `Congestion`;
//! 7. standing again under the record's lock, this device a writer, and in a sealed space the
//!    epoch in force is the query's (`NotYet`) and the person is in its audience (`NoRoute`): the
//!    query is sealed there and plain in a public space, else `NoRoute`;
//! 8. a sealed query is opened under the pair key (derived once per (asker device, ephemeral
//!    key, epoch) and kept); a prefix of the path is served, else a signed `NotServed` answer;
//! 9. the asker person's handlers in flight and the server's: over them, `Congestion`, no wait
//!    queue; then the handler runs under the query's deadline, and its answer is signed and sent.
//!
//! **Not the deleted answers family.** Nothing a handler answers is stored, cached, recomputed
//! or made an entry; the state here is memory bounded by queries in flight and judged members.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Interest, NackReason};
use ndn_security::PairKeys;
use ndn_security::cert_name::key_name_of;
use ndn_transport::FaceId;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};

use super::seal::{answer_aad, open_query, pair_context, query_aad, seal_answer};
use super::types::{Asker, Query, QueryId, Reply, Via};
use crate::chan::answer::ASK_CLOCK_WINDOW_MS;
use crate::chan::standing::{Who, gate, standing};
use crate::chan::verify::Bucket;
use crate::chan::wire::{SERVES_MAX, SERVES_OCTETS_MAX};
use crate::node::NodeInner;
use crate::rt::{self, Instant};
use crate::seal;
use crate::wire::{
    ANSWER_BYTES_MAX, AnswerBody, AskSeal, EpochId, QUERY_ASK_MAX, QueryAnswer, QueryAsk, Status,
    device_of, name_value_len, parse_query_name, parse_space_name,
};

/// How long the replay set keeps a query: a copy is acceptable only within 120 s of the signed
/// time, and the signed time was within 120 s of the arrival of the original, so 240 s from
/// arrival is sound.
pub(crate) const REPLAY_KEPT: Duration = Duration::from_secs(240);

/// The most queries the replay set holds: past it a new query is refused `Congestion` (a set
/// that dropped entries would let a copy run again).
pub(crate) const REPLAY_MAX: usize = 262_144;

/// The handlers one asker person has running at once, on all her devices.
pub(crate) const PERSON_INFLIGHT: usize = 8;

/// The handlers running at once on this node, whoever asked.
pub(crate) const HANDLERS_MAX: usize = 64;

/// The queries a second one asker person is admitted, and the burst: charged after the signature
/// verified.
pub(crate) const PERSON_RATE: f64 = 64.0;
pub(crate) const PERSON_BURST: f64 = 128.0;

/// The answer octets a second one asker person is sent, and the burst (4 MiB each).
pub(crate) const PERSON_OCTETS_RATE: f64 = 4.0 * 1024.0 * 1024.0;

/// The pair keys this node keeps, one per (space, asker device).
pub(crate) const PAIRS_MAX: usize = 1024;

/// The asker persons this node keeps counters of before it sweeps those idle a minute.
const PEOPLE_SWEEP: usize = 4096;

/// How the node says a query ended: a signed answer, a Nack, or nothing at all (`Reply::Pass`, a
/// handler past the asker's deadline).
#[derive(Debug)]
pub(crate) enum QueryOutcome {
    /// The signed Data: sent with `NoCache`.
    Data(Bytes),
    /// A Nack and nothing else.
    Nack(NackReason),
    /// Nothing is sent: the Interest is left to lapse, and the asker counts the server silent.
    Silent,
}

// -- The replay set --------------------------------------------------------------------------------

/// What the replay set said of a query.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Replayed {
    Fresh,
    Replay,
    /// The set is full.
    Full,
}

/// The queries seen in the last [`REPLAY_KEPT`], by a 128-bit digest of (asker key, nonce, signed
/// time): `ndn_security::ReplayGuard` scans a key's records linearly, sized for a few asks a
/// second, and a game's queries are tens a second per key.
pub(crate) struct Replay {
    seen: Mutex<ReplaySet>,
    cap: usize,
}

#[derive(Default)]
struct ReplaySet {
    ids: HashSet<[u8; 16]>,
    order: VecDeque<(Instant, [u8; 16])>,
}

impl Default for Replay {
    fn default() -> Replay {
        Replay {
            seen: Mutex::default(),
            cap: REPLAY_MAX,
        }
    }
}

impl Replay {
    /// A set that holds at most `cap` queries.
    #[cfg(test)]
    pub(crate) fn with_cap(cap: usize) -> Replay {
        Replay {
            seen: Mutex::default(),
            cap,
        }
    }

    /// Record the query (asker key, `nonce`, signed `time`) seen at `now`, if it is new and the
    /// set has room.
    pub(crate) fn check(&self, key: &Name, nonce: &[u8], time: u64, now: Instant) -> Replayed {
        let mut hash = Sha256::new();
        hash.update(key.encode_to_tlv());
        hash.update((nonce.len() as u32).to_be_bytes());
        hash.update(nonce);
        hash.update(time.to_be_bytes());
        let digest = hash.finalize();
        let mut id = [0u8; 16];
        id.copy_from_slice(&digest[..16]);
        let mut set = self.seen.lock();
        while let Some((at, old)) = set.order.front().copied() {
            if now.saturating_duration_since(at) < REPLAY_KEPT {
                break;
            }
            set.order.pop_front();
            set.ids.remove(&old);
        }
        if set.ids.contains(&id) {
            return Replayed::Replay;
        }
        if set.ids.len() >= self.cap {
            return Replayed::Full;
        }
        set.ids.insert(id);
        set.order.push_back((now, id));
        Replayed::Fresh
    }
}

// -- The asker persons' counters -------------------------------------------------------------------

/// The answer octets a person may still be sent: a bucket that may go into debt by one answer.
struct Octets {
    credit: f64,
    at: Option<Instant>,
}

impl Octets {
    fn refill(&mut self, now: Instant) {
        if let Some(at) = self.at {
            let elapsed = now.saturating_duration_since(at).as_secs_f64();
            self.credit = (self.credit + elapsed * PERSON_OCTETS_RATE).min(PERSON_OCTETS_RATE);
        }
        self.at = Some(now);
    }
}

/// What one asker person is held to, on all her devices together.
struct Person {
    inflight: usize,
    rate: Bucket,
    octets: Octets,
    last: Instant,
}

impl Person {
    fn new(now: Instant) -> Person {
        Person {
            inflight: 0,
            rate: Bucket::new(PERSON_RATE, PERSON_BURST),
            octets: Octets {
                credit: PERSON_OCTETS_RATE,
                at: None,
            },
            last: now,
        }
    }
}

/// One place among the handlers running, taken for an asker person and given back when dropped.
pub(crate) struct Slot<'a> {
    server: &'a ServerState,
    person: Name,
}

impl Slot<'_> {
    /// The answer of `octets` was sent to the person: her budget of answer octets pays for it.
    pub(crate) fn charge(&self, octets: usize, now: Instant) {
        if let Some(p) = self.server.people.lock().get_mut(&self.person) {
            p.octets.refill(now);
            p.octets.credit -= octets as f64;
        }
    }
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.server.running.fetch_sub(1, Ordering::SeqCst);
        if let Some(p) = self.server.people.lock().get_mut(&self.person) {
            p.inflight = p.inflight.saturating_sub(1);
        }
    }
}

// -- The pair keys ---------------------------------------------------------------------------------

/// The pair keys of one asker device in one space, with what they were derived for.
struct ServerPair {
    /// The key that signed the asker's queries, to judge it again.
    key: Name,
    ephemeral: [u8; 32],
    epoch: EpochId,
    keys: Arc<PairKeys>,
    /// The trust generation and fold version the asker was last judged by.
    judged_at: (u64, u64),
}

/// A sealed query, as the answer to it needs to know it.
struct Sealed {
    keys: Arc<PairKeys>,
    seal: AskSeal,
}

/// Why a pair could not be had.
enum PairRefused {
    /// The node keeps as many as it may.
    Full,
    /// The asker's key is no key an agreement can be made with.
    BadKey,
}

// -- What the server keeps -------------------------------------------------------------------------

/// What the server keeps: its limits, its replay set and its pair keys. In memory, bounded by the
/// queries in flight and the members judged; a restart forgets all of it.
#[derive(Default)]
pub(crate) struct ServerState {
    replay: Replay,
    people: Mutex<HashMap<Name, Person>>,
    /// The handlers running on this node.
    running: AtomicUsize,
    pairs: Mutex<HashMap<(Name, Name), ServerPair>>,
    /// The X25519 agreements made for pairs.
    agreements: AtomicU64,
    /// When each space's served prefixes were last announced.
    announced: Mutex<HashMap<Name, Instant>>,
}

impl ServerState {
    /// One token of `person`'s query rate.
    pub(crate) fn admit(&self, person: &Name, now: Instant) -> bool {
        let mut people = self.people.lock();
        if people.len() >= PEOPLE_SWEEP {
            people.retain(|_, p| {
                p.inflight > 0 || now.saturating_duration_since(p.last) < REPLAY_KEPT
            });
        }
        let p = people
            .entry(person.clone())
            .or_insert_with(|| Person::new(now));
        p.last = now;
        p.rate.take(now)
    }

    /// A place for `person`'s handler: the node runs fewer than [`HANDLERS_MAX`], the person
    /// fewer than [`PERSON_INFLIGHT`], and she has answer octets left to be sent.
    pub(crate) fn slot(&self, person: &Name, now: Instant) -> Option<Slot<'_>> {
        let mut people = self.people.lock();
        let p = people
            .entry(person.clone())
            .or_insert_with(|| Person::new(now));
        p.last = now;
        p.octets.refill(now);
        if p.inflight >= PERSON_INFLIGHT || p.octets.credit <= 0.0 {
            return None;
        }
        if self
            .running
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < HANDLERS_MAX).then_some(n + 1)
            })
            .is_err()
        {
            return None;
        }
        p.inflight += 1;
        Some(Slot {
            server: self,
            person: person.clone(),
        })
    }

    /// The pair keys of `device` in `space` for `seal`: the one held if it was derived for this
    /// ephemeral key and epoch, else a new agreement (replacing the old).
    fn pair(
        &self,
        node: &NodeInner,
        space: &Name,
        device: &Name,
        key: &Name,
        seal: &AskSeal,
        judged_at: (u64, u64),
    ) -> Result<Arc<PairKeys>, PairRefused> {
        let at = (space.clone(), device.clone());
        {
            let mut pairs = self.pairs.lock();
            if let Some(held) = pairs.get_mut(&at) {
                if held.ephemeral == seal.ephemeral && held.epoch == seal.epoch {
                    held.judged_at = judged_at;
                    return Ok(Arc::clone(&held.keys));
                }
            } else if pairs.len() >= PAIRS_MAX {
                return Err(PairRefused::Full);
            }
        }
        let context = pair_context(space, device, &node.device, &seal.epoch);
        let keys = node
            .recipient()
            .pair_keys_from(&seal.ephemeral, &context)
            .map_err(|_| PairRefused::BadKey)?;
        self.agreements.fetch_add(1, Ordering::Relaxed);
        let keys = Arc::new(keys);
        self.pairs.lock().insert(
            at,
            ServerPair {
                key: key.clone(),
                ephemeral: seal.ephemeral,
                epoch: seal.epoch.clone(),
                keys: Arc::clone(&keys),
                judged_at,
            },
        );
        Ok(keys)
    }

    /// Forget the pair of `device` in `space`.
    fn forget(&self, space: &Name, device: &Name) {
        self.pairs.lock().remove(&(space.clone(), device.clone()));
    }

    fn pair_spaces(&self) -> Vec<Name> {
        let mut spaces: Vec<Name> = self.pairs.lock().keys().map(|(s, _)| s.clone()).collect();
        spaces.sort();
        spaces.dedup();
        spaces
    }

    /// Of the pairs of `space`: those judged by `live` stay; the others stay only if `keep` says
    /// the asker still stands, and are then judged by `live`.
    fn rejudge(&self, space: &Name, live: (u64, u64), mut keep: impl FnMut(&ServerPair) -> bool) {
        self.pairs.lock().retain(|(s, _), pair| {
            if s != space || pair.judged_at == live {
                return true;
            }
            let stands = keep(pair);
            if stands {
                pair.judged_at = live;
            }
            stands
        });
    }

    fn forget_space(&self, space: &Name) {
        self.pairs.lock().retain(|(s, _), _| s != space);
    }

    /// Record that the prefixes of `space` were announced at `now`.
    pub(crate) fn announced(&self, space: &Name, now: Instant) {
        self.announced.lock().insert(space.clone(), now);
    }

    /// The spaces of `serving` whose served prefixes are due an announce at `now` (never
    /// announced, or the last was [`ANNOUNCE_EVERY`](crate::chan::channels::ANNOUNCE_EVERY)
    /// ago). A space no longer served is forgotten.
    pub(crate) fn announce_due(&self, serving: &[Name], now: Instant) -> Vec<Name> {
        let mut announced = self.announced.lock();
        announced.retain(|space, _| serving.contains(space));
        serving
            .iter()
            .filter(|space| {
                announced.get(*space).is_none_or(|at| {
                    now.saturating_duration_since(*at) >= crate::chan::channels::ANNOUNCE_EVERY
                })
            })
            .cloned()
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn agreements(&self) -> u64 {
        self.agreements.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn pairs_held(&self) -> usize {
        self.pairs.lock().len()
    }

    #[cfg(test)]
    pub(crate) fn running(&self) -> usize {
        self.running.load(Ordering::SeqCst)
    }

    /// The query-rate tokens `person` holds, as of her last admission (no refill is counted).
    #[cfg(test)]
    pub(crate) fn rate_tokens(&self, person: &Name) -> Option<f64> {
        self.people.lock().get(person).map(|p| p.rate.tokens())
    }
}

/// The served prefixes an announce lists: shortest first, at most [`SERVES_MAX`] names and
/// [`SERVES_OCTETS_MAX`] octets of name values in all; those that do not fit are left out (an
/// asker names them with `Targets::Devices`).
pub(crate) fn announced_prefixes(mut prefixes: Vec<Name>) -> Vec<Name> {
    prefixes.sort_by_cached_key(|p| (name_value_len(p), p.clone()));
    let mut octets = 0;
    let mut listed = Vec::new();
    for prefix in prefixes {
        octets += name_value_len(&prefix);
        if listed.len() == SERVES_MAX || octets > SERVES_OCTETS_MAX {
            break;
        }
        listed.push(prefix);
    }
    listed
}

/// The status a handler's reply says, if it says one: `Pass` says none. An answer over what the
/// signed path carries is `TooLarge`; a refusal's text is cut.
fn status_of(reply: Reply) -> Option<Status> {
    match reply {
        Reply::Answer(bytes) if bytes.len() > ANSWER_BYTES_MAX => Some(Status::TooLarge {
            max: ANSWER_BYTES_MAX as u64,
        }),
        Reply::Answer(bytes) => Some(Status::Answered(bytes)),
        Reply::Refuse(refusal) => Some(Status::refused(refusal.code, &refusal.text)),
        Reply::Pass => None,
    }
}

impl NodeInner {
    /// Answer one query (see the module docs for the order of the judgement). `ingress` is the
    /// forwarder face it arrived over, when the connection says.
    pub(crate) async fn query_answer(
        &self,
        interest: &Interest,
        ingress: Option<FaceId>,
    ) -> QueryOutcome {
        let arrived = Instant::now();
        let nack = QueryOutcome::Nack;
        let server = &self.query.server;

        // 1. The name, the size, the digest, the query.
        let Some((device, digest)) = parse_query_name(&interest.name) else {
            return nack(NackReason::NoRoute);
        };
        let Some(params) = interest.app_parameters().cloned() else {
            return nack(NackReason::NoRoute);
        };
        if device != self.device || params.len() > QUERY_ASK_MAX {
            return nack(NackReason::NoRoute);
        }
        let digest_holds = interest
            .parameters_portion()
            .is_some_and(|portion| Sha256::digest(&portion).as_slice() == digest);
        if !digest_holds {
            return nack(NackReason::NoRoute);
        }
        let Ok(ask) = QueryAsk::decode(params) else {
            return nack(NackReason::NoRoute);
        };
        let Some(sig_info) = interest.sig_info() else {
            return nack(NackReason::NoRoute);
        };
        let (Some(locator), Some(nonce), Some(signed_at)) = (
            sig_info.key_locator_name(),
            sig_info.sig_nonce.as_ref(),
            sig_info.sig_time,
        ) else {
            return nack(NackReason::NoRoute);
        };
        let key = key_name_of(&locator);
        let Some(asker_device) = device_of(&key) else {
            return nack(NackReason::NoRoute);
        };
        if parse_space_name(&ask.space).is_none() {
            return nack(NackReason::NoRoute);
        }

        // 2. The lookup budget, then the space and the standing of the key, offline.
        if !self.chan.gates.lookup(ingress, arrived) {
            return nack(NackReason::Congestion);
        }
        let Some(held) = self.space_of(&ask.space).filter(|s| !s.follower) else {
            return nack(NackReason::NoRoute);
        };
        if standing(&held.log.lock(), &self.judge, &key, Who::Listed).is_err() {
            return nack(NackReason::NoRoute);
        }

        // 3. The clock: within 120 s of this device's, and not before `serve` began (a restart
        // empties the replay set, and what was signed before it may be a copy).
        let floor = self.query.serving_since.get().copied().unwrap_or(0);
        if self.now().abs_diff(signed_at) > ASK_CLOCK_WINDOW_MS || signed_at < floor {
            tracing::debug!(%key, signed_at, floor, "query signed out of the clock window");
            return nack(NackReason::NoRoute);
        }

        // 4. The verification budget, whoever the query names.
        if !self.chan.gates.verify(ingress, arrived) {
            return nack(NackReason::Congestion);
        }

        // 5. The signature: the one expensive step.
        let generation = self.judge.generation();
        match self
            .judge
            .validate_interest(&ask.space, interest, &key, &ask.chain)
            .await
        {
            crate::trust::InterestJudged::Valid => {}
            crate::trust::InterestJudged::Pending(waiting) => {
                tracing::debug!(%key, "query not judged yet: {waiting}");
                return nack(NackReason::NotYet);
            }
            crate::trust::InterestJudged::Refused(why) => {
                tracing::debug!(%key, "query refused: {why}");
                return nack(NackReason::NoRoute);
            }
        }

        // 6. A replay costs the asker nothing; a new query is charged to her person's rate.
        match server.replay.check(&key, nonce, signed_at, arrived) {
            Replayed::Fresh => {}
            Replayed::Replay => return nack(NackReason::Duplicate),
            Replayed::Full => return nack(NackReason::Congestion),
        }

        // 7. Standing again under the record's lock, as the key that signed the query; this
        // device a writer; the sealed space's epoch and audience.
        let (person, epoch, judged_at) = {
            let log = held.log.lock();
            let Ok(person) = standing(&log, &self.judge, &key, Who::Listed) else {
                return nack(NackReason::NoRoute);
            };
            if gate(&log, &self.judge, Who::Writer, "queries").is_err() {
                return nack(NackReason::NoRoute);
            }
            let judged_at = (
                generation,
                log.fold.version().load(std::sync::atomic::Ordering::SeqCst),
            );
            let epoch = if log.sealed() {
                let Some(in_force) = log.fold.in_force() else {
                    return nack(NackReason::NotYet);
                };
                let Some(seal) = &ask.seal else {
                    // A plain query would show its path and octets to every forwarder.
                    return nack(NackReason::NoRoute);
                };
                if seal.epoch != in_force {
                    return nack(NackReason::NotYet);
                }
                if !log.fold.audience(&in_force).contains(&person) {
                    return nack(NackReason::NoRoute);
                }
                Some(in_force)
            } else if ask.seal.is_some() {
                return nack(NackReason::NoRoute);
            } else {
                None
            };
            (person, epoch, judged_at)
        };
        if !server.admit(&person, arrived) {
            return nack(NackReason::Congestion);
        }

        // 8. A sealed query is opened under the pair key; the path is then known.
        let (path, bytes, sealed) = match (&ask.seal, epoch) {
            (Some(seal), Some(_)) => {
                let keys = match server.pair(self, &ask.space, &asker_device, &key, seal, judged_at)
                {
                    Ok(keys) => keys,
                    Err(PairRefused::Full) => return nack(NackReason::Congestion),
                    Err(PairRefused::BadKey) => return nack(NackReason::NoRoute),
                };
                let aad = query_aad(
                    &self.device,
                    &asker_device,
                    &ask.space,
                    &seal.epoch,
                    &seal.ephemeral,
                    seal.seq,
                    &ask.id,
                );
                let Some(plain) = open_query(&keys, seal.seq, &aad, &ask.bytes) else {
                    // The asker holds a key this device does not: let the next query derive it
                    // again.
                    server.forget(&ask.space, &asker_device);
                    return nack(NackReason::NoRoute);
                };
                let Ok((path, bytes)) = QueryAsk::open_inner(Bytes::from(plain)) else {
                    return nack(NackReason::NoRoute);
                };
                (
                    path,
                    bytes,
                    Some(Sealed {
                        keys,
                        seal: seal.clone(),
                    }),
                )
            }
            _ => {
                let Some(path) = ask.path.clone() else {
                    return nack(NackReason::NoRoute);
                };
                (path, ask.bytes.clone(), None)
            }
        };
        let answer_to = Answering {
            name: &interest.name,
            id: ask.id,
            space: &ask.space,
            asker_device: &asker_device,
            sealed: sealed.as_ref(),
        };
        let Some((_, handler)) = self.query.table.lookup(&ask.space, &path) else {
            return self.query_sign(&answer_to, Status::NotServed, None);
        };

        // 9. The places, then the handler under the asker's deadline.
        let Some(slot) = server.slot(&person, arrived) else {
            return nack(NackReason::Congestion);
        };
        let deadline = arrived + Duration::from_millis(u64::from(ask.deadline_ms));
        let query = Query {
            id: QueryId(u64::from_be_bytes(ask.id)),
            path,
            bytes,
            asker: Asker {
                person,
                device: asker_device.clone(),
            },
            via: Via::Signed,
            deadline,
        };
        let wait = deadline.saturating_duration_since(Instant::now());
        let Ok(reply) = rt::timeout(wait, handler.answer(query)).await else {
            return QueryOutcome::Silent;
        };
        let Some(status) = status_of(reply) else {
            return QueryOutcome::Silent;
        };
        self.query_sign(&answer_to, status, Some(&slot))
    }

    /// The signed answer `status` to the query named `to.name`, sealed under the pair key in a
    /// sealed space. `slot` is charged the octets sent. The Data carries `FreshnessPeriod` 0
    /// (the dispatcher sends it `NoCache`) and this device's certificates as room allows.
    fn query_sign(
        &self,
        to: &Answering<'_>,
        status: Status,
        slot: Option<&Slot<'_>>,
    ) -> QueryOutcome {
        let body = match to.sealed {
            Some(Sealed { keys, seal }) => {
                let aad = answer_aad(
                    &self.device,
                    to.asker_device,
                    to.space,
                    &seal.epoch,
                    &seal.ephemeral,
                    seal.seq,
                    &to.id,
                );
                // The answer's nonce is the query's counter under the other key: the asker never
                // repeats a counter under one pair, and a counter of the server's own would
                // restart at 0 when its pair was evicted while the asker kept the ephemeral key.
                AnswerBody::Sealed {
                    seq: seal.seq,
                    cipher: seal_answer(keys, seal.seq, &aad, &status.encode_inner()),
                }
            }
            None => AnswerBody::Plain(status),
        };
        let answer = QueryAnswer {
            id: to.id,
            body,
            certs: self.signer_chain(),
        };
        let content = answer.encode().or_else(|_| {
            QueryAnswer {
                certs: Vec::new(),
                ..answer
            }
            .encode()
        });
        let content = match content {
            Ok(content) => content,
            Err(e) => {
                tracing::warn!("a query answer cannot be written: {e}");
                return QueryOutcome::Nack(NackReason::NoRoute);
            }
        };
        let builder = DataBuilder::new(to.name.clone(), &content).freshness(Duration::ZERO);
        match seal::sign(builder, &*self.signer) {
            Ok(wire) => {
                self.signatures
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if let Some(slot) = slot {
                    slot.charge(content.len(), Instant::now());
                }
                QueryOutcome::Data(wire)
            }
            Err(e) => {
                tracing::warn!("a query answer cannot be signed: {e}");
                QueryOutcome::Nack(NackReason::NoRoute)
            }
        }
    }

    /// Judge the pair keys held again from what is held now (offline): a pair whose asker no
    /// longer stands, or is out of the audience of the epoch in force, or was made for another
    /// epoch, is dropped. Cheap when the record and the trust generation have not moved.
    pub(crate) fn query_rejudge(&self) {
        let server = &self.query.server;
        for space in server.pair_spaces() {
            let Some(held) = self.space_of(&space).filter(|s| !s.follower) else {
                server.forget_space(&space);
                continue;
            };
            let log = held.log.lock();
            let live = (
                self.judge.generation(),
                log.fold.version().load(std::sync::atomic::Ordering::SeqCst),
            );
            if gate(&log, &self.judge, Who::Writer, "queries").is_err() {
                server.forget_space(&space);
                continue;
            }
            let in_force = log.fold.in_force();
            let audience = in_force.as_ref().map(|e| log.fold.audience(e));
            server.rejudge(&space, live, |pair| {
                let Ok(person) = standing(&log, &self.judge, &pair.key, Who::Listed) else {
                    return false;
                };
                match (&in_force, &audience) {
                    (Some(epoch), Some(members)) => {
                        pair.epoch == *epoch && members.contains(&person)
                    }
                    _ => true,
                }
            });
        }
    }

    /// The prefixes of `space` this device serves, as an announce lists them
    /// ([`announced_prefixes`]).
    pub(crate) fn query_serves(&self, space: &Name) -> Vec<Name> {
        announced_prefixes(self.query.table.prefixes(space))
    }
}

/// What an answer is addressed to: the query's name, id, space and asker, and the pair keys it is
/// sealed under in a sealed space.
struct Answering<'a> {
    name: &'a Name,
    id: [u8; 8],
    space: &'a Name,
    asker_device: &'a Name,
    sealed: Option<&'a Sealed>,
}
