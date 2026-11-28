//! The pairs of the `Ask` mode: the keys a server and one asker device share, and what each end
//! keeps of them (docs/specs/query.md, the channel path; docs/specs/channel.md §11.5).
//!
//! A channel's key is every receiver's, so a query sealed under it would prove "a holder of the
//! key" and not which asker. The session answer therefore also gives each asker a **pair**, the
//! two directional keys of one X25519 agreement ([`ndn_security::wrap_ck_to_pair`]) bound to the
//! space, the channel, the key epoch and both devices. A frame that opens under `Kq` is the
//! asker's (the device that signed the ask), one that opens under `Ka` the server's (the device
//! that signed the session): origin authentication between two parties, and **no
//! non-repudiation**: either could have made any frame.
//!
//! **Nonces.** Both directions use the nonce `epoch low octet, 0, 0, 0, qseq` (big-endian, 8
//! octets). `qseq` is the asker's counter under one pair, strictly rising from 0, never reused;
//! the answer repeats the query's `qseq` under the other key. A nonce is therefore used once under
//! each key, provided that
//!
//! * the **asker never repeats a `qseq` under a pair** ([`AskPair::next_qseq`]: a counter that
//!   takes a number once, whatever happens to the send: a retry is a new query with a new
//!   number, and two servers have two pairs and two counters);
//! * the **server answers a `qseq` at most once**: it marks the number in the pair's replay window
//!   *after* the AEAD opened and *before* it does anything else, so a copy of the frame, a
//!   concurrent copy and a retransmission are dropped, and every answer (the handler's, `Busy`,
//!   `NotServed`, `TooLarge`) is made only for a query it marked;
//! * a **pair is never re-derived**: its keys come from an ephemeral key the server made for one
//!   session answer, so a server that restarted, evicted the pair or re-keyed has no `Ka` to
//!   reuse: the asker's next ask gives new keys, a new pair id and a counter from 0. (On the
//!   signed path the asker's ephemeral key outlives the server's cache, which is why that path
//!   answers with the query's counter and no counter of its own; here the server's ephemeral
//!   key is as short-lived as the pair.)
//!
//! Everything is memory: a restart forgets every pair, and the asker finds out by silence
//! ([`AskPair::silence`]).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use ndn_foundation_types::Name;
use ndn_security::PairKeys;
use ndn_tlv::TlvWriter;
use parking_lot::Mutex;

use super::aead::{Aead, FrameCipher, NONCE_LEN};
use super::hub::Counter;
use super::limits::TAG_LEN;
use super::replay::{Replay, ReplayWindow};
use crate::rt::Instant;
use crate::wire::write_name;

/// The pairs a node keeps as a server, live and retired together. A channel keeps at most
/// [`ASKERS_PER_CHANNEL`](super::channels::ASKERS_PER_CHANNEL) askers and a node
/// [`CHANNELS_PER_SENDER`](super::channels::CHANNELS_PER_SENDER) channels; this is the bound of the
/// table whatever they say.
pub(crate) const PAIRS_MAX: usize = 16_384;

/// How long a pair that a new session of the same asker replaced still opens queries: the asker
/// installs the new session one round trip after the server made it, and the queries it sent in
/// that time name the old pair.
pub(crate) const RETIRED_GRACE: Duration = Duration::from_secs(5);

/// The longest a sealed `Busy` is sent to one pair: one a second (a query refused for a limit is
/// a frame that costs the server a seal, so the refusal is itself limited).
pub(crate) const BUSY_EVERY: Duration = Duration::from_secs(1);

/// The consecutive queries of one pair that nothing answered before the asker lets the session
/// go and asks again (a restarted or evicting server never answers a pair it forgot, and nothing
/// else tells the asker).
pub(crate) const SILENT_MAX: u32 = 3;

/// The counter of an asker's queries under a pair stays below this: 2^62 (the nonce has 8
/// octets and the frame refuses 2^63; a pair that reaches it is let go and asked again).
pub(crate) const QSEQ_LIMIT: u64 = 1 << 62;

/// How long an `Ask` session nobody queried is kept: a minute. It is kept while queries use it
/// (the node sends `Keep` every 10 s for it, so its route stands), and then let go with an
/// `Unsub`. The channel rule that a session ends when the last `Items` is dropped would defeat
/// reuse, so a query's `Items` does not end it.
pub(crate) const ASK_IDLE: Duration = Duration::from_secs(60);

/// What the pair keys are bound to: the space, both devices (each a `Name` TLV, so the encoding
/// is canonical), the channel id and the key epoch.
pub(crate) fn pair_context(
    space: &Name,
    channel: u64,
    key_epoch: u32,
    asker: &Name,
    server: &Name,
) -> Vec<u8> {
    let mut w = TlvWriter::new();
    write_name(&mut w, space);
    write_name(&mut w, asker);
    write_name(&mut w, server);
    w.write_raw(&channel.to_be_bytes());
    w.write_raw(&key_epoch.to_be_bytes());
    w.finish().to_vec()
}

/// The nonce of a query and of its answer: the key epoch's low octet, three zero octets, the
/// query's counter.
pub(crate) fn nonce(epoch: u8, qseq: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[0] = epoch;
    nonce[4..].copy_from_slice(&qseq.to_be_bytes());
    nonce
}

/// The two directional keys of a pair prepared for the session's AEAD.
pub(crate) struct PairCiphers {
    query: FrameCipher,
    answer: FrameCipher,
}

impl PairCiphers {
    pub(crate) fn new(keys: &PairKeys, aead: Aead) -> PairCiphers {
        PairCiphers {
            query: FrameCipher::from_key_octets(&keys.query, aead),
            answer: FrameCipher::from_key_octets(&keys.answer, aead),
        }
    }

    fn seal(cipher: &FrameCipher, epoch: u8, qseq: u64, aad: &[u8], plain: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(plain.len() + TAG_LEN);
        out.extend_from_slice(plain);
        let tag = cipher.seal_detached(nonce(epoch, qseq), aad, &mut out);
        out.extend_from_slice(&tag);
        out
    }

    fn open(
        cipher: &FrameCipher,
        epoch: u8,
        qseq: u64,
        aad: &[u8],
        sealed: &[u8],
    ) -> Option<Vec<u8>> {
        let mut buf = sealed.to_vec();
        cipher
            .open_in_place(nonce(epoch, qseq), aad, &mut buf)
            .ok()?;
        buf.truncate(sealed.len() - TAG_LEN);
        Some(buf)
    }

    /// Seal a query under `Kq`: the ciphertext, then the tag.
    pub(crate) fn seal_query(&self, epoch: u8, qseq: u64, aad: &[u8], plain: &[u8]) -> Vec<u8> {
        Self::seal(&self.query, epoch, qseq, aad, plain)
    }

    /// Open a query sealed under `Kq`; `None` when the tag does not verify.
    pub(crate) fn open_query(
        &self,
        epoch: u8,
        qseq: u64,
        aad: &[u8],
        sealed: &[u8],
    ) -> Option<Vec<u8>> {
        Self::open(&self.query, epoch, qseq, aad, sealed)
    }

    /// Seal an answer under `Ka` with the **query's** `qseq`.
    pub(crate) fn seal_answer(&self, epoch: u8, qseq: u64, aad: &[u8], plain: &[u8]) -> Vec<u8> {
        Self::seal(&self.answer, epoch, qseq, aad, plain)
    }

    /// Open an answer sealed under `Ka`; `None` when the tag does not verify.
    pub(crate) fn open_answer(
        &self,
        epoch: u8,
        qseq: u64,
        aad: &[u8],
        sealed: &[u8],
    ) -> Option<Vec<u8>> {
        Self::open(&self.answer, epoch, qseq, aad, sealed)
    }
}

impl std::fmt::Debug for PairCiphers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairCiphers(..)")
    }
}

// -- The server's half ----------------------------------------------------------------------------

/// Who a server pair is for and what it was made under.
#[derive(Clone, Debug)]
pub(crate) struct PairOwner {
    /// The space.
    pub(crate) space: Name,
    /// The channel id: the route queries go up.
    pub(crate) channel: u64,
    /// The key epoch the pair was given at.
    pub(crate) key_epoch: u32,
    /// The asker's device.
    pub(crate) device: Name,
    /// The asker's person, as judged when the ask was.
    pub(crate) person: Name,
    /// The key that signed the ask: judged again when the record moves.
    pub(crate) key: Name,
    /// The asker's path carries a stream: an answer too large for a datagram may go on it.
    pub(crate) stream: bool,
}

/// One asker device's pair at a server.
pub(crate) struct ServerPair {
    id: [u8; 8],
    /// Who it is for.
    pub(crate) owner: PairOwner,
    ciphers: PairCiphers,
    window: Mutex<ReplayWindow>,
    /// `(trust generation, fold version)` the asker was judged by last.
    judged_at: Mutex<(u64, u64)>,
    /// The space's fold version, shared with the record: with the trust generation it says, in
    /// two atomic loads, whether anything the asker was judged by has moved.
    fold: Arc<AtomicU64>,
    /// When the receiver's lease ends: no query opens after it.
    lease_until: Instant,
    /// When the next sealed `Busy` may be sent.
    busy_after: Mutex<Option<Instant>>,
    /// Set when a session of the same asker replaced this pair: it opens queries until then.
    retired: Mutex<Option<Instant>>,
    /// The use stamp that orders pairs (the idlest of the largest holder goes first).
    used: AtomicU64,
}

impl std::fmt::Debug for ServerPair {
    /// The pair's id and owner: never a key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerPair")
            .field("id", &self.id)
            .field("owner", &self.owner)
            .finish_non_exhaustive()
    }
}

impl ServerPair {
    /// A pair of `keys` for `owner`, sealed with `aead`, judged by `judged_at` (the trust
    /// generation and the value `fold`, the space's fold version, had), good until
    /// `lease_until`.
    pub(crate) fn new(
        keys: &PairKeys,
        aead: Aead,
        owner: PairOwner,
        judged_at: (u64, u64),
        fold: Arc<AtomicU64>,
        lease_until: Instant,
    ) -> ServerPair {
        ServerPair {
            id: keys.id,
            owner,
            ciphers: PairCiphers::new(keys, aead),
            window: Mutex::new(ReplayWindow::new()),
            judged_at: Mutex::new(judged_at),
            fold,
            lease_until,
            busy_after: Mutex::new(None),
            retired: Mutex::new(None),
            used: AtomicU64::new(0),
        }
    }

    /// The pair id: what a query names (a test asks; the table keys by it).
    #[cfg(test)]
    pub(crate) fn id(&self) -> [u8; 8] {
        self.id
    }

    /// The directional ciphers.
    pub(crate) fn ciphers(&self) -> &PairCiphers {
        &self.ciphers
    }

    /// Whether a query of counter `qseq` is worth opening: not marked, not below the window, not
    /// absurdly far above it. Marks nothing: a counter is marked only after its query opened.
    pub(crate) fn fresh(&self, qseq: u64) -> bool {
        let window = self.window.lock();
        window.check(qseq) == Replay::Fresh && !window.beyond(0, qseq)
    }

    /// Mark `qseq` as answered-for. `true` for the one caller that marked it: a copy that raced
    /// past [`Self::fresh`] and opened too gets `false` and is dropped, so each counter is
    /// answered at most once.
    pub(crate) fn mark(&self, qseq: u64) -> bool {
        self.window.lock().mark(qseq) == Replay::Fresh
    }

    /// What the asker was judged by last.
    pub(crate) fn judged_at(&self) -> (u64, u64) {
        *self.judged_at.lock()
    }

    /// Whether the trust generation `generation` or the space's fold has moved since the asker
    /// was judged: the asker is judged again before her query is opened.
    pub(crate) fn moved(&self, generation: u64) -> bool {
        self.judged_at() != (generation, self.fold.load(Ordering::SeqCst))
    }

    fn restamp(&self, at: (u64, u64)) {
        *self.judged_at.lock() = at;
    }

    /// Whether a sealed `Busy` may be sent at `now`; if so, the next is a second later.
    pub(crate) fn busy_due(&self, now: Instant) -> bool {
        let mut after = self.busy_after.lock();
        if after.is_some_and(|at| now < at) {
            return false;
        }
        *after = Some(now + BUSY_EVERY);
        true
    }

    /// Whether the pair opens queries at `now`: its lease has not ended and it was not retired
    /// longer ago than [`RETIRED_GRACE`].
    fn live(&self, now: Instant) -> bool {
        now < self.lease_until && self.retired.lock().is_none_or(|until| now < until)
    }
}

/// Why a pair was not installed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Full {
    /// [`PAIRS_MAX`] pairs are held.
    Table,
}

/// What a server counted of the frames of the channel path: why each was dropped and what it
/// cost. Each drop is a frame no handler saw and no answer was made for.
#[derive(Default)]
pub(crate) struct PairStats {
    /// `QUERY` frames that reached the server's judgement.
    pub(crate) queries: Counter,
    /// Shorter than a header plus a tag, over 2,048 octets, or a header that does not parse.
    pub(crate) malformed: Counter,
    /// A pair id this node holds no pair for on the route the frame names (never made, forgotten,
    /// lapsed or retired), or a key epoch octet that is not the pair's: dropped with no AEAD.
    pub(crate) unknown_pair: Counter,
    /// A counter already marked, below the window or beyond it: dropped with no AEAD.
    pub(crate) replayed: Counter,
    /// The asker no longer stands (the trust generation or the fold moved and she was judged
    /// again): the pair is dropped.
    pub(crate) rejudged_out: Counter,
    /// AEAD opens attempted: the only cryptography a query costs the server before a handler.
    pub(crate) opens: Counter,
    /// The tag did not verify.
    pub(crate) bad_seal: Counter,
    /// A plaintext that opened and is no query.
    pub(crate) bad_plain: Counter,
    /// A sealed `NotServed` was answered.
    pub(crate) not_served: Counter,
    /// A sealed `Busy` was answered.
    pub(crate) busy: Counter,
    /// A `Busy` the per-pair limit of one a second kept from being sent.
    pub(crate) busy_dropped: Counter,
    /// Handlers started.
    pub(crate) handlers: Counter,
    /// Answers sent (the handler's, a refusal, `TooLarge`).
    pub(crate) answers: Counter,
    /// A handler ended with no answer (`Pass`, or past the asker's deadline).
    pub(crate) silent: Counter,
    /// An answer the carrier could not take.
    pub(crate) not_sent: Counter,
}

#[derive(Default)]
struct ServerTable {
    by_id: HashMap<[u8; 8], Arc<ServerPair>>,
    /// The current pair of each (space, asker device).
    by_asker: HashMap<(Name, Name), [u8; 8]>,
    uses: u64,
}

/// The pairs a node holds as a server of `Ask` channels.
#[derive(Default)]
pub(crate) struct ServerPairs {
    table: Mutex<ServerTable>,
    pub(crate) stats: PairStats,
}

impl ServerPairs {
    /// Hold `pair`; the pair this asker device had before is retired (it opens queries for
    /// [`RETIRED_GRACE`] more). `Err` when the table is full: nothing was held.
    pub(crate) fn install(&self, pair: ServerPair, now: Instant) -> Result<Arc<ServerPair>, Full> {
        let mut table = self.table.lock();
        if table.by_id.len() >= PAIRS_MAX {
            sweep(&mut table, now);
            if table.by_id.len() >= PAIRS_MAX {
                return Err(Full::Table);
            }
        }
        let at = (pair.owner.space.clone(), pair.owner.device.clone());
        if let Some(old) = table.by_asker.get(&at).copied()
            && old != pair.id
            && let Some(old) = table.by_id.get(&old)
        {
            *old.retired.lock() = Some(now + RETIRED_GRACE);
        }
        table.uses += 1;
        pair.used.store(table.uses, Ordering::Relaxed);
        let id = pair.id;
        let pair = Arc::new(pair);
        table.by_asker.insert(at, id);
        table.by_id.insert(id, Arc::clone(&pair));
        Ok(pair)
    }

    /// The pair `id` names on channel `channel`, if it opens queries at `now`.
    pub(crate) fn get(&self, id: &[u8; 8], channel: u64, now: Instant) -> Option<Arc<ServerPair>> {
        let mut table = self.table.lock();
        let pair = table.by_id.get(id)?;
        if pair.owner.channel != channel || !pair.live(now) {
            return None;
        }
        let pair = Arc::clone(pair);
        table.uses += 1;
        pair.used.store(table.uses, Ordering::Relaxed);
        Some(pair)
    }

    /// Forget the pairs (live and retired) of `device` in `space`: it asks again to hold one.
    pub(crate) fn drop_device(&self, space: &Name, device: &Name) {
        let mut table = self.table.lock();
        table
            .by_id
            .retain(|_, p| !(p.owner.space == *space && p.owner.device == *device));
        table.by_asker.remove(&(space.clone(), device.clone()));
    }

    /// Forget every pair of `space`.
    pub(crate) fn drop_space(&self, space: &Name) {
        let mut table = self.table.lock();
        table.by_id.retain(|_, p| p.owner.space != *space);
        table.by_asker.retain(|(s, _), _| s != space);
    }

    /// Forget every pair.
    pub(crate) fn drop_all(&self) {
        let mut table = self.table.lock();
        table.by_id.clear();
        table.by_asker.clear();
    }

    /// The pairs of `space` judged by `live` stay; the others stay only if `keep` says the asker
    /// still stands, and are then judged by `live`. Returns the devices dropped.
    pub(crate) fn rejudge(
        &self,
        space: &Name,
        live: (u64, u64),
        mut keep: impl FnMut(&PairOwner) -> bool,
    ) -> Vec<Name> {
        let mut table = self.table.lock();
        let mut dropped = Vec::new();
        table.by_id.retain(|_, pair| {
            if pair.owner.space != *space {
                return true;
            }
            let stands = pair.judged_at() == live || keep(&pair.owner);
            if stands {
                pair.restamp(live);
            }
            stands
        });
        // `by_asker` follows `by_id`; a device is dropped when its current pair went.
        let held: Vec<[u8; 8]> = table.by_id.keys().copied().collect();
        table.by_asker.retain(|(s, d), id| {
            let kept = held.contains(id);
            if !kept && s == space {
                dropped.push(d.clone());
            }
            kept
        });
        dropped.sort();
        dropped.dedup();
        dropped
    }

    /// Forget what lapsed or was retired and is past its grace at `now`.
    pub(crate) fn sweep(&self, now: Instant) {
        sweep(&mut self.table.lock(), now);
    }

    /// The pairs held, live and retired (a test asks).
    #[cfg(test)]
    pub(crate) fn count(&self) -> usize {
        self.table.lock().by_id.len()
    }

    /// Whether `device` holds a live pair in `space` (a test asks).
    #[cfg(test)]
    pub(crate) fn has(&self, space: &Name, device: &Name) -> bool {
        self.table
            .lock()
            .by_asker
            .contains_key(&(space.clone(), device.clone()))
    }
}

fn sweep(table: &mut ServerTable, now: Instant) {
    table.by_id.retain(|_, p| p.live(now));
    let held: Vec<[u8; 8]> = table.by_id.keys().copied().collect();
    table.by_asker.retain(|_, id| held.contains(id));
}

// -- The asker's half -----------------------------------------------------------------------------

/// The pair an asker holds with one server, made when the session answer was taken.
pub(crate) struct AskPair {
    id: [u8; 8],
    /// The channel id: the route its queries go up.
    pub(crate) channel: u64,
    /// The key epoch the pair was given at.
    pub(crate) key_epoch: u32,
    ciphers: PairCiphers,
    next: AtomicU64,
    used: Mutex<Instant>,
    silent: AtomicU32,
}

impl std::fmt::Debug for AskPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AskPair")
            .field("id", &self.id)
            .field("channel", &self.channel)
            .finish_non_exhaustive()
    }
}

impl AskPair {
    /// The pair of `keys` for channel `channel` at `key_epoch`, made at `now`.
    pub(crate) fn new(
        keys: &PairKeys,
        aead: Aead,
        channel: u64,
        key_epoch: u32,
        now: Instant,
    ) -> AskPair {
        AskPair {
            id: keys.id,
            channel,
            key_epoch,
            ciphers: PairCiphers::new(keys, aead),
            next: AtomicU64::new(0),
            used: Mutex::new(now),
            silent: AtomicU32::new(0),
        }
    }

    /// The pair id.
    pub(crate) fn id(&self) -> [u8; 8] {
        self.id
    }

    /// The low octet of the key epoch: the nonce's and the headers'.
    pub(crate) fn epoch(&self) -> u8 {
        self.key_epoch as u8
    }

    /// The directional ciphers.
    pub(crate) fn ciphers(&self) -> &PairCiphers {
        &self.ciphers
    }

    /// The counter of the next query: each number is taken **once** (an atomic increment), so no
    /// two queries of the pair share one whatever becomes of the first, and `None` at
    /// [`QSEQ_LIMIT`]: the pair is used up and the asker asks again.
    pub(crate) fn next_qseq(&self) -> Option<u64> {
        let seq = self.next.fetch_add(1, Ordering::Relaxed);
        (seq < QSEQ_LIMIT).then_some(seq)
    }

    /// A query was sent under the pair at `now`.
    pub(crate) fn touch(&self, now: Instant) {
        *self.used.lock() = now;
    }

    /// When the pair was last used.
    pub(crate) fn used(&self) -> Instant {
        *self.used.lock()
    }

    /// An answer opened under the pair: the server holds it.
    pub(crate) fn answered(&self) {
        self.silent.store(0, Ordering::Relaxed);
    }

    /// A query of the pair got nothing by its deadline. Returns whether [`SILENT_MAX`] in a row
    /// did: the server has probably forgotten the pair, and the session should be let go.
    pub(crate) fn silence(&self) -> bool {
        self.silent.fetch_add(1, Ordering::Relaxed) + 1 >= SILENT_MAX
    }
}

/// The pairs an asker holds, by the id of the session (the channel) they belong to. A session
/// that ended or lapsed takes its pair with it ([`AskPairs::retain_sessions`]).
#[derive(Default)]
pub(crate) struct AskPairs {
    by_session: Mutex<HashMap<u64, Arc<AskPair>>>,
}

impl AskPairs {
    /// Hold `pair` for session `session`, replacing the one held. A query already sent under the
    /// old one keeps it (its pending entry holds a reference), so its answer still opens.
    pub(crate) fn set(&self, session: u64, pair: AskPair) -> Arc<AskPair> {
        let pair = Arc::new(pair);
        self.by_session.lock().insert(session, Arc::clone(&pair));
        pair
    }

    /// The pair of session `session`.
    pub(crate) fn get(&self, session: u64) -> Option<Arc<AskPair>> {
        self.by_session.lock().get(&session).cloned()
    }

    /// Forget the pair of `session`.
    pub(crate) fn remove(&self, session: u64) {
        self.by_session.lock().remove(&session);
    }

    /// Keep the pairs of the sessions `held` says are held; forget the rest.
    pub(crate) fn retain_sessions(&self, held: impl Fn(u64) -> bool) {
        self.by_session.lock().retain(|id, _| held(*id));
    }

    /// The sessions that hold a pair last used at least `idle` before `now`.
    pub(crate) fn idle(&self, now: Instant, idle: Duration) -> Vec<u64> {
        self.by_session
            .lock()
            .iter()
            .filter(|(_, p)| now.saturating_duration_since(p.used()) >= idle)
            .map(|(id, _)| *id)
            .collect()
    }

    /// The pairs held.
    #[cfg(test)]
    pub(crate) fn count(&self) -> usize {
        self.by_session.lock().len()
    }
}

#[cfg(test)]
#[path = "pair_tests.rs"]
mod tests;
