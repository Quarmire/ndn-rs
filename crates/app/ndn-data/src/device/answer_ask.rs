//! Asking another device for an answer (`docs/specs/answers.md` §15): the sealed ask exchange.
//!
//! A reader that finds no published answer may ask a signer its policy names: an Interest named
//! `<D>/32=ask-answer/<ParametersSha256Digest>` whose ApplicationParameters are an
//! [`AnswerAskEnvelope`]. It is sealed to the signer's seal key as an introduction's ask is, and
//! holds the question, the asker's device name and the asker's proof, a packet
//! `<A>/32=ask/<binding>` signed by its device key whose binding covers the question and the
//! ephemeral key. The reply is Data named as the Interest and signed by the signer's device key:
//! the signed answer packet, unchanged, or an [`AnswerAskRefusal`].
//!
//! The signer answers an ask only from an asker it authenticated, and in this order: the
//! parameters match the name's digest and the signer holds fewer asks than it may
//! ([`crate::AnswerConfig::asks_queued`]); the envelope opens and the proof, named for an asker
//! of a namespace the serving policy ([`AskServing`]) serves, verifies within the ask's
//! lifetime (else no reply at all, not even a Nack); the asker is of a role served; the asker
//! has no ask in progress and the signer is under its caps; the asker is of the audience of
//! every read, checked before anything is read from the network and again once the reads
//! are held; the answer is read from the store, or computed ([`Device::publish_answer`]) or
//! asked of the host ([`Device::provider_asks`]).

use std::collections::HashMap;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_app::Consumer;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Data, Name};
use ndn_security::confidentiality::ContentKey;
use ndn_tlv::TlvReader;
use tokio::sync::{OwnedSemaphorePermit, mpsc, oneshot};

use super::answer_get::{Opened, Reading, SIGNED_PER_SECOND, evaluator_reading};
use super::answer_reads::{STATE_READS_CHECKED_MAX, VersionFact};
use super::answers::Signing;
use super::{Device, Inner, St, local, rt};
use crate::answer::{
    AnswerAsk, AnswerAskBody, AnswerAskEnvelope, AnswerAskRefusal, AnswerKind, Answered,
    AskRefusal, AskServing, ProviderAsk, ReadRef, ReadSet, answer_ask_name, answer_ask_prefix, tlv,
};
use crate::collection::Epoch;
use crate::error::{AnswerRefusal, DataError};
use crate::layer::{Age, Answer, Got};
use crate::seal::{AskKey, open_ask_keyed};
use crate::wire::{self, device_of, parse_seal_key_name};

/// How long an asker is told to wait before asking again when the signer is busy or the answer
/// is not ready.
const RETRY_AFTER: Duration = Duration::from_secs(1);
/// The part of an ask's lifetime left for the signer to send its reply once its work is cut
/// short.
const REPLY_MARGIN: Duration = Duration::from_millis(200);
/// What an Interest that states no lifetime lasts (RFC-style default of NDN: 4 s).
const LIFETIME_DEFAULT: Duration = Duration::from_secs(4);
/// The provider asks held for a host to take ([`Device::provider_asks`]).
const PROVIDER_ASKS_QUEUED: usize = 64;
/// How many times one signer is asked when it answers `Busy` or `Pending`.
const ASK_ATTEMPTS: u32 = 3;
/// How many times one ask is sent when nothing answers it (the same parameters each time, so a
/// lost packet costs one more send and the signer's work is not repeated).
const ASK_SENDS: u32 = 3;
/// The longest an asker waits on a signer's `retry_after`.
const RETRY_AFTER_MAX: Duration = Duration::from_secs(10);
/// How stale an answer over reads its signer chose may be, which nothing on this device
/// confirmed: as long as a duration this device reports goes (about 136 years).
const UNCONFIRMED: Duration = Duration::from_secs(u32::MAX as u64);

fn answer_error(name: &Name, why: AnswerRefusal) -> DataError {
    DataError::Answer {
        name: name.clone(),
        why,
    }
}

/// What an ask nobody replied to says: a silent signer is not always an unreachable one.
fn no_reply(question: &Name) -> DataError {
    DataError::NotReady {
        name: question.clone(),
        why: "no signer replied to the ask. A signer that is not reached is silent, and so is one \
              that does not authenticate this device or does not serve it: a certificate that \
              lapsed by a clock (this device's own, or the signer's) makes the device silent \
              to the other, and a signer serves only the namespaces and roles its \
              Config::answers.serve_asks and ask_roles name. Check the clocks and certificates \
              of both devices and the signer's policy, then ask again once the signer is \
              reachable"
            .into(),
    }
}

/// What a signer keeps of the asks for an answer it holds.
#[derive(Default)]
pub(super) struct AnswerAsks {
    /// Asks held while they are opened and their proofs verified
    /// ([`crate::AnswerConfig::asks_queued`]).
    queued: usize,
    /// Of those, the asks whose asker's key has no certificate held here, so that fetching one
    /// may be what they wait for: at most [`uncached_queued`] of them.
    uncached: usize,
    /// Asks being worked on whose asker is of another namespace than this device's.
    foreign: usize,
    /// The same, for each such namespace.
    by_namespace: HashMap<Name, usize>,
    /// Calls of a provider function handed to the host and not provided yet, by the function
    /// and the digest of its inputs, with when each was handed over: a second ask of the same
    /// call waits for the first's answer ([`Device::provider_asks`]).
    calls: HashMap<(Name, [u8; 32]), rt::Instant>,
}

impl AnswerAsks {
    /// Asks held while they are opened and verified, for the cases.
    #[cfg(test)]
    pub(super) fn queued(&self) -> usize {
        self.queued
    }

    /// Asks held while opened whose asker's certificate is not held, for the cases.
    #[cfg(test)]
    pub(super) fn uncached(&self) -> usize {
        self.uncached
    }

    /// Count one more ask in progress of a device of the namespace `ns`, another than this
    /// device's, if the share `at_once` leaves other namespaces has room: half of it, and half
    /// of that for one namespace.
    fn take_foreign(&mut self, ns: &Name, at_once: usize) -> bool {
        let others = at_once / 2;
        let one = others.div_ceil(2).max(1);
        if self.foreign >= others || self.by_namespace.get(ns).is_some_and(|n| *n >= one) {
            return false;
        }
        self.foreign += 1;
        *self.by_namespace.entry(ns.clone()).or_default() += 1;
        true
    }

    fn release_foreign(&mut self, ns: &Name) {
        self.foreign = self.foreign.saturating_sub(1);
        if let Some(n) = self.by_namespace.get_mut(ns) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.by_namespace.remove(ns);
            }
        }
    }

    /// Note that the call of `function` over inputs of digest `inputs` is handed to the host:
    /// whether it is, that is, no other of the same call is waiting for it, within `time`.
    fn begin_call(&mut self, function: &Name, inputs: &[u8; 32], time: Duration) -> bool {
        let now = rt::Instant::now();
        self.calls
            .retain(|_, at| now.saturating_duration_since(*at) < time);
        match self.calls.entry((function.clone(), *inputs)) {
            std::collections::hash_map::Entry::Occupied(_) => false,
            std::collections::hash_map::Entry::Vacant(v) => {
                v.insert(now);
                true
            }
        }
    }

    /// The call of `function` over inputs of digest `inputs` is done (provided, or not taken).
    pub(super) fn done(&mut self, function: &Name, inputs: &[u8; 32]) {
        self.calls.remove(&(function.clone(), *inputs));
    }
}

/// The most asks held while opened that wait on a proof whose key has no certificate held: a
/// quarter of `asks_queued`, at least one (answers.md §15.3).
fn uncached_queued(asks_queued: usize) -> usize {
    (asks_queued / 4).max(1)
}

/// One ask held while it is opened and its proof verified, let go as it is dropped.
struct AskQueued<'a> {
    inner: &'a Inner,
    /// Whether it also holds one of the places of the asks whose asker's certificate is not
    /// held ([`uncached_queued`]).
    uncached: bool,
}

impl AskQueued<'_> {
    /// Hold one of the places of the asks whose asker's certificate is not held, if one is
    /// free; `false` when the share is taken.
    fn hold_uncached(&mut self) -> bool {
        if self.uncached {
            return true;
        }
        let mut st = self.inner.st.lock();
        let share = uncached_queued(self.inner.config.answers.asks_queued);
        if st.answer_asks.uncached >= share {
            tracing::debug!(
                me = %self.inner.device,
                held = st.answer_asks.uncached,
                "an ask for an answer whose asker's certificate is not held is not answered: its share of Config::answers.asks_queued is taken"
            );
            return false;
        }
        st.answer_asks.uncached += 1;
        self.uncached = true;
        true
    }
}

impl Drop for AskQueued<'_> {
    fn drop(&mut self) {
        let mut st = self.inner.st.lock();
        st.answer_asks.queued = st.answer_asks.queued.saturating_sub(1);
        if self.uncached {
            st.answer_asks.uncached = st.answer_asks.uncached.saturating_sub(1);
        }
    }
}

/// The caps one ask holds while it is worked on: the asker's one in progress
/// ([`Inner::take_ask`]), its namespace's share when it is not this device's, and one of the
/// signer's [`AnswerConfig::asks_at_once`] ([`crate::AnswerConfig`]). Given back when dropped,
/// wherever the work ends.
struct AskHold {
    inner: Arc<Inner>,
    asker: Name,
    /// The asker's namespace, when it is another's than this device's.
    foreign: Option<Name>,
    _permit: OwnedSemaphorePermit,
}

impl AskHold {
    /// The caps for an ask of `asker`, of namespace `ns`; `None` when one is spent.
    fn take(inner: &Arc<Inner>, asker: &Name, ns: &Name) -> Option<Self> {
        if !inner.take_ask(asker, 1) {
            return None;
        }
        let foreign = (*ns != inner.ns).then(|| ns.clone());
        if let Some(ns) = &foreign {
            let at_once = inner.config.answers.asks_at_once.max(1);
            if !inner.st.lock().answer_asks.take_foreign(ns, at_once) {
                inner.release_ask(asker);
                return None;
            }
        }
        match Arc::clone(&inner.asks_at_once).try_acquire_owned() {
            Ok(permit) => Some(AskHold {
                inner: Arc::clone(inner),
                asker: asker.clone(),
                foreign,
                _permit: permit,
            }),
            Err(_) => {
                if let Some(ns) = &foreign {
                    inner.st.lock().answer_asks.release_foreign(ns);
                }
                inner.release_ask(asker);
                None
            }
        }
    }
}

impl Drop for AskHold {
    fn drop(&mut self) {
        if let Some(ns) = &self.foreign {
            self.inner.st.lock().answer_asks.release_foreign(ns);
        }
        self.inner.release_ask(&self.asker);
    }
}

/// Who asks, for the checks of a read set.
#[derive(Clone)]
pub(super) struct Gate {
    pub(super) asker: Name,
    /// The asker's namespace.
    pub(super) ns: Name,
    /// Whether the asker must be a listed writer or reader of every collection read: it is of
    /// another namespace than this device's, and [`AskServing::OwnAndMembers`] serves it.
    pub(super) members: bool,
}

/// Whether a device may hold the key of an epoch, as far as what this device holds tells.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Standing {
    /// It may.
    In,
    /// It may not.
    Out,
    /// The records that tell are not all held here (yet): neither.
    NotHeld,
}

/// A signer's reply, as the asker reads it.
pub(super) enum Reply {
    /// The signed answer packet.
    Packet(Box<Data>),
    /// A refusal.
    Refused(AnswerAskRefusal),
}

// ---- the signer -----------------------------------------------------------------------------

impl Inner {
    /// Answer an ask for an answer (answers.md §15): the reply Data, signed by this device's key,
    /// named as the Interest; `None` for an ask that does not authenticate, or that no namespace
    /// this device serves made, or past the asks held already
    /// ([`crate::AnswerConfig::asks_queued`]), which get no reply at all. `lifetime`: the
    /// Interest's.
    pub(super) async fn answer_ask(
        self: &Arc<Self>,
        name: &Name,
        params: Option<Bytes>,
        lifetime: Option<Duration>,
    ) -> Option<Bytes> {
        let lifetime = lifetime.unwrap_or(LIFETIME_DEFAULT);
        let Some(params) = params.filter(|p| answer_ask_name(&self.device, p) == *name) else {
            tracing::debug!(me = %self.device, %name, "an ask for an answer is not answered: the name's digest is not the parameters'");
            return None;
        };
        let opened = {
            let mut queued = self.queue_answer_ask()?;
            rt::timeout(lifetime, self.open_answer_ask(params, &mut queued)).await
        };
        let (asker, ask, reply_key) = match opened {
            Ok(Ok(opened)) => opened,
            Ok(Err(why)) => {
                tracing::debug!(me = %self.device, %name, "an ask for an answer is not answered: {why}");
                return None;
            }
            Err(_) => {
                tracing::debug!(me = %self.device, %name, "an ask for an answer is not answered: it was not opened and its proof not verified within the ask's lifetime");
                return None;
            }
        };
        let content = match self.judge_answer_ask(&asker, ask, lifetime).await {
            Ok(packet) => packet,
            Err(refusal) => {
                tracing::debug!(me = %self.device, %asker, why = ?refusal.why, "an ask for an answer is refused");
                refusal.encode(&reply_key, name)
            }
        };
        self.sign(DataBuilder::new(name.clone(), &content).freshness(Duration::ZERO))
            .ok()
    }

    /// Hold one more ask while it is opened and verified, if the signer holds fewer than
    /// [`crate::AnswerConfig::asks_queued`].
    fn queue_answer_ask(&self) -> Option<AskQueued<'_>> {
        let mut st = self.st.lock();
        if st.answer_asks.queued >= self.config.answers.asks_queued {
            tracing::warn!(
                me = %self.device,
                held = st.answer_asks.queued,
                "an ask for an answer is not answered: as many asks as Config::answers.asks_queued allows are held already; its asker's retry is judged once they are done"
            );
            return None;
        }
        st.answer_asks.queued += 1;
        Some(AskQueued {
            inner: self,
            uncached: false,
        })
    }

    /// Whether the key an ask's proof names has a certificate vouched for held here (or is a
    /// trust anchor of the context that judges the proof): a lookup in the certificates this
    /// device holds, made before any slot or permit is taken for verifying, and never a
    /// fetch. A certificate fetched and not vouched for yet does not count: whoever is asked
    /// for one may serve it.
    fn proof_key_held(&self, proof: &Data) -> bool {
        let Some(key) = proof.sig_info().and_then(|s| s.key_locator_name()) else {
            return false;
        };
        let judge = self.judge_any(&proof.name);
        judge.cert_cache().holds_vouched(&key)
            || judge
                .keyring()
                .context_for(&proof.name)
                .anchor_for(&key)
                .is_some()
    }

    /// Whether the serving policy ([`AskServing`]) serves devices of the namespace `ns`: this
    /// device's own, and under [`AskServing::OwnAndMembers`] any other this device holds a trust
    /// context for. A device of any other namespace is not answered, however it proves itself,
    /// and no certificate is fetched to find out whether it does.
    fn serves_namespace(&self, ns: &Name) -> bool {
        match self.config.answers.serve_asks {
            AskServing::Off => false,
            AskServing::Own => !ns.is_empty() && *ns == self.ns,
            AskServing::OwnAndMembers => !ns.is_empty(),
        }
    }

    /// Whether the role of `asker`, a device of this device's namespace, is one
    /// [`crate::AnswerConfig::ask_roles`] serves. A name that carries no role is served only in a
    /// namespace that does not declare the role layout (its context lists no role in
    /// DataRequiresCut: a flat namespace has no role to refuse); where it does, a name with no
    /// role is no device the namespace's CA issued, so it is not served as one of the person's
    /// own ([`SignedTrustContext::is_role_less_device`](ndn_security::SignedTrustContext::is_role_less_device)).
    fn role_served(&self, asker: &Name) -> bool {
        let context = self.validator.keyring().context_for(asker);
        match context.role_of(asker) {
            None => !context.is_role_less_device(asker),
            Some(role) => self
                .config
                .answers
                .ask_roles
                .iter()
                .any(|served| served.as_bytes() == role),
        }
    }

    /// Steps 1 and 2: the envelope opens with this device's seal key, and the asker's proof,
    /// of a device of a namespace this device serves, verifies as the proof of this very ask.
    /// Why not, if not.
    async fn open_answer_ask(
        self: &Arc<Self>,
        params: Bytes,
        queued: &mut AskQueued<'_>,
    ) -> Result<(Name, AnswerAsk, ContentKey), &'static str> {
        let (envelope, body, reply_key) = {
            let _verifying = self
                .answer_verifying
                .acquire()
                .await
                .map_err(|_| "this device stopped")?;
            let envelope = AnswerAskEnvelope::decode(params).map_err(|_| "no envelope")?;
            let aad = answer_ask_prefix(&self.device).encode_to_tlv();
            let (plain, reply_key) = open_ask_keyed(
                &self.st.lock().keys.recipient,
                &aad,
                &envelope.ephemeral,
                &envelope.key,
                &envelope.sealed,
            )
            .ok_or("the envelope does not open")?;
            let body =
                AnswerAskBody::decode(Bytes::from(plain)).map_err(|_| "the body is malformed")?;
            (envelope, body, reply_key)
        };
        // Who the proof claims, unverified: nothing is fetched for a device of a namespace this
        // device does not serve.
        let (proof, claimed) = Self::claimed_asker(&body.proof)
            .filter(|(_, claimed)| *claimed == body.asker)
            .ok_or("its proof is not a packet signed by the device that asks")?;
        if !self.serves_namespace(&self.asker_namespace(&claimed)) {
            return Err("the asker is of no namespace this device serves");
        }
        let binding = AnswerAskBody::binding(&self.device, &body.ask, &envelope.ephemeral);
        // A proof whose key has a certificate held here verifies from what is held; any other
        // may wait on a fetch, so those take the one turn and the share of the queue meant for
        // them, and a crowd of them cannot keep the known devices waiting.
        let turns = if self.proof_key_held(&proof) {
            &self.answer_verifying
        } else if queued.hold_uncached() {
            &self.answer_uncached_verifying
        } else {
            return Err(
                "as many asks whose asker's certificate is not held here as \
                 Config::answers.asks_queued allows (a quarter of it) are waiting already; the \
                 asker asks again once they are done, and holds its certificate here after the \
                 first fetch of it",
            );
        };
        if !self.proves_with(turns, &proof, &claimed, &binding).await {
            return Err("its proof does not verify as the asker's, for this ask");
        }
        Ok((claimed, body.ask, reply_key))
    }

    /// Steps 3 to 7: what the signer answers an authenticated asker: the answer packet, or why
    /// not.
    async fn judge_answer_ask(
        self: &Arc<Self>,
        asker: &Name,
        ask: AnswerAsk,
        lifetime: Duration,
    ) -> Result<Bytes, AnswerAskRefusal> {
        let ns = self.asker_namespace(asker);
        let own = ns == self.ns;
        if own && !self.role_served(asker) {
            return Err(AskRefusal::NotServed.into());
        }
        let hold = AskHold::take(self, asker, &ns).ok_or(AskRefusal::Busy {
            retry_after: RETRY_AFTER,
        })?;
        let qname = self.ask_question_name(&ask)?;
        let gate = Gate {
            asker: asker.clone(),
            ns,
            members: self.config.answers.serve_asks == AskServing::OwnAndMembers && !own,
        };
        // The audience, before anything is read from the network or computed: of the reads the
        // asker states, or of the definition it names when the signer plans the rest.
        match (&ask.reads, &ask.definition) {
            (Some(set), _) => self.gate_reads(&gate, set, false).await?,
            (None, Some(definition)) => {
                let set = ReadSet::new([definition.clone()]).expect("one read");
                self.gate_reads(&gate, &set, false).await?;
                // The definition is read and judged again as held before anything is planned
                // over it, whether this signer knows the evaluator or not: what the evaluator
                // says of it, and what `CannotCheck` says of which evaluators this signer
                // knows, are for an asker who may read it. (The reads the plan makes past it
                // are judged in `planned`, as they are made.)
                self.fetched(&qname, &set).await?;
                self.gate_reads(&gate, &set, true).await?;
                if ask.kind == AnswerKind::Pure && self.config.evaluators.get(&ask.by).is_none() {
                    return Err(AskRefusal::CannotCheck.into());
                }
            }
            (None, None) => {}
        }
        // The id: planning reads, never evaluating. The reads that come of it are the ones
        // computed, so they are the ones judged, whoever chose them.
        let resolved = self.planned(&gate, &qname, &ask).await?;
        self.gate_reads(&gate, &resolved.reads, true).await?;
        if let Some(packet) = self.own_answer_wire(&resolved.id) {
            return Ok(packet);
        }
        let wait = lifetime
            .saturating_sub(REPLY_MARGIN)
            .min(self.config.answers.budget.time);
        match ask.kind {
            AnswerKind::Pure => {
                let planned = ask.reads.is_none();
                let stated = ask.stating(resolved.reads);
                self.compute_for_ask(hold, qname, stated, planned, wait)
                    .await
            }
            AnswerKind::Provider => self
                .provider_for_ask(&ask, resolved.id, asker, wait)
                .await
                .map_err(Into::into),
        }
    }

    /// The question's name, as `publish_question` takes it.
    fn ask_question_name(&self, ask: &AnswerAsk) -> Result<Name, AskRefusal> {
        let provider = (ask.kind == AnswerKind::Provider).then_some(&self.device);
        ask.name(provider).map_err(|e| {
            tracing::debug!(me = %self.device, "an ask names no question: {e}");
            match ask.kind {
                AnswerKind::Pure => AskRefusal::CannotCheck,
                AnswerKind::Provider => AskRefusal::NotProvided,
            }
        })
    }

    /// Plan the question, within [`crate::Budget::time`]: reads of versions not held are
    /// fetched, which takes as long as the network does, and the caps the ask holds are not
    /// kept for longer. `Pending` when it is not done: what was fetched is held, and the
    /// asker's next ask goes on from there. A known evaluator's refusal while planning is
    /// told with its words only as [`Self::admitted_words`] allows.
    async fn planned(
        self: &Arc<Self>,
        gate: &Gate,
        qname: &Name,
        ask: &AnswerAsk,
    ) -> Result<super::answer_get::Resolved, AnswerAskRefusal> {
        match rt::timeout(
            self.config.answers.budget.time,
            self.resolve_reading(qname, ask, false),
        )
        .await
        {
            Ok(Ok(resolved)) => Ok(resolved),
            Ok(Err(failed)) => {
                let refusal = self.ask_refusal(ask.kind, &failed.error);
                Err(self.admitted_words(gate, refusal, failed.read).await)
            }
            Err(_) => Err(AskRefusal::Pending {
                retry_after: RETRY_AFTER,
            }
            .into()),
        }
    }

    /// `refusal`, with the evaluator's words if it has any ([`AskRefusal::EvaluatorRefused`])
    /// only if the asker is of the audience of every one of `read`, the reads the evaluator
    /// had made when it spoke: its words quote what it read (a parse error quotes the value),
    /// and the asker, who may have left the reads to this signer, never chose them. If it is not
    /// of the audience of one, the refusal says so (`NotAudience`, `NotServed`: the reads are
    /// held, as they were just read, so this is what [`Self::gate_reads`] says of them again); any
    /// other verdict, and a refusal that carries no reads, gets the fixed text of the reason.
    async fn admitted_words(
        self: &Arc<Self>,
        gate: &Gate,
        refusal: AnswerAskRefusal,
        read: Vec<ReadRef>,
    ) -> AnswerAskRefusal {
        if refusal.why != AskRefusal::EvaluatorRefused {
            return refusal;
        }
        let fixed = || AnswerAskRefusal::new(AskRefusal::EvaluatorRefused);
        let set = match ReadSet::new(read) {
            Ok(set) if !set.reads().is_empty() => set,
            _ => return fixed(),
        };
        match self.gate_reads(gate, &set, true).await {
            Ok(()) => refusal,
            Err(why @ (AskRefusal::NotAudience { .. } | AskRefusal::NotServed)) => why.into(),
            Err(_) => fixed(),
        }
    }

    /// Read every read of `set`, within [`crate::Budget::time`] ([`Self::planned`]).
    async fn fetched(
        self: &Arc<Self>,
        qname: &Name,
        set: &ReadSet,
    ) -> Result<(), AnswerAskRefusal> {
        let budget = self.config.answers.budget;
        match rt::timeout(budget.time, self.read_all(set, budget)).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(f)) => {
                Err(self.ask_refusal(AnswerKind::Pure, &self.eval_error(qname, f, false)))
            }
            Err(_) => Err(AskRefusal::Pending {
                retry_after: RETRY_AFTER,
            }
            .into()),
        }
    }

    /// Step 6, pure: compute and sign the answer over exactly the reads `stated` — the ones
    /// judged ([`Self::publish_question`], idempotent) — in a task that holds the caps until it
    /// ends, answered or not, and for no longer than [`crate::Budget::time`]; `Pending` if it
    /// is not done within `wait`, and a later ask finds the stored answer. `planned`: the asker
    /// left the reads to the signer, so a refusal that the reads are not the evaluator's means
    /// the data moved since they were planned: `Pending`. The evaluator's own refusal of a
    /// definition or input is no such thing (the reads are exact versions, and an evaluation is
    /// a pure function of them): it is `EvaluatorRefused`.
    async fn compute_for_ask(
        self: &Arc<Self>,
        hold: AskHold,
        qname: Name,
        stated: AnswerAsk,
        planned: bool,
        wait: Duration,
    ) -> Result<Bytes, AnswerAskRefusal> {
        let (tx, rx) = oneshot::channel();
        let inner = Arc::clone(self);
        let time = self.config.answers.budget.time;
        rt::spawn(async move {
            let _hold = hold;
            let made = match rt::timeout(
                time,
                inner.publish_question(&qname, &stated, Signing::Asked),
            )
            .await
            {
                Ok(made) => made,
                Err(_) => Err(answer_error(
                    &qname,
                    AnswerRefusal::OverBudget {
                        what: "time to compute the answer".into(),
                    },
                )),
            };
            let _ = tx.send(made);
        });
        let pending = || {
            AnswerAskRefusal::new(AskRefusal::Pending {
                retry_after: RETRY_AFTER,
            })
        };
        match rt::timeout(wait, rx).await {
            Ok(Ok(Ok(name))) => self.answer_wire(&name).ok_or_else(pending),
            Ok(Ok(Err(DataError::BadRequest { why, .. })))
                if planned && !matches!(evaluator_reading(&why), Some(Reading::Refused(_))) =>
            {
                Err(pending())
            }
            Ok(Ok(Err(e))) => Err(self.ask_refusal(AnswerKind::Pure, &e)),
            Ok(Err(_)) | Err(_) => Err(pending()),
        }
    }

    /// Step 7, provider: hand the call to the host ([`Device::provider_asks`]), unless the same
    /// call is waiting for it already, and give the answer once it provides one within `wait`;
    /// `Pending` otherwise, and a later ask finds it. Not provided when no host takes the stream,
    /// or its queue is full.
    async fn provider_for_ask(
        self: &Arc<Self>,
        ask: &AnswerAsk,
        id: [u8; 32],
        asker: &Name,
        wait: Duration,
    ) -> Result<Bytes, AskRefusal> {
        let (Some(inputs), Some(tx)) = (ask.reads.clone(), self.provider_asks.lock().clone())
        else {
            return Err(AskRefusal::NotProvided);
        };
        let digest = inputs.digest().0;
        let handed = self.st.lock().answer_asks.begin_call(
            &ask.by,
            &digest,
            self.config.answers.budget.time,
        );
        if handed {
            let call = ProviderAsk {
                function: ask.by.clone(),
                inputs,
                asker: asker.clone(),
            };
            if tx.try_send(call).is_err() {
                self.st.lock().answer_asks.done(&ask.by, &digest);
                return Err(AskRefusal::NotProvided);
            }
        }
        self.wait_for_answer(&id, wait)
            .await
            .ok_or(AskRefusal::Pending {
                retry_after: RETRY_AFTER,
            })
    }

    /// The own answer at `id`, as served, once there is one, within `wait`.
    async fn wait_for_answer(&self, id: &[u8; 32], wait: Duration) -> Option<Bytes> {
        rt::timeout(wait, async {
            loop {
                // Armed before the look, so an answer served between the two is not missed.
                let mut served = pin!(self.progress.notified());
                served.as_mut().enable();
                if let Some(packet) = self.own_answer_wire(id) {
                    return packet;
                }
                served.await;
            }
        })
        .await
        .ok()
    }

    /// The packet of this device's own answer at `id`, if it signed one and serves it.
    fn own_answer_wire(&self, id: &[u8; 32]) -> Option<Bytes> {
        let name = self
            .st
            .lock()
            .answer_book
            .own_result(id)
            .map(|(name, _, _)| name.clone())?;
        self.answer_wire(&name)
    }

    /// The packet this device serves as the answer `name`.
    fn answer_wire(&self, name: &Name) -> Option<Bytes> {
        self.answer_packet(name).flatten()
    }

    /// What a failure of planning or computing is as a refusal of the ask. A known evaluator's
    /// refusal of the definition is `EvaluatorRefused`, with its words, which are shown to the
    /// asker for this reason only ([`AnswerAskRefusal::said`]).
    fn ask_refusal(&self, kind: AnswerKind, e: &DataError) -> AnswerAskRefusal {
        tracing::debug!(me = %self.device, "an ask for an answer failed here: {e}");
        let why = match e {
            DataError::CannotCheck { .. } => AskRefusal::CannotCheck,
            DataError::BadRequest { why, .. } if kind == AnswerKind::Pure => {
                match evaluator_reading(why) {
                    Some(Reading::Refused(words) | Reading::NotItsReads(words)) => {
                        return AnswerAskRefusal::evaluator_refused(words);
                    }
                    None => AskRefusal::CannotCheck,
                }
            }
            // A rate that passes with the second is no size to state smaller.
            DataError::Answer {
                why: AnswerRefusal::OverBudget { what },
                ..
            } if what == SIGNED_PER_SECOND => AskRefusal::Busy {
                retry_after: RETRY_AFTER,
            },
            DataError::Answer {
                why:
                    AnswerRefusal::OverBudget { .. }
                    | AnswerRefusal::TooLarge { .. }
                    | AnswerRefusal::TooManyStates { .. },
                ..
            } => AskRefusal::OverBudget,
            DataError::Unavailable { .. }
            | DataError::NotReady { .. }
            | DataError::Answer {
                why: AnswerRefusal::ReadsChanged(_),
                ..
            } => AskRefusal::Pending {
                retry_after: RETRY_AFTER,
            },
            _ => match kind {
                AnswerKind::Pure => AskRefusal::CannotCheck,
                AnswerKind::Provider => AskRefusal::NotProvided,
            },
        };
        why.into()
    }

    /// The checks of the reads of an ask, none of which reads or computes: an asker outside this
    /// device's namespace must be a listed writer or reader of every collection read when
    /// [`AskServing::OwnAndMembers`] serves it (`NotServed`); and the asker must be of the
    /// audience of every read (`NotAudience`, the index of the first it is not of).
    ///
    /// `held`: every read must be held here, as they are once they were read: one whose
    /// records are not is `Pending`, never admitted. Not `held`, a read not held yet is left
    /// to the check that follows its fetch.
    ///
    /// More reads of merge states than [`STATE_READS_CHECKED_MAX`] are refused
    /// (`OverBudget`: each is a replay of the collection's merge), and the rest runs off the
    /// executor within [`crate::Budget::time`], with the `St` lock held for one read at a time.
    pub(super) async fn gate_reads(
        self: &Arc<Self>,
        gate: &Gate,
        set: &ReadSet,
        held: bool,
    ) -> Result<(), AskRefusal> {
        let states = set
            .reads()
            .iter()
            .filter(|r| matches!(r, ReadRef::State { .. }))
            .count();
        if states > STATE_READS_CHECKED_MAX {
            tracing::debug!(me = %self.device, states, "an ask for an answer lists more reads of merge states than this device checks");
            return Err(AskRefusal::OverBudget);
        }
        let (inner, gate, set) = (Arc::clone(self), gate.clone(), set.clone());
        let ran = rt::blocking(
            self.config.answers.budget.time,
            self.config.answers.inline_work,
            move |cancel| inner.gate_reads_with(&gate, &set, held, cancel),
        )
        .await;
        match ran {
            Ok(Some(verdict)) => verdict,
            Ok(None) | Err(rt::Stopped::Deadline) => Err(AskRefusal::OverBudget),
            Err(rt::Stopped::NoThread) => Err(AskRefusal::Busy {
                retry_after: RETRY_AFTER,
            }),
        }
    }

    /// [`Self::gate_reads`] on the thread that runs it; `None` when `cancel` is raised first.
    fn gate_reads_with(
        &self,
        gate: &Gate,
        set: &ReadSet,
        held: bool,
        cancel: &rt::Cancel,
    ) -> Option<Result<(), AskRefusal>> {
        if gate.members {
            for r in set.reads() {
                if cancel.cancelled() {
                    return None;
                }
                let st = self.st.lock();
                let member = r.collection().ok().is_some_and(|c| {
                    st.record_in_force(&c).is_some_and(|m| {
                        m.lists_writer(&gate.asker)
                            || self.admits_record(&st, &m, &gate.asker, &gate.ns)
                    })
                });
                if !member {
                    return Some(Err(AskRefusal::NotServed));
                }
            }
        }
        let mut pending = false;
        for (index, r) in set.reads().iter().enumerate() {
            if cancel.cancelled() {
                return None;
            }
            let st = self.st.lock();
            match self.read_standing(&st, r, &gate.asker, &gate.ns) {
                Standing::In => {}
                Standing::Out => {
                    return Some(Err(AskRefusal::NotAudience {
                        index: index as u64,
                    }));
                }
                Standing::NotHeld => pending |= held,
            }
        }
        Some(match pending {
            true => Err(AskRefusal::Pending {
                retry_after: RETRY_AFTER,
            }),
            false => Ok(()),
        })
    }

    /// Whether `asker`, of namespace `ns`, is of the audience that read `r`: it may hold the key
    /// of every epoch the read is sealed in, by the members record that started that epoch and
    /// the one in force ([`Self::epoch_standing`]), never by the record in force alone, which
    /// could admit a reader later than the read. A read or a record not held here is
    /// [`Standing::NotHeld`], never admitted: the answer made of it is sealed under the keys of
    /// its epochs, which says who may open it, but not who may be told what it read.
    fn read_standing(&self, st: &St, r: &ReadRef, asker: &Name, ns: &Name) -> Standing {
        let Ok(c) = r.collection() else {
            return Standing::Out;
        };
        let epochs = match r {
            ReadRef::Version { name, .. } => match st.version_fact(name) {
                VersionFact::Held { epoch, .. } => epoch.into_iter().collect::<Vec<Epoch>>(),
                VersionFact::Refused | VersionFact::Unknown => return Standing::NotHeld,
            },
            ReadRef::State { collection, at, .. } => {
                match st.state_facts(collection, at.frontier(), &self.config.rules, &self.writer) {
                    Some(facts) => facts.epochs,
                    None => return Standing::NotHeld,
                }
            }
        };
        let mut standing = Standing::In;
        for e in &epochs {
            match self.epoch_standing(st, &c, e, asker, ns) {
                Standing::In => {}
                Standing::Out => return Standing::Out,
                Standing::NotHeld => standing = Standing::NotHeld,
            }
        }
        standing
    }

    /// Whether `device`, of namespace `dns`, may hold the key of epoch `e` of `c` (spec §9): a
    /// held owner-signed record of `c` — or of the folder whose epoch it is
    /// ([`St::seal_subject`]) — names `e`, the readers those records list (or `e`'s creator)
    /// admit it, and so does that subject's record in force when it seals. A record that
    /// is not held says nothing: [`Standing::NotHeld`].
    pub(super) fn epoch_standing(
        &self,
        st: &St,
        c: &Name,
        e: &Epoch,
        device: &Name,
        dns: &Name,
    ) -> Standing {
        let Some((epochs, Some(record))) = st.line_of(&st.seal_subject(c, e)) else {
            return Standing::NotHeld;
        };
        let Some(named) = epochs.get(e) else {
            return Standing::NotHeld;
        };
        let admitted = self.admits(st, &named.readers, Some(&e.creator), device, dns)
            && (record.epoch.is_none() || self.admits_record(st, record, device, dns));
        match admitted {
            true => Standing::In,
            false => Standing::Out,
        }
    }
}

// ---- the asker ------------------------------------------------------------------------------

impl Inner {
    /// The seal key of `signer` learned and verified already.
    fn held_seal_key(&self, signer: &Name) -> Option<[u8; 32]> {
        self.st
            .lock()
            .seal_keys
            .map
            .iter()
            .find_map(|(name, public)| {
                parse_seal_key_name(name)
                    .filter(|(device, _)| device == signer)
                    .map(|_| *public)
            })
    }

    /// Fetch the seal key packet of `signer` by its name, verify it is the signer's, and keep
    /// it in place of any held for the signer. Asked as every small signed packet the layer
    /// needs is ([`Inner::fetch_owed`]: up to `FETCH_TRIES` rounds, a pause between them), not
    /// once: a packet lost on a faulty link then costs a pause, not the whole of an
    /// [`Device::ask_answer`], which has no other way to go on without the key.
    async fn fetch_seal_key(self: &Arc<Self>, signer: &Name) -> Option<[u8; 32]> {
        let data = self.fetch_owed(wire::seal_key_prefix(signer), true).await?;
        let (device, public) = parse_seal_key_name(&data.name)?;
        if device != *signer || !self.seal_key_of(&data, &data.name, signer, &public).await {
            return None;
        }
        let mut st = self.st.lock();
        st.seal_keys
            .retain(|name| parse_seal_key_name(name).is_none_or(|(device, _)| device != *signer));
        // Not kept, and not used, when the listing of a writer's namespace that it
        // verified by went while it was fetched.
        let unheld = self.namespace_unheld(&data.name);
        st.keep_seal_key(&data.name, public, unheld)
            .then_some(public)
    }

    /// Send `params` to `prefix` and wait for the reply: one lifetime.
    async fn send_ask(&self, prefix: Name, params: &Bytes) -> Option<Data> {
        let _slot = self.slot(self.config.lifetime).await.ok()?;
        let b = InterestBuilder::new(prefix)
            .lifetime(self.config.lifetime)
            .app_parameters(params.to_vec());
        match Consumer::new(self.node.connection()).fetch_with(b).await {
            Ok(d) => Some(d),
            Err(e) => {
                tracing::trace!(me = %self.device, "an ask for an answer got no reply: {e}");
                None
            }
        }
    }

    /// The ask for `ask` sealed to the seal key `public` of `signer`, as it is sent: the name of
    /// its Interest, digest included, and the Interest's ApplicationParameters. Its proof is this
    /// device's, bound to the ask and to the ephemeral key it is sealed with; and the ask's own
    /// content key, which the signer seals the words of its refusal under.
    pub(super) fn build_ask(
        &self,
        signer: &Name,
        public: &[u8; 32],
        ask: &AnswerAsk,
    ) -> Result<(Name, Bytes, ContentKey), DataError> {
        let aad = answer_ask_prefix(signer).encode_to_tlv();
        let key = AskKey::to(public, &aad)
            .map_err(|e| local(format!("the ask could not be sealed to {signer}: {e}")))?;
        let binding = AnswerAskBody::binding(signer, ask, &key.ephemeral);
        let proof = self.ask_proof(&binding).ok_or_else(|| {
            local(format!(
                "the device key {} did not sign the ask",
                self.device
            ))
        })?;
        let body = AnswerAskBody {
            ask: ask.clone(),
            asker: self.device.clone(),
            proof,
        };
        let reply_key = key.reply_key();
        let sealed = key.seal(&body.encode(), &aad);
        let params = AnswerAskEnvelope {
            ephemeral: sealed.ephemeral,
            key: sealed.key,
            sealed: sealed.sealed,
        }
        .encode();
        Ok((answer_ask_name(signer, &params), params, reply_key))
    }

    /// One ask of `signer` for the answer to `ask`, sent until a reply comes (the same
    /// parameters each time): the signer's reply, verified as signed by it, or `None` if nothing
    /// came. A signer that regenerated its recipient key opens none of the sends, so once
    /// they all went unanswered the key is fetched again, and the ask sent again if it is
    /// another. The signer's seal key not held is [`DataError::NotReady`].
    async fn ask_once(
        self: &Arc<Self>,
        signer: &Name,
        question: &Name,
        ask: &AnswerAsk,
    ) -> Result<Option<Reply>, DataError> {
        let (mut public, mut cached) = match self.held_seal_key(signer) {
            Some(public) => (public, true),
            None => match self.fetch_seal_key(signer).await {
                Some(public) => (public, false),
                None => {
                    return Err(DataError::NotReady {
                        name: question.clone(),
                        why: format!(
                            "the signer's seal key is not held yet: {signer} did not give its \
                             seal key packet <{signer}/32=seal/...>; ask again once it is \
                             reachable"
                        ),
                    });
                }
            },
        };
        loop {
            let (name, params, reply_key) = self.build_ask(signer, &public, ask)?;
            for _ in 0..ASK_SENDS {
                let Some(data) = self.send_ask(answer_ask_prefix(signer), &params).await else {
                    continue;
                };
                // The reply is the signer's, or it is not taken: a refusal is as much its word
                // as an answer is.
                let signed = *data.name == name
                    && self
                        .verify(&data)
                        .await
                        .is_ok_and(|w| device_of(w.key()).as_ref() == Some(signer));
                if !signed {
                    tracing::debug!(me = %self.device, %signer, "a reply to an ask for an answer is not the signer's: dropped");
                    continue;
                }
                return Ok(Some(read_reply(&data, &reply_key).map_err(|why| {
                    answer_error(question, AnswerRefusal::Malformed(why))
                })?));
            }
            if !std::mem::take(&mut cached) {
                return Ok(None);
            }
            match self.fetch_seal_key(signer).await {
                Some(fresh) if fresh != public => public = fresh,
                _ => return Ok(None),
            }
        }
    }

    /// Ask `signer` for the answer to `ask`, again after the `retry_after` it names when it is
    /// busy or the answer is pending (at most [`ASK_ATTEMPTS`] asks): the answer packet it
    /// gave, `None` if it did not reply, or its refusal as an error.
    pub(super) async fn ask_signer(
        self: &Arc<Self>,
        signer: &Name,
        question: &Name,
        ask: &AnswerAsk,
    ) -> Result<Option<Data>, DataError> {
        let mut attempt = 1;
        loop {
            match self.ask_once(signer, question, ask).await? {
                None => return Ok(None),
                Some(Reply::Packet(data)) => return Ok(Some(*data)),
                Some(Reply::Refused(refusal)) => {
                    if let Some(wait) = refusal.why.retry_after()
                        && attempt < ASK_ATTEMPTS
                    {
                        attempt += 1;
                        rt::sleep(wait.min(RETRY_AFTER_MAX)).await;
                        continue;
                    }
                    // What the signer says is its word, and a hostile signer's words reach the
                    // user's terminal: this device says the reason's own, whatever came, except
                    // that an evaluator's refusal is shown as the evaluator's quoted words,
                    // cleaned here ([`AnswerAskRefusal::said`]).
                    let said = refusal.said();
                    return Err(answer_error(
                        question,
                        AnswerRefusal::AskRefused {
                            signer: signer.clone(),
                            why: refusal.why,
                            said,
                        },
                    ));
                }
            }
        }
    }

    /// An answer packet a signer gave for an ask: checked as every answer is, that it answers
    /// the question asked, and judged as a fetched one is (recompute, or trust by the policy).
    async fn take_asked(
        self: &Arc<Self>,
        question: &Name,
        ask: &AnswerAsk,
        data: Data,
        relays: &[Name],
    ) -> Result<Answered, DataError> {
        let opened: Opened = self.open_packet(data, Some(ask.kind), relays).await?;
        self.check_equivocation(&opened)?;
        let b = &opened.body.binding;
        let answers = b.by == ask.by
            && b.definition == ask.definition
            && ask.reads.as_ref().is_none_or(|s| *s == opened.body.reads);
        if !answers {
            return Err(answer_error(
                question,
                AnswerRefusal::Malformed(
                    "the packet the signer gave answers another question than the one asked (its \
                     evaluator or function, definition or reads differ); it is dropped"
                        .into(),
                ),
            ));
        }
        self.finish_opened(question, ask, opened, None).await
    }

    /// The answer to a question nothing published, from the signers the policy names that its
    /// policy could take an answer from ([`Inner::askable`]: the read set goes to no other),
    /// asked in its order until one gives it (answers.md §15); `fallback` — why nothing was
    /// found — if none answers at all (say so when some were asked and were silent), and the
    /// first refusal if one refuses. An answer over reads the asker left to the signer is
    /// [`Age::Newest`], unconfirmed: the signer chose its reads, and nothing here says how
    /// old they are.
    pub(super) async fn asked_answer(
        self: &Arc<Self>,
        question: &Name,
        ask: &AnswerAsk,
        fallback: DataError,
    ) -> Result<Answer, DataError> {
        let none = ReadSet::new([]).expect("an empty read set");
        let (signers, relays) =
            self.candidates(ask.kind, &ask.by, ask.reads.as_ref().unwrap_or(&none));
        let signers = self.askable(
            ask.kind,
            &ask.by,
            ask.reads.as_ref().unwrap_or(&none),
            signers,
        );
        let age = match ask.reads {
            Some(_) => Age::Exact,
            None => Age::Newest {
                unconfirmed_for: UNCONFIRMED,
            },
        };
        let mut refused: Option<DataError> = None;
        let mut silent = false;
        for signer in signers {
            let got = match self.ask_signer(&signer, question, ask).await {
                Ok(Some(data)) => self.take_asked(question, ask, data, &relays).await,
                Ok(None) => {
                    silent = true;
                    continue;
                }
                Err(e) => Err(e),
            };
            match got {
                Ok(answered) => {
                    return Ok(Answer {
                        got: Got::Answer(answered),
                        age,
                    });
                }
                Err(e) => {
                    refused.get_or_insert(e);
                }
            }
        }
        Err(match refused {
            Some(e) => e,
            None if silent && matches!(fallback, DataError::Unavailable { .. }) => {
                no_reply(question)
            }
            None => fallback,
        })
    }
}

/// Read a reply's Content: the answer packet, or a refusal, whose words (code 8) open under
/// `key`, the content key of the ask this reply answers, for the reply's name.
pub(super) fn read_reply(data: &Data, key: &ContentKey) -> Result<Reply, String> {
    let content = data
        .content()
        .cloned()
        .ok_or("the reply to an ask has no content")?;
    let (typ, _) = TlvReader::new(content.clone())
        .read_tlv()
        .map_err(|e| format!("the reply to an ask is not a TLV: {e:?}"))?;
    match typ {
        tlv::ANSWER_ASK_REFUSAL => AnswerAskRefusal::decode(content, key, &data.name)
            .map(Reply::Refused)
            .map_err(|e| e.to_string()),
        // The content of a packet is a Data TLV.
        0x06 => Data::decode(content)
            .map(|d| Reply::Packet(Box::new(d)))
            .map_err(|e| format!("the reply to an ask holds no packet: {e:?}")),
        _ => Err(format!(
            "the reply to an ask is neither an answer packet nor a refusal (TLV-TYPE {typ:#x})"
        )),
    }
}

// ---- the host -------------------------------------------------------------------------------

impl Device {
    /// Ask `signer`, a device, for the answer to `question` (answers.md §15): a pure question
    /// (`AnswerAsk::name(None)`) or a provider question (`AnswerAsk::name(Some(signer))`). The
    /// ask is sealed to the signer's seal key and proves this device's key. A packet the signer
    /// gives is checked as a fetched one is: signature, binding, reads, and the policy or a
    /// recomputation. The same path as `get` follows when it asks, without the policy's loop.
    ///
    /// A signer that refuses answers [`DataError::Answer`] with
    /// [`AnswerRefusal::AskRefused`](crate::AnswerRefusal): its reason and what to do
    /// ([`DataError::next`]). One that is not reached, does not authenticate this device, or
    /// does not serve it does not reply: [`DataError::NotReady`], which says so and that a
    /// certificate that lapsed, this device's or the signer's, makes either silent to the other.
    pub async fn ask_answer(&self, signer: &Name, question: &Name) -> Result<Got, DataError> {
        let inner = &self.inner;
        let (_, ask) = AnswerAsk::parse_with_x(question)?;
        if !wire::is_device_name(signer) || *signer == inner.device {
            return Err(DataError::BadRequest {
                name: question.clone(),
                why: format!(
                    "{signer} is not another device to ask: give a device name \
                     <namespace>/<device> of the signer, not this device's own"
                ),
            });
        }
        let none = ReadSet::new([]).expect("an empty read set");
        let (_, relays) = inner.candidates(ask.kind, &ask.by, ask.reads.as_ref().unwrap_or(&none));
        match inner.ask_signer(signer, question, &ask).await? {
            Some(data) => Ok(Got::Answer(
                inner.take_asked(question, &ask, data, &relays).await?,
            )),
            None => Err(no_reply(question)),
        }
    }

    /// The calls of functions that authenticated devices ask this device for, which the host
    /// computes (answers.md §15): a [`ProviderAsk`] for each provider ask whose asker is of the
    /// audience of every input and whose answer this device does not hold. The host computes the
    /// result and calls [`Device::provide`] with the function, the inputs and the result; the
    /// asker's next ask finds the answer. A call is delivered once while it waits: the same
    /// function over the same inputs, asked again by anyone before the host provides the
    /// answer, waits for that answer and is delivered again only after
    /// [`Budget::time`](crate::Budget) with none. A device whose host never takes this stream
    /// answers such asks `NotProvided`, as one whose queue (64 distinct calls) is full does.
    /// Taking it again replaces the stream: the earlier receiver ends, and the calls it was
    /// owed are delivered again.
    pub fn provider_asks(&self) -> mpsc::Receiver<ProviderAsk> {
        let (tx, rx) = mpsc::channel(PROVIDER_ASKS_QUEUED);
        let mut st = self.inner.st.lock();
        st.answer_asks.calls.clear();
        *self.inner.provider_asks.lock() = Some(tx);
        rx
    }
}
