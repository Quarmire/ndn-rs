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
//! envelope opens and its digest matches; the proof verifies (else no reply at all, not even a
//! Nack); the serving policy ([`AskServing`]) admits the asker; the asker has no ask in
//! progress and the signer is under its total cap; the asker is of the audience of every read,
//! checked before anything is computed; the answer is read from the store, or computed
//! ([`Device::publish_answer`]) or asked of the host ([`Device::provider_asks`]).

use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_app::Consumer;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Data, Name};
use ndn_tlv::TlvReader;
use tokio::sync::{OwnedSemaphorePermit, mpsc, oneshot};

use super::answer_get::Opened;
use super::answer_reads::VersionFact;
use super::{Device, Inner, St, local, rt};
use crate::answer::{
    AnswerAsk, AnswerAskBody, AnswerAskEnvelope, AnswerAskRefusal, AnswerKind, Answered,
    AskRefusal, AskServing, ProviderAsk, ReadRef, ReadSet, answer_ask_name, answer_ask_prefix, tlv,
};
use crate::error::{AnswerRefusal, DataError};
use crate::layer::{Age, Answer, Got};
use crate::seal::{AskKey, open_ask};
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

fn answer_error(name: &Name, why: AnswerRefusal) -> DataError {
    DataError::Answer {
        name: name.clone(),
        why,
    }
}

/// The caps one ask holds while it is worked on: the asker's one in progress
/// ([`Inner::take_ask`]) and one of the signer's [`AnswerConfig::asks_at_once`]
/// ([`crate::AnswerConfig`]). Given back when dropped, wherever the work ends.
struct AskHold {
    inner: Arc<Inner>,
    asker: Name,
    _permit: OwnedSemaphorePermit,
}

impl AskHold {
    fn take(inner: &Arc<Inner>, asker: &Name) -> Option<Self> {
        if !inner.take_ask(asker, 1) {
            return None;
        }
        match Arc::clone(&inner.asks_at_once).try_acquire_owned() {
            Ok(permit) => Some(AskHold {
                inner: Arc::clone(inner),
                asker: asker.clone(),
                _permit: permit,
            }),
            Err(_) => {
                inner.release_ask(asker);
                None
            }
        }
    }
}

impl Drop for AskHold {
    fn drop(&mut self) {
        self.inner.release_ask(&self.asker);
    }
}

/// Who asks, for the checks of a read set.
struct Gate<'a> {
    asker: &'a Name,
    /// The asker's namespace.
    ns: &'a Name,
    /// Whether the asker must be a listed writer or reader of every collection read: it is of
    /// another namespace than this device's, and [`AskServing::OwnAndMembers`] serves it.
    members: bool,
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
    /// named as the Interest; `None` for an ask that does not authenticate, which gets no reply
    /// at all. `lifetime`: the Interest's.
    pub(super) async fn answer_ask(
        self: &Arc<Self>,
        name: &Name,
        params: Option<Bytes>,
        lifetime: Option<Duration>,
    ) -> Option<Bytes> {
        let (asker, ask) = match self.open_answer_ask(name, params).await {
            Ok(opened) => opened,
            Err(why) => {
                tracing::debug!(me = %self.device, %name, "an ask for an answer is not answered: {why}");
                return None;
            }
        };
        let lifetime = lifetime.unwrap_or(LIFETIME_DEFAULT);
        let content = match self.judge_answer_ask(&asker, ask, lifetime).await {
            Ok(packet) => packet,
            Err(why) => {
                tracing::debug!(me = %self.device, %asker, ?why, "an ask for an answer is refused");
                AnswerAskRefusal::new(why).encode()
            }
        };
        self.sign(DataBuilder::new(name.clone(), &content).freshness(Duration::ZERO))
            .ok()
    }

    /// Steps 1 and 2: the parameters match the name's digest, the envelope opens with this
    /// device's seal key, and the asker's proof verifies as the proof of this very ask. Why not,
    /// if not.
    async fn open_answer_ask(
        self: &Arc<Self>,
        name: &Name,
        params: Option<Bytes>,
    ) -> Result<(Name, AnswerAsk), &'static str> {
        let params = params
            .filter(|p| answer_ask_name(&self.device, p) == *name)
            .ok_or("the name's digest is not the parameters'")?;
        let (envelope, body) = {
            let _verifying = self
                .verifying
                .acquire()
                .await
                .map_err(|_| "this device stopped")?;
            let envelope = AnswerAskEnvelope::decode(params).map_err(|_| "no envelope")?;
            let aad = answer_ask_prefix(&self.device).encode_to_tlv();
            let plain = open_ask(
                &self.st.lock().keys.recipient,
                &aad,
                &envelope.ephemeral,
                &envelope.key,
                &envelope.sealed,
            )
            .ok_or("the envelope does not open")?;
            let body =
                AnswerAskBody::decode(Bytes::from(plain)).map_err(|_| "the body is malformed")?;
            (envelope, body)
        };
        let proof = Data::decode(body.proof.clone()).map_err(|_| "its proof is not a packet")?;
        let binding = AnswerAskBody::binding(&self.device, &body.ask, &envelope.ephemeral);
        if !self.proves(&proof, &body.asker, &binding).await {
            return Err("its proof does not verify as the asker's, for this ask");
        }
        Ok((body.asker, body.ask))
    }

    /// Steps 3 to 7: what the signer answers an authenticated asker: the answer packet, or why
    /// not.
    async fn judge_answer_ask(
        self: &Arc<Self>,
        asker: &Name,
        ask: AnswerAsk,
        lifetime: Duration,
    ) -> Result<Bytes, AskRefusal> {
        let serving = self.config.answers.serve_asks;
        let ns = self.namespace_of_name(asker);
        let own = ns == self.ns;
        if serving == AskServing::Off || (serving == AskServing::Own && !own) {
            return Err(AskRefusal::NotServed);
        }
        let hold = AskHold::take(self, asker).ok_or(AskRefusal::Busy {
            retry_after: RETRY_AFTER,
        })?;
        let qname = self.ask_question_name(&ask)?;
        let gate = Gate {
            asker,
            ns: &ns,
            members: serving == AskServing::OwnAndMembers && !own,
        };
        // The audience, before anything is read or computed: of the reads the asker states.
        if let Some(set) = &ask.reads {
            self.gate_reads(&gate, set)?;
        }
        if ask.kind == AnswerKind::Pure
            && ask.reads.is_none()
            && self.config.evaluators.get(&ask.by).is_none()
        {
            return Err(AskRefusal::CannotCheck);
        }
        // The id: planning reads, never evaluating.
        let resolved = self
            .resolve_question(&qname, &ask, false)
            .await
            .map_err(|e| self.ask_refusal(ask.kind, &e))?;
        // Reads the asker leaves to be planned are known now: checked before the evaluator runs.
        if ask.reads.is_none() {
            self.gate_reads(&gate, &resolved.reads)?;
        }
        if let Some(packet) = self.own_answer_wire(&resolved.id) {
            return Ok(packet);
        }
        let wait = lifetime
            .saturating_sub(REPLY_MARGIN)
            .min(self.config.answers.budget.time);
        match ask.kind {
            AnswerKind::Pure => self.compute_for_ask(hold, qname, wait).await,
            AnswerKind::Provider => self.provider_for_ask(&ask, resolved.id, asker, wait).await,
        }
    }

    /// The question's name, as `publish_answer` takes it.
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

    /// Step 6, pure: compute and sign the answer ([`Device::publish_answer`], idempotent) in a
    /// task that holds the caps until it ends, answered or not; `Pending` if it is not done
    /// within `wait`, and a later ask finds the stored answer.
    async fn compute_for_ask(
        self: &Arc<Self>,
        hold: AskHold,
        qname: Name,
        wait: Duration,
    ) -> Result<Bytes, AskRefusal> {
        let (tx, rx) = oneshot::channel();
        let device = Device {
            inner: Arc::clone(self),
        };
        rt::spawn(async move {
            let _hold = hold;
            let _ = tx.send(device.publish_answer(&qname).await);
        });
        let pending = AskRefusal::Pending {
            retry_after: RETRY_AFTER,
        };
        match rt::timeout(wait, rx).await {
            Ok(Ok(Ok(name))) => self.answer_wire(&name).ok_or(pending),
            Ok(Ok(Err(e))) => Err(self.ask_refusal(AnswerKind::Pure, &e)),
            Ok(Err(_)) | Err(_) => Err(pending),
        }
    }

    /// Step 7, provider: hand the call to the host ([`Device::provider_asks`]) and give the answer
    /// once it provides one within `wait`; `Pending` otherwise, and a later ask finds it. Not
    /// provided when no host takes the stream, or its queue is full.
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
        let call = ProviderAsk {
            function: ask.by.clone(),
            inputs,
            asker: asker.clone(),
        };
        if tx.try_send(call).is_err() {
            return Err(AskRefusal::NotProvided);
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

    /// What a failure of planning or computing is as a refusal of the ask.
    fn ask_refusal(&self, kind: AnswerKind, e: &DataError) -> AskRefusal {
        tracing::debug!(me = %self.device, "an ask for an answer failed here: {e}");
        match e {
            DataError::CannotCheck { .. } => AskRefusal::CannotCheck,
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
        }
    }

    /// The checks of the reads of an ask, none of which reads or computes: an asker outside this
    /// device's namespace must be a listed writer or reader of every collection read when
    /// [`AskServing::OwnAndMembers`] serves it (`NotServed`); and the asker must be of the
    /// audience of every read (`NotAudience`, the index of the first it is not of).
    fn gate_reads(&self, gate: &Gate<'_>, set: &ReadSet) -> Result<(), AskRefusal> {
        let st = self.st.lock();
        if gate.members {
            let member = |r: &ReadRef| {
                r.collection()
                    .ok()
                    .and_then(|c| st.record_in_force(&c).map(|m| m.into_owned()))
                    .is_some_and(|m| {
                        m.lists_writer(gate.asker)
                            || self.admits_record(&st, &m, gate.asker, gate.ns)
                    })
            };
            if !set.reads().iter().all(member) {
                return Err(AskRefusal::NotServed);
            }
        }
        match set
            .reads()
            .iter()
            .position(|r| !self.read_admits(&st, r, gate.asker, gate.ns))
        {
            Some(index) => Err(AskRefusal::NotAudience {
                index: index as u64,
            }),
            None => Ok(()),
        }
    }

    /// Whether `asker`, of namespace `ns`, is of the audience that read `r`: it may hold the key
    /// of every epoch the read is sealed in, by the members record that started that epoch and
    /// the one in force ([`Self::may_hold`]), never by the record in force alone, which could
    /// admit a reader later than the read. A read whose epochs are not held here is judged by
    /// the record in force of its collection; the answer made of it is sealed under the keys of
    /// its epochs either way.
    fn read_admits(&self, st: &St, r: &ReadRef, asker: &Name, ns: &Name) -> bool {
        let Ok(c) = r.collection() else {
            return false;
        };
        let epochs = match r {
            ReadRef::Version { name, .. } => match st.version_fact(name) {
                VersionFact::Held { epoch, .. } => Some(epoch.into_iter().collect::<Vec<_>>()),
                _ => None,
            },
            ReadRef::State { collection, at, .. } => st
                .state_facts(collection, at.frontier(), &self.config.rules, &self.writer)
                .map(|f| f.epochs),
        };
        match epochs {
            Some(epochs) => epochs.iter().all(|e| self.may_hold(st, &c, e, asker, ns)),
            None => st
                .record_in_force(&c)
                .is_none_or(|m| m.epoch.is_none() || self.admits_record(st, &m, asker, ns)),
        }
    }
}

// ---- the asker ------------------------------------------------------------------------------

impl Inner {
    /// The recipient key of `signer`, as its seal key packet `<signer>/32=seal/<key>` names it:
    /// one learned and verified already, else fetched by the signer's name and verified as
    /// signed by the signer's device.
    async fn signer_seal_key(self: &Arc<Self>, signer: &Name) -> Option<[u8; 32]> {
        let held = self
            .st
            .lock()
            .seal_keys
            .map
            .iter()
            .find_map(|(name, public)| {
                parse_seal_key_name(name)
                    .filter(|(device, _)| device == signer)
                    .map(|_| *public)
            });
        if held.is_some() {
            return held;
        }
        let data = self.fetch(wire::seal_key_prefix(signer), true).await?;
        let (device, public) = parse_seal_key_name(&data.name)?;
        if device != *signer || !self.seal_key_of(&data, &data.name, signer, &public).await {
            return None;
        }
        self.st
            .lock()
            .seal_keys
            .insert((*data.name).clone(), public);
        Some(public)
    }

    /// Send `params` to `prefix` and wait for the reply: one lifetime.
    async fn send_ask(&self, prefix: Name, params: &Bytes) -> Option<Data> {
        let _slot = self.slots.acquire().await.ok()?;
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
    /// device's, bound to the ask and to the ephemeral key it is sealed with.
    pub(super) fn build_ask(
        &self,
        signer: &Name,
        public: &[u8; 32],
        ask: &AnswerAsk,
    ) -> Result<(Name, Bytes), DataError> {
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
        let sealed = key.seal(&body.encode(), &aad);
        let params = AnswerAskEnvelope {
            ephemeral: sealed.ephemeral,
            key: sealed.key,
            sealed: sealed.sealed,
        }
        .encode();
        Ok((answer_ask_name(signer, &params), params))
    }

    /// One ask of `signer` for the answer to `ask`, sent until a reply comes (the same
    /// parameters each time): the signer's reply, verified as signed by it, or `None` if nothing
    /// came. The signer's seal key not held is [`DataError::NotReady`].
    async fn ask_once(
        self: &Arc<Self>,
        signer: &Name,
        question: &Name,
        ask: &AnswerAsk,
    ) -> Result<Option<Reply>, DataError> {
        let Some(public) = self.signer_seal_key(signer).await else {
            return Err(DataError::NotReady {
                name: question.clone(),
                why: format!(
                    "the signer's seal key is not held yet: {signer} did not give its seal key \
                     packet <{signer}/32=seal/...>; ask again once it is reachable"
                ),
            });
        };
        let (name, params) = self.build_ask(signer, &public, ask)?;
        for _ in 0..ASK_SENDS {
            let Some(data) = self.send_ask(answer_ask_prefix(signer), &params).await else {
                continue;
            };
            // The reply is the signer's, or it is not taken: a refusal is as much its word as an
            // answer is.
            let signed = *data.name == name
                && self
                    .verify(&data)
                    .await
                    .is_ok_and(|w| device_of(w.key()).as_ref() == Some(signer));
            if !signed {
                tracing::debug!(me = %self.device, %signer, "a reply to an ask for an answer is not the signer's: dropped");
                continue;
            }
            return Ok(Some(read_reply(&data).map_err(|why| {
                answer_error(question, AnswerRefusal::Malformed(why))
            })?));
        }
        Ok(None)
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
                    let said = match refusal.explanation.is_empty() {
                        true => refusal.why.explain(),
                        false => refusal.explanation,
                    };
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

    /// The answer to a question nothing published, from the signers the policy names, asked in its
    /// order until one gives it (answers.md §15); `fallback` — why nothing was found — if none
    /// answers at all, and the first refusal if one refuses.
    pub(super) async fn asked_answer(
        self: &Arc<Self>,
        question: &Name,
        ask: &AnswerAsk,
        fallback: DataError,
    ) -> Result<Answer, DataError> {
        let none = ReadSet::new([]).expect("an empty read set");
        let (signers, relays) =
            self.candidates(ask.kind, &ask.by, ask.reads.as_ref().unwrap_or(&none));
        let mut refused: Option<DataError> = None;
        for signer in signers {
            let got = match self.ask_signer(&signer, question, ask).await {
                Ok(Some(data)) => self.take_asked(question, ask, data, &relays).await,
                Ok(None) => continue,
                Err(e) => Err(e),
            };
            match got {
                Ok(answered) => {
                    return Ok(Answer {
                        got: Got::Answer(answered),
                        age: Age::Exact,
                    });
                }
                Err(e) => {
                    refused.get_or_insert(e);
                }
            }
        }
        Err(refused.unwrap_or(fallback))
    }
}

/// Read a reply's Content: the answer packet, or a refusal.
pub(super) fn read_reply(data: &Data) -> Result<Reply, String> {
    let content = data
        .content()
        .cloned()
        .ok_or("the reply to an ask has no content")?;
    let (typ, _) = TlvReader::new(content.clone())
        .read_tlv()
        .map_err(|e| format!("the reply to an ask is not a TLV: {e:?}"))?;
    match typ {
        tlv::ANSWER_ASK_REFUSAL => AnswerAskRefusal::decode(content)
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
    /// ([`DataError::next`]). One that does not authenticate this device, or is not reached,
    /// does not reply: [`DataError::Unavailable`].
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
            None => Err(DataError::Unavailable {
                name: question.clone(),
            }),
        }
    }

    /// The calls of functions that authenticated devices ask this device for, which the host
    /// computes (answers.md §15): a [`ProviderAsk`] for each provider ask whose asker is of the
    /// audience of every input and whose answer this device does not hold. The host computes the
    /// result and calls [`Device::provide`] with the function, the inputs and the result; the
    /// asker's next ask finds the answer. A device whose host never takes this stream answers
    /// such asks `NotProvided`, as one whose queue (64 asks) is full does. Taking it again
    /// replaces the stream: the earlier receiver ends. The same call may be delivered again when
    /// the asker asks again before the host provides the answer.
    pub fn provider_asks(&self) -> mpsc::Receiver<ProviderAsk> {
        let (tx, rx) = mpsc::channel(PROVIDER_ASKS_QUEUED);
        *self.inner.provider_asks.lock() = Some(tx);
        rx
    }
}
