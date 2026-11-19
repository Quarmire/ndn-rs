//! The sealed ask exchange for answers (`docs/specs/answers.md` §15), at the level of one process:
//! the signer's checks and replies judged by handing it asks built as an asker builds them, and
//! the asker's loop over a connection that hands its Interests to the signer. The cases over a
//! real network are the conformance runner's `a19`…`a22`.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use futures::StreamExt;
use ndn_app::AppError;

use super::super::answer_ask::{Reply, read_reply};
use super::*;
use crate::NextStep;
use crate::answer::{
    AnswerAskBody, AnswerAskEnvelope, AnswerAskRefusal, AskRefusal, AskServing, answer_ask_name,
    answer_ask_prefix, parse_answer_ask_name,
};
use crate::seal::AskKey;

// ---- a connection to the signer -------------------------------------------------------------

/// What an asker's device fetches over: its Interests are handed to `signer` as a forwarder
/// would hand them, and what the signer answers comes back. Every Interest name is noted.
pub(super) struct Wire {
    signer: std::sync::OnceLock<Device>,
    tx: futures::channel::mpsc::UnboundedSender<Bytes>,
    rx: futures::lock::Mutex<futures::channel::mpsc::UnboundedReceiver<Bytes>>,
    asked: std::sync::Mutex<Vec<Name>>,
    /// While set, no ask for an answer is answered: the signer is silent.
    pub(super) muted: AtomicBool,
    /// The Content the signer replies to every ask for an answer with, instead of its own
    /// reply.
    pub(super) forced: std::sync::Mutex<Option<Bytes>>,
}

impl Wire {
    fn new() -> Arc<Wire> {
        let (tx, rx) = futures::channel::mpsc::unbounded();
        Arc::new(Wire {
            signer: std::sync::OnceLock::new(),
            tx,
            rx: futures::lock::Mutex::new(rx),
            asked: std::sync::Mutex::new(Vec::new()),
            muted: AtomicBool::new(false),
            forced: std::sync::Mutex::new(None),
        })
    }

    /// How many distinct asks for an answer were sent.
    fn asks(&self) -> usize {
        let mut names: Vec<Name> = self
            .asked
            .lock()
            .unwrap()
            .iter()
            .filter(|n| parse_answer_ask_name(n).is_some())
            .cloned()
            .collect();
        names.sort();
        names.dedup();
        names.len()
    }
}

#[async_trait::async_trait]
impl Connection for Wire {
    async fn send(&self, wire: Bytes) -> Result<(), AppError> {
        let Ok(interest) = Interest::decode(wire) else {
            return Ok(());
        };
        let Some(signer) = self.signer.get().cloned() else {
            return Ok(());
        };
        let name = (*interest.name).clone();
        let (params, lifetime) = (interest.app_parameters().cloned(), interest.lifetime());
        let by_prefix = interest.selectors().can_be_prefix;
        self.asked.lock().unwrap().push(name.clone());
        let (muted, forced) = (
            self.muted.load(Ordering::SeqCst),
            self.forced.lock().unwrap().clone(),
        );
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let reply = if parse_answer_ask_name(&name).is_some() {
                match (muted, forced) {
                    (true, _) => None,
                    // A signer that says what the test wants it to say, signed as it signs.
                    (false, Some(content)) => signer
                        .inner
                        .sign(DataBuilder::new(name.clone(), &content).freshness(Duration::ZERO))
                        .ok(),
                    (false, None) => signer.inner.answer_ask(&name, params, lifetime).await,
                }
            } else {
                signer.inner.packet_for(&name, by_prefix)
            };
            if let Some(wire) = reply {
                let _ = tx.unbounded_send(wire);
            }
        });
        Ok(())
    }
    async fn recv(&self) -> Option<Bytes> {
        self.rx.lock().await.next().await
    }
    async fn register_prefix(&self, _prefix: &Name) -> Result<(), AppError> {
        Ok(())
    }
}

/// Start `asker` fetching over a [`Wire`] to `signer`.
pub(super) async fn wired(
    w: &mut World,
    asker: &str,
    signer: &Device,
    tune: impl FnOnce(Config) -> Config,
) -> (Device, Arc<Wire>) {
    let wire = Wire::new();
    *w.link.lock().unwrap() = Some(wire.clone());
    let device = w.start(asker, tune).await;
    wire.signer.set(signer.clone()).ok();
    (device, wire)
}

// ---- asks handed to the signer --------------------------------------------------------------

/// What the signer said to one ask.
pub(super) enum Told {
    /// The signed answer packet.
    Answer(Box<Data>),
    Refused(AskRefusal),
    /// No reply at all.
    Silent,
}

/// An ask for `ask` from `asker`, built as it builds one, handed to `signer`'s answer to it.
pub(super) async fn told(
    asker: &Device,
    signer: &Device,
    ask: &AnswerAsk,
    lifetime: Option<Duration>,
) -> Told {
    let public = signer.inner.st.lock().keys.recipient.public();
    let (name, params) = asker.inner.build_ask(signer.name(), &public, ask).unwrap();
    heard(asker, signer, &name, params, lifetime).await
}

/// `params` handed to `signer` as the Interest `name`: what it replies.
async fn heard(
    asker: &Device,
    signer: &Device,
    name: &Name,
    params: Bytes,
    lifetime: Option<Duration>,
) -> Told {
    let Some(wire) = signer.inner.answer_ask(name, Some(params), lifetime).await else {
        return Told::Silent;
    };
    let data = Data::decode(wire).unwrap();
    assert_eq!(*data.name, *name, "the reply is named as the Interest");
    assert!(
        asker
            .inner
            .verify(&data)
            .await
            .is_ok_and(|w| { wire::device_of(w.key()).as_ref() == Some(signer.name()) }),
        "the reply is signed by the signer's device key"
    );
    match read_reply(&data).unwrap() {
        Reply::Packet(d) => Told::Answer(d),
        Reply::Refused(r) => {
            assert_eq!(
                r.explanation,
                r.why.explain(),
                "a refusal says why and what to do"
            );
            Told::Refused(r.why)
        }
    }
}

// ---- evaluators that count and take their time ------------------------------------------------

/// The cases' [`Sum`] that counts its evaluations, takes `delay` to evaluate and notes it started.
struct Counting {
    inner: Arc<dyn Evaluator>,
    calls: Arc<AtomicUsize>,
    started: Arc<AtomicBool>,
    delay: Duration,
}

#[async_trait::async_trait]
impl Evaluator for Counting {
    fn evaluator(&self) -> &Name {
        self.inner.evaluator()
    }

    async fn plan(&self, def: &Definition, reads: &mut dyn Reads) -> Result<(), PlanError> {
        self.inner.plan(def, reads).await
    }

    fn evaluate(&self, def: &Definition, view: &dyn ReadView) -> Result<Bytes, EvalError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.started.store(true, Ordering::SeqCst);
        std::thread::sleep(self.delay);
        self.inner.evaluate(def, view)
    }
}

/// `sum(1)` counting its evaluations: the evaluator, how many there were, whether one started.
pub(super) fn counting(delay: Duration) -> (Arc<dyn Evaluator>, Arc<AtomicUsize>, Arc<AtomicBool>) {
    let (calls, started) = (
        Arc::new(AtomicUsize::new(0)),
        Arc::new(AtomicBool::new(false)),
    );
    let ev: Arc<dyn Evaluator> = Arc::new(Counting {
        inner: sum(1),
        calls: Arc::clone(&calls),
        started: Arc::clone(&started),
        delay,
    });
    (ev, calls, started)
}

pub(super) fn serving(
    evals: Vec<Arc<dyn Evaluator>>,
    serve_asks: AskServing,
    asks_at_once: usize,
) -> impl FnOnce(Config) -> Config {
    move |c| Config {
        evaluators: evals.into_iter().fold(Evaluators::none(), |e, x| e.with(x)),
        answers: AnswerConfig {
            serve_asks,
            asks_at_once,
            ..AnswerConfig::default()
        },
        ..c
    }
}

/// An asker's policy: trust and ask exactly `signer` for pure answers.
pub(super) fn asking(signer: &str, lifetime: Duration) -> impl FnOnce(Config) -> Config {
    let policy = AnswerPolicy {
        pure: Signers::Devices(vec![n(signer)]),
        ..AnswerPolicy::default()
    };
    move |c| Config {
        lifetime,
        answers: AnswerConfig {
            policy,
            ..AnswerConfig::default()
        },
        ..c
    }
}

async fn until(flag: &AtomicBool) {
    for _ in 0..500 {
        if flag.load(Ordering::SeqCst) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the evaluation never started");
}

fn the_answer_name(signer: &Device, id: &[u8; 32]) -> Name {
    wire::answer_name(signer.name(), id)
}

// ---- the wire ---------------------------------------------------------------------------------

#[test]
fn the_envelope_its_body_and_every_refusal_round_trip_and_nothing_else_decodes() {
    let ask = AnswerAsk::provider(
        function(1),
        ReadSet::new([ReadRef::Version {
            name: n("/alice/laptop/32=log/alice/32=data/trip/budget/seq=1"),
            digest: crate::Hash([7; 32]),
        }])
        .unwrap(),
    );
    let body = AnswerAskBody {
        ask: ask.clone(),
        asker: n("/alice/phone"),
        proof: DataBuilder::new(n("/alice/phone/32=ask/x"), &[]).sign_digest_sha256(),
    };
    assert_eq!(AnswerAskBody::decode(body.encode()).unwrap(), body);
    let mut trailing = body.encode().to_vec();
    trailing.extend_from_slice(&[0x01, 0x00]);
    assert!(
        AnswerAskBody::decode(Bytes::from(trailing)).is_err(),
        "a TLV after the proof is refused"
    );

    let envelope = AnswerAskEnvelope {
        ephemeral: [3; 32],
        key: Bytes::from_static(b"wrapped"),
        sealed: Bytes::from_static(b"sealed"),
    };
    let tlv = envelope.encode();
    assert_eq!(
        ndn_tlv::TlvReader::new(tlv.clone()).read_tlv().unwrap().0,
        tlv::ANSWER_ASK_ENVELOPE,
        "TLV-TYPE 0x05DE"
    );
    assert_eq!(AnswerAskEnvelope::decode(tlv.clone()).unwrap(), envelope);
    let mut longer = tlv.to_vec();
    longer.push(0);
    assert!(AnswerAskEnvelope::decode(Bytes::from(longer)).is_err());
    assert!(
        AnswerAskEnvelope::decode(ask.encode()).is_err(),
        "another TLV is not an envelope"
    );

    let wait = Duration::from_millis(1500);
    let all = [
        AskRefusal::NotAudience { index: 5 },
        AskRefusal::Busy { retry_after: wait },
        AskRefusal::Pending { retry_after: wait },
        AskRefusal::CannotCheck,
        AskRefusal::NotProvided,
        AskRefusal::OverBudget,
        AskRefusal::NotServed,
    ];
    for (i, why) in all.into_iter().enumerate() {
        assert_eq!(why.code(), i as u64 + 1);
        let refusal = AnswerAskRefusal::new(why);
        assert!(!refusal.explanation.is_empty(), "{why:?} says why");
        let tlv = refusal.encode();
        assert_eq!(
            ndn_tlv::TlvReader::new(tlv.clone()).read_tlv().unwrap().0,
            tlv::ANSWER_ASK_REFUSAL,
            "TLV-TYPE 0x05DF"
        );
        assert_eq!(AnswerAskRefusal::decode(tlv).unwrap(), refusal);
    }
    assert_eq!(
        AnswerAskRefusal::new(AskRefusal::Busy { retry_after: wait })
            .why
            .retry_after(),
        Some(wait)
    );
    // A code outside 1..=7, a number on a reason that carries none, and words that are not
    // UTF-8 are refused.
    let value = |code: u8, param: u64, text: &[u8]| {
        let mut v = vec![code];
        v.extend_from_slice(&param.to_be_bytes());
        v.extend_from_slice(text);
        let mut w = ndn_tlv::TlvWriter::new();
        w.write_tlv(tlv::ANSWER_ASK_REFUSAL, &v);
        w.finish()
    };
    assert!(AnswerAskRefusal::decode(value(4, 0, b"x")).is_ok());
    assert!(AnswerAskRefusal::decode(value(0, 0, b"x")).is_err());
    assert!(AnswerAskRefusal::decode(value(8, 0, b"x")).is_err());
    assert!(AnswerAskRefusal::decode(value(4, 1, b"x")).is_err());
    assert!(AnswerAskRefusal::decode(value(4, 0, &[0xff, 0xfe])).is_err());

    // The ask's name: the signer's, the keyword, the digest of the parameters it carries.
    let signer = n("/alice/laptop");
    let name = answer_ask_name(&signer, &tlv);
    assert_eq!(parse_answer_ask_name(&name), Some(signer.clone()));
    assert_eq!(name.len(), signer.len() + 2);
    assert!(name.has_prefix(&answer_ask_prefix(&signer)));
    assert_ne!(name, answer_ask_name(&signer, b"other parameters"));
    assert_eq!(parse_answer_ask_name(&answer_ask_prefix(&signer)), None);
}

// ---- the signer: a provider ask, a pending ask ------------------------------------------------

#[tokio::test]
async fn a_provider_ask_is_delivered_to_the_host_and_answered_once_it_provides() {
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, knowing(vec![])).await;
    let policy = AnswerPolicy {
        providers: vec![(function(1), Signers::Devices(vec![n("/alice/laptop")]))],
        ..AnswerPolicy::default()
    };
    let (phone, _wire) = wired(&mut w, "/alice/phone", &laptop, with_policy(policy, vec![])).await;
    sync_all(&laptop, &phone);
    let inputs = ReadSet::new([newest(&laptop, &budget()).await]).unwrap();
    let q = AnswerAsk::provider(function(1), inputs.clone())
        .name(Some(&n("/alice/laptop")))
        .unwrap();

    // No host takes the stream: the signer does not provide the function, and says so.
    let refused = ask(&phone, &q).await.unwrap_err();
    assert!(
        matches!(
            &refused,
            DataError::Answer {
                why: AnswerRefusal::AskRefused {
                    why: AskRefusal::NotProvided,
                    ..
                },
                ..
            }
        ),
        "{refused:?}"
    );
    assert_eq!(refused.next(), NextStep::SetPolicy);

    // The host takes it: the call arrives with the function, the inputs and the asker, and the
    // answer it provides is what the asker gets.
    let mut calls = laptop.provider_asks();
    let host = laptop.clone();
    let hosted = tokio::spawn(async move {
        let call = calls.recv().await.expect("a provider ask");
        let result = Bytes::from(format!("{} summarized", call.inputs.reads().len()));
        host.provide(&call.function, call.inputs.clone(), result)
            .await
            .unwrap();
        call
    });
    let got = ask(&phone, &q).await.unwrap();
    let call = hosted.await.unwrap();
    assert_eq!(call.function, function(1));
    assert_eq!(call.inputs, inputs);
    assert_eq!(call.asker, n("/alice/phone"));
    assert_eq!(got.result, Bytes::from_static(b"1 summarized"));
    assert_eq!(got.kind, AnswerKind::Provider);
    assert!(
        matches!(&got.how, Provenance::Provider { signer, .. }
            if *signer == writer(&w.key_of("/alice/laptop"))),
        "{:?}",
        got.how
    );
    assert_eq!(
        got.name,
        the_answer_name(&laptop, &id_of(&got.name)),
        "the signer's own answer"
    );
}

#[tokio::test]
async fn a_pending_ask_is_asked_again_and_the_stored_answer_comes_back_without_a_second_evaluation()
{
    let mut w = World::new();
    // The evaluation takes longer than the ask's lifetime leaves the signer (400 ms of 600).
    let (ev, calls, _) = counting(Duration::from_millis(700));
    let laptop = alice_with_data(&mut w, serving(vec![ev], AskServing::Own, 4)).await;
    let (phone, wire) = wired(
        &mut w,
        "/alice/phone",
        &laptop,
        asking("/alice/laptop", Duration::from_millis(600)),
    )
    .await;
    let q = pure_question(newest(&laptop, &plan()).await, &sum_v(1));

    // This device knows no evaluator and holds no input: it asks, is told `Pending`, asks
    // again after the wait it was given, and gets the answer the signer kept.
    let got = ask(&phone, &q).await.unwrap();
    assert_eq!(got.result, Bytes::from_static(b"3"));
    assert!(
        matches!(&got.how, Provenance::Trusted { signer, .. }
            if *signer == writer(&w.key_of("/alice/laptop"))),
        "{:?}",
        got.how
    );
    assert_eq!(wire.asks(), 2, "one ask told Pending, one answered");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the second ask found the stored answer: nothing was computed again"
    );
    assert_eq!(
        got.name,
        the_answer_name(&laptop, &id_of(&got.name)),
        "the signer's answer"
    );
    // The signer's reply to the first ask itself.
    let again = AnswerAsk::pure(newest(&laptop, &plan()).await, sum_v(1));
    assert!(matches!(
        told(&phone, &laptop, &again, Some(Duration::from_millis(600))).await,
        Told::Answer(_)
    ));
}

#[tokio::test]
async fn a_signer_answers_pending_while_it_computes_and_the_answer_afterwards() {
    let mut w = World::new();
    let (ev, calls, _) = counting(Duration::from_millis(700));
    let laptop = alice_with_data(&mut w, serving(vec![ev], AskServing::Own, 4)).await;
    let phone = w.start("/alice/phone", knowing(vec![])).await;
    let ask = AnswerAsk::pure(newest(&laptop, &plan()).await, sum_v(1));
    let lifetime = Some(Duration::from_millis(600));
    match told(&phone, &laptop, &ask, lifetime).await {
        Told::Refused(AskRefusal::Pending { retry_after }) => {
            assert_eq!(retry_after, Duration::from_secs(1));
        }
        other => panic!("not Pending: {}", describe(&other)),
    }
    // Asked again before it is done: the work still holds the asker's one place.
    match told(&phone, &laptop, &ask, lifetime).await {
        Told::Refused(AskRefusal::Busy { .. }) => {}
        other => panic!("not Busy: {}", describe(&other)),
    }
    tokio::time::sleep(Duration::from_millis(600)).await;
    match told(&phone, &laptop, &ask, lifetime).await {
        Told::Answer(d) => assert!(wire::parse_answer_name(&d.name).is_some()),
        other => panic!("not the answer: {}", describe(&other)),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

pub(super) fn describe(t: &Told) -> String {
    match t {
        Told::Answer(_) => "an answer".into(),
        Told::Refused(r) => format!("{r:?}"),
        Told::Silent => "silence".into(),
    }
}

// ---- the signer: who is served, who is heard ----------------------------------------------------

#[tokio::test]
async fn a_signer_answers_only_the_namespaces_its_policy_serves_and_is_silent_to_the_rest() {
    let mut w = World::new();
    let (ev, calls, _) = counting(Duration::ZERO);
    let laptop = alice_with_data(&mut w, serving(vec![ev], AskServing::Off, 4)).await;
    let (phone, _wire) = wired(
        &mut w,
        "/alice/phone",
        &laptop,
        asking("/alice/laptop", Duration::from_millis(300)),
    )
    .await;
    // A signer that serves no asks does not reply at all, not even to its own person's device:
    // an ask of a namespace it does not serve is not worth a certificate fetch or a refusal.
    let q = pure_question(newest(&laptop, &plan()).await, &sum_v(1));
    let silent = phone.ask_answer(&n("/alice/laptop"), &q).await.unwrap_err();
    assert!(
        matches!(&silent, DataError::NotReady { why, .. } if why.contains("lapsed")),
        "{silent:?}"
    );
    assert_eq!(silent.next(), NextStep::RetryLater);
    assert_eq!(calls.load(Ordering::SeqCst), 0, "nothing was computed");

    // The default serves a person's own devices and no one else's, however well they prove who
    // they are: Bob's device gets no reply, Alice's phone its answer.
    let (ev, calls, _) = counting(Duration::ZERO);
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, serving(vec![ev], AskServing::Own, 4)).await;
    let bob = w.start("/bob/laptop", knowing(vec![])).await;
    let phone = w.start("/alice/phone", knowing(vec![])).await;
    let ask = AnswerAsk::pure(newest(&laptop, &plan()).await, sum_v(1));
    assert!(matches!(
        told(&bob, &laptop, &ask, None).await,
        Told::Silent
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(matches!(
        told(&phone, &laptop, &ask, None).await,
        Told::Answer(_)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_ask_that_does_not_authenticate_gets_no_reply_and_computes_nothing() {
    let mut w = World::new();
    let (ev, calls, _) = counting(Duration::ZERO);
    let laptop = alice_with_data(&mut w, serving(vec![ev], AskServing::Own, 4)).await;
    let phone = w.start("/alice/phone", knowing(vec![])).await;
    let tablet = w.start("/alice/tablet", knowing(vec![])).await;
    let ask = AnswerAsk::pure(newest(&laptop, &plan()).await, sum_v(1));
    let me = laptop.name().clone();
    let public = laptop.inner.st.lock().keys.recipient.public();
    let aad = answer_ask_prefix(&me).encode_to_tlv();

    // An ask sealed to the signer, made with a `proof`.
    let with_proof = |asker: &Name, proof: &dyn Fn(&[u8; 32]) -> Bytes| {
        let key = AskKey::to(&public, &aad).unwrap();
        let binding = AnswerAskBody::binding(&me, &ask, &key.ephemeral);
        let body = AnswerAskBody {
            ask: ask.clone(),
            asker: asker.clone(),
            proof: proof(&binding),
        };
        let sealed = key.seal(&body.encode(), &aad);
        let params = AnswerAskEnvelope {
            ephemeral: sealed.ephemeral,
            key: sealed.key,
            sealed: sealed.sealed,
        }
        .encode();
        (answer_ask_name(&me, &params), params)
    };
    let phone_name = phone.name().clone();
    let genuine = |b: &[u8; 32]| phone.inner.ask_proof(b).unwrap();
    // A proof only the digest vouches for, named right.
    let forged = |b: &[u8; 32]| {
        DataBuilder::new(wire::ask_name(&phone_name, b), &[])
            .freshness(Duration::ZERO)
            .sign_digest_sha256()
    };
    // A real proof of another ask.
    let of_another = |_: &[u8; 32]| phone.inner.ask_proof(&[9; 32]).unwrap();

    for (what, (name, params)) in [
        ("a forged proof", with_proof(&phone_name, &forged)),
        (
            "the proof of another ask",
            with_proof(&phone_name, &of_another),
        ),
        (
            "another device's proof",
            with_proof(tablet.name(), &genuine),
        ),
    ] {
        assert!(
            matches!(
                heard(&phone, &laptop, &name, params, None).await,
                Told::Silent
            ),
            "{what} gets no reply"
        );
    }
    // Parameters that are not the name's digest, that open to nothing, that are not an envelope.
    let (name, params) = with_proof(&phone_name, &genuine);
    assert!(matches!(
        heard(
            &phone,
            &laptop,
            &answer_ask_name(&me, b"x"),
            params.clone(),
            None
        )
        .await,
        Told::Silent
    ));
    let mut cut = params.to_vec();
    let last = cut.len() - 1;
    cut[last] ^= 1;
    let cut = Bytes::from(cut);
    assert!(matches!(
        heard(&phone, &laptop, &answer_ask_name(&me, &cut), cut, None).await,
        Told::Silent
    ));
    let junk = Bytes::from_static(b"not an envelope");
    assert!(matches!(
        heard(&phone, &laptop, &answer_ask_name(&me, &junk), junk, None).await,
        Told::Silent
    ));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "nothing was computed for any of them"
    );

    // The same ask, genuine, is answered.
    assert!(matches!(
        heard(&phone, &laptop, &name, params, None).await,
        Told::Answer(_)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_asker_outside_a_reads_audience_is_refused_not_audience_before_anything_is_evaluated() {
    let mut w = World::new();
    let (ev, calls, _) = counting(Duration::ZERO);
    let laptop = w
        .start("/alice/laptop", serving(vec![ev], AskServing::Own, 4))
        .await;
    // Sealed to the laptop alone: the phone is Alice's too, and no reader.
    let sealed_to_laptop = Share {
        rule: Rule::Log,
        writers: vec![n("/alice")],
        readers: vec![Audience::Device(n("/alice/laptop"))],
    };
    for c in [plan(), budget()] {
        laptop.share(&c, sealed_to_laptop.clone()).await.unwrap();
    }
    put_n(&laptop, &budget(), 3).await;
    put_def(&laptop, &plan(), &[&budget()]).await;
    let phone = w.start("/alice/phone", knowing(vec![])).await;
    let definition = newest(&laptop, &plan()).await;

    // The laptop computes the answer once, for itself: the reads that are the question.
    let stated = ask(&laptop, &pure_question(definition.clone(), &sum_v(1)))
        .await
        .unwrap()
        .reads;
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // States the reads: refused at the first it may not read, nothing evaluated.
    let by_reads = AnswerAsk::pure(definition.clone(), sum_v(1)).stating(stated.clone());
    assert!(
        matches!(
            told(&phone, &laptop, &by_reads, None).await,
            Told::Refused(AskRefusal::NotAudience { index: 0 })
        ),
        "the first read is the first it may not read"
    );
    // Leaves them to be planned: planned on the signer, refused before evaluating.
    let planned = AnswerAsk::pure(definition, sum_v(1));
    assert!(matches!(
        told(&phone, &laptop, &planned, None).await,
        Told::Refused(AskRefusal::NotAudience { .. })
    ));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "no evaluation ran for the asker outside the audience"
    );
    let refusal = AskRefusal::NotAudience { index: 0 };
    assert_eq!(refusal.next(), NextStep::AskOwner);
    assert!(refusal.explain().contains("owner"));

    // The audience itself is served: sealed to Alice's person, the phone is of it.
    let mut w = World::new();
    let laptop = sealed_alice(&mut w, knowing(vec![sum(1)]), &["/alice"]).await;
    let phone = w.start("/alice/phone", knowing(vec![])).await;
    let ask = AnswerAsk::pure(newest(&laptop, &plan()).await, sum_v(1));
    assert!(matches!(
        told(&phone, &laptop, &ask, None).await,
        Told::Answer(_)
    ));
}

#[tokio::test]
async fn an_asker_has_one_ask_in_progress_and_the_next_is_busy_until_it_is_done() {
    let mut w = World::new();
    let (ev, calls, started) = counting(Duration::from_millis(600));
    let laptop = alice_with_data(&mut w, serving(vec![ev], AskServing::Own, 4)).await;
    let phone = w.start("/alice/phone", knowing(vec![])).await;
    let ask = AnswerAsk::pure(newest(&laptop, &plan()).await, sum_v(1));

    let first = {
        let (phone, laptop, ask) = (phone.clone(), laptop.clone(), ask.clone());
        tokio::spawn(async move { told(&phone, &laptop, &ask, None).await })
    };
    until(&started).await;
    match told(&phone, &laptop, &ask, None).await {
        Told::Refused(r @ AskRefusal::Busy { retry_after }) => {
            assert_eq!(retry_after, Duration::from_secs(1));
            assert_eq!(r.next(), NextStep::RetryLater);
            assert_eq!(r.retry_after(), Some(retry_after));
        }
        other => panic!("not Busy: {}", describe(&other)),
    }
    assert!(matches!(first.await.unwrap(), Told::Answer(_)));
    // Done: the place is given back, and the answer comes from the store.
    assert!(matches!(
        told(&phone, &laptop, &ask, None).await,
        Told::Answer(_)
    ));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "evaluated once, for the first"
    );
}

#[tokio::test]
async fn asks_at_once_bounds_the_asks_of_all_askers_together() {
    let mut w = World::new();
    let (ev, calls, started) = counting(Duration::from_millis(600));
    let laptop = alice_with_data(&mut w, serving(vec![ev], AskServing::Own, 1)).await;
    let phone = w.start("/alice/phone", knowing(vec![])).await;
    let tablet = w.start("/alice/tablet", knowing(vec![])).await;
    let ask = AnswerAsk::pure(newest(&laptop, &plan()).await, sum_v(1));

    let first = {
        let (phone, laptop, ask) = (phone.clone(), laptop.clone(), ask.clone());
        tokio::spawn(async move { told(&phone, &laptop, &ask, None).await })
    };
    until(&started).await;
    // Another asker with nothing in progress: the signer is at its total.
    assert!(
        matches!(
            told(&tablet, &laptop, &ask, None).await,
            Told::Refused(AskRefusal::Busy { .. })
        ),
        "one ask at once, and it is the phone's"
    );
    assert!(matches!(first.await.unwrap(), Told::Answer(_)));
    assert!(matches!(
        told(&tablet, &laptop, &ask, None).await,
        Told::Answer(_)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

// ---- the host asks one device -----------------------------------------------------------------

#[tokio::test]
async fn ask_answer_asks_the_named_device_and_says_what_to_do_when_it_cannot() {
    // The signer gives its answer: judged as a fetched one is, taken on the policy's trust.
    let mut w = World::new();
    let (ev, calls, _) = counting(Duration::ZERO);
    let laptop = alice_with_data(&mut w, serving(vec![ev], AskServing::Own, 4)).await;
    let (phone, wire) = wired(&mut w, "/alice/phone", &laptop, knowing(vec![])).await;
    let q = pure_question(newest(&laptop, &plan()).await, &sum_v(1));
    let Got::Answer(a) = phone.ask_answer(&n("/alice/laptop"), &q).await.unwrap() else {
        panic!("an answer");
    };
    assert_eq!(a.result, Bytes::from_static(b"3"));
    assert!(
        matches!(&a.how, Provenance::Trusted { signer, .. }
            if *signer == writer(&w.key_of("/alice/laptop"))),
        "{:?}",
        a.how
    );
    assert_eq!(a.name, the_answer_name(&laptop, &a.id.0));
    assert_eq!(wire.asks(), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    // Itself is not asked.
    let me = phone.ask_answer(&n("/alice/phone"), &q).await.unwrap_err();
    assert!(matches!(me, DataError::BadRequest { .. }), "{me:?}");

    // A signer whose seal key is not to be had: retry later, and say why.
    let short = |c: Config| Config {
        lifetime: Duration::from_millis(300),
        ..c
    };
    let (lone, _) = wired(&mut w, "/alice/tablet", &laptop, short).await;
    let unreached = lone.ask_answer(&n("/alice/nobody"), &q).await.unwrap_err();
    assert!(
        matches!(&unreached, DataError::NotReady { why, .. }
            if why.contains("seal key is not held yet")),
        "{unreached:?}"
    );
    assert_eq!(unreached.next(), NextStep::RetryLater);

    // A signer that refuses: its reason, and the step that goes with it.
    let mut w = World::new();
    let (ev, calls, _) = counting(Duration::ZERO);
    let laptop = w
        .start("/alice/laptop", serving(vec![ev], AskServing::Own, 4))
        .await;
    let sealed_to_laptop = Share {
        rule: Rule::Log,
        writers: vec![n("/alice")],
        readers: vec![Audience::Device(n("/alice/laptop"))],
    };
    for c in [plan(), budget()] {
        laptop.share(&c, sealed_to_laptop.clone()).await.unwrap();
    }
    put_n(&laptop, &budget(), 3).await;
    put_def(&laptop, &plan(), &[&budget()]).await;
    let (phone, _wire) = wired(&mut w, "/alice/phone", &laptop, knowing(vec![])).await;
    let q = pure_question(newest(&laptop, &plan()).await, &sum_v(1));
    let refused = phone.ask_answer(&n("/alice/laptop"), &q).await.unwrap_err();
    assert!(
        matches!(
            &refused,
            DataError::Answer {
                why: AnswerRefusal::AskRefused {
                    why: AskRefusal::NotAudience { .. },
                    ..
                },
                ..
            }
        ),
        "{refused:?}"
    );
    assert_eq!(refused.next(), NextStep::AskOwner);
    assert!(!refused.retry());
    assert!(
        refused.to_string().contains("owner"),
        "it says what to do: {refused}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
