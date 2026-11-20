//! What the ask exchange costs the signer, whom it serves and what it tells (round 8): the
//! signer's caps, budgets and silences, judged by handing it asks as [`super::ask_tests`] does.

use std::sync::atomic::Ordering;

use super::ask_tests::{Told, asking, counting, describe, serving, told, wired};
use super::*;
use crate::NextStep;
use crate::answer::{
    AnswerAskBody, AnswerAskEnvelope, AnswerAskRefusal, AskRefusal, AskServing, answer_ask_name,
    answer_ask_prefix,
};
use crate::seal::AskKey;

/// The ask `ask`, sealed to `signer` as `asker`, with the proof `proof` makes of its binding.
fn sealed_by(
    signer: &Device,
    ask: &AnswerAsk,
    asker: &Name,
    proof: &dyn Fn(&[u8; 32]) -> Bytes,
) -> (Name, Bytes) {
    let public = signer.inner.st.lock().keys.recipient.public();
    let aad = answer_ask_prefix(signer.name()).encode_to_tlv();
    let key = AskKey::to(&public, &aad).unwrap();
    let binding = AnswerAskBody::binding(signer.name(), ask, &key.ephemeral);
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
    (answer_ask_name(signer.name(), &params), params)
}

/// A proof named for `claimed`, as a real one is, signed by a key nothing vouches for.
fn junk_proof(claimed: &Name, binding: &[u8; 32]) -> Bytes {
    let mgr = SecurityManager::new();
    let key = mgr
        .generate_ed25519(claimed.clone().append("KEY").append("1"))
        .unwrap();
    let signer = mgr.get_signer_sync(&key).unwrap();
    DataBuilder::new(wire::ask_name(claimed, binding), &[])
        .freshness(Duration::ZERO)
        .sign_sync(signer.sig_type(), Some(&key), |region| {
            signer.sign_sync(region).unwrap()
        })
}

/// Every certificate the validator of `device` is asked to fetch is noted, and never comes.
pub(super) fn fetching_nothing(w: &World, device: &str) -> Arc<std::sync::Mutex<Vec<Name>>> {
    let asked: Arc<std::sync::Mutex<Vec<Name>>> = Arc::default();
    let noted = Arc::clone(&asked);
    let fetch: ndn_security::FetchFn = Arc::new(move |name: Name| {
        noted.lock().unwrap().push(name);
        Box::pin(async {
            futures::future::pending::<()>().await;
            Err(ndn_security::FetchMiss::Absent)
        })
    });
    let validator = w.validator_of(device);
    let fetcher =
        ndn_security::CertFetcher::new(validator.cert_cache_arc(), fetch, Duration::from_secs(60))
            .with_negative_ttl(Duration::ZERO);
    assert!(validator.set_cert_fetcher(Arc::new(fetcher)).is_ok());
    asked
}

/// Each of `claims` asks `signer` for `ask` with a junk proof, all at once.
pub(super) fn flood(
    signer: &Device,
    ask: &AnswerAsk,
    claims: impl Iterator<Item = Name>,
) -> tokio::task::JoinSet<Option<Bytes>> {
    let mut set = tokio::task::JoinSet::new();
    for claimed in claims {
        let (name, params) = sealed_by(signer, ask, &claimed, &|b| junk_proof(&claimed, b));
        let signer = signer.clone();
        set.spawn(async move { signer.inner.answer_ask(&name, Some(params), None).await });
    }
    set
}

#[tokio::test]
async fn asks_claiming_a_namespace_the_signer_does_not_serve_fetch_no_certificate_and_cost_no_permit()
 {
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, serving(vec![sum(1)], AskServing::Own, 4)).await;
    let fetched = fetching_nothing(&w, "/alice/laptop");
    let ask = AnswerAsk::pure(newest(&laptop, &plan()).await, sum_v(1));

    // Sixteen strangers' envelopes, more than the permits, each proving a device of Bob's, whom
    // this signer does not serve: dropped at once, no certificate asked for, no permit kept.
    let mut set = flood(&laptop, &ask, (0..16).map(|i| n(&format!("/bob/ghost{i}"))));
    let all = tokio::time::timeout(Duration::from_millis(500), async {
        while let Some(done) = set.join_next().await {
            assert!(done.unwrap().is_none(), "no reply to a stranger");
        }
    })
    .await;
    assert!(
        all.is_ok(),
        "every ask of an unserved namespace is dropped without waiting for a certificate or a \
         permit; certificates asked for: {:?}",
        fetched.lock().unwrap()
    );
    assert!(
        fetched.lock().unwrap().is_empty(),
        "a certificate was fetched for a device of a namespace not served: {:?}",
        fetched.lock().unwrap()
    );
    assert_eq!(
        laptop.inner.verifying.available_permits(),
        laptop.inner.config.asks_verifying,
        "introductions, holds and audits keep every permit"
    );
}

#[tokio::test]
async fn proofs_of_asks_for_an_answer_are_verified_on_a_budget_of_their_own() {
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, serving(vec![sum(1)], AskServing::Own, 4)).await;
    let fetched = fetching_nothing(&w, "/alice/laptop");
    let ask = AnswerAsk::pure(newest(&laptop, &plan()).await, sum_v(1));
    // Devices of its own person's namespace are served, so their proofs are verified, and a
    // certificate fetch that never comes parks each verification.
    let mut set = flood(
        &laptop,
        &ask,
        (0..16).map(|i| n(&format!("/alice/ghost{i}"))),
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !fetched.lock().unwrap().is_empty(),
        "a served namespace's proofs are verified"
    );
    assert_eq!(
        laptop.inner.verifying.available_permits(),
        laptop.inner.config.asks_verifying,
        "the permits of introductions, holds and audits are not spent by asks for an answer"
    );
    set.abort_all();
}

/// The ask for `plan()` and, besides, a version of `budget()` the signer does not hold and no
/// one gives it: a read that takes as long as a fetch does.
pub(super) async fn ghost_ask(laptop: &Device) -> AnswerAsk {
    let def = newest(laptop, &plan()).await;
    let ReadRef::Version { name, .. } = newest(laptop, &budget()).await else {
        panic!("a version");
    };
    let s = name.to_string();
    let cut = s.rfind("/seq=").unwrap();
    let ghost = ReadRef::Version {
        name: n(&format!("{}/seq=99", &s[..cut])),
        digest: crate::Hash([9; 32]),
    };
    AnswerAsk::pure(def.clone(), sum_v(1)).stating(ReadSet::new([def, ghost]).unwrap())
}

/// A signer that serves members too, whose reads of a version it does not hold wait for a
/// fetch of up to a second and a half, and whose budget of time is `time`.
fn slow_fetcher(time: Duration) -> impl FnOnce(Config) -> Config {
    move |c| Config {
        lifetime: Duration::from_millis(1500),
        answers: AnswerConfig {
            serve_asks: AskServing::OwnAndMembers,
            asks_at_once: 4,
            budget: Budget {
                time,
                ..AnswerConfig::default().budget
            },
            ..AnswerConfig::default()
        },
        ..knowing(vec![sum(1)])(c)
    }
}

#[tokio::test]
async fn an_ask_waiting_for_a_fetch_gives_back_its_caps_within_the_budget_of_time() {
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, slow_fetcher(Duration::from_millis(300))).await;
    let phone = w.start("/alice/phone", knowing(vec![])).await;
    let ask = ghost_ask(&laptop).await;

    let first = {
        let (phone, laptop, ask) = (phone.clone(), laptop.clone(), ask.clone());
        tokio::spawn(async move { told(&phone, &laptop, &ask, None).await })
    };
    tokio::time::sleep(Duration::from_millis(700)).await;
    // The first waited for a version no one gives, for the budget of time and no longer: the
    // asker's place is free again, and the ask is told to wait, not that the signer is busy.
    match told(&phone, &laptop, &ask, None).await {
        Told::Refused(AskRefusal::Pending { .. }) => {}
        other => panic!("not Pending: {}", describe(&other)),
    }
    first.abort();
}

#[tokio::test]
async fn a_collaborators_devices_cannot_keep_the_persons_own_devices_waiting() {
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, slow_fetcher(Duration::from_millis(300))).await;
    let phone = w.start("/alice/phone", knowing(vec![])).await;
    let mut bobs = Vec::new();
    for device in ["/bob/laptop", "/bob/phone", "/bob/tablet", "/bob/watch"] {
        bobs.push(w.start(device, knowing(vec![])).await);
    }
    let ask = ghost_ask(&laptop).await;

    // Bob is a writer of what Alice shares, so each of his four devices is served, and each asks
    // for a version the signer must wait for.
    let mut held = Vec::new();
    for bob in &bobs {
        let (bob, laptop, ask) = (bob.clone(), laptop.clone(), ask.clone());
        held.push(tokio::spawn(async move {
            told(&bob, &laptop, &ask, None).await
        }));
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Alice's own phone is not kept waiting for them: other namespaces hold half the places at
    // most, and one namespace half of that.
    let valid = AnswerAsk::pure(newest(&laptop, &plan()).await, sum_v(1));
    assert!(
        matches!(told(&phone, &laptop, &valid, None).await, Told::Answer(_)),
        "Alice's phone is answered while Bob's devices wait for a fetch"
    );
    for h in held {
        h.abort();
    }
}

#[tokio::test]
async fn asks_cannot_drain_the_signers_own_signing_budget_and_a_rate_is_busy_not_a_smaller_read_set()
 {
    let mut w = World::new();
    let tune = |c: Config| Config {
        answers: AnswerConfig {
            sign_per_second: 4,
            ..AnswerConfig::default()
        },
        ..knowing(vec![sum(1)])(c)
    };
    let laptop = alice_with_data(&mut w, tune).await;
    let phone = w.start("/alice/phone", knowing(vec![])).await;

    // Each ask is over other reads (the data moved), so each is a new answer to sign. Asks have
    // half of the four a second: two are signed, then the signer is busy for a moment.
    let mut said = Vec::new();
    for v in 10..14 {
        put_n(&laptop, &budget(), v).await;
        let q = AnswerAsk::pure(newest(&laptop, &plan()).await, sum_v(1));
        said.push(told(&phone, &laptop, &q, None).await);
    }
    assert!(matches!(said[0], Told::Answer(_)), "{}", describe(&said[0]));
    assert!(matches!(said[1], Told::Answer(_)), "{}", describe(&said[1]));
    match &said[2] {
        Told::Refused(r @ AskRefusal::Busy { retry_after }) => {
            assert!(!retry_after.is_zero());
            assert_eq!(r.next(), NextStep::RetryLater);
        }
        other => panic!("not Busy: {}", describe(other)),
    }
    // The signer's own four a second were not touched.
    for v in 20..24 {
        put_n(&laptop, &budget(), v).await;
        let q = pure_question(newest(&laptop, &plan()).await, &sum_v(1));
        laptop.publish_answer(&q).await.unwrap();
    }
}

#[tokio::test]
async fn a_guest_or_a_relay_is_not_served_by_default_and_a_member_is() {
    let mut w = World::new();
    let (ev, calls, _) = counting(Duration::ZERO);
    let laptop = alice_with_data(&mut w, serving(vec![ev], AskServing::Own, 4)).await;
    let guest = w.start("/alice/guest/phone", knowing(vec![])).await;
    let relay = w.start("/alice/node/relay", knowing(vec![])).await;
    let tablet = w.start("/alice/member/tablet", knowing(vec![])).await;
    let ask = AnswerAsk::pure(newest(&laptop, &plan()).await, sum_v(1));

    // A friend's short-lived key proves it is Alice's device and is not served: the refusal
    // says so, and nothing was computed.
    for device in [&guest, &relay] {
        match told(device, &laptop, &ask, None).await {
            Told::Refused(r @ AskRefusal::NotServed) => assert_eq!(r.next(), NextStep::SetPolicy),
            other => panic!("{} not NotServed: {}", device.name(), describe(&other)),
        }
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(matches!(
        told(&tablet, &laptop, &ask, None).await,
        Told::Answer(_)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_refusal_the_signer_words_is_never_shown_as_it_came() {
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, serving(vec![sum(1)], AskServing::Own, 4)).await;
    let (phone, wire) = wired(
        &mut w,
        "/alice/phone",
        &laptop,
        asking("/alice/laptop", Duration::from_millis(600)),
    )
    .await;
    let hostile = AnswerAskRefusal {
        why: AskRefusal::NotServed,
        explanation: "\u{1b}[2J\u{1b}[31mpay me\r\n\u{7}".repeat(300),
    };
    *wire.forced_refusal.lock().unwrap() = Some(hostile);
    let q = pure_question(newest(&laptop, &plan()).await, &sum_v(1));
    let refused = phone.ask_answer(&n("/alice/laptop"), &q).await.unwrap_err();
    let text = refused.to_string();
    assert!(
        !text.chars().any(char::is_control),
        "control characters reached the user: {text:?}"
    );
    assert!(
        text.len() < 1024,
        "{} octets of the signer's words",
        text.len()
    );
    assert!(text.contains("serve_asks"), "it says what to do: {text}");
}

#[tokio::test]
async fn an_answer_over_reads_the_signer_chose_is_not_exact() {
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, serving(vec![sum(1)], AskServing::Own, 4)).await;
    let (phone, _wire) = wired(
        &mut w,
        "/alice/phone",
        &laptop,
        asking("/alice/laptop", Duration::from_millis(600)),
    )
    .await;
    let q = pure_question(newest(&laptop, &plan()).await, &sum_v(1));
    let got = phone.get(&q).await.unwrap();
    assert!(matches!(got.got, Got::Answer(_)));
    assert!(
        matches!(got.age, crate::layer::Age::Newest { .. }),
        "the asker left the reads to the signer, which chose the newest it holds: {:?}",
        got.age
    );
}

#[tokio::test]
async fn the_same_provider_call_waits_for_one_answer_and_a_duplicate_is_never_not_provided() {
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, knowing(vec![])).await;
    let phone = w.start("/alice/phone", knowing(vec![])).await;
    let inputs = ReadSet::new([newest(&laptop, &budget()).await]).unwrap();
    let ask = AnswerAsk::provider(function(1), inputs.clone());
    // The host takes the stream and is slow: it provides nothing for a while.
    let mut calls = laptop.provider_asks();
    let lifetime = Some(Duration::from_millis(230));

    // One audience asker retrying, as it does, more times than the queue holds.
    for i in 0..70 {
        match told(&phone, &laptop, &ask, lifetime).await {
            Told::Refused(AskRefusal::Pending { .. }) => {}
            other => panic!("ask {i}: not Pending: {}", describe(&other)),
        }
    }
    let mut delivered = 0;
    while calls.try_recv().is_ok() {
        delivered += 1;
    }
    assert_eq!(
        delivered, 1,
        "one call for the host, however often it is asked"
    );

    // The host provides: the next ask has the answer.
    laptop
        .provide(&function(1), inputs, Bytes::from_static(b"done"))
        .await
        .unwrap();
    assert!(matches!(
        told(&phone, &laptop, &ask, lifetime).await,
        Told::Answer(_)
    ));
}

#[tokio::test]
async fn a_signer_that_regenerated_its_seal_key_is_asked_again_with_the_new_one() {
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, serving(vec![sum(1)], AskServing::Own, 4)).await;
    let (phone, _wire) = wired(
        &mut w,
        "/alice/phone",
        &laptop,
        asking("/alice/laptop", Duration::from_millis(250)),
    )
    .await;
    let q = pure_question(newest(&laptop, &plan()).await, &sum_v(1));
    let signer = n("/alice/laptop");
    phone.ask_answer(&signer, &q).await.unwrap();

    // The signer makes a new recipient key and signs its seal key packet again.
    {
        let mut st = laptop.inner.st.lock();
        st.keys.edit().recipient = ndn_security::confidentiality::RecipientKey::generate();
        st.seal_key = None;
    }
    // The key the asker holds opens nothing there: three sends go unanswered, the key is
    // fetched again, and the ask goes out once more under it.
    let again = phone.ask_answer(&signer, &q).await;
    assert!(again.is_ok(), "{again:?}");
}

#[tokio::test]
async fn nothing_replying_says_a_lapsed_certificate_makes_a_device_silent_too() {
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, serving(vec![sum(1)], AskServing::Own, 4)).await;
    let (phone, wire) = wired(
        &mut w,
        "/alice/phone",
        &laptop,
        asking("/alice/laptop", Duration::from_millis(250)),
    )
    .await;
    let q = pure_question(newest(&laptop, &plan()).await, &sum_v(1));
    let signer = n("/alice/laptop");
    phone.ask_answer(&signer, &q).await.unwrap();
    wire.muted.store(true, Ordering::SeqCst);
    let silent = phone.ask_answer(&signer, &q).await.unwrap_err();
    assert!(
        matches!(&silent, DataError::NotReady { why, .. }
            if why.contains("lapsed") && why.contains("signer")),
        "{silent:?}"
    );
    assert_eq!(silent.next(), NextStep::RetryLater);
    assert!(silent.retry());
}

fn secret() -> Name {
    n("/alice/32=data/trip/secret")
}

/// An evaluator whose plan moves with the data: the first plan reads `budget()`, every later one
/// `secret()`, as a plan that a collaborator's write changes.
struct Flip {
    name: Name,
    plans: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl Evaluator for Flip {
    fn evaluator(&self) -> &Name {
        &self.name
    }

    async fn plan(&self, _: &Definition, reads: &mut dyn Reads) -> Result<(), PlanError> {
        let first = self.plans.fetch_add(1, Ordering::SeqCst) == 0;
        let (r, _) = reads
            .current(&if first { budget() } else { secret() })
            .await?;
        reads.read(&r).await?;
        Ok(())
    }

    fn evaluate(&self, _: &Definition, view: &dyn ReadView) -> Result<Bytes, EvalError> {
        let r = view
            .current(&secret())
            .or_else(|_| view.current(&budget()))?;
        let Got::Version(v) = view.read(r)? else {
            return Err(EvalError::Refused("an input is a version".into()));
        };
        let crate::Payload::Entry(content) = &v.payload else {
            return Err(EvalError::Refused("an input is one entry".into()));
        };
        Ok(content.get("n").cloned().unwrap_or_default())
    }
}

#[tokio::test]
async fn the_reads_computed_for_an_ask_are_the_reads_judged_even_when_the_data_moves_between_plans()
{
    let mut w = World::new();
    let flip = Arc::new(Flip {
        name: n("/conformance/eval/flip/v=1"),
        plans: std::sync::atomic::AtomicUsize::new(0),
    });
    let laptop = sealed_alice(&mut w, knowing(vec![flip.clone()]), &["/alice"]).await;
    // What the planner reads next is sealed to the laptop alone: Alice's phone may not read it.
    laptop
        .share(
            &secret(),
            Share {
                rule: Rule::Log,
                writers: vec![n("/alice")],
                readers: vec![Audience::Device(n("/alice/laptop"))],
            },
        )
        .await
        .unwrap();
    put_n(&laptop, &secret(), 7).await;
    let phone = w.start("/alice/phone", knowing(vec![])).await;
    let ask = AnswerAsk::pure(newest(&laptop, &plan()).await, flip.name.clone());

    // The reads the signer plans for the ask (budget) are the reads of the audience of the
    // phone; the plan the computation would make again reads the secret. The answer is made
    // over the reads that were judged or not at all.
    match told(&phone, &laptop, &ask, None).await {
        Told::Refused(AskRefusal::Pending { .. }) => {}
        other => panic!(
            "an answer over reads the asker may not read, or no wait: {}",
            describe(&other)
        ),
    }
}

#[tokio::test]
async fn cannot_check_is_told_only_to_an_asker_who_may_read_the_definition() {
    // The plan is sealed to the laptop alone and the laptop knows no evaluator: the phone, of
    // the same person and outside the plan's audience, is not told which evaluators the laptop
    // knows, but that it may not read the definition.
    let mut w = World::new();
    let laptop = w.start("/alice/laptop", knowing(vec![])).await;
    laptop
        .share(
            &plan(),
            Share {
                rule: Rule::Log,
                writers: vec![n("/alice")],
                readers: vec![Audience::Device(n("/alice/laptop"))],
            },
        )
        .await
        .unwrap();
    laptop.share(&budget(), log_share()).await.unwrap();
    put_n(&laptop, &budget(), 3).await;
    put_def(&laptop, &plan(), &[&budget()]).await;
    let phone = w.start("/alice/phone", knowing(vec![])).await;
    let ask = AnswerAsk::pure(newest(&laptop, &plan()).await, sum_v(9));
    match told(&phone, &laptop, &ask, None).await {
        Told::Refused(AskRefusal::NotAudience { .. }) => {}
        other => panic!("not NotAudience: {}", describe(&other)),
    }

    // Of the audience, the phone is told.
    let mut w = World::new();
    let laptop = sealed_alice(&mut w, knowing(vec![]), &["/alice"]).await;
    let phone = w.start("/alice/phone", knowing(vec![])).await;
    let ask = AnswerAsk::pure(newest(&laptop, &plan()).await, sum_v(9));
    match told(&phone, &laptop, &ask, None).await {
        Told::Refused(AskRefusal::CannotCheck) => {}
        other => panic!("not CannotCheck: {}", describe(&other)),
    }
}
