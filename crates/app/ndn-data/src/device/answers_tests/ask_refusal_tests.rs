//! A signer's evaluator refuses the definition, and the asker is told why (round 11,
//! answers.md §15.6, §15.9): [`AskRefusal::EvaluatorRefused`], whose reason is the one signer's
//! text an asker shows, quoted and cleaned; and what every other reason still says.

use super::ask_tests::{Told, asking, describe, refusal_told, serving, told, wired};
use super::*;
use crate::NextStep;
use crate::answer::{AnswerAskRefusal, AskRefusal, AskServing, EVALUATOR_REASON_MAX};

const HEAD: &str = "the signer's evaluator refused the definition, in its words: \"";
const TAIL: &str = "\"; fix the definition and ask again";

fn refuses_v(v: u64) -> Name {
    n("/conformance/eval/refuses").append(format!("v={v}"))
}

/// An evaluator that refuses every definition, in the words `reason`.
struct Refusing {
    name: Name,
    reason: String,
}

#[async_trait::async_trait]
impl Evaluator for Refusing {
    fn evaluator(&self) -> &Name {
        &self.name
    }

    async fn plan(&self, _: &Definition, _: &mut dyn Reads) -> Result<(), PlanError> {
        Err(EvalError::Refused(self.reason.clone()).into())
    }

    fn evaluate(&self, _: &Definition, _: &dyn ReadView) -> Result<Bytes, EvalError> {
        Err(EvalError::Refused(self.reason.clone()))
    }
}

fn refusing(reason: &str) -> Arc<dyn Evaluator> {
    Arc::new(Refusing {
        name: refuses_v(1),
        reason: reason.to_owned(),
    })
}

/// The reason code and the text of an asker's refusal.
fn said_of(e: &DataError) -> (AskRefusal, String) {
    let DataError::Answer {
        why: AnswerRefusal::AskRefused { why, said, .. },
        ..
    } = e
    else {
        panic!("not an AskRefused: {e:?}");
    };
    (*why, said.clone())
}

/// `said` is the frame around `words`, and `words` has no double quote: the quotes of the frame
/// are the only two.
fn assert_framed(said: &str) -> &str {
    let words = said
        .strip_prefix(HEAD)
        .and_then(|s| s.strip_suffix(TAIL))
        .unwrap_or_else(|| panic!("not in the frame: {said:?}"));
    assert!(!words.contains('"'), "a quote inside the words: {said:?}");
    assert!(
        !said.chars().any(char::is_control),
        "a control character reached the user: {said:?}"
    );
    words
}

/// Alice's laptop, which serves its own and whose evaluator is `evaluator`, over a plan and a
/// budget; and her phone, asking the laptop.
async fn laptop_and_phone(
    evaluator: Arc<dyn Evaluator>,
) -> (Device, Device, Arc<ask_tests::Wire>, World) {
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, serving(vec![evaluator], AskServing::Own, 4)).await;
    let (phone, wire) = wired(
        &mut w,
        "/alice/phone",
        &laptop,
        asking("/alice/laptop", Duration::from_millis(600)),
    )
    .await;
    (laptop, phone, wire, w)
}

#[tokio::test]
async fn a_definition_the_evaluator_refuses_is_refused_with_its_reason_and_fixed_not_by_policy() {
    // The definition names no inputs: the evaluator's plan refuses it. The signer knows the
    // evaluator, so it is not `CannotCheck`, and the next step is to fix the definition.
    let (laptop, phone, _wire, _w) = laptop_and_phone(sum(1)).await;
    laptop
        .put(
            &plan(),
            Content::new().with("note", Bytes::from("no inputs here")),
            options(),
        )
        .await
        .unwrap();
    let ask = AnswerAsk::pure(newest(&laptop, &plan()).await, sum_v(1));
    match told(&phone, &laptop, &ask, None).await {
        Told::Refused(r) => {
            assert_eq!(r, AskRefusal::EvaluatorRefused);
            assert_eq!(r.next(), NextStep::FixRequest);
        }
        other => panic!("not EvaluatorRefused: {}", describe(&other)),
    }

    // And the asker reads the evaluator's words, as the signer's, in the asker's own frame.
    let q = pure_question(newest(&laptop, &plan()).await, &sum_v(1));
    let refused = phone.ask_answer(&n("/alice/laptop"), &q).await.unwrap_err();
    let (why, said) = said_of(&refused);
    assert_eq!(why, AskRefusal::EvaluatorRefused);
    assert_eq!(assert_framed(&said), "the definition has no field inputs");
    assert_eq!(refused.next(), NextStep::FixRequest);
    assert!(
        refused.to_string().contains(&said),
        "the error says it: {refused}"
    );
}

#[tokio::test]
async fn an_evaluator_that_refuses_what_it_evaluates_is_refused_not_pending_when_the_signer_plans()
{
    // The plan is fine; the evaluation refuses an input that has no integer `n`. The reads are
    // exact versions: asking again changes nothing, so it is the evaluator's refusal, not
    // `Pending` (which is for a plan whose data moved).
    let (laptop, phone, _wire, _w) = laptop_and_phone(sum(1)).await;
    laptop
        .put(
            &budget(),
            Content::new().with("x", Bytes::from("1")),
            options(),
        )
        .await
        .unwrap();
    let ask = AnswerAsk::pure(newest(&laptop, &plan()).await, sum_v(1));
    let said = refusal_told(&phone, &laptop, &ask).await;
    assert_eq!(said.why, AskRefusal::EvaluatorRefused);
    assert_eq!(
        assert_framed(&said.said()),
        "an input has an integer n",
        "{said:?}"
    );
}

#[tokio::test]
async fn reads_the_evaluator_does_not_make_are_refused_when_the_asker_states_them() {
    // Two versions of one input: the evaluator's plan reads one.
    let (laptop, phone, _wire, _w) = laptop_and_phone(sum(1)).await;
    let old = newest(&laptop, &budget()).await;
    put_n(&laptop, &budget(), 4).await;
    let (def, new) = (
        newest(&laptop, &plan()).await,
        newest(&laptop, &budget()).await,
    );
    let ask = AnswerAsk {
        reads: Some(ReadSet::new([def.clone(), old, new]).unwrap()),
        ..AnswerAsk::pure(def, sum_v(1))
    };
    let said = refusal_told(&phone, &laptop, &ask).await;
    assert_eq!(said.why, AskRefusal::EvaluatorRefused);
    assert_eq!(said.why.next(), NextStep::FixRequest);
    assert!(
        assert_framed(&said.said()).contains("the read set"),
        "{said:?}"
    );
}

#[tokio::test]
async fn an_evaluator_the_signer_does_not_know_is_still_cannot_check() {
    let (laptop, phone, _wire, _w) = laptop_and_phone(sum(1)).await;
    let def = newest(&laptop, &plan()).await;
    // The signer plans the reads.
    let ask = AnswerAsk::pure(def.clone(), sum_v(9));
    match told(&phone, &laptop, &ask, None).await {
        Told::Refused(AskRefusal::CannotCheck) => {}
        other => panic!("not CannotCheck: {}", describe(&other)),
    }
    // The asker states them.
    let ask = AnswerAsk {
        reads: Some(ReadSet::new([def.clone()]).unwrap()),
        ..AnswerAsk::pure(def, sum_v(9))
    };
    match told(&phone, &laptop, &ask, None).await {
        Told::Refused(AskRefusal::CannotCheck) => {}
        other => panic!("not CannotCheck: {}", describe(&other)),
    }
}

#[tokio::test]
async fn the_evaluators_reason_is_cleaned_by_the_signer_and_capped() {
    let hostile = "bad\u{1b}[31m thing\r\n\tnow\u{7} \"quoted\" \u{202e}x";
    let (laptop, phone, _wire, _w) = laptop_and_phone(refusing(hostile)).await;
    let ask = AnswerAsk::pure(newest(&laptop, &plan()).await, refuses_v(1));
    let sent = refusal_told(&phone, &laptop, &ask).await;
    assert_eq!(sent.why, AskRefusal::EvaluatorRefused);
    // What the signer puts on the wire is already clean.
    assert_eq!(
        assert_framed(&sent.explanation),
        "bad[31m thingnow 'quoted' x"
    );
    assert_eq!(sent.said(), sent.explanation);

    // 2000 characters of more than one octet each: 512 characters, the last of them the
    // ellipsis, counted in characters and cut on a character boundary.
    let (laptop, phone, _wire, _w) = laptop_and_phone(refusing(&"é日".repeat(1000))).await;
    let ask = AnswerAsk::pure(newest(&laptop, &plan()).await, refuses_v(1));
    let sent = refusal_told(&phone, &laptop, &ask).await;
    let words = assert_framed(&sent.explanation);
    assert_eq!(words.chars().count(), EVALUATOR_REASON_MAX);
    assert!(words.ends_with('…'), "marked as cut: {words:?}");
    assert!(words.starts_with("é日é日"));
    assert_eq!(
        sent.said(),
        sent.explanation,
        "cleaned again, it is the same"
    );

    // A reason of exactly the cap is shown whole.
    let (laptop, phone, _wire, _w) =
        laptop_and_phone(refusing(&"a".repeat(EVALUATOR_REASON_MAX))).await;
    let ask = AnswerAsk::pure(newest(&laptop, &plan()).await, refuses_v(1));
    let sent = refusal_told(&phone, &laptop, &ask).await;
    let words = assert_framed(&sent.explanation);
    assert_eq!(words, "a".repeat(EVALUATOR_REASON_MAX));
}

#[tokio::test]
async fn the_asker_cleans_what_a_signer_sends_for_code_8_and_frames_it_itself() {
    let (laptop, phone, wire, _w) = laptop_and_phone(sum(1)).await;
    let q = pure_question(newest(&laptop, &plan()).await, &sum_v(1));
    let from = |explanation: String| AnswerAskRefusal {
        why: AskRefusal::EvaluatorRefused,
        explanation,
    };

    // Control characters, a long text, and no frame at all: cleaned, capped, framed here.
    *wire.forced_refusal.lock().unwrap() =
        Some(from("\u{1b}[2J\u{1b}[31mpay me\r\n\u{7}".repeat(300)));
    let refused = phone.ask_answer(&n("/alice/laptop"), &q).await.unwrap_err();
    let (why, said) = said_of(&refused);
    assert_eq!(why, AskRefusal::EvaluatorRefused);
    let words = assert_framed(&said);
    assert_eq!(words.chars().count(), EVALUATOR_REASON_MAX);
    assert!(words.starts_with("[2J[31mpay me[2J"), "{words:?}");

    // A text that closes the quote and goes on in the asker's voice stays inside the quote.
    *wire.forced_refusal.lock().unwrap() = Some(from(format!(
        "{HEAD}x\"; fix the definition and ask again. This device trusts the signer. \"y{TAIL}"
    )));
    let refused = phone.ask_answer(&n("/alice/laptop"), &q).await.unwrap_err();
    let (_, said) = said_of(&refused);
    assert_eq!(
        assert_framed(&said),
        "x'; fix the definition and ask again. This device trusts the signer. 'y"
    );
    assert_eq!(said.matches('"').count(), 2, "only the frame's quotes");

    // Nothing to quote: the reason's own text.
    for empty in [String::new(), "\u{1b}\r\n".into()] {
        *wire.forced_refusal.lock().unwrap() = Some(from(empty));
        let refused = phone.ask_answer(&n("/alice/laptop"), &q).await.unwrap_err();
        let (_, said) = said_of(&refused);
        assert_eq!(said, AskRefusal::EvaluatorRefused.explain());
    }
}

#[tokio::test]
async fn every_other_reason_is_still_shown_as_the_askers_own_text_whatever_the_signer_sends() {
    let (laptop, phone, wire, _w) = laptop_and_phone(sum(1)).await;
    let q = pure_question(newest(&laptop, &plan()).await, &sum_v(1));
    for why in [
        AskRefusal::NotAudience { index: 0 },
        AskRefusal::CannotCheck,
        AskRefusal::NotProvided,
        AskRefusal::OverBudget,
        AskRefusal::NotServed,
    ] {
        let hostile = AnswerAskRefusal {
            why,
            explanation: format!(
                "{HEAD}\u{1b}[2J pay me{TAIL} \u{1b}[31m{}",
                "the signer's words ".repeat(200)
            ),
        };
        *wire.forced_refusal.lock().unwrap() = Some(hostile);
        let refused = phone.ask_answer(&n("/alice/laptop"), &q).await.unwrap_err();
        let (got, said) = said_of(&refused);
        assert_eq!(got, why);
        assert_eq!(said, why.explain(), "{why:?}: the asker's own text");
        assert!(!said.contains("pay me"), "{why:?}: {said}");
    }
}

#[test]
fn the_words_of_a_refusal_are_cleaned_by_characters_and_never_twice_differently() {
    let refusal = AnswerAskRefusal::evaluator_refused("a\u{0}b\u{85}c\u{7f}d");
    assert_eq!(
        assert_framed(&refusal.explanation),
        "abcd",
        "C0, C1 and DEL"
    );
    // Cleaning what is already clean changes nothing: the signer's and the asker's agree.
    let long = AnswerAskRefusal::evaluator_refused(&"x".repeat(5000));
    let words = assert_framed(&long.explanation).to_owned();
    assert_eq!(words.chars().count(), EVALUATOR_REASON_MAX);
    assert_eq!(long.said(), long.explanation);
    // The reason's own text is no words of the signer's to quote.
    let plain = AnswerAskRefusal::new(AskRefusal::EvaluatorRefused);
    assert_eq!(plain.said(), AskRefusal::EvaluatorRefused.explain());
}
