//! What an evaluator's words may carry out of a signer (round 11 fix, answers.md §13.14, §15.6,
//! §15.9): code-8 words only to an asker admitted to every read the evaluator made, sealed under
//! the ask's own key, and cleaned of format characters and look-alike quotes.

use std::sync::atomic::{AtomicUsize, Ordering};

use ndn_security::confidentiality::ContentKey;

use super::ask_tests::{Told, asking, describe, serving, told, wired};
use super::*;
use crate::NextStep;
use crate::answer::{AnswerAskRefusal, AskRefusal, AskServing, tlv};

const HEAD: &str = "the signer's evaluator refused the definition, in its words: \"";
const TAIL: &str = "\"; fix the definition and ask again";

/// The value an evaluator's refusal quotes, as a parse error quotes the value it could not parse.
const SECRET: &str = "hunter2-not-for-bob";

/// An evaluator that refuses, quoting a value it read: the definition's field `note` (when the
/// definition lists no inputs), or the field `n` of the first input its plan reads.
struct Quoting {
    name: Name,
    plans: Arc<AtomicUsize>,
}

fn quoting_v(v: u64) -> Name {
    n("/conformance/eval/quoting").append(format!("v={v}"))
}

/// The evaluator, and how many plans it made.
fn quoting() -> (Arc<dyn Evaluator>, Arc<AtomicUsize>) {
    let plans = Arc::new(AtomicUsize::new(0));
    let ev = Arc::new(Quoting {
        name: quoting_v(1),
        plans: Arc::clone(&plans),
    });
    (ev, plans)
}

fn field(got: &Got, field: &str) -> String {
    let Got::Version(v) = got else {
        panic!("a version")
    };
    let crate::Payload::Entry(c) = &v.payload else {
        panic!("one entry")
    };
    String::from_utf8_lossy(c.get(field).expect("the field")).into_owned()
}

#[async_trait::async_trait]
impl Evaluator for Quoting {
    fn evaluator(&self) -> &Name {
        &self.name
    }

    async fn plan(&self, def: &Definition, reads: &mut dyn Reads) -> Result<(), PlanError> {
        self.plans.fetch_add(1, Ordering::SeqCst);
        let value = match inputs_of(def) {
            Ok(inputs) if !inputs.is_empty() => {
                let (r, _) = reads.current(&inputs[0]).await?;
                field(&reads.read(&r).await?, "n")
            }
            _ => field(&def.got, "note"),
        };
        Err(EvalError::Refused(format!("invalid type: string \"{value}\", expected i64")).into())
    }

    fn evaluate(&self, _: &Definition, _: &dyn ReadView) -> Result<Bytes, EvalError> {
        Err(EvalError::Refused("never evaluated".into()))
    }
}

/// `writers` write what `readers` (persons) read, sealed.
fn sealed_for(writers: &[&str], readers: &[&str]) -> Share {
    Share {
        rule: Rule::Log,
        writers: writers.iter().map(|w| n(w)).collect(),
        readers: readers.iter().map(|r| Audience::Person(n(r))).collect(),
    }
}

/// Whether the signer told the evaluator's words.
fn leaks(told: &Told) -> bool {
    matches!(told, Told::Refused(AskRefusal::EvaluatorRefused))
}

#[tokio::test]
async fn a_definition_the_asker_may_not_read_is_never_quoted_when_the_signer_has_not_held_it_yet() {
    // Alice's desk holds a note sealed to Alice alone, written after her laptop learned the
    // records: the laptop, which serves members, does not hold the version when Bob asks, so
    // the check before planning cannot judge it. Bob is a listed writer of the collection, and
    // the epoch that sealed the note dropped him.
    let (ev, plans) = quoting();
    let mut w = World::new();
    let desk = w.start("/alice/desk", knowing(vec![])).await;
    desk.share(&plan(), sealed_for(&["/alice", "/bob"], &["/alice"]))
        .await
        .unwrap();
    let (laptop, _wire) = wired(
        &mut w,
        "/alice/laptop",
        &desk,
        serving(vec![ev], AskServing::OwnAndMembers, 4),
    )
    .await;
    sync_all(&desk, &laptop);
    give_keys(&desk, &laptop, &[&plan()]);
    desk.put(
        &plan(),
        Content::new().with("note", Bytes::from(SECRET)),
        options(),
    )
    .await
    .unwrap();
    let bob = w.start("/bob/laptop", knowing(vec![])).await;
    let ask = AnswerAsk::pure(newest(&desk, &plan()).await, quoting_v(1));

    match told(&bob, &laptop, &ask, None).await {
        Told::Refused(AskRefusal::NotAudience { .. }) => {}
        other => panic!(
            "Bob, outside the epoch of the note, is told its value or something else: {}",
            describe(&other)
        ),
    }
    assert_eq!(
        plans.load(Ordering::SeqCst),
        0,
        "the evaluator never planned over a definition Bob may not read"
    );
    // Alice's own phone, of the audience, is told the words.
    let phone = w.start("/alice/phone", knowing(vec![])).await;
    let told_phone = told(&phone, &laptop, &ask, None).await;
    assert!(leaks(&told_phone), "{}", describe(&told_phone));
}

#[tokio::test]
async fn an_input_the_plan_read_past_the_definition_is_never_quoted_to_an_asker_outside_its_epoch()
{
    // Bob may read the definition, not the input it names; the plan reads the input and the
    // evaluator refuses, quoting it.
    let mut w = World::new();
    let laptop = w
        .start(
            "/alice/laptop",
            serving(vec![quoting().0], AskServing::OwnAndMembers, 4),
        )
        .await;
    laptop
        .share(
            &plan(),
            sealed_for(&["/alice", "/bob"], &["/alice", "/bob"]),
        )
        .await
        .unwrap();
    laptop
        .share(&budget(), sealed_for(&["/alice", "/bob"], &["/alice"]))
        .await
        .unwrap();
    laptop
        .put(
            &budget(),
            Content::new().with("n", Bytes::from(SECRET)),
            options(),
        )
        .await
        .unwrap();
    put_def(&laptop, &plan(), &[&budget()]).await;
    let bob = w.start("/bob/laptop", knowing(vec![])).await;
    let ask = AnswerAsk::pure(newest(&laptop, &plan()).await, quoting_v(1));

    match told(&bob, &laptop, &ask, None).await {
        Told::Refused(AskRefusal::NotAudience { index }) => {
            assert_eq!(index, 1, "the second read the plan made, the input");
        }
        other => panic!(
            "Bob is told the input's value or something else: {}",
            describe(&other)
        ),
    }
    // Alice's phone is of the audience of both and is told the words.
    let phone = w.start("/alice/phone", knowing(vec![])).await;
    let told_phone = told(&phone, &laptop, &ask, None).await;
    assert!(leaks(&told_phone), "{}", describe(&told_phone));
}

// ---- L1: the words are sealed ---------------------------------------------------------------

/// Alice's laptop, which serves its own and whose evaluator refuses in the words `reason`, and
/// her phone asking it.
async fn refusing_laptop(reason: &str) -> (Device, Device, Arc<ask_tests::Wire>, World) {
    let mut w = World::new();
    let laptop = alice_with_data(
        &mut w,
        serving(
            vec![Arc::new(Reasoning {
                name: quoting_v(2),
                reason: reason.to_owned(),
            })],
            AskServing::Own,
            4,
        ),
    )
    .await;
    let (phone, wire) = wired(
        &mut w,
        "/alice/phone",
        &laptop,
        asking("/alice/laptop", Duration::from_millis(600)),
    )
    .await;
    (laptop, phone, wire, w)
}

struct Reasoning {
    name: Name,
    reason: String,
}

#[async_trait::async_trait]
impl Evaluator for Reasoning {
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

#[tokio::test]
async fn the_words_of_code_8_are_not_in_the_replys_bytes_in_clear_and_the_asker_still_reads_them() {
    let (laptop, phone, _wire, _w) = refusing_laptop("the field zebra-quartz is wrong").await;
    let ask = AnswerAsk::pure(newest(&laptop, &plan()).await, quoting_v(2));
    let public = laptop.inner.st.lock().keys.recipient.public();
    let (name, params, _) = phone.inner.build_ask(laptop.name(), &public, &ask).unwrap();
    let reply = laptop
        .inner
        .answer_ask(&name, Some(params), None)
        .await
        .expect("the signer replies");
    for clear in [&b"zebra-quartz"[..], b"the signer's evaluator", b"refused"] {
        assert!(
            !contains(&reply, clear),
            "{} is in the reply Data in clear",
            String::from_utf8_lossy(clear)
        );
    }

    // The asker, which holds the ask's key, reads them.
    let q = pure_question(newest(&laptop, &plan()).await, &quoting_v(2));
    let refused = phone.ask_answer(&n("/alice/laptop"), &q).await;
    let Err(DataError::Answer {
        why: AnswerRefusal::AskRefused { why, said, .. },
        ..
    }) = refused
    else {
        panic!("not an AskRefused: {refused:?}");
    };
    assert_eq!(why, AskRefusal::EvaluatorRefused);
    assert!(said.contains("zebra-quartz"), "{said}");
}

/// The Content of a refusal of `code` whose explanation is `explanation`, as it was before the
/// words were sealed.
fn clear_refusal(code: u8, explanation: &[u8]) -> Bytes {
    let mut v = vec![code];
    v.extend_from_slice(&0u64.to_be_bytes());
    v.extend_from_slice(explanation);
    let mut w = ndn_tlv::TlvWriter::new();
    w.write_tlv(tlv::ANSWER_ASK_REFUSAL, &v);
    w.finish()
}

#[tokio::test]
async fn an_explanation_that_does_not_open_is_the_fixed_text_never_the_words_that_came() {
    let (laptop, phone, wire, _w) = refusing_laptop("not used").await;
    let q = pure_question(newest(&laptop, &plan()).await, &quoting_v(2));
    let said_to_asker = |content: Bytes| {
        let (wire, phone, q) = (wire.clone(), phone.clone(), q.clone());
        async move {
            *wire.forced.lock().unwrap() = Some(content);
            match phone.ask_answer(&n("/alice/laptop"), &q).await {
                Err(DataError::Answer {
                    why: AnswerRefusal::AskRefused { why, said, .. },
                    ..
                }) => (why, said),
                other => panic!("not an AskRefused: {other:?}"),
            }
        }
    };

    // Words in the clear, as the signer sent them before they were sealed.
    let (why, said) =
        said_to_asker(clear_refusal(8, format!("{HEAD}pay me{TAIL}").as_bytes())).await;
    assert_eq!(why, AskRefusal::EvaluatorRefused);
    assert_eq!(said, AskRefusal::EvaluatorRefused.explain());

    // Words sealed under another key than the ask's.
    let sealed = ContentKey::generate()
        .seal(format!("{HEAD}pay me{TAIL}").as_bytes(), b"anything")
        .to_bytes();
    let (why, said) = said_to_asker(clear_refusal(8, &sealed)).await;
    assert_eq!(why, AskRefusal::EvaluatorRefused);
    assert_eq!(said, AskRefusal::EvaluatorRefused.explain());
    assert_eq!(why.next(), NextStep::FixRequest);
}

// ---- L2: the sanitiser ----------------------------------------------------------------------

/// The words of `raw` as the signer sends them.
fn cleaned(raw: &str) -> String {
    let said = AnswerAskRefusal::evaluator_refused(raw).explanation;
    said.strip_prefix(HEAD)
        .and_then(|s| s.strip_suffix(TAIL))
        .unwrap_or_else(|| panic!("not in the frame: {said:?}"))
        .to_owned()
}

#[test]
fn zero_width_format_characters_are_dropped() {
    assert_eq!(cleaned("a\u{200b}b\u{200c}c\u{200d}d"), "abcd");
}

#[test]
fn word_joiners_and_invisible_operators_are_dropped() {
    assert_eq!(
        cleaned("a\u{2060}b\u{2061}c\u{2062}d\u{2063}e\u{2064}f"),
        "abcdef"
    );
}

#[test]
fn the_byte_order_mark_and_the_soft_hyphen_are_dropped() {
    assert_eq!(cleaned("a\u{feff}b\u{ad}c"), "abc");
}

#[test]
fn the_arabic_letter_mark_is_dropped() {
    assert_eq!(cleaned("a\u{61c}b"), "ab");
}

#[test]
fn tag_characters_are_dropped() {
    assert_eq!(cleaned("a\u{e0001}b\u{e0041}c\u{e007f}d"), "abcd");
}

#[test]
fn line_and_paragraph_separators_are_dropped() {
    assert_eq!(cleaned("a\u{2028}b\u{2029}c"), "abc");
}

#[test]
fn typographic_double_quotes_are_single_quotes() {
    for quote in [
        '\u{201c}', '\u{201d}', '\u{201e}', '\u{201f}', '\u{2033}', '\u{2036}', '\u{ff02}',
        '\u{301d}', '\u{301e}', '\u{301f}', '\u{2e42}', '\u{275d}', '\u{275e}', '\u{2ba}',
        '\u{2dd}', '\u{5f4}',
    ] {
        assert_eq!(
            cleaned(&format!("bad{quote} \u{2014} your device")),
            "bad' \u{2014} your device",
            "U+{:04X}",
            quote as u32
        );
    }
}

#[test]
fn the_asker_cleans_the_same_classes_again() {
    let raw = format!("{HEAD}a\u{200b}b\u{61c}c\u{2028}d\u{201d}e{TAIL}");
    let refusal = AnswerAskRefusal {
        why: AskRefusal::EvaluatorRefused,
        explanation: raw,
    };
    assert_eq!(refusal.said(), format!("{HEAD}abcd'e{TAIL}"));
}
