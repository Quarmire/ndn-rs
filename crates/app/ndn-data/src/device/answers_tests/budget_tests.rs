//! What an evaluation and the check of a signed answer's reads may spend (`docs/specs/answers.md`
//! §10, §13.10): `Reads::current` is counted against the reads budget, an evaluation and a
//! held-reads check run off the executor and within a time budget, over the time is a refusal,
//! the `St` lock is held only per read, and an answer that lists more reads of merge states than
//! the device checks is refused with the reason.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::super::answer_reads::{ReadFail, STATE_READS_CHECKED_MAX};
use super::*;
use crate::NextStep;
use crate::rt::Cancel;
use crate::version::{Frontier, Parents, Seq};

type Hook = Box<dyn Fn(&dyn ReadView) -> Result<(), EvalError> + Send + Sync>;

/// An evaluator of the cases' shape (the definition lists collections; it reads the newest of
/// each) whose plan calls `current` `currents` times per input and whose evaluation runs `hook`
/// after its reads.
struct Probe {
    name: Name,
    currents: usize,
    hook: Hook,
}

fn probe_v(v: u64) -> Name {
    n("/conformance/eval/probe").append(format!("v={v}"))
}

fn probe(
    v: u64,
    currents: usize,
    hook: impl Fn(&dyn ReadView) -> Result<(), EvalError> + Send + Sync + 'static,
) -> Arc<dyn Evaluator> {
    Arc::new(Probe {
        name: probe_v(v),
        currents,
        hook: Box::new(hook),
    })
}

#[async_trait::async_trait]
impl Evaluator for Probe {
    fn evaluator(&self) -> &Name {
        &self.name
    }

    async fn plan(&self, def: &Definition, reads: &mut dyn Reads) -> Result<(), PlanError> {
        for c in inputs_of(def)? {
            let mut found = None;
            for _ in 0..self.currents {
                found = Some(reads.current(&c).await?.0);
            }
            reads
                .read(&found.expect("a plan that calls current"))
                .await?;
        }
        Ok(())
    }

    fn evaluate(&self, def: &Definition, view: &dyn ReadView) -> Result<Bytes, EvalError> {
        for c in inputs_of(def)? {
            let r = view.current(&c)?;
            view.read(r)?;
        }
        (self.hook)(view)?;
        Ok(Bytes::from_static(b"ok"))
    }
}

fn default_budget() -> Budget {
    AnswerConfig::default().budget
}

/// Alice's laptop with the data of the cases, knowing `ev`, spending at most `budget`.
async fn laptop_with(w: &mut World, ev: Arc<dyn Evaluator>, budget: Budget) -> Device {
    alice_with_data(w, move |c| Config {
        evaluators: Evaluators::none().with(ev),
        answers: AnswerConfig {
            budget,
            ..AnswerConfig::default()
        },
        ..c
    })
    .await
}

async fn probe_question(dev: &Device, v: u64) -> Name {
    pure_question(newest(dev, &plan()).await, &probe_v(v))
}

/// How long a case waits for what it expects to happen at all before it calls it broken: a
/// bound for a failure, never what a pass depends on.
const POLLS: usize = 5_000;

/// An answer name no one signed, for the errors of a check.
fn some_answer() -> Name {
    wire::answer_name(&n("/alice/laptop"), &[7; 32])
}

/// A read of the state of a merge collection no device holds, the `i`th.
fn state_read(i: usize) -> ReadRef {
    let mut at = Parents::new();
    at.insert(
        &VersionId {
            writer: Writer::new(super::super::group_tests::key("/alice/laptop")),
            seq: Seq(1),
        },
        Some([i as u8; 32]),
    );
    ReadRef::State {
        collection: n("/alice/32=data/many").append(format!("c{i}")),
        rule: n("/test/merge/notes/v=1"),
        at,
        applied: Hash([0; 32]),
    }
}

pub(super) fn many_states(count: usize) -> ReadSet {
    ReadSet::new((0..count).map(state_read)).unwrap()
}

// ---- Reads::current is counted ------------------------------------------------------------------

#[tokio::test]
async fn a_plan_that_calls_current_over_and_over_spends_the_reads_budget() {
    let tight = Budget {
        reads: 10,
        ..default_budget()
    };
    // A few calls fit: the definition, three of `current`, one read.
    let mut w = World::new();
    let few = laptop_with(&mut w, probe(1, 3, |_| Ok(())), tight).await;
    let q = probe_question(&few, 1).await;
    assert_eq!(ask(&few, &q).await.unwrap().result, "ok");

    // A thousand do not: the reads budget is spent by the calls, though they read nothing new.
    let mut w2 = World::new();
    let many = laptop_with(&mut w2, probe(1, 1_000, |_| Ok(())), tight).await;
    let q = probe_question(&many, 1).await;
    let e = ask(&many, &q).await.unwrap_err();
    assert!(
        matches!(
            &e,
            DataError::Answer { why: AnswerRefusal::OverBudget { what }, .. } if what.contains("reads")
        ),
        "{e:?}"
    );
    assert_eq!(e.next(), NextStep::FixLocal);
    assert!(
        e.to_string().contains("raise Config::answers.budget"),
        "the refusal says what to do: {e}"
    );
}

// ---- off the executor, within a time -------------------------------------------------------------

#[tokio::test]
async fn a_device_operation_completes_while_an_evaluation_runs() {
    // The evaluation waits until an operation of the same device, run as a task of this
    // (single-threaded) runtime, has completed and told it so. If the evaluation held up the
    // executor, or the lock the operation needs, it never would: it gives up after POLLS
    // polls, which only a failure reaches.
    let done = Arc::new(AtomicBool::new(false));
    let seen = Arc::new(AtomicBool::new(false));
    let hook = {
        let (done, seen) = (Arc::clone(&done), Arc::clone(&seen));
        move |_: &dyn ReadView| {
            for _ in 0..POLLS {
                if done.load(Ordering::SeqCst) {
                    seen.store(true, Ordering::SeqCst);
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(EvalError::Refused(
                "the operation of the device did not complete while this evaluation ran".into(),
            ))
        }
    };
    let mut w = World::new();
    let laptop = laptop_with(&mut w, probe(1, 1, hook), default_budget()).await;
    let q = probe_question(&laptop, 1).await;
    let op = {
        let (laptop, done) = (laptop.clone(), Arc::clone(&done));
        tokio::spawn(async move {
            let got = laptop.get(&budget()).await;
            done.store(true, Ordering::SeqCst);
            got.is_ok()
        })
    };
    let answered = ask(&laptop, &q).await.unwrap();
    assert_eq!(answered.result, "ok");
    assert!(seen.load(Ordering::SeqCst));
    assert!(op.await.unwrap(), "the operation's own result");
}

#[tokio::test]
async fn an_evaluation_over_its_time_is_refused_and_is_told_to_stop() {
    let stopped = Arc::new(AtomicBool::new(false));
    let hook = {
        let stopped = Arc::clone(&stopped);
        move |view: &dyn ReadView| {
            for _ in 0..POLLS {
                if view.cancelled() {
                    stopped.store(true, Ordering::SeqCst);
                    return Err(EvalError::Refused("cancelled".into()));
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Ok(())
        }
    };
    let tiny = Budget {
        time: Duration::from_millis(20),
        ..default_budget()
    };
    let mut w = World::new();
    let laptop = laptop_with(&mut w, probe(1, 1, hook), tiny).await;
    let q = probe_question(&laptop, 1).await;
    let e = ask(&laptop, &q).await.unwrap_err();
    assert!(
        matches!(
            &e,
            DataError::Answer { why: AnswerRefusal::OverBudget { what }, .. } if what.contains("time")
        ),
        "{e:?}"
    );
    assert_eq!(e.next(), NextStep::FixLocal);
    assert!(
        e.to_string().contains("raise Config::answers.budget"),
        "the refusal says what to do: {e}"
    );
    for _ in 0..POLLS {
        if stopped.load(Ordering::SeqCst) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    panic!("the evaluation was never told to stop");
}

#[tokio::test]
async fn an_evaluation_that_never_checks_its_time_is_abandoned_at_its_deadline() {
    // The evaluation blocks until the case releases it, after the refusal: only the watchdog
    // can end the wait. (It gives up after 30 s on its own, so a failure ends.)
    let (release, held) = std::sync::mpsc::channel::<()>();
    let held = std::sync::Mutex::new(held);
    let hook = move |_: &dyn ReadView| {
        let _ = held.lock().unwrap().recv_timeout(Duration::from_secs(30));
        Ok(())
    };
    let tiny = Budget {
        time: Duration::from_millis(20),
        ..default_budget()
    };
    let mut w = World::new();
    let laptop = laptop_with(&mut w, probe(1, 1, hook), tiny).await;
    let q = probe_question(&laptop, 1).await;
    let e = ask(&laptop, &q).await.unwrap_err();
    let _ = release.send(());
    assert!(
        matches!(
            &e,
            DataError::Answer { why: AnswerRefusal::OverBudget { what }, .. } if what.contains("time")
        ),
        "{e:?}"
    );
}

// ---- the check of a signed answer's reads --------------------------------------------------------

#[tokio::test]
async fn an_answer_listing_more_state_reads_than_the_cap_is_refused_with_the_reason() {
    let mut w = World::new();
    let laptop = laptop_with(&mut w, probe(1, 1, |_| Ok(())), default_budget()).await;
    // At the cap: checked, none of its states held here.
    let at_cap = many_states(STATE_READS_CHECKED_MAX);
    let Ok(checked) = laptop.inner.check_reads(&some_answer(), &at_cap, &[]).await else {
        panic!("an answer at the cap is checked");
    };
    assert_eq!(checked.unverified as usize, STATE_READS_CHECKED_MAX);
    // One over: refused whole.
    let over = many_states(STATE_READS_CHECKED_MAX + 1);
    let Err(ReadFail::Data(e)) = laptop.inner.check_reads(&some_answer(), &over, &[]).await else {
        panic!("an answer over the cap is refused");
    };
    assert!(
        matches!(
            &e,
            DataError::Answer {
                why: AnswerRefusal::TooManyStates { states, limit },
                ..
            } if *states as usize == STATE_READS_CHECKED_MAX + 1 && *limit as usize == STATE_READS_CHECKED_MAX
        ),
        "{e:?}"
    );
    assert_eq!(e.next(), NextStep::FixRequest);
    assert!(
        e.to_string()
            .contains("ask its signer for an answer over fewer states"),
        "the refusal says what to do: {e}"
    );
}

#[tokio::test]
async fn the_state_lock_is_free_between_two_reads_of_a_check() {
    let mut w = World::new();
    let laptop = laptop_with(&mut w, probe(1, 1, |_| Ok(())), default_budget()).await;
    let set = many_states(64);
    let between = AtomicUsize::new(0);
    let checked = laptop.inner.check_reads_with(
        &set,
        &Cancel::within(Duration::from_secs(3600)),
        &mut || {
            between.fetch_add(1, Ordering::SeqCst);
            assert!(
                laptop.inner.st.try_lock().is_some(),
                "the St lock is held between two reads of a check, so no device operation \
                 can run until the whole check is done"
            );
        },
    );
    assert!(checked.is_some_and(|c| c.is_ok()));
    assert_eq!(between.load(Ordering::SeqCst), 64);
}

#[tokio::test]
async fn a_check_of_reads_over_its_time_is_a_refusal_never_trust() {
    let none = Budget {
        time: Duration::ZERO,
        ..default_budget()
    };
    let mut w = World::new();
    let laptop = laptop_with(&mut w, probe(1, 1, |_| Ok(())), none).await;
    let set = many_states(64);
    let Err(ReadFail::Data(e)) = laptop.inner.check_reads(&some_answer(), &set, &[]).await else {
        panic!("a check over its time is not a result");
    };
    assert!(
        matches!(
            &e,
            DataError::Answer { why: AnswerRefusal::OverBudget { what }, .. } if what.contains("time")
        ),
        "{e:?}"
    );
    assert_eq!(e.next(), NextStep::FixLocal);
}

// ---- what a read costs ---------------------------------------------------------------------------

/// `St::state_facts` for the reads a signed answer lists (answers.md §10): what it costs on a
/// merge collection of each size, at its newest frontier and at one in its past, so the cap on
/// the reads of states checked per answer has a number behind it. Run it on its own:
/// `cargo test --release -p ndn-data state_facts_cost -- --ignored --nocapture`.
#[tokio::test]
#[ignore = "a measurement, not a case"]
async fn state_facts_cost_of_a_listed_read() {
    use super::super::merge_tests as m;
    for versions in [8usize, 64, 512] {
        let mut w = World::new();
        let laptop = w
            .start("/alice/laptop", |c| Config {
                rules: m::rules(),
                ..c
            })
            .await;
        let c = m::c();
        laptop
            .share(
                &c,
                Share {
                    rule: Rule::Merge {
                        function: n(m::RULE),
                    },
                    writers: vec![n("/alice")],
                    readers: Vec::new(),
                },
            )
            .await
            .unwrap();
        for i in 0..versions {
            laptop
                .put_op(&c, m::edit(None, &format!("note {i}")), options())
                .await
                .unwrap();
        }
        let me = laptop.inner.writer.clone();
        let mut halfway = Frontier::new();
        halfway.include(&VersionId {
            writer: me.clone(),
            seq: Seq(versions as u64 / 2),
        });
        let now = laptop.inner.st.lock().colls[&c].at().clone();
        let rules = laptop.inner.config.rules.clone();
        for (label, at) in [("newest", now), ("halfway", halfway)] {
            let runs = 200;
            let st = laptop.inner.st.lock();
            let began = std::time::Instant::now();
            for _ in 0..runs {
                assert!(st.state_facts(&c, &at, &rules, &me).is_some());
            }
            let each = began.elapsed().as_nanos() / runs;
            println!(
                "state_facts, {versions:>4} versions, {label:>7} frontier: {each:>9} ns/read, \
                 {:>8.1} ms for {} reads",
                each as f64 * 65_536.0 / 1e6,
                65_536
            );
        }
    }
    // A signed answer of the most reads, one of a merge collection held and the rest not: the
    // whole check.
    let mut w = World::new();
    let laptop = laptop_with(&mut w, probe(1, 1, |_| Ok(())), default_budget()).await;
    let set = many_states(crate::answer::READS_MAX);
    let began = std::time::Instant::now();
    let checked = laptop
        .inner
        .check_reads_with(&set, &Cancel::within(Duration::from_secs(3600)), &mut || {})
        .unwrap();
    println!(
        "check of {} reads of states not held: {} ns/read, {:.1} ms (unverified {})",
        set.reads().len(),
        began.elapsed().as_nanos() / set.reads().len() as u128,
        began.elapsed().as_secs_f64() * 1e3,
        checked.map(|c| c.unverified).unwrap_or(0)
    );
}
