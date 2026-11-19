//! The signer's checks of the reads of an ask and its caps (round 8), judged on the functions
//! themselves: what is held and what is not, how many reads, how many asks.

use super::super::answer_ask::{Gate, Standing};
use super::ask_cost_tests::{fetching_nothing, flood, ghost_ask};
use super::ask_tests::{Told, counting, describe, serving, told};
use super::budget_tests::many_states;
use super::*;
use crate::answer::{AnswerKind, AskRefusal, AskServing};
use futures::FutureExt;

fn gate(asker: &str, ns: &str) -> Gate {
    Gate {
        asker: n(asker),
        ns: n(ns),
        members: false,
    }
}

/// The reads of the plan and of the budget, which Alice's laptop holds.
async fn held_reads(laptop: &Device) -> ReadSet {
    ReadSet::new([
        newest(laptop, &plan()).await,
        newest(laptop, &budget()).await,
    ])
    .unwrap()
}

#[tokio::test]
async fn a_read_the_signer_does_not_hold_is_never_admitted_once_the_reads_are_to_be_held() {
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, serving(vec![sum(1)], AskServing::Own, 4)).await;
    let ghost = ghost_ask(&laptop).await.reads.unwrap();
    let phone = gate("/alice/phone", "/alice");

    // Before the reads are fetched, what is not held yet is left to the check that follows the
    // fetch; after it, a read whose version and records are not held is not told as admitted
    // (the signer cannot know the audience), but that it is not held yet.
    assert_eq!(laptop.inner.gate_reads(&phone, &ghost, false).await, Ok(()));
    assert!(
        matches!(
            laptop.inner.gate_reads(&phone, &ghost, true).await,
            Err(AskRefusal::Pending { .. })
        ),
        "an unheld read is pending, not admitted"
    );
    // What is held and unsealed is admitted either way.
    let held = held_reads(&laptop).await;
    for strict in [false, true] {
        assert_eq!(laptop.inner.gate_reads(&phone, &held, strict).await, Ok(()));
    }
}

#[tokio::test]
async fn a_read_sealed_to_an_audience_admits_its_audience_and_no_other_device() {
    let mut w = World::new();
    let laptop = sealed_alice(&mut w, knowing(vec![sum(1)]), &["/alice"]).await;
    let held = held_reads(&laptop).await;
    let alice = gate("/alice/phone", "/alice");
    let bob = gate("/bob/laptop", "/bob");
    for strict in [false, true] {
        assert_eq!(laptop.inner.gate_reads(&alice, &held, strict).await, Ok(()));
        assert!(
            matches!(
                laptop.inner.gate_reads(&bob, &held, strict).await,
                Err(AskRefusal::NotAudience { .. })
            ),
            "Bob is no reader"
        );
    }
    // The standing of one epoch: the records are held here, so it is judged, not unknown.
    let ReadRef::Version { name, .. } = newest(&laptop, &budget()).await else {
        panic!("a version");
    };
    let super::super::answer_reads::VersionFact::Held {
        epoch: Some(epoch), ..
    } = laptop.inner.st.lock().version_fact(&name)
    else {
        panic!("a sealed version is held with its epoch");
    };
    let st = laptop.inner.st.lock();
    let asked = |who: &str, ns: &str| {
        laptop
            .inner
            .epoch_standing(&st, &budget(), &epoch, &n(who), &n(ns))
    };
    assert_eq!(asked("/alice/phone", "/alice"), Standing::In);
    assert_eq!(asked("/bob/laptop", "/bob"), Standing::Out);
    // A collection no record of is held says nothing.
    assert_eq!(
        laptop.inner.epoch_standing(
            &st,
            &n("/alice/32=data/other"),
            &epoch,
            &n("/alice/phone"),
            &n("/alice")
        ),
        Standing::NotHeld
    );
}

#[tokio::test]
async fn more_reads_of_states_than_are_checked_are_refused_without_the_state_lock() {
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, serving(vec![sum(1)], AskServing::Own, 4)).await;
    let phone = gate("/alice/phone", "/alice");
    // The most an Interest could be made to carry is far beyond what a check of merge states
    // takes: refused for that at once, on the first look and before anything else, with the
    // lock of the whole device held by someone else the whole time (a check that took it would
    // wait, and the one look would find it not done).
    for count in [1_025, 65_536] {
        let reads = many_states(count);
        let lock = laptop.inner.st.lock();
        let told = laptop
            .inner
            .gate_reads(&phone, &reads, false)
            .now_or_never();
        drop(lock);
        assert!(
            matches!(told, Some(Err(AskRefusal::OverBudget))),
            "{count} states: {told:?}"
        );
    }
    let refusal = AskRefusal::OverBudget;
    assert!(
        refusal.explain().contains("smaller read set"),
        "it says what to do: {}",
        refusal.explain()
    );
    // At the most checked, the reads are judged and the lock is let go between them.
    let at_most = many_states(1_024);
    assert_eq!(
        laptop.inner.gate_reads(&phone, &at_most, false).await,
        Ok(())
    );
}

#[tokio::test]
async fn the_asks_held_while_they_are_opened_are_bounded_and_the_rest_are_dropped() {
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, serving(vec![sum(1)], AskServing::Own, 4)).await;
    let _fetched = fetching_nothing(&w, "/alice/laptop");
    let ask = AnswerAsk::pure(newest(&laptop, &plan()).await, sum_v(1));
    let cap = laptop.inner.config.answers.asks_queued;

    // Strangers of the signer's own namespace, whose proofs wait for a certificate that never
    // comes, more of them than the signer holds: the rest are dropped without a reply, at once.
    let mut set = flood(
        &laptop,
        &ask,
        (0..cap + 8).map(|i| n(&format!("/alice/ghost{i}"))),
    );
    tokio::time::sleep(Duration::from_millis(400)).await;
    let mut dropped = 0;
    while let Some(done) = set.try_join_next() {
        assert!(done.unwrap().is_none());
        dropped += 1;
    }
    assert_eq!(dropped, 8, "the asks past the {cap} held are dropped");
    assert_eq!(laptop.inner.st.lock().answer_asks.queued(), cap);
    set.abort_all();
    while set.join_next().await.is_some() {}
    assert_eq!(
        laptop.inner.st.lock().answer_asks.queued(),
        0,
        "what was held is let go"
    );
}

#[tokio::test]
async fn only_the_devices_the_policy_could_take_an_answer_from_are_sent_the_reads() {
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, knowing(vec![])).await;
    laptop
        .share(
            &n("/alice/32=data/private"),
            Share {
                rule: Rule::Log,
                writers: vec![n("/alice")],
                readers: Vec::new(),
            },
        )
        .await
        .unwrap();
    put_n(&laptop, &n("/alice/32=data/private"), 1).await;
    let phone = w.start("/alice/phone", knowing(vec![])).await;
    sync_all(&laptop, &phone);
    let shared = ReadSet::new([newest(&laptop, &budget()).await]).unwrap();
    let both = ReadSet::new([
        newest(&laptop, &budget()).await,
        newest(&laptop, &n("/alice/32=data/private")).await,
    ])
    .unwrap();
    let candidates = vec![n("/alice/laptop"), n("/bob/laptop"), n("/carol/laptop")];
    let by = sum_v(1);

    // Bob and Carol write what Alice shares with them, so their answers over it are taken by
    // the default policy, and they are asked.
    assert_eq!(
        phone
            .inner
            .askable(AnswerKind::Pure, &by, &shared, candidates.clone()),
        candidates
    );
    // One read of what only Alice writes: their answers over the set would be refused, so the
    // set, which says what else its asker reads, is sent to neither.
    assert_eq!(
        phone
            .inner
            .askable(AnswerKind::Pure, &by, &both, candidates),
        vec![n("/alice/laptop")]
    );
}

#[tokio::test]
async fn a_relay_is_served_when_the_policy_names_its_role() {
    let mut w = World::new();
    let (ev, calls, _) = counting(Duration::ZERO);
    let tune = move |c: Config| Config {
        answers: AnswerConfig {
            ask_roles: vec!["admin".into(), "member".into(), "node".into()],
            ..AnswerConfig::default()
        },
        ..knowing(vec![ev])(c)
    };
    let laptop = alice_with_data(&mut w, tune).await;
    let relay = w.start("/alice/node/relay", knowing(vec![])).await;
    let guest = w.start("/alice/guest/phone", knowing(vec![])).await;
    let ask = AnswerAsk::pure(newest(&laptop, &plan()).await, sum_v(1));
    assert!(matches!(
        told(&relay, &laptop, &ask, None).await,
        Told::Answer(_)
    ));
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    // A role the policy leaves out is still refused.
    match told(&guest, &laptop, &ask, None).await {
        Told::Refused(AskRefusal::NotServed) => {}
        other => panic!("not NotServed: {}", describe(&other)),
    }
}

/// Round-8 L4: in a namespace whose context declares the role layout, a device named
/// `/<ns>/<device>` has no role the policy could name, so it is not served as the person's own;
/// a device with a role is, and a flat namespace (nothing listed) serves a role-less one as
/// before (`a_relay_is_served_when_the_policy_names_its_role` and the other cases of this file).
#[tokio::test]
async fn a_role_less_device_is_not_served_in_a_namespace_that_declares_the_role_layout() {
    let mut w = World::new().with_role_layout();
    let (ev, calls, _) = counting(Duration::ZERO);
    let laptop = alice_with_data(&mut w, knowing(vec![ev])).await;
    let phone = w.start("/alice/phone", knowing(vec![])).await;
    let member = w.start("/alice/member/phone", knowing(vec![])).await;
    let ask = AnswerAsk::pure(newest(&laptop, &plan()).await, sum_v(1));
    assert!(matches!(
        told(&member, &laptop, &ask, None).await,
        Told::Answer(_)
    ));
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    match told(&phone, &laptop, &ask, None).await {
        Told::Refused(AskRefusal::NotServed) => {}
        other => panic!("not NotServed: {}", describe(&other)),
    }
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "nothing was evaluated for a device that is not served"
    );
}
