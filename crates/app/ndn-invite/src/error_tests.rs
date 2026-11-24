//! The error (`error.rs`): what to do about each, and that each says why.

use ndn_foundation_types::Name;
use ndn_heap::{HeapError, NextStep};

use crate::error::InviteError;
use crate::policy::IntroRefusal;

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

fn refusals() -> Vec<IntroRefusal> {
    vec![
        IntroRefusal::Unknown,
        IntroRefusal::Used,
        IntroRefusal::Expired,
        IntroRefusal::Closed,
        IntroRefusal::WrongProof { left: 1 },
        IntroRefusal::Forged,
        IntroRefusal::Conflict,
        IntroRefusal::InviterConflict {
            inviter: n("/alice"),
            why: "is your own".into(),
        },
        IntroRefusal::Hint { why: "bad".into() },
        IntroRefusal::HintMismatch { why: "bad".into() },
        IntroRefusal::GoneUnproven { why: "bad".into() },
    ]
}

/// The mapping `ndf`'s `Code::BadCode` and the hosts act on: what each refusal
/// of an introduction asks of the caller.
#[test]
fn a_refusal_maps_to_the_next_step_the_old_layer_gave() {
    for (why, step) in [
        (IntroRefusal::WrongProof { left: 1 }, NextStep::FixRequest),
        (IntroRefusal::Forged, NextStep::RetryLater),
        (IntroRefusal::Hint { why: "x".into() }, NextStep::RetryLater),
        (
            IntroRefusal::GoneUnproven { why: "x".into() },
            NextStep::RetryLater,
        ),
        (IntroRefusal::Conflict, NextStep::FixLocal),
        (IntroRefusal::Unknown, NextStep::AskOwner),
        (IntroRefusal::Used, NextStep::AskOwner),
        (IntroRefusal::Expired, NextStep::AskOwner),
        (IntroRefusal::Closed, NextStep::AskOwner),
        (
            IntroRefusal::HintMismatch { why: "x".into() },
            NextStep::AskOwner,
        ),
        (
            IntroRefusal::InviterConflict {
                inviter: n("/a"),
                why: "x".into(),
            },
            NextStep::AskOwner,
        ),
    ] {
        let e = InviteError::Refused(why.clone());
        assert_eq!(e.next(), step, "{why:?}");
        assert_eq!(e.retry(), step == NextStep::RetryLater, "{why:?}");
        assert_eq!(e.refusal(), Some(&why));
    }
}

/// An error that is not a refusal names none, and keeps the next step of what
/// it wraps.
#[test]
fn the_other_variants_keep_the_step_of_what_they_wrap() {
    let heap = HeapError::NotReady {
        name: n("/alice/32=data/notes"),
        why: "the epoch key is not held".into(),
    };
    let wrapped = InviteError::from(heap.clone());
    assert_eq!(wrapped, InviteError::Heap(heap.clone()));
    assert_eq!(wrapped.next(), heap.next());
    assert!(wrapped.retry());
    assert_eq!(wrapped.refusal(), None);
    assert!(wrapped.to_string().contains("the epoch key is not held"));

    let local = InviteError::local("the store is full");
    assert_eq!(local.next(), NextStep::FixLocal);
    assert!(!local.retry());
    assert!(local.to_string().contains("the store is full"));

    let not_ready = InviteError::NotReady {
        name: n("/alice/32=data/notes"),
        why: "the admitting entry is not held yet".into(),
    };
    assert_eq!(not_ready.next(), NextStep::RetryLater);
    assert!(not_ready.retry());

    let bad = InviteError::BadRequest {
        why: "an offer allows one wrong try or more".into(),
    };
    assert_eq!(bad.next(), NextStep::FixRequest);
    assert!(!bad.retry());
}

/// Every error says why, and what to do about it, in its own words; a refusal
/// carries the refusal's text whole.
#[test]
fn every_error_says_why_and_what_to_do() {
    for why in refusals() {
        let text = InviteError::Refused(why.clone()).to_string();
        assert!(text.contains(&why.to_string()), "{text}");
        assert!(text.contains("refused"), "{text}");
    }
    let not_ready = InviteError::NotReady {
        name: n("/alice/32=data/notes"),
        why: "the epoch key is not held".into(),
    }
    .to_string();
    let space = n("/alice/32=data/notes").to_string();
    for part in [space.as_str(), "the epoch key is not held", "try again"] {
        assert!(not_ready.contains(part), "{not_ready}");
    }
    let local = InviteError::local("disk full").to_string();
    assert!(
        local.contains("disk full") && local.contains("fix this device"),
        "{local}"
    );
    let bad = InviteError::BadRequest { why: "x".into() }.to_string();
    assert!(
        bad.contains("x") && bad.contains("fix the request"),
        "{bad}"
    );
}
