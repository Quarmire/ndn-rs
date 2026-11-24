//! What a device's introductions allow (`policy.rs`) and why one is refused.

use ndn_foundation_types::Name;

use crate::policy::{DEPARTURE_FOR, HINT_RETRIES_MAX, IntroPolicy, IntroRefusal};

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

/// The default policy brings people's namespaces — one component or more, a
/// `/user/<hash>` — and never the root, a local scope or a name under one, nor
/// the shared `/user` or a name over it.
#[test]
fn the_default_policy_refuses_the_root_scopes_and_shared_prefixes_only() {
    let p = IntroPolicy::new();
    for ok in ["/alice", "/home/bob", "/user/3f9a", "/ia"] {
        assert_eq!(p.refuses(&n(ok)), None, "{ok}");
    }
    for refused in ["/", "/localhost", "/localhost/x", "/localhop/y", "/user"] {
        assert!(p.refuses(&n(refused)).is_some(), "{refused}");
    }
}

/// The broad names no introduction brings are exactly the original generic
/// top-level domains, `/user`, `/ndn` and the special-use names: a deployment
/// frees one by removing it, so the list is part of the contract.
#[test]
fn the_default_shared_list_is_the_documented_one() {
    let p = IntroPolicy::new();
    let shared: Vec<String> = p.shared.iter().map(Name::to_string).collect();
    assert_eq!(
        shared,
        [
            "/user", "/com", "/org", "/net", "/edu", "/gov", "/mil", "/int", "/info", "/biz",
            "/arpa", "/ndn", "/example", "/test", "/local", "/invalid"
        ]
    );
    assert_eq!(
        p.reserved.iter().map(Name::to_string).collect::<Vec<_>>(),
        ["/localhost", "/localhop"]
    );
    assert_eq!(p.min_components, 1);
    assert_eq!(p.wrong_tries_max, 16);
    assert_eq!(p.asks_queued, 32);
    assert_eq!(p.grant_for, None);
    assert_eq!(p.departure_for, DEPARTURE_FOR);
    assert_eq!(DEPARTURE_FOR.as_secs(), 7 * 24 * 3600);
    assert!(
        !p.local_candidates,
        "a stranger's code dials no local address"
    );
    assert!(p.short_code && p.hint_while_open);
    assert_eq!(
        (p.short_width, p.code_candidates, p.code_relays),
        (294, 3, 2)
    );
    // A name under a shared one is a person's; the shared one and a name over
    // it are not.
    assert_eq!(p.refuses(&n("/com/acme")), None);
    assert!(p.refuses(&n("/com")).is_some());
    let freed = IntroPolicy {
        shared: Vec::new(),
        ..IntroPolicy::new()
    };
    assert_eq!(freed.refuses(&n("/com")), None);
}

/// The minimum of components and the reserved scopes, both ways.
#[test]
fn a_namespace_under_or_over_a_reserved_name_is_refused_with_the_reason() {
    let p = IntroPolicy {
        min_components: 2,
        ..IntroPolicy::new()
    };
    assert!(p.refuses(&n("/alice")).unwrap().contains("min_components"));
    assert_eq!(p.refuses(&n("/alice/home")), None);
    assert!(p.refuses(&n("/localhost/x")).unwrap().contains("reserved"));
    assert!(p.refuses(&n("/")).unwrap().contains("root"));
    assert!(
        IntroPolicy::new()
            .refuses(&n("/user"))
            .unwrap()
            .contains("shared")
    );
}

/// Every refusal says why and what to do.
#[test]
fn every_refusal_says_why_and_what_to_do() {
    for (why, must) in [
        (
            IntroRefusal::Unknown,
            &["holds no such offer", "new code"][..],
        ),
        (IntroRefusal::Used, &["used by someone else", "new code"]),
        (IntroRefusal::Expired, &["expired", "new code"]),
        (IntroRefusal::Closed, &["closed to you", "new code"]),
        (
            IntroRefusal::WrongProof { left: 2 },
            &["secret is wrong", "check the code", "2 wrong tries left"],
        ),
        (IntroRefusal::Forged, &["someone else answered", "retry"]),
        (
            IntroRefusal::Conflict,
            &["namespace overlaps", "namespace of your own", "renew"],
        ),
        (
            IntroRefusal::InviterConflict {
                inviter: n("/alice"),
                why: "is your own".into(),
            },
            &[
                "/alice is your own",
                "nothing of it was adopted",
                "do not use",
            ],
        ),
        (
            IntroRefusal::Hint { why: "bad".into() },
            &["(bad)", "retry at most 3 times", "new code"],
        ),
        (
            IntroRefusal::HintMismatch { why: "bad".into() },
            &["(bad)", "not damage", "new code"],
        ),
        (
            IntroRefusal::GoneUnproven { why: "bad".into() },
            &["(bad)", "retry at most 3 times", "new code"],
        ),
    ] {
        let text = why.to_string();
        for part in must {
            assert!(
                text.contains(part),
                "{why:?} says {text:?}, without {part:?}"
            );
        }
    }
    assert_eq!(HINT_RETRIES_MAX, 3);
}

/// What travels is a code: a conflict of any kind goes as `Conflict`, and the
/// refusals that are only ever the joiner's own never reach the wire as
/// anything else.
#[test]
fn refusals_travel_by_code() {
    let codes = [
        (IntroRefusal::Forged, 0),
        (IntroRefusal::Unknown, 1),
        (IntroRefusal::Used, 2),
        (IntroRefusal::Expired, 3),
        (IntroRefusal::Closed, 4),
        (IntroRefusal::WrongProof { left: 9 }, 5),
        (IntroRefusal::Conflict, 6),
        (
            IntroRefusal::InviterConflict {
                inviter: n("/a"),
                why: String::new(),
            },
            6,
        ),
        (IntroRefusal::Hint { why: String::new() }, 6),
        (IntroRefusal::HintMismatch { why: String::new() }, 6),
        (IntroRefusal::GoneUnproven { why: String::new() }, 6),
    ];
    for (why, code) in codes {
        assert_eq!(why.code(), code, "{why:?}");
    }
}
