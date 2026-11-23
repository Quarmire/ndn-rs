//! Errors, refusals and next steps (spec §10).
//!
//! Under construction: the module lands behind its `wip-error` feature.

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use ndn_foundation_types::Name;

    use super::*;

    fn name(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn cut() -> Cut {
        Cut {
            device: name("/alice/phone"),
            keeps_to: 7,
        }
    }

    /// Every refusal, once. [`variant_no`] has no wildcard arm, so a new
    /// variant fails to compile there, and the count below fails here until
    /// it is listed.
    fn refusals() -> Vec<Refusal> {
        vec![
            Refusal::OutsideCut(cut()),
            Refusal::Lapsed {
                not_after: Timestamp(1_700_000_000_000),
                now: Timestamp(1_800_000_000_000),
            },
            Refusal::NotMember,
            Refusal::BadSignature,
            Refusal::Rollback,
            Refusal::Unsealed,
            Refusal::Sealed,
            Refusal::Suspected {
                key: name("/alice/phone/KEY/k1"),
                since: Timestamp(1_700_000_000_000),
            },
            Refusal::Untrusted {
                why: "the issuer is revoked".into(),
            },
            Refusal::AboveReservation { reserved: 41 },
            Refusal::Chain,
        ]
    }

    fn variant_no(r: &Refusal) -> usize {
        match r {
            Refusal::OutsideCut(_) => 0,
            Refusal::Lapsed { .. } => 1,
            Refusal::NotMember => 2,
            Refusal::BadSignature => 3,
            Refusal::Rollback => 4,
            Refusal::Unsealed => 5,
            Refusal::Sealed => 6,
            Refusal::Suspected { .. } => 7,
            Refusal::Untrusted { .. } => 8,
            Refusal::AboveReservation { .. } => 9,
            Refusal::Chain => 10,
        }
    }

    /// Every error, the refused ones once per refusal.
    fn errors() -> Vec<HeapError> {
        let n = || name("/alice/32=data/notes");
        let mut all = vec![
            HeapError::Unavailable { name: n() },
            HeapError::NotReady {
                name: n(),
                why: "the members entry is not held yet".into(),
            },
            HeapError::BadName {
                name: n(),
                why: "no 32=data component".into(),
            },
            HeapError::TooLarge {
                name: n(),
                limit: 8000,
            },
            HeapError::NotAllowed { space: n() },
            HeapError::Sealed { space: n() },
            HeapError::NotOwner { space: n() },
            HeapError::BadRequest {
                why: "an empty path names the space itself".into(),
            },
            HeapError::Local {
                reason: "the store is read-only".into(),
            },
        ];
        all.extend(refusals().into_iter().map(|why| HeapError::Refused {
            name: n(),
            why,
        }));
        all
    }

    /// The words each next step is told in; every text that ends in a step
    /// carries them.
    fn words(step: NextStep) -> &'static str {
        match step {
            NextStep::None => "nothing to do here",
            NextStep::RetryLater => "try again later",
            NextStep::AskOwner => "ask the owner",
            NextStep::UseOwnerDevice => "owner's device",
            NextStep::FixLocal => "fix this device",
            NextStep::FixName => "fix the name",
            NextStep::FixRequest => "fix the request",
        }
    }

    #[test]
    fn every_refusal_names_a_next_step() {
        assert_eq!(
            refusals()
                .iter()
                .map(variant_no)
                .collect::<BTreeSet<_>>()
                .len(),
            11,
            "the list covers every refusal"
        );
        let class = |r: Refusal| r.next();
        assert_eq!(class(Refusal::OutsideCut(cut())), NextStep::AskOwner);
        assert_eq!(class(Refusal::NotMember), NextStep::AskOwner);
        assert_eq!(
            class(Refusal::AboveReservation { reserved: 1 }),
            NextStep::AskOwner
        );
        assert_eq!(class(Refusal::BadSignature), NextStep::RetryLater);
        assert_eq!(class(Refusal::Rollback), NextStep::RetryLater);
        assert_eq!(class(Refusal::Chain), NextStep::None);
        assert_eq!(class(Refusal::Unsealed), NextStep::None);
        assert_eq!(class(Refusal::Sealed), NextStep::None);

        // The error carries its refusal's step, and a retry is exactly the
        // `RetryLater` class: nothing else may succeed unchanged.
        for e in errors() {
            assert_eq!(e.retry(), e.next() == NextStep::RetryLater, "{e:?}");
            if let HeapError::Refused { why, .. } = &e {
                assert_eq!(e.next(), why.next(), "{e:?}");
            }
        }
        assert_eq!(
            HeapError::NotOwner {
                space: name("/a/32=data/x")
            }
            .next(),
            NextStep::UseOwnerDevice
        );
        assert_eq!(
            HeapError::Sealed {
                space: name("/a/32=data/x")
            }
            .next(),
            NextStep::AskOwner
        );
        assert_eq!(
            HeapError::Local { reason: "x".into() }.next(),
            NextStep::FixLocal
        );
    }

    #[test]
    fn every_display_says_what_to_do() {
        for e in errors() {
            let text = e.to_string();
            assert!(text.len() > 40, "too terse to help: {text:?}");
            assert!(
                text.contains(words(e.next())),
                "{e:?} says `{text}` but not `{}`",
                words(e.next())
            );
            if let HeapError::Refused { why, .. } = &e {
                let inner = why.to_string();
                assert!(
                    inner.contains(words(why.next())),
                    "{why:?} says `{inner}` but not `{}`",
                    words(why.next())
                );
                assert!(text.contains(&inner), "the error carries the refusal's text");
            }
            assert!(!text.contains(['{', '}']), "debug formatting leaked: {text}");
        }
        // The lapse text is the trust crate's own, shared with the validator.
        let lapsed = Refusal::Lapsed {
            not_after: Timestamp(1_700_000_000_000),
            now: Timestamp(1_800_000_000_000),
        }
        .to_string();
        assert_eq!(
            lapsed,
            ndn_security::TrustError::lapse_text(1_700_000_000_000, 1_800_000_000_000)
        );
        // The cut's refusal names the device and the seq it keeps to.
        let outside = Refusal::OutsideCut(cut()).to_string();
        assert!(outside.contains("/alice/phone") && outside.contains('7'));
    }

    /// ndf's `From<NAMEError> for ndf::Error` (`ndf/src/error.rs:95-117`,
    /// re-pinned onto these variants), mirrored locally: the `Code` and
    /// `Next` classes ndf can produce from a [`HeapError`].
    mod ndf {
        use super::*;

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Code {
            NotMember,
            Refused,
            RetryLater,
            BadPath,
            Local,
        }

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Next {
            Nothing,
            Retry,
            AskOwner,
            OwnerDevice,
            FixInput,
            FixLocal,
        }

        impl From<NextStep> for Next {
            fn from(step: NextStep) -> Next {
                match step {
                    NextStep::None => Next::Nothing,
                    NextStep::RetryLater => Next::Retry,
                    NextStep::AskOwner => Next::AskOwner,
                    NextStep::UseOwnerDevice => Next::OwnerDevice,
                    NextStep::FixName | NextStep::FixRequest => Next::FixInput,
                    NextStep::FixLocal => Next::FixLocal,
                }
            }
        }

        pub fn of(e: &HeapError) -> (Code, Next) {
            let code = match e {
                HeapError::Unavailable { .. } | HeapError::NotReady { .. } => Code::RetryLater,
                HeapError::BadName { .. } | HeapError::TooLarge { .. } => Code::BadPath,
                HeapError::NotAllowed { .. } | HeapError::Sealed { .. } => Code::NotMember,
                HeapError::Refused { why, .. } => match why {
                    Refusal::OutsideCut(_)
                    | Refusal::Lapsed { .. }
                    | Refusal::NotMember
                    | Refusal::Suspected { .. }
                    | Refusal::AboveReservation { .. } => Code::NotMember,
                    Refusal::BadSignature | Refusal::Rollback => Code::RetryLater,
                    _ => Code::Refused,
                },
                HeapError::Local { .. } => Code::Local,
                _ => Code::Refused,
            };
            (code, e.next().into())
        }
    }

    #[test]
    fn ndfs_error_mapping_table() {
        use ndf::{Code, Next};
        let n = || name("/alice/32=data/notes");
        let of = |e: HeapError| ndf::of(&e);
        assert_eq!(
            of(HeapError::NotReady { name: n(), why: "x".into() }),
            (Code::RetryLater, Next::Retry)
        );
        assert_eq!(
            of(HeapError::Unavailable { name: n() }),
            (Code::RetryLater, Next::Retry)
        );
        assert_eq!(
            of(HeapError::BadName { name: n(), why: "x".into() }),
            (Code::BadPath, Next::FixInput)
        );
        assert_eq!(
            of(HeapError::TooLarge { name: n(), limit: 1 }),
            (Code::BadPath, Next::FixInput)
        );
        assert_eq!(
            of(HeapError::Sealed { space: n() }),
            (Code::NotMember, Next::AskOwner)
        );
        assert_eq!(
            of(HeapError::NotAllowed { space: n() }),
            (Code::NotMember, Next::AskOwner)
        );
        assert_eq!(
            of(HeapError::NotOwner { space: n() }),
            (Code::Refused, Next::OwnerDevice)
        );
        assert_eq!(
            of(HeapError::BadRequest { why: "x".into() }),
            (Code::Refused, Next::FixInput)
        );
        assert_eq!(
            of(HeapError::Local { reason: "disk".into() }),
            (Code::Local, Next::FixLocal)
        );
        for why in refusals() {
            let e = HeapError::Refused { name: n(), why: why.clone() };
            let (code, next) = of(e);
            match &why {
                Refusal::BadSignature | Refusal::Rollback => {
                    assert_eq!((code, next), (Code::RetryLater, Next::Retry), "{why:?}");
                }
                Refusal::OutsideCut(_)
                | Refusal::Lapsed { .. }
                | Refusal::NotMember
                | Refusal::Suspected { .. }
                | Refusal::AboveReservation { .. } => {
                    assert_eq!((code, next), (Code::NotMember, Next::AskOwner), "{why:?}");
                }
                Refusal::Untrusted { .. } => {
                    assert_eq!((code, next), (Code::Refused, Next::AskOwner), "{why:?}");
                }
                Refusal::Unsealed | Refusal::Sealed | Refusal::Chain => {
                    assert_eq!((code, next), (Code::Refused, Next::Nothing), "{why:?}");
                }
            }
        }
    }
}
