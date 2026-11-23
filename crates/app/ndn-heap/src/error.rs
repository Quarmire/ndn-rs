//! Errors, refusals and next steps (spec §10).
//!
//! Every [`HeapError`] says why in its message and what to do in
//! [`HeapError::next`]; [`HeapError::retry`] tells whether the same call,
//! unchanged, can succeed later. Failures the layer degrades instead
//! ("stale, never wrong") are not errors: a read answers what it holds. A
//! pending entry (one whose signer's certificate is not held yet) is not a
//! refusal either: it waits.

use std::fmt;

use ndn_foundation_types::Name;

/// What the caller can do about an error, by class. A host words the step
/// itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NextStep {
    /// Nothing the caller can do: the outcome is final and correct.
    None,
    /// Ask again later, unchanged: no path or holder answered, or this copy
    /// is bad and another may be good.
    RetryLater,
    /// Ask the space's owner: for membership, a reading key, or the
    /// re-admission of work a cut refused.
    AskOwner,
    /// Do it on a device holding the owner's key.
    UseOwnerDevice,
    /// Fix this device: its storage or its keys.
    FixLocal,
    /// Ask again with a name the layer can use: the error says how such a
    /// name is formed.
    FixName,
    /// Ask again as the error says: the request, as given, asks for
    /// something no device does.
    FixRequest,
}

/// A point in time, in milliseconds since the Unix epoch: the unit of a
/// certificate's validity and of what a trust context reports
/// ([`ndn_security::TrustError::Lapsed`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(pub u64);

impl fmt::Display for Timestamp {
    /// The instant as a UTC date-time (`20261123T101500Z`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let basic = ndn_security::iso8601::format_iso_basic(self.0.saturating_mul(1_000_000));
        write!(f, "{}Z", String::from_utf8_lossy(&basic))
    }
}

/// What a cut says about one device: the space's owner removed it, or its
/// namespace's trust context revoked its key, and the cut keeps the chain of
/// its entries only up to a tip.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Cut {
    /// The removed or revoked device, `<id>`.
    pub device: Name,
    /// The seq of the tip the cut keeps: the entries on the chain up to and
    /// including it stay valid, nothing above it and nothing off it.
    pub keeps_to: u64,
}

/// Why an entry was refused. A refused entry is never served as data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Its device was cut and the cut does not keep it, whatever date or seq
    /// it claims.
    OutsideCut(Cut),
    /// Its key's role needs a cut for Data and no certificate of the key is
    /// valid by this device's clock: the newest ended at `not_after`, and
    /// the clock reads `now`. Only this device's clock refuses it, so it is
    /// not kept as refused: it is judged again when fetched again.
    Lapsed {
        /// The last NotAfter of the key's certificates, by its CA's clock.
        not_after: Timestamp,
        /// What this device's clock read when it judged.
        now: Timestamp,
    },
    /// Its signer is not a writer of the space, by the members entries.
    NotMember,
    /// It does not verify: wrong signature, or bytes that do not match its
    /// name (a poisoned cache).
    BadSignature,
    /// It is a register value or notice older than one already seen from the
    /// same signer.
    Rollback,
    /// It is not sealed, and the members entries seal the space: its writer
    /// wrote it before hearing the entry that sealed the space.
    Unsealed,
    /// It is sealed, and the space is public: the mirror of
    /// [`Refusal::Unsealed`].
    Sealed,
    /// Its key is marked suspected on this device (it may be in a thief's
    /// hands): no new entry of it is taken while the mark stands; the
    /// entries held from before stay.
    Suspected {
        /// The key, `<id>/KEY/<k>`.
        key: Name,
        /// Since when, by this device's clock.
        since: Timestamp,
    },
    /// The durable rule, run again on its packet against the trust contexts
    /// held now, refuses it for a reason no cut can excuse: a key above its
    /// signer is revoked, or the chain is no longer authorized. It is taken
    /// back only if its key's chain verifies again.
    Untrusted {
        /// The validator's verdict.
        why: String,
    },
    /// Its `PREV` link names other bytes than the entry held at that seq
    /// (its writer named an entry that does not exist, or its key signed
    /// two at one seq): it does not extend the chain this device holds.
    Chain,
    /// The writer's entries are already held in as many separate runs, or
    /// gap statements, as this device keeps for one device
    /// (the log's cap on fragmentation), and this one would start
    /// another. It is not stored.
    Fragmented,
}

impl Refusal {
    /// What to do about it.
    pub fn next(&self) -> NextStep {
        match self {
            Refusal::OutsideCut(_)
            | Refusal::Lapsed { .. }
            | Refusal::NotMember
            | Refusal::Suspected { .. }
            | Refusal::Untrusted { .. }
            | Refusal::Fragmented => NextStep::AskOwner,
            Refusal::BadSignature | Refusal::Rollback => NextStep::RetryLater,
            Refusal::Unsealed | Refusal::Sealed | Refusal::Chain => NextStep::None,
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::OutsideCut(cut) => write!(
                f,
                "its device {} was cut (removed by the space's owner, or its key revoked by \
                 its namespace's trust context) and the cut keeps only the chain of its \
                 entries up to seq {}, which this entry is not on, whatever date or seq it \
                 claims; ask the owner (who may write the member back in, or re-admit this \
                 exact entry of a revoked key)",
                cut.device, cut.keeps_to
            ),
            Refusal::Lapsed { not_after, now } => {
                f.write_str(&ndn_security::TrustError::lapse_text(not_after.0, now.0))
            }
            Refusal::NotMember => f.write_str(
                "its key is not a writer of the space by the members entries; ask the owner to \
                 add it",
            ),
            Refusal::BadSignature => f.write_str(
                "it does not verify (signature, name or sealed payload); try again later, for \
                 it may verify when fetched from another holder",
            ),
            Refusal::Rollback => f.write_str(
                "it is older than one already seen from the same signer; try again later, for \
                 a current copy may come from another holder",
            ),
            Refusal::Unsealed => f.write_str(
                "it is not sealed, and the space is sealed: its writer wrote it before hearing \
                 the entry that sealed the space; nothing to do here, its writer writes it \
                 again, sealed",
            ),
            Refusal::Sealed => f.write_str(
                "it is sealed, and the space is public: its writer wrote it before hearing the \
                 entry that opened the space; nothing to do here, its writer writes it again, \
                 unsealed",
            ),
            Refusal::Suspected { key, since } => write!(
                f,
                "its key {key} is marked suspected on this device since {since} (it may be in \
                 a thief's hands), so no new entry of it is taken; ask the owner to finish \
                 the key's revocation (a cut bounded by when it was lost), or unsuspect the \
                 key if it is safe",
            ),
            Refusal::Untrusted { why } => write!(
                f,
                "the trust context held now no longer lets its signer's certificate chain sign \
                 it ({why}), which no cut excuses; it is taken back only once its key has a \
                 certificate from an issuer still trusted: ask the owner of the namespace to \
                 certify the writer again",
            ),
            Refusal::Chain => f.write_str(
                "its PREV link names other bytes than the entry held at that seq, so it does \
                 not extend the chain this device holds; nothing to do here, it never applies \
                 and nothing waits for it: its writer writes again over the state it holds",
            ),
            Refusal::Fragmented => f.write_str(
                "its writer's entries are already held in as many separate runs (or gap \
                 statements) as this device keeps for one device, and this one starts another; \
                 it is not stored and is asked for again once the runs between are filled; if \
                 the writer signs with gaps on purpose, ask the owner to remove it",
            ),
        }
    }
}

/// A failed call.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HeapError {
    /// Nothing by this name is held here and no holder answered.
    #[error(
        "{name} is not held here and no holder answered; try again later, when a holder is \
         reachable"
    )]
    Unavailable {
        /// The name asked for.
        name: Name,
    },
    /// What is asked cannot be done yet from what this device holds: `why`
    /// says what it waits for. The same call, unchanged, can succeed once it
    /// is held.
    #[error("{name} is not ready: {why}; try again later, unchanged")]
    NotReady {
        /// The name asked for.
        name: Name,
        /// What it waits for.
        why: String,
    },
    /// The name cannot name what the call takes: a space is
    /// `<owner>/32=data/<name>` and a path lies below it. Nothing by it can
    /// exist.
    #[error(
        "{name} is not a name of the heap: {why}; fix the name (a space is \
         `<owner>/32=data/<name>`, a path lies below it)"
    )]
    BadName {
        /// The name given.
        name: Name,
        /// Why not.
        why: String,
    },
    /// A value is larger than one entry carries, even in pieces.
    #[error(
        "a value at {name} is larger than the {limit} octets the heap carries for one path; \
         fix the name: put the parts under several names and refer to them by name"
    )]
    TooLarge {
        /// The path written.
        name: Name,
        /// The most it carries.
        limit: u64,
    },
    /// This device's key may not write into the space.
    #[error("this device may not write into {space}: {why}")]
    NotAllowed {
        /// The space.
        space: Name,
        /// Why, and what to do about it.
        why: String,
    },
    /// This device is not in the data's seal audience.
    #[error(
        "{space} is sealed to an audience this device is not in; ask the owner to add this \
         person as a reader"
    )]
    Sealed {
        /// The space.
        space: Name,
    },
    /// Only the space's owner signs its members entries.
    #[error("only the owner of {space} may change its members; use the owner's device")]
    NotOwner {
        /// The space.
        space: Name,
    },
    /// An entry is refused.
    #[error("{name} is refused: {why}")]
    Refused {
        /// The entry's name.
        name: Name,
        /// Why.
        why: Refusal,
    },
    /// The request asks for something no device does as given.
    #[error("the request cannot be done as given: {why}; fix the request")]
    BadRequest {
        /// Why, and what to ask instead.
        why: String,
    },
    /// A local failure: storage or keys.
    #[error("local failure: {reason}; fix this device (its storage or its keys)")]
    Local {
        /// What failed.
        reason: String,
    },
}

impl HeapError {
    /// Whether the same call, unchanged, can succeed later.
    pub fn retry(&self) -> bool {
        self.next() == NextStep::RetryLater
    }

    /// What to do about it.
    pub fn next(&self) -> NextStep {
        match self {
            HeapError::Unavailable { .. } | HeapError::NotReady { .. } => NextStep::RetryLater,
            HeapError::BadName { .. } | HeapError::TooLarge { .. } => NextStep::FixName,
            HeapError::Refused { why, .. } => why.next(),
            HeapError::NotAllowed { .. } | HeapError::Sealed { .. } => NextStep::AskOwner,
            HeapError::NotOwner { .. } => NextStep::UseOwnerDevice,
            HeapError::BadRequest { .. } => NextStep::FixRequest,
            HeapError::Local { .. } => NextStep::FixLocal,
        }
    }
}

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
            Refusal::Chain,
            Refusal::Fragmented,
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
            Refusal::Chain => 10,
            Refusal::Fragmented => 12,
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
            HeapError::NotAllowed {
                space: n(),
                why: "its person is no writer; ask the owner to add it".into(),
            },
            HeapError::Sealed { space: n() },
            HeapError::NotOwner { space: n() },
            HeapError::BadRequest {
                why: "an empty path names the space itself".into(),
            },
            HeapError::Local {
                reason: "the store is read-only".into(),
            },
        ];
        all.extend(
            refusals()
                .into_iter()
                .map(|why| HeapError::Refused { name: n(), why }),
        );
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
        assert_eq!(class(Refusal::BadSignature), NextStep::RetryLater);
        assert_eq!(class(Refusal::Rollback), NextStep::RetryLater);
        assert_eq!(class(Refusal::Chain), NextStep::None);
        assert_eq!(class(Refusal::Fragmented), NextStep::AskOwner);
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
                assert!(
                    text.contains(&inner),
                    "the error carries the refusal's text"
                );
            }
            assert!(
                !text.contains(['{', '}']),
                "debug formatting leaked: {text}"
            );
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
                    | Refusal::Suspected { .. } => Code::NotMember,
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
            of(HeapError::NotReady {
                name: n(),
                why: "x".into()
            }),
            (Code::RetryLater, Next::Retry)
        );
        assert_eq!(
            of(HeapError::Unavailable { name: n() }),
            (Code::RetryLater, Next::Retry)
        );
        assert_eq!(
            of(HeapError::BadName {
                name: n(),
                why: "x".into()
            }),
            (Code::BadPath, Next::FixInput)
        );
        assert_eq!(
            of(HeapError::TooLarge {
                name: n(),
                limit: 1
            }),
            (Code::BadPath, Next::FixInput)
        );
        assert_eq!(
            of(HeapError::Sealed { space: n() }),
            (Code::NotMember, Next::AskOwner)
        );
        assert_eq!(
            of(HeapError::NotAllowed {
                space: n(),
                why: "x".into()
            }),
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
            of(HeapError::Local {
                reason: "disk".into()
            }),
            (Code::Local, Next::FixLocal)
        );
        for why in refusals() {
            let e = HeapError::Refused {
                name: n(),
                why: why.clone(),
            };
            let (code, next) = of(e);
            match &why {
                Refusal::BadSignature | Refusal::Rollback => {
                    assert_eq!((code, next), (Code::RetryLater, Next::Retry), "{why:?}");
                }
                Refusal::OutsideCut(_)
                | Refusal::Lapsed { .. }
                | Refusal::NotMember
                | Refusal::Suspected { .. } => {
                    assert_eq!((code, next), (Code::NotMember, Next::AskOwner), "{why:?}");
                }
                Refusal::Untrusted { .. } | Refusal::Fragmented => {
                    assert_eq!((code, next), (Code::Refused, Next::AskOwner), "{why:?}");
                }
                Refusal::Unsealed | Refusal::Sealed | Refusal::Chain => {
                    assert_eq!((code, next), (Code::Refused, Next::Nothing), "{why:?}");
                }
            }
        }
    }
}
