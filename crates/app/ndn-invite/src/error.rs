//! The error of an introduction: what failed, why, and what to do.

use std::fmt::Display;

use ndn_foundation_types::Name;
use ndn_heap::{HeapError, NextStep};

use crate::policy::IntroRefusal;

/// A failed introduction call (`Invites::offer`, `join`, `close_offer`, …). Every
/// message says why and what to do.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum InviteError {
    /// The data layer failed: the space could not be opened, changed or waited
    /// for. Carries its own words and next step.
    #[error(transparent)]
    Heap(#[from] HeapError),
    /// An introduction was refused (spec §19): the refusal says why and what to
    /// do.
    #[error("the introduction is refused: {0}")]
    Refused(IntroRefusal),
    /// What is asked cannot be done yet from what this device holds: `why` says
    /// what it waits for. The same call, unchanged, can succeed once it is held.
    #[error("{name} is not ready: {why}; try again later, unchanged")]
    NotReady {
        /// The name asked for: the space a join waits to be admitted to, or the
        /// offer.
        name: Name,
        /// What it waits for.
        why: String,
    },
    /// The request asks for something no device does as given: a code that does
    /// not read, an offer allowing no wrong try.
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

impl InviteError {
    /// A local failure, storage or keys: `reason` says what failed.
    pub fn local(reason: impl Display) -> InviteError {
        InviteError::Local {
            reason: reason.to_string(),
        }
    }

    /// The refusal of an introduction this error is, if it is one: what a host
    /// words for its user (`Code::BadCode`).
    pub fn refusal(&self) -> Option<&IntroRefusal> {
        match self {
            InviteError::Refused(why) => Some(why),
            _ => None,
        }
    }

    /// Whether the same call, unchanged, can succeed later.
    pub fn retry(&self) -> bool {
        self.next() == NextStep::RetryLater
    }

    /// What to do about it.
    pub fn next(&self) -> NextStep {
        match self {
            InviteError::Heap(e) => e.next(),
            InviteError::NotReady { .. } => NextStep::RetryLater,
            InviteError::BadRequest { .. } => NextStep::FixRequest,
            InviteError::Local { .. } => NextStep::FixLocal,
            InviteError::Refused(why) => match why {
                IntroRefusal::WrongProof { .. } => NextStep::FixRequest,
                IntroRefusal::Forged
                | IntroRefusal::Hint { .. }
                | IntroRefusal::GoneUnproven { .. } => NextStep::RetryLater,
                IntroRefusal::Conflict => NextStep::FixLocal,
                IntroRefusal::Unknown
                | IntroRefusal::Used
                | IntroRefusal::Expired
                | IntroRefusal::Closed
                | IntroRefusal::HintMismatch { .. }
                | IntroRefusal::InviterConflict { .. } => NextStep::AskOwner,
            },
        }
    }
}
