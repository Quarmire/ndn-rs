//! Why a channel could not be set up, as the caller sees it. Every variant says why and what to
//! do (`next`), in the heap's [`NextStep`] vocabulary (docs/specs/channel.md, Limits and
//! refusals).

use ndn_foundation_types::Name;

use super::wire::RefusalCode;
use crate::error::NextStep;

/// A failed channel setup.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChanError {
    /// A name that is no space, or no device.
    #[error(
        "{name} cannot be used here: {why}; fix the name (a space is `<owner>/32=data/<name>`, \
         a sender is a device name `<namespace>/<device>`)"
    )]
    BadName {
        /// The name given.
        name: Name,
        /// Why not.
        why: String,
    },
    /// What the setup needs of this device is not held yet.
    #[error("channels over {space} are not ready: {why}; try again later, unchanged")]
    NotReady {
        /// The space.
        space: Name,
        /// What it waits for.
        why: String,
    },
    /// This device may not take part in channels over the space.
    #[error("this device may not use channels over {space}: {why}")]
    NotAllowed {
        /// The space.
        space: Name,
        /// Why, and what to do about it.
        why: String,
    },
    /// The sender did not answer: it Nacked the ask without a word.
    #[error(
        "{sender} does not answer this device's ask: it lists no member of the space whose key \
         signed the ask, or it holds no channel to give, or no certificate it trusts vouches for \
         this device's key; ask the owner of the space to add this device's person, or ask \
         again once the sender holds the record"
    )]
    NotAnswered {
        /// The device asked.
        sender: Name,
    },
    /// Nothing answered the ask: no path, or the sender is off.
    #[error(
        "nothing answered the ask to {sender} within its lifetime: the sender is off or no path \
         reaches it; ask again later"
    )]
    Unreachable {
        /// The device asked.
        sender: Name,
    },
    /// The sender is busy or cannot judge the ask yet.
    #[error(
        "{sender} cannot answer this ask now (it is over its rate for this device, it lacks a \
         certificate of this device's chain, or it saw this very ask before): ask again later, \
         signed afresh; the ask carries this device's chain, so enrol the device if the sender \
         keeps saying so"
    )]
    Busy {
        /// The device asked.
        sender: Name,
    },
    /// The sender declined for a reason of its own, in a signed answer.
    #[error("{sender} refused the ask ({code:?}): {text}")]
    Refused {
        /// The device asked.
        sender: Name,
        /// Why, as a code.
        code: RefusalCode,
        /// Why, and what to do, in the sender's words.
        text: String,
        /// Milliseconds before asking again is of use.
        retry_ms: u64,
    },
    /// The sender is no writer of the space now: a reader's device never sends.
    #[error(
        "{sender} signed a session for {space} and is no writer of it by the entries held here \
         ({why}): a reader receives and never emits; ask a device of a writer of the space"
    )]
    SenderNotWriter {
        /// The device that answered.
        sender: Name,
        /// The space.
        space: Name,
        /// What the entries held say of it.
        why: String,
    },
    /// The answer is not a session this device can use.
    #[error("the answer of {sender} cannot be used: {why}; ask again later")]
    BadAnswer {
        /// The device that answered.
        sender: Name,
        /// Why not.
        why: String,
    },
    /// This device's own failure: its key, its transport.
    #[error("local failure: {reason}; fix this device (its keys, its faces)")]
    Local {
        /// What failed.
        reason: String,
    },
}

impl ChanError {
    /// What to do about it.
    pub fn next(&self) -> NextStep {
        match self {
            ChanError::BadName { .. } => NextStep::FixName,
            ChanError::NotReady { .. }
            | ChanError::NotAnswered { .. }
            | ChanError::Unreachable { .. }
            | ChanError::Busy { .. }
            | ChanError::BadAnswer { .. } => NextStep::RetryLater,
            ChanError::NotAllowed { .. } => NextStep::AskOwner,
            ChanError::Refused { code, .. } => match code {
                RefusalCode::NotAudience => NextStep::AskOwner,
                RefusalCode::NoStream => NextStep::FixRequest,
                RefusalCode::Busy
                | RefusalCode::StaleEpoch
                | RefusalCode::TooMany
                | RefusalCode::NotReady => NextStep::RetryLater,
            },
            ChanError::SenderNotWriter { .. } => NextStep::FixRequest,
            ChanError::Local { .. } => NextStep::FixLocal,
        }
    }

    /// Whether the same ask, unchanged, can succeed later.
    pub fn retry(&self) -> bool {
        self.next() == NextStep::RetryLater
    }
}
