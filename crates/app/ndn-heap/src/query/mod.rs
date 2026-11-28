//! `serve` and the query on `get`: a handler answers by name, signed (docs/specs/query.md).
//!
//! **Not the deleted answers family.** A handler is a producer callback: it runs once per query
//! that reaches it and its result goes to that asker once. No answer is stored, cached,
//! recomputed, sealed by a reader or made an entry; what this layer keeps is memory bounded by
//! outstanding queries and judged members.

use crate::chan::answer::ASK_CLOCK_WINDOW_MS;

mod answers;
mod ask;
#[cfg(test)]
mod ask_tests;
#[cfg(test)]
mod rig;
mod seal;
mod serve;
#[cfg(test)]
mod serve_tests;
mod serving;
mod table;
mod types;

pub(crate) use answers::AnswerSink;
pub(crate) use table::{Hints, ServeTable};
// The sealing of a query and its answer in a sealed space (wire slice).
#[expect(unused_imports, reason = "taken up by the server and asker halves")]
pub(crate) use seal::{
    answer_aad, open_answer, open_query, pair_context, query_aad, seal_answer, seal_query,
};
pub(crate) use serve::QueryOutcome;
pub use serving::Serving;
pub use types::{
    ANSWER_MAX_DEFAULT, Answered, AppRefusal, Ask, Asker, DEADLINE_MAX, Handler, HandlerFuture,
    ProofError, ProvenAnswer, QUERY_MAX, Query, QueryError, QueryId, QueryPath, REFUSAL_TEXT_MAX,
    Reply, SERVE_PREFIX_MAX, SERVE_PREFIXES_MAX, ServeError, TARGETS_MAX, Targets, VerifiedAnswer,
    Via,
};

/// What a node keeps of queries: the prefixes it serves, the announce hints it has heard, and
/// the state of each half.
#[derive(Default)]
pub(crate) struct QueryNode {
    /// The prefixes this node's heaps serve.
    pub(crate) table: ServeTable,
    /// The devices announces say serve queries.
    pub(crate) hints: Hints,
    /// The replay floor, in milliseconds of this node's wall clock: a signed query made at or
    /// before it is refused with a plain Nack. Unset until the first `serve`, and a node with no
    /// floor answers no signed query at all.
    ///
    /// It is the moment of the first `serve` plus [`ASK_CLOCK_WINDOW_MS`]. The replay set is
    /// memory and a restart empties it, so a captured query a previous run answered would run its
    /// handler again; that run accepted it only if it was signed at most 120 s after it arrived
    /// (by the asker's clock, which may be ahead of this one's), and it arrived before this
    /// start. After this floor no such query is acceptable, whatever the asker's clock. The price
    /// is a **quiet period** after every start, from the first `serve` for 120 s plus how far
    /// behind this node's the asker's clock is, in which signed queries are refused; an asker
    /// sees the refusal and asks again later (docs/specs/query.md).
    pub(crate) replay_floor: std::sync::OnceLock<u64>,
    /// The server's half: its limits, replay guard and pair keys.
    pub(crate) server: serve::ServerState,
    /// The asker's half: its pending queries and pair keys.
    pub(crate) ask: ask::AskState,
}

impl QueryNode {
    /// Arm the replay floor if this is the first `serve` of the node (`now`: this node's clock,
    /// in milliseconds). It is called **before** a prefix enters the table, so that no handler is
    /// ever reachable while the floor is unset. Later calls change nothing.
    pub(crate) fn arm_replay_floor(&self, now: u64) {
        self.replay_floor.get_or_init(|| {
            let floor = now.saturating_add(ASK_CLOCK_WINDOW_MS);
            tracing::info!(
                floor,
                "serving: signed queries are refused until {floor} (ms, this node's clock), 120 s from now, \
                 because a restart empties the replay set and a copy of a query the last run answered must \
                 not run a handler again; an asker that is refused should ask again later"
            );
            floor
        });
    }
}
