//! `serve` and the query on `get`: a handler answers by name, signed (docs/specs/query.md).
//!
//! **Not the deleted answers family.** A handler is a producer callback: it runs once per query
//! that reaches it and its result goes to that asker once. No answer is stored, cached,
//! recomputed, sealed by a reader or made an entry; what this layer keeps is memory bounded by
//! outstanding queries and judged members.

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
    /// The wall-clock moment (milliseconds) this node first served: a signed query made before it
    /// is refused, so a restart's empty replay guard cannot be used to run a copy.
    pub(crate) serving_since: std::sync::OnceLock<u64>,
    /// The server's half: its limits, replay guard and pair keys.
    pub(crate) server: serve::ServerState,
    /// The asker's half: its pending queries and pair keys.
    pub(crate) ask: ask::AskState,
}
