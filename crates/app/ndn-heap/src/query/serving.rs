//! `Heap::serve`: register a handler for a prefix of the space, until the [`Serving`] drops.

use std::sync::Arc;

use ndn_foundation_types::Name;

use super::types::{Handler, ServeError};
use crate::chan::standing::{Who, gate};
use crate::error::HeapError;
use crate::node::NodeInner;
use crate::space::Heap;

/// A served prefix: the handler answers the queries under it until this is dropped.
///
/// Dropping it unregisters the prefix at once: a query that arrives after is answered
/// `NotServed`, and a handler already running is not told (its answer is still sent unless the
/// asker's deadline passed). The announce that lists the prefix stops with the next one.
#[must_use = "a Serving unregisters its prefix when dropped"]
pub struct Serving {
    node: Arc<NodeInner>,
    space: Name,
    prefix: Name,
    token: u64,
}

impl Serving {
    /// The prefix served, relative to the space.
    pub fn prefix(&self) -> &Name {
        &self.prefix
    }
}

impl std::fmt::Debug for Serving {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Serving")
            .field("space", &self.space)
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

impl Drop for Serving {
    fn drop(&mut self) {
        self.node.query.table.remove(&self.space, self.token);
        // The announce that lists this prefix is sent again without it.
        self.node.query_announce(&self.space);
    }
}

impl Heap {
    /// Serve `prefix` (relative to the space) with `handler`: a member that asks with
    /// `GetOptions::ask` is answered by it. The handler runs once per query that reaches it,
    /// with the asker's person and device **as the space judged them**, and its [`Reply`] goes
    /// to that asker once, in a Data signed by this device. The longest served prefix of the
    /// asked path answers; nested prefixes are allowed. Dropping the [`Serving`] stops it.
    ///
    /// Serving is **not** storing: nothing a handler answers is kept, cached or made an entry,
    /// and a second `get` runs the handler again (docs/specs/query.md).
    ///
    /// **Quiet period.** The first `serve` of a node starts a quiet period of 120 s (plus how far
    /// an asker's clock is behind this node's): a signed query made before it ends is refused
    /// with a plain Nack, and before the first `serve` every signed query is. A restart empties
    /// the replay set, and only the clock can tell a copy of a query the last run answered from
    /// a new one; the asker sees the refusal and should ask again later.
    ///
    /// # Errors
    ///
    /// Each [`ServeError`] says why and, by [`ServeError::next`], what to do: `NotWriter` (a
    /// reader's or a follower's device never serves: ask the owner), `NotReady` (the record is
    /// not held yet: retry), `Overlap`, `TooMany`, `BadPrefix` (fix the request).
    ///
    /// [`Reply`]: super::Reply
    pub fn serve(&self, prefix: Name, handler: impl Handler) -> Result<Serving, ServeError> {
        let space = self.inner.name.clone();
        if self.inner.follower {
            return Err(ServeError::NotWriter {
                space,
                why: "this device only follows the space: open it as a member".into(),
            });
        }
        {
            let log = self.inner.log.lock();
            gate(&log, &self.node.judge, Who::Writer, "serving").map_err(|e| match e {
                HeapError::NotReady { why, .. } => ServeError::NotReady {
                    space: space.clone(),
                    why,
                },
                HeapError::NotAllowed { why, .. } => ServeError::NotWriter {
                    space: space.clone(),
                    why,
                },
                other => ServeError::NotReady {
                    space: space.clone(),
                    why: other.to_string(),
                },
            })?;
        }
        // The replay floor is armed **before** the prefix is in the table: a handler is never
        // reachable while there is no floor. The first call of a node arms it; a call refused
        // below leaves it armed, which is sound: the floor only has to be 120 s past a moment
        // that is after this process started, and this call is.
        self.node.query.arm_replay_floor(self.node.now());
        let token = self
            .node
            .query
            .table
            .add(&space, prefix.clone(), Arc::new(handler))?;
        self.node.query_announce(&space);
        Ok(Serving {
            node: Arc::clone(&self.node),
            space,
            prefix,
            token,
        })
    }
}

impl NodeInner {
    /// The set of prefixes `space` serves changed: announce it now (the maintenance task
    /// announces it every 30 s besides).
    pub(crate) fn query_announce(&self, space: &Name) {
        let node = self.arc();
        let space = space.clone();
        self.tasks.spawn(async move {
            node.chan_announce(&space).await;
        });
    }
}
