//! Collections: the growing side of the model — their [`Rule`], their
//! owner-signed [`Members`], the [`Cut`]s that end a member or a key, and
//! the signed, nested [`Summary`] of what they hold.

use ndn_foundation_types::{Hash, Name};

use crate::version::{Audience, Frontier, Seq, VersionId, Writer};

/// What "newest" means in a collection. The collection decides, not the app.
/// A writer is always one key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Rule {
    /// A single key writes; the newest is its signed head, with a freshness
    /// bound. Sensors, a service's answers. Filled by slice 4.
    OneKey,
    /// Each member key appends; the collection is the union of exactly its
    /// members' logs. Chat, a photo library. Filled by slice 2.
    Log,
    /// Member logs plus a named merge function (a CRDT) every reader runs
    /// alike; `get` returns the merged state at a frontier. Notes across
    /// devices, a shared document. Filled by slice 1.
    Merge {
        /// The merge function's name; readers that do not know it cannot
        /// compute the state.
        function: Name,
    },
}

/// The owner-signed record of who may write into a collection and who may
/// read it (model change M2).
///
/// Writers write under their own prefixes; the collection gathers exactly
/// the keys listed here, so a reader can tell a member from a stranger
/// posting under the same collection name. [`share`](crate::DataLayer::share)
/// edits it; removing a member adds a [`Cut`]. Each revision supersedes the
/// previous one and the revision number never goes back (model invariant 3).
/// Owner-only records are filled by slice 1, the rest by slice 2.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Members {
    /// The collection this record governs.
    pub collection: Name,
    /// The owner's key, which signs this record.
    pub owner: Writer,
    /// This record's revision.
    pub revision: Seq,
    /// What "newest" means.
    pub rule: Rule,
    /// Key-name prefixes whose keys may write (e.g. `/alice`, `/bob`).
    pub writers: Vec<Name>,
    /// Who may read; the collection's seal follows this list.
    pub readers: Vec<Audience>,
    /// Removals and revocations in force.
    pub cuts: Vec<Cut>,
    /// Versions outside a cut that the owner signed back in.
    ///
    /// This answers the open item "a cut can drop honest work": a stolen
    /// device's offline edits that nobody had seen fall outside its cut, and
    /// the owner may re-admit specific ones. Filled by slice 5.
    pub readmitted: Vec<VersionId>,
}

/// A signed "up to here" for a key or a member (model change M3).
///
/// Everything by the keys under [`of`](Self::of) that lies inside
/// [`accept`](Self::accept) stays valid; anything else by those keys is
/// refused, whatever date it claims. It replaces clock-based signing-time
/// validity. A reader that receives a cut re-checks everything it already
/// accepted from those keys against it (open item "before a cut arrives").
/// Cuts on removal are filled by slice 2, revocation cuts by slice 5.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Cut {
    /// The key, or the prefix of a member's keys, being ended.
    pub of: Name,
    /// What stays valid: the frontier others had seen.
    pub accept: Frontier,
    /// The key that signed the cut (the collection owner, or the namespace
    /// authority for a revocation).
    pub signer: Writer,
}

impl Cut {
    /// Whether this cut refuses `id`: its key falls under [`of`](Self::of)
    /// and it lies outside [`accept`](Self::accept).
    pub fn refuses(&self, id: &VersionId) -> bool {
        id.writer.key().has_prefix(&self.of) && !self.accept.contains(id)
    }
}

/// One child of a nested summary: a sub-collection and the digest of its own
/// summary.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Child {
    /// The child collection.
    pub name: Name,
    /// The digest of the child's current summary.
    pub digest: Hash,
}

/// A collection's signed state (model primitive "Summary").
///
/// "I have everything" always means "everything in this signed summary"
/// (model invariant 4). A summary is signed by one writer; with many writers
/// each signs its own, and completeness is per writer, gathered by the
/// [`Members`] record (open item "who signs a shared summary"). A reader
/// refuses a summary older than one it has already seen from the same signer
/// (model invariant 3). Summaries nest: a collection of collections lists its
/// children by digest, so [`watch`](crate::DataLayer::watch) descends only
/// into children whose digest changed (model change M8). The summary also
/// maps sequence numbers to names; that mapping is part of its wire form.
/// Filled by slice 1.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Summary {
    /// The summarised collection.
    pub collection: Name,
    /// The key that signed this summary.
    pub signer: Writer,
    /// Everything the summary covers.
    pub frontier: Frontier,
    /// Sub-collections, by digest of their own summaries.
    pub children: Vec<Child>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(key: &str, seq: u64) -> VersionId {
        VersionId {
            writer: Writer::new(key.parse().unwrap()),
            seq: Seq(seq),
        }
    }

    #[test]
    fn a_cut_keeps_what_others_had_seen_and_refuses_the_rest() {
        let cut = Cut {
            of: "/bob".parse().unwrap(),
            accept: [id("/bob/phone/KEY/1", 41)].into_iter().collect(),
            signer: Writer::new("/alice/laptop/KEY/1".parse().unwrap()),
        };
        assert!(!cut.refuses(&id("/bob/phone/KEY/1", 41)));
        assert!(cut.refuses(&id("/bob/phone/KEY/1", 42)));
        // A key of the member never seen at all is outside the cut too.
        assert!(cut.refuses(&id("/bob/laptop/KEY/1", 1)));
        // Keys outside the member are not touched.
        assert!(!cut.refuses(&id("/carol/phone/KEY/1", 99)));
    }

    #[test]
    fn frontiers_only_grow_and_compare_per_writer() {
        let mut f: Frontier = [id("/a/KEY/1", 3), id("/b/KEY/1", 1)].into_iter().collect();
        f.include(&id("/a/KEY/1", 2));
        assert_eq!(f.get(&id("/a/KEY/1", 0).writer), Some(Seq(3)));
        let older: Frontier = [id("/a/KEY/1", 2)].into_iter().collect();
        assert!(f.covers(&older));
        assert!(!older.covers(&f));
        assert!(f.contains(&id("/b/KEY/1", 1)));
        assert!(!f.contains(&id("/c/KEY/1", 1)));
    }
}
