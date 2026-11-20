//! What an answer reads (`docs/specs/answers.md` §3.1, §4.1, §7.2, §7.3): the facts a device holds
//! of a version or a merge state, the two phases of an evaluation, and the checks of a read set
//! against what this device holds.
//!
//! Every read is of a version or state this device holds verified, bound by digest. A recompute
//! replays planning and evaluation against exactly a given read set.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_foundation_types::Hash;
use ndn_packet::Name;

use super::{Device, Held, Inner, St};
use crate::answer::{
    Budget, Definition, EvalError, Evaluator, PlanError, ReadRef, ReadSet, ReadView, Reads,
    applied_digest, epoch_order,
};
use crate::collection::{Epoch, Rule};
use crate::error::{AnswerRefusal, DataError};
use crate::layer::{Age, Got};
use crate::merge::MergeRules;
use crate::rt::Cancel;
use crate::version::{Frontier, Parents, VersionId, Writer};
use crate::wire::{self, parse_log_name};

/// The most reads of merge states a signed answer may list for this device to check against
/// what it holds (answers.md §10): each is a replay of the collection's merge up to a frontier
/// the signer chose ([`St::state_facts`]). More is refused whole, with the reason.
///
/// Measured in release (`state_facts_cost_of_a_listed_read`): 3.6 µs a read of a collection of
/// 8 versions at its newest frontier and 9.9 µs at one in its past; 28 µs and 0.40 ms at 64
/// versions; 0.21 ms and 24 ms at 512 versions. The cost of a past frontier grows about with the
/// square of the versions held, which a hostile member can add to, so the cap bounds the number
/// of replays (1,024 × 0.40 ms at 64 versions) and [`Budget::time`] their sum, whatever the
/// collections hold.
pub(super) const STATE_READS_CHECKED_MAX: usize = 1_024;

/// What this device holds of a version named by a read.
pub(super) enum VersionFact {
    /// Held verified: the digest of its packet and the epoch its payload is sealed in.
    Held {
        digest: [u8; 32],
        epoch: Option<Epoch>,
    },
    /// Held and refused here since (a cut, a revocation, its rule).
    Refused,
    /// Not held.
    Unknown,
}

/// What this device computes of a merge collection's state at a frontier (answers.md §3.1).
pub(super) struct StateFacts {
    /// The merge rule in force, by full name.
    pub(super) rule: Name,
    /// The frontier with every tip's digest.
    pub(super) parents: Parents,
    /// The applied-set digest.
    pub(super) applied: Hash,
    /// The epochs of every version the state is computed from, ascending.
    pub(super) epochs: Vec<Epoch>,
}

/// Why a read of a read set fails.
pub(super) enum ReadFail {
    /// The error `get` of it answers.
    Data(DataError),
    /// What this device holds of it conflicts with what the read says: evidence.
    Conflict(String),
    /// What the read says no longer holds here, no fault of the signer: ask again.
    Changed(String),
}

/// What checking the reads of an answer this device holds found, none in conflict.
#[derive(Default, PartialEq, Eq)]
pub(super) struct ReadsChecked {
    /// How many of its reads this device does not hold, so did not check.
    pub(super) unverified: u32,
    /// The epochs of the reads it holds, ascending.
    pub(super) epochs: Vec<Epoch>,
}

impl ReadsChecked {
    /// Whether the epochs `listed` are the ones the reads are sealed in: all of them when every
    /// read was checked, and at least those held when some were not.
    pub(super) fn lists(&self, listed: &[Epoch]) -> bool {
        match self.unverified {
            0 => self.epochs == listed,
            _ => self.epochs.iter().all(|e| listed.contains(e)),
        }
    }
}

/// Add `e` to `epochs`, ascending and once each.
pub(super) fn add_epoch(epochs: &mut Vec<Epoch>, e: &Epoch) {
    if let Err(at) = epochs.binary_search_by(|x| epoch_order(x, e)) {
        epochs.insert(at, e.clone());
    }
}

impl St {
    /// Whether `name` has equivocation evidence here: two packets of its writer at it, or two
    /// entries of the writer at its seq (data-layer.md §21). What this device holds at such a
    /// name is the first of them, not the one a signer read.
    pub(super) fn equivocal_name(&self, name: &Name) -> bool {
        self.twins.contains_key(name)
            || self
                .equivocal
                .values()
                .any(|by_seq| by_seq.values().any(|names| names.contains(name)))
    }

    /// What a read that names another digest than the version held at `name` is: a conflict
    /// (evidence against whoever signed it), unless `name` has equivocation evidence, when a
    /// signer may have read the other packet of its writer: then it is a read that no longer
    /// holds here, no fault of the signer (answers.md §8.1).
    pub(super) fn conflict(&self, name: &Name, why: String) -> ReadFail {
        match self.equivocal_name(name) {
            true => ReadFail::Changed(format!(
                "{why}; the writer of {name} signed two packets at it (equivocation evidence is \
                 held), so this device cannot tell which one the answer read: ask again once the \
                 writer's key is revoked or the equivocation is settled"
            )),
            false => ReadFail::Conflict(why),
        }
    }

    /// What is held of the version `name`.
    pub(super) fn version_fact(&self, name: &Name) -> VersionFact {
        let Some(c) = parse_log_name(name).and_then(|l| l.subject) else {
            return VersionFact::Unknown;
        };
        if self.refused.contains_key(name) || self.cut_out.contains_key(name) {
            return VersionFact::Refused;
        }
        match self.held.get(name) {
            Some(Held::Version(id)) => match self.colls.get(&c).and_then(|x| x.versions.get(id)) {
                Some(hv) => VersionFact::Held {
                    digest: hv.digest,
                    epoch: hv.epoch.clone(),
                },
                None => VersionFact::Unknown,
            },
            Some(Held::Locked) => {
                match self
                    .colls
                    .get(&c)
                    .and_then(|x| x.locked.iter().find(|l| l.name == *name))
                {
                    Some(l) => VersionFact::Held {
                        digest: wire::implicit_digest(&l.wire),
                        epoch: Some(l.epoch().clone()),
                    },
                    None => VersionFact::Unknown,
                }
            }
            _ => VersionFact::Unknown,
        }
    }

    /// The state of merge collection `c` at `at` as this device computes it, for a read: the
    /// rule in force, the frontier with its tips' digests, the applied-set digest and the epochs
    /// (answers.md §3.1). `None` while the state at `at` cannot be computed here (a version
    /// inside it not held, or the merge rule not known).
    ///
    /// The versions the state is computed from are those of `c` held here inside `at` that are
    /// not covered by a checkpoint applied, so a device that applied the covered versions before
    /// the checkpoint and one that never fetched them agree (data-layer.md §5.2).
    pub(super) fn state_facts(
        &self,
        c: &Name,
        at: &Frontier,
        rules: &MergeRules,
        me: &Writer,
    ) -> Option<StateFacts> {
        let coll = self.colls.get(c)?;
        let Rule::Merge { function } = &coll.members.as_ref()?.rule else {
            return None;
        };
        let (_, _, join) = self.value_and_cover_at(c, at, rules, me)?;
        let covered = |id: &VersionId| join.get(&id.writer).is_some_and(|s| *s >= id.seq.0);
        let mut parents = Parents::new();
        for (w, s) in at.iter() {
            let id = VersionId {
                writer: w.clone(),
                seq: s,
            };
            let digest = coll.versions.get(&id).map(|hv| hv.digest).or_else(|| {
                coll.locked
                    .iter()
                    .find(|l| l.writer == *w && l.seq == s.0)
                    .map(|l| wire::implicit_digest(&l.wire))
            })?;
            parents.insert(&id, Some(digest));
        }
        let mut epochs = Vec::new();
        let mut applied = Vec::new();
        for (id, hv) in &coll.versions {
            if at.contains(id) && !coll.pending.contains(id) && !covered(id) {
                applied.push((id.writer.clone(), id.seq.0, hv.digest));
                if let Some(e) = &hv.epoch {
                    add_epoch(&mut epochs, e);
                }
            }
        }
        Some(StateFacts {
            rule: function.clone(),
            parents,
            applied: applied_digest(applied),
            epochs,
        })
    }
}

/// An approximation of the octets a read brings, for the budget.
fn got_size(got: &Got) -> u64 {
    match got {
        Got::Version(v) => {
            let payload = match &v.payload {
                crate::version::Payload::Entry(c) => {
                    c.fields().map(|(k, v)| (k.len() + v.len()) as u64).sum()
                }
                crate::version::Payload::Block(es) => es
                    .iter()
                    .map(|e| {
                        e.content
                            .fields()
                            .map(|(k, v)| (k.len() + v.len()) as u64)
                            .sum::<u64>()
                    })
                    .sum(),
                crate::version::Payload::Large { size } => *size,
            };
            payload + v.op.as_ref().map_or(0, |o| o.len() as u64)
        }
        Got::State(s) => match &s.value {
            crate::merge::Value::Fields(c) => {
                c.fields().map(|(k, v)| (k.len() + v.len()) as u64).sum()
            }
            crate::merge::Value::Rule(b) => b.len() as u64,
        },
        _ => 0,
    }
}

impl Inner {
    /// `get` as a host calls it: the answer to a name, whichever verb path it takes.
    pub(super) async fn get_via_device(
        self: &Arc<Self>,
        name: &Name,
    ) -> Result<crate::layer::Answer, DataError> {
        use crate::layer::DataLayer;
        Device {
            inner: Arc::clone(self),
        }
        .get(name)
        .await
    }

    /// The exact read of what `got` is (a version or a merge state), and the epochs it is
    /// sealed in.
    pub(super) fn read_ref_of(&self, got: &Got) -> Result<(ReadRef, Vec<Epoch>), DataError> {
        let st = self.st.lock();
        match got {
            Got::Version(v) => {
                let epochs = match st.version_fact(&v.name) {
                    VersionFact::Held { epoch, .. } => epoch.into_iter().collect(),
                    _ => Vec::new(),
                };
                Ok((
                    ReadRef::Version {
                        name: v.name.clone(),
                        digest: Hash(v.digest),
                    },
                    epochs,
                ))
            }
            Got::State(s) => {
                let facts = st
                    .state_facts(&s.collection, &s.at, &self.config.rules, &self.writer)
                    .ok_or_else(|| DataError::NotReady {
                        name: s.name.clone(),
                        why: "the state is not computed here yet; ask again".into(),
                    })?;
                let at = facts.parents;
                Ok((
                    ReadRef::State {
                        collection: s.collection.clone(),
                        rule: facts.rule,
                        at,
                        applied: facts.applied,
                    },
                    facts.epochs,
                ))
            }
            _ => Err(DataError::BadRequest {
                name: Name::root(),
                why: "only a version or the state of a merge collection is read by an answer; \
                      name one of them"
                    .into(),
            }),
        }
    }

    /// The newest this device holds of `c` as an exact read (what a planning `current` gives):
    /// the read, what it opened to, how old it may be, and its epochs.
    pub(super) async fn current_read(
        self: &Arc<Self>,
        c: &Name,
    ) -> Result<(ReadRef, Got, Age, Vec<Epoch>), DataError> {
        let answer = self.get_via_device(c).await?;
        let (read, epochs) = self.read_ref_of(&answer.got)?;
        Ok((read, answer.got, answer.age, epochs))
    }

    /// Read exactly `r`: the version, or the merge state, fetched as `get` fetches, and
    /// checked against what the read says (answers.md §3.1): the digest of the version, the
    /// rule, the tips' digests and the applied set of the state.
    pub(super) async fn read_exact(
        self: &Arc<Self>,
        r: &ReadRef,
    ) -> Result<(Got, Vec<Epoch>), ReadFail> {
        match r {
            ReadRef::Version { name, digest } => {
                let answer = self.get_via_device(name).await.map_err(ReadFail::Data)?;
                let Got::Version(v) = answer.got else {
                    return Err(ReadFail::Data(DataError::BadName {
                        name: name.clone(),
                        why: "a read of a version names a log entry that is a version".into(),
                    }));
                };
                if v.digest != digest.0 {
                    return Err(self.st.lock().conflict(
                        name,
                        format!(
                            "the read names {name} with the digest {digest:?} and the version held \
                             here has another"
                        ),
                    ));
                }
                let epochs = match self.st.lock().version_fact(name) {
                    VersionFact::Held { epoch, .. } => epoch.into_iter().collect(),
                    _ => Vec::new(),
                };
                Ok((Got::Version(v), epochs))
            }
            ReadRef::State {
                collection,
                rule,
                at,
                applied,
            } => {
                let sname = wire::state_name(collection, at.frontier());
                let answer = self.get_via_device(&sname).await.map_err(ReadFail::Data)?;
                let facts = {
                    let st = self.st.lock();
                    // A tip held here with another digest than the read lists.
                    if let Some(coll) = st.colls.get(collection) {
                        for (w, s, d) in at.tips() {
                            let id = VersionId {
                                writer: w.clone(),
                                seq: s,
                            };
                            if let (Some(hv), Some(d)) = (coll.versions.get(&id), d)
                                && hv.digest != *d
                            {
                                return Err(st.conflict(
                                    &hv.version.name,
                                    format!(
                                        "the read names the tip {} seq {} of {collection} with \
                                         another digest than the version held here",
                                        w.key(),
                                        s.0
                                    ),
                                ));
                            }
                        }
                    }
                    st.state_facts(collection, at.frontier(), &self.config.rules, &self.writer)
                };
                let Some(facts) = facts else {
                    return Err(ReadFail::Changed(format!(
                        "the state of {collection} at that frontier is not computed here"
                    )));
                };
                if facts.rule != *rule {
                    return Err(ReadFail::Changed(format!(
                        "{collection} is merged here under {}, not under {rule}",
                        facts.rule
                    )));
                }
                if facts.applied != *applied {
                    return Err(ReadFail::Changed(format!(
                        "the versions of {collection} this device computes that state from are \
                         not the ones the read lists: one was withdrawn, pruned or expired \
                         since"
                    )));
                }
                if facts.parents != *at {
                    return Err(ReadFail::Conflict(format!(
                        "the tips of {collection} the read lists are not the packets held here"
                    )));
                }
                Ok((answer.got, facts.epochs))
            }
        }
    }

    /// Check the reads of the signed answer `name` against what this device holds
    /// (answers.md §7.3.2, §7.3.1, §10), without fetching, and collect the epochs they are sealed
    /// in: the answer is refused whole when it lists more reads of merge states than
    /// [`STATE_READS_CHECKED_MAX`], and the check runs off the executor within
    /// [`Budget::time`], over which it is a refusal, never trust. `listed`: the epochs the
    /// answer lists.
    ///
    /// The check holds the `St` lock one read at a time ([`Inner::check_reads_with`]), so what
    /// it judges is each read's check at the moment of that check. The one fact that joins
    /// reads is the epochs they are sealed in, which a fault (evidence against the signer) is
    /// made of when they are not the ones listed: so such a result is checked again, and when
    /// the second pass found other facts than the first, this device's state moved under the
    /// check, which is a read that no longer holds ([`ReadFail::Changed`]), no fault of the
    /// signer.
    pub(super) async fn check_reads(
        self: &Arc<Self>,
        name: &Name,
        set: &ReadSet,
        listed: &[Epoch],
    ) -> Result<ReadsChecked, ReadFail> {
        let states = set
            .reads()
            .iter()
            .filter(|r| matches!(r, ReadRef::State { .. }))
            .count();
        if states > STATE_READS_CHECKED_MAX {
            return Err(ReadFail::Data(DataError::Answer {
                name: name.clone(),
                why: AnswerRefusal::TooManyStates {
                    states: states as u64,
                    limit: STATE_READS_CHECKED_MAX as u64,
                },
            }));
        }
        let first = self.check_reads_pass(name, set).await?;
        if first.lists(listed) {
            return Ok(first);
        }
        let again = self.check_reads_pass(name, set).await?;
        if again != first {
            return Err(ReadFail::Changed(
                "what this device holds of its reads changed while they were checked".into(),
            ));
        }
        Ok(first)
    }

    /// One pass of [`Inner::check_reads`], on a thread of its own.
    async fn check_reads_pass(
        self: &Arc<Self>,
        name: &Name,
        set: &ReadSet,
    ) -> Result<ReadsChecked, ReadFail> {
        let inner = Arc::clone(self);
        let set = set.clone();
        let ran = crate::rt::blocking(
            self.config.answers.budget.time,
            self.config.answers.inline_work,
            move |cancel| inner.check_reads_with(&set, cancel, &mut || {}),
        )
        .await;
        let over = |what: &str| {
            ReadFail::Data(DataError::Answer {
                name: name.clone(),
                why: AnswerRefusal::OverBudget { what: what.into() },
            })
        };
        match ran {
            Ok(Some(checked)) => checked,
            Ok(None) | Err(crate::rt::Stopped::Deadline) => {
                Err(over("time to check the reads of an answer"))
            }
            Err(crate::rt::Stopped::NoThread) => Err(over(
                "threads to check the reads of an answer on, of which this device could start \
                 none",
            )),
        }
    }

    /// Check each read of `set` this device holds, one at a time, and collect the epochs they
    /// are sealed in; `None` when `cancel` is raised first. `between` runs before each read.
    ///
    /// The `St` lock is taken for one read and let go before the next, so a set of up to
    /// [`crate::answer::READS_MAX`] reads does not hold up every other operation of the device
    /// until it is done. That is sound because each read's check is a function of what is held
    /// of that read alone (its version's digest and standing, or its collection's state) and
    /// is judged against the state at that moment: a fault found is a fault of that read then,
    /// and what moves later (a version withdrawn, an equivocation found) is judged again by
    /// the rejudging of answers, which ends the evidence when its cause is gone
    /// (answers.md §8.2).
    pub(super) fn check_reads_with(
        &self,
        set: &ReadSet,
        cancel: &Cancel,
        between: &mut dyn FnMut(),
    ) -> Option<Result<ReadsChecked, ReadFail>> {
        let mut checked = ReadsChecked::default();
        for r in set.reads() {
            if cancel.cancelled() {
                return None;
            }
            between();
            let st = self.st.lock();
            if let Err(fail) = self.check_read(&st, r, &mut checked) {
                return Some(Err(fail));
            }
        }
        Some(Ok(checked))
    }

    /// Check one read of an answer against what `st` holds. A conflict of digests is evidence,
    /// unless the version it concerns has equivocation evidence of its own
    /// ([`St::equivocal_name`]); a read that no longer holds is not.
    fn check_read(&self, st: &St, r: &ReadRef, checked: &mut ReadsChecked) -> Result<(), ReadFail> {
        match r {
            ReadRef::Version { name, digest } => match st.version_fact(name) {
                VersionFact::Held { digest: held, .. } if held != digest.0 => {
                    return Err(st.conflict(
                        name,
                        format!(
                            "it names {name} with the digest {digest:?} and this device holds \
                             that version with another"
                        ),
                    ));
                }
                VersionFact::Held { epoch, .. } => {
                    if let Some(e) = &epoch {
                        add_epoch(&mut checked.epochs, e);
                    }
                }
                VersionFact::Refused => {
                    return Err(ReadFail::Changed(format!(
                        "the version {name} it read is refused here since"
                    )));
                }
                VersionFact::Unknown => checked.unverified += 1,
            },
            ReadRef::State {
                collection,
                rule,
                at,
                applied,
            } => {
                let Some(coll) = st.colls.get(collection) else {
                    checked.unverified += 1;
                    return Ok(());
                };
                let Some(members) = coll.members.as_ref() else {
                    checked.unverified += 1;
                    return Ok(());
                };
                for (w, s, d) in at.tips() {
                    let id = VersionId {
                        writer: w.clone(),
                        seq: s,
                    };
                    if let (Some(hv), Some(d)) = (coll.versions.get(&id), d)
                        && hv.digest != *d
                    {
                        return Err(st.conflict(
                            &hv.version.name,
                            format!(
                                "it names the tip {} seq {} of {collection} with another \
                                 digest than the version this device holds",
                                w.key(),
                                s.0
                            ),
                        ));
                    }
                }
                if let Rule::Merge { function } = &members.rule
                    && function != rule
                {
                    return Err(ReadFail::Changed(format!(
                        "{collection} is merged here under {function}, not under {rule}"
                    )));
                }
                match st.state_facts(collection, at.frontier(), &self.config.rules, &self.writer) {
                    Some(f) if f.applied != *applied => {
                        return Err(ReadFail::Changed(format!(
                            "the versions of {collection} the state is computed from here are \
                             not the ones the answer read: one was withdrawn, pruned or expired \
                             since"
                        )));
                    }
                    Some(f) => f
                        .epochs
                        .iter()
                        .for_each(|e| add_epoch(&mut checked.epochs, e)),
                    None => checked.unverified += 1,
                }
            }
        }
        Ok(())
    }
}

// ---- the two phases -----------------------------------------------------------------------------

/// How an evaluation fails.
pub(super) enum EvalFail {
    /// A read the layer refuses: the error `get` of it answers.
    Data(DataError),
    /// What this device holds of a read conflicts with it.
    Conflict(String),
    /// A read no longer holds here.
    Changed(String),
    /// The evaluator refuses its definition or its inputs.
    Refused(String),
    /// The reads are not the evaluator's reading of its definition (a recompute), or its plan
    /// and its evaluation disagree.
    NotItsReads(String),
    /// Over the host's budget.
    Over(String),
    /// Over a limit of answers.
    TooLarge(AnswerRefusal),
}

/// What an evaluation produced.
pub(super) struct Evaluated {
    pub(super) reads: ReadSet,
    pub(super) epochs: Vec<Epoch>,
    pub(super) result: Bytes,
    /// `Age::Exact` when the plan read nothing by `current`, else the greatest age among the
    /// collections it read.
    pub(super) age: Age,
}

/// A read set's reads by membership and by collection, for a plan or an evaluation that asks
/// for them many times: [`ReadSet::contains`] and [`ReadSet::current`] scan the whole set, and
/// a set lists up to [`crate::answer::READS_MAX`] reads.
struct SetIndex<'a> {
    reads: HashSet<&'a ReadRef>,
    /// The one read of each collection, `None` for a collection of several.
    current: HashMap<Name, Option<&'a ReadRef>>,
}

impl<'a> SetIndex<'a> {
    fn of(set: &'a ReadSet) -> Self {
        let mut current: HashMap<Name, Option<&ReadRef>> = HashMap::new();
        for r in set.reads() {
            if let Ok(c) = r.collection() {
                current
                    .entry(c)
                    .and_modify(|one| *one = None)
                    .or_insert(Some(r));
            }
        }
        SetIndex {
            reads: set.reads().iter().collect(),
            current,
        }
    }

    fn contains(&self, r: &ReadRef) -> bool {
        self.reads.contains(r)
    }

    /// As [`ReadSet::current`].
    fn current(&self, collection: &Name) -> Option<&'a ReadRef> {
        self.current.get(collection).copied().flatten()
    }
}

enum Mode<'a> {
    Plan,
    Replay(SetIndex<'a>),
}

/// The planning phase's [`Reads`]: every read goes through the layer.
struct Planner<'a> {
    inner: &'a Arc<Inner>,
    mode: Mode<'a>,
    budget: Budget,
    /// The reads the plan made through [`Reads::read`].
    read: Vec<ReadRef>,
    /// Those, for membership.
    read_seen: HashSet<ReadRef>,
    contents: HashMap<ReadRef, Got>,
    epochs: Vec<Epoch>,
    /// What `current` found, so a `read` of it does not fetch again.
    found: HashMap<ReadRef, (Got, Vec<Epoch>)>,
    /// How many times the plan called [`Reads::current`]: each is spent from the reads budget
    /// like a read of a distinct version or state (answers.md §10), found or not, so a plan
    /// cannot ask for the newest of a collection over and over for nothing.
    currents: usize,
    unconfirmed: Option<Duration>,
    spent_bytes: u64,
    /// What went wrong, beyond what a `DataError` can say.
    fail: Option<EvalFail>,
}

impl Planner<'_> {
    fn failed(&mut self, f: EvalFail, e: DataError) -> DataError {
        self.fail = Some(f);
        e
    }

    /// The refusal of the reads budget, when the reads and calls of `current` so far have
    /// spent it.
    fn over_reads(&mut self, name: Name) -> Option<DataError> {
        if self.contents.len() + self.currents < self.budget.reads {
            return None;
        }
        let what = "reads, calls of current included".to_string();
        Some(self.failed(
            EvalFail::Over(what.clone()),
            DataError::Answer {
                name,
                why: AnswerRefusal::OverBudget { what },
            },
        ))
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl Reads for Planner<'_> {
    async fn current(&mut self, collection: &Name) -> Result<(ReadRef, Age), DataError> {
        if let Some(over) = self.over_reads(collection.clone()) {
            return Err(over);
        }
        self.currents += 1;
        match &self.mode {
            Mode::Replay(index) => match index.current(collection) {
                Some(r) => Ok((r.clone(), Age::Exact)),
                None => {
                    let why = format!(
                        "the read set has no single read of {collection}: the plan reads \
                         outside it"
                    );
                    Err(self.failed(
                        EvalFail::NotItsReads(why.clone()),
                        DataError::BadRequest {
                            name: collection.clone(),
                            why,
                        },
                    ))
                }
            },
            Mode::Plan => {
                let (r, got, age, epochs) = self.inner.current_read(collection).await?;
                if let Age::Newest { unconfirmed_for } = age {
                    self.unconfirmed = Some(
                        self.unconfirmed
                            .map_or(unconfirmed_for, |u| u.max(unconfirmed_for)),
                    );
                }
                self.found.insert(r.clone(), (got, epochs));
                Ok((r, age))
            }
        }
    }

    async fn read(&mut self, r: &ReadRef) -> Result<Got, DataError> {
        if let Mode::Replay(index) = &self.mode
            && !index.contains(r)
        {
            let why = "the plan reads a version or state outside the read set".to_string();
            return Err(self.failed(
                EvalFail::NotItsReads(why.clone()),
                DataError::BadRequest {
                    name: r.collection().unwrap_or_else(|_| Name::root()),
                    why,
                },
            ));
        }
        if let Some(got) = self.contents.get(r) {
            let got = got.clone();
            if self.read_seen.insert(r.clone()) {
                self.read.push(r.clone());
            }
            return Ok(got);
        }
        if let Some(over) = self.over_reads(r.collection().unwrap_or_else(|_| Name::root())) {
            return Err(over);
        }
        let (got, epochs) = match self.found.get(r) {
            Some((got, epochs)) => (got.clone(), epochs.clone()),
            None => match self.inner.read_exact(r).await {
                Ok(x) => x,
                Err(ReadFail::Data(e)) => return Err(e),
                Err(ReadFail::Conflict(m)) => {
                    let e = DataError::Answer {
                        name: r.collection().unwrap_or_else(|_| Name::root()),
                        why: AnswerRefusal::ReadSet(m.clone()),
                    };
                    return Err(self.failed(EvalFail::Conflict(m), e));
                }
                Err(ReadFail::Changed(m)) => {
                    let e = DataError::Answer {
                        name: r.collection().unwrap_or_else(|_| Name::root()),
                        why: AnswerRefusal::ReadsChanged(m.clone()),
                    };
                    return Err(self.failed(EvalFail::Changed(m), e));
                }
            },
        };
        self.spent_bytes += got_size(&got);
        if self.spent_bytes > self.budget.read_bytes {
            let name = r.collection().unwrap_or_else(|_| Name::root());
            return Err(self.failed(
                EvalFail::Over("octets read".into()),
                DataError::Answer {
                    name,
                    why: AnswerRefusal::OverBudget {
                        what: "octets read".into(),
                    },
                },
            ));
        }
        for e in &epochs {
            add_epoch(&mut self.epochs, e);
        }
        self.read_seen.insert(r.clone());
        self.read.push(r.clone());
        self.contents.insert(r.clone(), got.clone());
        Ok(got)
    }
}

/// The evaluation phase's [`ReadView`]: what the plan read, in memory.
struct View<'a> {
    index: SetIndex<'a>,
    contents: &'a HashMap<ReadRef, Got>,
    used: RefCell<HashSet<ReadRef>>,
    outside: RefCell<Option<String>>,
    cancel: &'a Cancel,
}

impl View<'_> {
    /// The error of a call after the evaluation's time is over: it is abandoned.
    fn over_time(&self) -> EvalError {
        EvalError::Refused("the evaluation is over its time and is abandoned".into())
    }
}

impl ReadView for View<'_> {
    fn current(&self, collection: &Name) -> Result<&ReadRef, EvalError> {
        if self.cancel.cancelled() {
            return Err(self.over_time());
        }
        self.index.current(collection).ok_or_else(|| {
            let why = format!("the read set has no single read of {collection}");
            *self.outside.borrow_mut() = Some(why.clone());
            EvalError::NotItsReads(why)
        })
    }

    fn read(&self, r: &ReadRef) -> Result<&Got, EvalError> {
        if self.cancel.cancelled() {
            return Err(self.over_time());
        }
        match self.contents.get(r) {
            Some(got) => {
                self.used.borrow_mut().insert(r.clone());
                Ok(got)
            }
            None => {
                let why = "the evaluation reads a version or state the plan did not".to_string();
                *self.outside.borrow_mut() = Some(why.clone());
                Err(EvalError::NotItsReads(why))
            }
        }
    }

    fn cancelled(&self) -> bool {
        self.cancel.cancelled()
    }
}

impl Inner {
    /// Run `ev` over `definition`: planning its reads from what this device holds (`replay`
    /// `None`), or replaying plan and evaluation against exactly `replay`'s reads
    /// (answers.md §4.1: a recompute, which reads nothing outside the set and uses each read
    /// of it). The definition is one of the reads.
    pub(super) async fn evaluate_over(
        self: &Arc<Self>,
        ev: &Arc<dyn Evaluator>,
        definition: &ReadRef,
        replay: Option<&ReadSet>,
        run: bool,
    ) -> Result<Evaluated, EvalFail> {
        let budget = self.config.answers.budget;
        let (got, def_epochs) = match self.read_exact(definition).await {
            Ok(x) => x,
            Err(ReadFail::Data(e)) => return Err(EvalFail::Data(e)),
            Err(ReadFail::Conflict(m)) => return Err(EvalFail::Conflict(m)),
            Err(ReadFail::Changed(m)) => return Err(EvalFail::Changed(m)),
        };
        let def = Definition {
            reference: definition.clone(),
            got: got.clone(),
        };
        let mut planner = Planner {
            inner: self,
            mode: match replay {
                Some(set) => Mode::Replay(SetIndex::of(set)),
                None => Mode::Plan,
            },
            budget,
            read: Vec::new(),
            read_seen: HashSet::from([definition.clone()]),
            contents: HashMap::from([(definition.clone(), got)]),
            epochs: def_epochs,
            found: HashMap::new(),
            currents: 0,
            unconfirmed: None,
            spent_bytes: 0,
            fail: None,
        };
        planner.read.push(definition.clone());
        planner.spent_bytes = planner.contents.values().map(got_size).sum();
        if let Err(e) = ev.plan(&def, &mut planner).await {
            if let Some(f) = planner.fail.take() {
                return Err(f);
            }
            return Err(match e {
                PlanError::Data(e) => EvalFail::Data(e),
                PlanError::Eval(EvalError::Refused(m)) => EvalFail::Refused(m),
                PlanError::Eval(EvalError::NotItsReads(m)) => EvalFail::NotItsReads(m),
            });
        }
        let set = match replay {
            Some(set) => set.clone(),
            None => ReadSet::new(planner.read.iter().cloned()).map_err(EvalFail::TooLarge)?,
        };
        if let Some(set_replayed) = replay {
            // Every read of the set was read by the plan.
            let read: BTreeSet<&ReadRef> = planner.read.iter().collect();
            if let Some(missing) = set_replayed.reads().iter().find(|r| !read.contains(r)) {
                return Err(EvalFail::NotItsReads(format!(
                    "the plan never reads {}, which the read set lists",
                    match missing {
                        ReadRef::Version { name, .. } => name.to_string(),
                        ReadRef::State { collection, .. } => collection.to_string(),
                    }
                )));
            }
        }
        let age = match planner.unconfirmed {
            Some(unconfirmed_for) => Age::Newest { unconfirmed_for },
            None => Age::Exact,
        };
        if planner.epochs.len() > crate::answer::SEAL_EPOCHS_MAX {
            return Err(EvalFail::TooLarge(AnswerRefusal::TooLarge {
                what: "the epochs of the reads".into(),
                size: planner.epochs.len() as u64,
                limit: crate::answer::SEAL_EPOCHS_MAX as u64,
            }));
        }
        if !run {
            // Planned, not evaluated: a question taken on trust needs the reads, not a result.
            return Ok(Evaluated {
                reads: set,
                epochs: planner.epochs,
                result: Bytes::new(),
                age,
            });
        }
        // The evaluation is the host's synchronous code over up to READS_MAX reads: it runs on
        // a thread of its own, within the time budget, so it neither holds up the executor nor
        // runs for as long as it likes. Past the time it is abandoned and refused: the clock
        // only ever makes a refusal (answers.md §10).
        let contents = std::mem::take(&mut planner.contents);
        let evaluator = Arc::clone(ev);
        let ran = crate::rt::blocking(
            budget.time,
            self.config.answers.inline_work,
            move |cancel| {
                let (evaluated, used, outside) = {
                    let view = View {
                        index: SetIndex::of(&set),
                        contents: &contents,
                        used: RefCell::new(HashSet::new()),
                        outside: RefCell::new(None),
                        cancel,
                    };
                    let evaluated = evaluator.evaluate(&def, &view);
                    (evaluated, view.used.take(), view.outside.take())
                };
                (evaluated, used, outside, set)
            },
        )
        .await;
        let (evaluated, used, outside, set) = match ran {
            Ok(x) => x,
            Err(crate::rt::Stopped::Deadline) => {
                return Err(EvalFail::Over("time to evaluate".into()));
            }
            Err(crate::rt::Stopped::NoThread) => {
                return Err(EvalFail::Over(
                    "threads to evaluate on, of which this device could start none".into(),
                ));
            }
        };
        let result = match evaluated {
            Ok(r) => r,
            Err(EvalError::Refused(m)) => return Err(EvalFail::Refused(m)),
            Err(EvalError::NotItsReads(m)) => return Err(EvalFail::NotItsReads(m)),
        };
        if let Some(why) = outside {
            return Err(EvalFail::NotItsReads(why));
        }
        // Each read of the set, the definition aside, was used by the evaluation.
        if let Some(unused) = set
            .reads()
            .iter()
            .find(|r| *r != definition && !used.contains(*r))
        {
            return Err(EvalFail::NotItsReads(format!(
                "the evaluation never uses {}, which the read set lists",
                match unused {
                    ReadRef::Version { name, .. } => name.to_string(),
                    ReadRef::State { collection, .. } => collection.to_string(),
                }
            )));
        }
        if result.len() as u64 > budget.result_bytes {
            return Err(EvalFail::Over("octets of the result".into()));
        }
        Ok(Evaluated {
            reads: set,
            epochs: planner.epochs,
            result,
            age,
        })
    }

    /// Read every read of `set` in canonical order (a stated read set, a provider's inputs):
    /// the first the layer cannot read answers its error. Returns the epochs.
    pub(super) async fn read_all(
        self: &Arc<Self>,
        set: &ReadSet,
        budget: Budget,
    ) -> Result<Vec<Epoch>, EvalFail> {
        let mut epochs = Vec::new();
        let mut bytes = 0u64;
        if set.reads().len() > budget.reads {
            return Err(EvalFail::Over("reads".into()));
        }
        for r in set.reads() {
            let (got, es) = match self.read_exact(r).await {
                Ok(x) => x,
                Err(ReadFail::Data(e)) => return Err(EvalFail::Data(e)),
                Err(ReadFail::Conflict(m)) => return Err(EvalFail::Conflict(m)),
                Err(ReadFail::Changed(m)) => return Err(EvalFail::Changed(m)),
            };
            bytes += got_size(&got);
            if bytes > budget.read_bytes {
                return Err(EvalFail::Over("octets read".into()));
            }
            for e in &es {
                add_epoch(&mut epochs, e);
            }
        }
        if epochs.len() > crate::answer::SEAL_EPOCHS_MAX {
            return Err(EvalFail::TooLarge(AnswerRefusal::TooLarge {
                what: "the epochs of the reads".into(),
                size: epochs.len() as u64,
                limit: crate::answer::SEAL_EPOCHS_MAX as u64,
            }));
        }
        Ok(epochs)
    }
}
