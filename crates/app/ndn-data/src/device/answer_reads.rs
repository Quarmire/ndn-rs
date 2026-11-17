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
use crate::version::{Frontier, Parents, VersionId, Writer};
use crate::wire::{self, parse_log_name};

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

/// Add `e` to `epochs`, ascending and once each.
pub(super) fn add_epoch(epochs: &mut Vec<Epoch>, e: &Epoch) {
    if let Err(at) = epochs.binary_search_by(|x| epoch_order(x, e)) {
        epochs.insert(at, e.clone());
    }
}

impl St {
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
                    return Err(ReadFail::Conflict(format!(
                        "the read names {name} with the digest {digest:?} and the version held \
                         here has another"
                    )));
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
                                return Err(ReadFail::Conflict(format!(
                                    "the read names the tip {} seq {} of {collection} with \
                                     another digest than the version held here",
                                    w.key(),
                                    s.0
                                )));
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

    /// Check each read of `set` this device holds (answers.md §7.3.2, §7.3.1), without fetching:
    /// a conflict of digests is evidence, a read that no longer holds is not. Returns how many
    /// reads are not held here.
    pub(super) fn check_held_reads(&self, set: &ReadSet) -> Result<u32, ReadFail> {
        let st = self.st.lock();
        let mut unverified = 0u32;
        for r in set.reads() {
            match r {
                ReadRef::Version { name, digest } => match st.version_fact(name) {
                    VersionFact::Held { digest: held, .. } if held != digest.0 => {
                        return Err(ReadFail::Conflict(format!(
                            "it names {name} with the digest {digest:?} and this device holds \
                             that version with another"
                        )));
                    }
                    VersionFact::Held { .. } => {}
                    VersionFact::Refused => {
                        return Err(ReadFail::Changed(format!(
                            "the version {name} it read is refused here since"
                        )));
                    }
                    VersionFact::Unknown => unverified += 1,
                },
                ReadRef::State {
                    collection,
                    rule,
                    at,
                    applied,
                } => {
                    let Some(coll) = st.colls.get(collection) else {
                        unverified += 1;
                        continue;
                    };
                    let Some(members) = coll.members.as_ref() else {
                        unverified += 1;
                        continue;
                    };
                    for (w, s, d) in at.tips() {
                        let id = VersionId {
                            writer: w.clone(),
                            seq: s,
                        };
                        if let (Some(hv), Some(d)) = (coll.versions.get(&id), d)
                            && hv.digest != *d
                        {
                            return Err(ReadFail::Conflict(format!(
                                "it names the tip {} seq {} of {collection} with another digest \
                                 than the version this device holds",
                                w.key(),
                                s.0
                            )));
                        }
                    }
                    if let Rule::Merge { function } = &members.rule
                        && function != rule
                    {
                        return Err(ReadFail::Changed(format!(
                            "{collection} is merged here under {function}, not under {rule}"
                        )));
                    }
                    match st.state_facts(
                        collection,
                        at.frontier(),
                        &self.config.rules,
                        &self.writer,
                    ) {
                        Some(f) if f.applied != *applied => {
                            return Err(ReadFail::Changed(format!(
                                "the versions of {collection} the state is computed from here \
                                 are not the ones the answer read: one was withdrawn, pruned or \
                                 expired since"
                            )));
                        }
                        Some(_) => {}
                        None => unverified += 1,
                    }
                }
            }
        }
        Ok(unverified)
    }

    /// The epochs of `set`'s reads this device holds, ascending, and whether it holds every read
    /// (answers.md §5.1).
    pub(super) fn held_epochs(&self, set: &ReadSet) -> (Vec<Epoch>, bool) {
        let st = self.st.lock();
        let mut epochs = Vec::new();
        let mut all = true;
        for r in set.reads() {
            match r {
                ReadRef::Version { name, .. } => match st.version_fact(name) {
                    VersionFact::Held { epoch, .. } => {
                        if let Some(e) = &epoch {
                            add_epoch(&mut epochs, e);
                        }
                    }
                    _ => all = false,
                },
                ReadRef::State { collection, at, .. } => {
                    match st.state_facts(
                        collection,
                        at.frontier(),
                        &self.config.rules,
                        &self.writer,
                    ) {
                        Some(f) => f.epochs.iter().for_each(|e| add_epoch(&mut epochs, e)),
                        None => all = false,
                    }
                }
            }
        }
        (epochs, all)
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

enum Mode<'a> {
    Plan,
    Replay(&'a ReadSet),
}

/// The planning phase's [`Reads`]: every read goes through the layer.
struct Planner<'a> {
    inner: &'a Arc<Inner>,
    mode: Mode<'a>,
    budget: Budget,
    /// The reads the plan made through [`Reads::read`].
    read: Vec<ReadRef>,
    contents: HashMap<ReadRef, Got>,
    epochs: Vec<Epoch>,
    /// What `current` found, so a `read` of it does not fetch again.
    found: HashMap<ReadRef, (Got, Vec<Epoch>)>,
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
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl Reads for Planner<'_> {
    async fn current(&mut self, collection: &Name) -> Result<(ReadRef, Age), DataError> {
        match self.mode {
            Mode::Replay(set) => match set.current(collection) {
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
        if let Mode::Replay(set) = self.mode
            && !set.contains(r)
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
            if !self.read.contains(r) {
                self.read.push(r.clone());
            }
            return Ok(got);
        }
        if self.contents.len() >= self.budget.reads {
            let name = r.collection().unwrap_or_else(|_| Name::root());
            return Err(self.failed(
                EvalFail::Over("reads".into()),
                DataError::Answer {
                    name,
                    why: AnswerRefusal::OverBudget {
                        what: "reads".into(),
                    },
                },
            ));
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
        self.read.push(r.clone());
        self.contents.insert(r.clone(), got.clone());
        Ok(got)
    }
}

/// The evaluation phase's [`ReadView`]: what the plan read, in memory.
struct View<'a> {
    set: &'a ReadSet,
    contents: &'a HashMap<ReadRef, Got>,
    used: RefCell<HashSet<ReadRef>>,
    outside: RefCell<Option<String>>,
}

impl ReadView for View<'_> {
    fn current(&self, collection: &Name) -> Result<&ReadRef, EvalError> {
        self.set.current(collection).ok_or_else(|| {
            let why = format!("the read set has no single read of {collection}");
            *self.outside.borrow_mut() = Some(why.clone());
            EvalError::NotItsReads(why)
        })
    }

    fn read(&self, r: &ReadRef) -> Result<&Got, EvalError> {
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
                Some(set) => Mode::Replay(set),
                None => Mode::Plan,
            },
            budget,
            read: Vec::new(),
            contents: HashMap::from([(definition.clone(), got)]),
            epochs: def_epochs,
            found: HashMap::new(),
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
        let view = View {
            set: &set,
            contents: &planner.contents,
            used: RefCell::new(HashSet::new()),
            outside: RefCell::new(None),
        };
        let evaluated = ev.evaluate(&def, &view);
        let outside = view.outside.borrow().clone();
        let used = view.used.borrow().clone();
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
