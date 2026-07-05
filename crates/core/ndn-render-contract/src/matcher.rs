//! The matcher — obligations C6/C6′, C8, C9, C10 made executable.
//!
//! `match` takes the frozen DAG (manifests + vocabularies + contracts), a
//! per-consumer trust frontier, and an explicit work budget, and produces the
//! four ratified verdicts (ndf-red-team, C6′):
//!
//! - **Express** — a fidelity-preserving path from the manifest's type to the
//!   clause's target, through admitted edges only.
//! - **Approximate(loss-path)** — reachable, but at least one `maps-to` hop:
//!   fidelity is the minimum along the chain (C9) and cannot be laundered
//!   back up by a later lossless hop.
//! - **Refuse** — an explicitly declared refusal (redundant with
//!   default-refuse; kept as documentation, L-14).
//! - **Unresolved(missing)** — the DAG or frontier cannot answer: an
//!   unfetched/unadmitted defining vocabulary, a missing import, or a
//!   critical unknown TLV (R12). *Never a guess.*
//!
//! Three silences are meaningful and distinct (C6′): a clause whose target is
//! simply unreachable yields **no Match at all** (a mismatch is not a refusal
//! and not an unresolved); an intent no clause names is refused by default —
//! "unlisted intents are refused, never inferred".
//!
//! The matcher **never evaluates** (C8): selections, predicates, recurrence
//! rules, unit conversions are inert stratum data here; `via` is inert bytes.
//! Reachability is decidable and budgeted (C6): the walk is Dijkstra over a
//! finite, frontier-admitted edge set with memoized per-manifest closures —
//! the gauntlet's bomb (10-deep µ-groups × nested instantiation × a 50k-term
//! subsumption DAG) is a perf note, not a semantics change.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use ndn_manifest::dag::{FrozenDag, Resolution};
use ndn_manifest::hash::Hash;
use ndn_manifest::model::{Clause, Contract, Document, EdgeForm, Manifest, Subject, Via};

/// The per-consumer trust frontier (C10): which vocabularies' *edges* this
/// consumer admits into reachability. Two readers with different frontiers
/// may honestly render different verdicts from the same DAG — divergence is
/// rendered, not hidden.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrustFrontier {
    admitted: BTreeSet<Hash>,
}

impl TrustFrontier {
    /// An empty frontier: no semantic edges are admitted at all. Matching
    /// still works — only exact type-term identity can then Express.
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit a vocabulary's edges.
    pub fn admit(&mut self, vocabulary: Hash) -> &mut Self {
        self.admitted.insert(vocabulary);
        self
    }

    /// Whether a vocabulary's edges are admitted.
    pub fn admits(&self, vocabulary: &Hash) -> bool {
        self.admitted.contains(vocabulary)
    }

    /// Build from an iterator of vocabulary hashes.
    pub fn from_vocabularies<I: IntoIterator<Item = Hash>>(iter: I) -> Self {
        Self { admitted: iter.into_iter().collect() }
    }
}

/// An explicit work budget (C6: decidable *and* bounded). Exhaustion is a
/// typed error on the whole call, not a fifth verdict (D-K7): a partial
/// answer under a blown budget would be a guess wearing a verdict's clothes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    /// Maximum node visits across the whole match call.
    pub max_nodes: u64,
    /// Maximum edge traversals across the whole match call.
    pub max_edges: u64,
}

impl Budget {
    /// A generous default for interactive use.
    pub const fn generous() -> Self {
        Self { max_nodes: 1_000_000, max_edges: 4_000_000 }
    }
}

/// Budget exhaustion — which axis blew.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BudgetExceeded {
    /// Node-visit budget exhausted.
    Nodes,
    /// Edge-traversal budget exhausted.
    Edges,
}

/// What, exactly, the DAG or frontier could not answer (the Unresolved
/// verdict's payload — honest and specific, per C6′).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Missing {
    /// A term's defining vocabulary is not in the DAG (unfetched).
    Vocabulary(Hash),
    /// A term is referenced but no inserted vocabulary defines it.
    Term(Hash),
    /// A document's import closure has absent members.
    Import(Hash),
    /// The manifest (or contract) carries a critical unknown TLV (R12/W-19):
    /// something load-bearing is present that this implementation cannot
    /// read. Skipping it would be a guess.
    CriticalExtension,
}

/// The loss terms traversed, in hop order — the Approximate verdict's
/// declared cost (C9). Rendered to users as-is; never summarized away.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LossPath(pub Vec<Hash>);

/// The four ratified verdicts (C6′).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Full-fidelity path, admitted edges only.
    Express,
    /// Reachable through at least one lossy hop; the losses are declared.
    Approximate(LossPath),
    /// Explicitly refused by the contract (documentation; default-refuse
    /// covers everything unlisted anyway — L-14).
    Refuse,
    /// The question cannot be answered from this DAG under this frontier.
    Unresolved(Missing),
}

impl Verdict {
    /// Deterministic rank for selection (F46): lower is better.
    pub fn rank(&self) -> u8 {
        match self {
            Verdict::Express => 0,
            Verdict::Approximate(_) => 1,
            Verdict::Refuse => 2,
            Verdict::Unresolved(_) => 3,
        }
    }

    /// Loss-path length (0 for non-Approximate) — the F46 second key.
    pub fn loss_len(&self) -> usize {
        match self {
            Verdict::Approximate(l) => l.0.len(),
            _ => 0,
        }
    }
}

/// One (manifest, contract, clause) outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Match {
    /// The contract document's hash.
    pub contract: Hash,
    /// The manifest document's hash.
    pub manifest: Hash,
    /// The clause's intent name.
    pub intent: String,
    /// The verdict.
    pub verdict: Verdict,
    /// Term hops from the manifest's type to the clause target (inclusive),
    /// when a path exists; empty otherwise. Auditable, walkable provenance.
    pub path: Vec<Hash>,
}

/// The consumer's selection floor (C6′, red-team round): the minimum verdict
/// this consumer will accept. `Approximate` admits Express and Approximate;
/// `Express` admits only Express.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Floor {
    /// Only full-fidelity matches.
    Express,
    /// Full-fidelity or declared-loss matches.
    Approximate,
}

// ───────────────────────── edge index (C10-gated) ───────────────────────────

/// Directed, weighted adjacency assembled from *admitted* vocabularies only.
struct EdgeIndex {
    /// from-term → [(to-term, loss)]; loss = None for fidelity-preserving
    /// hops (narrower-than, equivalent-to), Some(loss-term) for maps-to.
    adj: BTreeMap<Hash, Vec<(Hash, Option<Hash>)>>,
}

impl EdgeIndex {
    fn build(dag: &FrozenDag, frontier: &TrustFrontier) -> Self {
        let mut adj: BTreeMap<Hash, Vec<(Hash, Option<Hash>)>> = BTreeMap::new();
        let mut push = |from: Hash, to: Hash, loss: Option<Hash>| {
            adj.entry(from).or_default().push((to, loss));
        };
        for (vh, decoded) in dag.iter() {
            // C10: an edge exists *for this consumer* only if its publishing
            // vocabulary is admitted. Unadmitted edges are not "false" — they
            // are simply not in this consumer's world.
            if !frontier.admits(vh) {
                continue;
            }
            let Document::Vocabulary(v) = &decoded.doc else { continue };
            for e in &v.edges {
                match e {
                    // narrower-than: the narrower term is usable where the
                    // broader is asked for — traverse narrower → broader.
                    EdgeForm::NarrowerThan { narrower, broader } => {
                        push(*narrower, *broader, None);
                    }
                    // equivalent-to: symmetric, lossless.
                    EdgeForm::EquivalentTo { a, b } => {
                        push(*a, *b, None);
                        push(*b, *a, None);
                    }
                    // maps-to: directional, lossy — the loss term rides along.
                    EdgeForm::MapsTo { from, to, loss, .. } => {
                        push(*from, *to, Some(*loss));
                    }
                    // Instance edges are L2 data, not subsumption: the
                    // matcher reads them as inert (C8).
                    EdgeForm::Edge { .. } => {}
                }
            }
        }
        // Deterministic traversal order: sort each adjacency list.
        for list in adj.values_mut() {
            list.sort();
        }
        Self { adj }
    }
}

/// Best-known path to a term: (lossy hops, total hops) minimized
/// lexicographically, so any zero-loss route beats every lossy one (C9:
/// Express only when *no* hop is lossy). Paths are stored as predecessor
/// pointers and reconstructed on demand — the bomb's 50k-term chain stays
/// O(E log V), not O(n²) ("the perf note is an index requirement, not a
/// semantics change").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Best {
    lossy: u32,
    hops: u32,
    /// The loss term on the incoming edge, if that edge was a maps-to.
    edge_loss: Option<Hash>,
    /// The predecessor term (None only for the source).
    prev: Option<Hash>,
}

/// Memoized single-source closure from one manifest type term, Dijkstra over
/// (lossy, hops). This is the "reachability memoizes" of the gauntlet's C6
/// verdict: one walk per manifest type, shared by every clause target.
fn closure(
    index: &EdgeIndex,
    source: Hash,
    nodes_left: &mut u64,
    edges_left: &mut u64,
) -> Result<BTreeMap<Hash, Best>, BudgetExceeded> {
    let mut best: BTreeMap<Hash, Best> = BTreeMap::new();
    // Priority queue as an ordered set keyed (lossy, hops, node) — pop_first
    // gives deterministic Dijkstra order; ties break on the term hash.
    let mut queue: BTreeSet<(u32, u32, Hash)> = BTreeSet::new();
    best.insert(source, Best { lossy: 0, hops: 0, edge_loss: None, prev: None });
    queue.insert((0, 0, source));
    while let Some((lossy, hops, node)) = queue.pop_first() {
        if *nodes_left == 0 {
            return Err(BudgetExceeded::Nodes);
        }
        *nodes_left -= 1;
        // Stale queue entry?
        let cur = *best.get(&node).expect("queued nodes have entries");
        if (cur.lossy, cur.hops) != (lossy, hops) {
            continue;
        }
        let Some(neighbors) = index.adj.get(&node) else { continue };
        for (to, loss) in neighbors {
            if *edges_left == 0 {
                return Err(BudgetExceeded::Edges);
            }
            *edges_left -= 1;
            let cand_lossy = lossy + u32::from(loss.is_some());
            let cand_hops = hops + 1;
            let better = match best.get(to) {
                None => true,
                Some(b) => (cand_lossy, cand_hops) < (b.lossy, b.hops),
            };
            if better {
                if let Some(old) = best.insert(
                    *to,
                    Best { lossy: cand_lossy, hops: cand_hops, edge_loss: *loss, prev: Some(node) },
                ) {
                    queue.remove(&(old.lossy, old.hops, *to));
                }
                queue.insert((cand_lossy, cand_hops, *to));
            }
        }
    }
    Ok(best)
}

/// Reconstruct the hop path (source..=target) and the loss terms in hop
/// order from the predecessor map.
fn reconstruct(best: &BTreeMap<Hash, Best>, target: Hash) -> (Vec<Hash>, Vec<Hash>) {
    let mut path = Vec::new();
    let mut losses = Vec::new();
    let mut cursor = Some(target);
    while let Some(node) = cursor {
        path.push(node);
        let b = &best[&node];
        if let Some(l) = b.edge_loss {
            losses.push(l);
        }
        cursor = b.prev;
    }
    path.reverse();
    losses.reverse();
    (path, losses)
}

// ───────────────────────── binds filter (F45) ───────────────────────────────

/// Does the contract's `binds` admit this manifest's subject? Empty binds
/// admit everything. Hash binds are exact; name binds are prefix filters
/// (stream subjects are prefixes — F3/C5's descendant).
fn binds_admit(contract: &Contract, describes: &Subject) -> bool {
    if contract.binds.is_empty() {
        return true;
    }
    contract.binds.iter().any(|b| match (b, describes) {
        (Subject::Hash(bh), Subject::Hash(mh)) => bh == mh,
        (Subject::Name(prefix), Subject::Name(name)) => name.starts_with(prefix.as_str()),
        _ => false,
    })
}

// ───────────────────────────── the matcher ──────────────────────────────────

/// Match every manifest in the DAG against every listed contract, under one
/// frontier and one budget. Contracts are referenced by document hash and
/// must be present in the DAG (they are documents like everything else).
///
/// Returns matches in deterministic order (manifest hash, contract hash,
/// clause order). Budget exhaustion fails the whole call (D-K7).
///
/// # Reading the result: the three silences (C6′)
///
/// An intent can be missing from the returned matches for three DIFFERENT
/// reasons, and only one of them produces a `Match` at all:
///
/// - **Mismatch** — the clause exists but its target is unreachable from
///   the manifest's type under this frontier: **no Match is emitted**. At
///   the call site this is `matches.iter().find(|m| m.intent == "x").is_none()`.
///   This is NOT a refusal and NOT missing knowledge — the offer simply
///   does not apply. (First-user trap, F54: withholding a bridge stratum
///   makes an intent vanish from the results; that vanishing IS the
///   verdictless answer.)
/// - **Refuse** — an explicit `Clause::Refuse` yields a `Match` with
///   `Verdict::Refuse`. Unlisted intents are refused by default *by
///   absence* — they look like mismatch above, never inferred into a Match.
/// - **Unresolved** — the DAG or frontier cannot answer (unfetched term,
///   unadmitted vocabulary, missing import, critical extension): a `Match`
///   with `Verdict::Unresolved(Missing)` names exactly what's absent.
///
/// Treat `None` as "this contract has nothing to say about that intent for
/// this manifest", `Refuse` as "it says no", and `Unresolved` as "it cannot
/// honestly answer yet".
pub fn r#match(
    dag: &FrozenDag,
    contracts: &[Hash],
    frontier: &TrustFrontier,
    budget: Budget,
) -> Result<Vec<Match>, BudgetExceeded> {
    let index = EdgeIndex::build(dag, frontier);
    let mut nodes_left = budget.max_nodes;
    let mut edges_left = budget.max_edges;
    let mut out = Vec::new();

    for (mh, mdecoded) in dag.iter() {
        let Document::Manifest(m) = &mdecoded.doc else { continue };
        // R12/W-19: a critical unknown TLV on the manifest means something
        // load-bearing is unreadable — every offer over it is Unresolved.
        let manifest_critical = mdecoded.critical;
        // One memoized closure per manifest type term (C6: memoize).
        let mut memo: Option<BTreeMap<Hash, Best>> = None;

        for ch in contracts {
            let Some(cdecoded) = dag.get(ch) else {
                // The contract itself is unfetched: nothing to offer.
                continue;
            };
            let Document::Contract(c) = &cdecoded.doc else { continue };
            if !binds_admit(c, &m.describes) {
                continue; // out of scope, silently — a filter, not a verdict
            }
            let contract_critical = cdecoded.critical;
            // C5: a contract with missing imports cannot vouch for its own
            // meaning — Unresolved, never a guess.
            let import_missing = match dag.import_closure(ch) {
                Resolution::Complete(_) => None,
                Resolution::Unresolved { missing, .. } => missing.first().copied(),
            };

            for clause in &c.clauses {
                match clause {
                    Clause::Refuse { intent } => {
                        out.push(Match {
                            contract: *ch,
                            manifest: *mh,
                            intent: intent.name.clone(),
                            verdict: Verdict::Refuse,
                            path: Vec::new(),
                        });
                    }
                    Clause::Express { intent, target, .. }
                    | Clause::Approximate { intent, target, .. } => {
                        let declared_lossy = matches!(clause, Clause::Approximate { .. });
                        let verdict_and_path = if manifest_critical || contract_critical {
                            Some((Verdict::Unresolved(Missing::CriticalExtension), Vec::new()))
                        } else if let Some(imp) = import_missing {
                            Some((Verdict::Unresolved(Missing::Import(imp)), Vec::new()))
                        } else {
                            resolve_reach(
                                dag,
                                &index,
                                &mut memo,
                                frontier,
                                m,
                                *target,
                                declared_lossy,
                                &mut nodes_left,
                                &mut edges_left,
                            )?
                        };
                        if let Some((verdict, path)) = verdict_and_path {
                            out.push(Match {
                                contract: *ch,
                                manifest: *mh,
                                intent: intent.name.clone(),
                                verdict,
                                path,
                            });
                        }
                        // else: plain mismatch — no Match (C6′: mismatch is
                        // neither refusal nor unresolved).
                    }
                }
            }
        }
    }
    Ok(out)
}

/// Reachability for one (manifest-type, target) pair, with memoized closure.
/// `None` = mismatch (no Match emitted). `Some((verdict, path))` otherwise.
#[allow(clippy::too_many_arguments)]
fn resolve_reach(
    dag: &FrozenDag,
    index: &EdgeIndex,
    memo: &mut Option<BTreeMap<Hash, Best>>,
    frontier: &TrustFrontier,
    m: &Manifest,
    target: Hash,
    declared_lossy: bool,
    nodes_left: &mut u64,
    edges_left: &mut u64,
) -> Result<Option<(Verdict, Vec<Hash>)>, BudgetExceeded> {
    let source = m.ty;
    // Trivial identity: the manifest's type IS the target (the T₀-over-IM₀
    // case, C3). No vocabulary needed, no edges consulted.
    if source == target {
        let verdict = if declared_lossy {
            Verdict::Approximate(LossPath::default())
        } else {
            Verdict::Express
        };
        return Ok(Some((verdict, alloc::vec![source])));
    }
    // Beyond identity, the manifest's type must be a term this consumer can
    // resolve: defined by a fetched AND admitted vocabulary (C6′/C10).
    match dag.defining_vocabulary(&source) {
        None => return Ok(Some((Verdict::Unresolved(Missing::Term(source)), Vec::new()))),
        Some(vh) if !frontier.admits(&vh) => {
            return Ok(Some((Verdict::Unresolved(Missing::Vocabulary(vh)), Vec::new())));
        }
        Some(_) => {}
    }
    // Memoized closure from this manifest's type (one walk, all clauses).
    if memo.is_none() {
        *memo = Some(closure(index, source, nodes_left, edges_left)?);
    }
    let reach = memo.as_ref().expect("just filled");
    match reach.get(&target) {
        Some(best) => {
            let (path, losses) = reconstruct(reach, target);
            let verdict = if best.lossy == 0 && !declared_lossy {
                Verdict::Express
            } else {
                // C9 fidelity monotonicity: one lossy hop anywhere demotes
                // the whole path; a declared-approximate clause never
                // upgrades to Express.
                Verdict::Approximate(LossPath(losses))
            };
            Ok(Some((verdict, path)))
        }
        None => {
            // Unreachable. If the target term is not even resolvable in this
            // DAG, that is a missing-knowledge situation, not a mismatch.
            if dag.defining_vocabulary(&target).is_none() {
                Ok(Some((Verdict::Unresolved(Missing::Term(target)), Vec::new())))
            } else {
                Ok(None)
            }
        }
    }
}

/// Deterministic selection under a floor (F46). Filters to the floor, then
/// orders by: verdict rank, loss-path length, contract hash, intent name.
/// Byte-identical inputs give byte-identical selections, forever.
pub fn select(mut matches: Vec<Match>, floor: Floor) -> Vec<Match> {
    matches.retain(|m| match (&m.verdict, floor) {
        (Verdict::Express, _) => true,
        (Verdict::Approximate(_), Floor::Approximate) => true,
        _ => false,
    });
    matches.sort_by(|a, b| {
        a.verdict
            .rank()
            .cmp(&b.verdict.rank())
            .then_with(|| a.verdict.loss_len().cmp(&b.verdict.loss_len()))
            .then_with(|| a.contract.cmp(&b.contract))
            .then_with(|| a.intent.cmp(&b.intent))
    });
    matches
}

/// The best match under a floor, if any.
pub fn select_best(matches: Vec<Match>, floor: Floor) -> Option<Match> {
    select(matches, floor).into_iter().next()
}

/// Resolve the `Via` behind a Match — the one correct lookup every consumer
/// would otherwise reimplement (F54).
///
/// The Match deliberately does not carry the Via: it stays inert data in
/// the contract (C8), referenced by hash like everything else. Dispatching
/// it therefore means walking back to the emitting contract's clause. The
/// fiddly part this helper owns: a contract may name the same intent in
/// several clauses, so when the Match carries a path, the clause is
/// disambiguated by its target being the path's FINAL hop; only when no
/// path exists (Unresolved) does it fall back to the first intent-name
/// match in author order. Refuse clauses carry no via and yield `None`.
pub fn contract_via<'a>(dag: &'a FrozenDag, m: &Match) -> Option<&'a Via> {
    let decoded = dag.get(&m.contract)?;
    let Document::Contract(c) = &decoded.doc else { return None };
    let want_target = m.path.last();
    let mut fallback: Option<&'a Option<Via>> = None;
    for clause in &c.clauses {
        let (intent, target, via) = match clause {
            Clause::Express { intent, target, via, .. }
            | Clause::Approximate { intent, target, via, .. } => (intent, target, via),
            Clause::Refuse { .. } => continue,
        };
        if intent.name != m.intent {
            continue;
        }
        if want_target == Some(target) {
            return via.as_ref();
        }
        if fallback.is_none() {
            fallback = Some(via);
        }
    }
    fallback.and_then(|v| v.as_ref())
}
