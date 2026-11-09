//! Covered versions as a basis (spec §5.2) against what the round-3 review
//! found (L5): a version written apart from a checkpoint over a wide past
//! waits for its whole basis set at most one budget of missed asks, not one
//! per basis; and a basis that arrives after it applied tells the watchers
//! when, and only when, it changes the value.

use futures::StreamExt;

use super::merge_tests::{
    Made, RULE, at, c, checkpoint, device, edit, give, in_pieces, n, rules, state, tip, version,
};
use super::*;

/// An in-test rule that merges an edit against the basis it names: an edit
/// (`E`, as [`edit`] makes it) whose named basis this state holds — applied,
/// or handed as a basis — reads "`<note>` over `<basis note>`", one whose
/// basis is not held reads its note alone (its conflict handling); a
/// checkpoint (`C`) replaces the notes of its past by its own.
struct Over {
    function: Name,
}

impl MergeRule for Over {
    fn function(&self) -> &Name {
        &self.function
    }

    fn start(&self, _collection: &Name, _local: &Writer) -> Box<dyn MergeState> {
        Box::new(OverState::default())
    }
}

#[derive(Default)]
struct OverState {
    /// Each note in the value: the version that wrote it, its words, and
    /// the basis it names (all zero: none).
    notes: Vec<(VersionId, String, [u8; 32])>,
    /// The words of every edit held, applied or handed, by digest.
    held: HashMap<[u8; 32], String>,
}

/// The basis an edit names and its words.
fn edit_of(op: &Op<'_>) -> Result<([u8; 32], String), MergeError> {
    let basis: [u8; 32] = op
        .bytes
        .get(1..33)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| MergeError("an edit names its basis".into()))?;
    let words =
        String::from_utf8(op.bytes[33..].to_vec()).map_err(|_| MergeError("not text".into()))?;
    Ok((basis, words))
}

impl MergeState for OverState {
    fn check(&self, op: &Op<'_>) -> Result<OpKind, MergeError> {
        match op.bytes.first() {
            Some(b'E') => {
                let (basis, _) = edit_of(op)?;
                if basis != [0; 32] && op.past.by_digest(&basis).is_none() {
                    return Err(MergeError("its basis is outside its past".into()));
                }
                Ok(OpKind::Edit)
            }
            Some(b'C') => Ok(OpKind::Checkpoint),
            _ => Err(MergeError("not an operation of this rule".into())),
        }
    }

    fn apply(&mut self, op: &Op<'_>) -> Result<Counting, MergeError> {
        match op.bytes.first() {
            Some(b'E') => {
                let (basis, words) = edit_of(op)?;
                self.held.insert(*op.digest, words.clone());
                self.notes.push((op.id.clone(), words, basis));
            }
            Some(b'C') => {
                self.notes.retain(|(id, ..)| !op.past.contains(id));
                let words = String::from_utf8(op.bytes[1..].to_vec())
                    .map_err(|_| MergeError("not text".into()))?;
                for t in words.split('\n').filter(|t| !t.is_empty()) {
                    self.notes.push((op.id.clone(), t.to_owned(), [0; 32]));
                }
            }
            _ => return Err(MergeError("not an operation of this rule".into())),
        }
        Ok(Counting::Counted)
    }

    fn basis(&mut self, op: &Op<'_>) -> Result<(), MergeError> {
        if op.bytes.first() == Some(&b'E') {
            let (_, words) = edit_of(op)?;
            self.held.insert(*op.digest, words);
        }
        Ok(())
    }

    fn value(&self, excluded: &BTreeSet<VersionId>) -> Value {
        let notes: BTreeSet<String> = self
            .notes
            .iter()
            .filter(|(id, ..)| !excluded.contains(id))
            .map(|(_, words, basis)| match self.held.get(basis) {
                Some(over) if *basis != [0; 32] => format!("{words} over {over}"),
                _ => words.clone(),
            })
            .collect();
        Value::Rule(Bytes::from(
            notes.into_iter().collect::<Vec<_>>().join("\n"),
        ))
    }
}

fn over_rules() -> MergeRules {
    MergeRules::standard().with(Arc::new(Over { function: n(RULE) }))
}

/// A note too large to travel inline: its version comes in pieces.
fn large(note: &str) -> String {
    format!("{note}{}", "p".repeat(3 * wire::INLINE_MAX))
}

/// Every change the watch has delivered so far.
async fn drain(changes: &mut Changes) -> Vec<Change> {
    let mut out = Vec::new();
    while let Ok(Some(Ok(change))) =
        tokio::time::timeout(Duration::from_millis(100), changes.next()).await
    {
        out.push(change);
    }
    out
}

/// Ask once for the pieces of each version `dev` fetches now, each ask
/// missing as a fetch that found them nowhere does
/// ([`Inner::spawn_pieces`]); once every one was asked and missed, the
/// misses are asked again as their pause ends. Whether anything was asked.
fn miss_round(dev: &Device) -> usize {
    let mut st = dev.inner.st.lock();
    let mut asked = st.wanted_pieces(&c());
    if asked.is_empty() {
        st.unfound.clear();
        asked = st.wanted_pieces(&c());
    }
    let mut missed = 0;
    for (v, _) in asked {
        st.unfound.insert(v.clone());
        *st.piece_misses.entry(v.clone()).or_insert(0) += 1;
        st.basis_unfound(&c(), &v);
        missed += 1;
    }
    missed
}

/// Miss asks for what `dev` fetches until `w` applies: how many missed.
fn misses_until_applied(dev: &Device, w: &Made) -> usize {
    let mut missed = 0;
    while !at(dev).contains(&w.id()) {
        let round = miss_round(dev);
        assert!(round > 0, "{:?} waits on bases nothing asks for", w.id());
        missed += round;
        assert!(missed < 10_000, "{:?} never applies", w.id());
    }
    missed
}

#[tokio::test]
async fn a_version_over_a_wide_covered_past_waits_one_budget_of_missed_asks_in_all() {
    let dev = device(rules()).await;
    let covered: Vec<(Made, Vec<pieces::Piece>)> = (1..=40)
        .map(|s| {
            let op = edit(None, &large(&format!("c{s}")));
            in_pieces("/carol/laptop", s, &[], op)
        })
        .collect();
    let newest = &covered.last().expect("forty").0;
    let cp = version("/alice/phone", 1, &[tip(newest)], checkpoint(&["cp"]));
    let w = version("/bob/laptop", 1, &[tip(newest)], edit(None, "w"));
    for (m, _) in &covered {
        give(&dev, m);
    }
    give(&dev, &cp);
    give(&dev, &w);
    assert!(at(&dev).contains(&cp.id()), "the checkpoint applies");
    assert!(
        !at(&dev).contains(&w.id()),
        "the version written apart waits for its basis"
    );
    let missed = misses_until_applied(&dev, &w);
    assert!(
        missed <= REFRESH_TRIES as usize,
        "a version written apart waits at most {REFRESH_TRIES} missed asks for its whole basis \
         set, not that many per basis; it waited {missed}"
    );
    // What it applied without is still fetched, and handed once whole.
    let (first, pieces) = &covered[0];
    {
        let mut st = dev.inner.st.lock();
        assert!(st.colls[&c()].cover.wanted.contains(&first.id()));
        st.unfound.clear();
        assert!(
            !st.wanted_pieces(&c()).is_empty(),
            "the bases it applied without are still fetched"
        );
    }
    for p in pieces {
        dev.inner.store.insert(p.name.clone(), p.wire.clone());
    }
    dev.inner.st.lock().pieces_arrived(&c(), &first.name);
    let st = dev.inner.st.lock();
    assert!(
        st.colls[&c()].cover.basis.contains(&first.id()),
        "handed late"
    );
    assert!(!st.colls[&c()].cover.wanted.contains(&first.id()));
    drop(st);
    dev.shutdown();
}

/// The value of `dev`'s collection, as the rule encodes it.
async fn value(dev: &Device) -> String {
    match state(dev).await.value {
        Value::Rule(b) => String::from_utf8(b.to_vec()).expect("text"),
        other => panic!("not the rule's encoding: {other:?}"),
    }
}

/// `w`, written over a covered version in pieces, applies without it once
/// its fetches missed; the covered version then arrives. What the watch
/// was told once it did, and the value before and after.
async fn late_basis(names_it: bool) -> (Vec<Change>, VersionId, String, String) {
    let dev = device(over_rules()).await;
    let mut changes = dev.watch(&c(), &Frontier::new()).await.unwrap();
    let (x, pieces) = in_pieces("/carol/laptop", 1, &[], edit(None, &large("x")));
    let cp = version("/alice/phone", 1, &[tip(&x)], checkpoint(&["cp"]));
    let basis = names_it.then(|| x.digest());
    let w = version("/bob/laptop", 1, &[tip(&x)], edit(basis, "w"));
    for m in [&x, &cp, &w] {
        give(&dev, m);
    }
    assert!(!at(&dev).contains(&w.id()), "it waits for its basis");
    misses_until_applied(&dev, &w);
    let before = value(&dev).await;
    drain(&mut changes).await;
    for p in pieces {
        dev.inner.store.insert(p.name, p.wire);
    }
    dev.inner.st.lock().pieces_arrived(&c(), &x.name);
    assert!(
        dev.inner.st.lock().colls[&c()]
            .cover
            .basis
            .contains(&x.id()),
        "handed once it arrived"
    );
    let told = drain(&mut changes).await;
    let after = value(&dev).await;
    dev.shutdown();
    (told, x.id(), before, after)
}

#[tokio::test]
async fn a_late_basis_that_changes_the_value_tells_the_watchers() {
    let (told, x, before, after) = late_basis(true).await;
    assert!(
        before.contains("w") && !before.contains("w over"),
        "{before}"
    );
    assert!(
        after.contains("w over x"),
        "merged again against it: {after}"
    );
    assert_eq!(
        told,
        vec![Change::Remerged {
            collection: c(),
            bases: vec![x],
        }],
        "a late basis that changed the value is told to the watchers"
    );
}

#[tokio::test]
async fn a_late_basis_that_changes_nothing_is_not_told() {
    let (told, _, before, after) = late_basis(false).await;
    assert_eq!(before, after);
    assert_eq!(told, Vec::new(), "nothing changed, nothing told");
}
