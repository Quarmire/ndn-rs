//! Membership as an operation fold (spec §5).
//!
//! What a space's members are is not stored anywhere: it is computed from the
//! Members and Epoch entries the owner's devices signed. Those entries are
//! facts in grow-only sets (`adds`, `removed`, `epochs`, `create`); every
//! query is a pure function of the sets, so two nodes holding the same
//! entries agree whatever order the entries reached them in and however
//! often they were applied. Removal wins over an Add of the same id; a person
//! removed and admitted again needs a fresh id.
//!
//! The module trusts its caller: only entries signed by a device of the
//! owner's namespace are applied (admission, spec §5).
//!
//! The fold keeps the carrier of every Members fact, so an entry the log
//! later withdraws (its signer's key revoked, say) can be taken out again
//! by [`Fold::withdraw_members`]: facts cannot be subtracted, so the sets
//! are recomputed from the remaining carriers, which is the same function
//! the incremental form computes.

use std::collections::{BTreeMap, BTreeSet};

use ndn_foundation_types::Name;

use crate::wire::{EntryRef, EpochBody, EpochId, MembersBody, Op, Role};

/// Who may read a space.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Readers {
    /// Everybody: a public space, never sealed.
    Anyone,
    /// These persons, the owner first and the rest sorted.
    Persons(Vec<Name>),
}

impl Readers {
    /// Whether `person` may read.
    pub fn contains(&self, person: &Name) -> bool {
        match self {
            Readers::Anyone => true,
            Readers::Persons(persons) => persons.contains(person),
        }
    }
}

/// One Add as its carrying entry said it.
#[derive(Clone, Debug)]
struct Added {
    carrier: EntryRef,
    who: Name,
    role: Role,
    epoch: Option<EpochId>,
}

/// The order that picks one of several entries claiming the same fact: the
/// lowest signed digest; device and seq only make the order total.
fn rank(carrier: &EntryRef) -> (&[u8; 32], &Name, u64) {
    (&carrier.digest, &carrier.device, carrier.seq)
}

/// The facts the Members entries state.
#[derive(Debug, Default)]
struct Facts {
    /// Add id → the Add, from the carrier of lowest rank.
    adds: BTreeMap<[u8; 16], Added>,
    /// Add id → the union of the tips of every Remove naming it.
    removed: BTreeMap<[u8; 16], BTreeSet<EntryRef>>,
    /// The Create of the carrier of lowest rank.
    create: Option<(EntryRef, bool)>,
}

impl Facts {
    fn absorb(&mut self, carrier: &EntryRef, body: &MembersBody) {
        if let Some(anyone) = body.create {
            let better = match &self.create {
                None => true,
                Some((held, held_anyone)) => (rank(carrier), anyone) < (rank(held), *held_anyone),
            };
            if better {
                self.create = Some((carrier.clone(), anyone));
            }
        }
        for op in &body.ops {
            match op {
                Op::Add {
                    id,
                    who,
                    role,
                    epoch,
                } => {
                    let better = match self.adds.get(id) {
                        None => true,
                        Some(held) => rank(carrier) < rank(&held.carrier),
                    };
                    if better {
                        self.adds.insert(
                            *id,
                            Added {
                                carrier: carrier.clone(),
                                who: who.clone(),
                                role: *role,
                                epoch: epoch.clone(),
                            },
                        );
                    }
                }
                Op::Remove { id, tips } => {
                    self.removed
                        .entry(*id)
                        .or_default()
                        .extend(tips.iter().cloned());
                }
            }
        }
    }
}

/// A space's membership, folded from its Members and Epoch entries.
#[derive(Debug)]
pub struct Fold {
    owner: Name,
    /// Every Members entry applied, so one can be withdrawn.
    carriers: BTreeMap<EntryRef, MembersBody>,
    facts: Facts,
    epochs: BTreeMap<EpochId, EpochBody>,
}

impl Fold {
    /// An empty fold for a space owned by `owner` (the first components of
    /// the space name): the owner alone writes and reads.
    pub fn new(owner: Name) -> Fold {
        Fold {
            owner,
            carriers: BTreeMap::new(),
            facts: Facts::default(),
            epochs: BTreeMap::new(),
        }
    }

    /// The space owner.
    pub fn owner(&self) -> &Name {
        &self.owner
    }

    /// Takes in the Members entry `carrier` (its signed-region digest is the
    /// tie-break between entries that claim one Add id). Idempotent and
    /// commutative.
    pub fn apply_members(&mut self, carrier: &EntryRef, body: &MembersBody) {
        if self.carriers.contains_key(carrier) {
            return;
        }
        self.facts.absorb(carrier, body);
        self.carriers.insert(carrier.clone(), body.clone());
    }

    /// Takes in the Epoch entry that made `id`. Idempotent and commutative:
    /// an owner device that signed two bodies for one id (equivocation, which
    /// the log reports) leaves the least of them by `(key_check, audience)`.
    pub fn apply_epoch(&mut self, id: EpochId, body: &EpochBody) {
        match self.epochs.get_mut(&id) {
            None => {
                self.epochs.insert(id, body.clone());
            }
            Some(held) => {
                if (&body.key_check, &body.audience) < (&held.key_check, &held.audience) {
                    *held = body.clone();
                }
            }
        }
    }

    /// Drops the Members entry `carrier` and everything only it said. Returns
    /// whether it was applied.
    pub fn withdraw_members(&mut self, carrier: &EntryRef) -> bool {
        if self.carriers.remove(carrier).is_none() {
            return false;
        }
        let mut facts = Facts::default();
        for (c, body) in &self.carriers {
            facts.absorb(c, body);
        }
        self.facts = facts;
        true
    }

    /// Drops the epoch `id` (the entry that made it, whichever copy). Returns
    /// whether it was known.
    pub fn withdraw_epoch(&mut self, id: &EpochId) -> bool {
        self.epochs.remove(id).is_some()
    }

    /// Whether the Add `id` still stands. A Remove of an Add naming the owner
    /// is ignored: the owner is a member by being the owner.
    fn stands(&self, id: &[u8; 16], added: &Added) -> bool {
        added.who == self.owner || !self.facts.removed.contains_key(id)
    }

    fn standing(&self, role: Role) -> impl Iterator<Item = &Added> {
        self.facts
            .adds
            .iter()
            .filter(move |(id, a)| a.role == role && self.stands(id, a))
            .map(|(_, a)| a)
    }

    /// `Some(anyone)` once a Create is known: whether everybody may read.
    pub fn create(&self) -> Option<bool> {
        self.facts.create.as_ref().map(|(_, anyone)| *anyone)
    }

    fn anyone(&self) -> bool {
        self.create() == Some(true)
    }

    /// The owner first, then `rest` sorted.
    fn owner_first(&self, rest: BTreeSet<Name>) -> Vec<Name> {
        let mut out = vec![self.owner.clone()];
        out.extend(rest.into_iter().filter(|p| *p != self.owner));
        out
    }

    /// The persons that may write: the owner first, then the rest sorted.
    pub fn writers(&self) -> Vec<Name> {
        self.owner_first(self.standing(Role::Writer).map(|a| a.who.clone()).collect())
    }

    /// Whom the space reads for: everybody, or the owner first and then the
    /// rest sorted.
    pub fn readers(&self) -> Readers {
        if self.anyone() {
            Readers::Anyone
        } else {
            Readers::Persons(self.owner_first(self.reader_set()))
        }
    }

    fn reader_set(&self) -> BTreeSet<Name> {
        let mut set: BTreeSet<Name> = self.standing(Role::Reader).map(|a| a.who.clone()).collect();
        set.insert(self.owner.clone());
        set
    }

    /// Every person the fold lists as a writer or a reader, the owner first
    /// and the rest sorted.
    pub fn persons(&self) -> Vec<Name> {
        let rest = self
            .facts
            .adds
            .iter()
            .filter(|(id, a)| self.stands(id, a))
            .map(|(_, a)| a.who.clone())
            .collect();
        self.owner_first(rest)
    }

    /// Whether `person` may write.
    pub fn is_writer(&self, person: &Name) -> bool {
        *person == self.owner || self.standing(Role::Writer).any(|a| a.who == *person)
    }

    /// Whether `person` may read.
    pub fn is_reader(&self, person: &Name) -> bool {
        self.anyone()
            || *person == self.owner
            || self.standing(Role::Reader).any(|a| a.who == *person)
    }

    /// The union of the tips of every removed writer Add naming `person`:
    /// what the owner held of that person's devices when it removed them.
    /// Sorted. Never any for the owner.
    pub fn removal_tips(&self, person: &Name) -> Vec<EntryRef> {
        if *person == self.owner {
            return Vec::new();
        }
        let tips: BTreeSet<&EntryRef> = self
            .facts
            .adds
            .iter()
            .filter(|(_, a)| a.role == Role::Writer && a.who == *person)
            .filter_map(|(id, _)| self.facts.removed.get(id))
            .flatten()
            .collect();
        tips.into_iter().cloned().collect()
    }

    /// Every person whose writer Add was removed and who no standing writer
    /// Add admits again, with the union of the removal tips (sorted); persons
    /// sorted, the owner never listed. This is what a restarted node needs to
    /// rebuild the cuts of removed writers from the entries alone.
    pub fn removed_writers(&self) -> Vec<(Name, Vec<EntryRef>)> {
        let mut gone: BTreeMap<&Name, BTreeSet<&EntryRef>> = BTreeMap::new();
        for (id, added) in &self.facts.adds {
            if added.role != Role::Writer || added.who == self.owner {
                continue;
            }
            if let Some(tips) = self.facts.removed.get(id) {
                gone.entry(&added.who).or_default().extend(tips);
            }
        }
        gone.into_iter()
            .filter(|(who, _)| !self.is_writer(who))
            .map(|(who, tips)| (who.clone(), tips.into_iter().cloned().collect()))
            .collect()
    }

    /// The ids of the Adds naming `person` that still stand, in either role:
    /// what a removal of the person names. Sorted by id; never any for the
    /// owner (a Remove of an Add naming the owner is ignored).
    pub fn standing_ids(&self, person: &Name) -> Vec<[u8; 16]> {
        if *person == self.owner {
            return Vec::new();
        }
        self.facts
            .adds
            .iter()
            .filter(|(id, a)| a.who == *person && self.stands(id, a))
            .map(|(id, _)| *id)
            .collect()
    }

    /// The epochs, in the order [`Fold::in_force`] prefers them (ascending).
    pub fn epochs(&self) -> Vec<EpochId> {
        self.epochs.keys().cloned().collect()
    }

    /// The held Epoch body for `id`.
    pub fn epoch_body(&self, id: &EpochId) -> Option<&EpochBody> {
        self.epochs.get(id)
    }

    /// Who is to hold epoch `e`'s key: its audience and the standing readers
    /// admitted to its history. A reader removed since is not in it; a person
    /// the epoch names who is no longer a reader still is, which is what keeps
    /// the epoch out of force.
    pub fn audience(&self, e: &EpochId) -> BTreeSet<Name> {
        let mut set: BTreeSet<Name> = self
            .epochs
            .get(e)
            .map(|b| b.audience.iter().cloned().collect())
            .unwrap_or_default();
        set.extend(
            self.standing(Role::Reader)
                .filter(|a| a.epoch.as_ref() == Some(e))
                .map(|a| a.who.clone()),
        );
        set
    }

    /// The epoch writers seal in: the greatest `(creator, seq)` whose audience
    /// is within the readers. `None` if there is none or the space is public.
    pub fn in_force(&self) -> Option<EpochId> {
        if self.anyone() {
            return None;
        }
        let readers = self.reader_set();
        self.epochs
            .keys()
            .rev()
            .find(|e| self.audience(e).is_subset(&readers))
            .cloned()
    }

    /// Whether the epoch in force is for exactly the readers. When it is not,
    /// the owner's devices owe the space an Epoch entry whose audience is
    /// `readers()`. A public space is always complete.
    pub fn complete(&self) -> bool {
        if self.anyone() {
            return true;
        }
        self.in_force()
            .is_some_and(|e| self.audience(&e) == self.reader_set())
    }
}

#[cfg(test)]
#[path = "fold_tests.rs"]
mod tests;
