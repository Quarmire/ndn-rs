//! Answers on a device (`docs/specs/answers.md`): what it keeps of them, serves, and holds as
//! evidence.
//!
//! An own answer is stored, and served only after the store's barrier (§6.2); another signer's
//! answer, taken after the checks of §7.3.3 and accepted by §7.3, is stored and served exactly as
//! signed, under this device's `32=held` (§3.3). What a device keeps of others' answers is bounded
//! per signer and in all (§10); what it signed and must keep (a provider's) is never evicted.
//! Evidence is kept whole under `/localhost/ndn-data/answer-evidence/`, never served and never
//! taken again (§8.2).
//!
//! Layout in the store (all under `/localhost`, which no device serves):
//!
//! | name | value |
//! |---|---|
//! | `/localhost/ndn-data/answers/<SHA-256 of the packet's name TLV>` | an answer packet, or a piece of one, as signed |
//! | `/localhost/ndn-data/answer-results/<id>` | the result digest of an own answer and its kind (1 octet) |
//! | `/localhost/ndn-data/answer-evidence/<SHA-256 of the answer's name TLV and its kind>/<implicit digest>` | an answer packet kept as evidence |

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use bytes::Bytes;
use ndn_foundation_types::NameComponent;
use sha2::{Digest, Sha256};

use super::{Inner, St, rt::Instant};
use crate::answer::{AnswerKind, AnswerStore};
use crate::error::DataError;
use crate::pieces::Piece;
use crate::version::Writer;
use crate::wire::{self, device_of, parse_answer_name, parse_answer_piece_name};
use ndn_packet::{Data, Name};

fn answers_prefix() -> Name {
    "/localhost/ndn-data/answers".parse().expect("a valid name")
}

fn results_prefix() -> Name {
    "/localhost/ndn-data/answer-results"
        .parse()
        .expect("a valid name")
}

fn evidence_prefix() -> Name {
    "/localhost/ndn-data/answer-evidence"
        .parse()
        .expect("a valid name")
}

fn component(octets: &[u8]) -> NameComponent {
    NameComponent::generic(Bytes::copy_from_slice(octets))
}

/// Where the packet named `name` (an answer, or a piece of one) is kept.
pub(super) fn stored_name(name: &Name) -> Name {
    let digest: [u8; 32] = Sha256::digest(name.encode_to_tlv()).into();
    answers_prefix().append_component(component(&digest))
}

/// Where the digest of the result of the answer named `name`, and its kind, are kept: for an own
/// answer, to know what it signed; for another's, to compare a second answer at one name.
fn result_name(name: &Name) -> Name {
    let digest: [u8; 32] = Sha256::digest(name.encode_to_tlv()).into();
    results_prefix().append_component(component(&digest))
}

/// Where a packet held as evidence is kept: under its answer's name and kind, then its own
/// implicit digest, so two packets at one name are two records.
pub(super) fn evidence_name(answer: &Name, kind: AnswerKind, packet: &[u8; 32]) -> Name {
    let mut h = Sha256::new();
    h.update(answer.encode_to_tlv());
    h.update([kind.code() as u8]);
    let dir: [u8; 32] = h.finalize().into();
    evidence_prefix()
        .append_component(component(&dir))
        .append_component(component(packet))
}

/// Whether `name` is one of the stored names of answers (the restore of the log skips them).
pub(super) fn is_stored(name: &Name) -> bool {
    name.has_prefix(&answers_prefix())
        || name.has_prefix(&results_prefix())
        || name.has_prefix(&evidence_prefix())
}

/// An answer this device signed.
struct Own {
    name: Name,
    kind: AnswerKind,
    /// The digest of its result (keyed when anything read is sealed).
    result: [u8; 32],
    /// The octets it takes in the store, its pieces included.
    size: u64,
    pieces: Vec<Name>,
    tick: u64,
}

/// An answer of another signer this device holds, verified and accepted.
struct Held {
    signer: Writer,
    /// The digest of its result.
    result: [u8; 32],
    size: u64,
    pieces: Vec<Name>,
    tick: u64,
}

/// What a device holds of answers: its own, others' it keeps for serving, the evidence it keeps.
#[derive(Default)]
pub(super) struct Book {
    /// This device's answers by id.
    own: BTreeMap<[u8; 32], Own>,
    /// The own answers behind the barrier: only these are served (answers.md §6.2).
    served: HashSet<Name>,
    /// Answers of others, by name.
    held: BTreeMap<Name, Held>,
    /// Every stored piece of an answer.
    pieces: HashSet<Name>,
    /// `(answer name, signer's key)`: what evidence is kept against, never served nor taken again.
    blocked: HashSet<(Name, Name)>,
    /// The digests of the packets kept as evidence, by answer name.
    evidenced: HashMap<Name, BTreeSet<[u8; 32]>>,
    /// When this device signed its recent answers, for its signing rate.
    signed: VecDeque<Instant>,
    /// Counts recency of use.
    tick: u64,
    /// Octets kept (held and own, pieces included).
    total: u64,
}

impl Book {
    fn touch(&mut self) -> u64 {
        self.tick += 1;
        self.tick
    }

    /// Whether evidence is kept against `signer`'s answer at `name`.
    pub(super) fn is_blocked(&self, name: &Name, signer: &Name) -> bool {
        self.blocked.contains(&(name.clone(), signer.clone()))
    }

    /// Whether evidence is kept against any signer's answer at `name`: it is not taken again.
    pub(super) fn is_blocked_name(&self, name: &Name) -> bool {
        self.blocked.iter().any(|(n, _)| n == name)
    }

    /// The digest of the result of the own answer at `id`, and its name.
    pub(super) fn own_result(&self, id: &[u8; 32]) -> Option<(&Name, [u8; 32], AnswerKind)> {
        self.own.get(id).map(|o| (&o.name, o.result, o.kind))
    }

    /// Whether the own answer at `id` is behind the barrier.
    pub(super) fn is_served(&self, name: &Name) -> bool {
        self.served.contains(name)
    }

    /// How many answers this device signed in the last second.
    pub(super) fn signed_in_the_last_second(&mut self, now: Instant) -> usize {
        while self
            .signed
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= std::time::Duration::from_secs(1))
        {
            self.signed.pop_front();
        }
        self.signed.len()
    }

    pub(super) fn note_signed(&mut self, now: Instant) {
        self.signed.push_back(now);
    }

    /// A state a restart cannot reach but a kill between signing and the barrier does: the own
    /// answer `name` is stored and not yet served.
    #[cfg(test)]
    pub(super) fn unserve(&mut self, name: &Name) {
        self.served.remove(name);
    }

    /// The digest of the result of the answer of another held at `name`.
    pub(super) fn held_result(&self, name: &Name) -> Option<[u8; 32]> {
        self.held.get(name).map(|h| h.result)
    }

    /// The names of the answers at `id` kept here, any signer's: this device's own, then those
    /// of others held.
    pub(super) fn names_at(&self, id: &[u8; 32], me: &Name) -> Vec<Name> {
        let mut out: Vec<Name> = self
            .own
            .get(id)
            .map(|o| o.name.clone())
            .into_iter()
            .collect();
        out.extend(
            self.held
                .keys()
                .filter(|n| parse_answer_name(n).is_some_and(|(d, i)| i == *id && d != *me))
                .cloned(),
        );
        out
    }

    /// The names of every answer held or own, for the checks after a trust context is adopted.
    fn every_name(&self) -> Vec<Name> {
        self.own
            .values()
            .map(|o| o.name.clone())
            .chain(self.held.keys().cloned())
            .collect()
    }

    /// Octets kept of `signer`'s held answers, and how many.
    fn of_signer(&self, signer: &Writer) -> (usize, u64) {
        self.held
            .values()
            .filter(|h| h.signer == *signer)
            .fold((0, 0), |(n, b), h| (n + 1, b + h.size))
    }
}

impl Inner {
    /// What this device answers for `name` when it is an answer's or a piece of one's
    /// (answers.md §6.2, §8.2, §13.9): `None` when the name is neither. An own answer is served
    /// once it is behind the barrier; another's held verified, as signed; never one with evidence
    /// kept against it, one whose signer a trust context held here revokes or whose key is marked
    /// suspected here ([`Device::suspect`](crate::Device::suspect)), or a piece of one of them.
    pub(super) fn answer_packet(&self, name: &Name) -> Option<Option<Bytes>> {
        let answer = match parse_answer_name(name) {
            Some(_) => name.clone(),
            None => parse_answer_piece_name(name)?.0,
        };
        let (device, _) = parse_answer_name(&answer)?;
        let st = self.st.lock();
        let book = &st.answer_book;
        let signer = if device == self.device {
            book.served
                .contains(&answer)
                .then(|| self.writer.key().clone())
        } else {
            book.held.get(&answer).map(|h| h.signer.key().clone())
        };
        let servable = signer.is_some_and(|key| {
            !book.is_blocked(&answer, &key)
                && !self.validator.keyring().context_for(&key).is_revoked(&key)
                && self.suspected_key(&st, &key).is_none()
        });
        let known = answer == *name || book.pieces.contains(name);
        Some(
            (servable && known)
                .then(|| self.store.get(&stored_name(name)))
                .flatten(),
        )
    }

    /// Whether `signer` is a key of this very device: what it signed is its own answer.
    pub(super) fn is_own_key(&self, signer: &Writer) -> bool {
        device_of(signer.key()).as_ref() == Some(&self.device)
    }

    /// The answer packet stored under `name`: its wire, if this device holds it (an own answer
    /// not yet behind the barrier included: this device may use it, it just does not serve it).
    pub(super) fn stored_answer(&self, name: &Name) -> Option<Bytes> {
        self.store.get(&stored_name(name))
    }

    /// Octets an answer takes in the store: its packet and its pieces.
    fn size_of(wire: &Bytes, pieces: &[Piece]) -> u64 {
        wire.len() as u64 + pieces.iter().map(|p| p.wire.len() as u64).sum::<u64>()
    }

    /// Make room for `incoming` octets in what is kept (answers.md §10): of `signer`'s answers
    /// first when it is over its own share, then, over the total, the oldest of every signer's
    /// held, then this device's own pure answers, which anyone recomputes. Never an own answer
    /// that must be kept (a provider's). Whether there is room now.
    fn make_room(&self, st: &mut St, signer: Option<&Writer>, incoming: u64) -> bool {
        let cfg: AnswerStore = self.config.answers.store;
        if incoming > cfg.total_bytes {
            return false;
        }
        if let Some(signer) = signer {
            if incoming > cfg.per_signer_bytes {
                return false;
            }
            loop {
                let (n, bytes) = st.answer_book.of_signer(signer);
                if n < cfg.per_signer_answers && bytes + incoming <= cfg.per_signer_bytes {
                    break;
                }
                let oldest = st
                    .answer_book
                    .held
                    .iter()
                    .filter(|(_, h)| h.signer == *signer)
                    .min_by_key(|(_, h)| h.tick)
                    .map(|(name, _)| name.clone());
                match oldest {
                    Some(name) => self.drop_held(st, &name),
                    None => return false,
                }
            }
        }
        while st.answer_book.total + incoming > cfg.total_bytes {
            let oldest_held = st
                .answer_book
                .held
                .iter()
                .min_by_key(|(_, h)| h.tick)
                .map(|(name, _)| name.clone());
            if let Some(name) = oldest_held {
                self.drop_held(st, &name);
                continue;
            }
            let oldest_pure = st
                .answer_book
                .own
                .iter()
                .filter(|(_, o)| o.kind == AnswerKind::Pure)
                .min_by_key(|(_, o)| o.tick)
                .map(|(id, _)| *id);
            match oldest_pure {
                Some(id) => self.drop_own(st, &id),
                None => return false,
            }
        }
        true
    }

    fn remove_packets(&self, st: &mut St, name: &Name, pieces: &[Name]) {
        self.store.remove(&stored_name(name));
        for p in pieces {
            self.store.remove(&stored_name(p));
            st.answer_book.pieces.remove(p);
        }
    }

    /// Drop the held answer of another at `name`, with its pieces.
    pub(super) fn drop_held(&self, st: &mut St, name: &Name) {
        if let Some(h) = st.answer_book.held.remove(name) {
            st.answer_book.total = st.answer_book.total.saturating_sub(h.size);
            self.store.remove(&result_name(name));
            self.remove_packets(st, name, &h.pieces);
        }
    }

    /// Drop this device's own answer at `id`, with its pieces: no longer stored, served or kept
    /// as what it signed.
    pub(super) fn drop_own(&self, st: &mut St, id: &[u8; 32]) {
        if let Some(o) = st.answer_book.own.remove(id) {
            st.answer_book.total = st.answer_book.total.saturating_sub(o.size);
            st.answer_book.served.remove(&o.name);
            self.store.remove(&result_name(&o.name));
            self.remove_packets(st, &o.name, &o.pieces);
        }
    }

    /// Keep an answer of another this device verified and accepted, as signed, to serve it
    /// (answers.md §3.3): within what it keeps per signer and in all (§10); one over its share
    /// is not kept, and the caller used it all the same. Whether it was kept.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn keep_held(
        &self,
        st: &mut St,
        name: &Name,
        signer: &Writer,
        kind: AnswerKind,
        wire: &Bytes,
        pieces: &[Piece],
        result: [u8; 32],
    ) -> bool {
        if st.answer_book.held.contains_key(name) {
            let tick = st.answer_book.touch();
            if let Some(h) = st.answer_book.held.get_mut(name) {
                h.tick = tick;
            }
            return true;
        }
        let size = Self::size_of(wire, pieces);
        if !self.make_room(st, Some(signer), size) {
            return false;
        }
        let _batch = self.stage.batch();
        for p in pieces {
            self.store.insert(stored_name(&p.name), p.wire.clone());
            st.answer_book.pieces.insert(p.name.clone());
        }
        let mut meta = result.to_vec();
        meta.push(kind.code() as u8);
        self.store.insert(result_name(name), Bytes::from(meta));
        self.store.insert(stored_name(name), wire.clone());
        let tick = st.answer_book.touch();
        st.answer_book.total += size;
        st.answer_book.held.insert(
            name.clone(),
            Held {
                signer: signer.clone(),
                result,
                size,
                pieces: pieces.iter().map(|p| p.name.clone()).collect(),
                tick,
            },
        );
        true
    }

    /// Keep an own answer signed: its packet and pieces, pieces first and the answer last in
    /// one batch, and the digest of its result beside it. Nothing is served yet
    /// ([`Self::serve_own`]). `Busy` when a provider answer, which must be kept, cannot be.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn keep_own(
        &self,
        st: &mut St,
        name: &Name,
        id: &[u8; 32],
        kind: AnswerKind,
        result: [u8; 32],
        wire: &Bytes,
        pieces: &[Piece],
    ) -> Result<(), DataError> {
        let size = Self::size_of(wire, pieces);
        if !self.make_room(st, None, size) {
            return Err(DataError::Answer {
                name: name.clone(),
                why: match size > self.config.answers.store.total_bytes {
                    true => crate::error::AnswerRefusal::TooLarge {
                        what: "the answer, in what this device keeps of answers".into(),
                        size,
                        limit: self.config.answers.store.total_bytes,
                    },
                    false => crate::error::AnswerRefusal::Busy,
                },
            });
        }
        let _batch = self.stage.batch();
        for p in pieces {
            self.store.insert(stored_name(&p.name), p.wire.clone());
            st.answer_book.pieces.insert(p.name.clone());
        }
        let mut meta = result.to_vec();
        meta.push(kind.code() as u8);
        self.store.insert(result_name(name), Bytes::from(meta));
        self.store.insert(stored_name(name), wire.clone());
        let tick = st.answer_book.touch();
        st.answer_book.total += size;
        st.answer_book.own.insert(
            *id,
            Own {
                name: name.clone(),
                kind,
                result,
                size,
                pieces: pieces.iter().map(|p| p.name.clone()).collect(),
                tick,
            },
        );
        Ok(())
    }

    /// The own answer `name` is behind the barrier: serve it (answers.md §6.2).
    pub(super) fn serve_own(&self, name: &Name) {
        self.st.lock().answer_book.served.insert(name.clone());
    }

    /// Keep `wire`, an answer packet this device verified, as evidence against its signer
    /// (answers.md §8.2): stored whole before it is reported, never served nor taken again.
    pub(super) fn keep_evidence(
        &self,
        st: &mut St,
        name: &Name,
        kind: AnswerKind,
        signer: &Name,
        wire: &Bytes,
    ) {
        let digest = wire::implicit_digest(wire);
        self.store
            .insert(evidence_name(name, kind, &digest), wire.clone());
        st.answer_book
            .evidenced
            .entry(name.clone())
            .or_default()
            .insert(digest);
        st.answer_book
            .blocked
            .insert((name.clone(), signer.clone()));
        // Never served, never held: whatever this device held at the name by that signer goes.
        if st.answer_book.held.contains_key(name) {
            self.drop_held(st, name);
        }
        st.answer_book.served.remove(name);
    }

    /// Read back what an earlier run kept: answers verified again (a key may have been revoked
    /// while the device was off), the digests of own results, and the evidence. Everything held
    /// is behind the flush the start made, so an own answer is served from the first moment.
    pub(super) async fn load_answers(&self) {
        // The digest of each result kept, by the answer's name.
        let mut results: HashMap<Name, ([u8; 32], AnswerKind)> = HashMap::new();
        let sidecars = self.store.scan_under(&results_prefix(), 0);
        let mut loaded: Vec<(Name, Data, Bytes)> = Vec::new();
        let mut piece_wires: Vec<(Name, Bytes)> = Vec::new();
        for (stored, wire) in self.store.scan_under(&answers_prefix(), 0) {
            let Ok(data) = Data::decode(wire.clone()) else {
                self.store.remove(&stored);
                continue;
            };
            let name = (*data.name).clone();
            if parse_answer_name(&name).is_some() {
                loaded.push((name, data, wire));
            } else if parse_answer_piece_name(&name).is_some() {
                piece_wires.push((name, wire));
            } else {
                self.store.remove(&stored);
            }
        }
        for (name, _, _) in &loaded {
            let side = result_name(name);
            if let Some((_, value)) = sidecars.iter().find(|(n, _)| *n == side)
                && let (Some(digest), Some(kind)) = (
                    value.get(..32).and_then(|d| <[u8; 32]>::try_from(d).ok()),
                    value
                        .get(32)
                        .and_then(|k| AnswerKind::of_code(u64::from(*k)).ok()),
                )
            {
                results.insert(name.clone(), (digest, kind));
            }
        }
        for (name, data, wire) in loaded {
            let Some((device, id)) = parse_answer_name(&name) else {
                continue;
            };
            let signer = match self.verify(&data).await {
                Ok(signer) => signer,
                Err(why) => {
                    tracing::info!(%name, "a stored answer no longer verifies ({why:?}): dropped");
                    self.store.remove(&stored_name(&name));
                    self.store.remove(&result_name(&name));
                    continue;
                }
            };
            let Some(record) = data
                .content()
                .and_then(|c| crate::answer::Record::decode(c.clone()).ok())
            else {
                self.store.remove(&stored_name(&name));
                continue;
            };
            let Some((result, kind)) = results.get(&name).copied() else {
                // Its result digest is lost: nothing here can vouch for it, so it is dropped;
                // a question asks again, or recomputes.
                self.store.remove(&stored_name(&name));
                continue;
            };
            let pieces: Vec<Name> = match &record.content {
                crate::answer::Content::Pieces { size, .. } => wire::piece_names(
                    &name,
                    &wire::ChunksBody {
                        size: *size,
                        root: [0; 32],
                    },
                )
                .collect(),
                _ => Vec::new(),
            };
            let mut size = wire.len() as u64;
            let mut st = self.st.lock();
            for p in &pieces {
                if let Some((_, w)) = piece_wires.iter().find(|(n, _)| n == p) {
                    size += w.len() as u64;
                    st.answer_book.pieces.insert(p.clone());
                }
            }
            let tick = st.answer_book.touch();
            st.answer_book.total += size;
            if device == self.device {
                st.answer_book.served.insert(name.clone());
                st.answer_book.own.insert(
                    id,
                    Own {
                        name: name.clone(),
                        kind,
                        result,
                        size,
                        pieces,
                        tick,
                    },
                );
            } else {
                st.answer_book.held.insert(
                    name.clone(),
                    Held {
                        signer,
                        result,
                        size,
                        pieces,
                        tick,
                    },
                );
            }
        }
        let mut st = self.st.lock();
        for (_, wire) in self.store.scan_under(&evidence_prefix(), 0) {
            let Ok(data) = Data::decode(wire.clone()) else {
                continue;
            };
            let Some(key) = data.sig_info().and_then(|s| s.key_locator_name()) else {
                continue;
            };
            st.answer_book
                .blocked
                .insert(((*data.name).clone(), (*key).clone()));
            st.answer_book
                .evidenced
                .entry((*data.name).clone())
                .or_default()
                .insert(wire::implicit_digest(&wire));
        }
    }

    /// After a trust context is adopted: every answer held or own whose signer's key or chain a
    /// context held now refuses is dropped, and no longer served (answers.md §13.9).
    pub(super) async fn rejudge_answers(&self) {
        let names = self.st.lock().answer_book.every_name();
        for name in names {
            let Some(wire) = self.stored_answer(&name) else {
                continue;
            };
            let Ok(data) = Data::decode(wire) else {
                continue;
            };
            if self.verify(&data).await.is_ok() {
                continue;
            }
            tracing::info!(%name, "an answer's signer is refused by a trust context held now: dropped");
            let mut st = self.st.lock();
            if let Some((_, id)) = parse_answer_name(&name)
                && st.answer_book.own.contains_key(&id)
            {
                self.drop_own(&mut st, &id);
            }
            self.drop_held(&mut st, &name);
        }
    }
}

#[cfg(test)]
impl super::Device {
    /// How many answers of others this device holds, to serve them.
    pub(super) fn answers_held(&self) -> usize {
        self.inner.st.lock().answer_book.held.len()
    }
}
