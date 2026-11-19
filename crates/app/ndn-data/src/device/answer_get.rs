//! Getting and making answers (`docs/specs/answers.md` §6, §7, §8): opening a packet and
//! checking it (§7.3.3), resolving a question (§7.2), recompute-or-trust (§7.3), evidence (§8) and
//! signing an answer (§6.2).
//!
//! Nothing here computes for a remote requester: an answer is made for this device's own host, by
//! [`Device::publish_answer`] and [`Device::provide`] (or by a `get` when
//! `Config::answers.publish` says so), and for no Interest but an authenticated ask of an asker
//! of the audience of every read, which `answer_ask` serves by those same calls (§15).

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use futures::future::join_all;
use ndn_foundation_types::Hash;
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Name};

use super::answer_reads::{EvalFail, Evaluated, ReadFail, VersionFact, add_epoch};
use super::answers::{Cause, Signing};
use super::heard::RELAYS_ASKED;
use super::{Device, Inner, local};
use crate::answer::{
    AnswerAsk, AnswerBinding, AnswerKind, Answered, Body, Content, Provenance, ReadRef, ReadSet,
    Record, Signers,
};
use crate::collection::Epoch;
use crate::error::{AnswerRefusal, DataError, Refusal};
use crate::events::{AnswerFault, EventDetail, ReadSetFault};
use crate::layer::{Age, Answer, Got};
use crate::pieces::{self, Piece, Shape};
use crate::seal::{self, AudienceKeys};
use crate::version::Writer;
use crate::wire::{
    self, INLINE_MAX, PAYLOAD_MAX, PieceKind, device_of, parse_answer_name,
    parse_answer_piece_name, parse_question_name, piece_name,
};

/// An answer packet that passed the checks of every answer (answers.md §7.3.3, steps 1 to 5).
pub(super) struct Opened {
    pub(super) data: Data,
    pub(super) name: Name,
    pub(super) id: [u8; 32],
    pub(super) signer: Writer,
    pub(super) kind: AnswerKind,
    pub(super) body: Body,
    pub(super) epochs: Vec<Epoch>,
    /// How many of its reads this device does not hold, so did not check.
    pub(super) unverified: u32,
    pub(super) result_digest: [u8; 32],
    /// Its pieces, when it travels in pieces.
    pub(super) pieces: Vec<Piece>,
}

/// A question resolved up to its binding and id (answers.md §7.2 steps 1 to 4).
pub(super) struct Resolved {
    pub(super) kind: AnswerKind,
    pub(super) binding: AnswerBinding,
    pub(super) reads: ReadSet,
    pub(super) epochs: Vec<Epoch>,
    pub(super) keys: Option<AudienceKeys>,
    pub(super) id: [u8; 32],
    pub(super) age: Age,
    /// The result this device's own evaluation gave, when it evaluated.
    pub(super) computed: Option<Bytes>,
}

fn answer_error(name: &Name, why: AnswerRefusal) -> DataError {
    DataError::Answer {
        name: name.clone(),
        why,
    }
}

/// What the refusal for signing too many answers in one second names
/// ([`AnswerRefusal::OverBudget`]): a rate that passes with the second, not a size.
pub(super) const SIGNED_PER_SECOND: &str = "answers signed per second";

impl Inner {
    // ---- keys ---------------------------------------------------------------------------------

    /// The audience keys of `epochs` (answers.md §5.2), `None` when there are none (nothing read
    /// is sealed). A key not held is [`DataError::Sealed`]: the reads that gave the epochs were
    /// read with it, so a missing one was erased or never granted.
    pub(super) fn audience(
        &self,
        epochs: &[Epoch],
        name: &Name,
    ) -> Result<Option<AudienceKeys>, DataError> {
        if epochs.is_empty() {
            return Ok(None);
        }
        let st = self.st.lock();
        let mut keys = Vec::with_capacity(epochs.len());
        for e in epochs {
            match st.keys.key_of_epoch(e) {
                Some(k) => keys.push(k),
                None => return Err(DataError::Sealed { name: name.clone() }),
            }
        }
        Ok(Some(seal::audience_keys(&keys, epochs)))
    }

    // ---- evidence -----------------------------------------------------------------------------

    /// Evidence of the read-set `fault` against the signer of each answer of `signed`, except one
    /// this device signed itself: that one was made before something this device holds changed
    /// (an evaluator upgraded under the same name), is no fault of any key, and is reproducible,
    /// so it is dropped and never blamed nor blocked (answers.md §8.2).
    fn blame(&self, signed: &[Opened], fault: ReadSetFault) {
        for o in signed {
            if self.is_own_key(&o.signer) {
                let mut st = self.st.lock();
                self.drop_own(&mut st, &o.id);
                continue;
            }
            self.raise_evidence(
                &o.data,
                o.kind,
                &o.signer,
                o.id,
                o.body.binding.reads.0,
                AnswerFault::ReadSet(fault),
            );
        }
    }

    /// Keep `data`, a verified answer packet, as evidence against `signer` and report it as the
    /// device-wide event `AnswerEvidence` (answers.md §8.2): stored whole first, once.
    pub(super) fn raise_evidence(
        &self,
        data: &Data,
        kind: AnswerKind,
        signer: &Writer,
        id: [u8; 32],
        readset: [u8; 32],
        fault: AnswerFault,
    ) {
        let name = (*data.name).clone();
        let mut st = self.st.lock();
        let cause = Cause::of(&fault);
        self.keep_evidence(&mut st, &name, kind, signer.key(), data.raw(), cause);
        st.report_event(EventDetail::Answer {
            answer: name,
            signer: signer.key().clone(),
            id,
            readset,
            fault,
        });
    }

    // ---- opening a packet ---------------------------------------------------------------------

    /// Check an answer packet as every answer is checked before anything of it is used
    /// (answers.md §7.3.3): its signature by the trust context, its exact decoding, its kind, the
    /// audience key that opens it, its binding against its name, its read set and epochs, and
    /// the reads this device holds. A packet that fails is refused as that packet, not as its
    /// name; what is evidence is kept and reported (§8).
    pub(super) async fn open_packet(
        self: &Arc<Self>,
        data: Data,
        want: Option<AnswerKind>,
        sources: &[Name],
    ) -> Result<Opened, DataError> {
        let name = (*data.name).clone();
        let refuse = |why: AnswerRefusal| answer_error(&name, why);
        let Some((device, id)) = parse_answer_name(&name) else {
            return Err(DataError::BadName {
                name,
                why: "an answer is <device>/32=answer/<id>, the id one component of 32 octets"
                    .into(),
            });
        };
        // 1. The signature, by the trust context as a log entry's is.
        let signer = match self.verify(&data).await {
            Ok(w) => w,
            Err(Refusal::OutsideCut(_)) => {
                return Err(refuse(AnswerRefusal::Untrusted {
                    why: "its signer's key is revoked by a trust context held here, and no cut \
                          lists an answer"
                        .into(),
                }));
            }
            Err(lapsed @ Refusal::Lapsed { .. }) => {
                return Err(refuse(AnswerRefusal::Untrusted {
                    why: lapsed.to_string(),
                }));
            }
            Err(_) => {
                return Err(refuse(AnswerRefusal::Untrusted {
                    why: "its signature, or the certificate chain of its key, does not verify \
                          here"
                        .into(),
                }));
            }
        };
        if device_of(signer.key()).as_ref() != Some(&device) {
            return Err(refuse(AnswerRefusal::Malformed(format!(
                "it is signed by {}, a key of another device than the one its name is under",
                signer.key()
            ))));
        }
        if let Some(since) = self.suspected_key(&self.st.lock(), signer.key()) {
            return Err(refuse(AnswerRefusal::Untrusted {
                why: format!(
                    "its signer's key {} is marked suspected here since {}, so no answer of it is \
                     taken or served; unsuspect the key if it is not lost, or revoke it",
                    signer.key(),
                    since.0
                ),
            }));
        }
        // Evidence that never ends refuses the packet at once; evidence of what this device
        // holds (a read's digest, the epochs) is judged again below, since what it holds may
        // have changed since.
        let blocked = self.st.lock().answer_book.cause_of(&name, signer.key());
        if blocked == Some(Cause::Signed) {
            return Err(refuse(AnswerRefusal::Equivocal));
        }
        let rejudging = blocked.is_some();
        // 2. Exact decoding, and the kind asked for.
        let Some(content) = data.content().cloned() else {
            return Err(refuse(AnswerRefusal::Malformed("it has no content".into())));
        };
        let record = Record::decode(content).map_err(|e| refuse(AnswerRefusal::Malformed(e.0)))?;
        if want.is_some_and(|k| k != record.kind) {
            return Err(refuse(AnswerRefusal::Malformed(format!(
                "it is an answer of kind {:?}, not the kind asked for",
                record.kind
            ))));
        }
        // 3. Open it with the audience key, or answer the error of §5.2.
        let mut pieces: Vec<Piece> = Vec::new();
        let (plain, epochs, keys) = match record.content {
            Content::Plain(body) => (body, Vec::new(), None),
            Content::Sealed { epochs, ciphertext } => {
                let keys = self
                    .audience(&epochs, &name)?
                    .expect("a sealed answer lists its epochs");
                let plain = seal::open_answer(&keys, &name, record.kind, &epochs, &ciphertext)
                    .ok_or_else(|| {
                        refuse(AnswerRefusal::Malformed(
                            "its payload does not open under the audience key of its epochs, or \
                             is not bound to this name, kind and epochs"
                                .into(),
                        ))
                    })?;
                (plain, epochs, Some(keys))
            }
            Content::Pieces { epochs, size, root } => {
                let (payload, got) = self.fetch_answer_pieces(&name, size, root, sources).await?;
                pieces = got;
                match epochs {
                    None => (payload, Vec::new(), None),
                    Some(epochs) => {
                        let keys = self
                            .audience(&epochs, &name)?
                            .expect("a sealed answer lists its epochs");
                        let plain = seal::open_answer(&keys, &name, record.kind, &epochs, &payload)
                            .ok_or_else(|| {
                                refuse(AnswerRefusal::Malformed(
                                    "its pieces do not open under the audience key of its \
                                         epochs"
                                        .into(),
                                ))
                            })?;
                        (plain, epochs, Some(keys))
                    }
                }
            }
        };
        // A sealed body is its AnswerBody and the padding it is due (answers.md §13.3).
        let plain = match keys {
            Some(_) => crate::answer::unpad_body(plain).map_err(refuse)?,
            None => plain,
        };
        // Evidence of what this device holds is kept against this signer's answer at this name
        // ([`Cause::Reads`]): the answer is judged afresh, and the evidence ends when it no
        // longer yields the fault (answers.md §8.2). A fault judged again is not told again.
        let evidence = |fault: AnswerFault, readset: [u8; 32], why: AnswerRefusal| match rejudging {
            true => refuse(AnswerRefusal::Equivocal),
            false => {
                self.raise_evidence(&data, record.kind, &signer, id, readset, fault);
                refuse(why)
            }
        };
        // 4. The binding against the name, the read set and the epochs.
        let body = match Body::decode(plain) {
            Ok(b) => b,
            Err(AnswerRefusal::ReadSet(why)) => {
                return Err(evidence(
                    AnswerFault::ReadSet(ReadSetFault::NotCanonical),
                    [0; 32],
                    AnswerRefusal::ReadSet(why),
                ));
            }
            Err(e) => return Err(refuse(e)),
        };
        let readset = body.binding.reads.0;
        if body.binding.kind != record.kind {
            return Err(refuse(AnswerRefusal::Malformed(
                "the kind in its record is not its binding's".into(),
            )));
        }
        if body.reads.digest() != body.binding.reads {
            return Err(evidence(
                AnswerFault::ReadSet(ReadSetFault::Digest),
                readset,
                AnswerRefusal::ReadSet(
                    "the digest of its read set is not the one its binding names".into(),
                ),
            ));
        }
        if let Some(def) = &body.binding.definition
            && !body.reads.contains(def)
        {
            return Err(evidence(
                AnswerFault::ReadSet(ReadSetFault::NotItsReads),
                readset,
                AnswerRefusal::ReadSet("its definition is not one of its reads".into()),
            ));
        }
        if seal::answer_id(&body.binding, keys.as_ref()) != id {
            return Err(evidence(
                AnswerFault::Binding,
                readset,
                AnswerRefusal::Binding,
            ));
        }
        // 5. The reads this device holds, and then the epochs they are sealed in: a read that no
        // longer holds here (a version withdrawn since) changes the epochs a state is computed
        // from, and is no fault of the signer, so it is classified before the epochs are.
        let checked = match self.check_reads(&name, &body.reads, &epochs).await {
            Ok(c) => c,
            Err(ReadFail::Conflict(why)) => {
                return Err(evidence(
                    AnswerFault::ReadSet(ReadSetFault::HeldConflict),
                    readset,
                    AnswerRefusal::ReadSet(why),
                ));
            }
            Err(ReadFail::Changed(why)) => {
                if rejudging {
                    self.lift_evidence(&mut self.st.lock(), &name, signer.key());
                }
                return Err(refuse(AnswerRefusal::ReadsChanged(why)));
            }
            Err(ReadFail::Data(e)) => return Err(e),
        };
        if !checked.lists(&epochs) {
            return Err(evidence(
                AnswerFault::ReadSet(ReadSetFault::Epochs),
                readset,
                AnswerRefusal::ReadSet(
                    "the epochs it lists are not the epochs its reads are sealed in".into(),
                ),
            ));
        }
        if rejudging {
            // The answer no longer yields the fault it was blocked for.
            self.lift_evidence(&mut self.st.lock(), &name, signer.key());
        }
        let unverified = checked.unverified;
        let result_digest = seal::result_digest(&body.result, keys.as_ref());
        Ok(Opened {
            kind: record.kind,
            data,
            name,
            id,
            signer,
            body,
            epochs,
            unverified,
            result_digest,
            pieces,
        })
    }

    /// Two verified answers at one name by one key whose opened results differ are
    /// equivocation (answers.md §8.1): both are kept as evidence and reported, and neither is
    /// used. The same result again (a sealed answer made twice has other bytes) is none.
    pub(super) fn check_equivocation(&self, o: &Opened) -> Result<(), DataError> {
        let first = {
            let st = self.st.lock();
            let own = st
                .answer_book
                .own_result(&o.id)
                .filter(|(name, _, _)| **name == o.name)
                .map(|(_, r, _)| r);
            own.or_else(|| st.answer_book.held_result(&o.name))
        };
        let Some(first) = first else {
            return Ok(());
        };
        if first == o.result_digest {
            return Ok(());
        }
        if self.is_own_key(&o.signer) {
            // A packet this device's key signed, whose result is not what this device holds at
            // its name: a copy made before an evaluator changed its output (answers.md §8.2).
            // No fault of the key, so no evidence and no block.
            return Err(answer_error(
                &o.name,
                AnswerRefusal::Untrusted {
                    why: "it is signed by this device's own key with a result other than the one \
                          this device holds at that name (a copy made before an evaluator \
                          changed its output); this device recomputes instead"
                        .into(),
                },
            ));
        }
        if let Some(wire) = self.stored_answer(&o.name)
            && let Ok(d) = Data::decode(wire)
        {
            let mut st = self.st.lock();
            self.keep_evidence(
                &mut st,
                &o.name,
                o.kind,
                o.signer.key(),
                d.raw(),
                Cause::Signed,
            );
        }
        self.raise_evidence(
            &o.data,
            o.kind,
            &o.signer,
            o.id,
            o.body.binding.reads.0,
            AnswerFault::Equivocation {
                other_result: first,
            },
        );
        Err(answer_error(&o.name, AnswerRefusal::Equivocal))
    }

    // ---- pieces -------------------------------------------------------------------------------

    /// One piece of an answer in pieces, checked against the digest its parent lists: kept
    /// here, else asked of its signer by name, else of each device in `sources` under its own
    /// name (`32=held`), each an owed fetch.
    async fn answer_piece(
        self: &Arc<Self>,
        name: &Name,
        digest: &[u8; 32],
        sources: &[Name],
    ) -> Option<Bytes> {
        if let Some(w) = self.stored_answer(name)
            && wire::implicit_digest(&w) == *digest
        {
            return Some(w);
        }
        /// Rounds of asks for one piece before it is missing (data-layer.md §17.1): the signer,
        /// then each device that may hold it; a lost packet costs a round, not the answer.
        const ANSWER_PIECE_ROUNDS: u32 = 3;
        let fits =
            |d: Data| (*d.name == *name && d.implicit_digest() == *digest).then(|| d.raw().clone());
        for _ in 0..ANSWER_PIECE_ROUNDS {
            if let Some(w) = self.fetch_owed(name.clone(), false).await.and_then(fits) {
                return Some(w);
            }
            for h in sources {
                if let Some(w) = self.fetch_held(name, h).await.and_then(fits) {
                    return Some(w);
                }
            }
        }
        None
    }

    /// The `size` octets of an answer's body (or ciphertext) from its pieces (answers.md §5.4,
    /// data-layer.md §13.1): each manifest node and chunk checked against the digest its parent
    /// lists, the root against the record's, a window at once. No custody is asked.
    async fn fetch_answer_pieces(
        self: &Arc<Self>,
        name: &Name,
        size: u64,
        root: [u8; 32],
        sources: &[Name],
    ) -> Result<(Bytes, Vec<Piece>), DataError> {
        let shape = Shape::of(size);
        let mut digests: HashMap<PieceKind, [u8; 32]> =
            HashMap::from([(PieceKind::Manifest(0), root)]);
        let mut got: Vec<Piece> = Vec::new();
        let missing = |p: &Name| DataError::Unavailable { name: p.clone() };
        for k in shape.manifests() {
            let kind = PieceKind::Manifest(k);
            let expected = *digests.get(&kind).ok_or_else(|| missing(name))?;
            let pname = piece_name(name, kind);
            let w = self
                .answer_piece(&pname, &expected, sources)
                .await
                .ok_or_else(|| missing(&pname))?;
            let listed =
                pieces::open_node(&shape, k, &w, &expected).ok_or_else(|| missing(&pname))?;
            for (kid, d) in shape
                .children(k)
                .ok_or_else(|| missing(&pname))?
                .into_iter()
                .zip(listed)
            {
                digests.insert(kid, d);
            }
            got.push(Piece {
                name: pname,
                wire: w,
                digest: expected,
            });
        }
        let window = self.config.window.max(1);
        let mut payload: Vec<u8> = Vec::with_capacity(size as usize);
        let chunks: Vec<u64> = (0..shape.chunks).collect();
        for batch in chunks.chunks(window) {
            let fetched = join_all(batch.iter().map(|i| {
                let kind = PieceKind::Chunk(*i);
                let pname = piece_name(name, kind);
                let expected = digests.get(&kind).copied();
                async move {
                    let expected = expected?;
                    let w = self.answer_piece(&pname, &expected, sources).await?;
                    Some((pname, expected, w))
                }
            }))
            .await;
            for (i, f) in batch.iter().zip(fetched) {
                let (pname, expected, w) =
                    f.ok_or_else(|| missing(&piece_name(name, PieceKind::Chunk(*i))))?;
                let content =
                    pieces::open_chunk(&shape, *i, &w, &expected).ok_or_else(|| missing(&pname))?;
                payload.extend_from_slice(&content);
                got.push(Piece {
                    name: pname,
                    wire: w,
                    digest: expected,
                });
            }
        }
        Ok((Bytes::from(payload), got))
    }

    // ---- policy -------------------------------------------------------------------------------

    /// Whether `s` covers `signer` for an answer over `reads` (answers.md §9): this device's own
    /// namespace, or a WRITER of every collection read by the records held (a reader of one is no
    /// writer: it could not have changed what the answer read), or a listed device.
    fn covers(&self, s: &Signers, signer: &Writer, reads: &ReadSet) -> bool {
        self.covers_key(s, signer.key(), reads)
    }

    /// [`Self::covers`] for the signer key `key`.
    fn covers_key(&self, s: &Signers, key: &Name, reads: &ReadSet) -> bool {
        let Some(device) = device_of(key) else {
            return false;
        };
        if s.names(&device) {
            return true;
        }
        let own = self.namespace_of_name(&device) == self.ns;
        match s {
            Signers::None | Signers::Devices(_) => false,
            Signers::Own => own,
            Signers::OwnAndMembers => {
                if own {
                    return true;
                }
                let st = self.st.lock();
                let mut collections = reads
                    .reads()
                    .iter()
                    .filter_map(|r| r.collection().ok())
                    .peekable();
                collections.peek().is_some()
                    && collections.all(|c| {
                        st.record_in_force(&c)
                            .is_some_and(|m| self.writer_by(&st, &m, &c, key))
                    })
            }
        }
    }

    /// Of the devices `signers` (from [`Self::candidates`]), those this device's policy could
    /// ever take an answer from for a question of `kind` by `by` over `reads` ([`Self::covers`]
    /// of the policy's list, judged by the device's name as a key of it): an ask carries the
    /// whole read set, so it is sent to no device whose answer would be refused anyway
    /// (answers.md §13.14).
    pub(super) fn askable(
        &self,
        kind: AnswerKind,
        by: &Name,
        reads: &ReadSet,
        signers: Vec<Name>,
    ) -> Vec<Name> {
        let policy = &self.config.answers.policy;
        signers
            .into_iter()
            .filter(|device| {
                let key = device.clone().append("KEY").append("asked");
                match kind {
                    AnswerKind::Pure => self.covers_key(&policy.pure, &key, reads),
                    AnswerKind::Provider => policy
                        .providers
                        .iter()
                        .filter(|(f, _)| f == by)
                        .any(|(_, s)| self.covers_key(s, &key, reads)),
                }
            })
            .collect()
    }

    /// Whether this device takes `signer`'s answer on trust (answers.md §7.3, §9): its own
    /// always; a pure answer from a signer the policy trusts for pure answers; a provider answer
    /// from a signer the policy names as a provider of exactly that function.
    pub(super) fn accepts(&self, o: &Opened) -> Result<(), AnswerRefusal> {
        if device_of(o.signer.key()).as_ref() == Some(&self.device) {
            return Ok(());
        }
        let policy = &self.config.answers.policy;
        match o.kind {
            AnswerKind::Pure => match self.covers(&policy.pure, &o.signer, &o.body.reads) {
                true => Ok(()),
                false => Err(AnswerRefusal::Untrusted {
                    why: format!(
                        "{} is not a signer this device's policy trusts for pure answers",
                        o.signer.key()
                    ),
                }),
            },
            AnswerKind::Provider => {
                let named = policy
                    .providers
                    .iter()
                    .filter(|(f, _)| *f == o.body.binding.by)
                    .any(|(_, s)| self.covers(s, &o.signer, &o.body.reads));
                match named {
                    true => Ok(()),
                    false => Err(AnswerRefusal::NotProvider {
                        signer: o.signer.clone(),
                        function: o.body.binding.by.clone(),
                    }),
                }
            }
        }
    }

    /// The devices a question asks for the answer at `id`, and the devices that may hold the
    /// packets of others (answers.md §7.2 step 5): for a pure answer those the policy trusts
    /// that this device knows; for a provider answer the devices the policy names for the
    /// function. Never this device.
    pub(super) fn candidates(
        &self,
        kind: AnswerKind,
        by: &Name,
        reads: &ReadSet,
    ) -> (Vec<Name>, Vec<Name>) {
        let st = self.st.lock();
        let policy = &self.config.answers.policy;
        let own = self.relays(&st, &self.ns, &self.device, &[]);
        let mut signers: Vec<Name> = Vec::new();
        let mut add = |s: &Signers| match s {
            Signers::None => {}
            Signers::Own => signers.extend(own.iter().cloned()),
            Signers::OwnAndMembers => {
                signers.extend(own.iter().cloned());
                for c in reads.reads().iter().filter_map(|r| r.collection().ok()) {
                    if let Some(ns) = wire::namespace_of(&c)
                        && ns != self.ns
                    {
                        signers.extend(self.relays(&st, &ns, &self.device, &[]));
                    }
                }
            }
            Signers::Devices(names) => {
                signers.extend(names.iter().filter(|n| wire::is_device_name(n)).cloned());
            }
        };
        match kind {
            AnswerKind::Pure => add(&policy.pure),
            AnswerKind::Provider => policy
                .providers
                .iter()
                .filter(|(f, _)| f == by)
                .for_each(|(_, s)| add(s)),
        }
        let mut seen = std::collections::BTreeSet::new();
        signers.retain(|d| *d != self.device && seen.insert(d.clone()));
        signers.truncate(RELAYS_ASKED);
        (signers, own)
    }

    /// Ask every candidate for the answer named `<D>/32=answer/<id>`, and, of the devices that
    /// may hold it, `32=held` (answers.md §7.2 step 5): owed fetches, all at once. Every packet
    /// that comes back, none judged.
    async fn ask_candidates(
        self: &Arc<Self>,
        signers: &[Name],
        relays: &[Name],
        id: &[u8; 32],
    ) -> Vec<Data> {
        let asks = signers.iter().map(|d| {
            let name = wire::answer_name(d, id);
            let relays: Vec<&Name> = relays.iter().filter(|r| *r != d).collect();
            async move {
                if let Some(data) = self.fetch_owed(name.clone(), false).await {
                    return Some(data);
                }
                for h in relays {
                    if let Some(data) = self.fetch_held(&name, h).await {
                        return Some(data);
                    }
                }
                None
            }
        });
        join_all(asks).await.into_iter().flatten().collect()
    }

    // ---- resolving a question -----------------------------------------------------------------

    /// Steps 1 to 4 of answers.md §7.2 for a question already parsed: the read set (stated, or
    /// planned by the evaluator), the epochs and audience key, the binding and the id. `run`:
    /// evaluate as well as plan (a recompute), so [`Resolved::computed`] is the result.
    pub(super) async fn resolve_question(
        self: &Arc<Self>,
        qname: &Name,
        ask: &AnswerAsk,
        run: bool,
    ) -> Result<Resolved, DataError> {
        let budget = self.config.answers.budget;
        let fail = |f: EvalFail| self.eval_error(qname, f, false);
        let (reads, epochs, computed, age) = match ask.kind {
            AnswerKind::Provider => {
                let set = ask.reads.clone().ok_or_else(|| DataError::BadRequest {
                    name: qname.clone(),
                    why: "a provider question states the inputs it asks about".into(),
                })?;
                let epochs = self.read_all(&set, budget).await.map_err(fail)?;
                (set, epochs, None, Age::Exact)
            }
            AnswerKind::Pure => {
                let def = ask
                    .definition
                    .clone()
                    .ok_or_else(|| DataError::BadRequest {
                        name: qname.clone(),
                        why: "a pure question names its definition".into(),
                    })?;
                let ev = self.config.evaluators.get(&ask.by).cloned();
                match (&ask.reads, ev) {
                    (None, None) => {
                        return Err(DataError::CannotCheck {
                            name: qname.clone(),
                            evaluator: ask.by.clone(),
                            why: "this program does not know the evaluator, so it cannot make \
                                  the reads; state the reads, or run a program that knows it"
                                .into(),
                        });
                    }
                    (None, Some(ev)) => {
                        let e = self
                            .evaluate_over(&ev, &def, None, run)
                            .await
                            .map_err(fail)?;
                        let Evaluated {
                            reads,
                            epochs,
                            result,
                            age,
                        } = e;
                        (reads, epochs, run.then_some(result), age)
                    }
                    (Some(set), ev) => {
                        if !set.contains(&def) {
                            return Err(DataError::BadRequest {
                                name: qname.clone(),
                                why: "the definition is not among the reads the question \
                                      states: an evaluator reads its definition like any other \
                                      input; add it to the read set"
                                    .into(),
                            });
                        }
                        match ev {
                            Some(ev) if run => {
                                let e = self
                                    .evaluate_over(&ev, &def, Some(set), true)
                                    .await
                                    .map_err(fail)?;
                                (e.reads, e.epochs, Some(e.result), Age::Exact)
                            }
                            _ => {
                                let epochs = self.read_all(set, budget).await.map_err(fail)?;
                                (set.clone(), epochs, None, Age::Exact)
                            }
                        }
                    }
                }
            }
        };
        // The keys, and the binding and id.
        let keys = self.audience(&epochs, qname)?;
        let binding = AnswerBinding {
            kind: ask.kind,
            definition: ask.definition.clone(),
            by: ask.by.clone(),
            reads: reads.digest(),
        };
        let id = seal::answer_id(&binding, keys.as_ref());
        Ok(Resolved {
            kind: ask.kind,
            binding,
            reads,
            epochs,
            keys,
            id,
            age,
            computed,
        })
    }

    /// What an evaluation's failure is as an error of `get` (answers.md §12). `signed`: an
    /// answer's signer put these reads there, so a read set that is not the evaluator's is a
    /// refusal of that answer, not of a question.
    pub(super) fn eval_error(&self, name: &Name, f: EvalFail, signed: bool) -> DataError {
        match f {
            EvalFail::Data(e) => e,
            EvalFail::Conflict(m) => answer_error(name, AnswerRefusal::ReadSet(m)),
            EvalFail::Changed(m) => answer_error(name, AnswerRefusal::ReadsChanged(m)),
            EvalFail::Refused(m) => DataError::BadRequest {
                name: name.clone(),
                why: format!(
                    "the evaluator refuses its definition or inputs: {m}; ask with a definition \
                     it takes"
                ),
            },
            EvalFail::NotItsReads(m) if signed => answer_error(name, AnswerRefusal::ReadSet(m)),
            EvalFail::NotItsReads(m) => DataError::BadRequest {
                name: name.clone(),
                why: format!(
                    "the stated reads are not the evaluator's reading of its definition: {m}; \
                     state the reads it makes, or ask without stating them"
                ),
            },
            EvalFail::Over(what) => answer_error(name, AnswerRefusal::OverBudget { what }),
            EvalFail::TooLarge(r) => answer_error(name, r),
        }
    }

    fn answered(&self, name: Name, r: &Resolved, result: Bytes, how: Provenance) -> Answered {
        Answered {
            name,
            id: Hash(r.id),
            kind: r.kind,
            binding: r.binding.clone(),
            reads: r.reads.clone(),
            result_digest: Hash(seal::result_digest(&result, r.keys.as_ref())),
            result,
            how,
        }
    }

    // ---- the verb -----------------------------------------------------------------------------

    /// `get` of an exact answer name or a question (answers.md §7).
    pub(super) async fn get_answer(self: &Arc<Self>, name: &Name) -> Result<Answer, DataError> {
        if parse_answer_name(name).is_some() {
            return self.get_answer_by_name(name).await;
        }
        if parse_answer_piece_name(name).is_some() {
            return Err(DataError::BadName {
                name: name.clone(),
                why: "a piece of an answer is fetched with the answer it belongs to; ask for the \
                      answer <device>/32=answer/<id>"
                    .into(),
            });
        }
        if parse_question_name(name).is_none() {
            return Err(DataError::BadName {
                name: name.clone(),
                why: "it has an answer or question keyword and is neither: an answer is \
                      <device>/32=answer/<id> (the id one component of 32 octets), a question \
                      <X>/32=question/<AnswerAsk> (build it with AnswerAsk::name)"
                    .into(),
            });
        }
        let (_, ask) = AnswerAsk::parse_with_x(name)?;
        self.get_question(name, ask).await
    }

    /// Whether this device recomputes `ask` (answers.md §7.3): a pure question whose evaluator
    /// it knows and the policy does not list for trust.
    fn recomputes(&self, ask: &AnswerAsk) -> bool {
        ask.kind == AnswerKind::Pure
            && self.config.evaluators.get(&ask.by).is_some()
            && !self.config.answers.policy.trust.contains(&ask.by)
    }

    async fn get_question(
        self: &Arc<Self>,
        qname: &Name,
        ask: AnswerAsk,
    ) -> Result<Answer, DataError> {
        if ask.kind == AnswerKind::Pure
            && self.config.evaluators.get(&ask.by).is_none()
            && ask.reads.is_none()
            && matches!(self.config.answers.policy.pure, Signers::None)
        {
            return Err(DataError::CannotCheck {
                name: qname.clone(),
                evaluator: ask.by.clone(),
                why: "this program does not know the evaluator and trusts no signer for it \
                      (the policy trusts none); run a program that knows it, or name a signer in \
                      the policy"
                    .into(),
            });
        }
        let run = self.recomputes(&ask);
        let r = match self.resolve_question(qname, &ask, run).await {
            Ok(r) => r,
            // Nothing here plans the reads (the evaluator is not known and none are stated):
            // the signers the policy names may be asked (answers.md §15).
            Err(e @ DataError::CannotCheck { .. }) => {
                return self.asked_answer(qname, &ask, e).await;
            }
            Err(e) => return Err(e),
        };
        let age = r.age;
        let answered = if run {
            self.finish_recomputed(qname, None, r, Vec::new()).await?
        } else {
            match self.finish_trusted(qname, &ask, r, None).await {
                Ok(a) => a,
                // No answer is published where this device looks, and none is held: ask the
                // signers the policy names (answers.md §15).
                Err(e @ DataError::Unavailable { .. }) => {
                    return self.asked_answer(qname, &ask, e).await;
                }
                Err(e) => return Err(e),
            }
        };
        Ok(Answer {
            got: Got::Answer(answered),
            age,
        })
    }

    async fn get_answer_by_name(self: &Arc<Self>, name: &Name) -> Result<Answer, DataError> {
        let (device, id) = parse_answer_name(name).expect("checked by the caller");
        if self.st.lock().answer_book.is_blocked_for_good(name) {
            // Evidence that never ends is kept against it (answers.md §8.2): never taken again.
            // Evidence of what this device holds is judged again when the packet is opened.
            return Err(answer_error(name, AnswerRefusal::Equivocal));
        }
        let (signers, relays) = {
            let st = self.st.lock();
            (
                vec![device.clone()],
                self.relays(&st, &self.ns, &device, &[]),
            )
        };
        // The packet: kept here, else asked of its signer and of the devices that may hold it.
        let data = match self.stored_answer(name).and_then(|w| Data::decode(w).ok()) {
            Some(d) => d,
            None => {
                if device == self.device {
                    return Err(DataError::Unavailable { name: name.clone() });
                }
                self.ask_candidates(&signers, &relays, &id)
                    .await
                    .into_iter()
                    .next()
                    .ok_or_else(|| DataError::Unavailable { name: name.clone() })?
            }
        };
        let opened = self.open_packet(data, None, &relays).await?;
        self.check_equivocation(&opened)?;
        let ask = AnswerAsk {
            kind: opened.kind,
            definition: opened.body.binding.definition.clone(),
            by: opened.body.binding.by.clone(),
            reads: Some(opened.body.reads.clone()),
        };
        let answered = self
            .finish_opened(name, &ask, opened, Some(name.clone()))
            .await?;
        Ok(Answer {
            got: Got::Answer(answered),
            age: Age::Exact,
        })
    }

    /// An answer packet that passed [`Self::open_packet`] and the equivocation check, judged as
    /// every answer is (answers.md §7.3): recomputed when the evaluator is known here, else
    /// taken on trust. `asked` is the name the caller asked for and `exact` the exact answer
    /// name it asked for, if it did; `ask` is what the packet answers.
    pub(super) async fn finish_opened(
        self: &Arc<Self>,
        asked: &Name,
        ask: &AnswerAsk,
        opened: Opened,
        exact: Option<Name>,
    ) -> Result<Answered, DataError> {
        let r = Resolved {
            kind: opened.kind,
            binding: opened.body.binding.clone(),
            reads: opened.body.reads.clone(),
            epochs: opened.epochs.clone(),
            keys: self.audience(&opened.epochs, asked)?,
            id: opened.id,
            age: Age::Exact,
            computed: None,
        };
        if self.recomputes(ask) {
            self.finish_recomputed(asked, exact, r, vec![opened]).await
        } else {
            self.finish_trusted(asked, ask, r, Some(opened)).await
        }
    }

    /// A pure answer this device recomputes (answers.md §7.3, 1): the result is its own, each
    /// signed answer held is compared by digest and confirms or is evidence, and nothing signed
    /// is returned. `signed`: answers already opened (an exact name asked for).
    async fn finish_recomputed(
        self: &Arc<Self>,
        asked: &Name,
        exact: Option<Name>,
        mut r: Resolved,
        signed: Vec<Opened>,
    ) -> Result<Answered, DataError> {
        let ev = self
            .config
            .evaluators
            .get(&r.binding.by)
            .cloned()
            .expect("recomputed only when the evaluator is known");
        let def = r
            .binding
            .definition
            .clone()
            .expect("a pure binding names its definition");
        if r.computed.is_none() {
            let e = self
                .evaluate_over(&ev, &def, Some(&r.reads), true)
                .await
                .map_err(|f| {
                    // The signed answer's read set is not the evaluator's reading of its
                    // definition: evidence against its signer, and the answer is refused.
                    if let EvalFail::NotItsReads(_) | EvalFail::Refused(_) = &f {
                        self.blame(&signed, ReadSetFault::NotItsReads);
                    }
                    if let EvalFail::Conflict(_) = &f {
                        self.blame(&signed, ReadSetFault::HeldConflict);
                    }
                    let is_signed = !signed.is_empty();
                    let f = match f {
                        EvalFail::Refused(m) if is_signed => EvalFail::NotItsReads(m),
                        f => f,
                    };
                    self.eval_error(asked, f, is_signed)
                })?;
            r.computed = Some(e.result);
        }
        let result = r.computed.clone().expect("computed above");
        let digest = seal::result_digest(&result, r.keys.as_ref());
        let (mut confirmed_by, mut disagreed_with): (Vec<Writer>, Vec<Writer>) =
            (Vec::new(), Vec::new());
        // The answers signed at this id this device holds: its own, others' held, and those
        // opened for an exact name.
        let mut seen: Vec<Opened> = signed;
        let held_names: Vec<Name> = {
            let st = self.st.lock();
            st.answer_book.names_at(&r.id, &self.device)
        };
        for n in held_names {
            if seen.iter().any(|o| o.name == n) {
                continue;
            }
            let Some(wire) = self.stored_answer(&n) else {
                continue;
            };
            let Ok(data) = Data::decode(wire) else {
                continue;
            };
            if let Ok(o) = self.open_packet(data, Some(AnswerKind::Pure), &[]).await {
                seen.push(o);
            }
        }
        for o in &seen {
            if o.result_digest == digest {
                confirmed_by.push(o.signer.clone());
            } else if self.is_own_key(&o.signer) {
                // An answer this device signed before its evaluator changed its output under
                // the same name (a host upgrade): no fault of any key, so no evidence and no
                // block. It is reproducible, so it is dropped and the recomputed value stands.
                tracing::info!(name = %o.name, "an own answer differs from the recomputed result: dropped");
                let mut st = self.st.lock();
                self.drop_own(&mut st, &o.id);
            } else {
                disagreed_with.push(o.signer.clone());
                self.raise_evidence(
                    &o.data,
                    o.kind,
                    &o.signer,
                    o.id,
                    o.body.binding.reads.0,
                    AnswerFault::Mismatch {
                        signed: o.result_digest,
                        recomputed: digest,
                        evaluator: r.binding.by.clone(),
                    },
                );
            }
        }
        // Signed answers confirmed by this device's recomputation are kept to serve.
        for o in seen.iter().filter(|o| o.result_digest == digest) {
            if device_of(o.signer.key()).as_ref() != Some(&self.device) {
                let mut st = self.st.lock();
                self.keep_held(
                    &mut st,
                    &o.name,
                    &o.signer,
                    o.kind,
                    o.data.raw(),
                    &o.pieces,
                    digest,
                );
            }
        }
        let mut name = exact
            .filter(|_| disagreed_with.is_empty())
            .unwrap_or_else(|| wire::answer_name(&self.device, &r.id));
        if self.config.answers.publish == crate::answer::Publish::Computed
            && self.st.lock().answer_book.own_result(&r.id).is_none()
        {
            match self
                .make_answer(
                    &r.binding,
                    &r.reads,
                    &r.epochs,
                    r.keys.as_ref(),
                    &result,
                    r.id,
                    Signing::Own,
                )
                .await
            {
                Ok(own) => {
                    if confirmed_by.is_empty() {
                        name = own;
                    }
                }
                Err(e) => tracing::debug!(%asked, "not published: {e}"),
            }
        }
        Ok(self.answered(
            name,
            &r,
            result,
            Provenance::Recomputed {
                confirmed_by,
                disagreed_with,
            },
        ))
    }

    /// An answer taken on trust (answers.md §7.3, 2): a pure answer whose evaluator is unknown
    /// here (or the policy lists for trust), or a provider answer. `first`: the packet an exact
    /// name was asked for. Looks in this device's store, then asks the candidates.
    async fn finish_trusted(
        self: &Arc<Self>,
        asked: &Name,
        ask: &AnswerAsk,
        r: Resolved,
        first: Option<Opened>,
    ) -> Result<Answered, DataError> {
        let mut found: Vec<Opened> = Vec::new();
        let mut packets: Vec<Data> = Vec::new();
        if let Some(o) = first {
            found.push(o);
        }
        // This device's store, by id, under any signer.
        let names: Vec<Name> = {
            let st = self.st.lock();
            st.answer_book.names_at(&r.id, &self.device)
        };
        for n in names {
            if found.iter().any(|o| o.name == n) {
                continue;
            }
            if let Some(d) = self.stored_answer(&n).and_then(|w| Data::decode(w).ok()) {
                packets.push(d);
            }
        }
        let mut refusals: Vec<AnswerRefusal> = Vec::new();
        let mut asked_network = false;
        loop {
            for d in packets.drain(..) {
                match self.open_packet(d, Some(r.kind), &[]).await {
                    Ok(o) => match self.check_equivocation(&o) {
                        Ok(()) => found.push(o),
                        Err(e) => return Err(e),
                    },
                    Err(DataError::Answer { why, .. }) => refusals.push(why),
                    Err(e) => return Err(e),
                }
            }
            let acceptable: Vec<&Opened> =
                found.iter().filter(|o| self.accepts(o).is_ok()).collect();
            if !acceptable.is_empty() || asked_network {
                break;
            }
            // Nothing acceptable held: ask the candidates, as owed fetches.
            asked_network = true;
            let (signers, relays) = self.candidates(r.kind, &r.binding.by, &r.reads);
            packets = self.ask_candidates(&signers, &relays, &r.id).await;
            if packets.is_empty() {
                break;
            }
        }
        let accepted: Vec<usize> = (0..found.len())
            .filter(|i| self.accepts(&found[*i]).is_ok())
            .collect();
        // Two signers the policy trusts, two results, and no way to recompute: evidence, and
        // nothing is returned.
        if let Some((&a, rest)) = accepted.split_first()
            && let Some(&b) = rest
                .iter()
                .find(|b| found[**b].result_digest != found[a].result_digest)
        {
            let (x, y) = (&found[a], &found[b]);
            // Never evidence against this device's own key (answers.md §8.2): of two, blame
            // the other.
            let (x, y) = if self.is_own_key(&y.signer) {
                (y, x)
            } else {
                (x, y)
            };
            self.raise_evidence(
                &y.data,
                y.kind,
                &y.signer,
                y.id,
                y.body.binding.reads.0,
                AnswerFault::Conflict {
                    other: x.name.clone(),
                    other_signer: x.signer.key().clone(),
                    other_result: x.result_digest,
                },
            );
            return Err(answer_error(asked, AnswerRefusal::Equivocal));
        }
        if let Some(&i) = accepted.first() {
            let o = found.swap_remove(i);
            if device_of(o.signer.key()).as_ref() != Some(&self.device) {
                let mut st = self.st.lock();
                self.keep_held(
                    &mut st,
                    &o.name,
                    &o.signer,
                    o.kind,
                    o.data.raw(),
                    &o.pieces,
                    o.result_digest,
                );
            }
            let how = match o.kind {
                AnswerKind::Pure => Provenance::Trusted {
                    signer: o.signer.clone(),
                    unverified_reads: o.unverified,
                },
                AnswerKind::Provider => Provenance::Provider {
                    signer: o.signer.clone(),
                    unverified_reads: o.unverified,
                },
            };
            let mut res = r;
            res.reads = o.body.reads.clone();
            return Ok(self.answered(o.name.clone(), &res, o.body.result.clone(), how));
        }
        // Nothing taken.
        if let Some(o) = found.first() {
            return Err(match o.kind {
                AnswerKind::Provider => match self.accepts(o) {
                    Err(why) => answer_error(asked, why),
                    Ok(()) => DataError::Unavailable {
                        name: asked.clone(),
                    },
                },
                AnswerKind::Pure => DataError::CannotCheck {
                    name: asked.clone(),
                    evaluator: ask.by.clone(),
                    why: format!(
                        "the only answers held are signed by devices this device's policy does \
                         not trust for pure answers ({}); {}",
                        found
                            .iter()
                            .map(|o| o.signer.key().to_string())
                            .collect::<Vec<_>>()
                            .join(", "),
                        match self.config.evaluators.get(&ask.by) {
                            Some(_) => "recompute it, or name a signer in the policy",
                            None => {
                                "run a program that knows the evaluator, or name a signer in the \
                                 policy"
                            }
                        }
                    ),
                },
            });
        }
        if let Some(AnswerRefusal::Equivocal) = refusals.first() {
            return Err(answer_error(asked, AnswerRefusal::Equivocal));
        }
        if let Some(why) = refusals.into_iter().next() {
            return Err(answer_error(asked, why));
        }
        Err(DataError::Unavailable {
            name: asked.clone(),
        })
    }

    // ---- making an answer ---------------------------------------------------------------------

    /// Sign the answer of `binding` over `reads` with `result` as this device's, store it behind
    /// the barrier and serve it (answers.md §6.2). Idempotent: an own answer at the id is not
    /// signed again; a provider keeps what it signed, so a different result at the id is
    /// [`AnswerRefusal::AlreadySigned`].
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn make_answer(
        self: &Arc<Self>,
        binding: &AnswerBinding,
        reads: &ReadSet,
        epochs: &[Epoch],
        keys: Option<&AudienceKeys>,
        result: &Bytes,
        id: [u8; 32],
        who: Signing,
    ) -> Result<Name, DataError> {
        let name = wire::answer_name(&self.device, &id);
        let too_large = |what: &str, size: u64, limit: u64| {
            answer_error(
                &name,
                AnswerRefusal::TooLarge {
                    what: what.into(),
                    size,
                    limit,
                },
            )
        };
        if reads.reads().len() > crate::answer::READS_MAX {
            return Err(too_large(
                "the reads of one answer",
                reads.reads().len() as u64,
                crate::answer::READS_MAX as u64,
            ));
        }
        if epochs.len() > crate::answer::SEAL_EPOCHS_MAX {
            return Err(too_large(
                "the epochs of the reads",
                epochs.len() as u64,
                crate::answer::SEAL_EPOCHS_MAX as u64,
            ));
        }
        let digest = seal::result_digest(result, keys);
        let body = Body {
            binding: binding.clone(),
            reads: reads.clone(),
            result: result.clone(),
        }
        .encode();
        if body.len() as u64 > PAYLOAD_MAX {
            return Err(too_large("the answer", body.len() as u64, PAYLOAD_MAX));
        }
        // What goes in the packet, and what in pieces. A sealed body is padded to its size bucket
        // first (answers.md §13.3), so the packet's size tells a relay the bucket and not the
        // number of reads.
        let carried = match keys {
            Some(k) => {
                let padded = crate::answer::pad_body(&body);
                seal::seal_answer(k, &name, binding.kind, epochs, &padded)
            }
            None => body.clone(),
        };
        if carried.len() as u64 > PAYLOAD_MAX {
            return Err(too_large(
                "the sealed answer, padded",
                carried.len() as u64,
                PAYLOAD_MAX,
            ));
        }
        let (content, pieces) = if carried.len() <= INLINE_MAX {
            (
                match keys {
                    Some(_) => Content::Sealed {
                        epochs: epochs.to_vec(),
                        ciphertext: carried,
                    },
                    None => Content::Plain(carried),
                },
                Vec::new(),
            )
        } else {
            let (pieces, chunks) = pieces::split(&name, &carried);
            (
                Content::Pieces {
                    epochs: keys.map(|_| epochs.to_vec()),
                    size: chunks.size,
                    root: chunks.root,
                },
                pieces,
            )
        };
        let record = Record {
            kind: binding.kind,
            content,
        }
        .encode();
        // Under one lock: is there an answer of this device at the id (a provider keeps what it
        // signed), else sign and keep it, so two calls never sign two results at one name.
        let existing: Result<Option<(Name, bool)>, DataError> = {
            let mut st = self.st.lock();
            match st.answer_book.own_result(&id) {
                Some((own_name, own_digest, _)) => {
                    if own_digest == digest || binding.kind == AnswerKind::Pure {
                        // Already signed: served once it is behind the barrier.
                        let own_name = own_name.clone();
                        let served = st.answer_book.is_served(&own_name);
                        Ok(Some((own_name, served)))
                    } else {
                        Err(answer_error(&name, AnswerRefusal::AlreadySigned))
                    }
                }
                None => {
                    let now = crate::rt::Instant::now();
                    let per_second = self.config.answers.sign_per_second as usize;
                    let limit = match who {
                        Signing::Own => per_second,
                        Signing::Asked => per_second.div_ceil(2),
                    };
                    if st.answer_book.signed_in_the_last_second(now, who) >= limit {
                        Err(answer_error(
                            &name,
                            AnswerRefusal::OverBudget {
                                what: SIGNED_PER_SECOND.into(),
                            },
                        ))
                    } else {
                        let wire = self.sign(DataBuilder::new(name.clone(), &record))?;
                        self.keep_own(&mut st, &name, &id, binding.kind, digest, &wire, &pieces)?;
                        st.answer_book.note_signed(now, who);
                        Ok(None)
                    }
                }
            }
        };
        if let Some((own_name, served)) = existing? {
            if !served {
                self.barrier_then_serve(&own_name).await?;
            }
            return Ok(own_name);
        }
        self.barrier_then_serve(&name).await?;
        Ok(name)
    }

    /// Wait for the store's barrier, then serve the own answer `name`: what was signed is
    /// behind it, so a power loss cannot take what a peer saw.
    async fn barrier_then_serve(&self, name: &Name) -> Result<(), DataError> {
        if !self.barrier().await {
            return Err(local(
                "this device stopped before the answer was made durable; nothing was served",
            ));
        }
        self.serve_own(name);
        Ok(())
    }

    /// [`Device::publish_answer`] for the pure question `ask`, named `question`: plan, evaluate,
    /// sign within `who`'s signing rate, store behind the barrier and serve.
    pub(super) async fn publish_question(
        self: &Arc<Self>,
        question: &Name,
        ask: &AnswerAsk,
        who: Signing,
    ) -> Result<Name, DataError> {
        if ask.kind != AnswerKind::Pure {
            return Err(DataError::BadRequest {
                name: question.clone(),
                why: "a provider answer is signed with Device::provide, over the inputs the \
                      function read and with its result; publish_answer is for pure questions"
                    .into(),
            });
        }
        if self.config.evaluators.get(&ask.by).is_none() {
            return Err(DataError::CannotCheck {
                name: question.clone(),
                evaluator: ask.by.clone(),
                why: "this program does not know the evaluator, so it cannot compute the \
                      answer it would sign; run a program that knows it"
                    .into(),
            });
        }
        let r = self.resolve_question(question, ask, true).await?;
        let result = r.computed.clone().expect("evaluated: run was asked for");
        self.make_answer(
            &r.binding,
            &r.reads,
            &r.epochs,
            r.keys.as_ref(),
            &result,
            r.id,
            who,
        )
        .await
    }
}

impl Device {
    /// The id a question resolves to (answers.md §7.2 steps 1 to 4: parse, read set, keys,
    /// binding): to hand to another device, or to build the exact name
    /// `<D>/32=answer/<id>` of any signer. A planned pure question plans (so it reads, and
    /// refuses as `get` of the reads does); a question that states its reads does not evaluate.
    pub async fn answer_id(&self, question: &Name) -> Result<Hash, DataError> {
        let (_, ask) = AnswerAsk::parse_with_x(question)?;
        let r = self.inner.resolve_question(question, &ask, false).await?;
        Ok(Hash(r.id))
    }

    /// Pure: plan and evaluate the question (a pure `AnswerAsk`'s name), sign the answer, store
    /// it behind the barrier and serve it. Idempotent: an answer of this device at the id is
    /// returned, not signed again. Returns `<this device>/32=answer/<id>`. The evaluator must be
    /// known here (`CannotCheck`). Over the limits of answers.md §10: `Answer{TooLarge}`.
    pub async fn publish_answer(&self, question: &Name) -> Result<Name, DataError> {
        let (_, ask) = AnswerAsk::parse_with_x(question)?;
        self.inner
            .publish_question(question, &ask, Signing::Own)
            .await
    }

    /// Provider: sign `result` as this device's answer of `function` over `inputs` (the signed
    /// reads it was computed from). Each input MUST be a read this device holds verified (an
    /// input only in an uncommitted local log has none: `BadRequest`, "commit it first").
    /// Returns the answer's name once the packet is behind the barrier. A second call at the same
    /// id with an equal result returns the same name; with a different result,
    /// `Answer { why: AlreadySigned }`: a provider keeps what it signed (answers.md §6.2).
    pub async fn provide(
        &self,
        function: &Name,
        inputs: ReadSet,
        result: Bytes,
    ) -> Result<Name, DataError> {
        let inner = &self.inner;
        let not_held = |what: String| DataError::BadRequest {
            name: function.clone(),
            why: format!(
                "{what} is not a signed version held here: commit it first (put it), then ask \
                 again; an answer is made only over signed data"
            ),
        };
        let mut epochs: Vec<Epoch> = Vec::new();
        {
            let st = inner.st.lock();
            for r in inputs.reads() {
                match r {
                    ReadRef::Version { name, digest } => match st.version_fact(name) {
                        VersionFact::Held { digest: d, epoch } if d == digest.0 => {
                            if let Some(e) = &epoch {
                                add_epoch(&mut epochs, e);
                            }
                        }
                        VersionFact::Held { .. } => {
                            return Err(DataError::BadRequest {
                                name: function.clone(),
                                why: format!(
                                    "the input {name} is named with another digest than the \
                                     version held here; name the version this device holds"
                                ),
                            });
                        }
                        VersionFact::Refused => {
                            return Err(answer_error(
                                function,
                                AnswerRefusal::ReadsChanged(format!(
                                    "the input {name} is refused here"
                                )),
                            ));
                        }
                        VersionFact::Unknown => return Err(not_held(name.to_string())),
                    },
                    ReadRef::State {
                        collection,
                        rule,
                        at,
                        applied,
                    } => match st.state_facts(
                        collection,
                        at.frontier(),
                        &inner.config.rules,
                        &inner.writer,
                    ) {
                        Some(f) if f.rule == *rule && f.applied == *applied && f.parents == *at => {
                            f.epochs.iter().for_each(|e| add_epoch(&mut epochs, e));
                        }
                        Some(_) => {
                            return Err(answer_error(
                                function,
                                AnswerRefusal::ReadsChanged(format!(
                                    "the state of {collection} this device holds is not the one \
                                     the input names"
                                )),
                            ));
                        }
                        None => return Err(not_held(format!("the state of {collection}"))),
                    },
                }
            }
        }
        if result.len() as u64 > PAYLOAD_MAX {
            return Err(answer_error(
                function,
                AnswerRefusal::TooLarge {
                    what: "the result".into(),
                    size: result.len() as u64,
                    limit: PAYLOAD_MAX,
                },
            ));
        }
        let keys = inner.audience(&epochs, function)?;
        let binding = AnswerBinding {
            kind: AnswerKind::Provider,
            definition: None,
            by: function.clone(),
            reads: inputs.digest(),
        };
        let id = seal::answer_id(&binding, keys.as_ref());
        let made = inner
            .make_answer(
                &binding,
                &inputs,
                &epochs,
                keys.as_ref(),
                &result,
                id,
                Signing::Own,
            )
            .await;
        // The call a host was asked for is done, answered or not: asked again, it is delivered
        // again ([`Device::provider_asks`]).
        inner.st.lock().answer_asks.done(function, &binding.reads.0);
        made
    }

    /// The newest this device holds of `collection` as an exact read, and how old it may be:
    /// what a planning `current` gives (answers.md §4.1). A host names a definition or an input
    /// with it, since a merge state's tips' digests and applied-set digest are not in
    /// [`State`](crate::State).
    pub async fn current_read(&self, collection: &Name) -> Result<(ReadRef, Age), DataError> {
        let (r, _, age, _) = self.inner.current_read(collection).await?;
        Ok((r, age))
    }

    /// The exact read of what `got` is, a version or the state of a merge collection, as this
    /// device holds it now.
    pub fn read_ref(&self, got: &Got) -> Result<ReadRef, DataError> {
        self.inner.read_ref_of(got).map(|(r, _)| r)
    }
}
