//! This device's own entries: a put, a Members entry, an Epoch entry, and
//! the cut a removal lists (plan 3.5 "Own put").

use ndn_foundation_types::Name;
use ndn_packet::encode::DataBuilder;
use ndn_security::confidentiality::ContentKey;
use ndn_sync::StoreOp;

use super::admit::{Applying, Fresh};
use super::chain::Status;
use super::*;
use crate::wire::{
    AFTER_MAX, Body, Entry, EntryRef, MembersBody, Op, Prev, Role, SealedBody, WireError,
};

impl Log {
    /// Sign, store and apply an own write of `payload` at `path`. `extra` are
    /// store writes that belong to the same batch (the pieces of a blob).
    /// An empty inline payload removes the path.
    ///
    /// [`HeapError::NotReady`] while the space's creation (or the epoch's
    /// key, in a sealed space) has not been seen, [`HeapError::NotAllowed`]
    /// when this device's person is not a writer.
    pub(crate) fn put(
        &mut self,
        path: &Name,
        payload: Payload,
        extra: Vec<StoreOp>,
        now: u64,
    ) -> Result<Step, HeapError> {
        let epoch = self.judge_own()?;
        if let Some(ticket) = self.gate()? {
            return Ok(Step::Wait(ticket));
        }
        let put = PutBody {
            path: path.clone(),
            payload,
        };
        let body = match epoch {
            None => Body::Put(put.clone()),
            Some(epoch) => {
                let name = log_name(&self.device, &self.space, self.next_seq);
                let key = self
                    .keys
                    .key(&self.space, &epoch)
                    .expect("judge_own found the key of the epoch in force");
                let plain = wire::encode_sealed_plain(&put).map_err(|e| wire_error(path, e))?;
                Body::Sealed(SealedBody {
                    sealed: seal::seal_payload(key, &name, &plain),
                    epoch,
                })
            }
        };
        let mut after = self.register.after_for_put(path);
        after.truncate(AFTER_MAX);
        self.sign_next(body, after, Some(put), extra, now, path)
    }

    /// Sign a Members entry (the space's creation, additions, removals). Only
    /// a device of the owner's namespace may.
    pub(crate) fn sign_members(&mut self, body: MembersBody, now: u64) -> Result<Step, HeapError> {
        self.owner_only()?;
        if let Some(ticket) = self.gate()? {
            return Ok(Step::Wait(ticket));
        }
        self.sign_next(
            Body::Members(body),
            vec![],
            None,
            vec![],
            now,
            &self.space.clone(),
        )
    }

    /// Sign an Epoch entry for `audience`: a fresh key, stored (wrapped to
    /// this device's seal key) in the batch of the entry that carries its
    /// check. Only a device of the owner's namespace may.
    pub(crate) fn sign_epoch(&mut self, audience: Vec<Name>, now: u64) -> Result<Step, HeapError> {
        self.owner_only()?;
        if let Some(ticket) = self.gate()? {
            return Ok(Step::Wait(ticket));
        }
        let epoch = EpochId {
            creator: self.device.clone(),
            seq: self.next_seq,
        };
        let key = ContentKey::generate();
        let key_check = seal::key_check(&key, &self.space, &epoch);
        self.keys.hold(&self.space, epoch.clone(), key);
        let (at, stored) = self
            .keys
            .record(&self.space, &epoch)
            .expect("the key was just held")
            .map_err(|e| HeapError::Local {
                reason: e.to_string(),
            })?;
        let body = Body::Epoch(wire::EpochBody {
            key_check,
            audience,
        });
        self.sign_next(
            body,
            self.epoch_tips(),
            None,
            vec![StoreOp::Insert(at, stored)],
            now,
            &self.space.clone(),
        )
    }

    /// The Epoch entries no held epoch replaces: what a new Epoch entry
    /// replaces, so that it is the one in force whatever the order of their
    /// creators' names. The greatest [`AFTER_MAX`] when there are more.
    fn epoch_tips(&self) -> Vec<EntryRef> {
        let mut refs = Vec::new();
        for id in self.fold.epoch_tips().into_iter().rev().take(AFTER_MAX) {
            let named = self.fold.epoch_body(&id);
            let digest = self
                .view()
                .wires_at(&id.creator, id.seq)
                .iter()
                .filter_map(decode_wire)
                .find(|(entry, _)| matches!(&entry.body, Body::Epoch(b) if Some(b) == named))
                .map(|(_, digest)| digest);
            if let Some(digest) = digest {
                refs.push(EntryRef {
                    device: id.creator,
                    seq: id.seq,
                    digest,
                });
            }
        }
        refs
    }

    /// Whether this device is an owner device: its name is under the space's
    /// owner's and its key is vouched for as the owner's person (the rule
    /// admission applies to Members and Epoch entries). The refusal says what
    /// to do.
    pub(crate) fn owner_only(&self) -> Result<(), HeapError> {
        if wire::owns(&self.space, &self.key) && self.person == *self.fold.owner() {
            Ok(())
        } else {
            Err(HeapError::NotOwner {
                space: self.space.clone(),
            })
        }
    }

    /// Whether this device may write now, and the epoch to seal in (none in a
    /// public space).
    pub(crate) fn judge_own(&self) -> Result<Option<EpochId>, HeapError> {
        let not_ready = |why: &str| HeapError::NotReady {
            name: self.space.clone(),
            why: why.into(),
        };
        let create = self.fold.create();
        if !self.fold.is_writer(&self.person) {
            return Err(if create.is_none() {
                not_ready(
                    "this device has not seen the space's creation, so it cannot tell whether it may write",
                )
            } else {
                HeapError::NotAllowed {
                    space: self.space.clone(),
                    why: "this device's person is not a writer of the space; ask the owner to \
                          add it as a writer"
                        .into(),
                }
            });
        }
        match create {
            None => Err(not_ready(
                "this device has not seen the space's creation yet",
            )),
            Some(true) => Ok(None),
            Some(false) => {
                let epoch = self.fold.in_force().ok_or_else(|| {
                    not_ready("no epoch of the space is in force yet, so nothing can be sealed")
                })?;
                if self.keys.key(&self.space, &epoch).is_none() {
                    return Err(not_ready(
                        "the key of the epoch in force has not arrived yet",
                    ));
                }
                Ok(Some(epoch))
            }
        }
    }

    /// `Ok(None)`: the next seq may be signed now; `Some(ticket)`: wait for it.
    fn gate(&self) -> Result<Option<Ticket>, HeapError> {
        if self.next_seq <= self.own_head {
            return Err(HeapError::Local {
                reason: format!(
                    "this device holds an entry of its own at seq {}, the last seq there is, so \
                     it can sign no more in this space; use another device or another space",
                    self.own_head
                ),
            });
        }
        match self.reservation.sign_gate(self.next_seq) {
            Gate::Ok => Ok(None),
            Gate::Wait(ticket) => Ok(Some(ticket)),
            Gate::Refused(why) => Err(HeapError::Local {
                reason: why.to_string(),
            }),
            Gate::Closed => Err(HeapError::Local {
                reason: "the node is closing, so no more entries are signed".into(),
            }),
        }
    }

    /// The link the next own entry states: the stored tip, dense or with the
    /// signed gap statement; the zero digest when nothing is held.
    fn own_prev(&self, seq: u64) -> Option<Prev> {
        match self.own_tip {
            None => (seq > 1).then_some(Prev {
                digest: [0; 32],
                seq: Some(0),
            }),
            Some(tip) if tip.seq.checked_add(1) == Some(seq) => Some(Prev {
                digest: tip.digest,
                seq: None,
            }),
            Some(tip) => Some(Prev {
                digest: tip.digest,
                seq: Some(tip.seq),
            }),
        }
    }

    /// Sign the next own entry with `body`, store it and everything that goes
    /// with it in one batch, apply it.
    fn sign_next(
        &mut self,
        body: Body,
        after: Vec<EntryRef>,
        put: Option<PutBody>,
        extra: Vec<StoreOp>,
        now: u64,
        subject: &Name,
    ) -> Result<Step, HeapError> {
        let seq = self.next_seq;
        let entry = Entry {
            prev: self.own_prev(seq),
            after,
            body,
        };
        let content = entry.encode().map_err(|e| wire_error(subject, e))?;
        let name = log_name(&self.device, &self.space, seq);
        let packet =
            seal::sign(DataBuilder::new(name.clone(), &content), &*self.signer).map_err(|e| {
                HeapError::Local {
                    reason: e.to_string(),
                }
            })?;
        let id = EntryRef {
            device: self.device.clone(),
            seq,
            digest: signed_digest(&packet),
        };
        let structural = matches!(entry.body, Body::Members(_) | Body::Epoch(_));
        let mut fx = Effects::default();
        if let Some(Prev {
            seq: Some(after), ..
        }) = entry.prev
        {
            fx.alerts.push(Alert::GapSigned {
                after,
                resumed: seq,
            });
        }
        let link = (
            entry.prev.map_or([0; 32], |p| p.digest),
            entry.prev.map_or(0, |p| p.seq.unwrap_or(seq - 1)),
        );
        self.store.apply(extra);
        let person = self.person.clone();
        let applying = Applying::new(id.clone(), person.clone(), entry, put);
        self.store_fresh(
            Fresh {
                id: &id,
                wire: &packet,
                person: &person,
                key_digest: self.key_digest,
                link: Some(link),
                status: None::<Status>,
                applying: Some(applying),
            },
            now,
            &mut fx,
        );
        self.next_seq = seq.saturating_add(1);
        fx.publish = Some(Publish { seq, structural });
        self.settle(&mut fx);
        Ok(Step::Done(EntryId::from(&id), fx))
    }

    /// What a removal of `person` binds: per device of the person this device
    /// knows, the highest entry it holds that passed admission (applied, or
    /// closed for want of its epoch's key) and its signed digest. A refused
    /// fork above it is no tip: the honest history below would wait for it
    /// for good. What it never held is outside the cut. The node decides how
    /// long it looked for more before asking (`Config.first_look`).
    pub(crate) fn removal_tips(&self, person: &Name) -> Vec<EntryRef> {
        let view = self.view();
        self.devices
            .iter()
            .filter(|(_, d)| d.person == *person)
            .filter_map(|(device, d)| {
                let mut at = d.held.max();
                while let Some(seq) = at {
                    if matches!(view.status(device, seq), None | Some(Status::Closed)) {
                        return Some(EntryRef {
                            device: device.clone(),
                            seq,
                            digest: view.marker(device, seq)?.signed_digest,
                        });
                    }
                    at = d.held.below(seq);
                }
                None
            })
            .collect()
    }

    /// The operations that remove `person` from every role: a `Remove` of
    /// each Add of the person that stands. Only a writer Add's Remove binds
    /// [`Log::removal_tips`] (the fold reads no tips of a reader's); they
    /// are spread over as many Removes of the Add as an entry holds, which
    /// the fold unites.
    pub(crate) fn remove_ops(&self, person: &Name) -> Vec<Op> {
        let tips = self.removal_tips(person);
        self.fold
            .standing_adds(person)
            .into_iter()
            .flat_map(|(id, role)| match role {
                Role::Writer => remove_with_tips(id, &tips),
                Role::Reader => vec![Op::Remove {
                    id,
                    tips: Vec::new(),
                }],
            })
            .collect()
    }
}

/// Whether a Members entry with `ops` can be signed: what the format and the
/// packet allow, with the longest chain link an entry states.
fn fits(ops: &[Op]) -> bool {
    Entry {
        prev: Some(Prev {
            digest: [1; 32],
            seq: Some(u64::MAX),
        }),
        after: Vec::new(),
        body: Body::Members(MembersBody {
            create: None,
            ops: ops.to_vec(),
        }),
    }
    .encode()
    .is_ok()
}

/// `Remove`s of `id` that together bind `tips`, each of which fits an entry.
fn remove_with_tips(id: [u8; 16], tips: &[EntryRef]) -> Vec<Op> {
    let mut out = Vec::new();
    let mut run: Vec<EntryRef> = Vec::new();
    for tip in tips {
        run.push(tip.clone());
        if run.len() > 1
            && !fits(&[Op::Remove {
                id,
                tips: run.clone(),
            }])
        {
            let last = run.pop().expect("just pushed");
            out.push(Op::Remove {
                id,
                tips: std::mem::take(&mut run),
            });
            run.push(last);
        }
    }
    out.push(Op::Remove { id, tips: run });
    out
}

/// `ops` as the bodies of as few Members entries as the entry limits allow:
/// no more operations than one carries, and no more octets than a packet.
pub(crate) fn pack_ops(ops: Vec<Op>) -> Vec<Vec<Op>> {
    let mut out = Vec::new();
    let mut batch: Vec<Op> = Vec::new();
    for op in ops {
        batch.push(op);
        if batch.len() > 1 && !fits(&batch) {
            let op = batch.pop().expect("just pushed");
            out.push(std::mem::take(&mut batch));
            batch.push(op);
        }
    }
    if !batch.is_empty() {
        out.push(batch);
    }
    out
}

/// A wire limit as the API says it.
fn wire_error(subject: &Name, e: WireError) -> HeapError {
    match e {
        WireError::TooLarge { max, .. } => HeapError::TooLarge {
            name: subject.clone(),
            limit: max as u64,
        },
        other => HeapError::BadRequest {
            why: other.to_string(),
        },
    }
}
