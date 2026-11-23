//! This device's own entries: a put, a Members entry, an Epoch entry, and
//! the cut a removal lists (plan 3.5 "Own put").

use std::sync::Arc;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_packet::encode::DataBuilder;
use ndn_security::confidentiality::ContentKey;
use ndn_sync::StoreOp;

use super::admit::{Applying, Fresh};
use super::chain::Status;
use super::*;
use crate::wire::{AFTER_MAX, MembersBody, Op, Prev, SealedBody, TIPS_MAX, WireError};

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
    ) -> Result<Step<Signed>, HeapError> {
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
    pub(crate) fn sign_members(
        &mut self,
        body: MembersBody,
        now: u64,
    ) -> Result<Step<Signed>, HeapError> {
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
    pub(crate) fn sign_epoch(
        &mut self,
        audience: Vec<Name>,
        now: u64,
    ) -> Result<Step<Signed>, HeapError> {
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
            vec![],
            None,
            vec![StoreOp::Insert(at, stored)],
            now,
            &self.space.clone(),
        )
    }

    fn owner_only(&self) -> Result<(), HeapError> {
        if wire::owns(&self.space, &self.key) {
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
            Some(tip) if tip.seq + 1 == seq => Some(Prev {
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
    ) -> Result<Step<Signed>, HeapError> {
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
        let stage = Arc::clone(&self.store);
        let _batch = stage.batch();
        self.store.apply(extra);
        let person = self.person.clone();
        let applying = Applying {
            id: id.clone(),
            name,
            person: person.clone(),
            entry,
            put,
        };
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
        self.next_seq = seq + 1;
        fx.publish = Some(Publish { seq, structural });
        self.settle(&mut fx);
        Ok(Step::Done(Signed {
            id: EntryId::from(&id),
            effects: fx,
        }))
    }

    /// What a removal of `person` binds: per device of the person this device
    /// knows, the highest verified seq it holds and its signed digest. What
    /// it never held is outside the cut. The node decides how long it looked
    /// for more before asking (`Config.first_look`).
    pub(crate) fn removal_tips(&self, person: &Name) -> Vec<EntryRef> {
        let mut tips: Vec<EntryRef> = self
            .devices
            .iter()
            .filter(|(_, d)| d.person == *person)
            .filter_map(|(device, d)| {
                d.tip.map(|t| EntryRef {
                    device: device.clone(),
                    seq: t.seq,
                    digest: t.digest,
                })
            })
            .collect();
        tips.truncate(TIPS_MAX);
        tips
    }

    /// The operations that remove `person` from every role: a `Remove` of
    /// each Add of the person that stands, bound by [`Log::removal_tips`].
    pub(crate) fn remove_ops(&self, person: &Name) -> Vec<Op> {
        let tips = self.removal_tips(person);
        self.fold
            .standing_ids(person)
            .into_iter()
            .map(|id| Op::Remove {
                id,
                tips: tips.clone(),
            })
            .collect()
    }
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
