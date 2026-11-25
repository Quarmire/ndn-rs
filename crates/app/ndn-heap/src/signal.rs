//! The signal gate for ndn-surface (spec §11).
//!
//! A signal is ephemeral live data — presence, cursors, a drag — pushed to the
//! members of a space and never an entry: nothing of it is stored, served or
//! counted here. The signal transport (`ndn_surface::signal`) asks the node
//! six things ([`NodeHandle::signal_scope`], [`NodeHandle::signal_header`],
//! [`NodeHandle::signal_sender`], [`NodeHandle::signal_view`],
//! [`NodeHandle::signal_member`], [`NodeHandle::revocations`]) and nothing
//! else leaves this module. What a run header costs the network (the
//! certificates its chain fetches, the budget of them) is the transport's.
//!
//! A **member** of a space, for signals, is a key of a device whose person the
//! operation fold lists as a writer (the owner always is) and which the trust
//! context governing that key does not revoke. The answer is read from what is
//! held at the call, so it flips on the first call after the entry that
//! removes a person, or the context that revokes a key, is held.
//!
//! The logic is free functions over one space's [`Log`] and the node's
//! [`Judge`], wrapped by the `NodeHandle` methods (a [`Node`](crate::Node)
//! dereferences to its handle): none holds a lock across an `.await`, and
//! none writes.

use std::fmt;
use std::sync::Arc;

use bytes::Bytes;
use hkdf::Hkdf;
use ndn_foundation_types::Name;
use ndn_packet::Data;
use ndn_packet::encode::DataBuilder;
use ndn_security::cert_name::key_name_of;
use ndn_security::confidentiality::ContentKey;
use ndn_security::{Signer, Validator};
use sha2::Sha256;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::chan::standing::{
    NO_RECORD, Unstanding, Who, gate as chan_gate, standing as chan_standing,
};
use crate::error::HeapError;
use crate::host::NodeHandle;
use crate::log::Log;
use crate::seal;
use crate::space::SpaceInner;
use crate::trust::Judge;
use crate::wire::{
    self, EpochId, device_of, parse_signal_run_name, signal_run_name, sync_group_of,
};

/// The domain label of a space's signal key.
const SIGNAL_KEY: &[u8] = b"ndn-heap/signal/1";

/// The domain label of a signal key's id.
const SIGNAL_KEY_ID: &[u8] = b"ndn-heap/signal/id/1";

/// The octets of a signal key's id ([`SignalKey::id`]).
pub const KEY_ID_LEN: usize = 8;

/// The octets of a signal run's id: a run header's last name component.
pub const RUN_ID_LEN: usize = wire::RUN_ID_LEN;

// -- What the transport is given ---------------------------------------------------------

/// What this device may do with signals over a space, by the entries it holds
/// (`signal_scope`).
#[derive(Clone, Debug)]
pub struct SignalScope {
    /// The space asked about.
    pub space: Name,
    /// A sealed space's signal keys held here: the epoch in force's first —
    /// the one to seal with — then those of the other epochs whose keys are
    /// held, by their epoch's seq, highest first (to open what members still
    /// seal in them). Empty when the space is not sealed.
    pub keys: Vec<SignalKey>,
    /// The sync groups to push into: the space's one group
    /// (`<owner>/32=sync/<space name>`).
    pub groups: Vec<Name>,
    /// The sync group this device listens on, where others push for it: the
    /// space's group.
    pub listen: Name,
}

/// A sealed space's signal key for one epoch (spec §11): HKDF-SHA256 with the
/// epoch's content key as input key material, no salt, and as info
/// `ndn-heap/signal/1` ‖ the space's Name TLV ‖ the epoch creator's Name TLV ‖
/// the epoch's seq as 8 octets big-endian. Its [`id`](Self::id) is the first 8
/// octets of HKDF-SHA256 with the signal key as input key material, no salt,
/// and info `ndn-heap/signal/id/1`.
///
/// The key is zeroed when dropped, and its `Debug` shows only the epoch and
/// the id.
#[derive(Clone)]
pub struct SignalKey {
    /// The epoch whose content key it is derived from.
    pub(crate) epoch: EpochId,
    /// Its id, carried beside what it seals so a receiver knows which key
    /// opens it.
    pub id: [u8; KEY_ID_LEN],
    key: Zeroizing<[u8; 32]>,
}

// The only secret is the `Zeroizing` key: dropping a `SignalKey` zeroes it.
impl ZeroizeOnDrop for SignalKey {}

impl SignalKey {
    /// The signal key of `space` in `epoch`, whose content key is `content`.
    pub(crate) fn derive(content: &ContentKey, space: &Name, epoch: &EpochId) -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(None, content.expose())
            .expand_multi_info(
                &[
                    SIGNAL_KEY,
                    &space.encode_to_tlv(),
                    &epoch.creator.encode_to_tlv(),
                    &epoch.seq.to_be_bytes(),
                ],
                &mut key[..],
            )
            .expect("32 octets is a valid HKDF-SHA256 output length");
        let mut id = [0u8; KEY_ID_LEN];
        Hkdf::<Sha256>::new(None, &key[..])
            .expand(SIGNAL_KEY_ID, &mut id)
            .expect("8 octets is a valid HKDF-SHA256 output length");
        Self {
            epoch: epoch.clone(),
            id,
            key,
        }
    }

    /// The key's 32 octets (an XChaCha20-Poly1305 key, signals.md).
    pub fn expose(&self) -> &[u8; 32] {
        &self.key
    }
}

impl fmt::Debug for SignalKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignalKey")
            .field("epoch", &self.epoch)
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// The signer of a run header, a member of the space by the entries held
/// (`signal_sender`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignalSender {
    /// The key that signed it.
    pub key: Name,
    /// That key's device.
    pub device: Name,
    /// The person of the device: the namespace of the trust context that
    /// governs its key. A transport bounds a sender's admissions and runs by
    /// it: a person can make as many keys and devices as it likes, never more
    /// persons.
    pub namespace: Name,
}

/// Why a run header is not admitted (`signal_sender` and the transport's
/// verification). Each says what to do.
/// None is kept: a refused header is dropped with its run.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SignalRefusal {
    /// Not a run header of this space.
    #[error(
        "not a signal run header of {scope}: {why}; drop it and its run (a run header of {scope} \
         is named <device>/32=signal/{scope}/32=run/<16-octet run id> and signed by that \
         device's key)"
    )]
    Malformed {
        /// The space it was offered for.
        scope: Name,
        /// What is wrong with it.
        why: String,
    },
    /// Its signature does not verify by this device's validator under the
    /// live rule, its key is revoked, or its certificate has expired.
    #[error(
        "a run header signed by {key} does not verify here, that key is revoked, or its \
         certificate has expired: drop its run (its sender sends the header again within a \
         second, so one damaged in transit is replaced; a revoked key's runs stay refused, and an \
         expired one's until its device renews its certificate)"
    )]
    BadSignature {
        /// The key its KeyLocator names.
        key: Name,
    },
    /// Its key is marked suspected on this node: reported stolen, or caught
    /// signing two packets at one name (spec §9.8). Revoked keys are
    /// `BadSignature`.
    #[error(
        "a run header signed by {key} is refused: this node marks that key suspected (reported \
         stolen, or caught signing two packets at one name): drop its run; its runs stay \
         refused until the host unsuspects the key (once a revocation of it is held it is \
         refused as revoked); the person's other devices are not affected"
    )]
    Suspected {
        /// The key its KeyLocator names.
        key: Name,
    },
    /// Its key is no member of the space by the entries held here.
    #[error(
        "{key} is no member of {scope} by the entries held here: drop its run; its runs are \
         refused until an entry admitting it is held (its owner adds it)"
    )]
    NotMember {
        /// The space.
        scope: Name,
        /// The key that signed it.
        key: Name,
    },
    /// The space's creation is not held here yet.
    #[error(
        "nothing about {scope} is decided here yet: {why}; drop the run for now and admit its \
         header again (it rides again within a second) once the creation is held"
    )]
    NotReady {
        /// The space.
        scope: Name,
        /// What it waits for.
        why: String,
    },
    /// Its signer is a member, and a certificate its chain needs is not held
    /// here and is not fetched now: the fetch budget of the signer's namespace
    /// is spent, its device backs off after a fetch that brought none, or no
    /// current certificate could be had.
    #[error(
        "a run header signed by {key} cannot be verified here now: {why}; drop its run for now \
         and admit its header again when it rides again (within a second) — it is admitted once \
         its certificate is held here"
    )]
    Unverified {
        /// The key its KeyLocator names.
        key: Name,
        /// What it waits for.
        why: String,
    },
}

// -- Membership --------------------------------------------------------------------------

/// The person `key` belongs to, if the fold lists that person as a writer or,
/// when `reads`, as a reader (everybody reads a public space), the trust
/// context governing the key does not revoke it and this node does not mark it
/// suspected (§9.8: no new entry of a suspected key is taken, and no run header
/// either); else the refusal: `NotMember` (no standing person owns the key),
/// `BadSignature` (the context revokes it) or `Suspected`. The context is the
/// one `judge` judges the key's packets about the space by (spec §11): the
/// node's own for a person it holds, else the view adopted for the person while
/// a listing of the space names her as a writer or a reader.
fn standing(log: &Log, judge: &Judge, key: &Name, reads: bool) -> Result<Name, SignalRefusal> {
    let who = if reads { Who::Reader } else { Who::Writer };
    chan_standing(log, judge, key, who).map_err(|why| match why {
        Unstanding::NotMember => SignalRefusal::NotMember {
            scope: log.space.clone(),
            key: key.clone(),
        },
        Unstanding::Revoked => SignalRefusal::BadSignature { key: key.clone() },
        Unstanding::Suspected => SignalRefusal::Suspected { key: key.clone() },
    })
}

/// [`NodeHandle::signal_member`] over one space.
pub(crate) fn signal_member(log: &Log, judge: &Judge, scope: &Name, key: &Name) -> bool {
    scope == &log.space && standing(log, judge, key, false).is_ok()
}

/// This device may use signals over the space: its creation is held and this
/// device's key is a writer of it, or, when `reads`, a reader.
fn own_gate(log: &Log, judge: &Judge, reads: bool) -> Result<(), HeapError> {
    chan_gate(
        log,
        judge,
        if reads { Who::Reader } else { Who::Writer },
        "signals",
    )
}

// -- The scope and the header ------------------------------------------------------------

/// [`NodeHandle::signal_scope`] over the space `log` holds.
pub(crate) fn signal_scope(log: &Log, judge: &Judge) -> Result<SignalScope, HeapError> {
    own_gate(log, judge, true)?;
    let space = &log.space;
    let keys = match log.sealed() {
        true => sealed_keys(log)?,
        false => Vec::new(),
    };
    let group = sync_group_of(space).ok_or_else(|| HeapError::not_a_space(space))?;
    Ok(SignalScope {
        space: space.clone(),
        keys,
        groups: vec![group.clone()],
        listen: group,
    })
}

/// The signal keys of the sealed space `log` holds: the epoch in force's
/// first, then those of the other epochs whose keys are held, by seq, highest
/// first.
fn sealed_keys(log: &Log) -> Result<Vec<SignalKey>, HeapError> {
    let (space, fold) = (&log.space, &log.fold);
    let Some(epoch) = fold.in_force() else {
        return Err(HeapError::NotReady {
            name: space.clone(),
            why: "no epoch of it is in force yet, so it has no signal key; ask again once the \
                  owner's epoch entry is held"
                .into(),
        });
    };
    let Some(content) = log.keys.key(space, &epoch) else {
        let person = &log.person;
        if person != fold.owner() && !fold.audience(&epoch).contains(person) {
            return Err(HeapError::Sealed {
                space: space.clone(),
            });
        }
        return Err(HeapError::NotReady {
            name: space.clone(),
            why: format!(
                "it is sealed, and the key of its epoch in force (seq {} of {}) is not held here \
                 yet; it arrives from the epoch's creator as a grant, so ask again once it has",
                epoch.seq, epoch.creator
            ),
        });
    };
    let mut keys: Vec<SignalKey> = fold
        .epochs()
        .into_iter()
        .filter(|e| *e != epoch)
        .filter_map(|e| Some(SignalKey::derive(log.keys.key(space, &e)?, space, &e)))
        .collect();
    keys.sort_by(|a, b| (b.epoch.seq, &b.epoch.creator).cmp(&(a.epoch.seq, &a.epoch.creator)));
    keys.insert(0, SignalKey::derive(content, space, &epoch));
    Ok(keys)
}

/// [`NodeHandle::signal_header`] over one space, signed by `signer`.
pub(crate) fn signal_header(
    log: &Log,
    judge: &Judge,
    signer: &dyn Signer,
    scope: &Name,
    run_id: &[u8; RUN_ID_LEN],
    body: &[u8],
) -> Result<Bytes, HeapError> {
    if scope != &log.space {
        return Err(HeapError::BadName {
            name: scope.clone(),
            why: format!("this gate holds the space {}, not this one", log.space),
        });
    }
    own_gate(log, judge, false)?;
    seal::sign(
        DataBuilder::new(signal_run_name(&log.device, scope, run_id), body),
        signer,
    )
    .map_err(HeapError::local)
}

// -- Run headers -------------------------------------------------------------------------

/// [`NodeHandle::signal_sender`] over one space.
pub(crate) fn signal_sender(
    log: &Log,
    judge: &Judge,
    scope: &Name,
    header: &Data,
) -> Result<SignalSender, SignalRefusal> {
    let malformed = |why: String| SignalRefusal::Malformed {
        scope: scope.clone(),
        why,
    };
    if scope != &log.space {
        return Err(malformed(format!(
            "this gate holds the space {}, not {scope}",
            log.space
        )));
    }
    let Some(run) = parse_signal_run_name(&header.name) else {
        return Err(malformed(format!(
            "its name {} is not <device>/32=signal/<space>/32=run/<16-octet run id>",
            header.name
        )));
    };
    if run.scope != *scope {
        return Err(malformed(format!(
            "it is a run header of {}, another space",
            run.scope
        )));
    }
    let Some(locator) = header.sig_info().and_then(|s| s.key_locator_name()) else {
        return Err(malformed("it names no signing key".into()));
    };
    let key = key_name_of(&locator);
    if device_of(&key).as_ref() != Some(&run.device) {
        return Err(malformed(format!(
            "it is named under the device {} and signed by {key}, a key of another device",
            run.device
        )));
    }
    if log.fold.create().is_none() {
        return Err(SignalRefusal::NotReady {
            scope: scope.clone(),
            why: NO_RECORD.into(),
        });
    }
    Ok(SignalSender {
        namespace: standing(log, judge, &key, false)?,
        device: run.device,
        key,
    })
}

// -- The node's methods ------------------------------------------------------------------

impl NodeHandle {
    /// The space `space` as a member has it open: the one a signal question is
    /// about. A space not open here (or carried only) is not decided.
    fn signal_space(&self, space: &Name) -> Option<Arc<SpaceInner>> {
        self.inner.space_of(space).filter(|s| !s.follower)
    }

    /// `f` over the log of `space` as a member has it open and the judge;
    /// `None` when the space is not open here.
    fn in_space<T>(&self, space: &Name, f: impl FnOnce(&Log, &Judge) -> T) -> Option<T> {
        let held = self.signal_space(space)?;
        let log = held.log.lock();
        Some(f(&log, &self.inner.judge))
    }

    /// What this node may do with signals over `space`, by the entries it
    /// holds (spec §11): its signal keys when the space is sealed, the sync
    /// group to push into and the one to listen on. A writer or a reader gets
    /// it (a reader of a sealed space holds the epoch key and must be able to
    /// receive); only a writer may send ([`Self::signal_header`]) or be
    /// admitted ([`Self::signal_member`], [`Self::signal_sender`]).
    ///
    /// [`HeapError::BadName`] when `space` is no space name (fix the name).
    /// [`HeapError::NotReady`] when the space is not open here or its creation
    /// is not held yet (retry), or, sealed, the key of its epoch in force has
    /// not arrived (it comes as a grant: ask again). [`HeapError::NotAllowed`]
    /// when this device is neither a writer nor a reader of the space, or the
    /// trust context governing its key revokes it. [`HeapError::Sealed`] when
    /// it is in the sealed space's audience by neither the epoch nor the
    /// owner, which may not hold its key.
    pub fn signal_scope(&self, space: &Name) -> Result<SignalScope, HeapError> {
        self.in_space(space, signal_scope)
            .unwrap_or_else(|| Err(not_open(space)))
    }

    /// Sign a signal run header for `scope` (spec §11): Data
    /// `<device>/32=signal/<scope>/32=run/<run_id>` with Content `body`,
    /// signed by this device's key, with no freshness period. Only a writer
    /// sends; refused as [`Self::signal_scope`] refuses, except that a sealed
    /// space's key need not be held. Nothing is stored or served.
    pub fn signal_header(
        &self,
        scope: &Name,
        run_id: &[u8; RUN_ID_LEN],
        body: &[u8],
    ) -> Result<Bytes, HeapError> {
        self.in_space(scope, |log, judge| {
            signal_header(log, judge, &*self.inner.signer, scope, run_id, body)
        })
        .unwrap_or_else(|| Err(not_open(scope)))
    }

    /// The signer of another device's run header for `scope`, if it is a
    /// member, before anything about it is verified (spec §11): its name is
    /// `<device>/32=signal/<scope>/32=run/<16 octets>`, `device` the device of
    /// the key its KeyLocator names (`Malformed` otherwise); the creation of
    /// the space is held (`NotReady` otherwise); and that key is a member by
    /// the entries held now (`NotMember` otherwise; `BadSignature` for a key
    /// the trust context governing it revokes). Synchronous and offline: a
    /// transport asks it before it spends anything on the header.
    pub fn signal_sender(&self, scope: &Name, data: &Data) -> Result<SignalSender, SignalRefusal> {
        self.in_space(scope, |log, judge| signal_sender(log, judge, scope, data))
            .unwrap_or_else(|| Err(not_open_refusal(scope)))
    }

    /// The validator that judges the signer of `data`, a run header for
    /// `scope` (spec §11.3): the node's own, or the view adopted for the
    /// signer's person while a listing of the space names her. A transport
    /// verifies the header by it under the **live** rule (certificates valid
    /// now, a revoked key refused), fetching the certificates of its chain as
    /// it budgets them, between two [`Self::signal_sender`] calls: the first
    /// before it spends anything on the header, the second once it verified,
    /// so a removal or a revocation held meanwhile ends the admission. The
    /// view decides nothing about membership and costs nothing to ask.
    ///
    /// [`SignalRefusal::NotReady`] when `scope` is not open here as a member.
    pub fn signal_view(&self, scope: &Name, data: &Data) -> Result<Arc<Validator>, SignalRefusal> {
        self.signal_space(scope)
            .ok_or_else(|| not_open_refusal(scope))?;
        Ok(self.inner.judge.view_for(&data.name, scope, true))
    }

    /// Whether `key` is a member of `scope` now (spec §11): a key of a device
    /// of a person the fold of the held Members entries lists as a writer
    /// (the owner always is), which the trust context governing it does not
    /// revoke. Synchronous and offline: the check of every signal packet,
    /// exact by what is held at the call. A space not open here has no
    /// members.
    pub fn signal_member(&self, scope: &Name, key: &Name) -> bool {
        self.in_space(scope, |log, judge| signal_member(log, judge, scope, key))
            .unwrap_or(false)
    }

    /// A count that moves whenever a trust context revoking keys is adopted
    /// here — the node's own, or a view adopted for a person (spec §9)
    /// replaced by a version that refuses more (spec §11). A transport that
    /// admitted run headers when it read one count and reads another now
    /// walks their chains again: a revoked issuer ends the runs it certified.
    pub fn revocations(&self) -> u64 {
        self.inner.judge.generation()
    }
}

/// Why nothing about `space` is decided: it is no space name, which no node
/// can open (fix the name), or this node has not opened it (retry).
fn not_open(space: &Name) -> HeapError {
    if wire::parse_space_name(space).is_none() {
        return HeapError::not_a_space(space);
    }
    HeapError::NotReady {
        name: space.clone(),
        why: NOT_OPEN.into(),
    }
}

fn not_open_refusal(space: &Name) -> SignalRefusal {
    SignalRefusal::NotReady {
        scope: space.clone(),
        why: NOT_OPEN.into(),
    }
}

const NOT_OPEN: &str = "it is not open here as a member; open it (Node::open) so its owner's \
                        entries arrive, then ask again";

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "signal_tests.rs"]
mod tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "signal_node_tests.rs"]
mod node_tests;
