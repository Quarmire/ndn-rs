//! The signal gate for ndn-surface (spec §11).
//!
//! A signal is ephemeral live data — presence, cursors, a drag — pushed to
//! the members of a space and never an entry: nothing of it is stored, served
//! or counted here. The signal transport (`ndn_surface::signal`) asks the
//! node six things, and nothing else leaves this module:
//!
//! - [`signal_scope`]: what this device may do with signals over the space —
//!   its signal keys when it is sealed, the sync group to push into and the
//!   one to listen on;
//! - [`signal_header`]: sign a run header with the device key;
//! - [`signal_sender`]: a run header's signer if it is a member, before
//!   anything is verified;
//! - [`signal_admit`]: admit another device's run header, or say why not
//!   ([`SignalRefusal`]);
//! - [`signal_member`]: whether a key is a member of the space now, asked for
//!   every packet;
//! - [`signal_revocations`]: a count that moves when a trust context revoking
//!   keys is adopted, so the chains of the runs admitted are walked again.
//!
//! A **member** of a space, for signals, is a key of a device whose person
//! the operation fold lists as a writer (the owner always is) and which the
//! trust context governing that key does not revoke. The answer is read from
//! what is held at the call: the fold of the Members entries the log holds and
//! the contexts the judge holds, so it flips on the first call after the
//! entry that removes a person, or the context that revokes a key, is held.
//!
//! These are free functions over one space's [`Log`] and the node's [`Judge`]
//! (the node wraps them as `Node::signal_*`): none holds a lock across an
//! `.await`, and none writes.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use hkdf::Hkdf;
use ndn_foundation_types::Name;
use ndn_packet::Data;
use ndn_packet::encode::DataBuilder;
use ndn_security::cert_name::key_name_of;
use ndn_security::confidentiality::ContentKey;
use ndn_security::safe_data::TrustPath;
use ndn_security::{Signer, ValidationResult, Validator};
use parking_lot::Mutex;
use sha2::Sha256;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::error::HeapError;
use crate::log::Log;
use crate::node::Node;
use crate::rt::Instant;
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

/// Run headers of one sender namespace that may wait for certificates at once
/// (spec §11).
pub const SIGNAL_FETCHES_PER_NAMESPACE: usize = 2;

/// How long no certificate is fetched for a device's run headers again once a
/// fetch for one of them brought none (spec §11).
pub const SIGNAL_FETCH_BACKOFF: Duration = Duration::from_secs(30);

/// Certificates fetched for one run header at most: one chain.
const SIGNAL_CHAIN_FETCHES: usize = 4;

/// Size at which devices past their back-off are swept.
const SIGNAL_BACKOFF_PRUNE_AT: usize = 1024;

/// Why nothing about a space is decided here yet.
const NO_RECORD: &str = "its creation, the owner's first members entry, is not held here yet; \
                         follow the space (watch it) so the owner's entries arrive, then ask again";

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
/// (`signal_sender`, `signal_admit`).
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

/// Why a run header is not admitted (`signal_admit`). Each says what to do.
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

/// Why a key is no member of a space for signals.
enum NotMember {
    /// No standing writer person owns it: its device's person is unknown here
    /// or not listed (or removed).
    Unlisted,
    /// The trust context governing it revokes it.
    Revoked,
}

/// The person `key` belongs to, if the fold lists that person as a writer and
/// the trust context governing the key does not revoke it: who may send.
fn member_by(log: &Log, judge: &Judge, key: &Name) -> Result<Name, NotMember> {
    standing_by(log, judge, key, false)
}

/// The person `key` belongs to, if the fold lists that person as a writer or,
/// when `reads`, as a reader (everybody reads a public space), and the trust
/// context governing the key does not revoke it. The context is the one `judge`
/// judges the key's packets about the space by (spec §11): the node's own for a
/// person it holds, else the view adopted for the person while a listing of the
/// space names her as a writer or a reader.
fn standing_by(log: &Log, judge: &Judge, key: &Name, reads: bool) -> Result<Name, NotMember> {
    if device_of(key).is_none() {
        return Err(NotMember::Unlisted);
    }
    let view = judge.view_for(key, log.space(), true);
    let context = view.keyring().context_for(key);
    let person = context.namespace();
    let fold = log.fold();
    if person.is_empty() || !(fold.is_writer(person) || (reads && fold.is_reader(person))) {
        return Err(NotMember::Unlisted);
    }
    match context.is_revoked(key) {
        true => Err(NotMember::Revoked),
        false => Ok(person.clone()),
    }
}

/// Whether `key` is a member of `scope` now (spec §11): a key of a device of a
/// person the fold of the held Members entries lists as a writer, which the
/// trust context governing it does not revoke. Synchronous and offline: the
/// check of every signal packet, exact by what is held at the call.
pub(crate) fn signal_member(log: &Log, judge: &Judge, scope: &Name, key: &Name) -> bool {
    scope == log.space() && member_by(log, judge, key).is_ok()
}

/// A count that moves whenever a trust context revoking keys is adopted here —
/// the node's own, or a view adopted for a person (spec §9) replaced by a
/// version that refuses more (spec §11). A transport that admitted run headers
/// when it read one count and reads another now walks their chains again: a
/// revoked issuer ends the runs it certified.
pub(crate) fn signal_revocations(judge: &Judge) -> u64 {
    judge.generation()
}

/// This device may use signals over the space: its creation is held and this
/// device's key is a writer of it, or, when `reads`, a reader.
fn own_gate(log: &Log, judge: &Judge, reads: bool) -> Result<(), HeapError> {
    if log.fold().create().is_none() {
        return Err(HeapError::NotReady {
            name: log.space().clone(),
            why: NO_RECORD.into(),
        });
    }
    let why = match standing_by(log, judge, log.key(), reads) {
        Ok(_) => return Ok(()),
        Err(NotMember::Unlisted) if reads => {
            "this device is neither a writer nor a reader of it by the entries held"
        }
        Err(NotMember::Unlisted) => "this device is no writer of it by the entries held",
        Err(NotMember::Revoked) => "the trust context governing this device's key revokes it",
    };
    tracing::debug!(space = %log.space(), key = %log.key(), "signals refused: {why}");
    Err(HeapError::NotAllowed {
        space: log.space().clone(),
        why: format!("{why}; ask the owner to add this device's person to the space"),
    })
}

// -- The scope and the header ------------------------------------------------------------

/// What this device may do with signals over the space `log` holds, by the
/// entries held now (spec §11): its signal keys when the space is sealed, the
/// sync group to push into and listen on. A writer or a reader gets it (a
/// reader of a sealed space holds the epoch key and must be able to receive);
/// only a writer may send ([`signal_header`]) or be admitted ([`signal_member`],
/// [`signal_sender`], [`signal_admit`]).
///
/// [`HeapError::NotReady`] when the space's creation is not held here yet, or,
/// sealed, the key of its epoch in force is not held yet (it arrives as a
/// grant: ask again). [`HeapError::NotAllowed`] when this device is neither a
/// writer nor a reader of the space by those entries, or the trust context
/// governing its key revokes it. [`HeapError::Sealed`] when it is in the
/// sealed space's audience by neither the epoch nor the owner, which may not
/// hold its key.
pub(crate) fn signal_scope(log: &Log, judge: &Judge) -> Result<SignalScope, HeapError> {
    own_gate(log, judge, true)?;
    let space = log.space();
    let keys = match log.sealed() {
        true => sealed_keys(log)?,
        false => Vec::new(),
    };
    let group = sync_group_of(space).ok_or_else(|| HeapError::BadName {
        name: space.clone(),
        why: "a space is `<owner>/32=data/<name>`".into(),
    })?;
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
    let (space, fold) = (log.space(), log.fold());
    let Some(epoch) = fold.in_force() else {
        return Err(HeapError::NotReady {
            name: space.clone(),
            why: "no epoch of it is in force yet, so it has no signal key; ask again once the \
                  owner's epoch entry is held"
                .into(),
        });
    };
    let Some(content) = log.keys().key(space, &epoch) else {
        let person = log.person();
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
    let mut others: Vec<SignalKey> = fold
        .epochs()
        .into_iter()
        .filter(|e| *e != epoch)
        .filter_map(|e| Some(SignalKey::derive(log.keys().key(space, &e)?, space, &e)))
        .collect();
    others.sort_by(|a, b| (b.epoch.seq, &b.epoch.creator).cmp(&(a.epoch.seq, &a.epoch.creator)));
    let mut keys = Vec::with_capacity(1 + others.len());
    keys.push(SignalKey::derive(content, space, &epoch));
    keys.extend(others);
    Ok(keys)
}

/// Sign a signal run header (spec §11): Data
/// `<device>/32=signal/<scope>/32=run/<run>`, its Content `body`, signed by
/// this device's key `signer`, with no freshness period. Refused as
/// [`signal_scope`] refuses, except that a sealed space's key need not be held
/// to sign one. Nothing is stored or served.
pub(crate) fn signal_header(
    log: &Log,
    judge: &Judge,
    signer: &dyn Signer,
    scope: &Name,
    run_id: &[u8; RUN_ID_LEN],
    body: &[u8],
) -> Result<Bytes, HeapError> {
    if scope != log.space() {
        return Err(HeapError::BadName {
            name: scope.clone(),
            why: format!("this gate holds the space {}, not this one", log.space()),
        });
    }
    own_gate(log, judge, false)?;
    seal::sign(
        DataBuilder::new(signal_run_name(log.device(), scope, run_id), body),
        signer,
    )
    .map_err(|e| HeapError::Local {
        reason: e.to_string(),
    })
}

// -- Run headers -------------------------------------------------------------------------

/// The signer of another device's signal run header for `scope`, if it is a
/// member, before anything about it is verified (spec §11): its name is
/// `<device>/32=signal/<scope>/32=run/<16 octets>`, `device` the device of the
/// key its KeyLocator names (`Malformed` otherwise); the creation of the space
/// is held (`NotReady` otherwise); and that key is a member by the entries held
/// now (`NotMember` otherwise; `BadSignature` for a key the trust context
/// governing it revokes). Synchronous and offline: a transport asks it before
/// it spends anything on the header. Nothing is verified.
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
    if scope != log.space() {
        return Err(malformed(format!(
            "this gate holds the space {}, not {scope}",
            log.space()
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
    if log.fold().create().is_none() {
        return Err(SignalRefusal::NotReady {
            scope: scope.clone(),
            why: NO_RECORD.into(),
        });
    }
    match member_by(log, judge, &key) {
        Ok(person) => Ok(SignalSender {
            namespace: person,
            device: run.device,
            key,
        }),
        Err(NotMember::Unlisted) => Err(SignalRefusal::NotMember {
            scope: scope.clone(),
            key,
        }),
        Err(NotMember::Revoked) => Err(SignalRefusal::BadSignature { key }),
    }
}

/// Admit another device's signal run header for `scope` (spec §11): its signer
/// is a member ([`signal_sender`], asked first, so a stranger's header costs
/// nothing more), and it verifies by the validator that judges the signer's
/// person (the node's own, or the view adopted for her) by the **live** rule:
/// its certificates valid now, a revoked key refused. The chain is walked from
/// the certificates held first; one not held is fetched only while fewer than
/// 2 headers of the signer's person wait for certificates, and not for a
/// device whose last fetch brought none within 30 s (`Unverified` otherwise:
/// ask again when the header rides again). Its signer is a member still once
/// it verified. The header is not kept, served nor counted.
///
/// `log` is locked only to read, never across a fetch.
pub(crate) async fn signal_admit(
    gate: &SignalGate,
    log: &Mutex<Log>,
    judge: &Judge,
    scope: &Name,
    header: &Data,
) -> Result<SignalSender, SignalRefusal> {
    let sender = signal_sender(&log.lock(), judge, scope, header)?;
    let view = judge.view_for(&header.name, scope, true);
    gate.verify(&view, &sender, header).await?;
    // A revocation or a removal held while the chain was fetched.
    match member_by(&log.lock(), judge, &sender.key) {
        Ok(_) => Ok(sender),
        Err(NotMember::Unlisted) => Err(SignalRefusal::NotMember {
            scope: scope.clone(),
            key: sender.key,
        }),
        Err(NotMember::Revoked) => Err(SignalRefusal::BadSignature { key: sender.key }),
    }
}

// -- The certificate fetch budget --------------------------------------------------------

/// What the gate keeps between questions (spec §11): the certificate fetches
/// run headers wait for.
#[derive(Default)]
pub(crate) struct SignalGate {
    fetches: Mutex<Fetches>,
}

#[derive(Default)]
struct Fetches {
    /// Run headers waiting for certificates, per sender namespace.
    waiting: HashMap<Name, usize>,
    /// Devices no certificate is fetched for until then.
    backoff: HashMap<Name, Instant>,
}

/// A sender namespace's place among the headers waiting for certificates,
/// given back when dropped.
struct FetchSlot<'a> {
    gate: &'a SignalGate,
    namespace: Name,
}

impl Drop for FetchSlot<'_> {
    fn drop(&mut self) {
        let mut f = self.gate.fetches.lock();
        if let Some(n) = f.waiting.get_mut(&self.namespace) {
            *n -= 1;
            if *n == 0 {
                f.waiting.remove(&self.namespace);
            }
        }
    }
}

impl SignalGate {
    /// A place for `sender`'s header among those waiting for certificates:
    /// refused while its device backs off, or while its namespace has
    /// [`SIGNAL_FETCHES_PER_NAMESPACE`] waiting.
    fn fetch_slot(&self, sender: &SignalSender) -> Result<FetchSlot<'_>, SignalRefusal> {
        let mut f = self.fetches.lock();
        let now = Instant::now();
        if let Some(until) = f.backoff.get(&sender.device).copied() {
            if now < until {
                return Err(SignalRefusal::Unverified {
                    key: sender.key.clone(),
                    why: format!(
                        "a certificate a header of {} needed could not be had a moment ago, and \
                         none is fetched for that device for {} s after",
                        sender.device,
                        SIGNAL_FETCH_BACKOFF.as_secs()
                    ),
                });
            }
            f.backoff.remove(&sender.device);
        }
        let waiting = f.waiting.entry(sender.namespace.clone()).or_default();
        if *waiting >= SIGNAL_FETCHES_PER_NAMESPACE {
            return Err(SignalRefusal::Unverified {
                key: sender.key.clone(),
                why: format!(
                    "{SIGNAL_FETCHES_PER_NAMESPACE} run headers of {} wait for certificates here \
                     already",
                    sender.namespace
                ),
            });
        }
        *waiting += 1;
        Ok(FetchSlot {
            gate: self,
            namespace: sender.namespace.clone(),
        })
    }

    /// A fetch for a header of `device` brought no certificate: none is
    /// fetched for it for [`SIGNAL_FETCH_BACKOFF`].
    fn backoff(&self, device: &Name) {
        let mut f = self.fetches.lock();
        let now = Instant::now();
        if f.backoff.len() >= SIGNAL_BACKOFF_PRUNE_AT {
            f.backoff.retain(|_, until| now < *until);
        }
        f.backoff.insert(device.clone(), now + SIGNAL_FETCH_BACKOFF);
    }

    /// Verify `sender`'s run header by `view`, the live rule (see
    /// [`signal_admit`]): the certificates held first; one missing fetched
    /// within the sender namespace's place among the headers waiting for
    /// certificates, at most [`SIGNAL_CHAIN_FETCHES`] of them.
    async fn verify(
        &self,
        view: &Validator,
        sender: &SignalSender,
        header: &Data,
    ) -> Result<(), SignalRefusal> {
        let key = &sender.key;
        let unverified = |why: String| SignalRefusal::Unverified {
            key: key.clone(),
            why,
        };
        let mut slot = None;
        for _ in 0..=SIGNAL_CHAIN_FETCHES {
            let (result, missing) = view.validate_chain_cached(header).await;
            let missing = match result {
                ValidationResult::Valid(safe)
                    if !matches!(safe.trust_path(), TrustPath::DigestSha256) =>
                {
                    return Ok(());
                }
                ValidationResult::Pending => missing,
                other => {
                    tracing::debug!(name = %header.name, %key, "signal run header refused: {other:?}");
                    return Err(SignalRefusal::BadSignature { key: key.clone() });
                }
            };
            let Some(missing) = missing else {
                return Err(SignalRefusal::BadSignature { key: key.clone() });
            };
            let Some(fetcher) = view.cert_fetcher() else {
                return Err(unverified(format!(
                    "the certificate {missing} its chain needs is not held here, and this device \
                     fetches none"
                )));
            };
            if slot.is_none() {
                slot = Some(self.fetch_slot(sender)?);
            }
            if let Err(e) = fetcher.fetch_missing(&missing, None).await {
                self.backoff(&sender.device);
                let held = match view.cert_cache().all(&missing).is_empty() {
                    false => {
                        "only an expired certificate of it is held here, so its device renews \
                         its certificate; "
                    }
                    true => "",
                };
                return Err(unverified(format!(
                    "no current certificate {missing} its chain needs could be had ({e}); {held}\
                     none is fetched for {} for {} s",
                    sender.device,
                    SIGNAL_FETCH_BACKOFF.as_secs()
                )));
            }
        }
        Err(unverified(format!(
            "its chain needs more than {SIGNAL_CHAIN_FETCHES} certificates not held here"
        )))
    }
}

// -- The node's methods ------------------------------------------------------------------

impl Node {
    /// The space `space` as a member has it open: the one a signal question is
    /// about. A space not open here (or carried only) is not decided.
    fn signal_space(&self, space: &Name) -> Option<Arc<SpaceInner>> {
        self.inner.space_of(space).filter(|s| !s.follower)
    }

    /// What this node may do with signals over `space`, by the entries it
    /// holds (spec §11): its signal keys when the space is sealed, and the
    /// sync group to push into and listen on. A writer or a reader gets it.
    ///
    /// [`HeapError::NotReady`] when the space is not open here or its creation
    /// is not held yet (retry), or, sealed, the key of its epoch in force has
    /// not arrived. [`HeapError::NotAllowed`] when this device is neither a
    /// writer nor a reader of the space, or its key is revoked.
    /// [`HeapError::Sealed`] when it is outside the sealed space's audience.
    pub fn signal_scope(&self, space: &Name) -> Result<SignalScope, HeapError> {
        let held = self.signal_space(space).ok_or_else(|| not_open(space))?;
        let log = held.log.lock();
        signal_scope(&log, &self.inner.judge)
    }

    /// Sign a signal run header for `scope`: Data
    /// `<device>/32=signal/<scope>/32=run/<run_id>` with Content `body`, signed
    /// by this device's key. Only a writer sends; refused as
    /// [`Self::signal_scope`] refuses, except that a sealed space's key need
    /// not be held. Nothing is stored or served.
    pub fn signal_header(
        &self,
        scope: &Name,
        run_id: &[u8; RUN_ID_LEN],
        body: &[u8],
    ) -> Result<Bytes, HeapError> {
        let held = self.signal_space(scope).ok_or_else(|| not_open(scope))?;
        let log = held.log.lock();
        signal_header(
            &log,
            &self.inner.judge,
            &*self.inner.signer,
            scope,
            run_id,
            body,
        )
    }

    /// The signer of another device's run header for `scope`, if it is a
    /// member (a writer), before anything about it is verified. Synchronous
    /// and offline.
    pub fn signal_sender(&self, scope: &Name, data: &Data) -> Result<SignalSender, SignalRefusal> {
        let held = self
            .signal_space(scope)
            .ok_or_else(|| not_open_refusal(scope))?;
        let log = held.log.lock();
        signal_sender(&log, &self.inner.judge, scope, data)
    }

    /// Admit another device's run header for `scope`: its signer is a member
    /// ([`Self::signal_sender`]) and it verifies by the live rule, fetching
    /// the certificates of its chain within the signer's person's budget (2
    /// waiting at a time, a 30 s back-off per device). The header is not kept.
    pub async fn signal_admit(
        &self,
        scope: &Name,
        data: &Data,
    ) -> Result<SignalSender, SignalRefusal> {
        let held = self
            .signal_space(scope)
            .ok_or_else(|| not_open_refusal(scope))?;
        signal_admit(
            &self.inner.signal_gate,
            &held.log,
            &self.inner.judge,
            scope,
            data,
        )
        .await
    }

    /// Whether `key` is a member (a writer's key, not revoked) of `scope` now,
    /// by the entries held: asked for every signal packet. A space not open
    /// here has no members.
    pub fn signal_member(&self, scope: &Name, key: &Name) -> bool {
        self.signal_space(scope)
            .is_some_and(|held| signal_member(&held.log.lock(), &self.inner.judge, scope, key))
    }

    /// A count that moves whenever a trust context revoking keys is adopted
    /// here, the node's own or a view adopted for a person: a transport that
    /// admitted run headers under one count walks their chains again under
    /// another.
    pub fn revocations(&self) -> u64 {
        signal_revocations(&self.inner.judge)
    }

    /// This device's signature over `header`, by the key the node signs
    /// entries with.
    pub fn sign(&self, header: &[u8]) -> Result<Bytes, HeapError> {
        self.inner
            .signer
            .sign_sync(header)
            .map_err(|e| HeapError::Local {
                reason: format!("the device key cannot sign: {e}"),
            })
    }
}

/// Why nothing about `space` is decided: this node has not opened it.
fn not_open(space: &Name) -> HeapError {
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
