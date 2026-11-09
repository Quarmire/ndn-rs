//! Signals: the gate (spec §20). What the signal transport asks a device —
//! the record in force over a scope, its signal keys, the groups to push
//! into, run headers signed and admitted, and membership per packet — and
//! nothing else: nothing of a signal is stored, served or counted here.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Name};
use ndn_security::cert_name::key_name_of;
use ndn_security::safe_data::TrustPath;
use ndn_security::{ValidationResult, sync_group};
use parking_lot::Mutex;

use super::{Device, Inner, St, bad_name};
use crate::collection::{Epoch, Members};
use crate::error::DataError;
use crate::layer::Share;
use crate::rt::{self, Instant};
use crate::signal::{SignalKey, SignalRefusal, SignalScope, SignalSender};
use crate::wire::{self, RUN_ID_LEN, device_of, parse_signal_run_name, signal_run_name};

/// Run headers of one sender namespace that may wait for certificates at
/// once (spec §20).
pub const SIGNAL_FETCHES_PER_NAMESPACE: usize = 2;

/// How long no certificate is fetched for a device's run headers again
/// once a fetch for one of them brought none (spec §20).
pub const SIGNAL_FETCH_BACKOFF: Duration = Duration::from_secs(30);

/// Certificates fetched for one run header at most: one chain.
const SIGNAL_CHAIN_FETCHES: usize = 4;

/// Size at which devices past their back-off are swept.
const SIGNAL_BACKOFF_PRUNE_AT: usize = 1024;

/// What the gate keeps between questions (spec §20): the certificate
/// fetches run headers wait for, and what tells a transport that a trust
/// context revoking keys was adopted.
#[derive(Default)]
pub(super) struct SignalGate {
    fetches: Mutex<Fetches>,
    /// Views adopted for a person's namespace (§6.3) replaced by a version
    /// that refuses more ([`Device::signal_revocations`]).
    pub(super) scoped_revocations: AtomicU64,
}

#[derive(Default)]
struct Fetches {
    /// Run headers waiting for certificates, per sender namespace.
    waiting: HashMap<Name, usize>,
    /// Devices no certificate is fetched for until then.
    backoff: HashMap<Name, Instant>,
}

/// A sender namespace's place among the headers waiting for
/// certificates, given back when dropped.
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
}

impl Device {
    /// What this device may do with signals over `scope`, a folder or a
    /// collection, by the record in force over it now (spec §20): that
    /// record, the scope's signal keys when it is sealed, the sync groups
    /// to push into and the one to listen on.
    ///
    /// [`DataError::NotReady`] when no record over `scope` is held here
    /// yet, or, sealed, the key of its epoch in force is not held yet (its
    /// ask is started, as a sealed get's: ask again).
    /// [`DataError::NotAllowed`] when this device is no member of `scope`
    /// by that record, or the trust context governing its key revokes it.
    /// [`DataError::Sealed`] when it is a member as a writer outside the
    /// sealed scope's audience, which may not hold its key.
    pub fn signal_scope(&self, scope: &Name) -> Result<SignalScope, DataError> {
        wire::data_marker(scope).map_err(|why| bad_name(scope, why))?;
        let inner = &self.inner;
        let (subject, epoch, start) = {
            let st = inner.st.lock();
            let m = inner.signal_gate(&st, scope)?;
            let Some(e) = m.epoch.as_ref() else {
                return Ok(inner.signal_scope_of(&st, scope, &m, Vec::new()));
            };
            if let Some(keys) = inner.signal_keys(&st, scope, e) {
                return Ok(inner.signal_scope_of(&st, scope, &m, keys));
            }
            let s = st.seal_subject(scope, e);
            if !inner.may_hold(&st, &s.name, e, &inner.device, &inner.ns) {
                return Err(DataError::Sealed {
                    name: scope.clone(),
                });
            }
            let start = !st.asking.contains(&(s.name.clone(), e.clone()));
            (s.name, e.clone(), start)
        };
        let why = format!(
            "it is sealed, and the key of its epoch in force (seq {} of {}) is not held here yet; \
             it is being asked for from the epoch's creator and the devices that write into it, \
             so ask again once it arrives",
            epoch.seq.0, epoch.creator
        );
        if start {
            let inner = Arc::clone(&self.inner);
            rt::spawn(async move {
                inner.obtain(&subject, &epoch).await;
            });
        }
        Err(DataError::NotReady {
            name: scope.clone(),
            why,
        })
    }

    /// Sign a signal run header (spec §20): Data
    /// `<device>/32=signal/<scope>/32=run/<run>`, its Content `content`,
    /// signed by this device's key, with no freshness period. Refused as
    /// [`Self::signal_scope`] refuses, except that a sealed scope's key
    /// need not be held to sign one. Nothing is stored or served.
    pub fn signal_header(
        &self,
        scope: &Name,
        run: &[u8; RUN_ID_LEN],
        content: &[u8],
    ) -> Result<Bytes, DataError> {
        wire::data_marker(scope).map_err(|why| bad_name(scope, why))?;
        let inner = &self.inner;
        inner.signal_gate(&inner.st.lock(), scope)?;
        inner.sign(DataBuilder::new(
            signal_run_name(&inner.device, scope, run),
            content,
        ))
    }

    /// The signer of another device's signal run header for `scope`, if it
    /// is a member, before anything about it is verified (spec §20): its
    /// name is `<device>/32=signal/<scope>/32=run/<16 octets>`, `device`
    /// the device of the key its KeyLocator names (`Malformed` otherwise);
    /// a record over `scope` is held (`NotReady` otherwise); and that key
    /// is a member of `scope` by the record in force now (`NotMember`
    /// otherwise; `BadSignature` for a key the trust context governing it
    /// revokes). Synchronous and offline: a transport asks it before it
    /// spends anything on the header. Nothing is verified.
    pub fn signal_sender(
        &self,
        scope: &Name,
        header: &Data,
    ) -> Result<SignalSender, SignalRefusal> {
        let malformed = |why: String| SignalRefusal::Malformed {
            scope: scope.clone(),
            why,
        };
        let Some(run) = parse_signal_run_name(&header.name) else {
            return Err(malformed(format!(
                "its name {} is not <device>/32=signal/<scope>/32=run/<16-octet run id>",
                header.name
            )));
        };
        if run.scope != *scope {
            return Err(malformed(format!(
                "it is a run header of {}, another scope",
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
        let inner = &self.inner;
        let st = inner.st.lock();
        let Some(m) = st.record_in_force(scope) else {
            return Err(SignalRefusal::NotReady {
                scope: scope.clone(),
                why: NO_RECORD.into(),
            });
        };
        match inner.signal_member_by(&st, &m, scope, &key) {
            Ok(()) => {}
            Err(NotMember::Unlisted) => {
                return Err(SignalRefusal::NotMember {
                    scope: scope.clone(),
                    key,
                });
            }
            Err(NotMember::Revoked) => return Err(SignalRefusal::BadSignature { key }),
        }
        let namespace = inner.group_namespace_of(&st, &run.device);
        Ok(SignalSender {
            namespace: match namespace.is_empty() {
                true => run.device.clone(),
                false => namespace,
            },
            device: run.device,
            key,
        })
    }

    /// Admit another device's signal run header for `scope` (spec §20):
    /// its signer is a member ([`Self::signal_sender`], asked first, so a
    /// stranger's header costs nothing more), and it verifies by this
    /// device's validator (for a member's self-certifying namespace
    /// adopted for the folder, the view adopted for it, §6.3) by the
    /// **live** rule: its certificates valid now, a revoked key refused.
    /// The chain is walked from the certificates held first; one not held
    /// is fetched only while fewer than 2 headers of the signer's namespace
    /// wait for certificates, and not for a device whose last fetch brought
    /// none within 30 s (`Unverified` otherwise: ask again when the header
    /// rides again). Its signer is a member still once it verified.
    /// The header is not kept, served nor counted as a version.
    pub async fn signal_admit(
        &self,
        scope: &Name,
        header: &Data,
    ) -> Result<SignalSender, SignalRefusal> {
        let sender = self.signal_sender(scope, header)?;
        self.inner.signal_verify(&sender, header).await?;
        if !self.signal_member(scope, &sender.key) {
            return Err(SignalRefusal::NotMember {
                scope: scope.clone(),
                key: sender.key,
            });
        }
        Ok(sender)
    }

    /// A count that moves whenever a trust context revoking keys is
    /// adopted here — the device's own, or a view adopted for a person's
    /// namespace (§6.3) replaced by a version that refuses more (spec
    /// §20). A transport that admitted run headers when it read one count
    /// and reads another now walks their chains again: a revoked issuer
    /// ends the runs it certified. One atomic load each.
    pub fn signal_revocations(&self) -> u64 {
        let inner = &self.inner;
        inner
            .validator
            .keyring()
            .revocation_epoch()
            .wrapping_add(inner.signals.scoped_revocations.load(Ordering::SeqCst))
    }

    /// Whether `key` is a member of `scope` now (spec §20): a writer
    /// prefix of the record in force over `scope` covers it, or that
    /// record's audience admits its device, and the trust context governing
    /// it does not revoke it. Synchronous, under the device's lock: the
    /// check of every signal packet, exact by the records held at the call.
    pub fn signal_member(&self, scope: &Name, key: &Name) -> bool {
        let inner = &self.inner;
        let st = inner.st.lock();
        st.record_in_force(scope)
            .is_some_and(|m| inner.signal_member_by(&st, &m, scope, key).is_ok())
    }
}

/// Why nothing about a scope is decided here yet.
const NO_RECORD: &str = "no members record over it is held here yet; follow it (watch it, or get \
                         a collection under it) so its owner's record arrives, then ask again";

/// Why a key is no member of a scope for signals.
enum NotMember {
    /// No writer prefix covers it and the audience does not admit it.
    Unlisted,
    /// The trust context governing it revokes it.
    Revoked,
}

impl Inner {
    /// Verify `sender`'s run header by the live rule (spec §20,
    /// [`Device::signal_admit`]): the certificates held first; one missing
    /// fetched within the sender namespace's place among the headers
    /// waiting for certificates, at most [`SIGNAL_CHAIN_FETCHES`] of them.
    async fn signal_verify(
        &self,
        sender: &SignalSender,
        header: &Data,
    ) -> Result<(), SignalRefusal> {
        let judge = self.judge(&header.name);
        let key = &sender.key;
        let unverified = |why: String| SignalRefusal::Unverified {
            key: key.clone(),
            why,
        };
        let mut slot = None;
        for _ in 0..=SIGNAL_CHAIN_FETCHES {
            let (result, missing) = judge.validate_chain_cached(header).await;
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
            let Some(fetcher) = judge.cert_fetcher() else {
                return Err(unverified(format!(
                    "the certificate {missing} its chain needs is not held here, and this device \
                     fetches none"
                )));
            };
            if slot.is_none() {
                slot = Some(self.signals.fetch_slot(sender)?);
            }
            if let Err(e) = fetcher.fetch_missing(&missing, None).await {
                self.signals.backoff(&sender.device);
                let held = match judge.cert_cache().all(&missing).is_empty() {
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

    /// The record in force over `scope` when this device may use signals
    /// over it: held, and this device a member by it (spec §20).
    fn signal_gate<'a>(&self, st: &'a St, scope: &Name) -> Result<Cow<'a, Members>, DataError> {
        let Some(m) = st.record_in_force(scope) else {
            return Err(DataError::NotReady {
                name: scope.clone(),
                why: NO_RECORD.into(),
            });
        };
        if let Err(why) = self.signal_member_by(st, &m, scope, self.writer.key()) {
            match why {
                NotMember::Unlisted => {
                    tracing::debug!(%scope, key = %self.writer.key(), "signals refused: this device is no member by the record in force")
                }
                NotMember::Revoked => {
                    tracing::debug!(%scope, key = %self.writer.key(), "signals refused: the trust context governing this device's key revokes it")
                }
            }
            return Err(DataError::NotAllowed {
                collection: scope.clone(),
                writer: self.writer.clone(),
            });
        }
        Ok(m)
    }

    /// Whether `key` is a member of `scope` by `m`, the record in force over
    /// it (spec §20): a writer prefix `m` lists covers it (a key kept only
    /// by a cut is not), or `m`'s audience admits its device; and the trust
    /// context governing it — as this device judges the key's packets
    /// about `scope` — does not revoke it.
    fn signal_member_by(
        &self,
        st: &St,
        m: &Members,
        scope: &Name,
        key: &Name,
    ) -> Result<(), NotMember> {
        let Some(device) = device_of(key) else {
            return Err(NotMember::Unlisted);
        };
        let listed = m.lists_writer(key)
            || self.admits_record(st, m, &device, &self.namespace_of_name(&device));
        if !listed {
            return Err(NotMember::Unlisted);
        }
        let revoked = self
            .judge_signer(st, key, scope)
            .keyring()
            .context_for(key)
            .is_revoked(key);
        match revoked {
            true => Err(NotMember::Revoked),
            false => Ok(()),
        }
    }

    /// The signal keys of `scope`, sealed in epoch `e` (spec §20): `e`'s
    /// first, then those of the other epochs of its record line whose keys
    /// are held, by their record's seq, highest first. `None` when `e`'s
    /// key is not held.
    fn signal_keys(&self, st: &St, scope: &Name, e: &Epoch) -> Option<Vec<SignalKey>> {
        let first = SignalKey::derive(&st.keys.key(scope, e)?, scope, e);
        let mut others: Vec<SignalKey> = st
            .line_of(&st.seal_subject(scope, e))
            .into_iter()
            .flat_map(|(epochs, _)| epochs.keys())
            .filter(|x| *x != e)
            .filter_map(|x| Some(SignalKey::derive(&st.keys.key(scope, x)?, scope, x)))
            .collect();
        others.sort_by_key(|k| std::cmp::Reverse(k.epoch.seq.0));
        let mut keys = Vec::with_capacity(1 + others.len());
        keys.push(first);
        keys.extend(others);
        Some(keys)
    }

    /// What [`Device::signal_scope`] answers for `scope`, its record in
    /// force `m` and its signal keys `keys`: the groups are those a version
    /// about `scope` is published into ([`Self::groups_of`]), with those
    /// `m` names (the nearest folder's, for a collection with no record of
    /// its own).
    fn signal_scope_of(
        &self,
        st: &St,
        scope: &Name,
        m: &Members,
        keys: Vec<SignalKey>,
    ) -> SignalScope {
        let mut namespaces = self.groups_of(st, scope);
        self.groups_named(st, m, &mut namespaces);
        SignalScope {
            scope: scope.clone(),
            share: Share::of(m),
            keys,
            groups: namespaces.iter().map(sync_group).collect(),
            listen: sync_group(&self.ns),
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "signal_tests.rs"]
mod tests;
