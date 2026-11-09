//! Signals: the gate (spec §20). What the signal transport asks a device —
//! the record in force over a scope, its signal keys, the groups to push
//! into, run headers signed and admitted, and membership per packet — and
//! nothing else: nothing of a signal is stored, served or counted here.

use std::borrow::Cow;
use std::sync::Arc;

use bytes::Bytes;
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Name};
use ndn_security::cert_name::key_name_of;
use ndn_security::sync_group;

use super::{Device, Inner, St, bad_name};
use crate::collection::{Epoch, Members};
use crate::error::DataError;
use crate::layer::Share;
use crate::rt;
use crate::signal::{SignalKey, SignalRefusal, SignalScope};
use crate::wire::{self, RUN_ID_LEN, device_of, parse_signal_run_name, signal_run_name};

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

    /// Admit another device's signal run header for `scope` (spec §20): its
    /// name is `<device>/32=signal/<scope>/32=run/<16 octets>`, `device`
    /// the device of the key its KeyLocator names; it verifies by this
    /// device's validator (for a member's self-certifying namespace adopted
    /// for the folder, the view adopted for it, §6.3; certificates fetched
    /// as for versions; a revoked key refused); and its key is a member of
    /// `scope` by the record in force now ([`Self::signal_member`]). The
    /// signer's key name when admitted. The header is not kept, served nor
    /// counted as a version.
    pub async fn signal_admit(&self, scope: &Name, header: &Data) -> Result<Name, SignalRefusal> {
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
        if inner.st.lock().record_in_force(scope).is_none() {
            return Err(SignalRefusal::NotReady {
                scope: scope.clone(),
                why: NO_RECORD.into(),
            });
        }
        if let Err(why) = inner.verify(header).await {
            tracing::debug!(%scope, %key, ?why, "signal run header refused: it does not verify");
            return Err(SignalRefusal::BadSignature { key });
        }
        if !self.signal_member(scope, &key) {
            return Err(SignalRefusal::NotMember {
                scope: scope.clone(),
                key,
            });
        }
        Ok(key)
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
