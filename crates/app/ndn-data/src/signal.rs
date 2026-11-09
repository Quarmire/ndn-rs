//! Signals: the gate (spec data-layer §20; `docs/specs/signals.md` for the
//! rest).
//!
//! A signal is ephemeral live data — presence, cursors, a drag, live
//! unsigned edits — pushed to the members of a folder or collection and
//! never a version: nothing of it is stored, served or counted here. The
//! signal transport (`ndn_surface::signal`) asks a [`Device`](crate::Device)
//! six things, and nothing else leaves this crate:
//!
//! - [`Device::signal_scope`](crate::Device::signal_scope): what this
//!   device may do with signals over a scope — the record in force, the
//!   scope's signal keys when it is sealed, the sync groups to push into and
//!   the one to listen on;
//! - [`Device::signal_header`](crate::Device::signal_header): sign a run
//!   header with the device key;
//! - [`Device::signal_sender`](crate::Device::signal_sender): a run
//!   header's signer if it is a member, before anything is verified;
//! - [`Device::signal_admit`](crate::Device::signal_admit): admit another
//!   device's run header, or say why not ([`SignalRefusal`]);
//! - [`Device::signal_member`](crate::Device::signal_member): whether a key
//!   is a member of a scope now, asked for every packet;
//! - [`Device::signal_revocations`](crate::Device::signal_revocations): a
//!   count that moves when a trust context revoking keys is adopted, so the
//!   chains of the runs admitted are walked again.
//!
//! A **member** of a scope, for signals, is a device whose key a writer
//! prefix of the record in force over the scope covers, or which that
//! record's audience admits, and whose key the trust context governing it
//! does not revoke.

use std::fmt;

use hkdf::Hkdf;
use ndn_foundation_types::Name;
use ndn_security::confidentiality::ContentKey;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::collection::Epoch;
use crate::layer::Share;

/// The domain label of a scope's signal key.
const SIGNAL_KEY: &[u8] = b"ndn-data/signal/1";

/// The domain label of a signal key's id.
const SIGNAL_KEY_ID: &[u8] = b"ndn-data/signal/id/1";

/// The octets of a signal key's id ([`SignalKey::id`]).
pub const KEY_ID_LEN: usize = 8;

/// What this device may do with signals over `scope`, by the record in
/// force now ([`Device::signal_scope`](crate::Device::signal_scope)).
#[derive(Clone, Debug)]
pub struct SignalScope {
    /// The folder or collection asked about.
    pub scope: Name,
    /// The record in force over it, as [`members`](crate::DataLayer::members)
    /// answers.
    pub share: Share,
    /// A sealed scope's signal keys held here: the epoch in force's first —
    /// the one to seal with — then those of the other epochs of its record
    /// line whose keys are held, by their record's seq, highest first (to
    /// open what members still seal in them). Empty when the scope is not
    /// sealed.
    pub keys: Vec<SignalKey>,
    /// The sync groups to push into (`<O>/32=sync`): of the scope's
    /// namespace and of every namespace its record names, as data-layer §12
    /// publishes a version about it (adopted self-certifying ones
    /// included).
    pub groups: Vec<Name>,
    /// This device's own namespace's sync group, where others push for it.
    pub listen: Name,
}

/// A sealed scope's signal key for one epoch (spec data-layer §20):
/// HKDF-SHA256 with the epoch's content key as input key material, no salt,
/// and as info `ndn-data/signal/1` ‖ the scope's Name TLV ‖ the epoch
/// creator's Name TLV ‖ the epoch's seq as 8 octets big-endian. Its
/// [`id`](Self::id) is the first 8 octets of HKDF-SHA256 with the signal
/// key as input key material, no salt, and info `ndn-data/signal/id/1`.
///
/// The key is zeroed when dropped, and its `Debug` shows only the epoch and
/// the id.
#[derive(Clone)]
pub struct SignalKey {
    /// The epoch whose content key it is derived from.
    pub epoch: Epoch,
    /// Its id, carried beside what it seals so a receiver knows which key
    /// opens it.
    pub id: [u8; KEY_ID_LEN],
    key: Zeroizing<[u8; 32]>,
}

impl SignalKey {
    /// The signal key of `scope` in `epoch`, whose content key is
    /// `content`.
    pub(crate) fn derive(content: &ContentKey, scope: &Name, epoch: &Epoch) -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(None, content.expose())
            .expand_multi_info(
                &[
                    SIGNAL_KEY,
                    &scope.encode_to_tlv(),
                    &epoch.creator.encode_to_tlv(),
                    &epoch.seq.0.to_be_bytes(),
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

/// The signer of a run header, a member of the scope by the record in force
/// ([`Device::signal_sender`](crate::Device::signal_sender),
/// [`Device::signal_admit`](crate::Device::signal_admit)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignalSender {
    /// The key that signed it.
    pub key: Name,
    /// That key's device.
    pub device: Name,
    /// The namespace whose sync group the device notices in (spec §12) —
    /// the device itself when none is held — which a transport bounds a
    /// sender's admissions and runs by: a person listed by prefix can make
    /// as many keys and devices as it likes, never more namespaces.
    pub namespace: Name,
}

/// Why a run header is not admitted
/// ([`Device::signal_admit`](crate::Device::signal_admit)). Each says what
/// to do. None is kept: a refused header is dropped with its run.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SignalRefusal {
    /// Not a run header of this scope.
    #[error(
        "not a signal run header of {scope}: {why}; drop it and its run (a run header of {scope} \
         is named <device>/32=signal/{scope}/32=run/<16-octet run id> and signed by that \
         device's key)"
    )]
    Malformed {
        /// The scope it was offered for.
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
    /// Its key is no member of the scope by the record in force here.
    #[error(
        "{key} is no member of {scope} by the record in force here: drop its run; its runs are \
         refused until a record admitting it is held (its owner adds it)"
    )]
    NotMember {
        /// The scope.
        scope: Name,
        /// The key that signed it.
        key: Name,
    },
    /// No members record over the scope is held here yet.
    #[error(
        "nothing about {scope} is decided here yet: {why}; drop the run for now and admit its \
         header again (it rides again within a second) once the record is held"
    )]
    NotReady {
        /// The scope.
        scope: Name,
        /// What it waits for.
        why: String,
    },
    /// Its signer is a member, and a certificate its chain needs is not
    /// held here and is not fetched now: the fetch budget of the signer's
    /// namespace is spent, its device backs off after a fetch that brought
    /// none, or no current certificate could be had.
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
