//! Epoch keys, sealing and grants (spec §6): the crypto and key half.
//!
//! A sealed space is read in an *epoch*, named by the Epoch entry that
//! started it. The epoch key is 32 random octets made by the owner device
//! that signed that entry; the entry carries the key's **check**
//! ([`key_check`]), so any key a device is given can be checked against the
//! owner-signed entry before it is used ([`accept_key`]). Readers get keys
//! as grants, each wrapped to the asker's published seal key
//! ([`wrap_key`]), one per epoch of one space; the granter's decision is
//! [`may_grant`]. Payloads are sealed with ChaCha20-Poly1305
//! ([`ContentKey`]), their AAD the entry's name ([`seal_payload`]).
//!
//! Everything here is pure and synchronous: the pull protocol over the
//! network (asking, serving, fetching the asker's seal key) calls it.
//! Every secret is held in a type that zeroizes on drop.

use std::collections::HashMap;

use bytes::Bytes;
use hkdf::Hkdf;
use ndn_foundation_types::Name;
use ndn_packet::Data;
use ndn_packet::encode::DataBuilder;
use ndn_security::confidentiality::{
    ConfidentialityError, ContentKey, RecipientKey, Sealed, wrap_ck_to,
};
use ndn_security::{SecurityManager, Signer};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::fold::Fold;
use crate::store;
use crate::wire::{self, EpochId, Grant};

/// The domain label of an epoch key's check.
const KEY_CHECK: &[u8] = b"ndn-heap/seal/check/1";

/// Why a key operation failed: the key store, or a key that cannot be
/// wrapped to.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SealError {
    /// The key store keeps something else than a recipient secret under the
    /// device's secret name.
    #[error(
        "the key store keeps {name} as {len} octets; a recipient secret is 32. Nothing was \
         replaced, because grants wrapped to the old key would be lost: remove that entry from \
         the key store by hand to make a new recipient key"
    )]
    BadSecret {
        /// Where the key store keeps the device's recipient secret.
        name: Name,
        /// The octets it holds there.
        len: usize,
    },
    /// The key store did not keep a new recipient secret.
    #[error("the key store cannot keep {name}: {reason}; the device has no seal key until it can")]
    Store {
        /// Where the secret was to be kept.
        name: Name,
        /// What the key store said.
        reason: String,
    },
    /// The public key to wrap to agrees no shared secret.
    #[error("a key cannot be wrapped to this seal key: {0}")]
    Wrap(#[from] ConfidentialityError),
    /// A Data packet could not be signed.
    #[error(
        "the device key {key} did not sign ({reason}); the data layer needs a key that signs \
         synchronously"
    )]
    Sign {
        /// The device key.
        key: Name,
        /// What the signer said.
        reason: String,
    },
}

// ---- the key check -----------------------------------------------------------------------------

/// The check of `key` as the content key of `epoch` of `space`: HKDF-SHA256
/// with the key as input key material, no salt, and `info` the label, the
/// TLV of `space`, the TLV of the epoch's creator and the epoch's seq as 8
/// octets, big-endian. The Epoch entry starting the epoch carries it.
pub(crate) fn key_check(key: &ContentKey, space: &Name, epoch: &EpochId) -> [u8; 32] {
    let mut check = [0u8; 32];
    Hkdf::<Sha256>::new(None, key.expose())
        .expand_multi_info(
            &[
                KEY_CHECK,
                &space.encode_to_tlv(),
                &epoch.creator.encode_to_tlv(),
                &epoch.seq.to_be_bytes(),
            ],
            &mut check,
        )
        .expect("32 octets is a valid HKDF-SHA256 output length");
    check
}

/// Whether `key` is the key of `epoch` of `space`, given the `named` check
/// of the held owner-signed Epoch entry naming it. A key is taken only if
/// it is.
pub(crate) fn accept_key(
    named: &[u8; 32],
    space: &Name,
    epoch: &EpochId,
    key: &ContentKey,
) -> bool {
    key_check(key, space, epoch) == *named
}

// ---- sealing -----------------------------------------------------------------------------------

/// Seal `plaintext` under `key`, bound to the entry's name: `nonce ‖ tag ‖
/// ciphertext` with a fresh random 96-bit nonce.
pub(crate) fn seal_payload(key: &ContentKey, entry: &Name, plaintext: &[u8]) -> Bytes {
    key.seal(plaintext, &entry.encode_to_tlv()).to_bytes()
}

/// Open a payload [`seal_payload`] made: `None` if it is not `key`'s, not
/// this entry's, malformed or altered.
pub(crate) fn open_payload(key: &ContentKey, entry: &Name, stored: &[u8]) -> Option<Vec<u8>> {
    let sealed = Sealed::from_bytes(stored).ok()?;
    key.open(&sealed, &entry.encode_to_tlv()).ok()
}

// ---- wrapping ----------------------------------------------------------------------------------

/// Wrap `key` to the seal key `to`, binding the name of what carries it
/// (`aad`): a grant's name, or the store name an epoch key is kept under.
/// Returns the Content of a grant: the fresh ephemeral public key and
/// `nonce ‖ tag ‖ ciphertext`. Take `to` only from a seal key packet its
/// device signed.
pub(crate) fn wrap_key(to: &[u8; 32], key: &ContentKey, aad: &Name) -> Result<Bytes, SealError> {
    let (ephemeral, wrapped) = wrap_ck_to(to, key, &aad.encode_to_tlv())?;
    Ok(Grant {
        ephemeral,
        ciphertext: wrapped.to_bytes(),
    }
    .encode())
}

/// The key [`wrap_key`] wrapped to `recipient` under `aad`, from the
/// Content of a grant; `None` if it is malformed, not wrapped to that key
/// under that name, or altered.
pub(crate) fn unwrap_key(
    recipient: &RecipientKey,
    aad: &Name,
    content: Bytes,
) -> Option<ContentKey> {
    let grant = Grant::decode(content).ok()?;
    let sealed = Sealed::from_bytes(&grant.ciphertext).ok()?;
    recipient
        .unwrap_ck(&grant.ephemeral, &sealed, &aad.encode_to_tlv())
        .ok()
}

/// Sign `builder` with the device key `signer`, which must sign
/// synchronously.
fn sign(builder: DataBuilder, signer: &dyn Signer) -> Result<Bytes, SealError> {
    let mut failed = None;
    let wire = builder.sign_sync(
        signer.sig_type(),
        Some(signer.key_name()),
        |region| match signer.sign_sync(region) {
            Ok(sig) => sig,
            Err(e) => {
                failed = Some(e);
                Bytes::new()
            }
        },
    );
    match failed {
        Some(e) => Err(SealError::Sign {
            key: signer.key_name().clone(),
            reason: e.to_string(),
        }),
        None => Ok(wire),
    }
}

/// The answer to a grant ask: the Data packet `name` (`<G>/32=grant/<ask>`)
/// whose Content wraps `key` to the asker's seal key `to` under that name
/// ([`wrap_key`]), signed by the granter's device key. The granter has
/// decided by [`may_grant`] and taken `to` from a seal key packet the
/// asker's device signed.
pub(crate) fn grant_packet(
    to: &[u8; 32],
    key: &ContentKey,
    name: &Name,
    signer: &dyn Signer,
) -> Result<Bytes, SealError> {
    let content = wrap_key(to, key, name)?;
    sign(DataBuilder::new(name.clone(), &content), signer)
}

/// This device's seal key packet `<D>/32=seal/<public key>`: the X25519
/// public key as Content, signed by the device key, so whoever wraps a key
/// to it knows the device published it.
pub(crate) fn seal_key_packet(
    device: &Name,
    public: &[u8; 32],
    signer: &dyn Signer,
) -> Result<Bytes, SealError> {
    let name = wire::seal_key_name(device, public);
    sign(
        DataBuilder::new(name, &wire::encode_seal_key(public)),
        signer,
    )
}

/// Whether `data` is the seal key packet of `device` for `public`: named
/// `<device>/32=seal/<public>` and carrying that key. That the packet is
/// signed by the device's key is the validator's to say (`trust`); a key
/// is taken from a packet only when both hold.
pub(crate) fn seal_key_matches(data: &Data, device: &Name, public: &[u8; 32]) -> bool {
    *data.name == wire::seal_key_name(device, public)
        && data
            .content()
            .and_then(|c| wire::decode_seal_key(c.clone()).ok())
            .is_some_and(|p| p == *public)
}

// ---- the recipient key -------------------------------------------------------------------------

/// Where the key store keeps this device's recipient secret:
/// `/localhost/ndn-heap/seal/<device>`, under no prefix any device serves.
pub(crate) fn recipient_secret_name(device: &Name) -> Name {
    let base: Name = "/localhost/ndn-heap/seal".parse().expect("a valid name");
    Name::from_components(base.components().iter().chain(device.components()).cloned())
}

/// This device's recipient key: the one its key store keeps, else a new
/// one, kept there. Made once; grants are wrapped to its public half.
pub(crate) fn recipient_key(
    store: &SecurityManager,
    device: &Name,
) -> Result<RecipientKey, SealError> {
    let name = recipient_secret_name(device);
    if let Some(kept) = store.secret(&name) {
        let mut secret =
            <[u8; 32]>::try_from(kept.as_slice()).map_err(|_| SealError::BadSecret {
                name,
                len: kept.len(),
            })?;
        let key = RecipientKey::from_bytes(secret);
        secret.zeroize();
        return Ok(key);
    }
    let key = RecipientKey::generate();
    store
        .put_secret(name.clone(), key.expose())
        .map_err(|e| SealError::Store {
            name,
            reason: e.to_string(),
        })?;
    Ok(key)
}

// ---- the keys one device holds -----------------------------------------------------------------

/// The keys one device holds: its recipient key, and the epoch keys it made
/// or was granted, by space and epoch. Every key zeroizes when dropped.
pub(crate) struct Keys {
    /// This device's recipient key: grants and stored epoch keys are wrapped
    /// to its public half.
    recipient: RecipientKey,
    /// Epoch keys, each checked against the Epoch entry naming its epoch.
    held: HashMap<Name, HashMap<EpochId, ContentKey>>,
}

// Every field is a `ZeroizeOnDrop` type or a map of them: dropping `Keys`
// drops, and so zeroizes, each secret it holds.
impl ZeroizeOnDrop for Keys {}

impl Keys {
    /// The keys of a device whose recipient key is `recipient`, holding no
    /// epoch key yet.
    pub(crate) fn new(recipient: RecipientKey) -> Self {
        Self {
            recipient,
            held: HashMap::new(),
        }
    }

    /// This device's recipient key.
    pub(crate) fn recipient(&self) -> &RecipientKey {
        &self.recipient
    }

    /// The public half of the recipient key: the seal key this device
    /// publishes.
    pub(crate) fn public(&self) -> [u8; 32] {
        self.recipient.public()
    }

    /// The key of `epoch` of `space`, if held.
    pub(crate) fn key(&self, space: &Name, epoch: &EpochId) -> Option<&ContentKey> {
        self.held.get(space)?.get(epoch)
    }

    /// Hold a key this device made itself as the key of `epoch` of `space`.
    /// The caller computed the epoch entry's check from it ([`key_check`]),
    /// so it matches by construction; a key from anywhere else goes through
    /// [`Keys::take`].
    pub(crate) fn hold(&mut self, space: &Name, epoch: EpochId, key: ContentKey) {
        self.held
            .entry(space.clone())
            .or_default()
            .insert(epoch, key);
    }

    /// Hold `key` as the key of `epoch` of `space` only if it matches the
    /// `named` check of the held owner-signed Epoch entry naming that epoch
    /// ([`accept_key`]). Whether it did; a key that did not is dropped
    /// (zeroized).
    pub(crate) fn take(
        &mut self,
        space: &Name,
        epoch: &EpochId,
        named: &[u8; 32],
        key: ContentKey,
    ) -> bool {
        if !accept_key(named, space, epoch, &key) {
            return false;
        }
        self.hold(space, epoch.clone(), key);
        true
    }

    /// What the store is to keep so the held key of `epoch` of `space`
    /// survives a restart: the store key ([`store::epoch_key`]) and the
    /// key wrapped to this device's seal key under that name ([`wrap_key`]).
    /// `None` if no key is held for the epoch. The caller writes it in the
    /// batch that makes the key's Epoch entry durable.
    pub(crate) fn record(
        &self,
        space: &Name,
        epoch: &EpochId,
    ) -> Option<Result<(Name, Bytes), SealError>> {
        let key = self.key(space, epoch)?;
        let at = store::epoch_key(space, &epoch.creator, epoch.seq);
        Some(wrap_key(&self.public(), key, &at).map(|stored| (at, stored)))
    }

    /// Take the epoch key the store kept ([`Keys::record`]), on the same
    /// terms as [`Keys::take`]. A value that is malformed, not wrapped to
    /// this device under the store name of `epoch` of `space`, or whose key
    /// fails the check is dropped. Whether the key was held.
    pub(crate) fn restore(
        &mut self,
        space: &Name,
        epoch: &EpochId,
        named: &[u8; 32],
        stored: Bytes,
    ) -> bool {
        let at = store::epoch_key(space, &epoch.creator, epoch.seq);
        match unwrap_key(&self.recipient, &at, stored) {
            Some(key) => self.take(space, epoch, named, key),
            None => false,
        }
    }

    /// Take a key granted for `epoch` of `space` only if a held
    /// owner-signed Epoch entry of `fold` names the epoch and its check
    /// matches ([`Keys::take`]). Whether it was held; a key for an epoch no
    /// held entry names, or that fails the check, is dropped (zeroized).
    pub(crate) fn take_named(
        &mut self,
        fold: &Fold,
        space: &Name,
        epoch: &EpochId,
        key: ContentKey,
    ) -> bool {
        match fold.epoch_body(epoch) {
            Some(body) => self.take(space, epoch, &body.key_check, key),
            None => false,
        }
    }
}

// ---- the granter's decision --------------------------------------------------------------------

/// Why a grant is not answered (spec §6): the first of the four conditions
/// that does not hold. A refused ask gets no answer and its granter
/// fetches nothing for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum GrantRefusal {
    /// No held owner-signed Epoch entry names the epoch.
    #[error(
        "no held owner-signed Epoch entry names the epoch: it may be the owner's entry this \
         device has not received yet, or an epoch that does not exist; ask again after sync"
    )]
    EpochNotNamed,
    /// The asker's person is not in the epoch's audience.
    #[error(
        "the asker's person is not in the epoch's audience: the epoch ended before the person \
         was listed as a reader and stays closed to it; the owner can add it as a reader of an \
         epoch to open that epoch's history"
    )]
    NotInAudience,
    /// The asker's person is not a reader of the space now.
    #[error(
        "the asker's person is not a reader of the space now (removed, or never listed): grants \
         are forward only; the owner can add it back as a reader"
    )]
    NotReaderNow,
    /// This device does not hold the epoch's key.
    #[error(
        "this device does not hold the epoch's key: it neither made it nor was granted it; ask \
         the epoch's creator or another reader device"
    )]
    KeyNotHeld,
}

/// The facts a granter decides on: the owner-signed Epoch entries it holds,
/// the membership fold, and its keys. Implemented over the fold and the
/// keys by the node; a test view in the tests.
pub(crate) trait GrantView {
    /// Whether a held owner-signed Epoch entry names `epoch`.
    fn names_epoch(&self, epoch: &EpochId) -> bool;
    /// Whether the audience of `epoch` contains `person`.
    fn in_audience(&self, epoch: &EpochId, person: &Name) -> bool;
    /// Whether `person` is a reader of the space now.
    fn reads_now(&self, person: &Name) -> bool;
    /// Whether this device holds the key of `epoch`.
    fn holds_key(&self, epoch: &EpochId) -> bool;
}

/// Whether the key of `epoch` may be granted to a device of `asker`'s
/// person: **all four** of (1) a held owner-signed Epoch entry names the
/// epoch, (2) its audience contains the person, (3) the person reads the
/// space now, (4) this device holds the key. Forward only: a removed reader
/// fails (3) for every later ask. Pure; first failure named.
pub(crate) fn may_grant<V: GrantView + ?Sized>(
    view: &V,
    epoch: &EpochId,
    asker: &Name,
) -> Result<(), GrantRefusal> {
    if !view.names_epoch(epoch) {
        return Err(GrantRefusal::EpochNotNamed);
    }
    if !view.in_audience(epoch, asker) {
        return Err(GrantRefusal::NotInAudience);
    }
    if !view.reads_now(asker) {
        return Err(GrantRefusal::NotReaderNow);
    }
    if !view.holds_key(epoch) {
        return Err(GrantRefusal::KeyNotHeld);
    }
    Ok(())
}

/// The [`GrantView`] a granter has: the membership fold of the space (whose
/// Epoch entries it holds, owner-signed: the log applies no other) and the
/// keys of this device.
pub(crate) struct Granter<'a> {
    /// The space's membership fold.
    pub fold: &'a Fold,
    /// This device's keys.
    pub keys: &'a Keys,
    /// The space.
    pub space: &'a Name,
}

impl GrantView for Granter<'_> {
    fn names_epoch(&self, epoch: &EpochId) -> bool {
        self.fold.epoch_body(epoch).is_some()
    }

    fn in_audience(&self, epoch: &EpochId, person: &Name) -> bool {
        self.fold.audience(epoch).contains(person)
    }

    fn reads_now(&self, person: &Name) -> bool {
        self.fold.is_reader(person)
    }

    fn holds_key(&self, epoch: &EpochId) -> bool {
        self.keys.key(self.space, epoch).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    use ndn_packet::Data;
    use ndn_packet::encode::DataBuilder;
    use ndn_security::verifier::{Ed25519Verifier, VerifyOutcome};
    use ndn_security::{Ed25519Signer, Signer};

    use crate::wire::{self, EntryRef, EpochBody, Grant, MembersBody, Op, Role};

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn epoch(creator: &str, seq: u64) -> EpochId {
        EpochId {
            creator: n(creator),
            seq,
        }
    }

    fn keys() -> Keys {
        Keys::new(RecipientKey::generate())
    }

    #[test]
    fn a_key_that_fails_the_key_check_is_dropped() {
        let (space, e) = (n("/alice/32=data/notes"), epoch("/alice/laptop", 4));
        let key = ContentKey::generate();
        let named = key_check(&key, &space, &e);
        assert!(accept_key(&named, &space, &e, &key));
        assert!(
            !accept_key(&named, &space, &e, &ContentKey::generate()),
            "another key"
        );
        assert!(
            !accept_key(&named, &n("/alice/32=data/other"), &e, &key),
            "another space"
        );
        assert!(
            !accept_key(&named, &space, &epoch("/alice/laptop", 9), &key),
            "another epoch"
        );
        assert!(
            !accept_key(&named, &space, &epoch("/alice/phone", 4), &key),
            "another creator"
        );

        let mut held = keys();
        assert!(!held.take(&space, &e, &named, ContentKey::generate()));
        assert!(held.key(&space, &e).is_none(), "a failing key is not held");
        assert!(held.take(&space, &e, &named, key.clone()));
        assert_eq!(held.key(&space, &e).unwrap().expose(), key.expose());
        assert!(
            held.key(&n("/alice/32=data/other"), &e).is_none(),
            "a key is held for one space"
        );
        assert!(
            held.key(&space, &epoch("/alice/laptop", 9)).is_none(),
            "a key is held for one epoch"
        );
    }

    #[test]
    fn seal_then_open_round_trips_and_the_aad_binds_the_entry_name() {
        let key = ContentKey::generate();
        let name = n("/alice/laptop/32=log/alice/32=data/notes/seq=5");
        let plain = b"the path and the payload, as TLV".as_slice();
        let stored = seal_payload(&key, &name, plain);
        assert_eq!(
            stored.len(),
            12 + 16 + plain.len(),
            "nonce ‖ tag ‖ ciphertext"
        );
        assert_ne!(&stored[28..], plain, "the payload is not in the clear");
        assert_eq!(open_payload(&key, &name, &stored).as_deref(), Some(plain));
        assert_ne!(
            stored,
            seal_payload(&key, &name, plain),
            "a fresh random nonce each time"
        );

        let other = n("/alice/laptop/32=log/alice/32=data/notes/seq=6");
        assert_eq!(
            open_payload(&key, &other, &stored),
            None,
            "bound to its name"
        );

        let mut flipped = stored.to_vec();
        *flipped.last_mut().unwrap() ^= 1;
        assert_eq!(open_payload(&key, &name, &flipped), None, "tampered");
        assert_eq!(open_payload(&key, &name, &stored[..20]), None, "truncated");
    }

    #[test]
    fn a_wrong_epoch_key_does_not_open() {
        let name = n("/alice/laptop/32=log/alice/32=data/notes/seq=5");
        let stored = seal_payload(&ContentKey::generate(), &name, b"secret");
        assert_eq!(open_payload(&ContentKey::generate(), &name, &stored), None);
    }

    /// A view with each of the four facts a grant needs switchable.
    struct View {
        names: bool,
        audience: bool,
        reads: bool,
        holds: bool,
    }

    impl GrantView for View {
        fn names_epoch(&self, _: &EpochId) -> bool {
            self.names
        }
        fn in_audience(&self, _: &EpochId, _: &Name) -> bool {
            self.audience
        }
        fn reads_now(&self, _: &Name) -> bool {
            self.reads
        }
        fn holds_key(&self, _: &EpochId) -> bool {
            self.holds
        }
    }

    #[test]
    fn may_grant_refuses_each_of_the_four_conditions_and_names_which() {
        let e = epoch("/alice/laptop", 1);
        let asker = n("/bob");
        let all = View {
            names: true,
            audience: true,
            reads: true,
            holds: true,
        };
        assert_eq!(may_grant(&all, &e, &asker), Ok(()));
        let refusals = [
            (
                View {
                    names: false,
                    ..all
                },
                GrantRefusal::EpochNotNamed,
            ),
            (
                View {
                    audience: false,
                    ..all
                },
                GrantRefusal::NotInAudience,
            ),
            (
                View {
                    reads: false,
                    ..all
                },
                GrantRefusal::NotReaderNow,
            ),
            (
                View {
                    holds: false,
                    ..all
                },
                GrantRefusal::KeyNotHeld,
            ),
        ];
        let mut said = BTreeSet::new();
        for (view, refusal) in refusals {
            assert_eq!(may_grant(&view, &e, &asker), Err(refusal));
            assert!(
                said.insert(refusal.to_string()),
                "each says which: {refusal}"
            );
        }
        // Every condition is checked in the plan's order.
        let none = View {
            names: false,
            audience: false,
            reads: false,
            holds: false,
        };
        assert_eq!(
            may_grant(&none, &e, &asker),
            Err(GrantRefusal::EpochNotNamed)
        );
    }

    #[test]
    fn the_epoch_key_round_trips_through_the_wrap_and_the_grant_aad_binds_the_grant_name() {
        let me = RecipientKey::generate();
        let key = ContentKey::generate();
        let grant = n("/alice/laptop/32=grant/abc");
        let content = wrap_key(&me.public(), &key, &grant).unwrap();
        let opened = unwrap_key(&me, &grant, content.clone()).unwrap();
        assert_eq!(opened.expose(), key.expose());
        assert!(
            unwrap_key(&me, &n("/alice/laptop/32=grant/abd"), content.clone()).is_none(),
            "another grant name"
        );
        assert!(
            unwrap_key(&RecipientKey::generate(), &grant, content.clone()).is_none(),
            "another recipient"
        );
        let mut torn = Grant::decode(content.clone()).unwrap();
        let mut flipped = torn.ciphertext.to_vec();
        *flipped.last_mut().unwrap() ^= 1;
        torn.ciphertext = Bytes::from(flipped);
        assert!(unwrap_key(&me, &grant, torn.encode()).is_none(), "tampered");
        assert!(
            unwrap_key(&me, &grant, content.slice(..content.len() - 3)).is_none(),
            "truncated"
        );
        let again = wrap_key(&me.public(), &key, &grant).unwrap();
        assert_ne!(
            Grant::decode(again).unwrap().ephemeral,
            Grant::decode(content).unwrap().ephemeral,
            "a fresh ephemeral key per wrap"
        );
    }

    #[test]
    fn a_made_key_is_kept_wrapped_to_the_device_and_restored_only_under_its_name_and_check() {
        let (space, e) = (n("/alice/32=data/notes"), epoch("/alice/laptop", 2));
        let key = ContentKey::generate();
        let named = key_check(&key, &space, &e);
        let mut first = keys();
        assert!(
            first.record(&space, &e).is_none(),
            "nothing held, nothing kept"
        );
        first.hold(&space, e.clone(), key.clone());
        let (at, stored) = first.record(&space, &e).unwrap().unwrap();
        assert_eq!(at, store::epoch_key(&space, &e.creator, e.seq));
        assert_ne!(
            stored.as_ref(),
            key.expose().as_slice(),
            "the key is not stored in the clear"
        );

        // A restart: the same recipient key, no epoch key held.
        let mut second = Keys::new(first.recipient().clone());
        assert!(
            !second.restore(&space, &e, &[0; 32], stored.clone()),
            "a stored key that fails the check is dropped"
        );
        // The check would match (it is of the same key); only the store name,
        // the AAD, differs.
        let (later, other) = (epoch("/alice/laptop", 3), n("/alice/32=data/other"));
        assert!(
            !second.restore(
                &space,
                &later,
                &key_check(&key, &space, &later),
                stored.clone()
            ),
            "a stored key is bound to the store name of its epoch"
        );
        assert!(
            !second.restore(&other, &e, &key_check(&key, &other, &e), stored.clone()),
            "and of its space"
        );
        assert!(
            !second.restore(&space, &e, &named, stored.slice(..9)),
            "malformed"
        );
        assert!(
            !keys().restore(&space, &e, &named, stored.clone()),
            "another device's recipient key does not open it"
        );
        assert!(second.key(&space, &e).is_none());
        assert!(second.restore(&space, &e, &named, stored));
        assert_eq!(second.key(&space, &e).unwrap().expose(), key.expose());
    }

    #[test]
    fn a_grant_packet_carries_the_key_for_its_name_only() {
        let (asker, granter_signer) = (keys(), signer("/alice/laptop/KEY/k1", 5));
        let key = ContentKey::generate();
        let name = n("/alice/laptop/32=grant/x");
        let wire = grant_packet(&asker.public(), &key, &name, &granter_signer).unwrap();
        let data = Data::decode(wire).unwrap();
        assert_eq!(*data.name, name);
        let opened = unwrap_key(asker.recipient(), &name, data.content().unwrap().clone());
        assert_eq!(opened.unwrap().expose(), key.expose());
        let other = n("/alice/laptop/32=grant/y");
        assert!(unwrap_key(asker.recipient(), &other, data.content().unwrap().clone()).is_none());
    }

    fn signer(key: &str, seed: u8) -> Ed25519Signer {
        Ed25519Signer::from_seed(&[seed; 32], n(key))
    }

    #[test]
    fn the_seal_key_packet_is_the_devices_own_and_names_its_key() {
        let device = n("/alice/laptop");
        let signer = signer("/alice/laptop/KEY/k1", 5);
        let public = RecipientKey::generate().public();
        let wire = seal_key_packet(&device, &public, &signer).unwrap();
        let data = Data::decode(wire).unwrap();
        assert_eq!(*data.name, wire::seal_key_name(&device, &public));
        let locator = data.sig_info().unwrap().key_locator_name().unwrap();
        assert_eq!(*locator, n("/alice/laptop/KEY/k1"));
        assert_eq!(
            Ed25519Verifier.verify_sync(
                data.signed_region(),
                data.sig_value(),
                &signer.public_key().unwrap()
            ),
            VerifyOutcome::Valid
        );
        assert!(seal_key_matches(&data, &device, &public));
        assert!(
            !seal_key_matches(&data, &device, &RecipientKey::generate().public()),
            "another key"
        );
        assert!(
            !seal_key_matches(&data, &n("/alice/phone"), &public),
            "another device"
        );
        // The same packet under a name that claims another key does not pass.
        let lying = DataBuilder::new(
            wire::seal_key_name(&device, &RecipientKey::generate().public()),
            &wire::encode_seal_key(&public),
        )
        .sign_sync(signer.sig_type(), Some(signer.key_name()), |r| {
            signer.sign_sync(r).unwrap()
        });
        let lying = Data::decode(lying).unwrap();
        assert!(!seal_key_matches(&lying, &device, &public));
    }

    #[test]
    fn a_signer_that_cannot_sign_synchronously_is_refused_with_its_key_named() {
        struct Async(Name);
        impl Signer for Async {
            fn sig_type(&self) -> ndn_packet::SignatureType {
                ndn_packet::SignatureType::SignatureEd25519
            }
            fn key_name(&self) -> &Name {
                &self.0
            }
            fn sign<'a>(
                &'a self,
                _: &'a [u8],
            ) -> futures::future::BoxFuture<'a, Result<Bytes, ndn_security::TrustError>>
            {
                Box::pin(async { Ok(Bytes::new()) })
            }
        }
        let device = n("/alice/laptop");
        let public = RecipientKey::generate().public();
        let Err(err) = seal_key_packet(&device, &public, &Async(n("/alice/laptop/KEY/k1"))) else {
            panic!("an async-only signer cannot sign a seal key packet");
        };
        assert!(err.to_string().contains("/alice/laptop/KEY/k1"), "{err}");
    }

    /// The owner `/o` lists readers `/p/1` and `/p/2` and signs epoch 1 for
    /// the owner and both; a granter holds the key.
    fn sealed_space() -> (Fold, Keys, Name, EpochId, ContentKey) {
        let (space, e) = (n("/o/32=data/s"), epoch("/o/d0", 1));
        let key = ContentKey::generate();
        let mut fold = Fold::new(n("/o"));
        let carrier = |seq: u64| EntryRef {
            device: n("/o/d0"),
            seq,
            digest: [seq as u8; 32],
        };
        let add = |i: u8, who: &str| Op::Add {
            id: [i; 16],
            who: n(who),
            role: Role::Reader,
            epoch: None,
        };
        fold.apply_members(
            &carrier(2),
            &MembersBody {
                create: None,
                ops: vec![add(1, "/p/1"), add(2, "/p/2")],
            },
        );
        fold.apply_epoch(
            e.clone(),
            &EpochBody {
                key_check: key_check(&key, &space, &e),
                audience: vec![n("/o"), n("/p/1"), n("/p/2")],
            },
        );
        let mut granter = keys();
        granter.hold(&space, e.clone(), key.clone());
        (fold, granter, space, e, key)
    }

    #[test]
    fn a_removed_reader_is_refused_every_later_grant() {
        let (mut fold, granter, space, e, key) = sealed_space();
        let (kept, removed) = (n("/p/1"), n("/p/2"));
        fn view<'a>(fold: &'a Fold, keys: &'a Keys, space: &'a Name) -> Granter<'a> {
            Granter { fold, keys, space }
        }
        assert_eq!(may_grant(&view(&fold, &granter, &space), &e, &kept), Ok(()));
        assert_eq!(
            may_grant(&view(&fold, &granter, &space), &e, &removed),
            Ok(())
        );
        assert_eq!(
            granter.key(&space, &e).unwrap().expose(),
            key.expose(),
            "the key the grant would wrap"
        );

        fold.apply_members(
            &EntryRef {
                device: n("/o/d0"),
                seq: 3,
                digest: [3; 32],
            },
            &MembersBody {
                create: None,
                ops: vec![Op::Remove {
                    id: [2; 16],
                    tips: vec![],
                }],
            },
        );
        assert_eq!(
            may_grant(&view(&fold, &granter, &space), &e, &removed),
            Err(GrantRefusal::NotReaderNow),
            "still in the old epoch's audience, but no longer a reader"
        );
        assert_eq!(
            may_grant(&view(&fold, &granter, &space), &e, &kept),
            Ok(()),
            "others are served"
        );

        // The owner repairs: a new epoch, for the readers that remain. The
        // removed reader is in neither condition for it.
        let next = epoch("/o/d0", 4);
        fold.apply_epoch(
            next.clone(),
            &EpochBody {
                key_check: [0; 32],
                audience: vec![n("/o"), n("/p/1")],
            },
        );
        let mut holding = keys();
        holding.hold(&space, next.clone(), ContentKey::generate());
        let later = Granter {
            fold: &fold,
            keys: &holding,
            space: &space,
        };
        assert_eq!(
            may_grant(&later, &next, &removed),
            Err(GrantRefusal::NotInAudience),
            "the new epoch is not for the removed reader"
        );
        assert_eq!(may_grant(&later, &next, &kept), Ok(()));
        assert_eq!(
            may_grant(&later, &e, &kept),
            Err(GrantRefusal::KeyNotHeld),
            "the condition that fails is named"
        );
        assert_eq!(
            may_grant(&later, &epoch("/o/d0", 9), &kept),
            Err(GrantRefusal::EpochNotNamed)
        );
    }

    #[test]
    fn a_key_is_taken_only_for_an_epoch_a_held_entry_names() {
        let (fold, _, space, e, key) = sealed_space();
        let mut reader = keys();
        assert!(
            !reader.take_named(&fold, &space, &epoch("/o/d0", 9), key.clone()),
            "no held entry names the epoch"
        );
        assert!(
            !reader.take_named(&fold, &space, &e, ContentKey::generate()),
            "the key does not match the named check"
        );
        assert!(reader.key(&space, &e).is_none());
        assert!(reader.take_named(&fold, &space, &e, key.clone()));
        assert_eq!(reader.key(&space, &e).unwrap().expose(), key.expose());
    }

    #[test]
    fn the_recipient_key_is_made_once_and_stable_across_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let identity = n("/alice");
        let device = n("/alice/laptop");
        let (first, public) = {
            let (sm, _) = SecurityManager::auto_init(&identity, dir.path()).unwrap();
            let key = recipient_key(&sm, &device).unwrap();
            let again = recipient_key(&sm, &device).unwrap();
            assert_eq!(key.public(), again.public(), "made once in a run");
            (key.expose().to_vec(), key.public())
        };
        let (sm, _) = SecurityManager::auto_init(&identity, dir.path()).unwrap();
        let back = recipient_key(&sm, &device).unwrap();
        assert_eq!(back.expose().to_vec(), first, "kept across a restart");
        assert_eq!(back.public(), public);
        let other = recipient_key(&sm, &n("/alice/phone")).unwrap();
        assert_ne!(other.public(), public, "one per device");
    }

    #[test]
    fn a_recipient_secret_of_the_wrong_length_is_refused_not_replaced() {
        let sm = SecurityManager::new();
        let device = n("/alice/laptop");
        sm.put_secret(recipient_secret_name(&device), &[1u8; 31])
            .unwrap();
        let Err(err) = recipient_key(&sm, &device) else {
            panic!("a secret of 31 octets is not a recipient key");
        };
        assert!(matches!(err, SealError::BadSecret { len: 31, .. }), "{err}");
        assert_eq!(
            sm.secret(&recipient_secret_name(&device)).unwrap().len(),
            31,
            "the stored bytes are left alone"
        );
    }

    #[test]
    fn the_recipient_secret_lives_under_the_local_prefix() {
        assert_eq!(
            recipient_secret_name(&n("/alice/laptop")),
            n("/localhost/ndn-heap/seal/alice/laptop")
        );
    }

    #[test]
    fn keys_are_zeroized_on_drop() {
        fn zeroizes<T: ZeroizeOnDrop>() {}
        zeroizes::<ContentKey>();
        zeroizes::<RecipientKey>();
        zeroizes::<Keys>();
    }
}
