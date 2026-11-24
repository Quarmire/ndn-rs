//! The state an introduction keeps, in the node's store (`Node::store()`), under
//! `/localhost/ndn-invite/`, a prefix no device serves: the key of each kind of
//! note, built and read back here, and the writes that are durable before a reply.
//!
//! | key | what it holds |
//! |---|---|
//! | `offer/<id>` | the offer: the Data the device signed, served as it is |
//! | `key/<id>` | the offer's proof key, wrapped to the recipient key, with a MAC |
//! | `tries/<id>` | the wrong tries of all askers of the offer and the time of the last counted, with a MAC |
//! | `tries/<id>/<digest>` | the wrong tries of one asker (the digest of its key), with a MAC |
//! | `using/<id>` | the asker key being admitted: the one that holds the offer until it is used, with a MAC |
//! | `accepted/<id>` | the acceptance made for that key (a retry of it is answered alike) |
//! | `closed/<id>` | that the offer was closed, by its maker or by wrong tries (any value closes) |
//! | `used/<id>` | the use mark: the key the offer was used by, with a MAC |
//! | `hint/<id>` | the offer's hint token (short code), wrapped like the proof key, with a MAC |
//! | `grant/<id>` | a grant of an offer: the key, the namespaces, the space, the role |
//! | `mirror/<S>/<key>` | the joiner's grant for its inviter's link (`<key>`: the inviter's digest) |
//!
//! `<id>` is the offer's id, one generic component of 16 octets; `<digest>` and
//! `<key>` one generic component of 32. A space is a prefix of the names of spaces
//! that extend it, so spelled as components a scan of one space's keys would list
//! another's: where a space is followed by more components in a key (`mirror`), it is one
//! component holding its `Name` TLV.
//!
//! A write is in the store when [`put_durable`] returns, and a flush of the store
//! ([`DataStore::sync`]) that began after it has returned: a restart finds it. The
//! flush runs on a thread of its own, as the data layer's own flusher does, so a
//! paused or virtual clock is not held up by a blocking pool.

use std::sync::{Arc, LazyLock};

use bytes::Bytes;
use ndn_foundation_types::{Name, NameComponent};
use ndn_sync::{DataStore, StoreOp};

use crate::error::InviteError;
use crate::wire::OfferId;

/// `/localhost/ndn-invite`: the prefix of every key.
pub fn root() -> Name {
    static ROOT: LazyLock<Name> =
        LazyLock::new(|| "/localhost/ndn-invite".parse().expect("a valid name"));
    ROOT.clone()
}

/// `/localhost/ndn-invite/<kind>`: the prefix of every key of a kind.
fn kind(kind: &'static str) -> Name {
    root().append(kind)
}

fn id_component(id: &OfferId) -> NameComponent {
    NameComponent::generic(Bytes::copy_from_slice(id))
}

/// `<kind>/<id>`.
fn of_id(kind_name: &'static str, id: &OfferId) -> Name {
    kind(kind_name).append_component(id_component(id))
}

/// `name` as one component: its `Name` TLV.
fn tlv_component(name: &Name) -> NameComponent {
    NameComponent::generic(name.encode_to_tlv())
}

/// The offer id a `<kind>/<id>` key names, `None` for any other key.
fn parse_id(kind_name: &'static str, key: &Name) -> Option<OfferId> {
    let prefix = kind(kind_name);
    if !key.has_prefix(&prefix) {
        return None;
    }
    let [id] = &key.components()[prefix.len()..] else {
        return None;
    };
    <OfferId>::try_from(&id.value[..]).ok()
}

/// `offer/<id>`: the offer.
pub fn offer_key(id: &OfferId) -> Name {
    of_id("offer", id)
}

/// `key/<id>`: the offer's proof key.
pub fn key_key(id: &OfferId) -> Name {
    of_id("key", id)
}

/// `tries/<id>`: the wrong tries of all the offer's askers together. Every
/// asker's counter, [`tries_asker_key`], lies under it.
pub fn tries_key(id: &OfferId) -> Name {
    of_id("tries", id)
}

/// `tries/<id>/<digest>`: the wrong tries of one asker, `digest` being the digest
/// of its key.
pub fn tries_asker_key(id: &OfferId, digest: &[u8; 32]) -> Name {
    tries_key(id).append_component(NameComponent::generic(Bytes::copy_from_slice(digest)))
}

/// `using/<id>`: the asker key being admitted under the offer.
pub fn using_key(id: &OfferId) -> Name {
    of_id("using", id)
}

/// `accepted/<id>`: the acceptance made for the asker key.
pub fn accepted_key(id: &OfferId) -> Name {
    of_id("accepted", id)
}

/// `closed/<id>`: that the offer was closed.
pub fn closed_key(id: &OfferId) -> Name {
    of_id("closed", id)
}

/// `used/<id>`: the use mark.
pub fn used_key(id: &OfferId) -> Name {
    of_id("used", id)
}

/// `hint/<id>`: the offer's hint record.
pub fn hint_key(id: &OfferId) -> Name {
    of_id("hint", id)
}

/// `grant/<id>`: the grant the offer made.
pub fn grant_key(id: &OfferId) -> Name {
    of_id("grant", id)
}

/// `mirror/<S>/<key>`: the joiner's grant for the inviter's link in `space`,
/// `key` being the inviter's key digest.
pub fn mirror_key(space: &Name, key: &[u8; 32]) -> Name {
    mirror_listing(space).append_component(NameComponent::generic(Bytes::copy_from_slice(key)))
}

/// `offer/`: every offer.
pub fn offer_listing() -> Name {
    kind("offer")
}

/// `grant/`: every grant.
pub fn grant_listing() -> Name {
    kind("grant")
}

/// `mirror/<S>`: every mirror note of `space`, and of no space that extends it.
pub fn mirror_listing(space: &Name) -> Name {
    kind("mirror").append_component(tlv_component(space))
}

/// The id an `offer/<id>` key names.
pub fn parse_offer_key(key: &Name) -> Option<OfferId> {
    parse_id("offer", key)
}

/// The id a `grant/<id>` key names.
pub fn parse_grant_key(key: &Name) -> Option<OfferId> {
    parse_id("grant", key)
}

/// The inviter's key digest a `mirror/<S>/<key>` key of `space` names.
pub fn parse_mirror_key(space: &Name, key: &Name) -> Option<[u8; 32]> {
    let prefix = mirror_listing(space);
    if !key.has_prefix(&prefix) {
        return None;
    }
    let [digest] = &key.components()[prefix.len()..] else {
        return None;
    };
    <[u8; 32]>::try_from(&digest.value[..]).ok()
}

/// Every note under `listing`, with its key and value, in name order.
pub fn list(store: &dyn DataStore, listing: &Name) -> Vec<(Name, Bytes)> {
    store.scan_under(listing, 0)
}

/// Return once a flush of `store` that began now has returned: everything the store
/// accepted before the call is durable, or the error says it may not be.
pub async fn flush(store: &Arc<dyn DataStore>) -> Result<(), InviteError> {
    let flushed = sync(store).await;
    flushed.map_err(|why| {
        InviteError::local(format_args!(
            "the store could not make the introduction's notes durable: {why}; nothing was \
             reported as done that is not, so free space or fix the disk, then try again"
        ))
    })
}

/// [`DataStore::sync`], on a thread of its own when it touches a disk (the data
/// layer's own flusher does the same: a paused tokio clock, a simulation, advances
/// only while no pool task runs, so a flush held on the pool would stop every timer
/// around it); inline when the store has nothing to flush, and on wasm32.
async fn sync(store: &Arc<dyn DataStore>) -> std::io::Result<()> {
    #[cfg(not(target_arch = "wasm32"))]
    if !store.sync_is_immediate() {
        let store = Arc::clone(store);
        let (done, flushed) = tokio::sync::oneshot::channel();
        std::thread::Builder::new()
            .name("ndn-invite-flush".into())
            .spawn(move || {
                let _ = done.send(store.sync());
            })?;
        return flushed.await.unwrap_or_else(|e| {
            Err(std::io::Error::other(format!(
                "the flush did not finish ({e})"
            )))
        });
    }
    store.sync()
}

/// Write the note `key` and return once it is durable.
pub async fn put_durable(
    store: &Arc<dyn DataStore>,
    key: Name,
    value: Bytes,
) -> Result<(), InviteError> {
    store.insert(key, value);
    flush(store).await
}

/// Delete the note `key` and return once the deletion is durable.
pub async fn remove_durable(store: &Arc<dyn DataStore>, key: &Name) -> Result<(), InviteError> {
    store.remove(key);
    flush(store).await
}

/// Apply `ops` as one batch (all of it or, after a kill, none of it, on a store
/// whose engine batches) and return once it is durable.
pub async fn apply_durable(
    store: &Arc<dyn DataStore>,
    ops: Vec<StoreOp>,
) -> Result<(), InviteError> {
    store.apply(ops);
    flush(store).await
}
