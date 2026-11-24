//! Serving entries, held copies, pieces, seal keys and grants (spec §7).
//!
//! What a device answers, by the keyword right after its own name
//! ([`served_kind`]):
//!
//! * `<D>/32=log/<S>/seq=<n>` and the pieces under it: the entry, as far as
//!   the node lets it be served (`NodeInner::served`): its own entry at or below
//!   its head and not held back (a structural entry waits for its flush).
//! * `<H>/32=held/<Name>`: a packet this device keeps of another device,
//!   only if the node holds and admitted it (a follower serves what it
//!   verified), wrapped in a DigestSha256 packet so it carries no claim to
//!   have been signed by this device.
//! * `<D>/32=seal/<key>`: this device's seal key packet.
//! * `<G>/32=grant/<ask>`: the key of an epoch, **only** when the node says
//!   the asker may have it (`NodeInner::may_grant`); anything else is not
//!   answered and this device fetches nothing for it. Then the asker's seal key
//!   packet is fetched and judged (once per key: kept while verified and while
//!   the judge's generation is the one it was verified in), the node decides
//!   again with the key that signed it (a revoked key is granted nothing), and
//!   the answer is signed by this device with the key wrapped to that seal key.
//!
//! Names under `/localhost` are never served, and neither is a name another
//! device owns. Every ask that is not answered is Nacked, never left to time
//! out.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use bytes::Bytes;
use ndn_app::Responder;
use ndn_foundation_types::Name;
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Interest, NackReason};
use parking_lot::Mutex;

use crate::fetch::Kind;
use crate::limit::Counts;
use crate::rt;
use crate::seal::seal_key_matches;
use crate::sync::{HostRef, Net, Shared};
use crate::trust::Judged;
use crate::wire::{
    GrantAsk, Served, parse_grant_name, parse_held_name, parse_log_name, parse_piece_name,
    parse_seal_key_name, served_kind,
};

/// How many grants a granter keeps to answer an ask it answered before without
/// signing again.
const GRANTS_KEPT: usize = 4096;

/// The most grant asks of one asker device worked on at once: an admitted
/// reader can name any number of seal keys of its own device, and none of them
/// is to take the node's fetch slots from its own fetches.
const GRANTS_PER_ASKER: usize = 32;

/// A map that keeps the last [`GRANTS_KEPT`] entries put in it, for one
/// generation of the judge (`NodeInner::generation`): an entry put or asked
/// for under another generation is not there, and putting under a new one
/// drops the rest. What a revocation may have changed is judged again, not
/// served from here.
struct Kept<V> {
    generation: u64,
    order: VecDeque<Name>,
    map: HashMap<Name, V>,
}

impl<V> Default for Kept<V> {
    fn default() -> Self {
        Kept {
            generation: 0,
            order: VecDeque::new(),
            map: HashMap::new(),
        }
    }
}

impl<V: Clone> Kept<V> {
    fn get(&self, generation: u64, key: &Name) -> Option<V> {
        if self.generation != generation {
            return None;
        }
        self.map.get(key).cloned()
    }

    fn insert(&mut self, generation: u64, key: Name, value: V) {
        if self.generation != generation {
            self.generation = generation;
            self.order.clear();
            self.map.clear();
        }
        if self.map.insert(key.clone(), value).is_none() {
            self.order.push_back(key);
            if self.order.len() > GRANTS_KEPT
                && let Some(old) = self.order.pop_front()
            {
                self.map.remove(&old);
            }
        }
    }
}

/// What a granter keeps: the grants it answered, the seal keys it verified
/// and how many asks of each asker it is working on.
#[derive(Default)]
pub(crate) struct Granting {
    grants: Mutex<Kept<Bytes>>,
    seal_keys: Mutex<Kept<Name>>,
    asks: Counts,
}

/// Answer one Interest for this device. Spawn it per Interest: a grant fetches
/// before it answers, so it runs as its own task.
pub(crate) async fn answer(net: Arc<Net>, interest: Interest, responder: Responder) {
    let shared = Arc::clone(&net.shared);
    let name = (*interest.name).clone();
    let host = &shared.host;
    let me = host.device().clone();
    let packet = match served_kind(&name).filter(|_| !is_local(&name)) {
        Some(Served::Log) => {
            let wire = packet(host, &name, Some(&me));
            // A peer asking for an entry of this device took the notice that
            // named it (or a later one): nothing is announced again for it.
            if wire.is_some()
                && let Some(log) = parse_log_name(&name)
                && let Some(group) = net.group(&log.space)
            {
                group.herald.taken(log.seq);
            }
            wire
        }
        Some(Served::Held) => held_packet(host, &me, &name),
        Some(Served::Seal) => host.seal_key_packet(&name),
        Some(Served::Grant) => {
            if let Some((_, ask)) = parse_grant_name(&name).filter(|(g, _)| *g == me) {
                rt::spawn(async move {
                    let wire = grant(&shared, &name, ask).await;
                    reply(&name, responder, wire).await;
                });
                return;
            }
            None
        }
        None => None,
    };
    reply(&name, responder, packet).await;
}

/// Whether `name` is under `/localhost`: never served.
fn is_local(name: &Name) -> bool {
    name.components()
        .first()
        .is_some_and(|c| c.value.as_ref() == b"localhost")
}

async fn reply(name: &Name, responder: Responder, packet: Option<Bytes>) {
    tracing::trace!(%name, answered = packet.is_some(), "interest");
    let sent = match packet {
        Some(wire) => responder.respond_bytes(wire).await,
        None => responder.nack(NackReason::NoRoute).await,
    };
    if let Err(e) = sent {
        tracing::debug!(%name, "reply not sent: {e}");
    }
}

/// The entry `name` names, or a piece under one, as the node serves it; with
/// `only`, an entry of that device alone.
fn packet(host: &HostRef, name: &Name, only: Option<&Name>) -> Option<Bytes> {
    let (log, piece) = match parse_log_name(name) {
        Some(log) => (log, None),
        None => (parse_log_name(&parse_piece_name(name)?.entry)?, Some(name)),
    };
    if only.is_some_and(|device| log.device != *device) {
        return None;
    }
    match piece {
        None => host.served(&log.space, &log.device, log.seq),
        Some(piece) => host.served_piece(&log.space, &log.device, log.seq, piece),
    }
}

/// What this device answers under its own name (`32=held`) for the packet
/// `original` of any device: only what the node serves, in a DigestSha256
/// wrapper.
fn held_packet(host: &HostRef, me: &Name, name: &Name) -> Option<Bytes> {
    let (holder, original) = parse_held_name(name)?;
    if holder != *me {
        return None;
    }
    let wire = packet(host, &original, None)?;
    Some(DataBuilder::new(name.clone(), &wire).sign_digest_sha256())
}

/// Answer a grant ask (spec §6.5): the node decides first, before anything is
/// fetched; then the asker's seal key is fetched and judged, the node decides
/// again with the key that signed it, and the key is wrapped to the seal key.
/// One name, one packet while it is kept: kept only for the judge's
/// generation it was made in (a revocation ends what was kept before it).
async fn grant(shared: &Arc<Shared>, name: &Name, ask: GrantAsk) -> Option<Bytes> {
    let host = &shared.host;
    let (asker, public) = parse_seal_key_name(&ask.seal_key)?;
    if let Err(why) = host.may_grant(&ask.space, &ask.epoch, &asker, None) {
        tracing::debug!(%asker, epoch = ?ask.epoch, "grant refused: {why}");
        return None;
    }
    let generation = host.generation();
    if let Some(kept) = shared.grants.grants.lock().get(generation, name) {
        return Some(kept);
    }
    let Some(_slot) = shared.grants.asks.take(&asker, GRANTS_PER_ASKER) else {
        tracing::debug!(%asker, "grant not answered: the asker has as many grant asks in progress here as it may ({GRANTS_PER_ASKER}); its next round asks again once they end");
        return None;
    };
    let kept = shared
        .grants
        .seal_keys
        .lock()
        .get(generation, &ask.seal_key);
    let key = match kept {
        Some(key) => key,
        None => {
            let verified = match shared.fetcher.once(ask.seal_key.clone(), &Kind::Pull).await {
                Ok(data) => seal_key_verified(shared, &data, &ask, &asker, &public).await,
                Err(_) => None,
            };
            let Some(key) = verified else {
                tracing::debug!(%asker, "grant not answered: its seal key did not come, or did not verify as its own; the asker's next round asks again");
                return None;
            };
            shared
                .grants
                .seal_keys
                .lock()
                .insert(generation, ask.seal_key.clone(), key.clone());
            key
        }
    };
    if let Err(why) = host.may_grant(&ask.space, &ask.epoch, &asker, Some(&key)) {
        tracing::debug!(%asker, %key, epoch = ?ask.epoch, "grant refused: {why}");
        return None;
    }
    let wire = host.grant_packet(&ask.space, &ask.epoch, &asker, &key, &public, name)?;
    shared
        .grants
        .grants
        .lock()
        .insert(generation, name.clone(), wire.clone());
    Some(wire)
}

/// The key that signed `data` if it is `asker`'s seal key packet for `public`,
/// judged as signed by the asker's device.
async fn seal_key_verified(
    shared: &Shared,
    data: &Data,
    ask: &GrantAsk,
    asker: &Name,
    public: &[u8; 32],
) -> Option<Name> {
    if !seal_key_matches(data, asker, public) {
        return None;
    }
    match shared
        .host
        .validate_device_packet(&ask.space, data, asker)
        .await
    {
        Judged::Valid(v) => Some(v.key),
        _ => None,
    }
}

#[cfg(test)]
#[path = "serve_tests.rs"]
mod tests;
