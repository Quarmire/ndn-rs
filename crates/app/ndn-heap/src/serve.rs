//! Serving entries, held copies, pieces, seal keys and grants (spec §7).
//!
//! What a device answers, by the keyword right after its own name
//! ([`served_kind`]):
//!
//! * `<D>/32=log/<S>/seq=<n>` and the pieces under it: the entry, as far as
//!   the node lets it be served ([`Host::served`]): its own entry at or below
//!   its head and not held back (a structural entry waits for its flush).
//! * `<H>/32=held/<Name>`: a packet this device keeps of another device,
//!   only if the node holds and admitted it (a follower serves what it
//!   verified), wrapped in a DigestSha256 packet so it carries no claim to
//!   have been signed by this device.
//! * `<D>/32=seal/<key>`: this device's seal key packet.
//! * `<G>/32=grant/<ask>`: the key of an epoch, **only** when the node says
//!   the asker may have it ([`Host::may_grant`]); anything else is not
//!   answered and this device fetches nothing for it. Then the asker's seal key
//!   packet is fetched and judged (once per key: kept while verified), and the
//!   answer is signed by this device with the key wrapped to that seal key.
//!
//! Names under `/localhost` are never served, and neither is a name another
//! device owns. Every ask that is not answered is Nacked, never left to time
//! out.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::Arc;

use bytes::Bytes;
use ndn_app::Responder;
use ndn_foundation_types::Name;
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Interest, NackReason};
use parking_lot::Mutex;

use crate::rt;
use crate::seal::seal_key_matches;
use crate::sync::{Host, Net, Shared};
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

/// The most seal keys learned in the background at once, and the most of one
/// asker's.
const SEAL_LEARNING_MAX: usize = 64;
const SEAL_LEARNING_PER_ASKER: usize = 2;

/// A map that keeps the last `cap` entries put in it.
struct Kept<V> {
    cap: usize,
    order: VecDeque<Name>,
    map: HashMap<Name, V>,
}

impl<V: Clone> Kept<V> {
    fn new(cap: usize) -> Self {
        Kept {
            cap,
            order: VecDeque::new(),
            map: HashMap::new(),
        }
    }

    fn get(&self, key: &Name) -> Option<V> {
        self.map.get(key).cloned()
    }

    fn insert(&mut self, key: Name, value: V) {
        if self.map.insert(key.clone(), value).is_none() {
            self.order.push_back(key);
            while self.order.len() > self.cap {
                if let Some(old) = self.order.pop_front() {
                    self.map.remove(&old);
                }
            }
        }
    }
}

/// What a granter keeps: the grants it answered, the seal keys it verified,
/// the ones it is still learning and how many asks of each asker it is
/// working on.
pub(crate) struct Granting {
    grants: Mutex<Kept<Bytes>>,
    seal_keys: Mutex<Kept<()>>,
    learning: Mutex<BTreeSet<Name>>,
    asks: Mutex<BTreeMap<Name, usize>>,
}

impl Default for Granting {
    fn default() -> Self {
        Granting {
            grants: Mutex::new(Kept::new(GRANTS_KEPT)),
            seal_keys: Mutex::new(Kept::new(GRANTS_KEPT)),
            learning: Mutex::new(BTreeSet::new()),
            asks: Mutex::new(BTreeMap::new()),
        }
    }
}

/// One grant ask of an asker being worked on; given back when dropped.
struct Slot<'a> {
    asks: &'a Mutex<BTreeMap<Name, usize>>,
    asker: Name,
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        let mut asks = self.asks.lock();
        if let Some(n) = asks.get_mut(&self.asker) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                asks.remove(&self.asker);
            }
        }
    }
}

impl Granting {
    fn slot(&self, asker: &Name) -> Option<Slot<'_>> {
        let mut asks = self.asks.lock();
        let n = asks.entry(asker.clone()).or_default();
        if *n >= GRANTS_PER_ASKER {
            return None;
        }
        *n += 1;
        Some(Slot {
            asks: &self.asks,
            asker: asker.clone(),
        })
    }
}

/// Answer one Interest for this device. Spawn it per Interest: a grant fetches
/// before it answers, so it runs as its own task.
pub(crate) async fn answer(net: Arc<Net>, interest: Interest, responder: Responder) {
    let shared = Arc::clone(&net.shared);
    let name = (*interest.name).clone();
    let host = Arc::clone(&shared.host);
    let me = host.device().clone();
    if is_local(&name) {
        return reply(&name, responder, None).await;
    }
    let packet = match served_kind(&name) {
        Some(Served::Log) => log_packet(&*host, &me, &name),
        Some(Served::Held) => held_packet(&*host, &me, &name),
        Some(Served::Seal) => parse_seal_key_name(&name)
            .filter(|(device, _)| *device == me)
            .and_then(|_| host.seal_key_packet(&name)),
        Some(Served::Grant) => {
            let Some((granter, ask)) = parse_grant_name(&name).filter(|(g, _)| *g == me) else {
                return reply(&name, responder, None).await;
            };
            let _ = granter;
            rt::spawn(async move {
                let wire = grant(&shared, &name, ask).await;
                reply(&name, responder, wire).await;
            });
            return;
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

/// An entry of this device, or a piece under one, as the node serves it.
fn log_packet(host: &dyn Host, me: &Name, name: &Name) -> Option<Bytes> {
    if let Some(log) = parse_log_name(name) {
        return if log.device == *me {
            host.served(&log.space, &log.device, log.seq)
        } else {
            None
        };
    }
    let piece = parse_piece_name(name)?;
    let log = parse_log_name(&piece.entry)?;
    if log.device == *me {
        host.served_piece(&log.space, &log.device, log.seq, name)
    } else {
        None
    }
}

/// What this device answers under its own name (`32=held`) for the packet
/// `original` of any device: only what the node serves, in a DigestSha256
/// wrapper.
fn held_packet(host: &dyn Host, me: &Name, name: &Name) -> Option<Bytes> {
    let (holder, original) = parse_held_name(name)?;
    if holder != *me {
        return None;
    }
    let wire = match parse_log_name(&original) {
        Some(log) => host.served(&log.space, &log.device, log.seq)?,
        None => {
            let piece = parse_piece_name(&original)?;
            let log = parse_log_name(&piece.entry)?;
            host.served_piece(&log.space, &log.device, log.seq, &original)?
        }
    };
    Some(DataBuilder::new(name.clone(), &wire).sign_digest_sha256())
}

/// Answer a grant ask (spec §6.5): the node decides first, before anything is
/// fetched; then the asker's seal key is fetched and judged, and the key
/// wrapped to it. One name, one packet while it is kept.
async fn grant(shared: &Arc<Shared>, name: &Name, ask: GrantAsk) -> Option<Bytes> {
    let host = &shared.host;
    let (asker, public) = parse_seal_key_name(&ask.seal_key)?;
    if let Err(why) = host.may_grant(&ask.space, &ask.epoch, &asker) {
        tracing::debug!(%asker, epoch = ?ask.epoch, "grant refused: {why}");
        return None;
    }
    if let Some(kept) = shared.grants.grants.lock().get(name) {
        return Some(kept);
    }
    let Some(_slot) = shared.grants.slot(&asker) else {
        tracing::debug!(%asker, "grant not answered: the asker has as many grant asks in progress here as it may ({GRANTS_PER_ASKER}); its next round asks again once they end");
        return None;
    };
    if shared.grants.seal_keys.lock().get(&ask.seal_key).is_none() {
        let verified = match shared.fetcher.once(ask.seal_key.clone()).await {
            Ok(data) => seal_key_verified(shared, &data, &ask, &asker, &public).await,
            Err(_) => false,
        };
        if !verified {
            tracing::debug!(%asker, "grant not answered: its seal key did not come, or did not verify as its own; asked again in the background");
            learn_seal_key(shared, ask, asker, public);
            return None;
        }
        shared
            .grants
            .seal_keys
            .lock()
            .insert(ask.seal_key.clone(), ());
    }
    let wire = host.grant_packet(&ask.space, &ask.epoch, &asker, &public, name)?;
    shared
        .grants
        .grants
        .lock()
        .insert(name.clone(), wire.clone());
    Some(wire)
}

/// Whether `data` is `asker`'s seal key packet for `public`, judged as signed
/// by the asker's device.
async fn seal_key_verified(
    shared: &Shared,
    data: &Data,
    ask: &GrantAsk,
    asker: &Name,
    public: &[u8; 32],
) -> bool {
    seal_key_matches(data, asker, public)
        && matches!(
            shared
                .host
                .validate_device_packet(&ask.space, data, asker)
                .await,
            Judged::Valid(_)
        )
}

/// Ask again, in the background, for the seal key a grant's ask in place did
/// not get: up to the fetch tries, one run per key, and, verified, it is kept,
/// so the asker's next round of grant asks is answered at once. Only an asker
/// the node admits gets here: a stranger costs no asks. A run beyond the caps
/// is not started; the asker's next ask starts it once one ends.
fn learn_seal_key(shared: &Arc<Shared>, ask: GrantAsk, asker: Name, public: [u8; 32]) {
    {
        let mut learning = shared.grants.learning.lock();
        if learning.contains(&ask.seal_key) {
            return;
        }
        let of_asker = learning.iter().filter(|k| k.has_prefix(&asker)).count();
        if learning.len() >= SEAL_LEARNING_MAX || of_asker >= SEAL_LEARNING_PER_ASKER {
            tracing::debug!(%asker, "seal key not asked again in the background: as many runs are under way as this device allows; the asker's next grant ask starts it once one ends");
            return;
        }
        learning.insert(ask.seal_key.clone());
    }
    let shared = Arc::clone(shared);
    rt::spawn(async move {
        let got = match shared.fetcher.owed(ask.seal_key.clone()).await {
            Some(data) => seal_key_verified(&shared, &data, &ask, &asker, &public).await,
            None => false,
        };
        if got {
            shared
                .grants
                .seal_keys
                .lock()
                .insert(ask.seal_key.clone(), ());
        }
        shared.grants.learning.lock().remove(&ask.seal_key);
    });
}

#[cfg(test)]
#[path = "serve_tests.rs"]
mod tests;
