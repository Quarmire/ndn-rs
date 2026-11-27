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
//!   answered. The first decision is made from the ask as parsed and nothing more: the
//!   parse is bounded (a seal key packet of at most 2,048 octets and at most 4 certificates
//!   of 6,144 octets in all, [`parse_grant_name`] stops at the first over the limit), and
//!   no signature is checked, no certificate judged and nothing fetched until the node
//!   has said yes by the names. The ask carries the
//!   asker's seal key packet and the certificates of its signer chain, so this is one
//!   exchange and the granter fetches nothing: the packet is judged as the asker device's
//!   at every ask, from the certificates held and carried (the carried ones only as
//!   unverified copies, dropped again if no walk vouches for them; a lapse of the
//!   asker's certificate moves no counter, so nothing about its key is kept), the node
//!   decides again with the key that signed it (a revoked key is granted nothing), and the
//!   answer is signed by this device with the key wrapped to that seal key.
//! * `<D>/32=<keyword>/…` for a keyword a host registered
//!   ([`Node::extend`](crate::Node::extend)): the extension answers, `None` is Nacked.
//!   Core keywords are never given to an extension.
//!
//! Names under `/localhost` are never served, and neither is a name another
//! device owns. Every ask that is not answered is Nacked, never left to time
//! out.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Weak};

use bytes::Bytes;
use ndn_app::Responder;
use ndn_foundation_types::Name;
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Interest, NackReason};
use ndn_security::cert_name::{is_cert_name, is_key_name, key_name_of};
use parking_lot::Mutex;

use crate::chan::answer::ChanAnswer;
use crate::chan::hub::ChanPort;
use crate::chan::route::setup_headers;
use crate::limit::Counts;
use crate::query::QueryOutcome;
use crate::seal::seal_key_matches;
use crate::sync::{HostRef, Net, Shared};
use crate::trust::Judged;
use crate::wire::{
    ASKER_CHAIN_MAX, GrantAsk, Served, parse_grant_name, parse_held_name, parse_log_name,
    parse_piece_name, parse_seal_key_name, served_kind,
};

/// How many grants a granter keeps to answer an ask it answered before without
/// signing again.
const GRANTS_KEPT: usize = 4096;

/// The most grant asks of one asker device worked on at once: an admitted
/// reader can name any number of seal keys of its own device, and none of them
/// is to take the judge's time from the node's own entries.
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

/// What a granter keeps: the grants it answered and how many asks of each asker it is working
/// on.
#[derive(Default)]
pub(crate) struct Granting {
    grants: Mutex<Kept<Bytes>>,
    asks: Counts,
}

/// Answer one Interest for this device. Spawn it per Interest: a grant judges the seal key
/// packet it carries (which may need a certificate fetched) before it answers, so it runs as
/// its own task.
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
                shared.tasks.clone().spawn(async move {
                    let wire = grant(&shared, &name, ask).await;
                    reply(&name, responder, wire).await;
                });
                return;
            }
            None
        }
        // `<D>/32=chan/<digest>`: a channel ask, judged and answered by the node (channel.md).
        Some(Served::Chan) => {
            if let Some(port) = shared.chan.get().and_then(Weak::upgrade) {
                shared.tasks.clone().spawn(chan(port, interest, responder));
                return;
            }
            None
        }
        // `<D>/32=query/<digest>`: a query, judged and answered by the node (query.md): a signed
        // answer, a Nack, or nothing at all for `Reply::Pass`.
        Some(Served::Query) => {
            if let Some(port) = shared.chan.get().and_then(Weak::upgrade) {
                shared.tasks.clone().spawn(query(port, interest, responder));
                return;
            }
            None
        }
        // `<D>/KEY/<id>` (or a certificate of that key): the certificate a validator asks for
        // by the KeyLocator of this device's entries. The device answers for its own chain
        // and for nothing else of the kind ([`own_key_name`]).
        None if own_key_name(&me, &name) && !is_local(&name) => host.held_certificate(&name),
        // A keyword no core kind owns: the extension that registered it, if one did, answers
        // (its own task, as a grant's: it may sign and wait); anything else is Nacked.
        None => match shared.extensions.answering(&me, &name) {
            Some(extension) if !is_local(&name) => {
                shared.tasks.spawn(async move {
                    let answer = extension.answer(&interest).await;
                    let Some(answer) = answer else {
                        reply(&name, responder, None).await;
                        return;
                    };
                    // A label rides on an LpPacket; an answer without one goes out bare.
                    let sent = match answer.headers() {
                        Some(headers) => responder.respond_bytes_with(answer.wire, headers).await,
                        None => responder.respond_bytes(answer.wire).await,
                    };
                    if let Err(e) = sent {
                        tracing::debug!(%name, "reply not sent: {e}");
                    }
                });
                return;
            }
            _ => None,
        },
    };
    reply(&name, responder, packet).await;
}

/// Answer a channel ask (channel.md): the node judges it in the order the spec gives and answers
/// a signed session, a signed refusal or a Nack, so no ask is left to time out. Whatever it
/// answers is never cached (`CachePolicy = NoCache`).
async fn chan(port: Arc<dyn ChanPort>, interest: Interest, responder: Responder) {
    let name = (*interest.name).clone();
    let sent = match port.answer(interest, responder.incoming_face()).await {
        ChanAnswer::Data(wire) => {
            responder
                .respond_bytes_with(wire, setup_headers(None))
                .await
        }
        ChanAnswer::Session { wire, id } => {
            responder
                .respond_bytes_with(wire, setup_headers(Some(id)))
                .await
        }
        ChanAnswer::Nack(reason) => responder.nack(reason).await,
    };
    if let Err(e) = sent {
        tracing::debug!(%name, "channel answer not sent: {e}");
    }
}

/// Answer a query (query.md). The answer is signed by this device, `FreshnessPeriod` 0 and never
/// cached (`CachePolicy = NoCache`: it is for this asker alone). A query the handler passed on is
/// left unanswered: dropping the [`Responder`] sends nothing, so the asker counts the server
/// silent at its own deadline.
async fn query(port: Arc<dyn ChanPort>, interest: Interest, responder: Responder) {
    let name = (*interest.name).clone();
    let sent = match port.query(interest, responder.incoming_face()).await {
        QueryOutcome::Data(wire) => {
            responder
                .respond_bytes_with(wire, setup_headers(None))
                .await
        }
        QueryOutcome::Nack(reason) => responder.nack(reason).await,
        QueryOutcome::Silent => Ok(()),
    };
    if let Err(e) = sent {
        tracing::debug!(%name, "query answer not sent: {e}");
    }
}

/// Whether `name` is under `/localhost`: never served.
fn is_local(name: &Name) -> bool {
    name.components()
        .first()
        .is_some_and(|c| c.value.as_ref() == b"localhost")
}

/// Whether `name` is a key name `<device>/KEY/<id>`, or a certificate name of that key, of
/// `device` itself: the one place a node answers by name for a certificate, and it only
/// answers with its own chain ([`crate::trust::Judge::own_certificate`]).
fn own_key_name(device: &Name, name: &Name) -> bool {
    (is_key_name(name) || is_cert_name(name))
        && name.has_prefix(device)
        && key_name_of(name).len() == device.len() + 2
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
/// `original` of any device: only what the node serves, or a certificate its validator
/// vouches for ([`crate::trust::Judge::held_certificate`]), in a DigestSha256 wrapper.
fn held_packet(host: &HostRef, me: &Name, name: &Name) -> Option<Bytes> {
    let (holder, original) = parse_held_name(name)?;
    if holder != *me {
        return None;
    }
    let wire = packet(host, &original, None).or_else(|| host.held_certificate(&original))?;
    Some(DataBuilder::new(name.clone(), &wire).sign_digest_sha256())
}

/// Answer a grant ask (spec §6.5) in the one exchange: the node decides first, from the ask as
/// parsed (its names and nothing judged: the parse is bounded, no signature is checked, no
/// certificate vouched for, nothing fetched); then the seal key packet the ask carries is
/// judged as the asker's device's, **at every ask** (nothing about the asker's key is kept: a
/// lapse of its certificate moves no counter, only the clock refuses it), the node decides
/// again with the key that signed it, and the key is wrapped to the seal key. One name, one
/// packet while it is kept, and only after both decisions: kept only for the judge's
/// generation it was made in (a revocation ends what was kept before it).
async fn grant(shared: &Arc<Shared>, name: &Name, ask: GrantAsk) -> Option<Bytes> {
    let host = &shared.host;
    let (asker, public) = parse_seal_key_name(&ask.seal_key)?;
    if let Err(why) = host.may_grant(&ask.space, &ask.epoch, &asker, None) {
        tracing::debug!(%asker, epoch = ?ask.epoch, "grant refused: {why}");
        return None;
    }
    let generation = host.generation();
    let Some(_slot) = shared.grants.asks.take(&asker, GRANTS_PER_ASKER) else {
        tracing::debug!(%asker, "grant not answered: the asker has as many grant asks in progress here as it may ({GRANTS_PER_ASKER}); its next round asks again once they end");
        return None;
    };
    let key = match seal_key_verified(shared, &ask, &asker, &public).await {
        Ok(key) => key,
        Err(why) => {
            tracing::debug!(%asker, "grant not answered: {why}");
            return None;
        }
    };
    if let Err(why) = host.may_grant(&ask.space, &ask.epoch, &asker, Some(&key)) {
        tracing::debug!(%asker, %key, epoch = ?ask.epoch, "grant refused: {why}");
        return None;
    }
    // Recorded before the key is given, so that a lapse of this key owes the space an epoch.
    if let Err(why) = host.note_grantee(&ask.space, &key, &ask) {
        tracing::debug!(%asker, %key, "grant not answered: {why}");
        return None;
    }
    if let Some(kept) = shared.grants.grants.lock().get(generation, name) {
        return Some(kept);
    }
    let wire = host.grant_packet(&ask.space, &ask.epoch, &asker, &key, &public, name)?;
    shared
        .grants
        .grants
        .lock()
        .insert(generation, name.clone(), wire.clone());
    Some(wire)
}

/// The key that signed the seal key packet the ask carries, if it is `asker`'s seal key packet
/// for `public`, judged as signed by the asker's device; else why not, and what to do.
async fn seal_key_verified(
    shared: &Shared,
    ask: &GrantAsk,
    asker: &Name,
    public: &[u8; 32],
) -> Result<Name, String> {
    let not_the_askers = "the seal key packet in the ask is not the asker's own (it does not carry the key it is named for, or its device's key does not verify); the asker's next round asks again";
    let data = Data::decode(ask.seal_packet.clone()).map_err(|_| not_the_askers.to_string())?;
    if !seal_key_matches(&data, asker, public) {
        return Err(not_the_askers.to_string());
    }
    match shared
        .host
        .validate_asker_packet(&ask.space, &data, asker, &ask.chain)
        .await
    {
        Judged::Valid(v) => Ok(v.key),
        Judged::Refused(why) => Err(format!(
            "the asker's seal key packet is refused ({why}); a key is granted only to a device the trust context vouches for now: the asker's next round asks again"
        )),
        Judged::Pending(waiting) => Err(format!(
            "the asker's seal key packet cannot be judged from the certificates this node holds and the {} certificate(s) the ask carries ({waiting}); a grant ask makes this node fetch nothing (spec 6.5), so the asker's device must carry the certificates of its signing key and of its issuers in the ask (at most {ASKER_CHAIN_MAX}): it holds none of its own when it carries none, so enrol it or load its certificate; a chain that does not reach this node's trust anchors is refused; the asker's next round asks again",
            ask.chain.len()
        )),
    }
}

#[cfg(test)]
#[path = "serve_tests.rs"]
mod tests;
