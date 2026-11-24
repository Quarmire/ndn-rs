//! The introductions of one device: the [`Invites`] handle, the state its offers, asks
//! and hint records share, and the [`Extension`] that serves them under
//! `<D>/32=intro`, `<D>/32=hint` and `<D>/32=ask` (spec §19).
//!
//! The offer (`offer.rs`), the join (`join.rs`), the hint records (`hint.rs`) and the
//! grants (`grants.rs`) are `impl`s on the types here. What an offer needs to be
//! judged lives in the node's store under `/localhost/ndn-invite/` (`store.rs`), each
//! note durable before the reply it backs; what this module keeps in memory is only
//! what is made again from those notes at a start.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Weak};
use std::time::Duration;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_heap::host::{AnswerFuture, Extension, NodeHandle};
use ndn_heap::{Node, Timestamp};
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Data, Interest};
use ndn_security::verifier::verify_public_key_signature;
use ndn_security::{VerifyOutcome, public_key_digest};
use ndn_sync::DataStore;
use parking_lot::Mutex;

use crate::error::InviteError;
use crate::grants::Grants;
use crate::hint::HintServed;
use crate::host::Host;
use crate::policy::IntroPolicy;
use crate::sealed::open_note;
use crate::store;
use crate::wire::{
    self, HINT_TOKEN_LEN, IntroRecord, NONCE_LEN, OfferBody, OfferId, offer_name, parse_hint_name,
    parse_intro_name, parse_offer_name,
};

/// The keywords this crate's [`Extension`] claims: the asks and offers
/// (`<D>/32=intro`), the short codes' hint records (`<D>/32=hint`), and the proof
/// packets an ask and an answer carry (`<X>/32=ask/<binding>`, which the node signs
/// only under a keyword an extension registered).
const KEYWORDS: &[&str] = &["intro", "hint", "ask"];

/// Answers an ask keeps, signed, so that asking again gets the same packet.
const ANSWERS_KEPT: usize = 1024;

/// Fills a buffer with random octets.
pub type Entropy = Arc<dyn Fn(&mut [u8]) + Send + Sync>;

/// What tunes a device's introductions beyond its [`IntroPolicy`].
#[derive(Clone)]
pub struct InviteConfig {
    /// How many asks are opened and verified at once (at least 1; default 8): the
    /// asks held in all are bounded by [`IntroPolicy::asks_queued`].
    pub asks_verifying: usize,
    /// Where the offer's id and secret and an ask's nonce come from (default: the
    /// operating system's randomness).
    pub entropy: Entropy,
}

impl InviteConfig {
    /// Defaults: 8 asks verified at once, the operating system's randomness.
    pub fn new() -> InviteConfig {
        InviteConfig {
            asks_verifying: 8,
            entropy: Arc::new(|buf| {
                getrandom::getrandom(buf).expect("the operating system provides randomness");
            }),
        }
    }
}

impl Default for InviteConfig {
    fn default() -> InviteConfig {
        InviteConfig::new()
    }
}

impl std::fmt::Debug for InviteConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InviteConfig")
            .field("asks_verifying", &self.asks_verifying)
            .finish_non_exhaustive()
    }
}

/// A bounded map of what was answered, by name, oldest dropped first.
pub(crate) struct Kept<V> {
    map: BTreeMap<Name, V>,
    order: VecDeque<Name>,
    cap: usize,
}

impl<V> Kept<V> {
    fn new(cap: usize) -> Self {
        Self {
            map: BTreeMap::new(),
            order: VecDeque::new(),
            cap,
        }
    }

    pub(crate) fn get(&self, k: &Name) -> Option<&V> {
        self.map.get(k)
    }

    pub(crate) fn insert(&mut self, k: Name, v: V) {
        if self.map.insert(k.clone(), v).is_none() {
            self.order.push_back(k);
            if self.order.len() > self.cap
                && let Some(old) = self.order.pop_front()
            {
                self.map.remove(&old);
            }
        }
    }
}

/// An own offer held: what it says, and the signed Data that is served.
#[derive(Clone)]
pub(crate) struct Held {
    pub(crate) body: OfferBody,
    pub(crate) wire: Bytes,
}

/// What a device keeps in memory of its introductions.
pub(crate) struct State {
    /// The own offers, by id.
    pub(crate) offers: BTreeMap<OfferId, Held>,
    /// The own offers that publish a hint record, by their hint token: an Interest
    /// for `<D>/32=hint/<token>` is answered only for a token held here.
    pub(crate) hints: BTreeMap<[u8; HINT_TOKEN_LEN], OfferId>,
    /// The hint record last signed for each token, for a few seconds.
    pub(crate) hint_served: BTreeMap<[u8; HINT_TOKEN_LEN], HintServed>,
    /// Asks held now, verifying or waiting for their turn.
    pub(crate) queued: usize,
    /// The answers given, by ask name.
    pub(crate) answers: Kept<Bytes>,
}

/// What the offers, asks, joins and grants of one device share.
pub(crate) struct Inner {
    pub(crate) node: NodeHandle,
    pub(crate) host: Arc<dyn Host>,
    pub(crate) policy: IntroPolicy,
    pub(crate) config: InviteConfig,
    /// The node's store; every note lives under `/localhost/ndn-invite/`.
    pub(crate) store: Arc<dyn DataStore>,
    /// SHA-256 of this device's public key as its certificate carries it.
    own_key: [u8; 32],
    /// This device's public key: what its offers' signatures are verified under.
    own_public: Bytes,
    pub(crate) state: Mutex<State>,
    /// Opening and verifying asks: at most [`InviteConfig::asks_verifying`] at once.
    pub(crate) verifying: tokio::sync::Semaphore,
    /// Asks are judged one at a time: a use, a wrong try counted, a closing mark each
    /// see what the one before wrote.
    pub(crate) serial: tokio::sync::Mutex<()>,
    /// The grants and mirror notes.
    pub(crate) grants: Arc<Grants>,
}

/// One ask held ([`State::queued`]), let go as it is dropped.
pub(crate) struct Queued<'a>(pub(crate) &'a Inner);

impl Drop for Queued<'_> {
    fn drop(&mut self) {
        let mut st = self.0.state.lock();
        st.queued = st.queued.saturating_sub(1);
    }
}

/// A device's introductions: offer a space (`offer`), join one by a code (`join`),
/// end what a join granted (`end_grant`, …). A cheap handle: clones share one device's
/// state; the node serves them for as long as one lives.
#[derive(Clone)]
pub struct Invites {
    pub(crate) inner: Arc<Inner>,
}

impl std::fmt::Debug for Invites {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Invites")
            .field("device", self.inner.node.name())
            .finish()
    }
}

impl Invites {
    /// Start the introductions of `node`'s device: register the extension that serves
    /// offers, hint records and ask proofs, read back what an earlier run kept under
    /// `/localhost/ndn-invite/` (offers, hint tokens, grants, mirror notes) and begin
    /// to follow the spaces those grants are about. `host` is what the introductions
    /// need of the device's host: its anchor, adopting another person's, dialling.
    ///
    /// # Errors
    ///
    /// [`InviteError::Heap`] when the node refuses the extension's keywords or has
    /// stopped; [`InviteError::Local`] when the device's key is not one that gives its
    /// public key.
    pub fn start(
        node: &Node,
        host: Arc<dyn Host>,
        policy: IntroPolicy,
        config: InviteConfig,
    ) -> Result<Invites, InviteError> {
        let node = node.handle();
        let public = node
            .keys()
            .signing_identity_for(node.name())
            .ok()
            .and_then(|identity| identity.signer.public_key())
            .ok_or_else(|| {
                InviteError::local(format_args!(
                    "no public key of {} is available to the introductions: give the device a \
                     key that exposes its public key",
                    node.name()
                ))
            })?;
        let own_key = public_key_digest(&public);
        let own_public = public;
        let grants = Grants::new(node.clone(), Arc::clone(&host), policy.clone());
        let inner = Arc::new(Inner {
            store: Arc::clone(node.store()),
            node,
            host,
            verifying: tokio::sync::Semaphore::new(config.asks_verifying.max(1)),
            policy,
            config,
            own_key,
            own_public,
            state: Mutex::new(State {
                offers: BTreeMap::new(),
                hints: BTreeMap::new(),
                hint_served: BTreeMap::new(),
                queued: 0,
                answers: Kept::new(ANSWERS_KEPT),
            }),
            serial: tokio::sync::Mutex::new(()),
            grants,
        });
        inner.restore();
        inner
            .node
            .extend(Arc::new(Served(Arc::downgrade(&inner))))?;
        inner.grants.start();
        Ok(Invites { inner })
    }

    /// The state this handle shares.
    pub(crate) fn inner(&self) -> &Arc<Inner> {
        &self.inner
    }
}

/// The extension the node serves: it holds the device's introductions weakly, so a
/// node does not keep a dropped [`Invites`] alive, and answers nothing once it is gone.
struct Served(Weak<Inner>);

impl Extension for Served {
    fn keywords(&self) -> &'static [&'static str] {
        KEYWORDS
    }

    fn answer<'a>(&'a self, interest: &'a Interest) -> AnswerFuture<'a> {
        Box::pin(async move { self.0.upgrade()?.serve(interest).await })
    }
}

impl Inner {
    /// What this device answers for `interest`, under one of its keywords: its own
    /// offer at `<D>/32=intro/offer/<id>`, an ask at `<D>/32=intro/<digest>`, the hint
    /// record at `<D>/32=hint/<token>`. Anything else — an offer id nobody made, a
    /// proof's name (`32=ask`, which is signed, never asked for) — is `None`: refusal
    /// is silence, so a prober learns nothing.
    async fn serve(&self, interest: &Interest) -> Option<Bytes> {
        let name = &*interest.name;
        let device = self.node.name();
        if let Some((from, id)) = parse_offer_name(name) {
            if from != *device {
                return None;
            }
            return self
                .state
                .lock()
                .offers
                .get(&id)
                .map(|held| held.wire.clone());
        }
        if parse_intro_name(name).is_some_and(|d| d == *device) {
            return self
                .answer_intro(name, interest.app_parameters().cloned())
                .await;
        }
        if parse_hint_name(name).is_some_and(|(d, _)| d == *device) {
            return self.hint_packet(name);
        }
        None
    }

    /// This device's clock, as the node reads it.
    pub(crate) fn now(&self) -> Timestamp {
        self.node.now()
    }

    /// SHA-256 of this device's public key.
    pub(crate) fn own_key_digest(&self) -> [u8; 32] {
        self.own_key
    }

    /// Fill `buf` from the configured entropy.
    pub(crate) fn entropy(&self, buf: &mut [u8]) {
        (self.config.entropy)(buf);
    }

    /// A fresh nonce.
    pub(crate) fn nonce(&self) -> [u8; NONCE_LEN] {
        let mut nonce = [0u8; NONCE_LEN];
        self.entropy(&mut nonce);
        nonce
    }

    /// A fresh offer id.
    pub(crate) fn fresh_id(&self) -> OfferId {
        let mut id = [0u8; wire::OFFER_ID_LEN];
        self.entropy(&mut id);
        id
    }

    /// A proof of who asks, for this device's own asks and answers: `<me>/32=ask/
    /// <binding>`, signed by the device key through the node (which signs it because
    /// `ask` is a keyword this crate registered).
    pub(crate) fn ask_proof(&self, binding: &[u8; 32]) -> Option<Bytes> {
        let name = wire::ask_name(self.node.name(), binding);
        self.node
            .sign_packet(DataBuilder::new(name, &[]).freshness(Duration::ZERO))
            .ok()
    }

    /// Fetch `name` with the forwarding hint `hints` (none: by name), and `params` as
    /// its ApplicationParameters (`name` then gains their digest). `None` when nothing
    /// answered within the node's Interest lifetime.
    pub(crate) async fn fetch(
        &self,
        name: Name,
        hints: &[Name],
        params: Option<&Bytes>,
    ) -> Option<Data> {
        let lifetime = self.node.config().lifetime;
        let mut b = InterestBuilder::new(name).lifetime(lifetime);
        if !hints.is_empty() {
            b = b.forwarding_hint(hints.to_vec());
        }
        if let Some(p) = params {
            b = b.app_parameters(p.to_vec());
        }
        match self.node.consumer().fetch_with(b).await {
            Ok(d) => Some(d),
            Err(e) => {
                tracing::trace!(me = %self.node.name(), "introduction fetch missed: {e}");
                None
            }
        }
    }

    /// Whether some own offer has not expired by this device's clock: a stranger's
    /// introduction link is worth taking. A closed offer counts, since it still
    /// answers the writer it admitted until it expires (spec §19.2).
    pub(crate) fn intro_open(&self) -> bool {
        let now = self.now();
        self.state
            .lock()
            .offers
            .values()
            .any(|h| h.body.until > now)
    }

    /// Whether an Interest for `name` may cross an introduction link a stranger dialled
    /// (spec §19.2): an ask (`<D>/32=intro/<digest>`) while an offer is open; an own
    /// offer's packet (`<D>/32=intro/offer/<id>`) that has not expired; the hint
    /// record of a short code (`<D>/32=hint/<token>`, a token of one of this device's
    /// own offers: open, or closed or expired, when its gone mark is the answer). A
    /// hint token this device does not hold, another offer's id, or any other packet
    /// this device holds by name is not carried.
    pub(crate) fn intro_carries(&self, name: &Name) -> bool {
        let device = self.node.name();
        let now = self.now();
        let st = self.state.lock();
        if let Some((from, id)) = parse_offer_name(name) {
            return from == *device && st.offers.get(&id).is_some_and(|h| h.body.until > now);
        }
        if let Some(from) = parse_intro_name(name) {
            return from == *device && st.offers.values().any(|h| h.body.until > now);
        }
        if let Some((from, token)) = parse_hint_name(name) {
            return from == *device && st.hints.contains_key(&token);
        }
        false
    }

    /// Read back what an earlier run kept: the own offers (the signed packets that are
    /// served) and each one's hint token.
    fn restore(&self) {
        let device = self.node.name();
        let mut st = self.state.lock();
        for (key, wire) in store::list(self.store.as_ref(), &store::offer_listing()) {
            let Some(id) = store::parse_offer_key(&key) else {
                continue;
            };
            let name = offer_name(device, &id);
            let Ok(data) = Data::decode(wire.clone()) else {
                tracing::warn!(%name, "an offer note that does not decode; ignored");
                continue;
            };
            let record = data
                .content()
                .and_then(|c| IntroRecord::decode(c.clone()).ok());
            let Some(IntroRecord::Offer(body)) = record else {
                tracing::warn!(%name, "an offer note that holds no offer; ignored");
                continue;
            };
            if *data.name != name {
                tracing::warn!(%name, "an offer note named otherwise than its key; ignored");
                continue;
            }
            // The device's own key signed every offer it made: a note that anyone else
            // wrote into the store, or changed, is not an offer of this device's (spec §18).
            let signed = data.sig_info().is_some_and(|info| {
                matches!(
                    verify_public_key_signature(
                        info.sig_type,
                        data.signed_region(),
                        data.sig_value(),
                        &self.own_public,
                    ),
                    Ok(VerifyOutcome::Valid)
                )
            });
            if !signed {
                tracing::warn!(%name, "an offer note the device's key did not sign; ignored");
                continue;
            }
            let hint = store::hint_key(&id);
            if let Some(token) = self
                .store
                .get(&hint)
                .and_then(|note| open_note(self.node.recipient(), &hint, &note))
            {
                let mut t = [0u8; HINT_TOKEN_LEN];
                t.copy_from_slice(&token[..HINT_TOKEN_LEN]);
                st.hints.insert(t, id);
            }
            st.offers.insert(id, Held { body, wire });
        }
    }
}
