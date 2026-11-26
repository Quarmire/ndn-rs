//! The sibling surface of the node: the interface for `ndn-invite` only
//! (spec §10.9). A program that only reads and writes spaces never needs it.
//!
//! A sibling crate adds a protocol of its own to a device (introductions, a
//! link layer's questions) that rides the node's key, its trust, its store and
//! its serving, without the layer growing a case for it:
//!
//! * [`Extension`] answers the Interests under `<D>/32=<keyword>` for the
//!   keywords it registered with [`NodeHandle::extend`]; the core router gives
//!   it nothing else, and a keyword the layer's own names carry (`log`, `seal`,
//!   `grant`, …) or another extension holds is refused at registration. An
//!   Interest it does not answer is Nacked like any other.
//! * [`NodeHandle::sign_packet`] signs a Data with the device's key, but only
//!   one named `<D>/32=<keyword>/…` for a registered keyword: the node is no
//!   oracle that signs a name of the caller's choosing (an entry at a chosen
//!   name would make the device equivocate, a certificate name would speak
//!   for the namespace).
//! * the node's own parts, lent: [`consumer`](NodeHandle::consumer) (its face),
//!   [`validator`](NodeHandle::validator) (with its keyring and certificate
//!   cache), [`keys`](NodeHandle::keys), [`store`](NodeHandle::store) (under
//!   a prefix of the sibling's own, `/localhost/ndn-<crate>/`),
//!   [`recipient`](NodeHandle::recipient) (the secret a sibling derives its
//!   own keys from), [`now`](NodeHandle::now), [`config`](NodeHandle::config)
//!   (the lifetimes its waits are bounded by), [`person_of`](NodeHandle::person_of)
//!   and [`adopted_persons`](NodeHandle::adopted_persons).
//! * [`note_joined`](NodeHandle::note_joined) and
//!   [`fetch_entry`](NodeHandle::fetch_entry): what a join and a departure need
//!   of the space that the space's own surface does not give.
//! * [`Heap::removed_by`]: the Members entry that removed a person.
//!
//! [`Node`](crate::Node) dereferences to a [`NodeHandle`], so every method here
//! is the node's own; the handle is what an [`Extension`] keeps, since a node
//! stops when it is dropped and a handle does not.

use std::collections::BTreeMap;
use std::sync::Arc;

use bytes::Bytes;
use ndn_app::Consumer;
use ndn_foundation_types::{Name, tlv_type};
use ndn_packet::Interest;
use ndn_packet::encode::DataBuilder;
use ndn_security::confidentiality::RecipientKey;
use ndn_security::{SecurityManager, Validator};
use ndn_sync::DataStore;
use parking_lot::RwLock;

use crate::error::{HeapError, Timestamp};
use crate::log::Log;
use crate::node::{Config, NodeInner};
use crate::register::EntryId;
use crate::space::Heap;
use crate::store::Kind;
use crate::wire::{CORE_KEYWORDS, parse_log_name};

/// What an [`Extension`] answers an Interest with: the Data wire, and, if the answer sets up a
/// route in the forwarders on its reverse path, the label that does it.
///
/// The label is an NDNLPv2 `SideRoute { id, ttl }` on the Data (channel.md, The forwarder's side
/// table): each forwarder that matched the Interest installs a route for the 64-bit `id` and
/// sends the Data on with the label, so frames of that id that the extension then sends over its
/// connection (`ndn_app::Connection::send_side`) reach whoever asked. The heap's own channel
/// setup uses it; an extension carrying frames of its own may.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    /// The signed Data.
    pub wire: Bytes,
    /// The route label `(id, ttl in seconds)`, if the answer carries one.
    pub side: Option<(u64, u16)>,
}

impl Answer {
    /// A Data that sets up no route.
    pub fn plain(wire: Bytes) -> Answer {
        Answer { wire, side: None }
    }

    /// A Data that carries the route label `(id, ttl_secs)`.
    pub fn routed(wire: Bytes, id: u64, ttl_secs: u16) -> Answer {
        Answer {
            wire,
            side: Some((id, ttl_secs)),
        }
    }

    /// The LP headers the answer goes out with, `None` for a plain one (it goes out bare).
    pub(crate) fn headers(&self) -> Option<ndn_packet::lp::LpHeaders> {
        let (id, ttl_secs) = self.side?;
        Some(ndn_packet::lp::LpHeaders {
            side_route: Some(ndn_packet::lp::SideRoute { id, ttl_secs }),
            ..ndn_packet::lp::LpHeaders::default()
        })
    }
}

/// The future of an [`Extension::answer`].
#[cfg(not(target_arch = "wasm32"))]
pub type AnswerFuture<'a> = futures::future::BoxFuture<'a, Option<Answer>>;
/// The future of an [`Extension::answer`].
#[cfg(target_arch = "wasm32")]
pub type AnswerFuture<'a> = futures::future::LocalBoxFuture<'a, Option<Answer>>;

/// A protocol a sibling crate adds to a device: it answers the Interests under
/// `<D>/32=<keyword>` (`D` the device) for each of its [`keywords`](Self::keywords).
///
/// Each Interest is answered in a task of its own, so an answer may sign, wait
/// for the store or ask the network. The core router never gives an extension
/// an Interest under `/localhost`, a name of another device, or a core keyword.
pub trait Extension: Send + Sync {
    /// The keywords it answers: each non-empty, lowercase ASCII letters, digits
    /// and `-`, and not one the layer's own names carry nor one another
    /// extension registered. Read once, when it is registered.
    fn keywords(&self) -> &'static [&'static str];

    /// The answer to `interest` (the Data wire, and a route label if it sets one up), or `None`:
    /// the Interest is then Nacked, as one nothing answers is.
    fn answer<'a>(&'a self, interest: &'a Interest) -> AnswerFuture<'a>;
}

/// The extensions a node serves, by keyword.
#[derive(Default)]
pub(crate) struct Extensions {
    owners: RwLock<BTreeMap<&'static str, Arc<dyn Extension>>>,
}

/// The keyword right after `device` in `name`, if `name` is under `device`.
fn own_keyword<'n>(device: &Name, name: &'n Name) -> Option<&'n [u8]> {
    let next = name.components().get(device.len())?;
    (name.has_prefix(device) && next.typ == tlv_type::KEYWORD).then(|| next.value.as_ref())
}

/// Whether `word` can be a keyword an extension claims.
fn is_keyword(word: &str) -> bool {
    !word.is_empty()
        && word
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

/// The first octet of a join note ([`Kind::JOINED`]): its form.
const JOINED_NOTE: u8 = 1;

fn stopped() -> HeapError {
    HeapError::local("the node is stopped")
}

impl Extensions {
    /// Register `extension` for all its keywords, or for none.
    fn register(&self, extension: Arc<dyn Extension>) -> Result<(), HeapError> {
        let words = extension.keywords();
        let bad = |why: String| HeapError::BadRequest { why };
        if words.is_empty() {
            return Err(bad(
                "an extension that claims no keyword is never asked anything: give it the \
                 keyword its Interests carry after the device name"
                    .into(),
            ));
        }
        let mut owners = self.owners.write();
        for (i, word) in words.iter().enumerate() {
            if !is_keyword(word) {
                return Err(bad(format!(
                    "{word:?} is no keyword an extension can claim: use lowercase ASCII \
                     letters, digits and `-`, at least one"
                )));
            }
            if CORE_KEYWORDS.contains(&word.as_bytes()) {
                return Err(bad(format!(
                    "the keyword {word} is one the layer's own names carry (an entry, a space, a \
                     seal key, a grant, …), served by the core: claim a keyword of your own"
                )));
            }
            if owners.contains_key(word) || words[..i].contains(word) {
                return Err(bad(format!(
                    "the keyword {word} is claimed already: an extension answers its own \
                     keywords only, so claim another"
                )));
            }
        }
        for word in words.iter().copied() {
            owners.insert(word, Arc::clone(&extension));
        }
        Ok(())
    }

    /// The extension that answers `name` for the device `me`: the one that
    /// registered the keyword right after `me`.
    pub(crate) fn answering(&self, me: &Name, name: &Name) -> Option<Arc<dyn Extension>> {
        let word = std::str::from_utf8(own_keyword(me, name)?).ok()?;
        self.owners.read().get(word).cloned()
    }

    /// Why a node does not sign `name` for its extensions as device `me`, or
    /// `None` when it does: only `<me>/32=<keyword>/…` of a registered keyword.
    fn refusal(&self, me: &Name, name: &Name) -> Option<String> {
        let registered = || {
            let owners = self.owners.read();
            if owners.is_empty() {
                "none is registered".to_string()
            } else {
                format!(
                    "registered: {}",
                    owners.keys().copied().collect::<Vec<_>>().join(", ")
                )
            }
        };
        let why = if !name.has_prefix(me) {
            format!("it is not under this device's name {me}")
        } else if let Some(word) = own_keyword(me, name) {
            let owned = std::str::from_utf8(word)
                .ok()
                .is_some_and(|w| self.owners.read().contains_key(w));
            if CORE_KEYWORDS.contains(&word) {
                format!(
                    "its keyword {} belongs to the layer's own names",
                    String::from_utf8_lossy(word)
                )
            } else if owned {
                let key = |c: &ndn_foundation_types::NameComponent| {
                    c.typ == tlv_type::GENERIC_NAME_COMPONENT && c.value.as_ref() == b"KEY"
                };
                if !name.components().iter().any(key) {
                    return None;
                }
                "its name has a generic `KEY` component, the mark of a key's name and of a \
                 certificate's (`<id>/KEY/<id>/<issuer>/v=<n>`), which the device key never signs \
                 for an extension: name the packet without a `KEY` component"
                    .to_string()
            } else {
                format!(
                    "no extension registered its keyword {}",
                    String::from_utf8_lossy(word)
                )
            }
        } else {
            format!("it has no keyword right after this device's name {me}")
        };
        Some(format!(
            "{name} is not a name this node signs: {why}; a node signs for an extension only \
             `{me}/32=<keyword>/…` of a keyword registered with Node::extend ({})",
            registered()
        ))
    }
}

/// The node's host surface, on its own state.
impl NodeInner {
    /// [`NodeHandle::extend`].
    pub(crate) fn extend(&self, extension: Arc<dyn Extension>) -> Result<(), HeapError> {
        self.net()
            .ok_or_else(stopped)?
            .shared
            .extensions
            .register(extension)
    }

    /// [`NodeHandle::sign_packet`].
    pub(crate) fn sign_packet(&self, packet: DataBuilder) -> Result<Bytes, HeapError> {
        let net = self.net().ok_or_else(stopped)?;
        let extensions = &net.shared.extensions;
        let (mut refused, mut failed) = (None, None);
        let key = self.signer.key_name();
        let wire = packet.sign_sync(self.signer.sig_type(), Some(key), |region| {
            // The signed region begins with the name: judged here, from the very
            // bytes that would be signed, before the key is used.
            match Name::decode_from_tlv(Bytes::copy_from_slice(region)) {
                Ok(name) => {
                    if let Some(why) = extensions.refusal(&self.device, &name) {
                        refused = Some(why);
                        return Bytes::new();
                    }
                }
                Err(e) => {
                    refused = Some(format!(
                        "the packet's name does not decode ({e}); build it with DataBuilder::new"
                    ));
                    return Bytes::new();
                }
            }
            match self.signer.sign_sync(region) {
                Ok(signature) => signature,
                Err(e) => {
                    failed = Some(e);
                    Bytes::new()
                }
            }
        });
        if let Some(why) = refused {
            return Err(HeapError::BadRequest { why });
        }
        if let Some(e) = failed {
            return Err(HeapError::local(format!(
                "the device key {key} did not sign ({e}); the layer needs a key that signs \
                 synchronously"
            )));
        }
        self.signatures
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(wire)
    }

    /// [`NodeHandle::note_joined`].
    pub(crate) fn note_joined(&self, space: &Name) {
        let mut note = vec![JOINED_NOTE];
        if let Some(held) = self.space_of(space) {
            let log = held.log.lock();
            if log.fold.lists(&log.person) {
                return;
            }
            for remover in log.fold.removers(&log.person) {
                note.extend_from_slice(&remover.digest);
            }
        }
        self.store.insert(Kind::JOINED.of(space), Bytes::from(note));
        self.flusher.note_write();
    }

    /// Whether a refusal for want of a listing is a wait: an offer's answer
    /// admitted this device to `log`'s space ([`NodeHandle::note_joined`]), the
    /// fold does not list its person, and no removal of her arrived since the
    /// note was made (the admission was not undone before it was ever seen).
    /// The note is removed when the fold lists the person, and when a removal
    /// of her arrived that the note did not know of: what it waited for is no
    /// more to come.
    pub(crate) fn joining(&self, log: &Log) -> bool {
        let key = Kind::JOINED.of(&log.space);
        let Some(note) = self.store.get(&key) else {
            return false;
        };
        if log.fold.lists(&log.person) {
            self.release_joined(log);
            return false;
        }
        let known: Vec<&[u8]> = note.get(1..).unwrap_or_default().chunks_exact(32).collect();
        let undone =
            (log.fold.removers(&log.person).iter()).any(|r| !known.contains(&&r.digest[..]));
        if undone {
            self.store.remove(&key);
            self.flusher.note_write();
            return false;
        }
        true
    }

    /// Remove the join note of `log`'s space once its fold lists this device's
    /// person.
    pub(crate) fn release_joined(&self, log: &Log) {
        let key = Kind::JOINED.of(&log.space);
        if log.fold.lists(&log.person) && self.store.contains(&key) {
            self.store.remove(&key);
            self.flusher.note_write();
        }
    }

    /// [`NodeHandle::fetch_entry`].
    pub(crate) async fn fetch_entry(&self, name: &Name) -> Result<EntryId, HeapError> {
        let entry = parse_log_name(name).ok_or_else(|| HeapError::BadName {
            name: name.clone(),
            why: "an entry is named `<device>/32=log/<space>/seq=<n>`".into(),
        })?;
        let group = self
            .net()
            .ok_or_else(stopped)?
            .group(&entry.space)
            .ok_or_else(|| HeapError::BadRequest {
                why: format!(
                    "{} is not open here, so {name} would be judged by no fold: open the space \
                     (Node::open) before fetching one of its entries",
                    entry.space
                ),
            })?;
        group.fetch_entry(&entry).await
    }
}

/// A handle to a [`Node`](crate::Node): its host surface, and no more than the
/// parts an [`Extension`] needs to answer. Cheap to clone; dropping it stops
/// nothing; once the node stops, every method that needs the network answers
/// [`HeapError::Local`] and the rest read what the node held.
#[derive(Clone)]
pub struct NodeHandle {
    pub(crate) inner: Arc<NodeInner>,
}

impl std::fmt::Debug for NodeHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeHandle")
            .field("device", &self.inner.device)
            .finish()
    }
}

impl NodeHandle {
    pub(crate) fn of(inner: Arc<NodeInner>) -> NodeHandle {
        NodeHandle { inner }
    }

    /// The device's name.
    pub fn name(&self) -> &Name {
        &self.inner.device
    }

    /// The device's namespace: that of the trust context governing its name.
    pub fn namespace(&self) -> &Name {
        &self.inner.ns
    }

    /// The key this device signs with.
    pub fn writer(&self) -> &Name {
        self.inner.signer.key_name()
    }

    /// Join a space made elsewhere ([`Node::open`](crate::Node::open)).
    pub async fn open(&self, space: &Name) -> Result<Heap, HeapError> {
        self.inner.open_space(space).await
    }

    /// The space `space`, if the node has it open as a member
    /// ([`Node::space`](crate::Node::space)).
    pub fn space(&self, space: &Name) -> Option<Heap> {
        self.inner.member_space(space)
    }

    /// Wait for a flush covering everything written so far
    /// ([`Node::flush`](crate::Node::flush)): what a sibling's note is durable by.
    pub async fn flush(&self) -> Result<(), HeapError> {
        Ok(self.inner.flusher.flush().await?)
    }

    /// Run `task` as one of the node's own tasks, for a host or an extension that works
    /// alongside it (a watch it keeps on a space, a loop that judges what it holds): the task
    /// is dropped, with whatever it holds (a [`Heap`], this handle), when the node stops, and
    /// [`Node::close`](crate::Node::close) returns once it has been. A task spawned on
    /// another runtime handle is not waited for by `close`, and a [`Heap`] it holds keeps the
    /// node, and so its store, until it ends. A node that has stopped starts it and drops it at
    /// once.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn spawn<F: Future<Output = ()> + Send + 'static>(&self, task: F) {
        self.inner.tasks.spawn(task);
    }

    /// As the native one: `task` is one of the node's own tasks.
    #[cfg(target_arch = "wasm32")]
    pub fn spawn<F: Future<Output = ()> + 'static>(&self, task: F) {
        self.inner.tasks.spawn(task);
    }

    /// Register `extension` to answer the Interests under `<D>/32=<keyword>`
    /// for each of its keywords, and to have the node sign packets named
    /// under them ([`Self::sign_packet`]).
    ///
    /// # Errors
    ///
    /// [`HeapError::BadRequest`], registering nothing, for an extension that
    /// claims no keyword, a word that is no keyword (lowercase ASCII letters,
    /// digits and `-`), a keyword the layer's own names carry (`data`, `log`,
    /// `seal`, `grant`, `held`, `piece`, `manifest`, `sync`, `chan`), or
    /// one already claimed; [`HeapError::Local`] once the node stopped.
    pub fn extend(&self, extension: Arc<dyn Extension>) -> Result<(), HeapError> {
        self.inner.extend(extension)
    }

    /// Sign `packet` with the device's key. Only a packet named
    /// `<D>/32=<keyword>/…` (`D` this device, the keyword right after it) of a
    /// keyword an extension registered ([`Self::extend`]) is signed: the name is
    /// read from the bytes about to be signed, before the key is used. So the
    /// node signs no entry (`32=log`), no certificate or key name, nothing of
    /// another device and nothing under a keyword nobody claimed.
    ///
    /// # Errors
    ///
    /// [`HeapError::BadRequest`] naming why the name is refused;
    /// [`HeapError::Local`] when the key does not sign synchronously or the
    /// node stopped.
    pub fn sign_packet(&self, packet: DataBuilder) -> Result<Bytes, HeapError> {
        self.inner.sign_packet(packet)
    }

    /// A consumer on the node's own face: its Interests go where the node's
    /// go, by the routes the host set. A new one each call.
    pub fn consumer(&self) -> Consumer {
        Consumer::new(Arc::clone(&self.inner.conn))
    }

    /// The validator the node judges by: its keyring (the trust contexts held)
    /// and its certificate cache.
    pub fn validator(&self) -> &Arc<Validator> {
        &self.inner.judge.validator
    }

    /// The key store the node was started with.
    pub fn keys(&self) -> &Arc<SecurityManager> {
        &self.inner.keys
    }

    /// The node's store. A sibling keeps its own records under
    /// `/localhost/ndn-<crate>/`, a prefix no device serves and the layer never
    /// scans, and makes them durable with [`Self::flush`].
    pub fn store(&self) -> &Arc<dyn DataStore> {
        &self.inner.store
    }

    /// This device's X25519 recipient key. Its secret is kept by the key store,
    /// never in the data store, so a sibling derives the keys that protect its
    /// own notes from it (HKDF, a label of its own).
    pub fn recipient(&self) -> &RecipientKey {
        self.inner.recipient()
    }

    /// Note that an offer's answer admitted this device to `space` while the
    /// space's members do not list its person yet: stored at
    /// `/localhost/ndn-heap/joined/<space>`. While it stands and the space's
    /// fold does not list the person, a put the fold would refuse as
    /// [`HeapError::NotAllowed`] answers [`HeapError::NotReady`] (retry: the
    /// entry that lists the person is on its way); the note is removed when the
    /// fold lists the person (owner, writer or reader) and when a removal of her
    /// arrives that the note did not know of (the admission was undone before it
    /// was ever seen: the refusal is `NotAllowed` again), and nothing is noted
    /// for a space that lists her already. Durable with the node's next flush,
    /// as the host's own notes are. Open the space first: the note keeps the
    /// removals of her held then, so that an earlier invitation's are not taken
    /// for this one's.
    pub fn note_joined(&self, space: &Name) {
        self.inner.note_joined(space);
    }

    /// Fetch the entry `name` (`<device>/32=log/<space>/seq=<n>`) of a space
    /// open here and admit it through the ordinary judge, which refuses what it
    /// refuses: nothing of the entry bypasses it, and nothing else is fetched.
    /// The writer is asked, then the heard members that vouch for its log. Its
    /// id when the entry is held (whether it was applied is
    /// [`Heap::applied`]'s to say).
    ///
    /// # Errors
    ///
    /// [`HeapError::BadName`] for a name that is no entry's;
    /// [`HeapError::BadRequest`] for a space not open here;
    /// [`HeapError::Refused`] with the judge's reason;
    /// [`HeapError::NotReady`] while a context or certificate it needs is not
    /// held; [`HeapError::Unavailable`] when no holder answered.
    pub async fn fetch_entry(&self, name: &Name) -> Result<EntryId, HeapError> {
        self.inner.fetch_entry(name).await
    }

    /// The node's clock, as the times it writes are read.
    pub fn now(&self) -> Timestamp {
        Timestamp(self.inner.now())
    }

    /// What tunes the node: the Interest lifetime and the first look a
    /// sibling's waits are bounded by.
    pub fn config(&self) -> &Config {
        &self.inner.config
    }

    /// The person of a device: the namespace of the trust context that governs
    /// it here (the self-certifying namespace a person's name hashes to, while
    /// no context of it is held).
    pub fn person_of(&self, device: &Name) -> Name {
        self.inner.person_of(device)
    }

    /// The persons whose trust context this node adopted for the spaces that
    /// list them (scoped adoption by the host's [`Adopter`](crate::Adopter)),
    /// sorted: a person whose context the keyring holds is not one, and neither
    /// is one still being adopted.
    pub fn adopted_persons(&self) -> Vec<Name> {
        self.inner.judge.adopted_persons()
    }
}

impl Heap {
    /// The Members entry that removed `person`, who the space lists no more
    /// (neither as writer nor as reader): of the entries applied that remove an
    /// Add of hers, the one of the lowest signed digest, so that every node
    /// holding the same entries names the same one. The entry's log name is
    /// `<device>/32=log/<space>/seq=<n>`, what the removed person's node asks
    /// [`NodeHandle::fetch_entry`] for. `None` for a person the space lists, one
    /// it never listed, and the owner.
    pub fn removed_by(&self, person: &Name) -> Option<EntryId> {
        self.inner.log.lock().fold.removal_record(person)
    }
}
