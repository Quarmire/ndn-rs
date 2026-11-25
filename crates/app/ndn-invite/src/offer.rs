//! The offering side of an introduction (spec §19): making an offer, closing it, and
//! answering the asks that name it.
//!
//! An offer is a Data `<D>/32=intro/offer/<id>` signed by the device's key through the
//! node, kept at `offer/<id>` and served by the extension. What judging an ask needs
//! — the proof key, the wrong tries, the key being admitted, the acceptance given, the
//! use mark, the closing mark — is in the store under `/localhost/ndn-invite/`, each
//! note durable before the reply it backs; the offer is never a log entry.
use std::sync::Arc;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_heap::{Heap, HeapError, MembersChange};
use ndn_packet::Data;
use ndn_packet::encode::DataBuilder;
use ndn_sync::StoreOp;
use ndn_trust_envelope::Introduction;

use crate::credentials::{Opened, device_of, open_credentials, overlap};
use crate::error::InviteError;
use crate::host::{Code, LinkHint, Offer, Role};
use crate::invites::{Held, Inner, Invites, Queued};
use crate::marks::{self, Use};
use crate::policy::IntroRefusal;
use crate::proofs::{SECRET_LEN, answer_proof, ask_proves, commitment, proof_key};
use crate::sealed::{open_ask, open_note, wrap_note};
use crate::store;
use crate::wire::{
    AnswerBody, AskBody, IntroAsk, IntroRecord, OfferBody, OfferId, Outcome, UsedBody, ask_name,
    intro_name, intro_prefix, offer_name, parse_offer_name,
};

impl Invites {
    /// Make a one-use offer of `space` (spec §19.2): a space of this device's
    /// namespace that this node has open. The offer — the space, the role, the expiry,
    /// the wrong tries that close it, a commitment to a fresh secret and this device's
    /// seal key — is a Data named `<D>/32=intro/32=offer/<id>` (`id`: 16 random octets,
    /// as hard to guess as a secret of that size), signed by the device's key; it and
    /// the offer's proof key are durable before the code is returned. The code is the
    /// compact link, the words, and — when [`crate::IntroPolicy::short_code`] is on, the
    /// host gives a first contact and the line fits — a short code, whose hint token
    /// is kept the same way and whose hint record is then served
    /// ([`Code::short_why`] says why a code has no short form, and then nothing of a
    /// hint is published). Nothing secret is published.
    ///
    /// # Errors
    ///
    /// [`InviteError::BadRequest`] for a space this node does not have open, an offer
    /// that allows no wrong try or expires already; [`InviteError::Heap`] with
    /// `NotOwner` (next step: use an owner device) for a space of another namespace
    /// and for a device that is no owner device of the space — a `guest` or `node`
    /// device of the owner, which could not add a joiner — so that no code is shown that
    /// admits nobody; [`InviteError::NotReady`] while this device has not seen the
    /// space's creation; [`InviteError::Local`] when the host gives no anchor or the
    /// notes cannot be made durable.
    pub async fn offer(&self, space: &Name, offer: Offer) -> Result<Code, InviteError> {
        self.inner.make_offer(space, offer).await
    }

    /// Close the offer `offer` this device made, for good (spec §19.2): a closing mark,
    /// durable before this returns. Every ask of it is refused as closed from then on,
    /// its user's too; what the offer granted stays, until the space's members remove
    /// it. Closing a closed offer does nothing more.
    ///
    /// # Errors
    ///
    /// [`InviteError::BadRequest`] for a name that is no offer of this device's;
    /// [`InviteError::Local`] when the mark cannot be made durable.
    pub async fn close_offer(&self, offer: &Name) -> Result<(), InviteError> {
        let inner = &self.inner;
        let id = match parse_offer_name(offer) {
            Some((maker, id)) if maker == *inner.node.name() => id,
            Some((maker, _)) => {
                return Err(InviteError::BadRequest {
                    why: format!(
                        "the offer was made by the device {maker}, which alone answers and \
                         closes it: close it there"
                    ),
                });
            }
            None => {
                return Err(InviteError::BadRequest {
                    why: "this is no offer's name (<device>/32=intro/offer/<id>): give the name \
                          the offer printed"
                        .into(),
                });
            }
        };
        if !inner.state.lock().offers.contains_key(&id) {
            return Err(InviteError::BadRequest {
                why: "this device holds no offer of that name: give the name the offer printed"
                    .into(),
            });
        }
        inner.close(&id).await
    }
}

/// The device an ask's proof claims asks, by its key locator, and the proof's packet:
/// unverified, for the checks that cost nothing.
fn claimed_asker(proof: &Bytes) -> Option<(Data, Name)> {
    let data = Data::decode(proof.clone()).ok()?;
    let key = data.sig_info()?.key_locator_name()?;
    let asker = device_of(&key)?;
    Some((data, asker))
}

impl Inner {
    fn offer_held(&self, id: &OfferId) -> Option<Held> {
        self.state.lock().offers.get(id).cloned()
    }

    async fn make_offer(&self, space: &Name, offer: Offer) -> Result<Code, InviteError> {
        let device = self.node.name().clone();
        let ns = self.node.namespace().clone();
        let parsed =
            ndn_heap::wire::parse_space_name(space).ok_or_else(|| InviteError::BadRequest {
                why: format!(
                    "{space} is no space name (<owner>/32=data/<name>): offer a space the \
                     data layer made"
                ),
            })?;
        if parsed.owner != ns {
            return Err(HeapError::NotOwner {
                space: space.clone(),
            }
            .into());
        }
        if offer.tries == 0 {
            return Err(InviteError::BadRequest {
                why: "an offer closes after one wrong try or more: give tries >= 1".into(),
            });
        }
        if offer.until <= self.now() {
            return Err(InviteError::BadRequest {
                why: "the offer's expiry has passed by this device's clock: give a later one"
                    .into(),
            });
        }
        let heap = self
            .node
            .space(space)
            .ok_or_else(|| InviteError::BadRequest {
                why: format!(
                    "{space} is not open on this device: create it (Node::create) or open it \
                     (Node::open), then offer it"
                ),
            })?;
        // What a code of this device can do is decided by the space's creation and by this
        // device's standing in it, so both are known before a code is shown: a joiner
        // answered by a device that cannot admit it would meet silence (spec §5.3).
        if !heap.members_known() {
            return Err(InviteError::NotReady {
                name: space.clone(),
                why: "this device has not seen the space's creation, so it does not know who \
                      the space lists or whether it is public"
                    .into(),
            });
        }
        // Only an owner device (an `admin` or `member` device of the owner) signs the members
        // entry that admits a joiner: a guest or a node device of the owner shows no code.
        heap.owner_device()?;
        let credentials = crate::credentials::credentials(&self.node, &*self.host)?;
        let own = open_credentials(&credentials)
            .await
            .filter(|o| *o.ctx.namespace() == ns)
            .ok_or_else(|| {
                InviteError::local(format_args!(
                    "the host gives an anchor that is not {ns}'s signed trust context with a \
                     chain to this device's key: fix the host's enrollment"
                ))
            })?;
        let mut secret = [0u8; SECRET_LEN];
        self.entropy(&mut secret);
        let id = self.fresh_id();
        let name = offer_name(&device, &id);
        let seal_key = self.node.recipient().public();
        let key_note = wrap_note(
            self.node.recipient(),
            &store::key_key(&id),
            proof_key(&secret, &name),
        )
        .map_err(|e| {
            InviteError::local(format_args!(
                "the offer's proof key could not be wrapped: {e}"
            ))
        })?;
        let body = OfferBody {
            space: space.clone(),
            role: offer.role,
            until: offer.until,
            tries: offer.tries,
            commitment: commitment(&secret),
            seal_key,
        };
        let wire = self.node.sign_packet(DataBuilder::new(
            name.clone(),
            &IntroRecord::Offer(body.clone()).encode(),
        ))?;
        // Durable before the offer is served or its code shown: a stop before leaves no
        // offer, and one after leaves the whole of it.
        store::apply_durable(
            &self.store,
            vec![
                StoreOp::Insert(store::key_key(&id), key_note),
                StoreOp::Insert(store::offer_key(&id), wire.clone()),
            ],
        )
        .await?;
        self.state.lock().offers.insert(id, Held { body, wire });
        let relays = self
            .node
            .validator()
            .keyring()
            .context_for(&device)
            .relays()
            .iter()
            .map(|r| r.device.to_string())
            .collect();
        let intro = Introduction {
            namespace: Some(ns.to_string()),
            fingerprint: own.fingerprint(),
            offer: name.to_string(),
            secret,
            link_hint: None,
            relays,
        };
        let words = intro.to_words().to_string();
        // The host's link hint: this device's key and where to dial it, kept within one
        // QR by dropping what does not fit (spec §19.2).
        let hint = self.host.link_hint();
        let link = LinkHint::code_link(intro, hint.as_ref(), &self.policy).ok_or_else(|| {
            InviteError::local(format_args!(
                "the offer's link does not fit one QR even without relay hints or a link hint \
                 (the offer name {name} is too long): offer a space of a shorter name"
            ))
        })?;
        // The short code, and with it the hint record it names: made only when the host
        // gives a first contact and the line fits; its token durable before it is shown.
        let (short, short_why) = match self
            .short_code(&id, &secret, &own.fingerprint(), hint.as_ref())
            .await?
        {
            Ok(text) => (Some(text), None),
            Err(why) => (None, Some(why)),
        };
        Ok(Code {
            offer: name,
            link,
            words,
            short,
            short_why,
        })
    }

    // ---- what the store holds of an offer ---------------------------------------------

    /// The proof key of the own offer `id`, from the store.
    fn proof_key_of(&self, id: &OfferId) -> Option<[u8; 32]> {
        let key = store::key_key(id);
        open_note(self.node.recipient(), &key, &self.store.get(&key)?)
    }

    /// The own offer `id`'s wrong tries counted toward
    /// [`IntroPolicy::wrong_tries_max`](crate::IntroPolicy), and when the last one was
    /// counted (milliseconds, by this device's clock).
    pub(crate) fn overall_tries(&self, id: &OfferId) -> (u32, u64) {
        let key = store::tries_key(id);
        let Some(note) = self.store.get(&key) else {
            return (0, 0);
        };
        marks::open(self.node.recipient(), &key, &note)
            .and_then(|b| {
                let count = u32::from_be_bytes(b.get(..4)?.try_into().ok()?);
                let at = u64::from_be_bytes(b.get(4..12)?.try_into().ok()?);
                (b.len() == 12).then_some((count, at))
            })
            // A count that does not read is the cap: wrong tries are never given back by
            // a note that cannot be told from a forgery.
            .unwrap_or((u32::MAX, u64::MAX))
    }

    /// How many wrong tries the key of public key digest `digest` asked the own offer
    /// `id` with; a count that does not read is more than any offer allows.
    fn asker_tries(&self, id: &OfferId, digest: &[u8; 32]) -> u32 {
        let key = store::tries_asker_key(id, digest);
        let Some(note) = self.store.get(&key) else {
            return 0;
        };
        marks::open(self.node.recipient(), &key, &note)
            .and_then(|b| <[u8; 4]>::try_from(b.as_ref()).ok())
            .map_or(u32::MAX, u32::from_be_bytes)
    }

    /// Count a wrong try of the offer `id` by the key of digest `digest`, durably:
    /// against the asker always; toward the overall cap once the pause after the last
    /// one counted there passed (the policy's backoff, doubled by each counted). The
    /// asker's count and the overall one, once the flush covers them.
    async fn count_wrong(
        &self,
        id: &OfferId,
        digest: &[u8; 32],
    ) -> Result<(u32, u32), InviteError> {
        let recipient = self.node.recipient();
        let mine = self.asker_tries(id, digest).saturating_add(1);
        let asker = store::tries_asker_key(id, digest);
        let mut ops = vec![StoreOp::Insert(
            asker.clone(),
            marks::seal(recipient, &asker, &mine.to_be_bytes()),
        )];
        let (mut all, last) = self.overall_tries(id);
        let now = self.now().0;
        let pause = u64::try_from(self.policy.backoff.as_millis())
            .unwrap_or(u64::MAX)
            .saturating_mul(1u64 << all.saturating_sub(1).min(32));
        if all == 0 || now >= last.saturating_add(pause) {
            all = all.saturating_add(1);
            let mut v = Vec::with_capacity(12);
            v.extend_from_slice(&all.to_be_bytes());
            v.extend_from_slice(&now.to_be_bytes());
            let overall = store::tries_key(id);
            ops.push(StoreOp::Insert(
                overall.clone(),
                marks::seal(recipient, &overall, &v),
            ));
        }
        store::apply_durable(&self.store, ops).await?;
        Ok((mine, all))
    }

    /// The use of the own offer `id` that is under way (a stop came between its start and
    /// its use mark).
    fn using(&self, id: &OfferId) -> Use {
        marks::using_by(self.store.as_ref(), self.node.recipient(), id)
    }

    /// The use mark of the own offer `id`.
    fn used(&self, id: &OfferId) -> Use {
        marks::used_by(self.store.as_ref(), self.node.recipient(), id)
    }

    /// Whether a closing mark of the own offer `id` is held. Any value closes: a forged
    /// closing mark only closes, which is the side to fail on.
    fn closing_mark(&self, id: &OfferId) -> bool {
        self.store.contains(&store::closed_key(id))
    }

    /// Whether the offer `id` is closed: by its closing mark, by wrong tries of all
    /// askers at the policy's cap, because a use note does not read, or because the
    /// person it was used by is no longer listed by its space (a removed member never
    /// comes back by its code, spec §19.7). Derived from durable data on every call, never
    /// cached; a space that raised `Alert::RolledBack` closes every offer first
    /// ([`Self::close_after_rollback`]).
    pub(crate) fn offer_closed(&self, id: &OfferId, body: &OfferBody) -> bool {
        self.close_after_rollback();
        if self.closing_mark(id) || self.overall_tries(id).0 >= self.policy.wrong_tries_max {
            return true;
        }
        let key = match self.used(id) {
            Use::By(key, _) => key,
            Use::Unreadable => return true,
            Use::Not => match self.using(id) {
                Use::By(key, _) => key,
                Use::Unreadable => return true,
                Use::Not => return false,
            },
        };
        let (Some(device), Some(heap)) = (device_of(&key), self.node.space(&body.space)) else {
            return false;
        };
        heap.removed_by(&self.node.person_of(&device)).is_some()
    }

    // ---- a store that may be older than what the device did ---------------------------------

    /// Close every offer held, when `distrusts` holds of the open heap of one of the spaces
    /// the offers name, and say why. The notes of an offer (`used/`, `using/`, `tries/`) are
    /// authenticated and cannot be forged, but a copy of the store older than what the device
    /// did holds an older note that still reads: a restored backup would let a code be used
    /// again, or give wrong tries back. The closing marks are in the store when this returns
    /// (every judgement reads them) and flushed in the background: a stop before the flush
    /// ends is an unclean start, which closes them again. Whether any was closed.
    fn close_every_offer_if(&self, why: &str, distrusts: impl Fn(&Heap) -> bool) -> bool {
        let held: Vec<(OfferId, Name)> = self
            .state
            .lock()
            .offers
            .iter()
            .map(|(id, held)| (*id, held.body.space.clone()))
            .collect();
        let Some(space) = held
            .iter()
            .map(|(_, space)| space)
            .find(|space| self.node.space(space).is_some_and(|heap| distrusts(&heap)))
        else {
            return false;
        };
        let open: Vec<OfferId> = held
            .iter()
            .map(|(id, _)| *id)
            .filter(|id| !self.closing_mark(id))
            .collect();
        if !open.is_empty() {
            self.store.apply(
                open.iter()
                    .map(|id| StoreOp::Insert(store::closed_key(id), Bytes::from_static(&[1])))
                    .collect(),
            );
            for id in &open {
                self.drop_hint_served(id);
            }
            tracing::warn!(device = %self.node.name(), %space, closed = open.len(), "every open offer of this device is closed: {why}; make a new offer for each code still wanted");
            let store = Arc::clone(&self.store);
            ndn_app::rt::spawn(async move {
                if let Err(e) = store::flush(&store).await {
                    tracing::warn!("the closing of the offers is not durable: {e}");
                }
            });
        }
        true
    }

    /// At a start: close every offer read back when the node opened a space they name after
    /// a stop it did not make ([`Heap::started_unclean`]): the store may be a copy older
    /// than what this device did and the peers hold.
    pub(crate) fn close_after_unclean_start(&self) {
        self.close_every_offer_if(
            "the space they name was opened after a stop the node did not make, so the notes of the offers may be older than what this device did",
            Heap::started_unclean,
        );
    }

    /// Every time a space the offers name has raised `Alert::RolledBack` since the offers were
    /// last closed for it ([`Heap::rollbacks`]: an entry signed under this device's name lies
    /// above what it kept, so the store is an old image or a copy of one, or a copy of this
    /// device's key signs): close every offer held then. An offer made after a rollback is
    /// not about it, but one made before the next rollback is: the count is kept per space,
    /// and any alert above it closes again, not only the first of the process.
    fn close_after_rollback(&self) {
        let mut acted = self.rollbacks_acted.lock();
        let seen = std::cell::RefCell::new(Vec::new());
        let closed = self.close_every_offer_if(
            "a space they name found this device's store older than what its peers hold, so the notes of the offers cannot be trusted",
            |heap| {
                let count = heap.rollbacks();
                let fresh = count > acted.get(heap.name()).copied().unwrap_or(0);
                if fresh {
                    seen.borrow_mut().push((heap.name().clone(), count));
                }
                fresh
            },
        );
        if closed {
            acted.extend(seen.into_inner());
        }
    }

    /// Close the offer `id`, durably, and drop the packet kept for its hint token so
    /// that the next ask of the token is answered with the gone mark.
    pub(crate) async fn close(&self, id: &OfferId) -> Result<(), InviteError> {
        if !self.closing_mark(id) {
            store::put_durable(&self.store, store::closed_key(id), Bytes::from_static(&[1]))
                .await?;
        }
        self.drop_hint_served(id);
        Ok(())
    }

    // ---- answering an ask --------------------------------------------------------------

    /// Answer an ask of this device (spec §19.4): open it, prove its asker, judge it in the
    /// order specified, and answer — admitting the asker, or refusing and saying why. One
    /// ask at a time; the same ask asked again gets the same answer while it is kept.
    /// `None` (a Nack) for what does not open, for an asker that proved no key — a
    /// refusal travels only to an asker that proved a key, so a prober learns nothing of
    /// what the device holds — for an offer this device holds none of, and for an ask
    /// past the ones held already
    /// ([`IntroPolicy::asks_queued`](crate::IntroPolicy)): opening and verifying run at
    /// most [`InviteConfig::asks_verifying`](crate::InviteConfig) at once.
    pub(crate) async fn answer_intro(&self, name: &Name, params: Option<Bytes>) -> Option<Bytes> {
        if let Some(r) = self.state.lock().answers.get(name) {
            return Some(r.clone());
        }
        let device = self.node.name().clone();
        // The name's digest binds the parameters: an ask is its parameters.
        let params = params.filter(|p| intro_name(&device, p) == *name)?;
        let _held = {
            let mut st = self.state.lock();
            if st.queued >= self.policy.asks_queued {
                tracing::warn!(
                    me = %device,
                    held = st.queued,
                    "an introduction ask is not answered: as many asks as IntroPolicy::asks_queued allows are held already; its asker's retry is judged once they are done"
                );
                return None;
            }
            st.queued += 1;
            Queued(self)
        };
        let (body, proof, asker, opened, by) = {
            let _verifying = self.verifying.acquire().await.ok()?;
            let ask = IntroAsk::decode(params).ok()?;
            let aad = intro_prefix(&device).encode_to_tlv();
            let plain = open_ask(
                self.node.recipient(),
                &aad,
                &ask.ephemeral,
                &ask.key,
                &ask.sealed,
            )?;
            let body = AskBody::decode(Bytes::from(plain)).ok()?;
            let (proof, asker) = claimed_asker(&body.asker)?;
            let opened = open_credentials(&body.credentials).await?;
            // The asker proves a key before anything is said to it: the proof packet is
            // this ask's (its name binds the ask), signed by a key of the asking device
            // that chains to the anchor the credentials carry.
            let (key, digest) = opened.signer(&proof).await?;
            if *proof.name != ask_name(&asker, &body.binding(&device))
                || device_of(&key).as_ref() != Some(&asker)
            {
                tracing::debug!(offer = %body.offer, %asker, "an ask whose asker's proof does not verify; not answered");
                return None;
            }
            (body, proof, asker, opened, (key, digest))
        };
        let _turn = self.serial.lock().await;
        if let Some(r) = self.state.lock().answers.get(name) {
            return Some(r.clone());
        }
        let answer = self.judge_ask(&body, &proof, &asker, &opened, by).await?;
        let reply = DataBuilder::new(name.clone(), &answer.encode()).sign_digest_sha256();
        self.state
            .lock()
            .answers
            .insert(name.clone(), reply.clone());
        Some(reply)
    }

    /// Judge an opened ask whose asker proved the key `by` (spec §19.4), in order: the
    /// offer is this device's and known (else no answer); not closed; not used by another
    /// key (its user is answered the acceptance it was given, and nothing more is done);
    /// not expired by this device's clock; the asker's own wrong tries not spent; the proof
    /// is right (a wrong one counted durably, against the asker and toward the overall
    /// cap); the asker's namespace is no other's. Then the use is noted, the asker's anchor
    /// adopted, the asker added to the space with one members change, and the acceptance,
    /// the use mark and the grant kept, all durable before the answer; a failure before
    /// lets the use go.
    async fn judge_ask(
        &self,
        body: &AskBody,
        proof: &Data,
        asker: &Name,
        opened: &Opened,
        by: (Name, [u8; 32]),
    ) -> Option<AnswerBody> {
        let offer = &body.offer;
        let refuse = |(asker, digest): (Name, [u8; 32]), why| AnswerBody {
            offer: offer.clone(),
            asker,
            digest,
            outcome: Outcome::Refused(why),
            proof: None,
        };
        let id = parse_offer_name(offer)
            .filter(|(device, _)| device == self.node.name())
            .map(|(_, id)| id);
        let held = id.and_then(|id| {
            let ob = self.offer_held(&id)?.body;
            Some((id, self.proof_key_of(&id)?, ob))
        });
        // An offer this device does not hold is no answer, not a refusal: a prober that
        // guesses an id is met with the silence of every other miss (spec §2.3).
        let (id, pk, ob) = held?;
        // A use mark that is there and does not read is a use by a key nobody knows: the
        // offer is used, whoever asks (spec §18).
        let used = match self.used(&id) {
            Use::By(key, digest) => Some((key, digest)),
            Use::Unreadable => return Some(refuse(by, IntroRefusal::Used)),
            Use::Not => None,
        };
        let closed = self.offer_closed(&id, &ob);
        // A closed offer admits no one new: only the key a use mark names is still
        // answered (below), until the offer expires (spec §9.2 step 5).
        if closed && used.as_ref() != Some(&by) {
            return Some(refuse(by, IntroRefusal::Closed));
        }
        // One use: a use mark, else a use a stop interrupted. Its user is answered
        // again — never admitted again: a later members entry may have removed it
        // (spec §19.7).
        let user = match (&used, self.using(&id)) {
            (Some(user), _) => Some(user.clone()),
            (None, Use::By(key, digest)) => Some((key, digest)),
            // A use under way that does not read is a use by a key nobody knows.
            (None, Use::Unreadable) => return Some(refuse(by, IntroRefusal::Used)),
            (None, Use::Not) => None,
        };
        match user {
            Some(user) if user != by => return Some(refuse(by, IntroRefusal::Used)),
            Some(_) if used.is_some() => {
                if closed && ob.until <= self.now() {
                    return Some(refuse(by, IntroRefusal::Expired));
                }
                return self.accepted_again(&id, offer, &ob, &pk, by);
            }
            _ => {}
        }
        if ob.until <= self.now() {
            return Some(refuse(by, IntroRefusal::Expired));
        }
        if self.asker_tries(&id, &by.1) >= ob.tries {
            return Some(refuse(by, IntroRefusal::Closed));
        }
        if !ask_proves(&pk, offer, &by.0, &by.1, &body.nonce, &body.proof) {
            let (mine, all) = self.count_wrong(&id, &by.1).await.ok()?;
            if all >= self.policy.wrong_tries_max {
                self.close(&id).await.ok()?;
                return Some(refuse(by, IntroRefusal::Closed));
            }
            if mine >= ob.tries {
                return Some(refuse(by, IntroRefusal::Closed));
            }
            return Some(refuse(
                by,
                IntroRefusal::WrongProof {
                    left: ob.tries - mine,
                },
            ));
        }
        let theirs = opened.ctx.namespace().clone();
        let conflict = if asker.has_prefix(&theirs) {
            overlap(&self.node, &self.policy, &theirs, &opened.fingerprint())
        } else {
            Some(format!("is not a prefix of the asking device {asker}"))
        };
        if let Some(why) = conflict {
            tracing::info!(%offer, namespace = %theirs, "an ask refused as a conflict: the namespace {why}");
            return Some(refuse(by, IntroRefusal::Conflict));
        }
        // The use, noted before anything of it is done: a stop from here on leaves the
        // offer this key's, and its retry finishes the use.
        let using_note = store::using_key(&id);
        let mut using = by.0.encode_to_tlv().to_vec();
        using.extend_from_slice(&by.1);
        store::put_durable(
            &self.store,
            using_note.clone(),
            marks::seal(self.node.recipient(), &using_note, &using),
        )
        .await
        .ok()?;
        if let Err(why) = self.host.adopt(&opened.link()).await {
            tracing::warn!(%offer, namespace = %theirs, "the host did not adopt the asker's anchor: {why}; the offer is not spent and the asker's retry is judged again");
            self.release(&id).await;
            return None;
        }
        let keyring = self.node.validator().keyring();
        if !opened.vouched_by(keyring) {
            tracing::info!(%offer, namespace = %theirs, "an ask refused as a conflict: its credentials carry anchors the namespace adopted from its genesis does not hold");
            self.release(&id).await;
            return Some(refuse(by, IntroRefusal::Conflict));
        }
        // The proof again, judged by what this device now holds of the namespace: a key
        // its held version revokes, shown with an older version, does not ask for it.
        if opened.signer_held(keyring, proof).await.as_ref() != Some(&by) {
            tracing::info!(%offer, namespace = %theirs, key = %by.0, "an ask refused as a conflict: its proof does not verify under the namespace as this device holds it (a key the held version revokes, or credentials older than it)");
            self.release(&id).await;
            return Some(refuse(by, IntroRefusal::Conflict));
        }
        for c in opened.chain(&by.0, &theirs) {
            self.node.validator().cert_cache().insert(c);
        }
        let admitted = match self.admit_joiner(&ob.space, ob.role, &theirs).await {
            Ok(admitted) => admitted,
            Err(e) => {
                tracing::warn!(%offer, namespace = %theirs, "the asker is not added to the space: {e}; the offer is not spent and the asker's retry is judged again");
                self.release(&id).await;
                return None;
            }
        };
        let answer = self.acceptance(offer, &ob, &pk, by.clone(), admitted)?;
        // The acceptance, the use mark and the grant (spec §19.8) are one durable batch:
        // all of it is there before the answer, or none. The grant is made only here: an
        // asker answered again (above) is granted nothing more, and its `until` is not
        // extended.
        let grant = self
            .grants
            .grant_note(&id, by.1, &theirs, &ob.space, ob.role);
        let used_note = store::used_key(&id);
        let mark = IntroRecord::Used(UsedBody {
            offer: offer.clone(),
            by: Some(by),
        })
        .encode();
        let mut ops = vec![
            StoreOp::Insert(store::accepted_key(&id), answer.encode()),
            StoreOp::Insert(
                used_note.clone(),
                marks::seal(self.node.recipient(), &used_note, &mark),
            ),
        ];
        if let Some((op, _)) = &grant {
            ops.push(op.clone());
        }
        ops.push(StoreOp::Remove(store::using_key(&id)));
        if let Err(e) = store::apply_durable(&self.store, ops).await {
            tracing::warn!(%offer, "the use mark is not durable: {e}; the asker's retry finishes the use");
            return None;
        }
        if let Some((_, pending)) = grant {
            self.grants.granted(&pending);
        }
        Some(answer)
    }

    /// Drop the note of a use of `id` that did not happen (the host did not adopt the
    /// asker, or it was not added): the offer is not spent.
    async fn release(&self, id: &OfferId) {
        if let Err(e) = store::remove_durable(&self.store, &store::using_key(id)).await {
            tracing::debug!(offer = ?id, "an offer's use note was not dropped durably: {e}");
        }
    }

    /// Make `ns` a member of `space` as `role` (spec §19.4): one members change adds it
    /// as a writer (a writer's role) and as a reader. The members entry that made it,
    /// to name in the answer; `None` when the space lists `ns` in that role already,
    /// so that no entry is made to say it again.
    async fn admit_joiner(
        &self,
        space: &Name,
        role: Role,
        ns: &Name,
    ) -> Result<Option<ndn_heap::EntryId>, HeapError> {
        let heap = self
            .node
            .space(space)
            .ok_or_else(|| HeapError::BadRequest {
                why: format!("{space} is not open on this device: open it to admit a joiner"),
            })?;
        let members = heap.members();
        let write = role == Role::Writer && !members.writers.contains(ns);
        let read = !members.readers.contains(ns);
        if !write && !read {
            return Ok(None);
        }
        heap.change(MembersChange {
            add_writers: if role == Role::Writer {
                vec![ns.clone()]
            } else {
                Vec::new()
            },
            add_readers: vec![ns.clone()],
            remove: Vec::new(),
        })
        .await
        .map(Some)
    }

    /// The acceptance of the offer `offer` for its asker key `by`: the space, the role,
    /// this device's credentials and proof packet, the members entry that admitted the
    /// asker (`admitted`), the answer proof.
    fn acceptance(
        &self,
        offer: &Name,
        ob: &OfferBody,
        pk: &[u8; 32],
        (key, digest): (Name, [u8; 32]),
        admitted: Option<ndn_heap::EntryId>,
    ) -> Option<AnswerBody> {
        let credentials = crate::credentials::credentials(&self.node, &*self.host).ok()?;
        let mut answer = AnswerBody {
            offer: offer.clone(),
            asker: key,
            digest,
            outcome: Outcome::Accepted {
                space: ob.space.clone(),
                role: ob.role,
                credentials,
                inviter: Bytes::new(),
                admitted,
            },
            proof: None,
        };
        let signed = self.ask_proof(&answer.binding())?;
        if let Outcome::Accepted { inviter, .. } = &mut answer.outcome {
            *inviter = signed;
        }
        answer.proof = Some(answer_proof(pk, &answer));
        Some(answer)
    }

    /// The acceptance the used offer was answered with, for its user `by`, asking
    /// again: as kept. Neither adopts nor admits anything.
    fn accepted_again(
        &self,
        id: &OfferId,
        offer: &Name,
        ob: &OfferBody,
        pk: &[u8; 32],
        by: (Name, [u8; 32]),
    ) -> Option<AnswerBody> {
        let kept = self
            .store
            .get(&store::accepted_key(id))
            .and_then(|b| AnswerBody::decode(b).ok())
            .filter(|a| a.asker == by.0 && a.digest == by.1);
        match kept {
            Some(a) => Some(a),
            None => self.acceptance(offer, ob, pk, by, None),
        }
    }
}
