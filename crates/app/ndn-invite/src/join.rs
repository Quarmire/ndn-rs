//! The joiner's side of an introduction (spec §19.3): read the code, judge it before
//! anything is dialled, reach the inviter, fetch and check the offer, send the sealed
//! ask, check the answer against the code, adopt the inviter's anchor, open the space,
//! and return once this person may write there.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_foundation_types::{Name, tlv_type};
use ndn_heap::wire::log_name;
use ndn_heap::{EntryId, Heap};
use ndn_packet::Data;
use ndn_packet::encode::InterestBuilder;
use ndn_security::anchor_fingerprint;
use ndn_security::self_certifying::self_certifying_digest;
use ndn_trust_envelope::words::WORD_COUNT as WORDS_FORM_WORDS;
use ndn_trust_envelope::{IntroWords, TrustEnvelope};
#[cfg(not(target_arch = "wasm32"))]
use tokio::time::Instant;
use tracing::debug;
#[cfg(target_arch = "wasm32")]
use web_time::Instant;

use crate::credentials::{Fingerprint, credentials, device_of, open_credentials, overlap};
use crate::error::InviteError;
use crate::host::{Joined, LinkHint, Role};
use crate::invites::{Inner, Invites};
use crate::join_hint::{ASK_TRIES, FirstContact, OFFER_TRIES};
use crate::policy::IntroRefusal;
use crate::proofs::{SECRET_LEN, answer_proves, ask_proof, commitment, hint_token, proof_key};
use crate::sealed::seal_ask;
use crate::short::{Contact, ShortCode};
use crate::wire::{
    self, AnswerBody, AskBody, HINT_TOKEN_LEN, IntroAsk, IntroRecord, Outcome, hint_name,
    intro_name, intro_prefix, parse_offer_name,
};

/// How often a join looks again at what it waits for (the data layer fetches and
/// syncs on its own; a join only watches what arrived).
const POLL: Duration = Duration::from_millis(20);

/// What a code says.
struct Parsed {
    /// The offer's name. A short code does not carry it: the hint record it names
    /// says it, verified (`None` until then).
    offer: Option<Name>,
    /// The inviter's device: the offer's, or the short code's.
    device: Name,
    secret: [u8; SECRET_LEN],
    fingerprint: Fingerprint,
    namespace: Option<Name>,
    relays: Vec<String>,
    link_hint: Option<LinkHint>,
    /// A short code's token and first contact.
    short: Option<Short>,
}

/// What a short code gives beside the device and the secret.
struct Short {
    /// The token the hint record is named by ([`hint_token`] of the secret).
    token: [u8; HINT_TOKEN_LEN],
    /// The first contact: an address to dial or a relay to hint through; none when
    /// the Interests go by name.
    contact: Option<Contact>,
}

/// The namespace a whole `fingerprint` names: the prefix of `device` up to its
/// self-certifying component, when that component is it (a self-certifying
/// namespace is named by its anchor's fingerprint).
fn self_certifying_namespace(device: &Name, fingerprint: &[u8]) -> Option<Name> {
    let at = device
        .components()
        .iter()
        .position(|c| c.typ == ndn_packet::tlv_type::SELF_CERTIFYING)?;
    let ns = Name::from_components(device.components()[..=at].iter().cloned());
    matches!(self_certifying_digest(&ns), Ok(Some(d)) if d == fingerprint).then_some(ns)
}

fn bad(why: impl Into<String>) -> InviteError {
    InviteError::BadRequest { why: why.into() }
}

/// The owner namespace of a space name `<O>/32=data/…`.
fn space_owner(space: &Name) -> Option<Name> {
    let comps = space.components();
    let at = comps
        .iter()
        .position(|c| c.typ == tlv_type::KEYWORD && c.value.as_ref() == b"data")?;
    (at > 0).then(|| Name::from_components(comps[..at].iter().cloned()))
}

/// Read a code: an `ndn-trust://intro/…` link (or its https mirror), the words form
/// (an offer name, then 24 words), or a short code (a device name, perhaps a first
/// contact, then 20 or 36 words: [`ShortCode`]). The number of words tells the last
/// two apart. A link hint's loopback and link-local addresses are dropped unless
/// `local_candidates` ([`IntroPolicy::local_candidates`](crate::IntroPolicy)); a
/// short code's are refused.
fn parse_code(code: &str, local_candidates: bool) -> Result<Parsed, InviteError> {
    let code = code.trim();
    // The device of an offer's name `<D>/32=intro/offer/<id>`.
    let offered =
        |offer: Name| {
            let device = parse_offer_name(&offer).map(|(device, _)| device).ok_or_else(|| {
            bad(format!(
                "the code's offer {offer} is no offer's name (<device>/32=intro/offer/<id>): \
                 check the code"
            ))
        })?;
            Ok::<_, InviteError>((offer, device))
        };
    let offer_of = |s: &str| {
        s.parse::<Name>().map_err(|_| {
            bad(format!(
                "the code names its offer as {s}, which is no name: check the code"
            ))
        })
    };
    if code.starts_with('/') {
        if ShortCode::word_count(code) != WORDS_FORM_WORDS {
            let s = ShortCode::parse(code, local_candidates).map_err(|e| bad(e.to_string()))?;
            let namespace = self_certifying_namespace(&s.device, &s.fingerprint);
            let fingerprint = Fingerprint::of(&s.fingerprint, &s.secret).ok_or_else(|| {
                bad("the code carries a fingerprint of neither 10 nor 32 octets: check the code")
            })?;
            return Ok(Parsed {
                offer: None,
                device: s.device,
                secret: s.secret,
                fingerprint,
                namespace,
                relays: Vec::new(),
                link_hint: None,
                short: Some(Short {
                    token: hint_token(&s.secret),
                    contact: s.contact,
                }),
            });
        }
        let w = IntroWords::parse(code).map_err(|e| {
            bad(format!(
                "the code's words do not read ({e}): check each word"
            ))
        })?;
        let (offer, device) = offered(offer_of(&w.offer)?)?;
        return Ok(Parsed {
            offer: Some(offer),
            device,
            secret: w.secret,
            fingerprint: Fingerprint::Prefix(w.fingerprint.to_vec()),
            namespace: None,
            relays: Vec::new(),
            link_hint: None,
            short: None,
        });
    }
    match TrustEnvelope::from_uri(code) {
        Ok(TrustEnvelope::Intro(i)) => {
            let namespace = match &i.namespace {
                Some(ns) => Some(ns.parse::<Name>().map_err(|_| {
                    bad(format!(
                        "the code names the inviter as {ns}, which is no name"
                    ))
                })?),
                None => None,
            };
            let (offer, device) = offered(offer_of(&i.offer)?)?;
            Ok(Parsed {
                offer: Some(offer),
                device,
                secret: i.secret,
                fingerprint: Fingerprint::Whole(i.fingerprint),
                namespace,
                relays: i.relays.clone(),
                link_hint: i
                    .link_hint
                    .as_deref()
                    .and_then(|v| LinkHint::decode(v, local_candidates).ok()),
                short: None,
            })
        }
        Ok(other) => Err(bad(format!(
            "this is an ndn-trust {} link, not an introduction's code: give it to what takes \
             that kind",
            other.kind().as_str()
        ))),
        Err(e) => Err(bad(format!(
            "the code is neither an ndn-trust://intro link, nor a device name, address and \
             words (a short code), nor an offer name and 24 words ({e}): check what was scanned \
             or typed"
        ))),
    }
}

/// The error of a join whose inviter device did not answer.
fn offline(offer: &Name, device: &Name) -> InviteError {
    InviteError::NotReady {
        name: offer.clone(),
        why: format!(
            "the inviter's device {device} does not answer (offline or unreachable): retry \
             later; the offer waits for you until it expires"
        ),
    }
}

impl Invites {
    /// Join the space a code offers (spec §19.3). The code is read (a link, the
    /// words, or a short code) and judged before anything is dialled or asked; a
    /// short code's hint record is fetched over its first contact and verified; then
    /// the offer is fetched from the inviting device, an ask sealed to the seal key
    /// the offer holds is sent, carrying this device's credentials and a proof of
    /// the secret bound to its key; the answer is checked against the code (bound to
    /// this key, proving the secret, signed by the inviting device under the anchor
    /// the code names); the host adopts the inviter's anchor; the space is opened
    /// ([`NodeHandle::open`](ndn_heap::host::NodeHandle::open)) and noted as joined
    /// ([`NodeHandle::note_joined`](ndn_heap::host::NodeHandle::note_joined)).
    ///
    /// Returns only once this person may write there: the space lists it, its epoch
    /// key is held (asked of the owner's devices by the data layer as soon as the
    /// space is open) and the members entry the answer names as the one that admitted
    /// it is applied, within `first_look * 3 + lifetime`. No answer, or the bound
    /// passing: [`InviteError::NotReady`], retry later, naming what is awaited — the
    /// offer waits, and joining again with the same code is answered again.
    ///
    /// Then, durably, the join keeps the **mirror note** (the inviter's end of the
    /// grant, spec §19.8) and tells the host.
    ///
    /// # Errors
    ///
    /// [`InviteError::BadRequest`] for a code that does not read or offers a space of
    /// this device's own namespace; [`InviteError::Refused`] with the refusal (the
    /// code judged before dialling, an answer that does not prove the code, the
    /// inviter's refusal); [`InviteError::NotReady`]; [`InviteError::Local`].
    pub async fn join(&self, code: &str) -> Result<Joined, InviteError> {
        self.inner.join_by(code).await
    }
}

impl Inner {
    /// Fetch `name` as fresh Data only (`MustBeFresh`), with the forwarding hint `hints`.
    /// The offer is asked for so: a link or words code has nothing that verifies the
    /// offer before the answer does, so a copy damaged in flight is found out only after
    /// the ask, and a forwarder that kept it would answer every retry that does not ask
    /// for fresh Data with the same copy until it is evicted. The offer packet has no
    /// freshness period, which no cache counts as fresh, so each fetch reaches the
    /// inviter's device.
    async fn fetch_fresh(&self, name: Name, hints: &[Name]) -> Option<Data> {
        let mut b = InterestBuilder::new(name)
            .lifetime(self.node.config().lifetime)
            .must_be_fresh();
        if !hints.is_empty() {
            b = b.forwarding_hint(hints.to_vec());
        }
        match self.node.consumer().fetch_with(b).await {
            Ok(data) => Some(data),
            Err(e) => {
                debug!(me = %self.node.name(), "the offer fetch missed: {e}");
                None
            }
        }
    }

    /// The forwarding hint a join's Interests carry: the relays the code names, else
    /// those this device's own namespace advertises. Hints only reach; nothing they
    /// say is trusted (spec §19.7).
    fn relays_for(&self, from_code: &[String]) -> Vec<Name> {
        let named: Vec<Name> = from_code.iter().filter_map(|s| s.parse().ok()).collect();
        if !named.is_empty() {
            return named;
        }
        self.node
            .validator()
            .keyring()
            .context_for(self.node.name())
            .relays()
            .iter()
            .map(|r| r.device.clone())
            .collect()
    }

    /// Why a join refuses `code` before it dials or asks anything, if it does (spec
    /// §19.3). The code names the offering `device`, and the dial gives whoever holds
    /// the code's key a link, so both are judged first:
    /// - a code that names a namespace `device` is not under is altered
    ///   ([`IntroRefusal::Forged`]);
    /// - the namespace it names is judged as an inviter's ([`overlap`]);
    /// - a `device` under a namespace this device already trusts is refused, unless
    ///   the code names that very namespace (or none) and its fingerprint is one of
    ///   that namespace's anchors: the same anchor is a party known already, and a
    ///   second invitation from it is welcome. A code that claims a device of a
    ///   namespace this device trusts under another anchor would have the link, and
    ///   with it the namespace's Interests, go to whoever holds the key.
    fn refuse_before_dial(&self, code: &Parsed, device: &Name) -> Option<IntroRefusal> {
        if let Some(ns) = &code.namespace {
            if !device.has_prefix(ns) {
                return Some(IntroRefusal::Forged);
            }
            if let Fingerprint::Whole(fp) = &code.fingerprint
                && let Some(why) = overlap(&self.node, &self.policy, ns, fp)
            {
                return Some(IntroRefusal::InviterConflict {
                    inviter: ns.clone(),
                    why,
                });
            }
        }
        for ctx in self.node.validator().keyring().contexts() {
            let held = ctx.namespace();
            if !device.has_prefix(held) {
                continue;
            }
            let named = code.namespace.as_ref().is_none_or(|ns| ns == held);
            let anchored = ctx
                .anchors()
                .iter()
                .any(|a| code.fingerprint.matches(&anchor_fingerprint(a.value())));
            if !(named && anchored) {
                return Some(IntroRefusal::InviterConflict {
                    inviter: held.clone(),
                    why: format!(
                        "is a namespace this device trusts already, and the code does not name \
                         one of its anchors, yet it offers {device}, a device under it"
                    ),
                });
            }
        }
        None
    }

    /// [`Invites::join`].
    async fn join_by(&self, code: &str) -> Result<Joined, InviteError> {
        let code = parse_code(code, self.policy.local_candidates)?;
        let device = code.device.clone();
        // What a refusal names before the offer is known (a short code's hint record
        // says it): the offer, else the inviter's device.
        if device == *self.node.name() || device.has_prefix(self.node.namespace()) {
            return Err(bad(format!(
                "the code offers a space of this device's own namespace ({device}): it is \
                 yours already"
            )));
        }
        // What the code says is judged before anything is dialled or asked (spec
        // §19.3): the dial gives whoever holds the key a link, and a code's device
        // name is only what it claims.
        if let Some(why) = self.refuse_before_dial(&code, &device) {
            return Err(InviteError::Refused(why));
        }
        let host = Arc::clone(&self.host);
        let credentials = credentials(&self.node, host.as_ref())?;
        let own = open_credentials(&credentials).await.ok_or_else(|| {
            InviteError::local(
                "the host gives an anchor that is no signed trust context: fix the host's \
                 enrollment",
            )
        })?;
        let me = self.node.writer().clone();
        let digest = self.own_key_digest();
        // A short code's first contact, reached before any Interest (spec §19.3 step
        // 3): an address is dialled with no key to expect, a relay is the Interests'
        // forwarding hint, and no contact leaves them to be routed by name.
        let first = match &code.short {
            Some(Short {
                contact: Some(contact),
                ..
            }) => Some(self.first_contact(&host, &device, contact).await?),
            Some(_) => Some(FirstContact {
                hints: Vec::new(),
                linked: None,
            }),
            None => None,
        };
        // A join that fails after a dial takes the dial's link down
        // ([`Host::undial`]): what answered at the hint's key proved nothing, and the
        // link is kept only once the inviter's namespace is held and the link
        // identified. The first contact's link, which proved no certificate, is not
        // kept either.
        let mut dialled: Option<LinkHint> = None;
        let mut linked_first = first.as_ref().and_then(|f| f.linked.clone());
        let joined: Result<Joined, InviteError> = async {
            let (offer, hints, vouching) = if let (Some(short), Some(first)) = (&code.short, &first)
            {
                // The hint record, fetched over the first contact and verified before
                // anything else is sent (§3.4, §3.5).
                let asked = hint_name(&device, &short.token);
                let data = self.fetch_hint(&device, &asked, first).await?;
                let hinted = self
                    .verify_hint(
                        &data,
                        &asked,
                        &device,
                        &code.fingerprint,
                        code.namespace.as_ref(),
                    )
                    .await
                    .map_err(InviteError::Refused)?;
                // The relays the Interests go through when no link carries them: the
                // one the code named, then the record's.
                let mut hints = first.hints.clone();
                for relay in &hinted.relays {
                    if !hints.contains(relay) {
                        hints.push(relay.clone());
                    }
                }
                if hints.is_empty() {
                    hints = self.relays_for(&[]);
                }
                // The first contact's link is kept only when the key it proved is the
                // record's: the dial expected no key, so what answered may be any
                // party on the path to the address, which relays the genuine record.
                // A link of another key is taken down now, before the offer is fetched
                // or the ask sent, and the join goes by the record's own dial, then
                // relays, then by name; it is never the link's routes (spec §19.3).
                let same = linked_first
                    .as_ref()
                    .is_some_and(|l| l.key == hinted.link.key);
                if !same && let Some(first_link) = linked_first.take() {
                    host.undial(&first_link, &device);
                }
                // Dial as a code's link hint is: by the record's key and candidates,
                // unless the first contact's link is that key's already.
                if same {
                    hints.clear();
                } else if !hinted.link.candidates.is_empty() {
                    match host
                        .dial(&hinted.link, &device, self.node.config().first_look)
                        .await
                    {
                        Ok(()) => {
                            hints.clear();
                            dialled = Some(hinted.link);
                        }
                        Err(why) => {
                            debug!(offer = %hinted.offer, "the hint record's link hint was not dialled: {why}");
                        }
                    }
                }
                (hinted.offer, hints, Some(hinted.opened))
            } else {
                let offer = code.offer.clone().ok_or_else(|| {
                    InviteError::local("a code that is neither a link, words nor a short code was read")
                })?;
                // The code's link hint, dialled before any Interest (spec §19.3, step
                // 0): on success the Interests go by name over that link; any failure
                // leaves the relay hints (or routing by name) as before.
                let mut hints = self.relays_for(&code.relays);
                if let Some(hint) = &code.link_hint {
                    match host.dial(hint, &device, self.node.config().first_look).await {
                        Ok(()) => {
                            hints.clear();
                            dialled = Some(hint.clone());
                        }
                        Err(why) => {
                            debug!(%offer, "the code's link hint was not dialled: {why}");
                        }
                    }
                }
                (offer, hints, None)
            };
            let forged = || InviteError::Refused(IntroRefusal::Forged);
            // A hint record's offer is the inviter's device's own: a name another
            // device's would be asked of the wrong device.
            if parse_offer_name(&offer).is_none_or(|(d, _)| d != device) {
                return Err(forged());
            }
            let pk = proof_key(&code.secret, &offer);
            // The offer, as the offering device serves it.
            let mut fetched = None;
            for _ in 0..OFFER_TRIES {
                fetched = self.fetch_fresh(offer.clone(), &hints).await;
                if fetched.is_some() {
                    break;
                }
            }
            let entry = fetched.ok_or_else(|| offline(&offer, &device))?;
            if *entry.name != offer {
                return Err(forged());
            }
            let Some(IntroRecord::Offer(ob)) = entry
                .content()
                .and_then(|c| IntroRecord::decode(c.clone()).ok())
            else {
                return Err(InviteError::Refused(IntroRefusal::Unknown));
            };
            // The offer must be signed by a key of the inviter's device that chains to
            // the anchor the verified record's credentials carry, before the ask is
            // sealed to the seal key it holds: with the commitment public, a party on
            // the path could else substitute the seal key and read the ask. Nothing
            // proves it for a link or words form (no record): the answer's credentials
            // are checked after.
            let by_device = |k: &Option<(Name, [u8; 32])>| {
                k.as_ref()
                    .is_some_and(|(k, _)| device_of(k).as_ref() == Some(&device))
            };
            if let Some(vouching) = &vouching
                && !by_device(&vouching.signer(&entry).await)
            {
                return Err(forged());
            }
            // A short code's secret is whole in the code (a checksum guards it against
            // a typo), so an offer that is not committed to it is another offer than
            // the code's: a record that names it, whoever signed it, is no record of
            // this code's offer. Judged on an offer the record's credentials vouch for,
            // and refused before the ask, which would only count a wrong try.
            if code.short.is_some() && ob.commitment != commitment(&code.secret) {
                return Err(InviteError::Refused(IntroRefusal::HintMismatch {
                    why: format!("offer: {offer} was not made with this code's secret"),
                }));
            }

            // The ask.
            let nonce = self.nonce();
            let mut body = AskBody {
                offer: offer.clone(),
                nonce,
                proof: ask_proof(&pk, &offer, &me, &digest, &nonce),
                credentials,
                asker: Bytes::new(),
            };
            body.asker = self
                .ask_proof(&body.binding(&device))
                .ok_or_else(|| InviteError::local(format!("the device key {me} did not sign the ask")))?;
            let mine = Data::decode(body.asker.clone()).map_err(InviteError::local)?;
            if own.signer(&mine).await != Some((me.clone(), digest)) {
                return Err(InviteError::local(format!(
                    "the anchor the host gives does not certify this device's key {me} (no \
                     chain of valid certificates to it): renew the certificate or fix the \
                     enrollment"
                )));
            }
            let aad = intro_prefix(&device).encode_to_tlv();
            let sealed = seal_ask(&ob.seal_key, &aad, &body.encode())
                .map_err(|e| InviteError::local(format!("the ask could not be sealed: {e}")))?;
            let params = IntroAsk {
                ephemeral: sealed.ephemeral,
                key: sealed.key,
                sealed: sealed.sealed,
            }
            .encode();
            let name = intro_name(&device, &params);
            let prefix = intro_prefix(&device);
            let mut answered = None;
            for _ in 0..ASK_TRIES {
                answered = self.fetch(prefix.clone(), &hints, Some(&params)).await;
                if answered.is_some() {
                    break;
                }
            }
            let data = answered.ok_or_else(|| offline(&offer, &device))?;

            // The answer, checked against the code.
            let answer = data
                .content()
                .filter(|_| *data.name == name)
                .and_then(|c| AnswerBody::decode(c.clone()).ok())
                .filter(|a| a.offer == offer && a.asker == me && a.digest == digest)
                .ok_or_else(forged)?;
            let (space, role, theirs_credentials, signed, admitted) = match &answer.outcome {
                Outcome::Refused(why) => return Err(InviteError::Refused(why.clone())),
                Outcome::Accepted {
                    space,
                    role,
                    credentials,
                    inviter,
                    admitted,
                } => (space.clone(), *role, credentials, inviter, admitted.clone()),
            };
            if !answer_proves(&pk, &answer) {
                return Err(forged());
            }
            let theirs = open_credentials(theirs_credentials).await.ok_or_else(forged)?;
            let inviter = theirs.ctx.namespace().clone();
            let signed = Data::decode(signed.clone()).map_err(|_| forged())?;
            let signer = theirs.signer(&signed).await;
            if !code.fingerprint.matches(&theirs.fingerprint())
                || code.namespace.as_ref().is_some_and(|ns| *ns != inviter)
                || !device.has_prefix(&inviter)
                || *signed.name != wire::ask_name(&device, &answer.binding())
                || !by_device(&signer)
                || !by_device(&theirs.signer(&entry).await)
                || ob.commitment != commitment(&code.secret)
                || ob.space != space
                || ob.role != role
                || space_owner(&space).as_ref() != Some(&inviter)
                || admitted
                    .as_ref()
                    .is_some_and(|id| !id.device.has_prefix(&inviter))
            {
                return Err(forged());
            }
            // The inviter proved the code: its namespace is judged as one the code
            // named would have been — the words name none.
            if let Some(why) = overlap(&self.node, &self.policy, &inviter, &theirs.fingerprint()) {
                return Err(InviteError::Refused(IntroRefusal::InviterConflict {
                    inviter,
                    why,
                }));
            }
            host.adopt(&theirs.link()).await.map_err(|why| {
                InviteError::local(format!(
                    "this device's host did not adopt {inviter}'s anchor ({why}): fix that and \
                     join again with the same code (the offer is yours: asking again is \
                     answered again)"
                ))
            })?;
            let keyring = self.node.validator().keyring();
            if !theirs.vouched_by(keyring) {
                return Err(InviteError::Refused(IntroRefusal::InviterConflict {
                    inviter,
                    why: "carries anchors its namespace, adopted from its genesis, does not hold"
                        .into(),
                }));
            }
            // Its signatures again, judged by what this device now holds of the
            // namespace: a key the held version revokes, shown with an older version,
            // does not answer for it.
            if theirs.signer_held(keyring, &signed).await != signer
                || !by_device(&theirs.signer_held(keyring, &entry).await)
            {
                return Err(InviteError::Refused(IntroRefusal::InviterConflict {
                    inviter,
                    why: "answered with a key its namespace, as this device holds it, does not \
                          certify (a key the held version revokes, or credentials older than it)"
                        .into(),
                }));
            }
            let (key, inviter_key) = signer.ok_or_else(forged)?;
            for c in theirs.chain(&key, &inviter) {
                self.node.validator().cert_cache().insert(c);
            }
            // The joiner is no stranger from here on: the space is opened (the data
            // layer pulls what it lacks, the epoch key by its grant among it) and
            // noted as joined, so that a put in the window before the entry that lists
            // this person arrives is `NotReady`, never a refusal to ask the owner about.
            let heap = self.node.open(&space).await?;
            self.node.note_joined(&space);
            self.await_admission(&heap, &space, role, admitted.as_ref()).await?;
            // The grant's other end (spec §19.8): the inviter, by the key that signed
            // the answer verified above, may link back for this space while it lists
            // this device.
            self.keep_mirror(inviter_key, &inviter, &space).await?;
            Ok(Joined {
                space,
                role,
                inviter,
            })
        }
        .await;
        if joined.is_err() {
            for link in [dialled, linked_first].into_iter().flatten() {
                host.undial(&link, &device);
            }
        }
        joined
    }

    /// What `join` still waits for before this device, admitted to `space` as `role`,
    /// may write there, in the order it arrives: the space's creation, the entry that
    /// lists this person, the epoch key (the grant) and the entry the answer names as
    /// the one that admitted it. `None`: all are held.
    fn admission_missing(
        &self,
        heap: &Heap,
        space: &Name,
        role: Role,
        admitted: Option<&EntryId>,
    ) -> Option<String> {
        if !heap.members_known() {
            return Some(format!(
                "the creation of {space} has not been heard here yet: it comes from the \
                 inviter's device once it answers"
            ));
        }
        let person = self.node.namespace();
        let members = heap.members();
        let listed = match role {
            Role::Writer => members.writers.contains(person),
            Role::Reader => true,
        } && members.readers.contains(person);
        if !listed {
            return Some(format!(
                "the members of {space} held here do not list {person} as {} yet: the entry \
                 that admits it, signed when the offer admitted it, has not arrived",
                match role {
                    Role::Writer => "a writer",
                    Role::Reader => "a reader",
                }
            ));
        }
        if !heap.holds_epoch_key() {
            return Some(format!(
                "this device is admitted to {space}, but the epoch key of the space (its \
                 grant) is not held here yet: it is asked of the owner's devices and arrives \
                 once one answers"
            ));
        }
        if let Some(id) = admitted.filter(|id| !heap.applied(id)) {
            return Some(format!(
                "the members entry {} seq {} that admitted this device to {space} is not \
                 applied here yet: it is fetched from its writer and arrives once that device \
                 answers",
                id.device, id.seq
            ));
        }
        None
    }

    /// Wait until the space lists this person, its epoch key is held and the entry
    /// the answer named is applied ([`Self::admission_missing`]), for at most
    /// `first_look * 3 + lifetime` (the bound of every wait of a join), fetching the
    /// admitting entry by name while it is missing. [`InviteError::NotReady`] naming
    /// what is missing when the bound passes: join again with the same code, which is
    /// safe.
    async fn await_admission(
        &self,
        heap: &Heap,
        space: &Name,
        role: Role,
        admitted: Option<&EntryId>,
    ) -> Result<(), InviteError> {
        let config = self.node.config();
        let deadline = Instant::now() + config.first_look * 3 + config.lifetime;
        loop {
            let Some(missing) = self.admission_missing(heap, space, role, admitted) else {
                return Ok(());
            };
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(InviteError::NotReady {
                    name: space.clone(),
                    why: format!(
                        "{missing}; join again with the same code (the offer answers the \
                         device it admitted)"
                    ),
                });
            }
            if let Some(id) = admitted.filter(|id| !heap.applied(id)) {
                let entry = log_name(&id.device, space, id.seq);
                // The writer is asked, then the members that vouch for its log; a
                // miss is waited out like any other absence.
                let _ = ndn_app::rt::timeout(left, self.node.fetch_entry(&entry)).await;
                if self
                    .admission_missing(heap, space, role, admitted)
                    .is_none()
                {
                    return Ok(());
                }
            }
            ndn_app::rt::sleep(POLL.min(deadline.saturating_duration_since(Instant::now()))).await;
        }
    }
}
