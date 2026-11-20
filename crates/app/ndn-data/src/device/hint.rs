//! The hint record of a short code (SHAPES-R10 §2, §3): what an inviter device
//! publishes about an open offer, by a name only the code's holder can ask for,
//! and what a joiner does with it. The inviter makes the record **on request** from
//! the host's current link hint and its namespace's relays, signs it with the device
//! key as it signs everything it serves ([`Inner::sign`]), keeps the signed record a
//! few seconds ([`HINT_CACHE`]) and answers a signed gone mark once the offer is not
//! open. The joiner fetches it over the first contact a code names and trusts
//! nothing of it until it verifies against the code ([`Inner::verify_hint`]).
//! Types and bytes are [`crate::intro`]'s.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Name};
use ndn_security::confidentiality::{ContentKey, wrap_ck_to};
use ndn_security::self_certifying::self_certifying_digest;

use super::intro::{Fingerprint, OFFER_TRIES, Opened, local_name, open_credentials};
use super::{Inner, local, open_grant};
use crate::error::DataError;
use crate::intro::{
    Contact, HINT_RELAYS_MAX, HintCandidate, HintKind, HintRecord, IntroRefusal, Introducer,
    LINK_HINT_CANDIDATES_MAX, LinkHint, SECRET_LEN, ShortCode, hint_token, keyed_fingerprint,
    parse_hint_name,
};
use crate::rt::Instant;
use crate::version::Timestamp;
use crate::wire::{device_of, parse_log_name};

/// How long a signed hint record is answered again as it is, and its
/// `FreshnessPeriod`: a signature is paid at most once in this time for an
/// offer, however often the token is asked for, and a cache does not hold an
/// address past the time this device would give it. The record itself is made
/// from what the host knows when it is asked, so a moved address is current
/// within this time.
pub(super) const HINT_CACHE: Duration = Duration::from_secs(5);

/// A hint record signed and kept for [`HINT_CACHE`]: what it said
/// (`None`: the record, else the gone mark's reason) and the Data.
pub(super) struct HintServed {
    at: Instant,
    state: Option<IntroRefusal>,
    wire: Bytes,
}

/// What the inviter keeps of the packets it signed for hint tokens
/// (`Intros::hint_served`) lives [`HINT_CACHE`] and no longer: whatever lapsed
/// is dropped whenever a hint Interest is answered or refused, a token is kept,
/// or an offer closes. What stays is the token of each own offer
/// (`Intros::hints`, one token and one name), for as long as the offer is held:
/// §19.5 serves a gone mark for the token of a closed or expired offer, which
/// needs the token known, and the offers themselves are never pruned.
pub(super) fn sweep_hint_served(st: &mut super::St) {
    st.intro
        .hint_served
        .retain(|_, served| served.at.elapsed() < HINT_CACHE);
}

/// The offer `offer` closed: the packet kept for its token (the record it
/// would answer again, within [`HINT_CACHE`]) is dropped at once, and the
/// next ask signs the gone mark.
pub(super) fn drop_hint_served(st: &mut super::St, offer: &Name) {
    let intro = &mut st.intro;
    intro
        .hint_served
        .retain(|token, _| intro.hints.get(token) != Some(offer));
    sweep_hint_served(st);
}

/// Where the store keeps an own offer's hint token, wrapped to the device's
/// recipient key under a local name like its proof key, so a writer of the
/// store cannot make it read.
fn hint_token_name(offer: &Name) -> Name {
    local_name("hint", offer)
}

impl Inner {
    /// Keep the hint `token` of the own offer `offer`, durably (the note is
    /// durable with the store's next barrier, as the offer's proof key is) and
    /// in memory: from now on its record is served ([`Self::hint_packet`]).
    /// The 16 octets are the first of the 32 a wrapped content key holds.
    pub(super) fn keep_hint(
        &self,
        st: &mut super::St,
        offer: &Name,
        token: [u8; 16],
    ) -> Result<(), DataError> {
        let name = hint_token_name(offer);
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(&token);
        let (ephemeral, wrapped) = wrap_ck_to(
            &st.keys.recipient.public(),
            &ContentKey::from_bytes(key),
            &name.encode_to_tlv(),
        )
        .map_err(|e| local(format!("the offer's hint token could not be wrapped: {e}")))?;
        self.store.insert(
            name,
            crate::wire::encode_grant(&ephemeral, &wrapped.to_bytes()),
        );
        sweep_hint_served(st);
        st.intro.hints.insert(token, offer.clone());
        Ok(())
    }

    /// Read back, at start, the hint tokens of the own offers held: a note
    /// that is not wrapped to this device's key under its name is ignored, and
    /// its offer publishes no hint.
    pub(super) fn restore_hints(&self) {
        let mut st = self.st.lock();
        let own: Vec<Name> = st
            .intro
            .offers
            .keys()
            .filter(|o| parse_log_name(o).is_some_and(|l| l.device == self.device))
            .cloned()
            .collect();
        for offer in own {
            let name = hint_token_name(&offer);
            let Some(wire) = self.store.get(&name) else {
                continue;
            };
            let Some(key) = open_grant(&st.keys.recipient, &name, wire) else {
                tracing::debug!(%offer, "a hint token note that is not wrapped to this device's key; ignored");
                continue;
            };
            let mut token = [0u8; 16];
            token.copy_from_slice(&key.expose()[..16]);
            st.intro.hints.insert(token, offer);
        }
    }

    /// What this device answers for `name`, `<D>/32=hint/<token>`: for a token
    /// of one of its own offers, the signed [`HintRecord`] while the offer is
    /// open (not expired by this device's clock, not closed) — or always, when
    /// [`IntroPolicy::hint_while_open`](crate::intro::IntroPolicy) is off — and
    /// else a signed gone mark of why not; for any other name `None` (a Nack):
    /// a token nobody holds is neither a record nor a gone mark, so a prober
    /// learns nothing.
    pub(super) fn hint_packet(&self, name: &Name) -> Option<Bytes> {
        let (device, token) = parse_hint_name(name)?;
        if device != self.device {
            return None;
        }
        let now = (self.config.clock)();
        let (offer, until, state) = {
            let mut st = self.st.lock();
            sweep_hint_served(&mut st);
            let offer = st.intro.hints.get(&token)?.clone();
            let ob = st.intro.offers.get(&offer)?;
            let spent = self.overall_tries(&offer).0 >= self.config.intro.wrong_tries_max;
            let state = if !self.config.intro.hint_while_open {
                None
            } else if ob.until <= now {
                Some(IntroRefusal::Expired)
            } else if st.intro.closed.contains(&offer) || spent {
                Some(IntroRefusal::Closed)
            } else {
                None
            };
            if let Some(s) = st
                .intro
                .hint_served
                .get(&token)
                .filter(|s| s.state == state && s.at.elapsed() < HINT_CACHE)
            {
                return Some(s.wire.clone());
            }
            (offer, ob.until, state)
        };
        let record = match state.clone() {
            Some(why) => HintRecord::Gone {
                why,
                credentials: self.credentials().ok()?,
            },
            None => self.hint_offered(offer, until)?,
        };
        // A record is held by a cache for [`HINT_CACHE`]; a gone mark not at all:
        // a mark that a cache kept could outlive the inviter's say, and an
        // impostor's would sit there too.
        let fresh = if state.is_some() {
            Duration::ZERO
        } else {
            HINT_CACHE
        };
        let wire = self
            .sign(DataBuilder::new(name.clone(), &record.encode()).freshness(fresh))
            .ok()?;
        self.st.lock().intro.hint_served.insert(
            token,
            HintServed {
                at: Instant::now(),
                state,
                wire: wire.clone(),
            },
        );
        Some(wire)
    }

    /// The record of the open offer `offer`: the host's link hint now (its key
    /// and up to [`LINK_HINT_CANDIDATES_MAX`] addresses; with none, this
    /// device's key and no address), the relays its namespace advertises, the
    /// offer's expiry and this device's credentials, as an answer carries them.
    fn hint_offered(&self, offer: Name, until: Timestamp) -> Option<HintRecord> {
        let hint = self.introducer().ok()?.link_hint();
        let (key, mut candidates) = match hint {
            Some(h) => (h.key, h.candidates),
            None => (self.own_key?, Vec::new()),
        };
        candidates.truncate(LINK_HINT_CANDIDATES_MAX);
        let relays = self
            .validator
            .keyring()
            .context_for(&self.device)
            .relays()
            .iter()
            .take(HINT_RELAYS_MAX)
            .map(|r| r.device.clone())
            .collect();
        Some(HintRecord::Offered {
            offer,
            key,
            candidates,
            relays,
            until,
            credentials: self.credentials().ok()?,
        })
    }

    /// The short code of the own offer `offer` (SHAPES-R10 §1), and with it the
    /// hint record it names: `Ok(Ok(text))` once its token is kept (durable at
    /// the store's next barrier), `Ok(Err(why))` — nothing published — when
    /// the policy is off ([`IntroPolicy::short_code`](crate::intro::IntroPolicy)),
    /// when there is no first contact (a dialable candidate of the host's link
    /// `hint` under `local_candidates`, else a relay of the namespace), or when
    /// the line is wider than `short_width`. The fingerprint is the whole `anchor`
    /// when this device's namespace is the self-certifying one it is the digest
    /// of (the line then writes it `161=*`), else the 10 octets of the tag
    /// [`keyed_fingerprint`] makes of it with the offer's `secret`. An
    /// address or relay that makes the line too wide gives way to the next.
    pub(super) fn short_code(
        &self,
        offer: &Name,
        secret: &[u8; SECRET_LEN],
        anchor: &[u8; 32],
        hint: Option<&LinkHint>,
    ) -> Result<Result<String, String>, DataError> {
        let policy = &self.config.intro;
        if !policy.short_code {
            return Ok(Err(
                "short codes are off (IntroPolicy::short_code): this offer has its \
                           link and its words"
                    .into(),
            ));
        }
        // The first contact is the first of the hint's order whose line fits:
        // the host's dialable candidates, then the namespace's relays.
        let mut contacts: Vec<Contact> = Vec::new();
        for c in hint
            .into_iter()
            .flat_map(|h| h.candidates.iter())
            .filter(|c| c.dialable(policy.local_candidates))
        {
            let contact = Contact::Address(c.addr);
            if !contacts.contains(&contact) {
                contacts.push(contact);
            }
        }
        for r in self
            .validator
            .keyring()
            .context_for(&self.device)
            .relays()
            .iter()
            .take(HINT_RELAYS_MAX)
        {
            contacts.push(Contact::Relay(r.device.clone()));
        }
        if contacts.is_empty() {
            return Ok(Err(
                "no short code: the host gives no first contact to put in it (a link hint with \
                 an address that can be dialled from elsewhere — Introducer::link_hint, and \
                 loopback or link-local only with IntroPolicy::local_candidates — or a relay \
                 advertised by the namespace's trust context); give the link, or the words with \
                 the offer's name"
                    .into(),
            ));
        }
        let whole = matches!(self_certifying_digest(&self.ns), Ok(Some(d)) if d == *anchor);
        let fingerprint = if whole {
            anchor.to_vec()
        } else {
            keyed_fingerprint(secret, anchor).to_vec()
        };
        let mut narrowest = usize::MAX;
        let tried = contacts.len();
        for contact in contacts {
            let code = ShortCode {
                device: self.device.clone(),
                contact: Some(contact),
                secret: *secret,
                fingerprint: fingerprint.clone(),
            };
            let text = match code.encode() {
                Ok(text) => text,
                Err(e) => return Ok(Err(format!("no short code: {e}"))),
            };
            let width = text.chars().count();
            if width <= policy.short_width {
                let mut st = self.st.lock();
                self.keep_hint(&mut st, offer, hint_token(secret))?;
                return Ok(Ok(text));
            }
            narrowest = narrowest.min(width);
        }
        Ok(Err(format!(
            "no short code: with {} (and {} first contact{} tried) its line would be at least \
             {narrowest} characters, past IntroPolicy::short_width ({}): the names are the \
             owner's choice, so give the link, or the words with the offer's name",
            self.device,
            tried,
            if tried == 1 { "" } else { "s" },
            policy.short_width
        )))
    }
}

/// What a join reaches the inviter by before it holds the hint record: the
/// forwarding hint its Interests carry, and the link a dialled address made.
pub(super) struct FirstContact {
    /// The relay a relay contact names, as the Interests' forwarding hint.
    pub(super) hints: Vec<Name>,
    /// The link [`Introducer::dial_first`] made, as the hint
    /// [`Introducer::undial`] takes it down by: its key is what the handshake
    /// proved.
    pub(super) linked: Option<LinkHint>,
}

/// A hint record that verified against its code (§3.5): what the join goes on
/// with.
pub(super) struct Hinted {
    /// The offer's name: a log entry of the inviter's device.
    pub(super) offer: Name,
    /// Where and by which key to dial the inviter now; no candidates: no dial.
    pub(super) link: LinkHint,
    /// Relays to forward through when a dial fails.
    pub(super) relays: Vec<Name>,
    /// The record's credentials, opened: what vouches, before anything is
    /// sealed to it, for the offer entry the inviter's device serves.
    pub(super) opened: Opened,
}

/// Which side of the line a failed check of a hint Data falls on: only damage
/// in flight is worth a retry.
enum Unproven {
    /// A packet that is not what was asked for, does not read, whose
    /// credentials do not open, or whose signature does not verify under them:
    /// damage in flight shows as this, and so does an impostor's packet.
    Damaged(String),
    /// It verifies — its signature checks under credentials that open — but is
    /// not the code's inviter's: another namespace, another anchor, another
    /// device. No damage in flight does that.
    Mismatch(String),
}

impl Unproven {
    fn why(self) -> String {
        match self {
            Unproven::Damaged(why) | Unproven::Mismatch(why) => why,
        }
    }

    /// The refusal of a hint record.
    fn refusal(self) -> IntroRefusal {
        match self {
            Unproven::Damaged(why) => IntroRefusal::Hint { why },
            Unproven::Mismatch(why) => IntroRefusal::HintMismatch { why },
        }
    }
}

impl Inner {
    /// Reach the inviter's device `device` the way a short code says: dial the
    /// one address with no key to expect ([`Introducer::dial_first`]), or take
    /// the relay's name for the Interests' forwarding hint. An address that does
    /// not answer is `NotReady` (retry later).
    pub(super) async fn first_contact(
        &self,
        introducer: &Arc<dyn Introducer>,
        device: &Name,
        contact: &Contact,
    ) -> Result<FirstContact, DataError> {
        match contact {
            Contact::Relay(relay) => Ok(FirstContact {
                hints: vec![relay.clone()],
                linked: None,
            }),
            Contact::Address(addr) => {
                let key = introducer
                    .dial_first(device, *addr, self.config.first_look)
                    .await
                    .map_err(|why| DataError::NotReady {
                        name: device.clone(),
                        why: format!(
                            "the first contact {addr} did not answer ({why}): check the address \
                             and that the inviter's device is on, then retry; or ask for a new code"
                        ),
                    })?;
                Ok(FirstContact {
                    hints: Vec::new(),
                    linked: Some(LinkHint {
                        key,
                        candidates: vec![HintCandidate {
                            kind: HintKind::Advertised,
                            addr: *addr,
                        }],
                    }),
                })
            }
        }
    }

    /// Fetch the hint record `asked` over the first contact `first`, as often
    /// as an offer is fetched ([`OFFER_TRIES`]). `NotReady` when none came.
    pub(super) async fn fetch_hint(
        &self,
        device: &Name,
        asked: &Name,
        first: &FirstContact,
    ) -> Result<Data, DataError> {
        for _ in 0..OFFER_TRIES {
            if let Some(data) = self.fetch_hinted(asked.clone(), &first.hints, None).await {
                return Ok(data);
            }
        }
        Err(DataError::NotReady {
            name: device.clone(),
            why: "the inviter's hint for this offer was not fetched from the first contact \
                  (offline, wrong address or relay, a relay this device cannot reach, or the \
                  offer is closed): retry, check the code, or ask for a new code"
                .into(),
        })
    }

    /// The checks a hint Data — a record or a gone mark — passes before it is
    /// believed, in the order that tells damage from a mismatch: its
    /// `credentials` open (a trust context signed by one of its own anchors,
    /// valid now); its signature is good by the public key of a certificate
    /// those credentials chain to their anchor ([`Opened::authentic_signer`]);
    /// and only then, the packet being authentic, that their namespace is the
    /// one the code's `device` is under (and the `namespace` the code names,
    /// when it does), that their anchor's fingerprint is the code's
    /// `fingerprint`, that the signing key is one of `device`, and that the
    /// context's schema lets it sign this name ([`Opened::signer`]). The
    /// opened credentials and the anchor's whole fingerprint.
    async fn prove_hint(
        &self,
        data: &Data,
        credentials: &[Bytes],
        device: &Name,
        fingerprint: &Fingerprint,
        namespace: Option<&Name>,
    ) -> Result<(Opened, [u8; 32]), Unproven> {
        let Some(opened) = open_credentials(credentials).await else {
            return Err(Unproven::Damaged(
                "credentials: they carry no trust context signed by one of its own anchors, or \
                 no valid certificates"
                    .into(),
            ));
        };
        let Some(signer) = opened.authentic_signer(data).await else {
            return Err(Unproven::Damaged(
                "signer: its signature is not good by a key the credentials chain to their \
                 anchor"
                    .into(),
            ));
        };
        let ns = opened.ctx.namespace().clone();
        if !device.has_prefix(&ns) || namespace.is_some_and(|n| *n != ns) {
            return Err(Unproven::Mismatch(format!(
                "namespace: the credentials are of {ns}, which is not the namespace the code's \
                 device {device} is under"
            )));
        }
        let anchor = opened.fingerprint();
        if !fingerprint.matches(&anchor) {
            return Err(Unproven::Mismatch(
                "anchor: the anchor its credentials carry is not the one the code names, or the \
                 code was made before the keyed fingerprint: ask the inviter for a new one"
                    .into(),
            ));
        }
        if device_of(&signer).as_ref() != Some(device) {
            return Err(Unproven::Mismatch(format!(
                "signer: it is signed by {signer}, which is no key of {device}"
            )));
        }
        if opened.signer(data).await.is_none_or(|(k, _)| k != signer) {
            return Err(Unproven::Mismatch(format!(
                "signer: the credentials' trust schema does not let {signer} sign {}",
                data.name
            )));
        }
        Ok((opened, anchor))
    }

    /// Verify the hint record `data`, the answer to the Interest for `asked`, as
    /// the inviter's device `device` made it, against the code's `fingerprint`
    /// (and its `namespace`, when it names one) — before anything is dialled,
    /// asked or adopted (§3.5): the Data is named exactly as asked and decodes;
    /// it proves itself ([`Self::prove_hint`]), and a gone mark that does so
    /// ends the code as it says ([`IntroRefusal::Closed`],
    /// [`IntroRefusal::Expired`]) while one that does not is
    /// [`IntroRefusal::GoneUnproven`], anyone's; the offer is a log entry of
    /// `device`; and the namespace is judged as an inviter's
    /// ([`Self::overlap`]). A failure before the signature verifies is
    /// [`IntroRefusal::Hint`] (damage in flight cannot be told from it); one
    /// after is [`IntroRefusal::HintMismatch`].
    pub(super) async fn verify_hint(
        &self,
        data: &Data,
        asked: &Name,
        device: &Name,
        fingerprint: &Fingerprint,
        namespace: Option<&Name>,
    ) -> Result<Hinted, IntroRefusal> {
        let damaged = |why: &str| IntroRefusal::Hint { why: why.into() };
        if *data.name != *asked {
            return Err(damaged(
                "wrong name: the packet is not the record asked for",
            ));
        }
        let Some(record) = data
            .content()
            .and_then(|c| HintRecord::decode(c.clone(), self.config.intro.local_candidates).ok())
        else {
            return Err(damaged("wrong record: its content is no hint record"));
        };
        let (offer, key, candidates, relays, credentials) = match record {
            HintRecord::Gone { why, credentials } => {
                // A mark proves itself as a record does, and only then ends the
                // code as it says: any party on the path can make one that
                // does not, so a mark that fails any check is no end of the
                // code, whichever check it fails.
                return match self
                    .prove_hint(data, &credentials, device, fingerprint, namespace)
                    .await
                {
                    Ok(_) => Err(why),
                    Err(unproven) => Err(IntroRefusal::GoneUnproven {
                        why: unproven.why(),
                    }),
                };
            }
            HintRecord::Offered {
                offer,
                key,
                candidates,
                relays,
                credentials,
                ..
            } => (offer, key, candidates, relays, credentials),
        };
        let (opened, anchor) = self
            .prove_hint(data, &credentials, device, fingerprint, namespace)
            .await
            .map_err(Unproven::refusal)?;
        if !parse_log_name(&offer).is_some_and(|l| l.device == *device && l.subject.is_some()) {
            return Err(IntroRefusal::HintMismatch {
                why: format!("offer: {offer} is no log entry of a folder of {device}"),
            });
        }
        // The inviter is proven the one the code names, so its namespace is
        // judged as an inviter's now, before anything is dialled.
        let ns = opened.ctx.namespace().clone();
        if let Some(why) = self.overlap(&ns, &anchor) {
            return Err(IntroRefusal::InviterConflict { inviter: ns, why });
        }
        Ok(Hinted {
            offer,
            link: LinkHint { key, candidates },
            relays,
            opened,
        })
    }
}
