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

use super::intro::{Fingerprint, OFFER_TRIES, local_name, open_credentials};
use super::{Inner, local, open_grant};
use crate::error::DataError;
use crate::intro::{
    Contact, HINT_RELAYS_MAX, HintCandidate, HintKind, HintRecord, IntroRefusal, Introducer,
    LINK_HINT_CANDIDATES_MAX, LinkHint, SECRET_LEN, SHORT_FINGERPRINT_LEN, ShortCode, hint_token,
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
            let st = self.st.lock();
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
            Some(why) => HintRecord::Gone(why),
            None => self.hint_offered(offer, until)?,
        };
        let wire = self
            .sign(DataBuilder::new(name.clone(), &record.encode()).freshness(HINT_CACHE))
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
    /// of (the line then writes it `161=*`), else its first ten octets. An
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
            anchor[..SHORT_FINGERPRINT_LEN].to_vec()
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
}

/// Why a hint record is not taken.
pub(super) enum HintFault {
    /// What the inviter or the join's judgment refuses with: a gone mark (the
    /// offer is expired or closed), or an inviter's namespace this device cannot
    /// take ([`IntroRefusal::InviterConflict`]).
    Refused(IntroRefusal),
    /// It does not prove the inviter's: the reason (a name, the credentials,
    /// the anchor, the signer, the offer).
    Bad(String),
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

    /// Verify the hint record `data`, the answer to the Interest for `asked`, as
    /// the inviter's device `device` made it, against the code's `fingerprint`
    /// (and its `namespace`, when it names one) — before anything is dialled,
    /// asked or adopted (§3.5): the Data is named exactly as asked and decodes;
    /// a gone mark is refused as it says; the credentials open (a trust
    /// context signed by one of its own anchors, valid now); the anchor's
    /// fingerprint is the code's; the namespace is judged as an inviter's
    /// ([`Self::overlap`]); the record is signed by a key of `device` that
    /// chains to that anchor; and the offer is a log entry of `device`.
    pub(super) async fn verify_hint(
        &self,
        data: &Data,
        asked: &Name,
        device: &Name,
        fingerprint: &Fingerprint,
        namespace: Option<&Name>,
    ) -> Result<Hinted, HintFault> {
        let bad = |why: String| Err(HintFault::Bad(why));
        if *data.name != *asked {
            return bad("wrong name: the packet is not the record asked for".into());
        }
        let Some(record) = data
            .content()
            .and_then(|c| HintRecord::decode(c.clone(), self.config.intro.local_candidates).ok())
        else {
            return bad("wrong record: its content is no hint record".into());
        };
        let (offer, key, candidates, relays, credentials) = match record {
            HintRecord::Gone(why) => return Err(HintFault::Refused(why)),
            HintRecord::Offered {
                offer,
                key,
                candidates,
                relays,
                credentials,
                ..
            } => (offer, key, candidates, relays, credentials),
        };
        let Some(opened) = open_credentials(&credentials).await else {
            return bad(
                "credentials: they carry no trust context signed by one of its own anchors, or \
                 no valid certificates"
                    .into(),
            );
        };
        let ns = opened.ctx.namespace().clone();
        if !device.has_prefix(&ns) || namespace.is_some_and(|n| *n != ns) {
            return bad(format!(
                "credentials: they are of {ns}, which is not the namespace the code's device \
                 {device} is under"
            ));
        }
        let anchor = opened.fingerprint();
        if !fingerprint.matches(&anchor) {
            return bad(
                "anchor: the anchor its credentials carry is not the one the code names".into(),
            );
        }
        let signer = opened.signer(data).await;
        if signer
            .as_ref()
            .is_none_or(|(k, _)| device_of(k).as_ref() != Some(device))
        {
            return bad(format!(
                "signer: its signature does not verify as a key of {device} chained to the \
                 anchor"
            ));
        }
        if !parse_log_name(&offer).is_some_and(|l| l.device == *device && l.subject.is_some()) {
            return bad(format!(
                "offer: {offer} is no log entry of a folder of {device}"
            ));
        }
        // The inviter is proven the one the code names, so its namespace is
        // judged as an inviter's now, before anything is dialled.
        if let Some(why) = self.overlap(&ns, &anchor) {
            return Err(HintFault::Refused(IntroRefusal::InviterConflict {
                inviter: ns,
                why,
            }));
        }
        Ok(Hinted {
            offer,
            link: LinkHint { key, candidates },
            relays,
        })
    }
}
