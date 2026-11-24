//! The hint record of a short code, as the inviter serves it (spec §19.2, §19.5): what
//! an inviter device publishes about an open offer, by a name only the code's holder
//! can ask for. The inviter makes the record **on request** from the host's current
//! link hint and its namespace's relays, signs it with the device key through the node,
//! keeps the signed record a few seconds ([`HINT_CACHE`]) and answers a signed gone
//! mark once the offer is not open. The joiner's half — fetching the record over the
//! first contact and trusting nothing of it until it verifies against the code — is
//! `join.rs`'s.

use std::time::Duration;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_heap::Timestamp;
use ndn_packet::encode::DataBuilder;
use ndn_security::self_certifying::self_certifying_digest;
use ndn_trust_envelope::HINT_RELAYS_MAX;
#[cfg(not(target_arch = "wasm32"))]
use tokio::time::Instant;
#[cfg(target_arch = "wasm32")]
use web_time::Instant;

use crate::error::InviteError;
use crate::host::{LINK_HINT_CANDIDATES_MAX, LinkHint};
use crate::invites::{Inner, State};
use crate::policy::IntroRefusal;
use crate::proofs::{SECRET_LEN, hint_token, keyed_fingerprint};
use crate::sealed::wrap_note;
use crate::short::{Contact, ShortCode};
use crate::store;
use crate::wire::{HINT_TOKEN_LEN, HintRecord, OfferId, parse_hint_name};

/// How long a signed hint record is answered again as it is, and its
/// `FreshnessPeriod`: a signature is paid at most once in this time for an offer,
/// however often the token is asked for, and a cache does not hold an address past the
/// time this device would give it. The record itself is made from what the host knows
/// when it is asked, so a moved address is current within this time.
pub(crate) const HINT_CACHE: Duration = Duration::from_secs(5);

/// A hint record signed and kept for [`HINT_CACHE`]: what it said (`None`: the
/// record, else the gone mark's reason) and the Data.
pub(crate) struct HintServed {
    at: Instant,
    state: Option<IntroRefusal>,
    wire: Bytes,
}

/// What the inviter keeps of the packets it signed for hint tokens
/// ([`State::hint_served`]) lives [`HINT_CACHE`] and no longer: whatever lapsed is
/// dropped whenever a hint Interest is answered or refused, a token is kept, or an
/// offer closes. What stays is the token of each own offer ([`State::hints`]), for as
/// long as the offer is held: §19.5 serves a gone mark for the token of a closed or
/// expired offer, which needs the token known, and the offers themselves are never
/// pruned.
fn sweep_hint_served(st: &mut State) {
    st.hint_served
        .retain(|_, served| served.at.elapsed() < HINT_CACHE);
}

impl Inner {
    /// The offer `id` closed: the packet kept for its token (the record it would answer
    /// again, within [`HINT_CACHE`]) is dropped at once, and the next ask signs the
    /// gone mark.
    pub(crate) fn drop_hint_served(&self, id: &OfferId) {
        let mut st = self.state.lock();
        let st = &mut *st;
        st.hint_served
            .retain(|token, _| st.hints.get(token) != Some(id));
        sweep_hint_served(st);
    }

    /// Keep the hint `token` of the own offer `id`, durably (wrapped to the device's
    /// recipient key under the note's name, so a writer of the store cannot make it
    /// read) and then in memory: from now on its record is served
    /// ([`Self::hint_packet`]). The 16 octets are the first of the 32 a wrapped
    /// content key holds.
    async fn keep_hint(
        &self,
        id: &OfferId,
        token: [u8; HINT_TOKEN_LEN],
    ) -> Result<(), InviteError> {
        let key = store::hint_key(id);
        let mut secret = [0u8; 32];
        secret[..HINT_TOKEN_LEN].copy_from_slice(&token);
        let note = wrap_note(self.node.recipient(), &key, secret).map_err(|e| {
            InviteError::local(format_args!(
                "the offer's hint token could not be wrapped: {e}"
            ))
        })?;
        store::put_durable(&self.store, key, note).await?;
        let mut st = self.state.lock();
        sweep_hint_served(&mut st);
        st.hints.insert(token, *id);
        Ok(())
    }

    /// What this device answers for `name`, `<D>/32=hint/<token>`: for a token of one of
    /// its own offers, the signed [`HintRecord`] while the offer is open (not expired by
    /// this device's clock, not closed) — or always, when
    /// [`IntroPolicy::hint_while_open`](crate::IntroPolicy) is off — and else a signed
    /// gone mark of why not; for any other name `None` (a Nack): a token nobody holds
    /// is neither a record nor a gone mark, so a prober learns nothing.
    pub(crate) fn hint_packet(&self, name: &Name) -> Option<Bytes> {
        let (device, token) = parse_hint_name(name)?;
        if device != *self.node.name() {
            return None;
        }
        let now = self.now();
        let (id, body) = {
            let mut st = self.state.lock();
            sweep_hint_served(&mut st);
            let id = *st.hints.get(&token)?;
            (id, st.offers.get(&id)?.body.clone())
        };
        let state = if !self.policy.hint_while_open {
            None
        } else if body.until <= now {
            Some(IntroRefusal::Expired)
        } else if self.offer_closed(&id, &body) {
            Some(IntroRefusal::Closed)
        } else {
            None
        };
        if let Some(s) = self
            .state
            .lock()
            .hint_served
            .get(&token)
            .filter(|s| s.state == state && s.at.elapsed() < HINT_CACHE)
        {
            return Some(s.wire.clone());
        }
        let credentials = crate::credentials::credentials(&self.node, &*self.host).ok()?;
        let record = match state.clone() {
            Some(why) => HintRecord::Gone { why, credentials },
            None => self.hint_offered(&id, body.until, credentials)?,
        };
        // A record is held by a cache for [`HINT_CACHE`]; a gone mark not at all: a mark
        // that a cache kept could outlive the inviter's say, and an impostor's would sit
        // there too.
        let fresh = if state.is_some() {
            Duration::ZERO
        } else {
            HINT_CACHE
        };
        let wire = self
            .node
            .sign_packet(DataBuilder::new(name.clone(), &record.encode()).freshness(fresh))
            .ok()?;
        self.state.lock().hint_served.insert(
            token,
            HintServed {
                at: Instant::now(),
                state,
                wire: wire.clone(),
            },
        );
        Some(wire)
    }

    /// The record of the open offer `id`: the host's link hint now (its key and up to
    /// [`LINK_HINT_CANDIDATES_MAX`] addresses; with none, this device's key and no
    /// address), the relays its namespace advertises, the offer's expiry and this
    /// device's credentials, as an answer carries them.
    fn hint_offered(
        &self,
        id: &OfferId,
        until: Timestamp,
        credentials: Vec<Bytes>,
    ) -> Option<HintRecord> {
        let (key, mut candidates) = match self.host.link_hint() {
            Some(h) => (h.key, h.candidates),
            None => (self.own_key_digest(), Vec::new()),
        };
        candidates.truncate(LINK_HINT_CANDIDATES_MAX);
        Some(HintRecord::Offered {
            offer: crate::wire::offer_name(self.node.name(), id),
            key,
            candidates,
            relays: self.relays(),
            until,
            credentials,
        })
    }

    /// The relays the device's namespace advertises, by name, at most
    /// [`HINT_RELAYS_MAX`].
    fn relays(&self) -> Vec<Name> {
        self.node
            .validator()
            .keyring()
            .context_for(self.node.name())
            .relays()
            .iter()
            .take(HINT_RELAYS_MAX)
            .map(|r| r.device.clone())
            .collect()
    }

    /// The short code of the own offer `id`, and with it the hint record it names:
    /// `Ok(Ok(text))` once its token is kept durably, `Ok(Err(why))` — nothing published
    /// — when the policy is off ([`IntroPolicy::short_code`](crate::IntroPolicy)), when
    /// there is no first contact (a dialable candidate of the host's link `hint` under
    /// `local_candidates`, else a relay of the namespace), or when the line is wider than
    /// `short_width`. The fingerprint is the whole `anchor` when this device's namespace
    /// is the self-certifying one it is the digest of (the line then writes it
    /// `161=*`), else the 10 octets of the tag [`keyed_fingerprint`] makes of it with
    /// the offer's `secret`. An address or relay that makes the line too wide gives way
    /// to the next.
    pub(crate) async fn short_code(
        &self,
        id: &OfferId,
        secret: &[u8; SECRET_LEN],
        anchor: &[u8; 32],
        hint: Option<&LinkHint>,
    ) -> Result<Result<String, String>, InviteError> {
        let policy = &self.policy;
        if !policy.short_code {
            return Ok(Err(
                "short codes are off (IntroPolicy::short_code): this offer has its link and \
                 its words"
                    .into(),
            ));
        }
        // The first contact is the first of the hint's order whose line fits: the host's
        // dialable candidates, then the namespace's relays.
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
        contacts.extend(self.relays().into_iter().map(Contact::Relay));
        if contacts.is_empty() {
            return Ok(Err(
                "no short code: the host gives no first contact to put in it (a link hint with \
                 an address that can be dialled from elsewhere — Host::link_hint, and loopback \
                 or link-local only with IntroPolicy::local_candidates — or a relay advertised \
                 by the namespace's trust context); give the link, or the words with the \
                 offer's name"
                    .into(),
            ));
        }
        let whole = matches!(
            self_certifying_digest(self.node.namespace()),
            Ok(Some(d)) if d == *anchor
        );
        let fingerprint = if whole {
            anchor.to_vec()
        } else {
            keyed_fingerprint(secret, anchor).to_vec()
        };
        let device = self.node.name();
        let mut narrowest = usize::MAX;
        let tried = contacts.len();
        for contact in contacts {
            let code = ShortCode {
                device: device.clone(),
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
                self.keep_hint(id, hint_token(secret)).await?;
                return Ok(Ok(text));
            }
            narrowest = narrowest.min(width);
        }
        Ok(Err(format!(
            "no short code: with {device} (and {tried} first contact{} tried) its line would be \
             at least {narrowest} characters, past IntroPolicy::short_width ({}): the names are \
             the owner's choice, so give the link, or the words with the offer's name",
            if tried == 1 { "" } else { "s" },
            policy.short_width
        )))
    }
}
