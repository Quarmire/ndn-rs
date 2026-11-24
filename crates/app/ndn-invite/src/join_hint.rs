//! The joiner's half of a short code's hint record (spec §19.2, §19.3 steps 3–5):
//! reaching the inviter by the code's first contact, fetching the record named by a
//! token only the code's holder can ask for, and believing nothing of it until it
//! verifies against the code. What the inviter publishes is `hint.rs`'s.

use std::sync::Arc;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_packet::Data;

use crate::credentials::{Fingerprint, Opened, device_of, open_credentials, overlap};
use crate::error::InviteError;
use crate::host::{HintCandidate, HintKind, Host, LinkHint};
use crate::invites::Inner;
use crate::policy::IntroRefusal;
use crate::short::Contact;
use crate::wire::{HintRecord, parse_offer_name};

/// How many times a join sends its ask (the same parameters each time, so a retry
/// is answered from the answer the inviter keeps for it) before it says the
/// inviter is not reachable. On a lossy path about half of the exchanges fail (the
/// faulty network of spec §18.1: a fifth of the packets lost each way, some held
/// past the Interest's lifetime); eight sends leave about one join in two hundred
/// unanswered, and an inviter really offline is reported after eight lifetimes.
pub(crate) const ASK_TRIES: u32 = 8;

/// How many times a join asks for the offer record, or the hint record: as often
/// as it asks.
pub(crate) const OFFER_TRIES: u32 = ASK_TRIES;

/// What a join reaches the inviter by before it holds the hint record: the
/// forwarding hint its Interests carry, and the link a dialled address made.
pub(crate) struct FirstContact {
    /// The relay a relay contact names, as the Interests' forwarding hint.
    pub(crate) hints: Vec<Name>,
    /// The link [`Host::dial_first`] made, as the hint [`Host::undial`] takes it
    /// down by: its key is what the handshake proved.
    pub(crate) linked: Option<LinkHint>,
}

/// A hint record that verified against its code (§3.5): what the join goes on with.
pub(crate) struct Hinted {
    /// The offer's name `<D>/32=intro/offer/<id>`, of the inviter's device.
    pub(crate) offer: Name,
    /// Where and by which key to dial the inviter now; no candidates: no dial.
    pub(crate) link: LinkHint,
    /// Relays to forward through when a dial fails.
    pub(crate) relays: Vec<Name>,
    /// The record's credentials, opened: what vouches, before anything is sealed to
    /// it, for the offer packet the inviter's device serves.
    pub(crate) opened: Opened,
}

/// Which side of the line a failed check of a hint Data falls on: only damage in
/// flight is worth a retry.
enum Unproven {
    /// A packet that is not what was asked for, does not read, whose credentials do
    /// not open, or whose signature does not verify under them: damage in flight
    /// shows as this, and so does an impostor's packet.
    Damaged(String),
    /// It verifies — its signature checks under credentials that open — but is not
    /// the code's inviter's: another namespace, another anchor, another device. No
    /// damage in flight does that.
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
    /// Reach the inviter's device `device` the way a short code says: dial the one
    /// address with no key to expect ([`Host::dial_first`]), or take the relay's
    /// name for the Interests' forwarding hint. An address that does not answer is
    /// `NotReady` (retry later).
    pub(crate) async fn first_contact(
        &self,
        host: &Arc<dyn Host>,
        device: &Name,
        contact: &Contact,
    ) -> Result<FirstContact, InviteError> {
        match contact {
            Contact::Relay(relay) => Ok(FirstContact {
                hints: vec![relay.clone()],
                linked: None,
            }),
            Contact::Address(addr) => {
                let key = host
                    .dial_first(device, *addr, self.node.config().first_look)
                    .await
                    .map_err(|why| InviteError::NotReady {
                        name: device.clone(),
                        why: format!(
                            "the first contact {addr} did not answer ({why}): check the address \
                             and that the inviter's device is on, then retry; or ask for a new \
                             code"
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

    /// Fetch the hint record `asked` over the first contact `first`, as often as an
    /// offer is fetched ([`OFFER_TRIES`]). `NotReady` when none came.
    pub(crate) async fn fetch_hint(
        &self,
        device: &Name,
        asked: &Name,
        first: &FirstContact,
    ) -> Result<Data, InviteError> {
        for _ in 0..OFFER_TRIES {
            if let Some(data) = self.fetch(asked.clone(), &first.hints, None).await {
                return Ok(data);
            }
        }
        Err(InviteError::NotReady {
            name: device.clone(),
            why: "the inviter's hint for this offer was not fetched from the first contact \
                  (offline, wrong address or relay, a relay this device cannot reach, or the \
                  offer is closed): retry, check the code, or ask for a new code"
                .into(),
        })
    }

    /// The checks a hint Data — a record or a gone mark — passes before it is
    /// believed, in the order that tells damage from a mismatch: its `credentials`
    /// open (a trust context signed by one of its own anchors, valid now); its
    /// signature is good by the public key of a certificate those credentials chain
    /// to their anchor ([`Opened::authentic_signer`]); and only then, the packet
    /// being authentic, that their namespace is the one the code's `device` is
    /// under (and the `namespace` the code names, when it does), that their
    /// anchor's fingerprint is the code's `fingerprint`, that the signing key is
    /// one of `device`, and that the context's schema lets it sign this name
    /// ([`Opened::signer`]). The opened credentials and the anchor's whole
    /// fingerprint.
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
    /// the inviter's device `device` made it, against the code's `fingerprint` (and
    /// its `namespace`, when it names one) — before anything is dialled, asked or
    /// adopted (§3.5): the Data is named exactly as asked and decodes; it proves
    /// itself ([`Self::prove_hint`]), and a gone mark that does so ends the code as
    /// it says ([`IntroRefusal::Closed`], [`IntroRefusal::Expired`]) while one that
    /// does not is [`IntroRefusal::GoneUnproven`], anyone's; the offer is one of
    /// `device`; and the namespace is judged as an inviter's
    /// ([`overlap`]). A failure before the signature verifies is
    /// [`IntroRefusal::Hint`] (damage in flight cannot be told from it); one after
    /// is [`IntroRefusal::HintMismatch`].
    pub(crate) async fn verify_hint(
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
            .and_then(|c| HintRecord::decode(c.clone(), self.policy.local_candidates).ok())
        else {
            return Err(damaged("wrong record: its content is no hint record"));
        };
        let (offer, key, candidates, relays, credentials) = match record {
            HintRecord::Gone { why, credentials } => {
                // A mark proves itself as a record does, and only then ends the code
                // as it says: any party on the path can make one that does not, so a
                // mark that fails any check is no end of the code, whichever check it
                // fails.
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
        if parse_offer_name(&offer).is_none_or(|(d, _)| d != *device) {
            return Err(IntroRefusal::HintMismatch {
                why: format!("offer: {offer} is no offer of {device}"),
            });
        }
        // The inviter is proven the one the code names, so its namespace is judged as
        // an inviter's now, before anything is dialled.
        let ns = opened.ctx.namespace().clone();
        if let Some(why) = overlap(&self.node, &self.policy, &ns, &anchor) {
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
