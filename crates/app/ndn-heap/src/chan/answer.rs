//! The sender's half of the setup: judging an ask `<this device>/32=chan/<digest>` and answering
//! it with a signed session or a signed refusal (docs/specs/channel.md, Judging the asker).
//!
//! The steps run cheapest first, so a stranger costs nothing and a member costs one signature
//! verification. Each step that refuses without a word answers a Nack, and nothing is signed for
//! it:
//!
//! 1. the name is `<this device>/32=chan/<digest>`, the ApplicationParameters are at most 8 KiB
//!    and hash to the digest, the ask parses;
//! 2. the KeyLocator names a device key and the space is open here as a member;
//! 3. the key **stands** ([`standing`], `Who::Listed`: a person the space lists, owner-capable,
//!    not revoked, not suspected) by the entries held now: else `NoRoute`;
//! 4. the asker key's token bucket (4 a second, burst 8): else `Congestion`;
//! 5. the signature verifies from the certificates held and the at most four carried, fetching
//!    nothing ([`Judge::validate_interest`]): `Pending` is `NotYet`, a refusal `NoRoute`;
//! 6. the ask is no replay (the replay guard of the signed Interest): `Duplicate`.
//!
//! Then the asker is a verified member and may be answered with a **signed** record:
//! standing again (the entries may have moved while the signature was checked), this device a
//! writer of the space, a sealed space's audience of the epoch in force, the carriers, the caps;
//! a refusal here is a signed `CHAN_REFUSAL` that says why and what to do. Otherwise the key is
//! wrapped to the ask's recipient and the session is signed, `FreshnessPeriod` 0.

use std::time::Duration;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_packet::encode::DataBuilder;
use ndn_packet::{CachePolicyType, Interest, LpHeaders, NackReason};
use ndn_security::ReplayCheck;
use ndn_security::Signer;
use ndn_security::cert_name::key_name_of;
use ndn_security::confidentiality::{ContentKey, wrap_ck_to};
use sha2::{Digest, Sha256};

use super::aead::Aead;

use super::channels::{Admitted, Asker, Cap};
use super::key::ChannelKey;
use super::standing::{Who, gate, standing};
use super::wire::{
    ASK_MAX, CarrierOffer, ChanAsk, RefusalCode, RefusalRecord, SessionRecord, Window, carrier,
};
use crate::error::HeapError;
use crate::node::NodeInner;
use crate::rt::Instant;
use crate::seal;
use crate::trust::InterestJudged;
use crate::wire::{device_of, parse_chan_name, parse_space_name};

/// The checkpoint period a session names (milliseconds): the default of the checkpoint stage.
pub(crate) const CKPT_MS: u64 = 20;

/// The largest frame a session names for a datagram carrier: what one QUIC datagram carries at
/// the smallest path MTU.
pub(crate) const FRAME_MAX: u64 = 1200;

/// What a `Window` channel replays when the asker asked for no more: 256 messages, 1 MiB, 10 s.
pub(crate) const WINDOW: Window = Window {
    messages: 256,
    bytes: 1024 * 1024,
    ms: 10_000,
};

/// The octets of a wrapped key: the ephemeral key, the nonce, the tag and the key.
const WRAP_LEN: usize = 32 + 12 + 16 + 32;

/// What the sender answers an ask with.
#[derive(Debug)]
pub(crate) enum ChanAnswer {
    /// A signed Data: a session or a refusal. Send it with [`no_cache`].
    Data(Bytes),
    /// A Nack and nothing else.
    Nack(NackReason),
}

/// `wire`, a Data, in an NDNLPv2 packet that says `CachePolicy = NoCache`: nothing of a channel's
/// setup is ever cached.
pub(crate) fn no_cache(wire: &Bytes) -> Bytes {
    ndn_packet::lp::encode_lp_with_headers(
        wire,
        &LpHeaders {
            cache_policy: Some(CachePolicyType::NoCache),
            ..LpHeaders::default()
        },
    )
}

/// A signed Data `name` with `content`, `FreshnessPeriod` 0, by `signer`.
fn signed(signer: &dyn Signer, name: &Name, content: &[u8]) -> Result<Bytes, HeapError> {
    let builder = DataBuilder::new(name.clone(), content).freshness(Duration::ZERO);
    seal::sign(builder, signer).map_err(HeapError::local)
}

/// The signed session Data `name` for the receiver whose recipient key is `recipient`: `record`
/// with its key wrapped to that key, the Name TLV of the Data as the AAD, so the key opens only
/// under that name and only with that recipient's secret.
pub(crate) fn session_data(
    signer: &dyn Signer,
    name: &Name,
    mut record: SessionRecord,
    key: &ChannelKey,
    recipient: &[u8; 32],
) -> Result<Bytes, HeapError> {
    let content = ContentKey::from_bytes(*key.expose());
    let (ephemeral, sealed) = wrap_ck_to(recipient, &content, &name.encode_to_tlv())
        .map_err(|e| HeapError::local(format!("the key cannot be wrapped to the asker: {e}")))?;
    let mut wrap = ephemeral.to_vec();
    wrap.extend_from_slice(&sealed.to_bytes());
    record.wrap = Bytes::from(wrap);
    record.key_id = key.id();
    let content = record
        .encode()
        .map_err(|e| HeapError::local(format!("the session cannot be written: {e}")))?;
    signed(signer, name, &content)
}

/// The signed refusal Data `name`.
pub(crate) fn refusal_data(
    signer: &dyn Signer,
    name: &Name,
    refusal: &RefusalRecord,
) -> Result<Bytes, HeapError> {
    signed(signer, name, &refusal.encode())
}

/// How a verdict that is not an answer ends.
enum Verdict {
    /// Nack, nothing signed.
    Nack(NackReason),
    /// A signed refusal.
    Refuse(RefusalRecord),
    /// The asker is admitted: sign the session.
    Admit(Box<Admitted>, ChanAsk),
}

fn refuse(code: RefusalCode, text: impl Into<String>, retry_ms: u64) -> Verdict {
    Verdict::Refuse(RefusalRecord {
        code,
        text: text.into(),
        retry_ms,
    })
}

impl NodeInner {
    /// Answer one ask (see the module docs for the order of the judgement).
    pub(crate) async fn chan_answer(&self, interest: &Interest) -> ChanAnswer {
        let name = (*interest.name).clone();
        match self.chan_judge(interest).await {
            Verdict::Nack(reason) => ChanAnswer::Nack(reason),
            Verdict::Refuse(refusal) => {
                self.chan.stats.refused.bump();
                match refusal_data(&*self.signer, &name, &refusal) {
                    Ok(wire) => {
                        self.signatures
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        ChanAnswer::Data(wire)
                    }
                    Err(e) => {
                        tracing::warn!("a channel refusal cannot be signed: {e}");
                        ChanAnswer::Nack(NackReason::NoRoute)
                    }
                }
            }
            Verdict::Admit(admitted, ask) => match self.chan_session(&name, &admitted, &ask) {
                Ok(wire) => {
                    self.signatures
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    self.chan.stats.answered.bump();
                    ChanAnswer::Data(wire)
                }
                Err(e) => {
                    tracing::warn!("a channel session cannot be signed: {e}");
                    ChanAnswer::Nack(NackReason::NoRoute)
                }
            },
        }
    }

    /// The signed session for `ask`, as `admitted` gives it.
    fn chan_session(
        &self,
        name: &Name,
        admitted: &Admitted,
        ask: &ChanAsk,
    ) -> Result<Bytes, HeapError> {
        let carriers = [carrier::DATAGRAM, carrier::STREAM]
            .into_iter()
            .filter(|kind| ask.carriers.contains(kind))
            .map(|kind| CarrierOffer {
                kind,
                params: Bytes::new(),
            })
            .collect();
        // What the sender says of itself (its name table, its window, its frame size and next
        // sequence), and the frames that follow the session on the stream, queued now.
        let terms = self.chan_tx_welcome(ask, admitted);
        let mut session = SessionRecord {
            id: admitted.id,
            sender: self.device.clone(),
            space: ask.space.clone(),
            mode: ask.mode,
            key_epoch: admitted.key_epoch,
            key_id: [0; 8],
            wrap: Bytes::new(),
            aead: Aead::preferred(),
            carriers,
            table: terms.table,
            ckpt_ms: CKPT_MS,
            window: terms.window,
            lifetime: admitted.lifetime,
            audience_epoch: admitted.audience.clone(),
            frame_max: terms.frame_max,
            seq: terms.seq,
            certs: self.judge.chain_of(self.signer.key_name()),
        };
        // A session over its limit (counted with the wrapped key it will carry) gives up the
        // certificates first: the receiver then judges the sender from the certificates it
        // holds, and says so if it cannot.
        let sized = SessionRecord {
            wrap: Bytes::from(vec![0; WRAP_LEN]),
            ..session.clone()
        };
        if sized.encode().is_err() {
            session.certs.clear();
        }
        session_data(&*self.signer, name, session, &admitted.key, &ask.recipient)
    }

    async fn chan_judge(&self, interest: &Interest) -> Verdict {
        let stats = &self.chan.stats;
        stats.asks.bump();
        let nack = |reason| Verdict::Nack(reason);

        // 1. The name, the size, the digest, the ask.
        let Some((device, digest)) = parse_chan_name(&interest.name) else {
            stats.malformed.bump();
            return nack(NackReason::NoRoute);
        };
        let Some(params) = interest.app_parameters().cloned() else {
            stats.malformed.bump();
            return nack(NackReason::NoRoute);
        };
        if device != self.device {
            return nack(NackReason::NoRoute);
        }
        if params.len() > ASK_MAX {
            stats.oversize.bump();
            return nack(NackReason::NoRoute);
        }
        let digest_holds = interest
            .parameters_portion()
            .is_some_and(|portion| Sha256::digest(&portion).as_slice() == digest);
        if !digest_holds {
            stats.malformed.bump();
            return nack(NackReason::NoRoute);
        }
        let Ok(ask) = ChanAsk::decode(params) else {
            stats.malformed.bump();
            return nack(NackReason::NoRoute);
        };
        let Some(sig_info) = interest.sig_info() else {
            stats.malformed.bump();
            return nack(NackReason::NoRoute);
        };

        // 2. The key, the space.
        let Some(locator) = sig_info.key_locator_name() else {
            stats.malformed.bump();
            return nack(NackReason::NoRoute);
        };
        let key = key_name_of(&locator);
        let Some(asker_device) = device_of(&key) else {
            stats.malformed.bump();
            return nack(NackReason::NoRoute);
        };
        if parse_space_name(&ask.space).is_none() {
            stats.malformed.bump();
            return nack(NackReason::NoRoute);
        }
        let Some(held) = self.space_of(&ask.space).filter(|s| !s.follower) else {
            stats.strangers.bump();
            return nack(NackReason::NoRoute);
        };

        // 3. Standing, offline, by the entries held now.
        if standing(&held.log.lock(), &self.judge, &key, Who::Listed).is_err() {
            stats.strangers.bump();
            return nack(NackReason::NoRoute);
        }

        // 4. The asker's bucket.
        let now = Instant::now();
        if !self.chan.channels.throttle(&key, now) {
            stats.throttled.bump();
            return nack(NackReason::Congestion);
        }

        // 5. The signature: the one expensive step.
        let generation = self.judge.generation();
        match self
            .judge
            .validate_interest(&ask.space, interest, &key, &ask.chain)
            .await
        {
            InterestJudged::Valid => {}
            InterestJudged::Pending(waiting) => {
                tracing::debug!(%key, "ask not judged yet: {waiting}");
                stats.pending.bump();
                return nack(NackReason::NotYet);
            }
            InterestJudged::Refused(why) => {
                tracing::debug!(%key, "ask refused: {why}");
                stats.unverified.bump();
                return nack(NackReason::NoRoute);
            }
        }

        // 6. A replay.
        match self.chan.replay.check(sig_info) {
            ReplayCheck::Fresh => {}
            ReplayCheck::Replay => {
                stats.replays.bump();
                return nack(NackReason::Duplicate);
            }
            ReplayCheck::NoAntiReplayFields => {
                stats.malformed.bump();
                return nack(NackReason::NoRoute);
            }
        }

        // The asker is a verified member: what follows is answered with a signed record. The
        // entries are read again, under one lock, as the key that signed the ask: they may have
        // moved while the signature was checked.
        let log = held.log.lock();
        let Ok(person) = standing(&log, &self.judge, &key, Who::Listed) else {
            stats.strangers.bump();
            return nack(NackReason::NoRoute);
        };
        if gate(&log, &self.judge, Who::Writer, "channels").is_err() {
            // This device is no writer: it has no channel to give.
            self.chan.wake();
            return nack(NackReason::NoRoute);
        }
        let audience = if log.sealed() {
            let Some(in_force) = log.fold.in_force() else {
                return refuse(
                    RefusalCode::NotReady,
                    "this sender holds no epoch of the sealed space in force yet: ask again in a \
                     moment, when the owner's epoch entry has reached it",
                    2000,
                );
            };
            if let Some(asked) = &ask.epoch
                && *asked != in_force
            {
                return if log.fold.epoch_body(asked).is_none() {
                    refuse(
                        RefusalCode::StaleEpoch,
                        "this sender has not seen the epoch you hold yet: ask again in a moment",
                        1000,
                    )
                } else {
                    refuse(
                        RefusalCode::NotReady,
                        "this sender is on a newer epoch than the one you hold: wait for the \
                         record that carries it, then ask again",
                        2000,
                    )
                };
            }
            if !log.fold.audience(&in_force).contains(&person) {
                return refuse(
                    RefusalCode::NotAudience,
                    "your person is not in the audience of the sealed space's epoch in force: \
                     ask the owner to add you as a reader, or to write an epoch that lists you",
                    0,
                );
            }
            Some(in_force)
        } else {
            None
        };
        if ask.mode.needs_stream() && !ask.carriers.contains(&carrier::STREAM) {
            return refuse(
                RefusalCode::NoStream,
                "a Reliable or Window channel needs a stream carrier and the ask lists none: ask \
                 with Latest, or ask from a link that carries streams (or put the value instead)",
                0,
            );
        }
        let judged_at = (
            generation,
            log.fold.version().load(std::sync::atomic::Ordering::SeqCst),
        );
        let asker = Asker {
            device: &asker_device,
            key: &key,
            wanted: ask.lifetime,
        };
        match self
            .chan
            .channels
            .admit(&ask.space, ask.mode, &asker, audience, judged_at, now)
        {
            Ok(admitted) => {
                if admitted.rekeyed {
                    self.chan.stats.rekeys.bump();
                }
                drop(log);
                Verdict::Admit(Box::new(admitted), ask)
            }
            Err(Cap::Channels) => refuse(
                RefusalCode::TooMany,
                "this sender keeps as many channels as it may (64): ask again later, or ask a \
                 device that sends less",
                30_000,
            ),
            Err(Cap::Receivers) => refuse(
                RefusalCode::TooMany,
                "this channel has as many receivers as it may (256): ask again later, when a \
                 receiver has gone",
                30_000,
            ),
        }
    }
}
