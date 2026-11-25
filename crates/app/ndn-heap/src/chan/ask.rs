//! The receiver's half of the setup: asking a sender for a channel and judging its answer
//! (docs/specs/channel.md, Judging the sender).
//!
//! The ask is a signed Interest `<sender>/32=chan/<digest>` ([`NodeInner::sign_ask`]); the answer
//! is judged in this order, each step before the next is spent:
//!
//! 1. the Data's name is the Interest's name;
//! 2. the Data verifies as the sender's by the durable rule, from the certificates held and the
//!    at most four the session carries, fetching nothing ([`Judge::validate_asker_packet`]);
//! 3. the key that signed it is a **writer** of the space now, not revoked, not suspected
//!    ([`standing`] with `Who::Writer`): a Data from a reader is [`ChanError::SenderNotWriter`];
//! 4. a refusal is told as it is (it is signed, so it is the sender's word);
//! 5. a sealed space's session names the epoch the sender judged this device by, and it equals the
//!    epoch in force here: an older one is a sender that has not caught up (`StaleEpoch`, ask
//!    again soon), a newer one waits for the record (`NotReady`);
//! 6. the wrapped key opens under this device's recipient secret with the Data's name as the AAD
//!    and is the key the session names (`S_KEY_ID`);
//! 7. the session is installed: new, or the renewal of the channel already held.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::Bytes;
use ndn_app::{AppError, Consumer};
use ndn_foundation_types::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_packet::{Data, Interest, NackReason};
use ndn_security::confidentiality::Sealed;

use super::channels::LIFETIME_DEFAULT;
use super::error::ChanError;
use super::key::ChannelKey;
use super::sessions::RecvSession;
use super::standing::{Who, gate, standing};
use super::wire::{Answer, ChanAsk, ChannelMode, SessionRecord, carrier};
use crate::error::HeapError;
use crate::node::NodeInner;
use crate::rt::Instant;
use crate::trust::Judged;
use crate::wire::{chan_prefix, is_device_name, parse_space_name};

/// How long an ask waits for its answer: the Interest's lifetime and half a second.
const ASK_WAIT: Duration = Duration::from_millis(4500);

/// The lifetime of an ask's Interest.
const ASK_LIFETIME: Duration = Duration::from_secs(4);

/// The octets the ephemeral key takes at the head of a wrapped key.
const EPHEMERAL: usize = 32;

fn not_ready(space: &Name, why: impl Into<String>) -> ChanError {
    ChanError::NotReady {
        space: space.clone(),
        why: why.into(),
    }
}

fn bad_answer(sender: &Name, why: impl Into<String>) -> ChanError {
    ChanError::BadAnswer {
        sender: sender.clone(),
        why: why.into(),
    }
}

impl NodeInner {
    /// Sign the ask `<device>/32=chan/<digest>` whose ApplicationParameters are `params`: an
    /// InterestSignatureInfo with this device's key as the KeyLocator, a SignatureNonce and a
    /// SignatureTime, MustBeFresh, an InterestLifetime of 4 s. The name is the only one this
    /// signs: a signed Interest of this device's key is a command anywhere that trusts the key.
    pub(crate) fn sign_ask(&self, device: &Name, params: &[u8]) -> Result<Bytes, HeapError> {
        let key = self.signer.key_name();
        let mut failed = None;
        let wire = InterestBuilder::new(chan_prefix(device))
            .must_be_fresh()
            .lifetime(ASK_LIFETIME)
            .app_parameters(params.to_vec())
            .sign_sync(self.signer.sig_type(), Some(key), |region| {
                self.signer.sign_sync(region).unwrap_or_else(|e| {
                    failed = Some(e);
                    Bytes::new()
                })
            });
        if let Some(e) = failed {
            return Err(HeapError::local(format!(
                "the device key {key} did not sign the ask ({e}); the layer needs a key that \
                 signs synchronously"
            )));
        }
        self.signatures.fetch_add(1, Ordering::Relaxed);
        Ok(wire)
    }

    /// Ask the device `sender` for its channel of `mode` over `space`, and install the session it
    /// answers with, or renew the one held (the same channel id, a new key and lifetime).
    pub(crate) async fn chan_ask(
        &self,
        space: &Name,
        sender: &Name,
        mode: ChannelMode,
    ) -> Result<Arc<RecvSession>, ChanError> {
        self.chan_ask_since(space, sender, mode, None).await
    }

    /// [`Self::chan_ask`] of a `Window` channel that names the first sequence still needed
    /// (`ASK_SINCE`): the sender replays what its window holds from there. `None` asks for no
    /// replay.
    pub(crate) async fn chan_ask_since(
        &self,
        space: &Name,
        sender: &Name,
        mode: ChannelMode,
        since: Option<u64>,
    ) -> Result<Arc<RecvSession>, ChanError> {
        if parse_space_name(space).is_none() {
            return Err(ChanError::BadName {
                name: space.clone(),
                why: "it is no space name".into(),
            });
        }
        if !is_device_name(sender) {
            return Err(ChanError::BadName {
                name: sender.clone(),
                why: "it is no device name: no keyword or digest component".into(),
            });
        }
        if *sender == self.device {
            return Err(ChanError::NotAllowed {
                space: space.clone(),
                why: "a device does not ask itself for a channel".into(),
            });
        }
        let held = self
            .space_of(space)
            .filter(|s| !s.follower)
            .ok_or_else(|| {
                not_ready(
                    space,
                    "it is not open here as a member; open it (Node::open) so its owner's entries arrive",
                )
            })?;
        let epoch = {
            let log = held.log.lock();
            gate(&log, &self.judge, Who::Listed, "channels").map_err(|e| match e {
                HeapError::NotReady { why, .. } => not_ready(space, why),
                HeapError::NotAllowed { why, .. } => ChanError::NotAllowed {
                    space: space.clone(),
                    why,
                },
                other => ChanError::Local {
                    reason: other.to_string(),
                },
            })?;
            log.sealed().then(|| log.fold.in_force()).flatten()
        };
        let ask = ChanAsk {
            space: space.clone(),
            prefix: Name::root(),
            mode,
            recipient: self.recipient().public(),
            carriers: vec![carrier::DATAGRAM, carrier::STREAM],
            lifetime: LIFETIME_DEFAULT,
            epoch,
            since,
            chain: self.signer_chain(),
        };
        let params = ask.encode().map_err(|e| ChanError::Local {
            reason: format!("the ask cannot be written: {e}"),
        })?;
        let wire = self
            .sign_ask(sender, &params)
            .map_err(|e| ChanError::Local {
                reason: e.to_string(),
            })?;
        let interest = Interest::decode(wire.clone()).map_err(|e| ChanError::Local {
            reason: format!("the signed ask does not decode: {e}"),
        })?;
        let name = (*interest.name).clone();
        // What the judges say now is what a verdict about the answer stands for.
        let generation = self.judge.generation();
        self.chan.stats.asked.bump();
        let data = Consumer::new(Arc::clone(&self.conn))
            .fetch_wire(wire, ASK_WAIT)
            .await
            .map_err(|e| match e {
                AppError::Nacked {
                    reason: Some(NackReason::NoRoute),
                } => ChanError::NotAnswered {
                    sender: sender.clone(),
                },
                AppError::Nacked {
                    reason:
                        Some(NackReason::NotYet | NackReason::Congestion | NackReason::Duplicate),
                } => ChanError::Busy {
                    sender: sender.clone(),
                },
                AppError::Timeout | AppError::Nacked { .. } | AppError::Closed => {
                    ChanError::Unreachable {
                        sender: sender.clone(),
                    }
                }
                other => bad_answer(sender, other.to_string()),
            })?;
        self.chan_take_answer(space, sender, mode, &name, data, generation)
            .await
    }

    /// Judge the answer `data` to the ask named `name`, and install what it gives (the module docs
    /// list the steps). `generation` is what [`Judge::generation`] read before the ask went out.
    pub(crate) async fn chan_take_answer(
        &self,
        space: &Name,
        sender: &Name,
        mode: ChannelMode,
        name: &Name,
        data: Data,
        generation: u64,
    ) -> Result<Arc<RecvSession>, ChanError> {
        // 1. The name.
        if *data.name != *name {
            return Err(bad_answer(
                sender,
                format!("it is named {}, not the ask's {name}", data.name),
            ));
        }
        let content = data
            .content()
            .cloned()
            .ok_or_else(|| bad_answer(sender, "it has no content"))?;
        let answer = Answer::decode(content).map_err(|e| bad_answer(sender, e.to_string()))?;
        // 2. The signature: the sender's, from the certificates held and carried.
        let carried = match &answer {
            Answer::Session(s) => s.certs.clone(),
            Answer::Refusal(_) => Vec::new(),
        };
        let key = match self
            .judge
            .validate_asker_packet(&data, sender, space, &carried)
            .await
        {
            Judged::Valid(v) => v.key,
            Judged::Refused(why) => {
                return Err(bad_answer(
                    sender,
                    format!("its signature is refused ({why}): it is not the sender's"),
                ));
            }
            Judged::Pending(waiting) => {
                return Err(bad_answer(
                    sender,
                    format!(
                        "it cannot be verified from the certificates held and carried ({waiting}); \
                         nothing is fetched for a channel"
                    ),
                ));
            }
        };
        let held = self
            .space_of(space)
            .filter(|s| !s.follower)
            .ok_or_else(|| not_ready(space, "the space is no longer open here as a member"))?;
        let log = held.log.lock();
        // 3. The sender is a writer now.
        if let Err(why) = standing(&log, &self.judge, &key, Who::Writer) {
            return Err(ChanError::SenderNotWriter {
                sender: sender.clone(),
                space: space.clone(),
                why: format!("{why:?}"),
            });
        }
        // 4. A refusal is the sender's word.
        let record = match answer {
            Answer::Refusal(r) => {
                return Err(ChanError::Refused {
                    sender: sender.clone(),
                    code: r.code,
                    text: r.text,
                    retry_ms: r.retry_ms,
                });
            }
            Answer::Session(record) => *record,
        };
        if record.sender != *sender || record.space != *space || record.mode != mode {
            return Err(bad_answer(
                sender,
                "the session is not for the sender, space and mode that were asked",
            ));
        }
        // 5. The epoch.
        if log.sealed() {
            let in_force = log.fold.in_force();
            if record.audience_epoch != in_force {
                let known = record
                    .audience_epoch
                    .as_ref()
                    .is_some_and(|e| log.fold.epoch_body(e).is_some());
                return Err(ChanError::Refused {
                    sender: sender.clone(),
                    code: if known {
                        super::wire::RefusalCode::StaleEpoch
                    } else {
                        super::wire::RefusalCode::NotReady
                    },
                    text: if known {
                        "the sender judged this device by an epoch that is no longer in force \
                         here: it has not caught up with the record; ask again in a moment"
                            .into()
                    } else {
                        "the sender judged this device by an epoch this device does not hold \
                         yet: wait for the record that carries it, then ask again"
                            .into()
                    },
                    retry_ms: if known { 1000 } else { 2000 },
                });
            }
        }
        // 6. The key.
        let channel_key =
            unwrap_session_key(self, &record, name).map_err(|why| bad_answer(sender, why))?;
        // 7. Installed.
        let judged_at = (generation, log.fold.version().load(Ordering::SeqCst));
        let now = Instant::now();
        let existing = self.chan.sessions.get(record.id).filter(|s| {
            s.ended().is_none() && s.space() == space && s.sender() == sender && s.mode() == mode
        });
        let session = match existing {
            Some(session) => {
                session.renewed(&record, channel_key, key, judged_at, now);
                session
            }
            None => {
                let session = Arc::new(RecvSession::new(
                    &record,
                    channel_key,
                    key,
                    Arc::clone(&self.judge),
                    log.fold.version(),
                    judged_at,
                    now,
                ));
                self.chan.sessions.insert(Arc::clone(&session));
                session
            }
        };
        self.chan.stats.installed.bump();
        Ok(session)
    }
}

/// The key `record` wraps to this device, opened under its recipient secret with `name` as the AAD
/// and checked against the key id the session names.
pub(crate) fn unwrap_session_key(
    node: &NodeInner,
    record: &SessionRecord,
    name: &Name,
) -> Result<ChannelKey, String> {
    let opened = open_wrap(node.recipient(), &record.wrap, name)?;
    let key = ChannelKey::from_bytes(opened);
    if key.id() != record.key_id {
        return Err("the key it wraps is not the key it names (S_KEY_ID)".into());
    }
    Ok(key)
}

/// The 32 octets `wrap` (the ephemeral key, then the sealed key) hides, opened with `recipient`
/// and `name` as the AAD.
pub(crate) fn open_wrap(
    recipient: &ndn_security::confidentiality::RecipientKey,
    wrap: &[u8],
    name: &Name,
) -> Result<[u8; 32], String> {
    if wrap.len() <= EPHEMERAL {
        return Err("the wrapped key is too short".into());
    }
    let ephemeral = <[u8; 32]>::try_from(&wrap[..EPHEMERAL]).expect("32 octets");
    let sealed = Sealed::from_bytes(&wrap[EPHEMERAL..])
        .map_err(|e| format!("the wrapped key is malformed ({e})"))?;
    let key = recipient
        .unwrap_ck(&ephemeral, &sealed, &name.encode_to_tlv())
        .map_err(|_| {
            "the key does not open under this device's recipient secret with the Data's name \
             as its AAD: it was wrapped to another device, or to another name"
                .to_string()
        })?;
    Ok(*key.expose())
}
