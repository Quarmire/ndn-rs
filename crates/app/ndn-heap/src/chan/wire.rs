//! The records of the channel setup (`docs/specs/channel.md`, §Setup and §TLV tables): the ask a
//! receiver sends in its ApplicationParameters, the session a sender answers with, the refusal it
//! answers with instead, and the announce a sender pushes into a space's sync group.
//!
//! TLV-TYPEs are the block 0x0660–0x06BF. Odd is critical: a decoder refuses a type it does not
//! know. Even is skippable and reserved for additive fields, as in heap.md §3.4. Numbers are
//! NonNegativeIntegers. A record is at most [`ASK_MAX`] (the ask) or [`SESSION_MAX`] (the session)
//! octets; the certificates an ask or a session carries are bounded as a grant ask's are.

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_tlv::{TlvReader, TlvWriter};

use super::aead::Aead;
use crate::wire::{ASKER_CHAIN_MAX, ASKER_CHAIN_OCTETS_MAX};
use crate::wire::{
    EpochId, WireError, each, fields, once, only, read_array, read_epoch_id, read_name, read_nni,
    tlv, write_epoch_id, write_nni,
};

/// `{ ASK_SPACE, ASK_PREFIX, ASK_MODE, ASK_RECIPIENT, ASK_CARRIERS, ASK_LIFETIME, ASK_EPOCH?,
/// ASK_SINCE?, ASKER_CERT* }`: the ApplicationParameters of an ask.
pub(crate) const CHAN_ASK: u64 = 0x0661;
/// Name: the space.
pub(crate) const ASK_SPACE: u64 = 0x0663;
/// Name: the path prefix the receiver wants (a filter and a hint for the table).
pub(crate) const ASK_PREFIX: u64 = 0x0665;
/// 1 `Latest`, 2 `Reliable`, 3 `Window`.
pub(crate) const ASK_MODE: u64 = 0x0667;
/// 32 octets: the asker's X25519 recipient key.
pub(crate) const ASK_RECIPIENT: u64 = 0x0669;
/// The carriers the asker can use: a list of kind octets.
pub(crate) const ASK_CARRIERS: u64 = 0x066B;
/// NonNegativeInteger: seconds the asker wants (at most 86,400, clamped by the sender).
pub(crate) const ASK_LIFETIME: u64 = 0x066D;
/// EpochId the asker holds in force (sealed spaces).
pub(crate) const ASK_EPOCH: u64 = 0x066F;
/// `Window` only: the first sequence the asker still needs replayed.
pub(crate) const ASK_SINCE: u64 = 0x0671;
/// The Content of the answering Data.
pub(crate) const CHAN_SESSION: u64 = 0x0673;
/// 8 octets: the channel id.
pub(crate) const S_ID: u64 = 0x0675;
/// Name: the sender's device.
pub(crate) const S_SENDER: u64 = 0x0677;
/// Name: the space.
pub(crate) const S_SPACE: u64 = 0x0679;
/// As [`ASK_MODE`].
pub(crate) const S_MODE: u64 = 0x067B;
/// NonNegativeInteger: counts re-keys; the frame header carries its low 8 bits.
pub(crate) const S_KEY_EPOCH: u64 = 0x067D;
/// 8 octets: the first 8 of HKDF-SHA256(K, `ndn-channel/id/1`).
pub(crate) const S_KEY_ID: u64 = 0x067F;
/// 32 octets ephemeral X25519 key, then the sealed key (`nonce ‖ tag ‖ ciphertext`).
pub(crate) const S_WRAP: u64 = 0x0681;
/// 1 AES-256-GCM, 2 ChaCha20-Poly1305.
pub(crate) const S_AEAD: u64 = 0x0683;
/// Repeatable: a kind octet, then its parameters.
pub(crate) const S_CARRIER: u64 = 0x0685;
/// `{ S_BIND* }`: at most 64 binds and 4 KiB.
pub(crate) const S_TABLE: u64 = 0x0687;
/// `{ B_ID, B_NAME }`.
pub(crate) const S_BIND: u64 = 0x0689;
/// NonNegativeInteger: checkpoint period in ms.
pub(crate) const S_CKPT_MS: u64 = 0x068B;
/// `{ W_MESSAGES, W_BYTES, W_MS }`: `Window` mode.
pub(crate) const S_WINDOW: u64 = 0x068D;
/// NonNegativeInteger: seconds, from receipt, on the receiver's monotonic clock.
pub(crate) const S_LIFETIME: u64 = 0x068F;
/// EpochId (sealed spaces).
pub(crate) const S_AUDIENCE_EPOCH: u64 = 0x0691;
/// NonNegativeInteger: the largest frame the sender will send on a datagram carrier.
pub(crate) const S_FRAME_MAX: u64 = 0x0693;
/// NonNegativeInteger: the next sequence the sender will use.
pub(crate) const S_SEQ: u64 = 0x0695;
/// Repeatable, at most 4 and 6,144 octets in all: a certificate Data of the sender's chain.
pub(crate) const S_CERT: u64 = 0x0697;
/// The Content of an answering Data that refuses: `{ R_CODE, R_TEXT, R_RETRY }`.
pub(crate) const CHAN_REFUSAL: u64 = 0x0699;
/// NonNegativeInteger: a [`RefusalCode`].
pub(crate) const R_CODE: u64 = 0x069B;
/// UTF-8, at most 256 octets: why, and what to do.
pub(crate) const R_TEXT: u64 = 0x069D;
/// NonNegativeInteger: milliseconds before asking again is of use.
pub(crate) const R_RETRY: u64 = 0x069F;
/// `{ S_SENDER, ASK_MODE+ }`: the ApplicationParameters of an announce.
pub(crate) const CHAN_ANNOUNCE: u64 = 0x06A1;
/// NonNegativeInteger: a name id.
pub(crate) const B_ID: u64 = 0x06A3;
/// Name: what the id names.
pub(crate) const B_NAME: u64 = 0x06A5;
/// NonNegativeInteger: messages a window replays.
pub(crate) const W_MESSAGES: u64 = 0x06A7;
/// NonNegativeInteger: octets a window replays.
pub(crate) const W_BYTES: u64 = 0x06A9;
/// NonNegativeInteger: milliseconds a window replays.
pub(crate) const W_MS: u64 = 0x06AB;

/// The most octets of an ask's ApplicationParameters.
pub(crate) const ASK_MAX: usize = 8 * 1024;
/// The most octets of a session's Content.
pub(crate) const SESSION_MAX: usize = 8000;
/// The most seconds a session may be asked to last.
pub(crate) const LIFETIME_MAX: u64 = 86_400;
/// The most binds a session carries.
pub(crate) const TABLE_BINDS_MAX: usize = 64;
/// The most octets of the binds a session carries.
pub(crate) const TABLE_OCTETS_MAX: usize = 4 * 1024;
/// The most octets of a refusal's text.
pub(crate) const TEXT_MAX: usize = 256;
/// The most carrier kinds an ask lists.
const CARRIERS_MAX: usize = 16;
/// The most octets of one certificate an ask or a session carries (the held-copy limit).
const CERT_MAX: usize = 4096;

/// The carrier kinds ([`ASK_CARRIERS`], [`S_CARRIER`]).
pub(crate) mod carrier {
    /// A datagram of the link's connection.
    pub(crate) const DATAGRAM: u8 = 1;
    /// The link's unidirectional stream.
    pub(crate) const STREAM: u8 = 2;
    /// Frame bytes through any face.
    #[allow(dead_code)] // wire vocabulary: stage 4's faces offer it
    pub(crate) const FACE_BYTES: u8 = 3;
    /// A raw L2 face.
    #[allow(dead_code)] // wire vocabulary: stage 4's L2 face offers it
    pub(crate) const L2: u8 = 4;
    /// A shared-memory ring.
    #[allow(dead_code)] // wire vocabulary: a stage 4+ shared-memory face offers it
    pub(crate) const RING: u8 = 5;
}

/// How a channel treats a message the carrier cannot take now (`docs/specs/channel.md`, Modes).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ChannelMode {
    /// Newest per name; drop the oldest; never blocks.
    Latest,
    /// Ordered; blocks the sender.
    Reliable,
    /// Reliable, plus a replayable history.
    Window,
}

impl ChannelMode {
    /// The mode's code on the wire.
    pub(crate) fn code(self) -> u64 {
        match self {
            ChannelMode::Latest => 1,
            ChannelMode::Reliable => 2,
            ChannelMode::Window => 3,
        }
    }

    /// The mode a code names.
    pub(crate) fn from_code(code: u64) -> Result<ChannelMode, WireError> {
        match code {
            1 => Ok(ChannelMode::Latest),
            2 => Ok(ChannelMode::Reliable),
            3 => Ok(ChannelMode::Window),
            _ => Err(WireError::Malformed(
                "a channel mode is 1 (Latest), 2 (Reliable) or 3 (Window)",
            )),
        }
    }

    /// Whether the mode needs a stream (it may not drop).
    pub(crate) fn needs_stream(self) -> bool {
        self != ChannelMode::Latest
    }
}

/// Why a sender refuses an ask it judged (the `R_CODE` field of a `CHAN_REFUSAL`, channel.md §7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusalCode {
    /// The asker's person is not in the audience of the epoch in force.
    NotAudience,
    /// The sender is busy: ask again after the refusal's `retry_ms`.
    Busy,
    /// The carrier lacks a stream for a reliable mode.
    NoStream,
    /// The sender's epoch is not the asker's.
    StaleEpoch,
    /// A cap of the sender is reached (channels, receivers).
    TooMany,
    /// The sender has nothing to answer with yet.
    NotReady,
}

impl RefusalCode {
    pub(crate) fn code(self) -> u64 {
        match self {
            RefusalCode::NotAudience => 1,
            RefusalCode::Busy => 2,
            RefusalCode::NoStream => 3,
            RefusalCode::StaleEpoch => 4,
            RefusalCode::TooMany => 5,
            RefusalCode::NotReady => 6,
        }
    }

    fn from_code(code: u64) -> Result<RefusalCode, WireError> {
        match code {
            1 => Ok(RefusalCode::NotAudience),
            2 => Ok(RefusalCode::Busy),
            3 => Ok(RefusalCode::NoStream),
            4 => Ok(RefusalCode::StaleEpoch),
            5 => Ok(RefusalCode::TooMany),
            6 => Ok(RefusalCode::NotReady),
            _ => Err(WireError::Malformed(
                "a refusal code is 1 to 6 (NotAudience, Busy, NoStream, StaleEpoch, TooMany, NotReady)",
            )),
        }
    }
}

// -- Helpers ---------------------------------------------------------------------------------

/// A TLV of type `typ` whose value is the components of `name` (a `Name` value).
fn write_name_as(w: &mut TlvWriter, typ: u64, name: &Name) {
    w.write_nested(typ, |w| {
        for c in name.components() {
            w.write_tlv(c.typ, &c.value);
        }
    });
}

/// A TLV of type `typ` whose value is an `EPOCH_ID`'s fields.
fn write_epoch_as(w: &mut TlvWriter, typ: u64, epoch: &EpochId) {
    // `write_epoch_id` writes the `EPOCH_ID` TLV; its value is what `typ` holds.
    let mut inner = TlvWriter::new();
    write_epoch_id(&mut inner, epoch);
    let wire = inner.finish();
    let mut r = TlvReader::new(wire);
    let (_, value) = r.read_tlv().expect("a TLV this function just wrote");
    w.write_tlv(typ, &value);
}

/// What `slot` holds, or the refusal that names the missing field.
fn need<T>(slot: Option<T>, what: &'static str) -> Result<T, WireError> {
    slot.ok_or(WireError::Missing(what))
}

fn nni_u32(v: &[u8], what: &'static str) -> Result<u32, WireError> {
    u32::try_from(read_nni(v)?).map_err(|_| WireError::Malformed(what))
}

/// Take certificate `cert` into `chain` under the limits of a grant ask's chain.
fn take_cert(
    chain: &mut Vec<Bytes>,
    octets: &mut usize,
    cert: Bytes,
    what: &'static str,
) -> Result<(), WireError> {
    *octets += cert.len();
    if chain.len() == ASKER_CHAIN_MAX || *octets > ASKER_CHAIN_OCTETS_MAX || cert.len() > CERT_MAX {
        return Err(WireError::TooLarge {
            what,
            size: *octets,
            max: ASKER_CHAIN_OCTETS_MAX,
        });
    }
    chain.push(cert);
    Ok(())
}

// -- The ask -----------------------------------------------------------------------------------

/// What a receiver asks a sender for: the ApplicationParameters of
/// `<sender>/32=chan/<digest>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ChanAsk {
    /// The space.
    pub space: Name,
    /// The path prefix the receiver wants (empty: everything).
    pub prefix: Name,
    /// The mode.
    pub mode: ChannelMode,
    /// The asker's X25519 recipient key: the key the session's `K` is wrapped to.
    pub recipient: [u8; 32],
    /// The carrier kinds the asker can use.
    pub carriers: Vec<u8>,
    /// Seconds the asker wants.
    pub lifetime: u64,
    /// The epoch the asker holds in force, in a sealed space.
    pub epoch: Option<EpochId>,
    /// `Window` only: the first sequence still needed.
    pub since: Option<u64>,
    /// The certificates of the asker's signer chain, leaf first, each a whole Data.
    pub chain: Vec<Bytes>,
}

impl ChanAsk {
    /// The `CHAN_ASK` TLV; refused if it is over [`ASK_MAX`] octets or carries more
    /// certificates than a grant ask's chain does.
    pub(crate) fn encode(&self) -> Result<Bytes, WireError> {
        let (mut chain, mut octets) = (Vec::new(), 0);
        for cert in &self.chain {
            take_cert(
                &mut chain,
                &mut octets,
                cert.clone(),
                "the certificates an ask carries",
            )?;
        }
        let mut w = TlvWriter::new();
        w.write_nested(CHAN_ASK, |w| {
            write_name_as(w, ASK_SPACE, &self.space);
            write_name_as(w, ASK_PREFIX, &self.prefix);
            write_nni(w, ASK_MODE, self.mode.code());
            w.write_tlv(ASK_RECIPIENT, &self.recipient);
            w.write_tlv(ASK_CARRIERS, &self.carriers);
            write_nni(w, ASK_LIFETIME, self.lifetime);
            if let Some(epoch) = &self.epoch {
                write_epoch_as(w, ASK_EPOCH, epoch);
            }
            if let Some(since) = self.since {
                write_nni(w, ASK_SINCE, since);
            }
            for cert in &self.chain {
                w.write_tlv(tlv::ASKER_CERT, cert);
            }
        });
        let wire = w.finish();
        if wire.len() > ASK_MAX {
            return Err(WireError::TooLarge {
                what: "a channel ask",
                size: wire.len(),
                max: ASK_MAX,
            });
        }
        Ok(wire)
    }

    /// Decode a `CHAN_ASK` TLV of at most [`ASK_MAX`] octets. The parse stops at the first
    /// certificate over the chain's limits.
    pub(crate) fn decode(content: Bytes) -> Result<ChanAsk, WireError> {
        if content.len() > ASK_MAX {
            return Err(WireError::TooLarge {
                what: "a channel ask",
                size: content.len(),
                max: ASK_MAX,
            });
        }
        let value = only(content, CHAN_ASK, "an ask is one CHAN_ASK TLV")?;
        let (mut space, mut prefix, mut mode, mut recipient) = (None, None, None, None);
        let (mut carriers, mut lifetime, mut epoch, mut since) = (None, None, None, None);
        let (mut chain, mut octets) = (Vec::new(), 0);
        fields!(value, |v| {
            ASK_SPACE => once(&mut space, read_name(v)?, "an ask's space")?,
            ASK_PREFIX => once(&mut prefix, read_name(v)?, "an ask's prefix")?,
            ASK_MODE => once(&mut mode, ChannelMode::from_code(read_nni(&v)?)?, "an ask's mode")?,
            ASK_RECIPIENT => once(
                &mut recipient,
                read_array::<32>(&v, "an ask's recipient key is 32 octets")?,
                "an ask's recipient key",
            )?,
            ASK_CARRIERS => {
                if v.len() > CARRIERS_MAX {
                    return Err(WireError::TooMany {
                        what: "an ask's carriers",
                        count: v.len(),
                        max: CARRIERS_MAX,
                    });
                }
                once(&mut carriers, v.to_vec(), "an ask's carriers")?
            },
            ASK_LIFETIME => once(&mut lifetime, read_nni(&v)?, "an ask's lifetime")?,
            ASK_EPOCH => once(&mut epoch, read_epoch_id(v)?, "an ask's epoch")?,
            ASK_SINCE => once(&mut since, read_nni(&v)?, "an ask's since")?,
            tlv::ASKER_CERT => take_cert(&mut chain, &mut octets, v, "the certificates an ask carries")?,
        });
        Ok(ChanAsk {
            space: need(space, "an ask's space")?,
            prefix: need(prefix, "an ask's prefix")?,
            mode: need(mode, "an ask's mode")?,
            recipient: need(recipient, "an ask's recipient key")?,
            carriers: need(carriers, "an ask's carriers")?,
            lifetime: need(lifetime, "an ask's lifetime")?,
            epoch,
            since,
            chain,
        })
    }
}

// -- The session -----------------------------------------------------------------------------

/// One carrier a session offers: its kind and its parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CarrierOffer {
    /// The kind ([`carrier`]).
    pub kind: u8,
    /// What the kind needs (the ring's name digest); empty for the others.
    pub params: Bytes,
}

/// One name id a session binds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Bind {
    /// The id.
    pub id: u64,
    /// The name it stands for.
    pub name: Name,
}

/// What a `Window` channel replays to a late joiner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Window {
    /// Messages.
    pub messages: u64,
    /// Octets.
    pub bytes: u64,
    /// Milliseconds.
    pub ms: u64,
}

/// What a sender answers an ask with: the Content of the session Data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SessionRecord {
    /// The channel id.
    pub id: u64,
    /// The sender's device.
    pub sender: Name,
    /// The space.
    pub space: Name,
    /// The mode.
    pub mode: ChannelMode,
    /// How many times the channel was re-keyed.
    pub key_epoch: u32,
    /// The key's id.
    pub key_id: [u8; 8],
    /// The ephemeral X25519 key (32 octets), then the sealed key.
    pub wrap: Bytes,
    /// The AEAD of the frames.
    pub aead: Aead,
    /// The carriers on offer.
    pub carriers: Vec<CarrierOffer>,
    /// The name ids bound so far.
    pub table: Vec<Bind>,
    /// The checkpoint period in milliseconds.
    pub ckpt_ms: u64,
    /// `Window` mode: what is replayed.
    pub window: Option<Window>,
    /// Seconds, from receipt.
    pub lifetime: u64,
    /// The audience epoch the sender judged by, in a sealed space.
    pub audience_epoch: Option<EpochId>,
    /// The largest frame on a datagram carrier.
    pub frame_max: u64,
    /// The next sequence the sender will use.
    pub seq: u64,
    /// The certificates of the sender's chain, leaf first, each a whole Data.
    pub certs: Vec<Bytes>,
}

impl SessionRecord {
    /// The `CHAN_SESSION` TLV; refused if it is over [`SESSION_MAX`] octets.
    pub(crate) fn encode(&self) -> Result<Bytes, WireError> {
        let (mut chain, mut octets) = (Vec::new(), 0);
        for cert in &self.certs {
            take_cert(
                &mut chain,
                &mut octets,
                cert.clone(),
                "the certificates a session carries",
            )?;
        }
        if self.table.len() > TABLE_BINDS_MAX {
            return Err(WireError::TooMany {
                what: "a session's name table",
                count: self.table.len(),
                max: TABLE_BINDS_MAX,
            });
        }
        let mut w = TlvWriter::new();
        w.write_nested(CHAN_SESSION, |w| {
            w.write_tlv(S_ID, &self.id.to_be_bytes());
            write_name_as(w, S_SENDER, &self.sender);
            write_name_as(w, S_SPACE, &self.space);
            write_nni(w, S_MODE, self.mode.code());
            write_nni(w, S_KEY_EPOCH, u64::from(self.key_epoch));
            w.write_tlv(S_KEY_ID, &self.key_id);
            w.write_tlv(S_WRAP, &self.wrap);
            write_nni(w, S_AEAD, u64::from(self.aead.code()));
            for c in &self.carriers {
                let mut value = vec![c.kind];
                value.extend_from_slice(&c.params);
                w.write_tlv(S_CARRIER, &value);
            }
            if !self.table.is_empty() {
                w.write_nested(S_TABLE, |w| {
                    for bind in &self.table {
                        w.write_nested(S_BIND, |w| {
                            write_nni(w, B_ID, bind.id);
                            write_name_as(w, B_NAME, &bind.name);
                        });
                    }
                });
            }
            write_nni(w, S_CKPT_MS, self.ckpt_ms);
            if let Some(window) = &self.window {
                w.write_nested(S_WINDOW, |w| {
                    write_nni(w, W_MESSAGES, window.messages);
                    write_nni(w, W_BYTES, window.bytes);
                    write_nni(w, W_MS, window.ms);
                });
            }
            write_nni(w, S_LIFETIME, self.lifetime);
            if let Some(epoch) = &self.audience_epoch {
                write_epoch_as(w, S_AUDIENCE_EPOCH, epoch);
            }
            write_nni(w, S_FRAME_MAX, self.frame_max);
            write_nni(w, S_SEQ, self.seq);
            for cert in &self.certs {
                w.write_tlv(S_CERT, cert);
            }
        });
        let wire = w.finish();
        if wire.len() > SESSION_MAX {
            return Err(WireError::TooLarge {
                what: "a channel session",
                size: wire.len(),
                max: SESSION_MAX,
            });
        }
        Ok(wire)
    }

    /// Decode a `CHAN_SESSION` TLV of at most [`SESSION_MAX`] octets.
    pub(crate) fn decode(content: Bytes) -> Result<SessionRecord, WireError> {
        if content.len() > SESSION_MAX {
            return Err(WireError::TooLarge {
                what: "a channel session",
                size: content.len(),
                max: SESSION_MAX,
            });
        }
        let value = only(content, CHAN_SESSION, "a session is one CHAN_SESSION TLV")?;
        let (mut id, mut sender, mut space, mut mode) = (None, None, None, None);
        let (mut key_epoch, mut key_id, mut wrap, mut aead) = (None, None, None, None);
        let (mut carriers, mut table, mut ckpt_ms, mut window) = (Vec::new(), None, None, None);
        let (mut lifetime, mut audience, mut frame_max, mut seq) = (None, None, None, None);
        let (mut certs, mut octets) = (Vec::new(), 0);
        fields!(value, |v| {
            S_ID => once(&mut id, u64::from_be_bytes(read_array::<8>(&v, "a channel id is 8 octets")?), "a session's id")?,
            S_SENDER => once(&mut sender, read_name(v)?, "a session's sender")?,
            S_SPACE => once(&mut space, read_name(v)?, "a session's space")?,
            S_MODE => once(&mut mode, ChannelMode::from_code(read_nni(&v)?)?, "a session's mode")?,
            S_KEY_EPOCH => once(&mut key_epoch, nni_u32(&v, "a key epoch is a 32-bit number")?, "a session's key epoch")?,
            S_KEY_ID => once(&mut key_id, read_array::<8>(&v, "a key id is 8 octets")?, "a session's key id")?,
            S_WRAP => once(&mut wrap, v, "a session's wrapped key")?,
            S_AEAD => once(
                &mut aead,
                u8::try_from(read_nni(&v)?)
                    .ok()
                    .and_then(Aead::from_code)
                    .ok_or(WireError::Malformed(
                        "a session's AEAD is 1 (AES-256-GCM) or 2 (ChaCha20-Poly1305)",
                    ))?,
                "a session's AEAD",
            )?,
            S_CARRIER => {
                let Some((kind, params)) = v.split_first() else {
                    return Err(WireError::Malformed("a carrier names its kind in its first octet"));
                };
                carriers.push(CarrierOffer { kind: *kind, params: Bytes::copy_from_slice(params) })
            },
            S_TABLE => {
                if v.len() > TABLE_OCTETS_MAX {
                    return Err(WireError::TooLarge {
                        what: "a session's name table",
                        size: v.len(),
                        max: TABLE_OCTETS_MAX,
                    });
                }
                once(&mut table, read_table(v)?, "a session's name table")?
            },
            S_CKPT_MS => once(&mut ckpt_ms, read_nni(&v)?, "a session's checkpoint period")?,
            S_WINDOW => once(&mut window, read_window(v)?, "a session's window")?,
            S_LIFETIME => once(&mut lifetime, read_nni(&v)?, "a session's lifetime")?,
            S_AUDIENCE_EPOCH => once(&mut audience, read_epoch_id(v)?, "a session's audience epoch")?,
            S_FRAME_MAX => once(&mut frame_max, read_nni(&v)?, "a session's frame limit")?,
            S_SEQ => once(&mut seq, read_nni(&v)?, "a session's sequence")?,
            S_CERT => take_cert(&mut certs, &mut octets, v, "the certificates a session carries")?,
        });
        Ok(SessionRecord {
            id: need(id, "a session's id")?,
            sender: need(sender, "a session's sender")?,
            space: need(space, "a session's space")?,
            mode: need(mode, "a session's mode")?,
            key_epoch: need(key_epoch, "a session's key epoch")?,
            key_id: need(key_id, "a session's key id")?,
            wrap: need(wrap, "a session's wrapped key")?,
            aead: need(aead, "a session's AEAD")?,
            carriers,
            table: table.unwrap_or_default(),
            ckpt_ms: need(ckpt_ms, "a session's checkpoint period")?,
            window,
            lifetime: need(lifetime, "a session's lifetime")?,
            audience_epoch: audience,
            frame_max: need(frame_max, "a session's frame limit")?,
            seq: need(seq, "a session's sequence")?,
            certs,
        })
    }
}

fn read_table(value: Bytes) -> Result<Vec<Bind>, WireError> {
    let mut binds = Vec::new();
    each(value, |t, v| {
        if t != S_BIND {
            return Ok(false);
        }
        if binds.len() == TABLE_BINDS_MAX {
            return Err(WireError::TooMany {
                what: "a session's name table",
                count: binds.len() + 1,
                max: TABLE_BINDS_MAX,
            });
        }
        let (mut id, mut name) = (None, None);
        fields!(v, |b| {
            B_ID => once(&mut id, read_nni(&b)?, "a bind's id")?,
            B_NAME => once(&mut name, read_name(b)?, "a bind's name")?,
        });
        binds.push(Bind {
            id: need(id, "a bind's id")?,
            name: need(name, "a bind's name")?,
        });
        Ok(true)
    })?;
    Ok(binds)
}

fn read_window(value: Bytes) -> Result<Window, WireError> {
    let (mut messages, mut bytes, mut ms) = (None, None, None);
    fields!(value, |v| {
        W_MESSAGES => once(&mut messages, read_nni(&v)?, "a window's messages")?,
        W_BYTES => once(&mut bytes, read_nni(&v)?, "a window's octets")?,
        W_MS => once(&mut ms, read_nni(&v)?, "a window's milliseconds")?,
    });
    Ok(Window {
        messages: need(messages, "a window's messages")?,
        bytes: need(bytes, "a window's octets")?,
        ms: need(ms, "a window's milliseconds")?,
    })
}

// -- The refusal ---------------------------------------------------------------------------------

/// A signed refusal: what a sender answers a judged ask with when it declines for a reason of
/// its own policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RefusalRecord {
    /// Why, as a code.
    pub code: RefusalCode,
    /// Why, and what to do, in a sentence.
    pub text: String,
    /// Milliseconds before asking again is of use; 0 for never mind.
    pub retry_ms: u64,
}

impl RefusalRecord {
    /// The `CHAN_REFUSAL` TLV; the text is cut to [`TEXT_MAX`] octets at a character boundary.
    pub(crate) fn encode(&self) -> Bytes {
        let mut end = self.text.len().min(TEXT_MAX);
        while !self.text.is_char_boundary(end) {
            end -= 1;
        }
        let mut w = TlvWriter::new();
        w.write_nested(CHAN_REFUSAL, |w| {
            write_nni(w, R_CODE, self.code.code());
            w.write_tlv(R_TEXT, &self.text.as_bytes()[..end]);
            write_nni(w, R_RETRY, self.retry_ms);
        });
        w.finish()
    }

    /// Decode a `CHAN_REFUSAL` TLV.
    pub(crate) fn decode(content: Bytes) -> Result<RefusalRecord, WireError> {
        let value = only(content, CHAN_REFUSAL, "a refusal is one CHAN_REFUSAL TLV")?;
        let (mut code, mut text, mut retry) = (None, None, None);
        fields!(value, |v| {
            R_CODE => once(&mut code, RefusalCode::from_code(read_nni(&v)?)?, "a refusal's code")?,
            R_TEXT => {
                if v.len() > TEXT_MAX {
                    return Err(WireError::TooLarge {
                        what: "a refusal's text",
                        size: v.len(),
                        max: TEXT_MAX,
                    });
                }
                let s = String::from_utf8(v.to_vec())
                    .map_err(|_| WireError::Malformed("a refusal's text is UTF-8"))?;
                once(&mut text, s, "a refusal's text")?
            },
            R_RETRY => once(&mut retry, read_nni(&v)?, "a refusal's retry")?,
        });
        Ok(RefusalRecord {
            code: need(code, "a refusal's code")?,
            text: need(text, "a refusal's text")?,
            retry_ms: need(retry, "a refusal's retry")?,
        })
    }
}

/// The Content of a Data that answers an ask: a session or a refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Answer {
    /// A session.
    Session(Box<SessionRecord>),
    /// A refusal.
    Refusal(RefusalRecord),
}

impl Answer {
    /// Decode the Content of an answering Data by the type of its one TLV.
    pub(crate) fn decode(content: Bytes) -> Result<Answer, WireError> {
        let mut r = TlvReader::new(content.clone());
        let (typ, _) = r.read_tlv().map_err(|e| WireError::Tlv(format!("{e:?}")))?;
        match typ {
            CHAN_SESSION => Ok(Answer::Session(Box::new(SessionRecord::decode(content)?))),
            CHAN_REFUSAL => Ok(Answer::Refusal(RefusalRecord::decode(content)?)),
            t if t % 2 == 1 => Err(WireError::UnknownCritical(t)),
            _ => Err(WireError::Malformed(
                "an answer to a channel ask is a CHAN_SESSION or a CHAN_REFUSAL",
            )),
        }
    }
}

// -- The announce -----------------------------------------------------------------------------

/// What a sender pushes into a space's sync group: who it is and the modes it has channels in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Announce {
    /// The sender's device.
    pub sender: Name,
    /// The modes, each once.
    pub modes: Vec<ChannelMode>,
}

impl Announce {
    /// The `CHAN_ANNOUNCE` TLV.
    pub(crate) fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(CHAN_ANNOUNCE, |w| {
            write_name_as(w, S_SENDER, &self.sender);
            for mode in &self.modes {
                write_nni(w, ASK_MODE, mode.code());
            }
        });
        w.finish()
    }

    /// Decode a `CHAN_ANNOUNCE` TLV: a device and one to three modes.
    pub(crate) fn decode(content: Bytes) -> Result<Announce, WireError> {
        let value = only(
            content,
            CHAN_ANNOUNCE,
            "an announce is one CHAN_ANNOUNCE TLV",
        )?;
        let (mut sender, mut modes) = (None, Vec::new());
        fields!(value, |v| {
            S_SENDER => once(&mut sender, read_name(v)?, "an announce's sender")?,
            ASK_MODE => {
                let mode = ChannelMode::from_code(read_nni(&v)?)?;
                if modes.contains(&mode) {
                    return Err(WireError::Duplicate("an announce's mode"));
                }
                modes.push(mode)
            },
        });
        if modes.is_empty() {
            return Err(WireError::Missing("an announce's modes"));
        }
        Ok(Announce {
            sender: need(sender, "an announce's sender")?,
            modes,
        })
    }
}

#[cfg(test)]
#[path = "wire_tests.rs"]
mod tests;
