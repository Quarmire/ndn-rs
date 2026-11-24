//! The introduction's bytes and names (`docs/specs/invite.md`).
//!
//! Every packet an inviting device publishes is named under its own device name
//! `D` (its key name without `KEY/<id>`), so the hierarchical trust schema admits
//! it everywhere and Interests for it route to the device:
//!
//! | packet | name | signed by |
//! |---|---|---|
//! | offer | `<D>/32=intro/offer/<id>` (`id`: 16 random octets, one generic component) | the device key |
//! | ask (an Interest; its answer is named alike) | `<D>/32=intro/<ParametersSha256Digest>` | answer: the device key |
//! | hint record | `<D>/32=hint/<token>` | the device key |
//! | an asker's or an answerer's proof | `<X>/32=ask/<binding>` | the key of `X` |
//!
//! The offer's name is not derived from anything the inviter shows but its code:
//! 16 random octets cannot be guessed, so a refusal to anyone who asks without
//! the code is silence. A name parses one way: `D` has no keyword component, so
//! the first `32=intro`, `32=hint` or `32=ask` ends it.
//!
//! The TLV-TYPEs keep the numbers of the exchange's first version (0x0520–0x057F
//! and the block 0x05B0–0x05BF of the hint): even numbers are skippable and a
//! reader passes over one it does not know, odd ones are critical and a reader
//! refuses what carries one it does not know.

use std::net::{IpAddr, SocketAddr};

use bytes::Bytes;
use ndn_foundation_types::{Name, NameComponent, tlv_type};
use ndn_heap::{EntryId, Timestamp};
use ndn_tlv::{TlvReader, TlvWriter};
use ndn_trust_envelope::HINT_RELAYS_MAX;
use sha2::{Digest, Sha256};

use crate::host::{HintCandidate, HintKind, LINK_HINT_CANDIDATES_MAX, Role};
use crate::policy::IntroRefusal;

/// TLV-TYPE numbers.
pub mod tlv {
    /// NonNegativeInteger: a sequence number. Only inside [`ADMITTED`].
    pub const SEQ: u64 = 0x0526;
    /// An entry of the space's log: `Name` (the writing device), `Seq`,
    /// `Digest` (the signed-region digest). The Members entry the inviter's
    /// change made when it admitted the asker, in an answer that accepts; the
    /// joiner waits to hold exactly it.
    pub const ADMITTED: u64 = 0x052A;
    /// A date (ms since the Unix epoch): an introduction offer's expiry.
    pub const KEEP_UNTIL: u64 = 0x052E;
    /// Octets: an ask's fresh random nonce (16).
    pub const NONCE: u64 = 0x0531;
    /// Octets: the asker's proof that it asks, a Data packet `<asker>/32=ask/
    /// <binding>` signed by the asker device's key; in an answer, the same of
    /// the inviter.
    pub const ASKER: u64 = 0x053B;
    /// 32 octets: an introduction's proof.
    pub const PROOF: u64 = 0x053F;
    /// SHA-256 digest (32 octets): an offer's commitment, an asker key's
    /// digest, an entry's signed-region digest.
    pub const DIGEST: u64 = 0x055E;
    /// A key's name: `Name`.
    pub const WRITER: u64 = 0x0568;
    /// Octets: a content key wrapped to the seal key, or an ask's fields sealed.
    pub const CIPHERTEXT: u64 = 0x0574;
    /// A device's seal key: 32 octets, an X25519 public key.
    pub const SEAL_KEY: u64 = 0x0576;
    /// The asker's ephemeral X25519 public key: 32 octets.
    pub const EPHEMERAL_KEY: u64 = 0x057C;

    /// An offer: `Name` (the space), `Role`, `KeepUntil` (its expiry), `Tries`,
    /// `Digest` (the commitment to its secret), `SealKey` (the offering
    /// device's). The Content of the offer packet.
    pub const INTRO_OFFER: u64 = 0x0561;
    /// An offer used: `Name` (the offer), then `Writer` and `Digest` (the asker
    /// key it was used by) — or, without them, closed.
    pub const INTRO_USED: u64 = 0x0563;
    /// An ask, in its Interest's parameters: `EphemeralKey`, `Ciphertext` (a
    /// content key wrapped to the offer's seal key), `Ciphertext` (the ask's
    /// fields, sealed under it).
    pub const INTRO_ASK: u64 = 0x0565;
    /// An answer: `Name` (offer), `Writer`, `Digest` (the asker key), then
    /// `Name` (space), `Role`, [`Admitted`](ADMITTED), `Credentials`, `Asker` —
    /// or `IntroRefused` — then `Proof`.
    pub const INTRO_ANSWER: u64 = 0x0567;
    /// NonNegativeInteger: 0 reader, 1 writer.
    pub const ROLE: u64 = 0x0569;
    /// NonNegativeInteger: wrong tries (allowed, in an offer; left, in a
    /// refusal).
    pub const TRIES: u64 = 0x056B;
    /// NonNegativeInteger (1 unknown, 2 used, 3 expired, 4 closed, 5 wrong
    /// proof, 6 conflict), then `Tries` (left) for a wrong proof.
    pub const INTRO_REFUSED: u64 = 0x056D;
    /// Data packets, each whole: a signed trust context, then certificates of
    /// its signer key's chain.
    pub const CREDENTIALS: u64 = 0x056F;

    /// 32 octets: SHA-256 of the inviter device's public key as a certificate
    /// carries it (an Ed25519 key's 32 octets): the key the link handshake must
    /// prove. In the value of the intro envelope's `LinkHint` (0x0478).
    pub const LINK_KEY: u64 = 0x05B0;
    /// One direct-path candidate address, repeatable: one octet of kind (0 host,
    /// 1 reflexive, 2 advertised, 3 mapped), the IP address (4 octets for IPv4,
    /// 16 for IPv6), the UDP port (2 octets, big-endian).
    pub const LINK_CANDIDATE: u64 = 0x05B2;
    /// A hint record: `HintOffer`, `LinkKey`, `LinkCandidate`s, `HintRelay`s,
    /// `HintUntil`, `Credentials` — or, for an offer no longer served, just a
    /// `HintGone` and `Credentials`.
    pub const INTRO_HINT: u64 = 0x05B4;
    /// The offer the record is bound to: a `Name` (the offer's name).
    pub const HINT_OFFER: u64 = 0x05B6;
    /// A relay device that reaches the inviter, repeatable (at most 8): a
    /// `Name`.
    pub const HINT_RELAY: u64 = 0x05B8;
    /// NonNegativeInteger: 3 expired, 4 closed (the codes of `IntroRefused`).
    /// The offer is no longer served.
    pub const HINT_GONE: u64 = 0x05BA;
    /// NonNegativeInteger: the offer's expiry, in milliseconds. Informational.
    pub const HINT_UNTIL: u64 = 0x05BC;
}

/// The keyword of an ask's and an offer's name: `<D>/32=intro/…`.
pub(crate) const INTRO: &[u8] = b"intro";
/// The keyword that follows [`INTRO`] in an offer's name.
pub(crate) const OFFER: &[u8] = b"offer";
/// The keyword of a hint record's name: `<D>/32=hint/<token>`.
pub(crate) const HINT: &[u8] = b"hint";
/// The keyword of a proof's name: `<X>/32=ask/<binding>`.
const ASK: &[u8] = b"ask";

/// The octets of an ask's nonce.
pub const NONCE_LEN: usize = 16;

/// The octets of an offer's id, the last component of its name.
pub const OFFER_ID_LEN: usize = 16;

/// An offer's id: 16 random octets, the last component of its name.
pub type OfferId = [u8; OFFER_ID_LEN];

/// Octets of a hint token.
pub const HINT_TOKEN_LEN: usize = 16;

/// The most components after `32=data` in a space's name.
const SPACE_REST_MAX: usize = 4;

// ---- primitives -------------------------------------------------------------------------------

/// Why bytes do not decode.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("malformed introduction record: {0}")]
pub struct WireError(pub String);

pub(crate) fn bad(what: impl Into<String>) -> WireError {
    WireError(what.into())
}

pub(crate) fn kw(word: &'static [u8]) -> NameComponent {
    NameComponent::keyword(Bytes::from_static(word))
}

pub(crate) fn is_kw(c: &NameComponent, word: &[u8]) -> bool {
    c.typ == tlv_type::KEYWORD && c.value.as_ref() == word
}

pub(crate) fn name_of(comps: &[NameComponent]) -> Name {
    Name::from_components(comps.iter().cloned())
}

/// A component that may stand in a namespace or a device name: no keyword (those
/// mark the layer's own names) and no digest.
fn is_plain(c: &NameComponent) -> bool {
    !matches!(
        c.typ,
        tlv_type::KEYWORD | tlv_type::IMPLICIT_SHA256 | tlv_type::PARAMETERS_SHA256
    )
}

/// Whether `comps` can be a device name: not the root, and no keyword or digest
/// component, so the first `32=intro`, `32=hint` or `32=ask` after it ends it.
pub(crate) fn is_device_comps(comps: &[NameComponent]) -> bool {
    !comps.is_empty() && comps.iter().all(is_plain)
}

/// Whether `name` is a space's name `<O>/32=data/<c1>[/<c2>…]`: a namespace (not
/// the root, no keyword, digest or sequence number) then the one keyword `data`
/// and one to four generic components.
fn is_space(name: &Name) -> bool {
    let comps = name.components();
    let Some(at) = comps.iter().position(|c| is_kw(c, b"data")) else {
        return false;
    };
    let (owner, rest) = (&comps[..at], &comps[at + 1..]);
    !owner.is_empty()
        && owner
            .iter()
            .all(|c| is_plain(c) && c.typ != tlv_type::SEQUENCE_NUM)
        && (1..=SPACE_REST_MAX).contains(&rest.len())
        && rest
            .iter()
            .all(|c| c.typ == tlv_type::GENERIC_NAME_COMPONENT)
}

pub(crate) fn write_nni(w: &mut TlvWriter, typ: u64, v: u64) {
    let b = v.to_be_bytes();
    let s = match v {
        0..=0xFF => &b[7..],
        0x100..=0xFFFF => &b[6..],
        0x1_0000..=0xFFFF_FFFF => &b[4..],
        _ => &b[..],
    };
    w.write_tlv(typ, s);
}

pub(crate) fn read_nni(v: &[u8]) -> Result<u64, WireError> {
    Ok(match v.len() {
        1 => u64::from(v[0]),
        2 => u64::from(u16::from_be_bytes([v[0], v[1]])),
        4 => u64::from(u32::from_be_bytes([v[0], v[1], v[2], v[3]])),
        8 => u64::from_be_bytes([v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]]),
        _ => return Err(bad("a NonNegativeInteger is 1, 2, 4 or 8 octets")),
    })
}

pub(crate) fn write_name(w: &mut TlvWriter, name: &Name) {
    w.write_nested(tlv_type::NAME, |w| {
        for c in name.components() {
            w.write_tlv(c.typ, &c.value);
        }
    });
}

pub(crate) fn read_name(value: Bytes) -> Result<Name, WireError> {
    Name::decode(value).map_err(|e| bad(format!("bad name: {e:?}")))
}

pub(crate) fn read_digest(v: &[u8]) -> Result<[u8; 32], WireError> {
    <[u8; 32]>::try_from(v).map_err(|_| bad("a digest is 32 octets"))
}

pub(crate) fn read_nonce(v: &[u8]) -> Result<[u8; NONCE_LEN], WireError> {
    <[u8; NONCE_LEN]>::try_from(v).map_err(|_| bad("a nonce is 16 octets"))
}

/// Read one TLV that spans `content` whole: its type and value.
fn one(content: Bytes, what: &str) -> Result<(u64, Bytes), WireError> {
    let mut r = TlvReader::new(content);
    let (typ, value) = r.read_tlv().map_err(|e| bad(format!("bad TLV: {e:?}")))?;
    if !r.is_empty() {
        return Err(bad(format!("{what} is one TLV")));
    }
    Ok((typ, value))
}

/// Iterate the TLVs of `value`, handing each to `f`, which returns whether it
/// knew the type; skip unknown even types and refuse unknown odd (critical) ones.
pub(crate) fn each(
    value: Bytes,
    mut f: impl FnMut(u64, Bytes) -> Result<bool, WireError>,
) -> Result<(), WireError> {
    let mut r = TlvReader::new(value);
    while !r.is_empty() {
        let (typ, v) = r.read_tlv().map_err(|e| bad(format!("bad TLV: {e:?}")))?;
        if !f(typ, v)? && typ % 2 == 1 {
            return Err(bad(format!("unknown critical TLV-TYPE {typ:#x}")));
        }
    }
    Ok(())
}

/// Read a `Writer` TLV's value: one Name, a key.
pub(crate) fn read_writer(v: Bytes) -> Result<Name, WireError> {
    let (t, v) = one(v, "a writer")?;
    if t != tlv_type::NAME {
        return Err(bad("a writer is a key name"));
    }
    read_name(v)
}

/// The name a `HintOffer` or `HintRelay` wraps: one Name TLV.
fn read_wrapped_name(value: Bytes) -> Result<Name, WireError> {
    let (typ, inner) = one(value, "a hint's name")?;
    if typ != tlv_type::NAME {
        return Err(bad("a hint's name is one Name"));
    }
    read_name(inner)
}

fn write_credentials(w: &mut TlvWriter, packets: &[Bytes]) {
    let mut inner = TlvWriter::new();
    for p in packets {
        inner.write_raw(p);
    }
    w.write_tlv(tlv::CREDENTIALS, &inner.finish());
}

fn read_credentials(v: Bytes) -> Result<Vec<Bytes>, WireError> {
    let mut packets = Vec::new();
    let mut r = TlvReader::new(v.clone());
    let mut at = 0usize;
    while !r.is_empty() {
        let before = r.remaining();
        let (t, _) = r.read_tlv().map_err(|e| bad(format!("bad TLV: {e:?}")))?;
        if t != ndn_packet::tlv_type::DATA {
            return Err(bad("credentials are Data packets"));
        }
        let len = before - r.remaining();
        packets.push(v.slice(at..at + len));
        at += len;
    }
    if packets.is_empty() {
        return Err(bad("credentials carry a trust context"));
    }
    Ok(packets)
}

/// The entry an `Admitted` TLV names, as one nested TLV: `Name` (the device),
/// `Seq`, `Digest`.
fn write_admitted(w: &mut TlvWriter, id: &EntryId) {
    w.write_nested(tlv::ADMITTED, |w| {
        write_name(w, &id.device);
        write_nni(w, tlv::SEQ, id.seq);
        w.write_tlv(tlv::DIGEST, &id.digest);
    });
}

/// Read the value of an `Admitted` TLV: a device, a seq and a digest, each once.
fn read_admitted(value: Bytes) -> Result<EntryId, WireError> {
    let (mut device, mut seq, mut digest) = (None, None, None);
    fn once<T>(slot: &mut Option<T>, v: T, what: &str) -> Result<(), WireError> {
        match slot.replace(v) {
            None => Ok(()),
            Some(_) => Err(bad(format!("an admitting entry names its {what} once"))),
        }
    }
    each(value, |t, v| {
        match t {
            tlv_type::NAME => once(&mut device, read_name(v)?, "device")?,
            tlv::SEQ => once(&mut seq, read_nni(&v)?, "seq")?,
            tlv::DIGEST => once(&mut digest, read_digest(&v)?, "digest")?,
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    match (device, seq, digest) {
        (Some(device), Some(seq), Some(digest)) if is_device_comps(device.components()) => {
            Ok(EntryId {
                device,
                seq,
                digest,
            })
        }
        _ => Err(bad(
            "an admitting entry names its device (no keyword component), its seq and its digest",
        )),
    }
}

// ---- names ------------------------------------------------------------------------------------

/// `<device>/32=intro`: an ask Interest's name before its parameters digest,
/// what an ask's sealing binds as associated data, and the prefix of the offers.
pub fn intro_prefix(device: &Name) -> Name {
    device.clone().append_component(kw(INTRO))
}

/// An ask's name: `<device>/32=intro/<ParametersSha256Digest>`, the digest over
/// the ApplicationParameters TLV that carries `params` (the [`IntroAsk`] TLV), as
/// the Interest carries it and its answer is named. The ask travels in the
/// parameters, not the name: its credentials take a few KB, and a link reads an
/// Interest's name from its first fragment.
pub fn intro_name(device: &Name, params: &[u8]) -> Name {
    let mut w = TlvWriter::new();
    w.write_tlv(ndn_packet::tlv_type::APP_PARAMETERS, params);
    let digest = Sha256::digest(w.finish());
    intro_prefix(device).append_component(NameComponent::new(
        tlv_type::PARAMETERS_SHA256,
        Bytes::copy_from_slice(&digest),
    ))
}

/// The device `<device>/32=intro/<ParametersSha256Digest>` asks.
pub fn parse_intro_name(name: &Name) -> Option<Name> {
    let comps = name.components();
    let at = comps.iter().position(|c| is_kw(c, INTRO))?;
    (is_device_comps(&comps[..at])
        && at + 2 == comps.len()
        && comps[at + 1].typ == tlv_type::PARAMETERS_SHA256
        && comps[at + 1].value.len() == 32)
        .then(|| name_of(&comps[..at]))
}

/// `<device>/32=intro/offer`: the prefix of a device's offers.
pub fn offer_prefix(device: &Name) -> Name {
    intro_prefix(device).append_component(kw(OFFER))
}

/// An offer's name: `<device>/32=intro/offer/<id>`, the id one generic component
/// of [`OFFER_ID_LEN`] random octets. An offer is a Data signed by the device's
/// key, held and served by the device; its name is as hard to guess as its id.
pub fn offer_name(device: &Name, id: &OfferId) -> Name {
    offer_prefix(device).append_component(NameComponent::generic(Bytes::copy_from_slice(id)))
}

/// The device and the id an offer name `<device>/32=intro/offer/<id>` names;
/// `None` for any other name (the prefix, a longer name, an id of another length
/// or type, an ask's name).
pub fn parse_offer_name(name: &Name) -> Option<(Name, OfferId)> {
    let comps = name.components();
    let at = comps.iter().position(|c| is_kw(c, INTRO))?;
    let [offer, id] = comps.get(at + 1..)? else {
        return None;
    };
    (is_device_comps(&comps[..at])
        && is_kw(offer, OFFER)
        && id.typ == tlv_type::GENERIC_NAME_COMPONENT)
        .then(|| <OfferId>::try_from(&id.value[..]).ok())
        .flatten()
        .map(|id| (name_of(&comps[..at]), id))
}

/// `<device>/32=hint`: the prefix of a device's hint records.
pub fn hint_prefix(device: &Name) -> Name {
    device.clone().append_component(kw(HINT))
}

/// A hint record's name: `<device>/32=hint/<token>`.
pub fn hint_name(device: &Name, token: &[u8; HINT_TOKEN_LEN]) -> Name {
    hint_prefix(device).append(token)
}

/// The device and token a hint name `<device>/32=hint/<token>` names; `None` for
/// any other name (a hint prefix, a longer name, a token of another length).
pub fn parse_hint_name(name: &Name) -> Option<(Name, [u8; HINT_TOKEN_LEN])> {
    let comps = name.components();
    let at = comps.iter().position(|c| is_kw(c, HINT))?;
    let token = comps.get(at + 1)?;
    (is_device_comps(&comps[..at])
        && at + 2 == comps.len()
        && token.typ == tlv_type::GENERIC_NAME_COMPONENT)
        .then(|| <[u8; HINT_TOKEN_LEN]>::try_from(&token.value[..]).ok())
        .flatten()
        .map(|token| (name_of(&comps[..at]), token))
}

/// The name prefixes a stranger's link to `device` carries (spec §19.2): the
/// ask and the offer under `<device>/32=intro`, and a short code's hint record
/// under `<device>/32=hint`, and nothing else of the device.
pub fn introduction_prefixes(device: &Name) -> [Name; 2] {
    [intro_prefix(device), hint_prefix(device)]
}

/// A protocol whose asks or answers carry a proof `<device>/32=ask/<binding>`
/// ([`ask_name`]): its label opens every binding it makes, so a proof made for
/// one protocol never verifies as another's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AskProtocol {
    /// An introduction ask ([`AskBody`]).
    IntroAsk,
    /// An introduction answer ([`AnswerBody`]).
    IntroAnswer,
}

impl AskProtocol {
    /// Every protocol.
    pub const ALL: [AskProtocol; 2] = [AskProtocol::IntroAsk, AskProtocol::IntroAnswer];

    /// The octets opening its bindings: ASCII ending in a zero octet, so none is
    /// a prefix of another.
    pub const fn label(self) -> &'static [u8] {
        match self {
            AskProtocol::IntroAsk => b"ndn-invite intro ask\0",
            AskProtocol::IntroAnswer => b"ndn-invite intro answer\0",
        }
    }
}

/// What a proof of `protocol` names: SHA-256 over its label, then `parts` in
/// order. The receiver computes it with the label of the protocol it expects, and
/// the proof verifies only if it names that binding.
pub fn ask_binding(protocol: AskProtocol, parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(protocol.label());
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}

/// The name of an asker's proof: `<asker>/32=ask/<binding>`. Its Data packet,
/// signed by the asker device's key, rides in the ask it proves, so a stranger's
/// ask costs the answerer no work and no signature.
pub fn ask_name(asker: &Name, binding: &[u8; 32]) -> Name {
    asker
        .clone()
        .append_component(kw(ASK))
        .append_component(NameComponent::generic(Bytes::copy_from_slice(binding)))
}

/// Parse `<asker>/32=ask/<binding>`.
pub fn parse_ask_name(name: &Name) -> Option<(Name, [u8; 32])> {
    let comps = name.components();
    let at = comps.iter().position(|c| is_kw(c, ASK))?;
    if !is_device_comps(&comps[..at]) || at + 2 != comps.len() {
        return None;
    }
    let binding = <[u8; 32]>::try_from(comps[at + 1].value.as_ref()).ok()?;
    Some((name_of(&comps[..at]), binding))
}

// ---- the offer and its use mark ---------------------------------------------------------------

/// An offer record (spec §19.1): the Content of the offer packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfferBody {
    /// The space offered.
    pub space: Name,
    /// What it grants.
    pub role: Role,
    /// Its expiry.
    pub until: Timestamp,
    /// The wrong tries it allows.
    pub tries: u32,
    /// SHA-256 of the label and the secret ([`commitment`](crate::proofs::commitment)).
    pub commitment: [u8; 32],
    /// The offering device's seal key: asks are sealed to it.
    pub seal_key: [u8; 32],
}

/// A use mark (spec §19.1): the offer used by a key, or closed. The first mark
/// naming a key stands; a closing mark closes the offer whenever it comes, used
/// or not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsedBody {
    /// The offer packet's name, `<D>/32=intro/offer/<id>`.
    pub offer: Name,
    /// The key it was used by and its public key's digest; `None`: closed for
    /// good (all askers' wrong tries at the device's cap, its maker's
    /// `close_offer`, or the member it brought removed).
    pub by: Option<(Name, [u8; 32])>,
}

/// An introduction's record: what an offer packet carries, and a use mark.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IntroRecord {
    /// An offer.
    Offer(OfferBody),
    /// A use mark.
    Used(UsedBody),
}

impl IntroRecord {
    /// Its TLV.
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        match self {
            IntroRecord::Offer(b) => w.write_nested(tlv::INTRO_OFFER, |w| {
                write_name(w, &b.space);
                write_nni(w, tlv::ROLE, b.role.code());
                write_nni(w, tlv::KEEP_UNTIL, b.until.0);
                write_nni(w, tlv::TRIES, u64::from(b.tries));
                w.write_tlv(tlv::DIGEST, &b.commitment);
                w.write_tlv(tlv::SEAL_KEY, &b.seal_key);
            }),
            IntroRecord::Used(b) => w.write_nested(tlv::INTRO_USED, |w| {
                write_name(w, &b.offer);
                if let Some((key, digest)) = &b.by {
                    w.write_nested(tlv::WRITER, |w| write_name(w, key));
                    w.write_tlv(tlv::DIGEST, digest);
                }
            }),
        }
        w.finish()
    }

    /// Read one record: an `IntroOffer` or an `IntroUsed` TLV, and nothing else.
    pub fn decode(content: Bytes) -> Result<Self, WireError> {
        let (typ, value) = one(content, "an introduction record")?;
        match typ {
            tlv::INTRO_OFFER => {
                let (mut space, mut role, mut until, mut tries, mut commitment, mut seal_key) =
                    (None, None, None, None, None, None);
                each(value, |t, v| {
                    match t {
                        tlv_type::NAME => space = Some(read_name(v)?),
                        tlv::ROLE => role = Some(Role::from_code(read_nni(&v)?)?),
                        tlv::KEEP_UNTIL => until = Some(Timestamp(read_nni(&v)?)),
                        tlv::TRIES => tries = Some(read_nni(&v)?),
                        tlv::DIGEST => commitment = Some(read_digest(&v)?),
                        tlv::SEAL_KEY => seal_key = Some(read_digest(&v)?),
                        _ => return Ok(false),
                    }
                    Ok(true)
                })?;
                let space = space.ok_or_else(|| bad("an offer names its space"))?;
                if !is_space(&space) {
                    return Err(bad(
                        "an offer's space is a space name <owner>/32=data/<name>",
                    ));
                }
                let tries = tries
                    .filter(|t| (1..=u64::from(u32::MAX)).contains(t))
                    .ok_or_else(|| bad("an offer allows one wrong try or more"))?;
                Ok(IntroRecord::Offer(OfferBody {
                    space,
                    role: role.ok_or_else(|| bad("an offer names its role"))?,
                    until: until.ok_or_else(|| bad("an offer names its expiry"))?,
                    tries: tries as u32,
                    commitment: commitment.ok_or_else(|| bad("an offer carries its commitment"))?,
                    seal_key: seal_key.ok_or_else(|| bad("an offer carries its seal key"))?,
                }))
            }
            tlv::INTRO_USED => {
                let (mut offer, mut key, mut digest) = (None, None, None);
                each(value, |t, v| {
                    match t {
                        tlv_type::NAME => offer = Some(read_name(v)?),
                        tlv::WRITER => key = Some(read_writer(v)?),
                        tlv::DIGEST => digest = Some(read_digest(&v)?),
                        _ => return Ok(false),
                    }
                    Ok(true)
                })?;
                let offer = offer.ok_or_else(|| bad("a use mark names its offer"))?;
                parse_offer_name(&offer).ok_or_else(|| bad("a use mark names an offer's name"))?;
                let by = match (key, digest) {
                    (Some(k), Some(d)) => Some((k, d)),
                    (None, None) => None,
                    _ => return Err(bad("a use mark names its asker key with its digest")),
                };
                Ok(IntroRecord::Used(UsedBody { offer, by }))
            }
            other => Err(bad(format!(
                "{other:#x} is neither an IntroOffer nor an IntroUsed"
            ))),
        }
    }
}

// ---- the ask ----------------------------------------------------------------------------------

/// An ask as it travels: sealed to the offering device's seal key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntroAsk {
    /// The asker's ephemeral X25519 public key.
    pub ephemeral: [u8; 32],
    /// A fresh content key, wrapped to the seal key.
    pub key: Bytes,
    /// The [`AskBody`], sealed under that content key.
    pub sealed: Bytes,
}

/// An ask's fields, once opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AskBody {
    /// The offer asked for.
    pub offer: Name,
    /// Fresh per ask.
    pub nonce: [u8; NONCE_LEN],
    /// HMAC-SHA256 of the asker's binding under the offer's proof key
    /// ([`ask_proof`](crate::proofs::ask_proof)).
    pub proof: [u8; 32],
    /// The asker's signed trust context and its key's certificates.
    pub credentials: Vec<Bytes>,
    /// The asker's proof packet `<J>/32=ask/<binding>`, signed by its key.
    pub asker: Bytes,
}

impl AskBody {
    /// The fields the asker's proof packet binds: everything but itself.
    pub fn fields(&self) -> Bytes {
        let mut w = TlvWriter::new();
        write_name(&mut w, &self.offer);
        w.write_tlv(tlv::NONCE, &self.nonce);
        w.write_tlv(tlv::PROOF, &self.proof);
        write_credentials(&mut w, &self.credentials);
        w.finish()
    }

    /// What the asker's proof packet names: the introduction ask's label, the
    /// offering device's Name TLV and [`fields`](Self::fields) ([`ask_binding`]).
    pub fn binding(&self, device: &Name) -> [u8; 32] {
        ask_binding(
            AskProtocol::IntroAsk,
            &[&device.encode_to_tlv(), &self.fields()],
        )
    }

    /// Its plaintext.
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_raw(&self.fields());
        w.write_tlv(tlv::ASKER, &self.asker);
        w.finish()
    }

    /// Read a plaintext.
    pub fn decode(plain: Bytes) -> Result<Self, WireError> {
        let (mut offer, mut nonce, mut proof, mut credentials, mut asker) =
            (None, None, None, None, None);
        each(plain, |t, v| {
            match t {
                tlv_type::NAME => offer = Some(read_name(v)?),
                tlv::NONCE => nonce = Some(read_nonce(&v)?),
                tlv::PROOF => proof = Some(read_digest(&v)?),
                tlv::CREDENTIALS => credentials = Some(read_credentials(v)?),
                tlv::ASKER => asker = Some(v),
                _ => return Ok(false),
            }
            Ok(true)
        })?;
        Ok(Self {
            offer: offer.ok_or_else(|| bad("an ask names its offer"))?,
            nonce: nonce.ok_or_else(|| bad("an ask carries a nonce"))?,
            proof: proof.ok_or_else(|| bad("an ask carries its proof"))?,
            credentials: credentials.ok_or_else(|| bad("an ask carries its credentials"))?,
            asker: asker.ok_or_else(|| bad("an ask carries the asker's proof"))?,
        })
    }
}

impl IntroAsk {
    /// Its `IntroAsk` TLV: an ask Interest's ApplicationParameters.
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(tlv::INTRO_ASK, |w| {
            w.write_tlv(tlv::EPHEMERAL_KEY, &self.ephemeral);
            w.write_tlv(tlv::CIPHERTEXT, &self.key);
            w.write_tlv(tlv::CIPHERTEXT, &self.sealed);
        });
        w.finish()
    }

    /// Read an ask Interest's ApplicationParameters: one `IntroAsk`.
    pub fn decode(params: Bytes) -> Result<Self, WireError> {
        let (typ, value) = one(params, "an ask's parameters")?;
        if typ != tlv::INTRO_ASK {
            return Err(bad("an ask's parameters are one IntroAsk"));
        }
        let (mut ephemeral, mut texts) = (None, Vec::new());
        each(value, |t, v| {
            match t {
                tlv::EPHEMERAL_KEY => ephemeral = Some(read_digest(&v)?),
                tlv::CIPHERTEXT => texts.push(v),
                _ => return Ok(false),
            }
            Ok(true)
        })?;
        let [key, sealed]: [Bytes; 2] = texts
            .try_into()
            .map_err(|_| bad("an ask carries two ciphertexts"))?;
        Ok(Self {
            ephemeral: ephemeral.ok_or_else(|| bad("an ask carries its ephemeral key"))?,
            key,
            sealed,
        })
    }
}

// ---- the answer -------------------------------------------------------------------------------

/// What an answer says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The asker is a member.
    Accepted {
        /// The space.
        space: Name,
        /// What the offer granted.
        role: Role,
        /// The inviter's signed trust context and its device key's certificates.
        credentials: Vec<Bytes>,
        /// The offering device's proof packet `<D>/32=ask/<binding>`, signed by
        /// its key ([`AnswerBody::binding`]).
        inviter: Bytes,
        /// The Members entry the inviter's change made when it admitted the
        /// asker: the joiner returns from its join once it holds exactly this
        /// entry. `None` in an answer that does not name one.
        admitted: Option<EntryId>,
    },
    /// Refused, and why ([`IntroRefusal::Forged`] never travels).
    Refused(IntroRefusal),
}

/// An answer (spec §19.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnswerBody {
    /// The offer.
    pub offer: Name,
    /// The asker key it answers.
    pub asker: Name,
    /// That key's public key digest.
    pub digest: [u8; 32],
    /// What it says.
    pub outcome: Outcome,
    /// HMAC-SHA256 of [`AnswerBody::proven`] under the offer's proof key: present
    /// exactly on an acceptance. A refusal is not authenticated (a joiner whose
    /// secret is wrong could not check it anyway); it grants nothing and changes
    /// nothing (spec §19.7).
    pub proof: Option<[u8; 32]>,
}

impl AnswerBody {
    fn head(&self, w: &mut TlvWriter) {
        write_name(w, &self.offer);
        w.write_nested(tlv::WRITER, |w| write_name(w, &self.asker));
        w.write_tlv(tlv::DIGEST, &self.digest);
    }

    fn outcome_fields(&self, w: &mut TlvWriter, with_inviter: bool) {
        match &self.outcome {
            Outcome::Accepted {
                space,
                role,
                credentials,
                inviter,
                admitted,
            } => {
                write_name(w, space);
                write_nni(w, tlv::ROLE, role.code());
                if let Some(admitted) = admitted {
                    write_admitted(w, admitted);
                }
                write_credentials(w, credentials);
                if with_inviter {
                    w.write_tlv(tlv::ASKER, inviter);
                }
            }
            Outcome::Refused(why) => {
                write_nni(w, tlv::INTRO_REFUSED, why.code());
                if let IntroRefusal::WrongProof { left } = why {
                    write_nni(w, tlv::TRIES, u64::from(*left));
                }
            }
        }
    }

    /// What the offering device's proof packet names: the introduction answer's
    /// label and the answer's fields before it ([`ask_binding`]).
    pub fn binding(&self) -> [u8; 32] {
        let mut w = TlvWriter::new();
        self.head(&mut w);
        self.outcome_fields(&mut w, false);
        ask_binding(AskProtocol::IntroAnswer, &[&w.finish()])
    }

    /// What its `Proof` is over: every field before it.
    pub fn proven(&self) -> Bytes {
        let mut w = TlvWriter::new();
        self.head(&mut w);
        self.outcome_fields(&mut w, true);
        w.finish()
    }

    /// Its TLV, an answer packet's Content.
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(tlv::INTRO_ANSWER, |w| {
            w.write_raw(&self.proven());
            if let Some(p) = &self.proof {
                w.write_tlv(tlv::PROOF, p);
            }
        });
        w.finish()
    }

    /// Read an answer packet's Content.
    pub fn decode(content: Bytes) -> Result<Self, WireError> {
        let (typ, value) = one(content, "an answer")?;
        if typ != tlv::INTRO_ANSWER {
            return Err(bad("an answer is one IntroAnswer"));
        }
        let mut names = Vec::new();
        let (mut asker, mut digest, mut role, mut credentials, mut inviter) =
            (None, None, None, None, None);
        let mut admitted = None;
        let (mut refused, mut left, mut proof) = (None, None, None);
        each(value, |t, v| {
            match t {
                tlv_type::NAME => names.push(read_name(v)?),
                tlv::WRITER => asker = Some(read_writer(v)?),
                tlv::DIGEST => digest = Some(read_digest(&v)?),
                tlv::ROLE => role = Some(Role::from_code(read_nni(&v)?)?),
                tlv::ADMITTED => {
                    if admitted.replace(read_admitted(v)?).is_some() {
                        return Err(bad("an answer names one admitting entry"));
                    }
                }
                tlv::CREDENTIALS => credentials = Some(read_credentials(v)?),
                tlv::ASKER => inviter = Some(v),
                tlv::INTRO_REFUSED => refused = Some(read_nni(&v)?),
                tlv::TRIES => left = Some(read_nni(&v)?),
                tlv::PROOF => proof = Some(read_digest(&v)?),
                _ => return Ok(false),
            }
            Ok(true)
        })?;
        let mut names = names.into_iter();
        let offer = names
            .next()
            .ok_or_else(|| bad("an answer names its offer"))?;
        let outcome = match (refused, names.next(), proof) {
            (Some(code), None, None) => Outcome::Refused(refusal(code, left)?),
            (None, Some(space), Some(_)) => Outcome::Accepted {
                space,
                role: role.ok_or_else(|| bad("an answer names the role"))?,
                credentials: credentials
                    .ok_or_else(|| bad("an answer carries the inviter's credentials"))?,
                inviter: inviter.ok_or_else(|| bad("an answer carries the inviter's proof"))?,
                admitted,
            },
            _ => {
                return Err(bad(
                    "an answer either admits, naming the space and proving the secret, or \
                     refuses, without a proof",
                ));
            }
        };
        Ok(Self {
            offer,
            asker: asker.ok_or_else(|| bad("an answer names the asker key"))?,
            digest: digest.ok_or_else(|| bad("an answer names the asker key's digest"))?,
            outcome,
            proof,
        })
    }
}

/// The refusal an `IntroRefused` code and the `Tries` left beside it say.
fn refusal(code: u64, left: Option<u64>) -> Result<IntroRefusal, WireError> {
    Ok(match code {
        1 => IntroRefusal::Unknown,
        2 => IntroRefusal::Used,
        3 => IntroRefusal::Expired,
        4 => IntroRefusal::Closed,
        5 => IntroRefusal::WrongProof {
            left: u32::try_from(left.ok_or_else(|| bad("a wrong proof says the tries left"))?)
                .map_err(|_| bad("tries left fit 32 bits"))?,
        },
        6 => IntroRefusal::Conflict,
        other => return Err(bad(format!("{other} is no refusal of an introduction"))),
    })
}

// ---- the link hint and the hint record --------------------------------------------------------

/// A link hint's TLVs into `w`: `key`, then each of the first `keep` (at most
/// [`LINK_HINT_CANDIDATES_MAX`]) dialable distinct `candidates` once, in order.
/// The inviter's own gathering chose which addresses to offer, so loopback and
/// link-local ones are written as they are.
pub(crate) fn write_link_hint(
    w: &mut TlvWriter,
    key: &[u8; 32],
    candidates: &[HintCandidate],
    keep: usize,
) {
    w.write_tlv(tlv::LINK_KEY, key);
    let mut seen: Vec<&HintCandidate> = Vec::new();
    for c in candidates {
        if seen.len() == keep.min(LINK_HINT_CANDIDATES_MAX) {
            break;
        }
        if !c.dialable(true) || seen.contains(&c) {
            continue;
        }
        seen.push(c);
        let mut value = [0u8; 19];
        value[0] = c.kind.code();
        let len = match c.addr.ip() {
            IpAddr::V4(ip) => {
                value[1..5].copy_from_slice(&ip.octets());
                7
            }
            IpAddr::V6(ip) => {
                value[1..17].copy_from_slice(&ip.octets());
                19
            }
        };
        value[len - 2..len].copy_from_slice(&c.addr.port().to_be_bytes());
        w.write_tlv(tlv::LINK_CANDIDATE, &value[..len]);
    }
}

/// One `LinkCandidate`'s value: the candidate it names, `None` for a kind this
/// version does not know, an error for a length that is no address.
pub(crate) fn read_candidate(v: &[u8]) -> Result<Option<HintCandidate>, WireError> {
    let ip_len = match v.len() {
        7 => 4,
        19 => 16,
        n => {
            return Err(bad(format!(
                "a link candidate is 7 or 19 octets (kind, address, port), not {n}"
            )));
        }
    };
    let Some(kind) = HintKind::from_code(v[0]) else {
        return Ok(None);
    };
    let ip = if ip_len == 4 {
        IpAddr::from(<[u8; 4]>::try_from(&v[1..5]).expect("4 octets"))
    } else {
        IpAddr::from(<[u8; 16]>::try_from(&v[1..17]).expect("16 octets"))
    };
    let port = u16::from_be_bytes([v[1 + ip_len], v[2 + ip_len]]);
    Ok(Some(HintCandidate {
        kind,
        addr: SocketAddr::new(ip, port),
    }))
}

/// A hint record (spec §19.2): the content of the Data named
/// `<device>/32=hint/<token>` ([`hint_name`]), signed by the device key. What the
/// joiner needs to dial the inviter after a short code's first contact: the key,
/// where to try it, relays by name and the credentials that let it verify the
/// signer with nothing but the code's fingerprint — or a mark that the offer is no
/// longer served.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HintRecord {
    /// The offer is served.
    Offered {
        /// The offer's name: the record is bound to it, under the device's
        /// signature, at a name only the secret's holder can ask for.
        offer: Name,
        /// SHA-256 of the device's public key: what the dial must prove
        /// ([`LinkHint::key`](crate::LinkHint::key)).
        key: [u8; 32],
        /// Where to try, most promising first, at most
        /// [`LINK_HINT_CANDIDATES_MAX`] (reachability hints only).
        candidates: Vec<HintCandidate>,
        /// Devices that relay to the inviter, by name, at most
        /// [`HINT_RELAYS_MAX`].
        relays: Vec<Name>,
        /// The offer's expiry. Informational: the offer judges its own.
        until: Timestamp,
        /// The inviter's signed trust context and the certificate chain of the
        /// signing key, as an answer carries them ([`Outcome::Accepted`]'s
        /// credentials).
        credentials: Vec<Bytes>,
    },
    /// The offer is no longer served: [`IntroRefusal::Expired`] or
    /// [`IntroRefusal::Closed`], the only refusals a hint record gives (any other
    /// is written as `Closed`). It carries the inviter's credentials and is signed
    /// as a record is, so that the joiner verifies it as it does a record: a mark
    /// that does not verify is anyone's, and ends nothing
    /// ([`IntroRefusal::GoneUnproven`]).
    Gone {
        /// Why the offer is not served.
        why: IntroRefusal,
        /// The inviter's signed trust context and the certificate chain of the
        /// signing key, as a record carries them.
        credentials: Vec<Bytes>,
    },
}

impl HintRecord {
    /// Its TLV, a hint Data's Content.
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(tlv::INTRO_HINT, |w| match self {
            HintRecord::Offered {
                offer,
                key,
                candidates,
                relays,
                until,
                credentials,
            } => {
                w.write_nested(tlv::HINT_OFFER, |w| write_name(w, offer));
                write_link_hint(w, key, candidates, LINK_HINT_CANDIDATES_MAX);
                for relay in relays.iter().take(HINT_RELAYS_MAX) {
                    w.write_nested(tlv::HINT_RELAY, |w| write_name(w, relay));
                }
                write_nni(w, tlv::HINT_UNTIL, until.0);
                write_credentials(w, credentials);
            }
            HintRecord::Gone { why, credentials } => {
                let code = if matches!(why, IntroRefusal::Expired) {
                    IntroRefusal::Expired.code()
                } else {
                    IntroRefusal::Closed.code()
                };
                write_nni(w, tlv::HINT_GONE, code);
                write_credentials(w, credentials);
            }
        });
        w.finish()
    }

    /// Read a hint Data's Content. Candidates are read as a link hint's are
    /// ([`LinkHint::decode`](crate::LinkHint::decode)): loopback and link-local
    /// addresses are passed over unless `include_local`
    /// ([`IntroPolicy::local_candidates`](crate::IntroPolicy::local_candidates)).
    /// An error says what is wrong.
    pub fn decode(content: Bytes, include_local: bool) -> Result<Self, WireError> {
        let (typ, value) = one(content, "a hint record")?;
        if typ != tlv::INTRO_HINT {
            return Err(bad("a hint record is one IntroHint"));
        }
        let (mut offer, mut key, mut until, mut credentials, mut gone) =
            (None, None, None, None, None);
        let mut candidates: Vec<HintCandidate> = Vec::new();
        let mut relays: Vec<Name> = Vec::new();
        each(value, |t, v| {
            match t {
                tlv::HINT_OFFER => {
                    if offer.replace(read_wrapped_name(v)?).is_some() {
                        return Err(bad("a hint record names one offer"));
                    }
                }
                tlv::LINK_KEY => {
                    if key.replace(read_digest(&v)?).is_some() {
                        return Err(bad("a hint record names one key"));
                    }
                }
                tlv::LINK_CANDIDATE => {
                    if let Some(c) = read_candidate(&v)?
                        && c.dialable(include_local)
                        && candidates.len() < LINK_HINT_CANDIDATES_MAX
                        && !candidates.contains(&c)
                    {
                        candidates.push(c);
                    }
                }
                tlv::HINT_RELAY => {
                    if relays.len() == HINT_RELAYS_MAX {
                        return Err(bad(format!(
                            "a hint record names at most {HINT_RELAYS_MAX} relays"
                        )));
                    }
                    relays.push(read_wrapped_name(v)?);
                }
                tlv::HINT_UNTIL => {
                    if until.replace(Timestamp(read_nni(&v)?)).is_some() {
                        return Err(bad("a hint record has one expiry"));
                    }
                }
                tlv::CREDENTIALS => {
                    if credentials.replace(read_credentials(v)?).is_some() {
                        return Err(bad("a hint record has one set of credentials"));
                    }
                }
                tlv::HINT_GONE => {
                    if gone.replace(read_nni(&v)?).is_some() {
                        return Err(bad("a hint record has one gone mark"));
                    }
                }
                _ => return Ok(false),
            }
            Ok(true)
        })?;
        if let Some(code) = gone {
            if offer.is_some()
                || key.is_some()
                || until.is_some()
                || !candidates.is_empty()
                || !relays.is_empty()
            {
                return Err(bad("a gone mark carries nothing but its credentials"));
            }
            let credentials = credentials.ok_or_else(|| {
                bad("a gone mark carries the inviter's credentials, which prove it")
            })?;
            return Ok(HintRecord::Gone {
                why: match code {
                    3 => IntroRefusal::Expired,
                    4 => IntroRefusal::Closed,
                    other => {
                        return Err(bad(format!(
                            "{other} is no gone mark (3 expired, 4 closed)"
                        )));
                    }
                },
                credentials,
            });
        }
        Ok(HintRecord::Offered {
            offer: offer.ok_or_else(|| bad("a hint record names its offer"))?,
            key: key.ok_or_else(|| bad("a hint record names its key"))?,
            candidates,
            relays,
            until: until.ok_or_else(|| bad("a hint record names the offer's expiry"))?,
            credentials: credentials
                .ok_or_else(|| bad("a hint record carries the inviter's credentials"))?,
        })
    }
}
