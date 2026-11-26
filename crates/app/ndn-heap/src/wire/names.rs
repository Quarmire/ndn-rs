//! The names of the layer's packets (`docs/specs/heap.md`, §2).
//!
//! Every packet a device publishes is named under the device itself (its key
//! name without `KEY/<id>`), so a hierarchical trust schema admits it
//! everywhere and Interests for it route to the device:
//!
//! | packet | name |
//! |---|---|
//! | space | `<O>/32=data/<c1>[/<c2>…]` (1 to 4 generic components) |
//! | entry | `<D>/32=log/<S>/seq=<n>` |
//! | piece | `<entry name>/32=piece/seg=<i>` (see [`super::pieces`]) |
//! | seal key | `<D>/32=seal/<public key>` |
//! | grant | `<G>/32=grant/<GrantAsk TLV>` |
//! | held copy | `<H>/32=held/<Name TLV of the original>` |
//! | sync group | `<O>/32=sync/<c1>[/<c2>…]` |
//! | channel ask and session | `<D>/32=chan/<ParametersSha256Digest>` |
//! | channel announce | `<sync group>/32=chan/<ParametersSha256Digest>` |
//!
//! Every name parses one way: `D`, `O`, `G` and `H` have no keyword component,
//! so the first keyword ends them; a seal key's and a grant's last component
//! is one opaque value.

use bytes::Bytes;
use ndn_foundation_types::{Name, NameComponent, tlv_type};
use ndn_packet::Data;
use ndn_tlv::TlvWriter;

use super::prim::{WireError, fields, once, read_epoch_id, read_name, write_epoch_id, write_name};
use super::tlv;
use super::types::{EntryRef, EpochId};

const DATA: &[u8] = b"data";
const LOG: &[u8] = b"log";
const SEAL: &[u8] = b"seal";
const GRANT: &[u8] = b"grant";
const HELD: &[u8] = b"held";
const CHAN: &[u8] = b"chan";
pub(super) const PIECE: &[u8] = b"piece";
pub(super) const MANIFEST: &[u8] = b"manifest";
const SYNC: &[u8] = ndn_security::trust_context::SYNC_GROUP_KEYWORD;

/// Every keyword the layer's own names carry: a space (`data`), an entry
/// (`log`), its pieces (`piece`, `manifest`), a seal key, a grant, a held copy
/// (`seal`, `grant`, `held`), a sync group (`sync`) and a channel ask (`chan`). The sibling
/// surface refuses an extension that claims one
/// of them ([`crate::host`]).
pub(crate) const CORE_KEYWORDS: &[&[u8]] =
    &[DATA, LOG, SEAL, GRANT, HELD, PIECE, MANIFEST, SYNC, CHAN];

/// The most components a space name has after its `32=data`.
pub(crate) const SPACE_REST_MAX: usize = 4;

/// A keyword component.
pub(crate) fn kw(word: &'static [u8]) -> NameComponent {
    NameComponent::keyword(Bytes::from_static(word))
}

/// Whether `c` is the keyword `word`.
pub(crate) fn is_kw(c: &NameComponent, word: &[u8]) -> bool {
    c.typ == tlv_type::KEYWORD && c.value.as_ref() == word
}

/// The name of `comps`.
pub(crate) fn name_of(comps: &[NameComponent]) -> Name {
    Name::from_components(comps.iter().cloned())
}

/// A component that may stand in a namespace or a device name: neither a
/// keyword (those mark the layer's own names) nor a digest.
fn is_plain(c: &NameComponent) -> bool {
    !matches!(
        c.typ,
        tlv_type::KEYWORD | tlv_type::IMPLICIT_SHA256 | tlv_type::PARAMETERS_SHA256
    )
}

/// Whether `name` can be a namespace (an owner or a person): not the root,
/// and only plain components that are not sequence numbers (an entry name
/// ends in one, so a namespace must not).
///
/// Public: a sibling crate judges the persons and owners it is told of by it.
pub fn is_namespace(name: &Name) -> bool {
    is_namespace_comps(name.components())
}

fn is_namespace_comps(comps: &[NameComponent]) -> bool {
    !comps.is_empty()
        && comps
            .iter()
            .all(|c| is_plain(c) && c.typ != tlv_type::SEQUENCE_NUM)
}

/// Whether `name` can be a device name: not the root, and no keyword or
/// digest component, so the first keyword after it ends it.
pub(crate) fn is_device_name(name: &Name) -> bool {
    is_device_comps(name.components())
}

pub(crate) fn is_device_comps(comps: &[NameComponent]) -> bool {
    !comps.is_empty() && comps.iter().all(is_plain)
}

/// How many leading components of key name `key` (`<D>/KEY/<key-id>`) name
/// its device `D`; `None` for a name that is no key name.
pub(crate) fn device_len(key: &Name) -> Option<usize> {
    let comps = key.components();
    let d = comps.len().checked_sub(2)?;
    (d >= 1
        && comps[d].typ == tlv_type::GENERIC_NAME_COMPONENT
        && comps[d].value.as_ref() == b"KEY")
        .then_some(d)
}

/// The device a key belongs to: the key name without `KEY/<key-id>`.
pub(crate) fn device_of(key: &Name) -> Option<Name> {
    device_len(key).map(|n| name_of(&key.components()[..n]))
}

/// Whether the device named by `device` lies under the owner namespace of
/// `space`: the name half of the owner rule, which depends on the two names
/// alone and so is judged alike by every member in any arrival order.
pub(crate) fn device_owns(space: &Name, device: &[NameComponent]) -> bool {
    parse_space_name(space).is_some_and(|s| {
        let owner = s.owner.components();
        device.len() >= owner.len() && device[..owner.len()] == *owner
    })
}

/// Whether the key `key` (`<D>/KEY/<id>`) is a key of an owner device of
/// `space`: its device lies under the namespace before the space's
/// `32=data`. Alice's laptop and phone both own `/alice/32=data/notes`;
/// Bob's laptop does not; a name that is no key name has no owner.
pub(crate) fn owns(space: &Name, key: &Name) -> bool {
    device_len(key).is_some_and(|n| device_owns(space, &key.components()[..n]))
}

/// A parsed space name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaceName {
    /// The namespace that owns the space (before `32=data`).
    pub owner: Name,
    /// The 1 to 4 generic components after `32=data`.
    pub rest: Vec<NameComponent>,
}

/// Parse `<O>/32=data/<c1>[/<c2>…]`: `O` is a namespace, 1 to 4 generic
/// components follow the one `32=data`.
///
/// Public: a sibling crate that filters names reads a space's owner and path by it.
pub fn parse_space_name(name: &Name) -> Option<SpaceName> {
    let comps = name.components();
    let at = comps.iter().position(|c| is_kw(c, DATA))?;
    let (owner, rest) = (&comps[..at], &comps[at + 1..]);
    if !is_namespace_comps(owner)
        || rest.is_empty()
        || rest.len() > SPACE_REST_MAX
        || !rest
            .iter()
            .all(|c| c.typ == tlv_type::GENERIC_NAME_COMPONENT)
    {
        return None;
    }
    Some(SpaceName {
        owner: name_of(owner),
        rest: rest.to_vec(),
    })
}

/// The sync group of a space: `<O>/32=sync/<rest of S>`, the owner's group
/// ([`ndn_security::sync_group`]) plus the components after `32=data`.
pub fn sync_group_of(space: &Name) -> Option<Name> {
    let s = parse_space_name(space)?;
    let mut comps = ndn_security::sync_group(&s.owner).components().to_vec();
    comps.extend(s.rest);
    Some(Name::from_components(comps))
}

/// `<device>/32=log/<space>`: what every entry name of the device in the
/// space extends.
pub(crate) fn log_prefix(device: &Name, space: &Name) -> Name {
    let mut comps = device.components().to_vec();
    comps.push(kw(LOG));
    comps.extend(space.components().iter().cloned());
    Name::from_components(comps)
}

/// An entry's name: `<device>/32=log/<space>/seq=<seq>`.
pub fn log_name(device: &Name, space: &Name, seq: u64) -> Name {
    log_prefix(device, space).append_component(NameComponent::sequence_num(seq))
}

/// A parsed entry name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogName {
    /// The device whose log it is.
    pub device: Name,
    /// The space the entry is in.
    pub space: Name,
    /// Its sequence number in the (device, space) log.
    pub seq: u64,
}

/// Parse `<device>/32=log/<space>/seq=<seq>`: the device is everything before
/// the first `32=log` (a device name has no keyword), the space a space name.
///
/// Public: a sibling crate that filters names reads an entry's device and space by it.
pub fn parse_log_name(name: &Name) -> Option<LogName> {
    let comps = name.components();
    let at = comps.iter().position(|c| is_kw(c, LOG))?;
    let (last, space) = comps[at + 1..].split_last()?;
    let seq = last.as_sequence_num()?;
    if !is_device_comps(&comps[..at]) {
        return None;
    }
    let space = name_of(space);
    parse_space_name(&space)?;
    Some(LogName {
        device: name_of(&comps[..at]),
        space,
        seq,
    })
}

impl EntryRef {
    /// The name of the entry this reference points at, in `space`.
    pub(crate) fn name(&self, space: &Name) -> Name {
        log_name(&self.device, space, self.seq)
    }
}

/// `<device>/32=<word>/<opaque>`: a name whose last component is one opaque
/// generic value (a seal key, a grant ask, a held name).
fn keyed(device: &Name, word: &'static [u8], opaque: Bytes) -> Name {
    (device.clone().append_component(kw(word))).append_component(NameComponent::generic(opaque))
}

/// The device and the opaque value of a [`keyed`] name; `None` for any other.
fn parse_keyed<'a>(name: &'a Name, word: &[u8]) -> Option<(Name, &'a Bytes)> {
    let comps = name.components();
    let at = comps.iter().position(|c| is_kw(c, word))?;
    let [opaque] = &comps[at + 1..] else {
        return None;
    };
    (is_device_comps(&comps[..at]) && opaque.typ == tlv_type::GENERIC_NAME_COMPONENT)
        .then(|| (name_of(&comps[..at]), &opaque.value))
}

/// A device's seal key's name: `<device>/32=seal/<public key>`, the last
/// component the 32 octets of its X25519 public key.
///
/// Public: a sibling crate's cases name a seal key as the layer does.
pub fn seal_key_name(device: &Name, public: &[u8; 32]) -> Name {
    keyed(device, SEAL, Bytes::copy_from_slice(public))
}

/// Parse `<device>/32=seal/<public key>`.
///
/// Public: a sibling crate that filters names tells a seal key's name by it.
pub fn parse_seal_key_name(name: &Name) -> Option<(Name, [u8; 32])> {
    let (device, public) = parse_keyed(name, SEAL)?;
    Some((device, public.as_ref().try_into().ok()?))
}

/// The most octets of the seal key packet a grant ask carries: a signed Data of one X25519 key
/// is a few hundred, so this bounds what an ask may make a granter hold and decode, and the
/// size of the Interest name.
pub(crate) const SEAL_KEY_PACKET_MAX: usize = 2048;

/// The most certificates a grant ask carries of the asker's signer chain.
pub const ASKER_CHAIN_MAX: usize = 4;

/// The most octets of one certificate a grant ask carries (the held-copy limit).
pub(crate) const ASKER_CERT_MAX: usize = 4096;

/// The most octets of the chain a grant ask carries in all, so that the Interest's name with
/// the seal key packet stays inside one packet.
pub(crate) const ASKER_CHAIN_OCTETS_MAX: usize = 6144;

/// What a grant answers: the key of one epoch of a space, for the holder of
/// a seal key. The ask carries the asker's seal key packet itself (a signed
/// Data of a few hundred octets) and the certificates of its signer chain, so
/// the granter judges it where it stands and asks nothing back: the exchange
/// is one Interest and one Data.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GrantAsk {
    /// The asker's seal key packet's name, `<D>/32=seal/<public key>`
    /// ([`seal_key_name`]): the name of the packet in [`Self::seal_packet`].
    pub seal_key: Name,
    /// The space whose epoch key is asked for.
    pub space: Name,
    /// The epoch.
    pub epoch: EpochId,
    /// The asker's seal key packet as signed by its device: the whole Data.
    pub seal_packet: Bytes,
    /// The certificates of the key that signed [`Self::seal_packet`] and of its issuers, leaf
    /// first, each a whole Data: at most [`ASKER_CHAIN_MAX`], each at most 4,096 octets and
    /// 6,144 in all. The granter holds them only as unverified copies for the one judging.
    /// May be empty: the granter then judges from the certificates it holds.
    pub chain: Vec<Bytes>,
}

impl GrantAsk {
    /// An ask for `epoch` of `space` that carries `seal_packet`, the asker's seal key packet;
    /// refused if that is no Data named `<device>/32=seal/<public key>` or is over
    /// 2,048 octets. Whether the device signed it is for the granter's judge. It carries no
    /// certificates until [`Self::with_chain`].
    pub fn new(space: Name, epoch: EpochId, seal_packet: Bytes) -> Result<GrantAsk, WireError> {
        if seal_packet.len() > SEAL_KEY_PACKET_MAX {
            return Err(WireError::TooLarge {
                what: "a grant ask's seal key packet",
                size: seal_packet.len(),
                max: SEAL_KEY_PACKET_MAX,
            });
        }
        let data = Data::decode(seal_packet.clone()).map_err(|_| {
            WireError::Malformed("a grant ask carries the asker's seal key packet, a Data")
        })?;
        if parse_seal_key_name(&data.name).is_none() || parse_space_name(&space).is_none() {
            return Err(WireError::Malformed(
                "a grant ask carries a seal key packet (<device>/32=seal/<key>) and names a \
                 space (<owner>/32=data/<path>)",
            ));
        }
        Ok(GrantAsk {
            seal_key: (*data.name).clone(),
            space,
            epoch,
            seal_packet,
            chain: Vec::new(),
        })
    }

    /// This ask carrying `chain`, the certificates of the asker's signer chain, leaf first;
    /// refused if there are more than [`ASKER_CHAIN_MAX`], one is no Data or is over 4,096
    /// octets, or all are over 6,144. Whether the chain is the signer's is for the judge.
    pub fn with_chain(mut self, chain: Vec<Bytes>) -> Result<GrantAsk, WireError> {
        let total: usize = chain.iter().map(Bytes::len).sum();
        if chain.len() > ASKER_CHAIN_MAX
            || total > ASKER_CHAIN_OCTETS_MAX
            || chain.iter().any(|c| c.len() > ASKER_CERT_MAX)
        {
            return Err(WireError::TooLarge {
                what: "the certificates a grant ask carries",
                size: total,
                max: ASKER_CHAIN_OCTETS_MAX,
            });
        }
        if chain.iter().any(|c| Data::decode(c.clone()).is_err()) {
            return Err(WireError::Malformed(
                "a grant ask carries the asker's certificates, each a Data",
            ));
        }
        self.chain = chain;
        Ok(self)
    }

    /// The `GRANT_ASK` TLV: `{ Name(space), EPOCH_ID, SEAL_KEY_PACKET, ASKER_CERT* }`.
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(tlv::GRANT_ASK, |w| {
            write_name(w, &self.space);
            write_epoch_id(w, &self.epoch);
            w.write_tlv(tlv::SEAL_KEY_PACKET, &self.seal_packet);
            for cert in &self.chain {
                w.write_tlv(tlv::ASKER_CERT, cert);
            }
        });
        w.finish()
    }

    /// Decode a `GRANT_ASK` TLV; the space must be a space name, the epoch's
    /// creator a device, the packet a seal key packet's Data ([`Self::new`]) and the
    /// certificates Data within the limits ([`Self::with_chain`]). The parse stops at the first
    /// certificate over [`ASKER_CHAIN_MAX`] or [`ASKER_CHAIN_OCTETS_MAX`] octets in all,
    /// before it keeps it or reads anything after it.
    pub(crate) fn decode(content: Bytes) -> Result<GrantAsk, WireError> {
        let value = super::prim::only(content, tlv::GRANT_ASK, "a grant ask is one GRANT_ASK TLV")?;
        let (mut space, mut epoch, mut packet) = (None, None, None);
        let (mut chain, mut chain_octets) = (Vec::new(), 0);
        fields!(value, |v| {
            tlv_type::NAME => once(&mut space, read_name(v)?, "a grant ask's space")?,
            tlv::EPOCH_ID => once(&mut epoch, read_epoch_id(v)?, "a grant ask's epoch")?,
            tlv::SEAL_KEY_PACKET => once(&mut packet, v, "a grant ask's seal key packet")?,
            tlv::ASKER_CERT => {
                chain_octets += v.len();
                if chain.len() == ASKER_CHAIN_MAX || chain_octets > ASKER_CHAIN_OCTETS_MAX {
                    return Err(WireError::TooLarge {
                        what: "the certificates a grant ask carries",
                        size: chain_octets,
                        max: ASKER_CHAIN_OCTETS_MAX,
                    });
                }
                chain.push(v)
            },
        });
        let (Some(space), Some(epoch), Some(packet)) = (space, epoch, packet) else {
            return Err(WireError::Malformed(
                "a grant ask has a space name, an epoch and the asker's seal key packet",
            ));
        };
        GrantAsk::new(space, epoch, packet)?.with_chain(chain)
    }
}

/// A grant's name: `<granter>/32=grant/<GrantAsk TLV>`.
///
/// Public: a sibling crate's cases name a grant as the layer does.
pub fn grant_name(granter: &Name, ask: &GrantAsk) -> Name {
    keyed(granter, GRANT, ask.encode())
}

/// Parse `<granter>/32=grant/<GrantAsk TLV>`. Only the canonical encoding
/// parses, so one ask has one name.
///
/// Public: a sibling crate that filters names reads the space a grant ask is for by it.
pub fn parse_grant_name(name: &Name) -> Option<(Name, GrantAsk)> {
    let (granter, value) = parse_keyed(name, GRANT)?;
    let ask = GrantAsk::decode(value.clone()).ok()?;
    (ask.encode() == *value).then_some((granter, ask))
}

/// The name that asks holder `holder` for a packet it keeps of another
/// device, `original` (an entry or a piece): `<holder>/32=held/<Name TLV>`.
/// It routes to the holder by its own name.
///
/// Public: a sibling crate's cases name a held copy as the layer does.
pub fn held_name(holder: &Name, original: &Name) -> Name {
    keyed(holder, HELD, original.encode_to_tlv())
}

/// Parse `<holder>/32=held/<Name TLV>`.
///
/// Public: a sibling crate that filters names unwraps a held copy's name by it.
pub fn parse_held_name(name: &Name) -> Option<(Name, Name)> {
    let (holder, value) = parse_keyed(name, HELD)?;
    Some((holder, Name::decode_from_tlv(value.clone()).ok()?))
}

/// The asks and fetches a device serves, by the keyword right after its own
/// name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Served {
    /// `<device>/32=log/…`: an entry, or a piece under one.
    Log,
    /// `<holder>/32=held/<name>`.
    Held,
    /// `<device>/32=seal/<key>`.
    Seal,
    /// `<granter>/32=grant/<ask>`.
    Grant,
    /// `<device>/32=chan/<ParametersSha256Digest>`: a channel ask, answered by a session.
    Chan,
}

/// Which [`Served`] name `name` can be, by one look: each kind's parser takes
/// everything before its keyword as a device name, which holds no keyword and
/// no digest, so only the first such component can be that keyword. The
/// parser of the kind still judges the name.
pub(crate) fn served_kind(name: &Name) -> Option<Served> {
    match keyword_of(name)? {
        LOG => Some(Served::Log),
        HELD => Some(Served::Held),
        SEAL => Some(Served::Seal),
        GRANT => Some(Served::Grant),
        CHAN => Some(Served::Chan),
        _ => None,
    }
}

/// The octets of a channel ask's parameters digest: the last component of its name.
const CHAN_DIGEST_LEN: usize = 32;

/// `<device>/32=chan`: what a channel ask is named under before its parameters digest is
/// appended (an Interest with ApplicationParameters gets that component from its encoder).
///
/// Public: a sibling crate's cases name a channel ask as the layer does.
pub fn chan_prefix(device: &Name) -> Name {
    device.clone().append_component(kw(CHAN))
}

/// The device of `<device>/32=chan`, the name an ask is made under before its digest: `None` for
/// any other name.
pub(crate) fn parse_chan_prefix(name: &Name) -> Option<Name> {
    let (last, device) = name.components().split_last()?;
    (is_kw(last, CHAN) && is_device_comps(device)).then(|| name_of(device))
}

/// A channel ask's name, and the name of the session that answers it:
/// `<device>/32=chan/<ParametersSha256Digest>`, `device` the device that answers.
///
/// Public: a sibling crate's cases name a channel ask as the layer does.
pub fn chan_ask_name(device: &Name, digest: &[u8; 32]) -> Name {
    chan_prefix(device).append_component(NameComponent::new(
        tlv_type::PARAMETERS_SHA256,
        Bytes::copy_from_slice(digest),
    ))
}

/// Parse `<device>/32=chan/<ParametersSha256Digest>`: `device` is everything before the first
/// `32=chan` (a device name, so it holds no keyword), exactly one component follows, and it is a
/// ParametersSha256DigestComponent of 32 octets. Nothing else parses.
///
/// Public: a sibling crate that filters names tells a channel ask by it.
pub fn parse_chan_name(name: &Name) -> Option<(Name, [u8; 32])> {
    let comps = name.components();
    let at = comps.iter().position(|c| is_kw(c, CHAN))?;
    let [digest] = &comps[at + 1..] else {
        return None;
    };
    if !is_device_comps(&comps[..at]) || digest.typ != tlv_type::PARAMETERS_SHA256 {
        return None;
    }
    let digest = <[u8; CHAN_DIGEST_LEN]>::try_from(digest.value.as_ref()).ok()?;
    Some((name_of(&comps[..at]), digest))
}

/// The announce of a channel: `<sync group of the space>/32=chan/<ParametersSha256Digest>`: the
/// ask's shape under the group instead of a device.
#[cfg(test)]
pub(crate) fn chan_announce_name(group: &Name, digest: &[u8; 32]) -> Name {
    chan_ask_name(group, digest)
}

/// Parse an announce, `<sync group>/32=chan/<ParametersSha256Digest>`: the sync group of a
/// space (`<O>/32=sync/<c1>[/<c2>…]`, `O` a namespace and one to four generic components after
/// the keyword) and its digest. Which space the group is of is the node's to say.
pub(crate) fn parse_chan_announce_name(name: &Name) -> Option<(Name, [u8; 32])> {
    let comps = name.components();
    let [group @ .., chan, digest] = comps else {
        return None;
    };
    if !is_kw(chan, CHAN) || digest.typ != tlv_type::PARAMETERS_SHA256 {
        return None;
    }
    let sync = group.iter().position(|c| is_kw(c, SYNC))?;
    let rest = &group[sync + 1..];
    let plain_rest = rest
        .iter()
        .all(|c| c.typ == tlv_type::GENERIC_NAME_COMPONENT);
    if !is_namespace_comps(&group[..sync])
        || rest.is_empty()
        || rest.len() > SPACE_REST_MAX
        || !plain_rest
    {
        return None;
    }
    let digest = <[u8; CHAN_DIGEST_LEN]>::try_from(digest.value.as_ref()).ok()?;
    Some((name_of(group), digest))
}

/// The first keyword of `name`: what a device's names are routed by, since
/// the device name before it holds no keyword and no digest. `None` when the
/// first component that is not plain is no keyword, or there is none.
pub(crate) fn keyword_of(name: &Name) -> Option<&[u8]> {
    let first = name.components().iter().find(|c| !is_plain(c))?;
    (first.typ == tlv_type::KEYWORD).then(|| first.value.as_ref())
}
