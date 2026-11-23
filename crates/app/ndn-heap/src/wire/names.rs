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
//!
//! Every name parses one way: `D`, `O`, `G` and `H` have no keyword component,
//! so the first keyword ends them; a seal key's and a grant's last component
//! is one opaque value.

use bytes::Bytes;
use ndn_foundation_types::{Name, NameComponent, tlv_type};
use ndn_tlv::{TlvReader, TlvWriter};

use super::prim::{WireError, each, once, read_array, read_epoch_id, read_name, write_epoch_id, write_name};
use super::tlv;
use super::types::{EntryRef, EpochId};

const DATA: &[u8] = b"data";
const LOG: &[u8] = b"log";
const SEAL: &[u8] = b"seal";
const GRANT: &[u8] = b"grant";
const HELD: &[u8] = b"held";
pub(super) const PIECE: &[u8] = b"piece";
pub(super) const MANIFEST: &[u8] = b"manifest";

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
pub(crate) fn is_namespace(name: &Name) -> bool {
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
pub(crate) struct SpaceName {
    /// The namespace that owns the space (before `32=data`).
    pub owner: Name,
    /// The 1 to 4 generic components after `32=data`.
    pub rest: Vec<NameComponent>,
}

/// `<owner>/32=data/<rest…>`.
pub(crate) fn space_name(owner: &Name, rest: &[NameComponent]) -> Name {
    let mut comps = owner.components().to_vec();
    comps.push(kw(DATA));
    comps.extend(rest.iter().cloned());
    Name::from_components(comps)
}

/// Parse `<O>/32=data/<c1>[/<c2>…]`: `O` is a namespace, 1 to 4 generic
/// components follow the one `32=data`.
pub(crate) fn parse_space_name(name: &Name) -> Option<SpaceName> {
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
pub(crate) fn sync_group_of(space: &Name) -> Option<Name> {
    let s = parse_space_name(space)?;
    let mut comps = ndn_security::sync_group(&s.owner).components().to_vec();
    comps.extend(s.rest);
    Some(Name::from_components(comps))
}

/// An entry's name: `<device>/32=log/<space>/seq=<seq>`.
pub(crate) fn log_name(device: &Name, space: &Name, seq: u64) -> Name {
    let mut comps = device.components().to_vec();
    comps.push(kw(LOG));
    comps.extend(space.components().iter().cloned());
    comps.push(NameComponent::sequence_num(seq));
    Name::from_components(comps)
}

/// A parsed entry name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LogName {
    /// The device whose log it is.
    pub device: Name,
    /// The space the entry is in.
    pub space: Name,
    /// Its sequence number in the (device, space) log.
    pub seq: u64,
}

/// Parse `<device>/32=log/<space>/seq=<seq>`: the device is everything before
/// the first `32=log` (a device name has no keyword), the space a space name.
pub(crate) fn parse_log_name(name: &Name) -> Option<LogName> {
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

/// `<device>/32=seal`: the prefix of every [`seal_key_name`] of `device`, what
/// a device's seal key packet is asked for by when its key is not known yet.
pub(crate) fn seal_key_prefix(device: &Name) -> Name {
    device.clone().append_component(kw(SEAL))
}

/// A device's seal key's name: `<device>/32=seal/<public key>`, the last
/// component the 32 octets of its X25519 public key.
pub(crate) fn seal_key_name(device: &Name, public: &[u8; 32]) -> Name {
    seal_key_prefix(device).append_component(NameComponent::generic(Bytes::copy_from_slice(public)))
}

/// Parse `<device>/32=seal/<public key>`.
pub(crate) fn parse_seal_key_name(name: &Name) -> Option<(Name, [u8; 32])> {
    let comps = name.components();
    let at = comps.iter().position(|c| is_kw(c, SEAL))?;
    if !is_device_comps(&comps[..at]) || at + 2 != comps.len() {
        return None;
    }
    let last = &comps[at + 1];
    if last.typ != tlv_type::GENERIC_NAME_COMPONENT {
        return None;
    }
    let public = <[u8; 32]>::try_from(last.value.as_ref()).ok()?;
    Some((name_of(&comps[..at]), public))
}

/// What a grant answers: the key of one epoch of a space, for the holder of
/// a seal key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct GrantAsk {
    /// The asker's seal public key.
    pub seal_key: [u8; 32],
    /// The space whose epoch key is asked for.
    pub space: Name,
    /// The epoch.
    pub epoch: EpochId,
}

impl GrantAsk {
    /// The `GRANT_ASK` TLV: `{ SEAL_KEY, Name(space), EPOCH_ID }`.
    pub(crate) fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(tlv::GRANT_ASK, |w| {
            w.write_tlv(tlv::SEAL_KEY, &self.seal_key);
            write_name(w, &self.space);
            write_epoch_id(w, &self.epoch);
        });
        w.finish()
    }

    /// Decode a `GRANT_ASK` TLV; the space must be a space name and the
    /// epoch's creator a device.
    pub(crate) fn decode(content: Bytes) -> Result<GrantAsk, WireError> {
        let value = super::prim::only(content, tlv::GRANT_ASK, "a grant ask is one GRANT_ASK TLV")?;
        let (mut seal_key, mut space, mut epoch) = (None, None, None);
        each(value, |t, v| {
            match t {
                tlv::SEAL_KEY => once(
                    &mut seal_key,
                    read_array::<32>(&v, "a seal key is 32 octets")?,
                    "a grant ask's seal key",
                )?,
                tlv_type::NAME => once(&mut space, read_name(v)?, "a grant ask's space")?,
                tlv::EPOCH_ID => once(&mut epoch, read_epoch_id(v)?, "a grant ask's epoch")?,
                _ => return Ok(false),
            }
            Ok(true)
        })?;
        match (seal_key, space, epoch) {
            (Some(seal_key), Some(space), Some(epoch)) if parse_space_name(&space).is_some() => {
                Ok(GrantAsk {
                    seal_key,
                    space,
                    epoch,
                })
            }
            _ => Err(WireError::Malformed(
                "a grant ask has a seal key, a space name and an epoch",
            )),
        }
    }
}

/// A grant's name: `<granter>/32=grant/<GrantAsk TLV>`.
pub(crate) fn grant_name(granter: &Name, ask: &GrantAsk) -> Name {
    granter
        .clone()
        .append_component(kw(GRANT))
        .append_component(NameComponent::generic(ask.encode()))
}

/// Parse `<granter>/32=grant/<GrantAsk TLV>`. Only the canonical encoding
/// parses, so one ask has one name.
pub(crate) fn parse_grant_name(name: &Name) -> Option<(Name, GrantAsk)> {
    let comps = name.components();
    let at = comps.iter().position(|c| is_kw(c, GRANT))?;
    if !is_device_comps(&comps[..at])
        || at + 2 != comps.len()
        || comps[at + 1].typ != tlv_type::GENERIC_NAME_COMPONENT
    {
        return None;
    }
    let ask = GrantAsk::decode(comps[at + 1].value.clone()).ok()?;
    (ask.encode() == comps[at + 1].value).then(|| (name_of(&comps[..at]), ask))
}

/// `<holder>/32=held`: the prefix of every [`held_name`] of `holder`.
pub(crate) fn held_prefix(holder: &Name) -> Name {
    holder.clone().append_component(kw(HELD))
}

/// The name that asks holder `holder` for a packet it keeps of another
/// device, `original` (an entry or a piece): `<holder>/32=held/<Name TLV>`.
/// It routes to the holder by its own name.
pub(crate) fn held_name(holder: &Name, original: &Name) -> Name {
    held_prefix(holder).append_component(NameComponent::generic(original.encode_to_tlv()))
}

/// Parse `<holder>/32=held/<Name TLV>`.
pub(crate) fn parse_held_name(name: &Name) -> Option<(Name, Name)> {
    let comps = name.components();
    let at = comps.iter().position(|c| is_kw(c, HELD))?;
    if !is_device_comps(&comps[..at])
        || at + 2 != comps.len()
        || comps[at + 1].typ != tlv_type::GENERIC_NAME_COMPONENT
    {
        return None;
    }
    let original = Name::decode_from_tlv(comps[at + 1].value.clone()).ok()?;
    Some((name_of(&comps[..at]), original))
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
}

/// Which [`Served`] name `name` can be, by one look: each kind's parser takes
/// everything before its keyword as a device name, which holds no keyword and
/// no digest, so only the first such component can be that keyword. The
/// parser of the kind still judges the name.
pub(crate) fn served_kind(name: &Name) -> Option<Served> {
    let first = name.components().iter().find(|c| !is_plain(c))?;
    if first.typ != tlv_type::KEYWORD {
        return None;
    }
    match first.value.as_ref() {
        LOG => Some(Served::Log),
        HELD => Some(Served::Held),
        SEAL => Some(Served::Seal),
        GRANT => Some(Served::Grant),
        _ => None,
    }
}
