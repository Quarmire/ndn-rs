//! The plain types of an introduction and what the host does for it (spec
//! §19): the role an offer grants, the offer, the code, the grants, departures
//! and joined spaces the link layer is told, the inviter's link hint, and the
//! [`Host`] trait.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_heap::Timestamp;
use ndn_tlv::TlvWriter;
use ndn_trust_envelope::{Introduction, TrustEnvelope};

use crate::policy::IntroPolicy;
use crate::wire::{WireError, bad, each, read_candidate, read_digest, tlv, write_link_hint};

// ---- what callers see -------------------------------------------------------------------------

/// What an offer grants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    /// The joiner reads the space.
    Reader,
    /// The joiner reads and writes the space.
    Writer,
}

impl Role {
    pub(crate) fn code(self) -> u64 {
        match self {
            Role::Reader => 0,
            Role::Writer => 1,
        }
    }

    pub(crate) fn from_code(c: u64) -> Result<Self, WireError> {
        match c {
            0 => Ok(Role::Reader),
            1 => Ok(Role::Writer),
            other => Err(bad(format!("{other} is no role"))),
        }
    }
}

/// A one-use offer of a space, as the owner asks for it (`Invites::offer`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Offer {
    /// What it grants.
    pub role: Role,
    /// Its expiry, judged by the offering device's clock (spec §8.5).
    pub until: Timestamp,
    /// How many wrong tries of one asker (one key) close it to that asker (at
    /// least one): its wrong try that makes this many closes the offer to it for
    /// good, even to the right secret. Others' tries are counted apart; all
    /// askers' together are bounded by
    /// [`IntroPolicy::wrong_tries_max`](crate::IntroPolicy::wrong_tries_max).
    pub tries: u32,
}

/// A **grant** (spec §19.8): an offer of this device admitted a person, and the
/// host's link layer may link with the device holding `key` as a person of
/// `namespaces`, for as long as the space lists them (and, if `until` is set, not
/// past it). What [`Host::grant`] is told and `Invites::grants` lists.
///
/// A grant is authority to *link*, not to read: it informs, never widens. The
/// space's members and the epoch keys still decide what a link is answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    /// The asker's key's public-key digest: what a link's handshake proves
    /// (ndn-link's `KeyFingerprint`). A person's other keys are not granted.
    pub key: [u8; 32],
    /// The namespaces the person may be identified in: the asker's namespace, as
    /// the join adopted it.
    pub namespaces: Vec<Name>,
    /// The space the offer admitted the person to.
    pub folder: Name,
    /// The person's role in the space **now**: derived from the members in force
    /// for it (a writer demoted to a reader is a reader), not the offer's.
    pub role: Role,
    /// A date after which the grant is over, by the inviter's clock; `None`: no
    /// date, the grant lasts while the space lists the person and ends when it no
    /// longer does (the default, [`IntroPolicy::grant_for`]).
    pub until: Option<Timestamp>,
}

/// Writers listed per joined space: [`JoinedFolder::writers`] keeps at most this
/// many namespaces (sorted, the first ones), so a hostile inviter's entry that
/// lists a crowd of writers makes the link layer route no more than this many
/// prefixes for one space.
pub const JOINED_WRITERS_MAX: usize = 16;

/// A space this device **joined** (spec §19.8, the mirror grant), and what its
/// link to the inviter must route for it: what `Invites::joined_folders` lists,
/// one for each live mirror note whose space still lists this device.
///
/// It is derived on every call from the members in force and the device's own MAC'd
/// mirror note, never cached, and it carries no authority of its own: the link
/// layer routes by it, the inviter's per-packet filter still decides what crosses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinedFolder {
    /// The inviter's device key's digest: the mirror grant's key. Under a host
    /// whose link key is its device key, the inviter's ndn-link `KeyFingerprint`; a
    /// host with another link key maps it itself, as it does for grants.
    pub inviter: [u8; 32],
    /// The space's namespace, which is the inviter's namespace.
    pub owner: Name,
    /// The space the offer admitted this device to.
    pub folder: Name,
    /// This device's role in the members in force now: a writer when they list
    /// the device's person as one, else a reader.
    pub role: Role,
    /// The namespaces of the other writers the members in force list, minus this
    /// device's own namespace and every namespace above or below it (a hostile
    /// inviter's entry cannot make this device route its own names, or a broad
    /// parent of them, toward the inviter), and minus every name that could win a
    /// longer match over a route this device has: only a name that names itself
    /// (the namespace of a trust context held here, or a self-certifying person's),
    /// that [`IntroPolicy::refuses`] does not refuse (no reserved or broad shared
    /// name) and that lies neither above nor below a namespace held or adopted here
    /// (spec §19.8 rule 18); only namespaces; sorted (the order of `Name`, the
    /// canonical one); at most [`JOINED_WRITERS_MAX`], the first of them.
    pub writers: Vec<Name>,
}

/// What a person who was **let go** is to be told (spec §19.8): the space stopped
/// listing a granted person, and the grant's note keeps a **departure mark** (MAC'd
/// with it) for [`IntroPolicy::departure_for`], so that the link layer can show the
/// person — online now or back later — the one entry that lets them go, and nothing
/// else. What [`Host::departure`] is told and `Invites::departures` lists.
///
/// A mark is a hint of *which name to fetch*; it carries no authority: the person
/// validates the entry by its signatures (`Surface::take_departure`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Departure {
    /// The person's device key (the grant's key).
    pub key: [u8; 32],
    /// The namespaces the grant admitted the key in.
    pub namespaces: Vec<Name>,
    /// The space the person was let go of.
    pub folder: Name,
    /// The log entry name of the held Members entry that leaves the person out:
    /// `<signer device>/32=log/<space>/seq=<n>`. Its pieces are named by it and
    /// carried with it.
    pub record: Name,
    /// By this device's clock: the mark is no longer served after it.
    pub until: Timestamp,
}

/// An offer's code: what the owner shows the joiner. Its link and words carry the
/// secret; [`Debug`] shows neither.
#[derive(Clone, PartialEq, Eq)]
pub struct Code {
    /// The offer packet's name, `<D>/32=intro/offer/<id>`.
    pub offer: Name,
    /// `ndn-trust://intro/<base64url>`, at most one QR
    /// ([`ndn_trust_envelope::qr::MAX_TEXT_LEN`]).
    pub link: String,
    /// The offer's name and 24 words: the secret and the anchor fingerprint's first
    /// half.
    pub words: String,
    /// The **short code**, one line a person can read aloud or type
    /// ([`ShortCode`](crate::ShortCode)): the inviter's device name, a first
    /// contact, and 20 or 36 words. `None` when [`short_why`](Self::short_why) says
    /// why.
    pub short: Option<String>,
    /// Why there is no short code, when `short` is `None`: policy off, no first
    /// contact the host can give, or a line past [`IntroPolicy::short_width`].
    /// `None` when there is one.
    pub short_why: Option<String>,
}

impl std::fmt::Debug for Code {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Code")
            .field("offer", &self.offer)
            .finish_non_exhaustive()
    }
}

impl Code {
    /// What to show: the short code when there is one, else the link.
    pub fn share(&self) -> &str {
        self.short.as_deref().unwrap_or(&self.link)
    }
}

/// What a join brought (`Invites::join`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Joined {
    /// The space this device now reads (and writes, as a writer).
    pub space: Name,
    /// What the offer granted.
    pub role: Role,
    /// The inviter's namespace, adopted.
    pub inviter: Name,
}

/// The most direct-path candidate addresses a code carries, and a join dials: a
/// hint is a few addresses of one device, and a code stays within one QR (spec
/// §19.2).
pub const LINK_HINT_CANDIDATES_MAX: usize = 8;

/// How the inviter's device knows a candidate address of its own: the kinds of
/// ndn-link (`ndn_link::CandidateKind`; ndn-link.md), by the same codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HintKind {
    /// An address of one of its interfaces, on its link socket's port.
    Host,
    /// The address a linked device sees it at: beyond the NATs on that path.
    Reflexive,
    /// An address configured to reach its link socket (a port forward).
    Advertised,
    /// An address a port-mapping protocol mapped to its link socket.
    Mapped,
}

impl HintKind {
    /// The kind's octet on the wire.
    pub fn code(self) -> u8 {
        match self {
            HintKind::Host => 0,
            HintKind::Reflexive => 1,
            HintKind::Advertised => 2,
            HintKind::Mapped => 3,
        }
    }

    /// The kind a code names; `None` for one this version does not know.
    pub fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0 => HintKind::Host,
            1 => HintKind::Reflexive,
            2 => HintKind::Advertised,
            3 => HintKind::Mapped,
            _ => return None,
        })
    }
}

/// One address where a device may be tried directly, over UDP.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HintCandidate {
    /// How the device knows it.
    pub kind: HintKind,
    /// The address and port.
    pub addr: SocketAddr,
}

impl HintCandidate {
    /// Whether a device can sensibly be dialled at this address: not the
    /// unspecified, a multicast or the broadcast address, not port 0, and, unless
    /// `include_local`, not a loopback or link-local one. A code from a stranger is
    /// not made to send datagrams to those.
    pub(crate) fn dialable(&self, include_local: bool) -> bool {
        let ip = self.addr.ip().to_canonical();
        self.addr.port() != 0
            && !ip.is_unspecified()
            && !ip.is_multicast()
            && !matches!(ip, IpAddr::V4(v4) if v4.is_broadcast())
            && (include_local || !is_local(ip))
    }
}

/// Whether `ip` is a loopback or link-local address (the ones ndn-link's candidate
/// gathering leaves out).
fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// The inviter's link hint (spec §19.2): the key of its device and where to try it
/// directly. The key is what the dial's handshake proves; the addresses only say
/// where to try (spec §19.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkHint {
    /// SHA-256 of the device's public key as a certificate carries it: the key the
    /// link must prove (the fingerprint of ndn-link's `KeyFingerprint`).
    pub key: [u8; 32],
    /// Where to try, most promising first, at most [`LINK_HINT_CANDIDATES_MAX`].
    pub candidates: Vec<HintCandidate>,
}

impl LinkHint {
    /// The hint's TLVs (the value of the intro envelope's `LinkHint`): the key,
    /// then each of the first [`LINK_HINT_CANDIDATES_MAX`] candidates once, in
    /// order. The inviter's own gathering chose which addresses to offer, so
    /// loopback and link-local ones it was given are written as they are.
    pub fn encode(&self) -> Bytes {
        self.encode_first(self.candidates.len())
    }

    /// [`encode`](Self::encode) with at most `keep` candidates.
    fn encode_first(&self, keep: usize) -> Bytes {
        let mut w = TlvWriter::new();
        write_link_hint(&mut w, &self.key, &self.candidates, keep);
        w.finish()
    }

    /// Read the value of an intro envelope's `LinkHint`: one key and its
    /// candidates — the first [`LINK_HINT_CANDIDATES_MAX`] distinct ones that name
    /// an address this device may dial and a kind this version knows; the others
    /// are passed over. Loopback and link-local addresses are passed over unless
    /// `include_local` ([`IntroPolicy::local_candidates`]): a stranger's code does
    /// not make this device send datagrams to itself or its link. An error says
    /// what is wrong: a join carries on without the hint (it only helps to reach).
    pub fn decode(value: &[u8], include_local: bool) -> Result<Self, String> {
        let mut key = None;
        let mut candidates: Vec<HintCandidate> = Vec::new();
        each(Bytes::copy_from_slice(value), |t, v| {
            match t {
                tlv::LINK_KEY => {
                    if key.is_some() {
                        return Err(bad("a link hint names two keys"));
                    }
                    key = Some(read_digest(&v)?);
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
                _ => return Ok(false),
            }
            Ok(true)
        })
        .map_err(|e| e.0)?;
        Ok(LinkHint {
            key: key.ok_or("a link hint names no key")?,
            candidates,
        })
    }

    /// The link of an offer's code carrying `hint`, within one QR: the secret, the
    /// offer and the fingerprint are never dropped; at most
    /// [`IntroPolicy::code_relays`] relay hints are named and at most
    /// [`IntroPolicy::code_candidates`] candidates carried; relay hints go first
    /// (all of them), then the hint's last candidates one by one, then the hint
    /// itself. `None` when even those do not fit.
    pub fn code_link(
        mut intro: Introduction,
        hint: Option<&LinkHint>,
        policy: &IntroPolicy,
    ) -> Option<String> {
        intro.relays.truncate(policy.code_relays);
        if let Some(hint) = hint.filter(|h| !h.candidates.is_empty()) {
            let most = hint
                .candidates
                .len()
                .min(LINK_HINT_CANDIDATES_MAX)
                .min(policy.code_candidates);
            for keep in (1..=most).rev() {
                let link = TrustEnvelope::Intro(Introduction {
                    link_hint: Some(hint.encode_first(keep)),
                    ..intro.clone()
                })
                .qr_uri();
                if link.is_some() {
                    return link;
                }
            }
        }
        TrustEnvelope::Intro(Introduction {
            link_hint: None,
            ..intro
        })
        .qr_uri()
    }
}

// ---- the host ---------------------------------------------------------------------------------

/// The future of a [`Host::dial`].
#[cfg(not(target_arch = "wasm32"))]
pub type Dialing<'a> = futures::future::BoxFuture<'a, Result<(), String>>;
/// The future of a [`Host::dial`].
#[cfg(target_arch = "wasm32")]
pub type Dialing<'a> = futures::future::LocalBoxFuture<'a, Result<(), String>>;

/// The future of a [`Host::dial_first`]: the key the link proved.
#[cfg(not(target_arch = "wasm32"))]
pub type FirstDialing<'a> = futures::future::BoxFuture<'a, Result<[u8; 32], String>>;
/// The future of a [`Host::dial_first`]: the key the link proved.
#[cfg(target_arch = "wasm32")]
pub type FirstDialing<'a> = futures::future::LocalBoxFuture<'a, Result<[u8; 32], String>>;

/// The future of a [`Host::adopt`].
#[cfg(not(target_arch = "wasm32"))]
pub type Adopting<'a> = futures::future::BoxFuture<'a, Result<(), String>>;
/// The future of a [`Host::adopt`].
#[cfg(target_arch = "wasm32")]
pub type Adopting<'a> = futures::future::LocalBoxFuture<'a, Result<(), String>>;

/// What the host does for introductions (`Invites::start`'s host): give this
/// device's anchor link, adopt another person's, dial the inviter, and tell its link
/// layer of grants, departures and joined spaces. Adopting a namespace for one
/// space alone is the node's ([`ndn_heap::Adopter`]), not the host's here.
pub trait Host: Send + Sync {
    /// The signed trust-context Data of this device's namespace, whole, as the host
    /// adopted it (what an inline anchor link carries).
    fn anchor(&self) -> Option<Bytes>;

    /// Adopt `link`, an inline anchor link (`TrustEnvelope::Anchor` with namespace,
    /// fingerprint and signed context) the layer has already checked: `Ok` once
    /// this device's validator trusts the namespace; an error says why not. A host
    /// on a forwarder adopts through it, so the forwarder also validates and routes
    /// the namespace.
    ///
    /// A self-certifying namespace (`/user/<0xA1: …>`) not held is adopted by name
    /// over the network (`ndn_cert::adopt_anchor_link`): its version 1 fetched and
    /// checked against the name, the newest reached from it; the context the link
    /// carries is never taken alone — a version 1 is only compared with the fetched
    /// one, and a different one refused as a fork. With no network to fetch over,
    /// refuse, saying to join again once the person's devices are reachable.
    fn adopt<'a>(&'a self, link: &'a TrustEnvelope) -> Adopting<'a>;

    /// This device's link hint for an offer's code (spec §19.2): its link key's
    /// fingerprint and the direct-path addresses a joiner may try now (at most
    /// [`LINK_HINT_CANDIDATES_MAX`] are kept, in this order), so a joiner with no
    /// routes and no daemon dials this device by key. `None` (the default): the code
    /// carries no hint; a host that listens for links gives one. The layer calls it
    /// once per `Invites::offer` and once for each hint record it makes on request
    /// (`HintRecord`), so a restarted host or a moved address is always current.
    fn link_hint(&self) -> Option<LinkHint> {
        None
    }

    /// Dial the inviter's device `inviter` by the hint its code carried (spec
    /// §19.3): try `hint.candidates` in order, and link only to the device whose key
    /// is `hint.key` (the handshake proves it; an address that answers with another
    /// key is no link), within `within` in all. `Ok` once a link to that device is
    /// up and carries Interests for `inviter`'s names (the offer fetch and the ask)
    /// to it; an error says why not — the unreachable addresses, a wrong key — and
    /// the join carries on by the relays the code names, else by name. The dial
    /// sends nothing of the code's secret: it is the host's link layer's, and the
    /// secret only ever travels inside the sealed ask.
    ///
    /// The default dials nothing: a host with no link layer of its own says so, and
    /// the join falls back as above.
    fn dial<'a>(&'a self, hint: &'a LinkHint, inviter: &'a Name, within: Duration) -> Dialing<'a> {
        let _ = (hint, within);
        Box::pin(async move {
            Err(format!(
                "this host has no link layer to dial {inviter} with (Host::dial): route to it, \
                 or run the device on a host that dials link hints"
            ))
        })
    }

    /// Dial the inviter's device `inviter` at the **one address** a short code names
    /// (spec §19.3 step 0, short form), with **no key to expect**: the code carries
    /// none, the hint record fetched over this link names it. `Ok(key)` once a link
    /// is up, `key` being the SHA-256 of the public key the handshake proved (the
    /// fingerprint of ndn-link's `KeyFingerprint`); until the joiner holds the
    /// inviter's namespace the link routes only
    /// [`introduction_prefixes`](crate::introduction_prefixes) of `inviter` — never
    /// the names the code claims for the device — so whoever answers at the address
    /// gets the introduction's Interests and nothing else, and what it may send in
    /// is bounded (answers under those prefixes, Interests for the joiner's own
    /// device names). The dial sends an **empty hello**: no certificate, no
    /// membership. The address is only a hint: it may be answered by anyone, and
    /// everything it serves is verified against the code. Within `within`; an error
    /// says why not. The host ends the link with [`undial`](Self::undial) when the
    /// join fails, and the join does so at once when the verified hint record names
    /// another key than the one returned.
    ///
    /// The default dials nothing: a host with no link layer says so, and the join
    /// says the first contact could not be reached.
    fn dial_first<'a>(
        &'a self,
        inviter: &'a Name,
        addr: SocketAddr,
        within: Duration,
    ) -> FirstDialing<'a> {
        let _ = (addr, within);
        Box::pin(async move {
            Err(format!(
                "this host has no link layer to dial {inviter} with (Host::dial_first): route \
                 to it, or run the device on a host that dials link hints"
            ))
        })
    }

    /// The join that dialled `inviter` by `hint` ([`dial`](Self::dial)) failed, or a
    /// first contact's link ([`dial_first`](Self::dial_first)) proved a key the
    /// verified hint record does not name: take down what the dial made. What
    /// answered at the hint's key proved nothing the join could check, so the link
    /// to it — which only carried the introduction — is not kept; a link that was up
    /// before the dial, or that has been identified since (the join went on, and
    /// this host holds the inviter's namespace), is left as it is. Called once for
    /// each such link, before the join's error is returned or, for a first contact
    /// of another key, before the offer is fetched.
    ///
    /// The default does nothing: a host with no link layer dialled nothing.
    fn undial(&self, hint: &LinkHint, inviter: &Name) {
        let _ = (hint, inviter);
    }

    /// An offer of this device admitted a person: the host's link layer may link
    /// with `grant.key` as a person of `grant.namespaces` in the role `grant.role`,
    /// until `grant.until` if it has one (else for as long as the space lists them)
    /// (spec §19.8). Called once the acceptance and the grant note are durable,
    /// never for a retry of the same asker, a refused ask, or when
    /// [`IntroPolicy::grant_for`] is `Some(Duration::ZERO)`; **again** with the grant
    /// as it now stands when the members change the person's role in the space (a
    /// writer demoted to a reader: the host replaces the grant, and a link made under
    /// the old role is closed); and again with the same value, for each grant in
    /// force, when the invitations start after a restart. A grant informs the link
    /// layer, never widens what the layer serves: the members and the epoch keys
    /// still decide what is answered.
    ///
    /// The default does nothing: a host with no link layer, or one that serves by
    /// policy.
    fn grant(&self, grant: &Grant) {
        let _ = grant;
    }

    /// The grant of `key` **for `folder`** has ended before its date: the space no
    /// longer lists the person (spec §19.8). Called once for each such grant (so once
    /// for each space a person was let into and is now left out of, naming that
    /// space only: the person's grant of another space stands), **before** the end is
    /// made durable (in memory only, and conservative: should the durable write fail,
    /// the change is judged again and the grant ended again); a grant that merely
    /// expired is not announced (the link layer judges `until` by its own clock). Not
    /// called for an end the host made (`Invites::end_grant`): the host knows. When
    /// the policy keeps a departure mark ([`IntroPolicy::departure_for`]),
    /// [`departure`](Self::departure) is called **just before** it, so a link layer
    /// that narrows a link on its last grant's end already holds the mark.
    ///
    /// The default does nothing.
    fn revoke_grant(&self, key: &[u8; 32], folder: &Name) {
        let _ = (key, folder);
    }

    /// The person of `departure.key` was **let go** of `departure.folder` by the held
    /// Members entry `departure.record` (spec §19.8): called once, **just before**
    /// [`revoke_grant`](Self::revoke_grant) for the same grant, in memory and before
    /// the mark is made durable, and again with the same value for each mark in
    /// force when the invitations start after a restart. The link layer may show the
    /// person that entry and nothing else until `departure.until`. Not called when
    /// [`IntroPolicy::departure_for`] is zero, nor for an end the host made.
    ///
    /// The default does nothing.
    fn departure(&self, departure: &Departure) {
        let _ = departure;
    }
}
