//! Introductions (spec §19): a stranger joins a folder by a code.
//!
//! The owner's device makes a one-use **offer** ([`Device::offer`]): a
//! record in its own log naming the folder, the [`Role`] it grants, its
//! expiry, the wrong tries it allows, a commitment to a secret and the
//! device's seal key. The [`Code`] carries the offer's name, the secret and
//! the owner's anchor fingerprint, as an `ndn-trust://intro/…` link
//! ([`ndn_trust_envelope::Introduction`]) or as words. The joiner's device
//! ([`Device::join`]) fetches the offer, sends an **ask** sealed to the
//! offering device carrying its own anchor link and a proof of the secret
//! bound to its key, and takes the **answer**: the folder, the role and the
//! owner's anchor link, bound to its key. The owner's device adopts the
//! joiner's anchor, adds the joiner to the folder's members record and
//! marks the offer used in its log; the joiner, unless the owner's
//! namespace overlaps one it trusts, adopts the owner's anchor and follows
//! the folder. [`IntroPolicy`] is what a device allows of it.
//!
//! This module holds the types, the bytes ([`IntroRecord`], [`IntroAsk`],
//! [`AskBody`], [`AnswerBody`]) and the proofs; the exchange itself is the
//! device's.
//!
//! [`Device::offer`]: crate::Device::offer
//! [`Device::join`]: crate::Device::join

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use bytes::Bytes;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use ndn_foundation_types::{Name, NameComponent, tlv_type};
use ndn_security::ScopedContext;
use ndn_tlv::{TlvReader, TlvWriter};
use ndn_trust_envelope::{Introduction, TrustEnvelope};
use sha2::{Digest, Sha256};

use crate::version::Timestamp;
use crate::wire::{
    self, NONCE_LEN, WireError, bad, each, is_device_comps, is_kw, kw, name_of, read_digest,
    read_name, read_nni, read_nonce, read_writer, tlv, write_name, write_nni,
};

/// Octets of an offer's secret ([`ndn_trust_envelope::INTRO_SECRET_LEN`]).
pub const SECRET_LEN: usize = ndn_trust_envelope::INTRO_SECRET_LEN;

/// The keyword of an ask's name: `<D>/32=intro/<IntroAsk>`.
const INTRO: &[u8] = b"intro";

/// Domain labels of the exchange's derivations.
const COMMIT: &[u8] = b"ndn-data/intro/commit/1";
const PROOF_KEY: &[u8] = b"ndn-data/intro/proof/1";
const ASK_PROOF: &[u8] = b"ndn-data/intro/ask/1";
const ANSWER_PROOF: &[u8] = b"ndn-data/intro/answer/1";

type HmacSha256 = Hmac<Sha256>;

// ---- what callers see -------------------------------------------------------------------------

/// What an offer grants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    /// The joiner reads the folder.
    Reader,
    /// The joiner reads and writes the folder.
    Writer,
}

impl Role {
    fn code(self) -> u64 {
        match self {
            Role::Reader => 0,
            Role::Writer => 1,
        }
    }

    fn from_code(c: u64) -> Result<Self, WireError> {
        match c {
            0 => Ok(Role::Reader),
            1 => Ok(Role::Writer),
            other => Err(bad(format!("{other} is no role"))),
        }
    }
}

/// A one-use offer of a folder, as the owner asks for it
/// ([`Device::offer`](crate::Device::offer)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Offer {
    /// What it grants.
    pub role: Role,
    /// Its expiry, judged by the offering device's clock (spec §8.5).
    pub until: Timestamp,
    /// How many wrong tries of one asker (one key) close it to that asker
    /// (at least one): its wrong try that makes this many closes the offer
    /// to it for good, even to the right secret. Others' tries are
    /// counted apart; all askers' together are bounded by
    /// [`IntroPolicy::wrong_tries_max`].
    pub tries: u32,
}

/// What a device's introductions allow and cost it (`Config::intro`, spec
/// §19.4, §19.7): which namespaces an introduction may bring, either way,
/// and how wrong tries and a crowd of asks are bounded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntroPolicy {
    /// The fewest name components a namespace an introduction brings has:
    /// the root, over every name, is never brought, whatever this says.
    pub min_components: usize,
    /// Names no introduction brings, nor a name under or over one: scopes
    /// that are never a person's (`/localhost`, `/localhop`).
    pub reserved: Vec<Name>,
    /// Typed prefixes shared by many people's namespaces (`/user`, whose
    /// `/user/<hash>` names are people's): no introduction brings one of
    /// them or a name over it; a name under one is a person's like any
    /// other.
    pub shared: Vec<Name>,
    /// Wrong tries of one offer, all askers' together, that close it for
    /// everyone, durably: the backstop under per-asker counting
    /// ([`Offer::tries`]), which anyone can make new askers for.
    pub wrong_tries_max: u32,
    /// The pause after a wrong try counted toward `wrong_tries_max`,
    /// doubled by each one counted (by the offering device's clock): a
    /// wrong try within the pause counts against its asker alone, so
    /// closing an offer for everyone takes strangers about `backoff`
    /// times 2^`wrong_tries_max`.
    pub backoff: std::time::Duration,
    /// Asks a device holds at once — verifying their asker or waiting for
    /// their turn to be judged; one more gets no answer (a Nack) at once,
    /// and its asker retries.
    pub asks_queued: usize,
}

impl IntroPolicy {
    /// Defaults: one component at least (`/alice`); `/localhost` and
    /// `/localhop` reserved; `/user` shared; 16 wrong tries in all, the
    /// pause after each counted from 1 s doubling; 32 asks held.
    pub fn new() -> Self {
        let n = |s: &str| s.parse::<Name>().expect("a valid name");
        Self {
            min_components: 1,
            reserved: vec![n("/localhost"), n("/localhop")],
            shared: vec![n("/user")],
            wrong_tries_max: 16,
            backoff: std::time::Duration::from_secs(1),
            asks_queued: 32,
        }
    }

    /// Why no introduction brings the namespace `ns` by this policy, if it
    /// does not: the answer completes "the namespace `<ns>` …".
    pub fn refuses(&self, ns: &Name) -> Option<String> {
        if ns.is_empty() {
            return Some("is the root, over every name".into());
        }
        if ns.len() < self.min_components {
            return Some(format!(
                "has fewer than {} name components (IntroPolicy::min_components)",
                self.min_components
            ));
        }
        if let Some(r) = self
            .reserved
            .iter()
            .find(|r| ns.has_prefix(r) || r.has_prefix(ns))
        {
            return Some(format!(
                "overlaps {r}, a reserved name no introduction brings (IntroPolicy::reserved)"
            ));
        }
        if let Some(s) = self.shared.iter().find(|s| s.has_prefix(ns)) {
            return Some(format!(
                "is or lies over {s}, a prefix many people's namespaces share \
                 (IntroPolicy::shared)"
            ));
        }
        None
    }
}

impl Default for IntroPolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// An offer's code: what the owner shows the joiner. Its link and words
/// carry the secret; [`Debug`] shows neither.
#[derive(Clone, PartialEq, Eq)]
pub struct Code {
    /// The offer record's name, `<D>/32=log/<folder>/seq=<n>`.
    pub offer: Name,
    /// `ndn-trust://intro/<base64url>`, at most one QR
    /// ([`ndn_trust_envelope::qr::MAX_TEXT_LEN`]).
    pub link: String,
    /// The offer's name and 24 words: the secret and the anchor
    /// fingerprint's first half.
    pub words: String,
}

impl std::fmt::Debug for Code {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Code")
            .field("offer", &self.offer)
            .finish_non_exhaustive()
    }
}

/// What a join brought ([`Device::join`](crate::Device::join)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Joined {
    /// The folder this device now reads (and writes, as a writer).
    pub folder: Name,
    /// What the offer granted.
    pub role: Role,
    /// The inviter's namespace, adopted.
    pub inviter: Name,
}

/// Why an introduction was refused (spec §19.5).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum IntroRefusal {
    /// The offering device holds no such offer.
    Unknown,
    /// Another key joined with this offer.
    Used,
    /// It expired by the offering device's clock.
    Expired,
    /// Too many wrong tries — this asker's own, or the offer's in all
    /// (`IntroPolicy::wrong_tries_max`) — or closed by its maker: refused for
    /// good, even with the right secret.
    Closed,
    /// The proof of the secret is wrong; it counted as a wrong try of this
    /// asker.
    WrongProof {
        /// Wrong tries this asker has left before the offer closes to it.
        left: u32,
    },
    /// What answered for the inviter proves neither the code's secret nor
    /// its anchor.
    Forged,
    /// The asker's namespace is the inviter's own, lies under or over it or
    /// under or over any namespace the inviter's device trusts, is one it
    /// trusts under another anchor, or is one no introduction brings (the
    /// root, a reserved or shared name: `IntroPolicy`): adopting it would let
    /// one namespace speak for another. Also: the asker's credentials do
    /// not hold under its namespace as the inviter's device trusts it (they
    /// carry anchors it does not hold, or a key the held version revokes).
    Conflict,
    /// The inviter's namespace, judged by the joiner: it overlaps a
    /// namespace this device already trusts or is its own (equal under
    /// another anchor, under or over it), or is one no introduction brings.
    /// Nothing of it was adopted. Never on the wire.
    InviterConflict {
        /// The inviter's namespace.
        inviter: Name,
        /// What it overlaps, and how.
        why: String,
    },
}

impl std::fmt::Display for IntroRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntroRefusal::Unknown => f.write_str(
                "the inviter's device holds no such offer: ask the inviter for a new code",
            ),
            IntroRefusal::Used => {
                f.write_str("the offer was used by someone else: ask the inviter for a new code")
            }
            IntroRefusal::Expired => f.write_str(
                "the offer expired by the inviter's clock: ask the inviter for a new code",
            ),
            IntroRefusal::Closed => f.write_str(
                "the offer is closed to you, for good (too many wrong tries, or closed by the \
                 inviter): ask the inviter for a new code",
            ),
            IntroRefusal::WrongProof { left } => write!(
                f,
                "the code's secret is wrong (a mistyped word or link?): check the code; {left} \
                 wrong tries left before the offer closes to you"
            ),
            IntroRefusal::Forged => f.write_str(
                "what answered for the inviter proves neither the code's secret nor its anchor \
                 (someone else answered): retry, and check the code",
            ),
            IntroRefusal::Conflict => f.write_str(
                "your namespace overlaps the inviter's, or one the inviter's device trusts, or \
                 is one no introduction brings (the root, a reserved or shared name): join from \
                 a device of a namespace of your own; or your device's credentials do not hold \
                 under your namespace as the inviter's device trusts it (an older version, or a \
                 key a newer version revokes): renew this device's certificate and join again",
            ),
            IntroRefusal::InviterConflict { inviter, why } => write!(
                f,
                "the inviter's namespace {inviter} {why}, so adopting it would let one namespace \
                 speak for another: nothing of it was adopted; do not use this code, and ask \
                 whoever sent it for a code from a namespace of their own"
            ),
        }
    }
}

impl IntroRefusal {
    fn code(&self) -> u64 {
        match self {
            IntroRefusal::Unknown => 1,
            IntroRefusal::Used => 2,
            IntroRefusal::Expired => 3,
            IntroRefusal::Closed => 4,
            IntroRefusal::WrongProof { .. } => 5,
            IntroRefusal::Conflict | IntroRefusal::InviterConflict { .. } => 6,
            IntroRefusal::Forged => 0,
        }
    }
}

/// The most direct-path candidate addresses a code carries, and a join
/// dials: a hint is a few addresses of one device, and a code stays within
/// one QR (spec §19.2).
pub const LINK_HINT_CANDIDATES_MAX: usize = 8;

/// How the inviter's device knows a candidate address of its own: the
/// kinds of ndn-link (`ndn_link::CandidateKind`; ndn-link.md), by the same
/// codes.
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
    /// unspecified, a multicast or the broadcast address, and not port 0.
    /// A code from a stranger is not made to send datagrams to those.
    fn dialable(&self) -> bool {
        let ip = self.addr.ip().to_canonical();
        self.addr.port() != 0
            && !ip.is_unspecified()
            && !ip.is_multicast()
            && !matches!(ip, IpAddr::V4(v4) if v4.is_broadcast())
    }
}

/// The inviter's link hint (spec §19.2): the key of its device and where to
/// try it directly. The key is what the dial's handshake proves; the
/// addresses only say where to try (spec §19.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkHint {
    /// SHA-256 of the device's public key as a certificate carries it: the
    /// key the link must prove (the fingerprint of ndn-link's
    /// `KeyFingerprint`).
    pub key: [u8; 32],
    /// Where to try, most promising first, at most
    /// [`LINK_HINT_CANDIDATES_MAX`].
    pub candidates: Vec<HintCandidate>,
}

impl LinkHint {
    /// The hint's TLVs (the value of the intro envelope's `LinkHint`): the
    /// key, then each of the first [`LINK_HINT_CANDIDATES_MAX`] candidates
    /// once, in order.
    pub fn encode(&self) -> Bytes {
        self.encode_first(self.candidates.len())
    }

    /// [`encode`](Self::encode) with at most `keep` candidates.
    fn encode_first(&self, keep: usize) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_tlv(tlv::LINK_KEY, &self.key);
        let mut seen: Vec<&HintCandidate> = Vec::new();
        for c in &self.candidates {
            if seen.len() == keep.min(LINK_HINT_CANDIDATES_MAX) {
                break;
            }
            if !c.dialable() || seen.contains(&c) {
                continue;
            }
            seen.push(c);
            let mut value = vec![c.kind.code()];
            match c.addr.ip() {
                IpAddr::V4(ip) => value.extend_from_slice(&ip.octets()),
                IpAddr::V6(ip) => value.extend_from_slice(&ip.octets()),
            }
            value.extend_from_slice(&c.addr.port().to_be_bytes());
            w.write_tlv(tlv::LINK_CANDIDATE, &value);
        }
        w.finish()
    }

    /// Read the value of an intro envelope's `LinkHint`: one key and its
    /// candidates — the first [`LINK_HINT_CANDIDATES_MAX`] distinct ones
    /// that name an address this device may dial and a kind this version
    /// knows; the others are passed over. An error says what is wrong: a
    /// join carries on without the hint (it only helps to reach).
    pub fn decode(value: &[u8]) -> Result<Self, String> {
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
                        return Ok(true);
                    };
                    let ip = if ip_len == 4 {
                        IpAddr::from(<[u8; 4]>::try_from(&v[1..5]).expect("4 octets"))
                    } else {
                        IpAddr::from(<[u8; 16]>::try_from(&v[1..17]).expect("16 octets"))
                    };
                    let port = u16::from_be_bytes([v[1 + ip_len], v[2 + ip_len]]);
                    let c = HintCandidate {
                        kind,
                        addr: SocketAddr::new(ip, port),
                    };
                    if c.dialable()
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

    /// The link of an offer's code carrying `hint`, within one QR: the
    /// secret, the offer and the fingerprint are never dropped; relay hints
    /// go first (all of them), then the hint's last candidates one by one,
    /// then the hint itself. `None` when even those do not fit.
    pub(crate) fn code_link(intro: Introduction, hint: Option<&LinkHint>) -> Option<String> {
        if let Some(hint) = hint.filter(|h| !h.candidates.is_empty()) {
            let most = hint.candidates.len().min(LINK_HINT_CANDIDATES_MAX);
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

/// The future of an [`Introducer::dial`].
#[cfg(not(target_arch = "wasm32"))]
pub type Dialing<'a> = futures::future::BoxFuture<'a, Result<(), String>>;
/// The future of an [`Introducer::dial`].
#[cfg(target_arch = "wasm32")]
pub type Dialing<'a> = futures::future::LocalBoxFuture<'a, Result<(), String>>;

/// The future of an [`Introducer::adopt`].
#[cfg(not(target_arch = "wasm32"))]
pub type Adopting<'a> = futures::future::BoxFuture<'a, Result<(), String>>;
/// The future of an [`Introducer::adopt`].
#[cfg(target_arch = "wasm32")]
pub type Adopting<'a> = futures::future::LocalBoxFuture<'a, Result<(), String>>;

/// The future of an [`Introducer::adopt_scoped`].
#[cfg(not(target_arch = "wasm32"))]
pub type Scoping<'a> = futures::future::BoxFuture<'a, Result<ScopedContext, String>>;
/// The future of an [`Introducer::adopt_scoped`].
#[cfg(target_arch = "wasm32")]
pub type Scoping<'a> = futures::future::LocalBoxFuture<'a, Result<ScopedContext, String>>;

/// What the host does for introductions (`Config::introducer`): give this
/// device's anchor link, and adopt another person's — for the whole node,
/// or for this device's data layer alone, to judge the data of the folders
/// that list that person as a writer (spec §6.3).
pub trait Introducer: Send + Sync {
    /// The signed trust-context Data of this device's namespace, whole, as
    /// the host adopted it (what an inline anchor link carries).
    fn anchor(&self) -> Option<Bytes>;

    /// Adopt `link`, an inline anchor link (`TrustEnvelope::Anchor` with
    /// namespace, fingerprint and signed context) the layer has already
    /// checked: `Ok` once this device's validator trusts the namespace; an
    /// error says why not. A host on a forwarder adopts through it, so the
    /// forwarder also validates and routes the namespace.
    ///
    /// A self-certifying namespace (`/user/<0xA1: …>`) not held is adopted
    /// by name over the network (`ndn_cert::adopt_anchor_link`): its version
    /// 1 fetched and checked against the name, the newest reached from it;
    /// the context the link carries is never taken alone — a version 1 is
    /// only compared with the fetched one, and a different one refused as a
    /// fork. With no network to fetch over, refuse, saying to join again
    /// once the person's devices are reachable.
    fn adopt<'a>(&'a self, link: &'a TrustEnvelope) -> Adopting<'a>;

    /// Adopt the self-certifying namespace `namespace` (`/user/<0xA1: …>`),
    /// which a members record this layer holds lists as a writer, by name
    /// for this data layer alone (spec §6.3): version 1 fetched and checked
    /// as the genesis the name hashes, the newest reached from it
    /// (`ndn_cert::adopt_scoped`, `ndn_identity::adopt_scoped_via_engine`);
    /// `held`, the version the layer holds already — one it kept across a
    /// restart included — is refreshed from by continuity instead, so a
    /// branch that does not descend from it is refused. The namespace is
    /// adopted into no keyring the node judges by: the node's forwarder, and
    /// every path but the layer's judging of those folders, keep refusing it
    /// as a person's namespace not held. The result carries the newest
    /// version's signed Data (`ScopedContext::data`), which the layer keeps.
    ///
    /// Transit, idempotent: on an `Ok` — with `held` or without — the host
    /// carries the namespace's Data to this device though its forwarder
    /// cannot validate it (forwarded unvalidated to the Interests pending for
    /// it and never cached) and routes its sync group, taking that on only
    /// if it does not carry the namespace already; it carries it until
    /// [`release_scoped`](Self::release_scoped). An error leaves the
    /// carrying as it was before the call, says why and what to do; the
    /// layer asks again later. The layer validates every packet itself, and
    /// refuses an `Ok` older than the newest version it adopted of the
    /// namespace before, or of that number with other content (releasing
    /// it when it held no version).
    ///
    /// The default refuses: a host that cannot fetch a namespace without
    /// adopting it for the node, or cannot carry its Data in transit, says
    /// so, and the folders' versions of that writer wait here until the
    /// node adopts the namespace (an anchor link naming it).
    fn adopt_scoped<'a>(
        &'a self,
        namespace: &'a Name,
        held: Option<&'a ScopedContext>,
    ) -> Scoping<'a> {
        let _ = held;
        Box::pin(async move {
            Err(format!(
                "this host adopts no namespace for one folder alone, so {namespace}, a writer in \
                 a folder this device reads, is not trusted here: adopt {namespace} by name on \
                 this device's node (an anchor link naming it), or run the device on a host \
                 that adopts namespaces for a folder (spec §6.3)"
            ))
        })
    }

    /// No members record the layer holds lists `namespace` any more, or the
    /// node now holds it, or the layer refused the host's adoption: the host
    /// stops carrying its Data to this device in transit. Releasing a
    /// namespace the host does not carry does nothing.
    fn release_scoped(&self, namespace: &Name) {
        let _ = namespace;
    }

    /// This device's link hint for an offer's code (spec §19.2): its link
    /// key's fingerprint and the direct-path addresses a joiner may try now
    /// (at most [`LINK_HINT_CANDIDATES_MAX`] are kept, in this order), so a
    /// joiner with no routes and no daemon dials this device by key. `None`
    /// (the default): the code carries no hint; a host that listens for
    /// links gives one. The layer calls it once per [`Device::offer`].
    ///
    /// [`Device::offer`]: crate::Device::offer
    fn link_hint(&self) -> Option<LinkHint> {
        None
    }

    /// Dial the inviter's device `inviter` by the hint its code carried
    /// (spec §19.3): try `hint.candidates` in order, and link only to the
    /// device whose key is `hint.key` (the handshake proves it; an address
    /// that answers with another key is no link), within `within` in all.
    /// `Ok` once a link to that device is up and carries Interests for
    /// `inviter`'s names (the offer fetch and the ask) to it; an error
    /// says why not — the unreachable addresses, a wrong key — and the join
    /// carries on by the relays the code names, else by name. The dial
    /// sends nothing of the code's secret: it is the host's link layer's,
    /// and the secret only ever travels inside the sealed ask.
    ///
    /// The default dials nothing: a host with no link layer of its own says
    /// so, and the join falls back as above.
    fn dial<'a>(&'a self, hint: &'a LinkHint, inviter: &'a Name, within: Duration) -> Dialing<'a> {
        let _ = (hint, within);
        Box::pin(async move {
            Err(format!(
                "this host has no link layer to dial {inviter} with (Introducer::dial): route to \
                 it, or run the device on a host that dials link hints"
            ))
        })
    }
}

// ---- records ----------------------------------------------------------------------------------

/// An offer record (spec §19.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfferBody {
    /// The folder offered.
    pub folder: Name,
    /// What it grants.
    pub role: Role,
    /// Its expiry.
    pub until: Timestamp,
    /// The wrong tries it allows.
    pub tries: u32,
    /// SHA-256 of the label and the secret ([`commitment`]).
    pub commitment: [u8; 32],
    /// The offering device's seal key: asks are sealed to it.
    pub seal_key: [u8; 32],
}

/// A use mark (spec §19.1): the offer used by a key, or closed. The first
/// mark naming a key stands; a closing mark closes the offer whenever it
/// comes, used or not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsedBody {
    /// The offer record's name.
    pub offer: Name,
    /// The key it was used by and its public key's digest; `None`: closed
    /// for good (all askers' wrong tries at the device's cap, its maker's
    /// `close_offer`, or the member it brought removed).
    pub by: Option<(Name, [u8; 32])>,
}

/// An introduction's log record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IntroRecord {
    /// An offer.
    Offer(OfferBody),
    /// A use mark.
    Used(UsedBody),
}

impl IntroRecord {
    /// The folder the record's log entry is about.
    pub fn subject(&self) -> Option<Name> {
        match self {
            IntroRecord::Offer(b) => Some(b.folder.clone()),
            IntroRecord::Used(b) => wire::parse_log_name(&b.offer).and_then(|l| l.subject),
        }
    }

    /// Its TLV.
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        match self {
            IntroRecord::Offer(b) => w.write_nested(tlv::INTRO_OFFER, |w| {
                write_name(w, &b.folder);
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

    /// Decode the value of an `IntroOffer` or `IntroUsed` TLV.
    pub(crate) fn decode(typ: u64, value: Bytes) -> Result<Self, WireError> {
        if typ == tlv::INTRO_OFFER {
            let (mut folder, mut role, mut until, mut tries, mut commitment, mut seal_key) =
                (None, None, None, None, None, None);
            each(value, |t, v| {
                match t {
                    tlv_type::NAME => folder = Some(read_name(v)?),
                    tlv::ROLE => role = Some(Role::from_code(read_nni(&v)?)?),
                    tlv::KEEP_UNTIL => until = Some(Timestamp(read_nni(&v)?)),
                    tlv::TRIES => tries = Some(read_nni(&v)?),
                    tlv::DIGEST => commitment = Some(read_digest(&v)?),
                    tlv::SEAL_KEY => seal_key = Some(read_digest(&v)?),
                    _ => return Ok(false),
                }
                Ok(true)
            })?;
            let folder = folder.ok_or_else(|| bad("an offer names its folder"))?;
            wire::data_marker(&folder).map_err(|_| bad("an offer's folder is a folder name"))?;
            let tries = tries
                .filter(|t| (1..=u64::from(u32::MAX)).contains(t))
                .ok_or_else(|| bad("an offer allows one wrong try or more"))?;
            return Ok(IntroRecord::Offer(OfferBody {
                folder,
                role: role.ok_or_else(|| bad("an offer names its role"))?,
                until: until.ok_or_else(|| bad("an offer names its expiry"))?,
                tries: tries as u32,
                commitment: commitment.ok_or_else(|| bad("an offer carries its commitment"))?,
                seal_key: seal_key.ok_or_else(|| bad("an offer carries its seal key"))?,
            }));
        }
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
        wire::parse_log_name(&offer)
            .and_then(|l| l.subject)
            .ok_or_else(|| bad("a use mark names an offer's log entry"))?;
        let by = match (key, digest) {
            (Some(k), Some(d)) => Some((k, d)),
            (None, None) => None,
            _ => return Err(bad("a use mark names its asker key with its digest")),
        };
        Ok(IntroRecord::Used(UsedBody { offer, by }))
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
    /// ([`ask_proof`]).
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

    /// What the asker's proof packet names: the introduction ask's label,
    /// the offering device's Name TLV and [`fields`](Self::fields)
    /// ([`wire::ask_binding`]).
    pub fn binding(&self, device: &Name) -> [u8; 32] {
        wire::ask_binding(
            wire::AskProtocol::IntroAsk,
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
        let mut r = TlvReader::new(params);
        let (typ, value) = r.read_tlv().map_err(|e| bad(format!("bad TLV: {e:?}")))?;
        if typ != tlv::INTRO_ASK || !r.is_empty() {
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

/// An ask's name: `<device>/32=intro/<ParametersSha256Digest>`, the digest
/// over the ApplicationParameters TLV that carries `params` (the
/// [`IntroAsk`] TLV), as the Interest carries it and its answer is named.
/// The ask travels in the parameters, not the name: its credentials take a
/// few KB, and a link reads an Interest's name from its first fragment.
pub fn intro_name(device: &Name, params: &[u8]) -> Name {
    let mut w = TlvWriter::new();
    w.write_tlv(ndn_packet::tlv_type::APP_PARAMETERS, params);
    let digest = Sha256::digest(w.finish());
    intro_prefix(device).append_component(NameComponent::new(
        tlv_type::PARAMETERS_SHA256,
        Bytes::copy_from_slice(&digest),
    ))
}

/// `<device>/32=intro`: an ask Interest's name before its parameters
/// digest, and what an ask's sealing binds as associated data.
pub fn intro_prefix(device: &Name) -> Name {
    device.clone().append_component(kw(INTRO))
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

/// The name prefixes a stranger's link to `device` carries (spec §19.2): the
/// offer fetch `<device>/32=held` and the ask `<device>/32=intro`, and
/// nothing else of the device.
pub fn introduction_prefixes(device: &Name) -> [Name; 2] {
    [wire::held_prefix(device), intro_prefix(device)]
}

// ---- the answer -------------------------------------------------------------------------------

/// What an answer says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The asker is a member.
    Accepted {
        /// The folder.
        folder: Name,
        /// What the offer granted.
        role: Role,
        /// The inviter's signed trust context and its device key's
        /// certificates.
        credentials: Vec<Bytes>,
        /// The offering device's proof packet `<D>/32=ask/<binding>`,
        /// signed by its key ([`AnswerBody::binding`]).
        inviter: Bytes,
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
    /// HMAC-SHA256 of [`AnswerBody::proven`] under the offer's proof key:
    /// present exactly on an acceptance. A refusal is not authenticated (a
    /// joiner whose secret is wrong could not check it anyway); it grants
    /// nothing and changes nothing (spec §19.7).
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
                folder,
                role,
                credentials,
                inviter,
            } => {
                write_name(w, folder);
                write_nni(w, tlv::ROLE, role.code());
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

    /// What the offering device's proof packet names: the introduction
    /// answer's label and the answer's fields before it
    /// ([`wire::ask_binding`]).
    pub fn binding(&self) -> [u8; 32] {
        let mut w = TlvWriter::new();
        self.head(&mut w);
        self.outcome_fields(&mut w, false);
        wire::ask_binding(wire::AskProtocol::IntroAnswer, &[&w.finish()])
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
        let mut r = TlvReader::new(content);
        let (typ, value) = r.read_tlv().map_err(|e| bad(format!("bad TLV: {e:?}")))?;
        if typ != tlv::INTRO_ANSWER || !r.is_empty() {
            return Err(bad("an answer is one IntroAnswer"));
        }
        let mut names = Vec::new();
        let (mut asker, mut digest, mut role, mut credentials, mut inviter) =
            (None, None, None, None, None);
        let (mut refused, mut left, mut proof) = (None, None, None);
        each(value, |t, v| {
            match t {
                tlv_type::NAME => names.push(read_name(v)?),
                tlv::WRITER => asker = Some(read_writer(v)?),
                tlv::DIGEST => digest = Some(read_digest(&v)?),
                tlv::ROLE => role = Some(Role::from_code(read_nni(&v)?)?),
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
            (None, Some(folder), Some(_)) => Outcome::Accepted {
                folder,
                role: role.ok_or_else(|| bad("an answer names the role"))?,
                credentials: credentials
                    .ok_or_else(|| bad("an answer carries the inviter's credentials"))?,
                inviter: inviter.ok_or_else(|| bad("an answer carries the inviter's proof"))?,
            },
            _ => {
                return Err(bad(
                    "an answer either admits, naming the folder and proving the secret, or \
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

// ---- the secret and its proofs ----------------------------------------------------------------

/// The commitment an offer carries to its secret: SHA-256 over the label
/// `ndn-data/intro/commit/1` and the secret.
pub fn commitment(secret: &[u8; SECRET_LEN]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(COMMIT);
    h.update(secret);
    h.finalize().into()
}

/// The offer's proof key: HKDF-SHA256 with the secret as input keying
/// material, no salt, and as info the label `ndn-data/intro/proof/1` and
/// the offer's Name TLV.
pub fn proof_key(secret: &[u8; SECRET_LEN], offer: &Name) -> [u8; 32] {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, secret)
        .expand_multi_info(&[PROOF_KEY, &offer.encode_to_tlv()], &mut key)
        .expect("32 octets is a valid HKDF-SHA256 output length");
    key
}

fn mac(key: &[u8; 32], label: &[u8], parts: &[&[u8]]) -> HmacSha256 {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC accepts a key of any length");
    m.update(label);
    for p in parts {
        m.update(p);
    }
    m
}

/// An ask's proof: HMAC-SHA256 under the proof key over the label
/// `ndn-data/intro/ask/1`, the offer's and the asker key's Name TLVs, the
/// key's public key digest and the ask's nonce.
pub fn ask_proof(
    key: &[u8; 32],
    offer: &Name,
    asker: &Name,
    digest: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
) -> [u8; 32] {
    let tlvs = (offer.encode_to_tlv(), asker.encode_to_tlv());
    mac(key, ASK_PROOF, &[&tlvs.0, &tlvs.1, digest, nonce])
        .finalize()
        .into_bytes()
        .into()
}

/// Whether `proof` is the ask's proof ([`ask_proof`]), compared in
/// constant time.
pub fn ask_proves(
    key: &[u8; 32],
    offer: &Name,
    asker: &Name,
    digest: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    proof: &[u8; 32],
) -> bool {
    let tlvs = (offer.encode_to_tlv(), asker.encode_to_tlv());
    mac(key, ASK_PROOF, &[&tlvs.0, &tlvs.1, digest, nonce])
        .verify_slice(proof)
        .is_ok()
}

/// An answer's proof: HMAC-SHA256 under the proof key over the label
/// `ndn-data/intro/answer/1` and [`AnswerBody::proven`].
pub fn answer_proof(key: &[u8; 32], answer: &AnswerBody) -> [u8; 32] {
    mac(key, ANSWER_PROOF, &[&answer.proven()])
        .finalize()
        .into_bytes()
        .into()
}

/// Whether `answer` carries its proof under `key`, compared in constant
/// time.
pub fn answer_proves(key: &[u8; 32], answer: &AnswerBody) -> bool {
    answer.proof.is_some_and(|p| {
        mac(key, ANSWER_PROOF, &[&answer.proven()])
            .verify_slice(&p)
            .is_ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Record, decode_record, encode_record, log_name};

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn offer_name() -> Name {
        log_name(&n("/alice/laptop"), Some(&n("/alice/32=data/notes")), 7)
    }

    /// The default policy brings people's namespaces — one component or
    /// more, a `/user/<hash>` — and never the root, a local scope or a
    /// name under one, nor the shared `/user` or a name over it.
    #[test]
    fn the_default_policy_refuses_the_root_scopes_and_shared_prefixes_only() {
        let p = IntroPolicy::new();
        for ok in ["/alice", "/home/bob", "/user/3f9a", "/ia"] {
            assert_eq!(p.refuses(&n(ok)), None, "{ok}");
        }
        for refused in ["/", "/localhost", "/localhost/x", "/localhop/y", "/user"] {
            assert!(p.refuses(&n(refused)).is_some(), "{refused}");
        }
    }

    /// Both records round-trip through the log's record codec; a use mark
    /// naming a key without its digest, and an offer allowing no wrong try,
    /// are refused.
    #[test]
    fn intro_records_round_trip_and_malformed_ones_are_refused() {
        let offer = IntroRecord::Offer(OfferBody {
            folder: n("/alice/32=data/notes"),
            role: Role::Writer,
            until: Timestamp(1_800_000_000_000),
            tries: 3,
            commitment: commitment(&[9; SECRET_LEN]),
            seal_key: [4; 32],
        });
        let used = IntroRecord::Used(UsedBody {
            offer: offer_name(),
            by: Some((n("/bob/phone/KEY/k1"), [5; 32])),
        });
        let closed = IntroRecord::Used(UsedBody {
            offer: offer_name(),
            by: None,
        });
        for r in [offer.clone(), used, closed] {
            let bytes = encode_record(&Record::Intro(r.clone()));
            assert_eq!(decode_record(bytes).unwrap(), Record::Intro(r.clone()));
            assert_eq!(r.subject(), Some(n("/alice/32=data/notes")));
        }
        let mut w = TlvWriter::new();
        w.write_nested(tlv::INTRO_USED, |w| {
            write_name(w, &offer_name());
            w.write_nested(tlv::WRITER, |w| write_name(w, &n("/bob/phone/KEY/k1")));
        });
        assert!(decode_record(w.finish()).is_err());
        let IntroRecord::Offer(mut none) = offer else {
            unreachable!()
        };
        none.tries = 0;
        assert!(decode_record(IntroRecord::Offer(none).encode()).is_err());
    }

    /// An ask round-trips through an Interest's parameters, and the name
    /// `intro_name` computes is the one the Interest carries (its answer is
    /// named so); its body round-trips, and the asker's binding changes
    /// with every field it covers.
    #[test]
    fn an_ask_round_trips_and_its_binding_covers_its_fields() {
        let ask = IntroAsk {
            ephemeral: [1; 32],
            key: Bytes::from_static(&[2; 60]),
            sealed: Bytes::from_static(&[3; 90]),
        };
        let device = n("/alice/laptop");
        let params = ask.encode();
        let wire = ndn_packet::encode::InterestBuilder::new(intro_prefix(&device))
            .app_parameters(params.to_vec())
            .build();
        let interest = ndn_packet::Interest::decode(wire).unwrap();
        assert_eq!(*interest.name, intro_name(&device, &params));
        assert_eq!(parse_intro_name(&interest.name), Some(device.clone()));
        assert_eq!(
            IntroAsk::decode(interest.app_parameters().unwrap().clone()).unwrap(),
            ask
        );
        assert_eq!(parse_intro_name(&intro_prefix(&device)), None);
        let body = AskBody {
            offer: offer_name(),
            nonce: [6; NONCE_LEN],
            proof: [7; 32],
            credentials: vec![data_packet(1), data_packet(2)],
            asker: data_packet(3),
        };
        assert_eq!(AskBody::decode(body.encode()).unwrap(), body);
        let d = n("/alice/laptop");
        let other_nonce = AskBody {
            nonce: [8; NONCE_LEN],
            ..body.clone()
        };
        let other_creds = AskBody {
            credentials: vec![data_packet(1)],
            ..body.clone()
        };
        assert_ne!(body.binding(&d), other_nonce.binding(&d));
        assert_ne!(body.binding(&d), other_creds.binding(&d));
        assert_ne!(body.binding(&d), body.binding(&n("/alice/phone")));
    }

    /// Answers round-trip, accepted and refused; the proof covers the
    /// asker, and a different key or a changed field does not verify; an
    /// acceptance without a proof, or a refusal with one, is malformed.
    #[test]
    fn answers_round_trip_and_their_proof_binds_the_asker_and_every_field() {
        let secret = [0x5A; SECRET_LEN];
        let key = proof_key(&secret, &offer_name());
        let mut accepted = AnswerBody {
            offer: offer_name(),
            asker: n("/bob/phone/KEY/k1"),
            digest: [5; 32],
            outcome: Outcome::Accepted {
                folder: n("/alice/32=data/notes"),
                role: Role::Reader,
                credentials: vec![data_packet(1)],
                inviter: data_packet(4),
            },
            proof: None,
        };
        accepted.proof = Some(answer_proof(&key, &accepted));
        assert_eq!(AnswerBody::decode(accepted.encode()).unwrap(), accepted);
        assert!(answer_proves(&key, &accepted));
        let other_key = proof_key(&[0x5B; SECRET_LEN], &offer_name());
        assert!(!answer_proves(&other_key, &accepted));
        let carol = AnswerBody {
            asker: n("/carol/phone/KEY/k1"),
            ..accepted.clone()
        };
        assert!(!answer_proves(&key, &carol));
        let unproven = AnswerBody {
            proof: None,
            ..accepted.clone()
        };
        assert!(AnswerBody::decode(unproven.encode()).is_err());
        for why in [
            IntroRefusal::Unknown,
            IntroRefusal::Used,
            IntroRefusal::Expired,
            IntroRefusal::Closed,
            IntroRefusal::WrongProof { left: 2 },
            IntroRefusal::Conflict,
        ] {
            let mut refused = AnswerBody {
                outcome: Outcome::Refused(why),
                proof: None,
                ..accepted.clone()
            };
            assert_eq!(AnswerBody::decode(refused.encode()).unwrap(), refused);
            refused.proof = Some(answer_proof(&key, &refused));
            assert!(AnswerBody::decode(refused.encode()).is_err());
        }
    }

    /// The ask's proof binds the offer, the asker key, its digest and the
    /// nonce: changing any one fails it, as does another secret.
    #[test]
    fn an_ask_proof_binds_offer_key_digest_and_nonce() {
        let secret = [0x11; SECRET_LEN];
        let key = proof_key(&secret, &offer_name());
        let (bob, digest, nonce) = (n("/bob/phone/KEY/k1"), [5; 32], [6; NONCE_LEN]);
        let p = ask_proof(&key, &offer_name(), &bob, &digest, &nonce);
        assert!(ask_proves(&key, &offer_name(), &bob, &digest, &nonce, &p));
        let other_offer = log_name(&n("/alice/laptop"), Some(&n("/alice/32=data/notes")), 8);
        assert!(!ask_proves(&key, &other_offer, &bob, &digest, &nonce, &p));
        assert!(!ask_proves(
            &key,
            &offer_name(),
            &n("/carol/phone/KEY/k1"),
            &digest,
            &nonce,
            &p
        ));
        assert!(!ask_proves(&key, &offer_name(), &bob, &[6; 32], &nonce, &p));
        assert!(!ask_proves(
            &key,
            &offer_name(),
            &bob,
            &digest,
            &[7; NONCE_LEN],
            &p
        ));
        let guessed = proof_key(&[0x12; SECRET_LEN], &offer_name());
        assert!(!ask_proves(
            &guessed,
            &offer_name(),
            &bob,
            &digest,
            &nonce,
            &p
        ));
        assert_ne!(commitment(&secret), commitment(&[0x12; SECRET_LEN]));
    }

    /// A small Data packet's wire, distinct per `tag`.
    fn data_packet(tag: u8) -> Bytes {
        ndn_packet::encode::DataBuilder::new(n("/x").append(vec![tag]), &[tag]).sign_digest_sha256()
    }

    fn host(i: u8) -> HintCandidate {
        HintCandidate {
            kind: HintKind::Host,
            addr: SocketAddr::from(([192, 168, 1, i], 7000 + u16::from(i))),
        }
    }

    fn host6(i: u16) -> HintCandidate {
        HintCandidate {
            kind: HintKind::Advertised,
            addr: SocketAddr::from((
                [0x2001, 0xdb8, 0x1234, 0x5678, 0xaaaa, 0xbbbb, 0xcccc, i],
                9000 + i,
            )),
        }
    }

    /// A hint round-trips; what a reader does not know — an even type, a
    /// candidate kind of a later version — is passed over, and what makes
    /// no sense — an odd type, two keys, a candidate of the wrong size, no
    /// key — is refused.
    #[test]
    fn a_link_hint_round_trips_and_malformed_ones_are_refused() {
        let hint = LinkHint {
            key: [0x42; 32],
            candidates: vec![host(2), host6(1), host(3)],
        };
        assert_eq!(LinkHint::decode(&hint.encode()).unwrap(), hint);

        let mut w = TlvWriter::new();
        w.write_tlv(tlv::LINK_KEY, &[1; 32]);
        w.write_tlv(0x05BE, b"a later even field");
        w.write_tlv(tlv::LINK_CANDIDATE, &[9, 10, 0, 0, 1, 0x1B, 0x58]);
        w.write_tlv(tlv::LINK_CANDIDATE, &[0, 10, 0, 0, 2, 0x1B, 0x58]);
        let got = LinkHint::decode(&w.finish()).unwrap();
        assert_eq!(got.candidates.len(), 1, "an unknown kind is passed over");

        let refused = |build: &dyn Fn(&mut TlvWriter)| {
            let mut w = TlvWriter::new();
            build(&mut w);
            LinkHint::decode(&w.finish()).unwrap_err()
        };
        refused(&|w| {
            w.write_tlv(tlv::LINK_KEY, &[1; 32]);
            w.write_tlv(tlv::LINK_KEY, &[2; 32]);
        });
        refused(&|w| w.write_tlv(tlv::LINK_CANDIDATE, &[0, 10, 0, 0, 1, 0x1B, 0x58]));
        refused(&|w| {
            w.write_tlv(tlv::LINK_KEY, &[1; 32]);
            w.write_tlv(tlv::LINK_CANDIDATE, &[0, 10, 0, 0, 1, 0x1B]);
        });
        refused(&|w| {
            w.write_tlv(tlv::LINK_KEY, &[1; 31]);
        });
        refused(&|w| {
            w.write_tlv(tlv::LINK_KEY, &[1; 32]);
            w.write_tlv(0x05BF, b"a later critical field");
        });
    }

    /// A code from a stranger is not made to send datagrams to addresses
    /// nobody is at, and a hint's candidates are bounded and distinct.
    #[test]
    fn a_link_hint_keeps_only_dialable_distinct_candidates_up_to_its_bound() {
        let unusable = [
            HintCandidate {
                kind: HintKind::Host,
                addr: SocketAddr::from(([0, 0, 0, 0], 7000)),
            },
            HintCandidate {
                kind: HintKind::Host,
                addr: SocketAddr::from(([224, 0, 0, 1], 7000)),
            },
            HintCandidate {
                kind: HintKind::Host,
                addr: SocketAddr::from(([255, 255, 255, 255], 7000)),
            },
            HintCandidate {
                kind: HintKind::Host,
                addr: SocketAddr::from(([10, 0, 0, 1], 0)),
            },
            HintCandidate {
                kind: HintKind::Host,
                addr: SocketAddr::from(([0u16; 8], 7000)),
            },
        ];
        let mut candidates: Vec<HintCandidate> = unusable.to_vec();
        candidates.push(host(1));
        candidates.push(host(1));
        candidates.extend((2..40).map(host));
        let hint = LinkHint {
            key: [3; 32],
            candidates,
        };
        let got = LinkHint::decode(&hint.encode()).unwrap();
        assert_eq!(got.candidates.len(), LINK_HINT_CANDIDATES_MAX);
        assert_eq!(got.candidates[0], host(1));
        assert_eq!(got.candidates[1], host(2));
        // The encoding keeps at most the bound whatever the host gave, so a
        // hostile reader gets no more than a conforming one.
        let encoded = hint.encode();
        let mut count = 0;
        let mut r = TlvReader::new(encoded);
        while !r.is_empty() {
            if r.read_tlv().unwrap().0 == tlv::LINK_CANDIDATE {
                count += 1;
            }
        }
        assert!(count <= LINK_HINT_CANDIDATES_MAX);
    }

    fn code_with(offer: String, relays: usize) -> Introduction {
        Introduction {
            namespace: Some("/home/alice".into()),
            fingerprint: [0xA5; ndn_trust_envelope::ANCHOR_FINGERPRINT_LEN],
            offer,
            secret: [0x3C; SECRET_LEN],
            link_hint: None,
            relays: (0..relays)
                .map(|i| format!("/community/node/relay-{i:04}"))
                .collect(),
        }
    }

    /// The code's size, with and without a full hint of the most candidates,
    /// IPv6 (the longest), beside several relay hints: within one QR with
    /// room to spare, so the bound on candidates is what keeps it there.
    #[test]
    fn a_code_with_a_full_link_hint_stays_within_one_qr() {
        let offer = "/home/alice/laptop/32=log/home/alice/32=data/notebook/seq=12".to_string();
        let hint = LinkHint {
            key: [0x42; 32],
            candidates: (0..LINK_HINT_CANDIDATES_MAX as u16).map(host6).collect(),
        };
        let without = LinkHint::code_link(code_with(offer.clone(), 4), None).unwrap();
        let with = LinkHint::code_link(code_with(offer.clone(), 4), Some(&hint)).unwrap();
        let max = ndn_trust_envelope::qr::MAX_TEXT_LEN;
        assert!(without.len() < with.len() && with.len() <= max / 2);
        eprintln!(
            "code size: {} octets without a hint, {} with one of {} IPv6 candidates (a QR holds {max})",
            without.len(),
            with.len(),
            LINK_HINT_CANDIDATES_MAX
        );
        let Ok(TrustEnvelope::Intro(i)) = TrustEnvelope::from_uri(&with) else {
            panic!("an introduction link");
        };
        assert_eq!(
            LinkHint::decode(&i.link_hint.unwrap()).unwrap(),
            hint,
            "a hint that fits is carried whole"
        );
    }

    /// An offer name that leaves room for few candidates keeps the first
    /// ones that fit and drops the relays first; one that leaves room for
    /// none drops the hint and still gives a code; the secret, offer and
    /// fingerprint are never dropped.
    #[test]
    fn a_code_that_cannot_hold_the_whole_hint_trims_it_and_never_the_secret() {
        let max = ndn_trust_envelope::qr::MAX_TEXT_LEN;
        let hint = LinkHint {
            key: [0x42; 32],
            candidates: (0..LINK_HINT_CANDIDATES_MAX as u16).map(host6).collect(),
        };
        // An offer name long enough that only some candidates fit beside it.
        let mut trimmed = None;
        for pad in (1400..1700).step_by(4) {
            let offer = format!(
                "/home/alice/laptop/32=log/home/alice/32=data/{}/seq=12",
                "n".repeat(pad)
            );
            let Some(link) = LinkHint::code_link(code_with(offer.clone(), 40), Some(&hint)) else {
                break;
            };
            assert!(
                link.len() <= max,
                "a code of {} octets is past one QR",
                link.len()
            );
            let Ok(TrustEnvelope::Intro(i)) = TrustEnvelope::from_uri(&link) else {
                panic!("an introduction link");
            };
            assert_eq!(i.offer, offer);
            assert_eq!(i.secret, [0x3C; SECRET_LEN]);
            assert_eq!(i.fingerprint, [0xA5; 32]);
            if let Some(bytes) = &i.link_hint {
                let got = LinkHint::decode(bytes).unwrap();
                assert_eq!(got.candidates[..], hint.candidates[..got.candidates.len()]);
                if got.candidates.len() < hint.candidates.len() {
                    assert!(i.relays.is_empty(), "relays go before candidates");
                    trimmed = Some(got.candidates.len());
                }
            } else {
                trimmed.get_or_insert(0);
            }
        }
        assert!(trimmed.is_some(), "no offer name length trimmed the hint");
    }
}
