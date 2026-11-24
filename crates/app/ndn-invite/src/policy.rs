//! What a device's introductions allow and cost it, and why one is refused
//! (spec §19.4, §19.5, §19.7).

use std::time::Duration;

use ndn_foundation_types::Name;

/// How long a departure mark lasts by default ([`IntroPolicy::departure_for`]):
/// seven days.
pub const DEPARTURE_FOR: Duration = Duration::from_secs(7 * 24 * 3600);

/// How often a host that retries a join by itself may retry it after a refusal
/// that is worth a retry ([`IntroRefusal::Hint`], [`IntroRefusal::GoneUnproven`]):
/// three. The join itself already fetches the record several times for packets
/// that were lost; what a retry buys is a record that was corrupted in flight
/// arriving intact, which one retry does for a single corrupted packet, a second
/// for a burst, and a third is the margin. A path that damages the same record
/// four joins in a row is not damage: the first contact is broken or hostile, and
/// the next step is to ask the inviter for a new code. A user's own retries are
/// not counted.
pub const HINT_RETRIES_MAX: u32 = 3;

/// What a device's introductions allow and cost it (`Invites::start`'s policy,
/// spec §19.4, §19.7): which namespaces an introduction may bring, either way,
/// and how wrong tries and a crowd of asks are bounded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntroPolicy {
    /// The fewest name components a namespace an introduction brings has: the
    /// root, over every name, is never brought, whatever this says.
    pub min_components: usize,
    /// Names no introduction brings, nor a name under or over one: scopes that
    /// are never a person's (`/localhost`, `/localhop`).
    pub reserved: Vec<Name>,
    /// Names shared by many people's namespaces, held by no one: typed prefixes
    /// (`/user`, whose `/user/<hash>` names are people's) and broad top-level
    /// names (`/com`, `/org`, `/ndn`, `/test`, ...). No introduction brings one of
    /// them or a name over it; a name under one (`/user/<hash>`, `/com/acme`) is a
    /// person's like any other. A deployment that wants one of them for a person's
    /// namespace frees it by removing it from this list.
    pub shared: Vec<Name>,
    /// Wrong tries of one offer, all askers' together, that close it for
    /// everyone, durably: the backstop under per-asker counting
    /// ([`Offer::tries`](crate::Offer::tries)), which anyone can make new askers
    /// for.
    pub wrong_tries_max: u32,
    /// The pause after a wrong try counted toward `wrong_tries_max`, doubled by
    /// each one counted (by the offering device's clock): a wrong try within the
    /// pause counts against its asker alone, so closing an offer for everyone
    /// takes strangers about `backoff` times 2^`wrong_tries_max`.
    pub backoff: Duration,
    /// Asks a device holds at once — verifying their asker or waiting for their
    /// turn to be judged; one more gets no answer (a Nack) at once, and its asker
    /// retries.
    pub asks_queued: usize,
    /// Whether a code's link hint may name this machine's own addresses —
    /// loopback (`127.0.0.1`, `::1`) and link-local (`169.254.0.0/16`,
    /// `fe80::/10`) — which a join then dials. Off by default: a code from a
    /// stranger must not make this device send datagrams to services on itself or
    /// on its link, and the inviter's own gathering never offers such an address
    /// to a device elsewhere (ndn-link `HostCandidates`). Turn it on for two
    /// devices of one machine (tests, a demo).
    pub local_candidates: bool,
    /// An optional hard bound on how long a grant lasts after the admission it
    /// follows (spec §19.8), by the offering device's clock. `None` (the
    /// default): the grant has no date, it follows the members entry in force: it
    /// lasts while the space lists the person and ends when it no longer does.
    /// `Some(d)`: it is also over `d` after the admission; the host can renew it
    /// (`Invites::renew_grant`). `Some(Duration::ZERO)`: no grant is made (nothing
    /// is kept, [`Host::grant`](crate::Host::grant) is never called) and the host
    /// links with the person by its serving policy alone.
    pub grant_for: Option<Duration>,
    /// How long a **departure mark** lasts (spec §19.8): when the space stops
    /// listing a granted person, the grant's note keeps a mark of the entry's name
    /// for this long after, by this device's clock, so the link layer can tell a
    /// person who was offline (or whose link was open) which entry let them go.
    /// Default seven days. `Duration::ZERO`: no mark is made
    /// ([`Host::departure`](crate::Host::departure) is never called) and the link
    /// just closes. The host's own `Invites::end_grant` never makes a mark.
    pub departure_for: Duration,
    /// Whether an offer also makes a **short code** ([`Code::short`](crate::Code),
    /// spec §19.2) and publishes the hint record it names. On by default; off: an
    /// offer gives its link and words alone. A short code is made only when the
    /// host gives a first contact (a dialable candidate in its link hint, or a
    /// relay of the namespace) and the line fits `short_width`.
    pub short_code: bool,
    /// The most characters a short code's one line may have: 294, three lines of
    /// 98 columns. A longer one is not made, and
    /// [`Code::short_why`](crate::Code) says why: longer names are the owner's
    /// choice, and the full link still works.
    pub short_width: usize,
    /// Whether a hint record is served only while its offer is open (not expired,
    /// not closed); afterwards a gone mark answers for the same token. On by
    /// default: a cache must not hold an address past its use. Off: the record is
    /// served until the device stops. Either way the offer answers by its own
    /// rules, so a hint that outlives its offer joins no one.
    pub hint_while_open: bool,
    /// The most of the link hint's candidate addresses a **full link** carries
    /// (default 3): a code is typed, scanned and sent, and a hint is a few
    /// addresses of one device. The hint record serves all of them
    /// ([`LINK_HINT_CANDIDATES_MAX`](crate::LINK_HINT_CANDIDATES_MAX)).
    pub code_candidates: usize,
    /// The most relay devices a **full link** names (default 2), by name.
    pub code_relays: usize,
}

impl IntroPolicy {
    /// Defaults: one component at least (`/alice`); `/localhost` and `/localhop`
    /// reserved; shared: `/user`, the original generic top-level domains (`/com`,
    /// `/org`, `/net`, `/edu`, `/gov`, `/mil`, `/int`, `/info`, `/biz`, `/arpa`),
    /// `/ndn`, and the special-use names (`/example`, `/test`, `/local`,
    /// `/invalid`); 16 wrong tries in all, the pause after each counted from 1 s
    /// doubling; 32 asks held; a grant has no date (it follows the membership); a
    /// departure mark lasts seven days.
    pub fn new() -> Self {
        let n = |s: &str| s.parse::<Name>().expect("a valid name");
        Self {
            min_components: 1,
            reserved: vec![n("/localhost"), n("/localhop")],
            shared: [
                "/user", "/com", "/org", "/net", "/edu", "/gov", "/mil", "/int", "/info", "/biz",
                "/arpa", "/ndn", "/example", "/test", "/local", "/invalid",
            ]
            .into_iter()
            .map(n)
            .collect(),
            wrong_tries_max: 16,
            backoff: Duration::from_secs(1),
            asks_queued: 32,
            local_candidates: false,
            grant_for: None,
            departure_for: DEPARTURE_FOR,
            short_code: true,
            short_width: 294,
            hint_while_open: true,
            code_candidates: 3,
            code_relays: 2,
        }
    }

    /// Why no introduction brings the namespace `ns` by this policy, if it does
    /// not: the answer completes "the namespace `<ns>` …".
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
    /// The proof of the secret is wrong; it counted as a wrong try of this asker.
    WrongProof {
        /// Wrong tries this asker has left before the offer closes to it.
        left: u32,
    },
    /// What answered for the inviter proves neither the code's secret nor its
    /// anchor.
    Forged,
    /// The asker's namespace is the inviter's own, lies under or over it or under
    /// or over any namespace the inviter's device trusts, is one it trusts under
    /// another anchor, or is one no introduction brings (the root, a reserved or
    /// shared name: `IntroPolicy`): adopting it would let one namespace speak for
    /// another. Also: the asker's credentials do not hold under its namespace as
    /// the inviter's device trusts it (they carry anchors it does not hold, or a
    /// key the held version revokes).
    Conflict,
    /// The inviter's namespace, judged by the joiner: it overlaps a namespace this
    /// device already trusts or is its own (equal under another anchor, under or
    /// over it), or is one no introduction brings. Nothing of it was adopted.
    /// Never on the wire.
    InviterConflict {
        /// The inviter's namespace.
        inviter: Name,
        /// What it overlaps, and how.
        why: String,
    },
    /// What answered at a short code's first contact came damaged, or does not
    /// prove it is the inviter's: the hint record's name or content does not read,
    /// its credentials do not open, or its signature does not verify under them
    /// (spec §19.3). Nothing was dialled, asked or adopted. Damage in flight shows
    /// as exactly this, and cannot be told from an impostor's packet, so a retry
    /// is right — at most [`HINT_RETRIES_MAX`] times: a host that retries by
    /// itself MUST stop there — and refused every time, the first contact is not
    /// to be used. Never on the wire (its code is that of a conflict, which it is
    /// not; no peer sends it).
    Hint {
        /// Which check failed (wrong name, record, credentials, signer).
        why: String,
    },
    /// A hint record that **verifies** — its signature checks under credentials
    /// that open — but is not the one this code names: its credentials are of
    /// another namespace than the code's device is under, or carry another anchor
    /// than the code's, or the record is signed by another device, or names an
    /// offer that is no offer of the code's device or was not made with the code's
    /// secret. That is no damage in flight, the work of whoever answered (or a code
    /// made before the keyed fingerprint), and retrying cannot change it: ask the
    /// inviter for a new code. Never on the wire.
    HintMismatch {
        /// Which check failed (namespace, anchor, signer, offer).
        why: String,
    },
    /// A gone mark (`HintRecord::Gone`) that does not prove itself: it does not
    /// read, or its credentials do not open, or its signature does not verify
    /// under them as a key of the code's device chained to the code's anchor.
    /// Anyone on the path can make such a mark, so it never ends a code
    /// ([`Closed`](Self::Closed), [`Expired`](Self::Expired) are only what a
    /// verified mark says): retry, at most [`HINT_RETRIES_MAX`] times, then ask the
    /// inviter. Never on the wire.
    GoneUnproven {
        /// Which check failed.
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
            IntroRefusal::Hint { why } => write!(
                f,
                "what answered at the first contact does not prove it is the inviter's, or came \
                 damaged ({why}): retry at most {HINT_RETRIES_MAX} times; if it is refused every \
                 time, do not use this code's first contact: ask the inviter for a new code, and \
                 check the code was copied whole"
            ),
            IntroRefusal::HintMismatch { why } => write!(
                f,
                "what answered at the first contact proves itself, but not as the inviter this \
                 code names ({why}): this is not damage in flight and a retry will not change \
                 it: do not use this code's first contact, ask the inviter for a new code, and \
                 check the code was copied whole"
            ),
            IntroRefusal::GoneUnproven { why } => write!(
                f,
                "the first contact says the offer is closed but can't prove it ({why}): retry, \
                 or ask the inviter; retry at most {HINT_RETRIES_MAX} times, then ask the \
                 inviter for a new code"
            ),
        }
    }
}

impl IntroRefusal {
    /// The code a refusal travels as (an `IntroRefused` TLV): a conflict of any
    /// kind goes as 6, and a forgery as 0 (it is never sent).
    pub(crate) fn code(&self) -> u64 {
        match self {
            IntroRefusal::Unknown => 1,
            IntroRefusal::Used => 2,
            IntroRefusal::Expired => 3,
            IntroRefusal::Closed => 4,
            IntroRefusal::WrongProof { .. } => 5,
            IntroRefusal::Conflict
            | IntroRefusal::InviterConflict { .. }
            | IntroRefusal::Hint { .. }
            | IntroRefusal::HintMismatch { .. }
            | IntroRefusal::GoneUnproven { .. } => 6,
            IntroRefusal::Forged => 0,
        }
    }
}
