//! The short code (spec §19.2): one line a person can read aloud or type.
//!
//! ```text
//! short   = device SP [ contact SP ] word{20}      named: 10 octets of keyed fingerprint
//!         | device SP [ contact SP ] word{36}      whole: 32 octets of fingerprint
//! device  = an absolute NDN URI of the inviter's device: /alice/member/laptop
//! contact = "[" IPv6 "]" ":" port | IPv4 ":" port | relay-name   (starts with "/")
//! word    = a BIP39 English word; case and spacing do not matter
//! ```
//!
//! The words carry what cannot be fetched: the offer's secret (16 octets)
//! and the anchor's fingerprint (10 octets of a tag keyed by the secret, or
//! the whole 32 when the
//! namespace is self-certifying) with a 12-bit checksum
//! ([`ndn_trust_envelope::words::encode_checked`]) that also covers the text
//! before the words — the device name and the first contact — so a typo
//! anywhere in the line is refused, not tried. One self-certifying component
//! equal to the whole fingerprint is written `161=*` instead of its 96
//! characters of escapes; a 36-word code carries the fingerprint it stands
//! for.
//!
//! The code names no offer: the hint record at
//! [`hint_name`](super::hint_name)`(device, `[`hint_token`](super::hint_token)`(secret))`
//! does, signed by the inviter.

use std::net::SocketAddr;

use ndn_foundation_types::{Name, NameComponent};
use ndn_packet::tlv_type::SELF_CERTIFYING;
use ndn_trust_envelope::{ANCHOR_FINGERPRINT_LEN, words};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::{HintCandidate, HintKind, SECRET_LEN};

/// Octets of the keyed fingerprint ([`keyed_fingerprint`](super::keyed_fingerprint),
/// an HMAC of the anchor's fingerprint under the code's secret) a named
/// namespace's short code carries (80 bits; spec §19.7 gives the reason). A
/// self-certifying namespace's carries all [`ANCHOR_FINGERPRINT_LEN`].
pub const SHORT_FINGERPRINT_LEN: usize = 10;

/// Words of a code with a [`SHORT_FINGERPRINT_LEN`]-octet fingerprint.
const NAMED_WORDS: usize = 20;

/// Words of a code with the whole fingerprint.
const WHOLE_WORDS: usize = 36;

/// Where to reach the inviter before the hint record is held.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Contact {
    /// An address to dial, with no key to expect (the code carries none);
    /// only a hint: whoever answers is judged by what it then serves.
    Address(SocketAddr),
    /// A relay device by name: the hint Interest goes through it as its
    /// forwarding hint.
    Relay(Name),
}

/// A short code, read or to be written ([`encode`](Self::encode),
/// [`parse`](Self::parse)).
#[derive(Clone, PartialEq, Eq)]
pub struct ShortCode {
    /// The inviter's device name; a self-certifying component is the whole
    /// component (what `161=*` stands for), never the placeholder.
    pub device: Name,
    /// The first contact; `None` when the host knows none and the joiner
    /// must route to the device by name.
    pub contact: Option<Contact>,
    /// The offer's secret. [`Debug`] never shows it.
    pub secret: [u8; SECRET_LEN],
    /// The anchor's fingerprint as the code carries it: all
    /// [`ANCHOR_FINGERPRINT_LEN`] octets (a self-certifying namespace, whose
    /// name it is), or [`SHORT_FINGERPRINT_LEN`] octets of the tag
    /// [`keyed_fingerprint`](super::keyed_fingerprint) makes of it with this
    /// code's secret.
    pub fingerprint: Vec<u8>,
}

impl std::fmt::Debug for ShortCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShortCode")
            .field("device", &self.device)
            .field("contact", &self.contact)
            .field("secret", &"<secret>")
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

/// Why a short code could not be read or written. Each says what is wrong
/// and what to do, and carries exactly the fact the message names.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ShortError {
    /// The code has this many words after its device name and first contact:
    /// not 20 or 36. (24 is today's words form: the caller reads it as that.)
    #[error(
        "the code has {0} words; a short code has 20 or 36 words, today's words form 24: the \
         code was cut off or has extra words: copy it again whole"
    )]
    Words(usize),
    /// The word at this position (from 1, among the words) is not on the
    /// list.
    #[error("word {0} is not a BIP39 English word: check word {0}")]
    UnknownWord(usize),
    /// Every word is on the list but the checksum does not match.
    #[error(
        "the code does not read (a word, the address or the device name is mistyped, or two \
         words are swapped): check each against what you were given; the inviter's device \
         name and address are part of the check"
    )]
    Checksum,
    /// A first contact that is neither an address nor a relay's name, or one
    /// that no device can dial (port 0, the unspecified or a multicast
    /// address). Carries the token as written.
    #[error(
        "the code's first contact `{0}` is neither a dialable address (`192.0.2.7:4433`, \
         `[2001:db8::7]:4433`) nor a relay's name (starting with /): check it against what \
         you were given"
    )]
    Contact(String),
    /// `161=*` (the whole fingerprint) with the 20 words of a named code,
    /// which carry only part of it.
    #[error(
        "the device name uses `161=*`, the whole fingerprint, which only a 36-word code \
         carries: the code was cut off, or copied from a code of another shape; copy it \
         again whole"
    )]
    Placeholder,
    /// The first contact is a loopback or link-local address, which this
    /// device does not dial from a code.
    #[error(
        "the code's first contact {0} is an address of this machine or its link; this \
         device does not dial one from a code (`IntroPolicy::local_candidates`): ask for a \
         code with an address of the inviter's device that can be reached from here, or \
         allow it in the policy for two devices of one machine"
    )]
    Local(SocketAddr),
    /// A device name that is not an absolute NDN name (it must start with /
    /// and be a valid URI). Carries the token as written.
    #[error(
        "the code's device name `{0}` is not an NDN name (starting with /, not the root): \
         check it against what you were given, or copy the code again whole"
    )]
    Device(String),
    /// Writing: a fingerprint that is neither [`SHORT_FINGERPRINT_LEN`] nor
    /// [`ANCHOR_FINGERPRINT_LEN`] octets.
    #[error("a short code carries 10 or 32 octets of fingerprint, not {0}")]
    Fingerprint(usize),
}

/// The self-certifying component `161=*` stands for in text: type 0xA1 and
/// a single `*`. A real one is 32 octets, so the two never meet.
fn is_placeholder(c: &NameComponent) -> bool {
    c.typ == SELF_CERTIFYING && c.value.as_ref() == b"*"
}

/// A token that starts like a contact: `/`, `[` or a digit. No word does.
fn looks_like_contact(token: &str) -> bool {
    token.starts_with(['/', '[']) || token.starts_with(|c: char| c.is_ascii_digit())
}

/// `name` in the canonical text of a short code, a component for which
/// `star` holds written `161=*`. `Err(())` for the root, which names no
/// device and no relay.
fn write_name(
    out: &mut String,
    name: &Name,
    star: impl Fn(&NameComponent) -> bool,
) -> Result<(), ()> {
    if name.is_empty() {
        return Err(());
    }
    for c in name.components() {
        out.push('/');
        if star(c) {
            out.push_str("161=*");
        } else {
            let one = Name::from_components([c.clone()]).to_string();
            out.push_str(&one[1..]);
        }
    }
    Ok(())
}

/// A device name as written in a code, or why it is not one.
fn parse_name(token: &str) -> Option<Name> {
    token
        .starts_with('/')
        .then(|| token.parse::<Name>().ok())
        .flatten()
        .filter(|n| !n.is_empty())
}

/// `name` with every `161=*` placeholder replaced by the whole fingerprint.
fn fill(name: &Name, fingerprint: &[u8]) -> Name {
    Name::from_components(name.components().iter().map(|c| {
        if is_placeholder(c) {
            NameComponent::new(SELF_CERTIFYING, bytes::Bytes::copy_from_slice(fingerprint))
        } else {
            c.clone()
        }
    }))
}

impl ShortCode {
    /// The text before the words, which the checksum is bound to: the
    /// device name, a single space, then the first contact, when present.
    /// `star` says which components of a name are written `161=*`.
    fn bound(
        device: &Name,
        contact: Option<&Contact>,
        star: impl Fn(&NameComponent) -> bool + Copy,
    ) -> Result<String, ShortError> {
        let mut text = String::with_capacity(96);
        write_name(&mut text, device, star).map_err(|()| ShortError::Device(device.to_string()))?;
        match contact {
            None => {}
            Some(Contact::Address(addr)) => {
                text.push(' ');
                text.push_str(&addr.to_string());
            }
            Some(Contact::Relay(relay)) => {
                text.push(' ');
                write_name(&mut text, relay, star)
                    .map_err(|()| ShortError::Contact(relay.to_string()))?;
            }
        }
        Ok(text)
    }

    /// The canonical one-line text: the device name, the first contact when
    /// there is one, and the words (20 for a 10-octet fingerprint, 36 for the
    /// whole). With the whole fingerprint every self-certifying component of
    /// the device and the relay equal to it is written `161=*`. A
    /// fingerprint of another length is refused, as is a name that cannot be
    /// written back as read (the root, or a `161` component of one octet
    /// `*`, which `161=*` would then mean).
    pub fn encode(&self) -> Result<String, ShortError> {
        let len = self.fingerprint.len();
        if len != SHORT_FINGERPRINT_LEN && len != ANCHOR_FINGERPRINT_LEN {
            return Err(ShortError::Fingerprint(len));
        }
        let whole = (len == ANCHOR_FINGERPRINT_LEN).then_some(&self.fingerprint[..]);
        let names = std::iter::once(&self.device).chain(match &self.contact {
            Some(Contact::Relay(relay)) => Some(relay),
            _ => None,
        });
        for name in names {
            if name.components().iter().any(is_placeholder) {
                return Err(ShortError::Device(name.to_string()));
            }
        }
        let star = |c: &NameComponent| {
            c.typ == SELF_CERTIFYING && whole.is_some_and(|w| c.value.as_ref() == w)
        };
        let mut text = Self::bound(&self.device, self.contact.as_ref(), star)?;
        let mut payload = Zeroizing::new(Vec::with_capacity(SECRET_LEN + len));
        payload.extend_from_slice(&self.secret);
        payload.extend_from_slice(&self.fingerprint);
        let words = words::encode_checked(&payload, &text)
            .map_err(|_| ShortError::Fingerprint(self.fingerprint.len()))?;
        text.push(' ');
        text.push_str(&words);
        Ok(text)
    }

    /// How many words follow the device name and the first contact in
    /// `text`: what tells a short code (20 or 36) from today's words form
    /// (24). Counts tokens only; it judges nothing.
    pub fn word_count(text: &str) -> usize {
        let mut tokens = text.split_whitespace().skip(1).peekable();
        if tokens.peek().is_some_and(|t| looks_like_contact(t)) {
            tokens.next();
        }
        tokens.count()
    }

    /// Read a short code. Refused, in this order: a device name that is not
    /// a name ([`ShortError::Device`]), a first contact that is not one
    /// ([`ShortError::Contact`]), a number of words other than 20 or 36
    /// ([`ShortError::Words`]), `161=*` with 20 words
    /// ([`ShortError::Placeholder`]), a word off the list
    /// ([`ShortError::UnknownWord`]), a checksum that does not match the
    /// words, the device name and the first contact ([`ShortError::Checksum`]),
    /// and a first contact this device does not dial from a code
    /// ([`ShortError::Local`]: loopback and link-local, unless
    /// `include_local`, [`IntroPolicy::local_candidates`](super::IntroPolicy)).
    /// Case and spacing do not matter.
    pub fn parse(text: &str, include_local: bool) -> Result<Self, ShortError> {
        let mut tokens = text.split_whitespace();
        let Some(first) = tokens.next() else {
            return Err(ShortError::Words(0));
        };
        let device = parse_name(first).ok_or_else(|| ShortError::Device(first.to_owned()))?;
        let rest: Vec<&str> = tokens.collect();
        let contact_token = rest.first().copied().filter(|t| looks_like_contact(t));
        let contact = match contact_token {
            None => None,
            Some(t) if t.starts_with('/') => Some(Contact::Relay(
                parse_name(t).ok_or_else(|| ShortError::Contact(t.to_owned()))?,
            )),
            Some(t) => Some(Contact::Address(
                t.parse::<SocketAddr>()
                    .map_err(|_| ShortError::Contact(t.to_owned()))?,
            )),
        };
        let words = &rest[usize::from(contact.is_some())..];
        if words.len() != NAMED_WORDS && words.len() != WHOLE_WORDS {
            return Err(ShortError::Words(words.len()));
        }
        let starred = device.components().iter().any(is_placeholder)
            || matches!(&contact, Some(Contact::Relay(r)) if r.components().iter().any(is_placeholder));
        if starred && words.len() == NAMED_WORDS {
            return Err(ShortError::Placeholder);
        }
        let bound = Self::bound(&device, contact.as_ref(), is_placeholder)?;
        let payload = words::decode_checked(&words.join(" "), &bound).map_err(|e| match e {
            words::WordsError::UnknownWord(at) => ShortError::UnknownWord(at),
            _ => ShortError::Checksum,
        })?;
        let (secret, fingerprint) = payload.split_at(SECRET_LEN);
        let (device, contact) = if starred {
            (
                fill(&device, fingerprint),
                contact.map(|c| match c {
                    Contact::Relay(r) => Contact::Relay(fill(&r, fingerprint)),
                    other => other,
                }),
            )
        } else {
            (device, contact)
        };
        if let (Some(Contact::Address(addr)), Some(token)) = (&contact, contact_token) {
            let candidate = HintCandidate {
                kind: HintKind::Host,
                addr: *addr,
            };
            if !candidate.dialable(true) {
                return Err(ShortError::Contact(token.to_owned()));
            }
            if !candidate.dialable(include_local) {
                return Err(ShortError::Local(*addr));
            }
        }
        Ok(ShortCode {
            device,
            contact,
            secret: secret.try_into().expect("a payload begins with the secret"),
            fingerprint: fingerprint.to_vec(),
        })
    }

    /// Whether `fingerprint`, the SHA-256 of an anchor's key, is the one this
    /// code names: the whole 32 octets equal it, or the 10 octets are the tag
    /// keyed by this code's secret ([`keyed_fingerprint`](super::keyed_fingerprint))
    /// of it. Compared in constant time.
    pub fn matches(&self, fingerprint: &[u8; ANCHOR_FINGERPRINT_LEN]) -> bool {
        match <[u8; ANCHOR_FINGERPRINT_LEN]>::try_from(&self.fingerprint[..]) {
            Ok(whole) => whole.ct_eq(fingerprint).into(),
            Err(_) => {
                super::keyed_fingerprint_matches(&self.secret, fingerprint, &self.fingerprint)
            }
        }
    }
}
