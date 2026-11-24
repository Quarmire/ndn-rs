//! Introductions (`docs/specs/invite.md`): a stranger joins a space of the data
//! layer (`ndn-heap`) by a code.
//!
//! The inviter's device makes a one-use **offer**: a Data packet named
//! `<D>/32=intro/offer/<id>` (`id`: 16 random octets), signed by the device's
//! key, naming the space, the [`Role`] it grants, its expiry, the wrong tries it
//! allows, a commitment to a secret and the device's seal key. The [`Code`]
//! carries the offer's name, the secret and the inviter's anchor fingerprint, as a
//! compact `ndn-trust://intro/…` link ([`ndn_trust_envelope::Introduction`]), as
//! words, or as a **short code** ([`ShortCode`]): a line of 20 or 36 words after
//! the inviter's device name and a first contact, whose offer is named by a
//! signed [`wire::HintRecord`] the inviter serves at [`hint_name`]. The joiner's
//! device fetches the offer, sends an **ask** sealed to the offering device carrying its
//! own anchor link and a proof of the secret bound to its key, and takes the
//! **answer**: the space, the role, the inviter's anchor link and the members
//! entry that admitted it ([`wire::tlv::ADMITTED`]). [`IntroPolicy`] is what a
//! device allows of it.
//!
//! This crate holds the plain types ([`host`]), the bytes ([`wire`]), the short
//! code's text ([`short`]), the proofs ([`proofs`]), the policy ([`policy`]), the
//! keys of the state the exchange keeps under `/localhost/ndn-invite/`
//! ([`store`]) and the error ([`InviteError`]).

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]

pub mod error;
pub mod host;
pub mod policy;
pub mod proofs;
pub mod short;
pub mod store;
pub mod wire;

#[cfg(test)]
mod error_tests;
#[cfg(test)]
mod host_tests;
#[cfg(test)]
mod policy_tests;
#[cfg(test)]
mod proofs_tests;
#[cfg(test)]
mod short_tests;
#[cfg(test)]
mod store_tests;
#[cfg(test)]
mod wire_tests;

pub use crate::error::InviteError;
pub use crate::host::{
    Adopting, Code, Departure, Dialing, FirstDialing, Grant, HintCandidate, HintKind, Host,
    JOINED_WRITERS_MAX, Joined, JoinedFolder, LINK_HINT_CANDIDATES_MAX, LinkHint, Offer, Role,
};
pub use crate::policy::{DEPARTURE_FOR, HINT_RETRIES_MAX, IntroPolicy, IntroRefusal};
pub use crate::proofs::{SECRET_LEN, hint_token};
pub use crate::short::{Contact, SHORT_FINGERPRINT_LEN, ShortCode, ShortError};
pub use crate::wire::{
    hint_name, hint_prefix, intro_name, intro_prefix, introduction_prefixes, offer_name,
    parse_hint_name, parse_intro_name, parse_offer_name,
};
