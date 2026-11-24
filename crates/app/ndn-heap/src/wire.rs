//! The log's wire format (`docs/specs/heap.md`, §2 and §3), public so that a
//! program outside the crate can build, name, read and digest an entry exactly
//! as the log does, for example a conformance suite that reads what a node
//! stored at an exact `(device, space, seq)`.
//!
//! * An entry is [`Entry`]: its `PREV`/`PREV_SEQ` link ([`Prev`]), the heads
//!   it supersedes (`after`, a list of [`EntryRef`]) and its [`Body`]. A
//!   plain write is [`Body::Put`] of a [`PutBody`] (a path and a
//!   [`Payload::Inline`] payload, which when empty is a removal).
//!   [`Entry::encode`] and [`Entry::decode`] convert it to and from the
//!   Content of its packet, refusing with a [`WireError`] what the format
//!   cannot carry.
//! * [`log_name`] is the name of the entry at `(device, space, seq)`.
//! * [`signed_digest`] (of the wire bytes) and [`signed_digest_of`] (of a
//!   decoded Data) are the digest of the signed region, the one every `PREV`,
//!   `after` and [`EntryRef`] names an entry by.
//!
//! The function that signs an entry is not public: a program that could sign
//! an entry with a signer it passes in could make a device equivocate (two
//! entries at one name, its key suspected everywhere), and nothing outside
//! the crate needs it, since [`Heap::put`](crate::Heap::put) signs with the
//! node's own key.
//!
//! ```compile_fail,E0603
//! // Signing an entry at a chosen name is the node's own business.
//! let _ = ndn_heap::wire::sign_entry;
//! ```
//!
//! A node holds the same entries to the same rules whoever built them: what
//! this module lets a program build, the node's admission still judges
//! (signature and trust, membership, the chain, cuts).
//!
//! The other submodules (names, the keyword router, pieces, grant, seal-key
//! and manifest records, the TLV-TYPE registry 0x0600–0x063F, odd critical,
//! even skippable) are the layer's own.

mod codec;
mod digest;
mod names;
mod pieces;
mod prim;
mod sign;
pub(crate) mod tlv;
mod types;

pub(crate) use codec::*;
pub(crate) use digest::*;
pub(crate) use names::*;
pub(crate) use pieces::*;
pub use prim::WireError;
pub(crate) use prim::{each, fields, once, read_name};
pub(crate) use sign::{SignError, sign_entry};

pub use digest::{signed_digest, signed_digest_of};
pub use names::log_name;
pub use types::*;

#[cfg(test)]
mod codec_tests;
#[cfg(test)]
mod names_tests;
