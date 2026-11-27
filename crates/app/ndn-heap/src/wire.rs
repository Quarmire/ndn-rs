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
//! The parsers of the names a device serves ([`parse_space_name`], [`parse_log_name`],
//! [`parse_piece_name`], [`parse_seal_key_name`], [`parse_grant_name`], [`parse_held_name`],
//! [`parse_chan_name`]) and [`is_namespace`] are public: a sibling
//! crate that filters packets by name (`ndn-invite`'s folder scope) judges them by the layer's
//! own grammar, never a copy of it.
//!
//! ```
//! use ndn_foundation_types::Name;
//! use ndn_heap::wire::{PieceKind, log_name, parse_log_name, parse_piece_name, parse_space_name};
//!
//! let space: Name = "/alice/32=data/notes".parse().unwrap();
//! assert_eq!(parse_space_name(&space).unwrap().owner, "/alice".parse::<Name>().unwrap());
//! let entry = log_name(&"/alice/laptop".parse().unwrap(), &space, 3);
//! let log = parse_log_name(&entry).unwrap();
//! assert_eq!((log.space, log.seq), (space, 3));
//! let piece: Name = format!("{entry}/32=piece/seg=2").parse().unwrap();
//! assert_eq!(parse_piece_name(&piece).unwrap().kind, PieceKind::Chunk(2));
//! ```
//!
//! The other submodules (names, the keyword router, pieces, grant, seal-key
//! and manifest records, the TLV-TYPE registry 0x0600–0x063F, odd critical,
//! even skippable) are the layer's own.

mod codec;
mod digest;
mod names;
mod pieces;
mod prim;
mod query;
mod sign;
pub(crate) mod tlv;
mod types;

pub(crate) use codec::*;
pub(crate) use digest::*;
pub(crate) use names::*;
pub(crate) use pieces::*;
pub use prim::WireError;
pub(crate) use prim::{
    each, fields, once, only, read_array, read_epoch_id, read_name, read_nni, write_epoch_id,
    write_name, write_nni,
};
#[expect(
    unused_imports,
    reason = "the query halves take these up; remove the unused ones then"
)]
pub(crate) use query::{
    A_SEALED, ANSWER_BYTES_MAX, ANSWER_CONTENT_MAX, ANSWER_SEALED_MAX, ANSWER_TEXT_MAX, AnswerBody,
    AskSeal, DEADLINE_MAX_MS, QUERY_ASK_MAX, QUERY_BYTES_MAX, QUERY_PATH_MAX, QUERY_SEALED_MAX,
    QueryAnswer, QueryAsk, Status, name_value_len,
};
pub(crate) use sign::{SignError, sign_entry};

pub use digest::{signed_digest, signed_digest_of};
pub use names::ASKER_CHAIN_MAX;
pub(crate) use names::ASKER_CHAIN_OCTETS_MAX;
pub use names::{
    GrantAsk, LogName, SpaceName, chan_ask_name, chan_prefix, grant_name, held_name, is_namespace,
    log_name, parse_chan_name, parse_grant_name, parse_held_name, parse_log_name, parse_query_name,
    parse_seal_key_name, parse_space_name, query_ask_name, query_prefix, seal_key_name,
    seal_prefix, sync_group_of,
};
pub use pieces::{PieceKind, PieceName, parse_piece_name, piece_name};
pub use types::*;

#[cfg(test)]
mod codec_tests;
#[cfg(test)]
mod names_tests;
