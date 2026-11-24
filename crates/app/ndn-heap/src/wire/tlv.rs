//! TLV-TYPE numbers, the block 0x0600–0x063F (`docs/specs/heap.md`, §3).
//! Odd is critical: a decoder refuses a type it does not know. Even is
//! skippable and reserved for additive fields. 0x063D–0x063F and every even
//! number stay free.

/// The Content of every log packet.
pub(crate) const ENTRY: u64 = 0x0601;
/// NonNegativeInteger: 0 Put, 1 Members, 2 Epoch.
pub(crate) const KIND: u64 = 0x0603;
/// 32 octets: the signed-region digest of the entry at `PREV_SEQ` (or at
/// `seq − 1`); absent only at seq 1; 32 zero octets with `PREV_SEQ` 0 say
/// "this device lost everything before".
pub(crate) const PREV: u64 = 0x0605;
/// NonNegativeInteger; present iff the previous entry's seq is not `seq − 1`
/// (the signed gap statement).
pub(crate) const PREV_SEQ: u64 = 0x0607;
/// `{ Name(device), SEQ, DIGEST }`.
pub(crate) const ENTRY_REF: u64 = 0x0609;
/// NonNegativeInteger: a sequence number.
pub(crate) const SEQ: u64 = 0x060B;
/// 32 octets: a signed-region digest (an implicit digest in a manifest node).
pub(crate) const DIGEST: u64 = 0x060D;
/// A name relative to the space: 1 to 8 generic components, at most 200
/// octets in all.
pub(crate) const PATH: u64 = 0x060F;
/// Payload octets, at most `INLINE_MAX`; empty is a removal.
pub(crate) const INLINE: u64 = 0x0611;
/// `{ SIZE, ROOT }`: a larger payload, in pieces under the entry.
pub(crate) const BLOB: u64 = 0x0613;
/// NonNegativeInteger: the octets of a blob.
pub(crate) const SIZE: u64 = 0x0615;
/// 32 octets: the root digest of a blob's manifest tree.
pub(crate) const ROOT: u64 = 0x0617;
/// `{ EPOCH_ID, CIPHERTEXT }`: replaces `PATH` and the payload.
pub(crate) const SEALED: u64 = 0x0619;
/// `{ Name(creator device), SEQ }`: one epoch.
pub(crate) const EPOCH_ID: u64 = 0x061B;
/// `nonce ‖ tag ‖ ciphertext`.
pub(crate) const CIPHERTEXT: u64 = 0x061D;
/// 32 octets: the granter's ephemeral public key (grant answers).
pub(crate) const EPHEMERAL_KEY: u64 = 0x061F;
/// `{ CREATE?, (ADD | REMOVE)* }`, at most 32 operations.
pub(crate) const MEMBERS: u64 = 0x0621;
/// `{ ANYONE }`: the space's creation, once.
pub(crate) const CREATE: u64 = 0x0623;
/// NonNegativeInteger 0 or 1: whether readers are everybody.
pub(crate) const ANYONE: u64 = 0x0625;
/// `{ ID, Name(who), ROLE, EPOCH_ID? }`.
pub(crate) const ADD: u64 = 0x0627;
/// 16 octets: names an addition.
pub(crate) const ID: u64 = 0x0629;
/// NonNegativeInteger: 0 writer, 1 reader.
pub(crate) const ROLE: u64 = 0x062B;
/// `{ ID, ENTRY_REF* }`, at most 64 tips.
pub(crate) const REMOVE: u64 = 0x062D;
/// `{ KEY_CHECK, AUDIENCE }`.
pub(crate) const EPOCH_BODY: u64 = 0x062F;
/// 32 octets: the epoch key's check value.
pub(crate) const KEY_CHECK: u64 = 0x0631;
/// `{ Name* }`, at most 256 persons.
pub(crate) const AUDIENCE: u64 = 0x0633;
/// `{ Name(space), EPOCH_ID, SEAL_KEY_PACKET }`: the last component of a
/// grant's name.
pub(crate) const GRANT_ASK: u64 = 0x0635;
/// 32 octets: an X25519 public key, the Content of a seal-key packet.
pub(crate) const SEAL_KEY: u64 = 0x0637;
/// `{ EPHEMERAL_KEY, CIPHERTEXT }`: the Content of a grant answer.
pub(crate) const GRANT: u64 = 0x0639;
/// The asker's seal key packet, the whole signed Data `<D>/32=seal/<public
/// key>`, carried in the grant ask so the granter verifies it without fetching
/// it.
pub(crate) const SEAL_KEY_PACKET: u64 = 0x063B;
