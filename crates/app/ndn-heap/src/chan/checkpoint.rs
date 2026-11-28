//! The checkpoint record (docs/specs/channel.md, Checkpoints): what a sender signs about the frames
//! it sent, and what a receiver reads back.
//!
//! A `CHECKPOINT` frame is sealed under the channel key (stream class, kind `0x31`, `count` 0, one
//! sequence) and its plaintext is
//!
//! ```text
//! lo (varint) | hi (varint)             the sequences it covers: [lo, hi)
//! n (varint)                            the frames in the list, at most 4,096
//! n x ( seq0 delta (varint) | h (16) )  the frames sent with lo <= seq0 < hi, in order of seq0
//! signature (64)                        Ed25519 by the device key the session Data was signed with
//! ```
//!
//! then any padding of the form the frame layer defines (a short frame is padded inside the
//! plaintext). The first `seq0 delta` counts from `lo`, each later one from the entry before it,
//! so the entries rise (a delta of 0 would list a `seq0` twice, which no sender does and a
//! receiver accepts only as one frame's second hash). `h` is the first 16 octets of
//! [`frame_hash`](super::ring::frame_hash) of the frame's octets as they went on the wire: header,
//! ciphertext and tag.
//!
//! The signature is over `"ndn-channel/checkpoint/1" || channel id (8, big-endian) || key epoch
//! (4, big-endian: the whole epoch, the header carries only its low octet) || lo (8) || hi (8) ||
//! n (8) || SHA-256(entries)`, each of `lo`, `hi` and `n` as 8 octets big-endian, and `entries`
//! the octets of the list exactly as written (every varint is minimal: the reader refuses a
//! longer form, so the digest a receiver computes is the one the sender signed). The channel id
//! and the key epoch bind a checkpoint to its channel and its key, so a replay of a checkpoint
//! into another channel, or into the same channel under another epoch, fails to verify (and fails
//! to open, since the frame key differs).
//!
//! The range is **what the sender can vouch is complete**: a frame with `lo <= seq0 < hi` that a
//! receiver accepted and the list lacks (or lists with another hash) was not sent by the sender.
//! A frame the sender sent after the checkpoint was built has `seq0 >= hi` (the sender's `hi` is
//! below the first sequence still waiting to be sent), so a receiver that holds it has nothing to
//! say yet. If the sender's ring forgot a frame (over 4,096 frames or 4 MiB between two
//! checkpoints) `lo` is raised past it, so a forgotten frame is never a mismatch.

use bytes::{BufMut, Bytes, BytesMut};
use ndn_security::{Ed25519PublicKey, Signer, VerifyOutcome};
use sha2::{Digest, Sha256};

use super::message::{MessageError, check_padding};
use super::ring::{HASH_LEN, RING_FRAMES};
use super::varint;

/// The domain label of a checkpoint's signature.
pub(crate) const LABEL: &[u8] = b"ndn-channel/checkpoint/1";

/// Octets of the signature.
pub(crate) const SIG_LEN: usize = 64;

/// The most frames one checkpoint lists: what the sender's ring holds.
pub(crate) const MAX_ENTRIES: usize = RING_FRAMES;

/// Why a checkpoint is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum CheckpointError {
    /// The record ends inside a field.
    #[error("the checkpoint ends inside its {what}: drop the frame")]
    Truncated { what: &'static str },
    /// A varint longer than its value needs: the digest of the list would not be canonical.
    #[error("the checkpoint's {what} is not in its shortest form: drop the frame")]
    NotMinimal { what: &'static str },
    /// `hi` below `lo`.
    #[error("the checkpoint covers [{lo}, {hi}), which ends before it begins: drop the frame")]
    Range { lo: u64, hi: u64 },
    /// More frames than a sender's ring holds.
    #[error("the checkpoint lists {n} frames, over the {MAX_ENTRIES} a ring holds: drop the frame")]
    TooMany { n: u64 },
    /// A listed `seq0` outside `[lo, hi)`.
    #[error(
        "the checkpoint lists a frame at {seq0}, outside its range [{lo}, {hi}): drop the frame"
    )]
    Outside { seq0: u64, lo: u64, hi: u64 },
    /// What follows the record is not padding.
    #[error(transparent)]
    Padding(#[from] MessageError),
    /// A value no varint holds, or a signer that did not sign.
    #[error("the checkpoint cannot be written: {why}")]
    Unwritable { why: &'static str },
}

/// A decoded checkpoint: the range, the list and the signature, with the digest the signature
/// covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Record {
    /// First sequence covered.
    pub(crate) lo: u64,
    /// One past the last sequence covered.
    pub(crate) hi: u64,
    /// `(seq0, hash)` of the frames listed, rising in `seq0`.
    pub(crate) entries: Vec<(u64, [u8; HASH_LEN])>,
    /// The signature.
    pub(crate) signature: [u8; SIG_LEN],
    /// SHA-256 of the list's octets as read.
    digest: [u8; 32],
}

/// The octets the signature covers.
fn signed_message(
    channel: u64,
    epoch: u32,
    lo: u64,
    hi: u64,
    n: u64,
    digest: &[u8; 32],
) -> [u8; LABEL.len() + 8 + 4 + 8 + 8 + 8 + 32] {
    let mut out = [0u8; LABEL.len() + 8 + 4 + 8 + 8 + 8 + 32];
    let mut at = 0;
    let mut put = |bytes: &[u8]| {
        out[at..at + bytes.len()].copy_from_slice(bytes);
        at += bytes.len();
    };
    put(LABEL);
    put(&channel.to_be_bytes());
    put(&epoch.to_be_bytes());
    put(&lo.to_be_bytes());
    put(&hi.to_be_bytes());
    put(&n.to_be_bytes());
    put(digest);
    out
}

/// The list's octets: each `seq0` as a delta from the one before (the first from `lo`), then its
/// hash. `entries` rise (a repeated `seq0` is a delta of 0).
fn entries_octets(lo: u64, entries: &[(u64, [u8; HASH_LEN])]) -> Result<BytesMut, CheckpointError> {
    let mut out = BytesMut::with_capacity(entries.len() * (HASH_LEN + 2));
    let mut previous = lo;
    for (seq0, hash) in entries {
        let delta = seq0
            .checked_sub(previous)
            .ok_or(CheckpointError::Unwritable {
                why: "the list does not rise",
            })?;
        varint::write(&mut out, delta).map_err(|_| CheckpointError::Unwritable {
            why: "a sequence no varint holds",
        })?;
        out.put_slice(hash);
        previous = *seq0;
    }
    Ok(out)
}

/// Writes and signs the checkpoint of `entries` over `[lo, hi)` for `channel` at `epoch`: the
/// plaintext to seal (no padding: sealing pads a short frame). `signer` must sign synchronously
/// with Ed25519.
pub(crate) fn sign(
    signer: &dyn Signer,
    channel: u64,
    epoch: u32,
    lo: u64,
    hi: u64,
    entries: &[(u64, [u8; HASH_LEN])],
) -> Result<Bytes, CheckpointError> {
    sign_with(
        |message| {
            signer
                .sign_sync(message)
                .ok()
                .and_then(|sig| <[u8; SIG_LEN]>::try_from(&sig[..]).ok())
        },
        channel,
        epoch,
        lo,
        hi,
        entries,
    )
}

/// [`sign`] with the signature made by `sign_message` (`None`: it did not sign).
pub(crate) fn sign_with(
    sign_message: impl FnOnce(&[u8]) -> Option<[u8; SIG_LEN]>,
    channel: u64,
    epoch: u32,
    lo: u64,
    hi: u64,
    entries: &[(u64, [u8; HASH_LEN])],
) -> Result<Bytes, CheckpointError> {
    if hi < lo {
        return Err(CheckpointError::Range { lo, hi });
    }
    if entries.len() > MAX_ENTRIES {
        return Err(CheckpointError::TooMany {
            n: entries.len() as u64,
        });
    }
    if let Some((seq0, _)) = entries.iter().find(|(s, _)| *s < lo || *s >= hi) {
        return Err(CheckpointError::Outside {
            seq0: *seq0,
            lo,
            hi,
        });
    }
    let list = entries_octets(lo, entries)?;
    let digest: [u8; 32] = Sha256::digest(&list).into();
    let message = signed_message(channel, epoch, lo, hi, entries.len() as u64, &digest);
    let signature = sign_message(&message).ok_or(CheckpointError::Unwritable {
        why: "the device key did not sign",
    })?;
    let mut out = BytesMut::with_capacity(list.len() + SIG_LEN + 24);
    let overflow = |_| CheckpointError::Unwritable {
        why: "a sequence no varint holds",
    };
    varint::write(&mut out, lo).map_err(overflow)?;
    varint::write(&mut out, hi).map_err(overflow)?;
    varint::write(&mut out, entries.len() as u64).map_err(overflow)?;
    out.put_slice(&list);
    out.put_slice(&signature);
    Ok(out.freeze())
}

impl Record {
    /// Reads one checkpoint from an opened `CHECKPOINT` frame's plaintext, then requires nothing
    /// but padding to its end. Nothing is verified: see [`Record::verify`].
    pub(crate) fn decode(plaintext: &[u8]) -> Result<Record, CheckpointError> {
        let mut at = 0usize;
        let read = |what: &'static str, at: &mut usize| -> Result<u64, CheckpointError> {
            let (value, n) =
                varint::read(&plaintext[*at..]).ok_or(CheckpointError::Truncated { what })?;
            if varint::len(value) != Some(n) {
                return Err(CheckpointError::NotMinimal { what });
            }
            *at += n;
            Ok(value)
        };
        let lo = read("first sequence", &mut at)?;
        let hi = read("last sequence", &mut at)?;
        if hi < lo {
            return Err(CheckpointError::Range { lo, hi });
        }
        let n = read("frame count", &mut at)?;
        if n > MAX_ENTRIES as u64 {
            return Err(CheckpointError::TooMany { n });
        }
        let list_start = at;
        let mut entries = Vec::with_capacity(n as usize);
        let mut previous = lo;
        for _ in 0..n {
            let delta = read("sequence delta", &mut at)?;
            let seq0 = previous.checked_add(delta).filter(|s| *s < hi).ok_or(
                CheckpointError::Outside {
                    seq0: previous.saturating_add(delta),
                    lo,
                    hi,
                },
            )?;
            let hash: [u8; HASH_LEN] = plaintext
                .get(at..at + HASH_LEN)
                .and_then(|h| h.try_into().ok())
                .ok_or(CheckpointError::Truncated { what: "hash" })?;
            at += HASH_LEN;
            entries.push((seq0, hash));
            previous = seq0;
        }
        let digest: [u8; 32] = Sha256::digest(&plaintext[list_start..at]).into();
        let signature: [u8; SIG_LEN] = plaintext
            .get(at..at + SIG_LEN)
            .and_then(|s| s.try_into().ok())
            .ok_or(CheckpointError::Truncated { what: "signature" })?;
        at += SIG_LEN;
        check_padding(&plaintext[at..])?;
        Ok(Record {
            lo,
            hi,
            entries,
            signature,
            digest,
        })
    }

    /// Whether the signature verifies under `public_key` (an Ed25519 key, decoded once by the
    /// caller) for the channel `channel` at the full key epoch `epoch`.
    pub(crate) fn verify(&self, channel: u64, epoch: u32, public_key: &Ed25519PublicKey) -> bool {
        let message = signed_message(
            channel,
            epoch,
            self.lo,
            self.hi,
            self.entries.len() as u64,
            &self.digest,
        );
        matches!(
            public_key.verify(&message, &self.signature),
            VerifyOutcome::Valid
        )
    }

    /// The hashes listed at `seq0` (one for any honest sender).
    pub(crate) fn listed(&self, seq0: u64) -> impl Iterator<Item = &[u8; HASH_LEN]> + '_ {
        let start = self.entries.partition_point(|(s, _)| *s < seq0);
        self.entries[start..]
            .iter()
            .take_while(move |(s, _)| *s == seq0)
            .map(|(_, h)| h)
    }
}

#[cfg(test)]
#[path = "checkpoint_tests.rs"]
mod tests;
