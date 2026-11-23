//! Signing a log entry: the one place an entry becomes a Data packet, for the
//! log's own entries and for a program that forges one at an exact name.

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_packet::encode::DataBuilder;
use ndn_security::Signer;

use super::{Entry, WireError};
use crate::seal::{self, SealError};

/// Why an entry was not signed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SignError {
    /// The entry cannot be encoded: the format does not carry it.
    #[error("{0}")]
    Wire(#[from] WireError),
    /// The signer did not sign.
    #[error(
        "the device key {key} did not sign ({reason}); the data layer needs a key that signs \
         synchronously"
    )]
    Signer {
        /// The signer's key name.
        key: Name,
        /// What the signer said.
        reason: String,
    },
}

/// The Data packet that carries `entry` at `name`, signed by `signer`: the
/// Content is [`Entry::encode`]d, and the signature, made synchronously by
/// `signer`, names `signer`'s key as its key locator.
///
/// This is what the log does for each entry it writes itself, with the
/// device's key and the entry's [`log_name`](super::log_name). The name is
/// taken as given, so a program that signs an entry at some other name
/// (or with another device's key, or with a `PREV` that chains nowhere) gets
/// the packet it asked for, which a node then judges as it judges any packet.
/// The entry's id is `(device, seq, signed_digest(&packet))`.
pub fn sign_entry(signer: &dyn Signer, name: &Name, entry: &Entry) -> Result<Bytes, SignError> {
    let content = entry.encode()?;
    seal::sign(DataBuilder::new(name.clone(), &content), signer).map_err(|e| match e {
        SealError::Sign { key, reason } => SignError::Signer { key, reason },
        other => SignError::Signer {
            key: signer.key_name().clone(),
            reason: other.to_string(),
        },
    })
}
