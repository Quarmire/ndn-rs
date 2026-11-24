//! Signing a log entry: the one place an entry becomes a Data packet. It is the crate's own:
//! a function that signs an entry at a chosen name with a signer it is given would let a host
//! make a device equivocate, and no program outside the crate needs it.

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_packet::encode::DataBuilder;
use ndn_security::Signer;

use super::{Entry, WireError};
use crate::seal::{self, SealError};

/// Why an entry was not signed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SignError {
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
/// The log does this for each entry it writes itself, with the device's key and the entry's
/// [`log_name`](super::log_name). The name is taken as given (the tests of the crate sign at
/// other names, with other devices' keys and with a `PREV` that chains nowhere, to see a node
/// judge them). The entry's id is `(device, seq, signed_digest(&packet))`.
pub(crate) fn sign_entry(
    signer: &dyn Signer,
    name: &Name,
    entry: &Entry,
) -> Result<Bytes, SignError> {
    let content = entry.encode()?;
    seal::sign(DataBuilder::new(name.clone(), &content), signer).map_err(|e| match e {
        SealError::Sign { key, reason } => SignError::Signer { key, reason },
        other => SignError::Signer {
            key: signer.key_name().clone(),
            reason: other.to_string(),
        },
    })
}
