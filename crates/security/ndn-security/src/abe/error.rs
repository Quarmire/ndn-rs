//! Error type for the ndn-abe layer.

use serde::{Deserialize, Serialize};

use crate::abe::AbeSchemeId;

/// Errors from the ABE layer.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq, Serialize, Deserialize)]
pub enum AbeError {
    /// Policy string failed to parse.
    #[error("policy parse error: {0}")]
    PolicyParse(String),
    /// The rabe ABE scheme reported an error.
    #[error("ABE scheme error: {0}")]
    SchemeError(String),
    /// Decryption failed — policy not satisfied or wrong attribute keys.
    #[error("decryption failed: policy not satisfied or wrong keys")]
    DecryptionFailed,
    /// Attribute keys are expired or missing for the named attribute.
    #[error("attribute keys expired or missing for '{0}'")]
    KeysExpiredOrMissing(String),
    /// The scheme is not supported by this build.
    #[error("unsupported scheme {0:?}")]
    UnsupportedScheme(AbeSchemeId),
    /// The ciphertext carries an unsupported schema_version.
    #[error("ciphertext schema version {0} unsupported")]
    UnsupportedCiphertextVersion(u16),
    /// The ciphertext bytes are malformed.
    #[error("ciphertext malformed: {0}")]
    CiphertextMalformed(String),
    /// Serialization or deserialization of rabe types failed.
    #[error("serialization error: {0}")]
    Serialization(String),
    /// A multi-authority policy was given to a single-authority function.
    #[error("multi-authority policy not supported in single-authority context")]
    MultiAuthorityNotSupported,
}
