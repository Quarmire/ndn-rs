use thiserror::Error;

#[derive(Debug, Error)]
pub enum TrustError {
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("invalid key encoding")]
    InvalidKey,
    #[error("certificate not found: {name}")]
    CertNotFound { name: String },
    #[error("certificate chain too deep (limit: {limit})")]
    ChainTooDeep { limit: usize },
    #[error("certificate chain cycle detected at: {name}")]
    ChainCycle { name: String },
    #[error("name does not match trust schema")]
    SchemaMismatch,
    #[error("key store error: {0}")]
    KeyStore(String),
}
