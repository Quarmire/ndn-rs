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
    /// A certificate hop the governing trust context refuses: `issuer` may
    /// not certify `cert`; `why` says which rule refused it and what to do.
    #[error("certificate {cert} is not authorized by its issuer {issuer}: {why}")]
    CertNotAuthorized {
        cert: String,
        issuer: String,
        why: String,
    },
    /// The chain ends at a self-signed certificate that is no trust anchor of
    /// the trust context governing the packet: nothing vouches for it.
    #[error(
        "certificate chain ends at self-signed certificate {cert}, which is not a trust anchor \
         of the trust context for {namespace}: adopt the trust context of the namespace that \
         issued it (`ndn-fwd adopt <anchor link>`), or add {cert} as a trust anchor"
    )]
    UntrustedSelfSigned { cert: String, namespace: String },
    #[error("key store error: {0}")]
    KeyStore(String),
    #[error("unsupported signature type: {name} (code {code})")]
    UnsupportedSignatureType { code: u64, name: String },
    /// A signature type that no public key verifies, where a signer's public
    /// key (a certificate's or trust anchor's) was to verify it: a digest
    /// (DigestSha256, DigestBlake3) names no signer and anyone can compute
    /// it; a symmetric MAC (HmacWithSha256, BLAKE3-keyed) verifies only under
    /// a shared secret, and a public key is no secret — anyone holding it
    /// could compute the MAC.
    #[error(
        "{sig_type} is not a public-key signature, so the signer's public key cannot verify it: \
         {why}"
    )]
    NotPublicKeySignature { sig_type: String, why: &'static str },
    #[error("certificate revoked in trust context: {name}")]
    Revoked { name: String },
    /// A trust context arrived for a namespace the validator expects one for
    /// (an adoption in progress) and failed the expectation.
    #[error("trust context for {namespace} refused while adopting it: {reason}")]
    ExpectedContextRefused { namespace: String, reason: String },
}
