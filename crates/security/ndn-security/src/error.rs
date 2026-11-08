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
    /// The trust context governing the packet holds no trust anchor, so no
    /// signer can be trusted: the validator refuses at once
    /// ([`Validator::refuse_without_anchors`](crate::Validator::refuse_without_anchors),
    /// security profile `default` without a security manager).
    #[error(
        "no trust anchor is configured for {namespace}, so no signer can be trusted (security \
         profile \"default\" without a security manager fails closed): configure trust anchors \
         (a security manager / [security] identity whose PIB holds them, or `ndn-fwd adopt \
         <anchor link>`), or choose profile \"accept-signed\" (signature only) or \"disabled\" \
         explicitly"
    )]
    NoTrustAnchors { namespace: String },
    #[error("key store error: {0}")]
    KeyStore(String),
    /// No identity this device holds may sign `name`. `why` names the
    /// trusted prefix and what to do: the device only follows the prefix
    /// covering `name` (verify only; enroll in it to publish), or no identity
    /// of the device covers `name` at all. Never answered with another
    /// prefix's key or a default key instead.
    #[error("cannot sign {name}: {why}")]
    NoSigningIdentity { name: String, why: String },
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
    /// The trust context refuses what `name` (a key or certificate name)
    /// signed: `why` says which rule (a revocation without a cut, outside
    /// the key's cut, a lapsed key whose role needs a cut — see the
    /// `REVOKED*` constants) and what to do.
    #[error("refused by the trust context: {name} {why}")]
    Revoked { name: String, why: &'static str },
    /// A trust context arrived for a namespace the validator expects one for
    /// (an adoption in progress) and failed the expectation.
    #[error("trust context for {namespace} refused while adopting it: {reason}")]
    ExpectedContextRefused { namespace: String, reason: String },
    /// The packet `name` lies in a person's self-certifying namespace
    /// (`/user/<0xA1: …>`) that this node does not hold: such names are
    /// judged only by their own trust context, never by the trust anchors
    /// held for other names nor by a held `/user` or `/` context, so every
    /// packet in it is refused — signed or not — until it is adopted.
    #[error(
        "{name} is in the self-certifying namespace {namespace}, which this node does not hold: \
         a person's names are judged only by their own trust context, never by the trust \
         anchors this node holds for other names; adopt {namespace} by name first (its anchor \
         link: `ndn-fwd adopt <anchor link>`, which fetches and checks its genesis)"
    )]
    PersonalNamespaceNotHeld { name: String, namespace: String },
}

impl TrustError {
    /// [`TrustError::Revoked`] `why`: a Revocation entry covers the name
    /// and no cut excuses the packet.
    pub const REVOKED: &'static str = "is revoked in the trust context; whatever it signed is \
                                       refused (the owner may revoke it with a cut to keep what \
                                       it signed before it was lost)";
    /// [`TrustError::Revoked`] `why`: the key is revoked with a cut that
    /// does not accept this packet (outside its ranges, not listed by its
    /// manifest, not exactly re-admitted, or verified under another public
    /// key than the cut's).
    pub const REVOKED_OUTSIDE_CUT: &'static str = "is revoked with a cut that does not accept this packet; the owner can re-admit it by \
         its full name (`ndn-fwd readmit`)";
    /// [`TrustError::Revoked`] `why`: no Revocation covers the key, but its
    /// device role is listed in DataRequiresCut and no certificate of the
    /// key that verifies the packet is valid now.
    pub const REVOKED_LAPSED: &'static str = "lapsed: its certificate expired and its role needs a cut (DataRequiresCut), so its Data \
         waits for the owner to revoke the key with a cut that keeps what it signed";
}
