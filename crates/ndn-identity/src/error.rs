use thiserror::Error;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("security error: {0}")]
    Security(#[from] ndn_security::TrustError),
    #[error("cert error: {0}")]
    Cert(#[from] ndn_cert::CertError),
    #[error("DID error: {0}")]
    Did(#[from] ndn_did::DidError),
    #[error("app error: {0}")]
    App(#[from] ndn_app::AppError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("name error: {0}")]
    Name(String),
    #[error("enrollment failed: {0}")]
    Enrollment(String),
    #[error("renewal failed: {0}")]
    Renewal(String),
    #[error("not enrolled: call enroll() or provision() first")]
    NotEnrolled,
}
