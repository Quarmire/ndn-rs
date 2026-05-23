//! Identity lifecycle on top of `ndn-security::KeyChain`: creation,
//! NDNCERT enrollment, persistent storage, background renewal.
//!
//! ```rust,no_run
//! use ndn_identity::NdnIdentity;
//! # async fn example() -> Result<(), ndn_identity::IdentityError> {
//! let identity = NdnIdentity::ephemeral("/com/example/alice")?;
//! let signer = identity.signer()?;
//! # Ok(()) }
//! ```

pub mod ca;
pub mod device;
pub mod device_approval_net;
pub mod email;
pub mod enroll;
pub mod error;
pub mod identity;
pub mod renewal;

pub use ca::{ApproveFeed, NdncertCa, NdncertCaBuilder};
pub use device::{DeviceConfig, FactoryCredential, RenewalPolicy};
pub use email::LoggingEmailSender;
pub use device_approval_net::{
    AllowAnyApprover, ApprovalFeed, ApprovalSink, ApproverAuthorizer, DEFAULT_APPROVAL_TIMEOUT,
    DidApproverAuthorizer, PendingApproval, StaticTrustedApprovers, offer_approval,
    offer_signed_approval, pull_and_record_approval, pull_and_record_approval_with_resolver,
    pull_and_validate_approval, resolve_approver_key, run_approver, serve_approve_feed,
    serve_approve_feed_validated,
};
pub use enroll::{ChallengeParams, EnrollConfig};
pub use error::IdentityError;
pub use identity::NdnIdentity;
