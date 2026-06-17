//! Identity lifecycle on top of `ndn-security::KeyChain`: creation,
//! NDNCERT enrollment, persistent storage, background renewal.
//!
//! ```rust,no_run
//! use ndn_identity::Identity;
//! # async fn example() -> Result<(), ndn_identity::IdentityError> {
//! let identity = Identity::ephemeral("/com/example/alice")?;
//! let signer = identity.signer()?;
//! # Ok(()) }
//! ```

pub mod ca;
pub mod delegation;
pub mod device;
pub mod recovery_bundle;
pub mod revocation;
pub mod signed_delegation;
pub mod device_approval_net;
pub mod email;
pub mod enroll;
pub mod error;
pub mod facade;
pub mod identity;
pub mod renewal;
pub mod transition;
pub mod trust_context;

pub use ca::{CaApproveFeed, NdncertCa, NdncertCaBuilder};
pub use device::{DeviceConfig, FactoryCredential, RenewalPolicy};
pub use device_approval_net::{
    AllowAnyApprover, ApprovalFeed, ApprovalSink, ApproverAuthorizer, DEFAULT_APPROVAL_TIMEOUT,
    DidApproverAuthorizer, PendingApproval, StaticTrustedApprovers, offer_approval,
    offer_signed_approval, pull_and_record_approval, pull_and_record_approval_with_resolver,
    pull_and_validate_approval, resolve_approver_key, run_approver, serve_approve_feed,
    serve_approve_feed_validated,
};
pub use email::LoggingEmailSender;
pub use enroll::{ChallengeParams, EnrollConfig};
pub use error::IdentityError;
/// Deprecated alias for [`Identity`]; kept for one release.
#[allow(deprecated)]
pub use identity::NdnIdentity;
// The Custodian trait + KeyId now live in `ndn-custodian` (wasm-safe). Re-export
// them so existing `ndn_identity::Custodian` / `KeyId` paths keep working.
pub use delegation::{Delegation, DelegationError};
pub use revocation::{RevocationError, RevocationRecord};
pub use signed_delegation::{DelegatedSigner, SignedDelegation};
pub use facade::Identity;
#[cfg(not(target_arch = "wasm32"))]
pub use ndn_security::custodian::OsKeyringCustodian;
pub use ndn_security::custodian::{
    BrowserExtensionCustodian, Custodian, CustodianError, CustodianRef, CustodianRegistry,
    InPageCustodian, RemoteCustodian, UnlockContext, UnwrappedKey, WrappedKey,
};
pub use transition::{
    AuthorityOutcome, CertRotation, ChainError, DidDocumentRotation, KeyRecovery, KeyState,
    RecoveryProof, RecoverySignature, TransitionAuthority, TransitionProof, TransitionVerifier,
    resolve_chain,
};
pub use trust_context::{
    AdoptionProvenance, CapabilitySet, FaceIdRef, Fingerprint, IdentityLifetime, IdentityRef,
    KeyId, SharedTrustContext, SyncBundle, SyncBundleError, TrustContext, TrustContextError,
    VerificationOutcome,
};
