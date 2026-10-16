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

pub mod adopt;
pub mod ca;
pub mod context_sync;
pub mod delegation;
pub mod device;
pub mod device_approval_net;
pub mod email;
mod engine_exchange;
pub mod enroll;
pub mod error;
pub mod facade;
pub mod invite;
pub mod identity_ref;
pub mod recovery_bundle;
pub mod renewal;
pub mod revocation;
pub mod signed_delegation;
pub mod transition;

pub use adopt::adopt_anchor_link_via_engine;
pub use invite::enroll_with_invite_via_engine;
pub use ca::{NdncertCa, NdncertCaBuilder};
pub use device::{DeviceConfig, FactoryCredential, RenewalPolicy};
pub use device_approval_net::{
    ApprovalFeed, ApprovalSink, DEFAULT_APPROVAL_TIMEOUT, PendingApproval, offer_signed_approval,
    pull_and_validate_approval, run_approver, serve_approve_feed_validated,
};
pub use email::LoggingEmailSender;
pub use enroll::{ChallengeParams, NdncertClient};
pub use error::IdentityError;
pub use delegation::{Delegation, DelegationError};
pub use facade::Identity;
pub use identity_ref::{CapabilitySet, IdentityLifetime, IdentityRef};
#[cfg(not(target_arch = "wasm32"))]
pub use ndn_security::custodian::OsKeyringCustodian;
// The Custodian trait + KeyId live in `ndn_security::custodian` (wasm-safe).
// Re-exported so `ndn_identity::Custodian` / `KeyId` paths resolve.
pub use ndn_security::custodian::{
    BrowserExtensionCustodian, Custodian, CustodianError, CustodianRef, CustodianRegistry,
    InPageCustodian, KeyId, RemoteCustodian, UnlockContext, UnwrappedKey, WrappedKey,
};
pub use revocation::{RevocationError, RevocationRecord};
pub use signed_delegation::{DelegatedSigner, SignedDelegation};
pub use transition::{
    AuthorityOutcome, CertRotation, ChainError, DidDocumentRotation, KeyRecovery, KeyState,
    RecoveryProof, RecoverySignature, TransitionAuthority, TransitionProof, TransitionVerifier,
    resolve_chain,
};
