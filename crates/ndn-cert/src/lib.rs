//! NDNCERT v0.3 — automated NDN certificate issuance protocol.
//!
//! Transport-agnostic: protocol messages encode as NDN TLV in
//! `ApplicationParameters` / `Content`. Producer/Consumer wiring lives in
//! `ndn-identity`.
//!
//! Endpoints: `/<ca>/CA/{INFO, PROBE, NEW, CHALLENGE/<req-id>, REVOKE}`.

pub mod attestation;
pub mod ca;
pub mod challenge;
pub mod client;
pub mod ecdh;
pub mod error;
pub mod hub;
pub mod onboarding;
pub mod policy;
pub mod protocol;
pub mod tlv;

pub use attestation::{
    ATTESTATION_DESCRIPTION_KEY, AttestationSet, ChallengeAttestation, Combinator,
};
pub use ca::{CaConfig, CaState};
pub use challenge::email::{EmailChallenge, EmailSender};
pub use challenge::nop::NopChallenge;
pub use challenge::pin::PinChallenge;
pub use challenge::possession::PossessionChallenge;
pub use challenge::token::{TokenChallenge, TokenCheck, TokenStore};
#[cfg(feature = "yubikey-challenge")]
pub use challenge::yubikey::YubikeyHotpChallenge;
pub use challenge::{ChallengeHandler, ChallengeOutcome, ChallengeState};
pub use client::EnrollmentSession;
pub use ecdh::{EcdhKeypair, SessionKey};
pub use error::CertError;
pub use hub::{HubInit, ValidityMode, init_hub};
pub use onboarding::{
    AdvertConfig, AnchorAdvert, BootstrapTicket, adopt_with_tofu, anchor_fingerprint,
    rdr_context_name, rdr_metadata_name,
};
pub use policy::{
    AcceptAllIssuance, DelegationPolicy, HierarchicalPolicy, IssuanceContext, IssuanceDecision,
    IssuancePolicy, NamespacePolicy, PolicyDecision, RequireAttestationKind,
};
pub use protocol::{
    CaProfile, CertRequest, ChallengeRequest, ChallengeResponse, ChallengeStatus, ErrorCode,
    NewResponse, ProbeResponse, RevokeRequest, RevokeResponse, RevokeStatus,
};
