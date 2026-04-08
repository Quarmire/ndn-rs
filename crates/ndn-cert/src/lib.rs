//! NDNCERT — NDN Certificate Management Protocol.
//!
//! This crate implements the NDNCERT protocol for automated NDN certificate
//! issuance. It is transport-agnostic: protocol types are serialized to/from
//! JSON bytes that are carried in NDN ApplicationParameters and Content fields.
//! The network wiring (Producer/Consumer) lives in the `ndn-identity` crate.
//!
//! Phase 1C will replace the JSON wire format with full NDN TLV encoding
//! (NDNCERT 0.3 type assignments defined in [`protocol`]), enabling interop
//! with the reference C++ implementation (`ndncert-ca-server`/`ndncert-client`).
//!
//! # Protocol overview
//!
//! ```text
//! Client                           CA
//!   |                               |
//!   |-- Interest: /<ca>/CA/INFO --> |
//!   |<- Data: CaProfile  --------- |
//!   |                               |
//!   |-- Interest: /<ca>/CA/PROBE --> |  (optional: check namespace before enrolling)
//!   |<- Data: ProbeResponse ------- |
//!   |                               |
//!   |-- Interest: /<ca>/CA/NEW  --> | (ApplicationParameters: CertRequest)
//!   |<- Data: NewResponse --------- | (request_id + available challenges)
//!   |                               |
//!   |-- Interest: /<ca>/CA/CHALLENGE/<req-id> --> | (ApplicationParameters: ChallengeRequest)
//!   |<- Data: ChallengeResponse ---- |   (Approved: cert | Processing: more rounds | Denied: error)
//!   |                               |
//!   |-- Interest: /<ca>/CA/REVOKE --> |  (optional: revoke an existing cert)
//!   |<- Data: RevokeResponse ------- |
//! ```

pub mod ca;
pub mod challenge;
pub mod client;
pub mod ecdh;
pub mod error;
pub mod policy;
pub mod protocol;
pub mod tlv;

pub use ca::{CaConfig, CaState};
pub use ecdh::{EcdhKeypair, SessionKey};
pub use challenge::{ChallengeHandler, ChallengeOutcome, ChallengeState};
pub use challenge::email::{EmailChallenge, EmailSender};
pub use challenge::pin::PinChallenge;
pub use challenge::yubikey::YubikeyHotpChallenge;
pub use challenge::possession::PossessionChallenge;
pub use challenge::token::{TokenChallenge, TokenStore};
pub use client::EnrollmentSession;
pub use error::CertError;
pub use policy::{DelegationPolicy, HierarchicalPolicy, NamespacePolicy, PolicyDecision};
pub use protocol::{
    CaProfile, CertRequest, ChallengeRequest, ChallengeResponse, ChallengeStatus, ErrorCode,
    NewResponse, ProbeResponse, RevokeRequest, RevokeResponse, RevokeStatus,
};
