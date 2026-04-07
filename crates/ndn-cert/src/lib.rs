//! NDNCERT — NDN Certificate Management Protocol.
//!
//! This crate implements the NDNCERT protocol for automated NDN certificate
//! issuance. It is transport-agnostic: protocol types are serialized to/from
//! JSON bytes that are carried in NDN ApplicationParameters and Content fields.
//! The network wiring (Producer/Consumer) lives in the `ndn-identity` crate.
//!
//! # Protocol overview
//!
//! ```text
//! Client                           CA
//!   |                               |
//!   |-- Interest: /<ca>/CA/INFO --> |
//!   |<- Data: CaProfile  --------- |
//!   |                               |
//!   |-- Interest: /<ca>/CA/NEW  --> | (ApplicationParameters: CertRequest)
//!   |<- Data: NewResponse --------- | (request_id + available challenges)
//!   |                               |
//!   |-- Interest: /<ca>/CA/CHALLENGE/<req-id> --> | (ApplicationParameters: ChallengeRequest)
//!   |<- Data: ChallengeResponse ---- |   (Approved: issued cert | Denied: error)
//! ```

pub mod ca;
pub mod challenge;
pub mod client;
pub mod error;
pub mod policy;
pub mod protocol;

pub use ca::{CaConfig, CaState};
pub use challenge::{ChallengeHandler, ChallengeOutcome, ChallengeState};
pub use challenge::possession::PossessionChallenge;
pub use challenge::token::{TokenChallenge, TokenStore};
pub use client::EnrollmentSession;
pub use error::CertError;
pub use policy::{DelegationPolicy, HierarchicalPolicy, NamespacePolicy, PolicyDecision};
pub use protocol::{CaProfile, CertRequest, ChallengeRequest, ChallengeResponse, NewResponse};
