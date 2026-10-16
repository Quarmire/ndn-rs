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
pub mod context_store;
pub mod ecdh;
pub mod error;
pub mod hub;
pub mod onboarding;
pub mod policy;
pub mod protocol;
pub mod roles;
pub mod store;
pub mod tlv;

pub use attestation::{
    ATTESTATION_DESCRIPTION_KEY, AttestationSet, ChallengeAttestation, Combinator,
};
pub use ca::{CaConfig, CaState};
pub use store::{CaSnapshot, CaStore, FileCaStore};
pub use challenge::email::{EmailChallenge, EmailSender};
pub use challenge::nop::NopChallenge;
pub use challenge::pin::PinChallenge;
pub use challenge::possession::PossessionChallenge;
pub use challenge::token::{TokenChallenge, TokenCheck, TokenStore};
#[cfg(feature = "yubikey-challenge")]
pub use challenge::yubikey::YubikeyHotpChallenge;
pub use challenge::{ChallengeHandler, ChallengeOutcome, ChallengeState};
pub use client::{CaExchange, ChallengeRound, EnrollmentSession};
pub use ecdh::{EcdhKeypair, SessionKey};
pub use error::CertError;
pub use context_store::{
    ContextStoreError, adopt_envelope_into_store, context_file_path, load_persisted_contexts,
    persist_context,
};
pub use hub::{
    HubInit, HubInitError, PersistedHub, ValidityMode, ca_key_name, device_key_name, init_hub,
    init_hub_in_pib, root_key_name,
};
pub use onboarding::{
    AdoptError, AdvertConfig, AnchorAdvert, adopt_anchor_envelope, adopt_unsigned_legacy_with_tofu,
    adopt_with_tofu, anchor_fingerprint, open_signed_context, rdr_metadata_name,
};
pub use policy::{
    AcceptAllIssuance, DelegationPolicy, HierarchicalPolicy, IssuanceContext, IssuanceDecision,
    IssuancePolicy, NamespacePolicy, PolicyDecision, RequireAttestationKind, RolePolicy,
};
pub use roles::{NetworkSchema, Role, RoleError, network_schema};
pub use protocol::{
    CaProfile, CertRequest, ChallengeRequest, ChallengeResponse, ChallengeStatus, ErrorCode,
    NewResponse, ProbeResponse, RevokeRequest, RevokeResponse, RevokeStatus,
};
