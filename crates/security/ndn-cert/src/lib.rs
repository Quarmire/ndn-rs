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
pub mod context_update;
pub mod ecdh;
pub mod error;
pub mod invite;
pub mod namespace;
pub mod onboarding;
pub mod policy;
pub mod protocol;
pub mod roles;
pub mod store;
pub mod tlv;

pub use attestation::{
    ATTESTATION_DESCRIPTION_KEY, AttestationSet, ChallengeAttestation, Combinator,
};
pub use ca::{CaConfig, CaRevocation, CaState};
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
    persist_context, read_stored_context, read_stored_contexts,
};
pub use context_update::{
    BumpError, ContextBump, ContextRefresh, ContextUpdate, RefreshError, UpdateRefusal,
    bump_context_revoking, key_name_of, open_context_update, refresh_context,
};
pub use namespace::{
    NamespaceInit, NamespaceInitError, PersistedNamespace, ValidityMode, ca_key_name,
    device_key_name, init_namespace, init_namespace_in_pib, root_key_name,
};
pub use invite::{
    INVITE_ENROLL_MAX_EXCHANGES, InviteEnrollError, InviteEnrollFailure, InviteEnrollment,
    InviteLink, IssuedCertificate, enroll_with_invite, ensure_invite_context, new_device_key_name,
};
pub use onboarding::{
    AdoptError, AdvertConfig, AnchorAdvert, AnchorLink, CONTEXT_EXPECTATION_TTL,
    FetchContextError, LinkAdoption, adopt_anchor_envelope, adopt_anchor_link,
    adopt_unsigned_legacy_with_tofu, adopt_with_tofu, anchor_fingerprint, context_pointer,
    fetch_context, fetch_context_pointer, fetch_versioned_context, open_signed_context,
    rdr_metadata_name, rdr_prefix,
};
pub use policy::{
    AcceptAllIssuance, DelegationPolicy, HierarchicalPolicy, IssuanceContext, IssuanceDecision,
    IssuancePolicy, NamespacePolicy, PolicyDecision, RequireAttestationKind, RolePolicy,
    SingleKeyIdentity,
};
pub use roles::{NamespaceSchema, Role, RoleError, namespace_schema};
pub use protocol::{
    CaProfile, CertRequest, ChallengeRequest, ChallengeResponse, ChallengeStatus, ErrorCode,
    NewResponse, ProbeResponse, RevokeRequest, RevokeResponse, RevokeStatus,
};
