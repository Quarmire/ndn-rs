//! NDNCERT v0.3 — automated NDN certificate issuance protocol.
//!
//! Transport-agnostic: protocol messages encode as NDN TLV in
//! `ApplicationParameters` / `Content`. Producer/Consumer wiring lives in
//! `ndn-identity`.
//!
//! Endpoints: `/<ca>/CA/{INFO, PROBE, NEW, CHALLENGE/<req-id>, REVOKE}`, plus
//! `/<ca>/CA/{APPROVAL, PENDING}` for enrollment by an admin's approval
//! ([`approval`]).

pub mod approval;
pub mod attestation;
pub mod ca;
pub mod ca_policy;
pub mod challenge;
pub mod client;
pub mod context_store;
pub mod context_update;
pub mod ecdh;
pub mod enroll_target;
pub mod error;
pub mod invite;
pub mod issuers;
pub mod namespace;
pub mod onboarding;
pub mod policy;
pub mod protocol;
pub mod recovery;
pub mod renewal;
pub mod report;
pub mod revocation;
pub mod roles;
pub mod root_device;
pub mod root_store;
pub mod store;
pub mod tlv;

pub use approval::{
    ApprovalEnrollError, ApprovalPoll, ApprovalRecord, ApprovalRefusal, ApprovalService,
    ApprovalState, ApprovalStore, Approver, ApproverError, Decision, HeldStatus, OutgoingRequest,
    OutgoingState, PendingRequest, RefusalKind, RequestStatus, RequestStore, fetch_pending,
    normalize_code, poll_approval, push_decision, request_status, verification_code,
};
pub use attestation::{
    ATTESTATION_DESCRIPTION_KEY, AttestationSet, ChallengeAttestation, Combinator,
};
pub use ca::{CaConfig, CaRevocation, CaState};
pub use ca_policy::{
    ChallengeOrder, ChallengeSlot, NamespacePolicies, PolicyError, PolicyInput, SchemaPlanError,
    SchemaUpdatePlan, challenge_order, plan_schema_update, same_link_policy,
};
pub use challenge::device_approval::DeviceApprovalChallenge;
pub use challenge::email::{EmailChallenge, EmailSender};
pub use challenge::nop::NopChallenge;
pub use challenge::pin::PinChallenge;
pub use challenge::possession::PossessionChallenge;
pub use challenge::token::{ApprovalRoleToken, TokenChallenge, TokenCheck, TokenStore};
#[cfg(feature = "yubikey-challenge")]
pub use challenge::yubikey::YubikeyHotpChallenge;
pub use challenge::{ChallengeHandler, ChallengeOutcome, ChallengeState};
pub use client::{CaExchange, ChallengeExchange, ChallengeRound, EnrollmentSession};
pub use context_store::{
    ContextStoreError, adopt_envelope_into_store, context_file_path, context_version_path,
    context_versions_dir, load_persisted_contexts, persist_context, read_stored_context,
    read_stored_contexts, read_stored_versions, remove_stored_context,
};
pub use context_update::{
    BumpError, CatchUpStop, ContextBump, ContextRefresh, ContextStep, ContextUpdate,
    MAX_CATCH_UP_TIME, MAX_CATCH_UP_VERSIONS, RefreshError, SchemaBump, SchemaChange, Unfetched,
    UpdateRefusal, VersionSource, bump_context_revoking, bump_context_schema, follow_versions,
    key_name_of, link_narrowing, open_context_update, refresh_context, relay_narrowing,
    revocations_to_add, schema_change,
};
pub use ecdh::{EcdhKeypair, SessionKey};
pub use enroll_target::{EnrollTarget, EnrollTargetError};
pub use error::CertError;
pub use invite::{
    EnrollLink, INVITE_ENROLL_MAX_EXCHANGES, InviteEnrollError, InviteEnrollFailure,
    InviteEnrollment, InviteLink, IssuedCertificate, IssuedCheckError, check_chain,
    enroll_with_invite, ensure_invite_context, new_device_key_name,
};
pub use namespace::{
    NamespaceInit, NamespaceInitError, PersistedNamespace, ValidityMode, ca_key_name,
    device_key_name, init_namespace, init_namespace_in_pib, init_namespace_in_pib_with,
    root_key_name,
};
pub use onboarding::{
    AdoptError, AdvertConfig, AnchorAdvert, AnchorLink, CONTEXT_EXPECTATION_TTL, FetchContextError,
    LinkAdoption, adopt_anchor_envelope, adopt_anchor_link, adopt_unsigned_legacy_with_tofu,
    adopt_with_tofu, anchor_fingerprint, context_pointer, fetch_context, fetch_context_pointer,
    fetch_versioned_context, open_signed_context, rdr_metadata_name, rdr_prefix,
};
pub use policy::{
    AcceptAllIssuance, AllIssuance, ApprovalPolicy, DelegationPolicy, HierarchicalPolicy,
    IssuanceContext, IssuanceDecision, IssuancePolicy, NamespacePolicy, PolicyDecision,
    RequireAttestationKind, RolePolicy, RoleTerms, SingleKeyIdentity,
};
pub use protocol::{
    CaProfile, CertRequest, ChallengeRequest, ChallengeResponse, ChallengeStatus, ErrorCode,
    NewResponse, ProbeResponse, RevokeRequest, RevokeResponse, RevokeStatus,
};
pub use recovery::{
    FileKit, KitFormat, OldRoot, RecoveredNamespace, RecoveryError, RecoveryPlan, RecoverySeed,
    RecoveryVersion, YubikeyKit, add_recovery_anchor, kit_anchor, recover_namespace_in_pib,
    recovery_anchor, recovery_key_name, recovery_version, reissue_version, remove_recovery_anchor,
    seal_file_kit,
};
pub use renewal::{
    RENEWAL_CHALLENGE, RenewalError, issuing_ca_prefix, renew_certificate, renewal_proof_message,
};
pub use revocation::{RevocationError, RevocationPlan, keys_to_revoke, plan_revocation};
pub use roles::{NamespaceSchema, Role, RoleError, namespace_schema};
pub use root_device::{RootDevice, RootDeviceError, held_context, kit_namespace, root_device};
pub use root_store::{
    NewRootStore, RootSecret, RootStore, RootStoreError, RootStoreKind, RootUnlockKind, SlotGuard,
    os_keychain_reachable, read_root_secret, read_secret,
};
pub use store::{CaSnapshot, CaStore, FileCaStore};
