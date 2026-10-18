//! Packet signing, verification, and trust management for NDN.
//!
//! Signers produce signatures; verifiers check them; the [`Validator`]
//! chains verification with a [`TrustSchema`] to decide whether data is
//! trustworthy. Only validated data is wrapped in [`SafeData`], so the
//! compiler enforces that unverified packets are never forwarded.
//!
//! Key types: [`Signer`] / [`Verifier`] (traits), [`Validator`],
//! [`TrustSchema`], [`SafeData`], [`CertCache`], [`FilePib`], and
//! [`SecurityManager`] as the high-level facade.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(missing_docs)]

pub mod active_signer;
#[cfg(feature = "abe")]
#[cfg_attr(docsrs, doc(cfg(feature = "abe")))]
pub mod abe;
pub mod capability;
pub mod cert_cache;
pub mod cert_fetcher;
pub mod cert_name;
pub mod cert_set;
pub mod confidentiality;
#[cfg(feature = "custodian")]
#[cfg_attr(docsrs, doc(cfg(feature = "custodian")))]
pub mod custodian;
pub mod did;
pub mod error;
#[cfg(feature = "ndnsec-compat")]
#[cfg_attr(docsrs, doc(cfg(feature = "ndnsec-compat")))]
pub mod file_tpm;
mod hmac_sha256;
pub mod iso8601;
pub mod keychain;
pub mod keyring;
pub mod lvs;
pub mod lvs_compile;
pub mod manager;
pub mod pib;
pub mod profile;
pub mod replay_guard;
pub mod safe_data;
pub mod safebag;
pub mod secure_fs;
pub mod sign_ext;
pub mod signer;
pub mod signing_info;
pub mod spki;
#[cfg(feature = "ndnsec-compat")]
#[cfg_attr(docsrs, doc(cfg(feature = "ndnsec-compat")))]
pub mod sqlite_pib;
pub mod trust_context;
pub mod trust_schema;
pub mod unverified;
pub mod validator;
pub mod verifier;
#[cfg(feature = "yubikey-piv")]
#[cfg_attr(docsrs, doc(cfg(feature = "yubikey-piv")))]
pub mod yubikey;

pub use active_signer::ActiveSigner;
pub use capability::{Capability, CapabilityError};
pub use cert_cache::{CertCache, Certificate};
pub use cert_fetcher::{CertFetcher, DirectFetchFn, FetchFn, FetchMiss};
pub use cert_set::CertSet;
pub use confidentiality::{ContentKey, EpochPolicy, RotatingKey, Sealed, unwrap_ck, wrap_ck};
pub use error::TrustError;
pub use keychain::{KeyAlgorithm, KeyChain};
pub use keyring::Keyring;
pub use lvs::{LvsError, LvsModel, LvsUserFn, UserFnRegistry};
pub use lvs_compile::{
    LvsCompileError, compile as compile_lvs, compile_to_binary as compile_lvs_to_binary,
};
pub use manager::{SecurityManager, encode_cert_data, encode_cert_data_with_description};
pub use pib::{FilePib, PibError};
pub use profile::SecurityProfile;
pub use replay_guard::{KeyFingerprint, ReplayCheck, ReplayGuard};
pub use safe_data::SafeData;
pub use sign_ext::SignWith;
pub use signer::{
    Blake3KeyedSigner, Blake3Signer, EcdsaP256Signer, Ed25519Signer, HmacSha256Signer,
    SIGNATURE_TYPE_DIGEST_BLAKE3_KEYED, SIGNATURE_TYPE_DIGEST_BLAKE3_PLAIN, Signer,
};
pub use signing_info::{SignatureInfoOverrides, SignerSelection, SigningInfo};
pub use trust_context::{
    ContextExplanation, EnrollmentHint, KeyRole, LinkPolicy, OpenContextError, SchemaBlob,
    SchemaFormat, SignedTrustContext, SignedTrustContextError, SigningPair, anchor_fingerprint,
    context_namespace_of, dryrun_orphans,
};
pub use trust_schema::{
    NamePattern, PatternComponent, PatternParseError, SchemaGate, SchemaMatch, SchemaRule,
    TrustSchema,
};
pub use unverified::{Unverified, VerifyError};
pub use validator::{
    AdmittedContext, ContextExpectation, ExpectContextError, ExpectationOutcome,
    InterestValidationOutcome,
    ValidationResult, Validator,
};
pub use verifier::{
    Blake3DigestVerifier, Blake3KeyedVerifier, Ed25519Verifier, Verifier, VerifyOutcome,
    ed25519_verify_batch, verify_by_sig_type, verify_digest,
};
#[cfg(feature = "yubikey-piv")]
pub use yubikey::{
    YubikeyPinPolicy, YubikeyPiv, YubikeySlot, YubikeySlotState, YubikeyTouchPolicy,
};

pub use did::{
    DereferencedResource, DidController, DidDocument, DidDocumentMetadata, DidError,
    DidResolutionResult, DidResolver, DidUrl, IdentityProof, KeyDidResolver, NdnDidResolver,
    RecoveryCommitment, Service, ServiceEndpoint, UniversalResolver, VerificationMethod,
    VerificationRef, cert_to_did_document, deref_did_url, did_to_name, name_to_did,
};
