//! Packet signing, verification, and trust management for NDN.
//!
//! Signers produce signatures; verifiers check them; the [`Validator`]
//! chains verification with a [`TrustSchema`] to decide whether data is
//! trustworthy. Only validated data is wrapped in [`SafeData`], so the
//! compiler enforces that unverified packets are never forwarded.
//!
//! Key types: [`Signer`] / [`Verifier`] (traits), [`Validator`],
//! [`TrustSchema`], [`SafeData`], [`CertCache`], [`KeyStore`], and
//! [`SecurityManager`] as the high-level facade.

#![allow(missing_docs)]

#[cfg(feature = "abe")]
pub mod abe;
#[cfg(feature = "custodian")]
pub mod custodian;
pub mod safebag;
pub mod cert_cache;
pub mod cert_fetcher;
pub mod did;
pub mod error;
pub mod file_tpm;
mod hmac_sha256;
pub mod iso8601;
pub mod key_store;
pub mod keychain;
pub mod keyring;
pub mod lvs;
pub mod manager;
pub mod pib;
pub mod profile;
pub mod replay_guard;
pub mod safe_bag;
pub mod safe_data;
pub mod sign_ext;
pub mod signer;
pub mod signing_info;
pub mod spki;
#[cfg(feature = "sqlite-pib")]
pub mod sqlite_pib;
pub mod trust;
pub mod trust_context;
pub mod trust_schema;
pub mod unverified;
pub mod validation_policy;
pub mod validator;
pub mod verifier;
#[cfg(feature = "yubikey-piv")]
pub mod yubikey;

pub use cert_cache::{CertCache, Certificate};
pub use cert_fetcher::{CertFetcher, FetchFn};
pub use error::TrustError;
pub use key_store::{KeyAlgorithm, KeyStore, MemKeyStore};
pub use keychain::KeyChain;
pub use keyring::Keyring;
pub use lvs::{LvsError, LvsModel};
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
pub use trust::{InsecureTrust, LvsTrust, StaticTrust, TrustPolicy};
pub use trust_context::{
    EnrollmentHint, SchemaBlob, SchemaFormat, SignedTrustContext, SignedTrustContextError,
    SigningPair, dryrun_orphans,
};
pub use trust_schema::{
    NamePattern, PatternComponent, PatternParseError, SchemaGate, SchemaRule, TrustSchema,
};
pub use unverified::{Unverified, VerifyError};
pub use validation_policy::{
    AcceptAllPolicy, ChainedPolicy, ConfigChecker, ConfigPolicy, ConfigRule, HierarchicalPolicy,
    LvsPolicy, PolicyVerdict, ValidationPolicy,
};
pub use validator::{InterestValidationOutcome, ValidationResult, Validator};
pub use verifier::{
    Blake3DigestVerifier, Blake3KeyedVerifier, Ed25519Verifier, Verifier, VerifyOutcome,
    ed25519_verify_batch,
};
#[cfg(feature = "yubikey-piv")]
pub use yubikey::{YubikeyKeyStore, YubikeySlot};

pub use did::{
    DereferencedResource, DidController, DidDocument, DidDocumentMetadata, DidError,
    DidResolutionResult, DidResolver, DidUrl, IdentityProof, KeyDidResolver, NdnDidResolver,
    RecoveryCommitment, Service, ServiceEndpoint, UniversalResolver, VerificationMethod,
    VerificationRef, cert_to_did_document, deref_did_url, did_to_name, name_to_did,
};
