//! # ndn-security -- Packet signing, verification, and trust management
//!
//! Provides cryptographic primitives and trust-policy enforcement for NDN
//! packets. Signers produce signatures; verifiers check them; the validator
//! chains verification with a [`TrustSchema`] to decide whether data is
//! trustworthy. Only validated data is wrapped in [`SafeData`], giving the
//! compiler a way to enforce that unverified packets are never forwarded.
//!
//! ## Key types
//!
//! - [`Signer`] / [`Verifier`] -- signing and verification traits
//! - [`Ed25519Signer`], [`Ed25519Verifier`], [`HmacSha256Signer`] -- concrete impls
//! - [`Validator`] -- chains verification + trust schema lookup
//! - [`TrustSchema`] -- name-pattern rules for trust decisions
//! - [`SafeData`] -- newtype proving a Data packet has been validated
//! - [`CertCache`], [`KeyStore`] -- certificate and key storage
//! - [`SecurityManager`] -- high-level facade combining the above

#![allow(missing_docs)]

pub mod cert_cache;
pub mod cert_fetcher;
pub mod did;
pub mod error;
pub mod key_store;
pub mod keychain;
pub mod lvs;
pub mod manager;
pub mod pib;
pub mod profile;
pub mod safe_data;
pub mod sign_ext;
pub mod signer;
pub mod trust_schema;
pub mod validator;
pub mod verifier;
#[cfg(feature = "yubikey-piv")]
pub mod yubikey;
pub mod zone;

pub use cert_cache::{CertCache, Certificate};
pub use cert_fetcher::{CertFetcher, FetchFn};
pub use error::TrustError;
pub use key_store::{KeyAlgorithm, KeyStore, MemKeyStore};
pub use keychain::KeyChain;
pub use lvs::{LvsError, LvsModel};
pub use manager::SecurityManager;
pub use pib::{FilePib, PibError};
pub use profile::SecurityProfile;
pub use safe_data::SafeData;
pub use sign_ext::SignWith;
pub use signer::{
    Blake3KeyedSigner, Blake3Signer, Ed25519Signer, HmacSha256Signer,
    SIGNATURE_TYPE_DIGEST_BLAKE3_KEYED, SIGNATURE_TYPE_DIGEST_BLAKE3_PLAIN, Signer,
};
pub use trust_schema::{NamePattern, PatternComponent, PatternParseError, SchemaRule, TrustSchema};
pub use validator::{ValidationResult, Validator};
pub use verifier::{
    Blake3DigestVerifier, Blake3KeyedVerifier, Ed25519Verifier, Verifier, VerifyOutcome,
};
#[cfg(feature = "yubikey-piv")]
pub use yubikey::{YubikeyKeyStore, YubikeySlot};
pub use zone::{ZoneKey, verify_zone_root, zone_root_from_pubkey, zone_root_to_did};

// DID convenience re-exports (use `ndn_security::did::...` for the full API)
pub use did::{
    DereferencedResource, DidController, DidDocument, DidDocumentMetadata, DidError,
    DidResolutionResult, DidResolver, DidUrl, KeyDidResolver, NdnDidResolver, Service,
    ServiceEndpoint, UniversalResolver, VerificationMethod, VerificationRef,
    build_zone_did_document, build_zone_succession_document, cert_to_did_document, deref_did_url,
    did_to_name, name_to_did,
};
