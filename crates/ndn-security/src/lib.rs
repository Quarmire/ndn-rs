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
pub mod error;
pub mod key_store;
pub mod manager;
pub mod pib;
pub mod profile;
pub mod safe_data;
pub mod signer;
pub mod trust_schema;
pub mod validator;
pub mod verifier;
#[cfg(feature = "yubikey-piv")]
pub mod yubikey;

pub use cert_cache::{CertCache, Certificate};
pub use cert_fetcher::{CertFetcher, FetchFn};
pub use error::TrustError;
pub use key_store::{KeyAlgorithm, KeyStore, MemKeyStore};
#[cfg(feature = "yubikey-piv")]
pub use yubikey::{YubikeyKeyStore, YubikeySlot};
pub use manager::SecurityManager;
pub use pib::{FilePib, PibError};
pub use profile::SecurityProfile;
pub use safe_data::SafeData;
pub use signer::{Ed25519Signer, HmacSha256Signer, Signer};
pub use trust_schema::{NamePattern, PatternComponent, TrustSchema};
pub use validator::{ValidationResult, Validator};
pub use verifier::{Ed25519Verifier, Verifier, VerifyOutcome};
