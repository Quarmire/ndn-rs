//! NDN identity management — high-level lifecycle for NDN identities.
//!
//! `ndn-identity` provides [`NdnIdentity`]: a unified handle for an NDN
//! signing identity that handles creation, enrollment via NDNCERT, persistent
//! storage, and background certificate renewal.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use ndn_identity::NdnIdentity;
//!
//! # async fn example() -> Result<(), ndn_identity::IdentityError> {
//! // Ephemeral (tests, quick prototypes)
//! let identity = NdnIdentity::ephemeral("/com/example/alice")?;
//!
//! // Persistent — load or create
//! let identity = NdnIdentity::open_or_create(
//!     std::path::Path::new("/var/lib/ndn/identity"),
//!     "/com/example/alice",
//! )?;
//!
//! // Use the signer
//! let signer = identity.signer()?;
//! println!("Identity: {}", identity.name());
//! println!("DID: {}", identity.did());
//! # Ok(())
//! # }
//! ```
//!
//! # Fleet provisioning
//!
//! ```rust,no_run
//! use ndn_identity::{NdnIdentity, DeviceConfig, FactoryCredential, RenewalPolicy};
//! use std::time::Duration;
//!
//! # async fn example() -> Result<(), ndn_identity::IdentityError> {
//! let identity = NdnIdentity::provision(DeviceConfig {
//!     namespace: "/com/acme/fleet/VIN-123456".parse().unwrap(),
//!     storage: Some("/var/lib/ndn/device".into()),
//!     factory_credential: FactoryCredential::Token("factory-token-abc".to_string()),
//!     ca_prefix: Some("/com/acme/fleet/CA".parse().unwrap()),
//!     renewal: RenewalPolicy::WhenPercentRemaining(20),
//!     delegate: vec![],
//! }).await?;
//! # Ok(())
//! # }
//! ```

pub mod ca;
pub mod device;
pub mod enroll;
pub mod error;
pub mod identity;
pub mod renewal;

pub use ca::{NdncertCa, NdncertCaBuilder};
pub use device::{DeviceConfig, FactoryCredential, RenewalPolicy};
pub use enroll::{ChallengeParams, EnrollConfig};
pub use error::IdentityError;
pub use identity::NdnIdentity;
