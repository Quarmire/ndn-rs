//! Which key signs a producer's Data: one signer fixed for the producer
//! ([`Producer::with_signer`](crate::Producer::with_signer)), or the key a
//! [`SecurityManager`] chooses by each Data's name
//! ([`Producer::with_signers`](crate::Producer::with_signers)) — a device
//! taking part in several trusted prefixes signs each prefix's Data with
//! that prefix's key.

use std::sync::Arc;

use ndn_packet::Name;
use ndn_security::{SecurityManager, Signer};

use crate::AppError;

#[derive(Clone)]
pub(crate) enum DataSigner {
    /// Every Data is signed with this signer.
    Fixed(Arc<dyn Signer>),
    /// Each Data is signed with the key [`SecurityManager::signer_for`]
    /// chooses by its name.
    ByName(Arc<SecurityManager>),
}

impl DataSigner {
    /// The signer for a Data named `name`; [`AppError::Signing`] (with why
    /// and what to do) when no key of the device may sign it.
    pub(crate) fn signer_for(&self, name: &Name) -> Result<Arc<dyn Signer>, AppError> {
        match self {
            Self::Fixed(signer) => Ok(Arc::clone(signer)),
            Self::ByName(mgr) => mgr.signer_for(name).map_err(AppError::Signing),
        }
    }
}
