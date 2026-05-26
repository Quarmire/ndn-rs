//! Browser-extension custodian. Phase 1 stub: detects extension presence via
//! `window.ndnIdentity` (on wasm targets) and reports `is_available == false`
//! until Phase 5 wires the Chrome MV3 backend.

use async_trait::async_trait;
use bytes::Bytes;
use ndn_packet::Name;

use crate::custodian::{
    Custodian, CustodianError, CustodianRef, UnlockContext, UnwrappedKey, WrappedKey,
};
use crate::trust_context::KeyId;

#[derive(Default)]
pub struct BrowserExtensionCustodian;

impl BrowserExtensionCustodian {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Custodian for BrowserExtensionCustodian {
    fn kind(&self) -> CustodianRef {
        CustodianRef::BrowserExtension
    }

    async fn is_available(&self) -> bool {
        false
    }

    fn prompts_per_action(&self) -> bool {
        true
    }

    async fn unlock(&self, _ctx: UnlockContext) -> Result<(), CustodianError> {
        Err(CustodianError::Unavailable)
    }

    async fn sign(
        &self,
        _key_id: &KeyId,
        _name: &Name,
        _content: &[u8],
    ) -> Result<Bytes, CustodianError> {
        Err(CustodianError::Unavailable)
    }

    async fn unwrap_for(
        &self,
        _key_id: &KeyId,
        _wrapped: &WrappedKey,
    ) -> Result<UnwrappedKey, CustodianError> {
        Err(CustodianError::Unavailable)
    }
}
