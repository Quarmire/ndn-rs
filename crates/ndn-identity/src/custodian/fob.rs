//! Fob custodian — signing routed over a face to a remote signer (a phone or
//! hardware fob). Phase 1 ships the shape; the remote-sign wire protocol
//! lands when Phase 4 wires `/_/fob/<fob-id>/sign?...`.

use async_trait::async_trait;
use bytes::Bytes;
use ndn_packet::Name;

use crate::custodian::{
    Custodian, CustodianError, CustodianRef, UnlockContext, UnwrappedKey, WrappedKey,
};
use crate::trust_context::KeyId;

pub struct FobCustodian {
    fob_id: String,
}

impl FobCustodian {
    pub fn new(fob_id: impl Into<String>) -> Self {
        Self {
            fob_id: fob_id.into(),
        }
    }
}

#[async_trait]
impl Custodian for FobCustodian {
    fn kind(&self) -> CustodianRef {
        CustodianRef::Fob {
            fob_id: self.fob_id.clone(),
        }
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
