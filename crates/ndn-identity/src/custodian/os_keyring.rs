//! Desktop-only OS keyring custodian. Phase 1 ships the shape; full
//! integration with `keyring` crate is gated to a follow-up phase so we
//! don't drag a non-wasm dep into builds that target the browser.

#[cfg(not(target_arch = "wasm32"))]
mod imp {
    use async_trait::async_trait;
    use bytes::Bytes;
    use ndn_packet::Name;

    use crate::custodian::{
        Custodian, CustodianError, CustodianRef, UnlockContext, UnwrappedKey, WrappedKey,
    };
    use crate::trust_context::KeyId;

    #[derive(Default)]
    pub struct OsKeyringCustodian {
        service: String,
    }

    impl OsKeyringCustodian {
        pub fn new(service: impl Into<String>) -> Self {
            Self {
                service: service.into(),
            }
        }

        pub fn service(&self) -> &str {
            &self.service
        }
    }

    #[async_trait]
    impl Custodian for OsKeyringCustodian {
        fn kind(&self) -> CustodianRef {
            CustodianRef::OsKeyring
        }

        async fn is_available(&self) -> bool {
            false
        }

        fn prompts_per_action(&self) -> bool {
            false
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
}

#[cfg(not(target_arch = "wasm32"))]
pub use imp::OsKeyringCustodian;
