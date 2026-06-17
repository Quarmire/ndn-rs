//! In-page custodian — holds in-process signing keys in memory. The
//! least-secure tier; only acceptable on a personal, trusted device. The
//! dashboard surfaces a banner whenever this is the active custodian on an
//! untrusted machine (Phase 5 + Phase 6).
//!
//! Holds any [`Signer`] (not just a raw `Ed25519Signer`), so a key loaded from
//! a `KeyChain` / decrypted SafeBag drops straight in.

use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use ndn_packet::Name;
use crate::{Ed25519Signer, Signer};

use crate::custodian::KeyId;
use crate::custodian::custodian::{
    Custodian, CustodianError, CustodianRef, UnlockContext, UnwrappedKey, WrappedKey,
};

#[derive(Default)]
pub struct InPageCustodian {
    keys: DashMap<KeyId, Arc<dyn Signer>>,
    unlocked: RwLock<bool>,
}

impl InPageCustodian {
    pub fn new() -> Self {
        Self {
            keys: DashMap::new(),
            unlocked: RwLock::new(true),
        }
    }

    /// Convenience for a freshly-generated Ed25519 key.
    pub fn insert(&self, key_id: KeyId, signer: Ed25519Signer) {
        self.keys.insert(key_id, Arc::new(signer));
    }

    /// Hold an arbitrary in-process signer (e.g. a `KeyChain`'s signer).
    pub fn insert_signer(&self, key_id: KeyId, signer: Arc<dyn Signer>) {
        self.keys.insert(key_id, signer);
    }

    /// The held key's public-key bytes, if the signer exposes them.
    pub fn public_key(&self, key_id: &KeyId) -> Option<Bytes> {
        self.keys.get(key_id).and_then(|s| s.public_key())
    }
}

#[async_trait]
impl Custodian for InPageCustodian {
    fn kind(&self) -> CustodianRef {
        CustodianRef::InPage
    }

    async fn is_available(&self) -> bool {
        true
    }

    fn prompts_per_action(&self) -> bool {
        false
    }

    async fn unlock(&self, _ctx: UnlockContext) -> Result<(), CustodianError> {
        *self.unlocked.write().expect("unlock RwLock poisoned") = true;
        Ok(())
    }

    async fn sign(
        &self,
        key_id: &KeyId,
        _name: &Name,
        content: &[u8],
    ) -> Result<Bytes, CustodianError> {
        // Clone the Arc out before awaiting — never hold a DashMap guard across
        // an await point.
        let signer = self
            .keys
            .get(key_id)
            .ok_or_else(|| CustodianError::UnknownKey(key_id.as_name().clone()))?
            .clone();
        signer
            .sign(content)
            .await
            .map_err(|e| CustodianError::SignFailed(e.to_string()))
    }

    async fn unwrap_for(
        &self,
        _key_id: &KeyId,
        _wrapped: &WrappedKey,
    ) -> Result<UnwrappedKey, CustodianError> {
        Err(CustodianError::UnwrapFailed("Phase 4".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Ed25519Verifier;

    fn fresh_signer(name: &str) -> (KeyId, Ed25519Signer) {
        let n: Name = name.parse().unwrap();
        let seed = [7u8; 32];
        let signer = Ed25519Signer::from_seed(&seed, n.clone());
        (KeyId(n), signer)
    }

    #[tokio::test]
    async fn sign_and_verify_roundtrip() {
        let custodian = InPageCustodian::new();
        let (key_id, signer) = fresh_signer("/test/alice/KEY/k1");
        let pk = signer.public_key_bytes();
        custodian.insert(key_id.clone(), signer);

        let name: Name = "/test/alice/doc".parse().unwrap();
        let content = b"hello world";
        let sig = custodian.sign(&key_id, &name, content).await.unwrap();
        let outcome = Ed25519Verifier.verify_sync(content, &sig, &pk);
        assert!(matches!(outcome, crate::VerifyOutcome::Valid));
    }

    #[tokio::test]
    async fn unlock_is_idempotent() {
        let custodian = InPageCustodian::new();
        custodian.unlock(UnlockContext::default()).await.unwrap();
        custodian.unlock(UnlockContext::default()).await.unwrap();
        assert!(custodian.is_available().await);
    }

    #[tokio::test]
    async fn unknown_key_errors() {
        let custodian = InPageCustodian::new();
        let key_id = KeyId("/missing/KEY/k".parse().unwrap());
        let err = custodian
            .sign(&key_id, &"/some/name".parse().unwrap(), b"x")
            .await
            .unwrap_err();
        assert!(matches!(err, CustodianError::UnknownKey(_)));
    }
}
