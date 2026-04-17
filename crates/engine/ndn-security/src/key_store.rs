use crate::{Signer, TrustError};
use dashmap::DashMap;
use ndn_packet::Name;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAlgorithm {
    Ed25519,
    EcdsaP256,
    Rsa2048,
}

pub trait KeyStore: Send + Sync + 'static {
    fn get_signer(
        &self,
        key_name: &Name,
    ) -> impl std::future::Future<Output = Result<Arc<dyn Signer>, TrustError>> + Send;

    fn generate_key(
        &self,
        name: Name,
        algo: KeyAlgorithm,
    ) -> impl std::future::Future<Output = Result<Name, TrustError>> + Send;

    fn delete_key(
        &self,
        key_name: &Name,
    ) -> impl std::future::Future<Output = Result<(), TrustError>> + Send;
}

pub struct MemKeyStore {
    keys: DashMap<Arc<Name>, Arc<dyn Signer>>,
}

impl MemKeyStore {
    pub fn new() -> Self {
        Self {
            keys: DashMap::new(),
        }
    }

    pub fn get_signer_sync(&self, key_name: &Name) -> Result<Arc<dyn Signer>, TrustError> {
        self.keys
            .iter()
            .find(|r| r.key().as_ref() == key_name)
            .map(|r| Arc::clone(r.value()))
            .ok_or_else(|| TrustError::CertNotFound {
                name: key_name.to_string(),
            })
    }

    pub fn add<S: Signer>(&self, key_name: Arc<Name>, signer: S) {
        self.keys.insert(key_name, Arc::new(signer));
    }
}

impl Default for MemKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyStore for MemKeyStore {
    async fn get_signer(&self, key_name: &Name) -> Result<Arc<dyn Signer>, TrustError> {
        self.keys
            .iter()
            .find(|r| r.key().as_ref() == key_name)
            .map(|r| Arc::clone(r.value()))
            .ok_or_else(|| TrustError::CertNotFound {
                name: key_name.to_string(),
            })
    }

    async fn generate_key(&self, _name: Name, _algo: KeyAlgorithm) -> Result<Name, TrustError> {
        Err(TrustError::KeyStore(
            "MemKeyStore does not support key generation".into(),
        ))
    }

    async fn delete_key(&self, key_name: &Name) -> Result<(), TrustError> {
        let key = self
            .keys
            .iter()
            .find(|r| r.key().as_ref() == key_name)
            .map(|r| Arc::clone(r.key()));
        if let Some(k) = key {
            self.keys.remove(&k);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::Ed25519Signer;
    use bytes::Bytes;
    use ndn_packet::NameComponent;

    fn key_name(s: &'static str) -> Arc<Name> {
        Arc::new(Name::from_components([NameComponent::generic(
            Bytes::from_static(s.as_bytes()),
        )]))
    }

    #[tokio::test]
    async fn add_and_get_signer() {
        let store = MemKeyStore::new();
        let kn = key_name("mykey");
        let signer = Ed25519Signer::from_seed(&[1u8; 32], (*kn).clone());
        store.add(Arc::clone(&kn), signer);
        let retrieved = store.get_signer(&kn).await.unwrap();
        assert_eq!(retrieved.key_name(), &*kn);
    }

    #[tokio::test]
    async fn get_missing_key_returns_err() {
        let store = MemKeyStore::new();
        let kn = key_name("missing");
        assert!(matches!(
            store.get_signer(&kn).await,
            Err(TrustError::CertNotFound { .. })
        ));
    }

    #[tokio::test]
    async fn delete_key_removes_it() {
        let store = MemKeyStore::new();
        let kn = key_name("delkey");
        let signer = Ed25519Signer::from_seed(&[2u8; 32], (*kn).clone());
        store.add(Arc::clone(&kn), signer);
        store.delete_key(&kn).await.unwrap();
        assert!(matches!(
            store.get_signer(&kn).await,
            Err(TrustError::CertNotFound { .. })
        ));
    }

    #[tokio::test]
    async fn generate_key_returns_err() {
        let store = MemKeyStore::new();
        let result = store
            .generate_key((*key_name("k")).clone(), KeyAlgorithm::Ed25519)
            .await;
        assert!(result.is_err());
    }
}
