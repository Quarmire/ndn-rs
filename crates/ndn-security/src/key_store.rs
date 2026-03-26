use std::sync::Arc;
use dashmap::DashMap;
use ndn_packet::Name;
use crate::{Signer, TrustError};

/// Supported key algorithms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAlgorithm {
    Ed25519,
    EcdsaP256,
    Rsa2048,
}

/// Persistent key storage.
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

/// In-memory key store for testing.
pub struct MemKeyStore {
    keys: DashMap<Arc<Name>, Arc<dyn Signer>>,
}

impl MemKeyStore {
    pub fn new() -> Self {
        Self { keys: DashMap::new() }
    }

    pub fn add<S: Signer>(&self, key_name: Arc<Name>, signer: S) {
        self.keys.insert(key_name, Arc::new(signer));
    }
}

impl Default for MemKeyStore {
    fn default() -> Self { Self::new() }
}

impl KeyStore for MemKeyStore {
    async fn get_signer(&self, key_name: &Name) -> Result<Arc<dyn Signer>, TrustError> {
        self.keys
            .iter()
            .find(|r| r.key().as_ref() == key_name)
            .map(|r| Arc::clone(r.value()))
            .ok_or_else(|| TrustError::CertNotFound { name: key_name.to_string() })
    }

    async fn generate_key(&self, _name: Name, _algo: KeyAlgorithm) -> Result<Name, TrustError> {
        Err(TrustError::KeyStore("MemKeyStore does not support key generation".into()))
    }

    async fn delete_key(&self, key_name: &Name) -> Result<(), TrustError> {
        let key = self.keys
            .iter()
            .find(|r| r.key().as_ref() == key_name)
            .map(|r| Arc::clone(r.key()));
        if let Some(k) = key {
            self.keys.remove(&k);
        }
        Ok(())
    }
}
