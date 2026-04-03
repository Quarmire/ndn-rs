use crate::TrustError;
use dashmap::DashMap;
use ndn_packet::{Data, Name};
use std::sync::Arc;

/// A decoded NDN certificate (a signed Data packet with a public key payload).
#[derive(Clone, Debug)]
pub struct Certificate {
    pub name: Arc<Name>,
    pub public_key: bytes::Bytes,
    pub valid_from: u64,
    pub valid_until: u64,
}

impl Certificate {
    pub fn decode(_data: &Data) -> Result<Self, TrustError> {
        // Placeholder — full certificate TLV decoding to be implemented.
        Err(TrustError::InvalidKey)
    }
}

/// In-memory certificate cache.
///
/// Certificates are just named Data packets — fetching one is a normal NDN
/// Interest. The cache avoids re-fetching recently validated certificates.
pub struct CertCache {
    local: DashMap<Arc<Name>, Certificate>,
}

impl CertCache {
    pub fn new() -> Self {
        Self {
            local: DashMap::new(),
        }
    }

    pub fn get(&self, key_name: &Arc<Name>) -> Option<Certificate> {
        self.local.get(key_name).map(|r| r.clone())
    }

    pub fn insert(&self, cert: Certificate) {
        self.local.insert(Arc::clone(&cert.name), cert);
    }
}

impl Default for CertCache {
    fn default() -> Self {
        Self::new()
    }
}
