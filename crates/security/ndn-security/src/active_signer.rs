//! The key a node signs its own packets with *now*, when that key can change
//! while the node runs (an enrollment gives it a certified key).
//!
//! Holders keep one shared [`ActiveSigner`]. Every signing site takes one
//! [`current`](ActiveSigner::current) snapshot per packet and uses that
//! snapshot for both the KeyLocator and the signature, so a packet never
//! pairs one key's name with another key's signature, however often the key
//! is [`replace`](ActiveSigner::replace)d. Taking a snapshot is an atomic
//! load; a replaced signer is dropped once no packet still holds it.

use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::Signer;

pub struct ActiveSigner {
    current: ArcSwap<Arc<dyn Signer>>,
}

impl ActiveSigner {
    pub fn new(signer: Arc<dyn Signer>) -> Self {
        Self {
            current: ArcSwap::from_pointee(signer),
        }
    }

    /// The signer to sign one packet with: its key name is that packet's
    /// KeyLocator.
    pub fn current(&self) -> Arc<dyn Signer> {
        (**self.current.load()).clone()
    }

    /// Sign with `signer` from now on. Packets already being signed finish
    /// with the snapshot they took.
    pub fn replace(&self, signer: Arc<dyn Signer>) {
        self.current.store(Arc::new(signer));
    }
}

impl std::fmt::Debug for ActiveSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActiveSigner")
            .field("key", self.current().key_name())
            .finish()
    }
}
