//! YubiKey PIV hardware-backed signers (feature: `yubikey-piv`).
//!
//! Private keys live in YubiKey PIV slots and never leave the hardware. All
//! signing operations are performed on-device via PC/SC. Requires `pcscd`
//! running and a YubiKey connected via USB or NFC.
//!
//! [`YubikeyPiv`] is a factory: it produces an `Arc<dyn Signer>` for a slot,
//! which the caller registers with
//! [`SecurityManager::register_signer`](crate::SecurityManager::register_signer).
//!
//! ## PIV slot recommendations
//!
//! | Slot | Constant              | Recommended use in NDN              |
//! |------|-----------------------|-------------------------------------|
//! | 9a   | `Authentication`      | Router/node identity key (default)  |
//! | 9c   | `Signature`           | Sub-CA certificate signing key      |
//! | 9d   | `KeyManagement`       | Key agreement / ECDH                |
//! | 9e   | `CardAuthentication`  | Short-lived / service keys          |
//!
//! ## Headless bootstrapping flow
//!
//! ```text
//! 1. Admin generates P-256 key in slot 9a via dashboard
//!    → YubiKey stores key, returns public key bytes
//! 2. NDN NDNCERT enrollment uses the YubiKey signer for the NEW Interest
//!    → Signed Interest proves key ownership without exposing the private key
//! 3. CA issues NDN identity certificate bound to the P-256 public key
//! 4. Router signs all subsequent packets on-device (button touch optional)
//! ```

use std::sync::Arc;

use bytes::Bytes;
use ndn_packet::{Name, SignatureType};
use yubikey::{
    PinPolicy, TouchPolicy, YubiKey,
    piv::{self, AlgorithmId, SlotId},
};

use crate::{Signer, TrustError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum YubikeySlot {
    Authentication,
    Signature,
    KeyManagement,
    CardAuthentication,
}

impl From<YubikeySlot> for SlotId {
    fn from(slot: YubikeySlot) -> Self {
        match slot {
            YubikeySlot::Authentication => SlotId::Authentication,
            YubikeySlot::Signature => SlotId::Signature,
            YubikeySlot::KeyManagement => SlotId::KeyManagement,
            YubikeySlot::CardAuthentication => SlotId::CardAuthentication,
        }
    }
}

/// Handle to a connected YubiKey that produces PIV slot signers.
///
/// Thread-safe: the `YubiKey` handle is accessed via a `Mutex` and device
/// I/O is dispatched to `tokio::task::spawn_blocking` to avoid blocking the
/// async executor during PC/SC I/O. Signers share this handle.
pub struct YubikeyPiv {
    yk: Arc<std::sync::Mutex<YubiKey>>,
}

impl YubikeyPiv {
    pub fn open() -> Result<Self, TrustError> {
        let yk =
            YubiKey::open().map_err(|e| TrustError::KeyStore(format!("YubiKey not found: {e}")))?;
        Ok(Self {
            yk: Arc::new(std::sync::Mutex::new(yk)),
        })
    }

    /// Signer for the P-256 key already held in `slot`, named `key_name`
    /// (does not communicate with the device).
    pub fn signer(&self, key_name: Name, slot: YubikeySlot) -> Arc<dyn Signer> {
        Arc::new(YubikeySigner {
            yk: Arc::clone(&self.yk),
            key_name,
            slot,
        })
    }

    /// Generate a new P-256 key in `slot` and return its signer (named
    /// `key_name`) plus the raw uncompressed EC public key bytes (65 bytes:
    /// `0x04 || X || Y`).
    ///
    /// The management key must be authenticated; if the YubiKey still has its factory
    /// default management key it is used automatically.
    pub async fn generate(
        &self,
        key_name: Name,
        slot: YubikeySlot,
    ) -> Result<(Arc<dyn Signer>, Bytes), TrustError> {
        let yk = Arc::clone(&self.yk);
        let slot_id = SlotId::from(slot);

        let pub_bytes: Vec<u8> =
            tokio::task::spawn_blocking(move || -> Result<Vec<u8>, TrustError> {
                let mut guard = yk
                    .lock()
                    .map_err(|_| TrustError::KeyStore("YubiKey mutex poisoned".into()))?;
                let spki = piv::generate(
                    &mut guard,
                    slot_id,
                    AlgorithmId::EccP256,
                    PinPolicy::Default,
                    TouchPolicy::Default,
                )
                .map_err(|e| TrustError::KeyStore(format!("YubiKey generate failed: {e}")))?;

                Ok(spki.subject_public_key.raw_bytes().to_vec())
            })
            .await
            .map_err(|e| TrustError::KeyStore(format!("spawn_blocking join error: {e}")))??;

        Ok((self.signer(key_name, slot), Bytes::from(pub_bytes)))
    }
}

/// A [`Signer`] backed by a specific PIV slot on a YubiKey.
///
/// Signing dispatches to `spawn_blocking` to avoid blocking the async executor
/// during PC/SC hardware I/O.
struct YubikeySigner {
    yk: Arc<std::sync::Mutex<YubiKey>>,
    key_name: Name,
    slot: YubikeySlot,
}

impl Signer for YubikeySigner {
    fn sig_type(&self) -> SignatureType {
        SignatureType::SignatureSha256WithEcdsa
    }

    fn key_name(&self) -> &Name {
        &self.key_name
    }

    fn sign<'a>(
        &'a self,
        region: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Bytes, TrustError>> + Send + 'a>>
    {
        let digest = {
            use sha2::Digest;
            sha2::Sha256::digest(region).to_vec()
        };

        let yk = Arc::clone(&self.yk);
        let slot_id = SlotId::from(self.slot);

        Box::pin(async move {
            let sig_bytes: Vec<u8> =
                tokio::task::spawn_blocking(move || -> Result<Vec<u8>, TrustError> {
                    let mut guard = yk
                        .lock()
                        .map_err(|_| TrustError::KeyStore("YubiKey mutex poisoned".into()))?;
                    piv::sign_data(&mut guard, &digest, AlgorithmId::EccP256, slot_id)
                        .map(|buf| buf.to_vec())
                        .map_err(|e| TrustError::KeyStore(format!("YubiKey sign failed: {e}")))
                })
                .await
                .map_err(|e| TrustError::KeyStore(format!("spawn_blocking join error: {e}")))??;

            Ok(Bytes::from(sig_bytes))
        })
    }
}
