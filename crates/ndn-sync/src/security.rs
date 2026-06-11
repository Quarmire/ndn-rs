//! Sync-Interest authentication (gap #2): [`SyncSigner`] /
//! [`SyncValidator`] traits, an HMAC-SHA256 group-key implementation
//! ([`HmacKey`], ndn-svs `SIGNER_TYPE_HMAC`), and an [`Insecure`] no-op
//! pair (`SIGNER_TYPE_NULL`).
//!
//! Sync Interests carry their state vector in ApplicationParameters; on
//! an untrusted link an unauthenticated peer could inject false state or
//! hijack a node's sequence space. Signing closes that. The traits are
//! kept deliberately small so `ndn-security` stays out of the dependency
//! tree — the HMAC path needs only `hmac` + `sha2` (both wasm-safe), and
//! the signed-Interest encoding/verification reuses ndn-packet's
//! spec-compliant machinery (`InterestBuilder::sign_sync`,
//! `Interest::signed_region`).
//!
//! The driver ([`crate::svs_sync`]) calls [`SyncValidator::validate`]
//! *before* merge and [`SyncSigner::sign`] on every outgoing Interest.
//! Both default to [`Insecure`], so existing callers are unaffected
//! until they opt in via [`SvsConfig`](crate::SvsConfig).

use std::fmt;
use std::sync::Arc;

use bytes::Bytes;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sha2::digest::KeyInit;

use ndn_packet::encode::InterestBuilder;
use ndn_packet::{Interest, Name, SignatureType};

type HmacSha256 = Hmac<Sha256>;

/// Why an inbound Sync Interest was refused before its state vector was
/// merged.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Rejected {
    #[error("sync interest is not signed")]
    Unsigned,
    #[error("unexpected signature type (want HMAC-SHA256)")]
    WrongSigType,
    #[error("signature verification failed")]
    BadSignature,
    #[error("malformed signed interest")]
    Malformed,
}

/// Signs outgoing Sync Interests. The implementor owns the final wire
/// encoding so it can append the NDN `InterestSignatureInfo` /
/// `InterestSignatureValue` TLVs.
pub trait SyncSigner: Send + Sync + fmt::Debug {
    /// Consume a fully-populated builder (name + AppParameters) and
    /// return the signed (or, for [`Insecure`], plain) Interest wire.
    fn sign(&self, builder: InterestBuilder) -> Bytes;
}

/// Gates inbound Sync Interests before their state vector is merged.
pub trait SyncValidator: Send + Sync + fmt::Debug {
    fn validate(&self, raw: &Bytes) -> Result<(), Rejected>;
}

/// `SIGNER_TYPE_NULL`: emit the unsigned wire, accept everything. The
/// default — preserves pre-security behaviour on closed/local links.
#[derive(Debug, Default, Clone, Copy)]
pub struct Insecure;

impl SyncSigner for Insecure {
    fn sign(&self, builder: InterestBuilder) -> Bytes {
        builder.build()
    }
}

impl SyncValidator for Insecure {
    fn validate(&self, _raw: &Bytes) -> Result<(), Rejected> {
        Ok(())
    }
}

/// `SIGNER_TYPE_HMAC`: a shared symmetric group key. The same value both
/// signs outgoing and validates inbound Sync Interests — the ndn-svs
/// closed-group default. Cheap, and enough to stop state injection and
/// sequence-space hijacking from off-group parties.
#[derive(Clone)]
pub struct HmacKey {
    key: Vec<u8>,
    key_name: Name,
}

impl fmt::Debug for HmacKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HmacKey")
            .field("key_name", &self.key_name)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl HmacKey {
    /// `key_name` identifies the group key and rides in the Interest's
    /// `KeyLocator` (NDN Packet Format requires one for HMAC-SHA256).
    pub fn new(key: impl Into<Vec<u8>>, key_name: Name) -> Self {
        Self {
            key: key.into(),
            key_name,
        }
    }

    fn mac(&self, region: &[u8]) -> Bytes {
        let mut m = HmacSha256::new_from_slice(&self.key)
            .expect("HMAC accepts a key of any length");
        m.update(region);
        Bytes::copy_from_slice(&m.finalize().into_bytes())
    }
}

impl SyncSigner for HmacKey {
    fn sign(&self, builder: InterestBuilder) -> Bytes {
        builder.sign_sync(
            SignatureType::SignatureHmacWithSha256,
            Some(&self.key_name),
            |region| self.mac(region),
        )
    }
}

impl SyncValidator for HmacKey {
    fn validate(&self, raw: &Bytes) -> Result<(), Rejected> {
        let interest = Interest::decode(raw.clone()).map_err(|_| Rejected::Malformed)?;
        let info = interest.sig_info().ok_or(Rejected::Unsigned)?;
        if info.sig_type != SignatureType::SignatureHmacWithSha256 {
            return Err(Rejected::WrongSigType);
        }
        let region = interest.signed_region().ok_or(Rejected::Malformed)?;
        let sig = interest.sig_value().ok_or(Rejected::Unsigned)?;
        let mut m = HmacSha256::new_from_slice(&self.key)
            .expect("HMAC accepts a key of any length");
        m.update(&region);
        // `verify_slice` is constant-time.
        m.verify_slice(sig.as_ref()).map_err(|_| Rejected::BadSignature)
    }
}

/// Default signer — [`Insecure`].
pub fn default_signer() -> Arc<dyn SyncSigner> {
    Arc::new(Insecure)
}

/// Default validator — [`Insecure`] (accept-all).
pub fn default_validator() -> Arc<dyn SyncValidator> {
    Arc::new(Insecure)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_packet::Name;
    use std::time::Duration;

    fn builder() -> InterestBuilder {
        InterestBuilder::new("/ndn/svs".parse::<Name>().unwrap().append_version(2))
            .lifetime(Duration::from_millis(1000))
            .app_parameters(vec![0xC9, 0x00])
    }

    fn key(name: &str, bytes: &[u8]) -> HmacKey {
        HmacKey::new(bytes.to_vec(), name.parse::<Name>().unwrap())
    }

    #[test]
    fn hmac_sign_then_validate_roundtrips() {
        let k = key("/keys/group", b"super-secret-group-key");
        let wire = k.sign(builder());
        assert!(k.validate(&wire).is_ok(), "self-signed must validate");
    }

    #[test]
    fn hmac_rejects_wrong_key() {
        let signer = key("/keys/group", b"key-A");
        let other = key("/keys/group", b"key-B");
        let wire = signer.sign(builder());
        assert_eq!(other.validate(&wire), Err(Rejected::BadSignature));
    }

    #[test]
    fn hmac_rejects_unsigned() {
        let k = key("/keys/group", b"key");
        let unsigned = builder().build();
        assert_eq!(k.validate(&unsigned), Err(Rejected::Unsigned));
    }

    #[test]
    fn hmac_rejects_tampered_state_vector() {
        let k = key("/keys/group", b"key");
        let wire = k.sign(builder());
        // Flip a byte in the AppParameters region (the state vector).
        let mut bad = wire.to_vec();
        let n = bad.len();
        bad[n - 1] ^= 0xFF;
        let bad = Bytes::from(bad);
        // Either the MAC fails or the packet no longer decodes — both
        // are rejections, never a silent accept.
        assert!(k.validate(&bad).is_err());
    }

    #[test]
    fn insecure_accepts_anything() {
        let wire = builder().build();
        assert!(Insecure.validate(&wire).is_ok());
        assert!(Insecure.validate(&Bytes::from_static(b"garbage")).is_ok());
    }
}
