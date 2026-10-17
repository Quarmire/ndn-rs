//! YubiKey PIV hardware-backed signers (feature: `yubikey-piv`).
//!
//! Private keys live in YubiKey PIV slots and never leave the hardware. All
//! signing operations are performed on-device via PC/SC. Requires `pcscd`
//! running and a YubiKey connected via USB or NFC.
//!
//! [`YubikeyPiv`] is a factory: it produces an `Arc<dyn Signer>` for a slot,
//! which the caller registers with
//! [`SecurityManager::register_signer`](crate::SecurityManager::register_signer)
//! or signs with directly. A signer made with
//! [`YubikeyPiv::signer_with`] reports its public key and verifies the PIN
//! immediately before each signature, so it works with a slot whose PIN
//! policy is `always`. Device I/O runs on tokio's blocking pool when a tokio
//! runtime is current and inline otherwise, so the signer also works under
//! `futures::executor::block_on` and in programs without a runtime.
//!
//! PIV keys here are ECDSA P-256; the YubiKey generates them (they cannot be
//! exported) and this module does not import keys.
//!
//! ## PIV slot recommendations
//!
//! | Slot | Constant              | Recommended use in NDN              |
//! |------|-----------------------|-------------------------------------|
//! | 9a   | `Authentication`      | Router/node identity key (default)  |
//! | 9c   | `Signature`           | Namespace root / sub-CA signing key |
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

use std::str::FromStr;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use ndn_packet::{Name, SignatureType};
use yubikey::{
    MgmKey, PinPolicy, TouchPolicy, YubiKey,
    piv::{self, AlgorithmId, SlotId},
};
use zeroize::Zeroizing;

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

impl YubikeySlot {
    /// The PIV slot id as written by `ykman` (`9a`, `9c`, `9d`, `9e`).
    pub fn as_str(self) -> &'static str {
        match self {
            YubikeySlot::Authentication => "9a",
            YubikeySlot::Signature => "9c",
            YubikeySlot::KeyManagement => "9d",
            YubikeySlot::CardAuthentication => "9e",
        }
    }
}

impl FromStr for YubikeySlot {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "9a" => Ok(YubikeySlot::Authentication),
            "9c" => Ok(YubikeySlot::Signature),
            "9d" => Ok(YubikeySlot::KeyManagement),
            "9e" => Ok(YubikeySlot::CardAuthentication),
            _ => Err(format!("unknown PIV slot {s:?} (one of 9a, 9c, 9d, 9e)")),
        }
    }
}

/// When the token asks for the PIN before using a generated key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum YubikeyPinPolicy {
    /// Once per session (until the token is unplugged or reselected).
    Once,
    /// Before every signature.
    Always,
}

impl YubikeyPinPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            YubikeyPinPolicy::Once => "once",
            YubikeyPinPolicy::Always => "always",
        }
    }
}

impl FromStr for YubikeyPinPolicy {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "once" => Ok(YubikeyPinPolicy::Once),
            "always" => Ok(YubikeyPinPolicy::Always),
            _ => Err(format!("unknown PIN policy {s:?} (once, always)")),
        }
    }
}

impl From<YubikeyPinPolicy> for PinPolicy {
    fn from(p: YubikeyPinPolicy) -> Self {
        match p {
            YubikeyPinPolicy::Once => PinPolicy::Once,
            YubikeyPinPolicy::Always => PinPolicy::Always,
        }
    }
}

/// Whether the token wants a physical touch for each use of a generated key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum YubikeyTouchPolicy {
    Never,
    /// A touch for every signature.
    Always,
    /// A touch, then 15 s of signatures without one.
    Cached,
}

impl YubikeyTouchPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            YubikeyTouchPolicy::Never => "never",
            YubikeyTouchPolicy::Always => "always",
            YubikeyTouchPolicy::Cached => "cached",
        }
    }
}

impl FromStr for YubikeyTouchPolicy {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "never" => Ok(YubikeyTouchPolicy::Never),
            "always" => Ok(YubikeyTouchPolicy::Always),
            "cached" => Ok(YubikeyTouchPolicy::Cached),
            _ => Err(format!("unknown touch policy {s:?} (never, always, cached)")),
        }
    }
}

impl From<YubikeyTouchPolicy> for TouchPolicy {
    fn from(p: YubikeyTouchPolicy) -> Self {
        match p {
            YubikeyTouchPolicy::Never => TouchPolicy::Never,
            YubikeyTouchPolicy::Always => TouchPolicy::Always,
            YubikeyTouchPolicy::Cached => TouchPolicy::Cached,
        }
    }
}

type SharedKey = Arc<Mutex<YubiKey>>;

/// Run `f` on the token: on tokio's blocking pool when a runtime is current
/// (PC/SC I/O blocks, possibly for a touch), inline otherwise.
async fn on_device<T, F>(yk: SharedKey, f: F) -> Result<T, TrustError>
where
    T: Send + 'static,
    F: FnOnce(&mut YubiKey) -> Result<T, TrustError> + Send + 'static,
{
    let run = move || {
        let mut guard = yk
            .lock()
            .map_err(|_| TrustError::KeyStore("YubiKey mutex poisoned".into()))?;
        f(&mut guard)
    };
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => handle
            .spawn_blocking(run)
            .await
            .map_err(|e| TrustError::KeyStore(format!("YubiKey I/O task failed: {e}")))?,
        Err(_) => run(),
    }
}

/// Verify `pin`; a wrong one says how many tries are left.
fn verify_pin_on(yk: &mut YubiKey, pin: &[u8]) -> Result<(), TrustError> {
    yk.verify_pin(pin).map_err(|e| match e {
        yubikey::Error::WrongPin { tries } => TrustError::KeyStore(format!(
            "wrong YubiKey PIN ({tries} tries left before the PIN locks)"
        )),
        yubikey::Error::PinLocked => TrustError::KeyStore(
            "the YubiKey PIN is locked; unblock it with the PUK (`ykman piv access unblock-pin`)"
                .into(),
        ),
        e => TrustError::KeyStore(format!("YubiKey PIN verification failed: {e}")),
    })
}

/// SPKI DER of a P-256 public key from the uncompressed SEC1 point.
fn p256_spki(point: &[u8]) -> Bytes {
    Bytes::from(crate::signer::p256_spki_wrap(point))
}

/// Handle to a connected YubiKey that produces PIV slot signers.
///
/// Thread-safe: the `YubiKey` handle is accessed via a `Mutex`, and device
/// I/O runs off the async executor (see the module docs). Signers share this
/// handle.
pub struct YubikeyPiv {
    yk: SharedKey,
    serial: u32,
}

impl YubikeyPiv {
    /// The single connected YubiKey.
    pub fn open() -> Result<Self, TrustError> {
        let yk =
            YubiKey::open().map_err(|e| TrustError::KeyStore(format!("YubiKey not found: {e}")))?;
        Ok(Self::from_device(yk))
    }

    /// The connected YubiKey with serial number `serial`.
    pub fn open_by_serial(serial: u32) -> Result<Self, TrustError> {
        let yk = YubiKey::open_by_serial(yubikey::Serial(serial)).map_err(|e| {
            TrustError::KeyStore(format!("YubiKey with serial {serial} not found: {e}"))
        })?;
        Ok(Self::from_device(yk))
    }

    fn from_device(yk: YubiKey) -> Self {
        let serial = yk.serial().0;
        Self {
            yk: Arc::new(Mutex::new(yk)),
            serial,
        }
    }

    /// The token's serial number.
    pub fn serial(&self) -> u32 {
        self.serial
    }

    /// Verify the PIV PIN.
    pub async fn verify_pin(&self, pin: &[u8]) -> Result<(), TrustError> {
        let pin = Zeroizing::new(pin.to_vec());
        on_device(Arc::clone(&self.yk), move |yk| verify_pin_on(yk, &pin)).await
    }

    /// The SPKI DER public key of the P-256 key held in `slot`, read from the
    /// slot's metadata (YubiKey firmware 5.3 or later).
    pub async fn slot_public_key(&self, slot: YubikeySlot) -> Result<Bytes, TrustError> {
        let slot_id = SlotId::from(slot);
        on_device(Arc::clone(&self.yk), move |yk| {
            let meta = piv::metadata(yk, slot_id).map_err(|e| {
                TrustError::KeyStore(format!(
                    "cannot read slot {} of the YubiKey (firmware 5.3 or later reports a slot's \
                     key): {e}",
                    slot.as_str()
                ))
            })?;
            let spki = meta.public.ok_or_else(|| {
                TrustError::KeyStore(format!("slot {} of the YubiKey holds no key", slot.as_str()))
            })?;
            Ok(p256_spki(spki.subject_public_key.raw_bytes()))
        })
        .await
    }

    /// Signer for the P-256 key already held in `slot`, named `key_name`
    /// (does not communicate with the device). It reports no public key and
    /// verifies no PIN; see [`signer_with`](Self::signer_with).
    pub fn signer(&self, key_name: Name, slot: YubikeySlot) -> Arc<dyn Signer> {
        Arc::new(YubikeySigner {
            yk: Arc::clone(&self.yk),
            key_name,
            slot,
            public_key: None,
            pin: None,
        })
    }

    /// Signer for the P-256 key held in `slot` whose SPKI DER public key is
    /// `public_key`, named `key_name`. With `pin`, the PIN is verified right
    /// before each signature (a slot with PIN policy `always` needs that).
    pub fn signer_with(
        &self,
        key_name: Name,
        slot: YubikeySlot,
        public_key: Bytes,
        pin: Option<Zeroizing<Vec<u8>>>,
    ) -> Arc<dyn Signer> {
        Arc::new(YubikeySigner {
            yk: Arc::clone(&self.yk),
            key_name,
            slot,
            public_key: Some(public_key),
            pin,
        })
    }

    /// Generate a new P-256 key in `slot` and return its signer (named
    /// `key_name`) plus the raw uncompressed EC public key bytes (65 bytes:
    /// `0x04 || X || Y`), with the slot's default PIN and touch policies.
    ///
    /// Generating needs the PIV management key; the factory default is used.
    pub async fn generate(
        &self,
        key_name: Name,
        slot: YubikeySlot,
    ) -> Result<(Arc<dyn Signer>, Bytes), TrustError> {
        let point = self
            .generate_on_device(slot, PinPolicy::Default, TouchPolicy::Default, None)
            .await?;
        Ok((self.signer(key_name, slot), point))
    }

    /// Generate a new P-256 key in `slot` with explicit PIN and touch
    /// policies, after verifying `pin`, with the factory-default management
    /// key. Returns a
    /// [`signer_with`](Self::signer_with) signer holding `pin` and the
    /// key's SPKI DER public key. Replaces whatever key `slot` held.
    pub async fn generate_with_policy(
        &self,
        key_name: Name,
        slot: YubikeySlot,
        pin_policy: YubikeyPinPolicy,
        touch_policy: YubikeyTouchPolicy,
        pin: Zeroizing<Vec<u8>>,
    ) -> Result<(Arc<dyn Signer>, Bytes), TrustError> {
        let point = self
            .generate_on_device(
                slot,
                pin_policy.into(),
                touch_policy.into(),
                Some(pin.clone()),
            )
            .await?;
        let spki = p256_spki(&point);
        Ok((self.signer_with(key_name, slot, spki.clone(), Some(pin)), spki))
    }

    async fn generate_on_device(
        &self,
        slot: YubikeySlot,
        pin_policy: PinPolicy,
        touch_policy: TouchPolicy,
        pin: Option<Zeroizing<Vec<u8>>>,
    ) -> Result<Bytes, TrustError> {
        let slot_id = SlotId::from(slot);
        on_device(Arc::clone(&self.yk), move |yk| {
            if let Some(pin) = &pin {
                verify_pin_on(yk, pin)?;
            }
            yk.authenticate(MgmKey::default()).map_err(|e| {
                TrustError::KeyStore(format!(
                    "the YubiKey's PIV management key is not the factory default ({e}); \
                     generating a key here needs the factory management key (yubikey 0.8 reads \
                     a PIN-protected one only behind its `untested` feature)"
                ))
            })?;
            let spki = piv::generate(yk, slot_id, AlgorithmId::EccP256, pin_policy, touch_policy)
                .map_err(|e| TrustError::KeyStore(format!("YubiKey generate failed: {e}")))?;
            Ok(Bytes::copy_from_slice(spki.subject_public_key.raw_bytes()))
        })
        .await
    }
}

/// A [`Signer`] backed by a specific PIV slot on a YubiKey.
struct YubikeySigner {
    yk: SharedKey,
    key_name: Name,
    slot: YubikeySlot,
    public_key: Option<Bytes>,
    pin: Option<Zeroizing<Vec<u8>>>,
}

impl Signer for YubikeySigner {
    fn sig_type(&self) -> SignatureType {
        SignatureType::SignatureSha256WithEcdsa
    }

    fn key_name(&self) -> &Name {
        &self.key_name
    }

    fn public_key(&self) -> Option<Bytes> {
        self.public_key.clone()
    }

    fn sign<'a>(
        &'a self,
        region: &'a [u8],
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<Bytes, TrustError>> + Send + 'a>> {
        let digest = {
            use sha2::Digest;
            sha2::Sha256::digest(region).to_vec()
        };
        let slot_id = SlotId::from(self.slot);
        let pin = self.pin.clone();
        let yk = Arc::clone(&self.yk);
        Box::pin(async move {
            on_device(yk, move |yk| {
                if let Some(pin) = &pin {
                    verify_pin_on(yk, pin)?;
                }
                piv::sign_data(yk, &digest, AlgorithmId::EccP256, slot_id)
                    .map(|buf| Bytes::copy_from_slice(&buf))
                    .map_err(|e| TrustError::KeyStore(format!("YubiKey sign failed: {e}")))
            })
            .await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_and_policy_names_round_trip() {
        for slot in [
            YubikeySlot::Authentication,
            YubikeySlot::Signature,
            YubikeySlot::KeyManagement,
            YubikeySlot::CardAuthentication,
        ] {
            assert_eq!(slot.as_str().parse::<YubikeySlot>(), Ok(slot));
        }
        for p in [YubikeyPinPolicy::Once, YubikeyPinPolicy::Always] {
            assert_eq!(p.as_str().parse::<YubikeyPinPolicy>(), Ok(p));
        }
        for t in [
            YubikeyTouchPolicy::Never,
            YubikeyTouchPolicy::Always,
            YubikeyTouchPolicy::Cached,
        ] {
            assert_eq!(t.as_str().parse::<YubikeyTouchPolicy>(), Ok(t));
        }
        assert!("9f".parse::<YubikeySlot>().is_err());
    }

    /// The SPKI wrapper produces what an in-memory P-256 signer reports, so
    /// a token key and its certificate carry the same public key bytes.
    #[test]
    fn p256_spki_matches_software_signer() {
        let sw = crate::EcdsaP256Signer::from_seed(&[7u8; 32], "/k".parse().unwrap()).unwrap();
        let spki = sw.public_key().unwrap();
        // The uncompressed point is the SPKI's last 65 bytes.
        assert_eq!(p256_spki(&spki[spki.len() - 65..]), spki);
    }
}
