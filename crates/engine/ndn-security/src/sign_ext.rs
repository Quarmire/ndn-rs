//! [`SignWith`] — extension trait for ergonomic packet signing with a [`Signer`].

use std::cell::RefCell;

use bytes::Bytes;
use ndn_packet::encode::{DataBuilder, InterestBuilder};

use crate::{Signer, TrustError};

/// Extension trait that adds a high-level `sign_with` method to packet builders.
///
/// Extracts the signature algorithm and key locator from the signer automatically,
/// eliminating the need to pass them explicitly.
///
/// # Example
///
/// ```rust,no_run
/// use ndn_packet::encode::DataBuilder;
/// use ndn_security::{KeyChain, SignWith};
///
/// # fn example() -> Result<(), ndn_security::TrustError> {
/// let kc = KeyChain::ephemeral("/com/example/alice")?;
/// let signer = kc.signer()?;
///
/// let wire = DataBuilder::new("/com/example/alice/data", b"hello")
///     .sign_with_sync(&*signer)?;
/// # Ok(())
/// # }
/// ```
pub trait SignWith: Sized {
    /// Sign this packet using the given signer (synchronous).
    ///
    /// The signature algorithm and key locator name are taken from `signer`.
    /// Use this for Ed25519 and HMAC-SHA256 signers, which are always
    /// CPU-bound and have fast synchronous paths.
    fn sign_with_sync(self, signer: &dyn Signer) -> Result<Bytes, TrustError>;
}

impl SignWith for DataBuilder {
    fn sign_with_sync(self, signer: &dyn Signer) -> Result<Bytes, TrustError> {
        let sig_type = signer.sig_type();
        let key_name = signer.key_name().clone();
        let captured_err: RefCell<Option<TrustError>> = RefCell::new(None);
        let wire = self.sign_sync(sig_type, Some(&key_name), |region| {
            match signer.sign_sync(region) {
                Ok(sig) => sig,
                Err(e) => {
                    *captured_err.borrow_mut() = Some(e);
                    Bytes::new()
                }
            }
        });
        if let Some(e) = captured_err.into_inner() {
            Err(e)
        } else {
            Ok(wire)
        }
    }
}

impl SignWith for InterestBuilder {
    fn sign_with_sync(self, signer: &dyn Signer) -> Result<Bytes, TrustError> {
        let sig_type = signer.sig_type();
        let key_name = signer.key_name().clone();
        let captured_err: RefCell<Option<TrustError>> = RefCell::new(None);
        let wire = self.sign_sync(sig_type, Some(&key_name), |region| {
            match signer.sign_sync(region) {
                Ok(sig) => sig,
                Err(e) => {
                    *captured_err.borrow_mut() = Some(e);
                    Bytes::new()
                }
            }
        });
        if let Some(e) = captured_err.into_inner() {
            Err(e)
        } else {
            Ok(wire)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KeyChain, signer::Ed25519Signer};
    use ndn_packet::encode::DataBuilder;

    #[test]
    fn data_sign_with_sync_roundtrip() {
        let kc = KeyChain::ephemeral("/test/producer").unwrap();
        let signer = kc.signer().unwrap();

        let wire = DataBuilder::new("/test/producer/data", b"payload")
            .sign_with_sync(&*signer)
            .unwrap();

        let data = ndn_packet::Data::decode(wire).unwrap();
        assert_eq!(data.name.to_string(), "/test/producer/data");

        let si = data.sig_info().unwrap();
        let kl = si.key_locator.as_ref().unwrap();
        assert_eq!(kl.to_string(), signer.key_name().to_string());
    }

    #[test]
    fn interest_sign_with_sync_roundtrip() {
        let seed = [42u8; 32];
        let key_name: ndn_packet::Name = "/test/key".parse().unwrap();
        let signer = Ed25519Signer::from_seed(&seed, key_name);

        let wire = InterestBuilder::new("/test/prefix")
            .sign_with_sync(&signer)
            .unwrap();

        let _interest = ndn_packet::Interest::decode(wire).unwrap();
    }
}
