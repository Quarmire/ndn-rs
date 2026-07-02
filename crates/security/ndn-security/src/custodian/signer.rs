//! [`CustodianSigner`] — adapts a [`Custodian`] into an `crate::Signer`,
//! so a custodian can sign anywhere a `Signer` is expected (mgmt command
//! Interests, Data). This is the seam that "routes signing through a custodian":
//! `MgmtClient::with_signer(Arc::new(CustodianSigner::new(...)))` and every
//! command Interest is signed by the custodian.
//!
//! The [`Custodian`] trait only exposes `sign(key_id, name, content)`, so the
//! signing metadata NDN needs *before* it can build the signed region —
//! `sig_type`, key name, public key — is captured at construction. The async
//! `Signer::sign` maps straight onto the async `Custodian::sign` (no blocking),
//! so a remote Fob/extension custodian works here too.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::{Signer, TrustError};
use bytes::Bytes;
use ndn_packet::{Name, SignatureType};

use crate::custodian::{Custodian, KeyId};

/// A [`Signer`] backed by a [`Custodian`] holding `key_id`.
pub struct CustodianSigner {
    custodian: Arc<dyn Custodian>,
    key_id: KeyId,
    sig_type: SignatureType,
    public_key: Option<Bytes>,
    /// Certificate name to advertise in the `KeyLocator` of signed
    /// Interests/Data. NDN validators key trust anchors by *certificate*
    /// name, so a signed command whose KeyLocator names only the bare key
    /// can't be resolved to a self-signed anchor — set this to the operator
    /// cert's full name when known.
    cert_name: Option<Name>,
}

impl CustodianSigner {
    /// `sig_type` / `public_key` describe the key behind `key_id` in
    /// `custodian` (the trait doesn't expose them). For an in-page Ed25519 key
    /// that is `SignatureEd25519` + the 32-byte verifying key.
    pub fn new(
        custodian: Arc<dyn Custodian>,
        key_id: KeyId,
        sig_type: SignatureType,
        public_key: Option<Bytes>,
    ) -> Self {
        Self {
            custodian,
            key_id,
            sig_type,
            public_key,
            cert_name: None,
        }
    }

    /// Advertise `cert_name` in the `KeyLocator` of signed Interests/Data.
    /// Without it, the KeyLocator falls back to the bare key name, which a
    /// validator can't resolve to a certificate-keyed trust anchor.
    pub fn with_cert_name(mut self, cert_name: Name) -> Self {
        self.cert_name = Some(cert_name);
        self
    }
}

impl Signer for CustodianSigner {
    fn sig_type(&self) -> SignatureType {
        self.sig_type
    }

    fn key_name(&self) -> &Name {
        self.key_id.as_name()
    }

    fn cert_name(&self) -> Option<&Name> {
        self.cert_name.as_ref()
    }

    fn public_key(&self) -> Option<Bytes> {
        self.public_key.clone()
    }

    fn sign<'a>(
        &'a self,
        region: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<Bytes, TrustError>> + Send + 'a>> {
        Box::pin(async move {
            self.custodian
                .sign(&self.key_id, self.key_id.as_name(), region)
                .await
                .map_err(|e| TrustError::KeyStore(e.to_string()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custodian::InPageCustodian;
    use crate::{Ed25519Signer, Ed25519Verifier, VerifyOutcome};

    #[tokio::test]
    async fn custodian_signer_signs_and_verifies() {
        let name: Name = "/op/alice/KEY/k1".parse().unwrap();
        let key_id = KeyId(name.clone());
        let inner = Ed25519Signer::from_seed(&[7u8; 32], name.clone());
        let pk = inner.public_key_bytes();

        let custodian = Arc::new(InPageCustodian::new());
        custodian.insert(key_id.clone(), inner);

        let cs = CustodianSigner::new(
            custodian,
            key_id,
            SignatureType::SignatureEd25519,
            Some(Bytes::copy_from_slice(&pk)),
        );

        assert_eq!(cs.sig_type(), SignatureType::SignatureEd25519);
        assert_eq!(cs.key_name().to_string(), "/op/alice/KEY/k1");

        let region = b"signed command region";
        let sig = cs.sign(region).await.expect("custodian signs");
        assert!(matches!(
            Ed25519Verifier.verify_sync(region, &sig, &pk),
            VerifyOutcome::Valid
        ));
    }
}
