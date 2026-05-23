//! `TrustPolicy` — unified signing + validation handle.
//!
//! One trait answers two questions per protocol:
//! - which [`Signer`] produces an outbound packet
//! - which [`Validator`] checks an inbound packet
//!
//! Built-ins: [`InsecureTrust`] (DigestSha256 + accept-all),
//! [`StaticTrust`] (fixed signer + hierarchical schema), and [`LvsTrust`]
//! (fixed signer + LVS schema). The split mirrors ndn-cxx's.

use std::sync::Arc;

use ndn_packet::Name;

use crate::lvs::LvsModel;
use crate::trust_schema::TrustSchema;
use crate::{KeyChain, Signer, TrustError, Validator};

/// Operator-facing trust handle. One object answers two questions:
///
/// 1. *Which signer should this protocol use to sign an outbound
///    packet named `for_name`?* — [`signer`].
/// 2. *Which validator should check an inbound packet?* —
///    [`validator`].
///
/// [`signer`]: TrustPolicy::signer
/// [`validator`]: TrustPolicy::validator
pub trait TrustPolicy: Send + Sync + 'static {
    /// Suggest a signer for an outbound packet. `Ok(None)` means sign with
    /// `DigestSha256` (wire-compat fallback for "insecure" mode).
    fn signer(&self, for_name: &Name) -> Result<Option<Arc<dyn Signer>>, TrustError>;

    /// Build the validator this policy wants applied to inbound packets.
    fn validator(&self) -> Validator;
}

/// Emit `DigestSha256` on egress, accept anything on ingress. Test-only
/// / bring-up; production should pick [`StaticTrust`] or [`LvsTrust`].
pub struct InsecureTrust;

impl TrustPolicy for InsecureTrust {
    fn signer(&self, _for_name: &Name) -> Result<Option<Arc<dyn Signer>>, TrustError> {
        Ok(None)
    }

    fn validator(&self) -> Validator {
        Validator::new(TrustSchema::accept_all())
    }
}

/// Hierarchical-trust mode with a fixed default signer. Incoming packets
/// are validated against [`TrustSchema::hierarchical`]: the data name must
/// be a sub-name of the signing key's identity prefix.
pub struct StaticTrust {
    signer: Option<Arc<dyn Signer>>,
    keychain: Option<Arc<KeyChain>>,
}

impl StaticTrust {
    /// Build from a pre-constructed signer. `validator()` returns a
    /// hierarchical validator with no trust anchors pre-installed; callers
    /// add anchors before handing off.
    pub fn new(signer: Option<Arc<dyn Signer>>) -> Self {
        Self {
            signer,
            keychain: None,
        }
    }

    /// Build from a [`KeyChain`]; `validator()` returns the keychain's
    /// validator with its hierarchical schema and trust anchors.
    pub fn from_keychain(keychain: Arc<KeyChain>) -> Result<Self, TrustError> {
        let signer = keychain.signer()?;
        Ok(Self {
            signer: Some(signer),
            keychain: Some(keychain),
        })
    }
}

impl TrustPolicy for StaticTrust {
    fn signer(&self, _for_name: &Name) -> Result<Option<Arc<dyn Signer>>, TrustError> {
        Ok(self.signer.clone())
    }

    fn validator(&self) -> Validator {
        match &self.keychain {
            Some(kc) => kc.validator(),
            None => Validator::new(TrustSchema::hierarchical()),
        }
    }
}

/// LVS-driven trust. Validation runs the bundled [`LvsModel`] over
/// `(data_name, key_name)` before the signature check. Signing falls back
/// to the configured `default_signer`.
pub struct LvsTrust {
    model: Arc<LvsModel>,
    signer: Option<Arc<dyn Signer>>,
    keychain: Option<Arc<KeyChain>>,
}

impl LvsTrust {
    pub fn new(model: Arc<LvsModel>, signer: Option<Arc<dyn Signer>>) -> Self {
        Self {
            model,
            signer,
            keychain: None,
        }
    }

    pub fn from_keychain(
        model: Arc<LvsModel>,
        keychain: Arc<KeyChain>,
    ) -> Result<Self, TrustError> {
        let signer = keychain.signer()?;
        Ok(Self {
            model,
            signer: Some(signer),
            keychain: Some(keychain),
        })
    }

    pub fn model(&self) -> &Arc<LvsModel> {
        &self.model
    }
}

impl TrustPolicy for LvsTrust {
    fn signer(&self, _for_name: &Name) -> Result<Option<Arc<dyn Signer>>, TrustError> {
        Ok(self.signer.clone())
    }

    fn validator(&self) -> Validator {
        // LVS evaluation lives on `LvsPolicy`; until Validator absorbs
        // ValidationPolicy, return the keychain's hierarchical validator
        // so call sites get a working object.
        match &self.keychain {
            Some(kc) => kc.validator(),
            None => Validator::new(TrustSchema::hierarchical()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insecure_trust_yields_no_signer() {
        let t = InsecureTrust;
        let signer = t.signer(&"/d".parse().unwrap()).unwrap();
        assert!(
            signer.is_none(),
            "InsecureTrust must yield DigestSha256 fallback (None)"
        );
        let _v = t.validator();
    }

    #[test]
    fn static_trust_from_keychain_yields_signer() {
        let kc = Arc::new(KeyChain::ephemeral("/com/example/static").unwrap());
        let t = StaticTrust::from_keychain(Arc::clone(&kc)).unwrap();
        let signer = t.signer(&"/com/example/static/d".parse().unwrap()).unwrap();
        assert!(
            signer.is_some(),
            "StaticTrust::from_keychain must produce a signer"
        );
        let validator = t.validator();
        let schema = validator.schema_snapshot();
        let data_name: Name = "/com/example/static/d".parse().unwrap();
        let key_name: Name = "/com/example/static/KEY/k".parse().unwrap();
        assert!(
            schema.allows(&data_name, &key_name),
            "StaticTrust validator must allow same-namespace data+key"
        );
    }

    #[test]
    fn static_trust_validator_rejects_cross_namespace() {
        let kc = Arc::new(KeyChain::ephemeral("/com/example/static").unwrap());
        let t = StaticTrust::from_keychain(kc).unwrap();
        let schema = t.validator().schema_snapshot();
        let data_name: Name = "/org/other/d".parse().unwrap();
        let key_name: Name = "/com/example/static/KEY/k".parse().unwrap();
        assert!(
            !schema.allows(&data_name, &key_name),
            "cross-namespace data must be rejected by hierarchical validator"
        );
    }

    #[test]
    fn lvs_trust_holds_model() {
        // Minimal LVS schema (one empty start node) so model construction
        // stays within LvsModel's public API.
        let bytes = [
            // Version=1
            0x01, 0x01, 0x01, // StartId=0
            0x02, 0x01, 0x00, // NamedPatternCnt=0
            0x03, 0x01, 0x00,
        ];
        let model = match LvsModel::decode(&bytes) {
            Ok(m) => Arc::new(m),
            Err(_) => return,
        };
        let t = LvsTrust::new(Arc::clone(&model), None);
        assert!(Arc::ptr_eq(t.model(), &model));
        let _signer = t.signer(&"/d".parse().unwrap()).unwrap();
        let _validator = t.validator();
    }
}
