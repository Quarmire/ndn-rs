//! Delegation — a principal grants a scoped capability to a subordinate key.
//!
//! This is the *device* axis of the identity model (design note §3): a principal
//! authorizes a per-device subordinate key to act, within a scope, on its behalf.
//! Losing a device ≠ losing the principal.
//!
//! The canonical NDN floor needs no new artifact: **the certificate *is* the
//! delegation.** A subordinate key issued by the principal (the issuer
//! `KeyLocator`) is, by NDN convention, delegated by it; the trust schema then
//! decides which names the subordinate may sign. [`Delegation`] makes that grant
//! explicit and enforces the two properties the floor guarantees:
//!
//! 1. the subordinate's certificate is genuinely issued by the principal key, and
//! 2. the subordinate lives **within the principal's namespace** — a principal
//!    cannot delegate authority it does not itself hold.
//!
//! The scope vocabulary ([`CapabilitySet`]) is the *open* part of the frame:
//! today name-prefix signing plus the unwrap/enroll/mgmt flags; the richer ndf
//! `DelegationAtom` (capability, reversibility, sub-delegation) is a future
//! mechanism behind this same frame, deferred per the §11 cross-reference.

use ndn_packet::Name;

use ndn_security::verifier::verify_by_sig_type;
use ndn_security::{Certificate, VerifyOutcome};

use crate::transition::{identity_of, key_name_of};
use crate::trust_context::pattern_under;
use crate::{CapabilitySet, IdentityRef};

/// A scoped grant from a principal to a subordinate (device) key.
///
/// Construct the *verified* form with [`Delegation::verify`] (proven by the
/// certificate chain) or capture the *intended* grant a derived [`IdentityRef`]
/// expresses with [`Delegation::from_derived`].
#[derive(Debug, Clone)]
pub struct Delegation {
    /// The principal's identity namespace (the grantor).
    pub principal: Name,
    /// The subordinate's identity namespace (the grantee).
    pub subordinate: Name,
    /// What the subordinate is authorized to do.
    pub scope: CapabilitySet,
}

/// Why a delegation failed to verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegationError {
    /// A certificate name was malformed (no `KEY` component).
    Malformed,
    /// The subordinate namespace is not under the principal's namespace — a
    /// principal cannot delegate authority it does not hold.
    OutOfNamespace,
    /// The subordinate certificate's issuer is not the principal key.
    NotIssuedByPrincipal,
    /// The issuance signature does not verify under the principal key.
    SignatureInvalid,
}

impl Delegation {
    /// Verify that `subordinate_cert` is a genuine, in-namespace delegation from
    /// `principal_cert`. On success the returned [`Delegation`] is scoped to
    /// signing under the subordinate's own namespace — the authority the
    /// certificate chain actually proves. Capability flags
    /// (`unwrap_for`/`enroll`/`mgmt`) are *not* provable from the cert alone and
    /// stay off here; assert them via the schema or [`from_derived`].
    ///
    /// [`from_derived`]: Self::from_derived
    pub async fn verify(
        principal_cert: &Certificate,
        subordinate_cert: &Certificate,
    ) -> Result<Delegation, DelegationError> {
        let principal = identity_of(&principal_cert.name).ok_or(DelegationError::Malformed)?;
        let subordinate = identity_of(&subordinate_cert.name).ok_or(DelegationError::Malformed)?;

        // A principal may only delegate within its own namespace.
        if !subordinate.has_prefix(&principal) {
            return Err(DelegationError::OutOfNamespace);
        }

        // Cert-as-delegation: the subordinate cert must be issued by the
        // principal key (its KeyLocator names the principal key).
        let principal_key = key_name_of(&principal_cert.name).ok_or(DelegationError::Malformed)?;
        let issuer = subordinate_cert
            .issuer
            .as_ref()
            .ok_or(DelegationError::NotIssuedByPrincipal)?;
        match key_name_of(issuer) {
            Some(issuer_key) if issuer_key == principal_key => {}
            _ => return Err(DelegationError::NotIssuedByPrincipal),
        }

        // And the issuance signature must verify under the principal key.
        let (Some(region), Some(sig)) = (
            subordinate_cert.signed_region.as_ref(),
            subordinate_cert.sig_value.as_ref(),
        ) else {
            return Err(DelegationError::SignatureInvalid);
        };
        match verify_by_sig_type(
            subordinate_cert.sig_type,
            region,
            sig,
            &principal_cert.public_key,
        )
        .await
        {
            Ok(VerifyOutcome::Valid) => {}
            _ => return Err(DelegationError::SignatureInvalid),
        }

        let scope = CapabilitySet {
            sign: vec![pattern_under(&subordinate)],
            ..Default::default()
        };
        Ok(Delegation {
            principal,
            subordinate,
            scope,
        })
    }

    /// Capture the grant a `parent → derived` [`IdentityRef`] pair expresses,
    /// wiring `derived_from` into the frame. This carries the derived identity's
    /// full [`CapabilitySet`] (the principal's *intent*); unlike [`verify`] it is
    /// not cryptographically checked against the certificate chain.
    ///
    /// [`verify`]: Self::verify
    pub fn from_derived(parent: &IdentityRef, derived: &IdentityRef) -> Delegation {
        Delegation {
            principal: parent.name.clone(),
            subordinate: derived.name.clone(),
            scope: derived.capabilities.clone(),
        }
    }

    /// Whether this delegation authorizes signing `name`.
    pub fn may_sign(&self, name: &Name) -> bool {
        self.scope.may_sign(name)
    }

    /// Whether the subordinate may unwrap content keys on the principal's behalf.
    pub fn may_unwrap(&self) -> bool {
        self.scope.unwrap_for
    }

    /// Whether the subordinate may enroll further identities under the principal.
    pub fn may_enroll(&self) -> bool {
        self.scope.enroll
    }

    /// Whether the subordinate may issue management commands for the principal.
    pub fn may_manage(&self) -> bool {
        self.scope.mgmt
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust_context::{IdentityLifetime, KeyId};
    use ndn_security::SecurityManager;

    /// Issue a principal cert and a subordinate cert under `sub_name`, signed by
    /// `issuer` (the principal key, or an attacker for the forged case).
    async fn delegation_certs(
        principal_name: &str,
        sub_name: &str,
        issuer_name: &str,
    ) -> (Certificate, Certificate) {
        let mgr = SecurityManager::new();
        let make = |name: &str| -> Name {
            let n: Name = name.parse().unwrap();
            mgr.generate_ed25519(n.clone()).unwrap();
            n
        };
        let principal = make(principal_name);
        let p_pub = mgr
            .get_signer_sync(&principal)
            .unwrap()
            .public_key()
            .unwrap();
        let principal_cert = mgr.issue_self_signed(&principal, p_pub, u64::MAX).unwrap();

        let sub = make(sub_name);
        let s_pub = mgr.get_signer_sync(&sub).unwrap().public_key().unwrap();
        // The attacker case needs its own key in the store to sign with.
        let issuer = if issuer_name == principal_name {
            principal
        } else {
            make(issuer_name)
        };
        let sub_cert = mgr
            .certify(&sub, s_pub, &issuer, 31_536_000_000)
            .await
            .unwrap();
        (principal_cert, sub_cert)
    }

    #[tokio::test]
    async fn verify_accepts_in_namespace_grant_and_scopes_to_subordinate() {
        let (principal, sub) = delegation_certs(
            "/alice/KEY/kp",
            "/alice/device/phone/KEY/kd",
            "/alice/KEY/kp",
        )
        .await;

        let d = Delegation::verify(&principal, &sub).await.expect("verify");
        assert_eq!(d.principal, "/alice".parse::<Name>().unwrap());
        assert_eq!(
            d.subordinate,
            "/alice/device/phone".parse::<Name>().unwrap()
        );

        // Scoped to the subordinate's own subtree.
        assert!(d.may_sign(&"/alice/device/phone/data".parse().unwrap()));
        assert!(!d.may_sign(&"/alice/other/thing".parse().unwrap()));
        // Capability flags are off — not provable from the cert.
        assert!(!d.may_unwrap() && !d.may_enroll() && !d.may_manage());
    }

    #[tokio::test]
    async fn verify_rejects_out_of_namespace_and_forged_issuer() {
        // Subordinate outside the principal's namespace: principal cannot delegate it.
        let (principal, foreign_sub) =
            delegation_certs("/alice/KEY/kp", "/bob/device/x/KEY/kd", "/alice/KEY/kp").await;
        assert!(matches!(
            Delegation::verify(&principal, &foreign_sub).await,
            Err(DelegationError::OutOfNamespace)
        ));

        // Subordinate in-namespace but issued by an attacker, not the principal.
        let (principal2, forged_sub) = delegation_certs(
            "/alice/KEY/kp",
            "/alice/device/phone/KEY/kd",
            "/evil/KEY/kx",
        )
        .await;
        assert!(matches!(
            Delegation::verify(&principal2, &forged_sub).await,
            Err(DelegationError::NotIssuedByPrincipal)
        ));
    }

    #[test]
    fn from_derived_wires_identity_ref_into_the_frame() {
        use crate::TrustContext;
        use ndn_security::custodian::CustodianRef;

        let parent = IdentityRef {
            name: "/alice".parse().unwrap(),
            key_id: KeyId::placeholder_for(&"/alice".parse().unwrap()),
            custodian: CustodianRef::InPage,
            lifetime: IdentityLifetime::Persistent,
            derived_from: None,
            capabilities: CapabilitySet::default(),
        };
        let ctx = TrustContext::adopted(
            "/alice".parse().unwrap(),
            std::time::SystemTime::UNIX_EPOCH,
            "test",
        );
        let derived = ctx.derive_sub(
            "/alice/device/phone".parse().unwrap(),
            IdentityLifetime::Persistent,
            &parent,
            CustodianRef::InPage,
        );

        let d = Delegation::from_derived(&parent, &derived);
        assert_eq!(d.principal, parent.name);
        assert_eq!(d.subordinate, derived.name);
        assert!(d.may_sign(&"/alice/device/phone/x".parse().unwrap()));
        // The grant records the derivation the IdentityRef encodes.
        assert!(derived.derived_from.is_some());
    }
}
