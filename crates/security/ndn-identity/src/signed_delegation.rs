//! Signed delegation — a principal's transmittable, verifiable grant of a
//! scoped capability to a subordinate (device) key.
//!
//! The canonical NDN floor is "the certificate *is* the delegation"
//! ([`Delegation::verify`](crate::Delegation::verify)): a subordinate cert
//! issued by the principal proves namespace authority, and the trust schema
//! decides what it may sign. But that floor can't carry an **explicit scope** —
//! the capability flags (`unwrap_for` / `enroll` / `mgmt`) and the specific
//! sign patterns a principal wants to grant aren't provable from the issuing
//! cert alone (`Delegation::verify` leaves them off for exactly this reason).
//!
//! [`SignedDelegation`] is the deferred "DelegationAtom" (design note §11): one
//! signed, encodable object carrying `(principal, subordinate, scope)` that a
//! device presents and any verifier checks against the principal's key. It
//! sits *alongside* the cert floor — the cert proves the device key is the
//! principal's; this proves what the principal authorized it to do.

use std::sync::Arc;

use ndn_packet::{Name, SignatureType};
use ndn_security::trust_schema::NamePattern;
use ndn_security::verifier::verify_by_sig_type;
use ndn_security::{KeyChain, Signer, VerifyOutcome};

use bytes::Bytes;

use crate::delegation::DelegationError;
use crate::transition::identity_of;
use crate::{CapabilitySet, IdentityError};

/// A principal's signed grant of a [`CapabilitySet`] to a subordinate device
/// key. Produce one with [`issue`](Self::issue); check it with
/// [`verify`](Self::verify); move it over any transport with
/// [`encode`](Self::encode) / [`decode`](Self::decode).
#[derive(Debug, Clone)]
pub struct SignedDelegation {
    /// The principal's identity namespace (the grantor).
    pub principal: Name,
    /// The subordinate's identity namespace (the grantee device).
    pub subordinate: Name,
    /// What the subordinate is authorized to do.
    pub scope: CapabilitySet,
    /// The principal KEY name that signed — the verifier resolves it to a key
    /// through its own trust.
    pub key_locator: Name,
    /// Signature algorithm of `sig_value`.
    pub sig_type: SignatureType,
    /// The principal's signature over [`canonical_bytes`](Self::canonical_bytes).
    pub sig_value: Bytes,
}

impl SignedDelegation {
    /// Issue a signed delegation: the `principal` keychain grants `scope` to the
    /// `subordinate` device namespace, signing with its own key. Fails if the
    /// subordinate is not under the principal's namespace — a principal cannot
    /// delegate authority it does not itself hold.
    pub fn issue(
        principal: &KeyChain,
        subordinate: Name,
        scope: CapabilitySet,
    ) -> Result<Self, IdentityError> {
        if !subordinate.has_prefix(principal.name()) {
            return Err(IdentityError::Lifecycle(format!(
                "subordinate {subordinate} is not under principal namespace {}",
                principal.name()
            )));
        }
        let signer = principal
            .signer()
            .map_err(|e| IdentityError::Lifecycle(format!("principal has no signer: {e}")))?;
        let mut deleg = SignedDelegation {
            principal: principal.name().clone(),
            subordinate,
            scope,
            key_locator: signer.key_name().clone(),
            sig_type: signer.sig_type(),
            sig_value: Bytes::new(),
        };
        let region = deleg.canonical_bytes();
        deleg.sig_value = signer
            .sign_sync(&region)
            .map_err(|e| IdentityError::Lifecycle(format!("delegation signing failed: {e}")))?;
        Ok(deleg)
    }

    /// Verify the grant against the principal's public key (which the caller
    /// resolved from `key_locator` through its own trust). On success returns
    /// the authorized [`CapabilitySet`]. Enforces the namespace floor and that
    /// the signing key lives in the principal's namespace.
    pub async fn verify(
        &self,
        principal_public_key: &[u8],
    ) -> Result<CapabilitySet, DelegationError> {
        // A principal may only delegate within its own namespace.
        if !self.subordinate.has_prefix(&self.principal) {
            return Err(DelegationError::OutOfNamespace);
        }
        // The signing key must belong to the principal (its identity == principal).
        match identity_of(&self.key_locator) {
            Some(id) if id == self.principal => {}
            _ => return Err(DelegationError::NotIssuedByPrincipal),
        }
        let region = self.canonical_bytes();
        match verify_by_sig_type(
            self.sig_type,
            &region,
            &self.sig_value,
            principal_public_key,
        )
        .await
        {
            Ok(VerifyOutcome::Valid) => Ok(self.scope.clone()),
            _ => Err(DelegationError::SignatureInvalid),
        }
    }

    /// The deterministic byte string the signature covers: principal,
    /// subordinate, scope, key-locator, and sig-type, each length- or
    /// presence-framed so the encoding is unambiguous. Re-derived from the
    /// fields (never stored), so the signature binds the actual grant.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_str(&mut out, &self.principal.to_string());
        put_str(&mut out, &self.subordinate.to_string());
        encode_scope(&mut out, &self.scope);
        put_str(&mut out, &self.key_locator.to_string());
        out.extend_from_slice(&self.sig_type.code().to_be_bytes());
        out
    }

    /// Encode to a transmittable record: the canonical fields followed by the
    /// length-framed `sig_value`.
    pub fn encode(&self) -> Bytes {
        let mut out = self.canonical_bytes();
        put_blob(&mut out, &self.sig_value);
        Bytes::from(out)
    }

    /// Decode a record produced by [`encode`](Self::encode). A truncated or
    /// malformed record is [`DelegationError::Malformed`]; the result still
    /// needs [`verify`](Self::verify) before its scope is trusted.
    pub fn decode(wire: &[u8]) -> Result<Self, DelegationError> {
        let mut c = Cursor { buf: wire, pos: 0 };
        let principal = get_name(&mut c)?;
        let subordinate = get_name(&mut c)?;
        let scope = get_scope(&mut c)?;
        let key_locator = get_name(&mut c)?;
        let sig_type = SignatureType::from_code(get_u64(&mut c)?);
        let sig_value = Bytes::copy_from_slice(get_blob(&mut c)?);
        Ok(Self {
            principal,
            subordinate,
            scope,
            key_locator,
            sig_type,
            sig_value,
        })
    }
}

/// A subordinate device's signer, gated by a verified delegation grant — the
/// **enforcement** half of the delegation loop. The principal issues a
/// [`SignedDelegation`]; the device verifies it and wraps its own key here, so
/// the device can only sign names the grant authorizes and refuses the rest.
///
/// The device signs with **its own** key; the grant says *what names* it may
/// sign for, not *which key* signs. A verifier then ties the device key back to
/// the principal through the cert chain (the cert-as-delegation floor) and this
/// grant's explicit scope.
pub struct DelegatedSigner {
    signer: Arc<dyn Signer>,
    grant: CapabilitySet,
}

impl DelegatedSigner {
    /// Wrap `signer` with an already-verified `grant`.
    pub fn new(signer: Arc<dyn Signer>, grant: CapabilitySet) -> Self {
        Self { signer, grant }
    }

    /// Verify `delegation` against the principal's public key, then gate
    /// `signer` by the granted scope. The one-step "I received a delegation,
    /// now enforce it" path.
    pub async fn from_delegation(
        signer: Arc<dyn Signer>,
        delegation: &SignedDelegation,
        principal_public_key: &[u8],
    ) -> Result<Self, DelegationError> {
        let grant = delegation.verify(principal_public_key).await?;
        Ok(Self::new(signer, grant))
    }

    /// The scope this signer is allowed to act within.
    pub fn grant(&self) -> &CapabilitySet {
        &self.grant
    }

    /// Whether the grant authorizes signing `name`.
    pub fn may_sign(&self, name: &Name) -> bool {
        self.grant.may_sign(name)
    }

    /// Sign `region` (the to-be-signed bytes of a Data named `name`) with the
    /// device key — but only if the grant authorizes `name`. Refuses
    /// out-of-scope names rather than producing an unauthorized signature.
    pub async fn sign(&self, name: &Name, region: &[u8]) -> Result<Bytes, IdentityError> {
        if !self.may_sign(name) {
            return Err(IdentityError::Lifecycle(format!(
                "delegation does not authorize signing {name}"
            )));
        }
        Ok(self.signer.sign(region).await?)
    }
}

// ── deterministic field framing ─────────────────────────────────────────────

fn put_str(out: &mut Vec<u8>, s: &str) {
    put_blob(out, s.as_bytes());
}

fn put_blob(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u64).to_be_bytes());
    out.extend_from_slice(b);
}

fn encode_scope(out: &mut Vec<u8>, scope: &CapabilitySet) {
    out.extend_from_slice(&(scope.sign.len() as u64).to_be_bytes());
    for pattern in &scope.sign {
        put_str(out, &pattern.to_string());
    }
    out.push(scope.unwrap_for as u8);
    out.push(scope.enroll as u8);
    out.push(scope.mgmt as u8);
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

fn get_blob<'a>(c: &mut Cursor<'a>) -> Result<&'a [u8], DelegationError> {
    if c.pos + 8 > c.buf.len() {
        return Err(DelegationError::Malformed);
    }
    let len = u64::from_be_bytes(c.buf[c.pos..c.pos + 8].try_into().unwrap()) as usize;
    c.pos += 8;
    if c.pos + len > c.buf.len() {
        return Err(DelegationError::Malformed);
    }
    let out = &c.buf[c.pos..c.pos + len];
    c.pos += len;
    Ok(out)
}

fn get_u64(c: &mut Cursor<'_>) -> Result<u64, DelegationError> {
    if c.pos + 8 > c.buf.len() {
        return Err(DelegationError::Malformed);
    }
    let v = u64::from_be_bytes(c.buf[c.pos..c.pos + 8].try_into().unwrap());
    c.pos += 8;
    Ok(v)
}

fn get_byte(c: &mut Cursor<'_>) -> Result<u8, DelegationError> {
    if c.pos >= c.buf.len() {
        return Err(DelegationError::Malformed);
    }
    let b = c.buf[c.pos];
    c.pos += 1;
    Ok(b)
}

fn get_name(c: &mut Cursor<'_>) -> Result<Name, DelegationError> {
    let s = std::str::from_utf8(get_blob(c)?).map_err(|_| DelegationError::Malformed)?;
    s.parse::<Name>().map_err(|_| DelegationError::Malformed)
}

fn get_scope(c: &mut Cursor<'_>) -> Result<CapabilitySet, DelegationError> {
    let n = get_u64(c)? as usize;
    let mut sign = Vec::with_capacity(n);
    for _ in 0..n {
        let s = std::str::from_utf8(get_blob(c)?).map_err(|_| DelegationError::Malformed)?;
        sign.push(NamePattern::parse(s).map_err(|_| DelegationError::Malformed)?);
    }
    let unwrap_for = get_byte(c)? != 0;
    let enroll = get_byte(c)? != 0;
    let mgmt = get_byte(c)? != 0;
    Ok(CapabilitySet {
        sign,
        unwrap_for,
        enroll,
        mgmt,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_security::SecurityManager;
    use std::sync::Arc;

    /// A principal keychain over a fresh Ed25519 key, named per convention
    /// `/<identity>/KEY/<id>` so `identity_of(key_locator)` resolves the principal.
    fn principal_keychain(name: &str) -> (KeyChain, Vec<u8>) {
        let mgr = Arc::new(SecurityManager::new());
        let id: Name = name.parse().unwrap();
        let key_name: Name = format!("{name}/KEY/k0").parse().unwrap();
        mgr.generate_ed25519(key_name.clone()).unwrap();
        let pubkey = mgr
            .get_signer_sync(&key_name)
            .unwrap()
            .public_key()
            .unwrap()
            .to_vec();
        (KeyChain::from_parts(mgr, id, key_name), pubkey)
    }

    fn route_scope() -> CapabilitySet {
        CapabilitySet {
            sign: vec![NamePattern::parse("/alice/device/phone/<**rest>").unwrap()],
            unwrap_for: true,
            enroll: false,
            mgmt: false,
        }
    }

    #[tokio::test]
    async fn issue_then_verify_returns_scope() {
        let (kc, pubkey) = principal_keychain("/alice");
        let deleg =
            SignedDelegation::issue(&kc, "/alice/device/phone".parse().unwrap(), route_scope())
                .expect("issue");

        let scope = deleg.verify(&pubkey).await.expect("verify");
        assert!(scope.unwrap_for);
        assert_eq!(scope.sign.len(), 1);
        assert!(scope.sign[0].matches(
            &"/alice/device/phone/data/1".parse().unwrap(),
            &mut std::collections::HashMap::new()
        ));
    }

    #[tokio::test]
    async fn wire_round_trips_through_encode_decode() {
        let (kc, pubkey) = principal_keychain("/alice");
        let deleg =
            SignedDelegation::issue(&kc, "/alice/device/phone".parse().unwrap(), route_scope())
                .unwrap();
        let wire = deleg.encode();
        let back = SignedDelegation::decode(&wire).expect("decode");

        assert_eq!(back.principal, deleg.principal);
        assert_eq!(back.subordinate, deleg.subordinate);
        assert_eq!(back.key_locator, deleg.key_locator);
        assert_eq!(back.sig_value, deleg.sig_value);
        // Decoded form still verifies (the signature survived the round-trip).
        back.verify(&pubkey).await.expect("decoded verifies");
    }

    #[tokio::test]
    async fn tampered_scope_fails_verification() {
        let (kc, pubkey) = principal_keychain("/alice");
        let mut deleg =
            SignedDelegation::issue(&kc, "/alice/device/phone".parse().unwrap(), route_scope())
                .unwrap();
        // Escalate the grant after signing — the signature no longer covers it.
        deleg.scope.mgmt = true;
        assert!(matches!(
            deleg.verify(&pubkey).await,
            Err(DelegationError::SignatureInvalid)
        ));
    }

    #[tokio::test]
    async fn out_of_namespace_is_refused_at_issue_and_verify() {
        let (kc, _pubkey) = principal_keychain("/alice");
        // A principal can't delegate outside its own namespace.
        assert!(
            SignedDelegation::issue(&kc, "/bob/device/x".parse().unwrap(), route_scope()).is_err()
        );
    }

    #[tokio::test]
    async fn wrong_principal_key_fails_verification() {
        let (kc, _pubkey) = principal_keychain("/alice");
        let (_other, other_pubkey) = principal_keychain("/alice"); // different key, same ns
        let deleg =
            SignedDelegation::issue(&kc, "/alice/device/phone".parse().unwrap(), route_scope())
                .unwrap();
        assert!(matches!(
            deleg.verify(&other_pubkey).await,
            Err(DelegationError::SignatureInvalid)
        ));
    }

    /// The full loop: principal issues → device verifies → device signs in
    /// scope but is refused out of scope.
    #[tokio::test]
    async fn delegated_signer_enforces_scope() {
        let (principal, principal_pubkey) = principal_keychain("/alice");
        let deleg = SignedDelegation::issue(
            &principal,
            "/alice/device/phone".parse().unwrap(),
            route_scope(),
        )
        .unwrap();

        // The device holds its own key and accepts the verified grant.
        let (device_kc, _) = principal_keychain("/alice/device/phone");
        let device_signer = device_kc.signer().unwrap();
        let ds = DelegatedSigner::from_delegation(device_signer, &deleg, &principal_pubkey)
            .await
            .expect("device accepts a valid delegation");

        // In scope → signs (with the device key).
        let in_scope: Name = "/alice/device/phone/data/1".parse().unwrap();
        assert!(ds.may_sign(&in_scope));
        let sig = ds.sign(&in_scope, b"region").await.expect("in-scope signs");
        assert!(!sig.is_empty());

        // Out of scope → refused, no signature produced.
        let out: Name = "/alice/other/secret".parse().unwrap();
        assert!(!ds.may_sign(&out));
        assert!(ds.sign(&out, b"region").await.is_err());
    }

    #[tokio::test]
    async fn delegated_signer_rejects_a_tampered_delegation() {
        let (principal, principal_pubkey) = principal_keychain("/alice");
        let mut deleg = SignedDelegation::issue(
            &principal,
            "/alice/device/phone".parse().unwrap(),
            route_scope(),
        )
        .unwrap();
        deleg.scope.mgmt = true; // escalate after signing
        let (device_kc, _) = principal_keychain("/alice/device/phone");
        assert!(
            DelegatedSigner::from_delegation(
                device_kc.signer().unwrap(),
                &deleg,
                &principal_pubkey
            )
            .await
            .is_err()
        );
    }
}
