//! [`Identity`] — the one managed identity above [`KeyChain`].
//!
//! `KeyChain` (in `ndn-security`) is the atom: a key, a cert, trust anchors —
//! sign and verify. It is the canonical NDN identity type and most code needs
//! nothing more. `Identity` is a `KeyChain` **with a lifecycle**: it derefs to
//! the keychain (so it signs and verifies exactly like one) and adds the
//! lifecycle NDN leaves to applications —
//!
//! - **enrollment / renewal** ([`enroll`](Identity::enroll),
//!   [`provision`](Identity::provision)) — get a certificate from a CA;
//! - **rotation** ([`rotate`](Identity::rotate)) — change the operational key
//!   under the prior key's authority, recorded as a `did:ndn` history;
//! - **recovery** ([`recover`](Identity::recover)) — install a new key under a
//!   pre-committed out-of-band authority when the operational key is lost;
//! - **delegation** ([`add_device`](Identity::add_device)) — grant a scoped
//!   capability to a device key.
//!
//! Reach for `Identity` when you need any of those; otherwise a bare `KeyChain`
//! is enough. (`NdnIdentity` is a deprecated alias for this type.)
//!
//! The safe default it imposes (design note §5): **recovery is designated at
//! creation.** [`create`](Identity::create) requires a [`RecoveryCommitment`];
//! the only unrecoverable path is the loud [`create_unrecoverable`](Identity::create_unrecoverable).

use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use ndn_packet::{Name, SignatureType};

use ndn_security::did::{UniversalResolver, name_to_did};
use ndn_security::{DidDocument, IdentityProof, KeyChain, RecoveryCommitment, Signer};

use crate::error::IdentityError;
use crate::renewal::RenewalHandle;
use crate::transition::{
    AuthorityOutcome, DidDocumentRotation, KeyRecovery, KeyState, RecoveryProof, RecoverySignature,
    TransitionAuthority, TransitionProof,
};
use crate::{CapabilitySet, Delegation};

/// A `KeyChain` with a managed lifecycle: enrollment, rotation, recovery, and
/// delegation. Derefs to the underlying [`KeyChain`] for day-to-day signing and
/// validation.
pub struct Identity {
    keychain: KeyChain,
    // Owns the background renewal task; dropped (and aborted) with the identity.
    #[allow(dead_code)]
    renewal: Option<RenewalHandle>,
    /// The `did:ndn` rotation history (genesis-first). Empty for a plain
    /// keychain-backed identity; populated by [`create`](Self::create) and
    /// [`rotate`](Self::rotate).
    history: Vec<IdentityProof>,
}

impl std::ops::Deref for Identity {
    type Target = KeyChain;

    fn deref(&self) -> &KeyChain {
        &self.keychain
    }
}

impl Identity {
    // ---- creation (keychain-backed) ------------------------------------------

    /// In-memory, self-signed; keys are not persisted. Good for tests and
    /// short-lived producers. No rotation history until you [`rotate`](Self::rotate).
    pub fn ephemeral(name: impl AsRef<str>) -> Result<Self, IdentityError> {
        Ok(Self::from_keychain(KeyChain::ephemeral(name)?, None))
    }

    /// File-backed: generates a key + self-signed cert on first run, reloads it
    /// afterwards.
    pub fn open_or_create(path: &Path, name: impl AsRef<str>) -> Result<Self, IdentityError> {
        Ok(Self::from_keychain(KeyChain::open_or_create(path, name)?, None))
    }

    /// Run the NDNCERT INFO → NEW → CHALLENGE exchange and persist the issued
    /// cert if `config.storage` is set.
    pub async fn enroll(config: crate::enroll::EnrollConfig) -> Result<Self, IdentityError> {
        crate::enroll::run_enrollment(config).await
    }

    /// Select the challenge from `config.factory_credential`, enroll, and
    /// (optionally) start background renewal.
    pub async fn provision(config: crate::device::DeviceConfig) -> Result<Self, IdentityError> {
        crate::device::run_provisioning(config).await
    }

    /// Bootstrap trust from a DID: `did:key` uses the public key directly as the
    /// anchor; `did:ndn` / `did:web` are resolved via `resolver`.
    pub async fn from_did(
        did: &str,
        name: impl AsRef<str>,
        resolver: &UniversalResolver,
    ) -> Result<Self, IdentityError> {
        let doc = resolver.resolve_document(did).await?;
        let identity = Self::ephemeral(name)?;
        if let Some(anchor) = ndn_security::did::did_document_to_trust_anchor(
            &doc,
            Arc::new(identity.keychain.name().clone()),
        ) {
            identity.keychain.add_trust_anchor(anchor);
        }
        Ok(identity)
    }

    /// Wrap an existing keychain (with an optional renewal task).
    pub fn from_keychain(keychain: KeyChain, renewal: Option<RenewalHandle>) -> Self {
        Self {
            keychain,
            renewal,
            history: Vec::new(),
        }
    }

    /// Wrap an existing keychain with no renewal task.
    pub fn from_keychain_public(keychain: KeyChain) -> Self {
        Self::from_keychain(keychain, None)
    }

    /// Drop the renewal task (if any) and return the keychain.
    pub fn into_keychain(self) -> KeyChain {
        self.keychain
    }

    // ---- principal lifecycle (did:ndn rotation history) ----------------------

    /// Create a principal from `keychain` with recovery **designated at
    /// creation** — the safe default. The keychain's identity is the principal
    /// namespace; its key self-signs the genesis key-state, which pre-commits
    /// `recovery` (the authority that can later recover the principal).
    pub fn create(
        keychain: KeyChain,
        recovery: RecoveryCommitment,
    ) -> Result<Self, IdentityError> {
        Self::genesis(keychain, Some(recovery))
    }

    /// Create a principal **with no recovery authority** — an explicit, loud
    /// escape hatch. If this key is lost, the principal is unrecoverable. Prefer
    /// [`create`](Self::create).
    pub fn create_unrecoverable(keychain: KeyChain) -> Result<Self, IdentityError> {
        Self::genesis(keychain, None)
    }

    fn genesis(
        keychain: KeyChain,
        recovery: Option<RecoveryCommitment>,
    ) -> Result<Self, IdentityError> {
        let did = name_to_did(keychain.name());
        let signer = keychain.signer()?;
        let genesis = build_proof(&did, signer.as_ref(), None, 0, recovery, signer.as_ref())?;
        Ok(Self {
            keychain,
            renewal: None,
            history: vec![genesis],
        })
    }

    /// Rotate the operational key: publish a new key-state signed by the current
    /// key (prior-key authority), carrying the recovery commitment forward, and
    /// swap in `new` as the operational keychain. Requires an existing history
    /// (created via [`create`](Self::create)).
    pub async fn rotate(&mut self, new: KeyChain) -> Result<(), IdentityError> {
        let current = self
            .history
            .last()
            .cloned()
            .ok_or_else(|| IdentityError::Lifecycle("rotate requires a created principal".into()))?;
        let did = name_to_did(self.keychain.name());
        let new_signer = new.signer()?;
        let cur_signer = self.keychain.signer()?;
        let next = build_proof(
            &did,
            new_signer.as_ref(),
            Some(&current),
            current.seq + 1,
            current.recovery.clone(),
            cur_signer.as_ref(),
        )?;
        authorize(&DidDocumentRotation, &current, &next, &TransitionProof::Intrinsic).await?;
        self.history.push(next);
        self.keychain = new;
        Ok(())
    }

    /// Recover a principal whose operational key is lost: given its published
    /// `history`, the pre-committed recovery authority (`recovery_signers`)
    /// authorizes `new` as the operational keychain.
    pub async fn recover(
        history: Vec<IdentityProof>,
        new: KeyChain,
        recovery_signers: &[(usize, &dyn Signer)],
    ) -> Result<Self, IdentityError> {
        let last = history
            .last()
            .ok_or_else(|| IdentityError::Lifecycle("recovery history is empty".into()))?
            .clone();
        let did = name_to_did(new.name());
        let new_signer = new.signer()?;
        // The recovered key-state proves possession by self-signing.
        let next = build_proof(
            &did,
            new_signer.as_ref(),
            Some(&last),
            last.seq + 1,
            last.recovery.clone(),
            new_signer.as_ref(),
        )?;
        let signed = next.canonical_bytes();
        let mut signatures = Vec::with_capacity(recovery_signers.len());
        for (key_index, signer) in recovery_signers {
            signatures.push(RecoverySignature {
                key_index: *key_index,
                signature: signer.sign_sync(&signed)?,
            });
        }
        let proof = TransitionProof::Recovery(RecoveryProof { signatures });
        authorize(&KeyRecovery, &last, &next, &proof).await?;

        let mut history = history;
        history.push(next);
        Ok(Self {
            keychain: new,
            renewal: None,
            history,
        })
    }

    /// Grant a subordinate (device) key a scoped capability under this principal.
    /// Returns the [`Delegation`] describing the grant; issuing the device's
    /// certificate (the verifiable form) is a separate custody step.
    pub fn add_device(&self, device: Name, scope: CapabilitySet) -> Delegation {
        Delegation {
            principal: self.keychain.name().clone(),
            subordinate: device,
            scope,
        }
    }

    // ---- accessors -----------------------------------------------------------

    /// The principal's `did:ndn` URI.
    pub fn did(&self) -> String {
        name_to_did(self.keychain.name())
    }

    /// The current key-state (rotation-history head), if this identity has a
    /// `did:ndn` history. `None` for a plain keychain-backed identity.
    pub fn current_key_state(&self) -> Option<&IdentityProof> {
        self.history.last()
    }

    /// The full rotation history, genesis-first (empty if never created/rotated).
    pub fn history(&self) -> &[IdentityProof] {
        &self.history
    }

    /// Whether the current key-state pre-commits a recovery authority.
    pub fn is_recoverable(&self) -> bool {
        self.history.last().is_some_and(|p| p.recovery.is_some())
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("name", &self.keychain.name().to_string())
            .field("key_name", &self.keychain.key_name().to_string())
            .field("history_len", &self.history.len())
            .finish()
    }
}

/// Build a signed [`IdentityProof`]: a DID Document carrying `doc_signer`'s
/// public key, linked to `parent`, at `seq`, pre-committing `recovery`, signed by
/// `signing`.
fn build_proof(
    did: &str,
    doc_signer: &dyn Signer,
    parent: Option<&IdentityProof>,
    seq: u64,
    recovery: Option<RecoveryCommitment>,
    signing: &dyn Signer,
) -> Result<IdentityProof, IdentityError> {
    let public_key = doc_signer
        .public_key()
        .ok_or_else(|| IdentityError::Lifecycle("signer exposes no public key".into()))?;
    let document = DidDocument::new_simple(did, format!("{did}#key-{seq}"), &public_key);
    let mut proof = IdentityProof {
        document,
        parent_ref: parent.map(|p| p.content_hash()),
        seq,
        recovery,
        sig_value: Bytes::new(),
        sig_type: SignatureType::SignatureEd25519,
    };
    proof.sig_value = signing.sign_sync(&proof.canonical_bytes())?;
    Ok(proof)
}

/// Run a transition authority and map a non-authorization to an error.
async fn authorize(
    authority: &dyn TransitionAuthority,
    prior: &IdentityProof,
    next: &IdentityProof,
    proof: &TransitionProof,
) -> Result<(), IdentityError> {
    match authority
        .authorizes(&KeyState::Did(prior.clone()), &KeyState::Did(next.clone()), proof)
        .await
    {
        AuthorityOutcome::Authorized => Ok(()),
        AuthorityOutcome::Refused(reason) => Err(IdentityError::Lifecycle(reason)),
        AuthorityOutcome::UnknownMethod(method) => Err(IdentityError::Lifecycle(format!(
            "unknown transition method: {method}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_security::Ed25519Signer;

    fn recovery_key(seed: u8) -> ([u8; 32], Ed25519Signer) {
        let s = Ed25519Signer::from_seed(&[seed; 32], "/recovery/KEY/r".parse().unwrap());
        (s.public_key_bytes(), s)
    }

    #[test]
    fn ephemeral_is_a_keychain_with_no_history() {
        let id = Identity::ephemeral("/alice").unwrap();
        // Derefs to KeyChain — signs and verifies like one.
        assert!(id.signer().is_ok());
        assert!(id.did().starts_with("did:ndn:"));
        assert!(id.history().is_empty());
        assert!(!id.is_recoverable());
    }

    #[tokio::test]
    async fn create_then_rotate_grows_a_verifiable_history() {
        let (rk_pub, _rk) = recovery_key(7);
        let kc = KeyChain::ephemeral("/alice").unwrap();
        let mut id = Identity::create(kc, RecoveryCommitment::Key(rk_pub)).unwrap();

        assert_eq!(id.current_key_state().unwrap().seq, 0);
        assert!(id.is_recoverable());

        id.rotate(KeyChain::ephemeral("/alice").unwrap()).await.unwrap();
        assert_eq!(id.current_key_state().unwrap().seq, 1);
        assert_eq!(id.history().len(), 2);

        // The whole history verifies as a rotation chain.
        let chain: Vec<KeyState> = id.history().iter().cloned().map(KeyState::Did).collect();
        let head = crate::resolve_chain(&DidDocumentRotation, &chain).await.unwrap();
        match head {
            KeyState::Did(p) => assert_eq!(p.seq, 1),
            _ => panic!("did head"),
        }
    }

    #[tokio::test]
    async fn recover_installs_a_new_key_via_the_committed_authority() {
        let (rk_pub, rk) = recovery_key(7);
        let id =
            Identity::create(KeyChain::ephemeral("/alice").unwrap(), RecoveryCommitment::Key(rk_pub))
                .unwrap();
        let published = id.history().to_vec();

        // The committed recovery key authorizes a fresh operational keychain.
        let recovered =
            Identity::recover(published, KeyChain::ephemeral("/alice").unwrap(), &[(0, &rk)])
                .await
                .unwrap();
        assert_eq!(recovered.current_key_state().unwrap().seq, 1);

        // A stranger's key cannot recover.
        let id2 =
            Identity::create(KeyChain::ephemeral("/bob").unwrap(), RecoveryCommitment::Key(rk_pub))
                .unwrap();
        let stranger = Ed25519Signer::from_seed(&[9; 32], "/evil/KEY/x".parse().unwrap());
        let err = Identity::recover(
            id2.history().to_vec(),
            KeyChain::ephemeral("/bob").unwrap(),
            &[(0, &stranger)],
        )
        .await;
        assert!(matches!(err, Err(IdentityError::Lifecycle(_))));
    }

    #[test]
    fn add_device_scopes_a_grant_under_the_principal() {
        let (rk_pub, _) = recovery_key(7);
        let id =
            Identity::create(KeyChain::ephemeral("/alice").unwrap(), RecoveryCommitment::Key(rk_pub))
                .unwrap();
        let scope = CapabilitySet {
            sign: vec![crate::trust_context::pattern_under(
                &"/alice/device/phone".parse().unwrap(),
            )],
            ..Default::default()
        };
        let grant = id.add_device("/alice/device/phone".parse().unwrap(), scope);
        assert_eq!(grant.principal, "/alice".parse::<Name>().unwrap());
        assert!(grant.may_sign(&"/alice/device/phone/data".parse().unwrap()));
    }
}
