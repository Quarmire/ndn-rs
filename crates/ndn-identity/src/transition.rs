//! Key-state transitions — the rotation ∪ recovery frame.
//!
//! A stable identity's key-state changes only through an **authorized
//! transition**. Ordinary rotation and recovery are the *same* operation,
//! differing only in *who authorizes* it — so they share one trait,
//! [`TransitionAuthority`], over one [`KeyState`].
//!
//! Two rotation impls ship, at the two layers from the design note §11
//! cross-reference:
//!
//! - [`CertRotation`] — the canonical NDN floor: the prior key signed the new
//!   key's certificate. No new wire convention; this is how ndn-cxx / ndnd
//!   already express a key reissued under a prior key.
//! - [`DidDocumentRotation`] — the `did:ndn` extension: a content-addressed
//!   chain of [`IdentityProof`]s (a verifiable rotation *history*), aligned with
//!   ndf-rs's `Kind::Sovereignty` IdentityProof so ndf builds on it unchanged.
//!
//! Recovery methods are later impls of the same trait.

use async_trait::async_trait;
use ndn_packet::Name;

use bytes::Bytes;

use ndn_security::verifier::verify_by_sig_type;
use ndn_security::{Certificate, IdentityProof, RecoveryCommitment, VerifyOutcome};

/// Identifies how a transition is authorized (`"cert-rotation"`,
/// `"did-rotation"`, `"key-recovery"`, and later others). New methods are added
/// over time.
pub type MethodId = str;

/// How a transition is proven, supplied alongside the key-states.
///
/// Rotation's proof is *intrinsic* — it is the new key-state's own signature
/// (the prior key signed it), so [`Intrinsic`](Self::Intrinsic) carries nothing.
/// Recovery's proof is *extrinsic*: the lost operational key cannot sign, so the
/// pre-committed recovery authority's signatures arrive separately in
/// [`Recovery`](Self::Recovery).
#[derive(Debug, Clone, Default)]
pub enum TransitionProof {
    /// The proof is the new key-state's own signature. Used by rotation.
    #[default]
    Intrinsic,
    /// Signatures by the pre-committed recovery authority. Used by recovery.
    Recovery(RecoveryProof),
}

/// Signatures by a pre-committed recovery authority over the new key-state's
/// canonical bytes. Each entry indexes a committed quorum key (index `0` for a
/// single [`RecoveryCommitment::Key`]).
#[derive(Debug, Clone, Default)]
pub struct RecoveryProof {
    pub signatures: Vec<RecoverySignature>,
}

/// One recovery signature: which committed key produced it, and the signature.
#[derive(Debug, Clone)]
pub struct RecoverySignature {
    /// Index into the commitment's key list (`0` for a single key).
    pub key_index: usize,
    /// Ed25519 signature over the new key-state's `canonical_bytes()`.
    pub signature: Bytes,
}

/// A published key-state — the unit a [`TransitionAuthority`] reasons over.
///
/// `Cert` is the canonical NDN floor (an interop-safe certificate); `Did` is the
/// `did:ndn` rotation-chain link (the verifiable-history extension). An authority
/// understands one variant and refuses the other.
// The `Did` variant is larger (it embeds a W3C DID Document); we keep both
// inline rather than box because `KeyState` is constructed at call sites and
// passed by reference into authorities — ergonomics over the few saved bytes.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum KeyState {
    /// A canonical NDN certificate key-state.
    Cert(Certificate),
    /// A `did:ndn` rotation-chain link.
    Did(IdentityProof),
}

/// The verdict of a [`TransitionAuthority`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityOutcome {
    /// The authority authorized the transition `prior → next`.
    Authorized,
    /// The authority rejected it, with a reason.
    Refused(String),
    /// No authority understood the requested method — **abstain**, do not
    /// reject. Forward-compat (crypto-agility shape): an old verifier seeing a
    /// future method must not treat it as invalid.
    UnknownMethod(String),
}

/// Who may authorize a transition of an identity's key-state from `prior` to
/// `next`. Rotation's authority is the prior operational key; recovery's is a
/// pre-committed out-of-band authority (a later impl). All share this trait so
/// one [`TransitionVerifier`] dispatches across them by method.
#[async_trait]
pub trait TransitionAuthority: Send + Sync {
    /// The method this authority implements (its [`MethodId`]).
    fn method_id(&self) -> &str;

    /// Decide whether this authority authorizes the transition `prior → next`,
    /// given `proof`. Rotation authorities use the intrinsic proof (the new
    /// key-state's own signature); recovery authorities read
    /// [`TransitionProof::Recovery`].
    async fn authorizes(
        &self,
        prior: &KeyState,
        next: &KeyState,
        proof: &TransitionProof,
    ) -> AuthorityOutcome;
}

/// **Canonical NDN key rotation:** the prior key signed the new key's
/// certificate. A rotation is an NDN cert for the *same* identity, a *different*
/// key, whose `KeyLocator` names the prior key and whose signature verifies
/// under it. No new wire format — this is exactly how ndn-cxx / ndnd express a
/// key being reissued under a prior key.
pub struct CertRotation;

#[async_trait]
impl TransitionAuthority for CertRotation {
    fn method_id(&self) -> &str {
        "cert-rotation"
    }

    async fn authorizes(
        &self,
        prior: &KeyState,
        next: &KeyState,
        _proof: &TransitionProof,
    ) -> AuthorityOutcome {
        let (KeyState::Cert(prior), KeyState::Cert(next)) = (prior, next) else {
            return AuthorityOutcome::Refused(
                "cert-rotation requires certificate key-states".into(),
            );
        };

        // 1. A rotation stays within the same identity (namespace).
        let (Some(prior_id), Some(next_id)) = (identity_of(&prior.name), identity_of(&next.name))
        else {
            return AuthorityOutcome::Refused("certificate name has no KEY component".into());
        };
        if prior_id != next_id {
            return AuthorityOutcome::Refused(format!(
                "rotation must stay in the same identity: {prior_id} → {next_id}"
            ));
        }

        // 2. It must be a *new* key — not the same cert re-presented.
        let (Some(prior_key), Some(next_key)) = (key_name_of(&prior.name), key_name_of(&next.name))
        else {
            return AuthorityOutcome::Refused("malformed key name".into());
        };
        if prior_key == next_key {
            return AuthorityOutcome::Refused("not a rotation: same key".into());
        }

        // 3. The new cert must be issued by the prior *key* (KeyLocator), not
        //    self-signed and not issued by anyone else.
        let Some(issuer) = next.issuer.as_ref() else {
            return AuthorityOutcome::Refused(
                "new certificate is self-signed, not issued by the prior key".into(),
            );
        };
        match key_name_of(issuer) {
            Some(issuer_key) if issuer_key == prior_key => {}
            _ => {
                return AuthorityOutcome::Refused(format!(
                    "new key not issued by the prior key (issuer {issuer})"
                ));
            }
        }

        // 4. The continuity signature verifies under the prior key.
        let (Some(region), Some(sig)) = (next.signed_region.as_ref(), next.sig_value.as_ref())
        else {
            return AuthorityOutcome::Refused("new certificate carries no signature".into());
        };
        match verify_by_sig_type(next.sig_type, region, sig, &prior.public_key).await {
            Ok(VerifyOutcome::Valid) => AuthorityOutcome::Authorized,
            Ok(VerifyOutcome::Invalid) => AuthorityOutcome::Refused(
                "continuity signature does not verify under the prior key".into(),
            ),
            Err(e) => AuthorityOutcome::Refused(format!("verify error: {e}")),
        }
    }
}

/// **`did:ndn` rotation history:** the next [`IdentityProof`] is the same DID
/// subject, the next monotonic sequence, content-addressed back to its
/// predecessor (`parent_ref == prior.content_hash()`), bears a *new* key, and is
/// signed by the prior key. Linking a chain of these yields a verifiable
/// rotation history (see [`resolve_chain`]). Aligned with ndf-rs's IdentityProof.
pub struct DidDocumentRotation;

#[async_trait]
impl TransitionAuthority for DidDocumentRotation {
    fn method_id(&self) -> &str {
        "did-rotation"
    }

    async fn authorizes(
        &self,
        prior: &KeyState,
        next: &KeyState,
        _proof: &TransitionProof,
    ) -> AuthorityOutcome {
        let (KeyState::Did(prior), KeyState::Did(next)) = (prior, next) else {
            return AuthorityOutcome::Refused("did-rotation requires did:ndn key-states".into());
        };

        // 1. Same DID subject — a rotation changes the key, not the identity.
        if prior.document.id != next.document.id {
            return AuthorityOutcome::Refused(format!(
                "rotation must keep the same DID subject: {} → {}",
                prior.document.id, next.document.id
            ));
        }

        // 2. Strictly monotonic sequence (no gaps, no replays).
        if next.seq != prior.seq.saturating_add(1) {
            return AuthorityOutcome::Refused(format!(
                "non-monotonic sequence: {} → {}",
                prior.seq, next.seq
            ));
        }

        // 3. Content-addressed back-link to the predecessor.
        if next.parent_ref != Some(prior.content_hash()) {
            return AuthorityOutcome::Refused(
                "parent_ref does not match the predecessor's content hash".into(),
            );
        }

        // 4. A genuinely new operational key.
        let (Some(prior_key), Some(next_key)) = (
            prior.document.ed25519_public_key(),
            next.document.ed25519_public_key(),
        ) else {
            return AuthorityOutcome::Refused(
                "DID document has no Ed25519 verification method".into(),
            );
        };
        if prior_key == next_key {
            return AuthorityOutcome::Refused("not a rotation: same key".into());
        }

        // 5. The continuity signature verifies under the prior key.
        match verify_by_sig_type(
            next.sig_type,
            &next.canonical_bytes(),
            &next.sig_value,
            &prior_key,
        )
        .await
        {
            Ok(VerifyOutcome::Valid) => AuthorityOutcome::Authorized,
            Ok(VerifyOutcome::Invalid) => AuthorityOutcome::Refused(
                "continuity signature does not verify under the prior key".into(),
            ),
            Err(e) => AuthorityOutcome::Refused(format!("verify error: {e}")),
        }
    }
}

/// **Key recovery:** a transition authorized not by the lost operational key but
/// by the recovery authority the *prior* key-state pre-committed
/// ([`IdentityProof::recovery`]). The four recovery invariants are enforced
/// structurally: the authority is (1) not the operational key, (2) pre-committed
/// (read from `prior`, signed into its canonical bytes before loss),
/// (3) out-of-band (its own keys), and (4) method-tagged (`"key-recovery"`, so an
/// old verifier abstains on future recovery methods).
///
/// Continuity is still proven — same DID subject, monotonic seq, `parent_ref`
/// back to `prior` — so a recovery is a normal link in the rotation history,
/// distinguished only by who signed it. Handles both a single
/// [`RecoveryCommitment::Key`] and an m-of-n [`RecoveryCommitment::Quorum`].
pub struct KeyRecovery;

#[async_trait]
impl TransitionAuthority for KeyRecovery {
    fn method_id(&self) -> &str {
        "key-recovery"
    }

    async fn authorizes(
        &self,
        prior: &KeyState,
        next: &KeyState,
        proof: &TransitionProof,
    ) -> AuthorityOutcome {
        let (KeyState::Did(prior), KeyState::Did(next)) = (prior, next) else {
            return AuthorityOutcome::Refused("key-recovery requires did:ndn key-states".into());
        };
        let TransitionProof::Recovery(recovery) = proof else {
            return AuthorityOutcome::Refused(
                "key-recovery needs a recovery proof, not the intrinsic signature".into(),
            );
        };

        // Continuity, identical to a rotation link.
        if prior.document.id != next.document.id {
            return AuthorityOutcome::Refused(format!(
                "recovery must keep the same DID subject: {} → {}",
                prior.document.id, next.document.id
            ));
        }
        if next.seq != prior.seq.saturating_add(1) {
            return AuthorityOutcome::Refused(format!(
                "non-monotonic sequence: {} → {}",
                prior.seq, next.seq
            ));
        }
        if next.parent_ref != Some(prior.content_hash()) {
            return AuthorityOutcome::Refused(
                "parent_ref does not match the predecessor's content hash".into(),
            );
        }

        // The recovery authority must have been pre-committed in `prior`.
        let Some(commitment) = prior.recovery.as_ref() else {
            return AuthorityOutcome::Refused(
                "no recovery authority was pre-committed by the prior key-state".into(),
            );
        };

        // The new operational key must differ from the lost one.
        match (
            prior.document.ed25519_public_key(),
            next.document.ed25519_public_key(),
        ) {
            (Some(p), Some(n)) if p == n => {
                return AuthorityOutcome::Refused("not a recovery: same key".into());
            }
            (_, None) => {
                return AuthorityOutcome::Refused(
                    "new DID document has no Ed25519 verification method".into(),
                );
            }
            _ => {}
        }

        // The recovery signatures must satisfy the pre-committed authority over
        // the new key-state's canonical bytes.
        let signed = next.canonical_bytes();
        match commitment {
            RecoveryCommitment::Key(key) => {
                if verify_any(recovery, &[*key], &signed).await >= 1 {
                    AuthorityOutcome::Authorized
                } else {
                    AuthorityOutcome::Refused(
                        "recovery signature does not verify under the committed key".into(),
                    )
                }
            }
            RecoveryCommitment::Quorum { keys, threshold } => {
                let valid = verify_any(recovery, keys, &signed).await;
                if valid >= *threshold {
                    AuthorityOutcome::Authorized
                } else {
                    AuthorityOutcome::Refused(format!(
                        "quorum not met: {valid} of {threshold} required recovery signatures valid"
                    ))
                }
            }
        }
    }
}

/// Count the distinct committed keys for which `recovery` carries a valid
/// signature over `signed`. Each committed key is credited at most once.
async fn verify_any(recovery: &RecoveryProof, keys: &[[u8; 32]], signed: &[u8]) -> usize {
    let mut credited = vec![false; keys.len()];
    for sig in &recovery.signatures {
        let Some(key) = keys.get(sig.key_index) else {
            continue;
        };
        if credited[sig.key_index] {
            continue;
        }
        if matches!(
            verify_by_sig_type(
                ndn_packet::SignatureType::SignatureEd25519,
                signed,
                &sig.signature,
                key,
            )
            .await,
            Ok(VerifyOutcome::Valid)
        ) {
            credited[sig.key_index] = true;
        }
    }
    credited.iter().filter(|c| **c).count()
}

/// Why resolving a rotation chain failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// The chain had no links.
    Empty,
    /// Link `index` was not authorized by its predecessor.
    BrokenLink {
        index: usize,
        outcome: AuthorityOutcome,
    },
}

/// Verify an ordered rotation chain (genesis first) under `authority` and return
/// the current (head) key-state. Each non-genesis link must be authorized by its
/// immediate predecessor; the genesis link (index 0) is the chain's trusted root
/// and is not re-authorized here.
///
/// Links are verified with the *intrinsic* proof — this resolves rotation
/// histories. A recovery link (which needs an extrinsic [`RecoveryProof`]) is
/// verified individually via the authority's [`authorizes`](TransitionAuthority::authorizes).
pub async fn resolve_chain<'a>(
    authority: &dyn TransitionAuthority,
    chain: &'a [KeyState],
) -> Result<&'a KeyState, ChainError> {
    let Some(head) = chain.last() else {
        return Err(ChainError::Empty);
    };
    for index in 1..chain.len() {
        match authority
            .authorizes(
                &chain[index - 1],
                &chain[index],
                &TransitionProof::Intrinsic,
            )
            .await
        {
            AuthorityOutcome::Authorized => {}
            outcome => return Err(ChainError::BrokenLink { index, outcome }),
        }
    }
    Ok(head)
}

/// Dispatches a transition to the [`TransitionAuthority`] for its declared
/// method, **abstaining** ([`AuthorityOutcome::UnknownMethod`]) when no
/// authority is registered for it — so a verifier that predates a method never
/// hard-rejects a transition it simply cannot evaluate.
#[derive(Default)]
pub struct TransitionVerifier {
    authorities: std::collections::HashMap<String, Box<dyn TransitionAuthority>>,
}

impl TransitionVerifier {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, authority: Box<dyn TransitionAuthority>) {
        self.authorities
            .insert(authority.method_id().to_string(), authority);
    }

    /// Verify the transition `prior → next` claimed under `method`, with `proof`.
    pub async fn verify(
        &self,
        method: &MethodId,
        prior: &KeyState,
        next: &KeyState,
        proof: &TransitionProof,
    ) -> AuthorityOutcome {
        match self.authorities.get(method) {
            Some(authority) => authority.authorizes(prior, next, proof).await,
            None => AuthorityOutcome::UnknownMethod(method.to_string()),
        }
    }
}

/// The identity (namespace) a key/cert name belongs to: everything before the
/// `KEY` component. `/alice/KEY/k1/<issuer>/<v>` → `/alice`.
pub(crate) fn identity_of(name: &Name) -> Option<Name> {
    let pos = key_component_pos(name)?;
    Some(Name::from_components(
        name.components()[..pos].iter().cloned(),
    ))
}

/// The key name (`<identity>/KEY/<keyid>`) of a key/cert name.
pub(crate) fn key_name_of(name: &Name) -> Option<Name> {
    let pos = key_component_pos(name)?;
    // identity components, then KEY (pos), then keyid (pos+1).
    if name.components().len() < pos + 2 {
        return None;
    }
    Some(Name::from_components(
        name.components()[..pos + 2].iter().cloned(),
    ))
}

fn key_component_pos(name: &Name) -> Option<usize> {
    name.components()
        .iter()
        .rposition(|c| c.value.as_ref() == b"KEY")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ndn_packet::SignatureType;
    use ndn_security::{DidDocument, Ed25519Signer, SecurityManager, Signer};

    // ---- canonical-floor (Certificate) fixtures -------------------------------

    /// (k1 self-signed genesis, k2 rotated-from-k1, k2 forged-by-attacker,
    /// bob's cert issued by alice's k1 — cross-identity).
    async fn cert_fixtures() -> (Certificate, Certificate, Certificate, Certificate) {
        let mgr = SecurityManager::new();
        let make_key = |name: &str| -> (Name, Bytes) {
            let n: Name = name.parse().unwrap();
            mgr.generate_ed25519(n.clone()).unwrap();
            let pk = mgr.get_signer_sync(&n).unwrap().public_key().unwrap();
            (n, pk)
        };

        let (k1, k1_pub) = make_key("/alice/KEY/k1");
        let k1_cert = mgr.issue_self_signed(&k1, k1_pub, u64::MAX).unwrap();

        let (k2, k2_pub) = make_key("/alice/KEY/k2");
        let k2_cert = mgr
            .certify(&k2, k2_pub.clone(), &k1, 31_536_000_000)
            .await
            .unwrap();

        let (evil, _) = make_key("/evil/KEY/x");
        let k2_forged = mgr
            .certify(&k2, k2_pub, &evil, 31_536_000_000)
            .await
            .unwrap();

        let (bob, bob_pub) = make_key("/bob/KEY/k1");
        let bob_cert = mgr
            .certify(&bob, bob_pub, &k1, 31_536_000_000)
            .await
            .unwrap();

        (k1_cert, k2_cert, k2_forged, bob_cert)
    }

    // ---- did:ndn rotation-chain fixtures --------------------------------------

    fn signer(seed: u8) -> Ed25519Signer {
        Ed25519Signer::from_seed(&[seed; 32], format!("/alice/KEY/k{seed}").parse().unwrap())
    }

    /// Build an [`IdentityProof`] for `did` whose document carries `doc_key`'s
    /// public key, linked to `parent`, at `seq`, pre-committing `recovery`, signed
    /// by `signing_key`.
    fn build_proof(
        did: &str,
        doc_key: &Ed25519Signer,
        parent: Option<&IdentityProof>,
        seq: u64,
        recovery: Option<RecoveryCommitment>,
        signing_key: &Ed25519Signer,
    ) -> IdentityProof {
        let document =
            DidDocument::new_simple(did, format!("{did}#key-{seq}"), &doc_key.public_key_bytes());
        let mut proof = IdentityProof {
            document,
            parent_ref: parent.map(|p| p.content_hash()),
            seq,
            recovery,
            sig_value: Bytes::new(),
            sig_type: SignatureType::SignatureEd25519,
        };
        proof.sig_value = signing_key.sign_sync(&proof.canonical_bytes()).unwrap();
        proof
    }

    const INTRINSIC: &TransitionProof = &TransitionProof::Intrinsic;

    // ---- witnesses ------------------------------------------------------------

    #[tokio::test]
    async fn cert_rotation_authorizes_only_a_prior_key_signed_rotation() {
        let (k1, k2, k2_forged, bob) = cert_fixtures().await;
        let rot = CertRotation;
        let cert = KeyState::Cert;

        // Genuine rotation: k2 issued by k1.
        assert_eq!(
            rot.authorizes(&cert(k1.clone()), &cert(k2), INTRINSIC)
                .await,
            AuthorityOutcome::Authorized
        );
        // Forged: k2 issued by an attacker, not the prior key.
        assert!(matches!(
            rot.authorizes(&cert(k1.clone()), &cert(k2_forged), INTRINSIC)
                .await,
            AuthorityOutcome::Refused(_)
        ));
        // Cross-identity: bob's key issued by alice's k1 is not alice's rotation.
        assert!(matches!(
            rot.authorizes(&cert(k1.clone()), &cert(bob), INTRINSIC)
                .await,
            AuthorityOutcome::Refused(_)
        ));
        // Not a rotation: the same key.
        assert!(matches!(
            rot.authorizes(&cert(k1.clone()), &cert(k1), INTRINSIC)
                .await,
            AuthorityOutcome::Refused(_)
        ));
    }

    #[tokio::test]
    async fn did_rotation_authorizes_chain_and_rejects_tampering() {
        let did = "did:ndn:alice";
        let (k0, k1) = (signer(0), signer(1));
        let genesis = build_proof(did, &k0, None, 0, None, &k0); // self-signed genesis
        let rot1 = build_proof(did, &k1, Some(&genesis), 1, None, &k0); // signed by prior k0
        let rot = DidDocumentRotation;
        let did_state = KeyState::Did;

        // Genuine rotation.
        assert_eq!(
            rot.authorizes(
                &did_state(genesis.clone()),
                &did_state(rot1.clone()),
                INTRINSIC
            )
            .await,
            AuthorityOutcome::Authorized
        );

        // Forged: rot1 signed by an attacker key (k9), not the prior k0.
        let forged = build_proof(did, &k1, Some(&genesis), 1, None, &signer(9));
        assert!(matches!(
            rot.authorizes(&did_state(genesis.clone()), &did_state(forged), INTRINSIC)
                .await,
            AuthorityOutcome::Refused(_)
        ));

        // Broken back-link: parent_ref points nowhere.
        let mut bad_parent = rot1.clone();
        bad_parent.parent_ref = Some([0u8; 32]);
        assert!(matches!(
            rot.authorizes(
                &did_state(genesis.clone()),
                &did_state(bad_parent),
                INTRINSIC
            )
            .await,
            AuthorityOutcome::Refused(_)
        ));

        // Sequence gap: seq jumps past genesis+1.
        let gap = build_proof(did, &k1, Some(&genesis), 5, None, &k0);
        assert!(matches!(
            rot.authorizes(&did_state(genesis.clone()), &did_state(gap), INTRINSIC)
                .await,
            AuthorityOutcome::Refused(_)
        ));

        // Wrong key-state type: a cert handed to the did authority.
        let (cert, ..) = cert_fixtures().await;
        assert!(matches!(
            rot.authorizes(
                &KeyState::Cert(cert.clone()),
                &KeyState::Cert(cert),
                INTRINSIC
            )
            .await,
            AuthorityOutcome::Refused(_)
        ));
    }

    #[tokio::test]
    async fn resolve_chain_verifies_full_history_and_locates_head() {
        let did = "did:ndn:alice";
        let (k0, k1, k2) = (signer(0), signer(1), signer(2));
        let genesis = build_proof(did, &k0, None, 0, None, &k0);
        let rot1 = build_proof(did, &k1, Some(&genesis), 1, None, &k0);
        let rot2 = build_proof(did, &k2, Some(&rot1), 2, None, &k1);

        let chain = vec![
            KeyState::Did(genesis),
            KeyState::Did(rot1),
            KeyState::Did(rot2.clone()),
        ];
        let head = resolve_chain(&DidDocumentRotation, &chain).await.unwrap();
        match head {
            KeyState::Did(proof) => assert_eq!(proof.seq, rot2.seq),
            _ => panic!("head should be a did key-state"),
        }

        // A chain with a tampered middle link fails at that index.
        let (k0b, k1b, k2b) = (signer(0), signer(1), signer(2));
        let g = build_proof(did, &k0b, None, 0, None, &k0b);
        let mut r1 = build_proof(did, &k1b, Some(&g), 1, None, &k0b);
        r1.seq = 7; // breaks monotonicity relative to genesis
        let r2 = build_proof(did, &k2b, Some(&r1), 2, None, &k1b);
        let broken = vec![KeyState::Did(g), KeyState::Did(r1), KeyState::Did(r2)];
        assert!(matches!(
            resolve_chain(&DidDocumentRotation, &broken).await,
            Err(ChainError::BrokenLink { index: 1, .. })
        ));
    }

    #[tokio::test]
    async fn verifier_dispatches_across_layers_and_abstains_on_unknown_method() {
        let (k1, k2, ..) = cert_fixtures().await;
        let did = "did:ndn:alice";
        let (s0, s1) = (signer(0), signer(1));
        let genesis = build_proof(did, &s0, None, 0, None, &s0);
        let rot1 = build_proof(did, &s1, Some(&genesis), 1, None, &s0);

        let mut v = TransitionVerifier::new();
        v.register(Box::new(CertRotation));
        v.register(Box::new(DidDocumentRotation));

        // Each method dispatches to the right authority over the right key-state.
        assert_eq!(
            v.verify(
                "cert-rotation",
                &KeyState::Cert(k1),
                &KeyState::Cert(k2),
                INTRINSIC
            )
            .await,
            AuthorityOutcome::Authorized
        );
        assert_eq!(
            v.verify(
                "did-rotation",
                &KeyState::Did(genesis.clone()),
                &KeyState::Did(rot1.clone()),
                INTRINSIC
            )
            .await,
            AuthorityOutcome::Authorized
        );
        // A method this verifier doesn't know → abstain, not reject.
        assert!(matches!(
            v.verify(
                "x.future-pq-method",
                &KeyState::Did(genesis),
                &KeyState::Did(rot1),
                INTRINSIC
            )
            .await,
            AuthorityOutcome::UnknownMethod(_)
        ));
    }

    // ---- recovery -------------------------------------------------------------

    /// A recovery `next` proof: the document carries `new_key`, links back to
    /// `prior`, and is *self*-signed (the new key proves possession). The recovery
    /// authority's signatures are returned separately as the [`RecoveryProof`].
    fn recovery_next(
        did: &str,
        new_key: &Ed25519Signer,
        prior: &IdentityProof,
        recoverers: &[(usize, &Ed25519Signer)],
    ) -> (IdentityProof, RecoveryProof) {
        let next = build_proof(did, new_key, Some(prior), prior.seq + 1, None, new_key);
        let signed = next.canonical_bytes();
        let signatures = recoverers
            .iter()
            .map(|(idx, signer)| RecoverySignature {
                key_index: *idx,
                signature: signer.sign_sync(&signed).unwrap(),
            })
            .collect();
        (next, RecoveryProof { signatures })
    }

    #[tokio::test]
    async fn key_recovery_accepts_committed_authority_and_rejects_otherwise() {
        let did = "did:ndn:alice";
        let (op, recovery_key, attacker, new_op) = (signer(0), signer(7), signer(9), signer(1));

        // Genesis pre-commits a single recovery key (held offline).
        let commitment = RecoveryCommitment::Key(recovery_key.public_key_bytes());
        let genesis = build_proof(did, &op, None, 0, Some(commitment), &op);

        let rec = KeyRecovery;

        // Genuine recovery: operational key lost, the committed recovery key
        // authorizes a new operational key.
        let (next, proof) = recovery_next(did, &new_op, &genesis, &[(0, &recovery_key)]);
        assert_eq!(
            rec.authorizes(
                &KeyState::Did(genesis.clone()),
                &KeyState::Did(next),
                &TransitionProof::Recovery(proof)
            )
            .await,
            AuthorityOutcome::Authorized
        );

        // Wrong signer: an attacker's signature does not satisfy the commitment.
        let (next2, bad) = recovery_next(did, &new_op, &genesis, &[(0, &attacker)]);
        assert!(matches!(
            rec.authorizes(
                &KeyState::Did(genesis.clone()),
                &KeyState::Did(next2),
                &TransitionProof::Recovery(bad)
            )
            .await,
            AuthorityOutcome::Refused(_)
        ));

        // Intrinsic proof is not a recovery proof.
        let (next3, _) = recovery_next(did, &new_op, &genesis, &[(0, &recovery_key)]);
        assert!(matches!(
            rec.authorizes(&KeyState::Did(genesis), &KeyState::Did(next3), INTRINSIC)
                .await,
            AuthorityOutcome::Refused(_)
        ));
    }

    #[tokio::test]
    async fn quorum_recovery_requires_threshold_distinct_signers() {
        let did = "did:ndn:bob";
        let (op, new_op) = (signer(0), signer(1));
        let guardians = [signer(10), signer(11), signer(12)];

        // Genesis pre-commits a 2-of-3 quorum.
        let commitment = RecoveryCommitment::Quorum {
            keys: guardians.iter().map(|g| g.public_key_bytes()).collect(),
            threshold: 2,
        };
        let genesis = build_proof(did, &op, None, 0, Some(commitment), &op);
        let rec = KeyRecovery;

        // Two distinct guardians → quorum met.
        let (next, proof) = recovery_next(
            did,
            &new_op,
            &genesis,
            &[(0, &guardians[0]), (1, &guardians[1])],
        );
        assert_eq!(
            rec.authorizes(
                &KeyState::Did(genesis.clone()),
                &KeyState::Did(next),
                &TransitionProof::Recovery(proof)
            )
            .await,
            AuthorityOutcome::Authorized
        );

        // One guardian (and a duplicate of it) → quorum not met.
        let (next2, proof2) = recovery_next(
            did,
            &new_op,
            &genesis,
            &[(0, &guardians[0]), (0, &guardians[0])],
        );
        assert!(matches!(
            rec.authorizes(
                &KeyState::Did(genesis),
                &KeyState::Did(next2),
                &TransitionProof::Recovery(proof2)
            )
            .await,
            AuthorityOutcome::Refused(_)
        ));
    }
}
