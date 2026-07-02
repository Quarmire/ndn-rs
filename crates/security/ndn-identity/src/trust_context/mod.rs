//! `TrustContext` — portable identity bundle, decoupled from any one engine.
//!
//! The synthesis runtime object (`.claude/notes/trust-context/synthesis-engine-identity-namespaces-2026-05-25.md`
//! §2). Composes the wire-canonical [`ndn_security::SignedTrustContext`] (anchors,
//! schema, version, CA endpoints) with the new identity-side metadata: held
//! [`IdentityRef`]s, [`AdoptionProvenance`], optional sync namespace, and
//! preferred publish-side `ForwardingHint` names.

use std::sync::Arc;
use std::time::SystemTime;

use ndn_packet::{Data, Name};
use ndn_security::safe_data::TrustPath;
use ndn_security::{Certificate, NamePattern, TrustSchema, ValidationResult, Validator};

use ndn_security::custodian::CustodianRef;

pub mod context_sync;
mod fingerprint;
mod identity_ref;
mod provenance;
mod sync;
pub mod sync_tlv;

pub use context_sync::{BundleFetcher, ContextSyncOutcome, process_update};
pub use fingerprint::Fingerprint;
pub use identity_ref::{CapabilitySet, IdentityLifetime, IdentityRef, KeyId};
pub use provenance::{AdoptionProvenance, FaceIdRef};
pub use sync::{SyncBundle, SyncBundleError};

/// Error surface for portable-context operations (identity lookup, signing
/// authorization decisions, sync export/import).
#[derive(Debug, thiserror::Error)]
#[allow(clippy::large_enum_variant)]
pub enum TrustContextError {
    #[error("no identity in this context can sign {0}")]
    NoSigner(Name),
    #[error("custodian unavailable: {0}")]
    CustodianUnavailable(String),
    #[error("custodian error: {0}")]
    Custodian(String),
    #[error("schema rejected ({data} ← {key})")]
    SchemaRejected { data: Name, key: Name },
    #[error("wire context error: {0}")]
    Wire(#[from] ndn_security::SignedTrustContextError),
}

/// The result of `verify` — either OK with the chain that anchored the data,
/// or a reason it was rejected.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum VerificationOutcome {
    Verified { anchor: Name },
    Rejected(String),
}

/// A trust domain: a name scope with the material needed to verify inside it
/// and (optionally) sign within it. Held by a custodian; replicated across a
/// user's devices via context-sync (Phase 2).
#[derive(Debug, Clone)]
pub struct TrustContext {
    pub name: Name,
    pub anchors: Vec<Certificate>,
    pub schema: TrustSchema,
    pub identities: Vec<IdentityRef>,
    pub ca_endpoints: Vec<Name>,
    pub sync_namespace: Option<Name>,
    pub publish_hints: Vec<Name>,
    pub provenance: AdoptionProvenance,
}

impl TrustContext {
    /// Empty adopted-only context at `name` with no anchors yet.
    pub fn adopted(name: Name, scanned_at: SystemTime, scanner_id: impl Into<String>) -> Self {
        Self {
            name,
            anchors: Vec::new(),
            schema: TrustSchema::accept_all(),
            identities: Vec::new(),
            ca_endpoints: Vec::new(),
            sync_namespace: None,
            publish_hints: Vec::new(),
            provenance: AdoptionProvenance::TofuRoot {
                scanned_at,
                scanner_id: scanner_id.into(),
            },
        }
    }

    /// Implicit `/` root context backing legacy flat-anchor state. See
    /// `LegacyRootBuilder` for the migration helper used by the engine and
    /// dashboard at first run.
    pub fn legacy_root(anchors: Vec<Certificate>) -> Self {
        Self {
            name: Name::root(),
            anchors,
            schema: TrustSchema::accept_all(),
            identities: Vec::new(),
            ca_endpoints: Vec::new(),
            sync_namespace: None,
            publish_hints: Vec::new(),
            provenance: AdoptionProvenance::Replicated {
                from_device: Name::root(),
                at: SystemTime::now(),
            },
        }
    }

    /// First identity whose capability `sign` patterns cover `name`. Returns
    /// `None` for adopted-only contexts (no identities held) or names outside
    /// every held identity's scope.
    pub fn can_sign(&self, name: &Name) -> Option<&IdentityRef> {
        self.identities.iter().find(|id| {
            id.capabilities
                .sign
                .iter()
                .any(|pat| pattern_matches(pat, name))
        })
    }

    /// Sign `name` + `content` via the first identity in this context that
    /// covers `name`, asking its custodian. `Result::Err` if no identity can
    /// sign or the custodian rejects.
    pub async fn sign(
        &self,
        name: &Name,
        content: &[u8],
        custodians: &ndn_security::custodian::CustodianRegistry,
    ) -> Result<bytes::Bytes, TrustContextError> {
        let id = self
            .can_sign(name)
            .ok_or_else(|| TrustContextError::NoSigner(name.clone()))?;
        let custodian = custodians.get(&id.custodian).ok_or_else(|| {
            TrustContextError::CustodianUnavailable(format!("{:?}", id.custodian))
        })?;
        custodian
            .sign(&id.key_id, name, content)
            .await
            .map_err(|e| TrustContextError::Custodian(e.to_string()))
    }

    /// Verify `data` against this context's anchors + schema, returning the
    /// anchor it chained to or a rejection reason. Read-only; does not touch the
    /// network (resolution operates over the locally-known anchors).
    ///
    /// An adopted-only context (no anchors) rejects everything — there is
    /// nothing to chain to, so it fails closed. A `DigestSha256`-only packet is
    /// rejected as unauthenticated (integrity, not identity), consistent with
    /// the consumer policy ([`Unverified::verify`](ndn_security::Unverified)).
    pub async fn verify(&self, data: &Data) -> VerificationOutcome {
        let validator = Validator::new(self.schema.clone());
        for anchor in &self.anchors {
            validator.add_trust_anchor(anchor.clone());
        }
        match validator.validate(data).await {
            ValidationResult::Valid(safe) => match safe.trust_path() {
                TrustPath::DigestSha256 => {
                    VerificationOutcome::Rejected("DigestSha256: integrity, not identity".into())
                }
                TrustPath::CertChain(chain) => VerificationOutcome::Verified {
                    anchor: chain
                        .last()
                        .cloned()
                        .unwrap_or_else(|| data.name.as_ref().clone()),
                },
                TrustPath::LocalFace { .. } => VerificationOutcome::Verified {
                    anchor: data.name.as_ref().clone(),
                },
            },
            ValidationResult::Invalid(e) => VerificationOutcome::Rejected(e.to_string()),
            ValidationResult::Pending => {
                VerificationOutcome::Rejected("certificate chain not resolved".into())
            }
        }
    }

    /// Derive a sub-identity authorized for `scope`, with `lifetime`. The
    /// caller is responsible for then enrolling the resulting key under the
    /// parent identity (NDNCERT or self-signed for ephemeral).
    pub fn derive_sub(
        &self,
        scope: Name,
        lifetime: IdentityLifetime,
        parent: &IdentityRef,
        custodian: CustodianRef,
    ) -> IdentityRef {
        IdentityRef {
            name: scope.clone(),
            key_id: KeyId::placeholder_for(&scope),
            custodian,
            lifetime,
            derived_from: Some(parent.key_id.clone()),
            capabilities: CapabilitySet {
                sign: vec![pattern_under(&scope)],
                ..Default::default()
            },
        }
    }

    /// Primary trust identifier for this context — SHA-256 of the first
    /// anchor's signed-region bytes (canonical NDN cert DER-equivalent).
    /// Adopted-only contexts with no anchors return the all-zero fingerprint.
    pub fn anchor_fingerprint(&self) -> Fingerprint {
        match self.anchors.first() {
            Some(cert) => Fingerprint::of_cert(cert),
            None => Fingerprint::zero(),
        }
    }

    /// Export the bundle that context-sync replicates to a sibling device.
    /// Phase 1 ships an anchors + schema + ca_endpoints snapshot; key
    /// material is **never** included unless wrapped for a specific recipient
    /// (Phase 2 + Phase 4).
    pub fn export_for_sync(&self) -> SyncBundle {
        SyncBundle {
            context_name: self.name.clone(),
            anchors: self.anchors.clone(),
            schema: self.schema.clone(),
            ca_endpoints: self.ca_endpoints.clone(),
        }
    }

    /// Convenience constructor for adopting an enrolled context with an
    /// initial identity and anchor set.
    pub fn enrolled(
        name: Name,
        anchors: Vec<Certificate>,
        identities: Vec<IdentityRef>,
        issued_by: Name,
        cert: Certificate,
    ) -> Self {
        Self {
            name,
            anchors,
            schema: TrustSchema::accept_all(),
            identities,
            ca_endpoints: Vec::new(),
            sync_namespace: None,
            publish_hints: Vec::new(),
            provenance: AdoptionProvenance::Enrolled {
                issued_by,
                cert,
                at: SystemTime::now(),
            },
        }
    }
}

/// A shared, atomically-replaceable `TrustContext` — what custodians and the
/// engine hold by reference once a context is bound to a surface.
pub type SharedTrustContext = Arc<TrustContext>;

/// Single match check between a [`NamePattern`] (LVS-style) and a target
/// `Name`. A pattern covers a name if every component pattern matches,
/// with multi-capture allowed to absorb the tail. This is intentionally
/// minimal — Phase 6 will surface the same logic through the dashboard's
/// plain-English renderer.
fn pattern_matches(pat: &NamePattern, name: &Name) -> bool {
    use ndn_security::PatternComponent::*;
    let comps = name.components();
    let mut i = 0usize;
    for pc in &pat.0 {
        match pc {
            Literal(lit) => {
                if i >= comps.len() || comps[i].value != lit.value {
                    return false;
                }
                i += 1;
            }
            Capture(_) => {
                if i >= comps.len() {
                    return false;
                }
                i += 1;
            }
            MultiCapture(_) => return true,
        }
    }
    i == comps.len()
}

pub(crate) fn pattern_under(prefix: &Name) -> NamePattern {
    use ndn_security::PatternComponent;
    let mut comps: Vec<PatternComponent> = prefix
        .components()
        .iter()
        .map(|c| PatternComponent::Literal(c.clone()))
        .collect();
    comps.push(PatternComponent::MultiCapture("_".into()));
    NamePattern(comps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_security::PatternComponent;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn legacy_root_uses_root_namespace() {
        let tc = TrustContext::legacy_root(vec![]);
        assert_eq!(tc.name, Name::root());
        assert!(tc.identities.is_empty());
    }

    #[test]
    fn can_sign_finds_covered_identity() {
        let mut tc = TrustContext::adopted(n("/home/bob"), SystemTime::now(), "test");
        let id = IdentityRef {
            name: n("/home/bob/alice"),
            key_id: KeyId::placeholder_for(&n("/home/bob/alice")),
            custodian: CustodianRef::InPage,
            lifetime: IdentityLifetime::Persistent,
            derived_from: None,
            capabilities: CapabilitySet {
                sign: vec![pattern_under(&n("/home/bob/alice"))],
                ..Default::default()
            },
        };
        tc.identities.push(id);
        assert!(tc.can_sign(&n("/home/bob/alice/doc")).is_some());
        assert!(tc.can_sign(&n("/home/bob/charlie/doc")).is_none());
    }

    #[tokio::test]
    async fn verify_accepts_authenticated_rejects_others() {
        use ndn_packet::encode::DataBuilder;
        use ndn_packet::{Data, SignatureType};
        use ndn_security::{Ed25519Signer, SignWith};
        use std::sync::Arc;

        // A signing identity whose self-cert is this context's anchor.
        let key = n("/ctx/dev/KEY/k1");
        let signer = Ed25519Signer::from_seed(&[3u8; 32], key.clone());
        let cert = Certificate {
            name: Arc::new(key),
            public_key: bytes::Bytes::copy_from_slice(&signer.public_key_bytes()),
            valid_from: 0,
            valid_until: u64::MAX,
            issuer: None,
            signed_region: None,
            sig_value: None,
            sig_type: SignatureType::SignatureEd25519,
        };
        let ctx = TrustContext::legacy_root(vec![cert]);

        let signed = |s: &Ed25519Signer| {
            Data::decode(
                DataBuilder::new("/ctx/dev/thing", b"hi")
                    .sign_with_sync(s)
                    .unwrap(),
            )
            .unwrap()
        };

        // Authenticated by the anchor key → Verified.
        assert!(matches!(
            ctx.verify(&signed(&signer)).await,
            VerificationOutcome::Verified { .. }
        ));

        // DigestSha256 (integrity, not identity) → Rejected.
        let digest =
            Data::decode(DataBuilder::new("/ctx/dev/thing", b"hi").sign_digest_sha256()).unwrap();
        assert!(matches!(
            ctx.verify(&digest).await,
            VerificationOutcome::Rejected(_)
        ));

        // A different (unknown) signer → Rejected.
        let other = Ed25519Signer::from_seed(&[9u8; 32], n("/evil/KEY/k1"));
        assert!(matches!(
            ctx.verify(&signed(&other)).await,
            VerificationOutcome::Rejected(_)
        ));

        // Adopted-only context (no anchors) fails closed.
        let adopted = TrustContext::adopted(n("/home/bob"), SystemTime::now(), "t");
        assert!(matches!(
            adopted.verify(&signed(&signer)).await,
            VerificationOutcome::Rejected(_)
        ));
    }

    #[test]
    fn pattern_literal_matches_exactly() {
        let pat = NamePattern(vec![
            PatternComponent::Literal(ndn_packet::NameComponent::generic(
                bytes::Bytes::from_static(b"home"),
            )),
            PatternComponent::Literal(ndn_packet::NameComponent::generic(
                bytes::Bytes::from_static(b"bob"),
            )),
        ]);
        assert!(pattern_matches(&pat, &n("/home/bob")));
        assert!(!pattern_matches(&pat, &n("/home")));
        assert!(!pattern_matches(&pat, &n("/home/alice")));
    }
}
