//! Expected-context admission: letting a device that holds no trust for a
//! namespace yet receive that namespace's signed trust context.
//!
//! A forwarder validates every Data it forwards. A device adopting a network
//! from a fingerprint-only anchor link fetches `<ns>/32=trust-context/v=<N>`,
//! signed by the network's root `<ns>/KEY/root`. The root is not an anchor the
//! device holds (that is what it is adopting), so the ordinary chain walk can
//! never succeed and the device's own forwarder drops the very Data it asked
//! for.
//!
//! While an adoption runs, the adopter registers a short-lived expectation
//! `{namespace, expected anchor fingerprint, deadline}`. A Data named
//! `<namespace>/32=trust-context/v=<N>` is then decided by the expectation
//! alone: admitted iff its content is a trust context for that namespace, it
//! is signed by an anchor that context lists, the signature verifies under
//! that anchor's key, and that anchor's key fingerprint equals the expected
//! one. Anything else at that name — a forged root, a digest signature, a
//! malformed context — is refused. Names of any other shape, and every name
//! while no expectation is active, are validated exactly as before.
//!
//! The admitted result is kept with the expectation so the adopter can take
//! it ([`ContextExpectation::finish`]) instead of verifying the same Data a
//! second time. Expectations end when the adopter finishes or drops its guard,
//! or at their deadline, whichever comes first; an expired expectation admits
//! nothing.
//!
//! An **update** of a held context is expected the same way
//! ([`Validator::expect_context_update`]), with the fingerprints of the held
//! version's anchors instead of one from an invite: the update must be signed
//! by a root this node already trusts (continuity), never merely by an anchor
//! it lists itself.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_packet::{Data, Name};
use web_time::Instant;

use crate::cert_cache::Certificate;
use crate::safe_data::TrustPath;
use crate::trust_context::{SignedTrustContext, anchor_fingerprint, context_namespace_of};
use crate::{SafeData, TrustError};

use super::{ValidationResult, Validator, now_ns};

/// One active expectation, held by the validator.
pub(super) struct Expectation {
    /// Unique per registration, so a guard withdraws only its own.
    id: u64,
    namespace: Name,
    /// Fingerprints of the anchors whose signature admits a context.
    expected_fingerprints: Vec<[u8; 32]>,
    purpose: Purpose,
    deadline: Instant,
    outcome: ExpectationOutcome,
}

/// Why a context is expected; decides only how a refusal is worded.
#[derive(Clone, Copy)]
enum Purpose {
    /// First contact: the fingerprint comes from an invite/QR.
    Adoption,
    /// An update of a held context: the fingerprints are its anchors'.
    Update { held_version: u64 },
}

/// Source of [`Expectation::id`].
static NEXT_EXPECTATION_ID: AtomicU64 = AtomicU64::new(0);

/// What happened under an expectation, returned by
/// [`ContextExpectation::finish`].
#[derive(Clone, Debug, Default)]
pub struct ExpectationOutcome {
    /// The last context admitted (should several versions have passed).
    pub admitted: Option<AdmittedContext>,
    /// Why the last refused context Data at the expected name was refused —
    /// so the adopter can say *why* nothing arrived (a forged or foreign
    /// network) instead of reporting a bare timeout.
    pub refused: Option<String>,
}

/// A trust context the validator admitted under an expectation: decoded,
/// signature-verified, and signed by the anchor with the expected fingerprint.
#[derive(Clone, Debug)]
pub struct AdmittedContext {
    pub context: Arc<SignedTrustContext>,
    /// The anchor that signed it (its fingerprint is the expected one).
    pub anchor: Certificate,
    /// The admitted Data wire, to match it against what the adopter received.
    pub wire: Bytes,
}

/// Why [`Validator::expect_context`] registered nothing.
#[derive(Debug, thiserror::Error)]
pub enum ExpectContextError {
    #[error(
        "an adoption or update of {0}'s trust context is already in progress on this node; \
         wait for it to finish (it ends by itself within its timeout) and retry"
    )]
    AlreadyExpected(String),
}

/// Guard for an active expectation. Dropping it withdraws the expectation;
/// [`finish`](Self::finish) withdraws it and returns what was admitted.
#[must_use = "dropping the guard withdraws the expectation at once"]
pub struct ContextExpectation<'a> {
    validator: &'a Validator,
    namespace: Name,
    /// The registration this guard owns: withdrawing by it never removes a
    /// newer expectation registered for the same namespace (after `finish`,
    /// or after this one's ttl passed).
    id: u64,
}

impl ContextExpectation<'_> {
    /// The namespace this expectation is for.
    pub fn namespace(&self) -> &Name {
        &self.namespace
    }

    /// Withdraw the expectation and return what happened under it.
    pub fn finish(self) -> ExpectationOutcome {
        // Drop runs `withdraw` again, which then finds nothing of its own.
        self.validator.withdraw_expectation(self.id)
    }
}

impl Drop for ContextExpectation<'_> {
    fn drop(&mut self) {
        self.validator.withdraw_expectation(self.id);
    }
}

impl Validator {
    /// Expect the signed trust context of `namespace`, signed by the anchor
    /// whose key fingerprint is `expected_fingerprint`, for at most `ttl`.
    /// Until the returned guard is finished or dropped (or `ttl` passes), a
    /// Data named `<namespace>/32=trust-context/v=<N>` is admitted only if it
    /// meets that expectation and refused otherwise (see the module docs).
    ///
    /// One expectation per namespace: a second one while the first is live is
    /// refused rather than replacing it.
    pub fn expect_context(
        &self,
        namespace: Name,
        expected_fingerprint: [u8; 32],
        ttl: Duration,
    ) -> Result<ContextExpectation<'_>, ExpectContextError> {
        self.register_expectation(namespace, vec![expected_fingerprint], Purpose::Adoption, ttl)
    }

    /// Expect an **update** of the held context `held`: while the guard
    /// lives, a Data named `<namespace>/32=trust-context/v=<N>` is admitted
    /// only if it is a self-consistent context of that namespace signed by a
    /// key that is an anchor of `held` (continuity: an update is authorized
    /// by the version it replaces, not by anchors it lists itself), and
    /// refused with a recorded reason otherwise. The version rule (strictly
    /// newer than `held`) is the updater's, which sees the fetched Data.
    ///
    /// Needed where this validator does not hold `held` itself (an app's
    /// embedded engine keeps contexts in its own keyring), and so that a
    /// refused update is reported with its reason rather than as a timeout.
    /// One expectation per namespace, as [`expect_context`](Self::expect_context).
    pub fn expect_context_update(
        &self,
        held: &SignedTrustContext,
        ttl: Duration,
    ) -> Result<ContextExpectation<'_>, ExpectContextError> {
        let fingerprints = held
            .anchors()
            .iter()
            .map(|r| anchor_fingerprint(r.value()))
            .collect();
        self.register_expectation(
            held.namespace().clone(),
            fingerprints,
            Purpose::Update {
                held_version: held.version(),
            },
            ttl,
        )
    }

    fn register_expectation(
        &self,
        namespace: Name,
        expected_fingerprints: Vec<[u8; 32]>,
        purpose: Purpose,
        ttl: Duration,
    ) -> Result<ContextExpectation<'_>, ExpectContextError> {
        let mut list = self
            .expectations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();
        list.retain(|e| e.deadline > now);
        if list.iter().any(|e| e.namespace == namespace) {
            return Err(ExpectContextError::AlreadyExpected(namespace.to_string()));
        }
        let id = NEXT_EXPECTATION_ID.fetch_add(1, Ordering::Relaxed);
        list.push(Expectation {
            id,
            namespace: namespace.clone(),
            expected_fingerprints,
            purpose,
            deadline: now + ttl,
            outcome: ExpectationOutcome::default(),
        });
        self.expecting.store(true, Ordering::Release);
        Ok(ContextExpectation {
            validator: self,
            namespace,
            id,
        })
    }

    fn withdraw_expectation(&self, id: u64) -> ExpectationOutcome {
        let mut list = self
            .expectations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let outcome = list
            .iter()
            .position(|e| e.id == id)
            .map(|i| list.swap_remove(i).outcome)
            .unwrap_or_default();
        self.expecting.store(!list.is_empty(), Ordering::Release);
        outcome
    }

    /// Record `f`'s change to the live expectation for `namespace`; `None`
    /// when it was withdrawn meanwhile.
    fn record(&self, namespace: &Name, f: impl FnOnce(&mut ExpectationOutcome)) -> Option<()> {
        let mut list = self
            .expectations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = list.iter_mut().find(|e| e.namespace == *namespace)?;
        f(&mut entry.outcome);
        Some(())
    }

    /// The expectation-based verdict for `data`, or `None` when no active
    /// expectation covers its name (validate as usual).
    pub(super) async fn admit_expected_context(&self, data: &Data) -> Option<ValidationResult> {
        if !self.expecting.load(Ordering::Acquire) {
            return None;
        }
        let namespace = context_namespace_of(&data.name)?;
        let (expected, purpose) = {
            let mut list = self
                .expectations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let now = Instant::now();
            list.retain(|e| e.deadline > now);
            self.expecting.store(!list.is_empty(), Ordering::Release);
            let e = list.iter().find(|e| e.namespace == namespace)?;
            (e.expected_fingerprints.clone(), e.purpose)
        };
        let refused = |reason: String| {
            self.record(&namespace, |o| o.refused = Some(reason.clone()));
            Some(ValidationResult::Invalid(TrustError::ExpectedContextRefused {
                namespace: namespace.to_string(),
                reason,
            }))
        };
        let (context, anchor) = match SignedTrustContext::open_received(data).await {
            Ok(opened) => opened,
            Err(e) => return refused(e.to_string()),
        };
        if !expected.contains(&anchor_fingerprint(&anchor)) {
            return refused(match purpose {
                Purpose::Adoption => format!(
                    "it is signed by {}, whose fingerprint is not the expected fingerprint \
                     from the invite/QR",
                    anchor.name
                ),
                Purpose::Update { held_version } => format!(
                    "it is signed by {}, which is not an anchor of the held version \
                     v{held_version} (an update must be signed by the root this node already \
                     trusts)",
                    anchor.name
                ),
            });
        }
        let Ok(inner) = Data::decode(data.raw().clone()) else {
            return refused("Data does not re-decode".into());
        };
        let admitted = AdmittedContext {
            context: Arc::new(context),
            anchor: anchor.clone(),
            wire: data.raw().clone(),
        };
        // Withdrawn meanwhile (the adopter gave up): admit nothing.
        self.record(&namespace, |o| o.admitted = Some(admitted))?;
        Some(ValidationResult::Valid(Box::new(SafeData {
            inner,
            trust_path: TrustPath::ExpectedContext {
                anchor: anchor.name.as_ref().clone(),
            },
            verified_at: now_ns(),
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust_schema::TrustSchema;

    /// A guard withdraws only its own expectation: finishing (or dropping)
    /// an expired one never removes a newer one for the same namespace.
    #[test]
    fn a_guard_never_withdraws_a_newer_expectation() {
        let v = Validator::new(TrustSchema::new());
        let ns: Name = "/home/bob".parse().unwrap();
        let old = v.expect_context(ns.clone(), [1; 32], Duration::ZERO).unwrap();
        let new = v
            .expect_context(ns.clone(), [2; 32], Duration::from_secs(30))
            .expect("the old one expired");
        old.finish();
        assert!(matches!(
            v.expect_context(ns.clone(), [3; 32], Duration::from_secs(30)),
            Err(ExpectContextError::AlreadyExpected(_))
        ));
        drop(new);
        assert!(v.expect_context(ns, [3; 32], Duration::from_secs(30)).is_ok());
    }
}
