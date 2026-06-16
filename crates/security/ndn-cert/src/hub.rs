//! Hub-archetype onboarding: stand up a network root, publish its
//! [`SignedTrustContext`] + [`BootstrapTicket`], and the clockless validity policy that
//! offline/embedded nodes degrade to.
//!
//! The home-hub is the local-gains-first archetype: one node is root + issuing
//! CA + rendezvous. Peers overhear or scan a QR, adopt the context (free), and
//! — only if they want to *produce* — enroll behind `token AND device-approval`.
//! See `.claude/notes/trust-context/trust-context-model-2026-05-25.md` §9, §16.

use std::sync::Arc;

use ndn_packet::Name;
use ndn_security::{Certificate, EnrollmentHint, SecurityManager, SignedTrustContext, TrustError};

use crate::onboarding::BootstrapTicket;

/// Result of initializing a hub.
pub struct HubInit {
    /// The network anchor's key name (`<namespace>/KEY/root`).
    pub anchor_key: Name,
    /// The self-signed network anchor certificate.
    pub anchor: Certificate,
    /// The published, versioned trust context (hierarchical, hub-default gate).
    pub context: Arc<SignedTrustContext>,
    /// The out-of-band bootstrap ticket (QR / deep link).
    pub ticket: BootstrapTicket,
}

impl HubInit {
    /// The context `Content` to publish at
    /// [`rdr_context_name`](crate::rdr_context_name)`(namespace, version)`.
    pub fn published_content(&self) -> bytes::Bytes {
        self.context.encode_content()
    }
}

/// Initialize a hub rooted at `namespace`: generate a signing key in `mgr`,
/// self-sign the network anchor, build a hierarchical context (the
/// skeleton-key-safe default) with the hub enrollment gate
/// (`token AND device-approval`), and mint a bootstrap ticket committing to the
/// anchor fingerprint.
///
/// The default deployment keeps the *root* offline and runs a delegated
/// context-signer online; this in-process helper signs directly for the
/// self-contained case (tests, single-box hubs). The signing key never leaves
/// `mgr`.
pub fn init_hub(mgr: &SecurityManager, namespace: &Name) -> Result<HubInit, TrustError> {
    let anchor_key = namespace.clone().append("KEY").append("root");
    mgr.generate_ed25519(anchor_key.clone())?;
    let pk = mgr
        .get_signer_sync(&anchor_key)?
        .public_key()
        .unwrap_or_default();
    let anchor = mgr.issue_self_signed(&anchor_key, pk, u64::MAX)?;

    let context = SignedTrustContext::hierarchical(namespace.clone())
        .with_version(1)
        .with_enrollment_hint(EnrollmentHint::hub_default());
    context.add_anchor(anchor.clone());
    let context = Arc::new(context);

    let ticket = BootstrapTicket::new(namespace, &anchor);
    Ok(HubInit {
        anchor_key,
        anchor,
        context,
        ticket,
    })
}

/// How a node enforces validity, given whether it has a reliable clock (N4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidityMode {
    /// Wall-clock present: enforce `ValidityPeriod` against the current time.
    WallClock,
    /// No reliable clock (embedded / freshly-imaged): rely on the keyring's
    /// **monotonic context version** plus **single-use / scoped tokens**
    /// instead of TTL. `ValidityPeriod` is still encoded but is not the sole
    /// offline gate; the `baked` archetype prefers approval + scope over TTL.
    Clockless,
}

impl ValidityMode {
    /// Pick a mode from whether a trusted wall-clock is available.
    pub fn detect(has_wall_clock: bool) -> Self {
        if has_wall_clock {
            ValidityMode::WallClock
        } else {
            ValidityMode::Clockless
        }
    }

    /// Whether validity may rely on TTL/`ValidityPeriod`. In `Clockless` mode
    /// it cannot — the caller must fall back to version + single-use tokens.
    pub fn ttl_enforceable(&self) -> bool {
        matches!(self, ValidityMode::WallClock)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn init_hub_builds_anchored_gated_context() {
        let mgr = SecurityManager::new();
        let hub = init_hub(&mgr, &n("/home/bob")).unwrap();
        assert_eq!(hub.anchor_key, n("/home/bob/KEY/root"));
        assert_eq!(hub.context.namespace(), &n("/home/bob"));
        assert_eq!(hub.context.version(), 1);
        assert!(hub.context.enforces_hierarchy());
        assert_eq!(
            hub.context.enrollment_hint(),
            Some(&EnrollmentHint::hub_default())
        );
        assert!(hub.context.is_anchor(&hub.anchor_key));
        // The ticket commits to the anchor we just minted.
        assert_eq!(
            hub.ticket.fingerprint(),
            Some(crate::anchor_fingerprint(&hub.anchor))
        );
    }

    #[test]
    fn validity_mode_clockless_disables_ttl() {
        assert_eq!(ValidityMode::detect(true), ValidityMode::WallClock);
        assert_eq!(ValidityMode::detect(false), ValidityMode::Clockless);
        assert!(ValidityMode::WallClock.ttl_enforceable());
        assert!(!ValidityMode::Clockless.ttl_enforceable());
    }
}
