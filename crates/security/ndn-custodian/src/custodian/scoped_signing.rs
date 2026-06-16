//! §7 scoped signing — bounded auto-approve grants in front of an
//! [`ApprovalGate`].
//!
//! Per-command biometric approval is the safe default, but it kills heavy edit
//! flows (40 Face-IDs to retune routes from a laptop). A *scoped grant* lets
//! the operator auto-approve a **bounded class** of requests for a **bounded
//! time** — never "forever", and never for catastrophic commands (trust
//! anchors, policy, revoke, custody), which always interrupt with a real
//! prompt even mid-scope.
//!
//! The kernel ([`ScopedSigningPolicy`]) is pure and deterministic: it
//! classifies a signed region by its **leading Name** (peeked from the bytes,
//! never a caller-supplied hint) and decides [`Decision::AutoApprove`] vs
//! [`Decision::Prompt`] against the live grants at a caller-supplied `now`.
//! [`ScopedApprovalGate`] wraps any [`ApprovalGate`] with it.
//!
//! §7's four bounds:
//! - **Device** — structural, not a field here: the policy lives on the
//!   responder serving *one* paired device's channel, so a grant only ever
//!   auto-approves that device's requests.
//! - **Duration** — every grant carries a hard `expires_at`; there is no
//!   unbounded grant.
//! - **Action class** — a grant may narrow to one [`ActionClass`].
//! - **Always-ask carve-outs** — [`ActionClass::Sensitive`] never auto-signs.
//!
//! Note on classification trust: a non-command region named to *look* like a
//! command (`/x/nfd/rib/…`) would classify as `Route`. That is acceptable —
//! the grant is short, device-bound, and the operator opted into that class;
//! the catastrophic carve-out is what protects trust/custody. Signing arbitrary
//! bytes still requires either a live matching grant or an explicit prompt.

use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use async_trait::async_trait;
use bytes::Bytes;
use ndn_packet::Name;

use crate::ApprovalGate;

/// The class of action a sign request commits to, derived from the management
/// module component of the signed region's leading Name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionClass {
    /// `…/nfd/rib/*` — route register / unregister.
    Route,
    /// `…/nfd/faces/*` — face create / destroy / update.
    Face,
    /// `…/nfd/strategy-choice/*` — strategy set / unset.
    Strategy,
    /// `…/nfd/cs/*` — content-store config / erase.
    ContentStore,
    /// Trust / custody / policy: `…/nfd/security/*` and `…/nfd/ca/*` — anchor
    /// add/remove, policy change, approve/deny, revoke. **Always-ask**: never
    /// auto-approved, even under a blanket grant.
    Sensitive,
    /// Anything else — application Data signing, unknown commands.
    Other,
}

impl ActionClass {
    /// Classify a signed region by peeking its leading Name. A region that
    /// isn't a Name, or whose name has no recognised `…/nfd/<module>` segment,
    /// is [`ActionClass::Other`].
    pub fn classify(region: &[u8]) -> Self {
        let Ok(name) = Name::decode_from_tlv(Bytes::copy_from_slice(region)) else {
            return ActionClass::Other;
        };
        let comps = name.components();
        // NFD command Interests lead with `/localhost/nfd/<module>/<verb>/…`;
        // classify on the component right after `nfd`.
        let module: Option<&[u8]> = comps
            .iter()
            .position(|c| c.value.as_ref() == b"nfd")
            .and_then(|i| comps.get(i + 1))
            .map(|c| c.value.as_ref());
        match module {
            Some(b"rib") => ActionClass::Route,
            Some(b"faces") => ActionClass::Face,
            Some(b"strategy-choice") => ActionClass::Strategy,
            Some(b"cs") => ActionClass::ContentStore,
            Some(b"security") | Some(b"ca") => ActionClass::Sensitive,
            _ => ActionClass::Other,
        }
    }

    /// Whether this class always interrupts with a prompt (§7 always-ask
    /// carve-outs), never auto-approved.
    pub fn is_always_ask(self) -> bool {
        matches!(self, ActionClass::Sensitive)
    }
}

/// A bounded auto-approve window (§7).
#[derive(Debug, Clone)]
pub struct ScopedGrant {
    /// Hard expiry — there is no unbounded grant.
    pub expires_at: SystemTime,
    /// `None` auto-approves any non-sensitive class; `Some(c)` narrows to `c`.
    pub action_filter: Option<ActionClass>,
}

/// What [`ScopedSigningPolicy::decide`] resolved to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// A live grant covers this request — sign without prompting.
    AutoApprove,
    /// No grant applies (or it's always-ask) — fall back to the gate prompt.
    Prompt,
}

/// The pure scoped-signing kernel: a set of live grants and the decision rule.
#[derive(Debug, Default)]
pub struct ScopedSigningPolicy {
    grants: Vec<ScopedGrant>,
}

impl ScopedSigningPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    /// Open an auto-approve window.
    pub fn grant(&mut self, grant: ScopedGrant) {
        self.grants.push(grant);
    }

    /// "Tap Stop" — revoke every active grant; subsequent requests prompt.
    pub fn clear(&mut self) {
        self.grants.clear();
    }

    /// How many grants are still live at `now` (prunes expired as a side
    /// effect). Useful for a "scope active" indicator.
    pub fn active_grants(&mut self, now: SystemTime) -> usize {
        self.grants.retain(|g| g.expires_at > now);
        self.grants.len()
    }

    /// Decide whether signing `region` auto-approves at `now`, or falls back to
    /// a prompt. Prunes expired grants. [`ActionClass::Sensitive`] always
    /// prompts regardless of any grant (always-ask carve-out).
    pub fn decide(&mut self, region: &[u8], now: SystemTime) -> Decision {
        self.grants.retain(|g| g.expires_at > now);
        let action = ActionClass::classify(region);
        if action.is_always_ask() {
            return Decision::Prompt;
        }
        let covered = self.grants.iter().any(|g| match g.action_filter {
            Some(filter) => filter == action,
            None => true,
        });
        if covered {
            Decision::AutoApprove
        } else {
            Decision::Prompt
        }
    }
}

/// Wraps an inner [`ApprovalGate`] with §7 scoped auto-approval. On a live
/// matching grant for a non-sensitive action it returns `true` without
/// prompting; otherwise it delegates to the inner gate (the biometric prompt).
pub struct ScopedApprovalGate {
    inner: Arc<dyn ApprovalGate>,
    policy: Mutex<ScopedSigningPolicy>,
}

impl ScopedApprovalGate {
    pub fn new(inner: Arc<dyn ApprovalGate>) -> Self {
        Self {
            inner,
            policy: Mutex::new(ScopedSigningPolicy::new()),
        }
    }

    /// Open a bounded auto-approve window: `action_filter` `None` covers any
    /// non-sensitive class, `Some(c)` narrows to `c`; `expires_at` is the hard
    /// ceiling the caller computed (e.g. `now + 15m`).
    pub fn grant(&self, action_filter: Option<ActionClass>, expires_at: SystemTime) {
        self.policy
            .lock()
            .unwrap()
            .grant(ScopedGrant {
                expires_at,
                action_filter,
            });
    }

    /// "Tap Stop" — revoke all grants; subsequent requests prompt again.
    pub fn stop(&self) {
        self.policy.lock().unwrap().clear();
    }

    /// Number of live grants right now.
    pub fn active_grants(&self) -> usize {
        self.policy.lock().unwrap().active_grants(SystemTime::now())
    }
}

#[async_trait]
impl ApprovalGate for ScopedApprovalGate {
    async fn approve(&self, region: &[u8]) -> bool {
        // Resolve the decision under the lock, then drop it before any await.
        let decision = self
            .policy
            .lock()
            .unwrap()
            .decide(region, SystemTime::now());
        match decision {
            Decision::AutoApprove => true,
            Decision::Prompt => self.inner.approve(region).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    fn region_for(uri: &str) -> Bytes {
        uri.parse::<Name>().unwrap().encode_to_tlv()
    }

    #[test]
    fn classify_maps_management_modules() {
        assert_eq!(
            ActionClass::classify(&region_for("/localhost/nfd/rib/register")),
            ActionClass::Route
        );
        assert_eq!(
            ActionClass::classify(&region_for("/localhost/nfd/faces/create")),
            ActionClass::Face
        );
        assert_eq!(
            ActionClass::classify(&region_for("/localhost/nfd/strategy-choice/set")),
            ActionClass::Strategy
        );
        assert_eq!(
            ActionClass::classify(&region_for("/localhost/nfd/security/anchor-add")),
            ActionClass::Sensitive
        );
        assert_eq!(
            ActionClass::classify(&region_for("/localhost/nfd/ca/approve")),
            ActionClass::Sensitive
        );
        // Application data and non-name bytes are Other.
        assert_eq!(
            ActionClass::classify(&region_for("/app/data/v1")),
            ActionClass::Other
        );
        assert_eq!(ActionClass::classify(&[0xff, 0x00, 0x01]), ActionClass::Other);
    }

    #[test]
    fn sensitive_action_always_prompts_even_under_blanket_grant() {
        let mut p = ScopedSigningPolicy::new();
        let now = SystemTime::now();
        p.grant(ScopedGrant {
            expires_at: now + Duration::from_secs(900),
            action_filter: None, // blanket
        });
        // A route edit auto-approves…
        assert_eq!(
            p.decide(&region_for("/localhost/nfd/rib/register"), now),
            Decision::AutoApprove
        );
        // …but anchor-add never does.
        assert_eq!(
            p.decide(&region_for("/localhost/nfd/security/anchor-add"), now),
            Decision::Prompt
        );
    }

    #[test]
    fn matching_grant_auto_approves_within_window() {
        let mut p = ScopedSigningPolicy::new();
        let now = SystemTime::now();
        p.grant(ScopedGrant {
            expires_at: now + Duration::from_secs(300),
            action_filter: Some(ActionClass::Route),
        });
        assert_eq!(
            p.decide(&region_for("/localhost/nfd/rib/register"), now),
            Decision::AutoApprove
        );
        // A different class isn't covered by a Route-only grant.
        assert_eq!(
            p.decide(&region_for("/localhost/nfd/faces/create"), now),
            Decision::Prompt
        );
    }

    #[test]
    fn expired_grant_prompts_and_is_pruned() {
        let mut p = ScopedSigningPolicy::new();
        let now = SystemTime::now();
        p.grant(ScopedGrant {
            expires_at: now - Duration::from_secs(1), // already expired
            action_filter: Some(ActionClass::Route),
        });
        assert_eq!(
            p.decide(&region_for("/localhost/nfd/rib/register"), now),
            Decision::Prompt
        );
        assert_eq!(p.active_grants(now), 0); // pruned
    }

    #[tokio::test]
    async fn scoped_gate_auto_approves_then_stop_falls_back_to_inner() {
        struct CountingGate(Arc<AtomicUsize>);
        #[async_trait]
        impl ApprovalGate for CountingGate {
            async fn approve(&self, _region: &[u8]) -> bool {
                self.0.fetch_add(1, Ordering::SeqCst);
                true
            }
        }

        let prompts = Arc::new(AtomicUsize::new(0));
        let gate = ScopedApprovalGate::new(Arc::new(CountingGate(prompts.clone())));
        let region = region_for("/localhost/nfd/rib/register");

        // No grant yet → the inner gate is prompted.
        assert!(gate.approve(&region).await);
        assert_eq!(prompts.load(Ordering::SeqCst), 1);

        // Grant route edits for 15m → auto-approves without prompting.
        gate.grant(Some(ActionClass::Route), SystemTime::now() + Duration::from_secs(900));
        assert!(gate.approve(&region).await);
        assert_eq!(prompts.load(Ordering::SeqCst), 1, "should not have prompted");

        // A sensitive command still prompts despite the grant.
        assert!(
            gate.approve(&region_for("/localhost/nfd/security/anchor-add"))
                .await
        );
        assert_eq!(prompts.load(Ordering::SeqCst), 2);

        // Stop → back to prompting for route edits too.
        gate.stop();
        assert!(gate.approve(&region).await);
        assert_eq!(prompts.load(Ordering::SeqCst), 3);
    }
}
