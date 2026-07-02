//! The soft → hard enforcement ratchet (threat T3).
//!
//! Certificate validity *windows* can only be enforced once wall-clock
//! uncertainty is tight enough to know which side of the window you are on.
//! That creates a bootstrap: window enforcement needs trusted time, trusted
//! time needs authenticated peers, authentication needs valid certs. The escape
//! is a ratchet with three load-bearing properties, encoded by this type:
//!
//! - **Fail-closed.** "Soft" does not mean "leniently accept an uncheckable
//!   window." It means *withhold* the high-stakes action that depends on the
//!   window. Soft never grants; it only refuses. So an adversary who keeps
//!   uncertainty high (jam, Sybil-with-fat-±u) pins a node in soft — which is
//!   denial-of-**service** (loud, visible: ±u is huge and published), never
//!   acceptance of what should be rejected. Denial-of-*trust* is thereby
//!   converted into denial-of-service by construction.
//! - **Append-only grants.** An authorisation, once made hard, is recorded and
//!   never retroactively revoked by this type. Uncertainty may later regrow and
//!   re-enter soft *for future* decisions, but that only withholds *new*
//!   authority — it cannot un-grant. So the granted-trust order has no cycle.
//! - **Chain validation is out of scope and always hard.** This type governs
//!   only the *window* check. Signature/chain validation needs no clock and is
//!   always enforced hard by the validator, so the ratchet never opens a door a
//!   forged or unauthorised cert can walk through.
//!
//! Together these give the termination argument: under a liveness assumption
//! (some authorised, bounded sample arrives periodically) uncertainty narrows
//! monotonically and enforcement promotes to hard in finite time; otherwise the
//! node sits in loud, safe DoS. It never transits into accepting bad time.

/// How strictly a clock-dependent validity window can be enforced right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowEnforcement {
    /// Uncertainty is too wide to check the window — the dependent action is
    /// **withheld** (fail-closed), never granted.
    Soft,
    /// Uncertainty is tight enough to enforce the window; the action may be
    /// authorised.
    Hard,
}

/// A recorded, immutable authorisation made under hard enforcement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grant {
    /// Opaque identifier for the authorised action.
    pub action_id: u32,
    /// The wall-clock uncertainty (ns) at the instant of grant — retained so a
    /// later, tighter bar can *flag* (not revoke) grants made when looser.
    pub uncertainty_at_grant_ns: u64,
    /// Local monotonic time (ns) of the grant. Monotone and sticky.
    pub mono_ns: u64,
}

/// The outcome of an authorisation request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Enforcement was hard; the action is authorised and recorded.
    Granted,
    /// Enforcement was soft; the action is withheld (fail-closed).
    Withheld,
}

/// Upper bound on retained grants for audit/re-flag. The security invariants
/// (fail-closed, withhold-only) do **not** depend on this storage — it is for
/// the on-promotion re-evaluation step; beyond capacity, [`Ratchet::overflowed`]
/// is set and a real deployment persists older grants to its signed log.
pub const MAX_GRANTS: usize = 64;

/// The enforcement ratchet. Answers "may I hard-enforce this window now?" and
/// keeps an append-only record of what was granted.
#[derive(Clone, Copy, Debug)]
pub struct Ratchet {
    grants: [Grant; MAX_GRANTS],
    len: usize,
    overflowed: bool,
    last_mono_ns: u64,
}

impl Default for Ratchet {
    fn default() -> Self {
        Self::new()
    }
}

impl Ratchet {
    /// A fresh ratchet with no grants.
    pub const fn new() -> Self {
        Self {
            grants: [Grant {
                action_id: 0,
                uncertainty_at_grant_ns: 0,
                mono_ns: 0,
            }; MAX_GRANTS],
            len: 0,
            overflowed: false,
            last_mono_ns: 0,
        }
    }

    /// Pure classification: is uncertainty tight enough to enforce a window that
    /// requires `threshold_ns`? Hard iff `uncertainty_ns <= threshold_ns`.
    pub const fn enforcement(uncertainty_ns: u64, threshold_ns: u64) -> WindowEnforcement {
        if uncertainty_ns <= threshold_ns {
            WindowEnforcement::Hard
        } else {
            WindowEnforcement::Soft
        }
    }

    /// Request authorisation for a window-dependent action.
    ///
    /// Grants **iff** enforcement is hard (`uncertainty_ns <= threshold_ns`),
    /// recording the grant; otherwise withholds. Never revokes a prior grant.
    /// The monotonic stamp is clamped so it cannot regress even if a caller
    /// passes a smaller `mono_ns`.
    pub fn authorize(
        &mut self,
        action_id: u32,
        threshold_ns: u64,
        uncertainty_ns: u64,
        mono_ns: u64,
    ) -> Decision {
        let mono = mono_ns.max(self.last_mono_ns);
        self.last_mono_ns = mono;
        match Self::enforcement(uncertainty_ns, threshold_ns) {
            WindowEnforcement::Hard => {
                let grant = Grant {
                    action_id,
                    uncertainty_at_grant_ns: uncertainty_ns,
                    mono_ns: mono,
                };
                if self.len < MAX_GRANTS {
                    self.grants[self.len] = grant;
                    self.len += 1;
                } else {
                    self.overflowed = true;
                }
                Decision::Granted
            }
            WindowEnforcement::Soft => Decision::Withheld,
        }
    }

    /// The append-only record of grants (up to [`MAX_GRANTS`]).
    pub fn granted(&self) -> &[Grant] {
        &self.grants[..self.len]
    }

    /// Whether more than [`MAX_GRANTS`] grants have been made (older ones not
    /// retained here). Does not affect the security invariants.
    pub const fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// On promotion to a tighter bar, the retained grants that were made when
    /// uncertainty was *looser* than `now_threshold_ns` — i.e. that would not be
    /// granted now and should be re-evaluated/flagged by the caller. This never
    /// revokes; it reports.
    pub fn stale_grant_count(&self, now_threshold_ns: u64) -> usize {
        self.granted()
            .iter()
            .filter(|g| g.uncertainty_at_grant_ns > now_threshold_ns)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soft_withholds_fail_closed() {
        let mut r = Ratchet::new();
        // uncertainty 10ms, action needs 1ms → soft → withheld.
        assert_eq!(
            r.authorize(1, 1_000_000, 10_000_000, 100),
            Decision::Withheld
        );
        assert!(r.granted().is_empty(), "soft grants nothing");
    }

    #[test]
    fn hard_grants_and_records() {
        let mut r = Ratchet::new();
        assert_eq!(r.authorize(7, 1_000_000, 500_000, 100), Decision::Granted);
        assert_eq!(r.granted().len(), 1);
        assert_eq!(r.granted()[0].action_id, 7);
    }

    #[test]
    fn progress_then_grant() {
        // As uncertainty narrows across the threshold, the same action promotes
        // from withheld to granted — the termination "progress" property.
        let mut r = Ratchet::new();
        assert_eq!(r.authorize(1, 1_000_000, 2_000_000, 10), Decision::Withheld);
        assert_eq!(r.authorize(1, 1_000_000, 900_000, 20), Decision::Granted);
    }

    #[test]
    fn regrowing_uncertainty_withholds_new_but_never_revokes() {
        // Grant while tight, then uncertainty regrows: new requests are withheld
        // (withhold-only), but the earlier grant is sticky — no permissive cycle.
        let mut r = Ratchet::new();
        r.authorize(1, 1_000_000, 500_000, 100);
        assert_eq!(r.granted().len(), 1);
        // Uncertainty regrows to 5ms; a new action is withheld.
        assert_eq!(
            r.authorize(2, 1_000_000, 5_000_000, 200),
            Decision::Withheld
        );
        // The first grant is still there — not revoked.
        assert_eq!(r.granted().len(), 1);
        assert_eq!(r.granted()[0].action_id, 1);
    }

    #[test]
    fn monotonic_stamp_cannot_regress() {
        let mut r = Ratchet::new();
        r.authorize(1, 1_000_000, 100, 1_000);
        r.authorize(2, 1_000_000, 100, 500); // caller passes an earlier stamp
        assert!(
            r.granted()[1].mono_ns >= r.granted()[0].mono_ns,
            "grant stamps are monotone"
        );
    }

    #[test]
    fn stale_grants_are_flagged_not_revoked_on_promotion() {
        let mut r = Ratchet::new();
        // Grant under a loose 10ms bar.
        r.authorize(1, 10_000_000, 8_000_000, 100);
        // Now the action's bar tightens to 1ms: the earlier grant is stale.
        assert_eq!(r.stale_grant_count(1_000_000), 1);
        // But it is still granted (reported, not revoked).
        assert_eq!(r.granted().len(), 1);
    }
}
