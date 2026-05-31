//! Issuance policy seam for NDNCERT.
//!
//! Three independent stages gate every issued certificate:
//!
//! 1. [`NamespacePolicy`] — pre-challenge: is the requested name in scope?
//! 2. [`crate::challenge::ChallengeHandler`] — interactive proof of control.
//! 3. [`IssuancePolicy`] — post-challenge: issue (with what validity) or deny.
//!
//! [`AcceptAllIssuance`] is the default for stage 3.

use std::time::Duration;

use ndn_packet::Name;
use ndn_security::Certificate;
pub use ndn_security::TrustPolicy as _TrustPolicy;

use crate::attestation::AttestationSet;
use crate::protocol::CertRequest;

#[derive(Debug, Clone)]
pub enum PolicyDecision {
    Allow,
    Deny(String),
}

pub trait NamespacePolicy: Send + Sync {
    /// `requester_cert` is `None` for first enrollment.
    fn evaluate(
        &self,
        requested_name: &Name,
        requester_cert: Option<&Certificate>,
        ca_prefix: &Name,
    ) -> PolicyDecision;
}

/// Allow requests strictly under the requester's own identity prefix
/// (or anywhere under the CA's identity prefix for first enrollment).
pub struct HierarchicalPolicy;

impl NamespacePolicy for HierarchicalPolicy {
    fn evaluate(
        &self,
        requested_name: &Name,
        requester_cert: Option<&Certificate>,
        ca_prefix: &Name,
    ) -> PolicyDecision {
        let ca_identity = strip_ca_suffix(ca_prefix);
        let requester_prefix = match requester_cert {
            None => ca_identity.clone(),
            Some(cert) => strip_key_suffix(cert.name.as_ref()),
        };

        if requested_name.has_prefix(&requester_prefix) {
            PolicyDecision::Allow
        } else {
            PolicyDecision::Deny(format!(
                "{} is not under requester prefix {}",
                requested_name, requester_prefix
            ))
        }
    }
}

/// Explicit (requester_prefix → allowed_prefix) delegation rules.
pub struct DelegationPolicy {
    pub rules: Vec<(Name, Name)>,
    /// If true, requesters without a cert may request under any allowed prefix.
    pub allow_new_devices: bool,
}

impl DelegationPolicy {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            allow_new_devices: true,
        }
    }

    pub fn allow(mut self, requester_prefix: Name, allowed_prefix: Name) -> Self {
        self.rules.push((requester_prefix, allowed_prefix));
        self
    }
}

impl Default for DelegationPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl NamespacePolicy for DelegationPolicy {
    fn evaluate(
        &self,
        requested_name: &Name,
        requester_cert: Option<&Certificate>,
        _ca_prefix: &Name,
    ) -> PolicyDecision {
        match requester_cert {
            None => {
                if self.allow_new_devices {
                    for (_, allowed) in &self.rules {
                        if requested_name.has_prefix(allowed) {
                            return PolicyDecision::Allow;
                        }
                    }
                    PolicyDecision::Deny("no matching rule for new device".to_string())
                } else {
                    PolicyDecision::Deny("new devices not allowed".to_string())
                }
            }
            Some(cert) => {
                let requester_identity = strip_key_suffix(cert.name.as_ref());
                for (req_prefix, allowed_prefix) in &self.rules {
                    if requester_identity.has_prefix(req_prefix)
                        && requested_name.has_prefix(allowed_prefix)
                    {
                        return PolicyDecision::Allow;
                    }
                }
                PolicyDecision::Deny("no matching delegation rule".to_string())
            }
        }
    }
}

pub struct IssuanceContext<'a> {
    pub cert_request: &'a CertRequest,
    pub challenge_type: &'a str,
    /// The attestation the satisfied challenge produced (a kind-only leaf
    /// when the handler supplied none). Lets a policy gate on *how* the
    /// challenge was met — e.g. require a signed `device-approval` leaf —
    /// beyond what `challenge_type` alone conveys. Always `Some` from the CA.
    pub attestation: Option<&'a AttestationSet>,
    pub ca_prefix: &'a Name,
    pub default_validity: Duration,
    pub max_validity: Duration,
}

#[derive(Debug, Clone)]
pub enum IssuanceDecision {
    /// Validity is clamped to `IssuanceContext::max_validity` before signing.
    Issue { validity: Duration },
    /// Surfaced to the requester via `error_info`.
    Deny(String),
}

/// Post-challenge issuance gate. Invoked once per request after the
/// challenge reaches [`crate::challenge::ChallengeOutcome::Approved`] and
/// before the CA mints the cert.
pub trait IssuancePolicy: Send + Sync {
    fn decide(&self, ctx: &IssuanceContext<'_>) -> IssuanceDecision;
}

/// Issues every challenge-passing request at `default_validity`.
pub struct AcceptAllIssuance;

impl IssuancePolicy for AcceptAllIssuance {
    fn decide(&self, ctx: &IssuanceContext<'_>) -> IssuanceDecision {
        IssuanceDecision::Issue {
            validity: ctx.default_validity,
        }
    }
}

/// Under `prefix`, require the satisfied challenge's attestation to carry a
/// leaf of `required_kind` (e.g. names under `/high-trust` must have been met
/// with a `device-approval` challenge). Requests outside `prefix` issue
/// normally. With `require_signed`, the matching leaf must additionally carry
/// an independent signature (the cross-process device-approval case) — so the
/// gate distinguishes a *signed* approval from an in-process one, which
/// `challenge_type` alone cannot.
pub struct RequireAttestationKind {
    pub prefix: Name,
    pub required_kind: String,
    pub require_signed: bool,
}

impl RequireAttestationKind {
    pub fn new(prefix: Name, required_kind: impl Into<String>) -> Self {
        Self {
            prefix,
            required_kind: required_kind.into(),
            require_signed: false,
        }
    }

    pub fn require_signed(mut self, yes: bool) -> Self {
        self.require_signed = yes;
        self
    }
}

impl IssuancePolicy for RequireAttestationKind {
    fn decide(&self, ctx: &IssuanceContext<'_>) -> IssuanceDecision {
        let Ok(name) = ctx.cert_request.name.parse::<Name>() else {
            return IssuanceDecision::Deny(format!(
                "unparsable subject name: {}",
                ctx.cert_request.name
            ));
        };
        if !name.has_prefix(&self.prefix) {
            return IssuanceDecision::Issue {
                validity: ctx.default_validity,
            };
        }
        let satisfied = ctx.attestation.is_some_and(|set| {
            set.leaves.iter().any(|leaf| {
                leaf.kind == self.required_kind
                    && (!self.require_signed || leaf.signature.is_some())
            })
        });
        if satisfied {
            IssuanceDecision::Issue {
                validity: ctx.default_validity,
            }
        } else {
            let signed = if self.require_signed { "signed " } else { "" };
            IssuanceDecision::Deny(format!(
                "names under {} require a {signed}`{}` challenge attestation",
                self.prefix, self.required_kind
            ))
        }
    }
}

fn strip_key_suffix(name: &Name) -> Name {
    let comps = name.components();
    let key_pos = comps
        .iter()
        .rposition(|c| c.typ == 0x08 && c.value.as_ref() == b"KEY");
    match key_pos {
        Some(pos) if pos > 0 => Name::from_components(comps[..pos].iter().cloned()),
        _ => name.clone(),
    }
}

fn strip_ca_suffix(name: &Name) -> Name {
    let comps = name.components();
    if let Some(last) = comps.last()
        && last.typ == 0x08
        && last.value.as_ref() == b"CA"
    {
        return Name::from_components(comps[..comps.len() - 1].iter().cloned());
    }
    name.clone()
}

#[cfg(test)]
mod issuance_tests {
    use super::*;
    use crate::protocol::CertRequest;

    fn ctx<'a>(
        req: &'a CertRequest,
        challenge_type: &'a str,
        ca_prefix: &'a Name,
    ) -> IssuanceContext<'a> {
        ctx_att(req, challenge_type, ca_prefix, None)
    }

    fn ctx_att<'a>(
        req: &'a CertRequest,
        challenge_type: &'a str,
        ca_prefix: &'a Name,
        attestation: Option<&'a AttestationSet>,
    ) -> IssuanceContext<'a> {
        IssuanceContext {
            cert_request: req,
            challenge_type,
            attestation,
            ca_prefix,
            default_validity: Duration::from_secs(86_400),
            max_validity: Duration::from_secs(7 * 86_400),
        }
    }

    fn req(name: &str) -> CertRequest {
        CertRequest {
            name: name.to_string(),
            public_key: String::new(),
            not_before: 0,
            not_after: 0,
        }
    }

    #[test]
    fn accept_all_issues_at_default_validity() {
        let policy = AcceptAllIssuance;
        let r = req("/registry/zone-a/device/x");
        let ca = "/registry/CA".parse::<Name>().unwrap();
        match policy.decide(&ctx(&r, "token", &ca)) {
            IssuanceDecision::Issue { validity } => {
                assert_eq!(validity, Duration::from_secs(86_400));
            }
            IssuanceDecision::Deny(r) => panic!("default policy should accept, got deny: {r}"),
        }
    }

    struct RegistryIssuance {
        allowed_zone: Name,
    }

    impl IssuancePolicy for RegistryIssuance {
        fn decide(&self, ctx: &IssuanceContext<'_>) -> IssuanceDecision {
            if ctx.challenge_type != "token" {
                return IssuanceDecision::Deny(format!(
                    "registry requires `token` challenge, got `{}`",
                    ctx.challenge_type
                ));
            }
            let Ok(name) = ctx.cert_request.name.parse::<Name>() else {
                return IssuanceDecision::Deny(format!(
                    "unparsable subject name: {}",
                    ctx.cert_request.name
                ));
            };
            if !name.has_prefix(&self.allowed_zone) {
                return IssuanceDecision::Deny(format!(
                    "{} is outside registry zone {}",
                    name, self.allowed_zone
                ));
            }
            IssuanceDecision::Issue {
                validity: Duration::from_secs(7 * 86_400),
            }
        }
    }

    #[test]
    fn registry_policy_allows_in_zone_token_request() {
        let zone: Name = "/registry/zone-a".parse().unwrap();
        let policy = RegistryIssuance { allowed_zone: zone };
        let r = req("/registry/zone-a/device/x");
        let ca = "/registry/CA".parse::<Name>().unwrap();
        match policy.decide(&ctx(&r, "token", &ca)) {
            IssuanceDecision::Issue { validity } => {
                assert_eq!(validity, Duration::from_secs(7 * 86_400));
            }
            IssuanceDecision::Deny(r) => panic!("expected accept, got deny: {r}"),
        }
    }

    #[test]
    fn registry_policy_denies_wrong_challenge() {
        let zone: Name = "/registry/zone-a".parse().unwrap();
        let policy = RegistryIssuance { allowed_zone: zone };
        let r = req("/registry/zone-a/device/x");
        let ca = "/registry/CA".parse::<Name>().unwrap();
        match policy.decide(&ctx(&r, "pin", &ca)) {
            IssuanceDecision::Deny(reason) => {
                assert!(
                    reason.contains("token"),
                    "deny reason should mention required challenge: {reason}"
                );
            }
            IssuanceDecision::Issue { .. } => panic!("expected deny on wrong challenge"),
        }
    }

    #[test]
    fn registry_policy_denies_out_of_zone() {
        let zone: Name = "/registry/zone-a".parse().unwrap();
        let policy = RegistryIssuance { allowed_zone: zone };
        let r = req("/registry/zone-b/device/x");
        let ca = "/registry/CA".parse::<Name>().unwrap();
        match policy.decide(&ctx(&r, "token", &ca)) {
            IssuanceDecision::Deny(reason) => {
                assert!(reason.contains("outside"), "reason: {reason}");
            }
            IssuanceDecision::Issue { .. } => panic!("expected deny on out-of-zone name"),
        }
    }

    use crate::attestation::{AttestationSet, ChallengeAttestation};

    fn signed_device_approval() -> AttestationSet {
        let mut leaf = ChallengeAttestation::of_kind("device-approval");
        leaf.signature = Some("c2ln".to_string()); // base64-ish placeholder
        AttestationSet::single(leaf)
    }

    #[test]
    fn require_attestation_allows_outside_gated_prefix() {
        let policy = RequireAttestationKind::new("/high-trust".parse().unwrap(), "device-approval");
        let r = req("/registry/zone-a/device/x");
        let ca = "/registry/CA".parse::<Name>().unwrap();
        // No attestation, but name is outside /high-trust → issue.
        assert!(matches!(
            policy.decide(&ctx(&r, "token", &ca)),
            IssuanceDecision::Issue { .. }
        ));
    }

    #[test]
    fn require_attestation_gates_inside_prefix() {
        let policy = RequireAttestationKind::new("/high-trust".parse().unwrap(), "device-approval");
        let r = req("/high-trust/device/x");
        let ca = "/high-trust/CA".parse::<Name>().unwrap();

        // token challenge → no device-approval leaf → deny.
        let token_att = AttestationSet::single(ChallengeAttestation::of_kind("token"));
        match policy.decide(&ctx_att(&r, "token", &ca, Some(&token_att))) {
            IssuanceDecision::Deny(reason) => assert!(reason.contains("device-approval")),
            IssuanceDecision::Issue { .. } => panic!("expected deny without device-approval leaf"),
        }

        // device-approval leaf present → issue.
        let da = signed_device_approval();
        assert!(matches!(
            policy.decide(&ctx_att(&r, "device-approval", &ca, Some(&da))),
            IssuanceDecision::Issue { .. }
        ));
    }

    #[test]
    fn require_signed_rejects_unsigned_leaf() {
        let policy = RequireAttestationKind::new("/high-trust".parse().unwrap(), "device-approval")
            .require_signed(true);
        let r = req("/high-trust/device/x");
        let ca = "/high-trust/CA".parse::<Name>().unwrap();

        // Unsigned (in-process) device-approval leaf → deny under require_signed.
        let unsigned = AttestationSet::single(ChallengeAttestation::of_kind("device-approval"));
        match policy.decide(&ctx_att(&r, "device-approval", &ca, Some(&unsigned))) {
            IssuanceDecision::Deny(reason) => assert!(reason.contains("signed")),
            IssuanceDecision::Issue { .. } => panic!("expected deny on unsigned leaf"),
        }

        // Signed leaf → issue.
        let signed = signed_device_approval();
        assert!(matches!(
            policy.decide(&ctx_att(&r, "device-approval", &ca, Some(&signed))),
            IssuanceDecision::Issue { .. }
        ));
    }
}
