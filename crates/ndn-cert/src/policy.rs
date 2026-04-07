//! Namespace policies — define what certificate names a CA may issue.
//!
//! A CA should only issue certificates for names within its authorized namespace.
//! Policies are checked before a challenge is even started, preventing
//! unauthorized cross-namespace issuance.

use ndn_packet::Name;
use ndn_security::Certificate;

/// Decision returned by a namespace policy evaluation.
#[derive(Debug, Clone)]
pub enum PolicyDecision {
    /// Allow the request.
    Allow,
    /// Deny the request with a reason.
    Deny(String),
}

/// A policy that decides whether a CA may issue a certificate for a given name.
pub trait NamespacePolicy: Send + Sync {
    /// Evaluate whether `requested_name` may be issued to a requester holding
    /// `requester_cert` (may be `None` for the first enrollment).
    fn evaluate(
        &self,
        requested_name: &Name,
        requester_cert: Option<&Certificate>,
        ca_prefix: &Name,
    ) -> PolicyDecision;
}

/// The hierarchical policy: a requester may only obtain certificates for names
/// that are strictly under their own current certificate's identity prefix.
///
/// A CA under `/com/acme/fleet/CA` may also issue to any name under
/// `/com/acme/fleet/`.
///
/// # Examples
///
/// - `/com/acme/fleet/VIN-123` can request `/com/acme/fleet/VIN-123/ecu/brake` ✓
/// - `/com/acme/fleet/VIN-123` cannot request `/com/acme/fleet/VIN-456/...` ✗
/// - A new device (no cert yet) may request any name under the CA's prefix ✓
pub struct HierarchicalPolicy;

impl NamespacePolicy for HierarchicalPolicy {
    fn evaluate(
        &self,
        requested_name: &Name,
        requester_cert: Option<&Certificate>,
        ca_prefix: &Name,
    ) -> PolicyDecision {
        // Extract CA identity prefix (strip /CA suffix if present)
        let ca_identity = strip_ca_suffix(ca_prefix);

        // New device (no existing cert): may request any name under the CA's namespace
        let requester_prefix = match requester_cert {
            None => ca_identity.clone(),
            Some(cert) => {
                // Strip /KEY/... suffix to get the identity name
                strip_key_suffix(cert.name.as_ref())
            }
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

/// A policy based on explicit delegation rules.
///
/// Each rule maps a requester name pattern to a set of allowed sub-prefixes.
pub struct DelegationPolicy {
    /// List of (requester_prefix, allowed_name_prefix) pairs.
    pub rules: Vec<(Name, Name)>,
    /// Whether to allow new devices (no cert) to request under any rule's allowed prefix.
    pub allow_new_devices: bool,
}

impl DelegationPolicy {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            allow_new_devices: true,
        }
    }

    /// Allow requester under `requester_prefix` to get certs under `allowed_prefix`.
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
                    // Allow new devices to request under any allowed prefix
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

fn strip_key_suffix(name: &Name) -> Name {
    let comps = name.components();
    // NAME_COMPONENT type is 0x08; "KEY" component
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
    // Strip trailing /CA component if present
    if let Some(last) = comps.last()
        && last.typ == 0x08
        && last.value.as_ref() == b"CA"
    {
        return Name::from_components(comps[..comps.len() - 1].iter().cloned());
    }
    name.clone()
}
