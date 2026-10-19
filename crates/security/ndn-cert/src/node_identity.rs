//! The node identity: the identity a device signs its own traffic as —
//! management responses, discovery records, routing updates, its link key —
//! as opposed to the Data it publishes under each trusted prefix, whose
//! name chooses the key (`ndn_security::SecurityManager::signer_for`).
//!
//! It is decided from durable data, first match wins
//! ([`choose_node_identity`]):
//!
//! 1. `[security] identity`, when the host's configuration names one;
//! 2. the PIB's default identity — recorded by the device's first
//!    enrollment, or set by an operator;
//! 3. the device identity in a namespace whose root this PIB holds (a root
//!    device takes part in its own namespace);
//! 4. the first enrolled: the device identity, in a namespace whose trust
//!    context the PIB keeps, whose currently valid certificate is oldest;
//! 5. none: the host signs with an in-memory key minted at startup.
//!
//! Enrolling in another namespace never changes it once there is one (an
//! enrollment records the PIB default only when there is none). Changing it
//! is an operator's act: `[security] identity`, or setting the PIB's
//! default identity.

use ndn_packet::Name;
use ndn_security::{Certificate, FilePib};

use crate::roles::parse_device_key;
use crate::root_store::RootStore;

/// Which rule chose the node identity ([`NodeIdentity::source`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeIdentitySource {
    /// The host's configuration names it (`[security] identity`).
    Configured,
    /// The PIB's default identity: recorded by the first enrollment, or
    /// set by an operator.
    PibDefault,
    /// The device identity in a namespace whose root this PIB holds.
    RootDevice,
    /// The device identity whose currently valid certificate is oldest.
    FirstEnrolled,
    /// No persistent identity: an in-memory key minted at startup.
    Ephemeral,
}

impl NodeIdentitySource {
    /// Stable token for machine-readable reports (`node_identity_source=`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Configured => "configured",
            Self::PibDefault => "pib-default",
            Self::RootDevice => "root-device",
            Self::FirstEnrolled => "first-enrolled",
            Self::Ephemeral => "ephemeral",
        }
    }

    /// Why this identity is the node identity, in words.
    pub fn describe(self) -> &'static str {
        match self {
            Self::Configured => "named by [security] identity in the configuration",
            Self::PibDefault => {
                "the PIB's default identity (recorded by the first enrollment or set by an \
                 operator)"
            }
            Self::RootDevice => "this device's identity in the namespace whose root it holds",
            Self::FirstEnrolled => {
                "the identity this device enrolled first (its oldest currently valid certificate)"
            }
            Self::Ephemeral => {
                "no persistent identity: an in-memory key minted at startup, not kept across \
                 restarts"
            }
        }
    }
}

impl std::fmt::Display for NodeIdentitySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The node identity and the rule that chose it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeIdentity {
    /// `None` for [`NodeIdentitySource::Ephemeral`].
    pub identity: Option<Name>,
    pub source: NodeIdentitySource,
}

/// Decide the node identity of a device whose PIB is `pib` (`None`: it has
/// none) and whose configuration names `configured`, by the rules of the
/// [module docs](self). Storage it cannot read (a root store, the stored
/// trust contexts) is logged and that rule skipped.
pub fn choose_node_identity(pib: Option<&FilePib>, configured: Option<&Name>) -> NodeIdentity {
    let chosen = |identity: Name, source| NodeIdentity {
        identity: Some(identity),
        source,
    };
    if let Some(identity) = configured {
        return chosen(identity.clone(), NodeIdentitySource::Configured);
    }
    let Some(pib) = pib else {
        return ephemeral();
    };
    match pib.get_default_identity() {
        Ok(Some(identity)) => return chosen(identity, NodeIdentitySource::PibDefault),
        Ok(None) => {}
        Err(e) => tracing::warn!(
            target: "security",
            pib = %pib.root().display(),
            error = %e,
            "unreadable default identity in the PIB; ignoring it"
        ),
    }
    let keys = match pib.list_keys() {
        Ok(keys) => keys,
        Err(e) => {
            tracing::warn!(
                target: "security",
                pib = %pib.root().display(),
                error = %e,
                "cannot list the PIB's keys; no persistent node identity"
            );
            return ephemeral();
        }
    };
    let roots = match RootStore::open_all(pib) {
        Ok(stores) => stores.iter().map(|s| s.namespace().clone()).collect(),
        Err(e) => {
            tracing::warn!(
                target: "security",
                pib = %pib.root().display(),
                error = %e,
                "cannot read the PIB's root stores; not choosing the node identity by them"
            );
            Vec::new()
        }
    };
    if let Some(identity) = oldest_device_identity(pib, &keys, &roots) {
        return chosen(identity, NodeIdentitySource::RootDevice);
    }
    let held = held_namespaces(pib);
    if let Some(identity) = oldest_device_identity(pib, &keys, &held) {
        return chosen(identity, NodeIdentitySource::FirstEnrolled);
    }
    ephemeral()
}

fn ephemeral() -> NodeIdentity {
    NodeIdentity {
        identity: None,
        source: NodeIdentitySource::Ephemeral,
    }
}

/// The namespaces whose trust context the PIB keeps.
fn held_namespaces(pib: &FilePib) -> Vec<Name> {
    match crate::context_store::read_stored_contexts(pib.root()) {
        Ok(stored) => stored
            .into_iter()
            .filter_map(|(_, read)| read.ok().map(|(ctx, _)| ctx.namespace().clone()))
            .collect(),
        Err(e) => {
            tracing::warn!(
                target: "security",
                pib = %pib.root().display(),
                error = %e,
                "cannot read the trust contexts kept in the PIB; not choosing the node identity \
                 by them"
            );
            Vec::new()
        }
    }
}

/// Of the device keys `/<ns>/<role>/<device>/KEY/…` in `namespaces`, the
/// identity of the one whose currently valid certificate is oldest (on a
/// tie, the smaller key name).
fn oldest_device_identity(pib: &FilePib, keys: &[Name], namespaces: &[Name]) -> Option<Name> {
    keys.iter()
        .filter_map(|key| {
            let ns = namespaces
                .iter()
                .find(|ns| parse_device_key(ns, key).is_some())?;
            let valid_from = pib
                .certs(key)
                .ok()?
                .iter()
                .filter(|c| Certificate::is_valid_now(c))
                .map(|c| c.valid_from)
                .min()?;
            let identity = Name::from_components(key.components()[..ns.len() + 2].iter().cloned());
            Some((valid_from, key, identity))
        })
        .min_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(b.1)))
        .map(|(_, _, identity)| identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NewRootStore;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    /// The rules in order: configured, PIB default, root device, none. An
    /// identity enrolled later never displaces one found earlier.
    #[test]
    fn node_identity_follows_the_rules_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let pib = FilePib::new(dir.path()).unwrap();
        assert_eq!(
            choose_node_identity(Some(&pib), None).source,
            NodeIdentitySource::Ephemeral
        );
        assert_eq!(
            choose_node_identity(None, None).source,
            NodeIdentitySource::Ephemeral
        );

        let persisted = futures::executor::block_on(crate::init_namespace_in_pib(
            &pib,
            &n("/home/bob"),
            "desk",
            false,
            &NewRootStore::File,
        ))
        .unwrap();
        let chosen = choose_node_identity(Some(&pib), None);
        assert_eq!(chosen.source, NodeIdentitySource::RootDevice);
        assert_eq!(chosen.identity, Some(persisted.device_identity.clone()));

        // A default identity recorded in the PIB takes precedence…
        let other = n("/work/acme/member/desk");
        ndn_security::SecurityManager::auto_init(&other, dir.path()).unwrap();
        pib.set_default_identity(&other).unwrap();
        let chosen = choose_node_identity(Some(&pib), None);
        assert_eq!(chosen.source, NodeIdentitySource::PibDefault);
        assert_eq!(chosen.identity, Some(other));

        // …and a configured one over everything.
        let configured = n("/configured/node");
        let chosen = choose_node_identity(Some(&pib), Some(&configured));
        assert_eq!(chosen.source, NodeIdentitySource::Configured);
        assert_eq!(chosen.identity, Some(configured));
    }
}
