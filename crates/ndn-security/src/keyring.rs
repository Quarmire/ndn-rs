//! [`Keyring`] — the set of [`TrustContext`]s a node holds.
//!
//! Adopting a context is additive and orthogonal: a node may hold
//! `/home/bob`, `/work/acme`, and `/transit/city` at once, validating data
//! under each by its own schema and anchors. A [`Validator`](crate::Validator)
//! dispatches each packet to the context selected by [`context_for`] —
//! longest-prefix match on the data/command name — never "any anchor I hold."
//!
//! [`context_for`]: Keyring::context_for

use std::sync::Arc;

use dashmap::DashMap;
use ndn_packet::Name;

use crate::trust_context::TrustContext;

/// A node's set of adopted trust contexts plus an ambient fallback context.
///
/// The `ambient` context (namespace `/`) backs the flat-anchor / single-schema
/// API on [`Validator`](crate::Validator) for backward compatibility; named
/// contexts adopted via [`adopt`](Self::adopt) take precedence by
/// longest-prefix match.
#[derive(Debug)]
pub struct Keyring {
    contexts: DashMap<Name, Arc<TrustContext>>,
    ambient: Arc<TrustContext>,
}

impl Keyring {
    pub(crate) fn with_ambient(ambient: Arc<TrustContext>) -> Self {
        Self {
            contexts: DashMap::new(),
            ambient,
        }
    }

    /// The ambient (root-namespace) context — the validation target for names
    /// not covered by any adopted context.
    pub fn ambient(&self) -> &Arc<TrustContext> {
        &self.ambient
    }

    /// Adopt a context into the keyring, keyed by its namespace.
    ///
    /// Anti-rollback: a context is accepted only if its `version` is **≥** the
    /// version currently held for the same namespace (a strictly older version
    /// is refused, so an attacker cannot serve a stale context to re-introduce
    /// a weakened schema or a revoked anchor). Returns `true` if adopted.
    pub fn adopt(&self, ctx: Arc<TrustContext>) -> bool {
        let ns = ctx.namespace().clone();
        if let Some(existing) = self.contexts.get(&ns)
            && ctx.version() < existing.version()
        {
            return false;
        }
        self.contexts.insert(ns, ctx);
        true
    }

    /// The version currently held for `namespace`, if any context is adopted.
    pub fn version_of(&self, namespace: &Name) -> Option<u64> {
        self.contexts.get(namespace).map(|c| c.version())
    }

    /// Drop a context by namespace; returns whether one was removed.
    pub fn forget(&self, namespace: &Name) -> bool {
        self.contexts.remove(namespace).is_some()
    }

    /// All adopted (non-ambient) contexts.
    pub fn contexts(&self) -> Vec<Arc<TrustContext>> {
        self.contexts
            .iter()
            .map(|r| Arc::clone(r.value()))
            .collect()
    }

    /// Number of adopted (non-ambient) contexts.
    pub fn len(&self) -> usize {
        self.contexts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.contexts.is_empty()
    }

    /// Select the context governing `name`: the adopted context whose
    /// namespace is the longest prefix of `name`, else the ambient context.
    pub fn context_for(&self, name: &Name) -> Arc<TrustContext> {
        let mut best: Option<Arc<TrustContext>> = None;
        let mut best_len = 0usize;
        for r in self.contexts.iter() {
            let ns = r.key();
            // ns is a prefix of name, and longer (more specific) than any
            // match so far.
            if name.has_prefix(ns) && (best.is_none() || ns.len() > best_len) {
                best_len = ns.len();
                best = Some(Arc::clone(r.value()));
            }
        }
        best.unwrap_or_else(|| Arc::clone(&self.ambient))
    }

    /// Whether `name` is an anchor in *any* held context (ambient included).
    /// Anchor *termination* during a chain walk is still per-context; this is
    /// the membership query used by diagnostics.
    pub fn is_anchor(&self, name: &Name) -> bool {
        self.ambient.is_anchor(name) || self.contexts.iter().any(|r| r.value().is_anchor(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn keyring() -> Keyring {
        let ambient = Arc::new(TrustContext::accept_all(Name::root()));
        Keyring::with_ambient(ambient)
    }

    #[test]
    fn empty_keyring_falls_back_to_ambient() {
        let kr = keyring();
        let ctx = kr.context_for(&n("/home/bob/doc"));
        assert_eq!(ctx.namespace(), &Name::root());
    }

    #[test]
    fn longest_prefix_match_wins() {
        let kr = keyring();
        kr.adopt(Arc::new(TrustContext::hierarchical(n("/home"))));
        kr.adopt(Arc::new(TrustContext::hierarchical(n("/home/bob"))));
        kr.adopt(Arc::new(TrustContext::hierarchical(n("/work/acme"))));

        assert_eq!(
            kr.context_for(&n("/home/bob/doc")).namespace(),
            &n("/home/bob")
        );
        assert_eq!(
            kr.context_for(&n("/home/alice/doc")).namespace(),
            &n("/home")
        );
        assert_eq!(
            kr.context_for(&n("/work/acme/sensor")).namespace(),
            &n("/work/acme")
        );
        // Unmatched namespace → ambient.
        assert_eq!(kr.context_for(&n("/transit/x")).namespace(), &Name::root());
    }

    #[test]
    fn forget_removes_context() {
        let kr = keyring();
        kr.adopt(Arc::new(TrustContext::hierarchical(n("/home/bob"))));
        assert_eq!(kr.len(), 1);
        assert!(kr.forget(&n("/home/bob")));
        assert!(kr.is_empty());
        assert_eq!(
            kr.context_for(&n("/home/bob/doc")).namespace(),
            &Name::root()
        );
    }
}
