//! Each held namespace's sync group on this device's forwarder:
//! `<ns>/32=sync` ([`ndn_security::sync_group`]), where the namespace's
//! devices say what they wrote (`docs/specs/data-layer.md` §12). Not the
//! trust-context group of [`crate::sync`].
//!
//! A forwarder holding a namespace's trust context runs the namespace's
//! group with the multicast strategy ([`carry`]), so a Sync Interest goes
//! to every face the group is routed to, never back where it came from: the
//! device's own member (its data layer registers the group for its sync
//! face) and each link that carries the namespace (the link library routes
//! the group over a link while it is up and admitted in the namespace, as it
//! routes the linked device's name). [`Participant::new`](crate::Participant::new)
//! carries the group of every namespace the keyring holds then and of each
//! one it adopts later; nothing in this crate drops a held namespace, so the
//! strategy stays while the forwarder runs.

use std::collections::HashSet;
use std::sync::Arc;

use ndn_engine::ForwarderEngine;
use ndn_packet::Name;
use ndn_security::{Keyring, sync_group};
use ndn_store::StrategyTable;
use ndn_strategy::{ErasedStrategy, MulticastStrategy};

/// Run `namespace`'s sync group with the multicast strategy on `engine`.
pub fn carry(engine: &ForwarderEngine, namespace: &Name) {
    install(&engine.strategy_table(), namespace);
}

fn install(strategies: &StrategyTable<dyn ErasedStrategy>, namespace: &Name) {
    strategies.insert(
        &sync_group(namespace),
        Arc::new(MulticastStrategy::new()) as Arc<dyn ErasedStrategy>,
    );
    tracing::debug!(
        target: "security",
        %namespace,
        group = %sync_group(namespace),
        "the namespace's sync group runs with the multicast strategy"
    );
}

/// Carry the group of every namespace `keyring` holds, now and as it adopts
/// new ones: each once, when first held (a newer version of a held
/// namespace leaves its strategy as it is).
pub(crate) fn carry_held(engine: &ForwarderEngine, keyring: &Keyring) {
    let strategies = engine.strategy_table();
    let carried = Arc::new(parking_lot::Mutex::new(HashSet::new()));
    let first = {
        let strategies = Arc::clone(&strategies);
        let carried = Arc::clone(&carried);
        move |namespace: &Name| {
            if carried.lock().insert(namespace.clone()) {
                install(&strategies, namespace);
            }
        }
    };
    // Listening first: a namespace adopted while the held ones are walked
    // is carried either way, and only once.
    let adopted = first.clone();
    keyring.on_adoption(move |ctx| adopted(ctx.namespace()));
    for ctx in keyring.contexts() {
        first(ctx.namespace());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_engine::{EngineBuilder, EngineConfig};
    use ndn_security::SignedTrustContext;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn strategy_at(engine: &ForwarderEngine, name: &Name) -> Option<Name> {
        engine
            .strategy_table()
            .dump()
            .into_iter()
            .find(|(prefix, _)| prefix == name)
            .map(|(_, s)| s.name().clone())
    }

    /// A namespace held at start and one adopted later both have their
    /// group run with multicast; nothing else gets a strategy.
    #[tokio::test]
    async fn held_and_adopted_namespaces_run_their_group_with_multicast() {
        let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
            .security_profile(ndn_security::SecurityProfile::Disabled)
            .build()
            .await
            .unwrap();
        let keyring = Keyring::new();
        assert!(keyring.adopt(Arc::new(SignedTrustContext::hierarchical(n("/alice")))));
        let before = engine.strategy_table().dump().len();

        carry_held(&engine, &keyring);
        let multicast = MulticastStrategy::strategy_name();
        assert_eq!(
            strategy_at(&engine, &n("/alice/32=sync")),
            Some(multicast.clone())
        );
        assert_eq!(strategy_at(&engine, &n("/home/bob/32=sync")), None);

        assert!(keyring.adopt(Arc::new(SignedTrustContext::hierarchical(n("/home/bob")))));
        assert_eq!(
            strategy_at(&engine, &n("/home/bob/32=sync")),
            Some(multicast)
        );
        assert_eq!(engine.strategy_table().dump().len(), before + 2);
        shutdown.shutdown().await;
    }
}
