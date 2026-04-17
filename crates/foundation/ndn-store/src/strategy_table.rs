use std::sync::Arc;

use ndn_packet::Name;

use crate::NameTrie;

/// Maps name prefixes to strategy instances via longest-prefix match.
///
/// This is a second `NameTrie` that runs in parallel with the FIB. It maps
/// name prefixes to strategy objects of type `S` (typically `dyn Strategy`
/// from `ndn-strategy`). Keeping the type parameter generic avoids a
/// dependency on `ndn-strategy` from `ndn-store`.
pub struct StrategyTable<S: Send + Sync + 'static + ?Sized>(NameTrie<Arc<S>>);

impl<S: Send + Sync + 'static + ?Sized> StrategyTable<S> {
    pub fn new() -> Self {
        Self(NameTrie::new())
    }

    pub fn lpm(&self, name: &Name) -> Option<Arc<S>> {
        self.0.lpm(name)
    }

    pub fn insert(&self, prefix: &Name, strategy: Arc<S>) {
        self.0.insert(prefix, strategy);
    }

    pub fn remove(&self, prefix: &Name) {
        self.0.remove(prefix);
    }

    pub fn dump(&self) -> Vec<(Name, Arc<S>)> {
        self.0.dump()
    }
}

impl<S: Send + Sync + 'static + ?Sized> Default for StrategyTable<S> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ndn_packet::NameComponent;

    fn name(components: &[&str]) -> Name {
        Name::from_components(
            components
                .iter()
                .map(|s| NameComponent::generic(Bytes::copy_from_slice(s.as_bytes()))),
        )
    }

    struct MockStrategy(u32);

    #[test]
    fn lpm_empty_returns_none() {
        let table: StrategyTable<MockStrategy> = StrategyTable::new();
        assert!(table.lpm(&name(&["a", "b"])).is_none());
    }

    #[test]
    fn lpm_exact_match() {
        let table: StrategyTable<MockStrategy> = StrategyTable::new();
        table.insert(&name(&["a"]), Arc::new(MockStrategy(1)));
        let s = table.lpm(&name(&["a"])).unwrap();
        assert_eq!(s.0, 1);
    }

    #[test]
    fn lpm_most_specific_wins() {
        let table: StrategyTable<MockStrategy> = StrategyTable::new();
        table.insert(&name(&["a"]), Arc::new(MockStrategy(10)));
        table.insert(&name(&["a", "b"]), Arc::new(MockStrategy(20)));
        let s = table.lpm(&name(&["a", "b", "c"])).unwrap();
        assert_eq!(s.0, 20);
    }

    #[test]
    fn lpm_fallback_to_shorter_prefix() {
        let table: StrategyTable<MockStrategy> = StrategyTable::new();
        table.insert(&name(&["a"]), Arc::new(MockStrategy(5)));
        let s = table.lpm(&name(&["a", "b"])).unwrap();
        assert_eq!(s.0, 5);
    }

    #[test]
    fn lpm_default_strategy_at_root() {
        let table: StrategyTable<MockStrategy> = StrategyTable::new();
        table.insert(&Name::root(), Arc::new(MockStrategy(99)));
        let s = table.lpm(&name(&["x", "y", "z"])).unwrap();
        assert_eq!(s.0, 99);
    }

    #[test]
    fn remove_clears_entry() {
        let table: StrategyTable<MockStrategy> = StrategyTable::new();
        table.insert(&name(&["a"]), Arc::new(MockStrategy(1)));
        table.remove(&name(&["a"]));
        assert!(table.lpm(&name(&["a"])).is_none());
    }

    #[test]
    fn insert_replaces_strategy() {
        let table: StrategyTable<MockStrategy> = StrategyTable::new();
        table.insert(&name(&["a"]), Arc::new(MockStrategy(1)));
        table.insert(&name(&["a"]), Arc::new(MockStrategy(2)));
        let s = table.lpm(&name(&["a"])).unwrap();
        assert_eq!(s.0, 2);
    }
}
