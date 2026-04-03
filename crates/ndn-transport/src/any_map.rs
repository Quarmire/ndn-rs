use std::any::{Any, TypeId};
use std::collections::HashMap;

/// A type-erased map keyed by `TypeId`.
///
/// Each concrete type can appear at most once (like a typed slot).
/// Used by `PacketContext::tags` for inter-stage communication and by
/// `StrategyContext::extensions` for cross-layer enrichment data.
pub struct AnyMap(HashMap<TypeId, Box<dyn Any + Send + Sync>>);

impl AnyMap {
    /// Create an empty map.
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    /// Insert a value, replacing any previous value of the same type.
    pub fn insert<T: Any + Send + Sync>(&mut self, val: T) {
        self.0.insert(TypeId::of::<T>(), Box::new(val));
    }

    /// Retrieve a reference to a value by type, if present.
    pub fn get<T: Any + Send + Sync>(&self) -> Option<&T> {
        self.0.get(&TypeId::of::<T>())?.downcast_ref()
    }

    /// Remove and return a value by type, if present.
    pub fn remove<T: Any + Send + Sync>(&mut self) -> Option<T> {
        self.0
            .remove(&TypeId::of::<T>())
            .and_then(|b| b.downcast().ok())
            .map(|b| *b)
    }
}

impl Default for AnyMap {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_get_roundtrip() {
        let mut m = AnyMap::new();
        m.insert(42u32);
        assert_eq!(m.get::<u32>(), Some(&42u32));
        assert!(m.get::<u64>().is_none());
    }

    #[test]
    fn insert_overwrite() {
        let mut m = AnyMap::new();
        m.insert(1u32);
        m.insert(2u32);
        assert_eq!(m.get::<u32>(), Some(&2u32));
    }

    #[test]
    fn remove_takes_value() {
        let mut m = AnyMap::new();
        m.insert(99u32);
        let v = m.remove::<u32>();
        assert_eq!(v, Some(99u32));
        assert!(m.get::<u32>().is_none());
    }

    #[test]
    fn different_types_coexist() {
        let mut m = AnyMap::new();
        m.insert(1u32);
        m.insert("hello");
        assert_eq!(m.get::<u32>(), Some(&1u32));
        assert_eq!(m.get::<&str>(), Some(&"hello"));
    }

    #[test]
    fn default_is_empty() {
        let m = AnyMap::default();
        assert!(m.get::<u32>().is_none());
    }
}
