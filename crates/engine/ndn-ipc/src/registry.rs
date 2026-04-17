use std::collections::HashMap;

use bytes::Bytes;

/// A registered service entry in the local namespace.
pub struct ServiceEntry {
    pub capabilities: Bytes,
}

/// Service registry backed by the NDN namespace.
///
/// Services advertise under `/local/services/<name>/info` (capabilities)
/// and `/local/services/<name>/alive` (heartbeat with short FreshnessPeriod).
/// Discovery is a CanBePrefix Interest for `/local/services`.
///
/// This in-memory implementation is used for testing and single-process deployments.
/// A production implementation would publish and fetch `Data` packets via the engine.
pub struct ServiceRegistry {
    services: HashMap<String, ServiceEntry>,
}

impl ServiceRegistry {
    pub fn new() -> Self {
        Self {
            services: HashMap::new(),
        }
    }

    pub fn register(&mut self, name: impl Into<String>, capabilities: Bytes) {
        self.services
            .insert(name.into(), ServiceEntry { capabilities });
    }

    pub fn lookup(&self, name: &str) -> Option<&ServiceEntry> {
        self.services.get(name)
    }

    pub fn unregister(&mut self, name: &str) -> bool {
        self.services.remove(name).is_some()
    }

    pub fn service_count(&self) -> usize {
        self.services.len()
    }
}

impl Default for ServiceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_lookup() {
        let mut reg = ServiceRegistry::new();
        reg.register("foo", Bytes::from_static(b"caps"));
        let entry = reg.lookup("foo").unwrap();
        assert_eq!(entry.capabilities, Bytes::from_static(b"caps"));
    }

    #[test]
    fn lookup_missing_returns_none() {
        let reg = ServiceRegistry::new();
        assert!(reg.lookup("missing").is_none());
    }

    #[test]
    fn unregister_removes_entry() {
        let mut reg = ServiceRegistry::new();
        reg.register("bar", Bytes::new());
        assert!(reg.unregister("bar"));
        assert!(reg.lookup("bar").is_none());
    }

    #[test]
    fn unregister_nonexistent_returns_false() {
        let mut reg = ServiceRegistry::new();
        assert!(!reg.unregister("nope"));
    }

    #[test]
    fn service_count() {
        let mut reg = ServiceRegistry::new();
        assert_eq!(reg.service_count(), 0);
        reg.register("a", Bytes::new());
        reg.register("b", Bytes::new());
        assert_eq!(reg.service_count(), 2);
        reg.unregister("a");
        assert_eq!(reg.service_count(), 1);
    }
}
