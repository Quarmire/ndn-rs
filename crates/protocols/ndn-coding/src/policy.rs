//! Coding-policy types and the in-memory policy table.

use std::sync::Arc;

use ndn_foundation_types::Name;
use ndn_store::NameTrie;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyRole {
    Produced,
    Consumed,
}

/// Open enum so an `Rlnc` arm can join later without churning callers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum CodingPolicy {
    Fec(FecPolicy),
    /// F2 in-network RLNC recoding (feature `f2-recode`). See
    /// [`crate::recode`] and `docs/doctrine/nc-recoding-trust-model-2026-05-23.md`.
    #[cfg(feature = "f2-recode")]
    Rlnc(crate::recode::RlncPolicy),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Field {
    Gf8,
}

/// Systematic K-of-N: K source + (N−K) parity segments per generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FecPolicy {
    pub k: u16,
    pub n: u16,
    #[serde(default = "FecPolicy::default_field")]
    pub field: Field,
}

impl FecPolicy {
    /// Returns `None` if `k == 0`, `n < k`, or `n > 255`.
    pub fn systematic(k: u16, n: u16) -> Option<Self> {
        if k == 0 || n < k || n > 255 {
            return None;
        }
        Some(Self {
            k,
            n,
            field: Self::default_field(),
        })
    }

    fn default_field() -> Field {
        Field::Gf8
    }

    /// K=16, N=20, GF(2^8) — applied when FEC is enabled with no parameters.
    pub fn default_enabled() -> Self {
        Self::systematic(16, 20).expect("16-of-20 is in range")
    }
}

/// One `NameTrie` per role with longest-prefix-match lookup.
#[derive(Default)]
pub struct CodingPolicyTable {
    produced: NameTrie<CodingPolicy>,
    consumed: NameTrie<CodingPolicy>,
}

impl CodingPolicyTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, prefix: &Name, role: PolicyRole, policy: CodingPolicy) {
        self.trie(role).insert(prefix, policy);
    }

    pub fn unset(&self, prefix: &Name, role: PolicyRole) {
        self.trie(role).remove(prefix);
    }

    pub fn lookup(&self, name: &Name, role: PolicyRole) -> Option<CodingPolicy> {
        self.trie(role).lpm(name)
    }

    pub fn get_exact(&self, name: &Name, role: PolicyRole) -> Option<CodingPolicy> {
        self.trie(role).get(name)
    }

    pub fn entries(&self) -> Vec<(Name, PolicyRole, CodingPolicy)> {
        let mut out = Vec::new();
        for (n, p) in self.produced.dump() {
            out.push((n, PolicyRole::Produced, p));
        }
        for (n, p) in self.consumed.dump() {
            out.push((n, PolicyRole::Consumed, p));
        }
        out
    }

    fn trie(&self, role: PolicyRole) -> &NameTrie<CodingPolicy> {
        match role {
            PolicyRole::Produced => &self.produced,
            PolicyRole::Consumed => &self.consumed,
        }
    }
}

impl std::fmt::Debug for CodingPolicyTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodingPolicyTable")
            .field("entries", &self.entries().len())
            .finish()
    }
}

pub type SharedPolicyTable = Arc<CodingPolicyTable>;

#[cfg(test)]
mod tests {
    use super::*;

    fn fec_policy(k: u16, n: u16) -> CodingPolicy {
        CodingPolicy::Fec(FecPolicy::systematic(k, n).unwrap())
    }

    #[test]
    fn set_and_lookup_exact() {
        let table = CodingPolicyTable::new();
        let prefix: Name = "/alice/video".parse().unwrap();
        table.set(&prefix, PolicyRole::Produced, fec_policy(8, 12));
        assert!(matches!(
            table.lookup(&prefix, PolicyRole::Produced),
            Some(CodingPolicy::Fec(_))
        ));
        assert!(table.lookup(&prefix, PolicyRole::Consumed).is_none());
    }

    #[test]
    fn longest_prefix_match() {
        let table = CodingPolicyTable::new();
        let video: Name = "/alice/video".parse().unwrap();
        let alice: Name = "/alice".parse().unwrap();
        table.set(&alice, PolicyRole::Produced, fec_policy(4, 6));
        table.set(&video, PolicyRole::Produced, fec_policy(16, 20));
        let child: Name = "/alice/video/v=1/seg=0".parse().unwrap();
        let policy = table.lookup(&child, PolicyRole::Produced).unwrap();
        match policy {
            CodingPolicy::Fec(p) => assert_eq!((p.k, p.n), (16, 20)),
            #[cfg(feature = "f2-recode")]
            CodingPolicy::Rlnc(_) => unreachable!("test inserts only Fec"),
        }
        let other: Name = "/alice/photos/seg=0".parse().unwrap();
        let policy = table.lookup(&other, PolicyRole::Produced).unwrap();
        match policy {
            CodingPolicy::Fec(p) => assert_eq!((p.k, p.n), (4, 6)),
            #[cfg(feature = "f2-recode")]
            CodingPolicy::Rlnc(_) => unreachable!("test inserts only Fec"),
        }
    }

    #[test]
    fn roles_are_independent() {
        let table = CodingPolicyTable::new();
        let prefix: Name = "/x".parse().unwrap();
        table.set(&prefix, PolicyRole::Produced, fec_policy(8, 10));
        table.set(&prefix, PolicyRole::Consumed, fec_policy(16, 20));
        match table.lookup(&prefix, PolicyRole::Produced).unwrap() {
            CodingPolicy::Fec(p) => assert_eq!(p.k, 8),
            #[cfg(feature = "f2-recode")]
            CodingPolicy::Rlnc(_) => unreachable!("test inserts only Fec"),
        }
        match table.lookup(&prefix, PolicyRole::Consumed).unwrap() {
            CodingPolicy::Fec(p) => assert_eq!(p.k, 16),
            #[cfg(feature = "f2-recode")]
            CodingPolicy::Rlnc(_) => unreachable!("test inserts only Fec"),
        }
    }

    #[test]
    fn unset_removes_entry() {
        let table = CodingPolicyTable::new();
        let p: Name = "/x".parse().unwrap();
        table.set(&p, PolicyRole::Produced, fec_policy(4, 6));
        assert!(table.lookup(&p, PolicyRole::Produced).is_some());
        table.unset(&p, PolicyRole::Produced);
        assert!(table.lookup(&p, PolicyRole::Produced).is_none());
    }

    #[test]
    fn entries_returns_all() {
        let table = CodingPolicyTable::new();
        table.set(
            &"/a".parse().unwrap(),
            PolicyRole::Produced,
            fec_policy(4, 5),
        );
        table.set(
            &"/b".parse().unwrap(),
            PolicyRole::Consumed,
            fec_policy(8, 10),
        );
        let entries = table.entries();
        assert_eq!(entries.len(), 2);
    }
}
