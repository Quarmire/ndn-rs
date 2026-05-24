//! Behavioural side of the `/localhost/nfd/coding/{set,unset,list}` mgmt
//! verbs over a `SharedPolicyTable`. Wire-protocol registration lives in
//! `ndn-mgmt`.

use std::sync::Arc;

use ndn_foundation_types::Name;

use crate::Result;
use crate::policy::{
    CodingPolicy, CodingPolicyTable, FecPolicy, Field, PolicyRole, SharedPolicyTable,
};

/// Mgmt-verb dispatcher for `/localhost/nfd/coding/*`; cheap to clone.
#[derive(Clone)]
pub struct CodingMgmtHandler {
    table: SharedPolicyTable,
}

impl CodingMgmtHandler {
    pub fn new(table: SharedPolicyTable) -> Self {
        Self { table }
    }

    pub fn with_new_table() -> Self {
        Self::new(Arc::new(CodingPolicyTable::new()))
    }

    pub fn table(&self) -> &SharedPolicyTable {
        &self.table
    }

    pub fn handle_set(&self, prefix: &Name, role: PolicyRole, policy: CodingPolicy) -> Result<()> {
        self.table.set(prefix, role, policy);
        Ok(())
    }

    pub fn handle_unset(&self, prefix: &Name, role: PolicyRole) -> Result<()> {
        self.table.unset(prefix, role);
        Ok(())
    }

    pub fn handle_list(&self) -> Result<Vec<CodingPolicyEntry>> {
        let mut entries = self
            .table
            .entries()
            .into_iter()
            .map(|(prefix, role, policy)| CodingPolicyEntry {
                prefix,
                role,
                policy,
            })
            .collect::<Vec<_>>();
        entries.sort_by(|a, b| (a.role as u8, &a.prefix).cmp(&(b.role as u8, &b.prefix)));
        Ok(entries)
    }
}

#[derive(Debug, Clone)]
pub struct CodingPolicyEntry {
    pub prefix: Name,
    pub role: PolicyRole,
    pub policy: CodingPolicy,
}

impl ndn_mgmt::CodingHandler for CodingMgmtHandler {
    fn set(&self, prefix: &Name, entry: ndn_mgmt::CodingEntry) -> std::result::Result<(), String> {
        let role = map_role(entry.role);
        let field = map_field_from_wire(entry.field);
        let fec = FecPolicy::systematic(entry.k, entry.n)
            .ok_or_else(|| format!("invalid (k, n) = ({}, {})", entry.k, entry.n))?;
        let policy = CodingPolicy::Fec(FecPolicy { field, ..fec });
        self.table.set(prefix, role, policy);
        Ok(())
    }

    fn unset(&self, prefix: &Name, role: ndn_mgmt::CodingRole) -> std::result::Result<(), String> {
        self.table.unset(prefix, map_role(role));
        Ok(())
    }

    fn list(&self) -> Vec<(Name, ndn_mgmt::CodingEntry)> {
        self.table
            .entries()
            .into_iter()
            .map(|(prefix, role, policy)| {
                let entry = match policy {
                    CodingPolicy::Fec(fec) => ndn_mgmt::CodingEntry {
                        role: map_role_to_wire(role),
                        k: fec.k,
                        n: fec.n,
                        field: map_field_to_wire(fec.field),
                    },
                    // F2 has no fixed N (recoders mint further combinations),
                    // so report `k` as the decode-rank target. Surfacing the
                    // recode policy in mgmt is deferred to the F2
                    // implementation pass (wire spec §8).
                    #[cfg(feature = "f2-recode")]
                    CodingPolicy::Rlnc(r) => ndn_mgmt::CodingEntry {
                        role: map_role_to_wire(role),
                        k: r.k,
                        n: r.k,
                        field: map_field_to_wire(r.field),
                    },
                };
                (prefix, entry)
            })
            .collect()
    }
}

fn map_role(r: ndn_mgmt::CodingRole) -> PolicyRole {
    match r {
        ndn_mgmt::CodingRole::Produced => PolicyRole::Produced,
        ndn_mgmt::CodingRole::Consumed => PolicyRole::Consumed,
    }
}

fn map_role_to_wire(r: PolicyRole) -> ndn_mgmt::CodingRole {
    match r {
        PolicyRole::Produced => ndn_mgmt::CodingRole::Produced,
        PolicyRole::Consumed => ndn_mgmt::CodingRole::Consumed,
    }
}

fn map_field_from_wire(f: ndn_mgmt::CodingFieldId) -> Field {
    match f {
        ndn_mgmt::CodingFieldId::Gf8 => Field::Gf8,
    }
}

fn map_field_to_wire(f: Field) -> ndn_mgmt::CodingFieldId {
    match f {
        Field::Gf8 => ndn_mgmt::CodingFieldId::Gf8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::FecPolicy;

    fn fec(k: u16, n: u16) -> CodingPolicy {
        CodingPolicy::Fec(FecPolicy::systematic(k, n).unwrap())
    }

    #[test]
    fn set_then_list() {
        let h = CodingMgmtHandler::with_new_table();
        let alice: Name = "/alice".parse().unwrap();
        let bob: Name = "/bob".parse().unwrap();
        h.handle_set(&alice, PolicyRole::Produced, fec(8, 12))
            .unwrap();
        h.handle_set(&bob, PolicyRole::Consumed, fec(16, 20))
            .unwrap();
        let list = h.handle_list().unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn unset_is_idempotent() {
        let h = CodingMgmtHandler::with_new_table();
        let p: Name = "/x".parse().unwrap();
        h.handle_unset(&p, PolicyRole::Produced).unwrap();
        h.handle_set(&p, PolicyRole::Produced, fec(4, 6)).unwrap();
        assert_eq!(h.handle_list().unwrap().len(), 1);
        h.handle_unset(&p, PolicyRole::Produced).unwrap();
        h.handle_unset(&p, PolicyRole::Produced).unwrap();
        assert_eq!(h.handle_list().unwrap().len(), 0);
    }

    #[test]
    fn shared_table_visible_to_both_consumers() {
        let table = Arc::new(CodingPolicyTable::new());
        let h = CodingMgmtHandler::new(Arc::clone(&table));
        let p: Name = "/y".parse().unwrap();
        h.handle_set(&p, PolicyRole::Produced, fec(4, 6)).unwrap();
        assert!(table.lookup(&p, PolicyRole::Produced).is_some());
    }

    #[test]
    fn wire_handler_round_trips() {
        use ndn_mgmt::CodingHandler as _;
        let h = CodingMgmtHandler::with_new_table();
        let prefix: Name = "/wire/test".parse().unwrap();
        let wire_entry = ndn_mgmt::CodingEntry {
            role: ndn_mgmt::CodingRole::Produced,
            k: 16,
            n: 20,
            field: ndn_mgmt::CodingFieldId::Gf8,
        };
        h.set(&prefix, wire_entry).unwrap();
        let listed = h.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].0, prefix);
        assert_eq!(listed[0].1, wire_entry);
        h.unset(&prefix, ndn_mgmt::CodingRole::Produced).unwrap();
        assert_eq!(h.list().len(), 0);
    }

    #[test]
    fn wire_handler_rejects_bad_kn() {
        use ndn_mgmt::CodingHandler as _;
        let h = CodingMgmtHandler::with_new_table();
        let prefix: Name = "/x".parse().unwrap();
        let bad = ndn_mgmt::CodingEntry {
            role: ndn_mgmt::CodingRole::Produced,
            k: 8,
            n: 4,
            field: ndn_mgmt::CodingFieldId::Gf8,
        };
        assert!(h.set(&prefix, bad).is_err());
    }
}
