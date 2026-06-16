//! Typed management handler for the rate-limit policy table; also
//! implements `ndn_mgmt::RateLimitMgmtBackend` for wire dispatch under
//! `/localhost/nfd/rate-limit/{set,unset,list}`.

use std::sync::Arc;

use crate::Result;
use crate::policy::{Cell, RateLimitPolicy, RateLimitPolicyTable, SharedPolicyTable};

#[derive(Clone)]
pub struct RateLimitMgmtHandler {
    table: SharedPolicyTable,
}

impl RateLimitMgmtHandler {
    pub fn new(table: SharedPolicyTable) -> Self {
        Self { table }
    }

    pub fn with_new_table() -> Self {
        Self::new(Arc::new(RateLimitPolicyTable::new()))
    }

    pub fn table(&self) -> &SharedPolicyTable {
        &self.table
    }

    pub fn handle_set(&self, policy: RateLimitPolicy) -> Result<()> {
        self.table.set(policy)
    }

    /// Idempotent: no error if the cell is already absent.
    pub fn handle_unset(&self, cell: &Cell) -> Result<()> {
        self.table.unset(cell)
    }

    pub fn handle_list(&self) -> Result<Vec<RateLimitListEntry>> {
        let mut entries: Vec<RateLimitListEntry> = self
            .table
            .entries()
            .into_iter()
            .map(|e| RateLimitListEntry {
                policy: e.policy.clone(),
                overflow_events: e.bucket.overflow_count(),
            })
            .collect();
        entries.sort_by(|a, b| {
            let ka = (
                a.policy.cell.direction as u8,
                a.policy.cell.face.map(|f| f.0).unwrap_or(0),
                a.policy
                    .cell
                    .prefix
                    .as_ref()
                    .map(|n| n.to_string())
                    .unwrap_or_default(),
            );
            let kb = (
                b.policy.cell.direction as u8,
                b.policy.cell.face.map(|f| f.0).unwrap_or(0),
                b.policy
                    .cell
                    .prefix
                    .as_ref()
                    .map(|n| n.to_string())
                    .unwrap_or_default(),
            );
            ka.cmp(&kb)
        });
        Ok(entries)
    }
}

/// Configured policy plus runtime counters.
#[derive(Debug, Clone)]
pub struct RateLimitListEntry {
    pub policy: RateLimitPolicy,
    pub overflow_events: u64,
}

use ndn_foundation_types::Name;

use crate::policy::{BucketSpec, Direction, FaceRef, Overflow, RateLimitPolicy as Policy};

impl ndn_mgmt::RateLimitMgmtBackend for RateLimitMgmtHandler {
    fn set(
        &self,
        prefix: Option<&Name>,
        entry: ndn_mgmt::RateLimitWireEntry,
    ) -> std::result::Result<(), String> {
        let policy = Policy {
            cell: Cell {
                face: entry.face_id.map(FaceRef),
                prefix: prefix.cloned(),
                direction: map_direction_from_wire(entry.direction),
            },
            bucket: BucketSpec {
                interest_pps: entry.interest_pps,
                interest_burst: entry.interest_burst,
                data_bps: entry.data_bps,
                data_burst_bytes: entry.data_burst_bytes,
            },
            overflow: map_overflow_from_wire(entry.overflow),
            queue_max: entry.queue_max,
        };
        self.table.set(policy).map_err(|e| e.to_string())
    }

    fn unset(
        &self,
        prefix: Option<&Name>,
        key: ndn_mgmt::RateLimitWireKey,
    ) -> std::result::Result<(), String> {
        let cell = Cell {
            face: key.face_id.map(FaceRef),
            prefix: prefix.cloned(),
            direction: map_direction_from_wire(key.direction),
        };
        self.table.unset(&cell).map_err(|e| e.to_string())
    }

    fn list(&self) -> Vec<ndn_mgmt::RateLimitWireListed> {
        self.table
            .entries()
            .into_iter()
            .map(|e| ndn_mgmt::RateLimitWireListed {
                prefix: e.policy.cell.prefix.clone(),
                entry: ndn_mgmt::RateLimitWireEntry {
                    face_id: e.policy.cell.face.map(|f| f.0),
                    direction: map_direction_to_wire(e.policy.cell.direction),
                    interest_pps: e.policy.bucket.interest_pps,
                    interest_burst: e.policy.bucket.interest_burst,
                    data_bps: e.policy.bucket.data_bps,
                    data_burst_bytes: e.policy.bucket.data_burst_bytes,
                    overflow: map_overflow_to_wire(e.policy.overflow),
                    queue_max: e.policy.queue_max,
                },
                overflow_events: e.bucket.overflow_count(),
            })
            .collect()
    }
}

fn map_direction_from_wire(d: ndn_mgmt::RateLimitDirection) -> Direction {
    match d {
        ndn_mgmt::RateLimitDirection::Inbound => Direction::Inbound,
        ndn_mgmt::RateLimitDirection::Outbound => Direction::Outbound,
    }
}

fn map_direction_to_wire(d: Direction) -> ndn_mgmt::RateLimitDirection {
    match d {
        Direction::Inbound => ndn_mgmt::RateLimitDirection::Inbound,
        Direction::Outbound => ndn_mgmt::RateLimitDirection::Outbound,
    }
}

fn map_overflow_from_wire(o: ndn_mgmt::RateLimitOverflow) -> Overflow {
    match o {
        ndn_mgmt::RateLimitOverflow::Nack => Overflow::Nack,
        ndn_mgmt::RateLimitOverflow::Drop => Overflow::Drop,
        ndn_mgmt::RateLimitOverflow::Queue => Overflow::Queue,
    }
}

fn map_overflow_to_wire(o: Overflow) -> ndn_mgmt::RateLimitOverflow {
    match o {
        Overflow::Nack => ndn_mgmt::RateLimitOverflow::Nack,
        Overflow::Drop => ndn_mgmt::RateLimitOverflow::Drop,
        Overflow::Queue => ndn_mgmt::RateLimitOverflow::Queue,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{BucketSpec, Direction, FaceRef, Overflow};

    fn p(face: Option<u64>, dir: Direction) -> RateLimitPolicy {
        RateLimitPolicy {
            cell: Cell {
                face: face.map(FaceRef),
                prefix: None,
                direction: dir,
            },
            bucket: BucketSpec::pps(100, 200),
            overflow: Overflow::Nack,
            queue_max: None,
        }
    }

    #[test]
    fn set_then_list() {
        let h = RateLimitMgmtHandler::with_new_table();
        h.handle_set(p(Some(1), Direction::Inbound)).unwrap();
        h.handle_set(p(Some(2), Direction::Outbound)).unwrap();
        let list = h.handle_list().unwrap();
        assert_eq!(list.len(), 2);
        for entry in &list {
            assert_eq!(entry.overflow_events, 0);
        }
    }

    #[test]
    fn unset_is_idempotent() {
        let h = RateLimitMgmtHandler::with_new_table();
        let policy = p(Some(1), Direction::Inbound);
        h.handle_unset(&policy.cell).unwrap();
        h.handle_set(policy.clone()).unwrap();
        h.handle_unset(&policy.cell).unwrap();
        h.handle_unset(&policy.cell).unwrap();
        assert_eq!(h.handle_list().unwrap().len(), 0);
    }
}
