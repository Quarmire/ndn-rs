//! `EngineRateLimitHook` implements [`ndn_engine::RateLimitHook`] over
//! a [`SharedPolicyTable`].
//!
//! `Overflow::Queue` cells fall through to `Drop` here; the engine
//! doesn't host a queue in this integration.

use ndn_engine::rate_limit_hook::{Decision, PacketKind, RateLimitHook};
use ndn_packet::Name;
use ndn_transport::FaceId;

use crate::bucket::BucketOutcome;
use crate::policy::{Direction, FaceRef, Overflow, SharedPolicyTable};

pub struct EngineRateLimitHook {
    table: SharedPolicyTable,
}

impl EngineRateLimitHook {
    pub fn new(table: SharedPolicyTable) -> Self {
        Self { table }
    }

    pub fn table(&self) -> &SharedPolicyTable {
        &self.table
    }
}

impl RateLimitHook for EngineRateLimitHook {
    fn check_inbound(
        &self,
        face: FaceId,
        name: &Name,
        kind: PacketKind,
        wire_bytes: usize,
    ) -> Decision {
        consult(
            &self.table,
            face,
            name,
            kind,
            wire_bytes,
            Direction::Inbound,
        )
    }

    fn check_outbound(
        &self,
        face: FaceId,
        name: &Name,
        kind: PacketKind,
        wire_bytes: usize,
    ) -> Decision {
        consult(
            &self.table,
            face,
            name,
            kind,
            wire_bytes,
            Direction::Outbound,
        )
    }
}

/// Most-restrictive-cell-wins: charge each matching cell until one
/// denies, then return that cell's overflow action. Each charged
/// bucket records its own overflow counter via `try_consume`.
fn consult(
    table: &SharedPolicyTable,
    face: FaceId,
    name: &Name,
    kind: PacketKind,
    wire_bytes: usize,
    direction: Direction,
) -> Decision {
    let entries = table.matches(FaceRef::from(face), Some(name), direction);
    if entries.is_empty() {
        return Decision::Permit;
    }
    let (interest_cost, data_bytes) = match kind {
        PacketKind::Interest => (1u32, 0u32),
        PacketKind::Data => (0u32, u32::try_from(wire_bytes).unwrap_or(u32::MAX)),
    };
    for entry in entries {
        if entry.bucket.try_consume(interest_cost, data_bytes) == BucketOutcome::Deny {
            return match entry.policy.overflow {
                Overflow::Nack => Decision::Nack,
                Overflow::Drop | Overflow::Queue => Decision::Drop,
            };
        }
    }
    Decision::Permit
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{BucketSpec, Cell, RateLimitPolicy, RateLimitPolicyTable};
    use std::sync::Arc;

    fn policy(
        face: Option<u64>,
        prefix: Option<&str>,
        dir: Direction,
        ov: Overflow,
    ) -> RateLimitPolicy {
        RateLimitPolicy {
            cell: Cell {
                face: face.map(FaceRef),
                prefix: prefix.map(|p| p.parse().unwrap()),
                direction: dir,
            },
            bucket: BucketSpec::pps(1, 2),
            overflow: ov,
            queue_max: None,
        }
    }

    #[test]
    fn permits_with_empty_table() {
        let table = Arc::new(RateLimitPolicyTable::new());
        let hook = EngineRateLimitHook::new(table);
        let name: Name = "/a".parse().unwrap();
        assert_eq!(
            hook.check_inbound(FaceId(1), &name, PacketKind::Interest, 100),
            Decision::Permit
        );
    }

    #[test]
    fn denies_with_nack_after_burst() {
        let table = Arc::new(RateLimitPolicyTable::new());
        table
            .set(policy(None, Some("/a"), Direction::Inbound, Overflow::Nack))
            .unwrap();
        let hook = EngineRateLimitHook::new(Arc::clone(&table));
        let name: Name = "/a/b".parse().unwrap();
        assert_eq!(
            hook.check_inbound(FaceId(1), &name, PacketKind::Interest, 100),
            Decision::Permit
        );
        assert_eq!(
            hook.check_inbound(FaceId(1), &name, PacketKind::Interest, 100),
            Decision::Permit
        );
        assert_eq!(
            hook.check_inbound(FaceId(1), &name, PacketKind::Interest, 100),
            Decision::Nack
        );
    }

    #[test]
    fn data_outbound_denies_with_drop() {
        let table = Arc::new(RateLimitPolicyTable::new());
        let mut p = policy(None, Some("/a"), Direction::Outbound, Overflow::Drop);
        p.bucket = BucketSpec::bps(10_000, 5_000);
        table.set(p).unwrap();
        let hook = EngineRateLimitHook::new(Arc::clone(&table));
        let name: Name = "/a/data".parse().unwrap();
        assert_eq!(
            hook.check_outbound(FaceId(1), &name, PacketKind::Data, 4_000),
            Decision::Permit
        );
        assert_eq!(
            hook.check_outbound(FaceId(1), &name, PacketKind::Data, 4_000),
            Decision::Drop
        );
    }

    #[test]
    fn no_matching_cell_permits() {
        let table = Arc::new(RateLimitPolicyTable::new());
        table
            .set(policy(Some(99), None, Direction::Inbound, Overflow::Drop))
            .unwrap();
        let hook = EngineRateLimitHook::new(table);
        let name: Name = "/a".parse().unwrap();
        assert_eq!(
            hook.check_inbound(FaceId(1), &name, PacketKind::Interest, 100),
            Decision::Permit
        );
    }
}
