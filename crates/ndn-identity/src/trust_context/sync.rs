//! Phase-1 stub for [`SyncBundle`]. Phase 2 (`context_sync` in `ndn-sync`)
//! gives this a wire encoding and SVS group integration. Today it is just the
//! data a sibling device needs to mirror the verify-only side of a context.

use ndn_packet::Name;
use ndn_security::{Certificate, TrustSchema};

#[derive(Debug, Clone)]
pub struct SyncBundle {
    pub context_name: Name,
    pub anchors: Vec<Certificate>,
    pub schema: TrustSchema,
    pub ca_endpoints: Vec<Name>,
}

impl SyncBundle {
    /// Whether this bundle carries any private-key material. Phase 1: always
    /// false — only Phase 4 introduces wrapped-key payloads. The witness
    /// `tcs07_context_sync_no_private_keys.sh` asserts this stays false on the
    /// wire for the base bundle.
    pub fn carries_private_keys(&self) -> bool {
        false
    }
}
