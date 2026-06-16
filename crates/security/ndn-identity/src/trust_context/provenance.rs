//! [`AdoptionProvenance`] — how I came to hold a [`TrustContext`].

use std::time::SystemTime;

use ndn_packet::Name;
use ndn_security::Certificate;

/// In-process face identifier; intentionally a numeric alias to avoid pulling
/// `ndn-engine` into `ndn-identity`. Phase 3's named-engine discovery will
/// promote this to a typed reference.
pub type FaceIdRef = u64;

#[derive(Debug, Clone)]
pub enum AdoptionProvenance {
    TofuRoot {
        scanned_at: SystemTime,
        scanner_id: String,
    },
    Enrolled {
        issued_by: Name,
        cert: Certificate,
        at: SystemTime,
    },
    Adopted {
        learned_via_face: FaceIdRef,
        at: SystemTime,
    },
    Replicated {
        from_device: Name,
        at: SystemTime,
    },
}
