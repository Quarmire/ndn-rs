use ndn_packet::Data;

/// The trust path used to validate a `SafeData`.
#[derive(Clone, Debug)]
pub enum TrustPath {
    /// Validated via full certificate chain.
    CertChain(Vec<ndn_packet::Name>),
    /// Trusted because it arrived on a local face with known process credentials.
    LocalFace { uid: u32 },
}

/// A Data packet whose signature has been verified.
///
/// `SafeData` can only be constructed by `Validator::validate()` or by the
/// local-trust fast path (`SafeData::from_local_trusted`). The `pub(crate)`
/// constructor prevents application code from bypassing verification.
///
/// Application callbacks receive `SafeData`, not `Data` — the compiler enforces
/// that unverified data cannot be passed where verified data is required.
pub struct SafeData {
    pub(crate) inner:       Data,
    pub(crate) trust_path:  TrustPath,
    pub(crate) verified_at: u64,
}

impl SafeData {
    /// Construct a `SafeData` from a Data packet that arrived on a trusted
    /// local face (bypasses crypto verification).
    pub(crate) fn from_local_trusted(data: Data, uid: u32) -> Self {
        Self {
            inner:       data,
            trust_path:  TrustPath::LocalFace { uid },
            verified_at: now_ns(),
        }
    }

    pub fn data(&self) -> &Data {
        &self.inner
    }

    pub fn trust_path(&self) -> &TrustPath {
        &self.trust_path
    }

    pub fn verified_at(&self) -> u64 {
        self.verified_at
    }
}

fn now_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}
