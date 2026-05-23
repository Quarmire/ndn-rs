use std::time::Duration;

use crate::face::{FaceKind, FacePersistency, ScopePolicy};
pub use ndn_packet::ContentHashTarget;

/// NFD `FaceFlags` bitmap positions surfaced in `FaceStatus.Flags`
/// (TLV 0x6C) and accepted by `faces/update` with `Flags`+`Mask`.
pub const BIT_LOCAL_FIELDS: u64 = 1 << 0;
pub const BIT_LP_RELIABILITY: u64 = 1 << 1;
pub const BIT_CONGESTION_MARKING: u64 = 1 << 2;

/// Mask of bits defined by NFD; bits outside are rejected by `faces/update`.
pub const NFD_FLAG_BITS: u64 = BIT_LOCAL_FIELDS | BIT_LP_RELIABILITY | BIT_CONGESTION_MARKING;

/// Snapshot of per-face ingress options returned by
/// [`LinkService::snapshot`](crate::link_service::LinkService::snapshot)
/// and consumed by the `faces/list` dataset writer.
#[derive(Clone, Debug, Default)]
pub struct FaceOptions {
    /// Which bytes to hash for the `Data::content_sha256` sidecar.
    /// `None` skips hashing (default for network faces).
    /// `Some(WholeContent)` hashes the entire Content field value (default for local-scope).
    /// `Some(InnerTlvType(t))` hashes the value bytes of the first inner TLV of type `t`.
    pub content_hash_target: Option<ContentHashTarget>,
    pub local_fields: bool,
    pub lp_reliability: bool,
    pub congestion_marking: bool,
    /// `None` means the transport reports unbounded framing (stream — TCP, Unix).
    pub effective_mtu: Option<u64>,
    pub base_congestion_marking_interval: Option<Duration>,
    pub default_congestion_threshold: Option<u64>,
    pub persistency: Option<FacePersistency>,
}

impl FaceOptions {
    /// IPC kinds (in-process / same-host apps) default to
    /// `content_hash_target = Some(WholeContent)`; wire/network faces default to
    /// `None`. This is a kind-level default — per-face locality (a loopback
    /// remote) is resolved elsewhere via [`crate::face::resolve_scope`].
    pub fn default_for_kind(kind: FaceKind) -> Self {
        Self {
            content_hash_target: if kind.scope_policy() == ScopePolicy::AlwaysLocal {
                Some(ContentHashTarget::WholeContent)
            } else {
                None
            },
            local_fields: false,
            lp_reliability: false,
            congestion_marking: false,
            effective_mtu: None,
            base_congestion_marking_interval: None,
            default_congestion_threshold: None,
            persistency: None,
        }
    }
}

/// Typed per-face option surfaced through
/// [`LinkService::apply`](crate::link_service::LinkService::apply).
///
/// One variant per knob `faces/update` accepts; the three NFD flag bits
/// are spelled out individually so request logs name the changed bit.
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FaceOption {
    LocalFields(bool),
    LpReliability(bool),
    CongestionMarking(bool),
    BaseCongestionMarkingInterval(Duration),
    DefaultCongestionThreshold(u64),
    /// `Some(n)` clamps to the transport's hard maximum; `None` reverts to default.
    EffectiveMtu(Option<u64>),
    Persistency(FacePersistency),
}

impl FaceOption {
    /// Stable kebab-case identifier used in [`FaceOptionError`] and
    /// `faces/update` response logs.
    pub fn name(&self) -> &'static str {
        match self {
            FaceOption::LocalFields(_) => "local-fields",
            FaceOption::LpReliability(_) => "lp-reliability",
            FaceOption::CongestionMarking(_) => "congestion-marking",
            FaceOption::BaseCongestionMarkingInterval(_) => "base-cong-interval",
            FaceOption::DefaultCongestionThreshold(_) => "def-cong-threshold",
            FaceOption::EffectiveMtu(_) => "mtu",
            FaceOption::Persistency(_) => "persistency",
        }
    }
}

/// Outcome of an attempt to apply a [`FaceOption`].
///
/// Variants map 1:1 to management status codes:
/// `NotSupportedByTransport` → 503, `Immutable` → 409, `OutOfRange` → 400.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FaceOptionError {
    NotSupportedByTransport { option: &'static str },
    Immutable { option: &'static str },
    OutOfRange {
        option: &'static str,
        reason: &'static str,
    },
}

impl FaceOptionError {
    pub fn option(&self) -> &'static str {
        match self {
            FaceOptionError::NotSupportedByTransport { option }
            | FaceOptionError::Immutable { option }
            | FaceOptionError::OutOfRange { option, .. } => option,
        }
    }
}

impl core::fmt::Display for FaceOptionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FaceOptionError::NotSupportedByTransport { option } => {
                write!(f, "face option '{option}' not supported by transport")
            }
            FaceOptionError::Immutable { option } => {
                write!(f, "face option '{option}' is immutable on this face")
            }
            FaceOptionError::OutOfRange { option, reason } => {
                write!(f, "face option '{option}' out of range: {reason}")
            }
        }
    }
}

impl std::error::Error for FaceOptionError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn face_option_roundtrip() {
        let opts = [
            FaceOption::LocalFields(true),
            FaceOption::LpReliability(false),
            FaceOption::CongestionMarking(true),
            FaceOption::BaseCongestionMarkingInterval(Duration::from_millis(100)),
            FaceOption::DefaultCongestionThreshold(64 * 1024),
            FaceOption::EffectiveMtu(Some(8800)),
            FaceOption::EffectiveMtu(None),
            FaceOption::Persistency(FacePersistency::Permanent),
        ];
        let expected = [
            "local-fields",
            "lp-reliability",
            "congestion-marking",
            "base-cong-interval",
            "def-cong-threshold",
            "mtu",
            "mtu",
            "persistency",
        ];
        for (opt, name) in opts.iter().zip(expected.iter()) {
            assert_eq!(opt.name(), *name, "stable name for {opt:?}");
        }
    }

    #[test]
    fn face_option_apply_default_errors() {
        use crate::link_service::{LinkService, PassthroughLinkService};

        let ls = PassthroughLinkService;
        for opt in [
            FaceOption::LocalFields(true),
            FaceOption::LpReliability(true),
            FaceOption::CongestionMarking(true),
            FaceOption::Persistency(FacePersistency::Persistent),
        ] {
            let err = ls.apply(opt).expect_err("default impl must error");
            match err {
                FaceOptionError::NotSupportedByTransport { option } => {
                    assert_eq!(option, opt.name());
                }
                other => panic!("expected NotSupportedByTransport, got {other:?}"),
            }
        }
    }

    #[test]
    fn face_options_default_is_inert() {
        let snap = FaceOptions::default();
        assert!(!snap.local_fields);
        assert!(!snap.lp_reliability);
        assert!(!snap.congestion_marking);
        assert_eq!(snap.effective_mtu, None);
        assert_eq!(snap.persistency, None);
    }
}
