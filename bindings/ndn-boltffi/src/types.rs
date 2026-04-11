//! FFI-safe value types and error enum.
//!
//! All types here use `#[data]` (which is identical to `#[error]` in BoltFFI)
//! to generate `WireEncode`/`WireDecode` impls.  We use `#[data]` uniformly to
//! avoid the name conflict between `boltffi::error` and `thiserror`'s
//! `#[error(...)]` derive helper attribute.

use boltffi::data;
use ndn_app::AppError;

// ── NdnData ───────────────────────────────────────────────────────────────────

/// An NDN Data packet — name plus content payload.
#[data]
#[derive(Debug, Clone)]
pub struct NdnData {
    /// Full NDN name as a URI string, e.g. `"/ndn/sensor/temperature"`.
    pub name: String,
    /// Raw content payload.
    pub content: Vec<u8>,
}

impl NdnData {
    pub(crate) fn from_packet(data: ndn_packet::Data) -> Self {
        Self {
            name: data.name.to_string(),
            content: data.content().map(|b| b.to_vec()).unwrap_or_default(),
        }
    }
}

// ── NdnSample ─────────────────────────────────────────────────────────────────

/// A publication received from an NDN sync group.
#[data]
#[derive(Debug, Clone)]
pub struct NdnSample {
    /// Full name of the published Data object.
    pub name: String,
    /// Publisher identifier (node key from the sync group).
    pub publisher: String,
    /// Per-publisher sequence number of this publication.
    pub seq: u64,
    /// Content payload, or `None` when `auto_fetch` is disabled.
    pub payload: Option<Vec<u8>>,
}

impl NdnSample {
    pub(crate) fn from_sample(s: ndn_app::Sample) -> Self {
        Self {
            name: s.name.to_string(),
            publisher: s.publisher,
            seq: s.seq,
            payload: s.payload.map(|b| b.to_vec()),
        }
    }
}

// ── NdnSecurityProfile ────────────────────────────────────────────────────────

/// How the embedded forwarder validates Data packet signatures.
#[data]
#[derive(Debug, Clone)]
pub enum NdnSecurityProfile {
    /// Full chain validation with certificate fetching (default).
    Default,
    /// Verify signature validity but skip trust schema and chain walking.
    AcceptSigned,
    /// No validation — all Data packets pass through unchecked.
    Disabled,
}

pub(crate) fn into_security_profile(p: NdnSecurityProfile) -> ndn_security::SecurityProfile {
    match p {
        NdnSecurityProfile::Default => ndn_security::SecurityProfile::Default,
        NdnSecurityProfile::AcceptSigned => ndn_security::SecurityProfile::AcceptSigned,
        NdnSecurityProfile::Disabled => ndn_security::SecurityProfile::Disabled,
    }
}

// ── NdnEngineConfig ───────────────────────────────────────────────────────────

/// Configuration for [`NdnEngine`](crate::NdnEngine).
///
/// # Platform notes
///
/// - `multicast_interface`: local Wi-Fi IPv4 address for NDN UDP multicast.
///   Android: convert `WifiManager.getConnectionInfo().ipAddress` to dotted-quad.
///   iOS: enumerate `NetworkInterface` for the active Wi-Fi interface.
///
/// - `persistent_cs_path`: directory for on-disk content store.
///   Android: `Context.getFilesDir().absolutePath + "/ndn-cs"`.
///   iOS: App Group container from
///   `FileManager.containerURL(forSecurityApplicationGroupIdentifier:)`.
///   Requires the `fjall` crate feature; silently ignored without it.
#[data]
#[derive(Debug, Clone)]
pub struct NdnEngineConfig {
    /// Content store capacity in MB (default: 8).
    pub cs_capacity_mb: u32,
    /// Signature validation mode.
    pub security_profile: NdnSecurityProfile,
    /// Local Wi-Fi interface IPv4 for NDN UDP multicast (`224.0.23.170:6363`).
    /// `None` disables multicast.
    pub multicast_interface: Option<String>,
    /// Unicast NDN hub addresses to connect at startup.
    /// Format: `"<ip>:<port>"`, e.g. `"128.195.198.169:6363"` (UCLA hub).
    pub unicast_peers: Vec<String>,
    /// NDN name for neighbor discovery Hello packets, e.g.
    /// `"/mobile/device/phone-alice"`. Requires `multicast_interface`.
    pub node_name: Option<String>,
    /// Forwarder pipeline threads (default: 1 — minimises battery drain).
    pub pipeline_threads: u32,
    /// Directory for persistent on-disk content store.
    /// Requires the `fjall` crate feature; ignored otherwise.
    pub persistent_cs_path: Option<String>,
}

// ── NdnError ──────────────────────────────────────────────────────────────────

/// Error returned by NDN operations.
///
/// Using `#[data]` (not `#[error]`) to avoid a name conflict between
/// `boltffi::error` and `thiserror`'s `#[error(...)]` derive helper.
/// Both map to the same BoltFFI macro internally.
#[data]
#[derive(Debug, thiserror::Error)]
pub enum NdnError {
    /// No Data received before the Interest lifetime expired (~4.5 s).
    #[error("timeout waiting for data: {name}")]
    Timeout { name: String },
    /// The forwarder returned a Nack (e.g. `NoRoute`, `CongestionMark`).
    #[error("interest nacked ({reason}): {name}")]
    Nacked { name: String, reason: String },
    /// Internal engine or I/O error.
    #[error("engine error: {msg}")]
    Engine { msg: String },
    /// The provided string is not a valid NDN name URI.
    #[error("invalid NDN name: {name}")]
    InvalidName { name: String },
    /// The provided string is not a valid `<ip>:<port>` address.
    #[error("invalid address: {addr}")]
    InvalidAddress { addr: String },
}

impl NdnError {
    pub(crate) fn from_app(e: AppError, name: &str) -> Self {
        match e {
            AppError::Timeout => NdnError::Timeout { name: name.to_string() },
            AppError::Nacked { reason } => NdnError::Nacked {
                name: name.to_string(),
                reason: format!("{reason:?}"),
            },
            AppError::Connection(e) => NdnError::Engine { msg: e.to_string() },
            AppError::Closed => NdnError::Engine { msg: "connection closed".into() },
            AppError::Protocol(msg) => NdnError::Engine { msg },
        }
    }

    pub(crate) fn engine(e: impl std::fmt::Display) -> Self {
        NdnError::Engine { msg: e.to_string() }
    }

    pub(crate) fn invalid_name(name: impl Into<String>) -> Self {
        NdnError::InvalidName { name: name.into() }
    }

    pub(crate) fn invalid_addr(addr: impl Into<String>) -> Self {
        NdnError::InvalidAddress { addr: addr.into() }
    }
}
