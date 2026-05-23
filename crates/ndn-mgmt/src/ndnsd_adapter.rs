//! Optional NDNSD-shape service-discovery adapter.
//!
//! NDNSD (Dulal & Wang, 2023 — `~/Downloads/ndnsd.pdf`) defines a
//! library-level layout under
//! `/<root>/<scope>/<type>/<identifier>/NDNSD/{discovery, service-info}`.
//! ndn-rs's primary control plane is the NFD-style mgmt verb surface
//! (`announce`/`withdraw`/`browse`/`list`); this adapter publishes the
//! same services under the NDNSD layout for cross-stack interop.
//!
//! ## Wire
//!
//! NDNSD specifies the namespace but no on-wire TLV codes. ndn-rs uses
//! the application-private range (`0xE0..=0xE4`); a future
//! authoritative NDNSD wire spec would supersede.
//!
//! - `NDNSD_SERVICE_INFO       = 0xE0` outer wrapper
//! - `NDNSD_SERVICE_NAME       = 0xE1` inner Name TLV (`0x07`)
//! - `NDNSD_LIFETIME_MS        = 0xE2` NonNegInt
//! - `NDNSD_DETAIL_KEY         = 0xE3` UTF-8 (optional, repeats)
//! - `NDNSD_DETAIL_VALUE       = 0xE4` UTF-8 (optional, repeats)

use std::sync::Arc;

use bytes::Bytes;
use ndn_engine::{EngineBuilder, PostBuildQueue};
use ndn_packet::Name;
use ndn_tlv::TlvWriter;

/// Application-private TLV-type allocations used by the NDNSD adapter.
pub mod tlv {
    pub const NDNSD_SERVICE_INFO: u64 = 0xE0;
    pub const NDNSD_SERVICE_NAME: u64 = 0xE1;
    pub const NDNSD_LIFETIME_MS: u64 = 0xE2;
    pub const NDNSD_DETAIL_KEY: u64 = 0xE3;
    pub const NDNSD_DETAIL_VALUE: u64 = 0xE4;
    /// Inner NDN `Name` TLV (NDN Packet Format v0.3) used inside
    /// `NDNSD_SERVICE_NAME`.
    pub const NDN_NAME: u64 = 0x07;
}

/// One row in the NDNSD discovery Data. `details` is a flat list of
/// `(key, value)` pairs corresponding to NDNSD's optional
/// "service-details" block.
#[derive(Debug, Clone)]
pub struct NdnsdServiceInfo {
    pub announced_prefix: Name,
    pub freshness_ms: u64,
    pub details: Vec<(String, String)>,
}

impl NdnsdServiceInfo {
    /// Construct with empty `details`.
    pub fn new(announced_prefix: Name, freshness_ms: u64) -> Self {
        Self {
            announced_prefix,
            freshness_ms,
            details: Vec::new(),
        }
    }
}

/// Encode a single `NdnsdServiceInfo` as a `NDNSD_SERVICE_INFO` TLV.
pub fn encode_service_info(info: &NdnsdServiceInfo) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_nested(tlv::NDNSD_SERVICE_INFO, |inner| {
        inner.write_nested(tlv::NDNSD_SERVICE_NAME, |sn| {
            sn.write_nested(tlv::NDN_NAME, |name_tlv| {
                for comp in info.announced_prefix.components() {
                    name_tlv.write_tlv(comp.typ, comp.value.as_ref());
                }
            });
        });
        let v = encode_non_neg_int(info.freshness_ms);
        inner.write_tlv(tlv::NDNSD_LIFETIME_MS, &v);
        for (k, val) in &info.details {
            inner.write_tlv(tlv::NDNSD_DETAIL_KEY, k.as_bytes());
            inner.write_tlv(tlv::NDNSD_DETAIL_VALUE, val.as_bytes());
        }
    });
    w.finish()
}

/// Encode an NDNSD discovery Data payload: a flat concatenation of
/// `NDNSD_SERVICE_INFO` TLVs, one per service.
pub fn encode_service_list(records: &[NdnsdServiceInfo]) -> Bytes {
    let mut w = TlvWriter::new();
    for r in records {
        let info_tlv = encode_service_info(r);
        w.write_raw(info_tlv.as_ref());
    }
    w.finish()
}

/// Mount a long-lived Producer at `root_prefix/NDNSD/discovery` whose
/// Data Content is the concatenated NDNSD service-info list.
///
/// `list_provider` runs on every Interest and produces the current
/// snapshot of services; the adapter encodes the list via
/// [`encode_service_list`].
pub fn mount_ndnsd_discovery<F>(
    builder: &mut EngineBuilder,
    post_build: &mut PostBuildQueue,
    root_prefix: Name,
    list_provider: F,
) where
    F: Fn() -> Vec<NdnsdServiceInfo> + Send + Sync + 'static,
{
    let discovery_prefix = root_prefix
        .append(b"NDNSD" as &[u8])
        .append(b"discovery" as &[u8]);
    let provider: Arc<dyn Fn() -> Vec<NdnsdServiceInfo> + Send + Sync + 'static> =
        Arc::new(list_provider);
    crate::status_bridge::mount_routing_status(
        builder,
        post_build,
        discovery_prefix.clone(),
        move || encode_service_list(&provider()),
    );
    tracing::info!(
        target: "discovery.ndnsd",
        prefix = %discovery_prefix,
        "NDNSD discovery Producer mounted",
    );
}

/// Mount a per-service Producer at
/// `<root_prefix>/<identifier>/NDNSD/service-info`. `info_provider`
/// runs on every Interest and returns the current
/// [`NdnsdServiceInfo`] for this identifier; the adapter encodes it
/// via [`encode_service_info`].
pub fn mount_ndnsd_service_info<F>(
    builder: &mut EngineBuilder,
    post_build: &mut PostBuildQueue,
    root_prefix: Name,
    identifier: &[u8],
    info_provider: F,
) where
    F: Fn() -> NdnsdServiceInfo + Send + Sync + 'static,
{
    let info_prefix = root_prefix
        .append(identifier)
        .append(b"NDNSD" as &[u8])
        .append(b"service-info" as &[u8]);
    let provider: Arc<dyn Fn() -> NdnsdServiceInfo + Send + Sync + 'static> =
        Arc::new(info_provider);
    crate::status_bridge::mount_routing_status(
        builder,
        post_build,
        info_prefix.clone(),
        move || encode_service_info(&provider()),
    );
    tracing::info!(
        target: "discovery.ndnsd",
        prefix = %info_prefix,
        "NDNSD per-service Producer mounted",
    );
}

fn encode_non_neg_int(v: u64) -> Vec<u8> {
    if v <= 0xFF {
        vec![v as u8]
    } else if v <= 0xFFFF {
        (v as u16).to_be_bytes().to_vec()
    } else if v <= 0xFFFF_FFFF {
        (v as u32).to_be_bytes().to_vec()
    } else {
        v.to_be_bytes().to_vec()
    }
}
