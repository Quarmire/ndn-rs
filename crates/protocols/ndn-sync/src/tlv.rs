//! Shared TLV / NonNegativeInteger codec for the SVS dialects.
//!
//! The implementation now lives in the no_std [`ndn_svs_core::tlv`] crate so a
//! constrained device can encode/decode SVS wire without std. This module
//! re-exports the four helpers ndn-sync's own modules (`dialect`, `mapping`,
//! `svsync`, `svs_sync`, `psync_*`) reach for as `crate::tlv::*`, so no call
//! site changed. The `write_varnumber` / `read_varnumber` primitives stay
//! internal to the core crate (only `read_tlv` / `write_tlv` need them, and
//! those are the ones ndn-sync uses).
//!
//! Codec unit tests (`nni_widths`, `nni_roundtrip`, `tlv_roundtrip`,
//! `varnumber_three_octet_form`) moved with the code into
//! `ndn-svs-core`'s `tlv` module.

pub(crate) use ndn_svs_core::tlv::{decode_nni, encode_nni, read_tlv, write_tlv};
