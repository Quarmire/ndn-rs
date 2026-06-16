//! BLE wire framing for the native GATT faces.
//!
//! The codec now lives in the shared, wasm-buildable [`ndn_ble_framing`] crate
//! so the native faces, the browser Web Bluetooth central, and the BLE
//! advertising face share one implementation. See that crate for the
//! NDNLPv2-vs-NDNts framing distinction and reassembly.

pub use ndn_ble_framing::{BleFraming, NdntsReassembler};
