//! NDN face transport over serial (UART) links for embedded and IoT, with
//! COBS framing. [`SerialFace`] is a `StreamFace` alias; open via
//! [`serial_face_open`] (feature `serial`).

#![allow(missing_docs)]

pub mod cobs;
#[allow(clippy::module_inception)]
pub mod serial;

pub use serial::SerialFace;
#[cfg(feature = "serial")]
pub use serial::serial_face_open;
