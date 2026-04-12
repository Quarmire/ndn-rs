//! Minimal NDN forwarder for bare-metal embedded targets.
//!
//! This crate is always `no_std`. It targets ARM Cortex-M, RISC-V, ESP32,
//! and similar MCUs. The design is inspired by zenoh-pico: reuse the protocol
//! core (`ndn-tlv`, `ndn-packet`) but replace the async runtime and OS-level
//! services with synchronous, allocation-optional alternatives.
//!
//! # Feature flags
//!
//! | Feature  | Description                                                    |
//! |----------|----------------------------------------------------------------|
//! | `alloc`  | Enables heap-backed collections (requires a global allocator) |
//! | `cs`     | Enable the optional content store                              |
//! | `ipc`    | Enable app↔forwarder SPSC queues                               |
//!
//! # Quickstart
//!
//! ```rust,ignore
//! use ndn_embedded::{Forwarder, Fib, FnClock, NoOpClock, wire};
//!
//! // One-line route registration from a name string:
//! let mut fib = Fib::<8>::new();
//! fib.add_route("/ndn/sensor", 1);   // forward /ndn/sensor/** to face 1
//!
//! // NoOpClock: PIT entries never expire (useful with fixed-size PIT + FIFO).
//! // FnClock:   supply a hardware millisecond counter.
//! // let clock = FnClock(|| read_systick_ms());
//! let mut fw = Forwarder::<64, 8, _>::new(fib, NoOpClock);
//!
//! // Encode packets without splitting names manually:
//! let mut buf = [0u8; 256];
//! let n = wire::encode_interest_name(&mut buf, "/ndn/sensor/temp", 42, 4000, false, false)
//!     .expect("buf too small");
//! let n = wire::encode_data_name(&mut buf, "/ndn/sensor/temp", b"23.5")
//!     .expect("buf too small");
//!
//! // In your MCU main loop:
//! // fw.process_packet(&raw_bytes, incoming_face_id, &mut faces);
//! // fw.run_one_tick();   // purge expired PIT entries
//! ```
#![allow(missing_docs)]
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod clock;
pub mod face;
pub mod fib;
pub mod forwarder;
pub mod pit;
pub mod wire;

#[cfg(feature = "cs")]
pub mod cs;

#[cfg(feature = "ipc")]
pub mod ipc;

#[cfg(feature = "ble")]
pub mod ble;

pub mod cobs;

pub use clock::{Clock, FnClock, NoOpClock};
pub use face::{ErasedFace, Face, FaceId};
pub use fib::{Fib, FibEntry};
pub use forwarder::Forwarder;
pub use pit::{Pit, PitEntry};
#[cfg(feature = "ble")]
pub use ble::{BlePlatform, EmbeddedBleFace};
