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
//! use ndn_embedded::{Forwarder, Fib, FibEntry, NoOpClock};
//!
//! let fib = Fib::<8>::new();
//! let mut fw = Forwarder::<64, 8, _>::new(fib, NoOpClock);
//! // In your MCU main loop:
//! // fw.process_packet(&raw_bytes, incoming_face_id, &mut faces);
//! // fw.run_one_tick();
//! ```
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

pub mod cobs;

pub use clock::{Clock, NoOpClock};
pub use face::{ErasedFace, Face, FaceId};
pub use fib::{Fib, FibEntry};
pub use forwarder::Forwarder;
pub use pit::{Pit, PitEntry};
