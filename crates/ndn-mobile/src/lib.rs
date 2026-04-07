//! # ndn-mobile — Embedded NDN forwarder for Android and iOS/iPadOS
//!
//! Provides a pre-configured, in-process NDN forwarder optimised for mobile
//! deployments.  On mobile the forwarder runs inside the application (no
//! separate router daemon), using [`AppFace`] for app↔forwarder communication
//! and standard UDP/TCP faces for network connectivity.
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────┐
//! │  Your App                                            │
//! │                                                      │
//! │  Consumer / Producer                                 │
//! │       │  ↑                                           │
//! │       ▼  │  AppHandle (tokio mpsc)                   │
//! │  ┌─────────────────────────────────────────────┐     │
//! │  │  MobileEngine (ForwarderEngine embedded)    │     │
//! │  │   ├── FIB / PIT / CS                        │     │
//! │  │   ├── AppFace  ◄──── app traffic            │     │
//! │  │   ├── UdpFace  ◄──── LAN multicast          │     │
//! │  │   └── UdpFace  ◄──── unicast NDN hub        │     │
//! │  └─────────────────────────────────────────────┘     │
//! └──────────────────────────────────────────────────────┘
//! ```
//!
//! ## Quick start
//!
//! ```no_run
//! use ndn_mobile::{Consumer, MobileEngine};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Build the engine (in-process only — no network faces)
//!     let (engine, handle) = MobileEngine::builder().build().await?;
//!
//!     // Consumer: fetch a named Data object
//!     let mut consumer = Consumer::from_handle(handle);
//!     let data = consumer.fetch("/ndn/edu/example/data/1").await?;
//!     println!("got {} bytes", data.content().map_or(0, |b| b.len()));
//!
//!     engine.shutdown().await;
//!     Ok(())
//! }
//! ```
//!
//! ## With UDP multicast (LAN discovery)
//!
//! ```no_run
//! use ndn_mobile::MobileEngine;
//! use std::net::Ipv4Addr;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let local_iface = Ipv4Addr::new(192, 168, 1, 10); // device's Wi-Fi IP
//!     let (engine, consumer_handle) = MobileEngine::builder()
//!         .with_udp_multicast(local_iface)
//!         .build()
//!         .await?;
//!
//!     // Produce data for /mobile/sensor/temp
//!     let mut producer = engine.register_producer("/mobile/sensor/temp");
//!     producer.serve(|_interest| async move {
//!         let data = ndn_packet::encode::DataBuilder::new(
//!             "/mobile/sensor/temp".parse::<ndn_mobile::Name>().unwrap(),
//!             b"23.5C",
//!         ).build();
//!         Some(data)
//!     }).await?;
//!
//!     engine.shutdown().await;
//!     Ok(())
//! }
//! ```
//!
//! ## Platform notes
//!
//! | Feature | Android | iOS/iPadOS |
//! |---------|---------|------------|
//! | AppFace (in-process) | ✓ | ✓ |
//! | UDP multicast | ✓ (Wi-Fi) | ✓ (Wi-Fi) |
//! | UDP unicast | ✓ | ✓ |
//! | TCP | ✓ | ✓ |
//! | Neighbor discovery (Hello/UDP) | ✓ | ✓ |
//! | Bluetooth NDN (via FFI stream) | ✓ | ✓ |
//! | Persistent content store | ✓ | ✓ (incl. App Groups) |
//! | Background suspend / resume | ✓ | ✓ |
//! | Raw Ethernet (L2) | ✗ | ✗ |
//!
//! This crate does not depend on `ndn-face-l2` (raw Ethernet) or
//! `ndn-face-serial` and does not use Unix domain sockets or POSIX SHM,
//! so it compiles cleanly for `aarch64-linux-android` and `aarch64-apple-ios`.

#![allow(missing_docs)]

pub mod bluetooth;
pub mod engine;

pub use bluetooth::bluetooth_face_from_parts;
pub use engine::{MobileEngine, MobileEngineBuilder};

// Re-export consumer/producer and core packet types for convenience.
pub use ndn_app::{AppError, Consumer, Producer};
pub use ndn_discovery::DiscoveryProfile;
pub use ndn_face_local::AppHandle;
pub use ndn_packet::{Data, Interest, Name};
pub use ndn_security::SecurityProfile;
pub use ndn_transport::FaceId;
pub use tokio_util::sync::CancellationToken;
