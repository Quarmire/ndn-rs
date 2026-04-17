//! # ndn-boltffi — BoltFFI bindings for ndn-rs
//!
//! Exposes the embedded [`MobileEngine`](ndn_mobile::MobileEngine) and the
//! high-level [`Consumer`](ndn_app::Consumer) / [`Producer`](ndn_app::Producer) /
//! [`Subscriber`](ndn_app::Subscriber) APIs to Android (Kotlin/JVM) and
//! iOS/iPadOS (Swift) via BoltFFI.
//!
//! ## Architecture
//!
//! The forwarder runs in-process via an embedded Tokio runtime owned by
//! [`NdnEngine`].  All public methods are **synchronous** on the FFI boundary
//! and block the calling thread for the duration of the operation (typically
//! < 4.5 s for a consumer fetch).  Call them on a background thread:
//!
//! - Kotlin: `withContext(Dispatchers.IO) { consumer.fetch("/ndn/...") }`
//! - Swift: `try await Task.detached { try consumer.fetch(name: "/ndn/...") }.value`
//!
//! ## Building
//!
//! ```bash
//! # Install BoltFFI CLI
//! cargo install boltffi_cli
//!
//! # Generate Android bindings (.so + Kotlin)
//! boltffi pack android
//!
//! # Generate iOS bindings (.xcframework + Swift)
//! boltffi pack apple
//! ```
//!
//! ## Android quick start (Kotlin)
//!
//! ```kotlin
//! val config = NdnEngineConfig(
//!     csCapacityMb = 8u,
//!     securityProfile = NdnSecurityProfile.DISABLED,
//!     multicastInterface = null,
//!     unicastPeers = listOf(),
//!     nodeName = null,
//!     pipelineThreads = 1u,
//!     persistentCsPath = filesDir.absolutePath + "/ndn-cs",
//! )
//! val engine = NdnEngine(config)
//!
//! val consumer = engine.consumer()
//! val data = withContext(Dispatchers.IO) { consumer.fetch("/ndn/sensor/temp") }
//! println("got: ${String(data.content)}")
//!
//! val producer = engine.registerProducer("/ndn/sensor")
//! withContext(Dispatchers.IO) {
//!     producer.serve(object : NdnInterestHandler {
//!         override fun handleInterest(name: String): ByteArray? =
//!             if (name.endsWith("/temp")) "23.5C".toByteArray() else null
//!     })
//! }
//! ```
//!
//! ## iOS quick start (Swift)
//!
//! ```swift
//! let config = NdnEngineConfig(
//!     csCapacityMb: 8,
//!     securityProfile: .disabled,
//!     multicastInterface: nil,
//!     unicastPeers: [],
//!     nodeName: nil,
//!     pipelineThreads: 1,
//!     persistentCsPath: nil
//! )
//! let engine = try NdnEngine(config: config)
//!
//! let consumer = try engine.consumer()
//! let data = try await Task.detached { try consumer.fetch(name: "/ndn/sensor/temp") }.value
//! print("got: \(String(bytes: data.content, encoding: .utf8)!)")
//! ```

pub mod codec;
pub mod consumer;
pub mod engine;
pub mod producer;
pub mod subscriber;
pub mod types;

pub use codec::NdnCodec;
pub use consumer::NdnConsumer;
pub use engine::NdnEngine;
pub use producer::{NdnInterestHandler, NdnProducer};
pub use subscriber::NdnSubscriber;
pub use types::{NdnData, NdnEngineConfig, NdnError, NdnSample, NdnSecurityProfile};
