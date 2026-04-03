//! # Loading a WASM Strategy
//!
//! This example shows how to load and register a forwarding strategy from
//! a compiled WebAssembly module using [`WasmStrategy`].
//!
//! ## Why WASM strategies?
//!
//! - **Hot-patching**: deploy new forwarding logic without recompiling the router
//! - **Research**: iterate on strategy algorithms without a full Rust build cycle
//! - **Sandboxing**: fuel-limited execution prevents infinite loops; no I/O access
//!
//! ## Host-Guest ABI
//!
//! The WASM module imports functions from the `"ndn"` namespace:
//!
//! | Function           | Returns          | Description                    |
//! |--------------------|------------------|--------------------------------|
//! | `get_in_face`      | `u32`            | Face the Interest arrived on   |
//! | `get_nexthop_count`| `u32`            | Number of FIB nexthops         |
//! | `get_nexthop`      | `u32` (err code) | Read nexthop into guest memory |
//! | `get_rtt_ns`       | `f64`            | RTT in ns (-1.0 if unknown)    |
//! | `get_rssi`         | `i32`            | RSSI in dBm (-128 if unknown)  |
//! | `get_satisfaction`  | `f32`            | Rate (-1.0 if unknown)         |
//! | `forward`          | —                | Forward to specified faces     |
//! | `nack`             | —                | Send Nack                      |
//! | `suppress`         | —                | Suppress the Interest          |
//!
//! The module must export `on_interest()` and optionally `on_nack()`.
//!
//! ## Writing a WASM strategy (Rust → wasm32)
//!
//! ```rust,ignore
//! // strategy.rs — compile with:
//! //   cargo build --target wasm32-unknown-unknown --release
//! extern "C" {
//!     fn get_nexthop_count() -> u32;
//!     fn get_nexthop(index: u32, out_face_id: *mut u32, out_cost: *mut u32) -> u32;
//!     fn forward(face_ids_ptr: *const u32, count: u32);
//!     fn nack(reason: u32);
//! }
//!
//! #[no_mangle]
//! pub extern "C" fn on_interest() {
//!     unsafe {
//!         let count = get_nexthop_count();
//!         if count == 0 { nack(0); return; }  // 0 = NoRoute
//!         // Forward to the first (lowest-cost) nexthop
//!         let (mut fid, mut cost) = (0u32, 0u32);
//!         get_nexthop(0, &mut fid, &mut cost);
//!         forward(&fid, 1);
//!     }
//! }
//! ```
//!
//! ## Running this example
//!
//! This example uses a minimal WAT (WebAssembly Text) module embedded as a
//! string, so it runs without any external `.wasm` file. For real use,
//! compile a Rust crate to `wasm32-unknown-unknown` and load with
//! `WasmStrategy::from_file()`.

use anyhow::Result;

use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_packet::Name;
use ndn_strategy_wasm::WasmStrategy;

/// A minimal WAT module that always forwards to the first nexthop.
///
/// This is the WebAssembly Text representation of the simplest possible
/// strategy: call `get_nexthop_count`, if > 0 read the first nexthop
/// and forward to it, otherwise nack.
const MINIMAL_STRATEGY_WAT: &str = r#"
(module
  ;; Import host functions from the "ndn" namespace
  (import "ndn" "get_nexthop_count" (func $get_nexthop_count (result i32)))
  (import "ndn" "get_nexthop" (func $get_nexthop (param i32 i32 i32) (result i32)))
  (import "ndn" "forward" (func $forward (param i32 i32)))
  (import "ndn" "nack" (func $nack (param i32)))

  ;; Guest memory (needed for get_nexthop to write into)
  (memory (export "memory") 1)

  ;; on_interest: forward to first nexthop, or nack if no route
  (func (export "on_interest")
    (local $count i32)
    (local $face_id i32)

    ;; Get nexthop count
    (local.set $count (call $get_nexthop_count))

    ;; If no nexthops, nack with NoRoute (reason=0)
    (if (i32.eqz (local.get $count))
      (then
        (call $nack (i32.const 0))
        return
      )
    )

    ;; Read first nexthop: face_id at offset 0, cost at offset 4
    (drop (call $get_nexthop
      (i32.const 0)   ;; index
      (i32.const 0)   ;; out_face_id pointer (memory offset 0)
      (i32.const 4)   ;; out_cost pointer (memory offset 4)
    ))

    ;; Forward to the face_id we just read
    (call $forward
      (i32.const 0)   ;; pointer to face_id array (offset 0 in memory)
      (i32.const 1)   ;; count = 1
    )
  )
)
"#;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // Parse WAT to WASM bytes.
    let wasm_bytes = wat::parse_str(MINIMAL_STRATEGY_WAT)?;

    // Load the WASM strategy.
    let strategy = WasmStrategy::from_bytes(
        Name::from_str("/localhost/nfd/strategy/wasm-minimal")?,
        &wasm_bytes,
        10_000, // fuel limit: 10k instructions per invocation
    )?;

    tracing::info!("Loaded WASM strategy from embedded WAT module");

    // Register with the engine.
    let (_engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .strategy(strategy)
        .build()
        .await?;

    tracing::info!("Engine running with WASM strategy");

    // The WASM strategy will:
    // 1. Be called for every Interest
    // 2. Execute the on_interest() function with fuel limit
    // 3. If fuel runs out → Suppress (safety)
    // 4. If the module traps → Suppress (safety)
    //
    // To load from a file instead:
    //   WasmStrategy::from_file(name, "/path/to/strategy.wasm", 10_000)?

    shutdown.shutdown().await;
    Ok(())
}

use std::str::FromStr;
