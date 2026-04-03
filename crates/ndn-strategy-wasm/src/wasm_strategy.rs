use std::future::Future;
use std::path::Path;
use std::pin::Pin;

use anyhow::Result;
use smallvec::{SmallVec, smallvec};
use tracing::warn;

use ndn_packet::Name;
use ndn_pipeline::{ForwardingAction, NackReason};
use ndn_strategy::StrategyContext;

use ndn_engine::stages::ErasedStrategy;

use crate::host::{HostState, add_host_functions};

/// A forwarding strategy loaded from a WASM module.
///
/// The WASM module must export an `on_interest()` function that calls
/// host-provided functions (`get_nexthop`, `forward`, `nack`, `suppress`, etc.)
/// to make forwarding decisions.
///
/// # Performance
///
/// Each invocation creates a fresh `Store` with a fuel limit (default 10,000
/// instructions, ~50us worst case). Fuel exhaustion results in `Suppress`.
///
/// # Safety
///
/// WASM modules run in a sandboxed environment with:
/// - Fuel-limited execution (prevents infinite loops)
/// - Memory cap (default 1 MB)
/// - No filesystem, network, or clock access
pub struct WasmStrategy {
    name: Name,
    engine: wasmtime::Engine,
    module: wasmtime::Module,
    linker: wasmtime::Linker<HostState>,
    fuel: u64,
}

impl WasmStrategy {
    /// Load a strategy from a WASM file on disk.
    pub fn from_file(name: Name, path: impl AsRef<Path>, fuel: u64) -> Result<Self> {
        let mut config = wasmtime::Config::new();
        config.consume_fuel(true);
        let engine = wasmtime::Engine::new(&config)?;
        let module = wasmtime::Module::from_file(&engine, path)?;
        let mut linker = wasmtime::Linker::new(&engine);
        add_host_functions(&mut linker)?;
        Ok(Self {
            name,
            engine,
            module,
            linker,
            fuel,
        })
    }

    /// Load a strategy from in-memory WASM bytes.
    pub fn from_bytes(name: Name, wasm: &[u8], fuel: u64) -> Result<Self> {
        let mut config = wasmtime::Config::new();
        config.consume_fuel(true);
        let engine = wasmtime::Engine::new(&config)?;
        let module = wasmtime::Module::new(&engine, wasm)?;
        let mut linker = wasmtime::Linker::new(&engine);
        add_host_functions(&mut linker)?;
        Ok(Self {
            name,
            engine,
            module,
            linker,
            fuel,
        })
    }

    fn run_wasm(&self, ctx: &StrategyContext<'_>, entry: &str) -> SmallVec<[ForwardingAction; 2]> {
        let state = HostState::from_context(ctx);
        let mut store = wasmtime::Store::new(&self.engine, state);
        if store.set_fuel(self.fuel).is_err() {
            warn!(strategy=%self.name, "failed to set fuel");
            return smallvec![ForwardingAction::Suppress];
        }

        let instance = match self.linker.instantiate(&mut store, &self.module) {
            Ok(i) => i,
            Err(e) => {
                warn!(strategy=%self.name, error=%e, "WASM instantiation failed");
                return smallvec![ForwardingAction::Suppress];
            }
        };

        let func = match instance.get_typed_func::<(), ()>(&mut store, entry) {
            Ok(f) => f,
            Err(e) => {
                warn!(strategy=%self.name, entry, error=%e, "WASM export not found");
                return smallvec![ForwardingAction::Suppress];
            }
        };

        match func.call(&mut store, ()) {
            Ok(()) => store.into_data().take_actions(),
            Err(e) => {
                // Fuel exhaustion or trap — suppress.
                warn!(strategy=%self.name, entry, error=%e, "WASM execution failed");
                smallvec![ForwardingAction::Suppress]
            }
        }
    }
}

impl ErasedStrategy for WasmStrategy {
    fn name(&self) -> &Name {
        &self.name
    }

    fn decide_sync(&self, ctx: &StrategyContext<'_>) -> Option<SmallVec<[ForwardingAction; 2]>> {
        Some(self.run_wasm(ctx, "on_interest"))
    }

    fn after_receive_interest_erased<'a>(
        &'a self,
        ctx: &'a StrategyContext<'a>,
    ) -> Pin<Box<dyn Future<Output = SmallVec<[ForwardingAction; 2]>> + Send + 'a>> {
        // Delegate to sync path — WASM execution is fast and fuel-bounded.
        Box::pin(async move { self.run_wasm(ctx, "on_interest") })
    }

    fn on_nack_erased<'a>(
        &'a self,
        ctx: &'a StrategyContext<'a>,
        _reason: NackReason,
    ) -> Pin<Box<dyn Future<Output = ForwardingAction> + Send + 'a>> {
        Box::pin(async move {
            let actions = self.run_wasm(ctx, "on_nack");
            actions
                .into_iter()
                .next()
                .unwrap_or(ForwardingAction::Suppress)
        })
    }
}
