//! [`WasmExecutor`] — a sandboxed, fuel-metered [`ComputeExecutor`].
//!
//! Mirrors the `ndn-strategy-wasm` precedent: a `wasmtime::Engine` with
//! `consume_fuel`, a fresh `Store` per invocation, and a small memory ABI.
//!
//! Guest contract — the module exports `memory` and a `compute` function
//! taking no arguments, and imports three host functions in the `ndn_compute`
//! namespace:
//!
//! - `input_len() -> u32` — byte length of the input.
//! - `read_input(dst_ptr: u32)` — host copies the input into guest memory at
//!   `dst_ptr` (the guest must reserve `input_len()` bytes there first).
//! - `write_output(src_ptr: u32, len: u32)` — host copies `len` bytes of output
//!   out of guest memory.
//!
//! A trap or fuel exhaustion surfaces as [`ComputeError::ComputeFailed`].

use std::path::Path;

use anyhow::Result;
use bytes::Bytes;

use crate::executor::ComputeExecutor;
use crate::registry::ComputeError;

const ENTRY: &str = "compute";

struct HostState {
    input: Vec<u8>,
    output: Option<Bytes>,
}

/// A compute kernel loaded from a WASM module. Each invocation runs in a fresh
/// `Store` with a fuel budget; trap or exhaustion yields an error.
pub struct WasmExecutor {
    engine: wasmtime::Engine,
    module: wasmtime::Module,
    linker: wasmtime::Linker<HostState>,
    fuel: u64,
}

impl WasmExecutor {
    /// Load from a `.wasm` (or `.wat`) file with a per-invocation `fuel` budget.
    pub fn from_file(path: impl AsRef<Path>, fuel: u64) -> Result<Self> {
        let (engine, linker) = Self::engine_and_linker()?;
        let module = wasmtime::Module::from_file(&engine, path)?;
        Ok(Self {
            engine,
            module,
            linker,
            fuel,
        })
    }

    /// Load from in-memory WASM (or WAT) bytes with a per-invocation `fuel`
    /// budget.
    pub fn from_bytes(wasm: &[u8], fuel: u64) -> Result<Self> {
        let (engine, linker) = Self::engine_and_linker()?;
        let module = wasmtime::Module::new(&engine, wasm)?;
        Ok(Self {
            engine,
            module,
            linker,
            fuel,
        })
    }

    fn engine_and_linker() -> Result<(wasmtime::Engine, wasmtime::Linker<HostState>)> {
        let mut config = wasmtime::Config::new();
        config.consume_fuel(true);
        let engine = wasmtime::Engine::new(&config)?;
        let mut linker = wasmtime::Linker::new(&engine);
        add_host_functions(&mut linker)?;
        Ok((engine, linker))
    }
}

impl ComputeExecutor for WasmExecutor {
    fn fuel(&self) -> Option<u64> {
        Some(self.fuel)
    }

    fn execute(&self, input: &[u8]) -> Result<Bytes, ComputeError> {
        let state = HostState {
            input: input.to_vec(),
            output: None,
        };
        let mut store = wasmtime::Store::new(&self.engine, state);
        store
            .set_fuel(self.fuel)
            .map_err(|e| ComputeError::ComputeFailed(format!("set_fuel: {e}")))?;

        let instance = self
            .linker
            .instantiate(&mut store, &self.module)
            .map_err(|e| ComputeError::ComputeFailed(format!("instantiate: {e}")))?;
        let func = instance
            .get_typed_func::<(), ()>(&mut store, ENTRY)
            .map_err(|e| ComputeError::ComputeFailed(format!("export `{ENTRY}`: {e}")))?;

        func.call(&mut store, ())
            .map_err(|e| ComputeError::ComputeFailed(format!("wasm trap: {e}")))?;

        store
            .into_data()
            .output
            .ok_or_else(|| ComputeError::ComputeFailed("guest produced no output".into()))
    }
}

fn add_host_functions(linker: &mut wasmtime::Linker<HostState>) -> Result<()> {
    linker.func_wrap(
        "ndn_compute",
        "input_len",
        |caller: wasmtime::Caller<'_, HostState>| -> u32 { caller.data().input.len() as u32 },
    )?;

    linker.func_wrap(
        "ndn_compute",
        "read_input",
        |mut caller: wasmtime::Caller<'_, HostState>, dst: u32| {
            let input = caller.data().input.clone();
            let mem = match caller.get_export("memory") {
                Some(wasmtime::Extern::Memory(m)) => m,
                _ => return,
            };
            let data = mem.data_mut(&mut caller);
            let d = dst as usize;
            if d.saturating_add(input.len()) <= data.len() {
                data[d..d + input.len()].copy_from_slice(&input);
            }
        },
    )?;

    linker.func_wrap(
        "ndn_compute",
        "write_output",
        |mut caller: wasmtime::Caller<'_, HostState>, src: u32, len: u32| {
            let mem = match caller.get_export("memory") {
                Some(wasmtime::Extern::Memory(m)) => m,
                _ => return,
            };
            let data = mem.data(&caller);
            let s = src as usize;
            let e = s.saturating_add(len as usize);
            if e <= data.len() {
                let out = Bytes::copy_from_slice(&data[s..e]);
                caller.data_mut().output = Some(out);
            }
        },
    )?;

    Ok(())
}
