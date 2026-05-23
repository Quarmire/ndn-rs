//! [`ComputeExecutor`] — the extensibility seam.
//!
//! An executor is a pure bytes-in / bytes-out compute kernel that knows nothing
//! about NDN packets. Native code, a [`WasmExecutor`](crate::WasmExecutor), or a
//! future remote-process backend all implement the same trait, so
//! [`ComputeService::executor_function`](crate::ComputeService::executor_function)
//! is backend-agnostic.
//!
//! `execute` is synchronous because the canonical backends (WASM, native
//! kernels) are CPU-bound; the service runs it on the compute face's task. Async
//! backends are better expressed as a native
//! [`function`](crate::ComputeService::function) closure.

use bytes::Bytes;

use crate::registry::ComputeError;

/// A bytes-in / bytes-out compute kernel.
pub trait ComputeExecutor: Send + Sync + 'static {
    /// Run the kernel over `input`, producing the result bytes.
    fn execute(&self, input: &[u8]) -> Result<Bytes, ComputeError>;

    /// Per-invocation fuel budget, if this executor meters CPU (e.g.
    /// [`WasmExecutor`](crate::WasmExecutor)). Surfaced in the `compute`
    /// management dataset; defaults to `None` for unmetered kernels.
    fn fuel(&self) -> Option<u64> {
        None
    }
}

/// Blanket impl so a plain `Fn(&[u8]) -> Result<Bytes, ComputeError>` is an
/// executor.
impl<F> ComputeExecutor for F
where
    F: Fn(&[u8]) -> Result<Bytes, ComputeError> + Send + Sync + 'static,
{
    fn execute(&self, input: &[u8]) -> Result<Bytes, ComputeError> {
        (self)(input)
    }
}
