//! `Arc` whose origin depends on the target's atomic capabilities (the same
//! split `ndn-packet` uses).
//!
//! - Default: `alloc::sync::Arc` (the type `std::sync::Arc` re-exports), which
//!   requires atomic CAS (`target_has_atomic = "ptr"`).
//! - `portable-atomic`: `portable_atomic_util::Arc`, for no-CAS targets
//!   (riscv32imc, thumbv6m, ...). The binary picks the CAS polyfill, typically
//!   `--cfg portable_atomic_unsafe_assume_single_core`.

#[cfg(feature = "portable-atomic")]
pub(crate) use portable_atomic_util::Arc;

#[cfg(not(feature = "portable-atomic"))]
pub(crate) use alloc::sync::Arc;
