//! Backing types whose origin depends on the target's atomic capabilities.
//!
//! - `std` builds always use `std::sync::Arc`.
//! - `no_std` builds default to `alloc::sync::Arc`, which requires
//!   `target_has_atomic = "ptr"` (RISC-V A extension, ARM v7+, etc.).
//! - `no_std` builds on no-atomic-CAS targets (riscv32imc, thumbv6m,
//!   MSP430, AVR) opt into the `portable-atomic` feature, which routes
//!   refcounting through `portable_atomic_util::Arc` and works alongside
//!   `bytes/extra-platforms`. Pick a CAS polyfill via the corresponding
//!   `portable-atomic` feature in the binary crate (typically
//!   `--cfg portable_atomic_unsafe_assume_single_core` on uniprocessor
//!   MCUs, or `critical-section` on hosted RTOSes).

#[cfg(all(
    not(feature = "std"),
    not(target_arch = "wasm32"),
    feature = "portable-atomic"
))]
pub(crate) use portable_atomic_util::Arc;

#[cfg(all(
    not(feature = "std"),
    not(target_arch = "wasm32"),
    not(feature = "portable-atomic")
))]
pub(crate) use alloc::sync::Arc;

#[cfg(any(feature = "std", target_arch = "wasm32"))]
pub(crate) use std::sync::Arc;
