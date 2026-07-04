//! The pinned fixed-point hashes (R14) — WRITTEN BY `ndn-bench freeze --pin`.
//!
//! Recorded by the bench on a real toolchain (D-K8); never hand-edited.
//! To re-pin after a DELIBERATE kernel change: set these to `None`, record
//! the supersession (L-07), and run the freeze again.

/// H(V₀.2), lowercase hex, once pinned.
pub const V0_2_HASH_HEX: Option<&str> = Some("568b95812f3de160d8b43c3acb168ba04ee49fd51276eaa55d74f3f650e24720");

/// H(IM₀), lowercase hex, once pinned.
pub const IM0_HASH_HEX: Option<&str> = Some("39cfe0fb02b0cd6333cef7320e48545ba1c60ada2ddf1daf2c559ab5d2aca85a");

/// H(T₀), lowercase hex, once pinned.
pub const T0_HASH_HEX: Option<&str> = Some("a7ac046135c87046cb77c4b8a55ae55fa9ee65301f10223a236f8ccabf8aa3c6");
