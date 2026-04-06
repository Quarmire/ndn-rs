---
name: doc-crate
description: Add or update crate-level documentation (//! doc comments) for an ndn-rs crate
user_invocable: true
---

The user wants to add or update crate-level `//!` documentation for a specific crate.

Steps:
1. Read the crate's `src/lib.rs` to check existing docs
2. Read the crate's `Cargo.toml` for dependencies and features
3. Browse key source files to understand the crate's purpose and public API
4. Write comprehensive `//!` doc comments at the top of `src/lib.rs` covering:
   - What the crate does (one paragraph)
   - Key types and traits exported
   - Usage examples where appropriate
   - Feature flags if any
5. Ensure the docs match the actual code, not aspirational design

The crate name is provided as the argument. If no argument, ask which crate.
