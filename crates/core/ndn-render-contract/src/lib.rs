//! ndn-render-contract — the upper half of **the Keel**: the render-contract
//! model and the matcher.
//!
//! # Where the built thing ends (read this first)
//!
//! This crate's output is a **verdict plus an inert `Via`** — nothing
//! here executes a renderer, and the render host that would (WASM sandbox,
//! ViewBlock typing, capability grants, Surface Authority) is design-only
//! and lives above this crate's waterline by construction (D-48). A
//! consumer today closes the loop itself: match → select → dispatch
//! `Via::Native` ids against its own in-process renderer registry. That is
//! the intended interim pattern, not a workaround — but it is YOUR registry
//! until the host exists.
//!
//! A render contract is a lens's signed promise (riverwatch: "declare less
//! than you can do if you must; never declare more"): which intents it
//! **expresses**, which it may **approximate**, which it **refuses** — over
//! which terms, optionally bound to which subjects. The contract *model*
//! lives in `ndn-manifest` (contracts are documents like everything else);
//! this crate owns the **matcher**: the decidable, budgeted, evaluation-free
//! procedure that binds manifests to contracts and renders one of four
//! verdicts — Express, Approximate(loss-path), Refuse, Unresolved(missing).
//!
//! Laws enforced here:
//!
//! - **C6/C6′** — matching is decidable, budgeted, and honest about
//!   ignorance: *unresolved ≠ refuse ≠ mismatch*.
//! - **C8** — matcher inertia: nothing requiring evaluation is ever matcher
//!   input. Selections and constraints are inert data; `via` is inert bytes.
//! - **C9** — fidelity monotonicity: one `maps-to` hop demotes the whole
//!   path to Approximate, and the demotion cannot be laundered back.
//! - **C10** — edges bind per-consumer: only frontier-admitted vocabularies
//!   contribute edges, so two readers may honestly diverge.
//! - **D-48** — this crate sits below the waterline and contains no policy:
//!   no signature checks, no authority walks, no I/O. Wrapping documents in
//!   Blocks adds history and authority — never meaning.
//!
//! Dependency discipline (C7, CI-enforced): `ndn-manifest` only. No ndf-*
//! crate, ever. C7 has a consumability corollary worth naming (F54, found
//! by the first cross-workspace consumer): zero transitive dependencies
//! means zero version-collision surface, which is what makes plain path
//! deps on these crates painless from OTHER cargo workspaces. C7 is a
//! feature consumers rely on, not just internal hygiene — treat adding a
//! dependency as a breaking change to them.
#![no_std]
#![deny(missing_docs)]

extern crate alloc;

pub mod matcher;

pub use matcher::{
    contract_via, r#match, select, select_best, Budget, BudgetExceeded, Floor, LossPath, Match,
    Missing, TrustFrontier, Verdict,
};

/// Re-exported for consumers dispatching a Match: the inert renderer
/// reference behind an Express/Approximate clause (`contract_via` resolves
/// it). Defined in `ndn-manifest` because contracts are documents.
pub use ndn_manifest::model::Via;
