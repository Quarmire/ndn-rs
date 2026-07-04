//! ndn-render-contract — the upper half of **the Keel**: the render-contract
//! model and the matcher.
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
//! crate, ever.
#![no_std]
#![deny(missing_docs)]

extern crate alloc;

pub mod matcher;

pub use matcher::{
    r#match, select, select_best, Budget, BudgetExceeded, Floor, LossPath, Match, Missing,
    TrustFrontier, Verdict,
};
