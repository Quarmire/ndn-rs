//! ndn-manifest — the NDF calculus kernel, as a pure spec crate.
//!
//! # Where the built thing ends (read this first)
//!
//! **Ratified and tested here:** the calculus — documents, canonical bytes,
//! the DAG, the kernel fixed point. Together with `ndn-render-contract`
//! (the matcher), the pipeline ends at a **verdict plus an inert `Via`**.
//! **Not built anywhere:** the render host — the runtime that turns
//! `Express + Via::Wasm` into pixels (renderer sandbox, ViewBlock typing,
//! capability grants, the Surface Authority). Those exist as design notes
//! only. The Riverwatch essay's surfaces are the design target, not a
//! runnable path; `examples/waterline-keel` proves the matcher and prints
//! verdicts — it does not close the loop to output. Plan integrations
//! accordingly: today's honest pattern is matcher-driven selection plus
//! your own in-process renderer registry behind `Via::Native`.
//!
//! This crate is the bottom half of **the Keel**: the layer the Waterline
//! suite stands on (the crate name stays unbranded on purpose — "the Keel"
//! is the suite-facing layer name only). It holds:
//!
//! - [`model`] — the frozen 32-term kernel V₀.2 as types (D-49, ratified):
//!   meaning travels as small documents; a term's identity is its hash.
//! - [`canon`] — the one canonical byte form, wire rules R1–R13
//!   (ndf-the-landing Act III). Every deviation is a typed reject; decode ∘
//!   encode is byte identity or reject; the document hash is SHA-256 over
//!   exactly these bytes.
//! - [`dag`] — content-addressed storage, the lockfile (petname → hash,
//!   F21), and the acyclic import walk. Loops are impossible by physics:
//!   definitional references are hash-only (C5).
//! - [`kernel`] — V₀.2 published as data written in itself, plus T₀ (the
//!   terminal contract) and IM₀ (the implicit-manifest stratum): the fixed
//!   point R14 pins, and the C3 total floor that makes refusal safe.
//! - [`hash`] — SHA-256 in-crate (D-K2), so the crate has zero dependencies.
//!
//! # The load-bearing laws
//!
//! - **Hash-only definitional references** (D-48/D-49): you cannot reference
//!   what does not exist yet, so the definitional graph is a DAG by
//!   construction — recursion lives inside one document (`rec-group`),
//!   never across documents.
//! - **Attributes are flat** (knob #4, four sieges survived): primitives or
//!   term refs only; structure routes to records or reification (P2).
//! - **The calculus contains no policy** (D-48 waterline corollary): this
//!   crate may sink below the waterline; its governance may not. It is
//!   consumed by the suite below and the Observatory above, unchanged.
//! - **Obligation C7, CI-enforced**: zero ndf-* dependencies — in fact zero
//!   dependencies — and `--no-default-features` builds, the way ndn-time
//!   already ships.
//!
//! The matcher lives one crate up (`ndn-render-contract`); the bench, the
//! script grammars, and the conformance corpus live in `ndn-bench`.
#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]

extern crate alloc;

pub mod canon;
pub mod dag;
pub mod hash;
pub mod kernel;
pub mod kernel_hash;
pub mod model;

pub use canon::{decode_document, document_hash, encode_decoded, encode_document, term_hash, EncodeError, Reject};
pub use dag::{FrozenDag, Lock, Resolution};
pub use hash::{sha256, Hash, Sha256};
pub use kernel::{derive_im0, fixed_point, im0, im0_terms, t0, v0_2, verify_fixed_point, FixedPoint, FixedPointStatus, Im0Terms};
pub use model::{
    Attribute, Cardinality, Clause, Contract, Decimal, Decoded, Document, EdgeForm, Field, Intent,
    Manifest, ManifestEntry, PrimitiveKind, RawTlv, Subject, Term, TypeExpr, Value, Via, Vocabulary,
};
