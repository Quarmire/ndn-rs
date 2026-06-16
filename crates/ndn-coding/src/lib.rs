//! # ndn-coding — Network coding for NDN
//!
//! Phase **F1**: end-to-end systematic K-of-N forward error correction
//! over named segment-sets. The producer publishes K source + (N−K)
//! parity Data segments per generation; the consumer recovers the
//! payload once any K of the N arrive. Every coded segment is an
//! independently named, independently signed Data object, so caches,
//! PIT aggregation, and signature verification all work unchanged —
//! intermediate forwarders are never modified. *Coded Data is just
//! Data.*
//!
//! ## Layers
//!
//! ```text
//! endpoint   CodedProducer / CodedFetcher        the "one obvious call"
//! ───────────────────────────────────────────────────────────────────
//! core       segment_payload + CodedAssembler     building blocks
//!            FecMetadata wire codec
//!            GF(2^8) + systematic K-of-N codec
//! ```
//!
//! The [`endpoint`] layer (default feature `endpoint`) is the ergonomic
//! producer/consumer API built on `ndn-app`. The core (codec + field +
//! encoder/decoder + assembler) carries no async runtime and is what an
//! embedded or in-browser build pulls with `--no-default-features`.
//!
//! ## What this crate is and isn't
//!
//! - **F1 (here):** producer-encoded, consumer-decoded FEC. The
//!   forwarder is unchanged.
//! - **F2 (implemented, off by default):** in-network RLNC recoding where
//!   forwarders mix Data along the path. A recoded packet is a new linear
//!   combination the producer never signed; its trust model is settled in
//!   `docs/doctrine/nc-recoding-trust-model-2026-05-23.md` (verify-on-decode
//!   against a producer-signed generation descriptor, with delegated-recoder
//!   signing as an in-flight upgrade). Gated behind `f2-recode` (pure core:
//!   the `recode` module) and `f2-recode-face` (native `RecoderFace`: the
//!   `recode_face` module); wire format in
//!   `docs/notes/coding-f2-wire-spec-2026-05-23.md`.
//! - **F3 (link-layer, off by default):** COPE-style *inter-flow* NC on a
//!   shared broadcast medium. The pure coding core is the `cope` module
//!   behind `f3-link`; driving it from a real broadcast face (a
//!   `LinkServiceFeature`) is the deployment seam and lives in a face driver,
//!   not here.
//!
//! ## Module map
//!
//! - [`policy`] — `CodingPolicy`, `CodingPolicyTable`, role enum.
//! - [`metadata`] — `FecMetadata` sub-TLV carried at the head of Content.
//! - [`field`] — GF(2^8) arithmetic; scalar reference + optional SIMD.
//! - [`fec`] — systematic K-of-N encoder/decoder over `bytes::Bytes`.
//! - [`segmenter`] — `segment_payload`: payload → K source + (N−K) parity.
//! - [`assembler`] — `CodedAssembler`: absorb any K of N, recover payload.
//! - [`endpoint`] — `CodedProducer` / `CodedFetcher` (feature `endpoint`).
//! - [`mgmt`] — `/localhost/nfd/coding/{set,unset,list}` policy backend.
//! - [`config`] — `serde` shapes for TOML `[[coding.policy]]` blocks.
//! - `recode` — F2 core: descriptor/vector codec, `GenerationBuffer`,
//!   verify-on-decode, fingerprint/token (feature `f2-recode`).
//! - `recode_face` — F2 native `RecoderFace` + delegated/token verify
//!   (feature `f2-recode-face`).
//! - `recode_compute` — register `_nc` as an ndn-compute function
//!   (feature `f2-recode-compute`).
//! - `cope` — F3 inter-flow (COPE) coding core + link framing
//!   (feature `f3-link`).
//! - `cope_face` — F3 `CopeBroadcastLink` + per-neighbor `CopeMemberFace`
//!   (next-hop feed) + reception-report frames (feature `f3-link-face`).
//! - `cope_mesh` — `CopeMesh`: auto-install member faces per neighbor on an
//!   engine + report/flush ticker + `spawn_neighbor_sync` routing-fed
//!   reconciliation (feature `f3-link-mesh`).
//!
//! Design and wire spec: `docs/notes/coding-design-2026-05-22.md`,
//! `docs/notes/coding-wire-spec-2026-05-22.md`, the F2 wire spec
//! `docs/notes/coding-f2-wire-spec-2026-05-23.md`, and the F2 trust-model
//! doctrine `docs/doctrine/nc-recoding-trust-model-2026-05-23.md`.

#![allow(missing_docs)]

pub mod assembler;
pub mod config;
#[cfg(feature = "f3-link")]
pub mod cope;
#[cfg(feature = "f3-link-face")]
pub mod cope_face;
#[cfg(feature = "f3-link-mesh")]
pub mod cope_mesh;
#[cfg(feature = "endpoint")]
pub mod endpoint;
pub mod fec;
pub mod field;
pub mod link_fec;
pub mod metadata;
#[cfg(feature = "mgmt")]
pub mod mgmt;
pub mod policy;
#[cfg(feature = "f2-recode")]
pub mod recode;
#[cfg(feature = "f2-recode-compute")]
pub mod recode_compute;
#[cfg(feature = "f2-recode-face")]
pub mod recode_face;
pub mod segmenter;

pub use assembler::CodedAssembler;
pub use config::{CodingConfig, CodingPolicyConfig};
#[cfg(feature = "endpoint")]
pub use endpoint::{CodedFetcher, CodedProducer, FetchConfig};
pub use fec::{Decoder, Encoder};
pub use link_fec::{LINK_FEC_MAGIC, LinkFecRx, LinkFecTx};
pub use metadata::{FecMetadata, SegmentRole, prepend_metadata, split_metadata};
#[cfg(feature = "mgmt")]
pub use mgmt::{CodingMgmtHandler, CodingPolicyEntry};
pub use policy::{CodingPolicy, CodingPolicyTable, FecPolicy, PolicyRole, SharedPolicyTable};
pub use segmenter::{EmittedSegment, segment_payload};

/// Crate-wide error type.
#[derive(Debug, thiserror::Error)]
pub enum CodingError {
    /// Policy lookup failed for the requested prefix.
    #[error("no coding policy installed for prefix")]
    NoPolicy,
    /// Parameter combination (K, N, field) is unsupported.
    #[error("invalid FEC parameters: k={k} n={n}")]
    InvalidParameters { k: u16, n: u16 },
    /// Decoder lacks rank to recover the generation.
    #[error("insufficient rank: have {have} of {needed}")]
    InsufficientRank { have: u16, needed: u16 },
    /// Encoder fed fewer or more than K source segments before
    /// parity was requested.
    #[error("encoder source count mismatch: have {have} of {needed}")]
    SourceCountMismatch { have: u16, needed: u16 },
    /// Segment index outside `[0, n)`.
    #[error("segment index {index} out of range (n={n})")]
    IndexOutOfRange { index: u16, n: u16 },
    /// Two segments in the same generation had different lengths.
    #[error("segment length mismatch: have {have}, expected {expected}")]
    SegmentLengthMismatch { have: usize, expected: usize },
    /// `FecMetadata` could not be parsed from MetaInfo.
    #[error("malformed FecMetadata sub-TLV")]
    MalformedMetadata,
    /// Catch-all for code paths not yet implemented.
    #[error("not yet implemented: {0}")]
    Unimplemented(&'static str),
}

pub type Result<T> = std::result::Result<T, CodingError>;
