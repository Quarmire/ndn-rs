//! F2 in-network RLNC recoding — types and seams (feature `f2-recode`).
//!
//! **Scaffolding.** The trust model is decided in
//! `docs/doctrine/nc-recoding-trust-model-2026-05-23.md` and the wire
//! format in `docs/notes/coding-f2-wire-spec-2026-05-23.md`. This module
//! defines the reviewable *shapes* — recode policy, generation descriptor,
//! coding vector, the `Recoder` seam — and implements the two genuinely
//! pure pieces (the GF(2^8) linear combination and rank-aware admission).
//! Engine wiring (the pre-Dispatch `Recoder` hook, the
//! `PitKeyDiscriminator::CodedGeneration` match) and the descriptor/vector
//! TLV codec are intentionally left as documented seams pending the
//! implementation pass (wire spec §8); they are marked `unimplemented!`.
//!
//! Mixing is **intra-flow only**: every operation here is scoped to one
//! `(generation_id, descriptor)`. Cross-generation mixing is out of scope
//! by construction — there is no API to combine packets of different
//! generations (doctrine §5, "Mixing scope").

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_tlv::{TlvReader, TlvWriter};

use crate::field;
use crate::metadata::{
    TYPE_FEC_FIELD, TYPE_FEC_GENERATION, TYPE_FEC_K, TYPE_FEC_METADATA, TYPE_FEC_ROLE,
};
use crate::policy::Field;
use crate::{CodingError, Result};

mod linalg;
mod wire;

use linalg::*;
use wire::*;

// F2 TLV type codes — continue the F1 0xC8 block; even, non-critical
// (wire spec §6). The `SymbolSize`/`GEN-DESCRIPTOR` collision flagged in
// §8 is resolved here: `SymbolSize` takes the distinct code 0xE6.
const TYPE_GEN_DESCRIPTOR: u64 = 0xD8;
const TYPE_CODING_VECTOR_WIDTH: u64 = 0xDA;
const TYPE_CONTENT_NAME: u64 = 0xDC;
const TYPE_SOURCE_COMMITMENT: u64 = 0xDE;
const TYPE_RECODE_POLICY: u64 = 0xE0;
const TYPE_DELEGATION_LOCATOR: u64 = 0xE2;
const TYPE_CODING_VECTOR: u64 = 0xE4;
const TYPE_SYMBOL_SIZE: u64 = 0xE6;
const TYPE_FINGERPRINT: u64 = 0xE8;
const TYPE_FP_R: u64 = 0xEA;
const TYPE_FP_H: u64 = 0xEC;
const TYPE_RECODE_TOKEN: u64 = 0xEE;
const TYPE_TOKEN_RECODER: u64 = 0xF0;
const TYPE_TOKEN_SIG: u64 = 0xF2;
const TYPE_FP_SEED_HASH: u64 = 0xF4;

/// Wire byte for `Role`: a recoded linear combination (wire spec §4).
/// Extends F1's 0 = source, 1 = parity.
const ROLE_CODED: u8 = 2;

/// Signed recoding permission carried in the generation descriptor
/// (wire spec §3.2). Never inferred from a descriptor's mere existence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecodePolicy {
    /// No recoding; producer-coded packets only (F1-like).
    None,
    /// Any forwarder may recode (verify-on-decode floor).
    Open,
    /// Only trust-schema-authorized recoder keys may recode (in-flight).
    Delegated,
    /// Recoding confined to a named trust domain.
    LocalDomain,
    /// Recoding requires a producer-issued capability token.
    TokenRequired,
}

impl RecodePolicy {
    /// Wire byte (wire spec §3.2).
    pub fn as_u8(self) -> u8 {
        match self {
            RecodePolicy::None => 0,
            RecodePolicy::Open => 1,
            RecodePolicy::Delegated => 2,
            RecodePolicy::LocalDomain => 3,
            RecodePolicy::TokenRequired => 4,
        }
    }

    /// Parse a wire byte; `None` for an unknown value.
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0 => RecodePolicy::None,
            1 => RecodePolicy::Open,
            2 => RecodePolicy::Delegated,
            3 => RecodePolicy::LocalDomain,
            4 => RecodePolicy::TokenRequired,
            _ => return None,
        })
    }

    /// Whether this policy authorizes in-flight (delegated-signed) recoding,
    /// as opposed to verify-on-decode only.
    pub fn is_delegated(self) -> bool {
        matches!(self, RecodePolicy::Delegated | RecodePolicy::LocalDomain)
    }
}

/// Coding policy for a generation under F2 (the `Rlnc` arm of
/// [`crate::policy::CodingPolicy`]). `k` source rows over `field`; the
/// coding-vector width equals `k`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RlncPolicy {
    pub k: u16,
    #[serde(default = "RlncPolicy::default_field")]
    pub field: Field,
    pub recode: RecodePolicy,
}

impl RlncPolicy {
    /// `None` if `k == 0` or `k > 255` (GF(2^8) generation bound).
    pub fn new(k: u16, recode: RecodePolicy) -> Option<Self> {
        if k == 0 || k > 255 {
            return None;
        }
        Some(Self {
            k,
            field: Self::default_field(),
            recode,
        })
    }

    fn default_field() -> Field {
        Field::Gf8
    }

    /// Coefficients per coding vector (= `k`).
    pub fn coding_vector_width(&self) -> u16 {
        self.k
    }
}

/// Producer commitment over the K source rows (wire spec §3.1). For
/// `encrypt-then-code`, these commit to *ciphertext* rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceCommitment {
    /// One SHA-256 per source row, in source-index order.
    RowHashes(Vec<[u8; 32]>),
    /// A single Merkle root over the source-row hashes.
    MerkleRoot([u8; 32]),
}

/// Probabilistic homomorphic fingerprint for cheap **in-flight** pollution
/// filtering (doctrine §6 resilience axis — *not* an authenticity mechanism;
/// verify-on-decode remains the authenticity backstop). The producer commits
/// to a random projection `r` (length = symbol size) and per-source-row
/// projections `h[s] = <r, source[s]>` over GF(2^8). For any coded packet
/// `(vector c, payload y)`, `<r, y>` must equal `Σ c[s]·h[s]` — homomorphic,
/// so it checks an arbitrary linear combination without decoding.
///
/// Adaptive resistance (doctrine §6): if `r` is public before an attacker
/// crafts a packet, it can be defeated. The **delayed-seed** mode
/// ([`LinearFingerprint::delayed`]) commits to `seed_hash = SHA-256(r)` while
/// withholding `r` (so `r` is empty until [`reveal`](Self::reveal)); coders
/// cannot filter in-flight (the seed is secret), but once the producer reveals
/// `r` the check verifies retroactively and *identifies* polluters — which an
/// attacker who committed before the reveal cannot pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinearFingerprint {
    /// Random projection vector, length = symbol size. **Empty** in the
    /// delayed mode until the seed is revealed.
    pub r: Vec<u8>,
    /// Per-source-row projections, length = K.
    pub h: Vec<u8>,
    /// `Some(SHA-256(r))` in the delayed mode; `None` for the immediate
    /// (public-`r`) mode.
    pub seed_hash: Option<[u8; 32]>,
}

impl LinearFingerprint {
    /// Immediate mode: `r` is public; coders filter pollution in-flight.
    pub fn for_sources(r: Vec<u8>, sources: &[Vec<u8>]) -> Self {
        let h = sources.iter().map(|row| gf_dot(&r, row)).collect();
        Self {
            r,
            h,
            seed_hash: None,
        }
    }

    /// Delayed mode: commit to `SHA-256(r)` and publish `h`, but **withhold
    /// `r`** (it stays empty until [`reveal`](Self::reveal)). No in-flight
    /// filtering; adaptive-resistant retroactive verification after reveal.
    pub fn delayed(r: &[u8], sources: &[Vec<u8>]) -> Self {
        let h = sources.iter().map(|row| gf_dot(r, row)).collect();
        Self {
            r: Vec::new(),
            h,
            seed_hash: Some(row_hash(r)),
        }
    }

    /// `true` if this is a delayed commitment whose seed is not yet revealed.
    pub fn is_delayed_unrevealed(&self) -> bool {
        self.seed_hash.is_some() && self.r.is_empty()
    }

    /// Reveal the seed: if `SHA-256(r)` matches the commitment, return the
    /// usable (immediate-equivalent) fingerprint with `r` filled in. `None` if
    /// the seed does not match the commitment (or this was not delayed).
    pub fn reveal(&self, r: &[u8]) -> Option<LinearFingerprint> {
        match self.seed_hash {
            Some(hash) if row_hash(r) == hash => Some(LinearFingerprint {
                r: r.to_vec(),
                h: self.h.clone(),
                seed_hash: self.seed_hash,
            }),
            _ => None,
        }
    }

    /// Encode as a standalone `Fingerprint` TLV — used to carry a
    /// consumer-challenge response as Data `Content` (wire spec §3.3).
    pub fn to_tlv(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(TYPE_FINGERPRINT, |f| {
            f.write_tlv(TYPE_FP_R, &self.r);
            f.write_tlv(TYPE_FP_H, &self.h);
            if let Some(sh) = &self.seed_hash {
                f.write_tlv(TYPE_FP_SEED_HASH, sh);
            }
        });
        w.finish()
    }

    /// Decode a standalone `Fingerprint` TLV.
    pub fn from_tlv(bytes: &[u8]) -> Result<Self> {
        let mut r = TlvReader::new(Bytes::copy_from_slice(bytes));
        let (typ, value) = r.read_tlv().map_err(|_| CodingError::MalformedMetadata)?;
        if typ != TYPE_FINGERPRINT {
            return Err(CodingError::MalformedMetadata);
        }
        decode_fingerprint(value)
    }

    /// Check a coded packet: `<r, payload>` must equal `Σ vector[s]·h[s]`.
    /// Returns `false` if `r` is not available (delayed-unrevealed) — callers
    /// must not treat that as a pass; gate with [`is_delayed_unrevealed`].
    pub fn check(&self, vector: &CodingVector, payload: &[u8]) -> bool {
        if self.r.is_empty() || payload.len() != self.r.len() || vector.len() != self.h.len() {
            return false;
        }
        let expected = vector
            .0
            .iter()
            .zip(&self.h)
            .fold(0u8, |acc, (&c, &hs)| acc ^ field::mul(c, hs));
        gf_dot(&self.r, payload) == expected
    }
}

/// The producer-signed generation descriptor (wire spec §3) — the trust
/// anchor every combination of the generation verifies against. Carried as
/// the `Content` of an ordinary signed Data at `<object>/<GEN>=<id>/_desc`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationDescriptor {
    pub generation_id: u64,
    pub k: u16,
    pub symbol_size: u32,
    pub field: Field,
    /// The coded object / version (`<object>` and its RDR version).
    pub content_name: Name,
    pub source_commitment: SourceCommitment,
    pub recode: RecodePolicy,
    /// Authorized recoder key namespace; REQUIRED iff `recode` is delegated.
    pub delegation: Option<Name>,
    /// Optional in-flight pollution fingerprint (doctrine §6). `None` ⇒
    /// verify-on-decode is the only pollution check.
    pub fingerprint: Option<LinearFingerprint>,
}

impl GenerationDescriptor {
    /// Coefficients per coding vector (= `k`).
    pub fn coding_vector_width(&self) -> u16 {
        self.k
    }

    /// Structural invariant: a delegated policy MUST name its recoder
    /// namespace (wire spec §3).
    pub fn is_well_formed(&self) -> bool {
        if self.recode.is_delegated() && self.delegation.is_none() {
            return false;
        }
        if let Some(fp) = &self.fingerprint {
            // `r` is empty in the delayed mode (withheld until reveal); only
            // require its length in the immediate / revealed case.
            let r_ok = fp.is_delayed_unrevealed() || fp.r.len() == self.symbol_size as usize;
            if !r_ok || fp.h.len() != self.k as usize {
                return false;
            }
        }
        match &self.source_commitment {
            SourceCommitment::RowHashes(h) => h.len() == self.k as usize,
            SourceCommitment::MerkleRoot(_) => true,
        }
    }

    /// Encode the descriptor as the `Content` TLV of its signed Data
    /// (wire spec §3). The outer Data signature is applied by the caller
    /// (e.g. a `Producer`); this is only the `Content` body.
    pub fn to_tlv(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(TYPE_GEN_DESCRIPTOR, |inner| {
            inner.write_tlv(TYPE_FEC_GENERATION, &encode_u64_be(self.generation_id));
            inner.write_tlv(TYPE_FEC_K, &self.k.to_be_bytes());
            inner.write_tlv(TYPE_SYMBOL_SIZE, &self.symbol_size.to_be_bytes());
            inner.write_tlv(TYPE_FEC_FIELD, &[field_code(self.field)]);
            inner.write_tlv(TYPE_CODING_VECTOR_WIDTH, &self.k.to_be_bytes());
            inner.write_tlv(TYPE_CONTENT_NAME, &self.content_name.encode_to_tlv());
            inner.write_tlv(
                TYPE_SOURCE_COMMITMENT,
                &encode_commitment(&self.source_commitment),
            );
            inner.write_tlv(TYPE_RECODE_POLICY, &[self.recode.as_u8()]);
            if let Some(d) = &self.delegation {
                inner.write_tlv(TYPE_DELEGATION_LOCATOR, &d.encode_to_tlv());
            }
            if let Some(fp) = &self.fingerprint {
                inner.write_nested(TYPE_FINGERPRINT, |f| {
                    f.write_tlv(TYPE_FP_R, &fp.r); // empty in delayed mode
                    f.write_tlv(TYPE_FP_H, &fp.h);
                    if let Some(sh) = &fp.seed_hash {
                        f.write_tlv(TYPE_FP_SEED_HASH, sh);
                    }
                });
            }
        });
        w.finish()
    }

    /// Decode a descriptor from a Data `Content` body (wire spec §3).
    pub fn from_tlv(content: &[u8]) -> Result<Self> {
        let mut r = TlvReader::new(Bytes::copy_from_slice(content));
        let (typ, value) = r.read_tlv().map_err(|_| CodingError::MalformedMetadata)?;
        if typ != TYPE_GEN_DESCRIPTOR {
            return Err(CodingError::MalformedMetadata);
        }
        let mut inner = TlvReader::new(value);
        let (mut gen_id, mut k, mut sym, mut field, mut width) = (None, None, None, None, None);
        let (mut name, mut commit, mut recode, mut deleg) = (None, None, None, None);
        let mut fingerprint = None;
        while !inner.is_empty() {
            let (t, v) = inner
                .read_tlv()
                .map_err(|_| CodingError::MalformedMetadata)?;
            match t {
                TYPE_FEC_GENERATION => gen_id = Some(decode_u64_be(&v)?),
                TYPE_FEC_K => k = Some(decode_u16_be(&v)?),
                TYPE_SYMBOL_SIZE => sym = Some(decode_u32_be(&v)?),
                TYPE_FEC_FIELD => field = Some(field_from_code(one_byte(&v)?)?),
                TYPE_CODING_VECTOR_WIDTH => width = Some(decode_u16_be(&v)?),
                TYPE_CONTENT_NAME => {
                    name =
                        Some(Name::decode_from_tlv(v).map_err(|_| CodingError::MalformedMetadata)?)
                }
                TYPE_SOURCE_COMMITMENT => commit = Some(decode_commitment(&v)?),
                TYPE_RECODE_POLICY => {
                    recode = Some(
                        RecodePolicy::from_u8(one_byte(&v)?)
                            .ok_or(CodingError::MalformedMetadata)?,
                    )
                }
                TYPE_DELEGATION_LOCATOR => {
                    deleg =
                        Some(Name::decode_from_tlv(v).map_err(|_| CodingError::MalformedMetadata)?)
                }
                TYPE_FINGERPRINT => fingerprint = Some(decode_fingerprint(v)?),
                _ => {} // unknown sub-TLV ignored (forward compatibility)
            }
        }
        let k = k.ok_or(CodingError::MalformedMetadata)?;
        // `width` is carried for explicitness; it MUST equal k (wire spec §4.1).
        if matches!(width, Some(w) if w != k) {
            return Err(CodingError::MalformedMetadata);
        }
        let desc = GenerationDescriptor {
            generation_id: gen_id.ok_or(CodingError::MalformedMetadata)?,
            k,
            symbol_size: sym.ok_or(CodingError::MalformedMetadata)?,
            field: field.ok_or(CodingError::MalformedMetadata)?,
            content_name: name.ok_or(CodingError::MalformedMetadata)?,
            source_commitment: commit.ok_or(CodingError::MalformedMetadata)?,
            recode: recode.ok_or(CodingError::MalformedMetadata)?,
            delegation: deleg,
            fingerprint,
        };
        if !desc.is_well_formed() {
            return Err(CodingError::MalformedMetadata);
        }
        Ok(desc)
    }
}

/// A producer-issued capability authorizing a recoder identity to recode a
/// generation under `RecodePolicy::token-required` (wire spec §3.2). The
/// producer signs `(generation_id, recoder)`; the recoder presents the token,
/// and a verifier checks the producer signature, that the token names this
/// generation, and that the recoded Data's signer falls under `recoder`.
/// Issuing/verifying the signature lives in `recode_face` (native);
/// this type is the wire form + the authorization predicate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecodeToken {
    pub generation_id: u64,
    /// Authorized recoder key (or namespace prefix).
    pub recoder: Name,
    /// Producer signature over [`RecodeToken::signed_bytes`].
    pub signature: Bytes,
}

impl RecodeToken {
    /// Canonical bytes the producer signs: `generation_id` (8B BE) followed by
    /// the recoder name's TLV. Stable across encoders.
    pub fn signed_bytes(generation_id: u64, recoder: &Name) -> Vec<u8> {
        let mut out = generation_id.to_be_bytes().to_vec();
        out.extend_from_slice(&recoder.encode_to_tlv());
        out
    }

    /// Whether `key_name` is authorized by this token (under `recoder`).
    pub fn authorizes(&self, key_name: &Name) -> bool {
        key_name.has_prefix(&self.recoder)
    }

    pub fn to_tlv(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(TYPE_RECODE_TOKEN, |inner| {
            inner.write_tlv(TYPE_FEC_GENERATION, &encode_u64_be(self.generation_id));
            inner.write_tlv(TYPE_TOKEN_RECODER, &self.recoder.encode_to_tlv());
            inner.write_tlv(TYPE_TOKEN_SIG, &self.signature);
        });
        w.finish()
    }

    pub fn from_tlv(bytes: &[u8]) -> Result<Self> {
        let mut r = TlvReader::new(Bytes::copy_from_slice(bytes));
        let (typ, value) = r.read_tlv().map_err(|_| CodingError::MalformedMetadata)?;
        if typ != TYPE_RECODE_TOKEN {
            return Err(CodingError::MalformedMetadata);
        }
        let mut inner = TlvReader::new(value);
        let (mut gen_id, mut recoder, mut sig) = (None, None, None);
        while !inner.is_empty() {
            let (t, v) = inner
                .read_tlv()
                .map_err(|_| CodingError::MalformedMetadata)?;
            match t {
                TYPE_FEC_GENERATION => gen_id = Some(decode_u64_be(&v)?),
                TYPE_TOKEN_RECODER => {
                    recoder =
                        Some(Name::decode_from_tlv(v).map_err(|_| CodingError::MalformedMetadata)?)
                }
                TYPE_TOKEN_SIG => sig = Some(v),
                _ => {}
            }
        }
        Ok(RecodeToken {
            generation_id: gen_id.ok_or(CodingError::MalformedMetadata)?,
            recoder: recoder.ok_or(CodingError::MalformedMetadata)?,
            signature: sig.ok_or(CodingError::MalformedMetadata)?,
        })
    }
}

/// A coding-vector row over GF(2^8): the coefficients of a coded packet over
/// the K source rows, in source-index order (wire spec §4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodingVector(pub Vec<u8>);

impl CodingVector {
    /// The identity row for systematic source segment `index` (so an F1
    /// `Role∈{source,parity}` packet is a coded packet whose vector is
    /// derived here — wire spec §4 interop note).
    pub fn unit(k: u16, index: u16) -> Self {
        let mut v = vec![0u8; k as usize];
        if (index as usize) < v.len() {
            v[index as usize] = 1;
        }
        CodingVector(v)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// One coded packet held by a recoder or absorbed by a consumer: its coding
/// vector plus the coded row bytes (length = descriptor `symbol_size`).
#[derive(Debug, Clone)]
pub struct CodedPacket {
    pub vector: CodingVector,
    pub payload: bytes::Bytes,
}

/// Produce a fresh linear combination of `held` packets with `coeffs[i]`
/// applied to `held[i]`, over GF(2^8). This is the core recode math (wire
/// spec §5 steps 2–3) and the consumer's combine step; it is fully
/// implemented and pure.
///
/// All held packets MUST share the same vector width and payload length
/// (one generation); returns `None` otherwise.
pub fn recode_combine(held: &[CodedPacket], coeffs: &[u8]) -> Option<CodedPacket> {
    if held.is_empty() || held.len() != coeffs.len() {
        return None;
    }
    let width = held[0].vector.len();
    let sym = held[0].payload.len();
    if held
        .iter()
        .any(|p| p.vector.len() != width || p.payload.len() != sym)
    {
        return None;
    }
    let mut vec = vec![0u8; width];
    let mut payload = vec![0u8; sym];
    for (p, &c) in held.iter().zip(coeffs) {
        field::mul_add(&mut vec, &p.vector.0, c);
        field::mul_add(&mut payload, &p.payload, c);
    }
    Some(CodedPacket {
        vector: CodingVector(vec),
        payload: bytes::Bytes::from(payload),
    })
}

/// Online rank tracker over GF(2^8) for rank-aware CS/consumer admission
/// (doctrine §5, wire spec §7 step 3). Holds a reduced (RREF) basis of the
/// coding vectors seen so far; admits a packet only if it adds rank.
///
/// Pure linear algebra — no crypto — so it runs on every engine target.
#[derive(Debug, Default)]
pub struct RankBasis {
    /// Each entry is `(pivot_column, normalized_row)`.
    pivots: Vec<(usize, Vec<u8>)>,
}

impl RankBasis {
    pub fn new() -> Self {
        Self::default()
    }

    /// Current rank (independent vectors absorbed).
    pub fn rank(&self) -> usize {
        self.pivots.len()
    }

    /// Reduce `v` against the current basis without mutating state, and
    /// report whether it would add rank (i.e. is *innovative*).
    pub fn is_innovative(&self, v: &CodingVector) -> bool {
        let mut row = v.0.clone();
        self.reduce(&mut row);
        row.iter().any(|&b| b != 0)
    }

    /// Absorb `v`. Returns `true` if it added rank (was innovative), `false`
    /// if it was linearly dependent (caller drops it — duplicate-vector
    /// drop is the degenerate case).
    pub fn absorb(&mut self, v: &CodingVector) -> bool {
        let mut row = v.0.clone();
        self.reduce(&mut row);
        match row.iter().position(|&b| b != 0) {
            None => false,
            Some(p) => {
                let pinv = field::inv(row[p]);
                field::scale(&mut row, pinv); // normalize pivot to 1
                self.pivots.push((p, row));
                true
            }
        }
    }

    /// Eliminate `row` against existing pivots (GF char 2: subtract == add).
    fn reduce(&self, row: &mut [u8]) {
        for (col, pivot_row) in &self.pivots {
            let coeff = row[*col];
            if coeff != 0 {
                field::mul_add(row, pivot_row, coeff);
            }
        }
    }
}

/// The forwarder-side recoding seam — a pre-Dispatch hook the engine
/// installs only when `f2-recode` is compiled and `RecodePolicy` permits
/// (doctrine §5). Defined here; engine wiring is the implementation pass.
pub trait Recoder {
    /// Whether this node may recode the given generation, given its
    /// descriptor and this node's policy/keys (doctrine §3b for delegated).
    fn may_recode(&self, descriptor: &GenerationDescriptor) -> bool;

    /// Emit a fresh combination from the coded packets currently held for
    /// the generation, or `None` if fewer than two are held or policy
    /// forbids it. Implementations build coefficients and call
    /// [`recode_combine`].
    fn recode(
        &self,
        descriptor: &GenerationDescriptor,
        held: &[CodedPacket],
    ) -> Option<CodedPacket>;
}

/// F2 name conventions (wire spec §2, fork B). Provisional markers.
///
/// ```text
/// generation : <object>/_gen/<id>
/// descriptor : <object>/_gen/<id>/_desc
/// coded req  : <object>/_gen/<id>/_req/<j>
/// ```
pub mod naming {
    use super::CodingVector;
    use ndn_foundation_types::Name;

    /// Generation-scope marker component.
    pub const GEN_MARKER: &[u8] = b"_gen";
    /// Coded-request marker component (fresh random combination per `<j>`).
    pub const REQ_MARKER: &[u8] = b"_req";
    /// Descriptor leaf component.
    pub const DESC_MARKER: &[u8] = b"_desc";
    /// Named-combination marker (deterministic combination for an explicit
    /// coding vector — the recode-as-named-computation form, doctrine §8).
    pub const NC_MARKER: &[u8] = b"_nc";
    /// Consumer-challenge marker: `…/_chal/<r>` requests the fingerprint
    /// response for the consumer-chosen projection `r` (doctrine §6).
    pub const CHAL_MARKER: &[u8] = b"_chal";

    /// `<object>/_gen/<id>`.
    pub fn generation_name(object: &Name, generation_id: u64) -> Name {
        object
            .clone()
            .append(GEN_MARKER)
            .append(generation_id.to_string())
    }

    /// `<object>/_gen/<id>/_desc`.
    pub fn descriptor_name(object: &Name, generation_id: u64) -> Name {
        generation_name(object, generation_id).append(DESC_MARKER)
    }

    /// `<object>/_gen/<id>/_req/<j>`.
    pub fn request_name(object: &Name, generation_id: u64, req: u64) -> Name {
        generation_name(object, generation_id)
            .append(REQ_MARKER)
            .append(req.to_string())
    }

    fn decimal(bytes: &[u8]) -> Option<u64> {
        std::str::from_utf8(bytes).ok()?.parse().ok()
    }

    /// Parse a coded-request name back into `(object, generation_id, req)`.
    /// `None` if it is not a `…/_gen/<id>/_req/<j>` name.
    pub fn parse_request(name: &Name) -> Option<(Name, u64, u64)> {
        let c = name.components();
        let n = c.len();
        if n < 4 || c[n - 4].value.as_ref() != GEN_MARKER || c[n - 2].value.as_ref() != REQ_MARKER {
            return None;
        }
        let generation_id = decimal(&c[n - 3].value)?;
        let req = decimal(&c[n - 1].value)?;
        let object = Name::from_components(c[..n - 4].iter().cloned());
        Some((object, generation_id, req))
    }

    /// `<object>/_gen/<id>/_nc/<vector-bytes>` — a request for the *specific*
    /// deterministic linear combination given by `vector` (doctrine §8). The
    /// coding-vector bytes are the final name component, so the answer is a
    /// deterministic, cacheable function of the name.
    pub fn vector_request_name(object: &Name, generation_id: u64, vector: &CodingVector) -> Name {
        generation_name(object, generation_id)
            .append(NC_MARKER)
            .append(&vector.0)
    }

    /// Parse a `…/_gen/<id>/_nc/<vector>` name into `(object, gen, vector)`.
    pub fn parse_vector_request(name: &Name) -> Option<(Name, u64, CodingVector)> {
        let c = name.components();
        let n = c.len();
        if n < 4 || c[n - 4].value.as_ref() != GEN_MARKER || c[n - 2].value.as_ref() != NC_MARKER {
            return None;
        }
        let generation_id = decimal(&c[n - 3].value)?;
        let vector = CodingVector(c[n - 1].value.to_vec());
        let object = Name::from_components(c[..n - 4].iter().cloned());
        Some((object, generation_id, vector))
    }

    /// `<object>/_gen/<id>/_chal/<r>` — a consumer-challenge for projection `r`.
    pub fn challenge_name(object: &Name, generation_id: u64, r: &[u8]) -> Name {
        generation_name(object, generation_id)
            .append(CHAL_MARKER)
            .append(r)
    }

    /// Parse a `…/_gen/<id>/_chal/<r>` name into `(object, gen, r)`.
    pub fn parse_challenge(name: &Name) -> Option<(Name, u64, Vec<u8>)> {
        let c = name.components();
        let n = c.len();
        if n < 4 || c[n - 4].value.as_ref() != GEN_MARKER || c[n - 2].value.as_ref() != CHAL_MARKER
        {
            return None;
        }
        let generation_id = decimal(&c[n - 3].value)?;
        let r = c[n - 1].value.to_vec();
        let object = Name::from_components(c[..n - 4].iter().cloned());
        Some((object, generation_id, r))
    }
}

/// Per-packet metadata for a coded (`Role=2`) packet (wire spec §4). Rides
/// at the head of `Content`, like F1's `FecMetadata`, but carries an
/// explicit `CodingVector` instead of a systematic `Index`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodedMetadata {
    pub generation_id: u64,
    pub k: u16,
    pub field: Field,
    pub vector: CodingVector,
}

impl CodedMetadata {
    /// Encode the metadata TLV (without the trailing coded row bytes).
    pub fn to_tlv(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(TYPE_FEC_METADATA, |inner| {
            inner.write_tlv(TYPE_FEC_GENERATION, &encode_u64_be(self.generation_id));
            inner.write_tlv(TYPE_FEC_ROLE, &[ROLE_CODED]);
            inner.write_tlv(TYPE_FEC_FIELD, &[field_code(self.field)]);
            inner.write_tlv(TYPE_FEC_K, &self.k.to_be_bytes());
            inner.write_tlv(TYPE_CODING_VECTOR, &self.vector.0);
        });
        w.finish()
    }

    /// Prepend the metadata to `payload` to form a coded packet `Content`.
    pub fn prepend(&self, payload: &[u8]) -> Bytes {
        let head = self.to_tlv();
        let mut buf = bytes::BytesMut::with_capacity(head.len() + payload.len());
        buf.extend_from_slice(&head);
        buf.extend_from_slice(payload);
        buf.freeze()
    }

    /// Decode a coded packet `Content`: the `CodedMetadata` head and the
    /// coded row bytes that follow. Errors if `Role != coded`.
    pub fn split(content: &[u8]) -> Result<(Self, Bytes)> {
        let mut r = TlvReader::new(Bytes::copy_from_slice(content));
        let (typ, value) = r.read_tlv().map_err(|_| CodingError::MalformedMetadata)?;
        if typ != TYPE_FEC_METADATA {
            return Err(CodingError::MalformedMetadata);
        }
        let end = r.position();
        let mut inner = TlvReader::new(value);
        let (mut gen_id, mut role, mut field, mut k, mut vec) = (None, None, None, None, None);
        while !inner.is_empty() {
            let (t, v) = inner
                .read_tlv()
                .map_err(|_| CodingError::MalformedMetadata)?;
            match t {
                TYPE_FEC_GENERATION => gen_id = Some(decode_u64_be(&v)?),
                TYPE_FEC_ROLE => role = Some(one_byte(&v)?),
                TYPE_FEC_FIELD => field = Some(field_from_code(one_byte(&v)?)?),
                TYPE_FEC_K => k = Some(decode_u16_be(&v)?),
                TYPE_CODING_VECTOR => vec = Some(CodingVector(v.to_vec())),
                _ => {}
            }
        }
        if role != Some(ROLE_CODED) {
            return Err(CodingError::MalformedMetadata);
        }
        let meta = CodedMetadata {
            generation_id: gen_id.ok_or(CodingError::MalformedMetadata)?,
            k: k.ok_or(CodingError::MalformedMetadata)?,
            field: field.ok_or(CodingError::MalformedMetadata)?,
            vector: vec.ok_or(CodingError::MalformedMetadata)?,
        };
        Ok((meta, Bytes::copy_from_slice(&content[end..])))
    }
}

/// Error from absorbing/decoding a generation against its descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// A coded packet disagreed with the descriptor (`generation_id`, `K`,
    /// `field`, or vector width).
    Mismatch,
    /// Decode produced source rows that fail the descriptor's
    /// `SourceCommitment` — pollution. The recovered content is discarded.
    CommitmentFailed,
    /// Not enough rank to decode yet (fewer than K independent packets).
    Incomplete,
    /// A coded packet failed the in-flight linear-fingerprint check
    /// (doctrine §6) — dropped before it could waste decode work.
    FingerprintFailed,
    /// The per-generation absorb budget was exceeded — a DoS guard against a
    /// flood of (possibly dependent/polluted) coded packets.
    BudgetExceeded,
    /// The generation is quarantined: too many rejected packets were seen, so
    /// further packets for it are refused (doctrine §6 pollution accounting).
    Quarantined,
}

/// Accumulates coded packets of **one** generation, gated by its descriptor,
/// and decodes with verify-on-decode (doctrine §3a, wire spec §7). Used by a
/// consumer to recover content and by a recoder to mint fresh combinations.
///
/// Intra-flow by construction: every absorbed packet is checked against the
/// single descriptor; cross-generation packets are rejected, not mixed.
pub struct GenerationBuffer {
    descriptor: GenerationDescriptor,
    basis: RankBasis,
    /// Innovative packets retained in arrival order (for recoding/decoding).
    packets: Vec<CodedPacket>,
    symbol_size: usize,
    fingerprint: Option<LinearFingerprint>,
    // pollution-resilience accounting (doctrine §6)
    /// Max absorb attempts before refusing (0 = unlimited). DoS guard.
    budget: usize,
    /// Rejected-packet count before quarantining the generation (0 = never).
    quarantine_threshold: usize,
    attempts: usize,
    rejected: usize,
    quarantined: bool,
    /// Decoded source rows, computed once at full rank and reused by
    /// `recode_exact`/`decode` (perf: avoids re-solving per call).
    sources: OnceLock<Vec<Vec<u8>>>,
}

impl GenerationBuffer {
    pub fn new(descriptor: GenerationDescriptor) -> Self {
        let symbol_size = descriptor.symbol_size as usize;
        let fingerprint = descriptor.fingerprint.clone();
        Self {
            descriptor,
            basis: RankBasis::new(),
            packets: Vec::new(),
            symbol_size,
            fingerprint,
            budget: 0,
            quarantine_threshold: 0,
            attempts: 0,
            rejected: 0,
            quarantined: false,
            sources: OnceLock::new(),
        }
    }

    /// The recovered K source rows, computed once at full rank and cached.
    /// Uses the systematic fast path (unit vectors → index, no GF work) when
    /// the held packets are systematic, else Gauss-Jordan. `None` until rank K.
    fn recovered_sources(&self) -> Option<&[Vec<u8>]> {
        let k = self.descriptor.k as usize;
        if self.basis.rank() < k {
            return None;
        }
        Some(self.sources.get_or_init(|| {
            systematic_sources(&self.packets, k, self.symbol_size)
                .or_else(|| solve_sources(&self.packets, k, self.symbol_size))
                .expect("rank == K decodes")
        }))
    }

    /// Set forwarder-local pollution limits (doctrine §6): `budget` caps total
    /// absorb attempts per generation (0 = unlimited); `quarantine_threshold`
    /// is the rejected-packet count after which the generation is refused
    /// (0 = never). Both are operator policy, not on the wire.
    pub fn with_limits(mut self, budget: usize, quarantine_threshold: usize) -> Self {
        self.budget = budget;
        self.quarantine_threshold = quarantine_threshold;
        self
    }

    /// Rejected-packet count (fingerprint/mismatch failures).
    pub fn rejected(&self) -> usize {
        self.rejected
    }

    /// Whether the generation has been quarantined.
    pub fn is_quarantined(&self) -> bool {
        self.quarantined
    }

    pub fn descriptor(&self) -> &GenerationDescriptor {
        &self.descriptor
    }

    /// Current decode rank.
    pub fn rank(&self) -> usize {
        self.basis.rank()
    }

    /// `true` once K independent packets are held (decodable).
    pub fn is_decodable(&self) -> bool {
        self.basis.rank() >= self.descriptor.k as usize
    }

    /// Number of innovative packets retained (== rank).
    pub fn held(&self) -> &[CodedPacket] {
        &self.packets
    }

    /// Absorb one coded packet. Validates it against the descriptor, then
    /// admits it **only if it adds rank** (rank-aware admission, doctrine §5).
    /// Returns `Ok(true)` if innovative and stored, `Ok(false)` if dependent
    /// (dropped), `Err(Mismatch)` if it does not belong to this generation.
    pub fn absorb(
        &mut self,
        meta: &CodedMetadata,
        payload: Bytes,
    ) -> std::result::Result<bool, DecodeError> {
        if self.quarantined {
            return Err(DecodeError::Quarantined);
        }
        if self.budget != 0 && self.attempts >= self.budget {
            return Err(DecodeError::BudgetExceeded);
        }
        self.attempts += 1;

        if meta.generation_id != self.descriptor.generation_id
            || meta.k != self.descriptor.k
            || meta.field != self.descriptor.field
            || meta.vector.len() != self.descriptor.k as usize
            || payload.len() != self.symbol_size
        {
            return Err(DecodeError::Mismatch);
        }
        // In-flight pollution filter (doctrine §6): drop a packet that fails
        // the homomorphic fingerprint before it can pollute the basis. Skipped
        // for a delayed-seed fingerprint (the seed is secret in flight — it is
        // checked retroactively via `verify_with_revealed_seed`).
        if let Some(fp) = &self.fingerprint
            && !fp.is_delayed_unrevealed()
            && !fp.check(&meta.vector, &payload)
        {
            self.note_rejection();
            return Err(DecodeError::FingerprintFailed);
        }
        if !self.basis.absorb(&meta.vector) {
            return Ok(false); // linearly dependent — no new rank
        }
        self.packets.push(CodedPacket {
            vector: meta.vector.clone(),
            payload,
        });
        Ok(true)
    }

    fn note_rejection(&mut self) {
        self.rejected += 1;
        if self.quarantine_threshold != 0 && self.rejected >= self.quarantine_threshold {
            self.quarantined = true;
        }
    }

    /// Mint a fresh random linear combination of the held packets, for a
    /// recoder to emit (wire spec §5). `coeffs` has one byte per held packet.
    /// Returns `None` if fewer than two packets are held.
    pub fn recode(&self, coeffs: &[u8]) -> Option<CodedPacket> {
        if self.packets.len() < 2 {
            return None;
        }
        recode_combine(&self.packets, coeffs)
    }

    /// Produce the **deterministic** combination whose coding vector over the
    /// sources is exactly `target` (recode-as-named-computation, doctrine §8).
    /// Requires full rank (the buffer must be able to recover the sources);
    /// returns `None` otherwise or on a width mismatch. The result is a pure
    /// function of `(generation, target)`, hence cacheable by name.
    pub fn recode_exact(&self, target: &CodingVector) -> Option<CodedPacket> {
        if target.len() != self.descriptor.k as usize {
            return None;
        }
        let sources = self.recovered_sources()?;
        let mut payload = vec![0u8; self.symbol_size];
        for (s, row) in sources.iter().enumerate() {
            field::mul_add(&mut payload, row, target.0[s]);
        }
        Some(CodedPacket {
            vector: target.clone(),
            payload: Bytes::from(payload),
        })
    }

    /// Answer a consumer's fingerprint **challenge** (doctrine §6,
    /// adaptive-resistant): given the consumer-chosen projection `r`, return
    /// `LinearFingerprint::for_sources(r, …)`. Only a holder whose recovered
    /// sources **verify against the descriptor commitment** answers (so the
    /// response is sound); `None` otherwise. The caller signs the response.
    pub fn answer_challenge(&self, r: &[u8]) -> Option<LinearFingerprint> {
        let sources = self.recovered_sources()?;
        if !verify_sources(sources, &self.descriptor.source_commitment) {
            return None;
        }
        Some(LinearFingerprint::for_sources(r.to_vec(), sources))
    }

    /// Consumer side: verify every held packet against a (signed) challenge
    /// response `fp`. Because the consumer chose `r` *after* packets were in
    /// flight, an attacker could not have crafted pollution to pass.
    pub fn verify_against_challenge(
        &self,
        fp: &LinearFingerprint,
    ) -> std::result::Result<(), DecodeError> {
        for p in &self.packets {
            if !fp.check(&p.vector, &p.payload) {
                return Err(DecodeError::FingerprintFailed);
            }
        }
        Ok(())
    }

    /// Retroactively verify all held packets against a now-revealed delayed
    /// fingerprint seed (doctrine §6, adaptive-resistant). Checks
    /// `SHA-256(r)` against the committed `seed_hash`, then every held packet's
    /// homomorphic fingerprint. `Err(FingerprintFailed)` on a seed mismatch or
    /// any polluted packet (an attacker who committed before the reveal cannot
    /// have passed); `Ok(())` if all pass or there is no delayed fingerprint.
    pub fn verify_with_revealed_seed(&self, r: &[u8]) -> std::result::Result<(), DecodeError> {
        let Some(fp) = &self.fingerprint else {
            return Ok(());
        };
        if fp.seed_hash.is_none() {
            return Ok(()); // immediate fingerprint: already filtered in-flight
        }
        let revealed = fp.reveal(r).ok_or(DecodeError::FingerprintFailed)?;
        for p in &self.packets {
            if !revealed.check(&p.vector, &p.payload) {
                return Err(DecodeError::FingerprintFailed);
            }
        }
        Ok(())
    }

    /// Decode the K source rows and verify them against the descriptor's
    /// `SourceCommitment` (verify-on-decode). On success returns the
    /// recovered payload (sources concatenated). On a commitment mismatch
    /// returns `CommitmentFailed` and the content is discarded as pollution.
    pub fn decode(&self) -> std::result::Result<Bytes, DecodeError> {
        let k = self.descriptor.k as usize;
        let sources = self.recovered_sources().ok_or(DecodeError::Incomplete)?;
        if !verify_sources(sources, &self.descriptor.source_commitment) {
            return Err(DecodeError::CommitmentFailed);
        }
        let mut out = bytes::BytesMut::with_capacity(k * self.symbol_size);
        for row in sources {
            out.extend_from_slice(row);
        }
        Ok(out.freeze())
    }
}

/// Binary Merkle root over per-row SHA-256 leaves (duplicate-last padding).
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let mut h = Sha256::new();
            h.update(pair[0]);
            h.update(if pair.len() == 2 { pair[1] } else { pair[0] });
            next.push(h.finalize().into());
        }
        level = next;
    }
    level[0]
}

/// SHA-256 of one row — the per-row commitment leaf (wire spec §3.1).
pub fn row_hash(row: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(row);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vec_of(bytes: &[u8]) -> CodingVector {
        CodingVector(bytes.to_vec())
    }

    #[test]
    fn recode_policy_roundtrips_wire_bytes() {
        for p in [
            RecodePolicy::None,
            RecodePolicy::Open,
            RecodePolicy::Delegated,
            RecodePolicy::LocalDomain,
            RecodePolicy::TokenRequired,
        ] {
            assert_eq!(RecodePolicy::from_u8(p.as_u8()), Some(p));
        }
        assert_eq!(RecodePolicy::from_u8(5), None);
    }

    #[test]
    fn delegated_descriptor_must_name_recoders() {
        let mut d = GenerationDescriptor {
            generation_id: 1,
            k: 2,
            symbol_size: 4,
            field: Field::Gf8,
            content_name: "/alice/clip".parse().unwrap(),
            source_commitment: SourceCommitment::RowHashes(vec![[0u8; 32], [1u8; 32]]),
            recode: RecodePolicy::Delegated,
            delegation: None,
            fingerprint: None,
        };
        assert!(
            !d.is_well_formed(),
            "delegated without namespace is ill-formed"
        );
        d.delegation = Some("/site-a/recoders".parse().unwrap());
        assert!(d.is_well_formed());
    }

    #[test]
    fn rank_basis_drops_dependent_vectors() {
        let mut basis = RankBasis::new();
        assert!(basis.absorb(&vec_of(&[1, 0, 0])));
        assert!(basis.absorb(&vec_of(&[0, 1, 0])));
        assert_eq!(basis.rank(), 2);

        // A linear combination of the two — not innovative.
        let dependent = vec_of(&[3, 5, 0]);
        assert!(!basis.is_innovative(&dependent));
        assert!(!basis.absorb(&dependent));
        assert_eq!(basis.rank(), 2);

        // A vector with a component in the third dimension — innovative.
        assert!(basis.is_innovative(&vec_of(&[7, 9, 2])));
        assert!(basis.absorb(&vec_of(&[7, 9, 2])));
        assert_eq!(basis.rank(), 3);
    }

    #[test]
    fn recode_combine_is_linear() {
        // Two systematic rows; recombine and check the vector tracks.
        let held = vec![
            CodedPacket {
                vector: CodingVector::unit(2, 0),
                payload: bytes::Bytes::from_static(&[10, 20]),
            },
            CodedPacket {
                vector: CodingVector::unit(2, 1),
                payload: bytes::Bytes::from_static(&[30, 40]),
            },
        ];
        let combined = recode_combine(&held, &[2, 3]).unwrap();
        // vector = 2*[1,0] + 3*[0,1] = [2,3]
        assert_eq!(combined.vector.0, vec![2, 3]);
        // payload[0] = 2·10 ⊕ 3·30  (GF(2^8))
        let expect0 = field::mul(2, 10) ^ field::mul(3, 30);
        assert_eq!(combined.payload[0], expect0);

        // mismatched lengths rejected
        assert!(recode_combine(&held, &[1]).is_none());
    }

    fn sample_descriptor(k: u16, sym: u32, commit: SourceCommitment) -> GenerationDescriptor {
        GenerationDescriptor {
            generation_id: 0x0102_0304,
            k,
            symbol_size: sym,
            field: Field::Gf8,
            content_name: "/alice/clip/v=3".parse().unwrap(),
            source_commitment: commit,
            recode: RecodePolicy::Open,
            delegation: None,
            fingerprint: None,
        }
    }

    #[test]
    fn descriptor_tlv_round_trips() {
        let commit = SourceCommitment::RowHashes(vec![row_hash(b"a"), row_hash(b"bb")]);
        let d = sample_descriptor(2, 8, commit);
        let wire = d.to_tlv();
        let back = GenerationDescriptor::from_tlv(&wire).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn descriptor_tlv_round_trips_delegated_merkle() {
        let mut d = sample_descriptor(3, 16, SourceCommitment::MerkleRoot([7u8; 32]));
        d.recode = RecodePolicy::Delegated;
        d.delegation = Some("/site-a/recoders".parse().unwrap());
        let back = GenerationDescriptor::from_tlv(&d.to_tlv()).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn recode_token_round_trips_and_authorizes() {
        let t = RecodeToken {
            generation_id: 7,
            recoder: "/site-b/recoders".parse().unwrap(),
            signature: Bytes::from_static(&[1, 2, 3, 4]),
        };
        assert_eq!(RecodeToken::from_tlv(&t.to_tlv()).unwrap(), t);
        assert!(t.authorizes(&"/site-b/recoders/k1".parse().unwrap()));
        assert!(!t.authorizes(&"/evil/k".parse().unwrap()));
    }

    #[test]
    fn coded_metadata_round_trips() {
        let meta = CodedMetadata {
            generation_id: 42,
            k: 3,
            field: Field::Gf8,
            vector: CodingVector(vec![1, 2, 3]),
        };
        let content = meta.prepend(&[9, 8, 7, 6]);
        let (back, payload) = CodedMetadata::split(&content).unwrap();
        assert_eq!(back, meta);
        assert_eq!(payload.as_ref(), &[9, 8, 7, 6]);
    }

    /// Build K source rows, commit to them, absorb the K systematic packets,
    /// decode, and verify-on-decode succeeds and recovers the rows.
    #[test]
    fn buffer_decodes_and_verifies_sources() {
        let sources: Vec<Vec<u8>> = vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8], vec![9, 10, 11, 12]];
        let commit = SourceCommitment::RowHashes(sources.iter().map(|r| row_hash(r)).collect());
        let desc = sample_descriptor(3, 4, commit);
        let mut buf = GenerationBuffer::new(desc);
        for (i, row) in sources.iter().enumerate() {
            let meta = CodedMetadata {
                generation_id: 0x0102_0304,
                k: 3,
                field: Field::Gf8,
                vector: CodingVector::unit(3, i as u16),
            };
            assert!(buf.absorb(&meta, Bytes::from(row.clone())).unwrap());
        }
        assert!(buf.is_decodable());
        let recovered = buf.decode().unwrap();
        let expect: Vec<u8> = sources.concat();
        assert_eq!(recovered.as_ref(), expect.as_slice());
    }

    /// Recode the systematic packets into fresh combinations, absorb those
    /// into a second buffer, and confirm it still decodes + verifies — i.e.
    /// recoding preserves the descriptor's trust anchor (verify-on-decode).
    #[test]
    fn recoded_combinations_still_verify() {
        let sources: Vec<Vec<u8>> = vec![vec![10, 20], vec![30, 40], vec![50, 60]];
        let commit = SourceCommitment::RowHashes(sources.iter().map(|r| row_hash(r)).collect());
        let desc = sample_descriptor(3, 2, commit.clone());

        // First buffer holds the systematic packets.
        let mut src_buf = GenerationBuffer::new(desc);
        for (i, row) in sources.iter().enumerate() {
            let meta = CodedMetadata {
                generation_id: 0x0102_0304,
                k: 3,
                field: Field::Gf8,
                vector: CodingVector::unit(3, i as u16),
            };
            src_buf.absorb(&meta, Bytes::from(row.clone())).unwrap();
        }

        // Recoder mints 3 independent combinations with distinct coefficients.
        let desc2 = sample_descriptor(3, 2, commit);
        let mut dst_buf = GenerationBuffer::new(desc2);
        for coeffs in [[1u8, 1, 0], [0, 1, 1], [1, 1, 1]] {
            let combo = src_buf.recode(&coeffs).expect("recode");
            let meta = CodedMetadata {
                generation_id: 0x0102_0304,
                k: 3,
                field: Field::Gf8,
                vector: combo.vector.clone(),
            };
            dst_buf.absorb(&meta, combo.payload).unwrap();
        }
        assert!(dst_buf.is_decodable());
        let recovered = dst_buf.decode().unwrap();
        assert_eq!(recovered.as_ref(), sources.concat().as_slice());
    }

    /// A polluted combination decodes to wrong sources and is rejected by
    /// verify-on-decode (authenticity holds; pollution is caught at decode).
    #[test]
    fn pollution_fails_verify_on_decode() {
        let sources: Vec<Vec<u8>> = vec![vec![1, 1], vec![2, 2], vec![3, 3]];
        let commit = SourceCommitment::RowHashes(sources.iter().map(|r| row_hash(r)).collect());
        let desc = sample_descriptor(3, 2, commit);
        let mut buf = GenerationBuffer::new(desc);
        for (i, row) in sources.iter().enumerate() {
            let mut payload = row.clone();
            if i == 1 {
                payload[0] ^= 0xff; // corrupt one source row
            }
            let meta = CodedMetadata {
                generation_id: 0x0102_0304,
                k: 3,
                field: Field::Gf8,
                vector: CodingVector::unit(3, i as u16),
            };
            buf.absorb(&meta, Bytes::from(payload)).unwrap();
        }
        assert_eq!(buf.decode(), Err(DecodeError::CommitmentFailed));
    }

    #[test]
    fn fingerprint_filters_pollution_in_flight() {
        let sources: Vec<Vec<u8>> = vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8], vec![9, 10, 11, 12]];
        let fp = LinearFingerprint::for_sources(vec![7, 11, 13, 17], &sources);
        // A genuine systematic packet passes.
        assert!(fp.check(&CodingVector::unit(3, 1), &sources[1]));
        // A genuine linear combination passes (homomorphic).
        let combo = recode_combine(
            &sources
                .iter()
                .enumerate()
                .map(|(i, r)| CodedPacket {
                    vector: CodingVector::unit(3, i as u16),
                    payload: Bytes::from(r.clone()),
                })
                .collect::<Vec<_>>(),
            &[2, 3, 5],
        )
        .unwrap();
        assert!(fp.check(&combo.vector, &combo.payload));
        // A polluted payload (claims vector e1 but carries wrong bytes) fails.
        assert!(!fp.check(&CodingVector::unit(3, 1), &[0, 0, 0, 0]));
    }

    #[test]
    fn buffer_fingerprint_rejects_before_decode() {
        let sources: Vec<Vec<u8>> = vec![vec![1, 2], vec![3, 4], vec![5, 6]];
        let mut desc = sample_descriptor(
            3,
            2,
            SourceCommitment::RowHashes(sources.iter().map(|r| row_hash(r)).collect()),
        );
        desc.fingerprint = Some(LinearFingerprint::for_sources(vec![9, 13], &sources));
        let mut buf = GenerationBuffer::new(desc);
        // Polluted packet (vector e0, wrong payload) is rejected in-flight.
        let bad = CodedMetadata {
            generation_id: 0x0102_0304,
            k: 3,
            field: Field::Gf8,
            vector: CodingVector::unit(3, 0),
        };
        assert_eq!(
            buf.absorb(&bad, Bytes::from_static(&[42, 42])),
            Err(DecodeError::FingerprintFailed)
        );
        assert_eq!(buf.rank(), 0, "polluted packet never entered the basis");
        // The genuine source-0 packet still absorbs.
        let good = CodedMetadata {
            generation_id: 0x0102_0304,
            k: 3,
            field: Field::Gf8,
            vector: CodingVector::unit(3, 0),
        };
        assert!(buf.absorb(&good, Bytes::from(sources[0].clone())).unwrap());
    }

    #[test]
    fn budget_and_quarantine_bound_pollution() {
        let sources: Vec<Vec<u8>> = vec![vec![1, 2], vec![3, 4], vec![5, 6]];
        let mut desc = sample_descriptor(
            3,
            2,
            SourceCommitment::RowHashes(sources.iter().map(|r| row_hash(r)).collect()),
        );
        desc.fingerprint = Some(LinearFingerprint::for_sources(vec![9, 13], &sources));
        // Quarantine after 2 rejections.
        let mut buf = GenerationBuffer::new(desc).with_limits(0, 2);
        let bad = CodedMetadata {
            generation_id: 0x0102_0304,
            k: 3,
            field: Field::Gf8,
            vector: CodingVector::unit(3, 0),
        };
        assert_eq!(
            buf.absorb(&bad, Bytes::from_static(&[0, 0])),
            Err(DecodeError::FingerprintFailed)
        );
        assert!(!buf.is_quarantined());
        assert_eq!(
            buf.absorb(&bad, Bytes::from_static(&[0, 0])),
            Err(DecodeError::FingerprintFailed)
        );
        assert!(
            buf.is_quarantined(),
            "quarantined after threshold rejections"
        );
        // Even a clean packet is now refused.
        assert_eq!(
            buf.absorb(&bad, Bytes::from(sources[0].clone())),
            Err(DecodeError::Quarantined)
        );

        // Budget caps total attempts.
        let desc2 = sample_descriptor(3, 2, SourceCommitment::MerkleRoot([0u8; 32]));
        let mut bbuf = GenerationBuffer::new(desc2).with_limits(1, 0);
        let m = CodedMetadata {
            generation_id: 0x0102_0304,
            k: 3,
            field: Field::Gf8,
            vector: CodingVector::unit(3, 0),
        };
        assert!(bbuf.absorb(&m, Bytes::from_static(&[1, 2])).is_ok());
        assert_eq!(
            bbuf.absorb(&m, Bytes::from_static(&[1, 2])),
            Err(DecodeError::BudgetExceeded)
        );
    }

    #[test]
    fn delayed_fingerprint_detects_pollution_after_reveal() {
        let sources: Vec<Vec<u8>> = vec![vec![1, 2], vec![3, 4], vec![5, 6]];
        let r = vec![9u8, 13];
        let fp = LinearFingerprint::delayed(&r, &sources);
        assert!(fp.is_delayed_unrevealed());
        assert!(fp.r.is_empty(), "seed withheld until reveal");
        assert!(fp.reveal(&r).is_some());
        assert!(
            fp.reveal(&[0, 0]).is_none(),
            "wrong seed rejected by commitment"
        );

        let mut desc = sample_descriptor(
            3,
            2,
            SourceCommitment::RowHashes(sources.iter().map(|r| row_hash(r)).collect()),
        );
        desc.fingerprint = Some(fp);
        assert_eq!(
            GenerationDescriptor::from_tlv(&desc.to_tlv()).unwrap(),
            desc
        );

        let meta = |i: u16| CodedMetadata {
            generation_id: 0x0102_0304,
            k: 3,
            field: Field::Gf8,
            vector: CodingVector::unit(3, i),
        };

        // Clean buffer: sources absorb (no in-flight filter — seed secret),
        // and verify retroactively once the seed is revealed.
        let mut good = GenerationBuffer::new(desc.clone());
        for (i, row) in sources.iter().enumerate() {
            assert!(
                good.absorb(&meta(i as u16), Bytes::from(row.clone()))
                    .unwrap()
            );
        }
        assert!(good.verify_with_revealed_seed(&r).is_ok());
        assert_eq!(
            good.verify_with_revealed_seed(&[0, 0]),
            Err(DecodeError::FingerprintFailed),
            "a wrong revealed seed fails the commitment"
        );

        // Polluted packet is admitted in flight (delayed → no filter) but
        // caught on reveal — which an attacker who committed first can't pass.
        let mut bad = GenerationBuffer::new(desc);
        assert!(bad.absorb(&meta(0), Bytes::from_static(&[42, 42])).unwrap());
        assert_eq!(
            bad.verify_with_revealed_seed(&r),
            Err(DecodeError::FingerprintFailed)
        );
    }

    #[test]
    fn recode_exact_is_deterministic_and_named() {
        let sources: Vec<Vec<u8>> = vec![vec![10, 20], vec![30, 40], vec![50, 60]];
        let commit = SourceCommitment::RowHashes(sources.iter().map(|r| row_hash(r)).collect());
        let desc = sample_descriptor(3, 2, commit);
        let mut buf = GenerationBuffer::new(desc);
        for (i, row) in sources.iter().enumerate() {
            let meta = CodedMetadata {
                generation_id: 0x0102_0304,
                k: 3,
                field: Field::Gf8,
                vector: CodingVector::unit(3, i as u16),
            };
            buf.absorb(&meta, Bytes::from(row.clone())).unwrap();
        }
        let target = CodingVector(vec![2, 3, 5]);
        let a = buf.recode_exact(&target).unwrap();
        let b = buf.recode_exact(&target).unwrap();
        assert_eq!(a.payload, b.payload, "named combination is deterministic");
        assert_eq!(a.vector, target);
        // payload == 2·src0 ⊕ 3·src1 ⊕ 5·src2 over GF(2^8)
        let mut expect = vec![0u8; 2];
        field::mul_add(&mut expect, &sources[0], 2);
        field::mul_add(&mut expect, &sources[1], 3);
        field::mul_add(&mut expect, &sources[2], 5);
        assert_eq!(a.payload.as_ref(), expect.as_slice());

        // The vector is carried in the name and round-trips.
        let object: Name = "/o".parse().unwrap();
        let name = naming::vector_request_name(&object, 0x0102_0304, &target);
        let (obj, gen_id, v) = naming::parse_vector_request(&name).unwrap();
        assert_eq!(obj, object);
        assert_eq!(gen_id, 0x0102_0304);
        assert_eq!(v, target);
        // a _req name is not a _nc name and vice versa
        assert!(naming::parse_vector_request(&naming::request_name(&object, 1, 0)).is_none());
        assert!(naming::parse_request(&name).is_none());
    }

    #[test]
    fn request_name_round_trips() {
        let object: Name = "/alice/clip/v=3".parse().unwrap();
        let name = naming::request_name(&object, 5, 3);
        let (obj, gen_id, req) = naming::parse_request(&name).unwrap();
        assert_eq!(obj, object);
        assert_eq!((gen_id, req), (5, 3));
        // a non-coded name is rejected
        assert!(naming::parse_request(&"/alice/clip/0".parse().unwrap()).is_none());
    }

    #[test]
    fn buffer_rejects_foreign_generation() {
        let desc = sample_descriptor(2, 2, SourceCommitment::MerkleRoot([0u8; 32]));
        let mut buf = GenerationBuffer::new(desc);
        let wrong = CodedMetadata {
            generation_id: 999, // not this generation
            k: 2,
            field: Field::Gf8,
            vector: CodingVector::unit(2, 0),
        };
        assert_eq!(
            buf.absorb(&wrong, Bytes::from_static(&[1, 2])),
            Err(DecodeError::Mismatch)
        );
    }
}
