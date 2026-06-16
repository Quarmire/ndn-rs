//! F2 native engine integration — the synthetic `RecoderFace` and
//! delegated-recoder signing/verify (feature `f2-recode-face`).
//!
//! Mirrors `ndn-compute`'s `ComputeFace`: a [`Transport`] the forwarder
//! routes coded-request Interests to (via a FIB entry on its `FaceId`).
//! When the node holds ≥2 coded packets of the requested generation and the
//! descriptor's [`RecodePolicy`] permits it, the face mints a fresh random
//! linear combination (wire spec §5) and injects it back as Data — without
//! touching any core engine code.
//!
//! Trust: under `RecodePolicy::open` the minted Data is `DigestSha256`
//! coded evidence verified at the consumer on decode (doctrine §3a). Under a
//! delegated policy the face signs with a recoder key; a verifier checks the
//! signer is authorized under the descriptor's delegation namespace
//! ([`verify_delegated_recoder`], doctrine §3b) — full cert-chain validation
//! to the trust anchor remains the engine validator's job.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use bytes::Bytes;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::warn;

use ndn_engine::ForwarderEngine;
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Interest, Name};
use ndn_security::{
    Ed25519Verifier, Signer, TrustSchema, ValidationResult, Validator, VerifyOutcome,
};
use ndn_transport::{FaceError, FaceId, FaceKind, FacePersistency, Transport};

use crate::recode::{
    CodedMetadata, CodingVector, GenerationBuffer, GenerationDescriptor, RecodePolicy, RecodeToken,
    naming,
};

/// Shared recoder state: the per-generation buffers, a runtime kill switch,
/// and a counter seeding coefficient choice.
pub struct RecoderState {
    /// Runtime kill switch (doctrine §5 operator control). When `false`, the
    /// face answers nothing and behaves as if no recoder were installed.
    enabled: AtomicBool,
    counter: AtomicU64,
    /// Buffers keyed by generation name (`<object>/_gen/<id>`).
    generations: Mutex<HashMap<Name, GenerationBuffer>>,
}

impl Default for RecoderState {
    fn default() -> Self {
        Self::new()
    }
}

impl RecoderState {
    pub fn new() -> Self {
        Self {
            enabled: AtomicBool::new(true),
            counter: AtomicU64::new(0x9E37_79B9),
            generations: Mutex::new(HashMap::new()),
        }
    }

    /// Enable/disable recoding at runtime (the kill switch).
    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Install an (empty) buffer for a generation under its descriptor.
    pub async fn install_generation(&self, descriptor: GenerationDescriptor) {
        let key = naming::generation_name(&descriptor.content_name, descriptor.generation_id);
        self.generations
            .lock()
            .await
            .insert(key, GenerationBuffer::new(descriptor));
    }

    /// Feed a coded packet this node received into the matching buffer
    /// (rank-aware; dependent packets are dropped). Returns `true` if it added
    /// rank. `object`/`generation_id` identify the generation.
    pub async fn feed(
        &self,
        object: &Name,
        generation_id: u64,
        meta: &CodedMetadata,
        payload: Bytes,
    ) -> bool {
        let key = naming::generation_name(object, generation_id);
        let mut gens = self.generations.lock().await;
        match gens.get_mut(&key) {
            Some(buf) => buf.absorb(meta, payload).unwrap_or(false),
            None => false,
        }
    }

    fn next_coeffs(&self, n: usize) -> Vec<u8> {
        let mut s = self
            .counter
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_mul(0x9E37_79B9_7F4A_7C15);
        (0..n)
            .map(|_| {
                s = s
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                let b = (s >> 33) as u8;
                if b == 0 { 1 } else { b } // coefficients must be non-zero
            })
            .collect()
    }

    /// Mint a coded Data answering `<object>/_gen/<id>/_req/<j>`, or `None`
    /// if disabled, the generation is unknown, fewer than two packets are
    /// held, or the policy forbids recoding.
    ///
    /// **Systematic-first (perf):** the first K requests (`req < K`) are served
    /// as the *systematic* source packets (unit coding vectors) — the recoder
    /// already holds them, so this is a copy with **no GF combine**, and a
    /// consumer that gets the K sources decodes by the unit-vector fast path
    /// (no Gauss-Jordan). Only requests beyond K mint random repair
    /// combinations. On a clean path this is the common case and erases most of
    /// the coding overhead.
    async fn mint(
        &self,
        object: &Name,
        generation_id: u64,
        req: u64,
        signer: Option<&Arc<dyn Signer>>,
    ) -> Option<Bytes> {
        if !self.is_enabled() {
            return None;
        }
        let key = naming::generation_name(object, generation_id);
        let gens = self.generations.lock().await;
        let buf = gens.get(&key)?;
        if matches!(buf.descriptor().recode, crate::recode::RecodePolicy::None) {
            return None; // policy gate
        }
        let k = buf.descriptor().k;
        let combo = if req < k as u64 {
            // Systematic source `req` — the exact unit-vector combination.
            buf.recode_exact(&CodingVector::unit(k, req as u16))?
        } else {
            let n = buf.held().len();
            if n < 2 {
                return None;
            }
            buf.recode(&self.next_coeffs(n))?
        };
        let meta = CodedMetadata {
            generation_id,
            k,
            field: buf.descriptor().field,
            vector: combo.vector,
        };
        let content = meta.prepend(&combo.payload);
        let name = naming::request_name(object, generation_id, req);
        Some(build_signed(name, content, signer))
    }

    /// Answer a `_nc/<vector>` request: the **deterministic** combination for
    /// an explicit coding vector (recode-as-named-computation, doctrine §8).
    /// Pure function of `(generation, vector)`, so the Data is cacheable by
    /// name. `None` if disabled, unknown, policy-forbidden, or not full rank.
    async fn mint_exact(
        &self,
        object: &Name,
        generation_id: u64,
        vector: CodingVector,
        signer: Option<&Arc<dyn Signer>>,
    ) -> Option<Bytes> {
        if !self.is_enabled() {
            return None;
        }
        let key = naming::generation_name(object, generation_id);
        let gens = self.generations.lock().await;
        let buf = gens.get(&key)?;
        if matches!(buf.descriptor().recode, RecodePolicy::None) {
            return None;
        }
        let combo = buf.recode_exact(&vector)?;
        let meta = CodedMetadata {
            generation_id,
            k: buf.descriptor().k,
            field: buf.descriptor().field,
            vector: combo.vector.clone(),
        };
        let content = meta.prepend(&combo.payload);
        let name = naming::vector_request_name(object, generation_id, &combo.vector);
        Some(build_signed(name, content, signer))
    }

    /// Answer a consumer fingerprint challenge `…/_chal/<r>` (doctrine §6):
    /// compute `LinearFingerprint::for_sources(r, …)` from descriptor-verified
    /// sources and return it (signed) as `Content`. `None` if the generation is
    /// unknown or its sources do not verify against the commitment.
    async fn mint_challenge(
        &self,
        object: &Name,
        generation_id: u64,
        r: Vec<u8>,
        signer: Option<&Arc<dyn Signer>>,
    ) -> Option<Bytes> {
        if !self.is_enabled() {
            return None;
        }
        let key = naming::generation_name(object, generation_id);
        let gens = self.generations.lock().await;
        let fp = gens.get(&key)?.answer_challenge(&r)?;
        let name = naming::challenge_name(object, generation_id, &r);
        Some(build_signed(name, fp.to_tlv(), signer))
    }
}

/// Build a coded Data: delegated-signed when a `signer` is present, else
/// `DigestSha256` coded evidence (verify-on-decode).
fn build_signed(name: Name, content: Bytes, signer: Option<&Arc<dyn Signer>>) -> Bytes {
    match signer {
        Some(s) => {
            DataBuilder::new(name, &content).sign_sync(s.sig_type(), Some(s.key_name()), |region| {
                s.sign_sync(region).expect("recoder sign")
            })
        }
        None => DataBuilder::new(name, &content).sign_digest_sha256(),
    }
}

/// Synthetic face that answers coded-request Interests by minting fresh
/// combinations from [`RecoderState`]. Wire FIB routes to its [`FaceId`].
pub struct RecoderFace {
    id: FaceId,
    state: Arc<RecoderState>,
    signer: Option<Arc<dyn Signer>>,
    tx: mpsc::Sender<Bytes>,
    rx: Mutex<mpsc::Receiver<Bytes>>,
}

impl RecoderFace {
    pub fn new(id: FaceId, state: Arc<RecoderState>, signer: Option<Arc<dyn Signer>>) -> Self {
        let (tx, rx) = mpsc::channel(64);
        Self {
            id,
            state,
            signer,
            tx,
            rx: Mutex::new(rx),
        }
    }
}

impl Transport for RecoderFace {
    fn id(&self) -> FaceId {
        self.id
    }

    fn kind(&self) -> FaceKind {
        FaceKind::Internal
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        self.rx.lock().await.recv().await.ok_or(FaceError::Closed)
    }

    async fn send_bytes(&self, pkt: Bytes) -> Result<(), FaceError> {
        let interest = match Interest::decode(pkt) {
            Ok(i) => i,
            Err(e) => {
                warn!("RecoderFace: failed to decode Interest: {e}");
                return Ok(());
            }
        };
        // `_req/<j>` → fresh random combination; `_nc/<vector>` → the exact
        // deterministic combination (recode-as-named-computation).
        let wire = if let Some((object, generation_id, req)) = naming::parse_request(&interest.name)
        {
            self.state
                .mint(&object, generation_id, req, self.signer.as_ref())
                .await
        } else if let Some((object, generation_id, vector)) =
            naming::parse_vector_request(&interest.name)
        {
            self.state
                .mint_exact(&object, generation_id, vector, self.signer.as_ref())
                .await
        } else if let Some((object, generation_id, r)) = naming::parse_challenge(&interest.name) {
            self.state
                .mint_challenge(&object, generation_id, r, self.signer.as_ref())
                .await
        } else {
            return Ok(()); // not a coded request
        };
        if let Some(wire) = wire
            && self.tx.send(wire).await.is_err()
        {
            warn!("RecoderFace: pipeline receiver dropped before Data could be injected");
        }
        Ok(())
    }
}

/// Handle returned by [`attach`]: the recoder's `FaceId` (register the
/// generation prefix to it in the FIB) and its shared state (seed buffers,
/// toggle the kill switch).
pub struct RecoderHandle {
    pub face_id: FaceId,
    pub state: Arc<RecoderState>,
    cancel: CancellationToken,
}

impl RecoderHandle {
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }
}

/// Attach a recoder to a running engine, allocating its synthetic
/// `Permanent` face. `signer` is `Some` for delegated in-flight signing,
/// `None` for `open` (verify-on-decode) recoding. The caller registers the
/// generation prefix to the returned `face_id` in the FIB and seeds the
/// buffers via [`RecoderState`].
pub fn attach(engine: &ForwarderEngine, signer: Option<Arc<dyn Signer>>) -> RecoderHandle {
    let cancel = CancellationToken::new();
    let face_id = engine.faces().alloc_id();
    let state = Arc::new(RecoderState::new());
    let face = RecoderFace::new(face_id, Arc::clone(&state), signer);
    engine.add_face_with_persistency(face, cancel.clone(), FacePersistency::Permanent);
    RecoderHandle {
        face_id,
        state,
        cancel,
    }
}

/// Verify a delegated-recoded coded Data (doctrine §3b): the signer named in
/// the KeyLocator must fall under the descriptor's delegation namespace
/// **and** the Ed25519 signature must be valid for `public_key`. Returns
/// `false` if the descriptor is not delegated, the key is out of namespace,
/// or the signature fails. Cert-chain validation to the trust anchor is the
/// engine validator's responsibility and is not duplicated here.
pub fn verify_delegated_recoder(
    data: &Data,
    descriptor: &GenerationDescriptor,
    public_key: &[u8],
) -> bool {
    let Some(deleg) = &descriptor.delegation else {
        return false; // not a delegated generation
    };
    let Some(key_name) = data.sig_info().and_then(|s| s.key_locator_name()) else {
        return false;
    };
    if !key_name.has_prefix(deleg) {
        return false; // signer not in the authorized recoder namespace
    }
    matches!(
        Ed25519Verifier.verify_sync(data.signed_region(), data.sig_value(), public_key),
        VerifyOutcome::Valid
    )
}

/// Like [`verify_delegated_recoder`] but anchors authorization in a producer
/// [`TrustSchema`] rather than a raw namespace prefix: the schema must permit
/// the recoded Data's signer key to sign the Data's name (`schema.allows`),
/// then the Ed25519 signature must verify. The schema is the producer-rooted
/// authorization rule (e.g. `/<obj>/_gen/<id>/_req/<j> <= /<dom>/recoders/<k>`),
/// strictly more expressive than a prefix. Resolving and chain-verifying the
/// recoder's *certificate* to the trust anchor remains the engine validator's
/// job; this checks the schema authorization + signature, the parts specific
/// to recoded Data.
pub fn verify_delegated_recoder_schema(
    data: &Data,
    schema: &TrustSchema,
    public_key: &[u8],
) -> bool {
    let Some(key_name) = data.sig_info().and_then(|s| s.key_locator_name()) else {
        return false;
    };
    if !schema.allows(&data.name, &key_name) {
        return false; // schema does not authorize this signer for this name
    }
    matches!(
        Ed25519Verifier.verify_sync(data.signed_region(), data.sig_value(), public_key),
        VerifyOutcome::Valid
    )
}

/// Verify a delegated-recoded coded Data by **resolving its certificate chain
/// to a trust anchor** (doctrine §3b) — the strongest delegated check. The
/// recoded Data's signer key is resolved (KeyLocator → cert cache / fetcher),
/// its certificate chain is walked to a configured trust anchor, and the
/// producer `TrustSchema` is enforced, all by the engine's [`Validator`]
/// (`validate_chain`). The descriptor's `delegation` namespace is applied as a
/// cheap pre-check before the (async, possibly cert-fetching) validation.
///
/// This supersedes [`verify_delegated_recoder`] (namespace + a supplied public
/// key) and [`verify_delegated_recoder_schema`] (schema gate + one signature):
/// here the recoder's authority is anchored by a real certificate chain, with
/// no public key supplied out of band. Multi-hop chain walking itself is
/// covered by `ndn-security`'s validator tests; this wires recoded Data into
/// it.
pub async fn verify_delegated_recoder_chained(
    data: &Data,
    descriptor: &GenerationDescriptor,
    validator: &Validator,
) -> bool {
    if let Some(deleg) = &descriptor.delegation {
        let Some(key_name) = data.sig_info().and_then(|s| s.key_locator_name()) else {
            return false;
        };
        if !key_name.has_prefix(deleg) {
            return false; // signer outside the descriptor's recoder namespace
        }
    }
    matches!(
        validator.validate_chain(data).await,
        ValidationResult::Valid(_)
    )
}

/// Issue a producer-signed [`RecodeToken`] authorizing `recoder` (a key or
/// namespace) to recode `generation_id` under `RecodePolicy::token-required`
/// (wire spec §3.2). `producer` must be the generation's producer key.
pub fn issue_token(producer: &dyn Signer, generation_id: u64, recoder: Name) -> RecodeToken {
    let signature = producer
        .sign_sync(&RecodeToken::signed_bytes(generation_id, &recoder))
        .expect("token signing is CPU-only");
    RecodeToken {
        generation_id,
        recoder,
        signature,
    }
}

/// Verify a token-authorized recoded coded Data: the descriptor must be
/// `token-required`; the token must name this generation and carry a valid
/// producer signature; the recoded Data's signer must fall under the token's
/// recoder namespace; and the recoder's own signature must verify. Two keys:
/// `producer_public_key` authenticates the token, `recoder_public_key` the
/// Data. (Ed25519 in v1; both verified with ordinary signatures.)
pub fn verify_token_recoder(
    data: &Data,
    descriptor: &GenerationDescriptor,
    token: &RecodeToken,
    producer_public_key: &[u8],
    recoder_public_key: &[u8],
) -> bool {
    if !matches!(descriptor.recode, RecodePolicy::TokenRequired) {
        return false;
    }
    if token.generation_id != descriptor.generation_id {
        return false;
    }
    // 1. producer authorized this token
    if !matches!(
        Ed25519Verifier.verify_sync(
            &RecodeToken::signed_bytes(token.generation_id, &token.recoder),
            &token.signature,
            producer_public_key,
        ),
        VerifyOutcome::Valid
    ) {
        return false;
    }
    // 2. the Data's signer is the token's authorized recoder
    let Some(key_name) = data.sig_info().and_then(|s| s.key_locator_name()) else {
        return false;
    };
    if !token.authorizes(&key_name) {
        return false;
    }
    // 3. the recoder's signature over the Data is valid
    matches!(
        Ed25519Verifier.verify_sync(data.signed_region(), data.sig_value(), recoder_public_key),
        VerifyOutcome::Valid
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use ndn_security::Ed25519Signer;

    use crate::policy::Field;
    use crate::recode::{CodingVector, SourceCommitment, row_hash};

    fn descriptor(
        object: &Name,
        recode: crate::recode::RecodePolicy,
        deleg: Option<Name>,
    ) -> (GenerationDescriptor, Vec<Vec<u8>>) {
        let sources = vec![vec![1u8, 2], vec![3, 4], vec![5, 6]];
        let commit = SourceCommitment::RowHashes(sources.iter().map(|r| row_hash(r)).collect());
        let d = GenerationDescriptor {
            generation_id: 7,
            k: 3,
            symbol_size: 2,
            field: Field::Gf8,
            content_name: object.clone(),
            source_commitment: commit,
            recode,
            delegation: deleg,
            fingerprint: None,
        };
        (d, sources)
    }

    async fn seed(
        state: &RecoderState,
        object: &Name,
        desc: &GenerationDescriptor,
        sources: &[Vec<u8>],
    ) {
        state.install_generation(desc.clone()).await;
        for (i, row) in sources.iter().enumerate() {
            let meta = CodedMetadata {
                generation_id: desc.generation_id,
                k: desc.k,
                field: Field::Gf8,
                vector: CodingVector::unit(desc.k, i as u16),
            };
            assert!(
                state
                    .feed(object, desc.generation_id, &meta, Bytes::from(row.clone()))
                    .await
            );
        }
    }

    #[tokio::test]
    async fn mint_open_is_decodable_evidence() {
        let object: Name = "/alice/clip".parse().unwrap();
        let (desc, sources) = descriptor(&object, crate::recode::RecodePolicy::Open, None);
        let state = RecoderState::new();
        seed(&state, &object, &desc, &sources).await;

        // Mint K independent combinations into a consumer buffer; decode.
        let mut consumer = GenerationBuffer::new(desc.clone());
        let mut req = 0u64;
        while !consumer.is_decodable() && req < 20 {
            if let Some(wire) = state.mint(&object, desc.generation_id, req, None).await {
                let data = Data::decode(wire).unwrap();
                let (meta, payload) = CodedMetadata::split(data.content().unwrap()).unwrap();
                consumer.absorb(&meta, payload).ok();
            }
            req += 1;
        }
        assert!(consumer.is_decodable());
        assert_eq!(
            consumer.decode().unwrap().as_ref(),
            sources.concat().as_slice()
        );
    }

    #[tokio::test]
    async fn consumer_challenge_detects_pollution() {
        use crate::recode::{GenerationBuffer, LinearFingerprint};

        let object: Name = "/alice/clip".parse().unwrap();
        let (desc, sources) = descriptor(&object, crate::recode::RecodePolicy::Open, None);
        let state = RecoderState::new();
        seed(&state, &object, &desc, &sources).await;

        // Consumer picks a fresh random projection r (length = symbol size = 2)
        // and asks the recoder (which holds descriptor-verified sources).
        let r = vec![7u8, 11];
        let wire = state
            .mint_challenge(&object, desc.generation_id, r.clone(), None)
            .await
            .expect("challenge answered");
        let data = Data::decode(wire).unwrap();
        let fp = LinearFingerprint::from_tlv(data.content().unwrap()).unwrap();
        assert_eq!(fp.r, r, "response is the fingerprint for the consumer's r");

        let (gen_id, k) = (desc.generation_id, desc.k);
        let meta = |i: u16| CodedMetadata {
            generation_id: gen_id,
            k,
            field: Field::Gf8,
            vector: CodingVector::unit(k, i),
        };

        // A consumer holding the genuine sources passes the challenge.
        let mut good = GenerationBuffer::new(desc.clone());
        for (i, row) in sources.iter().enumerate() {
            good.absorb(&meta(i as u16), Bytes::from(row.clone()))
                .unwrap();
        }
        assert!(good.verify_against_challenge(&fp).is_ok());

        // A consumer holding a polluted packet (chosen before r was known)
        // fails — the fresh challenge catches it.
        let mut bad = GenerationBuffer::new(desc);
        bad.absorb(&meta(0), Bytes::from_static(&[0xAA, 0xBB]))
            .unwrap();
        assert_eq!(
            bad.verify_against_challenge(&fp),
            Err(crate::recode::DecodeError::FingerprintFailed)
        );
    }

    #[tokio::test]
    async fn systematic_first_serves_sources_then_repair() {
        let object: Name = "/alice/clip".parse().unwrap();
        let (desc, sources) = descriptor(&object, crate::recode::RecodePolicy::Open, None);
        let k = desc.k;
        let state = RecoderState::new();
        seed(&state, &object, &desc, &sources).await;

        // The first K requests are the systematic sources (unit vectors) — no
        // GF combine to serve, no Gauss-Jordan to decode.
        for i in 0..k as u64 {
            let wire = state
                .mint(&object, desc.generation_id, i, None)
                .await
                .unwrap();
            let data = Data::decode(wire).unwrap();
            let (meta, _) = CodedMetadata::split(data.content().unwrap()).unwrap();
            assert_eq!(
                meta.vector,
                CodingVector::unit(k, i as u16),
                "req {i} (< K) is served as systematic source {i}"
            );
        }
        // Requests beyond K are repair combinations (still serve fine).
        let wire = state
            .mint(&object, desc.generation_id, k as u64, None)
            .await
            .unwrap();
        let data = Data::decode(wire).unwrap();
        let (meta, _) = CodedMetadata::split(data.content().unwrap()).unwrap();
        assert_eq!(meta.vector.len(), k as usize);
    }

    #[tokio::test]
    async fn kill_switch_and_policy_gate_stop_minting() {
        let object: Name = "/alice/clip".parse().unwrap();

        // policy = none → never mints
        let (desc_none, sources) = descriptor(&object, crate::recode::RecodePolicy::None, None);
        let state = RecoderState::new();
        seed(&state, &object, &desc_none, &sources).await;
        assert!(
            state.mint(&object, 7, 0, None).await.is_none(),
            "policy=none must not mint"
        );

        // policy = open but kill switch off → never mints
        let (desc_open, sources2) = descriptor(&object, crate::recode::RecodePolicy::Open, None);
        let state2 = RecoderState::new();
        seed(&state2, &object, &desc_open, &sources2).await;
        assert!(
            state2.mint(&object, 7, 0, None).await.is_some(),
            "enabled+open mints"
        );
        state2.set_enabled(false);
        assert!(
            state2.mint(&object, 7, 1, None).await.is_none(),
            "kill switch stops minting"
        );
    }

    #[tokio::test]
    async fn delegated_signing_authorizes_by_namespace() {
        let object: Name = "/alice/clip".parse().unwrap();
        let deleg: Name = "/site-a/recoders".parse().unwrap();
        let (desc, sources) = descriptor(
            &object,
            crate::recode::RecodePolicy::Delegated,
            Some(deleg.clone()),
        );

        // Authorized recoder key under the delegation namespace.
        let key_name: Name = "/site-a/recoders/k1".parse().unwrap();
        let signer = Ed25519Signer::from_seed(&[42u8; 32], key_name);
        let pk = signer.public_key_bytes();
        let signer: Arc<dyn Signer> = Arc::new(signer);

        let state = RecoderState::new();
        seed(&state, &object, &desc, &sources).await;
        let wire = state
            .mint(&object, 7, 0, Some(&signer))
            .await
            .expect("mint signed");
        let data = Data::decode(wire).unwrap();
        assert!(
            verify_delegated_recoder(&data, &desc, &pk),
            "authorized + valid sig accepted"
        );

        // Out-of-namespace key → rejected on authorization even with a valid sig.
        let mut bad_desc = desc.clone();
        bad_desc.delegation = Some("/other/recoders".parse().unwrap());
        assert!(
            !verify_delegated_recoder(&data, &bad_desc, &pk),
            "out-of-namespace rejected"
        );

        // Tampered public key → crypto fails.
        assert!(
            !verify_delegated_recoder(&data, &desc, &[0u8; 32]),
            "bad key rejected"
        );
    }

    #[tokio::test]
    async fn schema_authorizes_delegated_recoder() {
        use ndn_security::{SchemaRule, TrustSchema};

        let object: Name = "/alice/clip".parse().unwrap();
        let deleg: Name = "/site-a/recoders".parse().unwrap();
        let (desc, sources) = descriptor(&object, RecodePolicy::Delegated, Some(deleg));
        let recoder = Ed25519Signer::from_seed(&[5u8; 32], "/site-a/recoders/k1".parse().unwrap());
        let pk = recoder.public_key_bytes();
        let recoder: Arc<dyn Signer> = Arc::new(recoder);

        let state = RecoderState::new();
        seed(&state, &object, &desc, &sources).await;
        let wire = state
            .mint(&object, desc.generation_id, 0, Some(&recoder))
            .await
            .expect("mint signed");
        let data = Data::decode(wire).unwrap();

        // Producer schema: a /site-a/recoders/<k> key may sign coded requests.
        let mut schema = TrustSchema::new();
        schema.add_rule(
            SchemaRule::parse("/alice/clip/_gen/<id>/_req/<j> => /site-a/recoders/<k>").unwrap(),
        );
        assert!(verify_delegated_recoder_schema(&data, &schema, &pk));

        // A schema authorizing a different namespace does not permit this signer.
        let mut other = TrustSchema::new();
        other.add_rule(
            SchemaRule::parse("/alice/clip/_gen/<id>/_req/<j> => /other/recoders/<k>").unwrap(),
        );
        assert!(!verify_delegated_recoder_schema(&data, &other, &pk));
    }

    #[tokio::test]
    async fn chained_verify_resolves_cert_to_anchor() {
        use ndn_security::{Certificate, TrustSchema, ValidationResult, Validator};
        use std::sync::Arc as StdArc;

        let object: Name = "/alice/clip".parse().unwrap();
        let deleg: Name = "/site-a/recoders".parse().unwrap();
        let (desc, sources) = descriptor(&object, RecodePolicy::Delegated, Some(deleg));

        // Producer/anchor key, and a recoder key whose cert the anchor signs.
        let anchor_name: Name = "/alice/KEY/anchor".parse().unwrap();
        let anchor = Ed25519Signer::from_seed(&[1u8; 32], anchor_name.clone());
        let anchor_pk = anchor.public_key_bytes();
        let key_name: Name = "/site-a/recoders/k1/KEY/1".parse().unwrap();
        let recoder = Ed25519Signer::from_seed(&[2u8; 32], key_name.clone());
        let recoder_pk = recoder.public_key_bytes();

        // Recoder certificate (Data named by the key, content = pubkey) signed
        // by the anchor — the intermediate the chain walks through.
        let cert_wire = DataBuilder::new(key_name.clone(), &recoder_pk).sign_sync(
            ndn_packet::SignatureType::SignatureEd25519,
            Some(&anchor_name),
            |region| anchor.sign_sync(region).expect("anchor signs cert"),
        );
        let cert = Certificate::decode(&Data::decode(cert_wire).unwrap()).unwrap();

        // The recoder mints a coded Data signed by its key.
        let recoder_arc: Arc<dyn Signer> = Arc::new(recoder);
        let state = RecoderState::new();
        seed(&state, &object, &desc, &sources).await;
        let wire = state
            .mint(&object, desc.generation_id, 0, Some(&recoder_arc))
            .await
            .unwrap();
        let data = Data::decode(wire).unwrap();

        // Validator: anchor trusted, recoder cert in cache → chain resolves.
        let validator = Validator::new(TrustSchema::accept_all());
        validator.add_trust_anchor(Certificate {
            name: StdArc::new(anchor_name),
            public_key: Bytes::copy_from_slice(&anchor_pk),
            valid_from: 0,
            valid_until: u64::MAX,
            issuer: None,
            signed_region: None,
            sig_value: None,
            sig_type: ndn_packet::SignatureType::SignatureEd25519,
        });
        validator.cert_cache().insert(cert);
        assert!(
            matches!(
                validator.validate_chain(&data).await,
                ValidationResult::Valid(_)
            ),
            "sanity: chain resolves"
        );
        assert!(verify_delegated_recoder_chained(&data, &desc, &validator).await);

        // Descriptor delegation mismatch → rejected before validation.
        let mut bad = desc.clone();
        bad.delegation = Some("/other/recoders".parse().unwrap());
        assert!(!verify_delegated_recoder_chained(&data, &bad, &validator).await);

        // No anchor / cert → chain unresolved → rejected.
        let empty = Validator::new(TrustSchema::accept_all());
        assert!(!verify_delegated_recoder_chained(&data, &desc, &empty).await);
    }

    #[tokio::test]
    async fn token_required_capability_authorizes() {
        let object: Name = "/alice/clip".parse().unwrap();
        let (desc, sources) = descriptor(&object, RecodePolicy::TokenRequired, None);

        // Producer key (issues tokens) and a recoder key under /site-b/recoders.
        let producer = Ed25519Signer::from_seed(&[1u8; 32], "/alice/KEY/p".parse().unwrap());
        let producer_pk = producer.public_key_bytes();
        let recoder = Ed25519Signer::from_seed(&[2u8; 32], "/site-b/recoders/k1".parse().unwrap());
        let recoder_pk = recoder.public_key_bytes();
        let recoder: Arc<dyn Signer> = Arc::new(recoder);

        // Producer issues a token for the recoder namespace; recoder mints+signs.
        let token = issue_token(
            &producer,
            desc.generation_id,
            "/site-b/recoders".parse().unwrap(),
        );
        let state = RecoderState::new();
        seed(&state, &object, &desc, &sources).await;
        let wire = state
            .mint(&object, desc.generation_id, 0, Some(&recoder))
            .await
            .expect("mint signed");
        let data = Data::decode(wire).unwrap();

        assert!(
            verify_token_recoder(&data, &desc, &token, &producer_pk, &recoder_pk),
            "valid token + recoder signature accepted"
        );

        // Token authorizing a different recoder namespace → rejected.
        let wrong = issue_token(
            &producer,
            desc.generation_id,
            "/other/recoders".parse().unwrap(),
        );
        assert!(!verify_token_recoder(
            &data,
            &desc,
            &wrong,
            &producer_pk,
            &recoder_pk
        ));

        // Forged token (not the producer's key) → producer-signature check fails.
        assert!(!verify_token_recoder(
            &data,
            &desc,
            &token,
            &[9u8; 32],
            &recoder_pk
        ));
    }
}
