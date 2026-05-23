use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashMap;
use tracing::trace;

use crate::observability::targets as t;
use crate::pipeline::{Action, DecodedPacket, DropReason, PacketContext};
use ndn_packet::ContentHashTarget;
use ndn_packet::fragment::ReassemblyBuffer;
use ndn_packet::lp::{LpPacket, extract_fragment, is_lp_packet};
use ndn_packet::wire::ensure_nonce;
use ndn_packet::{Data, Interest, Nack, Name, tlv_type};
use ndn_store::NameHashes;
use ndn_transport::{FaceId, FaceOptions, FaceScope, FaceTable};

fn is_localhost_name(name: &Name) -> bool {
    name.components()
        .first()
        .is_some_and(|c| c.value.as_ref() == b"localhost")
}

/// `/localhop` scope enforcement lives in the strategy stage (egress-time,
/// mirroring NFD `daemon/fw/algorithm.cpp::wouldViolateScope`); this helper
/// is unit-test only.
#[cfg(test)]
fn is_localhop_name(name: &Name) -> bool {
    name.components()
        .first()
        .is_some_and(|c| c.value.as_ref() == b"localhop")
}

#[derive(Clone, Copy, Debug)]
pub struct CongestionMark(pub u64);

#[derive(Clone, Copy, Debug)]
pub struct NextHopFaceId(pub u64);

#[derive(Clone, Copy, Debug)]
pub struct LpCachePolicy(pub ndn_packet::CachePolicyType);

/// NDNLPv2 `PrefixAnnouncement` (TLV 0x0350) surfaced into `ctx.tags` for
/// self-learning strategies (mirrors NFD `self-learning-strategy.cpp`
/// reading `data.getTag<lp::PrefixAnnouncementTag>()`).
#[derive(Clone, Debug)]
pub struct PrefixAnnouncement(pub Bytes);

/// Decodes raw bytes into Interest, Data, or Nack. Handles bare TLV and
/// NDNLPv2 LpPacket wrappers (LpPackets with a Nack header produce
/// `DecodedPacket::Nack`). Enforces `/localhost` scope at ingress.
pub struct TlvDecodeStage {
    pub face_table: Arc<FaceTable>,
    pub(crate) reassembly: DashMap<FaceId, ReassemblyBuffer>,
    /// Per-face ingress option overrides. Missing entries fall back to
    /// `FaceOptions::default_for_kind` (local computes, network skips).
    face_options: DashMap<FaceId, FaceOptions>,
}

impl TlvDecodeStage {
    pub fn new(face_table: Arc<FaceTable>) -> Self {
        Self {
            face_table,
            reassembly: DashMap::new(),
            face_options: DashMap::new(),
        }
    }

    /// Override the ingress options for `face_id`, taking precedence over
    /// the `FaceKind`-derived default. Call after registering the face if
    /// the default is wrong (e.g. a network face hosting an in-process app).
    pub fn set_face_options(&self, face_id: FaceId, opts: FaceOptions) {
        self.face_options.insert(face_id, opts);
    }

    fn content_hash_target(&self, face_id: FaceId) -> Option<ContentHashTarget> {
        if let Some(opts) = self.face_options.get(&face_id) {
            return opts.content_hash_target;
        }
        self.face_table
            .get(face_id)
            .and_then(|f| FaceOptions::default_for_kind(f.kind()).content_hash_target)
    }

    /// Fast-path fragment collection bypassing `PacketContext` creation.
    ///
    /// - `Ok(Some(bytes))` -- reassembly complete
    /// - `Ok(None)` -- fragment buffered, waiting for more
    /// - `Err(bytes)` -- not a fragment; process through full pipeline
    pub fn try_collect_fragment(
        &self,
        face_id: FaceId,
        raw: Bytes,
    ) -> Result<Option<Bytes>, Bytes> {
        let hdr = match extract_fragment(&raw) {
            Some(h) => h,
            None => return Err(raw),
        };
        let fragment = raw.slice(hdr.frag_start..hdr.frag_end);
        let base_seq = hdr.sequence - hdr.frag_index;
        let mut rb = self.reassembly.entry(face_id).or_default();
        // `0` is the unicast endpoint id; multi-access faces (UDP multicast /
        // Ethernet / BLE) need a per-source identifier here.
        Ok(rb.process(0, base_seq, hdr.frag_index, hdr.frag_count, fragment))
    }

    pub fn process(&self, mut ctx: PacketContext) -> Action {
        let first_byte = match ctx.raw_bytes.first() {
            Some(&b) => b as u64,
            None => {
                trace!(target: t::FWD_PIPELINE, face=%ctx.face_id, "decode: empty packet");
                return Action::Drop(DropReason::MalformedPacket);
            }
        };

        if is_lp_packet(&ctx.raw_bytes) {
            trace!(target: t::FACE_LP, face=%ctx.face_id, len=ctx.raw_bytes.len(), "decode: LpPacket");
            return self.process_lp(ctx);
        }

        match first_byte {
            t_ if t_ == tlv_type::INTEREST => self.decode_interest(ctx),
            t_ if t_ == tlv_type::DATA => match Data::decode(ctx.raw_bytes.clone()) {
                Ok(mut data) => {
                    trace!(target: t::FWD_PIPELINE, face=%ctx.face_id, name=%data.name, "decoded");
                    if data.name.len() > 3 {
                        ctx.name_hashes = Some(NameHashes::compute(&data.name));
                    }
                    ctx.name = Some(data.name.clone());
                    if let Some(target) = self.content_hash_target(ctx.face_id) {
                        data.populate_content_sha256_with(target);
                    }
                    ctx.packet = DecodedPacket::Data(Box::new(data));
                    if let Some(drop) = self.check_scope(&ctx) {
                        return drop;
                    }
                    Action::Continue(ctx)
                }
                Err(e) => {
                    trace!(target: t::FWD_PIPELINE, face=%ctx.face_id, error=%e, "decode: malformed Data");
                    Action::Drop(DropReason::MalformedPacket)
                }
            },
            _ => {
                trace!(target: t::FWD_PIPELINE, face=%ctx.face_id, tlv_type=first_byte, "decode: unknown TLV type");
                Action::Drop(DropReason::MalformedPacket)
            }
        }
    }

    fn decode_interest(&self, mut ctx: PacketContext) -> Action {
        match Interest::decode(ctx.raw_bytes.clone()) {
            Ok(interest) => {
                if interest.hop_limit() == Some(0) {
                    trace!(target: t::FWD_PIPELINE, face=%ctx.face_id, name=%interest.name, "decode: HopLimit=0, dropping");
                    return Action::Drop(DropReason::HopLimitExceeded);
                }
                let nonce = interest.nonce().unwrap_or(0);
                trace!(target: t::FWD_PIPELINE, face=%ctx.face_id, name=%interest.name, nonce, "decoded");
                ctx.raw_bytes = ensure_nonce(&ctx.raw_bytes);
                // Decrement HopLimit on the incoming pipeline (after the
                // zero-check). Re-decode so downstream stages see the new
                // value.
                if interest.hop_limit().is_some()
                    && let Some((new_wire, _new_hl)) =
                        ndn_packet::interest::decrement_hop_limit(&ctx.raw_bytes)
                {
                    ctx.raw_bytes = new_wire;
                }
                let Ok(interest) = Interest::decode(ctx.raw_bytes.clone()) else {
                    return Action::Drop(DropReason::MalformedPacket);
                };
                if interest.name.len() > 3 {
                    ctx.name_hashes = Some(NameHashes::compute(&interest.name));
                }
                ctx.name = Some(interest.name.clone());
                ctx.packet = DecodedPacket::Interest(Box::new(interest));
                if let Some(drop) = self.check_scope(&ctx) {
                    return drop;
                }
                Action::Continue(ctx)
            }
            Err(e) => {
                trace!(target: t::FWD_PIPELINE, face=%ctx.face_id, error=%e, "decode: malformed Interest");
                Action::Drop(DropReason::MalformedPacket)
            }
        }
    }

    fn check_scope(&self, ctx: &PacketContext) -> Option<Action> {
        let name = ctx.name.as_ref()?;
        let is_non_local = self
            .face_table
            .get(ctx.face_id)
            .is_some_and(|f| f.scope() == FaceScope::NonLocal);
        if !is_non_local {
            return None;
        }
        if is_localhost_name(name) {
            trace!(target: t::FWD_PIPELINE, face=%ctx.face_id, name=%name, "decode: /localhost on non-local face, dropping");
            return Some(Action::Drop(DropReason::ScopeViolation));
        }
        // /localhop on non-local faces is permitted at ingress so the
        // Interest can be consumed locally (e.g. `/localhop/nfd/rib/register`);
        // the egress restriction is enforced in the strategy stage.
        None
    }

    /// Process an NDNLPv2 LpPacket, buffering fragments per-face until
    /// reassembly completes. Incomplete reassemblies return
    /// `Action::Drop(FragmentCollect)`; complete packets re-enter `process`.
    fn process_lp(&self, mut ctx: PacketContext) -> Action {
        let lp = match LpPacket::decode(ctx.raw_bytes.clone()) {
            Ok(lp) => lp,
            Err(e) => {
                trace!(target: t::FACE_LP, face=%ctx.face_id, error=%e, "decode: malformed LpPacket");
                return Action::Drop(DropReason::MalformedPacket);
            }
        };

        if let Some(mark) = lp.congestion_mark {
            ctx.tags.insert(CongestionMark(mark));
        }
        if let Some(token) = lp.pit_token.clone() {
            ctx.lp_pit_token = Some(token);
        }
        if let Some(face_id) = lp.next_hop_face_id {
            ctx.tags.insert(NextHopFaceId(face_id));
        }
        if let Some(ref policy) = lp.cache_policy {
            ctx.tags.insert(LpCachePolicy(*policy));
        }
        if let Some(ref pa) = lp.prefix_announcement {
            ctx.tags.insert(PrefixAnnouncement(pa.clone()));
        }

        if lp.is_ack_only() {
            return Action::Drop(DropReason::FragmentCollect);
        }

        let is_fragmented = lp.is_fragmented();
        let sequence = lp.sequence;
        let frag_index = lp.frag_index;
        let frag_count = lp.frag_count;
        let nack = lp.nack;

        let fragment = match lp.fragment {
            Some(f) => f,
            None => return Action::Drop(DropReason::MalformedPacket),
        };

        if is_fragmented {
            let face_id = ctx.face_id;
            let complete = {
                let mut rb = self.reassembly.entry(face_id).or_default();
                let seq = sequence.unwrap_or(0);
                let idx = frag_index.unwrap_or(0);
                let base_seq = seq - idx;
                rb.process(0, base_seq, idx, frag_count.unwrap_or(1), fragment)
            };
            match complete {
                Some(packet) => {
                    trace!(target: t::FACE_LP, face=%ctx.face_id, len=packet.len(), "decode: reassembled");
                    ctx.raw_bytes = packet;
                    return self.process(ctx);
                }
                None => {
                    return Action::Drop(DropReason::FragmentCollect);
                }
            }
        }

        if let Some(reason) = nack {
            match Interest::decode(fragment) {
                Ok(interest) => {
                    trace!(target: t::FWD_PIPELINE, face=%ctx.face_id, name=%interest.name, reason=?reason, "decode: Nack");
                    let nack = Nack::new(interest, reason);
                    if nack.interest.name.len() > 3 {
                        ctx.name_hashes = Some(NameHashes::compute(&nack.interest.name));
                    }
                    ctx.name = Some(nack.interest.name.clone());
                    ctx.packet = DecodedPacket::Nack(Box::new(nack));
                    if let Some(drop) = self.check_scope(&ctx) {
                        return drop;
                    }
                    Action::Continue(ctx)
                }
                Err(e) => {
                    trace!(target: t::FWD_PIPELINE, face=%ctx.face_id, error=%e, "decode: malformed nacked Interest");
                    Action::Drop(DropReason::MalformedPacket)
                }
            }
        } else {
            ctx.raw_bytes = fragment;
            self.process(ctx)
        }
    }
}

#[cfg(test)]
mod d02_tests {
    use super::*;
    use ndn_packet::Name;

    #[test]
    fn n07_is_localhost_name_recognises_prefix() {
        let n: Name = "/localhost/nfd/foo".parse().unwrap();
        assert!(is_localhost_name(&n));
        let n: Name = "/local/host/foo".parse().unwrap();
        assert!(!is_localhost_name(&n));
    }

    #[test]
    fn d02_is_localhop_name_recognises_prefix() {
        let n: Name = "/localhop/nfd/foo".parse().unwrap();
        assert!(is_localhop_name(&n));
        let n: Name = "/local/hop".parse().unwrap();
        assert!(!is_localhop_name(&n));
        let n: Name = "/localhost/foo".parse().unwrap();
        assert!(!is_localhop_name(&n));
    }
}

#[cfg(test)]
mod d01_tests {
    use super::*;
    use ndn_packet::Name;
    use ndn_packet::encode::InterestBuilder;

    fn empty_face_table() -> Arc<FaceTable> {
        Arc::new(FaceTable::new())
    }

    /// Decode stage decrements HopLimit before passing Interests downstream.
    #[test]
    fn d01_decode_stage_decrements_hop_limit() {
        let stage = TlvDecodeStage::new(empty_face_table());
        let name: Name = "/audit/d01".parse().unwrap();
        let wire = InterestBuilder::new(name).hop_limit(7).sign_digest_sha256();

        let ctx = PacketContext::new(wire, FaceId(0), 0);
        let action = stage.process(ctx);
        let new_ctx = match action {
            Action::Continue(ctx) => ctx,
            _ => panic!("expected Continue"),
        };
        let interest = Interest::decode(new_ctx.raw_bytes.clone()).unwrap();
        assert_eq!(
            interest.hop_limit(),
            Some(6),
            "HopLimit must be decremented by the decode stage"
        );
    }

    #[test]
    fn d01_decode_stage_drops_when_hop_limit_zero() {
        let stage = TlvDecodeStage::new(empty_face_table());
        let name: Name = "/audit/d01-zero".parse().unwrap();
        let wire = InterestBuilder::new(name).hop_limit(0).sign_digest_sha256();

        let ctx = PacketContext::new(wire, FaceId(0), 0);
        match stage.process(ctx) {
            Action::Drop(DropReason::HopLimitExceeded) => {}
            _ => panic!("expected Drop(HopLimitExceeded)"),
        }
    }

    #[test]
    fn g09_decode_stage_surfaces_prefix_announcement_tag() {
        use ndn_packet::Name;
        use ndn_packet::encode::InterestBuilder;

        let stage = TlvDecodeStage::new(empty_face_table());
        let name: Name = "/audit/g09".parse().unwrap();
        let interest_wire = InterestBuilder::new(name).sign_digest_sha256();
        assert!(
            interest_wire.len() < 253,
            "test fixture assumes single-byte length encoding"
        );

        // Hand-craft an LpPacket carrying a PrefixAnnouncement header
        // (TLV-TYPE 0x0350, encoded as the 3-byte var `FD 03 50`) followed
        // by the Fragment terminator (0x50). NDNLPv2 §3 places Fragment
        // last, with all headers preceding it in ascending TLV-TYPE order.
        let pa_payload: &[u8] = b"announce-payload";
        let mut inner: Vec<u8> = Vec::new();
        inner.extend_from_slice(&[0xFD, 0x03, 0x50]); // LP_PREFIX_ANNOUNCEMENT
        inner.push(pa_payload.len() as u8);
        inner.extend_from_slice(pa_payload);
        inner.push(0x50); // LP_FRAGMENT
        inner.push(interest_wire.len() as u8);
        inner.extend_from_slice(&interest_wire);

        let mut lp_wire_v: Vec<u8> = vec![0x64]; // LP_PACKET
        if inner.len() < 253 {
            lp_wire_v.push(inner.len() as u8);
        } else {
            lp_wire_v.extend_from_slice(&[
                0xFD,
                (inner.len() >> 8) as u8,
                (inner.len() & 0xFF) as u8,
            ]);
        }
        lp_wire_v.extend_from_slice(&inner);
        let lp_wire = bytes::Bytes::from(lp_wire_v);

        let ctx = PacketContext::new(lp_wire, FaceId(0), 0);
        let action = stage.process(ctx);
        let new_ctx = match action {
            Action::Continue(c) => c,
            _ => panic!("expected Continue from decode stage"),
        };
        let pa = new_ctx
            .tags
            .get::<PrefixAnnouncement>()
            .expect("PrefixAnnouncement tag must be present in ctx.tags after decode (G.09)");
        assert_eq!(pa.0.as_ref(), pa_payload);
    }

    #[test]
    fn d01_decode_stage_no_hop_limit_passes_through() {
        let stage = TlvDecodeStage::new(empty_face_table());
        let name: Name = "/audit/d01-none".parse().unwrap();
        let wire = ndn_packet::encode::encode_interest(&name, None);

        let ctx = PacketContext::new(wire, FaceId(0), 0);
        match stage.process(ctx) {
            Action::Continue(ctx) => {
                let i = Interest::decode(ctx.raw_bytes).unwrap();
                assert!(i.hop_limit().is_none());
            }
            _ => panic!("expected Continue"),
        }
    }
}

#[cfg(test)]
mod content_sha256_tests {
    use super::*;
    use ndn_packet::encode::DataBuilder;
    use ndn_packet::{ContentHashTarget, Data, SignatureType};
    use ndn_tlv::TlvWriter;
    use ndn_transport::{FaceError, FaceId, FaceKind, FaceOptions, Transport};
    use sha2::Digest as _;

    struct MockFace {
        id: FaceId,
        kind: FaceKind,
    }

    impl Transport for MockFace {
        fn id(&self) -> FaceId {
            self.id
        }

        fn kind(&self) -> FaceKind {
            self.kind
        }

        async fn recv_bytes(&self) -> Result<bytes::Bytes, FaceError> {
            std::future::pending::<Result<bytes::Bytes, FaceError>>().await
        }

        async fn send_bytes(&self, _pkt: bytes::Bytes) -> Result<(), FaceError> {
            Ok(())
        }
    }

    fn build_data_wire(content: &[u8]) -> bytes::Bytes {
        DataBuilder::new("/test/content-sha256", content).sign_sync(
            SignatureType::DigestSha256,
            None,
            |_| bytes::Bytes::from(vec![0u8; 32]),
        )
    }

    /// Build a Data whose Content is a TLV envelope containing a single
    /// child of `inner_type` with `inner_value` as value bytes.
    fn build_data_with_envelope(inner_type: u64, inner_value: &[u8]) -> bytes::Bytes {
        let mut env = TlvWriter::new();
        env.write_tlv(inner_type, inner_value);
        let envelope = env.finish();
        build_data_wire(&envelope)
    }

    fn decode_stage_with_face(face_id: FaceId, kind: FaceKind) -> (TlvDecodeStage, Arc<FaceTable>) {
        let face_table = Arc::new(FaceTable::new());
        face_table.insert(MockFace { id: face_id, kind });
        let stage = TlvDecodeStage::new(Arc::clone(&face_table));
        (stage, face_table)
    }

    fn extract_data(action: Action) -> Box<ndn_packet::Data> {
        let ctx = match action {
            Action::Continue(c) => c,
            _ => panic!("expected Continue"),
        };
        match ctx.packet {
            DecodedPacket::Data(d) => d,
            _ => panic!("expected Data"),
        }
    }

    #[test]
    fn app_face_default_whole_content() {
        let face_id = FaceId(1);
        let (stage, _) = decode_stage_with_face(face_id, FaceKind::App);
        let content = b"hello ndf";
        let wire = build_data_wire(content);
        let data = extract_data(stage.process(PacketContext::new(wire, face_id, 0)));
        let hash = data
            .content_sha256()
            .expect("App face must populate sidecar");
        let expected: [u8; 32] = sha2::Sha256::digest(content).into();
        assert_eq!(hash, expected);
    }

    #[test]
    fn network_face_default_none() {
        let face_id = FaceId(2);
        let (stage, _) = decode_stage_with_face(face_id, FaceKind::Udp);
        let wire = build_data_wire(b"irrelevant");
        let data = extract_data(stage.process(PacketContext::new(wire, face_id, 0)));
        assert!(
            data.content_sha256().is_none(),
            "Network face must not compute sidecar by default"
        );
    }

    #[test]
    fn network_face_override_whole_content() {
        let face_id = FaceId(3);
        let (stage, _) = decode_stage_with_face(face_id, FaceKind::Udp);
        stage.set_face_options(
            face_id,
            FaceOptions {
                content_hash_target: Some(ContentHashTarget::WholeContent),
                ..Default::default()
            },
        );
        let content = b"override test";
        let wire = build_data_wire(content);
        let data = extract_data(stage.process(PacketContext::new(wire, face_id, 0)));
        let hash = data
            .content_sha256()
            .expect("override must populate sidecar");
        let expected: [u8; 32] = sha2::Sha256::digest(content).into();
        assert_eq!(hash, expected);
    }

    #[test]
    fn app_face_inner_tlv_type_found() {
        let face_id = FaceId(4);
        let (stage, _) = decode_stage_with_face(face_id, FaceKind::App);
        stage.set_face_options(
            face_id,
            FaceOptions {
                content_hash_target: Some(ContentHashTarget::InnerTlvType(364)),
                ..Default::default()
            },
        );
        let inner_value = b"ndf payload bytes";
        let wire = build_data_with_envelope(364, inner_value);
        let data = extract_data(stage.process(PacketContext::new(wire, face_id, 0)));
        let hash = data
            .content_sha256()
            .expect("InnerTlvType(364) found → Some");
        let expected: [u8; 32] = sha2::Sha256::digest(inner_value).into();
        assert_eq!(
            hash, expected,
            "sidecar must equal SHA-256(inner TLV value)"
        );
    }

    #[test]
    fn inner_tlv_type_not_found_is_none() {
        let face_id = FaceId(5);
        let (stage, _) = decode_stage_with_face(face_id, FaceKind::App);
        stage.set_face_options(
            face_id,
            FaceOptions {
                content_hash_target: Some(ContentHashTarget::InnerTlvType(999)),
                ..Default::default()
            },
        );
        let wire = build_data_with_envelope(364, b"irrelevant");
        let data = extract_data(stage.process(PacketContext::new(wire, face_id, 0)));
        assert!(
            data.content_sha256().is_none(),
            "InnerTlvType not present → sidecar must be None"
        );
    }

    #[test]
    fn synthetic_data_has_no_sidecar() {
        let data = Data::decode(build_data_wire(b"local")).expect("decode ok");
        assert!(
            data.content_sha256().is_none(),
            "Data not from forwarder ingress must have content_sha256 = None"
        );
    }

    #[test]
    fn face_options_default_for_kind() {
        use ndn_transport::ContentHashTarget as CHT;
        assert_eq!(
            FaceOptions::default_for_kind(FaceKind::App).content_hash_target,
            Some(CHT::WholeContent),
            "App → WholeContent"
        );
        assert_eq!(
            FaceOptions::default_for_kind(FaceKind::Shm).content_hash_target,
            Some(CHT::WholeContent),
            "Shm → WholeContent"
        );
        assert_eq!(
            FaceOptions::default_for_kind(FaceKind::Udp).content_hash_target,
            None,
            "Udp → None"
        );
        assert_eq!(
            FaceOptions::default_for_kind(FaceKind::Tcp).content_hash_target,
            None,
            "Tcp → None"
        );
    }
}
