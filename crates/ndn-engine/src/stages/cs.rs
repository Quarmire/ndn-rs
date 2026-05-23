use std::sync::Arc;
use web_time::SystemTime;
use web_time::UNIX_EPOCH;

use tracing::trace;

use crate::observability::targets as t;
use crate::pipeline::{Action, DecodedPacket, PacketContext};
use ndn_packet::CachePolicyType;
use ndn_store::{CsAdmissionPolicy, CsMeta, ErasedContentStore};

use crate::stages::decode::LpCachePolicy;

pub struct CsLookupStage {
    pub cs: Arc<dyn ErasedContentStore>,
}

impl CsLookupStage {
    pub async fn process(&self, mut ctx: PacketContext) -> Action {
        let interest = match &ctx.packet {
            DecodedPacket::Interest(i) => i,
            _ => return Action::Continue(ctx),
        };

        // The Serve gate lives inside the CS (`get` returns None when disabled),
        // mirroring NFD's Cs::findImpl.
        if let Some(entry) = self.cs.get_erased(interest).await {
            trace!(target: t::FWD_CS, face=%ctx.face_id, name=?ctx.name, hit=true, "cs lookup");
            ctx.cs_hit = true;
            ctx.out_faces.push(ctx.face_id);
            ctx.tags.insert(entry);
            Action::Satisfy(ctx)
        } else {
            trace!(target: t::FWD_CS, face=%ctx.face_id, name=?ctx.name, hit=false, "cs lookup");
            Action::Continue(ctx)
        }
    }
}

pub struct CsInsertStage {
    pub cs: Arc<dyn ErasedContentStore>,
    pub admission: Arc<dyn CsAdmissionPolicy>,
}

impl CsInsertStage {
    pub async fn process(&self, ctx: PacketContext) -> Action {
        if let DecodedPacket::Data(ref data) = ctx.packet {
            // The Admit gate lives inside the CS (`insert` is a no-op when
            // disabled), mirroring NFD's Cs::insert.
            // Only verified Data enters the CS; unverified bytes could poison
            // downstream consumers. `ctx.verified` is set by ValidationStage
            // or by the local-face trusted-bypass in the pipeline.
            if !ctx.verified {
                trace!(target: t::FWD_CS, name=%data.name, "cs-insert: unverified Data, skipping");
                return Action::Satisfy(ctx);
            }

            if ctx
                .tags
                .get::<LpCachePolicy>()
                .is_some_and(|p| matches!(p.0, CachePolicyType::NoCache))
            {
                trace!(target: t::FWD_CS, name=%data.name, "cs-insert: NoCache LP policy, skipping");
                return Action::Satisfy(ctx);
            }

            if !self.admission.should_admit(data) {
                trace!(target: t::FWD_CS, name=%data.name, "cs-insert: rejected by admission policy");
                return Action::Satisfy(ctx);
            }

            let now_ns = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;

            let freshness_ms = data
                .meta_info()
                .and_then(|m| m.freshness_period)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let stale_at = now_ns + freshness_ms * 1_000_000;

            let meta = CsMeta { stale_at };
            self.cs
                .insert_erased(ctx.raw_bytes.clone(), data.name.clone(), meta)
                .await;
            trace!(target: t::FWD_CS, name=%data.name, freshness_ms, "cs-insert: cached");
        }
        Action::Satisfy(ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use bytes::Bytes;
    use ndn_packet::encode::DataBuilder;
    use ndn_packet::{Data, Interest, Name, SignatureType};
    use ndn_security::{Certificate, Ed25519Signer, Signer, TrustSchema, Validator};
    use ndn_store::{AdmitAllPolicy, LruCs};
    use ndn_transport::FaceId;

    use crate::pipeline::DecodedPacket;
    use crate::stages::validation::{PendingQueueConfig, ValidationStage};

    fn make_ctx_with_freshness(name: &str, verified: bool) -> PacketContext {
        let n: Name = name.parse().unwrap();
        let wire = DataBuilder::new(name, b"x")
            .freshness(std::time::Duration::from_secs(60))
            .sign_sync(SignatureType::DigestSha256, None, |_| {
                Bytes::from_static(&[0u8; 32])
            });
        let data = Data::decode(wire.clone()).unwrap();
        let mut ctx = PacketContext::new(wire, FaceId(0), 0);
        ctx.name = Some(Arc::new(n));
        ctx.packet = DecodedPacket::Data(Box::new(data));
        ctx.verified = verified;
        ctx
    }

    fn make_insert_stage() -> (CsInsertStage, Arc<LruCs>) {
        let cs = Arc::new(LruCs::new(1024 * 1024));
        let stage = CsInsertStage {
            cs: Arc::clone(&cs) as Arc<dyn ndn_store::ErasedContentStore>,
            admission: Arc::new(AdmitAllPolicy),
        };
        (stage, cs)
    }

    #[tokio::test]
    async fn d12_cs_rejects_unverified_ctx() {
        let (stage, cs) = make_insert_stage();
        let ctx = make_ctx_with_freshness("/test/d12/unverified", false);
        stage.process(ctx).await;

        let name: Name = "/test/d12/unverified".parse().unwrap();
        assert!(
            cs.get_erased(&Interest::new(name)).await.is_none(),
            "CS must not admit Data with ctx.verified=false (D.12)"
        );
    }

    #[tokio::test]
    async fn d12_cs_admits_verified_ctx() {
        let (stage, cs) = make_insert_stage();
        let ctx = make_ctx_with_freshness("/test/d12/verified", true);
        stage.process(ctx).await;

        let name: Name = "/test/d12/verified".parse().unwrap();
        assert!(
            cs.get_erased(&Interest::new(name)).await.is_some(),
            "CS must admit Data with ctx.verified=true"
        );
    }

    #[tokio::test]
    async fn d12_validation_sets_verified_on_valid() {
        let seed = [0xABu8; 32];
        let key_name: Name = "/test/KEY".parse().unwrap();
        let signer = Ed25519Signer::from_seed(&seed, key_name.clone());
        let pub_key = signer.public_key_bytes();

        let validator = {
            let v = Validator::new(TrustSchema::accept_all());
            v.add_trust_anchor(Certificate {
                name: Arc::new(key_name.clone()),
                public_key: Bytes::copy_from_slice(&pub_key),
                valid_from: 0,
                valid_until: u64::MAX,
                issuer: None,
                signed_region: None,
                sig_value: None,
                sig_type: SignatureType::SignatureEd25519,
            });
            Arc::new(v)
        };
        let validation = ValidationStage::new(
            Some(validator),
            None,
            PendingQueueConfig::default(),
            ndn_runtime::default_runtime(),
        );

        let wire = DataBuilder::new("/test/d12/signed", b"content")
            .freshness(std::time::Duration::from_secs(60))
            .sign_sync(SignatureType::SignatureEd25519, Some(&key_name), |region| {
                signer.sign_sync(region).unwrap()
            });
        let data = Data::decode(wire.clone()).unwrap();
        let mut ctx = PacketContext::new(wire, FaceId(0), 0);
        ctx.name = Some(Arc::clone(&data.name));
        ctx.packet = DecodedPacket::Data(Box::new(data));

        let action = validation.process(ctx).await;
        let ctx = match action {
            Action::Satisfy(c) => c,
            _ => panic!("expected Satisfy, got non-Satisfy action"),
        };
        assert!(
            ctx.verified,
            "ValidationStage must set ctx.verified=true on valid sig"
        );
    }

    #[tokio::test]
    async fn d12_validation_drops_bogus_sig() {
        let seed = [0xABu8; 32];
        let key_name: Name = "/test/KEY".parse().unwrap();
        let signer = Ed25519Signer::from_seed(&seed, key_name.clone());
        let pub_key = signer.public_key_bytes();

        let validator = {
            let v = Validator::new(TrustSchema::accept_all());
            v.add_trust_anchor(Certificate {
                name: Arc::new(key_name.clone()),
                public_key: Bytes::copy_from_slice(&pub_key),
                valid_from: 0,
                valid_until: u64::MAX,
                issuer: None,
                signed_region: None,
                sig_value: None,
                sig_type: SignatureType::SignatureEd25519,
            });
            Arc::new(v)
        };
        let validation = ValidationStage::new(
            Some(validator),
            None,
            PendingQueueConfig::default(),
            ndn_runtime::default_runtime(),
        );

        let wire = DataBuilder::new("/test/d12/bogus", b"content").sign_sync(
            SignatureType::SignatureEd25519,
            Some(&key_name),
            |_| Bytes::from(vec![0u8; 64]),
        );
        let data = Data::decode(wire.clone()).unwrap();
        let mut ctx = PacketContext::new(wire, FaceId(0), 0);
        ctx.name = Some(Arc::clone(&data.name));
        ctx.packet = DecodedPacket::Data(Box::new(data));

        let action = validation.process(ctx).await;
        assert!(
            matches!(action, Action::Drop(_)),
            "ValidationStage must drop Data with bogus signature"
        );
    }

    /// Default-deny: with no Validator wired, `ValidationStage` must leave
    /// `ctx.verified = false` so `CsInsertStage` refuses admission. The
    /// pipeline's local-face bypass handles trusted Data separately.
    #[tokio::test]
    async fn d12_disabled_validator_does_not_verify_network_data() {
        let validation = ValidationStage::disabled();
        let (stage, cs) = make_insert_stage();

        let wire = DataBuilder::new("/test/d12/network-novalidator", b"x")
            .freshness(std::time::Duration::from_secs(60))
            .sign_sync(SignatureType::DigestSha256, None, |_| {
                Bytes::from_static(&[0u8; 32])
            });
        let data = Data::decode(wire.clone()).unwrap();
        let mut ctx = PacketContext::new(wire, FaceId(0), 0);
        ctx.name = Some(Arc::clone(&data.name));
        ctx.packet = DecodedPacket::Data(Box::new(data));

        let action = validation.process(ctx).await;
        let ctx = match action {
            Action::Satisfy(c) => c,
            _ => panic!("disabled validator should Satisfy"),
        };
        assert!(
            !ctx.verified,
            "no-validator + non-local face must leave ctx.verified=false (D.12)"
        );

        let action = stage.process(ctx).await;
        assert!(matches!(action, Action::Satisfy(_)));

        let name: Name = "/test/d12/network-novalidator".parse().unwrap();
        assert!(
            cs.get_erased(&Interest::new(name)).await.is_none(),
            "unverified Data must NOT enter the CS (D.12 fail-secure)"
        );
    }
}
