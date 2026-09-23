use std::sync::Arc;

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
        // mirroring NFD's Cs::findImpl. Freshness is judged at the Interest's
        // arrival — the runtime clock `CsInsertStage` stamps `stale_at` on — so
        // FreshnessPeriod expires in virtual time under a simulated runtime.
        if let Some(entry) = self.cs.get_erased(interest, ctx.arrival).await {
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
    /// Admit Data that was never SUBJECT to validation (no validator
    /// configured). Default `false`, which keeps the documented fail-secure
    /// invariant: with no validator, nothing network-sourced is cached, and
    /// ndn-rs is deliberately stricter than NFD (ARCHITECTURE.md, D.12).
    ///
    /// Opting in trades that strictness for a working cache. It is the right
    /// trade only where trust is enforced above the forwarder — the miniMUAS
    /// fleet runs `[security] profile = "disabled"` precisely because NDNSF
    /// and NAC-ABE validate at the application layer — and there the coupling
    /// costs real capacity: measured 0.17% CS hit rate with 37 retained
    /// entries, against NFD's 7.33% and 12033 on the identical workload.
    ///
    /// This never admits Data a validator RAN and REJECTED, at any setting.
    pub admit_unverified: bool,
}

impl CsInsertStage {
    pub async fn process(&self, ctx: PacketContext) -> Action {
        if let DecodedPacket::Data(ref data) = ctx.packet {
            // The Admit gate lives inside the CS (`insert` is a no-op when
            // disabled), mirroring NFD's Cs::insert.
            // Only verified Data enters the CS; unverified bytes could poison
            // downstream consumers. `ctx.verified` is set by ValidationStage
            // or by the local-face trusted-bypass in the pipeline.
            // Admit when the signature was checked and passed, or when
            // nothing was ever checked AND the operator has opted in. Data
            // that a validator ran and rejected is never admitted.
            let unvalidated_ok = ctx.validation_not_configured && self.admit_unverified;
            if !ctx.verified && !unvalidated_ok {
                trace!(target: t::FWD_CS, name=%data.name, "cs-insert: not admitted (unverified)");
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

            // The Data's freshness window starts at its arrival (deterministic under a
            // virtual runtime), not a fresh wall-clock read. (ndn-lab slice 0b.)
            let now_ns = ctx.arrival;

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
    use ndn_packet::encode::{DataBuilder, InterestBuilder};
    use ndn_packet::{Data, Interest, Name, SignatureType};
    use ndn_security::{Certificate, Ed25519Signer, Signer, TrustSchema, Validator};
    use ndn_store::{AdmitAllPolicy, LruCs};
    use ndn_transport::FaceId;

    use crate::pipeline::DecodedPacket;
    use crate::stages::validation::{PendingQueueConfig, ValidationStage};

    /// Lookup time; the direct CS lookups here do not ask for MustBeFresh.
    const NOW: u64 = 1_000_000_000;

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
            admit_unverified: false,
        };
        (stage, cs)
    }

    fn interest_ctx(wire: Bytes) -> PacketContext {
        let interest = Interest::decode(wire.clone()).unwrap();
        let mut ctx = PacketContext::new(wire, FaceId(7), 0);
        ctx.name = Some(Arc::clone(&interest.name));
        ctx.packet = DecodedPacket::Interest(Box::new(interest));
        ctx
    }

    #[tokio::test]
    async fn d04_cs_lookup_must_be_fresh_misses_stale_cached_data() {
        let cs = Arc::new(LruCs::new(1024 * 1024));
        let name: Arc<Name> = Arc::new("/test/d04/stale".parse().unwrap());
        cs.insert_erased(
            Bytes::from_static(b"stale-data-wire"),
            Arc::clone(&name),
            CsMeta { stale_at: 0 },
        )
        .await;

        let stage = CsLookupStage {
            cs: Arc::clone(&cs) as Arc<dyn ndn_store::ErasedContentStore>,
        };
        let wire = InterestBuilder::new((*name).clone())
            .must_be_fresh()
            .build();

        let action = stage.process(interest_ctx(wire)).await;
        assert!(
            matches!(action, Action::Continue(_)),
            "stale cached Data must not satisfy MustBeFresh Interests"
        );
    }

    #[tokio::test]
    async fn d04_cs_lookup_without_must_be_fresh_hits_stale_cached_data() {
        let cs = Arc::new(LruCs::new(1024 * 1024));
        let name: Arc<Name> = Arc::new("/test/d04/stale-ok".parse().unwrap());
        cs.insert_erased(
            Bytes::from_static(b"stale-data-wire"),
            Arc::clone(&name),
            CsMeta { stale_at: 0 },
        )
        .await;

        let stage = CsLookupStage {
            cs: Arc::clone(&cs) as Arc<dyn ndn_store::ErasedContentStore>,
        };
        let wire = InterestBuilder::new((*name).clone()).build();

        let action = stage.process(interest_ctx(wire)).await;
        assert!(
            matches!(action, Action::Satisfy(_)),
            "non-MustBeFresh Interests may be satisfied by stale cached Data"
        );
    }

    /// End to end through both CS stages: a Data with FreshnessPeriod 1 s that
    /// arrives at runtime time T satisfies a MustBeFresh Interest arriving at
    /// T + 999 ms and not one at T + 1 s. Both stamps are `ctx.arrival` (the
    /// runtime clock), so under a virtual runtime the cache ages in virtual
    /// time — T here is a virtual-epoch instant nowhere near the wall clock.
    #[tokio::test]
    async fn cached_data_ages_on_the_runtime_clock() {
        const T: u64 = 5_000_000_000;
        let name = "/test/fresh/virtual";
        let wire = DataBuilder::new(name, b"x")
            .freshness(std::time::Duration::from_secs(1))
            .sign_sync(SignatureType::DigestSha256, None, |_| {
                Bytes::from_static(&[0u8; 32])
            });
        let data = Data::decode(wire.clone()).unwrap();
        let mut data_ctx = PacketContext::new(wire, FaceId(0), T);
        data_ctx.name = Some(Arc::clone(&data.name));
        data_ctx.packet = DecodedPacket::Data(Box::new(data));
        data_ctx.verified = true;

        let (insert, cs) = make_insert_stage();
        insert.process(data_ctx).await;
        let lookup = CsLookupStage {
            cs: cs as Arc<dyn ndn_store::ErasedContentStore>,
        };
        let fresh_interest_at = |arrival: u64| {
            let wire = InterestBuilder::new(name).must_be_fresh().build();
            let mut ctx = interest_ctx(wire);
            ctx.arrival = arrival;
            ctx
        };

        assert!(
            matches!(
                lookup.process(fresh_interest_at(T + 999_000_000)).await,
                Action::Satisfy(_)
            ),
            "still fresh 999 ms after arrival"
        );
        assert!(
            matches!(
                lookup.process(fresh_interest_at(T + 1_000_000_000)).await,
                Action::Continue(_)
            ),
            "stale once FreshnessPeriod has elapsed on the runtime clock"
        );
    }

    /// A validator RAN and rejected this Data, so it must not be cached.
    /// `validation_not_configured` stays false, which is what separates this
    /// from the "no validator at all" case below.
    #[tokio::test]
    async fn d12_cs_rejects_unverified_ctx() {
        let (stage, cs) = make_insert_stage();
        let ctx = make_ctx_with_freshness("/test/d12/unverified", false);
        stage.process(ctx).await;

        let name: Name = "/test/d12/unverified".parse().unwrap();
        assert!(
            cs.get_erased(&Interest::new(name), NOW).await.is_none(),
            "CS must not admit Data a validator rejected (D.12)"
        );
    }

    /// With NO validator configured the Data was never subject to validation,
    /// and the CS must still admit it -- NFD caches network Data regardless,
    /// and the consumer validates for itself.
    ///
    /// Regression guard for a measured outage: `[security] profile =
    /// "disabled"` meant no validator, which left `verified = false`, which
    /// made this stage refuse every network packet. The Content Store was
    /// silently dead -- 0.17% hit rate and 37 retained entries, against NFD's
    /// 7.33% and 12033 on the identical workload.
    #[tokio::test]
    async fn cs_still_refuses_unvalidated_data_by_default() {
        let (stage, cs) = make_insert_stage();
        let mut ctx = make_ctx_with_freshness("/test/cs/unvalidated-default", false);
        ctx.validation_not_configured = true;
        stage.process(ctx).await;

        let name: Name = "/test/cs/unvalidated-default".parse().unwrap();
        assert!(
            cs.get_erased(&Interest::new(name), NOW).await.is_none(),
            "fail-secure is the DEFAULT: no opt-in, no caching of unvalidated Data"
        );
    }

    #[tokio::test]
    async fn cs_admits_unvalidated_data_when_opted_in() {
        let (mut stage, cs) = make_insert_stage();
        stage.admit_unverified = true;
        let mut ctx = make_ctx_with_freshness("/test/cs/unvalidated-optin", false);
        ctx.validation_not_configured = true;
        stage.process(ctx).await;

        let name: Name = "/test/cs/unvalidated-optin".parse().unwrap();
        assert!(
            cs.get_erased(&Interest::new(name), NOW).await.is_some(),
            "with admit_unverified the CS caches Data no validator ever checked"
        );
    }

    /// The opt-in must NOT extend to Data a validator ran and rejected.
    #[tokio::test]
    async fn opt_in_never_admits_validator_rejected_data() {
        let (mut stage, cs) = make_insert_stage();
        stage.admit_unverified = true;
        let ctx = make_ctx_with_freshness("/test/cs/rejected", false);
        // validation_not_configured stays false: a validator ran and said no.
        stage.process(ctx).await;

        let name: Name = "/test/cs/rejected".parse().unwrap();
        assert!(
            cs.get_erased(&Interest::new(name), NOW).await.is_none(),
            "admit_unverified must never cache Data a validator rejected"
        );
    }

    #[tokio::test]
    async fn d12_cs_admits_verified_ctx() {
        let (stage, cs) = make_insert_stage();
        let ctx = make_ctx_with_freshness("/test/d12/verified", true);
        stage.process(ctx).await;

        let name: Name = "/test/d12/verified".parse().unwrap();
        assert!(
            cs.get_erased(&Interest::new(name), NOW).await.is_some(),
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
            cs.get_erased(&Interest::new(name), NOW).await.is_none(),
            "unverified Data must NOT enter the CS (D.12 fail-secure)"
        );
    }
}
