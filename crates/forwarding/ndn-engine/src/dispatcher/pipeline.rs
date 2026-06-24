use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, trace};

use crate::observability::targets as t;
use crate::pipeline::{
    Action, DecodedPacket, DropReason, ForwardingAction, NackReason, PacketContext,
};
use ndn_discovery_core::InboundMeta;
use ndn_store::PitToken;
use ndn_transport::{FaceId, FaceScope};

use super::{InboundPacket, PacketDispatcher};

impl PacketDispatcher {
    pub(super) const BATCH_SIZE: usize = 64;

    pub(super) async fn run_pipeline(
        self: &Arc<Self>,
        mut rx: mpsc::Receiver<InboundPacket>,
        cancel: CancellationToken,
    ) {
        let mut batch = Vec::with_capacity(Self::BATCH_SIZE);
        loop {
            let first = tokio::select! {
                biased;                _ = cancel.cancelled() => break,
                pkt = rx.recv() => match pkt {
                    Some(p) => p,
                    None    => break,
                },
            };
            batch.push(first);

            while batch.len() < Self::BATCH_SIZE {
                match rx.try_recv() {
                    Ok(p) => batch.push(p),
                    Err(_) => break,
                }
            }

            let parallel = self.pipeline_threads > 1;
            for pkt in batch.drain(..) {
                let InboundPacket {
                    raw,
                    face_id,
                    arrival,
                    meta,
                } = pkt;
                match self
                    .decode
                    .try_collect_fragment(face_id, meta.endpoint_id(), raw)
                {
                    Ok(None) => {
                        trace!(target: t::FACE_LP, face=%face_id, "fragment collected, awaiting reassembly");
                    }
                    Ok(Some(reassembled)) => {
                        let pkt = InboundPacket {
                            raw: reassembled,
                            face_id,
                            arrival,
                            meta,
                        };
                        if parallel {
                            let d = Arc::clone(self);
                            self.runtime.spawn(Box::pin(async move { d.process_packet(pkt).await }.instrument(
                                tracing::info_span!(target: t::FWD_PIPELINE, "pipeline_dispatch"),
                            )));
                        } else {
                            self.process_packet(pkt).await;
                        }
                    }
                    Err(raw) => {
                        let pkt = InboundPacket {
                            raw,
                            face_id,
                            arrival,
                            meta,
                        };
                        if parallel {
                            let d = Arc::clone(self);
                            self.runtime.spawn(Box::pin(async move { d.process_packet(pkt).await }.instrument(
                                tracing::info_span!(target: t::FWD_PIPELINE, "pipeline_dispatch"),
                            )));
                        } else {
                            self.process_packet(pkt).await;
                        }
                    }
                }
            }
        }
    }

    async fn process_packet(&self, pkt: InboundPacket) {
        let face_id = pkt.face_id;
        let span = tracing::info_span!(
            target: t::FWD_PIPELINE,
            "interest",
            in_face = %face_id,
            name = tracing::field::Empty,
            nonce = tracing::field::Empty,
        );
        self.process_packet_inner(pkt).instrument(span).await
    }

    async fn process_packet_inner(&self, pkt: InboundPacket) {
        trace!(target: t::FWD_PIPELINE, face=%pkt.face_id, len=pkt.raw.len(), "pipeline: packet arrived");
        let meta = pkt.meta;
        let ctx = match self.decode.decode_resolved(
            pkt.raw,
            pkt.face_id,
            pkt.arrival,
            meta.endpoint_id(),
        ) {
            Action::Continue(ctx) => ctx,
            Action::Drop(DropReason::FragmentCollect) => {
                trace!(target: t::FACE_LP, face=%pkt.face_id, "fragment collected, awaiting reassembly");
                return;
            }
            Action::Drop(r) => {
                debug!(target: t::FWD_PIPELINE, face=%pkt.face_id, reason=?r, "drop at decode");
                return;
            }
            other => {
                self.dispatch_action(other).await;
                return;
            }
        };

        self.forward_decoded(ctx, meta).await;
    }

    /// Forward an already-decoded packet: discovery hook, ingress counters,
    /// inbound rate limit, then the Interest/Data/Nack pipeline. Split out of
    /// `process_packet_inner` so the shared runtime (decode + forward in one
    /// task) and the partitioned runtime (decode in the RX front-end, forward
    /// in a worker) run the identical forwarding path. See
    /// `.claude/notes/partitioned-fwd-design-2026-05-24.md`.
    pub(crate) async fn forward_decoded(&self, ctx: PacketContext, meta: InboundMeta) {
        if let Some(ref name) = ctx.name {
            tracing::Span::current().record("name", name.to_string());
        }
        if let DecodedPacket::Interest(ref i) = ctx.packet
            && let Some(nonce) = i.nonce()
        {
            tracing::Span::current().record("nonce", nonce);
        }

        if self
            .discovery
            .on_inbound(&ctx.raw_bytes, ctx.face_id, &meta, &*self.discovery_ctx)
        {
            return;
        }

        let is_interest = matches!(ctx.packet, DecodedPacket::Interest(_));
        let is_data = matches!(ctx.packet, DecodedPacket::Data(_));
        if is_interest || is_data {
            if let Some(state) = self.face_states.get(&ctx.face_id) {
                if is_interest {
                    state.counters.in_interests.fetch_add(1, Ordering::Relaxed);
                } else {
                    state.counters.in_data.fetch_add(1, Ordering::Relaxed);
                }
                state
                    .counters
                    .in_bytes
                    .fetch_add(ctx.raw_bytes.len() as u64, Ordering::Relaxed);
            }
            let ctx = match self.check_rate_limit_inbound(ctx) {
                Ok(c) => c,
                Err(action) => {
                    self.dispatch_action(*action).await;
                    return;
                }
            };
            if is_interest {
                trace!(target: t::FWD_PIPELINE, face=%ctx.face_id, name=?ctx.name, "pipeline: Interest → interest_pipeline");
                self.interest_pipeline(ctx).await;
            } else {
                trace!(target: t::FWD_PIPELINE, face=%ctx.face_id, name=?ctx.name, "pipeline: Data → data_pipeline");
                self.data_pipeline(ctx).await;
            }
        } else {
            match &ctx.packet {
                DecodedPacket::Nack(_) => {
                    trace!(target: t::FWD_PIPELINE, face=%ctx.face_id, name=?ctx.name, "pipeline: Nack → nack_pipeline");
                    self.nack_pipeline(ctx).await;
                }
                DecodedPacket::Raw => {}
                _ => unreachable!("Interest/Data handled in the is_interest||is_data branch"),
            }
        }
    }

    async fn interest_pipeline(&self, ctx: PacketContext) {
        // G3 PathControl fast path (opt-in): a control Interest that mutates per-hop
        // FIB/session state in transit and walks onward — not normal forwarding, so
        // it bypasses CS/PIT/strategy entirely. `None` ⇒ one untaken branch.
        if let Some(handler) = &self.path_control
            && let DecodedPacket::Interest(i) = &ctx.packet
            && let Some(pc) = ndn_pathcontrol::PathControl::parse(&i.name)
        {
            if let Some(faces) = handler.decide(&pc, i, ctx.face_id).await {
                for face in faces {
                    self.enqueue_send(
                        face,
                        ctx.raw_bytes.clone(),
                        crate::engine::EgressIntent::default(),
                    )
                    .await;
                }
            }
            return;
        }

        // Data-plane name-activity signal (opt-in): notify soft-state that must follow
        // real traffic — e.g. ndn-pipes' relay PUI inactivity monitor, which renews a
        // pipe while its namespace is still being fetched. `None` ⇒ one untaken branch.
        // After the PathControl bypass (control Interests aren't data-plane use) and
        // before CS/PIT (a cache hit still counts as demand).
        if let Some(obs) = &self.name_activity
            && let DecodedPacket::Interest(i) = &ctx.packet
        {
            obs.on_activity(&i.name);
        }

        let ctx = match self.cs_lookup.process(ctx).await {
            Action::Continue(ctx) => ctx,
            Action::Satisfy(ctx) => {
                self.satisfy(ctx).await;
                return;
            }
            Action::Drop(r) => {
                debug!(target: t::FWD_CS, reason=?r, "drop at cs lookup");
                return;
            }
            other => {
                self.dispatch_action(other).await;
                return;
            }
        };

        let ctx = match self.pit_check.process(ctx).await {
            Action::Continue(ctx) => ctx,
            Action::Drop(r) => {
                debug!(target: t::FWD_PIT, reason=?r, "drop at pit check");
                return;
            }
            other => {
                self.dispatch_action(other).await;
                return;
            }
        };

        // Reflexive forwarding: an Interest carrying a REFLEXIVE_NAME installs a
        // temporary reverse route `name -> incoming face` (W-RF-1: only ever the
        // incoming face), bounded by the Interest lifetime (W-RF-3). A later
        // reverse Interest under that name routes back along this face.
        if let DecodedPacket::Interest(i) = &ctx.packet
            && let Some(rname) = i.reflexive_name()
        {
            let lifetime = i.lifetime().unwrap_or(Duration::from_millis(4000));
            if !self
                .reflexive
                .install(rname.as_ref(), ctx.face_id, lifetime)
            {
                debug!(
                    target: t::FWD_PIPELINE,
                    face = %ctx.face_id,
                    "reflexive route refused (per-face cap or face collision)"
                );
            }
        }

        // Reverse routing: an Interest whose name matches a live reflexive route
        // is a producer's reverse Interest — forward it *only* along that reverse
        // route (the exact inverse of the path the original Interest came in on),
        // never via FIB (W-RF-5). Reflexive names are unpredictable and never
        // appear in the FIB, so a normal Interest cannot match one.
        let reverse_face = if self.reflexive.is_empty() {
            None
        } else {
            ctx.name.as_deref().and_then(|n| self.reflexive.lookup(n))
        };
        if let Some(rev_face) = reverse_face {
            trace!(target: t::FWD_PIPELINE, face=%ctx.face_id, rev_face=%rev_face, "reflexive: reverse routing");
            self.dispatch_action(Action::Send(ctx, smallvec::smallvec![rev_face]))
                .await;
            return;
        }

        let action = self.strategy.process(ctx).await;
        self.dispatch_action(action).await;
    }

    async fn nack_pipeline(&self, ctx: PacketContext) {
        let nack = match &ctx.packet {
            DecodedPacket::Nack(n) => n,
            _ => return,
        };

        if !self.nacks_allowed_on_face(ctx.face_id) {
            debug!(target: t::FWD_PIT, face=?ctx.face_id, "nack on multi-access/ad-hoc face, dropping");
            return;
        }

        let name = match &ctx.name {
            Some(n) => n.clone(),
            None => return,
        };

        // PIT key is the bare Interest name; selectors live on each in-record.
        let token = PitToken::from_interest(&nack.interest.name);

        let has_pit_entry = self.strategy.pit.contains(&token);
        if !has_pit_entry {
            debug!(target: t::FWD_PIT, face=?ctx.face_id, "nack for unknown PIT entry, dropping");
            return;
        }

        let fib_entry_arc = self.strategy.fib.lpm(&name);
        let fib_entry_ref = fib_entry_arc.as_deref();
        let strategy_fib: Option<ndn_strategy::FibEntry> =
            fib_entry_ref.map(|e| ndn_strategy::FibEntry {
                nexthops: e
                    .nexthops
                    .iter()
                    .map(|nh| ndn_strategy::FibNexthop {
                        face_id: nh.face_id,
                        cost: nh.cost,
                    })
                    .collect(),
            });

        // See StrategyStage::process — skip the per-packet AnyMap when no
        // enricher is registered (known signals come from `signals`).
        let built_extensions;
        let extensions: &ndn_transport::AnyMap = if self.strategy.enrichers.is_empty() {
            static EMPTY: std::sync::LazyLock<ndn_transport::AnyMap> =
                std::sync::LazyLock::new(ndn_transport::AnyMap::new);
            &EMPTY
        } else {
            let mut e = ndn_transport::AnyMap::new();
            for enricher in &self.strategy.enrichers {
                enricher.enrich(strategy_fib.as_ref(), &mut e);
            }
            built_extensions = e;
            &built_extensions
        };

        // Upstreams already tried for this PIT entry — excluded from Nack
        // failover so two mutually-nacking nexthops don't ping-pong (D.09).
        let tried_faces: smallvec::SmallVec<[FaceId; 4]> = self
            .strategy
            .pit
            .with_entry(&token, |e| {
                e.out_records.iter().map(|r| FaceId(r.face_id)).collect()
            })
            .unwrap_or_default();

        let sctx = ndn_strategy::StrategyContext {
            name: &name,
            in_face: ctx.face_id,
            fib_entry: strategy_fib.as_ref(),
            pit_token: Some(token),
            tried_faces: &tried_faces,
            measurements: &self.strategy.measurements,
            signals: self.strategy.signals.as_ref(),
            extensions,
            runtime: &self.strategy.runtime,
        };

        let nack_reason = match nack.reason.unwrap_or(ndn_packet::NackReason::NoRoute) {
            ndn_packet::NackReason::NoRoute => NackReason::NoRoute,
            ndn_packet::NackReason::Duplicate => NackReason::Duplicate,
            ndn_packet::NackReason::Congestion => NackReason::Congestion,
            ndn_packet::NackReason::NotYet => NackReason::NotYet,
            ndn_packet::NackReason::Other(_) => NackReason::NoRoute,
        };

        let strategy = self
            .strategy
            .strategy_table
            .lpm(&name)
            .unwrap_or_else(|| Arc::clone(&self.strategy.default_strategy));
        let action = strategy.on_nack_erased(&sctx, nack_reason);
        match action {
            ForwardingAction::Forward(faces) => {
                let interest_wire = nack.interest.raw().clone();
                // Record the failover send as an out-record so a subsequent
                // Nack from this new upstream excludes it too (D.09).
                let nonce = nack.interest.nonce();
                let now = web_time::SystemTime::now()
                    .duration_since(web_time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;
                for face_id in &faces {
                    if let Some(nonce) = nonce {
                        self.strategy
                            .pit
                            .with_entry_mut(&token, |e| e.add_out_record(face_id.0, nonce, now));
                    }
                    if let Some(state) = self.face_states.get(face_id) {
                        state.counters.out_interests.fetch_add(1, Ordering::Relaxed);
                    }
                    // out_bytes is counted once, in the send loop, where the
                    // framed wire length is known.
                    self.enqueue_send(
                        *face_id,
                        interest_wire.clone(),
                        crate::engine::EgressIntent::default(),
                    )
                    .await;
                }
            }
            ForwardingAction::Nack(_reason) => {
                if let Some((_, entry)) = self.strategy.pit.remove(&token) {
                    let interest_wire = nack.interest.raw().clone();
                    let packet_reason = nack.reason.unwrap_or(ndn_packet::NackReason::NoRoute);
                    for face_id_raw in entry.in_record_faces() {
                        let face_id = FaceId(face_id_raw);
                        if !self.nacks_allowed_on_face(face_id) {
                            debug!(target: t::FWD_STRATEGY, face=%face_id, "nack propagation suppressed on multi-access/ad-hoc in-record face");
                            continue;
                        }
                        let intent = crate::engine::EgressIntent {
                            nack: Some(packet_reason),
                            ..Default::default()
                        };
                        // NFD NOutNacks.
                        if let Some(state) = self.face_states.get(&face_id) {
                            state.counters.out_nacks.fetch_add(1, Ordering::Relaxed);
                        }
                        self.enqueue_send(face_id, interest_wire.clone(), intent)
                            .await;
                    }
                }
            }
            ForwardingAction::Suppress
            | ForwardingAction::ForwardAfter { .. }
            | ForwardingAction::Broadcast => {
                debug!(target: t::FWD_STRATEGY, "nack suppressed by strategy");
            }
        }
    }

    async fn data_pipeline(&self, ctx: PacketContext) {
        // G1 congestion bridge (opt-in; `None` ⇒ one untaken branch). A returning
        // Data carrying an NDNLP congestion mark means the link it arrived over is
        // congesting; record it for the per-face signal the strategy reads. Done
        // before PIT match so a mark counts as link-level info regardless of routing.
        if let Some(fb) = &self.congestion_feedback
            && ctx.tags.get::<crate::stages::decode::CongestionMark>().is_some()
        {
            fb.observe(ctx.face_id);
        }

        let ctx = match self.pit_match.process(ctx) {
            Action::Continue(ctx) => ctx,
            Action::Drop(r) => {
                debug!(target: t::FWD_PIT, reason=?r, "data dropped at pit-match");
                return;
            }
            other => {
                self.dispatch_action(other).await;
                return;
            }
        };

        // Unsolicited Data (no matching PIT entry) is never forwarded
        // (`out_faces` is empty). Whether it is *cached* is the
        // UnsolicitedDataPolicy's call (NFD onDataUnsolicited): drop by default,
        // or opportunistically cache when overheard on a broadcast/ad-hoc
        // bearer. Admission still flows through validation below, so only
        // verified Data ever enters the CS (fail-secure).
        if ctx.unsolicited {
            let scope = self
                .face_table
                .get(ctx.face_id)
                .map(|f| f.scope())
                .unwrap_or(FaceScope::NonLocal);
            if !self.unsolicited_policy.admits(scope) {
                debug!(target: t::FWD_PIT, face=%ctx.face_id, "unsolicited data dropped (policy)");
                return;
            }
        }

        // Local faces (IPC or a loopback remote) are trusted by OS-level
        // access control; skip crypto for them. A remote WS/WT/WebRTC peer is
        // NonLocal here, so its Data is verified — unlike the old kind-only
        // classification, which trusted any browser peer.
        //
        // A face may opt OUT of the local fast-path via
        // `require_data_validation` (multi-tenant host: forged Data from one
        // local app must not poison the shared CS or spoof another app's
        // namespace). When required, validation runs as for a NonLocal face,
        // and fail-closes if no validator is configured.
        let is_local = self
            .face_table
            .get(ctx.face_id)
            .map(|f| f.scope() == FaceScope::Local)
            .unwrap_or(false);
        let require_local_validation = is_local
            && self
                .face_states
                .get(&ctx.face_id)
                .is_some_and(|s| s.require_data_validation());

        let ctx = if is_local && !require_local_validation {
            let mut ctx = ctx;
            ctx.verified = true;
            ctx
        } else {
            if require_local_validation && self.validation.validator.is_none() {
                debug!(
                    target: t::SECURITY,
                    face = %ctx.face_id,
                    "data on a require-validation face but no validator configured; dropping (fail-closed)"
                );
                return;
            }
            match self.validation.process(ctx).await {
                Action::Satisfy(ctx) => ctx,
                Action::Drop(r) => {
                    debug!(target: t::SECURITY, reason=?r, "data validation failed");
                    return;
                }
                other => {
                    self.dispatch_action(other).await;
                    return;
                }
            }
        };

        // Self-learning: a Data may carry a PrefixAnnouncement; learn a route
        // from it (validated) before caching/satisfying. Unsolicited Data is
        // cache-only and never drives route installation.
        if !ctx.unsolicited {
            self.try_self_learn(&ctx).await;
        }

        let action = self.cs_insert.process(ctx).await;
        self.dispatch_action(action).await;
    }

    /// Self-learning route install (mirrors NFD self-learning-strategy +
    /// RibManager::slAnnounce). On a Data carrying a PrefixAnnouncement, when
    /// the active strategy for the announced prefix is self-learning, **validate
    /// the announcement** (a separate signed object — *not* the outer Data) and
    /// only then install a route toward the arriving face. Fails closed: no
    /// validator, or an invalid/untrusted announcement, installs nothing.
    async fn try_self_learn(&self, ctx: &PacketContext) {
        use crate::stages::decode::PrefixAnnouncement as PaTag;
        let Some(pa_tag) = ctx.tags.get::<PaTag>() else {
            return;
        };
        let Ok(pa) = ndn_packet::PrefixAnnouncement::decode(pa_tag.0.clone()) else {
            return;
        };
        // Gate: only the self-learning strategy learns from announcements.
        let is_self_learning = self
            .strategy
            .strategy_table
            .lpm(&pa.announced_prefix)
            .is_some_and(|s| {
                s.name()
                    .components()
                    .iter()
                    .any(|c| c.value.as_ref() == b"self-learning")
            });
        if !is_self_learning {
            return;
        }
        // Validate the announcement against trust anchors. No validator → no
        // install (an unverified announcement must never install a route).
        let Some(validator) = self.validation.validator.as_ref() else {
            debug!(target: t::SECURITY, "self-learning: no validator, ignoring PrefixAnnouncement");
            return;
        };
        match validator.validate(&pa.data).await {
            ndn_security::ValidationResult::Valid(_) => {
                // NFD ROUTE_ORIGIN_PREFIXANN = 130.
                let expires_at = pa.expiration.map(|d| web_time::Instant::now() + d);
                self.rib.add(
                    &pa.announced_prefix,
                    crate::rib::RibRoute {
                        face_id: ctx.face_id,
                        origin: 130,
                        cost: 0,
                        flags: 0,
                        expires_at,
                    },
                );
                self.rib
                    .apply_to_fib(&pa.announced_prefix, &self.strategy.fib);
                debug!(target: t::FWD_FIB, prefix=%pa.announced_prefix, face=%ctx.face_id, "self-learning: route installed from PrefixAnnouncement");
            }
            _ => {
                debug!(target: t::SECURITY, prefix=%pa.announced_prefix, "self-learning: PrefixAnnouncement failed validation, no route installed");
            }
        }
    }

    pub(super) async fn run_validation_drain(&self, cancel: CancellationToken) {
        let tick_dur = Duration::from_millis(100);

        loop {
            let sleep = self.runtime.sleep(tick_dur);
            tokio::select! {
                biased;                _ = cancel.cancelled() => break,
                _ = sleep => {
                    let actions = self.validation.drain_pending().await;
                    for action in actions {
                        match action {
                            Action::Satisfy(ctx) => {
                                let action = self.cs_insert.process(ctx).await;
                                self.dispatch_action(action).await;
                            }
                            other => self.dispatch_action(other).await,
                        }
                    }
                }
            }
        }
    }

    /// Consult the rate-limit hook for an inbound packet. `Ok(ctx)` if the
    /// hook permits (or none installed); `Err(action)` short-circuits with
    /// `Drop(RateLimited)` or `Nack(Congestion)`. Boxed to keep the success
    /// path small (clippy `result_large_err`).
    fn check_rate_limit_inbound(&self, ctx: PacketContext) -> Result<PacketContext, Box<Action>> {
        let Some(hook) = self.rate_limit.as_ref() else {
            return Ok(ctx);
        };
        let Some(name) = ctx.name.as_ref() else {
            return Ok(ctx);
        };
        let (kind, is_interest) = match &ctx.packet {
            DecodedPacket::Interest(_) => (crate::rate_limit_hook::PacketKind::Interest, true),
            DecodedPacket::Data(_) => (crate::rate_limit_hook::PacketKind::Data, false),
            _ => return Ok(ctx),
        };
        let decision = hook.check_inbound(ctx.face_id, name, kind, ctx.raw_bytes.len());
        match decision {
            crate::rate_limit_hook::Decision::Permit => Ok(ctx),
            crate::rate_limit_hook::Decision::Drop => {
                debug!(
                    target: t::FWD_PIPELINE,
                    face = %ctx.face_id,
                    name = ?ctx.name,
                    "rate-limit: inbound dropped"
                );
                Err(Box::new(Action::Drop(DropReason::RateLimited)))
            }
            crate::rate_limit_hook::Decision::Nack if is_interest => {
                debug!(
                    target: t::FWD_PIPELINE,
                    face = %ctx.face_id,
                    name = ?ctx.name,
                    "rate-limit: inbound Interest NACKed (Congestion)"
                );
                Err(Box::new(Action::Nack(ctx, NackReason::Congestion)))
            }
            crate::rate_limit_hook::Decision::Nack => {
                // NACK is not meaningful for Data; fall back to silent drop.
                debug!(
                    target: t::FWD_PIPELINE,
                    face = %ctx.face_id,
                    name = ?ctx.name,
                    "rate-limit: inbound Data dropped (NACK not valid for Data)"
                );
                Err(Box::new(Action::Drop(DropReason::RateLimited)))
            }
        }
    }

    /// Consult the rate-limit hook for an outbound packet. Returns `true` if
    /// the packet may pass, `false` to drop.
    pub(super) fn check_rate_limit_outbound(
        &self,
        face: FaceId,
        name: Option<&ndn_packet::Name>,
        is_interest: bool,
        wire_bytes: usize,
    ) -> bool {
        let Some(hook) = self.rate_limit.as_ref() else {
            return true;
        };
        let Some(name) = name else {
            return true;
        };
        let kind = if is_interest {
            crate::rate_limit_hook::PacketKind::Interest
        } else {
            crate::rate_limit_hook::PacketKind::Data
        };
        let decision = hook.check_outbound(face, name, kind, wire_bytes);
        matches!(decision, crate::rate_limit_hook::Decision::Permit)
    }
}
