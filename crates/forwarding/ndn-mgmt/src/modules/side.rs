//! `/localhost/nfd/side/{list,quarantine}` — the forwarder's fan-out table for
//! side (channel) frames (ndn-rs extension, not an NFD module). See
//! [`ndn_engine::side`].
//!
//! Verbs:
//! - `list` — read-only status text: the counters (routes, sinks, frames and
//!   octets in and out, every drop by reason, the side PIT's `query:` line:
//!   breadcrumbs held and every refusal of a `QUERY` or an `ANSWER`, every refused install by
//!   reason), one line per route (id in hex, source face, each sink with the
//!   time left before it lapses, frames, octets, age), and the faces barred
//!   now. Changes nothing.
//! - `quarantine` — bar a face: `FaceId` (required; this command does not
//!   default to the requesting face) and an optional `ExpirationPeriod` in
//!   **milliseconds** (the NFD field). Without it the bar is the face's next
//!   one by its history (60 s, doubling for each repeat up to 1 h, back to 60 s
//!   after an hour clean; a call while a bar is live changes nothing and names
//!   what is left of it); with a value, that long, at most 1 h; `0` lifts the
//!   bar. A barred face has the side frames it sends dropped (`quarantined`)
//!   and no route installed from it; its own sinks' `Keep`s and `Unsub`s still
//!   count, and the NDN traffic over it goes on. The response names the length
//!   applied in `ExpirationPeriod`.
//!
//! Local operators only: a command for this module over `/localhop` is refused
//! (that path is for a neighbour's `rib/register` and `rib/unregister`).
//!
//! Being an ndn-rs-only module, every verb requires a signed command Interest
//! (the dispatcher enforces this for non-NFD-canonical modules).

use std::fmt::Write as _;
use std::time::Duration;

use async_trait::async_trait;
use ndn_engine::ForwarderEngine;
use ndn_mgmt_wire::{
    ControlParameters, ControlResponse,
    control_response::status,
    nfd_command::{module, verb},
};

use crate::MgmtResponse;
use crate::module::{MgmtContext, MgmtModule};

fn side_list(engine: &ForwarderEngine) -> ControlResponse {
    let side = engine.side();
    let s = side.stats();
    let mut text = String::new();
    let _ = writeln!(
        text,
        "routes={} sinks={} frames_in={} bytes_in={} frames_out={} bytes_out={}",
        s.routes, s.sinks, s.frames_in, s.bytes_in, s.frames_out, s.bytes_out
    );
    let _ = writeln!(
        text,
        "drops: unrouted={} wrong_source={} malformed={} class_unsupported={} quota={} \
         quarantined={} sink_full={} sink_error={}",
        s.unrouted,
        s.wrong_source,
        s.malformed,
        s.class_unsupported,
        s.quota,
        s.quarantined,
        s.sink_full,
        s.sink_error
    );
    let _ = writeln!(
        text,
        "held_back={} (frames a local sender was told Full for and keeps: not drops)",
        s.held_back
    );
    let _ = writeln!(
        text,
        "stream_held={} (stream frames a link's stream lane waited for room for: not drops) \
         stream_stalled={} (waited the bound, then routed: a full sink lost them) \
         stream_demoted={} (sinks that held the stream for the bound: lossy for a penalty, the \
         log names the face)",
        s.stream_held, s.stream_stalled, s.stream_demoted
    );
    let _ = writeln!(
        text,
        "up: keeps={} keeps_forwarded={} unsubs={} sinks_lapsed={}",
        s.keeps, s.keeps_forwarded, s.unsubs, s.sinks_lapsed
    );
    let _ = writeln!(
        text,
        "query: breadcrumbs={} queries={} answers={} rate_refused={} pit_dup={} pit_full={} \
         pit_face_full={} pit_route_full={} unmatched={} late={}",
        s.breadcrumbs,
        s.queries,
        s.answers,
        s.query_rate_refused,
        s.pit_dup,
        s.pit_full,
        s.pit_face_full,
        s.pit_route_full,
        s.unmatched,
        s.late
    );
    let _ = writeln!(
        text,
        "refused installs: table_full={} source_full={} sink_cap={} sink_face_full={} \
         source_mismatch={} sink_is_source={} quarantined={} face_gone={} not_carried={} \
         not_asked={}",
        s.refused_table_full,
        s.refused_source_full,
        s.refused_sink_cap,
        s.refused_sink_face_full,
        s.refused_source_mismatch,
        s.refused_sink_is_source,
        s.refused_quarantined,
        s.refused_face_gone,
        s.refused_not_carried,
        s.refused_not_asked
    );
    for route in side.list() {
        let sinks: Vec<String> = route
            .sinks
            .iter()
            .map(|k| format!("{}({:.1}s)", k.face.0, k.expires_in.as_secs_f64()))
            .collect();
        let _ = writeln!(
            text,
            "route id={:016x} source={} sinks=[{}] frames={} bytes={} age={:.1}s",
            route.id,
            route.source.0,
            sinks.join(" "),
            route.frames,
            route.bytes,
            route.age.as_secs_f64()
        );
    }
    let now = side.now();
    for (face, until) in side.quarantined() {
        let _ = writeln!(
            text,
            "quarantined face={} remaining={:.1}s",
            face.0,
            Duration::from_nanos(until.saturating_sub(now)).as_secs_f64()
        );
    }
    ControlResponse::ok_empty(text)
}

fn side_quarantine(params: ControlParameters, engine: &ForwarderEngine) -> ControlResponse {
    let Some(face) = params
        .face_id
        .filter(|&f| f != 0)
        .map(ndn_transport::FaceId)
    else {
        return ControlResponse::error(
            status::BAD_PARAMS,
            "side/quarantine needs a FaceId: name the face to bar (see faces/list, side/list)",
        );
    };
    let side = engine.side();
    let now = side.now();
    let applied_ms = match params.expiration_period {
        Some(0) => {
            side.lift(face);
            0
        }
        Some(ms) => {
            if engine.faces().get(face).is_none() {
                return no_such_face(face);
            }
            side.quarantine_for(face, now, Duration::from_millis(ms))
                .as_millis() as u64
        }
        None => {
            if engine.faces().get(face).is_none() {
                return no_such_face(face);
            }
            side.bar(face, now).as_millis() as u64
        }
    };
    tracing::warn!(
        target: "mgmt.side", face = face.0, bar_ms = applied_ms,
        "side frames from the face are {}",
        if applied_ms == 0 { "no longer barred" } else { "barred" }
    );
    ControlResponse::ok(
        if applied_ms == 0 {
            "bar lifted"
        } else {
            "face barred"
        },
        ControlParameters {
            face_id: Some(face.0),
            expiration_period: Some(applied_ms),
            ..Default::default()
        },
    )
}

fn no_such_face(face: ndn_transport::FaceId) -> ControlResponse {
    ControlResponse::error(
        status::BAD_PARAMS,
        format!(
            "no face {} on this forwarder: name a face from faces/list (a bar of length 0 lifts one)",
            face.0
        ),
    )
}

pub(crate) struct SideModule;

#[async_trait]
impl MgmtModule for SideModule {
    fn name(&self) -> &'static [u8] {
        module::SIDE
    }

    async fn dispatch(
        &self,
        verb_name: &[u8],
        params: ControlParameters,
        ctx: &MgmtContext<'_>,
    ) -> MgmtResponse {
        let engine = ctx.engine;
        let resp = match verb_name {
            v if v == verb::LIST => side_list(engine),
            v if v == verb::QUARANTINE => side_quarantine(params, engine),
            _ => ControlResponse::error(status::NOT_FOUND, "unknown side verb"),
        };
        resp.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_engine::side::SideId;
    use ndn_engine::{EngineBuilder, EngineConfig, ForwarderEngine};
    use ndn_transport::FaceId;
    use ndn_transport::{FaceKind, Transport};
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    fn ctx<'a>(
        engine: &'a ForwarderEngine,
        cancel: &'a CancellationToken,
        config: &'a dyn crate::MgmtConfig,
    ) -> MgmtContext<'a> {
        MgmtContext {
            engine,
            cancel,
            source_face: None,
            face_provisioners: &[],
            control_surfaces: &[],
            config,
            #[cfg(not(target_arch = "wasm32"))]
            pib: None,
            security_is_ephemeral: false,
            log_inspector: None,
            coding_handler: None,
            rate_limit_handler: None,
            compute_handler: None,
            webtransport_status_handler: None,
            ble_handler: None,
            approval_handler: None,
            invite_handler: None,
            trust_context_handler: None,
            #[cfg(not(target_arch = "wasm32"))]
            runtime_policy: None,
            face_events: None,
            route_events: None,
            strategy_events: None,
        }
    }

    /// A face that exists on the engine and does nothing.
    struct Quiet(FaceId);
    impl Transport for Quiet {
        fn id(&self) -> FaceId {
            self.0
        }
        fn kind(&self) -> FaceKind {
            FaceKind::Internal
        }
        async fn send_bytes(&self, _wire: bytes::Bytes) -> Result<(), ndn_transport::FaceError> {
            Ok(())
        }
        async fn recv_bytes(&self) -> Result<bytes::Bytes, ndn_transport::FaceError> {
            std::future::pending().await
        }
    }

    async fn call(
        engine: &ForwarderEngine,
        verb: &[u8],
        params: ControlParameters,
    ) -> ControlResponse {
        let cancel = CancellationToken::new();
        let config = crate::module::TestMgmtConfig::default();
        match SideModule
            .dispatch(verb, params, &ctx(engine, &cancel, &config))
            .await
        {
            MgmtResponse::Control(cr) => *cr,
            _ => panic!("expected a control response"),
        }
    }

    fn face_param(id: u64, ms: Option<u64>) -> ControlParameters {
        ControlParameters {
            face_id: Some(id),
            expiration_period: ms,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn list_shows_the_routes_and_counters_and_changes_nothing() {
        let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
            .face(Quiet(FaceId(1)))
            .face(Quiet(FaceId(2)))
            .build()
            .await
            .unwrap();
        engine
            .side()
            .install(
                SideId(0xABCD),
                FaceId(1),
                FaceId(2),
                Duration::from_secs(30),
            )
            .unwrap();

        let resp = call(&engine, b"list", ControlParameters::default()).await;
        assert!(resp.is_ok(), "{}", resp.status_text);
        let text = &resp.status_text;
        assert!(text.contains("routes=1 sinks=1"), "{text}");
        assert!(
            text.contains("route id=000000000000abcd source=1"),
            "{text}"
        );
        assert!(text.contains("sinks=[2("), "{text}");
        assert!(text.contains("unrouted=0"), "{text}");
        assert_eq!(engine.side().stats().routes, 1, "a read changes nothing");
        shutdown.shutdown().await;
    }

    /// A face that takes every side frame and does nothing else.
    struct Takes(FaceId);
    impl Transport for Takes {
        fn id(&self) -> FaceId {
            self.0
        }
        fn kind(&self) -> FaceKind {
            FaceKind::Internal
        }
        fn side_frame_max(&self) -> usize {
            10_000
        }
        fn forward_side(
            &self,
            _frame: bytes::Bytes,
            _class: ndn_transport::SideClass,
        ) -> Result<(), ndn_transport::SideRefused> {
            Ok(())
        }
        fn forward_side_from(
            &self,
            _frame: bytes::Bytes,
            _class: ndn_transport::SideClass,
            _ingress: FaceId,
        ) -> Result<(), ndn_transport::SideRefused> {
            Ok(())
        }
        async fn send_bytes(&self, _wire: bytes::Bytes) -> Result<(), ndn_transport::FaceError> {
            Ok(())
        }
        async fn recv_bytes(&self) -> Result<bytes::Bytes, ndn_transport::FaceError> {
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn list_shows_the_breadcrumbs_and_why_a_query_or_an_answer_was_refused() {
        use ndn_transport::SideClass;
        use ndn_transport::side_header::{AnswerPrefix, QueryPrefix};

        let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
            .face(Takes(FaceId(1)))
            .face(Takes(FaceId(2)))
            .build()
            .await
            .unwrap();
        let side = engine.side();
        side.install(
            SideId(0xABCD),
            FaceId(1),
            FaceId(2),
            Duration::from_secs(30),
        )
        .unwrap();
        let query = |token: u64| {
            let mut v = QueryPrefix {
                id: 0xABCD,
                token,
                ttl_ticks: 10,
            }
            .encode()
            .to_vec();
            v.resize(60, 0);
            bytes::Bytes::from(v)
        };
        let answer = |token: u64| {
            let mut v = AnswerPrefix {
                class: SideClass::Datagram,
                id: 0xABCD,
                token,
            }
            .encode()
            .to_vec();
            v.resize(60, 0);
            bytes::Bytes::from(v)
        };
        side.on_frame(FaceId(2), query(7), &engine.faces()); // a breadcrumb
        side.on_frame(FaceId(2), query(7), &engine.faces()); // a duplicate
        side.on_frame(FaceId(1), answer(8), &engine.faces()); // nobody asked 8

        let resp = call(&engine, b"list", ControlParameters::default()).await;
        assert!(resp.is_ok(), "{}", resp.status_text);
        let text = &resp.status_text;
        assert!(
            text.contains(
                "query: breadcrumbs=1 queries=1 answers=0 rate_refused=0 pit_dup=1 pit_full=0 \
                 pit_face_full=0 pit_route_full=0 unmatched=1 late=0"
            ),
            "{text}"
        );
        shutdown.shutdown().await;
    }

    #[tokio::test]
    async fn quarantine_bars_a_face_doubling_on_repeat_and_names_the_length() {
        let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
            .face(Quiet(FaceId(1)))
            .build()
            .await
            .unwrap();

        let first = call(&engine, b"quarantine", face_param(1, None)).await;
        assert!(first.is_ok(), "{}", first.status_text);
        assert_eq!(first.body.unwrap().expiration_period, Some(60_000));
        assert!(engine.side().is_quarantined(FaceId(1), engine.side().now()));
        // A call while the bar is live changes nothing: it names what is left, not a doubling.
        let again = call(&engine, b"quarantine", face_param(1, None)).await;
        let left = again.body.unwrap().expiration_period.unwrap();
        assert!(
            (59_000..=60_000).contains(&left),
            "a repeat while a bar is live names what is left of it, got {left} ms"
        );

        // An explicit length bars for that long; zero lifts the bar.
        let explicit = call(&engine, b"quarantine", face_param(1, Some(5_000))).await;
        assert_eq!(explicit.body.unwrap().expiration_period, Some(5_000));
        let lifted = call(&engine, b"quarantine", face_param(1, Some(0))).await;
        assert!(lifted.is_ok(), "{}", lifted.status_text);
        assert!(
            !engine.side().is_quarantined(FaceId(1), engine.side().now()),
            "a bar of zero length lifts the bar"
        );
        // The history stays: the next bar, after the first ended, is doubled.
        let second = call(&engine, b"quarantine", face_param(1, None)).await;
        assert_eq!(second.body.unwrap().expiration_period, Some(120_000));
        shutdown.shutdown().await;
    }

    #[tokio::test]
    async fn quarantine_refuses_what_it_cannot_do_and_says_why() {
        let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
            .face(Quiet(FaceId(1)))
            .build()
            .await
            .unwrap();

        // No face named: the command does not guess one.
        let none = call(&engine, b"quarantine", ControlParameters::default()).await;
        assert_eq!(none.status_code, status::BAD_PARAMS);
        assert!(none.status_text.contains("FaceId"), "{}", none.status_text);
        // A face this forwarder does not have.
        let gone = call(&engine, b"quarantine", face_param(99, None)).await;
        assert_eq!(gone.status_code, status::BAD_PARAMS);
        assert!(gone.status_text.contains("99"), "{}", gone.status_text);
        // An unknown verb.
        let bogus = call(&engine, b"bogus", ControlParameters::default()).await;
        assert_eq!(bogus.status_code, status::NOT_FOUND);
        assert!(engine.side().quarantined().is_empty(), "nothing was barred");
        shutdown.shutdown().await;
    }

    /// An `ExpirationPeriod` too long for a bar is the longest bar (an hour), and the answer
    /// names the length applied: no operator value bars a face for good.
    #[tokio::test]
    async fn an_expiration_period_longer_than_the_longest_bar_is_capped_and_says_so() {
        let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
            .face(Quiet(FaceId(1)))
            .build()
            .await
            .unwrap();
        let resp = call(&engine, b"quarantine", face_param(1, Some(u64::MAX))).await;
        assert!(resp.is_ok(), "{}", resp.status_text);
        assert_eq!(
            resp.body.unwrap().expiration_period,
            Some(3_600_000),
            "the length applied is the longest bar"
        );
        let side = engine.side();
        assert!(
            !side.is_quarantined(FaceId(1), side.now() + 3_601 * 1_000_000_000),
            "a bar of u64::MAX milliseconds never ended"
        );
        shutdown.shutdown().await;
    }
}
