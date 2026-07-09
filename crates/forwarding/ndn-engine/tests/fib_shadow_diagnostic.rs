//! The longest-prefix-match shadow diagnostic (skyfall FIELD-REPORT-2 §2 — "the
//! invisible-error killer").
//!
//! The bug class: LPM returns exactly ONE entry, so a coarse route and an exact-prefix
//! registration at different lengths never merge — whichever prefix is longer silently
//! wins, and the loser's face gets **nothing**: zero packets, no error (it cost skyfall
//! half a day). The diagnostic makes the forwarder's silent decision visible: the
//! `fwd.fib` event names the MATCHED entry's prefix and its nexthop faces, so the face
//! you expected but don't see is a one-line diagnosis.
//!
//! Red-capable: the load-bearing assertions are on `matched_prefix` — the field the
//! pre-fix event did not carry (it logged the queried name as "prefix", which can never
//! reveal a shadow because it is always equal to what you asked for).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_local::{InProcFace, InProcHandle};
use ndn_packet::encode::InterestBuilder;
use ndn_transport::FaceId;

const CONSUMER: u64 = 1;
const APP: u64 = 2;
const PEER: u64 = 3;

async fn recv_timeout(h: &InProcHandle) -> Option<bytes::Bytes> {
    tokio::time::timeout(Duration::from_millis(300), h.recv())
        .await
        .ok()
        .flatten()
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);
impl Capture {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}
impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Capture {
        self.clone()
    }
}

/// The skyfall shadow, reconstructed: an app face registered at the EXACT prefix
/// `/svc/data` (cost 0, the `register_prefix` shape) and a coarse route `/svc` → a peer
/// face, installed expecting it to carry traffic. An Interest under `/svc/data/…`
/// matches ONLY the longer entry: the peer face silently gets nothing — and the
/// diagnostic names exactly which entry won and which faces it carries.
#[tokio::test]
async fn a_shadowed_route_is_named_by_the_diagnostic() {
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("fwd.fib=trace"))
        .with_ansi(false)
        .with_writer(capture.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let (fc, hc) = InProcFace::new(FaceId(CONSUMER), 128);
    let (fa, ha) = InProcFace::new(FaceId(APP), 128);
    let (fp, hp) = InProcFace::new(FaceId(PEER), 128);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(fc)
        .face(fa)
        .face(fp)
        .build()
        .await
        .expect("engine build");

    // The app's exact-prefix registration (what `register_prefix` installs)…
    engine
        .fib()
        .add_nexthop(&"/svc/data".parse().unwrap(), FaceId(APP), 0);
    // …and the coarse route the operator THINKS will carry the traffic to the peer.
    engine
        .fib()
        .add_nexthop(&"/svc".parse().unwrap(), FaceId(PEER), 10);

    let interest = InterestBuilder::new("/svc/data/item/1")
        .lifetime(Duration::from_secs(2))
        .build();
    hc.send(interest).await.unwrap();

    // The silent half (the failure mode as skyfall lived it): the app face received the
    // Interest, the peer face received NOTHING — and no error anywhere.
    assert!(recv_timeout(&ha).await.is_some(), "the longer entry's face gets the Interest");
    assert!(
        recv_timeout(&hp).await.is_none(),
        "the shadowed route's face silently gets nothing — this is the bug class"
    );

    // The diagnostic half: the fwd.fib event names the entry that actually won.
    let text = capture.text();
    let line = text
        .lines()
        .find(|l| l.contains("matched_prefix"))
        .unwrap_or_else(|| panic!("no diagnostic event emitted — the shadow stays invisible:\n{text}"));
    assert!(
        line.contains("matched_prefix=/svc/data"),
        "the diagnostic names the WINNING entry (not the queried name): {line}"
    );
    assert!(
        line.contains("matched_depth=2"),
        "the matched prefix length makes the shadow legible: {line}"
    );
    assert!(
        line.contains("FaceId(2)") && !line.contains("FaceId(3)"),
        "the nexthop set shows the app face and NOT the shadowed peer face: {line}"
    );

    shutdown.shutdown().await;
}

/// The healthy contrast: routes at the SAME prefix merge into one entry (both faces in
/// its nexthops) — the diagnostic shows both, so "same prefix = merged, different
/// length = shadowed" is directly observable from the two events.
#[tokio::test]
async fn same_prefix_routes_merge_and_the_diagnostic_shows_both_faces() {
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("fwd.fib=trace"))
        .with_ansi(false)
        .with_writer(capture.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let (fc, hc) = InProcFace::new(FaceId(CONSUMER), 128);
    let (fa, _ha) = InProcFace::new(FaceId(APP), 128);
    let (fp, _hp) = InProcFace::new(FaceId(PEER), 128);
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .face(fc)
        .face(fa)
        .face(fp)
        .build()
        .await
        .expect("engine build");

    engine
        .fib()
        .add_nexthop(&"/svc/data".parse().unwrap(), FaceId(APP), 0);
    engine
        .fib()
        .add_nexthop(&"/svc/data".parse().unwrap(), FaceId(PEER), 10);

    let interest = InterestBuilder::new("/svc/data/item/1")
        .lifetime(Duration::from_secs(2))
        .build();
    hc.send(interest).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let text = capture.text();
    let line = text
        .lines()
        .find(|l| l.contains("matched_prefix"))
        .expect("diagnostic emitted");
    assert!(
        line.contains("FaceId(2)") && line.contains("FaceId(3)"),
        "same-prefix nexthops merged — both faces visible in one entry: {line}"
    );

    shutdown.shutdown().await;
}
