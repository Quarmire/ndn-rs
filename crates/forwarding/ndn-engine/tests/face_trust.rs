//! A face's *trust* decides Data validation and caching, not its *scope*
//! (trust-context.md §6.6): a TCP face to a loopback address is local in
//! scope (`/localhost` names stay on this host) but is a network face to
//! trust — any process on the host can open it — so a forged Data arriving
//! on it is refused, never cached and never served. A program face (an
//! in-process app face, a Unix socket whose peer the kernel identified)
//! keeps the fast path: its Data is not validated and is cached.
//!
//! Each rig is a forwarder under the default profile with no trust anchors
//! (every signed Data from a validated face is refused `untrusted-root`), a
//! consumer app face, and one upstream face of the kind under test. The
//! upstream answers the consumer's Interest for `/t/doc` with a Data signed by
//! a key nobody certified. The witness is what the consumer is told and
//! whether a second Interest for the same name is answered from the content
//! store (the upstream is not asked again) or reaches the upstream again.

use std::time::Duration;

use bytes::Bytes;
use ndn_engine::{EngineBuilder, EngineConfig, ForwarderEngine, ShutdownHandle};
use ndn_face::{IpcListener, ipc_face_connect, tcp_face_connect, tcp_face_from_stream};
use ndn_face_local::{InProcFace, InProcHandle};
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::lp::{LpPacket, encode_lp_nack};
use ndn_packet::{Data, NackReason, Name, Refusal, SignatureType};
use ndn_security::{Ed25519Signer, SecurityProfile, Signer};
use ndn_transport::{Face, FaceId, FaceKind, StreamFace, TlvCodec};
use tokio_util::sync::CancellationToken;

const CONSUMER: u64 = 1;
const UPSTREAM: u64 = 2;

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

/// The other end of the upstream face: what the test plays the producer with.
enum Peer {
    InProc(InProcHandle),
    Wire(Face),
}

impl Peer {
    async fn send(&self, wire: Bytes) {
        match self {
            Peer::InProc(h) => h.send(wire).await.expect("peer send"),
            Peer::Wire(f) => f.send_bytes(wire).await.expect("peer send"),
        }
    }

    /// Send `wire` as it is, with no link framing of its own (a Nack that is
    /// already an LpPacket).
    async fn send_raw(&self, wire: Bytes) {
        match self {
            Peer::InProc(h) => h.send(wire).await.expect("peer send"),
            Peer::Wire(f) => f.transport.send_bytes(wire).await.expect("peer send"),
        }
    }

    async fn recv(&self, ms: u64) -> Option<Bytes> {
        let fut = async {
            match self {
                Peer::InProc(h) => h.recv().await,
                Peer::Wire(f) => f.transport.recv_bytes().await.ok(),
            }
        };
        tokio::time::timeout(Duration::from_millis(ms), fut)
            .await
            .ok()
            .flatten()
    }
}

async fn recv_timeout(h: &InProcHandle, ms: u64) -> Option<Bytes> {
    tokio::time::timeout(Duration::from_millis(ms), h.recv())
        .await
        .ok()
        .flatten()
}

fn payload_of(wire: &Bytes) -> Option<Bytes> {
    match LpPacket::decode(wire.clone()) {
        Ok(lp) => lp.fragment,
        Err(_) => Some(wire.clone()),
    }
}

fn is_interest(wire: &Bytes) -> bool {
    payload_of(wire).is_some_and(|p| p.first() == Some(&0x05))
}

/// The refusal a reply carries, `None` for anything else.
fn refusal_of(wire: &Bytes) -> Option<Refusal> {
    LpPacket::decode(wire.clone()).ok()?.nack?.reason?.refusal()
}

fn is_data(wire: &Bytes) -> bool {
    match LpPacket::decode(wire.clone()) {
        Ok(lp) => lp.nack.is_none() && lp.fragment.is_some_and(|p| Data::decode(p).is_ok()),
        Err(_) => Data::decode(wire.clone()).is_ok(),
    }
}

/// `/t/doc` signed by a key no anchor covers: a forgery as far as this
/// forwarder can tell.
fn forged_doc() -> Bytes {
    let signer = Ed25519Signer::from_seed(&[5; 32], n("/t/KEY/k"));
    DataBuilder::new(n("/t/doc"), b"forged").sign_sync(
        SignatureType::SignatureEd25519,
        Some(signer.key_name()),
        |region| signer.sign_sync(region).unwrap(),
    )
}

struct Rig {
    consumer: InProcHandle,
    peer: Peer,
    engine: ForwarderEngine,
    shutdown: ShutdownHandle,
}

async fn build(
    upstream_is_app_face: bool,
) -> (
    ForwarderEngine,
    ShutdownHandle,
    InProcHandle,
    Option<InProcHandle>,
) {
    let (consumer_face, consumer) = InProcFace::new(FaceId(CONSUMER), 64);
    let mut builder = EngineBuilder::new(EngineConfig::default())
        .security_profile(SecurityProfile::Default)
        .face(consumer_face);
    let mut app_peer = None;
    if upstream_is_app_face {
        let (face, handle) = InProcFace::new(FaceId(UPSTREAM), 64);
        builder = builder.face(face);
        app_peer = Some(handle);
    }
    let (engine, shutdown) = builder.build().await.expect("engine build");
    (engine, shutdown, consumer, app_peer)
}

async fn rig_app() -> Rig {
    let (engine, shutdown, consumer, peer) = build(true).await;
    Rig {
        consumer,
        peer: Peer::InProc(peer.unwrap()),
        engine,
        shutdown,
    }
}

/// The upstream is a real TCP face over the loopback interface.
async fn rig_loopback_tcp() -> Rig {
    let (engine, shutdown, consumer, _) = build(false).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (client, accepted) = tokio::join!(tcp_face_connect(FaceId(0), addr), listener.accept());
    let (stream, _) = accepted.unwrap();
    engine.add_face(
        tcp_face_from_stream(FaceId(UPSTREAM), stream),
        CancellationToken::new(),
    );
    Rig {
        consumer,
        peer: Peer::Wire(Face::from_transport(client.unwrap())),
        engine,
        shutdown,
    }
}

/// The upstream is a Unix socket the forwarder accepted: the kernel gave it
/// the peer's credentials.
async fn rig_unix_with_credentials() -> Rig {
    let (engine, shutdown, consumer, _) = build(false).await;
    let path = std::env::temp_dir().join(format!("ndn-face-trust-{}.sock", std::process::id()));
    let listener = IpcListener::bind(path.to_str().unwrap()).unwrap();
    let (client, accepted) = tokio::join!(
        ipc_face_connect(FaceId(0), path.to_str().unwrap()),
        listener.accept_as(FaceId(UPSTREAM), FaceKind::App)
    );
    engine.add_face(accepted.unwrap(), CancellationToken::new());
    listener.cleanup();
    Rig {
        consumer,
        peer: Peer::Wire(Face::from_transport(client.unwrap())),
        engine,
        shutdown,
    }
}

/// The upstream is a Unix-kind stream face nobody asked the kernel about: no
/// credentials, so no evidence that a program is on the other end.
async fn rig_unix_without_credentials() -> Rig {
    let (engine, shutdown, consumer, _) = build(false).await;
    let (a, b) = tokio::net::UnixStream::pair().unwrap();
    let (ar, aw) = a.into_split();
    engine.add_face(
        StreamFace::new(
            FaceId(UPSTREAM),
            FaceKind::Unix,
            None,
            None,
            ar,
            aw,
            TlvCodec,
        ),
        CancellationToken::new(),
    );
    let (r, w) = b.into_split();
    let client: StreamFace<_, _, TlvCodec> =
        StreamFace::new(FaceId(0), FaceKind::Unix, None, None, r, w, TlvCodec);
    Rig {
        consumer,
        peer: Peer::Wire(Face::from_transport(client)),
        engine,
        shutdown,
    }
}

/// What the consumer was told when the upstream answered with the forgery,
/// and what happened to a second Interest for the same name.
struct Outcome {
    /// The first reply to the consumer.
    first: Option<Bytes>,
    /// The upstream saw the second Interest (the forgery was not cached).
    asked_again: bool,
    /// The consumer's second answer, if any.
    second: Option<Bytes>,
}

async fn forge_through(rig: &Rig) -> Outcome {
    let engine = &rig.engine;
    engine.fib().add_nexthop(&n("/t"), FaceId(UPSTREAM), 0);
    let ask = || {
        InterestBuilder::new(n("/t/doc"))
            .lifetime(Duration::from_secs(4))
            .build()
    };
    rig.consumer.send(ask()).await.expect("send Interest");
    let at_upstream = rig
        .peer
        .recv(1000)
        .await
        .expect("the Interest reaches the upstream");
    assert!(is_interest(&at_upstream));
    rig.peer.send(forged_doc()).await;
    let first = recv_timeout(&rig.consumer, 800).await;

    rig.consumer
        .send(ask())
        .await
        .expect("send second Interest");
    let asked_again = rig.peer.recv(500).await.is_some_and(|w| is_interest(&w));
    let second = recv_timeout(&rig.consumer, 300).await;
    Outcome {
        first,
        asked_again,
        second,
    }
}

/// Forged Data on a loopback TCP face: refused (the consumer is told why),
/// never cached, never served. Fails against a forwarder that trusts a face
/// for its loopback address.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forged_data_on_a_loopback_tcp_face_is_refused_and_never_cached() {
    let rig = rig_loopback_tcp().await;
    let out = forge_through(&rig).await;
    let first = out.first.expect("the consumer hears back");
    assert!(
        !is_data(&first),
        "forged Data on a loopback TCP face was delivered to the consumer"
    );
    assert_eq!(refusal_of(&first), Some(Refusal::UntrustedRoot));
    assert!(
        out.asked_again,
        "the second Interest was answered from the content store: the forgery was cached"
    );
    assert!(
        out.second.is_none_or(|w| !is_data(&w)),
        "a forged Data was served to the second Interest"
    );
    rig.shutdown.shutdown().await;
}

/// A face that is a Unix socket without credentials is as unproven as a TCP
/// face: its Data is validated.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forged_data_on_a_unix_face_without_credentials_is_refused_and_never_cached() {
    let rig = rig_unix_without_credentials().await;
    let out = forge_through(&rig).await;
    let first = out.first.expect("the consumer hears back");
    assert!(
        !is_data(&first),
        "forged Data on a credential-less Unix face was delivered"
    );
    assert_eq!(refusal_of(&first), Some(Refusal::UntrustedRoot));
    assert!(out.asked_again, "the forgery was cached");
    rig.shutdown.shutdown().await;
}

/// An in-process app face is a program: its Data is not validated, is served
/// and is cached (the second Interest is answered without asking again).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn data_on_an_app_face_is_served_and_cached() {
    let rig = rig_app().await;
    let out = forge_through(&rig).await;
    assert!(is_data(&out.first.expect("Data delivered")));
    assert!(!out.asked_again, "the app face's Data was not cached");
    assert!(is_data(&out.second.expect("served from the content store")));
    rig.shutdown.shutdown().await;
}

/// A Unix socket whose peer the kernel identified is a program face.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn data_on_a_unix_socket_with_peer_credentials_is_served_and_cached() {
    let rig = rig_unix_with_credentials().await;
    let out = forge_through(&rig).await;
    assert!(is_data(&out.first.expect("Data delivered")));
    assert!(!out.asked_again, "the Unix face's Data was not cached");
    assert!(is_data(&out.second.expect("served from the content store")));
    rig.shutdown.shutdown().await;
}

/// The consumer asks `/t/doc`; the upstream answers the Interest it was
/// forwarded with a refusal Nack ("revoked"). What the consumer hears.
async fn refusal_claimed_by_upstream(rig: &Rig) -> Bytes {
    rig.engine.fib().add_nexthop(&n("/t"), FaceId(UPSTREAM), 0);
    let interest = InterestBuilder::new(n("/t/doc"))
        .lifetime(Duration::from_secs(4))
        .build();
    rig.consumer.send(interest).await.expect("send Interest");
    let at_upstream = rig
        .peer
        .recv(1000)
        .await
        .expect("the Interest reaches the upstream");
    let interest = payload_of(&at_upstream).expect("an Interest");
    rig.peer
        .send_raw(encode_lp_nack(
            NackReason::Refused(Refusal::Revoked),
            &interest,
        ))
        .await;
    recv_timeout(&rig.consumer, 800)
        .await
        .expect("the consumer hears back")
}

fn nack_reason(wire: &Bytes) -> Option<NackReason> {
    LpPacket::decode(wire.clone()).ok()?.nack?.reason
}

/// That a key is revoked is the word of a validating forwarder the consumer
/// can believe, not of whoever opened a loopback socket: a refusal claimed by
/// a loopback TCP upstream reaches the consumer as NoRoute.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refusal_claimed_on_a_loopback_tcp_face_is_no_route() {
    let rig = rig_loopback_tcp().await;
    let got = refusal_claimed_by_upstream(&rig).await;
    assert_eq!(nack_reason(&got), Some(NackReason::NoRoute));
    rig.shutdown.shutdown().await;
}

/// A refusal from a program face (a forwarder of this host over its Unix
/// socket, an in-process peer) is kept for the local consumer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refusal_from_a_program_face_is_kept() {
    for rig in [rig_app().await, rig_unix_with_credentials().await] {
        let got = refusal_claimed_by_upstream(&rig).await;
        assert_eq!(refusal_of(&got), Some(Refusal::Revoked));
        rig.shutdown.shutdown().await;
    }
}
