//! Concurrent fetches sharing one `Node` (one `DemuxConnection`) each receive
//! exactly the reply that answers their own Interest.
//!
//! The scripted-forwarder tests drive the connection by hand, so reply order,
//! Nacks and late replies are chosen exactly; the engine tests run the same
//! invariants end to end through a real forwarder.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;

use ndn_app::{AppError, Connection, EngineAppExt, EngineBuilder, Node};
use ndn_engine::EngineConfig;
use ndn_packet::encode::{DataBuilder, InterestBuilder, encode_nack};
use ndn_packet::{Interest, NackReason, Name, NameComponent, tlv_type};

/// The app side of a scripted forwarder: what the app sends comes out of
/// `sent`, what the test pushes into `replies` is what the app receives.
struct ScriptedFace {
    sent: mpsc::UnboundedSender<Bytes>,
    replies: Mutex<mpsc::UnboundedReceiver<Bytes>>,
}

#[async_trait::async_trait]
impl Connection for ScriptedFace {
    async fn send(&self, wire: Bytes) -> Result<(), AppError> {
        self.sent.send(wire).map_err(|_| AppError::Closed)
    }

    async fn recv(&self) -> Option<Bytes> {
        self.replies.lock().await.recv().await
    }

    async fn register_prefix(&self, _prefix: &Name) -> Result<(), AppError> {
        Ok(())
    }
}

/// The forwarder end of a [`ScriptedFace`].
struct Forwarder {
    sent: mpsc::UnboundedReceiver<Bytes>,
    replies: mpsc::UnboundedSender<Bytes>,
}

impl Forwarder {
    /// The next Interest the app expressed.
    async fn interest(&mut self) -> Interest {
        let wire = tokio::time::timeout(Duration::from_secs(5), self.sent.recv())
            .await
            .expect("an Interest within 5 s")
            .expect("face open");
        Interest::decode(wire).expect("an Interest")
    }

    fn data(&self, name: &Name, content: &str) {
        let wire = DataBuilder::new(name.clone(), content.as_bytes()).sign_digest_sha256();
        self.replies.send(wire).expect("app side open");
    }

    fn nack(&self, interest: &Interest) {
        let wire = encode_nack(NackReason::NoRoute, interest.raw());
        self.replies.send(wire).expect("app side open");
    }
}

fn scripted() -> (Arc<ScriptedFace>, Forwarder) {
    let (sent_tx, sent_rx) = mpsc::unbounded_channel();
    let (reply_tx, reply_rx) = mpsc::unbounded_channel();
    let face = Arc::new(ScriptedFace {
        sent: sent_tx,
        replies: Mutex::new(reply_rx),
    });
    (
        face,
        Forwarder {
            sent: sent_rx,
            replies: reply_tx,
        },
    )
}

fn name(uri: &str) -> Name {
    uri.parse().expect("valid name")
}

fn content(data: &ndn_packet::Data) -> String {
    String::from_utf8(data.content().expect("content").to_vec()).expect("utf-8")
}

/// N fetches in flight at once, answered in the reverse of the order they were
/// sent: every fetch gets the Data for its own name, none is lost or swapped.
#[tokio::test]
async fn concurrent_fetches_each_get_their_own_data() {
    const N: usize = 16;
    let (face, mut fwd) = scripted();
    let node = Arc::new(Node::from_connection(face));

    let fetches: Vec<_> = (0..N)
        .map(|i| {
            let node = Arc::clone(&node);
            tokio::spawn(async move { node.fetch(name(&format!("/item/{i}"))).await })
        })
        .collect();

    let mut interests = Vec::with_capacity(N);
    for _ in 0..N {
        interests.push(fwd.interest().await);
    }
    for interest in interests.iter().rev() {
        fwd.data(&interest.name, &interest.name.to_string());
    }

    for (i, fetch) in fetches.into_iter().enumerate() {
        let data = fetch.await.expect("task").expect("fetch answered");
        let want = name(&format!("/item/{i}"));
        assert_eq!(*data.name, want);
        assert_eq!(content(&data), want.to_string());
    }
}

/// A Nack fails exactly the fetch whose Interest it carries; the other fetch
/// in flight is untouched and still gets its Data.
#[tokio::test]
async fn a_nack_reaches_only_the_fetch_it_answers() {
    let (face, mut fwd) = scripted();
    let node = Arc::new(Node::from_connection(face));

    // `/served` is first in line on the connection, so a shared reply queue
    // would hand it the Nack.
    let served = {
        let node = Arc::clone(&node);
        tokio::spawn(async move { node.fetch(name("/served")).await })
    };
    fwd.interest().await;
    let refused = {
        let node = Arc::clone(&node);
        tokio::spawn(async move { node.fetch(name("/refused")).await })
    };
    let refused_interest = fwd.interest().await;
    fwd.nack(&refused_interest);
    // Give the Nack time to be (mis)routed before the Data exists.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!served.is_finished(), "the Nack must not end the other fetch");
    fwd.data(&name("/served"), "ok");

    assert!(matches!(
        refused.await.expect("task"),
        Err(AppError::Nacked {
            reason: Some(NackReason::NoRoute)
        })
    ));
    assert_eq!(content(&served.await.expect("task").expect("served")), "ok");
}

/// Overlapping fetches are satisfied per NDN matching: one Data answers every
/// pending fetch it matches (two exact fetches of its name, a `CanBePrefix`
/// fetch of an ancestor, a fetch by its implicit digest), and leaves a fetch
/// it does not match waiting for its own Data.
#[tokio::test]
async fn overlapping_fetches_are_all_satisfied() {
    let (face, mut fwd) = scripted();
    let node = Node::from_connection(face);

    let one = name("/x/1");
    let one_wire = DataBuilder::new(one.clone(), b"one").sign_digest_sha256();
    let digest = ndn_packet::Data::decode(one_wire.clone())
        .expect("data")
        .implicit_digest();
    let by_digest = one.clone().append_component(NameComponent::new(
        tlv_type::IMPLICIT_SHA256,
        Bytes::copy_from_slice(&digest),
    ));

    // Each fetch is its own `Consumer` on the node's one (demultiplexed) connection.
    let fetch = |builder: InterestBuilder| {
        let mut consumer = ndn_app::Consumer::new(node.connection());
        tokio::spawn(async move { consumer.fetch_with(builder).await })
    };
    let exact_a = fetch(InterestBuilder::new(one.clone()));
    let exact_b = fetch(InterestBuilder::new(one.clone()));
    let prefix = fetch(InterestBuilder::new(name("/x")).can_be_prefix());
    let digest_fetch = fetch(InterestBuilder::new(by_digest));
    let two = fetch(InterestBuilder::new(name("/x/2")));
    for _ in 0..5 {
        fwd.interest().await;
    }

    // One Data for /x/1, sent once — the forwarder aggregates the face's
    // Interests and returns a single copy.
    fwd.replies.send(one_wire).expect("app side open");
    for (label, f) in [
        ("exact", exact_a),
        ("exact again", exact_b),
        ("CanBePrefix", prefix),
        ("implicit digest", digest_fetch),
    ] {
        let data = tokio::time::timeout(Duration::from_secs(2), f)
            .await
            .unwrap_or_else(|_| panic!("{label} fetch satisfied by the one Data"))
            .expect("task")
            .expect("fetch answered");
        assert_eq!(*data.name, one, "{label}");
        assert_eq!(content(&data), "one", "{label}");
    }

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!two.is_finished(), "/x/1 must not satisfy a fetch of /x/2");
    fwd.data(&name("/x/2"), "two");
    let data = two.await.expect("task").expect("fetch answered");
    assert_eq!(content(&data), "two");
}

/// A reply arriving after its fetch gave up reaches nobody: it is not queued
/// for a reader that may never come, the next fetch is not blocked by it, and
/// the abandoned Interest is forgotten once its lifetime ends.
#[tokio::test]
async fn a_reply_nobody_waits_for_is_discarded() {
    let (face, mut fwd) = scripted();
    let node = Node::from_connection(face);
    let conn = node.connection();
    let lifetime = Duration::from_millis(200);

    let mut consumer = ndn_app::Consumer::new(node.connection());
    let gave_up = consumer
        .fetch_with(InterestBuilder::new(name("/late")).lifetime(lifetime))
        .await;
    assert!(matches!(gave_up, Err(AppError::Timeout)));
    let late = fwd.interest().await;

    // The reply to the abandoned Interest, still within its lifetime.
    fwd.data(&late.name, "too late");
    assert!(
        tokio::time::timeout(Duration::from_millis(100), conn.recv())
            .await
            .is_err(),
        "the late reply must not be queued for raw readers"
    );
    let next = {
        let mut consumer = ndn_app::Consumer::new(node.connection());
        tokio::spawn(async move { consumer.fetch(name("/next")).await })
    };
    let interest = fwd.interest().await;
    fwd.data(&interest.name, "next");
    assert_eq!(content(&next.await.expect("task").expect("next")), "next");

    // Past the lifetime the abandoned Interest is gone: a Data of that name
    // now matches nothing pending and is handed to raw readers like any other
    // unsolicited packet.
    tokio::time::sleep(lifetime + Duration::from_millis(100)).await;
    fwd.data(&late.name, "unsolicited");
    let raw = tokio::time::timeout(Duration::from_secs(1), conn.recv())
        .await
        .expect("delivered to the raw queue")
        .expect("open");
    let data = ndn_packet::Data::decode(raw).expect("data");
    assert_eq!(content(&data), "unsolicited");
}

/// End to end through a real forwarder: N concurrent fetches on one `Node`,
/// answered by a producer that replies in reverse order, each get their own
/// Data.
#[tokio::test]
async fn engine_concurrent_fetches_on_one_node() {
    const N: u64 = 24;
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .build()
        .await
        .expect("engine build");
    let cancel = CancellationToken::new();
    let producer = engine.app_node(cancel.child_token());
    let consumer = Arc::new(engine.app_node(cancel.child_token()));

    let _guard = producer
        .serve(name("/item"), |interest, reply| async move {
            // Later items answer sooner, so replies arrive out of order.
            let i: u64 = interest.name.components()[1]
                .value
                .iter()
                .fold(0, |n, d| n * 10 + u64::from(d - b'0'));
            tokio::time::sleep(Duration::from_millis(5 * (N - i))).await;
            let _ = reply
                .respond((*interest.name).clone(), interest.name.to_string())
                .await;
        })
        .await
        .expect("serve");

    let fetches: Vec<_> = (0..N)
        .map(|i| {
            let consumer = Arc::clone(&consumer);
            tokio::spawn(async move { consumer.fetch(name(&format!("/item/{i}"))).await })
        })
        .collect();
    for (i, fetch) in fetches.into_iter().enumerate() {
        let data = fetch.await.expect("task").expect("fetch answered");
        assert_eq!(content(&data), format!("/item/{i}"));
    }

    drop(cancel);
    drop(engine);
    shutdown.shutdown().await;
}

/// Two segmented objects fetched concurrently on one `Node` share segment
/// numbers; each reassembles its own bytes.
#[tokio::test]
async fn engine_concurrent_object_fetches_on_one_node() {
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .build()
        .await
        .expect("engine build");
    let cancel = CancellationToken::new();
    let producer = engine.app_node(cancel.child_token());
    let consumer = engine.app_node(cancel.child_token());

    let a = vec![0xAAu8; 60_000];
    let b = vec![0xBBu8; 60_000];
    let _ga = producer
        .serve_object(name("/obj/a"), a.clone())
        .await
        .expect("serve a");
    let _gb = producer
        .serve_object(name("/obj/b"), b.clone())
        .await
        .expect("serve b");

    let fa = tokio::spawn(consumer.object(name("/obj/a")).fetch());
    let fb = tokio::spawn(consumer.object(name("/obj/b")).fetch());
    assert_eq!(&fa.await.expect("task").expect("a")[..], &a[..]);
    assert_eq!(&fb.await.expect("task").expect("b")[..], &b[..]);

    drop(cancel);
    drop(engine);
    shutdown.shutdown().await;
}
