//! A `ForwarderClient` reads management replies and data from one control
//! face. A prefix registered while a receive loop is already waiting on that
//! face must get its `rib/register` reply, and the data after it must reach
//! the receive loop — whatever the timing. Against a fake forwarder on a Unix
//! socket; no sleeps: the single-threaded runtime parks the receive loop in
//! `recv()` before the test task resumes.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_face::local::{IpcFace, IpcListener};
use ndn_ipc::{ForwarderClient, ForwarderError};
use ndn_mgmt_wire::ControlResponse;
use ndn_packet::encode::DataBuilder;
use ndn_packet::lp::{LpPacket, is_lp_packet};
use ndn_packet::{Data, Interest, Name};
use ndn_transport::{FaceId, FaceKind, Transport};
use tokio::sync::mpsc;

/// Bound on the whole exchange, so a lost reply fails the test instead of
/// hanging it. Never reached when the reply is routed right.
const BOUND: Duration = Duration::from_secs(10);

fn data(name: &str) -> Bytes {
    DataBuilder::new(name.parse::<Name>().unwrap(), b"x").sign_digest_sha256()
}

fn unwrap_lp(raw: Bytes) -> Bytes {
    if is_lp_packet(&raw)
        && let Ok(lp) = LpPacket::decode(raw.clone())
        && let Some(fragment) = lp.fragment
    {
        return fragment;
    }
    raw
}

fn name_of(wire: Bytes) -> String {
    Data::decode(wire).expect("a Data").name.to_string()
}

/// A fake forwarder at a fresh socket path, and a client connected to it the
/// way `ndn-app`'s `Node::connect` connects (the Unix data plane).
async fn fake_forwarder(test: &str) -> (ForwarderClient, IpcFace) {
    let path = std::env::temp_dir().join(format!("ndn-ipc-{test}-{}.sock", std::process::id()));
    let path = path.to_str().unwrap().to_owned();
    let listener = IpcListener::bind(&path).expect("bind the fake forwarder");
    let (client, forwarder) = tokio::join!(
        ForwarderClient::connect_unix_only(&path),
        listener.accept_as(FaceId(1), FaceKind::App)
    );
    listener.cleanup();
    (client.expect("connect"), forwarder.expect("accept"))
}

/// A receive loop on `client` that reports every packet it gets.
fn receive_loop(client: &Arc<ForwarderClient>) -> mpsc::UnboundedReceiver<Bytes> {
    let (tx, rx) = mpsc::unbounded_channel();
    let client = Arc::clone(client);
    tokio::spawn(async move {
        while let Some(pkt) = client.recv().await {
            if tx.send(pkt).is_err() {
                break;
            }
        }
    });
    rx
}

#[tokio::test]
async fn register_reply_reaches_the_registration_while_a_receive_loop_waits() {
    let (client, forwarder) = fake_forwarder("register").await;
    let client = Arc::new(client);
    let mut received = receive_loop(&client);

    // The loop takes the first Data and, on this single-threaded runtime,
    // runs on into its next `recv()` before this task resumes: from here on
    // it is waiting on the face.
    forwarder.send_bytes(data("/app/before")).await.unwrap();
    assert_eq!(name_of(received.recv().await.unwrap()), "/app/before");

    // The forwarder answers the registration, then sends more data.
    let answer = async {
        let interest = Interest::decode(unwrap_lp(forwarder.recv_bytes().await.unwrap()))
            .expect("the rib/register Interest");
        let reply = DataBuilder::new(
            (*interest.name).clone(),
            &ControlResponse::ok_empty("OK").encode(),
        )
        .sign_digest_sha256();
        forwarder.send_bytes(reply).await.unwrap();
        forwarder.send_bytes(data("/app/after")).await.unwrap();
    };
    let prefix: Name = "/app".parse().unwrap();
    let (registered, ()) = tokio::time::timeout(BOUND, async {
        tokio::join!(client.register_prefix(&prefix), answer)
    })
    .await
    .expect("the rib/register reply reaches register_prefix");
    registered.expect("rib/register succeeds");

    let next = tokio::time::timeout(BOUND, received.recv())
        .await
        .expect("the receive loop gets the data after the reply")
        .unwrap();
    assert_eq!(
        name_of(next),
        "/app/after",
        "the receive loop gets the data, not the management reply"
    );
}

#[tokio::test]
async fn registration_fails_closed_when_the_forwarder_goes_away_unanswered() {
    let (client, forwarder) = fake_forwarder("closed").await;
    let client = Arc::new(client);
    let _received = receive_loop(&client);

    let hang_up = async {
        forwarder
            .recv_bytes()
            .await
            .expect("the rib/register Interest");
        drop(forwarder);
    };
    let prefix: Name = "/app".parse().unwrap();
    let (registered, ()) = tokio::time::timeout(BOUND, async {
        tokio::join!(client.register_prefix(&prefix), hang_up)
    })
    .await
    .expect("an unanswered registration ends when the forwarder hangs up");
    assert!(
        matches!(registered, Err(ForwarderError::Closed)),
        "got {registered:?}"
    );
    assert!(client.is_dead());
}
