//! Two nodes of the heap layer, each over its own IPC connection to one daemon: one node's
//! `emit` reaches the other's `get`, the channel's frames crossing the daemon's side table as
//! side records on the two unix streams (channel.md §14.9, §14.10).

#![cfg(unix)]

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_app::{Connection, EngineBuilder, ForwarderEngine, IpcConnection};
use ndn_engine::EngineConfig;
use ndn_face::local::ProgramPeers;
use ndn_heap::{
    ChannelMode, Config, EmitOptions, GetOptions, Heap, Items, Modes, Node, Readers, Select, Share,
    Transport,
};
use ndn_ipc::ForwarderClient;
use ndn_mgmt::{MgmtHandles, mount_management, run_face_listener};
use ndn_packet::Name;
use ndn_security::{SecurityManager, SignedTrustContext, TrustSchema, Validator};
use tokio_util::sync::CancellationToken;

fn n(uri: &str) -> Name {
    uri.parse().unwrap()
}

/// A daemon: an engine with management mounted and the unix socket listener a local
/// application connects to (the peer's credentials make its face a program face, as the
/// daemon's own user's is).
struct Daemon {
    engine: ForwarderEngine,
    cancel: CancellationToken,
    socket: String,
    _dir: tempfile::TempDir,
    _shutdown: ndn_app::ShutdownHandle,
}

async fn daemon() -> Daemon {
    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .build()
        .await
        .expect("engine build");
    let cancel = CancellationToken::new();
    tokio::spawn(mount_management(
        &engine,
        cancel.clone(),
        Arc::new(ndn_config::ForwarderConfig::default()),
        None,
        MgmtHandles::default(),
    ));
    let dir = tempfile::tempdir().expect("tempdir");
    let sock = dir.path().join("ndn.sock");
    let socket = sock.to_str().expect("utf-8 path").to_owned();
    tokio::spawn({
        let (socket, engine, cancel) = (socket.clone(), engine.clone(), cancel.clone());
        async move { run_face_listener(&socket, ProgramPeers::this_user(), engine, cancel).await }
    });
    while !sock.exists() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Daemon {
        engine,
        cancel,
        socket,
        _dir: dir,
        _shutdown: shutdown,
    }
}

impl Daemon {
    async fn ipc(&self) -> Arc<IpcConnection> {
        let client = ForwarderClient::connect(&self.socket)
            .await
            .expect("connect to the daemon's socket");
        Arc::new(IpcConnection::new(client))
    }

    /// A node of the heap layer over its own IPC connections, as `ndn-heap` makes one: a
    /// connection for the node (it carries the channel frames) and one for the sync group.
    async fn node(&self, dev: &Dev) -> Node {
        let conn = self.ipc().await;
        let sync = self.ipc().await;
        let node = Node::start(
            Transport {
                node: ndn_app::Node::from_connection(Arc::clone(&conn) as Arc<dyn Connection>),
                sync: sync as Arc<dyn Connection>,
            },
            dev.name.clone(),
            Arc::clone(&dev.keys),
            Arc::clone(&dev.validator),
            Arc::new(ndn_sync::MemoryStore::new()),
            Config {
                first_look: Duration::from_millis(50),
                ..Config::new()
            },
        )
        .await
        .expect("the node starts over IPC");
        node.attach_forwarder()
            .expect("the IPC connection carries channel frames");
        node
    }
}

/// A device: its name, key and a validator that holds the namespace's anchor and every
/// device's certificate.
struct Dev {
    name: Name,
    keys: Arc<SecurityManager>,
    validator: Arc<Validator>,
}

/// The devices of the namespace `/alice`, each key certified by the namespace's root.
async fn world(devices: &[&str]) -> Vec<Dev> {
    let ns = n("/alice");
    let root = SecurityManager::new();
    let root_key = ns.clone().append("KEY").append("root");
    root.generate_ed25519(root_key.clone()).unwrap();
    let public = root
        .get_signer_sync(&root_key)
        .unwrap()
        .public_key()
        .unwrap();
    let anchor = root.issue_self_signed(&root_key, public, u64::MAX).unwrap();
    let mut made = Vec::new();
    for d in devices {
        let name = n(d);
        let keys = Arc::new(SecurityManager::new());
        let key = keys
            .generate_ed25519(name.clone().append("KEY").append("1"))
            .unwrap();
        let public = keys.get_signer_sync(&key).unwrap().public_key().unwrap();
        let cert = root
            .certify(&key, public, &root_key, 365 * 24 * 3600 * 1000)
            .await
            .unwrap();
        made.push((name, keys, cert));
    }
    made.iter()
        .map(|(name, keys, _)| {
            let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
            let ctx = SignedTrustContext::hierarchical(ns.clone());
            assert!(ctx.add_anchor(anchor.clone()));
            validator.adopt_context(Arc::new(ctx)).unwrap();
            for (_, _, cert) in &made {
                validator.cert_cache().insert(cert.clone());
            }
            Dev {
                name: name.clone(),
                keys: Arc::clone(keys),
                validator,
            }
        })
        .collect()
}

/// A space of `/alice` made by one node and opened by another, both over IPC to `d`, the
/// second holding the record.
async fn shared(d: &Daemon) -> (Node, Heap, Node, Heap) {
    ndn_namespace::sync_group::carry(&d.engine, &n("/alice"));
    let devs = world(&["/alice/laptop", "/alice/phone"]).await;
    let space = n("/alice/32=data/live");
    let sender = d.node(&devs[0]).await;
    let heap = within(
        "the space is made",
        sender.create(
            &space,
            Share {
                readers: Readers::Anyone,
                writers: vec![],
            },
        ),
    )
    .await
    .expect("the space is made over IPC");
    let receiver = d.node(&devs[1]).await;
    let opened = within("the peer opens the space", receiver.open(&space))
        .await
        .expect("the space is opened over IPC");
    within("the peer holds the space's record", async {
        while !opened.ready() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    (sender, heap, receiver, opened)
}

/// `what` within 30 s, or the test ends saying what it was waiting for.
async fn within<T>(what: &str, fut: impl Future<Output = T>) -> T {
    match tokio::time::timeout(Duration::from_secs(30), fut).await {
        Ok(v) => v,
        Err(_) => panic!("{what}: nothing within 30 s"),
    }
}

fn live(heap: &Heap, mode: Option<ChannelMode>) -> Items {
    heap.get(
        Select::Prefix(Name::root()),
        GetOptions {
            kept: false,
            modes: mode.map(Modes::only).unwrap_or_default(),
            ..GetOptions::default()
        },
    )
    .expect("a reader")
}

/// One node emits and the other's `get` takes the message, both over IPC.
#[tokio::test]
async fn a_nodes_emit_reaches_another_nodes_get_over_ipc() {
    let d = daemon().await;
    let (sender, heap, receiver, opened) = shared(&d).await;
    let mut items = live(&opened, None);
    // The first emission and the channel's setup race: emit until one arrives.
    let got = within("an emission reaching the other node's get", async {
        loop {
            heap.emit(
                &n("/pos"),
                Bytes::from_static(b"over-ipc"),
                EmitOptions::latest(),
            )
            .await
            .expect("the owner may emit");
            if let Ok(Some(item)) =
                tokio::time::timeout(Duration::from_millis(300), items.next()).await
            {
                return item;
            }
        }
    })
    .await
    .expect("an item, not a notice");
    assert_eq!(got.path.to_string(), "/pos");
    assert_eq!(&got.bytes[..], b"over-ipc");
    assert!(
        d.engine.side().stats().frames_out >= 1,
        "the frame went through the daemon's side table"
    );
    sender.shutdown();
    receiver.shutdown();
    d.cancel.cancel();
}

/// A burst of `Reliable` messages, each a stream frame, crosses the two sockets and the side
/// table in order and whole while the receiver reads them as they come: the stream lane
/// (1,024 frames) fills and drains, and nothing waits for ever on either socket.
#[tokio::test]
async fn a_reliable_burst_crosses_the_ipc_sockets_in_order() {
    const N: usize = 3000;
    let d = daemon().await;
    let (sender, heap, receiver, opened) = shared(&d).await;
    let mut items = live(&opened, Some(ChannelMode::Reliable));
    // Ask for the channel with one emission, then wait until the path works end to end.
    heap.emit(
        &n("/burst"),
        Bytes::from_static(b"open"),
        EmitOptions::reliable(),
    )
    .await
    .expect("the owner may emit");
    within("the receiver's HELLO", async {
        while !items.hello_seen() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;

    let send = async {
        for i in 0..N {
            let mut body = format!("msg-{i:05}").into_bytes();
            body.resize(900, b'.');
            heap.emit(&n("/burst"), Bytes::from(body), EmitOptions::reliable())
                .await
                .expect("the owner may emit");
        }
    };
    let read = async {
        let mut next = 0;
        while next < N {
            let got = items
                .next()
                .await
                .expect("the stream is open")
                .expect("an item, not a notice");
            if &got.bytes[..] == b"open" {
                continue;
            }
            assert_eq!(
                &got.bytes[..9],
                format!("msg-{next:05}").as_bytes(),
                "messages arrive in order, none lost"
            );
            next += 1;
        }
    };
    within("a burst of reliable messages", async {
        tokio::join!(send, read);
    })
    .await;
    sender.shutdown();
    receiver.shutdown();
    d.cancel.cancel();
}
