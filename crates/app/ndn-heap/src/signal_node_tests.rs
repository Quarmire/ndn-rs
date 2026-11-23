//! The signal gate through two nodes over one real forwarder (spec §11): a
//! member's run header, signed by one node, is admitted by another through
//! `Node::signal_admit`, and a removed writer's is refused from the first call
//! after the removal is held.

use std::sync::Arc;
use std::time::Duration;

use ndn_app::EngineAppExt;
use ndn_engine::EngineBuilder;
use ndn_foundation_types::Name;
use ndn_packet::Data;
use ndn_security::{Ed25519Verifier, VerifyOutcome};
use tokio_util::sync::CancellationToken;

use crate::HeapError;
use crate::error::NextStep;
use crate::fold::Readers;
use crate::node::tests::{Dev, cfg, space, world};
use crate::node::{Config, Node, Transport};
use crate::signal::{RUN_ID_LEN, SignalRefusal};
use crate::space::{MembersChange, Share};
use crate::test_kit::n;
use crate::wire::signal_run_name;

const RUN: [u8; RUN_ID_LEN] = [5; RUN_ID_LEN];

/// Timings that let a vector cross in milliseconds.
fn fast() -> Config {
    let mut c = cfg();
    c.settle = Duration::from_secs(3);
    c.svs.jitter_ms = 20;
    c.svs.suppression_period = Duration::from_millis(30);
    c.svs.sync_interval = Duration::from_secs(1);
    c
}

/// Poll `f` until it holds, or fail with `what`.
async fn eventually<F: Future<Output = bool>>(what: &str, mut f: impl FnMut() -> F) {
    for _ in 0..300 {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("not within 15 s: {what}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_members_header_is_admitted_at_a_peer_node_and_a_removed_writers_is_not() {
    let devs: Vec<Dev> = world(&["/alice/laptop", "/bob/phone"]).await;
    let (engine, shutdown) = EngineBuilder::new(Default::default())
        .build()
        .await
        .expect("an engine");
    shutdown.detach();
    for ns in ["/alice", "/bob"] {
        ndn_namespace::sync_group::carry(&engine, &n(ns));
    }
    let cancel = CancellationToken::new();
    let mut nodes = Vec::new();
    for dev in &devs {
        nodes.push(
            Node::start(
                Transport {
                    node: engine.app_node(cancel.child_token()),
                    sync: engine.app_face(cancel.child_token()),
                },
                dev.name.clone(),
                Arc::clone(&dev.keys),
                Arc::clone(&dev.validator),
                Arc::clone(&dev.store),
                fast(),
            )
            .await
            .expect("the node starts"),
        );
    }
    let (alice, bob) = (&nodes[0], &nodes[1]);
    let heap = alice
        .create(
            &space(),
            Share {
                readers: Readers::Anyone,
                writers: vec![n("/bob")],
            },
        )
        .await
        .unwrap();
    bob.open(&space()).await.unwrap();

    // Before the creation reaches it, a device decides nothing.
    let bob_key = bob.writer().key().clone();
    eventually("bob holds the creation, so it may use signals", || async {
        bob.signal_scope(&space()).is_ok()
    })
    .await;
    let scope = bob.signal_scope(&space()).unwrap();
    assert_eq!(scope.space, space());
    assert!(scope.keys.is_empty(), "a public space is not sealed");

    let wire = bob
        .signal_header(&space(), &RUN, b"run")
        .expect("a writer signs a run header");
    let header = Data::decode(wire).unwrap();
    assert_eq!(*header.name, signal_run_name(bob.name(), &space(), &RUN));
    let got = alice
        .signal_admit(&space(), &header)
        .await
        .expect("a member's header is admitted at the peer");
    assert_eq!(
        (got.key.clone(), got.device, got.namespace),
        (bob_key.clone(), bob.name().clone(), n("/bob"))
    );
    assert_eq!(alice.signal_sender(&space(), &header).unwrap().key, bob_key);
    assert!(alice.signal_member(&space(), &bob_key));

    // The node's own signature over bytes verifies by its public key.
    let signature = alice.sign(b"header octets").unwrap();
    let public = devs[0]
        .keys
        .get_signer_sync(alice.writer().key())
        .unwrap()
        .public_key()
        .unwrap();
    assert_eq!(
        Ed25519Verifier.verify_sync(b"header octets", &signature, &public),
        VerifyOutcome::Valid
    );

    // The owner removes Bob: from the first call after it, his header is a
    // stranger's, and at his own node the gate refuses.
    heap.change(MembersChange {
        remove: vec![n("/bob")],
        ..MembersChange::default()
    })
    .await
    .unwrap();
    assert!(!alice.signal_member(&space(), &bob_key));
    assert_eq!(
        alice.signal_admit(&space(), &header).await,
        Err(SignalRefusal::NotMember {
            scope: space(),
            key: bob_key
        })
    );
    eventually(
        "bob holds the removal and signs no more headers",
        || async {
            match bob.signal_header(&space(), &RUN, b"run") {
                Err(e @ HeapError::NotAllowed { .. }) => e.next() == NextStep::AskOwner,
                _ => false,
            }
        },
    )
    .await;
    assert!(
        bob.signal_scope(&space()).is_ok(),
        "a public space is read by everybody, a removed writer included"
    );
    cancel.cancel();
}
