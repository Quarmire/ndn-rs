//! The ask's signature time is the node's own clock (`Config::clock`), the clock the sender judges
//! it by, not the host's wall clock: a node whose clock is not the wall's (a simulated one, a
//! device whose clock was set) is still answered.

use std::sync::Arc;
use std::time::Duration;

use ndn_app::EngineAppExt;
use ndn_engine::EngineBuilder;
use ndn_foundation_types::Name;
use ndn_packet::Interest;
use tokio_util::sync::CancellationToken;

use super::standing::{Who, gate};
use crate::error::Timestamp;
use crate::fold::Readers;
use crate::node::tests::{cfg, space, world};
use crate::node::{Node, Transport};
use crate::space::Share;
use crate::test_kit::n;
use crate::wire::chan_prefix;

/// How far the nodes' clock is from the wall's: more than the 120 s the setup allows.
const OFF_MS: u64 = 3_600_000;

fn ready(node: &Node) -> bool {
    node.inner.space_of(&space()).is_some_and(|held| {
        let log = held.log.lock();
        gate(&log, &node.inner.judge, Who::Listed, "test").is_ok()
            && (!log.sealed() || log.fold.in_force().is_some())
    })
}

/// Alice and Bob, whose clocks both read an hour ahead of the wall's, and Bob asks Alice's
/// channel: the ask carries a time of Bob's clock, so Alice, judging by hers, answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ask_is_stamped_by_the_nodes_clock_and_answered_where_that_is_not_the_wall_clock() {
    let devs = world(&["/alice/laptop", "/bob/phone"]).await;
    let (engine, shutdown) = EngineBuilder::new(Default::default())
        .build()
        .await
        .expect("an engine");
    shutdown.detach();
    for dev in &devs {
        let ns = Name::from_components(dev.name.components()[..1].iter().cloned());
        ndn_namespace::sync_group::carry(&engine, &ns);
    }
    let cancel = CancellationToken::new();
    let mut nodes = Vec::new();
    for dev in &devs {
        let mut config = cfg();
        config.settle = Duration::from_secs(3);
        config.svs.jitter_ms = 20;
        config.svs.suppression_period = Duration::from_millis(30);
        config.svs.sync_interval = Duration::from_secs(1);
        let wall = Arc::clone(&config.clock);
        config.clock = Arc::new(move || Timestamp(wall().0 + OFF_MS));
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
                config,
            )
            .await
            .expect("the node starts"),
        );
    }
    let (alice, bob) = (&nodes[0], &nodes[1]);
    alice
        .create(
            &space(),
            Share {
                readers: Readers::Persons(vec![n("/bob")]),
                writers: vec![],
            },
        )
        .await
        .expect("alice creates the space");
    bob.open(&space()).await.expect("bob opens it");
    for _ in 0..300 {
        if nodes.iter().all(ready) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(nodes.iter().all(ready), "the nodes hold the record");

    let info = bob.ask_channel(&space(), alice.name()).await;
    assert!(
        info.is_ok(),
        "an ask made on a node whose clock is an hour off the wall's was not answered: {info:?}"
    );

    // The signed Interest itself carries the node's clock, not the wall's.
    let ask = super::wire::ChanAsk {
        space: space(),
        prefix: Name::root(),
        mode: super::wire::ChannelMode::Latest,
        recipient: bob.recipient().public(),
        carriers: vec![super::wire::carrier::DATAGRAM],
        lifetime: 3600,
        epoch: None,
        since: None,
        new: false,
        chain: bob.inner.signer_chain(),
    };
    let wire = bob
        .sign_interest(&chan_prefix(alice.name()), &ask.encode().unwrap())
        .unwrap();
    let stamped = Interest::decode(wire)
        .unwrap()
        .sig_info()
        .and_then(|s| s.sig_time)
        .expect("a signed ask carries a signature time");
    let clock = bob.inner.now();
    assert!(
        stamped.abs_diff(clock) < 5_000,
        "the ask is stamped {stamped} ms, the node's clock reads {clock} ms"
    );
}
