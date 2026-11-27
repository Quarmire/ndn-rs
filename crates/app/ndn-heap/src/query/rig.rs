//! The rig of the query tests: real nodes over one engine, a space shared among them, and the
//! queries a test builds by hand (a correct one, a sealed one, a hostile one) without going
//! through `get`, so the server is tested alone.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_app::{AppError, Connection, EngineAppExt, LpInfo};
use ndn_engine::EngineBuilder;
use ndn_foundation_types::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_packet::lp::{LpPacket, is_lp_packet};
use ndn_packet::{CachePolicyType, Data, Interest, NackReason};
use ndn_security::PairKeys;
use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

use super::seal::{answer_aad, open_answer, pair_context, query_aad, seal_query};
use crate::chan::standing::{Who, gate};
use crate::fold::Readers;
use crate::node::tests::{Dev, cfg, space, world};
use crate::node::{Config, Node, Transport};
use crate::space::{Heap, MembersChange, Share};
use crate::test_kit::n;
use crate::wire::{
    AnswerBody, AskSeal, EpochId, QueryAnswer, QueryAsk, Status, parse_query_name, query_ask_name,
    query_prefix,
};

/// Timings that let a vector cross in milliseconds.
pub(super) fn fast() -> Config {
    let mut c = cfg();
    c.settle = Duration::from_secs(3);
    c.svs.jitter_ms = 20;
    c.svs.suppression_period = Duration::from_millis(30);
    c.svs.sync_interval = Duration::from_secs(1);
    c
}

/// Poll `f` until it holds, or fail with `what`.
pub(super) async fn eventually(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..300 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("not within 15 s: {what}");
}

/// A face that records the query answers a node sends through it, and the cache policy each
/// went out with.
pub(super) struct Tap {
    inner: Arc<dyn Connection>,
    sent: Mutex<Vec<(Name, Option<CachePolicyType>)>>,
}

impl Tap {
    /// The cache policy the Data `name` was sent with, one entry for each time it was sent.
    pub(super) fn sent(&self, name: &Name) -> Vec<Option<CachePolicyType>> {
        let sent = self.sent.lock();
        sent.iter()
            .filter(|(n, _)| n == name)
            .map(|(_, policy)| *policy)
            .collect()
    }
}

#[async_trait::async_trait]
impl Connection for Tap {
    async fn send(&self, wire: Bytes) -> Result<(), AppError> {
        let (fragment, policy) = if is_lp_packet(&wire) {
            match LpPacket::decode(wire.clone()) {
                Ok(lp) => (lp.fragment, lp.cache_policy),
                Err(_) => (None, None),
            }
        } else {
            (Some(wire.clone()), None)
        };
        if let Some(fragment) = fragment
            && let Ok(data) = Data::decode(fragment)
            && parse_query_name(&data.name).is_some()
        {
            self.sent.lock().push(((*data.name).clone(), policy));
        }
        self.inner.send(wire).await
    }
    async fn recv(&self) -> Option<Bytes> {
        self.inner.recv().await
    }
    async fn recv_with_meta(&self) -> Option<(Bytes, LpInfo)> {
        self.inner.recv_with_meta().await
    }
    async fn register_prefix(&self, prefix: &Name) -> Result<(), AppError> {
        self.inner.register_prefix(prefix).await
    }
}

/// Devices of a world, the first `started` of them started on one engine (the others are bare
/// keys that sign queries by hand: [`bare_query_at`]).
pub(super) struct Rig {
    pub(super) nodes: Vec<Node>,
    /// What each node sent a query answer through.
    pub(super) taps: Vec<Arc<Tap>>,
    /// Each node's sync face: what an announce is sent into by hand.
    pub(super) syncs: Vec<Arc<dyn Connection>>,
    /// Every device of the world, started or not.
    pub(super) devs: Vec<Dev>,
    cancel: CancellationToken,
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// The first `started` of `devs` started on one engine, each node's `Config` (after [`fast`])
/// changed by `tweak(index, config)`.
pub(super) async fn rig_with(
    devs: Vec<Dev>,
    started: usize,
    tweak: impl Fn(usize, &mut Config),
) -> Rig {
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
    let (mut nodes, mut syncs, mut taps) = (Vec::new(), Vec::new(), Vec::new());
    for (i, dev) in devs.iter().take(started).enumerate() {
        let sync = engine.app_face(cancel.child_token());
        syncs.push(Arc::clone(&sync));
        let tap = Arc::new(Tap {
            inner: engine.app_face(cancel.child_token()),
            sent: Mutex::new(Vec::new()),
        });
        taps.push(Arc::clone(&tap));
        let mut config = fast();
        tweak(i, &mut config);
        nodes.push(
            Node::start(
                Transport {
                    node: ndn_app::Node::from_connection(tap as Arc<dyn Connection>),
                    sync,
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
    Rig {
        nodes,
        taps,
        syncs,
        devs,
        cancel,
    }
}

/// The devices named, all started on one engine: a world of the names.
pub(super) async fn rig(devices: &[&str]) -> Rig {
    rig_with(world(devices).await, devices.len(), |_, _| {}).await
}

/// The devices named, the first `started` of them started: the rest sign by hand.
pub(super) async fn rig_started(devices: &[&str], started: usize) -> Rig {
    rig_with(world(devices).await, started, |_, _| {}).await
}

/// This node holds the space's creation, lists its person, and (sealed) the epoch in force.
fn ready(node: &Node) -> bool {
    node.inner.space_of(&space()).is_some_and(|held| {
        let log = held.log.lock();
        gate(&log, &node.inner.judge, Who::Listed, "test").is_ok()
            && (!log.sealed() || log.fold.in_force().is_some())
    })
}

/// The space `/alice/32=data/notes` owned by the first device, `share` and `change` applied, open
/// at every other device, each ready.
pub(super) async fn shared(rig: &Rig, share: Share, change: Option<MembersChange>) -> Heap {
    let heap = rig.nodes[0].create(&space(), share).await.unwrap();
    if let Some(change) = change {
        heap.change(change).await.unwrap();
    }
    for node in &rig.nodes[1..] {
        // A device of a person the space does not list has nothing to open.
        if !node.name().to_string().starts_with("/dave") {
            node.open(&space()).await.unwrap();
        }
    }
    eventually("the nodes hold the record", || {
        rig.nodes
            .iter()
            .filter(|n| n.space(&space()).is_some())
            .all(ready)
    })
    .await;
    heap
}

fn persons(names: &[&str]) -> Vec<Name> {
    names.iter().map(|w| n(w)).collect()
}

/// A public space the owner and `writers` write: every listed person writes, nobody else is
/// listed (a public space lists no reader).
pub(super) async fn public(rig: &Rig, writers: &[&str]) -> Heap {
    let share = Share {
        readers: Readers::Anyone,
        writers: persons(writers),
    };
    shared(rig, share, None).await
}

/// A **sealed** space: `writers` write, `readers` and the writers read.
pub(super) async fn sealed(rig: &Rig, writers: &[&str], readers: &[&str]) -> Heap {
    let mut all = persons(readers);
    all.extend(persons(writers));
    all.sort();
    all.dedup();
    let share = Share {
        readers: Readers::Persons(all),
        writers: persons(writers),
    };
    shared(rig, share, None).await
}

/// The epoch in force at `node`.
pub(super) fn in_force_of(node: &Node) -> Option<EpochId> {
    node.inner
        .space_of(&space())
        .and_then(|held| held.log.lock().fold.in_force())
}

// -- Queries built by hand ---------------------------------------------------------------------

/// A correct plain query from `from`: the path (relative to the space) and the octets, a 3 s
/// deadline, a fresh id, and `from`'s certificates.
pub(super) fn plain_ask(from: &Node, path: &str, bytes: &[u8]) -> QueryAsk {
    plain_ask_for(path, bytes, from.inner.signer_chain())
}

fn plain_ask_for(path: &str, bytes: &[u8], chain: Vec<Bytes>) -> QueryAsk {
    let mut id = [0u8; 8];
    getrandom::getrandom(&mut id).unwrap();
    QueryAsk {
        space: space(),
        path: Some(n(path)),
        id,
        deadline_ms: 3000,
        bytes: Bytes::copy_from_slice(bytes),
        seal: None,
        chain,
    }
}

/// The Interest `<to>/32=query/<digest>` for `params` signed by `signer`'s device key at
/// `signed_at` (milliseconds), its KeyLocator naming `locator`: what a misbehaving or hostile
/// device writes by hand. `params` are whatever bytes a test wants the server to read.
pub(super) fn hostile_query_at(
    signer: &Node,
    locator: &Name,
    to: &Node,
    params: &[u8],
    signed_at: u64,
) -> Bytes {
    let key = Arc::clone(&signer.inner.signer);
    InterestBuilder::new(query_prefix(to.name()))
        .must_be_fresh()
        .lifetime(Duration::from_secs(3))
        .app_parameters(params.to_vec())
        .signature_time(signed_at)
        .sign_sync(key.sig_type(), Some(locator), |region| {
            key.sign_sync(region).unwrap()
        })
}

/// [`hostile_query_at`] signed now, by `signer`'s clock.
pub(super) fn hostile_query(signer: &Node, locator: &Name, to: &Node, params: &[u8]) -> Bytes {
    hostile_query_at(signer, locator, to, params, signer.inner.now())
}

/// A correct plain query that carries no certificate, for a signer that has no node.
pub(super) fn bare_ask(path: &str, bytes: &[u8]) -> QueryAsk {
    plain_ask_for(path, bytes, Vec::new())
}

/// `ask` to `to`, signed at `signed_at` by the device key of `dev`, which needs no node: the
/// server holds the whole world's certificates.
pub(super) fn bare_query_at(dev: &Dev, to: &Node, ask: &QueryAsk, signed_at: u64) -> Bytes {
    let key = dev.keys.signing_identity_for(&dev.name).unwrap().key;
    let signer = dev.keys.get_signer_sync(&key).unwrap();
    InterestBuilder::new(query_prefix(to.name()))
        .must_be_fresh()
        .lifetime(Duration::from_secs(3))
        .app_parameters(ask.encode().unwrap().to_vec())
        .signature_time(signed_at)
        .sign_sync(signer.sig_type(), Some(&key), |region| {
            signer.sign_sync(region).unwrap()
        })
}

/// `from`'s correct signed query `ask` to `to`, signed at `signed_at`.
pub(super) fn signed_query_at(from: &Node, to: &Node, ask: &QueryAsk, signed_at: u64) -> Bytes {
    hostile_query_at(from, from.writer(), to, &ask.encode().unwrap(), signed_at)
}

/// `from`'s correct signed query `ask` to `to`, signed now.
pub(super) fn signed_query(from: &Node, to: &Node, ask: &QueryAsk) -> Bytes {
    signed_query_at(from, to, ask, from.inner.now())
}

/// The Interest a signed query's octets decode to.
pub(super) fn interest_of(wire: &Bytes) -> Interest {
    Interest::decode(wire.clone()).unwrap()
}

/// Send `wire` from `node` and wait at most `wait` for the Data or the Nack.
pub(super) async fn send_for(node: &Node, wire: Bytes, wait: Duration) -> Result<Data, AppError> {
    node.consumer().fetch_wire(wire, wait).await
}

/// [`send_for`] with 5 s.
pub(super) async fn send(node: &Node, wire: Bytes) -> Result<Data, AppError> {
    send_for(node, wire, Duration::from_secs(5)).await
}

/// Whether `r` is the Nack `reason`.
pub(super) fn nacked(r: &Result<Data, AppError>, reason: NackReason) -> bool {
    matches!(r, Err(AppError::Nacked { reason: Some(r) }) if *r == reason)
}

/// The `QUERY_ANSWER` a Data carries.
pub(super) fn answer_of(data: &Data) -> QueryAnswer {
    QueryAnswer::decode(data.content().expect("a Data with content").clone()).unwrap()
}

/// The status a public space's answer carries.
pub(super) fn status_of(data: &Data) -> Status {
    match answer_of(data).body {
        AnswerBody::Plain(status) => status,
        AnswerBody::Sealed { .. } => panic!("a plain answer, not a sealed one"),
    }
}

/// Whether `data` verifies as `server`'s device-signed packet, as an asker judges it.
pub(super) async fn signed_by(asker: &Node, server: &Node, data: &Data) -> bool {
    let carried = answer_of(data).certs;
    matches!(
        asker
            .inner
            .judge
            .validate_asker_packet(data, server.name(), &space(), &carried)
            .await,
        crate::trust::Judged::Valid(_)
    )
}

/// The pair `from` holds with `to` for one epoch of a sealed space: derived once, as the asker
/// does, and the counter its queries are sealed under.
pub(super) struct Pair {
    keys: PairKeys,
    ephemeral: [u8; 32],
    epoch: EpochId,
    next: std::sync::atomic::AtomicU64,
}

/// What a sealed query is, to open its answer: the id and the counter.
pub(super) struct Sent {
    pub(super) id: [u8; 8],
    pub(super) seq: u64,
}

/// Derive the pair keys `from` holds with `to` for `epoch` of the space.
pub(super) fn pair(from: &Node, to: &Node, epoch: &EpochId) -> Pair {
    let context = pair_context(&space(), from.name(), to.name(), epoch);
    let (ephemeral, keys) = ndn_security::pair_keys_to(&to.recipient().public(), &context).unwrap();
    Pair {
        keys,
        ephemeral,
        epoch: epoch.clone(),
        next: std::sync::atomic::AtomicU64::new(0),
    }
}

impl Pair {
    /// A sealed ask of `path` and `bytes` from `from` to `to`, and what opens its answer.
    pub(super) fn ask(&self, from: &Node, to: &Node, path: &str, bytes: &[u8]) -> (QueryAsk, Sent) {
        let seq = self.next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut id = [0u8; 8];
        getrandom::getrandom(&mut id).unwrap();
        let aad = query_aad(
            to.name(),
            from.name(),
            &space(),
            &self.epoch,
            &self.ephemeral,
            seq,
            &id,
        );
        let inner = QueryAsk::seal_inner(&n(path), bytes);
        let ask = QueryAsk {
            space: space(),
            path: None,
            id,
            deadline_ms: 3000,
            bytes: seal_query(&self.keys, seq, &aad, &inner),
            seal: Some(AskSeal {
                ephemeral: self.ephemeral,
                epoch: self.epoch.clone(),
                seq,
            }),
            chain: from.inner.signer_chain(),
        };
        (ask, Sent { id, seq })
    }

    /// The status the sealed answer `data` carries to `sent`, opened under `Ka`; `None` if it
    /// does not open (or is plain).
    pub(super) fn open(&self, from: &Node, to: &Node, sent: &Sent, data: &Data) -> Option<Status> {
        let AnswerBody::Sealed { seq, cipher } = answer_of(data).body else {
            return None;
        };
        let aad = answer_aad(
            to.name(),
            from.name(),
            &space(),
            &self.epoch,
            &self.ephemeral,
            sent.seq,
            &sent.id,
        );
        let plain = open_answer(&self.keys, seq, &aad, &cipher)?;
        Status::decode_inner(Bytes::from(plain)).ok()
    }
}

/// The name a query of `ask` to `to` carries (its digest is the parameters'), for a test that
/// asserts a Data answers exactly it.
pub(super) fn name_of(to: &Node, wire: &Bytes) -> Name {
    let interest = interest_of(wire);
    let (_, digest) = crate::wire::parse_query_name(&interest.name).unwrap();
    query_ask_name(to.name(), &digest)
}
