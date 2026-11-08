//! What a large group costs (spec §5.5): the writer puts one group of `n`
//! versions, one per merge collection of one folder; a reader holding the
//! folder's members record takes them one by one, in seq order, as fetched,
//! and counts none before the last, then all. Timed by phase. Ignored (a
//! measurement); run in release:
//!
//! ```text
//! GROUP_SCALE=2000,10000 cargo test --release -p ndn-data --lib group_scale -- --ignored --nocapture
//! ```

use std::time::Instant;

use super::group_tests::{Unconnected, n};
use super::*;
use crate::layer::Share;
use ndn_security::TrustSchema;
use ndn_sync::MemoryStore;

const RULE: &str = "/bench/merge/count/v=1";

/// Every edit counts.
struct Count {
    function: Name,
}

impl MergeRule for Count {
    fn function(&self) -> &Name {
        &self.function
    }

    fn start(&self, _collection: &Name, _local: &Writer) -> Box<dyn MergeState> {
        Box::new(CountState(BTreeSet::new()))
    }
}

struct CountState(BTreeSet<VersionId>);

impl MergeState for CountState {
    fn check(&self, _op: &Op<'_>) -> Result<OpKind, MergeError> {
        Ok(OpKind::Edit)
    }

    fn apply(&mut self, op: &Op<'_>) -> Result<Counting, MergeError> {
        self.0.insert(op.id.clone());
        Ok(Counting::Counted)
    }

    fn value(&self, excluded: &BTreeSet<VersionId>) -> Value {
        let n = self.0.iter().filter(|id| !excluded.contains(id)).count() as u64;
        Value::Rule(Bytes::copy_from_slice(&n.to_be_bytes()))
    }
}

async fn start(device: &str, store: Arc<dyn DataStore>) -> Device {
    let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
    for ns in ["/alice", "/bob"] {
        validator
            .adopt_context(Arc::new(SignedTrustContext::hierarchical(n(ns))))
            .unwrap();
    }
    let keys = Arc::new(SecurityManager::new());
    keys.generate_ed25519(n(device).append("KEY").append("1"))
        .unwrap();
    let conn: Arc<dyn Connection> = Arc::new(Unconnected);
    Device::start(
        Transport {
            node: Node::from_connection(Arc::clone(&conn)),
            sync: conn,
        },
        n(device),
        keys,
        validator,
        store,
        Config {
            rules: MergeRules::standard().with(Arc::new(Count { function: n(RULE) })),
            first_look: Duration::from_millis(10),
            ..Config::new()
        },
    )
    .await
    .unwrap()
}

/// Every log entry `store` holds under `device`'s log, in seq order: its
/// name, packet, signer and record.
fn entries(store: &MemoryStore, device: &Name) -> Vec<(u64, Name, Bytes, Writer, Record)> {
    let entry = log_name(device, None, 0);
    let log = Name::from_components(entry.components()[..entry.len() - 1].iter().cloned());
    let mut out: Vec<_> = store
        .scan_under(&log, 0)
        .into_iter()
        .filter_map(|(name, wire)| {
            let seq = parse_log_name(&name)?.seq;
            let data = Data::decode(wire.clone()).ok()?;
            let writer = Writer::new((*data.sig_info()?.key_locator_name()?).clone());
            let record = wire::decode_record(data.content()?.clone()).ok()?;
            Some((seq, name, wire, writer, record))
        })
        .collect();
    out.sort_by_key(|e| e.0);
    out
}

async fn measure(count: usize) {
    let folder = n("/alice/32=data/doc");
    let colls: Vec<Name> = (0..count)
        .map(|i| folder.clone().append(format!("p{i}")))
        .collect();
    let alice_store = Arc::new(MemoryStore::new());
    let alice = start(
        "/alice/laptop",
        Arc::clone(&alice_store) as Arc<dyn DataStore>,
    )
    .await;
    alice
        .share_folder(
            &folder,
            Share {
                rule: Rule::Merge { function: n(RULE) },
                writers: vec![n("/alice")],
                readers: vec![Audience::Person(n("/bob"))],
            },
        )
        .await
        .unwrap();
    let items: Vec<(Name, Edit)> = colls
        .iter()
        .map(|c| (c.clone(), Edit::Op(Bytes::from_static(b"E"))))
        .collect();
    let at = Instant::now();
    let ids = alice
        .put_group(
            items,
            PutOptions {
                type_id: TypeId {
                    name: n("/types/count"),
                    revision: 1,
                },
                keep: Keep::Forever,
                batch: None,
            },
        )
        .await
        .unwrap();
    let put = at.elapsed();
    assert_eq!(ids.len(), count);
    let group: BTreeSet<&VersionId> = ids.iter().collect();
    let log = entries(&alice_store, alice.name());

    let bob = start("/bob/laptop", Arc::new(MemoryStore::new())).await;
    let (records, versions): (Vec<_>, Vec<_>) = log
        .into_iter()
        .partition(|e| !matches!(e.4, Record::Version(_)));
    let give = |e: &(u64, Name, Bytes, Writer, Record)| {
        let mut st = bob.inner.st.lock();
        bob.inner.take(
            &mut st,
            e.1.clone(),
            e.2.clone(),
            e.3.clone(),
            e.4.clone(),
            false,
        );
    };
    for e in &records {
        give(e);
    }
    // Bob holds the folder's epoch key, as a reader granted it does.
    for e in &records {
        if let Record::Members(body) = &e.4
            && let Some(epoch) = &body.epoch
        {
            let key = alice.inner.st.lock().keys.key(&body.collection, epoch);
            let key = key.expect("the writer holds its epoch's key");
            assert!(bob.inner.st.lock().take_key(&body.collection, epoch, key));
        }
    }
    let mut changes = bob.watch(&folder, &Frontier::new()).await.unwrap();
    assert_eq!(versions.len(), count);
    let at = Instant::now();
    let (last, rest) = versions.split_last().unwrap();
    for e in rest {
        give(e);
    }
    let waiting = at.elapsed();
    {
        let st = bob.inner.st.lock();
        assert!(
            colls
                .iter()
                .zip(&ids)
                .all(|(c, id)| st.colls.get(c).is_none_or(|x| !x.at().contains(id))),
            "nothing counts before the group is whole"
        );
    }
    let at = Instant::now();
    give(last);
    let complete = at.elapsed();
    println!(
        "group of {count}: writer put_group {put:.2?}; reader: first {} members taken \
         {waiting:.2?}, the last (group complete, all applied and judged) {complete:.2?}",
        count - 1
    );
    let at = Instant::now();
    let mut delivered = 0usize;
    {
        use futures::StreamExt;
        while delivered < count {
            match tokio::time::timeout(Duration::from_secs(60), changes.next()).await {
                Ok(Some(Ok(Change::Version(v)))) if group.contains(&v.id) => delivered += 1,
                Ok(Some(Ok(_))) => {}
                other => panic!("the watch ended after {delivered} versions: {other:?}"),
            }
        }
    }
    let watch = at.elapsed();
    let at = Instant::now();
    for (c, id) in colls.iter().zip(&ids) {
        match bob.get(c).await.unwrap().got {
            Got::State(s) => {
                assert!(s.at.contains(id) && s.not_counted.is_empty(), "{c}");
            }
            other => panic!("not a state: {other:?}"),
        }
    }
    let gets = at.elapsed();
    bob.shutdown();
    alice.shutdown();
    println!(
        "group of {count}: watch delivery after {watch:.2?}, a get of each collection {gets:.2?}"
    );
}

#[tokio::test]
#[ignore = "a measurement: run in release with --ignored --nocapture"]
async fn group_scale() {
    let sizes = std::env::var("GROUP_SCALE").unwrap_or_else(|_| "2000".into());
    for s in sizes.split(',') {
        measure(s.trim().parse().unwrap()).await;
    }
}
