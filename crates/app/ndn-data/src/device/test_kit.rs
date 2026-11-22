//! What the device's test files share: a forwarder that delivers nothing, a
//! device on it owning two collections, and entries made by hand to give it.

use super::*;
use crate::layer::Share;
use ndn_app::AppError;
use ndn_security::TrustSchema;
use ndn_sync::MemoryStore;

/// A forwarder that never delivers anything: the test hands the device the
/// packets it would have fetched.
pub(super) struct Unconnected;

#[async_trait::async_trait]
impl Connection for Unconnected {
    async fn send(&self, _wire: Bytes) -> Result<(), AppError> {
        Ok(())
    }
    async fn recv(&self) -> Option<Bytes> {
        futures::future::pending().await
    }
    async fn register_prefix(&self, _prefix: &Name) -> Result<(), AppError> {
        Ok(())
    }
}

pub(super) fn n(s: &str) -> Name {
    s.parse().unwrap()
}

pub(super) fn plan() -> Name {
    n("/alice/32=data/trip/plan")
}

pub(super) fn budget() -> Name {
    n("/alice/32=data/trip/budget")
}

pub(super) fn key(device: &str) -> Name {
    n(device).append("KEY").append("1")
}

pub(super) fn id(device: &str, seq: u64) -> VersionId {
    VersionId {
        writer: Writer::new(key(device)),
        seq: Seq(seq),
    }
}

pub(super) fn log_share() -> Share {
    Share {
        rule: Rule::Log,
        writers: vec![n("/alice"), n("/bob"), n("/carol")],
        readers: Vec::new(),
    }
}

/// `/alice/laptop` on a forwarder that delivers nothing, owning `plan()`
/// and `budget()` as log collections Alice, Bob and Carol write.
pub(super) async fn device() -> Device {
    device_with(MergeRules::standard(), log_share()).await
}

/// `/alice/laptop`, knowing `rules`, owning `plan()` and `budget()` shared
/// as `share` says.
pub(super) async fn device_with(rules: MergeRules, share: Share) -> Device {
    device_tuned(share, |c| Config { rules, ..c }).await
}

/// `/alice/laptop`, its configuration as `tune` makes it, owning `plan()`
/// and `budget()` shared as `share` says.
pub(super) async fn device_tuned(share: Share, tune: impl FnOnce(Config) -> Config) -> Device {
    let device = n("/alice/laptop");
    let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
    for ns in ["/alice", "/bob", "/carol"] {
        validator
            .adopt_context(Arc::new(SignedTrustContext::hierarchical(n(ns))))
            .unwrap();
    }
    let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
    let keys = Arc::new(SecurityManager::new());
    keys.generate_ed25519(device.clone().append("KEY").append("1"))
        .unwrap();
    let conn: Arc<dyn Connection> = Arc::new(Unconnected);
    let dev = Device::start(
        Transport {
            node: Node::from_connection(Arc::clone(&conn)),
            sync: conn,
        },
        device,
        keys,
        validator,
        store,
        tune(Config {
            first_look: Duration::from_millis(50),
            ..Config::new()
        }),
    )
    .await
    .unwrap();
    for c in [plan(), budget()] {
        dev.share(&c, share.clone()).await.unwrap();
    }
    dev
}

/// A log entry as fetched: its name, packet, signing key and record.
pub(super) struct Made {
    pub(super) name: Name,
    pub(super) packet: Bytes,
    pub(super) key: Name,
    pub(super) record: Record,
}

/// Entry `seq` of `device` about `c` carrying `record`, signed (unchecked)
/// by the device's key.
pub(super) fn made(device: &str, c: &Name, seq: u64, record: Record) -> Made {
    let name = log_name(&n(device), Some(c), seq);
    let key = key(device);
    let packet = DataBuilder::new(name.clone(), &wire::encode_record(&record)).sign_sync(
        ndn_packet::SignatureType::SignatureEd25519,
        Some(&key),
        |_| Bytes::from_static(&[0; 64]),
    );
    Made {
        name,
        packet,
        key,
        record,
    }
}

/// Version `seq` of `device` in `c`, naming `parents`.
pub(super) fn version(device: &str, c: &Name, seq: u64, parents: &[(&str, u64)]) -> Made {
    let body = VersionBody {
        collection: c.clone(),
        parents: parents.iter().map(|(d, s)| (id(d, *s), None)).collect(),
        type_id: TypeId {
            name: n("/types/note"),
            revision: 1,
        },
        seal: Seal { any_of: Vec::new() },
        keep: Keep::Forever,
        dated: Timestamp(1),
        rule: None,
        fields: Content::new().with("t", format!("{device} {seq}")),
        op: Bytes::new(),
        sealed: None,
        chunks: None,
    };
    made(device, c, seq, Record::Version(body))
}

pub(super) fn give(dev: &Device, m: &Made) {
    let mut st = dev.inner.st.lock();
    dev.inner.take(
        &mut st,
        m.name.clone(),
        m.packet.clone(),
        Writer::new(m.key.clone()),
        m.record.clone(),
        false,
    );
}

/// Whether `id` counts in `c` here: applied.
pub(super) fn counts(dev: &Device, c: &Name, id: &VersionId) -> bool {
    let st = dev.inner.st.lock();
    st.colls[c].at().contains(id) && st.colls[c].versions.contains_key(id)
}

pub(super) fn refusal(dev: &Device, name: &Name) -> Option<Refusal> {
    dev.inner.st.lock().refused.get(name).cloned()
}

pub(super) fn options() -> PutOptions {
    PutOptions {
        type_id: TypeId {
            name: n("/types/note"),
            revision: 1,
        },
        keep: Keep::Forever,
    }
}

/// Every change the watch has delivered so far.
pub(super) async fn drain(changes: &mut Changes) -> Vec<Change> {
    use futures::StreamExt;
    let mut out = Vec::new();
    while let Ok(Some(Ok(change))) =
        tokio::time::timeout(Duration::from_millis(100), changes.next()).await
    {
        out.push(change);
    }
    out
}
