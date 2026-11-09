//! Members' namespaces adopted for their folders (spec §6.3): what an
//! owner's records can make a device adopt and join, and what a restart
//! keeps of what was adopted.

use super::super::*;
use super::{Adopted, SCOPE_PER_SUBJECT, Scopes};
use crate::intro::{Adopting, Introducer, Scoping};
use crate::layer::Share;
use ndn_app::AppError;
use ndn_security::self_certifying::{Genesis, personal_namespace_of, self_certifying_name};
use ndn_security::{ScopedContext, TrustSchema};
use ndn_sync::MemoryStore;
use ndn_trust_envelope::TrustEnvelope;

/// A forwarder that never delivers anything.
struct Unconnected;

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

/// What a host's network serves of persons' trust contexts: each Interest
/// whose name equals a registered name is answered with that Data.
struct Net(Vec<(Name, Bytes)>);

impl ndn_cert::CaExchange for Net {
    fn express(
        &mut self,
        interest: Bytes,
    ) -> impl Future<Output = Result<Data, ndn_cert::CertError>> + Send {
        let interest = Interest::decode(interest).expect("a well-formed Interest");
        let reply = self
            .0
            .iter()
            .find(|(name, _)| *name == *interest.name)
            .map(|(_, wire)| Data::decode(wire.clone()).expect("a well-formed Data"))
            .ok_or_else(|| {
                ndn_cert::CertError::Transport(format!("no reply for {}", interest.name))
            });
        std::future::ready(reply)
    }
}

/// A host that adopts for a folder as the hosts do
/// (`ndn_cert::adopt_scoped`), over a network serving what the test gives
/// it, and carries in transit what it adopted until released, once.
#[derive(Default)]
struct Host {
    net: std::sync::Mutex<Vec<(Name, Bytes)>>,
    asked: std::sync::Mutex<Vec<(Name, Option<u64>)>>,
    carried: std::sync::Mutex<BTreeSet<Name>>,
}

impl Host {
    /// The network now serves `versions` (signed context Data) and, as the
    /// newest of their namespace, the last.
    fn serve(&self, versions: &[&Data]) {
        let mut net = Vec::new();
        if let Some(newest) = versions.last() {
            let ns = ndn_security::self_certifying::personal_namespace_of(&newest.name).unwrap();
            let asked = ndn_cert::rdr_metadata_name(&ns);
            let named = asked.clone().append_version(1).append_segment(0);
            net.push((
                asked,
                DataBuilder::new(named, &newest.name.encode_to_tlv()).build(),
            ));
        }
        for v in versions {
            net.push(((*v.name).clone(), v.raw().clone()));
        }
        *self.net.lock().unwrap() = net;
    }

    fn asked(&self) -> BTreeSet<Name> {
        self.asked
            .lock()
            .unwrap()
            .iter()
            .map(|(n, _)| n.clone())
            .collect()
    }

    /// The version held each adoption of `ns` was asked from.
    fn asked_from(&self, ns: &Name) -> Vec<Option<u64>> {
        self.asked
            .lock()
            .unwrap()
            .iter()
            .filter(|(n, _)| n == ns)
            .map(|(_, v)| *v)
            .collect()
    }

    fn carries(&self, ns: &Name) -> bool {
        self.carried.lock().unwrap().contains(ns)
    }
}

impl Introducer for Host {
    fn anchor(&self) -> Option<Bytes> {
        None
    }

    fn adopt<'a>(&'a self, _link: &'a TrustEnvelope) -> Adopting<'a> {
        Box::pin(async { Err("this host adopts nothing for the node".to_owned()) })
    }

    fn adopt_scoped<'a>(
        &'a self,
        namespace: &'a Name,
        held: Option<&'a ScopedContext>,
    ) -> Scoping<'a> {
        self.asked
            .lock()
            .unwrap()
            .push((namespace.clone(), held.map(|h| h.context().version())));
        let mut net = Net(self.net.lock().unwrap().clone());
        Box::pin(async move {
            let got = ndn_cert::adopt_scoped(None, &mut net, namespace, held)
                .await
                .map_err(|e| e.to_string())?;
            self.carried.lock().unwrap().insert(namespace.clone());
            Ok(got)
        })
    }

    fn release_scoped(&self, namespace: &Name) {
        self.carried.lock().unwrap().remove(namespace);
    }
}

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

fn key(device: &Name) -> Name {
    device.clone().append("KEY").append("1")
}

/// Alice's laptop, holding Alice's namespace, its host `host`, on `store`.
async fn laptop(host: &Arc<Host>, store: &Arc<dyn DataStore>) -> Device {
    let device = n("/alice/laptop");
    let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
    validator
        .adopt_context(Arc::new(SignedTrustContext::hierarchical(n("/alice"))))
        .unwrap();
    let keys = Arc::new(SecurityManager::new());
    keys.generate_ed25519_from_seed(key(&device), &[7; 32])
        .unwrap();
    let conn: Arc<dyn Connection> = Arc::new(Unconnected);
    Device::start(
        Transport {
            node: Node::from_connection(Arc::clone(&conn)),
            sync: conn,
        },
        device,
        keys,
        validator,
        Arc::clone(store),
        Config {
            first_look: Duration::from_millis(50),
            introducer: Some(Arc::clone(host) as Arc<dyn Introducer>),
            ..Config::new()
        },
    )
    .await
    .unwrap()
}

fn folder() -> Name {
    n("/alice/32=data/docs")
}

/// A person's namespace, by a made-up key.
fn user(i: u8) -> Name {
    self_certifying_name(&[i; 32])
}

/// A person's root key (from `seed`) in `mgr`: the namespace it names, the
/// key's name and its self-signed anchor.
fn person(mgr: &SecurityManager, seed: u8) -> (Name, Name, ndn_security::Certificate) {
    let seed = [seed; 32];
    let pk = ndn_security::Ed25519Signer::from_seed(&seed, Name::root()).public_key_bytes();
    let ns = self_certifying_name(&pk);
    let key = ns.clone().append("KEY").append("root");
    mgr.generate_ed25519_from_seed(key.clone(), &seed).unwrap();
    let anchor = mgr
        .issue_self_signed(&key, Bytes::copy_from_slice(&pk), u64::MAX)
        .unwrap();
    (ns, key, anchor)
}

/// Version 1 of `ns`'s trust context, checked as its genesis.
async fn genesis(
    mgr: &SecurityManager,
    ns: &Name,
    key: &Name,
    anchor: &ndn_security::Certificate,
) -> Genesis {
    let ctx = SignedTrustContext::hierarchical(ns.clone()).with_version(1);
    assert!(ctx.add_anchor(anchor.clone()));
    let signer = mgr.get_signer_sync(key).unwrap();
    let data = ctx.sign_into_data_async(signer.as_ref()).await.unwrap();
    Genesis::open_received(&data).await.unwrap()
}

/// `ns`'s context at `version`, reached from its genesis, as a host adopts
/// it for a folder.
async fn scoped_at(
    mgr: &SecurityManager,
    (ns, key, anchor): &(Name, Name, ndn_security::Certificate),
    version: u64,
) -> ScopedContext {
    let g = genesis(mgr, ns, key, anchor).await;
    let newest = match version {
        1 => Arc::clone(g.context()),
        v => {
            let ctx = SignedTrustContext::hierarchical(ns.clone()).with_version(v);
            assert!(ctx.add_anchor(anchor.clone()));
            Arc::new(ctx)
        }
    };
    ScopedContext::new(g, newest).unwrap()
}

/// Carol's namespace with two root keys: `k1`, which names it, and `k2`,
/// which her versions hand the root over to.
struct Carol {
    mgr: SecurityManager,
    ns: Name,
    k1: (Name, ndn_security::Certificate),
    k2: (Name, ndn_security::Certificate),
}

impl Carol {
    fn new() -> Carol {
        let mgr = SecurityManager::new();
        let (ns, k1, a1) = person(&mgr, 0xc0);
        let k2 = ns.clone().append("KEY").append("k2");
        mgr.generate_ed25519_from_seed(k2.clone(), &[0xc2; 32])
            .unwrap();
        let pk2 =
            ndn_security::Ed25519Signer::from_seed(&[0xc2; 32], Name::root()).public_key_bytes();
        let a2 = mgr
            .issue_self_signed(&k2, Bytes::copy_from_slice(&pk2), u64::MAX)
            .unwrap();
        Carol {
            mgr,
            ns,
            k1: (k1, a1),
            k2: (k2, a2),
        }
    }

    /// Version `v` of her context anchored at `anchors`, signed by `by`
    /// (one of them): `extra` tells apart two versions of one number.
    async fn version(
        &self,
        v: u64,
        anchors: &[&ndn_security::Certificate],
        by: &Name,
        extra: Option<&str>,
    ) -> Data {
        let mut ctx = SignedTrustContext::hierarchical(self.ns.clone()).with_version(v);
        if let Some(x) = extra {
            ctx = ctx.with_ca_endpoint(self.ns.clone().append(x));
        }
        for a in anchors {
            assert!(ctx.add_anchor((*a).clone()));
        }
        let signer = self.mgr.get_signer_sync(by).unwrap();
        let wire = ctx
            .sign_into_data_async(signer.as_ref())
            .await
            .unwrap()
            .raw()
            .clone();
        Data::decode(wire).unwrap()
    }
}

/// The version of `ns` adopted here for a folder, if one is.
fn adopted_version(dev: &Device, ns: &Name) -> Option<u64> {
    match dev.inner.st.lock().scopes.adopted.get(ns) {
        Some(Adopted::Held { ctx, .. }) => Some(ctx.context().version()),
        _ => None,
    }
}

/// Whether `dev` judges `name` by a view adopted for a folder, not by its
/// own validator (which refuses a person's namespace it does not hold).
fn scoped_judge(dev: &Device, name: &Name) -> bool {
    !Arc::ptr_eq(&dev.inner.judge(name), &dev.inner.validator)
}

/// Wait, in paused time, until `f` holds or `secs` pass.
async fn until(mut f: impl FnMut() -> bool, secs: u64) -> bool {
    for _ in 0..secs * 10 {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    f()
}

/// The changes queued on `changes` now.
async fn drain(changes: &mut crate::layer::Changes) -> Vec<Change> {
    let mut out = Vec::new();
    while let Ok(Some(Ok(c))) =
        tokio::time::timeout(Duration::from_millis(10), changes.next()).await
    {
        out.push(c);
    }
    out
}

/// An owner's record listing a hundred made-up persons' namespaces as
/// writers: the device asks its host to adopt at most
/// [`SCOPE_PER_SUBJECT`] of them — the first the record lists — joins the
/// sync group of none it has not adopted, and tells the folder's watchers
/// which it left out, why and what to do (M4).
#[tokio::test(start_paused = true)]
async fn a_record_listing_many_writers_adopts_at_most_the_cap_and_joins_no_group_of_the_others() {
    let host = Arc::new(Host::default());
    let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
    let dev = laptop(&host, &store).await;
    let f = folder();
    let people: Vec<Name> = (0..100).map(user).collect();
    let mut changes = dev.watch(&f, &Frontier::new()).await.unwrap();
    let mut writers = vec![n("/alice")];
    writers.extend(people.iter().cloned());
    dev.share_folder(
        &f,
        Share {
            rule: Rule::Log,
            writers,
            readers: Vec::new(),
        }
        .into(),
    )
    .await
    .unwrap();
    let plan = f.clone().append("plan");
    dev.put(
        &plan,
        Content::new().with("t", "1"),
        PutOptions {
            type_id: TypeId {
                name: n("/types/note"),
                revision: 1,
            },
            keep: Keep::Forever,
            batch: None,
        },
    )
    .await
    .unwrap();
    // The host refuses each; the device asks again, pause after pause.
    tokio::time::sleep(Duration::from_secs(600)).await;
    let groups: Vec<Name> = dev.inner.st.lock().groups.keys().cloned().collect();
    assert!(
        groups.iter().all(|g| personal_namespace_of(g).is_none()),
        "no group of a person's namespace nobody adopted is joined: {groups:?}"
    );
    let asked = host.asked();
    assert!(
        !asked.is_empty()
            && asked
                .iter()
                .all(|a| people[..SCOPE_PER_SUBJECT].contains(a)),
        "only the first {SCOPE_PER_SUBJECT} the record lists are asked for: {} asked",
        asked.len()
    );
    let told: Vec<(Vec<Name>, String)> = drain(&mut changes)
        .await
        .into_iter()
        .filter_map(|c| match c {
            Change::NotAdopted {
                collection,
                namespaces,
                why,
            } if collection == f => Some((namespaces, why)),
            _ => None,
        })
        .collect();
    assert_eq!(told.len(), 1, "told once: {told:?}");
    assert_eq!(told[0].0, people[SCOPE_PER_SUBJECT..].to_vec());
    assert!(
        told[0].1.contains("too many writers") && told[0].1.contains("list fewer"),
        "why, and what to do: {}",
        told[0].1
    );
    dev.shutdown();
}

/// Carol is adopted for Alice's folder at version 3 of her context, whose
/// versions 2 and 3 hand her root over from `k1` to `k2`. The device keeps
/// version 3, and after a restart judges by it at once and refreshes from
/// it, never from the genesis again (L1): a thief holding `k1` who serves
/// a branch from version 1 numbered past it — versions 2, 3 and 4 signed by
/// `k1` — is refused, since that branch does not descend from version 3;
/// a path serving only version 1 is refused; and Carol's own version 4,
/// once reachable, is adopted from version 3. Each restart is a new host,
/// which carries Carol in transit once a refresh from the restored version
/// succeeds.
#[tokio::test(start_paused = true)]
async fn a_restart_never_rolls_a_scoped_context_back_nor_takes_another_branch() {
    let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
    let carol = Carol::new();
    let ns = carol.ns.clone();
    let ((k1, a1), (k2, a2)) = (&carol.k1, &carol.k2);
    let v1 = carol.version(1, &[a1], k1, None).await;
    let v2 = carol.version(2, &[a1, a2], k1, None).await;
    let v3 = carol.version(3, &[a2], k2, None).await;
    let host = Arc::new(Host::default());
    host.serve(&[&v1, &v2, &v3]);
    let dev = laptop(&host, &store).await;
    let f = folder();
    dev.share_folder(
        &f,
        Share {
            rule: Rule::Log,
            writers: vec![n("/alice"), ns.clone()],
            readers: Vec::new(),
        }
        .into(),
    )
    .await
    .unwrap();
    assert!(
        until(|| adopted_version(&dev, &ns) == Some(3), 30).await,
        "precondition: Carol is adopted for the folder at version 3"
    );
    dev.shutdown();
    drop(dev);

    // The thief's branch, from version 1, numbered past version 3.
    let t2 = carol.version(2, &[a1], k1, Some("thief")).await;
    let t3 = carol.version(3, &[a1], k1, Some("thief")).await;
    let t4 = carol.version(4, &[a1], k1, Some("thief")).await;
    let host = Arc::new(Host::default());
    host.serve(&[&v1, &t2, &t3, &t4]);
    let dev = laptop(&host, &store).await;
    assert_eq!(
        adopted_version(&dev, &ns),
        Some(3),
        "the version kept judges again from the start"
    );
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert_eq!(
        adopted_version(&dev, &ns),
        Some(3),
        "a branch numbered past the version kept that does not descend from it is refused"
    );
    let from = host.asked_from(&ns);
    assert!(
        !from.is_empty() && from.iter().all(|v| *v == Some(3)),
        "refreshed from the version kept, never from the genesis: {from:?}"
    );
    assert!(
        !host.carries(&ns),
        "a failed refresh leaves nothing carried"
    );
    dev.shutdown();
    drop(dev);

    // A path serving only version 1.
    let host = Arc::new(Host::default());
    host.serve(&[&v1]);
    let dev = laptop(&host, &store).await;
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert_eq!(
        adopted_version(&dev, &ns),
        Some(3),
        "an older version is refused"
    );

    // Carol's own version 4 becomes reachable.
    let v4 = carol.version(4, &[a2], k2, None).await;
    host.serve(&[&v1, &v2, &v3, &v4]);
    assert!(
        until(|| adopted_version(&dev, &ns) == Some(4), 300).await,
        "her next version is adopted from the version kept"
    );
    assert!(
        host.carries(&ns),
        "a refresh from a restored version has the host carry the namespace in transit"
    );
    dev.shutdown();
}

/// A folder and a collection of one name each have their own record: the
/// collection's record, listing no person, does not erase the folder's
/// listing of Carol (L6).
#[tokio::test(start_paused = true)]
async fn a_folder_and_a_collection_of_one_name_list_their_writers_apart() {
    let host = Arc::new(Host::default());
    let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
    let carol = Carol::new();
    let ns = carol.ns.clone();
    let (k1, a1) = &carol.k1;
    host.serve(&[&carol.version(1, &[a1], k1, None).await]);
    let dev = laptop(&host, &store).await;
    let f = folder();
    let phone = n("/alice/phone");
    let record = |folder: bool, writers: Vec<Name>| {
        Record::Members(MembersBody {
            collection: f.clone(),
            folder,
            revision: 1,
            rule: Rule::Log,
            writers,
            readers: Vec::new(),
            cuts: Vec::new(),
            epoch: None,
            key_check: None,
            since: None,
            parent: None,
        })
    };
    let hand = |seq: u64, r: Record| {
        let name = log_name(&phone, Some(&f), seq);
        let k = key(&phone);
        let packet = DataBuilder::new(name.clone(), &wire::encode_record(&r)).sign_sync(
            ndn_packet::SignatureType::SignatureEd25519,
            Some(&k),
            |_| Bytes::from_static(&[0; 64]),
        );
        let mut st = dev.inner.st.lock();
        dev.inner
            .take(&mut st, name.clone(), packet, Writer::new(k), r, false);
        st.refused.get(&name).cloned()
    };
    assert_eq!(hand(1, record(true, vec![n("/alice"), ns.clone()])), None);
    assert_eq!(hand(2, record(false, vec![n("/alice")])), None);
    dev.inner.settle().await;
    let entry = log_name(
        &ns.clone().append("tablet"),
        Some(&f.clone().append("plan")),
        1,
    );
    assert!(
        until(|| scoped_judge(&dev, &entry), 30).await,
        "the folder's record still lists Carol for the folder: she is adopted and judged there"
    );
    dev.shutdown();
}

/// A burst of records listing an adopted namespace refreshes it once per
/// [`REFRESH_PAUSE_MAX`], not once per record; the refresh it defers is
/// asked once the pause ends (M4, record churn).
#[tokio::test]
async fn a_burst_of_records_refreshes_an_adopted_namespace_once_per_pause() {
    let mgr = SecurityManager::new();
    let carol = person(&mgr, 0xc0);
    let ns = carol.0.clone();
    let ctx = scoped_at(&mgr, &carol, 1).await;
    let judge = Arc::new(Validator::new(TrustSchema::hierarchical()).scoped_view(&ctx));
    let mut scopes = Scopes::default();
    scopes
        .adopted
        .insert(ns.clone(), Adopted::Held { ctx, judge });
    let subject = Subject {
        name: folder(),
        folder: true,
    };
    let record = Members {
        collection: folder(),
        folder: true,
        owner: Writer::new(key(&n("/alice/laptop"))),
        revision: Seq(1),
        rule: Rule::Log,
        writers: vec![n("/alice"), ns.clone()],
        readers: Vec::new(),
        cuts: Vec::new(),
        epoch: None,
        key_check: None,
        since: None,
        parent: None,
    };
    let held = |_: &Name| false;
    let t0 = Instant::now();
    scopes.note(&subject, Some(&record));
    let (asks, _) = scopes.asks_due(held, t0);
    assert_eq!(asks.len(), 1, "the first record refreshes it");
    scopes.refreshing.remove(&ns);
    let t1 = t0 + Duration::from_secs(1);
    for _ in 0..3 {
        scopes.note(&subject, Some(&record));
    }
    let (asks, wake) = scopes.asks_due(held, t1);
    assert!(asks.is_empty(), "within the pause, no refresh: {asks:?}");
    assert_eq!(
        wake,
        Some(t0 + REFRESH_PAUSE_MAX),
        "looked at again once it ends"
    );
    let (asks, _) = scopes.asks_due(held, t0 + REFRESH_PAUSE_MAX);
    assert_eq!(asks.len(), 1, "the deferred refresh, once");
}
