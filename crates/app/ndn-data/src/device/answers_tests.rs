//! Answers on a device (`docs/specs/answers.md`, conformance cases a1–a18 at the level of one
//! process): devices of three people on a forwarder that delivers nothing, certified by their
//! people's roots, so each verifies the other's packets; what the network would carry is handed
//! over by the test (`sync_all`, `hand`). The cases over a real network are the conformance
//! runner's `a1`…`a18`.

use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

use ndn_security::cert_name::{DEFAULT_ISSUER, new_cert_name};
use ndn_security::{Certificate, RevocationCut, SignedTrustContext, TrustSchema, encode_cert_data};
use ndn_sync::MemoryStore;

use super::answer_get::Opened;
use super::test_kit::{Unconnected, budget, log_share, n, options, plan};
use super::*;
use crate::answer::{
    AnswerAsk, AnswerBinding, AnswerConfig, AnswerKind, AnswerPolicy, AnswerStore, Answered,
    Budget, Content as RecordContent, Definition, EvalError, Evaluator, Evaluators, PlanError,
    Provenance, Publish, ReadRef, ReadSet, ReadView, Reads, Record as AnswerRecord, Signers, tlv,
};
use crate::error::AnswerRefusal;
use crate::events::{AnswerFault, EventDetail, EventKind, Meaning, ReadSetFault};
use crate::layer::Share;

mod ask_cost_tests;
mod ask_gate_tests;
mod ask_refusal_tests;
mod ask_tests;
mod ask_words_tests;
mod budget_tests;

const VALIDITY_MS: u64 = 365 * 24 * 3600 * 1000;

#[path = "answer_padding_tests.rs"]
mod padding;

fn now_ns() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
}

// ---- people and devices -------------------------------------------------------------------------

/// A person: a namespace whose root key certifies its devices.
struct Person {
    ns: Name,
    mgr: SecurityManager,
    root: Name,
    anchor: Certificate,
    ctx: Arc<SignedTrustContext>,
}

impl Person {
    fn new(ns: &str) -> Person {
        let mgr = SecurityManager::new();
        let root = mgr
            .generate_ed25519(n(ns).append("KEY").append("ns"))
            .unwrap();
        let signer = mgr.get_signer_sync(&root).unwrap();
        let anchor = mgr
            .issue_self_signed(&root, signer.public_key().unwrap(), VALIDITY_MS)
            .unwrap();
        let p = Person {
            ns: n(ns),
            mgr,
            root,
            anchor,
            ctx: Arc::new(SignedTrustContext::hierarchical(n(ns))),
        };
        Person {
            ctx: p.context(1, None),
            ..p
        }
    }

    /// The context at `version`, revoking `cut`'s key when given.
    fn context(&self, version: u64, cut: Option<RevocationCut>) -> Arc<SignedTrustContext> {
        let mut ctx = SignedTrustContext::hierarchical(self.ns.clone()).with_version(version);
        if let Some(cut) = cut {
            ctx = ctx
                .with_revocation(cut.key().clone())
                .with_revocation_cut(cut);
        }
        assert!(ctx.add_anchor(self.anchor.clone()));
        Arc::new(ctx)
    }

    async fn certify(&self, key: &Name, public: &[u8]) -> Certificate {
        let signer = self.mgr.get_signer_sync(&self.root).unwrap();
        let wire = encode_cert_data(
            &new_cert_name(key, DEFAULT_ISSUER),
            public,
            signer.as_ref(),
            now_ns() - 1_000_000_000,
            now_ns() + VALIDITY_MS * 1_000_000,
        )
        .await
        .unwrap();
        Certificate::decode(&Data::decode(wire).unwrap()).unwrap()
    }
}

/// One started device and what restarts it.
struct Node {
    name: Name,
    key: Name,
    keys: Arc<SecurityManager>,
    validator: Arc<Validator>,
    store: Arc<dyn DataStore>,
    device: Device,
}

/// Three people and every device started for them, all certified, all knowing each other's
/// certificates and every person's trust context.
struct World {
    people: Vec<Person>,
    certs: Vec<Certificate>,
    nodes: Vec<Node>,
    /// The connection the next device started fetches over, once: what hands its Interests to
    /// another device ([`ask_tests`]); else a forwarder that delivers nothing.
    link: std::sync::Mutex<Option<Arc<dyn Connection>>>,
}

impl World {
    fn new() -> World {
        World {
            people: ["/alice", "/bob", "/dave"].map(Person::new).into(),
            certs: Vec::new(),
            nodes: Vec::new(),
            link: std::sync::Mutex::new(None),
        }
    }

    /// Every person's context declares the role layout, as one `ndn-fwd init` made does (it
    /// lists a role in DataRequiresCut): a device with no role in its name is no device of it.
    fn with_role_layout(mut self) -> World {
        for p in &mut self.people {
            let ctx = SignedTrustContext::hierarchical(p.ns.clone())
                .with_version(1)
                .with_data_requires_cut("member");
            assert!(ctx.add_anchor(p.anchor.clone()));
            p.ctx = Arc::new(ctx);
        }
        self
    }

    async fn start(&mut self, device: &str, tune: impl FnOnce(Config) -> Config) -> Device {
        self.start_on(device, Arc::new(MemoryStore::new()), tune)
            .await
    }

    async fn start_on(
        &mut self,
        device: &str,
        store: Arc<dyn DataStore>,
        tune: impl FnOnce(Config) -> Config,
    ) -> Device {
        let name = n(device);
        let person = self
            .people
            .iter()
            .find(|p| name.has_prefix(&p.ns))
            .expect("a person of the world");
        let keys = Arc::new(SecurityManager::new());
        let key = keys
            .generate_ed25519(name.clone().append("KEY").append("1"))
            .unwrap();
        let public = keys.get_signer_sync(&key).unwrap().public_key().unwrap();
        let cert = person.certify(&key, &public).await;
        let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
        for p in &self.people {
            validator.adopt_context(Arc::clone(&p.ctx)).unwrap();
        }
        for c in self.certs.iter().chain([&cert]) {
            validator.cert_cache().insert(c.clone());
            keys.cert_cache().insert(c.clone());
        }
        for node in &self.nodes {
            node.validator.cert_cache().insert(cert.clone());
        }
        self.certs.push(cert);
        let device = self
            .boot(&name, &keys, &validator, &store, tune(Config::new()))
            .await;
        self.nodes.push(Node {
            name,
            key,
            keys,
            validator,
            store,
            device: device.clone(),
        });
        device
    }

    async fn boot(
        &self,
        name: &Name,
        keys: &Arc<SecurityManager>,
        validator: &Arc<Validator>,
        store: &Arc<dyn DataStore>,
        config: Config,
    ) -> Device {
        let sync: Arc<dyn Connection> = Arc::new(Unconnected);
        let fetch = self
            .link
            .lock()
            .unwrap()
            .take()
            .unwrap_or_else(|| Arc::clone(&sync));
        Device::start(
            Transport {
                node: Node_::from_connection(fetch),
                sync,
            },
            name.clone(),
            Arc::clone(keys),
            Arc::clone(validator),
            Arc::clone(store),
            Config {
                first_look: Duration::from_millis(20),
                ..config
            },
        )
        .await
        .unwrap()
    }

    /// Stop the device `device` and start it again on what it stored.
    async fn restart(&mut self, device: &str, tune: impl FnOnce(Config) -> Config) -> Device {
        let name = n(device);
        let at = self.nodes.iter().position(|x| x.name == name).unwrap();
        self.nodes[at].device.shutdown();
        let node = &self.nodes[at];
        let again = self
            .boot(
                &node.name,
                &node.keys,
                &node.validator,
                &node.store,
                tune(Config::new()),
            )
            .await;
        self.nodes[at].device = again.clone();
        again
    }

    fn key_of(&self, device: &str) -> Name {
        let name = n(device);
        self.nodes
            .iter()
            .find(|x| x.name == name)
            .unwrap()
            .key
            .clone()
    }

    fn validator_of(&self, device: &str) -> Arc<Validator> {
        let name = n(device);
        Arc::clone(
            &self
                .nodes
                .iter()
                .find(|x| x.name == name)
                .unwrap()
                .validator,
        )
    }

    fn store_of(&self, device: &str) -> Arc<dyn DataStore> {
        let name = n(device);
        Arc::clone(&self.nodes.iter().find(|x| x.name == name).unwrap().store)
    }
}

use ndn_app::Node as Node_;

fn writer(key: &Name) -> Writer {
    Writer::new(key.clone())
}

/// Every log entry `from` signed, taken by `to` as a peer's.
fn sync_all(from: &Device, to: &Device) {
    sync_except(from, to, None);
}

/// [`sync_all`] but for the entry named `skip`.
fn sync_except(from: &Device, to: &Device, skip: Option<&Name>) {
    let prefix =
        from.name()
            .clone()
            .append_component(ndn_foundation_types::NameComponent::keyword(
                Bytes::from_static(b"log"),
            ));
    for (name, wire) in from.inner.store.scan_under(&prefix, 0) {
        if skip == Some(&name) {
            continue;
        }
        let Ok(data) = Data::decode(wire.clone()) else {
            continue;
        };
        let Some(key) = data.sig_info().and_then(|s| s.key_locator_name()) else {
            continue;
        };
        let Some(record) = data
            .content()
            .and_then(|c| wire::decode_record(c.clone()).ok())
        else {
            continue;
        };
        let mut st = to.inner.st.lock();
        to.inner.take(
            &mut st,
            name,
            wire,
            Writer::new((*key).clone()),
            record,
            false,
        );
    }
}

/// An answer packet `by` serves, handed to `to` as a holder or cache would hand it: held, as a
/// packet checked and accepted.
async fn hand(by: &Device, name: &Name, to: &Device) -> Result<(), DataError> {
    let wire = by
        .inner
        .stored_answer(name)
        .expect("the packet is held where it came from");
    plant(to, wire).await
}

async fn plant(to: &Device, wire: Bytes) -> Result<(), DataError> {
    let data = Data::decode(wire).unwrap();
    let o: Opened = to.inner.open_packet(data, None, &[]).await?;
    to.inner.check_equivocation(&o)?;
    let mut st = to.inner.st.lock();
    to.inner.keep_held(
        &mut st,
        &o.name,
        &o.signer,
        o.kind,
        o.data.raw(),
        &o.pieces,
        o.result_digest,
    );
    Ok(())
}

// ---- evaluators ---------------------------------------------------------------------------------

fn sum_v(v: u64) -> Name {
    n("/conformance/eval/sum").append(format!("v={v}"))
}

/// The cases' evaluator: the definition is a version whose field `inputs` lists collections
/// (comma separated); it reads the newest of each and sums their integer `n`, plus `plus` each.
struct Sum {
    name: Name,
    plus: i64,
    /// Added to the result: a hostile program's wrong answer.
    lax: i64,
}

fn sum(v: u64) -> Arc<dyn Evaluator> {
    Arc::new(Sum {
        name: sum_v(v),
        plus: if v == 2 { 1 } else { 0 },
        lax: 0,
    })
}

fn lax_sum(v: u64) -> Arc<dyn Evaluator> {
    Arc::new(Sum {
        name: sum_v(v),
        plus: 0,
        lax: 1,
    })
}

fn inputs_of(def: &Definition) -> Result<Vec<Name>, EvalError> {
    let Got::Version(v) = &def.got else {
        return Err(EvalError::Refused("the definition is a version".into()));
    };
    let crate::Payload::Entry(c) = &v.payload else {
        return Err(EvalError::Refused("the definition is one entry".into()));
    };
    let list = c
        .get("inputs")
        .ok_or_else(|| EvalError::Refused("the definition has no field inputs".into()))?;
    Ok(String::from_utf8_lossy(list)
        .split(',')
        .filter(|s| !s.is_empty())
        .map(n)
        .collect())
}

#[async_trait::async_trait]
impl Evaluator for Sum {
    fn evaluator(&self) -> &Name {
        &self.name
    }

    async fn plan(&self, def: &Definition, reads: &mut dyn Reads) -> Result<(), PlanError> {
        for c in inputs_of(def)? {
            let (r, _) = reads.current(&c).await?;
            reads.read(&r).await?;
        }
        Ok(())
    }

    fn evaluate(&self, def: &Definition, view: &dyn ReadView) -> Result<Bytes, EvalError> {
        let mut total = self.lax;
        for c in inputs_of(def)? {
            let r = view.current(&c)?;
            let Got::Version(v) = view.read(r)? else {
                return Err(EvalError::Refused("an input is a version".into()));
            };
            let crate::Payload::Entry(content) = &v.payload else {
                return Err(EvalError::Refused("an input is one entry".into()));
            };
            let n: i64 = content
                .get("n")
                .and_then(|b| String::from_utf8_lossy(b).parse().ok())
                .ok_or_else(|| EvalError::Refused("an input has an integer n".into()))?;
            total += n + self.plus;
        }
        Ok(Bytes::from(total.to_string()))
    }
}

fn knowing(evals: Vec<Arc<dyn Evaluator>>) -> impl FnOnce(Config) -> Config {
    move |c| Config {
        evaluators: evals.into_iter().fold(Evaluators::none(), |e, x| e.with(x)),
        ..c
    }
}

fn with_policy(
    policy: AnswerPolicy,
    evals: Vec<Arc<dyn Evaluator>>,
) -> impl FnOnce(Config) -> Config {
    move |c| Config {
        evaluators: evals.into_iter().fold(Evaluators::none(), |e, x| e.with(x)),
        answers: AnswerConfig {
            policy,
            ..AnswerConfig::default()
        },
        ..c
    }
}

// ---- data ---------------------------------------------------------------------------------------

async fn put_n(dev: &Device, c: &Name, value: i64) -> VersionId {
    dev.put(
        c,
        Content::new().with("n", Bytes::from(value.to_string())),
        options(),
    )
    .await
    .unwrap()
}

async fn put_def(dev: &Device, c: &Name, inputs: &[&Name]) -> VersionId {
    let list = inputs
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(",");
    dev.put(
        c,
        Content::new().with("inputs", Bytes::from(list)),
        options(),
    )
    .await
    .unwrap()
}

/// The exact read of what `dev` holds newest of `c`.
async fn newest(dev: &Device, c: &Name) -> ReadRef {
    dev.current_read(c).await.unwrap().0
}

fn pure_question(def: ReadRef, ev: &Name) -> Name {
    AnswerAsk::pure(def, ev.clone()).name(None).unwrap()
}

async fn ask(dev: &Device, q: &Name) -> Result<Answered, DataError> {
    match dev.get(q).await?.got {
        Got::Answer(a) => Ok(a),
        other => panic!("not an answer: {other:?}"),
    }
}

fn id_of(name: &Name) -> [u8; 32] {
    wire::parse_answer_name(name).expect("an answer name").1
}

/// Alice's laptop owning `plan()` and `budget()` with `n` in the budget, and a definition in
/// the plan that sums it.
async fn alice_with_data(w: &mut World, tune: impl FnOnce(Config) -> Config) -> Device {
    let laptop = w.start("/alice/laptop", tune).await;
    for c in [plan(), budget()] {
        laptop.share(&c, log_share()).await.unwrap();
    }
    put_n(&laptop, &budget(), 3).await;
    put_def(&laptop, &plan(), &[&budget()]).await;
    laptop
}

fn the_same(a: &Answered, b: &Answered) {
    assert_eq!(a.result, b.result);
    assert_eq!(a.reads, b.reads);
    assert_eq!(a.binding, b.binding);
    assert_eq!(a.id, b.id);
    assert_eq!(a.result_digest, b.result_digest);
    assert_eq!(a.kind, b.kind);
}

fn events_of(dev: &Device, kind: EventKind) -> Vec<crate::events::DeviceEvent> {
    dev.pending_events()
        .into_iter()
        .filter(|e| e.kind() == kind)
        .collect()
}

/// The faults of the evidence events `dev` holds, the first of each and the newest coalesced
/// into it, taken: acknowledged, so the next evidence is the next event.
async fn faults_taken(dev: &Device) -> Vec<AnswerFault> {
    let events = events_of(dev, EventKind::AnswerEvidence);
    let mut out = Vec::new();
    for e in &events {
        for d in std::iter::once(&e.detail).chain(e.last.as_ref()) {
            if let EventDetail::Answer { fault, .. } = d {
                out.push(fault.clone());
            }
        }
    }
    dev.acknowledge(&events.iter().map(|e| e.id).collect::<Vec<_>>())
        .await
        .unwrap();
    out
}

// ---- a1: same read set, same name and answer ----------------------------------------------------

#[tokio::test]
async fn the_same_read_set_gives_the_same_id_and_answer_on_two_devices_and_a_third_reads_either() {
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, knowing(vec![sum(1)])).await;
    let phone = w.start("/alice/phone", knowing(vec![sum(1)])).await;
    let bob = w.start("/bob/laptop", knowing(vec![sum(1)])).await;
    sync_all(&laptop, &phone);
    sync_all(&laptop, &bob);
    let q = pure_question(newest(&laptop, &plan()).await, &sum_v(1));

    let planned = ask(&laptop, &q).await.unwrap();
    assert_eq!(planned.result, Bytes::from_static(b"3"));
    assert_eq!(
        planned.how,
        Provenance::Recomputed {
            confirmed_by: vec![],
            disagreed_with: vec![]
        },
        "nobody has answered: this device ran the evaluator"
    );
    assert_eq!(planned.binding.kind, AnswerKind::Pure);
    assert!(planned.binding.definition.is_some());
    assert_eq!(planned.binding.by, sum_v(1));
    assert_eq!(
        planned.reads.reads().len(),
        2,
        "the definition and the input"
    );
    assert_eq!(laptop.answer_id(&q).await.unwrap(), planned.id);

    let on_laptop = laptop.publish_answer(&q).await.unwrap();
    let on_phone = phone.publish_answer(&q).await.unwrap();
    assert_eq!(
        on_laptop,
        wire::answer_name(&n("/alice/laptop"), &planned.id.0)
    );
    assert_eq!(
        on_phone,
        wire::answer_name(&n("/alice/phone"), &planned.id.0)
    );
    assert_eq!(id_of(&on_laptop), id_of(&on_phone), "one binding, one id");
    let (a, b) = (
        ask(&laptop, &q).await.unwrap(),
        ask(&phone, &q).await.unwrap(),
    );
    the_same(&a, &b);
    // Publishing is idempotent.
    assert_eq!(laptop.publish_answer(&q).await.unwrap(), on_laptop);

    // A third device, in the folder, gets either by its exact name.
    for (by, name) in [(&laptop, &on_laptop), (&phone, &on_phone)] {
        hand(by, name, &bob).await.unwrap();
        let got = ask(&bob, name).await.unwrap();
        the_same(&got, &a);
        assert_eq!(got.name, *name, "the exact name asked for");
        let me = writer(&w.key_of(if by.name() == &n("/alice/laptop") {
            "/alice/laptop"
        } else {
            "/alice/phone"
        }));
        assert!(
            matches!(&got.how, Provenance::Recomputed { confirmed_by, disagreed_with }
            if confirmed_by.contains(&me) && disagreed_with.is_empty()),
            "{:?}",
            got.how
        );
    }
}

// ---- a2, a3, a4: what is bound ------------------------------------------------------------------

#[tokio::test]
async fn a_changed_read_set_is_a_new_name_and_the_old_answer_still_verifies_as_old() {
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, knowing(vec![sum(1)])).await;
    let q = pure_question(newest(&laptop, &plan()).await, &sum_v(1));
    let old = laptop.publish_answer(&q).await.unwrap();
    let before = ask(&laptop, &q).await.unwrap();
    assert!(matches!(
        laptop.get(&q).await.unwrap().age,
        Age::Newest { .. }
    ));

    put_n(&laptop, &budget(), 4).await;
    let after = ask(&laptop, &q).await.unwrap();
    assert_ne!(
        after.id, before.id,
        "one input version added: another read set"
    );
    assert_eq!(after.result, Bytes::from_static(b"4"));
    assert_ne!(after.reads.digest(), before.reads.digest());

    let again = laptop.get(&old).await.unwrap();
    assert_eq!(again.age, Age::Exact, "an exact name is not stale");
    let Got::Answer(old_answer) = again.got else {
        panic!()
    };
    assert_eq!(old_answer.id, before.id);
    assert_eq!(old_answer.result, Bytes::from_static(b"3"));
    assert!(
        matches!(&old_answer.how, Provenance::Recomputed { confirmed_by, .. } if confirmed_by.len() == 1)
    );
}

#[tokio::test]
async fn a_new_version_of_the_definition_is_a_new_name_and_an_old_answer_is_not_its_answer() {
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, knowing(vec![sum(1)])).await;
    let old_def = newest(&laptop, &plan()).await;
    let q_old = pure_question(old_def, &sum_v(1));
    let old_name = laptop.publish_answer(&q_old).await.unwrap();
    // A new definition: the same inputs, another version.
    put_def(&laptop, &plan(), &[&budget()]).await;
    let new_def = newest(&laptop, &plan()).await;
    let q_new = pure_question(new_def, &sum_v(1));
    let a_new = ask(&laptop, &q_new).await.unwrap();
    assert_ne!(
        laptop.answer_id(&q_new).await.unwrap(),
        laptop.answer_id(&q_old).await.unwrap(),
        "the definition's version is bound"
    );
    assert_ne!(
        wire::answer_name(&n("/alice/laptop"), &a_new.id.0),
        old_name
    );
    // The old answer is still the answer of the old definition.
    let old = ask(&laptop, &old_name).await.unwrap();
    assert_eq!(
        old.binding.definition,
        ask(&laptop, &q_old).await.unwrap().binding.definition
    );
    assert_ne!(old.binding.definition, a_new.binding.definition);
}

#[tokio::test]
async fn an_evaluator_is_bound_and_matched_by_its_exact_versioned_name() {
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, knowing(vec![sum(1), sum(2)])).await;
    let def = newest(&laptop, &plan()).await;
    let (q1, q2) = (
        pure_question(def.clone(), &sum_v(1)),
        pure_question(def.clone(), &sum_v(2)),
    );
    let (a1, a2) = (
        ask(&laptop, &q1).await.unwrap(),
        ask(&laptop, &q2).await.unwrap(),
    );
    assert_ne!(a1.id, a2.id, "v=1 and v=2 are other bindings");
    assert_eq!(
        (a1.result.as_ref(), a2.result.as_ref()),
        (&b"3"[..], &b"4"[..])
    );

    // A program that knows only v=2, trusting no signer: v=1 is "can't check here".
    let phone = w
        .start(
            "/alice/phone",
            with_policy(
                AnswerPolicy {
                    pure: Signers::None,
                    ..AnswerPolicy::default()
                },
                vec![sum(2)],
            ),
        )
        .await;
    sync_all(&laptop, &phone);
    let refused = ask(&phone, &q1).await.unwrap_err();
    assert!(
        matches!(&refused, DataError::CannotCheck { evaluator, .. } if *evaluator == sum_v(1)),
        "{refused:?}"
    );
    assert_eq!(refused.next(), crate::NextStep::UpdateProgram);
    assert!(!refused.retry());
    assert!(refused.to_string().contains(&sum_v(1).to_string()));
    // v=2's answer is not taken for v=1: it is another id.
    laptop.publish_answer(&q2).await.unwrap();
    let name2 = wire::answer_name(&n("/alice/laptop"), &a2.id.0);
    hand(&laptop, &name2, &phone).await.unwrap();
    let still = ask(&phone, &q1).await.unwrap_err();
    assert!(matches!(still, DataError::CannotCheck { .. }), "{still:?}");
    assert!(ask(&phone, &q2).await.is_ok(), "v=2 is checked here");
}

// ---- a5: a wrong answer from a member -----------------------------------------------------------

#[tokio::test]
async fn a_wrong_answer_from_a_member_is_evidence_and_the_reader_uses_its_own_value() {
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, knowing(vec![sum(1)])).await;
    let phone = w.start("/alice/phone", knowing(vec![lax_sum(1)])).await;
    sync_all(&laptop, &phone);
    let q = pure_question(newest(&laptop, &plan()).await, &sum_v(1));
    let wrong = phone.publish_answer(&q).await.unwrap();
    assert_eq!(
        ask(&phone, &q).await.unwrap().result,
        Bytes::from_static(b"4"),
        "the hostile program computes a wrong result and signs it at the right id"
    );
    assert_eq!(id_of(&wrong), laptop.answer_id(&q).await.unwrap().0);

    // The honest laptop is handed the packet and asked for it by its name.
    let honest = ask(&laptop, &q).await.unwrap();
    hand(&phone, &wrong, &laptop).await.unwrap();
    let got = ask(&laptop, &wrong).await.unwrap();
    assert_eq!(
        got.result,
        Bytes::from_static(b"3"),
        "its own value, not the signed one"
    );
    assert_eq!(got.result_digest, honest.result_digest);
    assert!(
        matches!(&got.how, Provenance::Recomputed { confirmed_by, disagreed_with }
        if confirmed_by.is_empty() && *disagreed_with == vec![writer(&w.key_of("/alice/phone"))]),
        "{:?}",
        got.how
    );
    assert_eq!(
        got.name,
        wire::answer_name(&n("/alice/laptop"), &honest.id.0),
        "the answer used is this device's own, not the signed one"
    );

    let events = events_of(&laptop, EventKind::AnswerEvidence);
    assert_eq!(events.len(), 1, "{:?}", laptop.pending_events());
    let e = &events[0];
    let EventDetail::Answer {
        answer,
        signer,
        id,
        readset,
        fault,
    } = &e.detail
    else {
        panic!("{e:?}")
    };
    assert_eq!(*answer, wrong);
    assert_eq!(*signer, w.key_of("/alice/phone"));
    assert_eq!(*id, honest.id.0);
    assert_eq!(*readset, honest.reads.digest().0);
    let AnswerFault::Mismatch {
        signed,
        recomputed,
        evaluator,
    } = fault
    else {
        panic!("{fault:?}")
    };
    assert_eq!(*evaluator, sum_v(1));
    assert_eq!(*recomputed, honest.result_digest.0);
    assert_ne!(signed, recomputed);
    assert_eq!(e.meaning(), Meaning::AnswerKept);
    assert_eq!(e.next_step(), crate::NextStep::UseOwnerDevice);
    assert_eq!(
        e.subject(),
        crate::EventSubject::Writer(w.key_of("/alice/phone"))
    );

    // Kept whole, never served onward, never taken again; the question still answers its own.
    let kept = laptop
        .inner
        .store
        .scan_under(&n("/localhost/ndn-data/answer-evidence"), 0);
    assert_eq!(kept.len(), 1);
    assert_eq!(
        laptop.inner.answer_packet(&wrong),
        Some(None),
        "an answer this device holds evidence of is never served"
    );
    let q_again = ask(&laptop, &q).await.unwrap();
    assert_eq!(q_again.result, Bytes::from_static(b"3"));
    assert_eq!(
        events_of(&laptop, EventKind::AnswerEvidence).len(),
        1,
        "told once"
    );
    // The wrong packet is not taken again.
    let again = plant(&laptop, phone.inner.stored_answer(&wrong).unwrap()).await;
    assert!(
        matches!(
            again,
            Err(DataError::Answer {
                why: AnswerRefusal::Equivocal,
                ..
            })
        ),
        "{again:?}"
    );
}

#[tokio::test]
async fn evidence_outlives_a_restart_and_stays_refused() {
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, knowing(vec![sum(1)])).await;
    let phone = w.start("/alice/phone", knowing(vec![lax_sum(1)])).await;
    sync_all(&laptop, &phone);
    let q = pure_question(newest(&laptop, &plan()).await, &sum_v(1));
    let wrong = phone.publish_answer(&q).await.unwrap();
    hand(&phone, &wrong, &laptop).await.unwrap();
    ask(&laptop, &wrong).await.unwrap();
    assert_eq!(events_of(&laptop, EventKind::AnswerEvidence).len(), 1);

    let laptop = w.restart("/alice/laptop", knowing(vec![sum(1)])).await;
    let events = events_of(&laptop, EventKind::AnswerEvidence);
    assert_eq!(
        events.len(),
        1,
        "the event is redelivered until acknowledged"
    );
    assert_eq!(laptop.inner.answer_packet(&wrong), Some(None));
    let again = plant(&laptop, phone.inner.stored_answer(&wrong).unwrap()).await;
    assert!(matches!(
        again,
        Err(DataError::Answer {
            why: AnswerRefusal::Equivocal,
            ..
        })
    ));
    // Acknowledged, it is gone and stays so.
    laptop.acknowledge(&[events[0].id]).await.unwrap();
    assert!(events_of(&laptop, EventKind::AnswerEvidence).is_empty());
}

// ---- a9: unknown evaluator ----------------------------------------------------------------------

#[tokio::test]
async fn an_unknown_evaluator_is_taken_on_trust_only_from_a_signer_the_policy_trusts() {
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, knowing(vec![sum(1)])).await;
    let q = pure_question(newest(&laptop, &plan()).await, &sum_v(1));
    let name = laptop.publish_answer(&q).await.unwrap();
    let truth = ask(&laptop, &q).await.unwrap();

    // The person's own device, default policy, does not know the evaluator.
    let phone = w.start("/alice/phone", knowing(vec![])).await;
    sync_all(&laptop, &phone);
    hand(&laptop, &name, &phone).await.unwrap();
    let got = ask(&phone, &name).await.unwrap();
    assert_eq!(got.result, truth.result);
    let Provenance::Trusted {
        signer,
        unverified_reads,
    } = &got.how
    else {
        panic!("{:?}", got.how)
    };
    assert_eq!(*signer, writer(&w.key_of("/alice/laptop")));
    assert_eq!(*unverified_reads, 0, "it holds both reads and checked them");
    // The same through a question that states the reads.
    let stated = AnswerAsk::pure(truth.binding.definition.clone().unwrap(), sum_v(1))
        .stating(truth.reads.clone())
        .name(None)
        .unwrap();
    let via_question = ask(&phone, &stated).await.unwrap();
    the_same(&via_question, &got);
    assert!(matches!(via_question.how, Provenance::Trusted { .. }));

    // Another device that holds none of the reads counts them.
    let tablet = w.start("/alice/tablet", knowing(vec![])).await;
    hand(&laptop, &name, &tablet).await.unwrap();
    let blind = ask(&tablet, &name).await.unwrap();
    assert!(
        matches!(&blind.how, Provenance::Trusted { unverified_reads, .. } if *unverified_reads == 2),
        "{:?}",
        blind.how
    );

    // A policy that trusts no one: "can't check here", naming the evaluator.
    let wary = w
        .start(
            "/alice/watch",
            with_policy(
                AnswerPolicy {
                    pure: Signers::None,
                    ..AnswerPolicy::default()
                },
                vec![],
            ),
        )
        .await;
    hand(&laptop, &name, &wary).await.unwrap();
    let e = ask(&wary, &name).await.unwrap_err();
    assert!(
        matches!(&e, DataError::CannotCheck { evaluator, .. } if *evaluator == sum_v(1)),
        "{e:?}"
    );
    assert_eq!(e.next(), crate::NextStep::UpdateProgram);

    // An answer from a signer it does not trust is never `Ok`: Dave is no member and no relative.
    let dave = w.start("/dave/laptop", knowing(vec![sum(1)])).await;
    sync_all(&laptop, &dave);
    let by_dave = dave.publish_answer(&q).await.unwrap();
    let pad = w.start("/alice/pad", knowing(vec![])).await;
    hand(&dave, &by_dave, &pad).await.unwrap();
    let refused = ask(&pad, &by_dave).await.unwrap_err();
    assert!(
        matches!(refused, DataError::CannotCheck { .. }),
        "{refused:?}"
    );
}

// ---- a12: provider answers ----------------------------------------------------------------------

fn function(v: u64) -> Name {
    n("/conformance/fn/summarize").append(format!("v={v}"))
}

#[tokio::test]
async fn a_provider_answer_binds_its_function_and_inputs_and_is_taken_only_from_a_named_provider() {
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, knowing(vec![])).await;
    let named = AnswerPolicy {
        providers: vec![(function(1), Signers::Devices(vec![n("/alice/laptop")]))],
        ..AnswerPolicy::default()
    };
    let phone = w.start("/alice/phone", with_policy(named, vec![])).await;
    let stranger = w.start("/alice/tablet", knowing(vec![])).await;
    for d in [&phone, &stranger] {
        sync_all(&laptop, d);
    }
    let input = newest(&laptop, &budget()).await;
    let inputs = ReadSet::new([input.clone()]).unwrap();
    let name = laptop
        .provide(
            &function(1),
            inputs.clone(),
            Bytes::from_static(b"a summary"),
        )
        .await
        .unwrap();
    // A second call, equal result: the same name; another result: refused, it keeps what it signed.
    assert_eq!(
        laptop
            .provide(
                &function(1),
                inputs.clone(),
                Bytes::from_static(b"a summary")
            )
            .await
            .unwrap(),
        name
    );
    let other = laptop
        .provide(&function(1), inputs.clone(), Bytes::from_static(b"another"))
        .await
        .unwrap_err();
    assert!(
        matches!(
            &other,
            DataError::Answer {
                why: AnswerRefusal::AlreadySigned,
                ..
            }
        ),
        "{other:?}"
    );
    assert_eq!(other.next(), crate::NextStep::None);
    // Another function version is another id.
    let v2 = laptop
        .provide(
            &function(2),
            inputs.clone(),
            Bytes::from_static(b"a summary"),
        )
        .await
        .unwrap();
    assert_ne!(id_of(&v2), id_of(&name));

    // The answer: function and inputs bound, no evaluator and no definition.
    hand(&laptop, &name, &phone).await.unwrap();
    let got = ask(&phone, &name).await.unwrap();
    assert_eq!(got.kind, AnswerKind::Provider);
    assert_eq!(got.binding.by, function(1));
    assert!(got.binding.definition.is_none());
    assert_eq!(got.binding.reads, inputs.digest());
    assert_eq!(got.result, Bytes::from_static(b"a summary"));
    assert!(
        matches!(&got.how, Provenance::Provider { signer, .. }
        if *signer == writer(&w.key_of("/alice/laptop"))),
        "{:?}",
        got.how
    );
    // Asked by a provider question that states the inputs.
    let q = AnswerAsk::provider(function(1), inputs.clone())
        .name(Some(&n("/alice/laptop")))
        .unwrap();
    assert_eq!(ask(&phone, &q).await.unwrap().id, got.id);
    assert_eq!(phone.answer_id(&q).await.unwrap(), got.id);

    // A device whose policy names no provider refuses it, saying what to change.
    hand(&laptop, &name, &stranger).await.unwrap();
    let refused = ask(&stranger, &name).await.unwrap_err();
    assert!(
        matches!(&refused, DataError::Answer { why: AnswerRefusal::NotProvider { function: f, .. }, .. } if *f == function(1)),
        "{refused:?}"
    );
    assert_eq!(refused.next(), crate::NextStep::SetPolicy);
}

#[tokio::test]
async fn two_results_at_one_name_by_one_key_are_equivocation_and_neither_is_used() {
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, knowing(vec![])).await;
    let named = AnswerPolicy {
        providers: vec![(function(1), Signers::Devices(vec![n("/alice/laptop")]))],
        ..AnswerPolicy::default()
    };
    let phone = w.start("/alice/phone", with_policy(named, vec![])).await;
    sync_all(&laptop, &phone);
    let inputs = ReadSet::new([newest(&laptop, &budget()).await]).unwrap();
    let name = laptop
        .provide(&function(1), inputs.clone(), Bytes::from_static(b"first"))
        .await
        .unwrap();
    hand(&laptop, &name, &phone).await.unwrap();
    assert_eq!(
        ask(&phone, &name).await.unwrap().result,
        Bytes::from_static(b"first")
    );

    // The key signs another result at the same name (a copy of the key, or a faulty program).
    let second = hostile_provider_answer(&laptop, &function(1), &inputs, b"second");
    assert_eq!(
        wire::parse_answer_name(&second.0).map(|x| x.1),
        Some(id_of(&name))
    );
    let planted = plant(&phone, second.1.clone()).await;
    assert!(
        matches!(
            &planted,
            Err(DataError::Answer {
                why: AnswerRefusal::Equivocal,
                ..
            })
        ),
        "{planted:?}"
    );
    let events = events_of(&phone, EventKind::AnswerEvidence);
    assert_eq!(events.len(), 1, "{:?}", phone.pending_events());
    assert!(
        matches!(&events[0].detail, EventDetail::Answer { fault: AnswerFault::Equivocation { .. }, answer, .. } if *answer == name)
    );
    // Both packets are kept; neither is served; the name is refused from now on.
    assert_eq!(
        phone
            .inner
            .store
            .scan_under(&n("/localhost/ndn-data/answer-evidence"), 0)
            .len(),
        2
    );
    assert_eq!(phone.inner.answer_packet(&name), Some(None));
    let again = ask(&phone, &name).await.unwrap_err();
    assert!(
        matches!(
            again,
            DataError::Answer {
                why: AnswerRefusal::Equivocal,
                ..
            }
        ),
        "{again:?}"
    );
}

/// A provider answer `dev`'s key signs by hand with `result`: past the layer's refusal to sign
/// two results at one name, as a copy of the key made before the first would.
fn hostile_provider_answer(
    dev: &Device,
    function: &Name,
    inputs: &ReadSet,
    result: &[u8],
) -> (Name, Bytes) {
    let binding = AnswerBinding {
        kind: AnswerKind::Provider,
        definition: None,
        by: function.clone(),
        reads: inputs.digest(),
    };
    let id = seal::answer_id(&binding, None);
    let name = wire::answer_name(dev.name(), &id);
    let body = crate::answer::Body {
        binding,
        reads: inputs.clone(),
        result: Bytes::copy_from_slice(result),
    };
    let record = AnswerRecord {
        kind: AnswerKind::Provider,
        content: RecordContent::Plain(body.encode()),
    };
    let wire = dev
        .inner
        .sign(DataBuilder::new(name.clone(), &record.encode()))
        .unwrap();
    (name, wire)
}

// ---- a13: unsigned work is not publishable ------------------------------------------------------

#[tokio::test]
async fn unsigned_work_has_no_read_and_a_commit_makes_it_publishable_under_a_new_name() {
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, knowing(vec![sum(1)])).await;
    let old_q = pure_question(newest(&laptop, &plan()).await, &sum_v(1));
    let old = laptop.publish_answer(&old_q).await.unwrap();

    // An input this device does not hold as a signed version: a version some other device
    // signed that never reached it, or an edit not committed. There is nothing to name.
    let ghost = ReadRef::Version {
        name: wire::log_name(&n("/alice/phone"), Some(&budget()), 9),
        digest: Hash([7; 32]),
    };
    let e = laptop
        .provide(
            &function(1),
            ReadSet::new([ghost]).unwrap(),
            Bytes::from_static(b"x"),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(&e, DataError::BadRequest { why, .. } if why.contains("commit it first")),
        "{e:?}"
    );
    assert_eq!(e.next(), crate::NextStep::FixRequest);
    assert_eq!(laptop.answers_held(), 0);
    assert!(
        laptop
            .inner
            .store
            .scan_under(&n("/localhost/ndn-data/answers"), 0)
            .iter()
            .all(|(name, _)| name != &old),
        "nothing named by the ghost was stored"
    );

    // The commit: the same question, asked after it, plans over the new version.
    put_n(&laptop, &budget(), 10).await;
    let published = laptop.publish_answer(&old_q).await.unwrap();
    assert_ne!(published, old, "the commit made a new read set, a new id");
    let got = ask(&laptop, &published).await.unwrap();
    assert_eq!(got.result, Bytes::from_static(b"10"));
}

// ---- a6, a8: sealed answers ---------------------------------------------------------------------

fn sealed_share(readers: &[&str]) -> Share {
    Share {
        rule: Rule::Log,
        writers: vec![n("/alice")],
        readers: readers.iter().map(|r| Audience::Person(n(r))).collect(),
    }
}

/// Alice's laptop with `plan()` and `budget()` sealed to `readers`.
async fn sealed_alice(
    w: &mut World,
    tune: impl FnOnce(Config) -> Config,
    readers: &[&str],
) -> Device {
    let laptop = w.start("/alice/laptop", tune).await;
    for c in [plan(), budget()] {
        laptop.share(&c, sealed_share(readers)).await.unwrap();
    }
    put_n(&laptop, &budget(), 3).await;
    put_def(&laptop, &plan(), &[&budget()]).await;
    laptop
}

/// Whether `needle` is among the octets of `hay`.
fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test]
async fn a_sealed_answer_hides_what_it_read_and_one_outside_the_audience_cannot_open_it() {
    let mut w = World::new();
    let laptop = sealed_alice(&mut w, knowing(vec![sum(1)]), &["/alice"]).await;
    let q = pure_question(newest(&laptop, &plan()).await, &sum_v(1));
    let name = laptop.publish_answer(&q).await.unwrap();
    let answered = ask(&laptop, &q).await.unwrap();
    assert_eq!(answered.result, Bytes::from_static(b"3"));
    assert_eq!(wire::parse_answer_name(&name).unwrap().1, answered.id.0);

    // The packet carries no collection, field, version, frontier, evaluator or result.
    let wire_bytes = laptop.inner.stored_answer(&name).unwrap();
    for hidden in [
        &b"trip"[..],
        b"plan",
        b"budget",
        b"conformance",
        b"sum",
        b"inputs",
        b"laptop/32=log",
    ] {
        assert!(
            !contains(&wire_bytes, hidden),
            "{} is in the clear in a sealed answer",
            String::from_utf8_lossy(hidden)
        );
    }
    assert_eq!(
        name.components().len(),
        4,
        "the device, 32=answer and the id: no content word"
    );
    let d = Data::decode(wire_bytes.clone()).unwrap();
    let rec = AnswerRecord::decode(d.content().unwrap().clone()).unwrap();
    let RecordContent::Sealed { epochs, .. } = &rec.content else {
        panic!("a sealed answer: {:?}", rec.content)
    };
    assert_eq!(
        epochs.len(),
        2,
        "the plan's epoch and the budget's, in the clear"
    );
    // An unsealed answer lists everything in the clear.
    let mut plain_world = World::new();
    let open = alice_with_data(&mut plain_world, knowing(vec![sum(1)])).await;
    let q2 = pure_question(newest(&open, &plan()).await, &sum_v(1));
    let name2 = open.publish_answer(&q2).await.unwrap();
    let clear = open.inner.stored_answer(&name2).unwrap();
    for shown in [&b"plan"[..], b"budget", b"sum"] {
        assert!(
            contains(&clear, shown),
            "{} is in an unsealed answer",
            String::from_utf8_lossy(shown)
        );
    }

    // Bob's device holds the sealed versions and no key: the question is `Sealed`, the very error
    // of a plain `get` of the collection, whether or not an answer exists; handed the name, it
    // gets the ciphertext and `Sealed` as well.
    let bob = w.start("/bob/laptop", knowing(vec![sum(1)])).await;
    sync_all(&laptop, &bob);
    let plain_get = bob.get(&budget()).await.unwrap_err();
    assert!(
        matches!(plain_get, DataError::Sealed { .. }),
        "{plain_get:?}"
    );
    let err = ask(&bob, &q).await.unwrap_err();
    assert!(matches!(err, DataError::Sealed { .. }), "{err:?}");
    assert_eq!(
        std::mem::discriminant(&err),
        std::mem::discriminant(&plain_get),
        "the same error as get of the collection"
    );
    assert!(bob.answer_id(&q).await.is_err(), "the id cannot be derived");
    bob.inner
        .store
        .insert(super::answers::stored_name(&name), wire_bytes.clone());
    let by_name = ask(&bob, &name).await.unwrap_err();
    assert!(matches!(by_name, DataError::Sealed { .. }), "{by_name:?}");
    // Another question, over a collection that does not exist, is not told apart from this one.
    let nothing = AnswerAsk::pure(
        ReadRef::Version {
            name: wire::log_name(&n("/alice/laptop"), Some(&n("/alice/32=data/trip/none")), 1),
            digest: Hash([1; 32]),
        },
        sum_v(1),
    )
    .name(None)
    .unwrap();
    let absent = ask(&bob, &nothing).await;
    assert!(absent.is_err(), "a question over nothing is no answer");
}

#[tokio::test]
async fn the_audience_of_an_answer_is_the_intersection_of_the_epochs_it_reads() {
    let mut w = World::new();
    let laptop = w.start("/alice/laptop", knowing(vec![sum(1)])).await;
    // A is read by Alice and Bob, B by Alice and Dave.
    let (a, b) = (budget(), n("/alice/32=data/trip/second"));
    laptop
        .share(&a, sealed_share(&["/alice", "/bob"]))
        .await
        .unwrap();
    laptop
        .share(&b, sealed_share(&["/alice", "/dave"]))
        .await
        .unwrap();
    laptop
        .share(&plan(), sealed_share(&["/alice", "/bob", "/dave"]))
        .await
        .unwrap();
    put_n(&laptop, &a, 3).await;
    put_n(&laptop, &b, 4).await;
    put_def(&laptop, &plan(), &[&a]).await;
    let only_a = pure_question(newest(&laptop, &plan()).await, &sum_v(1));
    put_def(&laptop, &plan(), &[&a, &b]).await;
    let both = pure_question(newest(&laptop, &plan()).await, &sum_v(1));
    let got = ask(&laptop, &both).await.unwrap();
    assert_eq!(got.result, Bytes::from_static(b"7"));
    assert_eq!(
        ask(&laptop, &only_a).await.unwrap().result,
        Bytes::from_static(b"3")
    );

    // Bob's device holds the keys of A's epoch and of the plan's, not of B's.
    let bob = w.start("/bob/laptop", knowing(vec![sum(1)])).await;
    let give_key = |c: &Name| {
        let st = laptop.inner.st.lock();
        let e = st.colls[c].members.as_ref().unwrap().epoch.clone().unwrap();
        let k = st.keys.key(c, &e).unwrap();
        drop(st);
        let mut bst = bob.inner.st.lock();
        bst.keys.edit().hold(c.clone(), e, k);
    };
    give_key(&a);
    give_key(&plan());
    sync_all(&laptop, &bob);
    // An answer over A alone (and the plan) opens for Bob; the one over A and B is `Sealed`.
    let opens = ask(&bob, &only_a).await.unwrap();
    assert_eq!(opens.result, Bytes::from_static(b"3"));
    let b_err = ask(&bob, &both).await.unwrap_err();
    assert!(
        matches!(b_err, DataError::Sealed { .. }),
        "Bob is not in B's audience: {b_err:?}"
    );
    // Handed the exact name of the answer over A and B, Bob holds the ciphertext and not the
    // audience key: `Sealed`, and the answer over A alone opens by name.
    let name_ab = laptop.publish_answer(&both).await.unwrap();
    let name_a = laptop.publish_answer(&only_a).await.unwrap();
    for name in [&name_ab, &name_a] {
        bob.inner.store.insert(
            super::answers::stored_name(name),
            laptop.inner.stored_answer(name).unwrap(),
        );
    }
    let by_name = ask(&bob, &name_ab).await.unwrap_err();
    assert!(
        matches!(by_name, DataError::Sealed { .. }),
        "the intersection: {by_name:?}"
    );
    assert_eq!(
        ask(&bob, &name_a).await.unwrap().result,
        Bytes::from_static(b"3")
    );
    // The epochs read are the three, each listed once.
    let mut epochs = Vec::new();
    for c in [&a, &b] {
        let st = laptop.inner.st.lock();
        epochs.push(st.colls[c].members.as_ref().unwrap().epoch.clone().unwrap());
    }
    let Ok(checked) = laptop.inner.check_reads(&name_ab, &got.reads, &[]).await else {
        panic!("the reads of its own answer hold");
    };
    assert_eq!(checked.unverified, 0, "it holds every read");
    let held = checked.epochs;
    assert!(
        epochs.iter().all(|e| held.contains(e)),
        "every epoch read is listed"
    );
    assert!(held.len() >= 3, "A's, B's and the plan's: {held:?}");
}

// ---- a14: durable before served -----------------------------------------------------------------

#[tokio::test]
async fn an_answer_is_served_only_behind_the_barrier_and_what_a_provider_signed_survives_a_restart()
{
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, knowing(vec![])).await;
    let inputs = ReadSet::new([newest(&laptop, &budget()).await]).unwrap();
    let name = laptop
        .provide(&function(1), inputs.clone(), Bytes::from_static(b"first"))
        .await
        .unwrap();
    // `provide` returned, so it is behind the barrier and served.
    assert!(
        laptop
            .inner
            .answer_packet(&name)
            .is_some_and(|p| p.is_some())
    );

    // The state between signing and the barrier: stored, not served.
    let store = w.store_of("/alice/laptop");
    let second = laptop
        .provide(&function(2), inputs.clone(), Bytes::from_static(b"x"))
        .await
        .unwrap();
    {
        let mut st = laptop.inner.st.lock();
        st.answer_book.unserve(&second);
    }
    assert_eq!(
        laptop.inner.answer_packet(&second),
        Some(None),
        "signed and stored, not served until it is behind the barrier"
    );
    assert!(laptop.inner.stored_answer(&second).is_some());

    // A restart serves what it signed, and signs no other result at the name.
    let laptop = w.restart("/alice/laptop", knowing(vec![])).await;
    assert!(
        laptop
            .inner
            .answer_packet(&name)
            .is_some_and(|p| p.is_some())
    );
    let again = laptop
        .provide(&function(1), inputs.clone(), Bytes::from_static(b"other"))
        .await
        .unwrap_err();
    assert!(
        matches!(
            again,
            DataError::Answer {
                why: AnswerRefusal::AlreadySigned,
                ..
            }
        ),
        "{again:?}"
    );
    assert_eq!(
        laptop
            .provide(&function(1), inputs, Bytes::from_static(b"first"))
            .await
            .unwrap(),
        name
    );
    drop(store);
}

// ---- a15: a revoked signer ----------------------------------------------------------------------

#[tokio::test]
async fn a_revoked_signers_answers_are_refused_and_no_longer_served() {
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, knowing(vec![sum(1)])).await;
    let phone = w.start("/alice/phone", knowing(vec![sum(1)])).await;
    sync_all(&laptop, &phone);
    let q = pure_question(newest(&laptop, &plan()).await, &sum_v(1));
    let name = phone.publish_answer(&q).await.unwrap();
    hand(&phone, &name, &laptop).await.unwrap();
    assert!(
        laptop
            .inner
            .answer_packet(&name)
            .is_some_and(|p| p.is_some()),
        "served while trusted"
    );
    assert!(ask(&laptop, &name).await.is_ok());

    // Alice revokes the phone's key; no cut lists an answer.
    let alice = &w.people[0];
    let cut = RevocationCut::new(w.key_of("/alice/phone"));
    laptop_adopts(&w, "/alice/laptop", alice.context(2, Some(cut)));
    for _ in 0..200 {
        if laptop.inner.answer_packet(&name) == Some(None) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        laptop.inner.answer_packet(&name),
        Some(None),
        "no longer served"
    );
    let refused = ask(&laptop, &name).await.unwrap_err();
    assert!(
        matches!(
            &refused,
            DataError::Answer {
                why: AnswerRefusal::Untrusted { .. },
                ..
            }
        ),
        "{refused:?}"
    );
    assert_eq!(refused.next(), crate::NextStep::AskOwner);
    // A pure question recomputed gives the same result under the laptop's own signature.
    let again = ask(&laptop, &q).await.unwrap();
    assert_eq!(again.result, Bytes::from_static(b"3"));
    let own = laptop.publish_answer(&q).await.unwrap();
    assert_eq!(
        id_of(&own),
        id_of(&name),
        "the same id under another device's signature"
    );
    assert_ne!(own, name);
}

fn laptop_adopts(w: &World, device: &str, ctx: Arc<SignedTrustContext>) {
    w.validator_of(device).keyring().adopt_update(ctx).unwrap();
}

// ---- a16: read-set faults -----------------------------------------------------------------------

/// An answer `dev`'s key signs by hand: the binding, the read set octets and the epochs it is
/// given, whatever they are.
fn forged_answer(
    dev: &Device,
    binding: AnswerBinding,
    read_set_tlv: Bytes,
    result: &[u8],
    epochs: &[Epoch],
) -> (Name, Bytes) {
    let id = seal::answer_id(&binding, None);
    let name = wire::answer_name(dev.name(), &id);
    let mut w = ndn_tlv::TlvWriter::new();
    w.write_nested(tlv::ANSWER_BODY, |w| {
        w.write_raw(&binding.encode());
        w.write_raw(&read_set_tlv);
        w.write_tlv(tlv::RESULT, result);
    });
    let body = w.finish();
    let _ = epochs;
    let record = AnswerRecord {
        kind: binding.kind,
        content: RecordContent::Plain(body),
    };
    let wire = dev
        .inner
        .sign(DataBuilder::new(name.clone(), &record.encode()))
        .unwrap();
    (name, wire)
}

#[tokio::test]
async fn read_set_faults_are_refused_with_evidence_and_a_withdrawn_read_is_not_evidence() {
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, knowing(vec![sum(1)])).await;
    let phone = w.start("/alice/phone", knowing(vec![sum(1)])).await;
    sync_all(&laptop, &phone);
    let q = pure_question(newest(&laptop, &plan()).await, &sum_v(1));
    let honest = ask(&laptop, &q).await.unwrap();
    let def = honest.binding.definition.clone().unwrap();
    let bind = |reads: Hash| AnswerBinding {
        kind: AnswerKind::Pure,
        definition: Some(def.clone()),
        by: sum_v(1),
        reads,
    };
    let faults_of = faults_taken;

    // A digest that is not the read set's.
    let (_, wrong_digest) = forged_answer(
        &phone,
        bind(Hash([5; 32])),
        honest.reads.encode(),
        b"3",
        &[],
    );
    let e = plant(&laptop, wrong_digest).await.unwrap_err();
    assert!(
        matches!(
            &e,
            DataError::Answer {
                why: AnswerRefusal::ReadSet(_),
                ..
            }
        ),
        "{e:?}"
    );
    assert!(
        faults_of(&laptop)
            .await
            .contains(&AnswerFault::ReadSet(ReadSetFault::Digest))
    );

    // A read set that is not canonical: the reads in the wrong order.
    let mut reads: Vec<ReadRef> = honest.reads.reads().to_vec();
    reads.reverse();
    let mut inner = ndn_tlv::TlvWriter::new();
    for r in &reads {
        inner.write_raw(&r.encode());
    }
    let mut w2 = ndn_tlv::TlvWriter::new();
    w2.write_tlv(tlv::READ_SET, &inner.finish());
    let (_, unsorted) = forged_answer(&phone, bind(Hash([6; 32])), w2.finish(), b"3", &[]);
    let e = plant(&laptop, unsorted).await.unwrap_err();
    assert!(
        matches!(&e, DataError::Answer { why: AnswerRefusal::ReadSet(m), .. } if m.contains("canonical")),
        "{e:?}"
    );
    assert!(
        faults_of(&laptop)
            .await
            .contains(&AnswerFault::ReadSet(ReadSetFault::NotCanonical))
    );

    // A definition that is not one of the reads.
    let other = ReadSet::new([honest.reads.reads()[1].clone()]).unwrap();
    let (_, no_def) = forged_answer(&phone, bind(other.digest()), other.encode(), b"3", &[]);
    let e = plant(&laptop, no_def).await.unwrap_err();
    assert!(
        matches!(
            &e,
            DataError::Answer {
                why: AnswerRefusal::ReadSet(_),
                ..
            }
        ),
        "{e:?}"
    );
    assert!(
        faults_of(&laptop)
            .await
            .contains(&AnswerFault::ReadSet(ReadSetFault::NotItsReads))
    );

    // A read whose digest conflicts with a version this device holds.
    let mut wrong: Vec<ReadRef> = honest.reads.reads().to_vec();
    for r in &mut wrong {
        if let ReadRef::Version { name, digest } = r
            && name.to_string().contains("budget")
        {
            *digest = Hash([9; 32]);
        }
    }
    let conflicting = ReadSet::new(wrong).unwrap();
    let (_, conflict) = forged_answer(
        &phone,
        bind(conflicting.digest()),
        conflicting.encode(),
        b"3",
        &[],
    );
    let e = plant(&laptop, conflict).await.unwrap_err();
    assert!(
        matches!(
            &e,
            DataError::Answer {
                why: AnswerRefusal::ReadSet(_),
                ..
            }
        ),
        "{e:?}"
    );
    assert!(
        faults_of(&laptop)
            .await
            .contains(&AnswerFault::ReadSet(ReadSetFault::HeldConflict))
    );

    // A version withdrawn after the answer: `ReadsChanged`, no evidence.
    let before = events_of(&phone, EventKind::AnswerEvidence).len();
    let (name, good) = {
        let n = laptop.publish_answer(&q).await.unwrap();
        (n.clone(), laptop.inner.stored_answer(&n).unwrap())
    };
    let _ = good;
    phone.inner.store.insert(
        super::answers::stored_name(&name),
        laptop.inner.stored_answer(&name).unwrap(),
    );
    // The phone refuses the budget version since (as a cut or a revocation would).
    let budget_version = honest
        .reads
        .reads()
        .iter()
        .find_map(|r| match r {
            ReadRef::Version { name, .. } if name.to_string().contains("budget") => {
                Some(name.clone())
            }
            _ => None,
        })
        .unwrap();
    {
        let mut st = phone.inner.st.lock();
        st.refused.insert(budget_version, Refusal::NotMember);
    }
    let changed = ask(&phone, &name).await.unwrap_err();
    assert!(
        matches!(
            &changed,
            DataError::Answer {
                why: AnswerRefusal::ReadsChanged(_),
                ..
            }
        ),
        "{changed:?}"
    );
    assert!(changed.retry());
    assert_eq!(changed.next(), crate::NextStep::RetryLater);
    assert_eq!(
        events_of(&phone, EventKind::AnswerEvidence).len(),
        before,
        "no evidence for a withdrawal"
    );
}

// ---- a17: limits --------------------------------------------------------------------------------

#[tokio::test]
async fn limits_are_enforced_and_never_change_a_result() {
    let mut w = World::new();
    // A budget of one read: the evaluation reads two (the definition and an input).
    let tight = Config::new();
    let laptop = alice_with_data(&mut w, |c| Config {
        evaluators: Evaluators::none().with(sum(1)),
        answers: AnswerConfig {
            budget: Budget {
                reads: 1,
                ..tight.answers.budget
            },
            ..AnswerConfig::default()
        },
        ..c
    })
    .await;
    let q = pure_question(newest(&laptop, &plan()).await, &sum_v(1));
    let e = ask(&laptop, &q).await.unwrap_err();
    assert!(
        matches!(
            &e,
            DataError::Answer {
                why: AnswerRefusal::OverBudget { .. },
                ..
            }
        ),
        "{e:?}"
    );
    assert_eq!(e.next(), crate::NextStep::FixLocal);
    // Over the octets of a result.
    let mut w2 = World::new();
    let small = alice_with_data(&mut w2, |c| Config {
        evaluators: Evaluators::none().with(sum(1)),
        answers: AnswerConfig {
            budget: Budget {
                result_bytes: 0,
                ..AnswerConfig::default().budget
            },
            ..AnswerConfig::default()
        },
        ..c
    })
    .await;
    let q2 = pure_question(newest(&small, &plan()).await, &sum_v(1));
    assert!(matches!(
        ask(&small, &q2).await.unwrap_err(),
        DataError::Answer {
            why: AnswerRefusal::OverBudget { .. },
            ..
        }
    ));

    // More reads than READS_MAX is TooLarge; so are too many epochs.
    let many = (0..=crate::answer::READS_MAX as u64).map(|i| ReadRef::Version {
        name: wire::log_name(&n("/alice/laptop"), Some(&budget()), i + 1),
        digest: Hash([1; 32]),
    });
    assert!(matches!(
        ReadSet::new(many),
        Err(AnswerRefusal::TooLarge { .. })
    ));

    // What a device signs per second is bounded.
    let mut w3 = World::new();
    let eager = alice_with_data(&mut w3, |c| Config {
        evaluators: Evaluators::none().with(sum(1)),
        answers: AnswerConfig {
            sign_per_second: 1,
            ..AnswerConfig::default()
        },
        ..c
    })
    .await;
    let mut results = Vec::new();
    for v in 4..7 {
        put_n(&eager, &budget(), v).await;
        let q = pure_question(newest(&eager, &plan()).await, &sum_v(1));
        results.push(eager.publish_answer(&q).await);
    }
    assert!(results[0].is_ok());
    assert!(
        results.iter().any(|r| matches!(
            r,
            Err(DataError::Answer {
                why: AnswerRefusal::OverBudget { .. },
                ..
            })
        )),
        "{results:?}"
    );
}

#[tokio::test]
async fn a_signers_answers_kept_are_capped_forgeries_are_unstored_and_a_provider_keeps_what_it_signed()
 {
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, |c| Config {
        evaluators: Evaluators::none().with(sum(1)),
        answers: AnswerConfig {
            store: AnswerStore {
                per_signer_answers: 2,
                per_signer_bytes: 64 << 20,
                total_bytes: 1 << 30,
            },
            ..AnswerConfig::default()
        },
        ..c
    })
    .await;
    let phone = w.start("/alice/phone", knowing(vec![sum(1)])).await;
    // Three answers of the phone, over three read sets.
    let mut names = Vec::new();
    for v in 4..7 {
        put_n(&laptop, &budget(), v).await;
        sync_all(&laptop, &phone);
        let q = pure_question(newest(&phone, &plan()).await, &sum_v(1));
        names.push(phone.publish_answer(&q).await.unwrap());
    }
    sync_all(&laptop, &phone);
    for n in &names {
        hand(&phone, n, &laptop).await.unwrap();
    }
    assert_eq!(
        laptop.answers_held(),
        2,
        "per signer, the oldest is dropped first"
    );
    assert!(laptop.inner.stored_answer(&names[0]).is_none());
    assert!(laptop.inner.stored_answer(&names[2]).is_some());

    // A forged answer (signed by nobody that verifies) is dropped, not stored.
    let (name, mut wire_bytes) = {
        let n = names[2].clone();
        (n, phone.inner.stored_answer(&names[2]).unwrap().to_vec())
    };
    let last = wire_bytes.len() - 1;
    wire_bytes[last] ^= 0xFF;
    let held = laptop.answers_held();
    let forged = plant(&laptop, Bytes::from(wire_bytes)).await;
    assert!(
        matches!(
            forged,
            Err(DataError::Answer {
                why: AnswerRefusal::Untrusted { .. },
                ..
            })
        ),
        "{forged:?}"
    );
    assert_eq!(laptop.answers_held(), held);
    let _ = name;

    // A provider that cannot keep a new answer refuses it, and drops no old one.
    let mut w2 = World::new();
    let provider = alice_with_data(&mut w2, |c| Config {
        answers: AnswerConfig {
            store: AnswerStore {
                per_signer_answers: 8,
                per_signer_bytes: 64 << 20,
                total_bytes: 4000,
            },
            ..AnswerConfig::default()
        },
        ..c
    })
    .await;
    let inputs = ReadSet::new([newest(&provider, &budget()).await]).unwrap();
    let mut made = Vec::new();
    let mut busy = None;
    for v in 1..20u64 {
        match provider
            .provide(
                &function(v),
                inputs.clone(),
                Bytes::from(vec![v as u8; 300]),
            )
            .await
        {
            Ok(n) => made.push(n),
            Err(e) => {
                busy = Some(e);
                break;
            }
        }
    }
    let busy = busy.expect("the store fills");
    assert!(
        matches!(
            &busy,
            DataError::Answer {
                why: AnswerRefusal::Busy,
                ..
            }
        ),
        "{busy:?}"
    );
    assert_eq!(busy.next(), crate::NextStep::FixLocal);
    for n in &made {
        assert!(
            provider.inner.answer_packet(n).is_some_and(|p| p.is_some()),
            "kept: {n}"
        );
    }
}

// ---- a18: pieces --------------------------------------------------------------------------------

/// An evaluator whose result is `size` octets, so an answer travels in pieces.
struct Big {
    name: Name,
    size: usize,
}

#[async_trait::async_trait]
impl Evaluator for Big {
    fn evaluator(&self) -> &Name {
        &self.name
    }
    async fn plan(&self, _: &Definition, _: &mut dyn Reads) -> Result<(), PlanError> {
        Ok(())
    }
    fn evaluate(&self, _: &Definition, _: &dyn ReadView) -> Result<Bytes, EvalError> {
        Ok(Bytes::from(vec![0x5A; self.size]))
    }
}

#[tokio::test]
async fn a_large_result_travels_in_pieces_sealed_or_not_and_reads_back_whole() {
    for sealed in [false, true] {
        let mut w = World::new();
        let big: Arc<dyn Evaluator> = Arc::new(Big {
            name: n("/conformance/eval/big/v=1"),
            size: 200 * 1024,
        });
        let laptop = match sealed {
            true => sealed_alice(&mut w, knowing(vec![big.clone()]), &["/alice"]).await,
            false => alice_with_data(&mut w, knowing(vec![big.clone()])).await,
        };
        let q = pure_question(newest(&laptop, &plan()).await, big.evaluator());
        let name = laptop.publish_answer(&q).await.unwrap();
        let direct = ask(&laptop, &q).await.unwrap();
        assert_eq!(direct.result.len(), 200 * 1024);
        let d = Data::decode(laptop.inner.stored_answer(&name).unwrap()).unwrap();
        let rec = AnswerRecord::decode(d.content().unwrap().clone()).unwrap();
        let RecordContent::Pieces { size, epochs, .. } = &rec.content else {
            panic!("in pieces: {:?}", rec.content)
        };
        assert!(*size > 200 * 1024 && epochs.is_some() == sealed, "{size}");
        // The pieces are DigestSha256 packets under the answer's name, served with it.
        let piece = wire::piece_name(&name, wire::PieceKind::Chunk(0));
        let w0 = laptop
            .inner
            .answer_packet(&piece)
            .expect("an answer's piece")
            .expect("served");
        assert!(matches!(
            Data::decode(w0).unwrap().sig_info().map(|s| s.sig_type),
            Some(ndn_packet::SignatureType::DigestSha256)
        ));
        assert!(
            wire::parse_piece_name(&piece).is_none(),
            "no custody names an answer's piece"
        );
        // Read back from the store, pieces checked, equal to the direct value.
        let by_name = ask(&laptop, &name).await.unwrap();
        the_same(&by_name, &direct);
        // A piece that is not the one listed is never taken.
        let manifest = wire::piece_name(&name, wire::PieceKind::Manifest(0));
        laptop.inner.store.insert(
            super::answers::stored_name(&manifest),
            laptop.inner.stored_answer(&piece).unwrap(),
        );
        assert!(
            ask(&laptop, &name).await.is_err(),
            "a wrong piece is not accepted"
        );
    }
}

// ---- the events and the verb --------------------------------------------------------------------

#[tokio::test]
async fn names_of_answers_that_do_not_parse_say_how_they_are_formed() {
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, knowing(vec![sum(1)])).await;
    for bad in [
        n("/alice/laptop/32=answer/short"),
        n("/alice/laptop/32=question/nope"),
        n("/alice/32=data/trip/plan/32=question"),
    ] {
        let e = laptop.get(&bad).await.unwrap_err();
        assert!(
            matches!(&e, DataError::BadName { why, .. } if why.contains("answer") || why.contains("question")),
            "{bad}: {e:?}"
        );
        assert_eq!(e.next(), crate::NextStep::FixName);
    }
    // A snapshot pins versions and states, not answers.
    let q = pure_question(newest(&laptop, &plan()).await, &sum_v(1));
    let e = laptop.snapshot(&[q]).await.unwrap_err();
    assert!(matches!(e, DataError::BadRequest { .. }), "{e:?}");
}

#[tokio::test]
async fn a_device_never_computes_for_an_interest_and_serves_only_what_it_signed_or_holds() {
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, with_policy(AnswerPolicy::default(), vec![sum(1)])).await;
    let q = pure_question(newest(&laptop, &plan()).await, &sum_v(1));
    let id = laptop.answer_id(&q).await.unwrap();
    let name = wire::answer_name(&n("/alice/laptop"), &id.0);
    // Not signed, so not served: asking for it makes no answer.
    assert_eq!(laptop.inner.answer_packet(&name), Some(None));
    // Published only when told to: a `get` signs nothing.
    ask(&laptop, &q).await.unwrap();
    assert_eq!(laptop.inner.answer_packet(&name), Some(None));
    let mut w2 = World::new();
    let computed = alice_with_data(&mut w2, |c| Config {
        evaluators: Evaluators::none().with(sum(1)),
        answers: AnswerConfig {
            publish: Publish::Computed,
            ..AnswerConfig::default()
        },
        ..c
    })
    .await;
    let q2 = pure_question(newest(&computed, &plan()).await, &sum_v(1));
    let got = ask(&computed, &q2).await.unwrap();
    let name2 = wire::answer_name(&n("/alice/laptop"), &got.id.0);
    assert!(
        computed
            .inner
            .answer_packet(&name2)
            .is_some_and(|p| p.is_some()),
        "Publish::Computed signs"
    );
    assert_eq!(got.name, name2);
    // The default config signs nothing by itself.
    assert_eq!(Publish::Never, AnswerConfig::default().publish);
    let _ = AtomicU64::new(0).load(AtomicOrdering::Relaxed);
}

// ---- the applied set after a checkpoint (answers.md §3.1, SHAPES-R5 §F.8) -------------------------

#[tokio::test]
async fn devices_that_took_a_checkpoints_past_in_other_orders_agree_on_the_state_they_read() {
    use super::merge_tests as m;
    let e1 = m::version("/alice/phone", 1, &[], m::edit(None, "one"));
    let e2 = m::version("/alice/phone", 2, &[m::tip(&e1)], m::edit(None, "two"));
    let other = m::version("/bob/phone", 1, &[], m::edit(None, "bob's"));
    let cp = m::version(
        "/alice/phone",
        3,
        &[m::tip(&e2)],
        m::checkpoint(&["merged"]),
    );
    // One device applied the covered versions and then the checkpoint; the other took the
    // checkpoint first, and the covered versions after it.
    let x = m::device(m::rules()).await;
    let y = m::device(m::rules()).await;
    for v in [&e1, &e2, &cp, &other] {
        m::give(&x, v);
    }
    for v in [&other, &cp, &e2, &e1] {
        m::give(&y, v);
    }
    let (sx, sy) = (m::state(&x).await, m::state(&y).await);
    assert_eq!(m::notes(&sx), m::notes(&sy), "the same value");
    assert_eq!(sx.at, sy.at);
    let (rx, _) = x.current_read(&m::c()).await.unwrap();
    let (ry, _) = y.current_read(&m::c()).await.unwrap();
    assert_eq!(rx, ry, "one state, one read, on every device");
    // The applied set is what the checkpoint leaves: itself and the concurrent version.
    let ReadRef::State { applied, .. } = &rx else {
        panic!("{rx:?}")
    };
    assert_eq!(
        *applied,
        crate::answer::applied_digest([
            (Writer::new(cp.key.clone()), 3, cp.digest()),
            (Writer::new(other.key.clone()), 1, other.digest()),
        ]),
        "covered versions are not in the applied set"
    );
}

// ---- round 5: who the default policy trusts ----------------------------------------------------

/// The content keys of `cs` that `from` holds, held by `to` as well: `to` is then in their audience.
fn give_keys(from: &Device, to: &Device, cs: &[&Name]) {
    for c in cs {
        let st = from.inner.st.lock();
        let e = st.colls[*c]
            .members
            .as_ref()
            .unwrap()
            .epoch
            .clone()
            .unwrap();
        let k = st.keys.key(c, &e).unwrap();
        drop(st);
        to.inner.st.lock().keys.edit().hold((*c).clone(), e, k);
    }
}

#[tokio::test]
async fn a_reader_only_member_is_not_trusted_for_an_answer_by_default_but_a_writer_and_a_named_signer_are()
 {
    for (writers, trusted_by_default) in [
        (vec![n("/alice")], false),
        (vec![n("/alice"), n("/bob")], true),
    ] {
        let mut w = World::new();
        let laptop = w.start("/alice/laptop", knowing(vec![sum(1)])).await;
        for c in [plan(), budget()] {
            laptop
                .share(
                    &c,
                    Share {
                        rule: Rule::Log,
                        writers: writers.clone(),
                        readers: ["/alice", "/bob", "/dave"]
                            .iter()
                            .map(|r| Audience::Person(n(r)))
                            .collect(),
                    },
                )
                .await
                .unwrap();
        }
        put_n(&laptop, &budget(), 3).await;
        put_def(&laptop, &plan(), &[&budget()]).await;
        let q = pure_question(newest(&laptop, &plan()).await, &sum_v(1));

        // Bob's device reads the folder, with every key, and signs a wrong answer at the right id.
        let bob = w.start("/bob/laptop", knowing(vec![lax_sum(1)])).await;
        give_keys(&laptop, &bob, &[&plan(), &budget()]);
        sync_all(&laptop, &bob);
        let forged = bob.publish_answer(&q).await.unwrap();

        // Dave's reader does not know the evaluator, so it cannot recompute: it trusts by policy.
        let mut readers = Vec::new();
        for (name, policy) in [
            ("/dave/default", AnswerPolicy::default()),
            (
                "/dave/named",
                AnswerPolicy {
                    pure: Signers::Devices(vec![n("/bob/laptop")]),
                    ..AnswerPolicy::default()
                },
            ),
        ] {
            let reader = w.start(name, with_policy(policy, vec![])).await;
            give_keys(&laptop, &reader, &[&plan(), &budget()]);
            sync_all(&laptop, &reader);
            hand(&bob, &forged, &reader).await.unwrap();
            readers.push(reader);
        }
        let by_default = ask(&readers[0], &forged).await;
        match trusted_by_default {
            true => {
                let got = by_default.expect("a writer of the folder is trusted by default");
                assert!(
                    matches!(&got.how, Provenance::Trusted { signer, .. }
                    if *signer == writer(&w.key_of("/bob/laptop"))),
                    "{:?}",
                    got.how
                );
            }
            false => {
                let e = by_default.expect_err(
                    "a member who only reads the folder could not have changed its data, and is \
                     not trusted by default",
                );
                assert!(matches!(&e, DataError::CannotCheck { .. }), "{e:?}");
            }
        }
        // The host names the signer: trusted, whatever the folder's record says.
        let named = ask(&readers[1], &forged)
            .await
            .expect("a signer the policy names");
        assert!(
            matches!(&named.how, Provenance::Trusted { .. }),
            "{:?}",
            named.how
        );
    }
}

#[tokio::test]
async fn a_suspected_key_is_neither_taken_nor_served_for_answers_until_unsuspected() {
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, knowing(vec![sum(1)])).await;
    let phone = w.start("/alice/phone", knowing(vec![])).await;
    sync_all(&laptop, &phone);
    let q = pure_question(newest(&laptop, &plan()).await, &sum_v(1));
    let name = laptop.publish_answer(&q).await.unwrap();
    let key = w.key_of("/alice/laptop");
    hand(&laptop, &name, &phone).await.unwrap();
    assert!(
        ask(&phone, &name).await.is_ok(),
        "the person's own device is trusted"
    );
    assert!(matches!(phone.inner.answer_packet(&name), Some(Some(_))));

    // The owner marks the key suspected, as log entries of it are refused (Device::suspect).
    phone.suspect(&key, Timestamp(1)).unwrap();
    let wire = laptop.inner.stored_answer(&name).unwrap();
    let refused = plant(&phone, wire.clone()).await.unwrap_err();
    assert!(
        matches!(&refused, DataError::Answer { why: AnswerRefusal::Untrusted { why }, .. } if why.contains("suspected")),
        "a suspected key's answer is not taken: {refused:?}"
    );
    let by_name = ask(&phone, &name).await.unwrap_err();
    assert!(
        matches!(
            &by_name,
            DataError::Answer {
                why: AnswerRefusal::Untrusted { .. },
                ..
            }
        ),
        "{by_name:?}"
    );
    assert_eq!(
        phone.inner.answer_packet(&name),
        Some(None),
        "and the one held is not served onward"
    );

    // Unsuspected, it is taken and served again.
    assert!(phone.unsuspect(&key));
    assert!(ask(&phone, &name).await.is_ok());
    assert!(matches!(phone.inner.answer_packet(&name), Some(Some(_))));
}

#[tokio::test]
async fn an_own_answer_made_before_an_evaluator_changed_is_dropped_and_recomputed_not_blamed() {
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, knowing(vec![sum(1)])).await;
    let q = pure_question(newest(&laptop, &plan()).await, &sum_v(1));
    let name = laptop.publish_answer(&q).await.unwrap();
    assert_eq!(
        ask(&laptop, &q).await.unwrap().result,
        Bytes::from_static(b"3")
    );
    assert!(laptop.inner.stored_answer(&name).is_some());

    // The host is upgraded, and the evaluator of the same name and version now gives another
    // output.
    let laptop = w.restart("/alice/laptop", knowing(vec![lax_sum(1)])).await;
    let got = ask(&laptop, &name).await.unwrap();
    assert_eq!(
        got.result,
        Bytes::from_static(b"4"),
        "the value is the recomputed one"
    );
    assert!(
        matches!(&got.how, Provenance::Recomputed { confirmed_by, disagreed_with }
        if confirmed_by.is_empty() && disagreed_with.is_empty()),
        "{:?}",
        got.how
    );
    assert!(
        events_of(&laptop, EventKind::AnswerEvidence).is_empty(),
        "no evidence against this device's own key: {:?}",
        laptop.pending_events()
    );
    assert!(
        !laptop.inner.st.lock().answer_book.is_blocked_name(&name),
        "the name is not blocked"
    );
    assert!(
        laptop.inner.stored_answer(&name).is_none(),
        "the stale answer is dropped, not kept as evidence nor served"
    );
    assert_eq!(laptop.inner.answer_packet(&name), Some(None));
    assert_eq!(
        ask(&laptop, &q).await.unwrap().result,
        Bytes::from_static(b"4")
    );
    assert!(
        laptop
            .inner
            .store
            .scan_under(&n("/localhost/ndn-data/answer-evidence"), 0)
            .is_empty()
    );
}

// ---- round 5: evidence blames only a signer at fault -------------------------------------------

/// Two packets of one writer at one name: `from`'s only version of `c` (its name, packet and
/// writer) and a second, signed by the same key with another date.
fn twin_of(from: &Device, c: &Name) -> (Name, Bytes, Writer, Bytes) {
    let (name, wire, writer) = {
        let st = from.inner.st.lock();
        let hv = st.colls[c].versions.values().next().expect("a version");
        (
            hv.version.name.clone(),
            hv.wire.clone(),
            hv.version.id.writer.clone(),
        )
    };
    let data = Data::decode(wire.clone()).unwrap();
    let Record::Version(mut body) = wire::decode_record(data.content().unwrap().clone()).unwrap()
    else {
        panic!("a version")
    };
    body.dated = Timestamp(body.dated.0 + 1);
    let twin = from
        .inner
        .sign(DataBuilder::new(
            name.clone(),
            &wire::encode_record(&Record::Version(body)),
        ))
        .unwrap();
    (name, wire, writer, twin)
}

/// `wire`, a packet of the log entry `name`, taken by `to` as a peer's.
fn take_entry(to: &Device, name: &Name, wire: Bytes, writer: &Writer) {
    let data = Data::decode(wire.clone()).unwrap();
    let record = wire::decode_record(data.content().unwrap().clone()).unwrap();
    let mut st = to.inner.st.lock();
    to.inner
        .take(&mut st, name.clone(), wire, writer.clone(), record, false);
}

#[tokio::test]
async fn a_read_of_a_version_its_writer_signed_twice_is_no_evidence_against_the_signer() {
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, knowing(vec![sum(1)])).await;
    let (name, _, writer_key, twin) = twin_of(&laptop, &budget());
    // The signer holds the writer's second packet at the name, and answers honestly over it.
    let phone = w.start("/alice/phone", knowing(vec![sum(1)])).await;
    sync_except(&laptop, &phone, Some(&name));
    take_entry(&phone, &name, twin.clone(), &writer_key);
    let q = pure_question(newest(&phone, &plan()).await, &sum_v(1));
    let signed = phone.publish_answer(&q).await.unwrap();
    let packet = phone.inner.stored_answer(&signed).unwrap();

    // A reader that holds the first packet, and then learns of the second: the read it holds
    // differs, and the writer is the one at fault.
    let tablet = w.start("/alice/tablet", knowing(vec![])).await;
    sync_all(&laptop, &tablet);
    take_entry(&tablet, &name, twin, &writer_key);
    assert_eq!(
        events_of(&tablet, EventKind::Equivocation).len(),
        1,
        "the writer's equivocation is told"
    );
    let refused = plant(&tablet, packet).await.unwrap_err();
    assert!(
        matches!(&refused, DataError::Answer { why: AnswerRefusal::ReadsChanged(m), .. } if m.contains("equivocation")),
        "refused for what it is, not blamed on its signer: {refused:?}"
    );
    assert!(
        events_of(&tablet, EventKind::AnswerEvidence).is_empty(),
        "no evidence against the honest signer: {:?}",
        tablet.pending_events()
    );
    assert!(!tablet.inner.st.lock().answer_book.is_blocked_name(&signed));
}

#[tokio::test]
async fn evidence_of_what_a_device_holds_ends_when_the_equivocation_is_found_or_the_read_is_withdrawn()
 {
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, knowing(vec![sum(1)])).await;
    let (name, _, writer_key, twin) = twin_of(&laptop, &budget());
    let phone = w.start("/alice/phone", knowing(vec![sum(1)])).await;
    sync_except(&laptop, &phone, Some(&name));
    take_entry(&phone, &name, twin.clone(), &writer_key);
    let q = pure_question(newest(&phone, &plan()).await, &sum_v(1));
    let signed = phone.publish_answer(&q).await.unwrap();
    let packet = phone.inner.stored_answer(&signed).unwrap();
    let is_kept = |dev: &Device| {
        !dev.inner
            .store
            .scan_under(&n("/localhost/ndn-data/answer-evidence"), 0)
            .is_empty()
    };

    // Held the first packet only, a read of the second is a conflict: evidence, and a block.
    let tablet = w.start("/alice/tablet", knowing(vec![])).await;
    sync_all(&laptop, &tablet);
    let e = plant(&tablet, packet.clone()).await.unwrap_err();
    assert!(
        matches!(
            &e,
            DataError::Answer {
                why: AnswerRefusal::ReadSet(_),
                ..
            }
        ),
        "{e:?}"
    );
    assert_eq!(events_of(&tablet, EventKind::AnswerEvidence).len(), 1);
    assert!(tablet.inner.st.lock().answer_book.is_blocked_name(&signed));
    assert!(is_kept(&tablet));
    // Met again while the fault stands: refused as blocked, and not told again.
    let again = plant(&tablet, packet.clone()).await.unwrap_err();
    assert!(
        matches!(
            &again,
            DataError::Answer {
                why: AnswerRefusal::Equivocal,
                ..
            }
        ),
        "{again:?}"
    );
    assert_eq!(events_of(&tablet, EventKind::AnswerEvidence).len(), 1);

    // The writer's second packet arrives: the signer is no longer at fault, and the block ends.
    take_entry(&tablet, &name, twin, &writer_key);
    let lifted = plant(&tablet, packet.clone()).await.unwrap_err();
    assert!(
        matches!(
            &lifted,
            DataError::Answer {
                why: AnswerRefusal::ReadsChanged(_),
                ..
            }
        ),
        "judged afresh, no longer the signer's fault: {lifted:?}"
    );
    assert!(!tablet.inner.st.lock().answer_book.is_blocked_name(&signed));
    assert!(!is_kept(&tablet), "the evidence is gone from the store too");

    // The same ending when the version read is withdrawn since (a cut, a revocation).
    let mut w2 = World::new();
    let laptop2 = alice_with_data(&mut w2, knowing(vec![sum(1)])).await;
    let phone2 = w2.start("/alice/phone", knowing(vec![sum(1)])).await;
    sync_all(&laptop2, &phone2);
    let q2 = pure_question(newest(&laptop2, &plan()).await, &sum_v(1));
    let honest = ask(&laptop2, &q2).await.unwrap();
    let def = honest.binding.definition.clone().unwrap();
    let mut wrong: Vec<ReadRef> = honest.reads.reads().to_vec();
    let mut budget_version = None;
    for r in &mut wrong {
        if let ReadRef::Version { name, digest } = r
            && name.to_string().contains("budget")
        {
            *digest = Hash([9; 32]);
            budget_version = Some(name.clone());
        }
    }
    let conflicting = ReadSet::new(wrong).unwrap();
    let (forged_name, conflict) = forged_answer(
        &phone2,
        AnswerBinding {
            kind: AnswerKind::Pure,
            definition: Some(def),
            by: sum_v(1),
            reads: conflicting.digest(),
        },
        conflicting.encode(),
        b"3",
        &[],
    );
    assert!(plant(&laptop2, conflict.clone()).await.is_err());
    assert_eq!(events_of(&laptop2, EventKind::AnswerEvidence).len(), 1);
    assert!(is_kept(&laptop2));
    laptop2
        .inner
        .st
        .lock()
        .refused
        .insert(budget_version.unwrap(), Refusal::NotMember);
    let gone = plant(&laptop2, conflict).await.unwrap_err();
    assert!(
        matches!(
            &gone,
            DataError::Answer {
                why: AnswerRefusal::ReadsChanged(_),
                ..
            }
        ),
        "{gone:?}"
    );
    assert!(!is_kept(&laptop2), "durably: nothing is kept to load again");
    let laptop2 = w2.restart("/alice/laptop", knowing(vec![sum(1)])).await;
    assert!(
        !laptop2
            .inner
            .st
            .lock()
            .answer_book
            .is_blocked_name(&forged_name)
    );
}

#[tokio::test]
async fn a_version_withdrawn_since_changes_the_epochs_of_a_state_and_is_a_changed_read_not_a_fault()
{
    use super::merge_tests as m;
    let f = function(1);
    let tune = |policy: AnswerPolicy| {
        move |c: Config| Config {
            rules: m::rules(),
            answers: AnswerConfig {
                policy,
                ..AnswerConfig::default()
            },
            ..c
        }
    };
    let named = || AnswerPolicy {
        providers: vec![(f.clone(), Signers::Devices(vec![n("/alice/phone")]))],
        ..AnswerPolicy::default()
    };
    let mut w = World::new();
    let c = m::c();
    let laptop = w.start("/alice/laptop", tune(named())).await;
    let sealed_to = |readers: &[&str]| Share {
        rule: Rule::Merge {
            function: n(m::RULE),
        },
        writers: vec![n("/alice")],
        readers: readers.iter().map(|r| Audience::Person(n(r))).collect(),
    };
    laptop
        .share(&c, sealed_to(&["/alice", "/bob"]))
        .await
        .unwrap();
    let first_epoch = laptop.inner.st.lock().colls[&c]
        .members
        .as_ref()
        .unwrap()
        .epoch
        .clone();
    let first_key = laptop
        .inner
        .st
        .lock()
        .keys
        .key(&c, first_epoch.as_ref().unwrap())
        .unwrap();
    // The phone writes one version in the first epoch.
    let phone = w.start("/alice/phone", tune(named())).await;
    sync_all(&laptop, &phone);
    give_keys(&laptop, &phone, &[&c]);
    phone
        .put_op(&c, m::edit(None, "one"), options())
        .await
        .unwrap();
    // A reader is removed: a second epoch. The phone writes its next version in it.
    sync_all(&phone, &laptop);
    laptop.share(&c, sealed_to(&["/alice"])).await.unwrap();
    let second_epoch = laptop.inner.st.lock().colls[&c]
        .members
        .as_ref()
        .unwrap()
        .epoch
        .clone();
    let second_key = laptop
        .inner
        .st
        .lock()
        .keys
        .key(&c, second_epoch.as_ref().unwrap())
        .unwrap();
    assert_ne!(
        first_epoch, second_epoch,
        "removing a reader starts an epoch"
    );
    sync_all(&laptop, &phone);
    give_keys(&laptop, &phone, &[&c]);
    phone
        .put_op(&c, m::edit(None, "two"), options())
        .await
        .unwrap();

    // The phone signs an answer of the function over the state it holds, in both epochs.
    let (state, _) = phone.current_read(&c).await.unwrap();
    let inputs = ReadSet::new([state]).unwrap();
    let name = phone
        .provide(&f, inputs, Bytes::from_static(b"summary"))
        .await
        .unwrap();

    // A reader holds all of it, with the keys of both epochs, and takes the answer.
    let tablet = w.start("/alice/tablet", tune(named())).await;
    for (e, key) in [(&first_epoch, &first_key), (&second_epoch, &second_key)] {
        let e = e.clone().expect("an epoch");
        tablet
            .inner
            .st
            .lock()
            .keys
            .edit()
            .hold(c.clone(), e, key.clone());
    }
    sync_all(&laptop, &tablet);
    sync_all(&phone, &tablet);
    hand(&phone, &name, &tablet)
        .await
        .expect("both epochs are held, and the answer opens");
    let answered = ask(&tablet, &name)
        .await
        .expect("a provider the policy names");
    assert!(matches!(answered.how, Provenance::Provider { .. }));

    // The reader withdraws the version of the first epoch (a cut, a revocation): the epochs the
    // state is computed from change, and the signer listed the right ones when it signed.
    let (v1_name, v1_writer, v1_digest) = {
        let st = tablet.inner.st.lock();
        let versions = &st.colls[&c].versions;
        let hv = versions
            .values()
            .filter(|hv| hv.version.id.writer.key().has_prefix(&n("/alice/phone")))
            .min_by_key(|hv| hv.version.id.seq.0)
            .unwrap_or_else(|| panic!("the first version, among {} held", versions.len()));
        (
            hv.version.name.clone(),
            hv.version.id.writer.clone(),
            hv.digest,
        )
    };
    {
        let mut st = tablet.inner.st.lock();
        tablet.inner.withdraw(
            &mut st,
            vec![(
                v1_name,
                v1_writer,
                v1_digest,
                Refusal::Untrusted {
                    why: "a cut".into(),
                },
            )],
        );
    }
    let before = events_of(&tablet, EventKind::AnswerEvidence).len();
    let changed = ask(&tablet, &name).await.unwrap_err();
    assert!(
        matches!(
            &changed,
            DataError::Answer {
                why: AnswerRefusal::ReadsChanged(_),
                ..
            }
        ),
        "a read withdrawn since, not a fault of the signer: {changed:?}"
    );
    assert_eq!(
        events_of(&tablet, EventKind::AnswerEvidence).len(),
        before,
        "{:?}",
        tablet.pending_events()
    );
    assert!(!tablet.inner.st.lock().answer_book.is_blocked_name(&name));
}

// ---- round 5: evidence is bounded ---------------------------------------------------------------

/// How many packets of evidence `dev` holds in its store, and their octets.
fn evidence_stored(dev: &Device) -> (usize, usize) {
    let all = dev
        .inner
        .store
        .scan_under(&n("/localhost/ndn-data/answer-evidence"), 0);
    (all.len(), all.iter().map(|(_, w)| w.len()).sum())
}

#[tokio::test]
async fn evidence_kept_against_signers_is_capped_per_signer_in_all_and_the_oldest_goes_first() {
    use super::answers::{
        Cause, EVIDENCE_PACKETS_PER_ANSWER, EVIDENCE_PER_SIGNER_ANSWERS, EVIDENCE_PER_SIGNER_BYTES,
        EVIDENCE_SIGNERS,
    };
    let keep = |dev: &Device, name: &Name, signer: &Name, wire: Vec<u8>| {
        let mut st = dev.inner.st.lock();
        dev.inner.keep_evidence(
            &mut st,
            name,
            AnswerKind::Pure,
            signer,
            &Bytes::from(wire),
            Cause::Signed,
        );
    };
    let blocked = |dev: &Device, name: &Name| dev.inner.st.lock().answer_book.is_blocked_name(name);

    // A hostile signer answers one question after another with a read set that is not its own:
    // each is a fault, and each is kept as evidence, but only so many.
    let mut w = World::new();
    let laptop = alice_with_data(&mut w, knowing(vec![sum(1)])).await;
    let phone = w.start("/alice/phone", knowing(vec![sum(1)])).await;
    sync_all(&laptop, &phone);
    let q = pure_question(newest(&laptop, &plan()).await, &sum_v(1));
    let honest = ask(&laptop, &q).await.unwrap();
    let def = honest.binding.definition.clone().unwrap();
    let asked = EVIDENCE_PER_SIGNER_ANSWERS + 6;
    let mut names = Vec::new();
    for i in 0..asked {
        let (name, wire) = forged_answer(
            &phone,
            AnswerBinding {
                kind: AnswerKind::Pure,
                definition: Some(def.clone()),
                by: sum_v(1),
                reads: Hash([i as u8 + 1; 32]),
            },
            honest.reads.encode(),
            b"3",
            &[],
        );
        assert!(plant(&laptop, wire).await.is_err());
        names.push(name);
    }
    assert_eq!(
        evidence_stored(&laptop).0,
        EVIDENCE_PER_SIGNER_ANSWERS,
        "evidence against one signer is capped"
    );
    for (i, name) in names.iter().enumerate() {
        assert_eq!(
            blocked(&laptop, name),
            i >= asked - EVIDENCE_PER_SIGNER_ANSWERS,
            "the oldest go first: answer {i} of {asked}"
        );
    }

    // The octets kept against one signer, whole packets of 64 KiB.
    let laptop = alice_with_data(&mut World::new(), knowing(vec![])).await;
    let hostile = n("/hostile/KEY/1");
    let named = |i: usize| wire::answer_name(&n("/hostile/laptop"), &[i as u8; 32]);
    let packet = 64 << 10;
    let fit = EVIDENCE_PER_SIGNER_BYTES as usize / packet;
    for i in 0..fit + 3 {
        keep(&laptop, &named(i), &hostile, vec![i as u8; packet]);
    }
    assert_eq!(
        evidence_stored(&laptop).0,
        fit,
        "octets kept per signer are capped"
    );
    assert!(!blocked(&laptop, &named(0)) && blocked(&laptop, &named(fit + 2)));

    // The signers evidence is kept against.
    let laptop = alice_with_data(&mut World::new(), knowing(vec![])).await;
    let signer = |i: usize| n(&format!("/hostile{i}/KEY/1"));
    let answer = |i: usize| wire::answer_name(&n(&format!("/hostile{i}/laptop")), &[1; 32]);
    let last = EVIDENCE_SIGNERS + 5;
    for i in 0..=last {
        keep(
            &laptop,
            &answer(i),
            &signer(i),
            vec![i as u8, (i >> 8) as u8],
        );
    }
    assert_eq!(
        evidence_stored(&laptop).0,
        EVIDENCE_SIGNERS,
        "signers evidence is kept against are capped"
    );
    assert!(!blocked(&laptop, &answer(0)) && blocked(&laptop, &answer(last)));

    // The packets kept at one answer name of one signer.
    let laptop = alice_with_data(&mut World::new(), knowing(vec![])).await;
    for i in 0..EVIDENCE_PACKETS_PER_ANSWER + 4 {
        keep(&laptop, &named(0), &hostile, vec![i as u8; 8]);
    }
    assert_eq!(evidence_stored(&laptop).0, EVIDENCE_PACKETS_PER_ANSWER);
    assert!(blocked(&laptop, &named(0)), "the block stands past the cap");
}
