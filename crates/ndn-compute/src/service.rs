//! [`ComputeService`] — the ergonomic, engine-attached front door.
//!
//! `attach` allocates the synthetic [`ComputeFace`](crate::ComputeFace) on a
//! live engine; each registration wires a FIB route for the function prefix to
//! that face. Results are injected back into the pipeline and cached like any
//! other Data.

use std::collections::HashMap;
use std::future::Future;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::CancellationToken;

use ndn_app::Consumer;
use ndn_engine::ForwarderEngine;
use ndn_face_local::InProcFace;
use ndn_mgmt::{ComputeDeterminism, ComputeFnKind, ComputeFunctionInfo, ComputeMgmtBackend};
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Interest, KeyLocator, Name, NameComponent};
use ndn_security::{SafeData, Validator};
use ndn_transport::{FaceId, FacePersistency};

use bytes::Bytes;

use crate::codec::{ComputeArgs, ComputeValue};
use crate::compute_face::ComputeFace;
use crate::executor::ComputeExecutor;
use crate::registry::{ComputeError, ComputeHandler, ComputeRegistry};
use crate::thunk::Thunk;

/// Freshness stamped on transparent function results, bounding how long the
/// Content Store memoizes them.
///
/// # Caching contract (when is a cached result authoritative vs. recompute)
///
/// A transparent result is named entirely by `(function, args)` (the
/// invocation name), so a cached Data object **is** the authoritative answer
/// for that name for as long as it is fresh. Concretely:
///
/// - **Within the freshness window** (`FreshnessPeriod > 0`, default here),
///   any cache or downstream node MAY serve the stored result without
///   recomputing — including satisfying a `MustBeFresh` Interest. The result
///   is reconstructible by any party from the name alone, so re-serving it is
///   indistinguishable from recomputing it.
/// - **Past the window**, a `MustBeFresh` Interest no longer matches the stored
///   copy and the request reaches the service, which recomputes. A non-fresh
///   (`MustBeFresh = false`) Interest may still be satisfied from cache — the
///   caller has opted into a possibly-stale answer.
/// - **Opaque** results ([`Determinism::Opaque`]) are stamped non-fresh and
///   name-disambiguated by a per-call nonce, so they are never authoritative
///   for a *different* call and are always recomputed.
///
/// This is the rule NDF references a compute result from a Block by: the name
/// is stable, and freshness — not the serving face — decides authority.
pub const DEFAULT_TRANSPARENT_FRESHNESS: Duration = Duration::from_secs(4);

/// Whether a function's result is determined solely by the invocation name.
///
/// See the module-level determinism contract in the crate docs and the
/// caching contract on [`DEFAULT_TRANSPARENT_FRESHNESS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Determinism {
    /// Result depends only on the name → cacheable, PIT-aggregatable, and
    /// authoritative-while-fresh (any holder may re-serve it).
    Transparent,
    /// Result may vary per call → the client adds a trailing nonce component
    /// and the result is non-fresh, so calls never alias and are always
    /// recomputed rather than served from cache.
    Opaque,
}

/// Component appended to a job prefix to form its thunk-poll namespace.
const THUNK_KEYWORD: &str = "thunk";

#[derive(Clone)]
enum JobState {
    Pending,
    Done(Bytes),
    Failed(String),
}

type JobStore = Arc<Mutex<HashMap<Name, JobState>>>;

/// Handle a compute function uses to pull inputs *by reference*: it issues an
/// in-process Interest for a parameter name and returns the response content.
///
/// This is the NFN-style "dereference an argument name" model (wire spec §3.2),
/// not RICE reflexive forwarding (§8): the parameter name must be routable to a
/// producer. Fetches through one shared in-process consumer are serialized.
#[derive(Clone)]
pub struct ComputeContext {
    fetcher: Arc<AsyncMutex<Consumer>>,
}

impl ComputeContext {
    /// Fetch `name` and return its Data content.
    pub async fn fetch(&self, name: impl Into<Name>) -> Result<Bytes, ComputeError> {
        let mut consumer = self.fetcher.lock().await;
        let data = consumer
            .fetch(name)
            .await
            .map_err(|e| ComputeError::ComputeFailed(format!("parameter fetch: {e}")))?;
        data.content()
            .map(|b| Bytes::copy_from_slice(b))
            .ok_or_else(|| ComputeError::ComputeFailed("parameter Data had no content".into()))
    }

    /// Fetch `name` and return it only if its signature validates against
    /// `validator`. A validation failure is an error (the computation is gated
    /// on it).
    pub async fn fetch_verified(
        &self,
        name: impl Into<Name>,
        validator: &Validator,
    ) -> Result<SafeData, ComputeError> {
        let mut consumer = self.fetcher.lock().await;
        consumer
            .fetch_verified(name, validator)
            .await
            .map_err(|e| ComputeError::ComputeFailed(format!("parameter fetch/verify: {e}")))
    }
}

/// An engine-attached registry of named compute functions.
///
/// Cheap to clone — every clone shares the same registry, face, and FIB wiring.
#[derive(Clone)]
pub struct ComputeService {
    engine: ForwarderEngine,
    face_id: FaceId,
    registry: Arc<ComputeRegistry>,
    cancel: CancellationToken,
    cost: u32,
    jobs: JobStore,
    /// Introspection table mirroring registrations, keyed by prefix, for the
    /// `compute` management dataset. Recorded at registration; the most
    /// specific label (typed/executor/reflexive/job) overwrites the Tier-0
    /// `Raw` note that [`register`](Self::register) lays down.
    functions: Arc<Mutex<HashMap<Name, FnRec>>>,
    /// Lazily created in-process consumer face used by `function_ref` handlers
    /// to pull parameters by reference. Created on first such registration so
    /// services that never use it pay nothing.
    fetcher: Arc<OnceLock<Arc<AsyncMutex<Consumer>>>>,
}

impl ComputeService {
    /// Attach a compute service to a running engine, allocating its synthetic
    /// face. The face is `Permanent`, so it is never idle-reaped.
    pub fn attach(engine: &ForwarderEngine) -> Self {
        Self::attach_with_cancel(engine, CancellationToken::new())
    }

    /// Like [`Self::attach`], but ties the compute face's lifetime to a caller
    /// supplied token (e.g. the engine's shutdown token) instead of an
    /// independent one.
    pub fn attach_with_cancel(engine: &ForwarderEngine, cancel: CancellationToken) -> Self {
        let face_id = engine.faces().alloc_id();
        let registry = Arc::new(ComputeRegistry::new());
        let face = ComputeFace::new(face_id, Arc::clone(&registry));
        engine.add_face_with_persistency(face, cancel.clone(), FacePersistency::Permanent);
        Self {
            engine: engine.clone(),
            face_id,
            registry,
            cancel,
            cost: 0,
            jobs: Arc::new(Mutex::new(HashMap::new())),
            functions: Arc::new(Mutex::new(HashMap::new())),
            fetcher: Arc::new(OnceLock::new()),
        }
    }

    /// Record a registration in the introspection table.
    fn note(
        &self,
        prefix: &Name,
        determinism: Determinism,
        kind: ComputeFnKind,
        fuel: Option<u64>,
    ) {
        self.functions.lock().unwrap().insert(
            prefix.clone(),
            FnRec {
                determinism,
                kind,
                fuel,
            },
        );
    }

    /// Snapshot of the registered compute functions (the `compute/list`
    /// dataset). Sorted by name for stable output.
    pub fn functions(&self) -> Vec<ComputeFunctionInfo> {
        snapshot(&self.functions)
    }

    /// A read-only [`ComputeMgmtBackend`] over this service's function table,
    /// for wiring into `MgmtHandles.compute_handler` so `/localhost/nfd/compute/list`
    /// reports the registered functions.
    pub fn mgmt_backend(&self) -> Arc<dyn ComputeMgmtBackend> {
        Arc::new(ComputeMgmtAdapter {
            functions: Arc::clone(&self.functions),
        })
    }

    /// The shared parameter-fetch consumer, created on first use: an in-process
    /// `Permanent` face wired to the engine.
    fn fetch_context(&self) -> ComputeContext {
        let fetcher = self
            .fetcher
            .get_or_init(|| {
                let id = self.engine.faces().alloc_id();
                let (face, handle) = InProcFace::new(id, 256);
                self.engine.add_face_with_persistency(
                    face,
                    self.cancel.clone(),
                    FacePersistency::Permanent,
                );
                Arc::new(AsyncMutex::new(Consumer::from_handle(handle)))
            })
            .clone();
        ComputeContext { fetcher }
    }

    /// The synthetic compute face's id.
    pub fn face_id(&self) -> FaceId {
        self.face_id
    }

    /// Tier 3 (RICE §8): register a function whose input is pulled *by
    /// reference over the reflexive path*. The invocation Interest carries a
    /// `REFLEXIVE_NAME` `R`; the node Interests `R/params` back along the
    /// reverse path the Interest came in on (no routable prefix needed on the
    /// consumer), receives the parameters as Data, computes, and answers.
    ///
    /// The consumer must (a) attach a reflexive name to the invocation
    /// (`InterestBuilder::reflexive_name` / `random_reflexive_name`), (b) make
    /// the invocation name unique per call — reflexive results are opaque, so
    /// distinct calls must not PIT-aggregate — and (c) serve `R/params`. Needs
    /// a multi-hop reflexive-forwarding-aware path (or a single hop).
    pub fn function_reflexive<O, F, Fut>(&self, prefix: impl Into<Name>, f: F)
    where
        O: ComputeValue + Send + 'static,
        F: Fn(Bytes) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<O, ComputeError>> + Send,
    {
        let handler = ReflexiveHandler {
            f: Arc::new(f),
            ctx: self.fetch_context(),
            _pd: PhantomData,
        };
        let prefix = prefix.into();
        self.register(prefix.clone(), handler);
        self.note(&prefix, Determinism::Opaque, ComputeFnKind::Reflexive, None);
    }

    /// Tier 3 (RICE §8, confidential): like [`Self::function_reflexive`], but
    /// the parameters are pulled back **encrypted**. The node advertises an
    /// ephemeral X25519 public key on the reverse Interest (`R/params/<pubkey>`),
    /// the consumer seals the params to it ([`seal`](crate::seal)), and the node
    /// decrypts — so on-path forwarders cannot read the params.
    ///
    /// Confidentiality only: pair with the authorization leg (signed D2) to
    /// also defeat an active on-path MITM of the key exchange. Requires the
    /// `sealed-params` feature.
    #[cfg(feature = "sealed-params")]
    pub fn function_reflexive_sealed<O, F, Fut>(&self, prefix: impl Into<Name>, f: F)
    where
        O: ComputeValue + Send + 'static,
        F: Fn(Bytes) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<O, ComputeError>> + Send,
    {
        let handler = SealedReflexiveHandler {
            f: Arc::new(f),
            ctx: self.fetch_context(),
            _pd: PhantomData,
        };
        let prefix = prefix.into();
        self.register(prefix.clone(), handler);
        self.note(&prefix, Determinism::Opaque, ComputeFnKind::Reflexive, None);
    }

    /// Tier 3 (RICE §8, authenticated **and** confidential): the secure
    /// default. The params pulled over the reverse path are both **encrypted**
    /// (sealed to the node's ephemeral key) and carried in **signed** Data that
    /// must validate against `validator`. Validating the signature over the
    /// sealed blob binds the ephemeral key exchange to an authenticated
    /// identity, so it resists the active-MITM that plain
    /// [`function_reflexive_sealed`](Self::function_reflexive_sealed) is open
    /// to. The closure receives the decrypted params and the verified signer.
    /// Requires the `sealed-params` feature.
    #[cfg(feature = "sealed-params")]
    pub fn function_reflexive_secure<O, F, Fut>(
        &self,
        prefix: impl Into<Name>,
        validator: Arc<Validator>,
        f: F,
    ) where
        O: ComputeValue + Send + 'static,
        F: Fn(Bytes, Option<Name>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<O, ComputeError>> + Send,
    {
        let handler = SecureReflexiveHandler {
            f: Arc::new(f),
            ctx: self.fetch_context(),
            validator,
            _pd: PhantomData,
        };
        let prefix = prefix.into();
        self.register(prefix.clone(), handler);
        self.note(&prefix, Determinism::Opaque, ComputeFnKind::Reflexive, None);
    }

    /// Tier 3 (RICE §8, authenticated): like [`Self::function_reflexive`], but
    /// the parameters pulled over the reverse path (`R/params`) must be **signed
    /// Data that validates against `validator`** before the computation runs.
    /// This is RICE's authorization leg — the consumer authenticates in the
    /// I2/D2 exchange, decoupled from the (unauthenticated) invocation. The
    /// closure also receives the verified signer's key name (the `KeyLocator`),
    /// for per-signer authorization or accounting; it is `None` for
    /// `DigestSha256` (integrity-only) params.
    ///
    /// Confidentiality (an encrypted-parameter key exchange) is out of scope —
    /// params travel in cleartext over the reverse path within the trust domain.
    pub fn function_reflexive_authenticated<O, F, Fut>(
        &self,
        prefix: impl Into<Name>,
        validator: Arc<Validator>,
        f: F,
    ) where
        O: ComputeValue + Send + 'static,
        F: Fn(Bytes, Option<Name>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<O, ComputeError>> + Send,
    {
        let handler = AuthReflexiveHandler {
            f: Arc::new(f),
            ctx: self.fetch_context(),
            validator,
            _pd: PhantomData,
        };
        let prefix = prefix.into();
        self.register(prefix.clone(), handler);
        self.note(&prefix, Determinism::Opaque, ComputeFnKind::Reflexive, None);
    }

    /// Tier 0: register an arbitrary [`ComputeHandler`] at `prefix` and wire a
    /// FIB route to the compute face.
    pub fn register<H: ComputeHandler>(&self, prefix: impl Into<Name>, handler: H) {
        let prefix = prefix.into();
        self.registry.register(&prefix, handler);
        self.engine
            .fib()
            .add_nexthop(&prefix, self.face_id, self.cost);
        // Tier-0 default; higher-level methods overwrite with a more
        // specific label after delegating here.
        self.note(&prefix, Determinism::Transparent, ComputeFnKind::Raw, None);
    }

    /// Tier 1: register a transparent typed function. Arguments are decoded
    /// from the name components after `prefix`; the result is framed as the
    /// response Data content with [`DEFAULT_TRANSPARENT_FRESHNESS`], so repeat
    /// calls hit the Content Store and concurrent identical calls coalesce.
    pub fn function<A, O, F, Fut>(&self, prefix: impl Into<Name>, f: F)
    where
        A: ComputeArgs + Send + 'static,
        O: ComputeValue + Send + 'static,
        F: Fn(A) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<O, ComputeError>> + Send,
    {
        let prefix = prefix.into();
        let handler = TypedHandler {
            f,
            prefix_len: prefix.len(),
            determinism: Determinism::Transparent,
            freshness: Some(DEFAULT_TRANSPARENT_FRESHNESS),
            _pd: PhantomData,
        };
        self.register(prefix.clone(), handler);
        self.note(
            &prefix,
            Determinism::Transparent,
            ComputeFnKind::Typed,
            None,
        );
    }

    /// Tier 1+: register a transparent typed function whose handler can pull
    /// inputs *by reference* via a [`ComputeContext`] — e.g. when an argument is
    /// the *name* of a large or remote parameter rather than the value itself.
    /// This is the NFN-style argument-dereference model (wire spec §3.2); the
    /// referenced name must be routable to a producer. It is **not** RICE
    /// reflexive forwarding (§8), which would let an unroutable consumer be
    /// called back — that needs engine-level support (see
    /// `docs/notes/compute-reflexive-pull-2026-05-21.md`).
    pub fn function_ref<A, O, F, Fut>(&self, prefix: impl Into<Name>, f: F)
    where
        A: ComputeArgs + Send + 'static,
        O: ComputeValue + Send + 'static,
        F: Fn(A, ComputeContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<O, ComputeError>> + Send,
    {
        let prefix = prefix.into();
        let handler = RefHandler {
            f: Arc::new(f),
            ctx: self.fetch_context(),
            prefix_len: prefix.len(),
            freshness: Some(DEFAULT_TRANSPARENT_FRESHNESS),
            _pd: PhantomData,
        };
        self.register(prefix.clone(), handler);
        self.note(
            &prefix,
            Determinism::Transparent,
            ComputeFnKind::Typed,
            None,
        );
    }

    /// Tier 1: register an opaque (non-deterministic) typed function. The
    /// client must append an unpredictable nonce as the final name component
    /// (see [`ComputeClient::call_opaque`](crate::ComputeClient::call_opaque));
    /// the handler strips it before decoding arguments, and the result is
    /// non-fresh so it is never served from cache to a later call.
    pub fn opaque_function<A, O, F, Fut>(&self, prefix: impl Into<Name>, f: F)
    where
        A: ComputeArgs + Send + 'static,
        O: ComputeValue + Send + 'static,
        F: Fn(A) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<O, ComputeError>> + Send,
    {
        let prefix = prefix.into();
        let handler = TypedHandler {
            f,
            prefix_len: prefix.len(),
            determinism: Determinism::Opaque,
            freshness: None,
            _pd: PhantomData,
        };
        self.register(prefix.clone(), handler);
        self.note(&prefix, Determinism::Opaque, ComputeFnKind::Typed, None);
    }

    /// Tier 2: register a transparent function backed by a [`ComputeExecutor`]
    /// (native kernel, [`WasmExecutor`](crate::WasmExecutor), …). The input is
    /// the single name component after `prefix`; the executor's output bytes
    /// become the response Data content. Because the input rides the name, the
    /// result caches and coalesces like any other transparent function — pair
    /// with [`ComputeClient::call`](crate::ComputeClient::call) using
    /// `Bytes`-typed arguments and results.
    pub fn executor_function<E: ComputeExecutor>(&self, prefix: impl Into<Name>, executor: E) {
        let prefix = prefix.into();
        let fuel = executor.fuel();
        let executor = Arc::new(executor);
        self.function(prefix.clone(), move |input: Bytes| {
            let executor = Arc::clone(&executor);
            async move { executor.execute(&input) }
        });
        // Overwrite the `Typed` note that `function` laid down.
        self.note(
            &prefix,
            Determinism::Transparent,
            ComputeFnKind::Executor,
            fuel,
        );
    }

    /// Tier 3: register a long-running transparent job. The invocation Interest
    /// (`<prefix>/<args…>`) returns a [`Thunk`] naming `<prefix>/thunk/<args…>`
    /// plus `estimate`; the computation runs in the background; the client polls
    /// the thunk name (see
    /// [`ComputeClient::call_job`](crate::ComputeClient::call_job)) until the
    /// result is ready.
    ///
    /// Jobs are transparent: identical arguments map to the same thunk, so
    /// concurrent callers share one execution. (`args` must not begin with a
    /// `"thunk"` component, which is reserved for the poll namespace.)
    pub fn job<A, O, F, Fut>(&self, prefix: impl Into<Name>, estimate: Duration, f: F)
    where
        A: ComputeArgs + Send + 'static,
        O: ComputeValue + Send + 'static,
        F: Fn(A) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<O, ComputeError>> + Send + 'static,
    {
        self.register_job(prefix.into(), estimate, f, Determinism::Transparent);
    }

    /// Tier 3: register an opaque long-running job. The client appends an
    /// unpredictable nonce (see
    /// [`ComputeClient::call_opaque_job`](crate::ComputeClient::call_opaque_job)),
    /// so every call maps to a distinct thunk and runs separately; results are
    /// non-fresh and never alias.
    pub fn opaque_job<A, O, F, Fut>(&self, prefix: impl Into<Name>, estimate: Duration, f: F)
    where
        A: ComputeArgs + Send + 'static,
        O: ComputeValue + Send + 'static,
        F: Fn(A) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<O, ComputeError>> + Send + 'static,
    {
        self.register_job(prefix.into(), estimate, f, Determinism::Opaque);
    }

    fn register_job<A, O, F, Fut>(
        &self,
        prefix: Name,
        estimate: Duration,
        f: F,
        determinism: Determinism,
    ) where
        A: ComputeArgs + Send + 'static,
        O: ComputeValue + Send + 'static,
        F: Fn(A) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<O, ComputeError>> + Send + 'static,
    {
        let thunk_root = prefix.clone().append(THUNK_KEYWORD);
        let result_freshness = match determinism {
            Determinism::Transparent => Some(DEFAULT_TRANSPARENT_FRESHNESS),
            Determinism::Opaque => None,
        };

        let invoke = InvokeHandler {
            f: Arc::new(f),
            jobs: Arc::clone(&self.jobs),
            prefix_len: prefix.len(),
            thunk_root: thunk_root.clone(),
            estimate,
            determinism,
            _pd: PhantomData,
        };
        let poll = PollHandler {
            jobs: Arc::clone(&self.jobs),
            estimate,
            result_freshness,
        };

        // The poll handler sits at the longer `<prefix>/thunk` prefix, so LPM
        // routes thunk-name Interests to it and bare invocations to `invoke`.
        self.register(thunk_root.clone(), poll);
        self.register(prefix.clone(), invoke);
        // The poll endpoint is an internal mechanism, not a user-facing
        // function: drop its `Raw` note and label the invoke prefix `Job`.
        self.functions.lock().unwrap().remove(&thunk_root);
        self.note(&prefix, determinism, ComputeFnKind::Job, None);
    }

    /// Cancel the compute face, stopping its reader/sender tasks. Registered
    /// FIB routes pointing at the face are cleaned up by the engine.
    pub fn shutdown(&self) {
        self.cancel.cancel();
    }
}

/// One row of the introspection table.
#[derive(Clone, Copy)]
struct FnRec {
    determinism: Determinism,
    kind: ComputeFnKind,
    fuel: Option<u64>,
}

/// Map the table to the `ndn-mgmt` wire type, sorted by name for stable
/// dataset output.
fn snapshot(functions: &Mutex<HashMap<Name, FnRec>>) -> Vec<ComputeFunctionInfo> {
    let mut out: Vec<ComputeFunctionInfo> = functions
        .lock()
        .unwrap()
        .iter()
        .map(|(prefix, rec)| ComputeFunctionInfo {
            prefix: prefix.clone(),
            determinism: match rec.determinism {
                Determinism::Transparent => ComputeDeterminism::Transparent,
                Determinism::Opaque => ComputeDeterminism::Opaque,
            },
            kind: rec.kind,
            fuel: rec.fuel,
        })
        .collect();
    out.sort_by_key(|info| info.prefix.encode_to_tlv());
    out
}

/// Read-only [`ComputeMgmtBackend`] over a service's function table.
struct ComputeMgmtAdapter {
    functions: Arc<Mutex<HashMap<Name, FnRec>>>,
}

impl ComputeMgmtBackend for ComputeMgmtAdapter {
    fn list(&self) -> Vec<ComputeFunctionInfo> {
        snapshot(&self.functions)
    }
}

struct TypedHandler<A, O, F> {
    f: F,
    prefix_len: usize,
    determinism: Determinism,
    freshness: Option<Duration>,
    _pd: PhantomData<fn() -> (A, O)>,
}

impl<A, O, F, Fut> ComputeHandler for TypedHandler<A, O, F>
where
    A: ComputeArgs + Send + 'static,
    O: ComputeValue + Send + 'static,
    F: Fn(A) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<O, ComputeError>> + Send,
{
    async fn compute(&self, interest: &Interest) -> Result<Data, ComputeError> {
        let arg_comps = arg_components(
            interest.name.components(),
            self.prefix_len,
            self.determinism,
        )?;
        let args = A::from_components(arg_comps)?;
        let out = (self.f)(args).await?;
        build_data((*interest.name).clone(), &out.encode(), self.freshness)
    }
}

/// Like [`TypedHandler`] but the closure also receives a [`ComputeContext`] to
/// pull parameters by reference. Always transparent.
struct RefHandler<A, O, F> {
    f: Arc<F>,
    ctx: ComputeContext,
    prefix_len: usize,
    freshness: Option<Duration>,
    _pd: PhantomData<fn() -> (A, O)>,
}

impl<A, O, F, Fut> ComputeHandler for RefHandler<A, O, F>
where
    A: ComputeArgs + Send + 'static,
    O: ComputeValue + Send + 'static,
    F: Fn(A, ComputeContext) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<O, ComputeError>> + Send,
{
    async fn compute(&self, interest: &Interest) -> Result<Data, ComputeError> {
        let arg_comps = arg_components(
            interest.name.components(),
            self.prefix_len,
            Determinism::Transparent,
        )?;
        let args = A::from_components(arg_comps)?;
        let out = (self.f)(args, self.ctx.clone()).await?;
        build_data((*interest.name).clone(), &out.encode(), self.freshness)
    }
}

/// Handler for [`ComputeService::function_reflexive`]: pulls the parameter set
/// over the reflexive reverse path (`R/params`), then computes.
struct ReflexiveHandler<O, F> {
    f: Arc<F>,
    ctx: ComputeContext,
    _pd: PhantomData<fn() -> O>,
}

impl<O, F, Fut> ComputeHandler for ReflexiveHandler<O, F>
where
    O: ComputeValue + Send + 'static,
    F: Fn(Bytes) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<O, ComputeError>> + Send,
{
    async fn compute(&self, interest: &Interest) -> Result<Data, ComputeError> {
        let reflexive = interest.reflexive_name().ok_or_else(|| {
            ComputeError::BadArguments("reflexive call missing reflexive name".into())
        })?;
        // Pull the parameters back along the reverse path the Interest arrived
        // on. The engine reverse-routes this to the consumer.
        let param_name = (**reflexive).clone().append("params");
        let params = self.ctx.fetch(param_name).await?;
        let out = (self.f)(params).await?;
        // Opaque per-consumer result; the invocation name is unique per call.
        build_data((*interest.name).clone(), &out.encode(), None)
    }
}

/// Handler for [`ComputeService::function_reflexive_sealed`]: advertises an
/// ephemeral X25519 key on the reverse Interest and decrypts the sealed params.
#[cfg(feature = "sealed-params")]
struct SealedReflexiveHandler<O, F> {
    f: Arc<F>,
    ctx: ComputeContext,
    _pd: PhantomData<fn() -> O>,
}

#[cfg(feature = "sealed-params")]
impl<O, F, Fut> ComputeHandler for SealedReflexiveHandler<O, F>
where
    O: ComputeValue + Send + 'static,
    F: Fn(Bytes) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<O, ComputeError>> + Send,
{
    async fn compute(&self, interest: &Interest) -> Result<Data, ComputeError> {
        let reflexive = interest.reflexive_name().ok_or_else(|| {
            ComputeError::BadArguments("reflexive call missing reflexive name".into())
        })?;
        let node = crate::sealed::NodeKeypair::generate()
            .map_err(|e| ComputeError::ComputeFailed(e.to_string()))?;
        // Reverse Interest carries the node's ephemeral pubkey: R/params/<pubkey>.
        let param_name = (**reflexive)
            .clone()
            .append("params")
            .append_component(NameComponent::generic(Bytes::copy_from_slice(&node.public)));
        let blob = self.ctx.fetch(param_name).await?;
        let params = node
            .open(&blob)
            .map_err(|e| ComputeError::ComputeFailed(format!("decrypt params: {e}")))?;
        let out = (self.f)(Bytes::from(params)).await?;
        build_data((*interest.name).clone(), &out.encode(), None)
    }
}

/// Handler for [`ComputeService::function_reflexive_secure`]: validates the
/// signed D2 (auth) and decrypts the sealed blob it carries (confidentiality).
#[cfg(feature = "sealed-params")]
struct SecureReflexiveHandler<O, F> {
    f: Arc<F>,
    ctx: ComputeContext,
    validator: Arc<Validator>,
    _pd: PhantomData<fn() -> O>,
}

#[cfg(feature = "sealed-params")]
impl<O, F, Fut> ComputeHandler for SecureReflexiveHandler<O, F>
where
    O: ComputeValue + Send + 'static,
    F: Fn(Bytes, Option<Name>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<O, ComputeError>> + Send,
{
    async fn compute(&self, interest: &Interest) -> Result<Data, ComputeError> {
        let reflexive = interest.reflexive_name().ok_or_else(|| {
            ComputeError::BadArguments("reflexive call missing reflexive name".into())
        })?;
        let node = crate::sealed::NodeKeypair::generate()
            .map_err(|e| ComputeError::ComputeFailed(e.to_string()))?;
        let param_name = (**reflexive)
            .clone()
            .append("params")
            .append_component(NameComponent::generic(Bytes::copy_from_slice(&node.public)));
        // Authorization gate: the signed D2 (whose content is the sealed blob)
        // must validate before we decrypt or compute.
        let safe = self.ctx.fetch_verified(param_name, &self.validator).await?;
        let signer = safe.data().sig_info().and_then(|si| match &si.key_locator {
            Some(KeyLocator::Name(n)) => Some((**n).clone()),
            _ => None,
        });
        let blob = safe.data().content().ok_or_else(|| {
            ComputeError::ComputeFailed("sealed params Data had no content".into())
        })?;
        let params = node
            .open(blob)
            .map_err(|e| ComputeError::ComputeFailed(format!("decrypt params: {e}")))?;
        let out = (self.f)(Bytes::from(params), signer).await?;
        build_data((*interest.name).clone(), &out.encode(), None)
    }
}

/// Handler for [`ComputeService::function_reflexive_authenticated`]: pulls the
/// params over the reverse path, validates the signed Data, and only then runs.
struct AuthReflexiveHandler<O, F> {
    f: Arc<F>,
    ctx: ComputeContext,
    validator: Arc<Validator>,
    _pd: PhantomData<fn() -> O>,
}

impl<O, F, Fut> ComputeHandler for AuthReflexiveHandler<O, F>
where
    O: ComputeValue + Send + 'static,
    F: Fn(Bytes, Option<Name>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<O, ComputeError>> + Send,
{
    async fn compute(&self, interest: &Interest) -> Result<Data, ComputeError> {
        let reflexive = interest.reflexive_name().ok_or_else(|| {
            ComputeError::BadArguments("reflexive call missing reflexive name".into())
        })?;
        let param_name = (**reflexive).clone().append("params");
        // Validation gate: an unauthorized / unverifiable D2 fails here and the
        // computation never runs.
        let safe = self.ctx.fetch_verified(param_name, &self.validator).await?;
        let signer = safe.data().sig_info().and_then(|si| match &si.key_locator {
            Some(KeyLocator::Name(n)) => Some((**n).clone()),
            _ => None,
        });
        let params = safe
            .data()
            .content()
            .map(|b| Bytes::copy_from_slice(b))
            .ok_or_else(|| ComputeError::ComputeFailed("params Data had no content".into()))?;
        let out = (self.f)(params, signer).await?;
        build_data((*interest.name).clone(), &out.encode(), None)
    }
}

/// The name components carrying a call's arguments: everything after the
/// function prefix, minus the trailing nonce for opaque calls.
fn arg_components(
    comps: &[NameComponent],
    prefix_len: usize,
    determinism: Determinism,
) -> Result<&[NameComponent], ComputeError> {
    if comps.len() < prefix_len {
        return Err(ComputeError::BadArguments(
            "name shorter than function prefix".into(),
        ));
    }
    match determinism {
        Determinism::Transparent => Ok(&comps[prefix_len..]),
        Determinism::Opaque => {
            let end = comps
                .len()
                .checked_sub(1)
                .filter(|end| *end >= prefix_len)
                .ok_or_else(|| {
                    ComputeError::BadArguments(
                        "opaque call missing trailing nonce component".into(),
                    )
                })?;
            Ok(&comps[prefix_len..end])
        }
    }
}

/// Build a signed-with-DigestSha256 Data named `name`, optionally fresh.
fn build_data(
    name: Name,
    content: &[u8],
    freshness: Option<Duration>,
) -> Result<Data, ComputeError> {
    let mut builder = DataBuilder::new(name, content);
    if let Some(freshness) = freshness {
        builder = builder.freshness(freshness);
    }
    Data::decode(builder.build()).map_err(|e| ComputeError::ComputeFailed(e.to_string()))
}

/// Job invocation endpoint at `<prefix>`: starts the background computation on
/// first sight of a given argument set and returns a thunk.
struct InvokeHandler<A, O, F> {
    f: Arc<F>,
    jobs: JobStore,
    prefix_len: usize,
    thunk_root: Name,
    estimate: Duration,
    determinism: Determinism,
    _pd: PhantomData<fn() -> (A, O)>,
}

impl<A, O, F, Fut> ComputeHandler for InvokeHandler<A, O, F>
where
    A: ComputeArgs + Send + 'static,
    O: ComputeValue + Send + 'static,
    F: Fn(A) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<O, ComputeError>> + Send + 'static,
{
    async fn compute(&self, interest: &Interest) -> Result<Data, ComputeError> {
        let comps = interest.name.components();
        let arg_comps = arg_components(comps, self.prefix_len, self.determinism)?;
        let args = A::from_components(arg_comps)?;

        // The thunk name carries every post-prefix component — including the
        // opaque nonce — so opaque jobs never share a thunk.
        let mut thunk_name = self.thunk_root.clone();
        for c in &comps[self.prefix_len..] {
            thunk_name = thunk_name.append_component(c.clone());
        }

        // Start the job exactly once per argument set. Insert under the lock so
        // two concurrent invocations cannot both spawn.
        let start = {
            let mut jobs = self.jobs.lock().unwrap();
            if jobs.contains_key(&thunk_name) {
                false
            } else {
                jobs.insert(thunk_name.clone(), JobState::Pending);
                true
            }
        };
        if start {
            let f = Arc::clone(&self.f);
            let jobs = Arc::clone(&self.jobs);
            let key = thunk_name.clone();
            tokio::spawn(async move {
                let state = match f(args).await {
                    Ok(out) => JobState::Done(out.encode()),
                    Err(e) => JobState::Failed(e.to_string()),
                };
                jobs.lock().unwrap().insert(key, state);
            });
        }

        let thunk = Thunk {
            thunk_name,
            eta: self.estimate,
        };
        build_data((*interest.name).clone(), &thunk.to_content(), None)
    }
}

/// Thunk poll endpoint at `<prefix>/thunk`: returns the result when ready, an
/// updated thunk while pending, or an error.
struct PollHandler {
    jobs: JobStore,
    estimate: Duration,
    result_freshness: Option<Duration>,
}

impl ComputeHandler for PollHandler {
    async fn compute(&self, interest: &Interest) -> Result<Data, ComputeError> {
        let thunk_name = (*interest.name).clone();
        let state = self.jobs.lock().unwrap().get(&thunk_name).cloned();
        match state {
            Some(JobState::Done(bytes)) => build_data(thunk_name, &bytes, self.result_freshness),
            Some(JobState::Failed(e)) => Err(ComputeError::ComputeFailed(e)),
            Some(JobState::Pending) => {
                let thunk = Thunk {
                    thunk_name: thunk_name.clone(),
                    eta: self.estimate,
                };
                build_data(thunk_name, &thunk.to_content(), None)
            }
            None => Err(ComputeError::NotFound),
        }
    }
}
