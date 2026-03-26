# ForwarderEngine and EngineBuilder

## `ForwarderEngine`

```rust
pub struct ForwarderEngine {
    inner: Arc<EngineInner>,
}

pub struct EngineInner {
    pub fib:            Arc<Fib>,
    pub pit:            Arc<Pit>,
    pub cs:             Arc<dyn ContentStore>,
    pub face_table:     Arc<FaceTable>,
    pub strategy_table: Arc<StrategyTable>,
    pub measurements:   Arc<MeasurementsTable>,
}
```

Every shared table is wrapped in `Arc`. The pipeline runner task, per-packet tasks, face tasks, expiry task, and control task all need concurrent access. `ForwarderEngine` is cheaply cloneable — cloning gives another handle to the same running engine, used to hand the engine to application code that adds faces or registers prefixes after startup.

## `ShutdownHandle`

```rust
pub struct ShutdownHandle {
    cancel: CancellationToken,
    tasks:  JoinSet<()>,
}

impl ShutdownHandle {
    pub async fn shutdown(self) {
        self.cancel.cancel();
        while let Some(result) = self.tasks.join_next().await {
            if let Err(e) = result {
                tracing::warn!("task panicked during shutdown: {e}");
            }
        }
    }
}
```

All long-running tasks receive a clone of the `CancellationToken`. Face tasks `tokio::select!` between `face.recv()` and `token.cancelled()`. When `cancel()` fires, tasks see the cancellation at their next `await` point, drain, and exit. Panics are caught by `JoinSet` and logged — a panicking face task does not bring down the whole forwarder.

## `EngineBuilder`

```rust
pub struct EngineConfig {
    pub pipeline_channel_cap: usize,  // backpressure bound (default 1024)
    pub cs_capacity_bytes:    usize,  // 0 = use NullCs (default 64 MB)
}

pub struct EngineBuilder {
    config: EngineConfig,
    faces:  Vec<Box<dyn FnOnce(Arc<FaceTable>) + Send>>,
}
```

`build()` in order:
1. Construct all shared tables
2. Build pipeline stage sequences (fixed at build time)
3. Create `mpsc` channel with `pipeline_channel_cap` capacity
4. Register pre-configured faces
5. Spawn all tasks into `JoinSet`
6. Return `(ForwarderEngine, ShutdownHandle)`

## Standalone Forwarder Usage

```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = EngineConfig::default();
    let (engine, shutdown) = EngineBuilder::new(config)
        .face(UdpFace::bind("0.0.0.0:6363").await?)
        .build()
        .await?;

    tokio::signal::ctrl_c().await?;
    shutdown.shutdown().await;
    Ok(())
}
```

## Embedded Usage

```rust
let (engine, shutdown) = EngineBuilder::new(config).build().await?;

let app_face = engine.new_app_face().await?;
app_face.register_prefix("/my/app".parse()?).await?;

let data = app_face.express(Interest::new("/my/app/data")).await?;
```

`new_app_face()` creates an `mpsc` channel pair, wraps one end as an `AppFace`, registers it in `FaceTable`, and spawns its face task — atomically from the application's perspective.

## Logging with `tracing`

The engine uses `tracing`, not `log`. In an async forwarder with thousands of in-flight packets, `tracing` spans carry context (`name`, `face_id`, `packet_type`) across `await` points, making "PIT miss" log lines actually useful.

**One span per packet** at pipeline entry:

```rust
let span = tracing::info_span!(
    "packet",
    name = tracing::field::Empty,  // recorded after decode
    face_id = ctx.face_id.0,
    packet_type = tracing::field::Empty,
);
// after TlvDecodeStage:
tracing::Span::current().record("name", tracing::field::display(&ctx.name));
```

**`#[tracing::instrument]` on stage methods**:

```rust
impl PipelineStage for PitCheckStage {
    #[tracing::instrument(skip(self, ctx), fields(pit_token, aggregated))]
    async fn process(&self, ctx: PacketContext) -> Result<Action> {
        // ...
        tracing::Span::current().record("pit_token", token.0);
        tracing::debug!(aggregated = was_aggregated, "PIT check");
        Ok(Action::Continue(ctx))
    }
}
```

**The engine crate never calls `tracing_subscriber::fmt::init()`** — that is the binary's responsibility. The library only emits events and spans.

**Subscriber setup in the binary**:

```rust
tracing_subscriber::registry()
    .with(tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_thread_ids(true))
    .with(tracing_opentelemetry::layer().with_tracer(otlp_tracer()?))
    .with(tracing_subscriber::EnvFilter::from_default_env())
    .init();
```

`EnvFilter` controls verbosity at runtime: `RUST_LOG=ndn_engine=info,ndn_engine::pipeline=debug`.

**Production log level defaults**: `ndn_engine=info` — face lifecycle, startup, errors only. `debug` on specific modules for live troubleshooting. `trace` on `ndn_engine::strategy` for development only (exposes measurement values, every forwarding decision).

**Key structured fields per component**:
- PIT stage: `aggregated: bool`, `pit_entries: usize`
- FIB stage: `nexthop_count: usize`, `strategy: &str`
- CS stage: `hit: bool`, `stale: bool` (a stale hit failing `MustBeFresh` is diagnostically different from a miss)
- Dispatch stage: `face_count: usize`, `bytes_sent: usize`

## Two Usage Modes — Same Engine Code

The standalone forwarder binary and the embedded library use identical engine code. The difference is only in how faces are configured and whether a `UnixControlFace` is added for external application connectivity.

**Library-first limitation**: Two separate Rust NDN applications on the same machine that each embed the engine directly will not forward to each other — they have independent engine instances with no shared state. The standalone binary with `AppFace` over shared memory (iceoryx2) is the solution for that case.
