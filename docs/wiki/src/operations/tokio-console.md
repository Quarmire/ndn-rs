# Debugging with tokio-console

tokio-console is an interactive task inspector for async Rust applications. It
connects to a running `ndn-fwd` process over gRPC and shows every live tokio
task by name, its poll count, idle time, and busy time. This is the right tool
when a face is stalling and you want to see which task is hung, or when you
want to understand where the forwarder is spending its time.

## When to use it

- A face reader stops receiving packets but the process is running.
- The pipeline is slow and you need to identify the bottleneck task.
- An expiry worker appears to have stopped ticking.
- You want to verify that NLSR's recompute loop is firing as expected.

## Build

```sh
RUSTFLAGS="--cfg tokio_unstable" \
  cargo build -p ndn-fwd --features console --profile console
```

The `--cfg tokio_unstable` flag enables tokio's internal task instrumentation
hooks. This is **not optional** — without it, tokio does not expose task data to
console-subscriber and the tool will show no tasks. The `console` Cargo profile
inherits `dev` settings and keeps debug symbols.

The long-lived task spans shipped in phase 2 name every persistent task so
tokio-console shows rows like `engine_task`, `face_read`, `face_write`,
`expiry`, `pipeline_dispatch`, `nlsr_sync`, and `nlsr_recompute` rather than
anonymous `tokio::spawn[…]` entries.

The console layer listens on `127.0.0.1:6669` by default. Override with:

```sh
TOKIO_CONSOLE_BIND=0.0.0.0:9999 \
  RUSTFLAGS="--cfg tokio_unstable" \
  cargo run -p ndn-fwd --features console --profile console
```

## Install tokio-console

```sh
cargo install --locked tokio-console
```

## Connect

```sh
tokio-console
```

With a custom bind address:

```sh
tokio-console http://127.0.0.1:9999
```

## Expected output

After connecting, the task list pane shows one row per live task. The `Name`
column will contain the span names set in phase 2:

```
 ID  Name                  State   Total  Busy    Idle    Polls
  1  engine_task           idle    1.2s   0.001s  1.199s      4
  2  expiry (pit)          idle    1.2s   0.000s  1.200s    120
  3  expiry (rib)          idle    1.2s   0.000s  1.200s      1
  4  expiry (idle_face)    idle    1.2s   0.000s  1.200s      0
  5  pipeline_dispatch     idle    1.2s   0.001s  1.199s     64
  6  face_read  (face_id=1) idle   1.2s   0.001s  1.199s      8
  7  face_write (face_id=1) idle   1.2s   0.000s  1.200s      2
```

If you see only `tokio::spawn[…]` rows, the binary was not built with
`--cfg tokio_unstable` or the `console` feature was not enabled.

## Production note

The `--features console` build is a debugging build, not for production use.
The overhead of `--cfg tokio_unstable` is small (a few extra atomic operations
per task poll) but measurable under high packet rates. The long-lived task
spans (added unconditionally in phase 2) have no runtime cost beyond the
`tracing::Span` the process already pays; only the console gRPC server is
gated behind the feature flag.
