//! End-to-end compute round-trips through an in-process forwarder.
//!
//! Mirrors the embedded-engine harness in
//! `crates/draft/ndn-coding/tests/end_to_end.rs`: a `ComputeService` attaches
//! to a live `ForwarderEngine`, registers functions, and `ComputeClient`s drive
//! Interests in over `InProcFace` handles.
//!
//! Witnesses:
//! - C-COMPUTE-02 — attach + FIB wiring + Content-Store memoization.
//! - C-COMPUTE-03 — typed `(i64, i64) -> i64` round-trip.
//! - C-COMPUTE-04 — transparent calls coalesce (one execution); opaque calls do
//!   not (one execution each).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ndn_app::Consumer;
use ndn_compute::{ComputeClient, ComputeContext, ComputeError, ComputeService};
use ndn_engine::{EngineBuilder, EngineConfig, ForwarderEngine, ShutdownHandle};
use ndn_face_local::InProcFace;
use ndn_packet::Name;

/// Build an embedded engine with `n` in-process consumer faces. Returns the
/// engine, its shutdown handle, and one `Consumer` per face.
async fn engine_with_consumers(n: usize) -> (ForwarderEngine, ShutdownHandle, Vec<Consumer>) {
    let mut builder = EngineBuilder::new(EngineConfig::default());
    let mut handles = Vec::with_capacity(n);
    for _ in 0..n {
        let id = builder.alloc_face_id();
        let (face, handle) = InProcFace::new(id, 256);
        builder = builder.face(face);
        handles.push(handle);
    }
    let (engine, shutdown) = builder.build().await.expect("engine build");
    let consumers = handles.into_iter().map(Consumer::from_handle).collect();
    (engine, shutdown, consumers)
}

// C-COMPUTE-02 + C-COMPUTE-03: attach, FIB wiring, typed round-trip, CS hit.
#[tokio::test]
async fn transparent_function_round_trip_and_cs_memoization() {
    let (engine, shutdown, mut consumers) = engine_with_consumers(1).await;
    let prefix: Name = "/calc/add".parse().unwrap();

    let service = ComputeService::attach(&engine);
    let calls = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&calls);
    service.function(prefix.clone(), move |(a, b): (i64, i64)| {
        let c = Arc::clone(&c);
        async move {
            c.fetch_add(1, Ordering::SeqCst);
            Ok::<i64, ComputeError>(a + b)
        }
    });

    let mut client = ComputeClient::new(consumers.remove(0));

    let first: i64 = client
        .call::<(i64, i64), i64>(prefix.clone(), (4, 5))
        .await
        .expect("first call");
    assert_eq!(first, 9);

    // Second identical call must be served from the Content Store, so the
    // handler is not invoked again.
    let second: i64 = client
        .call::<(i64, i64), i64>(prefix.clone(), (4, 5))
        .await
        .expect("second call");
    assert_eq!(second, 9);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "second call should hit the CS, not re-run the handler"
    );

    service.shutdown();
    drop(client);
    drop(engine);
    shutdown.shutdown().await;
}

// C-COMPUTE-04: two concurrent identical transparent calls coalesce in the PIT
// into a single handler execution.
#[tokio::test]
async fn transparent_concurrent_calls_coalesce() {
    let (engine, shutdown, mut consumers) = engine_with_consumers(2).await;
    let prefix: Name = "/calc/slow".parse().unwrap();

    let service = ComputeService::attach(&engine);
    let calls = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&calls);
    service.function(prefix.clone(), move |(a, b): (i64, i64)| {
        let c = Arc::clone(&c);
        async move {
            c.fetch_add(1, Ordering::SeqCst);
            // Stay in-flight long enough for the second Interest to aggregate
            // onto the same PIT entry before the result is produced.
            tokio::time::sleep(Duration::from_millis(200)).await;
            Ok::<i64, ComputeError>(a + b)
        }
    });

    let mut c0 = ComputeClient::new(consumers.remove(0));
    let mut c1 = ComputeClient::new(consumers.remove(0));
    let (r0, r1) = tokio::join!(
        c0.call::<(i64, i64), i64>(prefix.clone(), (7, 8)),
        c1.call::<(i64, i64), i64>(prefix.clone(), (7, 8)),
    );
    assert_eq!(r0.expect("call 0"), 15);
    assert_eq!(r1.expect("call 1"), 15);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "identical concurrent transparent calls must coalesce into one execution"
    );

    service.shutdown();
    drop(c0);
    drop(c1);
    drop(engine);
    shutdown.shutdown().await;
}

// C-COMPUTE-05: a WASM executor registered as a transparent function answers a
// real Interest end-to-end.
#[cfg(feature = "wasm-exec")]
#[tokio::test]
async fn wasm_executor_function_round_trip() {
    use bytes::Bytes;
    use ndn_compute::WasmExecutor;

    const ECHO_WAT: &str = r#"
    (module
      (import "ndn_compute" "input_len"    (func $input_len (result i32)))
      (import "ndn_compute" "read_input"   (func $read_input (param i32)))
      (import "ndn_compute" "write_output" (func $write_output (param i32 i32)))
      (memory (export "memory") 1)
      (func (export "compute")
        (local $n i32)
        (local.set $n (call $input_len))
        (call $read_input (i32.const 0))
        (call $write_output (i32.const 0) (local.get $n))))
    "#;

    let (engine, shutdown, mut consumers) = engine_with_consumers(1).await;
    let prefix: Name = "/wasm/echo".parse().unwrap();

    let service = ComputeService::attach(&engine);
    let wasm = wat::parse_str(ECHO_WAT).unwrap();
    service.executor_function(
        prefix.clone(),
        WasmExecutor::from_bytes(&wasm, 1_000_000).unwrap(),
    );

    let mut client = ComputeClient::new(consumers.remove(0));
    let out: Bytes = client
        .call::<Bytes, Bytes>(prefix.clone(), Bytes::from_static(b"ping"))
        .await
        .expect("wasm call");
    assert_eq!(&out[..], b"ping");

    service.shutdown();
    drop(client);
    drop(engine);
    shutdown.shutdown().await;
}

// C-COMPUTE-04: two opaque calls run the handler twice — the per-call nonce
// keeps them from coalescing or aliasing in the CS.
#[tokio::test]
async fn opaque_calls_do_not_coalesce() {
    let (engine, shutdown, mut consumers) = engine_with_consumers(1).await;
    let prefix: Name = "/rng/u64".parse().unwrap();

    let service = ComputeService::attach(&engine);
    let calls = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&calls);
    service.opaque_function(prefix.clone(), move |(): ()| {
        let c = Arc::clone(&c);
        async move {
            let n = c.fetch_add(1, Ordering::SeqCst) as u64;
            Ok::<u64, ComputeError>(n)
        }
    });

    let mut client = ComputeClient::new(consumers.remove(0));
    let first: u64 = client
        .call_opaque::<(), u64>(prefix.clone(), ())
        .await
        .expect("first opaque call");
    let second: u64 = client
        .call_opaque::<(), u64>(prefix.clone(), ())
        .await
        .expect("second opaque call");

    assert_ne!(first, second, "opaque results must not alias");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "each opaque call must re-run the handler"
    );

    service.shutdown();
    drop(client);
    drop(engine);
    shutdown.shutdown().await;
}

// C-COMPUTE-06: a long-running job returns a thunk; the client polls until the
// result is ready. A repeat call with the same args shares the finished job.
#[tokio::test]
async fn job_thunk_handshake_and_sharing() {
    let (engine, shutdown, mut consumers) = engine_with_consumers(1).await;
    let prefix: Name = "/job/double".parse().unwrap();

    let service = ComputeService::attach(&engine);
    let calls = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&calls);
    service.job(prefix.clone(), Duration::from_millis(50), move |n: i64| {
        let c = Arc::clone(&c);
        async move {
            c.fetch_add(1, Ordering::SeqCst);
            // Outlasts one RTT, so the client must take the thunk + poll path.
            tokio::time::sleep(Duration::from_millis(120)).await;
            Ok::<i64, ComputeError>(n * 2)
        }
    });

    let mut client = ComputeClient::new(consumers.remove(0));
    let out: i64 = client
        .call_job::<i64, i64>(
            prefix.clone(),
            21,
            Duration::from_millis(40),
            Duration::from_secs(3),
        )
        .await
        .expect("job result");
    assert_eq!(out, 42);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // Same args → same thunk → the finished job is reused, not re-run.
    let again: i64 = client
        .call_job::<i64, i64>(
            prefix.clone(),
            21,
            Duration::from_millis(40),
            Duration::from_secs(3),
        )
        .await
        .expect("second job result");
    assert_eq!(again, 42);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a job with identical args must not run twice"
    );

    service.shutdown();
    drop(client);
    drop(engine);
    shutdown.shutdown().await;
}

// Opaque jobs: each call runs separately (per-call nonce), so results may
// differ even with identical arguments.
#[tokio::test]
async fn opaque_job_runs_each_call_separately() {
    let (engine, shutdown, mut consumers) = engine_with_consumers(1).await;
    let prefix: Name = "/job/sample".parse().unwrap();

    let service = ComputeService::attach(&engine);
    let calls = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&calls);
    service.opaque_job(prefix.clone(), Duration::from_millis(30), move |(): ()| {
        let c = Arc::clone(&c);
        async move {
            let n = c.fetch_add(1, Ordering::SeqCst) as u64;
            tokio::time::sleep(Duration::from_millis(60)).await;
            Ok::<u64, ComputeError>(n)
        }
    });

    let mut client = ComputeClient::new(consumers.remove(0));
    let first: u64 = client
        .call_opaque_job::<(), u64>(
            prefix.clone(),
            (),
            Duration::from_millis(25),
            Duration::from_secs(3),
        )
        .await
        .expect("first opaque job");
    let second: u64 = client
        .call_opaque_job::<(), u64>(
            prefix.clone(),
            (),
            Duration::from_millis(25),
            Duration::from_secs(3),
        )
        .await
        .expect("second opaque job");

    assert_ne!(first, second, "opaque jobs must not alias results");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "each opaque job must run its own execution"
    );

    service.shutdown();
    drop(client);
    drop(engine);
    shutdown.shutdown().await;
}

// Argument-by-reference: a function_ref handler pulls a large/named parameter
// from a producer via ComputeContext::fetch (NFN-style dereference), rather than
// receiving the value in the invocation name. The handler re-enters the engine
// (a nested fetch); this works on the default single-threaded test runtime.
#[tokio::test]
async fn function_ref_pulls_parameter_by_reference() {
    use ndn_app::Producer;
    use ndn_packet::encode::DataBuilder;

    let mut builder = EngineBuilder::new(EngineConfig::default());
    let consumer_id = builder.alloc_face_id();
    let (cface, chandle) = InProcFace::new(consumer_id, 256);
    let producer_id = builder.alloc_face_id();
    let (pface, phandle) = InProcFace::new(producer_id, 256);
    builder = builder.face(cface).face(pface);
    let (engine, shutdown) = builder.build().await.expect("engine build");

    // A producer serves /data/blob = [1,2,3,4] (byte sum 10).
    let param: Name = "/data/blob".parse().unwrap();
    engine.fib().add_nexthop(&param, producer_id, 0);
    let producer = Producer::from_handle(phandle, param.clone());
    let serve_param = param.clone();
    let producer_task = tokio::spawn(async move {
        producer
            .serve(move |interest, responder| {
                let serve_param = serve_param.clone();
                async move {
                    if *interest.name == serve_param {
                        let wire = DataBuilder::new(serve_param, &[1u8, 2, 3, 4])
                            .freshness(Duration::from_secs(4))
                            .build();
                        responder.respond_bytes(wire).await.ok();
                    }
                }
            })
            .await
    });

    // /compute/sum takes a parameter *name*, fetches it, and sums its bytes.
    let service = ComputeService::attach(&engine);
    service.function_ref(
        "/compute/sum",
        |name: String, ctx: ComputeContext| async move {
            let pname: Name = name
                .parse()
                .map_err(|_| ComputeError::BadArguments("argument is not a name".into()))?;
            let bytes = ctx.fetch(pname).await?;
            Ok::<u64, ComputeError>(bytes.iter().map(|&b| b as u64).sum())
        },
    );

    let mut client = ComputeClient::new(Consumer::from_handle(chandle));
    let sum: u64 = client
        .call::<String, u64>("/compute/sum", "/data/blob".to_string())
        .await
        .expect("function_ref call");
    assert_eq!(sum, 10);

    producer_task.abort();
    service.shutdown();
    drop(client);
    drop(engine);
    shutdown.shutdown().await;
}

// RICE §8 end-to-end (reflexive forwarding): the consumer sends I1 carrying a
// reflexive name and no params in the name; the node pulls the params back over
// the reverse path (I2/D2), computes, and answers (D1). Single engine: the
// consumer face is the reverse target.
#[tokio::test]
async fn reflexive_function_end_to_end() {
    use bytes::Bytes;
    use ndn_packet::encode::{DataBuilder, InterestBuilder};
    use ndn_packet::{Data, Interest, random_reflexive_name};

    let mut builder = EngineBuilder::new(EngineConfig::default());
    let cid = builder.alloc_face_id();
    let (cface, chandle) = InProcFace::new(cid, 256);
    builder = builder.face(cface);
    let (engine, shutdown) = builder.build().await.expect("engine build");

    // Node: a reflexive function that sums the bytes it pulls from the consumer.
    let service = ComputeService::attach(&engine);
    service.function_reflexive("/svc/sum", |params: Bytes| async move {
        Ok::<u64, ComputeError>(params.iter().map(|&b| b as u64).sum())
    });

    // Consumer C sends I1 = /svc/sum/<unique> with a reflexive name R, no params
    // in the name.
    let r = random_reflexive_name();
    let i1 = InterestBuilder::new("/svc/sum/req-1")
        .reflexive_name(r)
        .lifetime(Duration::from_secs(4))
        .build();
    chandle.send(i1).await.expect("send I1");

    // C answers the node's reverse Interest (R/params) with the input bytes,
    // then collects the result D1.
    let mut result: Option<u64> = None;
    for _ in 0..50 {
        let pkt = match tokio::time::timeout(Duration::from_secs(2), chandle.recv()).await {
            Ok(Some(p)) => p,
            _ => break,
        };
        match pkt.first() {
            Some(&0x05) => {
                // Reverse Interest I2 = R/params → answer with D2 = [1,2,3,4].
                let i2 = Interest::decode(pkt).expect("decode I2");
                let d2 = DataBuilder::new((*i2.name).clone(), &[1u8, 2, 3, 4]).build();
                chandle.send(d2).await.expect("send D2");
            }
            Some(&0x06) => {
                // Result D1.
                let d1 = Data::decode(pkt).expect("decode D1");
                let content = d1.content().expect("D1 content");
                result = std::str::from_utf8(content)
                    .ok()
                    .and_then(|s| s.parse().ok());
                break;
            }
            _ => {}
        }
    }

    assert_eq!(
        result,
        Some(10),
        "node must return the sum of params pulled over the reflexive reverse path",
    );

    drop(chandle);
    drop(engine);
    shutdown.shutdown().await;
}

// RICE §8 authenticated leg (positive): the node validates the signed params
// Data (D2) before computing. D2 is signed with a real identity key whose cert
// the validator trusts — a DigestSha256-only D2 is (correctly) not authenticated
// and would be rejected, so the authenticated leg uses a genuine signer.
#[tokio::test]
async fn reflexive_authenticated_validates_and_computes() {
    use bytes::Bytes;
    use ndn_packet::encode::{DataBuilder, InterestBuilder};
    use ndn_packet::{Data, Interest, SignatureType, random_reflexive_name};
    use ndn_security::{Certificate, Ed25519Signer, SignWith, TrustSchema, Validator};
    use std::sync::Arc;

    let mut builder = EngineBuilder::new(EngineConfig::default());
    let cid = builder.alloc_face_id();
    let (cface, chandle) = InProcFace::new(cid, 256);
    builder = builder.face(cface);
    let (engine, shutdown) = builder.build().await.expect("engine build");

    let service = ComputeService::attach(&engine);

    // A real signing identity whose self-cert the validator trusts. accept_all
    // schema so the arbitrary reflexive D2 name is authorized; the cert lets the
    // Ed25519 signature actually resolve and verify.
    let d2_key: ndn_packet::Name = "/svc/signer/KEY/k1".parse().unwrap();
    let d2_signer = Ed25519Signer::from_seed(&[7u8; 32], d2_key.clone());
    let d2_cert = Certificate {
        name: Arc::new(d2_key),
        public_key: Bytes::copy_from_slice(&d2_signer.public_key_bytes()),
        valid_from: 0,
        valid_until: u64::MAX,
        issuer: None,
        signed_region: None,
        sig_value: None,
        sig_type: SignatureType::SignatureEd25519,
    };
    let validator = Validator::new(TrustSchema::accept_all());
    validator.cert_cache().insert(d2_cert);
    let validator = Arc::new(validator);
    service.function_reflexive_authenticated(
        "/svc/auth",
        validator,
        |params: Bytes, _signer| async move {
            Ok::<u64, ComputeError>(params.iter().map(|&b| b as u64).sum())
        },
    );

    let i1 = InterestBuilder::new("/svc/auth/req-1")
        .reflexive_name(random_reflexive_name())
        .lifetime(Duration::from_secs(4))
        .build();
    chandle.send(i1).await.expect("send I1");

    let mut result: Option<u64> = None;
    for _ in 0..50 {
        let pkt = match tokio::time::timeout(Duration::from_secs(2), chandle.recv()).await {
            Ok(Some(p)) => p,
            _ => break,
        };
        match pkt.first() {
            Some(&0x05) => {
                let i2 = Interest::decode(pkt).expect("decode I2");
                // D2 signed with the real identity key the validator trusts.
                let d2 = DataBuilder::new((*i2.name).clone(), &[2u8, 3, 5])
                    .sign_with_sync(&d2_signer)
                    .expect("sign D2");
                chandle.send(d2).await.expect("send D2");
            }
            Some(&0x06) => {
                let d1 = Data::decode(pkt).expect("decode D1");
                let content = d1.content().expect("D1 content");
                result = std::str::from_utf8(content)
                    .ok()
                    .and_then(|s| s.parse().ok());
                break;
            }
            _ => {}
        }
    }
    assert_eq!(result, Some(10), "validated params must be computed");

    drop(chandle);
    drop(engine);
    shutdown.shutdown().await;
}

// RICE §8 authenticated leg (negative): an unsigned D2 fails validation, so the
// node refuses to compute and no result is returned.
#[tokio::test]
async fn reflexive_authenticated_rejects_unsigned() {
    use bytes::Bytes;
    use ndn_packet::encode::{DataBuilder, InterestBuilder};
    use ndn_packet::{Data, Interest, random_reflexive_name};
    use ndn_security::{TrustSchema, Validator};
    use std::sync::Arc;

    let mut builder = EngineBuilder::new(EngineConfig::default());
    let cid = builder.alloc_face_id();
    let (cface, chandle) = InProcFace::new(cid, 256);
    builder = builder.face(cface);
    let (engine, shutdown) = builder.build().await.expect("engine build");

    let service = ComputeService::attach(&engine);
    let validator = Arc::new(Validator::new(TrustSchema::accept_all()));
    service.function_reflexive_authenticated(
        "/svc/auth",
        validator,
        |params: Bytes, _signer| async move {
            Ok::<u64, ComputeError>(params.iter().map(|&b| b as u64).sum())
        },
    );

    let i1 = InterestBuilder::new("/svc/auth/req-2")
        .reflexive_name(random_reflexive_name())
        .lifetime(Duration::from_secs(2))
        .build();
    chandle.send(i1).await.expect("send I1");

    let mut got_result = false;
    for _ in 0..50 {
        let pkt = match tokio::time::timeout(Duration::from_millis(800), chandle.recv()).await {
            Ok(Some(p)) => p,
            _ => break,
        };
        match pkt.first() {
            Some(&0x05) => {
                let i2 = Interest::decode(pkt).expect("decode I2");
                // Unsigned D2 — must fail the node's validation gate.
                let d2 = DataBuilder::new((*i2.name).clone(), &[2u8, 3, 5]).sign_none();
                chandle.send(d2).await.expect("send D2");
            }
            Some(&0x06) => {
                let _ = Data::decode(pkt);
                got_result = true;
                break;
            }
            _ => {}
        }
    }
    assert!(
        !got_result,
        "unsigned params must be rejected — no result computed"
    );

    drop(chandle);
    drop(engine);
    shutdown.shutdown().await;
}

// RICE §8 confidentiality leg: the consumer seals the params to the node's
// ephemeral key (advertised on the reverse Interest), so the params travel
// encrypted over the reverse path; the node decrypts and computes.
#[cfg(feature = "sealed-params")]
#[tokio::test]
async fn reflexive_sealed_end_to_end() {
    use bytes::Bytes;
    use ndn_packet::encode::{DataBuilder, InterestBuilder};
    use ndn_packet::{Data, Interest, random_reflexive_name};

    let mut builder = EngineBuilder::new(EngineConfig::default());
    let cid = builder.alloc_face_id();
    let (cface, chandle) = InProcFace::new(cid, 256);
    builder = builder.face(cface);
    let (engine, shutdown) = builder.build().await.expect("engine build");

    let service = ComputeService::attach(&engine);
    service.function_reflexive_sealed("/svc/sealed", |params: Bytes| async move {
        Ok::<u64, ComputeError>(params.iter().map(|&b| b as u64).sum())
    });

    let i1 = InterestBuilder::new("/svc/sealed/req-1")
        .reflexive_name(random_reflexive_name())
        .lifetime(Duration::from_secs(4))
        .build();
    chandle.send(i1).await.expect("send I1");

    let mut result: Option<u64> = None;
    for _ in 0..50 {
        let pkt = match tokio::time::timeout(Duration::from_secs(2), chandle.recv()).await {
            Ok(Some(p)) => p,
            _ => break,
        };
        match pkt.first() {
            Some(&0x05) => {
                let i2 = Interest::decode(pkt).expect("decode I2");
                // The reverse Interest carries the node's ephemeral pubkey as its
                // last component; seal the params to it.
                let node_pub = i2
                    .name
                    .components()
                    .last()
                    .expect("pubkey component")
                    .value
                    .clone();
                let blob = ndn_compute::seal(&node_pub, &[1u8, 2, 3, 4]).expect("seal");
                // The sealed blob must not contain the plaintext bytes verbatim.
                assert!(blob.windows(4).all(|w| w != [1u8, 2, 3, 4]));
                let d2 = DataBuilder::new((*i2.name).clone(), &blob).build();
                chandle.send(d2).await.expect("send D2");
            }
            Some(&0x06) => {
                let d1 = Data::decode(pkt).expect("decode D1");
                let content = d1.content().expect("D1 content");
                result = std::str::from_utf8(content)
                    .ok()
                    .and_then(|s| s.parse().ok());
                break;
            }
            _ => {}
        }
    }

    assert_eq!(
        result,
        Some(10),
        "node must decrypt sealed params and compute the sum"
    );

    drop(chandle);
    drop(engine);
    shutdown.shutdown().await;
}

// RICE §8 authenticated + confidential (the secure default): params are sealed
// to the node's ephemeral key AND carried in signed Data. The node validates
// the signature, then decrypts.
#[cfg(feature = "sealed-params")]
#[tokio::test]
async fn reflexive_secure_validates_decrypts_and_computes() {
    use bytes::Bytes;
    use ndn_packet::encode::{DataBuilder, InterestBuilder};
    use ndn_packet::{Data, Interest, random_reflexive_name};
    use ndn_security::{TrustSchema, Validator};
    use std::sync::Arc;

    let mut builder = EngineBuilder::new(EngineConfig::default());
    let cid = builder.alloc_face_id();
    let (cface, chandle) = InProcFace::new(cid, 256);
    builder = builder.face(cface);
    let (engine, shutdown) = builder.build().await.expect("engine build");

    let service = ComputeService::attach(&engine);
    let validator = Arc::new(Validator::new(TrustSchema::accept_all()));
    service.function_reflexive_secure(
        "/svc/secure",
        validator,
        |params: Bytes, _signer| async move {
            Ok::<u64, ComputeError>(params.iter().map(|&b| b as u64).sum())
        },
    );

    let i1 = InterestBuilder::new("/svc/secure/req-1")
        .reflexive_name(random_reflexive_name())
        .lifetime(Duration::from_secs(4))
        .build();
    chandle.send(i1).await.expect("send I1");

    let mut result: Option<u64> = None;
    for _ in 0..50 {
        let pkt = match tokio::time::timeout(Duration::from_secs(2), chandle.recv()).await {
            Ok(Some(p)) => p,
            _ => break,
        };
        match pkt.first() {
            Some(&0x05) => {
                let i2 = Interest::decode(pkt).expect("decode I2");
                let node_pub = i2.name.components().last().expect("pubkey").value.clone();
                // Seal, then sign the Data carrying the sealed blob.
                let blob = ndn_compute::seal(&node_pub, &[4u8, 6]).expect("seal");
                let d2 = DataBuilder::new((*i2.name).clone(), &blob).build();
                chandle.send(d2).await.expect("send D2");
            }
            Some(&0x06) => {
                let d1 = Data::decode(pkt).expect("decode D1");
                let content = d1.content().expect("D1 content");
                result = std::str::from_utf8(content)
                    .ok()
                    .and_then(|s| s.parse().ok());
                break;
            }
            _ => {}
        }
    }
    assert_eq!(
        result,
        Some(10),
        "secure variant must validate, decrypt, and compute"
    );

    drop(chandle);
    drop(engine);
    shutdown.shutdown().await;
}

// Negative: a sealed-but-unsigned D2 fails the authorization gate before
// decryption, so the secure variant computes nothing.
#[cfg(feature = "sealed-params")]
#[tokio::test]
async fn reflexive_secure_rejects_unsigned_sealed() {
    use bytes::Bytes;
    use ndn_packet::encode::{DataBuilder, InterestBuilder};
    use ndn_packet::{Data, Interest, random_reflexive_name};
    use ndn_security::{TrustSchema, Validator};
    use std::sync::Arc;

    let mut builder = EngineBuilder::new(EngineConfig::default());
    let cid = builder.alloc_face_id();
    let (cface, chandle) = InProcFace::new(cid, 256);
    builder = builder.face(cface);
    let (engine, shutdown) = builder.build().await.expect("engine build");

    let service = ComputeService::attach(&engine);
    let validator = Arc::new(Validator::new(TrustSchema::accept_all()));
    service.function_reflexive_secure(
        "/svc/secure",
        validator,
        |params: Bytes, _signer| async move {
            Ok::<u64, ComputeError>(params.iter().map(|&b| b as u64).sum())
        },
    );

    let i1 = InterestBuilder::new("/svc/secure/req-2")
        .reflexive_name(random_reflexive_name())
        .lifetime(Duration::from_secs(2))
        .build();
    chandle.send(i1).await.expect("send I1");

    let mut got_result = false;
    for _ in 0..50 {
        let pkt = match tokio::time::timeout(Duration::from_millis(800), chandle.recv()).await {
            Ok(Some(p)) => p,
            _ => break,
        };
        match pkt.first() {
            Some(&0x05) => {
                let i2 = Interest::decode(pkt).expect("decode I2");
                let node_pub = i2.name.components().last().expect("pubkey").value.clone();
                let blob = ndn_compute::seal(&node_pub, &[4u8, 6]).expect("seal");
                // Sealed but UNSIGNED — must fail the auth gate.
                let d2 = DataBuilder::new((*i2.name).clone(), &blob).sign_none();
                chandle.send(d2).await.expect("send D2");
            }
            Some(&0x06) => {
                let _ = Data::decode(pkt);
                got_result = true;
                break;
            }
            _ => {}
        }
    }
    assert!(
        !got_result,
        "unsigned sealed params must be rejected by the auth gate"
    );

    drop(chandle);
    drop(engine);
    shutdown.shutdown().await;
}

// RICE §8 multi-hop (the all-hops property): two ndn-rs forwarders joined by a
// link. The consumer is attached to forwarder A; the compute node runs on
// forwarder B. As I1 (carrying reflexive name R) travels consumer→A→B, each
// hop installs a reverse route; the node's reverse Interest then routes back
// B→A→consumer along those routes. Proves reflexive forwarding works through an
// intermediate forwarder, not just at the first hop.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reflexive_multi_hop_traverses_intermediate_forwarder() {
    use bytes::Bytes;
    use ndn_packet::encode::{DataBuilder, InterestBuilder};
    use ndn_packet::{Data, Interest, Name, random_reflexive_name};
    use ndn_transport::{FaceError, FaceId, FaceKind, Transport};

    // One end of a bidirectional inter-forwarder link.
    struct LinkEnd {
        id: FaceId,
        to_peer: tokio::sync::mpsc::Sender<Bytes>,
        from_peer: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Bytes>>,
    }
    impl Transport for LinkEnd {
        fn id(&self) -> FaceId {
            self.id
        }
        fn kind(&self) -> FaceKind {
            FaceKind::Internal // local scope → bare TLV, no LP framing
        }
        async fn send_bytes(&self, pkt: Bytes) -> Result<(), FaceError> {
            self.to_peer.send(pkt).await.map_err(|_| FaceError::Closed)
        }
        async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
            self.from_peer
                .lock()
                .await
                .recv()
                .await
                .ok_or(FaceError::Closed)
        }
    }
    fn link_pair(id_a: FaceId, id_b: FaceId) -> (LinkEnd, LinkEnd) {
        let (a2b_tx, a2b_rx) = tokio::sync::mpsc::channel(256);
        let (b2a_tx, b2a_rx) = tokio::sync::mpsc::channel(256);
        (
            LinkEnd {
                id: id_a,
                to_peer: a2b_tx,
                from_peer: tokio::sync::Mutex::new(b2a_rx),
            },
            LinkEnd {
                id: id_b,
                to_peer: b2a_tx,
                from_peer: tokio::sync::Mutex::new(a2b_rx),
            },
        )
    }

    // Forwarder A: consumer face + link-to-B face.
    let mut builder_a = EngineBuilder::new(EngineConfig::default());
    let consumer_id = builder_a.alloc_face_id();
    let (cface, chandle) = InProcFace::new(consumer_id, 256);
    let a_link_id = builder_a.alloc_face_id();

    // Forwarder B: link-to-A face + (compute attached after build).
    let mut builder_b = EngineBuilder::new(EngineConfig::default());
    let b_link_id = builder_b.alloc_face_id();

    let (a_link, b_link) = link_pair(a_link_id, b_link_id);
    builder_a = builder_a.face(cface).face(a_link);
    builder_b = builder_b.face(b_link);

    let (engine_a, shutdown_a) = builder_a.build().await.expect("engine A");
    let (engine_b, shutdown_b) = builder_b.build().await.expect("engine B");

    // A forwards /svc/compute toward B over the link.
    let svc: Name = "/svc/compute".parse().unwrap();
    engine_a.fib().add_nexthop(&svc, a_link_id, 0);

    // B runs the compute node.
    let service = ComputeService::attach(&engine_b);
    service.function_reflexive("/svc/compute", |params: Bytes| async move {
        Ok::<u64, ComputeError>(params.iter().map(|&b| b as u64).sum())
    });

    // Consumer (on A) sends I1 with a reflexive name and no in-name params.
    let i1 = InterestBuilder::new("/svc/compute/req-1")
        .reflexive_name(random_reflexive_name())
        .lifetime(Duration::from_secs(4))
        .build();
    chandle.send(i1).await.expect("send I1");

    let mut result: Option<u64> = None;
    for _ in 0..100 {
        let pkt = match tokio::time::timeout(Duration::from_secs(3), chandle.recv()).await {
            Ok(Some(p)) => p,
            _ => break,
        };
        match pkt.first() {
            Some(&0x05) => {
                // Reverse Interest reached the consumer through A — answer D2.
                let i2 = Interest::decode(pkt).expect("decode I2");
                let d2 = DataBuilder::new((*i2.name).clone(), &[3u8, 3, 4]).build();
                chandle.send(d2).await.expect("send D2");
            }
            Some(&0x06) => {
                let d1 = Data::decode(pkt).expect("decode D1");
                let content = d1.content().expect("D1 content");
                result = std::str::from_utf8(content)
                    .ok()
                    .and_then(|s| s.parse().ok());
                break;
            }
            _ => {}
        }
    }

    assert_eq!(
        result,
        Some(10),
        "reverse Interest must traverse the intermediate forwarder back to the consumer",
    );

    drop(chandle);
    drop(engine_a);
    drop(engine_b);
    shutdown_a.shutdown().await;
    shutdown_b.shutdown().await;
}
