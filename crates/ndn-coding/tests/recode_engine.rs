//! F2 engine integration: a `RecoderFace` attached to a real
//! `ForwarderEngine` answers coded-request Interests with fresh
//! combinations a consumer decodes and verifies. Proves the recoder runs on
//! the actual forwarding path (FIB → synthetic face → pipeline → consumer),
//! mirroring the `ndn-compute` attach pattern. Gated by `f2-recode-face`.

#![cfg(feature = "f2-recode-face")]

use std::time::Duration;

use bytes::Bytes;
use ndn_app::{Consumer, EngineBuilder};
use ndn_engine::EngineConfig;
use ndn_face::local::InProcFace;
use ndn_packet::Name;
use ndn_transport::{FaceError, FaceId, FaceKind, Transport};

use ndn_coding::policy::Field;
use ndn_coding::recode::{
    CodedMetadata, CodingVector, GenerationBuffer, GenerationDescriptor, RecodePolicy,
    SourceCommitment, naming, row_hash,
};
use ndn_coding::recode_face;

#[tokio::test]
async fn recoder_face_serves_innovative_combinations_through_engine() {
    // Payload split into K equal source rows.
    let k: u16 = 4;
    let symbol_size: u32 = 64;
    let payload: Vec<u8> = (0..(k as usize * symbol_size as usize))
        .map(|i| (i & 0xff) as u8)
        .collect();
    let sources: Vec<Vec<u8>> = payload
        .chunks(symbol_size as usize)
        .map(|c| c.to_vec())
        .collect();

    let object: Name = "/test/nc/clip".parse().unwrap();
    let generation_id = 1u64;
    let descriptor = GenerationDescriptor {
        generation_id,
        k,
        symbol_size,
        field: Field::Gf8,
        content_name: object.clone(),
        source_commitment: SourceCommitment::RowHashes(
            sources.iter().map(|r| row_hash(r)).collect(),
        ),
        recode: RecodePolicy::Open,
        delegation: None,
        fingerprint: None,
    };

    // Engine with one consumer face; attach the recoder as a synthetic face.
    // Allocate the consumer face id via the builder so it can't collide with
    // the recoder's `engine.faces().alloc_id()` (compute's attach pattern).
    let mut builder = EngineBuilder::new(EngineConfig::default());
    let consumer_id = builder.alloc_face_id();
    let (consumer_face, consumer_handle) = InProcFace::new(consumer_id, 256);
    builder = builder.face(consumer_face);
    let (engine, shutdown) = builder.build().await.expect("engine build");

    let handle = recode_face::attach(&engine, None);

    // Route the generation prefix to the recoder face, then seed its buffer
    // with the K systematic source packets (modelling a node that has
    // received them).
    let gen_prefix = naming::generation_name(&object, generation_id);
    engine.fib().add_nexthop(&gen_prefix, handle.face_id, 0);
    handle.state.install_generation(descriptor.clone()).await;
    for (i, row) in sources.iter().enumerate() {
        let meta = CodedMetadata {
            generation_id,
            k,
            field: Field::Gf8,
            vector: CodingVector::unit(k, i as u16),
        };
        assert!(
            handle
                .state
                .feed(&object, generation_id, &meta, Bytes::from(row.clone()))
                .await
        );
    }

    // Consumer pulls req=0,1,2,… ; each returns one innovative combination
    // minted by the recoder. Decode + verify-on-decode at rank K.
    let mut consumer = Consumer::from_handle(consumer_handle);
    let mut buf = GenerationBuffer::new(descriptor);
    for j in 0..16u64 {
        if buf.is_decodable() {
            break;
        }
        let name = naming::request_name(&object, generation_id, j);
        let data =
            match tokio::time::timeout(Duration::from_millis(300), consumer.fetch(name)).await {
                Ok(Ok(d)) => d,
                _ => continue,
            };
        let Some(content) = data.content() else {
            continue;
        };
        let Ok((meta, row)) = CodedMetadata::split(content) else {
            continue;
        };
        buf.absorb(&meta, row).ok();
    }

    assert!(
        buf.is_decodable(),
        "consumer reached rank K via the recoder"
    );
    let recovered = buf.decode().expect("decode + verify-on-decode");
    assert_eq!(recovered.as_ref(), payload.as_slice());

    drop(consumer);
    drop(engine);
    shutdown.shutdown().await;
}

/// Recode-as-named-computation (doctrine §8): a consumer requests specific
/// deterministic combinations by naming the coding vector
/// (`…/_gen/<id>/_nc/<vector>`). The recoder answers each with the exact
/// combination, so the responses are deterministic + cacheable. Here the
/// consumer names the K unit vectors, recovering the source rows directly.
#[tokio::test]
async fn named_vector_combinations_served_through_engine() {
    let k: u16 = 4;
    let symbol_size: u32 = 32;
    let payload: Vec<u8> = (0..(k as usize * symbol_size as usize))
        .map(|i| ((i * 7 + 1) & 0xff) as u8)
        .collect();
    let sources: Vec<Vec<u8>> = payload
        .chunks(symbol_size as usize)
        .map(|c| c.to_vec())
        .collect();

    let object: Name = "/test/nc/named".parse().unwrap();
    let generation_id = 3u64;
    let descriptor = GenerationDescriptor {
        generation_id,
        k,
        symbol_size,
        field: Field::Gf8,
        content_name: object.clone(),
        source_commitment: SourceCommitment::RowHashes(
            sources.iter().map(|r| row_hash(r)).collect(),
        ),
        recode: RecodePolicy::Open,
        delegation: None,
        fingerprint: None,
    };

    let mut builder = EngineBuilder::new(EngineConfig::default());
    let consumer_id = builder.alloc_face_id();
    let (consumer_face, consumer_handle) = InProcFace::new(consumer_id, 256);
    builder = builder.face(consumer_face);
    let (engine, shutdown) = builder.build().await.expect("engine build");

    let handle = recode_face::attach(&engine, None);
    let gen_prefix = naming::generation_name(&object, generation_id);
    engine.fib().add_nexthop(&gen_prefix, handle.face_id, 0);
    handle.state.install_generation(descriptor.clone()).await;
    for (i, row) in sources.iter().enumerate() {
        let meta = CodedMetadata {
            generation_id,
            k,
            field: Field::Gf8,
            vector: CodingVector::unit(k, i as u16),
        };
        handle
            .state
            .feed(&object, generation_id, &meta, Bytes::from(row.clone()))
            .await;
    }

    let mut consumer = Consumer::from_handle(consumer_handle);
    let mut buf = GenerationBuffer::new(descriptor);
    for i in 0..k {
        let target = CodingVector::unit(k, i);
        let name = naming::vector_request_name(&object, generation_id, &target);
        let data = tokio::time::timeout(Duration::from_millis(300), consumer.fetch(name))
            .await
            .expect("no timeout")
            .expect("fetch ok");
        let (meta, row) = CodedMetadata::split(data.content().unwrap()).unwrap();
        assert_eq!(meta.vector, target, "served the exact named combination");
        buf.absorb(&meta, row).ok();
    }
    assert!(buf.is_decodable());
    assert_eq!(buf.decode().unwrap().as_ref(), payload.as_slice());

    drop(consumer);
    drop(engine);
    shutdown.shutdown().await;
}

// One end of a bidirectional inter-forwarder link (copied from the
// ndn-compute end-to-end harness).
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
        FaceKind::Internal
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

/// Two-forwarder, two-consumer, lossy multicast: a recoder on forwarder B
/// serves both consumers on forwarder A across an A→B link. Each consumer
/// drops a different half of the responses (modelling independent lossy
/// links); because every coded request is answered by a fresh innovative
/// combination, both still reach rank K and decode + verify. This is the
/// multicast / loss-repair win on a real two-hop forwarding path.
#[tokio::test]
async fn multi_hop_lossy_multicast_recovers_at_both_consumers() {
    let k: u16 = 4;
    let symbol_size: u32 = 48;
    let payload: Vec<u8> = (0..(k as usize * symbol_size as usize))
        .map(|i| ((i * 3) & 0xff) as u8)
        .collect();
    let sources: Vec<Vec<u8>> = payload
        .chunks(symbol_size as usize)
        .map(|c| c.to_vec())
        .collect();

    let object: Name = "/test/nc/stream".parse().unwrap();
    let generation_id = 9u64;
    let descriptor = GenerationDescriptor {
        generation_id,
        k,
        symbol_size,
        field: Field::Gf8,
        content_name: object.clone(),
        source_commitment: SourceCommitment::RowHashes(
            sources.iter().map(|r| row_hash(r)).collect(),
        ),
        recode: RecodePolicy::Open,
        delegation: None,
        fingerprint: None,
    };

    // Forwarder A: two consumer faces + a link to B.
    let mut builder_a = EngineBuilder::new(EngineConfig::default());
    let c0_id = builder_a.alloc_face_id();
    let (c0_face, c0_handle) = InProcFace::new(c0_id, 256);
    let c1_id = builder_a.alloc_face_id();
    let (c1_face, c1_handle) = InProcFace::new(c1_id, 256);
    let a_link_id = builder_a.alloc_face_id();

    // Forwarder B: link to A (+ recoder attached after build).
    let mut builder_b = EngineBuilder::new(EngineConfig::default());
    let b_link_id = builder_b.alloc_face_id();

    let (a_link, b_link) = link_pair(a_link_id, b_link_id);
    builder_a = builder_a.face(c0_face).face(c1_face).face(a_link);
    builder_b = builder_b.face(b_link);
    let (engine_a, shutdown_a) = builder_a.build().await.expect("engine A");
    let (engine_b, shutdown_b) = builder_b.build().await.expect("engine B");

    // A forwards the generation prefix toward B; B answers from the recoder.
    let gen_prefix = naming::generation_name(&object, generation_id);
    engine_a.fib().add_nexthop(&gen_prefix, a_link_id, 0);
    let handle = recode_face::attach(&engine_b, None);
    engine_b.fib().add_nexthop(&gen_prefix, handle.face_id, 0);
    handle.state.install_generation(descriptor.clone()).await;
    for (i, row) in sources.iter().enumerate() {
        let meta = CodedMetadata {
            generation_id,
            k,
            field: Field::Gf8,
            vector: CodingVector::unit(k, i as u16),
        };
        handle
            .state
            .feed(&object, generation_id, &meta, Bytes::from(row.clone()))
            .await;
    }

    // Each consumer drops a different half of the requests (lossy links).
    async fn recover(
        consumer: &mut Consumer,
        object: &Name,
        generation_id: u64,
        descriptor: &GenerationDescriptor,
        drop_even: bool,
    ) -> Bytes {
        let mut buf = GenerationBuffer::new(descriptor.clone());
        for j in 0..32u64 {
            if buf.is_decodable() {
                break;
            }
            if (j % 2 == 0) == drop_even {
                continue; // this response is "lost"
            }
            let name = naming::request_name(object, generation_id, j);
            let data = match tokio::time::timeout(Duration::from_millis(300), consumer.fetch(name))
                .await
            {
                Ok(Ok(d)) => d,
                _ => continue,
            };
            if let Some(content) = data.content()
                && let Ok((meta, row)) = CodedMetadata::split(content)
            {
                buf.absorb(&meta, row).ok();
            }
        }
        assert!(buf.is_decodable(), "consumer reached rank K despite loss");
        buf.decode().expect("decode + verify-on-decode")
    }

    let mut c0 = Consumer::from_handle(c0_handle);
    let mut c1 = Consumer::from_handle(c1_handle);
    let r0 = recover(&mut c0, &object, generation_id, &descriptor, true).await;
    let r1 = recover(&mut c1, &object, generation_id, &descriptor, false).await;
    assert_eq!(r0.as_ref(), payload.as_slice());
    assert_eq!(r1.as_ref(), payload.as_slice());

    drop(c0);
    drop(c1);
    drop(engine_a);
    drop(engine_b);
    shutdown_a.shutdown().await;
    shutdown_b.shutdown().await;
}
