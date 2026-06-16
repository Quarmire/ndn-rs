//! `_nc/<vector>` deterministic recode registered as an ndn-compute function:
//! it appears in the `compute/list` dataset and a consumer fetching named
//! combinations through the compute face recovers the generation. Gated by
//! `f2-recode-compute`.

#![cfg(feature = "f2-recode-compute")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use ndn_app::{Consumer, EngineBuilder};
use ndn_compute::ComputeService;
use ndn_engine::EngineConfig;
use ndn_face::local::InProcFace;
use ndn_packet::Name;

use ndn_coding::policy::Field;
use ndn_coding::recode::{
    CodedMetadata, CodingVector, GenerationBuffer, GenerationDescriptor, RecodePolicy,
    SourceCommitment, naming, row_hash,
};
use ndn_coding::recode_compute::register_named_recode;

#[tokio::test]
async fn nc_registered_as_compute_function() {
    let k: u16 = 4;
    let symbol_size: u32 = 32;
    let payload: Vec<u8> = (0..(k as usize * symbol_size as usize))
        .map(|i| ((i * 5 + 2) & 0xff) as u8)
        .collect();
    let sources: Vec<Vec<u8>> = payload
        .chunks(symbol_size as usize)
        .map(|c| c.to_vec())
        .collect();

    let object: Name = "/test/nc/compute".parse().unwrap();
    let generation_id = 4u64;
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

    // Seed a full-rank buffer the compute handler will recode from.
    let buffer = Arc::new(Mutex::new(GenerationBuffer::new(descriptor)));
    {
        let mut buf = buffer.lock().unwrap();
        for (i, row) in sources.iter().enumerate() {
            let meta = CodedMetadata {
                generation_id,
                k,
                field: Field::Gf8,
                vector: CodingVector::unit(k, i as u16),
            };
            buf.absorb(&meta, Bytes::from(row.clone())).unwrap();
        }
    }

    let mut builder = EngineBuilder::new(EngineConfig::default());
    let consumer_id = builder.alloc_face_id();
    let (consumer_face, consumer_handle) = InProcFace::new(consumer_id, 256);
    builder = builder.face(consumer_face);
    let (engine, shutdown) = builder.build().await.expect("engine build");

    let service = ComputeService::attach(&engine);
    register_named_recode(&service, object.clone(), generation_id, Arc::clone(&buffer));

    // It shows up in the compute/list dataset, under the _nc prefix.
    let nc_prefix = naming::generation_name(&object, generation_id).append(naming::NC_MARKER);
    assert!(
        service.functions().iter().any(|f| f.prefix == nc_prefix),
        "named recode appears in compute/list"
    );

    // A consumer naming the K unit vectors recovers the sources via compute.
    let mut consumer = Consumer::from_handle(consumer_handle);
    let mut out = GenerationBuffer::new(GenerationDescriptor {
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
    });
    for i in 0..k {
        let target = CodingVector::unit(k, i);
        let name = naming::vector_request_name(&object, generation_id, &target);
        let data = tokio::time::timeout(Duration::from_millis(300), consumer.fetch(name))
            .await
            .expect("no timeout")
            .expect("compute fetch ok");
        let (meta, row) = CodedMetadata::split(data.content().unwrap()).unwrap();
        assert_eq!(meta.vector, target);
        out.absorb(&meta, row).ok();
    }
    assert!(out.is_decodable());
    assert_eq!(out.decode().unwrap().as_ref(), payload.as_slice());

    service.shutdown();
    drop(consumer);
    drop(engine);
    shutdown.shutdown().await;
}
