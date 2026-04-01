//! `ndn-put` — publish a file as named Data, optionally chunked.
//!
//! Usage: ndn-put /name/of/data <file> [--chunk-size <bytes>]

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use ndn_ipc::chunked::{ChunkedProducer, NDN_DEFAULT_SEGMENT_SIZE};
use ndn_packet::Name;

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let name_str = match args.next() {
        Some(s) => s,
        None => {
            eprintln!("usage: ndn-put <name> <file> [--chunk-size <bytes>]");
            std::process::exit(1);
        }
    };
    let file_path = match args.next() {
        Some(s) => s,
        None => {
            eprintln!("usage: ndn-put <name> <file> [--chunk-size <bytes>]");
            std::process::exit(1);
        }
    };

    let mut chunk_size = NDN_DEFAULT_SEGMENT_SIZE;
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--chunk-size" => {
                let val = args.next().unwrap_or_default();
                chunk_size = val.parse().unwrap_or(NDN_DEFAULT_SEGMENT_SIZE);
            }
            other => bail!("unknown flag: {other}"),
        }
    }

    let payload = tokio::fs::read(&file_path)
        .await
        .with_context(|| format!("reading {file_path}"))?;

    let name: Name = name_str.parse().unwrap_or_else(|_| Name::root());
    let producer = ChunkedProducer::new(name, Bytes::from(payload), chunk_size);

    println!(
        "ndn-put: publishing {} from {} ({} segment(s), chunk size {} B)",
        name_str,
        file_path,
        producer.segment_count(),
        chunk_size,
    );

    for i in 0..producer.segment_count() {
        let seg = producer.segment(i).unwrap();
        println!("  segment {}/{}: {} bytes", i, producer.segment_count() - 1, seg.len());
        // TODO: register prefix handler and serve each segment as Data via AppFace
    }

    println!("ndn-put: local forwarder connection not yet implemented");
    Ok(())
}
