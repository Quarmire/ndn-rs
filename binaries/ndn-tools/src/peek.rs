//! `ndn-peek` — fetch a single named Data packet and print its content.
//!
//! Usage: ndn-peek /name/of/data [--timeout-ms <ms>]

use anyhow::{bail, Result};
use bytes::Bytes;
use ndn_packet::{Interest, Name, NameComponent};

fn parse_name(s: &str) -> Result<Name> {
    let components: Vec<NameComponent> = s
        .split('/')
        .filter(|c| !c.is_empty())
        .map(|c| NameComponent::generic(Bytes::copy_from_slice(c.as_bytes())))
        .collect();
    if components.is_empty() {
        Ok(Name::root())
    } else {
        Ok(Name::from_components(components))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let name_str = match args.next() {
        Some(s) => s,
        None => {
            eprintln!("usage: ndn-peek <name> [--timeout-ms <ms>]");
            std::process::exit(1);
        }
    };

    let mut timeout_ms: u64 = 4000;
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--timeout-ms" => {
                let val = args.next().unwrap_or_default();
                timeout_ms = val.parse().unwrap_or(4000);
            }
            other => bail!("unknown flag: {other}"),
        }
    }

    let name = parse_name(&name_str)?;
    let _interest = Interest::new(name.clone());

    println!("ndn-peek: fetching {}", name_str);
    println!("ndn-peek: timeout {}ms", timeout_ms);
    // TODO: connect to local forwarder via AppFace and express Interest
    println!("ndn-peek: local forwarder connection not yet implemented");
    Ok(())
}
