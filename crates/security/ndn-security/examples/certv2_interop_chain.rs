//! ndn-rs side of the ndn-cxx interop witness
//! (`testbed/interop/c07_certv2_ndncxx_interop.sh`): writes NDN Certificate
//! Format v2 namespace chains issued with the public [`SecurityManager`] API,
//! for ndn-cxx to decode and validate.
//!
//! ```text
//! cargo run -p ndn-security --example certv2_interop_chain -- OUT_DIR
//! ```
//!
//! Writes raw Data TLV files to `OUT_DIR/ecdsa/` (ECDSA-P256, namespace
//! `/interop/ecdsa`) and `OUT_DIR/ed25519/` (Ed25519, `/interop/ed25519`):
//!
//! | file        | name                                     | signed by      |
//! |-------------|------------------------------------------|----------------|
//! | `root.cert` | `/<ns>/KEY/<kid>/self/v=…`               | itself         |
//! | `ca.cert`   | `/<ns>/CA/KEY/<kid>/NA/v=…`              | the root key   |
//! | `dev.cert`  | `/<ns>/member/dev/KEY/<kid>/NDNCERT/v=…` | the CA key     |
//! | `data.data` | `/<ns>/member/dev/data/v=…`              | the device key |
//!
//! Every KeyLocator names the signer's key (`/<…>/KEY/<kid>`), not one of its
//! certificates. The Data content is [`PAYLOAD`].

use std::error::Error;
use std::path::Path;

use bytes::Bytes;
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Name, name, tlv_type};
use ndn_security::cert_name::{self, DEFAULT_ISSUER, NDNCERT_ISSUER};
use ndn_security::{Certificate, SecurityManager, SignWith};
use ndn_tlv::TlvWriter;

/// Content of the signed Data; the witness flips a byte of it to tamper.
const PAYLOAD: &[u8] = b"ndn-rs certv2 interop payload";
const DAY_MS: u64 = 24 * 3600 * 1000;

#[derive(Clone, Copy)]
enum Alg {
    EcdsaP256,
    Ed25519,
}

// `issue_self_signed` blocks on its own futures executor, so the example runs
// on tokio rather than inside `futures::executor::block_on`.
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let out = std::env::args_os()
        .nth(1)
        .ok_or("usage: certv2_interop_chain OUT_DIR")?;
    let out = Path::new(&out);
    write_chain(&out.join("ecdsa"), name!("/interop/ecdsa"), Alg::EcdsaP256).await?;
    write_chain(
        &out.join("ed25519"),
        name!("/interop/ed25519"),
        Alg::Ed25519,
    )
    .await
}

async fn write_chain(dir: &Path, ns: Name, alg: Alg) -> Result<(), Box<dyn Error>> {
    std::fs::create_dir_all(dir)?;
    let mgr = SecurityManager::new();
    let dev_id = ns.clone().append("member").append("dev");
    let (root, root_pk) = new_key(&mgr, &ns, alg)?;
    let (ca, ca_pk) = new_key(&mgr, &ns.clone().append("CA"), alg)?;
    let (dev, dev_pk) = new_key(&mgr, &dev_id, alg)?;

    let root_cert = mgr.issue_self_signed(&root, root_pk, 365 * DAY_MS)?;
    let ca_cert = mgr
        .certify_as(&ca, ca_pk, &root, 365 * DAY_MS, DEFAULT_ISSUER, None)
        .await?;
    let dev_cert = mgr
        .certify_as(&dev, dev_pk, &ca, 30 * DAY_MS, NDNCERT_ISSUER, None)
        .await?;

    let signer = mgr.get_signer(&dev).await?;
    let data_name = dev_id
        .append("data")
        .append_version(cert_name::next_version());
    let data = DataBuilder::new(data_name.clone(), PAYLOAD)
        .sign_with(&*signer)
        .await?;

    for (file, cert) in [
        ("root.cert", &root_cert),
        ("ca.cert", &ca_cert),
        ("dev.cert", &dev_cert),
    ] {
        std::fs::write(dir.join(file), cert_wire(cert)?)?;
        println!("{}: {}", dir.join(file).display(), cert.name);
    }
    std::fs::write(dir.join("data.data"), &data)?;
    println!("{}: {data_name}", dir.join("data.data").display());
    Ok(())
}

/// A fresh key `<identity>/KEY/<random 8-byte hex key-id>` and its public key.
fn new_key(
    mgr: &SecurityManager,
    identity: &Name,
    alg: Alg,
) -> Result<(Name, Bytes), Box<dyn Error>> {
    let key_name = identity
        .clone()
        .append("KEY")
        .append(format!("{:016x}", rand::random::<u64>()));
    match alg {
        Alg::EcdsaP256 => mgr.generate_ecdsa_p256(key_name.clone())?,
        Alg::Ed25519 => mgr.generate_ed25519(key_name.clone())?,
    };
    let public_key = mgr
        .get_signer_sync(&key_name)?
        .public_key()
        .ok_or("signer exposes no public key")?;
    Ok((key_name, public_key))
}

/// The certificate as the Data packet it was decoded from.
fn cert_wire(cert: &Certificate) -> Result<Bytes, &'static str> {
    let (Some(region), Some(sig)) = (&cert.signed_region, &cert.sig_value) else {
        return Err("certificate carries no signed region");
    };
    let mut w = TlvWriter::new();
    w.write_nested(tlv_type::DATA, |w| {
        w.write_raw(region);
        w.write_tlv(tlv_type::SIGNATURE_VALUE, sig);
    });
    Ok(w.finish())
}
