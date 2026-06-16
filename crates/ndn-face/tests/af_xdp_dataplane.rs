//! Phase A data-path witness: an NDN Interest/Data round-trip between two
//! AF_XDP ether faces (one per veth end). Proves `AfXdpFace` works as a
//! forwarder face — standard `[eth|14][payload]` TX + filtered/stripped RX —
//! not just the raw RX spike. (af_xdp↔af_xdp isolates af_xdp: the `af_packet`
//! TPACKET face injects a non-standard 20-byte gap that only interops with
//! itself, so it's a poor yardstick here.)
//!
//! `#[ignore]` — needs root (XDP attach + XSK bind + AF_PACKET), a veth pair,
//! and a compiled redirect object. Run:
//!
//!   sudo ip link add veth0 type veth peer name veth1
//!   sudo ip link set veth0 up && sudo ip link set veth1 up
//!   sudo -E AFXDP_IF0=veth0 AFXDP_IF1=veth1 AFXDP_BPF=/path/redirect[.o] \
//!     ~/.cargo/bin/cargo test -p ndn-face-native --features af-xdp \
//!     --test af_xdp_dataplane -- --ignored --nocapture
//!   sudo ip link del veth0
//!
//! af_xdp(veth0) sends an Interest → arrives veth1 → af_packet recv → replies
//! Data → arrives veth0 → XDP redirect → af_xdp recv. A pass exercises both
//! af_xdp TX and RX against a known-good face.
#![cfg(all(target_os = "linux", feature = "af-xdp"))]

use std::time::Duration;

use ndn_face::l2::{AfXdpFace, get_interface_mac};
use ndn_face::{NamedEtherFace, RadioFaceMetadata};
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Data, Interest, Name};
use ndn_transport::{FaceId, Transport};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs root + veth pair + AFXDP_BPF object"]
async fn af_xdp_ether_roundtrip() {
    let if0 = std::env::var("AFXDP_IF0").unwrap_or_else(|_| "veth0".into());
    let if1 = std::env::var("AFXDP_IF1").unwrap_or_else(|_| "veth1".into());
    let bpf = std::env::var("AFXDP_BPF").expect("set AFXDP_BPF to the redirect object path");

    let mac0 = get_interface_mac(&if0).expect("mac veth0");
    let mac1 = get_interface_mac(&if1).expect("mac veth1");

    // af_xdp on if0 (peer = if1); af_xdp on if1 (peer = if0).
    let axf = AfXdpFace::new(FaceId(1), &if0, 0, mac1, bpf.clone().into()).expect("af_xdp if0");
    let axf1 = AfXdpFace::new(FaceId(2), &if1, 0, mac0, bpf.into()).expect("af_xdp if1");

    // Producer on if1: reply to each Interest with same-named Data. Keeps
    // serving (and so keeps `axf1` alive) for the duration of the test.
    let producer = tokio::spawn(async move {
        while let Ok(Ok(raw)) =
            tokio::time::timeout(Duration::from_secs(8), axf1.recv_bytes()).await
        {
            if let Ok(i) = Interest::decode(raw) {
                let data = DataBuilder::new((*i.name).clone(), b"afxdp-ok").sign_digest_sha256();
                let _ = axf1.send_bytes(data).await;
            }
        }
    });

    // Consumer on if0: send an Interest (retry — early veth frames can drop),
    // await the Data back over the AF_XDP RX path.
    let interest = InterestBuilder::new("/afxdp/witness")
        .lifetime(Duration::from_secs(2))
        .build();
    for _ in 0..20 {
        axf.send_bytes(interest.clone()).await.expect("af_xdp send");
        if let Ok(Ok(reply)) =
            tokio::time::timeout(Duration::from_millis(400), axf.recv_bytes()).await
            && let Ok(data) = Data::decode(reply)
        {
            assert_eq!(
                data.name.to_string(),
                "/afxdp/witness",
                "af_xdp must receive the Data for the Interest it sent"
            );
            producer.abort();
            return;
        }
    }
    producer.abort();
    panic!("no decodable Data received over the AF_XDP face within timeout");
}

/// Regression for the af_packet (NamedEtherFace) TPACKET TX 20-byte-gap bug:
/// frames the af_packet ether face sends must arrive as `[eth | NDN]` with no
/// gap. Verified against `AfXdpFace` (a raw-wire reader), which catches the gap
/// an `nef`-to-`nef` test would hide (the receiver `tp_mac` tracked the same
/// skew). Pre-fix the Interest arrives as `[20 zeros | truncated]` and fails to
/// decode. Run serially with `af_xdp_ether_roundtrip` (both bind veth0's XSK
/// queue): `... -- --ignored --test-threads=1`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs root + veth pair + AFXDP_BPF object; run with --test-threads=1"]
async fn af_packet_tx_reaches_af_xdp_without_gap() {
    let if0 = std::env::var("AFXDP_IF0").unwrap_or_else(|_| "veth0".into());
    let if1 = std::env::var("AFXDP_IF1").unwrap_or_else(|_| "veth1".into());
    let bpf = std::env::var("AFXDP_BPF").expect("set AFXDP_BPF to the redirect object path");
    let mac0 = get_interface_mac(&if0).expect("mac veth0");
    let mac1 = get_interface_mac(&if1).expect("mac veth1");

    // af_xdp receives on if0; the af_packet ether face transmits from if1.
    let axf = AfXdpFace::new(FaceId(1), &if0, 0, mac1, bpf.into()).expect("af_xdp if0");
    let nef = NamedEtherFace::new(
        FaceId(2),
        Name::root(),
        mac0,
        if1,
        RadioFaceMetadata::default(),
    )
    .expect("af_packet ether face");

    let interest = InterestBuilder::new("/afpkt/txfix")
        .lifetime(Duration::from_secs(2))
        .build();
    let sender = tokio::spawn(async move {
        loop {
            let _ = nef.send_bytes(interest.clone()).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });

    for _ in 0..40 {
        if let Ok(Ok(raw)) =
            tokio::time::timeout(Duration::from_millis(200), axf.recv_bytes()).await
            && let Ok(i) = Interest::decode(raw)
        {
            assert_eq!(
                i.name.to_string(),
                "/afpkt/txfix",
                "af_packet TX must land as [eth|NDN] (no gap) for af_xdp to decode it"
            );
            sender.abort();
            return;
        }
    }
    sender.abort();
    panic!("af_xdp received no decodable Interest from the af_packet TX -- 20-byte gap?");
}
