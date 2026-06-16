//! Issue #14 — server-side WebTransport listener loopback witness.
//!
//! Spins up `WebTransportListener` with a self-signed identity, connects via
//! a `wtransport` client, and exercises one Interest / one Data round-trip
//! over QUIC datagrams.

use std::time::Duration;

use bytes::Bytes;
use ndn_packet::fragment::ReassemblyBuffer;
use ndn_packet::lp::extract_fragment;
use ndn_transport::{ClientTls, FaceId, Transport};

use ndn_face_webtransport::{WebTransportFace, WebTransportListener, WtTlsConfig};

fn make_tlv(tag: u8, value: &[u8]) -> Bytes {
    use ndn_tlv::TlvWriter;
    let mut w = TlvWriter::new();
    w.write_tlv(tag as u64, value);
    w.finish()
}

#[tokio::test]
async fn i14_wt_loopback_round_trip() {
    let listener = WebTransportListener::bind(
        "127.0.0.1:0".parse().unwrap(),
        WtTlsConfig::SelfSigned {
            hostnames: vec!["localhost".into()],
        },
    )
    .await
    .expect("bind WT listener");
    let server_addr = listener.local_addr();

    // Trust whatever cert the listener self-signed.
    let client_config = wtransport::ClientConfig::builder()
        .with_bind_default()
        .with_no_cert_validation()
        .build();
    let client_endpoint = wtransport::Endpoint::client(client_config).expect("client endpoint");

    let server_task = tokio::spawn(async move { listener.accept(FaceId(1)).await });

    let url = format!("https://{}/ndn", server_addr);
    let client_conn = client_endpoint.connect(&url).await.expect("client connect");
    let client_face = WebTransportFace::from_connection(FaceId(0), client_conn, "client".into());

    let server_face = server_task.await.unwrap().expect("accept");

    // Client → Server (Interest)
    let interest = make_tlv(0x05, b"hello");
    client_face
        .send_bytes(interest.clone())
        .await
        .expect("send interest");
    let received = server_face.recv_bytes().await.expect("recv interest");
    assert_eq!(received, ndn_packet::lp::encode_lp_packet(&interest));

    // Server → Client (Data)
    let data = make_tlv(0x06, b"world");
    server_face
        .send_bytes(data.clone())
        .await
        .expect("send data");
    let received = client_face.recv_bytes().await.expect("recv data");
    assert_eq!(received, ndn_packet::lp::encode_lp_packet(&data));
}

/// A Data larger than the QUIC datagram size is split into NDNLPv2 fragments
/// (one per datagram) and reassembles to the original LP packet — the same
/// scheme NDNts' `H3Transport` + `LpService` use, so the two interoperate.
#[tokio::test]
async fn i14_wt_large_data_fragments_over_datagrams() {
    let listener = WebTransportListener::bind(
        "127.0.0.1:0".parse().unwrap(),
        WtTlsConfig::SelfSigned {
            hostnames: vec!["localhost".into()],
        },
    )
    .await
    .expect("bind WT listener");
    let server_addr = listener.local_addr();

    let client_config = wtransport::ClientConfig::builder()
        .with_bind_default()
        .with_no_cert_validation()
        .build();
    let client_endpoint = wtransport::Endpoint::client(client_config).expect("client endpoint");

    let server_task = tokio::spawn(async move { listener.accept(FaceId(1)).await });
    let url = format!("https://{}/ndn", server_addr);
    let client_conn = client_endpoint.connect(&url).await.expect("client connect");
    let client_face = WebTransportFace::from_connection(FaceId(0), client_conn, "client".into());
    let server_face = server_task.await.unwrap().expect("accept");

    // 8 KiB of content — spans several datagrams once fragmented.
    let big = make_tlv(0x06, &vec![0xAB; 8192]);
    let expected = ndn_packet::lp::encode_lp_packet(&big);

    // Drain continuously (the engine's face reader is always-on) and reassemble
    // exactly as the decode stage does: group by `sequence - frag_index`.
    let reader = tokio::spawn(async move {
        let mut reasm = ReassemblyBuffer::new(Duration::from_secs(5));
        loop {
            let dgram = client_face.recv_bytes().await.expect("recv");
            let h = extract_fragment(&dgram).expect("expected fragmented datagram");
            let base_seq = h.sequence - h.frag_index;
            let payload = dgram.slice(h.frag_start..h.frag_end);
            if let Some(full) = reasm.process(0, base_seq, h.frag_index, h.frag_count, payload) {
                return full;
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    server_face.send_bytes(big).await.expect("send big");

    let reconstructed = tokio::time::timeout(Duration::from_secs(10), reader)
        .await
        .expect("reader timed out")
        .expect("reader task");
    assert_eq!(reconstructed, expected);
}

/// The native outbound dial (`WebTransportFace::connect`, the forwarder-to-
/// forwarder path) reaches a listener and round-trips, pinning the listener's
/// self-signed leaf cert by SHA-256.
#[tokio::test]
async fn i14_wt_connect_dials_listener() {
    let listener = WebTransportListener::bind(
        "127.0.0.1:0".parse().unwrap(),
        WtTlsConfig::SelfSigned {
            hostnames: vec!["localhost".into()],
        },
    )
    .await
    .expect("bind WT listener");
    let server_addr = listener.local_addr();
    let hash = listener.leaf_cert_sha256().expect("leaf cert hash");

    let server_task = tokio::spawn(async move { listener.accept(FaceId(1)).await });

    let url = format!("https://{server_addr}/ndn");
    let client_face = WebTransportFace::connect(FaceId(0), &url, ClientTls::CertHashes(vec![hash]))
        .await
        .expect("dial");
    let server_face = server_task.await.unwrap().expect("accept");

    let interest = make_tlv(0x05, b"dialed");
    client_face
        .send_bytes(interest.clone())
        .await
        .expect("send interest");
    let received = server_face.recv_bytes().await.expect("recv interest");
    assert_eq!(received, ndn_packet::lp::encode_lp_packet(&interest));
}
