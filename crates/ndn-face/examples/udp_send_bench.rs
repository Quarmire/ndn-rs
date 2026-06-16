//! UDP send-throughput micro-benchmark: how many datagrams/sec one `UdpFace`
//! pushes when each `send_batch` ships a burst (a packet's NDNLPv2 fragments).
//! Build twice to compare `sendmmsg` against per-datagram `send_to`:
//!
//! ```text
//! cargo build -p ndn-face-native --release --no-default-features --features net \
//!   --example udp_send_bench                                            # single send
//! cargo build -p ndn-face-native --release --no-default-features \
//!   --features net,udp-sendmmsg --example udp_send_bench                # sendmmsg
//! ./target/release/examples/udp_send_bench [secs] [batch] [payload_bytes]
//! ```
//!
//! A drain thread empties the receiver so the sender sees backpressure, not
//! ENOBUFS. send PPS = the egress path's ceiling.

use std::net::UdpSocket;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_face::net::UdpFace;
use ndn_transport::{FaceId, Transport};

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let mut args = std::env::args().skip(1);
    let secs: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(5);
    let batch: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(8);
    let payload: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(40);

    let built_with_sendmmsg = cfg!(all(feature = "udp-sendmmsg", target_os = "linux"));

    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    let recv_addr = receiver.local_addr().unwrap();

    // Drain thread: keep the receiver socket empty so the sender hits
    // writability backpressure rather than ENOBUFS on its own buffer.
    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        receiver
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            while !stop.load(Ordering::Relaxed) {
                let _ = receiver.recv(&mut buf);
            }
        });
    }

    let face = UdpFace::bind("127.0.0.1:0".parse().unwrap(), recv_addr, FaceId(1))
        .await
        .expect("bind sender face");
    let wires: Vec<Bytes> = (0..batch)
        .map(|_| Bytes::from(vec![0xABu8; payload]))
        .collect();

    let mut sent = 0u64;
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(secs) {
        // Tight loop of batched sends; each call ships `batch` datagrams.
        for _ in 0..256 {
            if Transport::send_batch(&face, &wires).await.is_ok() {
                sent += batch as u64;
            }
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    stop.store(true, Ordering::Relaxed);

    let pps = (sent as f64 / elapsed) as u64;
    println!(
        "sendmmsg={built_with_sendmmsg} batch={batch} payload={payload}B secs={elapsed:.2} \
         sent={sent} send_pps={pps}"
    );
}
