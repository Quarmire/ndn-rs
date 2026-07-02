//! UDP receive-throughput micro-benchmark: how many datagrams/sec one
//! `UdpFace` can drain while several threads flood it. Build it twice and
//! compare to measure the `recvmmsg` batch path against single `recv_from`:
//!
//! ```text
//! cargo build --release --example udp_recv_bench                         # single
//! cargo build --release --example udp_recv_bench --features udp-recvmmsg # batched
//! ./target/release/examples/udp_recv_bench [secs] [sender_threads] [payload_bytes]
//! ```
//!
//! The senders share one socket (so all datagrams pass the face's peer filter)
//! and blast as fast as they can; the single async receiver counts what it
//! drains in the window. Received PPS = the receive path's ceiling (excess is
//! dropped by the kernel once SO_RCVBUF — capped by net.core.rmem_max — fills).

use std::net::UdpSocket;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ndn_face::net::UdpFace;
use ndn_transport::{FaceId, Transport};

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let mut args = std::env::args().skip(1);
    let secs: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(5);
    let n_senders: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(6);
    let payload: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(40);

    let built_with_recvmmsg = cfg!(all(feature = "udp-recvmmsg", target_os = "linux"));

    // Sender socket (shared by all sender threads → one source address).
    let sender = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
    let sender_addr = sender.local_addr().unwrap();

    // Receiver face on a fixed port; only accepts datagrams from `sender_addr`.
    let recv_addr: std::net::SocketAddr = "127.0.0.1:47474".parse().unwrap();
    let face = UdpFace::bind(recv_addr, sender_addr, FaceId(1))
        .await
        .expect("bind receiver");

    let stop = Arc::new(AtomicBool::new(false));
    let sent = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::new();
    for _ in 0..n_senders {
        let sk = sender.clone();
        let stop = stop.clone();
        let sent = sent.clone();
        let buf = vec![0xABu8; payload];
        handles.push(std::thread::spawn(move || {
            let mut local = 0u64;
            while !stop.load(Ordering::Relaxed) {
                for _ in 0..1024 {
                    if sk.send_to(&buf, recv_addr).is_ok() {
                        local += 1;
                    }
                }
            }
            sent.fetch_add(local, Ordering::Relaxed);
        }));
    }

    // Receiver: count drained datagrams for the window.
    let received = Arc::new(AtomicU64::new(0));
    let r2 = received.clone();
    let recv_task = tokio::spawn(async move {
        while face.recv_bytes().await.is_ok() {
            r2.fetch_add(1, Ordering::Relaxed);
        }
    });

    let start = Instant::now();
    tokio::time::sleep(Duration::from_secs(secs)).await;
    let elapsed = start.elapsed().as_secs_f64();
    stop.store(true, Ordering::Relaxed);
    recv_task.abort();
    for h in handles {
        let _ = h.join();
    }

    let recv = received.load(Ordering::Relaxed);
    let snt = sent.load(Ordering::Relaxed);
    let pps = (recv as f64 / elapsed) as u64;
    println!(
        "recvmmsg={built_with_recvmmsg} senders={n_senders} payload={payload}B secs={elapsed:.2} \
         sent={snt} received={recv} recv_pps={pps}"
    );
}
