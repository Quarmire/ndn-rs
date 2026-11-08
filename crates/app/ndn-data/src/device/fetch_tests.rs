//! Asking again under loss within one ask (spec §17.1): an Interest nothing
//! answers is expressed again after the device's retransmission timeout,
//! timed from the round trips it measured, within the same lifetime.

use super::*;
use ndn_app::AppError;
use ndn_packet::encode::DataBuilder;
use ndn_security::TrustSchema;
use ndn_sync::MemoryStore;

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

/// An Interest as carried: its name, nonce and lifetime.
type Carried = (Name, Option<u32>, Option<Duration>);

/// A forwarder that carries only Interests under `/lossy`: it loses the
/// first Interest for each name under `/lossy/lost` and answers every other
/// one at once with a Data under its name; it records every Interest it
/// carries.
struct LosesFirst {
    sent: std::sync::Mutex<Vec<Carried>>,
    tx: futures::channel::mpsc::UnboundedSender<Bytes>,
    rx: futures::lock::Mutex<futures::channel::mpsc::UnboundedReceiver<Bytes>>,
}

impl LosesFirst {
    fn new() -> Arc<Self> {
        let (tx, rx) = futures::channel::mpsc::unbounded();
        Arc::new(LosesFirst {
            sent: std::sync::Mutex::new(Vec::new()),
            tx,
            rx: futures::lock::Mutex::new(rx),
        })
    }

    fn sent(&self, name: &Name) -> Vec<Carried> {
        let sent = self.sent.lock().unwrap();
        sent.iter().filter(|i| i.0 == *name).cloned().collect()
    }
}

#[async_trait::async_trait]
impl Connection for LosesFirst {
    async fn send(&self, wire: Bytes) -> Result<(), AppError> {
        let Ok(interest) = Interest::decode(wire) else {
            return Ok(());
        };
        if !interest.name.has_prefix(&n("/lossy")) {
            return Ok(());
        }
        let name = (*interest.name).clone();
        let mut sent = self.sent.lock().unwrap();
        let again = !name.has_prefix(&n("/lossy/lost")) || sent.iter().any(|i| i.0 == name);
        sent.push((name.clone(), interest.nonce(), interest.lifetime()));
        if again {
            let reply = DataBuilder::new(name, b"here").build();
            let _ = self.tx.unbounded_send(reply);
        }
        Ok(())
    }
    async fn recv(&self) -> Option<Bytes> {
        self.rx.lock().await.next().await
    }
    async fn register_prefix(&self, _prefix: &Name) -> Result<(), AppError> {
        Ok(())
    }
}

async fn device_on(conn: Arc<dyn Connection>) -> Device {
    let device = n("/alice/phone");
    let validator = Arc::new(Validator::new(TrustSchema::hierarchical()));
    validator
        .adopt_context(Arc::new(SignedTrustContext::hierarchical(n("/alice"))))
        .unwrap();
    let keys = Arc::new(SecurityManager::new());
    keys.generate_ed25519(device.clone().append("KEY").append("1"))
        .unwrap();
    Device::start(
        Transport {
            node: Node::from_connection(Arc::clone(&conn)),
            sync: conn,
        },
        device,
        keys,
        validator,
        Arc::new(MemoryStore::new()),
        Config::new(),
    )
    .await
    .unwrap()
}

/// A lost Interest costs one retransmission timeout, not the lifetime: once
/// the device measured a round trip, it is expressed again under a fresh
/// nonce after the timeout that round trip gives, with the lifetime left,
/// and the second Interest is answered.
#[tokio::test(start_paused = true)]
async fn a_lost_interest_is_expressed_again_within_its_lifetime() {
    let conn = LosesFirst::new();
    let dev = device_on(conn.clone()).await;
    // Answered at once: a round trip of nothing, so the floor.
    assert!(dev.inner.fetch(n("/lossy/answered"), false).await.is_some());
    let name = n("/lossy/lost/one");
    let start = Instant::now();
    let got = dev.inner.fetch(name.clone(), false).await;
    let took = start.elapsed();
    assert!(
        got.is_some_and(|d| *d.name == name),
        "the Interest expressed again is answered"
    );
    assert_eq!(took, RTO_MIN, "it cost one retransmission timeout");
    let sent = conn.sent(&name);
    assert_eq!(sent.len(), 2, "expressed again once, answered then");
    assert_ne!(sent[0].1, sent[1].1, "under a fresh nonce");
    assert_eq!(sent[0].2, Some(dev.inner.config.lifetime));
    assert_eq!(
        sent[1].2,
        Some(dev.inner.config.lifetime - RTO_MIN),
        "within the same lifetime"
    );
    dev.shutdown();
}

/// The retransmission timeout follows the round trips measured (RFC 6298):
/// never under [`RTO_MIN`], never over the lifetime, doubled after each ask
/// that needed a re-expression or missed, until an ask answered by its
/// first Interest measures one again.
#[test]
fn the_retransmission_timeout_follows_measured_round_trips_within_its_bounds() {
    let lifetime = Duration::from_secs(2);
    let ms = Duration::from_millis;
    let mut rtt = Rtt::default();
    assert_eq!(
        rtt.rto(lifetime),
        lifetime,
        "none measured: none re-expressed"
    );
    rtt.sample(ms(20));
    assert_eq!(
        rtt.rto(lifetime),
        RTO_MIN,
        "20 ms + 4 · 10 ms is under the floor"
    );
    rtt.sample(ms(400));
    // srtt (7 · 20 + 400) / 8 = 67.5 ms; rttvar (3 · 10 + 380) / 4 = 102.5 ms.
    assert_eq!(rtt.rto(lifetime), Duration::from_micros(477_500));
    rtt.missed();
    assert_eq!(rtt.rto(lifetime), ms(955));
    rtt.missed();
    rtt.missed();
    assert_eq!(rtt.rto(lifetime), lifetime, "never over the lifetime");
    rtt.sample(ms(67) + Duration::from_micros(500));
    assert!(rtt.rto(lifetime) < ms(955), "a sample ends the doubling");
}
