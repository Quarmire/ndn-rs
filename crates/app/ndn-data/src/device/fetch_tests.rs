//! Asking again under loss within one ask (spec §17.1): an Interest nothing
//! answers is expressed again after the device's retransmission timeout,
//! timed from the round trips it measured, within the same lifetime.

use std::collections::HashSet;

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

/// A range read's probing lasts as many round trips on a slow path as on a
/// fast one (spec §5.4, §17.1): each of its looks is the first-look time
/// or [`RANGE_RTOS`] retransmission timeouts, whichever is longer — so a
/// path whose round trips near the 2 s lifetime gets 64 s, not 32 s — and
/// never more than `RANGE_LOOKS` · max(first look, `RANGE_RTOS` · lifetime).
#[test]
fn a_range_reads_bound_grows_with_the_measured_round_trip_and_is_capped() {
    let (look, lifetime) = (Duration::from_secs(4), Duration::from_secs(2));
    assert_eq!(
        range_bound(look, Duration::from_millis(250)),
        Duration::from_secs(32),
        "a fast path keeps eight first looks"
    );
    assert_eq!(
        range_bound(look, lifetime),
        Duration::from_secs(64),
        "a path whose timeout reached the lifetime gets eight looks of four timeouts"
    );
    let mut rtt = Rtt::default();
    for _ in 0..8 {
        rtt.missed();
    }
    assert_eq!(
        range_bound(look, rtt.rto(lifetime)),
        Duration::from_secs(64),
        "no path makes it longer"
    );
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

/// A forwarder that answers Interests for the packets it serves: those in
/// `lost` never, those in `forged` first with the refusal a forwarder gives
/// a reply that does not verify (`bad-signature`: forged or altered on the
/// way), then with the packet. It records every Interest it carries.
struct Serves {
    packets: HashMap<Name, Bytes>,
    lost: HashSet<Name>,
    forged: HashSet<Name>,
    sent: std::sync::Mutex<Vec<Name>>,
    tx: futures::channel::mpsc::UnboundedSender<Bytes>,
    rx: futures::lock::Mutex<futures::channel::mpsc::UnboundedReceiver<Bytes>>,
}

impl Serves {
    fn new(
        packets: impl IntoIterator<Item = (Name, Bytes)>,
        lost: HashSet<Name>,
        forged: HashSet<Name>,
    ) -> Arc<Self> {
        let (tx, rx) = futures::channel::mpsc::unbounded();
        Arc::new(Serves {
            packets: packets.into_iter().collect(),
            lost,
            forged,
            sent: std::sync::Mutex::new(Vec::new()),
            tx,
            rx: futures::lock::Mutex::new(rx),
        })
    }

    fn asked(&self, name: &Name) -> usize {
        self.sent
            .lock()
            .unwrap()
            .iter()
            .filter(|n| *n == name)
            .count()
    }
}

#[async_trait::async_trait]
impl Connection for Serves {
    async fn send(&self, wire: Bytes) -> Result<(), AppError> {
        let Ok(interest) = Interest::decode(wire.clone()) else {
            return Ok(());
        };
        let name = (*interest.name).clone();
        let Some(packet) = self.packets.get(&name) else {
            return Ok(());
        };
        let first = {
            let mut sent = self.sent.lock().unwrap();
            let first = !sent.contains(&name);
            sent.push(name.clone());
            first
        };
        let reply = if self.lost.contains(&name) {
            return Ok(());
        } else if first && self.forged.contains(&name) {
            ndn_packet::encode::encode_nack(
                NackReason::Refused(ndn_packet::Refusal::BadSignature),
                &wire,
            )
        } else {
            packet.clone()
        };
        let _ = self.tx.unbounded_send(reply);
        Ok(())
    }
    async fn recv(&self) -> Option<Bytes> {
        self.rx.lock().await.next().await
    }
    async fn register_prefix(&self, _prefix: &Name) -> Result<(), AppError> {
        Ok(())
    }
}

/// The longest one packet that never comes keeps an owed fetch
/// ([`Inner::fetch_owed`]): [`FETCH_TRIES`] asks of a lifetime and the
/// reply slack each, and the pauses between them.
fn owed_miss(lifetime: Duration) -> Duration {
    (lifetime + ndn_app::consumer::REPLY_SLACK) * FETCH_TRIES
        + (0..FETCH_TRIES - 1).map(retry_pause).sum::<Duration>()
}

/// A reply the forwarder refused as not verifying — forged or altered on
/// the way — is a miss asking again may mend (spec §17.1): an owed fetch
/// asks again, and the genuine packet that answers is taken.
#[tokio::test(start_paused = true)]
async fn a_reply_refused_as_forged_is_asked_again() {
    let name = n("/bob/laptop/32=log/bob/32=data/photos/seq=1");
    let genuine = DataBuilder::new(name.clone(), b"here").build();
    let conn = Serves::new(
        [(name.clone(), genuine.clone())],
        HashSet::new(),
        HashSet::from([name.clone()]),
    );
    let dev = device_on(conn.clone()).await;
    let got = dev.inner.fetch_owed(name.clone(), false).await;
    assert_eq!(
        got.map(|d| d.raw().clone()),
        Some(genuine),
        "asked again past the refused reply, the genuine packet is taken"
    );
    assert_eq!(conn.asked(&name), 2, "one ask more, no other");
    dev.shutdown();
}

/// A large payload's pieces are fetched a window at once (spec §4.1,
/// §17.1): pieces that do not come neither stop the walk nor hold back the
/// pieces behind them. Every piece that does come is fetched and kept in
/// the time of two pieces that never come (the first chunk, asked alone
/// for the source, then the rest at once), never one such piece after
/// another; the payload is not read while one is missing.
#[tokio::test(start_paused = true)]
async fn a_piece_walk_fetches_past_pieces_that_do_not_come_a_window_at_once() {
    let v = n("/bob/laptop/32=log/bob/32=data/photos/seq=1");
    let c = parse_log_name(&v).and_then(|l| l.subject).unwrap();
    let payload: Vec<u8> = (0..crate::wire::CHUNK * 200)
        .map(|i| (i * 31 % 251) as u8)
        .collect();
    let (pieces, chunks) = pieces::split(&v, &payload);
    let lost: HashSet<Name> = [0, 40, 80, 120, 160]
        .map(|i| piece_name(&v, PieceKind::Chunk(i)))
        .into();
    let conn = Serves::new(
        pieces.iter().map(|p| (p.name.clone(), p.wire.clone())),
        lost.clone(),
        HashSet::new(),
    );
    let dev = device_on(conn.clone()).await;
    let start = Instant::now();
    let got = dev.inner.walk_pieces(&v, &c, chunks, true).await;
    let took = start.elapsed();
    assert!(got.is_none(), "a piece not to be had leaves it unread");
    for p in pieces.iter().filter(|p| !lost.contains(&p.name)) {
        assert!(
            dev.inner.store.contains(&p.name),
            "{} is fetched past the pieces that did not come",
            p.name
        );
    }
    let miss = owed_miss(dev.inner.config.lifetime);
    assert!(
        took <= miss * 2,
        "took {took:?}: more than two pieces that never come ({miss:?} each)"
    );
    dev.shutdown();
}

/// A holder's take asks for an entry inside the hold record's `at` by its
/// name when a summary listed it but no walk took it (spec §13.2, §17.1):
/// asking the devices for their summaries again cannot bring it when the
/// walk counts it listed, so the take does not wait on them for it.
#[tokio::test(start_paused = true)]
async fn a_holders_take_asks_for_an_entry_it_heard_of_by_its_name() {
    let c = n("/alice/32=data/photos");
    let laptop = n("/alice/laptop");
    let writer = Writer::new(n("/alice/laptop/KEY/1"));
    let entry = log_name(&laptop, Some(&c), 2);
    // It never comes: what counts is that it is asked for.
    let conn = Serves::new(
        [(entry.clone(), DataBuilder::new(entry.clone(), b"").build())],
        HashSet::from([entry.clone()]),
        HashSet::new(),
    );
    let dev = device_on(conn.clone()).await;
    {
        let mut st = dev.inner.st.lock();
        st.holding.insert(
            c.clone(),
            Holding {
                hold: log_name(&laptop, Some(&c), 3),
                until: Timestamp(u64::MAX),
                at: [VersionId {
                    writer: writer.clone(),
                    seq: Seq(2),
                }]
                .into_iter()
                .collect(),
                lease: None,
            },
        );
        // A summary of the laptop's listed it.
        st.colls
            .entry(c.clone())
            .or_default()
            .entries
            .insert(writer, BTreeSet::from([2]));
    }
    dev.inner.take_held(&c, &n("/alice"));
    while dev.inner.st.lock().taking.contains(&c) {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    assert!(
        conn.asked(&entry) > 0,
        "the entry the summary listed is asked for by its name"
    );
    dev.shutdown();
}
