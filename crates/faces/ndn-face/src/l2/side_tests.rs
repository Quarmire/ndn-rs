//! The Ethernet faces' side path (channel frames), over a bus of stations in memory.
//!
//! `AF_PACKET` needs `CAP_NET_RAW`, which a test run does not have, so these tests drive the real
//! faces ([`NamedEtherFace`], [`MulticastEtherFace`]) over a mock [`EtherPort`]: stations on one
//! segment that share a [`Bus`], each with a bounded send queue, delivering a frame to the stations
//! the destination MAC names (the NDN multicast group reaches every station that joined it, never the
//! sender) and padding a payload under 46 octets as a NIC does. What is *not* covered is the
//! kernel: the TPACKET ring and the `sendto` that flushes it (`AfPacketPort`).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use ndn_engine::side::{SideConfig, SideId, SideOutcome, SideTable};
use ndn_packet::Name;
use ndn_transport::side_header::{MIN_FRAME_LEN, SideHeader, SideKind, UpOp, UpRecord};
use ndn_transport::{
    FaceAddr, FaceError, FaceId, FaceKind, FaceTable, SIDE_MARKER, SideClass, SideRefused,
    Transport,
};
use tokio::sync::Notify;

use super::af_packet::MacAddr;
use super::multicast_ether::NDN_ETHER_MCAST_MAC;
use super::port::EtherPort;
use super::radio::RadioFaceMetadata;
use super::{ETHER_PAYLOAD_MTU, MulticastEtherFace, NamedEtherFace};

/// One frame on the wire: who sent it, to which address, and the payload as sent.
#[derive(Clone, Debug)]
struct Wire {
    src: MacAddr,
    dst: MacAddr,
    payload: Bytes,
}

/// A segment: its stations, whether the medium is stalled, and every frame that crossed it.
#[derive(Default)]
struct Bus {
    stations: Mutex<Vec<Arc<Station>>>,
    stalled: AtomicBool,
    wire: Mutex<Vec<Wire>>,
}

impl Bus {
    fn frames_on_wire(&self) -> Vec<Wire> {
        self.wire.lock().unwrap().clone()
    }

    /// Stall the medium: queued frames stay queued, as with a NIC that is not draining its ring.
    fn stall(&self) {
        self.stalled.store(true, Ordering::SeqCst);
    }

    /// The medium drains again: every station sends what it had queued.
    fn resume(&self) {
        self.stalled.store(false, Ordering::SeqCst);
        let stations = self.stations.lock().unwrap().clone();
        for station in stations {
            self.drain(&station);
        }
    }

    /// Send what `from` has queued, each frame to the address it was queued for: a multicast
    /// address reaches every station that joined the group but the sender; a unicast address,
    /// the station that owns it; broadcast, every station but the sender. The payload is padded
    /// to 46 octets, as a NIC pads it.
    fn drain(&self, from: &Arc<Station>) {
        loop {
            let Some((dst, payload)) = from.txq.lock().unwrap().pop_front() else {
                break;
            };
            self.wire.lock().unwrap().push(Wire {
                src: from.mac,
                dst,
                payload: payload.clone(),
            });
            let mut padded = payload.to_vec();
            if padded.len() < MIN_FRAME_LEN {
                padded.resize(MIN_FRAME_LEN, 0);
            }
            let padded = Bytes::from(padded);
            for to in self.stations.lock().unwrap().iter() {
                let hears = to.mac != from.mac
                    && if dst == MacAddr::BROADCAST {
                        true
                    } else if dst.0[0] & 1 == 1 {
                        to.joined
                    } else {
                        to.mac == dst
                    };
                if hears {
                    to.inbox
                        .lock()
                        .unwrap()
                        .push_back((padded.clone(), from.mac));
                    to.rx.notify_one();
                }
            }
            from.tx_room.notify_one();
        }
    }
}

struct Station {
    mac: MacAddr,
    /// Whether the NIC joined the NDN multicast group.
    joined: bool,
    bus: Arc<Bus>,
    inbox: Mutex<VecDeque<(Bytes, MacAddr)>>,
    rx: Notify,
    txq: Mutex<VecDeque<(MacAddr, Bytes)>>,
    tx_cap: usize,
    tx_room: Notify,
}

#[derive(Clone)]
struct MockPort(Arc<Station>);

impl MockPort {
    fn on(bus: &Arc<Bus>, mac: u8, joined: bool, tx_cap: usize) -> Self {
        let station = Arc::new(Station {
            mac: MacAddr::new([0x02, 0, 0, 0, 0, mac]),
            joined,
            bus: Arc::clone(bus),
            inbox: Mutex::default(),
            rx: Notify::new(),
            txq: Mutex::default(),
            tx_cap,
            tx_room: Notify::new(),
        });
        bus.stations.lock().unwrap().push(Arc::clone(&station));
        Self(station)
    }

    fn mac(&self) -> MacAddr {
        self.0.mac
    }

    fn received(&self) -> usize {
        self.0.inbox.lock().unwrap().len()
    }
}

impl EtherPort for MockPort {
    fn try_pop_rx(&self) -> Option<(Bytes, MacAddr)> {
        self.0.inbox.lock().unwrap().pop_front()
    }

    fn try_push_tx(&self, payload: &[u8], dst: &MacAddr) -> bool {
        let mut q = self.0.txq.lock().unwrap();
        if q.len() >= self.0.tx_cap {
            return false;
        }
        q.push_back((*dst, Bytes::copy_from_slice(payload)));
        true
    }

    fn flush_tx(&self) -> std::io::Result<()> {
        if !self.0.bus.stalled.load(Ordering::SeqCst) {
            self.0.bus.drain(&self.0);
        }
        Ok(())
    }

    async fn readable(&self) -> std::io::Result<()> {
        self.0.rx.notified().await;
        Ok(())
    }

    async fn writable(&self) -> std::io::Result<()> {
        self.0.tx_room.notified().await;
        Ok(())
    }
}

fn marked(len: usize, fill: u8) -> Bytes {
    let mut v = vec![fill; len];
    v[0] = SIDE_MARKER;
    Bytes::from(v)
}

/// A unicast face on station `mac`, addressed to station `mac ^ 1`.
fn unicast(bus: &Arc<Bus>, mac: u8, tx_cap: usize) -> (NamedEtherFace<MockPort>, MockPort) {
    let port = MockPort::on(bus, mac, false, tx_cap);
    let peer = MacAddr::new([0x02, 0, 0, 0, 0, mac ^ 1]);
    let face = NamedEtherFace::with_port(
        FaceId(u64::from(mac)),
        "/test/node".parse::<Name>().unwrap(),
        peer,
        "eth0",
        RadioFaceMetadata::default(),
        port.clone(),
    );
    (face, port)
}

/// A multicast face (face id `id`) on station `mac`, which joined the group.
fn multicast(
    bus: &Arc<Bus>,
    id: u64,
    mac: u8,
    tx_cap: usize,
) -> (MulticastEtherFace<MockPort>, MockPort) {
    let port = MockPort::on(bus, mac, true, tx_cap);
    (
        MulticastEtherFace::with_port(FaceId(id), "eth0", port.clone()),
        port,
    )
}

async fn recv<T: Transport>(face: &T) -> Bytes {
    tokio::time::timeout(Duration::from_secs(2), face.recv_bytes())
        .await
        .expect("a frame within 2 s")
        .unwrap()
}

/// A forwarder's app face: records what the engine hands it, with the ingress face.
struct App {
    id: FaceId,
    side: Mutex<Vec<(Bytes, SideClass, FaceId)>>,
}

/// A transport over an [`App`], so the test keeps its handle on what the engine was handed.
struct AppFace(Arc<App>);

impl Transport for AppFace {
    fn id(&self) -> FaceId {
        self.0.id
    }
    fn kind(&self) -> FaceKind {
        FaceKind::App
    }
    fn side_frame_max(&self) -> usize {
        65_536
    }
    fn forward_side(&self, frame: Bytes, class: SideClass) -> Result<(), SideRefused> {
        self.forward_side_from(frame, class, FaceId::INVALID)
    }
    fn forward_side_from(
        &self,
        frame: Bytes,
        class: SideClass,
        ingress: FaceId,
    ) -> Result<(), SideRefused> {
        self.0.side.lock().unwrap().push((frame, class, ingress));
        Ok(())
    }
    async fn send_bytes(&self, _wire: Bytes) -> Result<(), FaceError> {
        Ok(())
    }
    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        std::future::pending().await
    }
}

/// A forwarder with an app face (id 1) and one Ethernet face (id 2) on a segment.
struct Forwarder {
    faces: Arc<FaceTable>,
    table: SideTable,
    app: Arc<App>,
}

impl Forwarder {
    fn new(ether: impl Transport) -> Self {
        assert_eq!(ether.id(), FaceId(2));
        let faces = Arc::new(FaceTable::new());
        let app = Arc::new(App {
            id: FaceId(1),
            side: Mutex::default(),
        });
        faces.insert(AppFace(Arc::clone(&app)));
        faces.insert(ether);
        Self {
            faces,
            table: SideTable::with_clock(SideConfig::default(), Arc::new(|| 1_000_000_000_000)),
            app,
        }
    }

    /// Route id 7 from `source` to `sink`.
    fn route(&self, source: u64, sink: u64) {
        self.table
            .install(
                SideId(7),
                FaceId(source),
                FaceId(sink),
                Duration::from_secs(30),
            )
            .unwrap();
    }
}

/// One `forward_side` on a `MulticastEtherFace` that is a route's sink puts one frame on the
/// segment, and every station that joined the group has it: each station's forwarder routes it
/// from its own multicast face (the route's source there) to its own app face. A station that did
/// not join, and the sender itself, hear nothing. The forwarder's table holds ids, faces and
/// counters; the receiving stations learn the route from the same Data (here: installed the way
/// the Data pipeline installs it, source = the face the Data arrived on).
#[tokio::test]
async fn a_multicast_ether_sink_reaches_two_stations_with_one_frame() {
    let bus = Arc::new(Bus::default());
    // The sender's forwarder: app face 1 is the route's source, the multicast face 2 its sink.
    let (a_face, a_port) = multicast(&bus, 2, 0xA0, 64);
    let a = Forwarder::new(a_face);
    a.route(1, 2);
    // Two receiving stations, each with its own forwarder: the multicast face is the source.
    let (b_face, b_port) = multicast(&bus, 2, 0xB0, 64);
    let b = Forwarder::new(b_face);
    b.route(2, 1);
    let (c_face, c_port) = multicast(&bus, 2, 0xC0, 64);
    let c = Forwarder::new(c_face);
    c.route(2, 1);
    // A station on the segment that has not joined the NDN group.
    let d_port = MockPort::on(&bus, 0xD0, false, 64);

    let sent = {
        let mut v = SideHeader::new(SideClass::Datagram, SideKind::Data, 7)
            .unwrap()
            .encode()
            .to_vec();
        v.resize(600, 0x5A);
        Bytes::from(v)
    };
    let outcome = a.table.on_frame(FaceId(1), sent.clone(), &a.faces);
    assert_eq!(
        outcome,
        SideOutcome::Routed {
            sinks: 1,
            delivered: 1,
            dropped: 0
        }
    );

    // One frame crossed the segment, to the group address, from the sender.
    let wire = bus.frames_on_wire();
    assert_eq!(
        wire.len(),
        1,
        "one frame for every station, not one per station"
    );
    assert_eq!(wire[0].dst, NDN_ETHER_MCAST_MAC);
    assert_eq!(wire[0].src, a_port.mac());
    assert_eq!(wire[0].payload, sent);

    // Both stations have it, and their forwarders hand it to their app faces from face 2.
    for (who, station, port) in [("B", &b, &b_port), ("C", &c, &c_port)] {
        let face = station.faces.get(FaceId(2)).unwrap();
        let (got, addr) = tokio::time::timeout(
            Duration::from_secs(2),
            face.transport.recv_bytes_with_addr(),
        )
        .await
        .expect("the frame within 2 s")
        .unwrap();
        assert_eq!(got, sent, "station {who} has the frame byte-identical");
        assert!(
            matches!(addr, Some(FaceAddr::Ether(mac)) if mac == a_port.mac().0),
            "from the sender's MAC"
        );
        assert_eq!(port.received(), 0, "and only the one frame");
        let outcome = station.table.on_frame(FaceId(2), got, &station.faces);
        assert_eq!(
            outcome,
            SideOutcome::Routed {
                sinks: 1,
                delivered: 1,
                dropped: 0
            }
        );
        let handed = station.app.side.lock().unwrap().clone();
        assert_eq!(handed.len(), 1, "station {who}'s app has one frame");
        assert_eq!(handed[0].0, sent);
        assert_eq!(handed[0].1, SideClass::Datagram);
        assert_eq!(handed[0].2, FaceId(2), "the ingress is the multicast face");
    }
    // The station that did not join, and the sender (no loopback), heard nothing.
    assert_eq!(
        d_port.received(),
        0,
        "a station outside the group hears nothing"
    );
    assert_eq!(a_port.received(), 0, "the sender does not hear itself");
    // And a frame of that route from a face that is not its source is not routed.
    assert!(matches!(
        b.table.on_frame(FaceId(1), sent, &b.faces),
        SideOutcome::Dropped(_)
    ));
}

/// A frame over the face's MTU is refused `TooLarge` by both calls, never fragmented and never
/// queued; the largest frame that fits crosses byte-identical; an NDN packet is not a side frame;
/// the stream class does not exist on Ethernet.
#[tokio::test]
async fn an_ethernet_side_frame_over_the_mtu_is_refused_and_nothing_is_queued() {
    for multicast_face in [false, true] {
        let bus = Arc::new(Bus::default());
        let (face, tx_port): (Box<dyn ndn_transport::ErasedTransport>, MockPort) = if multicast_face
        {
            let (f, p) = multicast(&bus, 0x10, 0x10, 8);
            (Box::new(f), p)
        } else {
            let (f, p) = unicast(&bus, 0x10, 8);
            (Box::new(f), p)
        };
        // The station the sender's frames are for: the group's member, or the unicast peer
        // (`mac ^ 1` = 0x11).
        let rx_port = MockPort::on(&bus, 0x11, true, 8);

        assert_eq!(face.side_frame_max(), ETHER_PAYLOAD_MTU);
        assert_eq!(ETHER_PAYLOAD_MTU, 1500);
        let over = marked(ETHER_PAYLOAD_MTU + 1, 1);
        let too_large = SideRefused::TooLarge {
            size: ETHER_PAYLOAD_MTU + 1,
            max: ETHER_PAYLOAD_MTU,
        };
        assert_eq!(
            face.forward_side(over.clone(), SideClass::Datagram),
            Err(too_large.clone()),
            "multicast: {multicast_face}"
        );
        assert_eq!(
            face.send_side(over, SideClass::Datagram).await,
            Err(too_large),
            "the default send_side refuses it the same way"
        );
        assert!(tx_port.0.txq.lock().unwrap().is_empty());
        assert!(
            bus.frames_on_wire().is_empty(),
            "nothing over the MTU reached the segment"
        );

        // The largest frame that fits, by both calls.
        let max = marked(ETHER_PAYLOAD_MTU, 2);
        face.forward_side(max.clone(), SideClass::Datagram).unwrap();
        face.send_side(max.clone(), SideClass::Datagram)
            .await
            .unwrap();
        assert_eq!(bus.frames_on_wire().len(), 2);
        assert!(bus.frames_on_wire().iter().all(|w| w.payload == max));
        assert_eq!(rx_port.received(), 2, "multicast: {multicast_face}");

        // An NDN packet (first octet not the marker) never takes the side path.
        let ndn = Bytes::from(vec![0x06; 100]);
        assert_eq!(
            face.forward_side(ndn.clone(), SideClass::Datagram),
            Err(SideRefused::Malformed)
        );
        assert_eq!(
            face.send_side(ndn, SideClass::Datagram).await,
            Err(SideRefused::Malformed)
        );
        // No ordered stream on Ethernet: the forwarder's stream-class frame is counted, not carried.
        assert_eq!(
            face.forward_side(marked(100, 3), SideClass::Stream),
            Err(SideRefused::NotCarried)
        );
        assert_eq!(bus.frames_on_wire().len(), 2);

        // The MTU the operator set bounds the frame: 1,200 takes 1,200 and refuses 1,201.
        face.set_send_mtu(Some(1200)).unwrap();
        assert_eq!(face.side_frame_max(), 1200);
        face.forward_side(marked(1200, 4), SideClass::Datagram)
            .unwrap();
        assert_eq!(
            face.forward_side(marked(1201, 4), SideClass::Datagram),
            Err(SideRefused::TooLarge {
                size: 1201,
                max: 1200
            })
        );
    }
}

/// A NIC pads a payload under 46 octets, so a receiver sees a short frame with trailing zeros:
/// the face does not hide that (it sends what it is given), which is why the channel codec makes
/// every frame self-delimiting or at least 46 octets. A frame of exactly 46 (an `UP` record) is
/// received byte-exact and parses.
#[tokio::test]
async fn a_short_side_frame_is_padded_by_the_nic_and_a_46_octet_frame_is_exact() {
    let bus = Arc::new(Bus::default());
    let (tx, _tx_port) = multicast(&bus, 1, 0x20, 8);
    let (rx, _rx_port) = multicast(&bus, 2, 0x21, 8);

    let up = Bytes::copy_from_slice(
        &UpRecord {
            id: 9,
            op: UpOp::Keep,
        }
        .encode(),
    );
    assert_eq!(up.len(), MIN_FRAME_LEN);
    tx.forward_side(up.clone(), SideClass::Datagram).unwrap();
    let got = recv(&rx).await;
    assert_eq!(got, up, "46 octets arrive as sent");
    assert_eq!(
        UpRecord::parse(&got).unwrap(),
        UpRecord {
            id: 9,
            op: UpOp::Keep
        }
    );

    let short = marked(11, 7);
    tx.forward_side(short.clone(), SideClass::Datagram).unwrap();
    let got = recv(&rx).await;
    assert_eq!(got.len(), MIN_FRAME_LEN, "a NIC pads under 46 octets");
    assert_eq!(&got[..11], &short[..]);
    assert!(got[11..].iter().all(|b| *b == 0), "with zeros");
}

/// A send queue with no room refuses `forward_side` `Full` at once, on both faces, and keeps what
/// it holds in order; `send_bytes` waits for room behind it and no frame is lost or reordered; the
/// queue takes frames again once the medium drains.
#[tokio::test]
async fn forward_side_is_full_when_the_send_queue_is_full_and_never_waits() {
    for multicast_face in [false, true] {
        let bus = Arc::new(Bus::default());
        let face: Arc<dyn ndn_transport::ErasedTransport> = if multicast_face {
            Arc::new(multicast(&bus, 0x30, 0x30, 4).0)
        } else {
            Arc::new(unicast(&bus, 0x30, 4).0)
        };
        let _peer = MockPort::on(&bus, 0x31, true, 4);
        bus.stall();
        for n in 1..=4u8 {
            assert_eq!(
                face.forward_side(marked(60, n), SideClass::Datagram),
                Ok(()),
                "frame {n} fits a queue of 4"
            );
        }
        let started = std::time::Instant::now();
        for _ in 0..3 {
            assert_eq!(
                face.forward_side(marked(60, 9), SideClass::Datagram),
                Err(SideRefused::Full),
                "multicast: {multicast_face}"
            );
        }
        assert!(
            started.elapsed() < Duration::from_millis(100),
            "a full queue is refused at once, not waited on"
        );
        assert!(bus.frames_on_wire().is_empty(), "the medium is stalled");

        // An NDN packet waits for room behind the four (the face's own sender may wait).
        let waiting = {
            let face = Arc::clone(&face);
            tokio::spawn(async move { face.send_bytes(marked(61, 5)).await })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!waiting.is_finished(), "send_bytes waits for room");

        bus.resume();
        tokio::time::timeout(Duration::from_secs(2), waiting)
            .await
            .expect("room made, the waiting send completes")
            .unwrap()
            .unwrap();
        let order: Vec<Bytes> = bus
            .frames_on_wire()
            .into_iter()
            .map(|w| w.payload)
            .collect();
        assert_eq!(
            order,
            vec![
                marked(60, 1),
                marked(60, 2),
                marked(60, 3),
                marked(60, 4),
                marked(61, 5)
            ],
            "what the queue held is sent in order, the refused frames not at all"
        );
        // Room again: `forward_side` takes a frame.
        assert_eq!(
            face.forward_side(marked(62, 6), SideClass::Datagram),
            Ok(())
        );
    }
}

/// The multicast face still answers a station by its own MAC (reply-to-source) and the unicast
/// frame reaches that station only; the refactor to a port changed no NDN behaviour.
#[tokio::test]
async fn a_unicast_reply_on_the_multicast_face_reaches_one_station() {
    let bus = Arc::new(Bus::default());
    let (a, a_port) = multicast(&bus, 1, 0x40, 8);
    let (b, _b_port) = multicast(&bus, 2, 0x41, 8);
    let (c, c_port) = multicast(&bus, 3, 0x42, 8);
    a.send_bytes(Bytes::from_static(b"\x05\x03abc"))
        .await
        .unwrap();
    let (got, addr) = b.recv_bytes_with_addr().await.unwrap();
    assert_eq!(&got[..5], b"\x05\x03abc");
    assert!(matches!(addr, Some(FaceAddr::Ether(mac)) if mac == a_port.mac().0));
    assert_eq!(
        c_port.received(),
        1,
        "a multicast send reaches every station"
    );
    let _ = recv(&c).await;
    b.send_bytes_to(addr.unwrap(), Bytes::from_static(b"\x06\x02hi"))
        .await
        .unwrap();
    assert_eq!(&recv(&a).await[..4], b"\x06\x02hi");
    assert_eq!(
        c_port.received(),
        0,
        "a reply by MAC reaches that station only"
    );
}
