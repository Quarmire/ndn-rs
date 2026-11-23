//! Test kit of the network half: a [`Host`] whose log is a toy (held seqs and
//! declared voids per device), and a [`Wire`] that answers the Interests the
//! half sends from a script and counts them, and carries the Interests a case
//! injects to the half's own server.
//!
//! The toy log decides nothing the real one does: an entry's Content is its
//! verdict. `g…` is genuine; `f…` fails its signature; `v` + 8 octets is
//! genuine and says its writer had nothing between that seq and its own (a
//! gap statement). What the cases check is what the network half asks for,
//! of whom, and how often, and what it hands the node.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_app::{AppError, Connection};
use ndn_foundation_types::Name;
use ndn_packet::encode::DataBuilder;
use ndn_packet::lp::encode_lp_nack;
use ndn_packet::{Data, Interest, NackReason};
use ndn_sync::StoreOp;
use parking_lot::Mutex;
use tokio::sync::mpsc;

use crate::error::Refusal;
use crate::log::{Blob, Outcome, Want};
use crate::register::EntryId;
use crate::seal::GrantRefusal;
use crate::sync::{Host, Taken};
use crate::test_kit::n;
use crate::trust::{Judged, Verified};
use crate::wire::{EpochId, log_name, parse_log_name};

/// The space the cases run in.
pub(crate) const SPACE: &str = "/alice/32=data/notes";

/// The space as a name.
pub(crate) fn space() -> Name {
    n(SPACE)
}

/// What the network does with an Interest.
pub(crate) enum Reply {
    /// Answer with this Data packet.
    Data(Bytes),
    /// Say nothing: the Interest times out.
    Silent,
    /// Answer with a Nack.
    Nack(NackReason),
}

type Script = Box<dyn Fn(&Name) -> Reply + Send + Sync>;

/// One face of a device, as the forwarder sees it.
pub(crate) struct Wire {
    /// Every Interest sent, in order, and when.
    asked: Mutex<Vec<(Name, tokio::time::Instant)>>,
    /// The Data and Nack packets the device sent: its answers.
    answers: Mutex<Vec<Bytes>>,
    script: Mutex<Script>,
    delay: Mutex<Duration>,
    live: Arc<AtomicUsize>,
    peak: AtomicUsize,
    inbound: mpsc::UnboundedSender<Bytes>,
    rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<Bytes>>,
    registered: Mutex<Vec<Name>>,
}

impl Wire {
    /// A face that answers every Interest with a Nack, no route, until a
    /// case scripts it.
    pub(crate) fn new() -> Arc<Wire> {
        let (inbound, rx) = mpsc::unbounded_channel();
        Arc::new(Wire {
            asked: Mutex::new(Vec::new()),
            answers: Mutex::new(Vec::new()),
            script: Mutex::new(Box::new(|_| Reply::Nack(NackReason::NoRoute))),
            delay: Mutex::new(Duration::from_millis(5)),
            live: Arc::new(AtomicUsize::new(0)),
            peak: AtomicUsize::new(0),
            inbound,
            rx: tokio::sync::Mutex::new(rx),
            registered: Mutex::new(Vec::new()),
        })
    }

    /// What the network answers from now on.
    pub(crate) fn script(&self, f: impl Fn(&Name) -> Reply + Send + Sync + 'static) {
        *self.script.lock() = Box::new(f);
    }

    /// How long a scripted answer takes.
    pub(crate) fn delay(&self, d: Duration) {
        *self.delay.lock() = d;
    }

    /// An Interest from the network for the device's own server.
    pub(crate) fn inject(&self, interest: Bytes) {
        let _ = self.inbound.send(interest);
    }

    /// The names asked so far.
    pub(crate) fn names(&self) -> Vec<Name> {
        self.asked.lock().iter().map(|(n, _)| n.clone()).collect()
    }

    /// When each Interest was sent.
    pub(crate) fn times(&self) -> Vec<(Name, tokio::time::Instant)> {
        self.asked.lock().clone()
    }

    /// How many Interests were sent for names under `prefix`.
    pub(crate) fn count(&self, prefix: &Name) -> usize {
        self.asked
            .lock()
            .iter()
            .filter(|(n, _)| n.has_prefix(prefix))
            .count()
    }

    /// How many Interests were sent in all.
    pub(crate) fn total(&self) -> usize {
        self.asked.lock().len()
    }

    /// The most Interests that were unanswered at once.
    pub(crate) fn peak(&self) -> usize {
        self.peak.load(Ordering::Relaxed)
    }

    /// The Data packet the device answered with at position `at` of its
    /// answers (a Nack is `None`).
    pub(crate) fn answer_at(&self, at: usize) -> Option<Data> {
        Data::decode(self.answers.lock().get(at)?.clone()).ok()
    }

    /// How many answers (Data or Nack) the device sent.
    pub(crate) fn answers(&self) -> usize {
        self.answers.lock().len()
    }

    /// The prefixes registered on this face.
    pub(crate) fn registered(&self) -> Vec<Name> {
        self.registered.lock().clone()
    }
}

#[async_trait::async_trait]
impl Connection for Wire {
    async fn send(&self, wire: Bytes) -> Result<(), AppError> {
        let Ok(interest) = Interest::decode(wire.clone()) else {
            self.answers.lock().push(wire);
            return Ok(());
        };
        let name = (*interest.name).clone();
        self.asked
            .lock()
            .push((name.clone(), tokio::time::Instant::now()));
        let reply = (self.script.lock())(&name);
        let delay = *self.delay.lock();
        let inbound = self.inbound.clone();
        match reply {
            Reply::Silent => {}
            Reply::Data(data) => {
                let live = self.live.fetch_add(1, Ordering::Relaxed) + 1;
                self.peak.fetch_max(live, Ordering::Relaxed);
                let counter = Arc::clone(&self.live);
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let _ = inbound.send(data);
                    counter.fetch_sub(1, Ordering::Relaxed);
                });
            }
            Reply::Nack(reason) => {
                let nack = encode_lp_nack(reason, &wire);
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let _ = inbound.send(nack);
                });
            }
        }
        Ok(())
    }

    async fn recv(&self) -> Option<Bytes> {
        self.rx.lock().await.recv().await
    }

    async fn register_prefix(&self, prefix: &Name) -> Result<(), AppError> {
        self.registered.lock().push(prefix.clone());
        Ok(())
    }
}

/// A sync face that records what is registered on it and what is sent, and
/// hears nothing.
pub(crate) struct Face {
    registered: Mutex<Vec<Name>>,
    sent: Mutex<Vec<Name>>,
}

impl Face {
    pub(crate) fn new() -> Arc<Face> {
        Arc::new(Face {
            registered: Mutex::new(Vec::new()),
            sent: Mutex::new(Vec::new()),
        })
    }

    pub(crate) fn registered(&self) -> Vec<Name> {
        self.registered.lock().clone()
    }

    /// The Interests sent below `prefix`.
    pub(crate) fn sent_in(&self, prefix: &Name) -> usize {
        self.sent
            .lock()
            .iter()
            .filter(|n| n.has_prefix(prefix))
            .count()
    }
}

#[async_trait::async_trait]
impl Connection for Face {
    async fn send(&self, wire: Bytes) -> Result<(), AppError> {
        if let Ok(interest) = Interest::decode(wire) {
            self.sent.lock().push((*interest.name).clone());
        }
        Ok(())
    }
    async fn recv(&self) -> Option<Bytes> {
        futures::future::pending().await
    }
    async fn register_prefix(&self, prefix: &Name) -> Result<(), AppError> {
        self.registered.lock().push(prefix.clone());
        Ok(())
    }
}

/// An entry packet of `device`'s log in the case's space: `body` is its
/// verdict for the toy log.
pub(crate) fn entry(device: &str, seq: u64, body: &[u8]) -> Bytes {
    DataBuilder::new(log_name(&n(device), &space(), seq), body).sign_digest_sha256()
}

/// A genuine entry.
pub(crate) fn genuine(device: &str, seq: u64) -> Bytes {
    entry(device, seq, b"g")
}

/// A genuine entry that declares nothing exists between `after` and itself.
pub(crate) fn declaring(device: &str, seq: u64, after: u64) -> Bytes {
    let mut body = vec![b'v'];
    body.extend_from_slice(&after.to_be_bytes());
    entry(device, seq, &body)
}

/// An entry that does not verify.
pub(crate) fn forged(device: &str, seq: u64) -> Bytes {
    entry(device, seq, b"f")
}

/// The toy log's state.
#[derive(Default)]
pub(crate) struct Toy {
    held: BTreeMap<Name, BTreeSet<u64>>,
    voids: BTreeMap<Name, BTreeSet<u64>>,
    high: BTreeMap<Name, u64>,
    pub head: u64,
    /// The devices the toy vouches for.
    pub vouched: BTreeSet<Name>,
    /// The devices that stand as relays, and whether first.
    pub standing: BTreeMap<Name, bool>,
    /// What `take` was handed, in order, as `(device, seq)`.
    pub taken: Vec<(Name, u64)>,
    /// What the log applied.
    pub applied: Vec<(Name, u64)>,
    /// The counters the host was told, in order.
    pub counters: Vec<(Name, u64)>,
    /// Blobs the next applied entry reports.
    pub blobs_on_take: Vec<Blob>,
    /// Blobs listed as owed.
    pub blobs_owed: Vec<Blob>,
    /// Assemblies handed over.
    pub assembled: Vec<(EntryId, Vec<StoreOp>)>,
    /// The epochs whose key is owed.
    pub owed: Vec<EpochId>,
    /// The grants `key_arrived` was handed: `(epoch, name)`.
    pub arrived: Vec<(EpochId, Name)>,
    /// Whether a granted key matches (the toy has no check).
    pub key_matches: bool,
    /// What `may_grant` says, per call, from the front; the last repeats.
    pub grant_says: Vec<Result<(), GrantRefusal>>,
    /// The packets the host serves: `(device, seq)`.
    pub served: BTreeMap<(Name, u64), Bytes>,
    /// The pieces the host serves, by name.
    pub pieces: BTreeMap<Name, Bytes>,
    /// This device's seal key packet.
    pub seal: Option<Bytes>,
    /// The validity the toy gives a device packet: the device it is of, or
    /// refused.
    pub device_packets_valid: bool,
    /// How many times `may_grant` was asked.
    pub grant_asks: usize,
}

/// The toy host.
pub(crate) struct Toyhost {
    device: Name,
    pub st: Mutex<Toy>,
}

impl Toyhost {
    pub(crate) fn new(device: &str) -> Arc<Toyhost> {
        Arc::new(Toyhost {
            device: n(device),
            st: Mutex::new(Toy {
                key_matches: true,
                device_packets_valid: true,
                ..Toy::default()
            }),
        })
    }

    /// Hold seqs `1..=up_to` of `device` already.
    pub(crate) fn hold(&self, device: &str, up_to: u64) {
        let mut st = self.st.lock();
        st.held.entry(n(device)).or_default().extend(1..=up_to);
    }

    pub(crate) fn holds(&self, device: &str, seq: u64) -> bool {
        self.st
            .lock()
            .held
            .get(&n(device))
            .is_some_and(|h| h.contains(&seq))
    }

    pub(crate) fn held_count(&self, device: &str) -> usize {
        self.st.lock().held.get(&n(device)).map_or(0, |h| h.len())
    }
}

#[async_trait::async_trait]
impl Host for Toyhost {
    fn device(&self) -> &Name {
        &self.device
    }

    async fn take(&self, _space: &Name, wire: Bytes) -> Taken {
        let Ok(data) = Data::decode(wire) else {
            return Taken::Decided {
                outcome: Outcome::Refused(Refusal::BadSignature),
                blobs: Vec::new(),
            };
        };
        let Some(log) = parse_log_name(&data.name) else {
            return Taken::Decided {
                outcome: Outcome::Refused(Refusal::BadSignature),
                blobs: Vec::new(),
            };
        };
        let mut st = self.st.lock();
        st.taken.push((log.device.clone(), log.seq));
        let body = data.content().cloned().unwrap_or_default();
        match body.first() {
            Some(b'g') | Some(b'v') => {}
            _ => {
                return Taken::Decided {
                    outcome: Outcome::Refused(Refusal::BadSignature),
                    blobs: Vec::new(),
                };
            }
        }
        if body.first() == Some(&b'v') {
            let after = u64::from_be_bytes(body[1..9].try_into().unwrap());
            st.voids
                .entry(log.device.clone())
                .or_default()
                .extend(after + 1..log.seq);
        }
        let fresh = st
            .held
            .entry(log.device.clone())
            .or_default()
            .insert(log.seq);
        if !fresh {
            return Taken::Decided {
                outcome: Outcome::Duplicate,
                blobs: Vec::new(),
            };
        }
        st.applied.push((log.device, log.seq));
        let blobs = std::mem::take(&mut st.blobs_on_take);
        st.blobs_owed.extend(blobs.iter().cloned());
        Taken::Decided {
            outcome: Outcome::Applied,
            blobs,
        }
    }

    fn missing(&self, _space: &Name) -> Vec<Want> {
        let st = self.st.lock();
        let mut out = Vec::new();
        for (device, high) in &st.high {
            let held = st.held.get(device);
            let void = st.voids.get(device);
            let mut run: Option<u64> = None;
            for seq in 1..=*high + 1 {
                let absent = seq <= *high
                    && !held.is_some_and(|h| h.contains(&seq))
                    && !void.is_some_and(|v| v.contains(&seq));
                match (absent, run) {
                    (true, None) => run = Some(seq),
                    (false, Some(first)) => {
                        out.push(Want {
                            device: device.clone(),
                            first,
                            last: seq - 1,
                            digest: None,
                        });
                        run = None;
                    }
                    _ => {}
                }
            }
        }
        out
    }

    fn high(&self, _space: &Name, device: &Name) -> u64 {
        self.st.lock().high.get(device).copied().unwrap_or(0)
    }

    fn head(&self, _space: &Name) -> u64 {
        self.st.lock().head
    }

    fn note_counter(&self, _space: &Name, device: &Name, seen: u64) {
        let mut st = self.st.lock();
        st.counters.push((device.clone(), seen));
        let high = st.high.entry(device.clone()).or_default();
        *high = (*high).max(seen);
    }

    fn vouched(&self, _space: &Name, device: &Name) -> bool {
        let st = self.st.lock();
        st.vouched.contains(device) || st.held.get(device).is_some_and(|h| !h.is_empty())
    }

    fn standing(&self, _space: &Name, device: &Name) -> Option<bool> {
        self.st.lock().standing.get(device).copied()
    }

    fn served(&self, _space: &Name, device: &Name, seq: u64) -> Option<Bytes> {
        self.st.lock().served.get(&(device.clone(), seq)).cloned()
    }

    fn served_piece(&self, _space: &Name, device: &Name, seq: u64, piece: &Name) -> Option<Bytes> {
        let st = self.st.lock();
        st.served.get(&(device.clone(), seq))?;
        st.pieces.get(piece).cloned()
    }

    fn seal_key_packet(&self, name: &Name) -> Option<Bytes> {
        let st = self.st.lock();
        let packet = st.seal.clone()?;
        (Data::decode(packet.clone()).ok()?.name.as_ref() == name).then_some(packet)
    }

    fn blobs(&self, _space: &Name) -> Vec<Blob> {
        self.st.lock().blobs_owed.clone()
    }

    fn assembled(&self, _space: &Name, blob: &Blob, ops: Vec<StoreOp>, _payload: Vec<u8>) {
        let mut st = self.st.lock();
        st.blobs_owed.retain(|b| b.id != blob.id);
        st.assembled.push((blob.id.clone(), ops));
    }

    fn owed_keys(&self, _space: &Name) -> Vec<EpochId> {
        self.st.lock().owed.clone()
    }

    fn seal_public(&self) -> [u8; 32] {
        [7; 32]
    }

    async fn validate_device_packet(&self, _space: &Name, _data: &Data, device: &Name) -> Judged {
        if !self.st.lock().device_packets_valid {
            return Judged::Refused(Refusal::BadSignature);
        }
        Judged::Valid(Verified {
            key: device.clone().append("KEY").append("1"),
            device: device.clone(),
            person: Name::from_components(device.components()[..1].iter().cloned()),
            key_digest: [0; 32],
        })
    }

    fn key_arrived(&self, _space: &Name, epoch: &EpochId, name: &Name, _content: Bytes) -> bool {
        let mut st = self.st.lock();
        st.arrived.push((epoch.clone(), name.clone()));
        let ok = st.key_matches;
        if ok {
            st.owed.retain(|e| e != epoch);
        }
        ok
    }

    fn may_grant(
        &self,
        _space: &Name,
        _epoch: &EpochId,
        _asker: &Name,
    ) -> Result<(), GrantRefusal> {
        let mut st = self.st.lock();
        st.grant_asks += 1;
        match st.grant_says.len() {
            0 => Ok(()),
            1 => st.grant_says[0],
            _ => st.grant_says.remove(0),
        }
    }

    fn grant_packet(
        &self,
        _space: &Name,
        _epoch: &EpochId,
        _asker: &Name,
        _to: &[u8; 32],
        name: &Name,
    ) -> Option<Bytes> {
        Some(DataBuilder::new(name.clone(), b"a key, wrapped").sign_digest_sha256())
    }
}
