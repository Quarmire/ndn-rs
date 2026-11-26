//! Checkpoints through real nodes (docs/specs/channel.md, Checkpoints, The receiver): a receiver
//! (Carol) that is handed frames sealed by hand under bob's channel key, as a key holder would
//! seal them, and checkpoints signed by bob's device key; and, where the sender's own loop is the
//! point, a real sender (bob) whose frames and checkpoints a link carries to Carol.
//!
//! Every test that hands frames in at a clock of its own stops the node's maintenance pass, which
//! reads the real clock.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::Bytes;
use futures::FutureExt;
use ndn_foundation_types::Name;
use ndn_security::Ed25519Signer;
use ndn_transport::{FaceId, SideClass, SideKind};
use parking_lot::Mutex;

use super::aead::FrameCipher;
use super::bar::IngressBar;
use super::carrier_kit::{Link, LinkConfig};
use super::channels::SendKey;
use super::checkpoint::{self, Record};
use super::config::ChannelConfig;
use super::control::Control;
use super::evidence::{ChannelEvidence, EvidenceKind};
use super::frame::{Header, open, seal};
use super::items::Items;
use super::limits::MESSAGE_DEFAULT;
use super::message::{MessageWriter, OutMessage};
use super::ring::frame_hash;
use super::rx::{Delivery, Dropped, RxStats};
use super::rx_tests::{Rig, eventually, rig_with, shared};
use super::sessions::{ChannelInfo, EndReason};
use super::verbs::{EmitOptions, GetNotice, GetOptions, Got, LiveEnd, Select, Trust};
use super::wire::ChannelMode;
use crate::log::Frontier;
use crate::log::{Alert, Change};
use crate::node::Node;
use crate::node::tests::{space, world};
use crate::rt::Instant;
use crate::space::Changes;
use crate::test_kit::n;

/// The faces of the cases: the link the sender's frames come over, and the one a key holder's do.
pub(super) const HONEST: u64 = 7;
pub(super) const HOLDER: u64 = 9;

/// A bar that remembers the faces it was asked to bar.
#[derive(Default)]
pub(super) struct Bars(pub(super) Mutex<Vec<u64>>);

impl IngressBar for Bars {
    fn bar(&self, ingress: u64) {
        self.0.lock().push(ingress);
    }
}

/// The name `/<letter>` as a Name TLV's value.
pub(super) fn name(i: u8) -> Vec<u8> {
    vec![0x08, 0x01, b'a' + i]
}

pub(super) fn path(i: u8) -> Name {
    n(&format!("/{}", (b'a' + i) as char))
}

pub(super) struct Ck {
    pub(super) rig: Rig,
    pub(super) link: Arc<Link>,
    pub(super) info: ChannelInfo,
    pub(super) send: SendKey,
    pub(super) cipher: FrameCipher,
    pub(super) bars: Arc<Bars>,
    pub(super) items: Items,
    pub(super) changes: Changes,
    pub(super) mode: ChannelMode,
    pub(super) t0: Instant,
}

/// Bob sends, Carol receives: a channel of `mode` set up by the real ask over a carrier with a
/// stream (so bob's session announces 20 ms checkpoints), an `Items` of Carol's asking for
/// `opts`, a watch of her space for alerts, and bob's key to seal frames by hand.
pub(super) async fn ck(mode: ChannelMode, opts: GetOptions, cfg: LinkConfig) -> Ck {
    ck_with(mode, opts, cfg, ChannelConfig::default().checkpoint).await
}

/// [`ck`] with the senders' checkpoint period set to `period`.
pub(super) async fn ck_with(
    mode: ChannelMode,
    opts: GetOptions,
    cfg: LinkConfig,
    period: Duration,
) -> Ck {
    let rig = rig_with(
        world(&["/alice/laptop", "/bob/phone", "/carol/tablet"]).await,
        ChannelConfig { checkpoint: period },
    )
    .await;
    shared(&rig).await;
    for node in &rig.nodes {
        node.inner
            .chan
            .checkpoints_off
            .store(false, Ordering::SeqCst);
    }
    let link = Link::new(LinkConfig {
        datagram_capacity: 100_000,
        ..cfg
    });
    rig.nodes[1].attach_carrier(link.clone());
    let bars = Arc::new(Bars::default());
    rig.nodes[2].attach_bar(bars.clone());
    let heap = rig.nodes[2].space(&space()).expect("carol is a member");
    let changes = heap.watch(&Frontier::default()).await.expect("a watch");
    let items = heap
        .live(Select::Prefix(Name::root()), opts)
        .expect("carol may read");
    let info = rig.nodes[2]
        .ask_channel_in(&space(), rig.nodes[1].name(), mode)
        .await
        .expect("bob is a writer");
    let send = rig.nodes[1]
        .inner
        .chan
        .channels
        .current(&space(), mode)
        .expect("bob opened the channel when he answered");
    let session = rig.nodes[2].inner.chan.sessions.get(info.channel).unwrap();
    let cipher = FrameCipher::new(&send.frame_key, session.terms().aead);
    // What the ask queued on bob's stream is not a case of these tests.
    link.take_stream();
    Ck {
        rig,
        link,
        info,
        send,
        cipher,
        bars,
        items,
        changes,
        mode,
        t0: Instant::now(),
    }
}

pub(super) fn latest() -> GetOptions {
    GetOptions::default()
}

pub(super) fn verified() -> GetOptions {
    GetOptions {
        trust: Trust::Verified,
        ..GetOptions::default()
    }
}

impl Ck {
    pub(super) fn bob(&self) -> &Node {
        &self.rig.nodes[1]
    }

    pub(super) fn carol(&self) -> &Node {
        &self.rig.nodes[2]
    }

    pub(super) fn stats(&self) -> &RxStats {
        &self.carol().inner.chan.stats.rx
    }

    pub(super) fn pause_tick(&self) {
        self.carol()
            .inner
            .chan
            .tick_paused
            .store(true, Ordering::SeqCst);
    }

    /// The sequence the sender's next message takes: where this receiver's frames begin.
    pub(super) fn start(&self) -> u64 {
        self.carol()
            .inner
            .chan
            .sessions
            .get(self.info.channel)
            .unwrap()
            .terms()
            .seq
    }

    pub(super) fn at(&self, ms: u64) -> Instant {
        self.t0 + Duration::from_millis(ms)
    }

    pub(super) fn class(&self) -> SideClass {
        if self.mode == ChannelMode::Latest {
            SideClass::Datagram
        } else {
            SideClass::Stream
        }
    }

    /// A `DATA` frame of one message named `/<letter>` (id `letter + 1`), as a holder of the key
    /// seals one.
    pub(super) fn data(&self, seq0: u64, letter: u8, payload: &[u8]) -> Bytes {
        let mut w = MessageWriter::new(
            self.class(),
            self.info.channel,
            self.send.key_epoch as u8,
            seq0,
            1_200,
            1_200,
            MESSAGE_DEFAULT,
        )
        .unwrap();
        let octets = name(letter);
        let mut m = OutMessage::new(u64::from(letter) + 1, payload);
        m.name = Some(&octets);
        w.push(&m).unwrap();
        w.seal(&self.cipher).unwrap()
    }

    pub(super) fn control(&self, seq0: u64, control: Control) -> Bytes {
        let header = Header::new(
            SideClass::Stream,
            SideKind::Control,
            self.info.channel,
            self.send.key_epoch as u8,
            seq0,
            0,
        )
        .unwrap();
        seal(&self.cipher, &header, &control.encode().unwrap()).unwrap()
    }

    /// A checkpoint of `frames` over `[lo, hi)` at sequence `seq`, signed by `signer`, sealed under
    /// the channel's key.
    pub(super) fn signed(
        &self,
        signer: &dyn ndn_security::Signer,
        epoch: u32,
        channel: u64,
        seq: u64,
        lo: u64,
        hi: u64,
        frames: &[&Bytes],
    ) -> Bytes {
        let mut entries: Vec<(u64, [u8; 16])> = frames
            .iter()
            .map(|f| (Header::decode(f).unwrap().seq0, frame_hash(f)))
            .collect();
        entries.sort_by_key(|(seq0, _)| *seq0);
        let record = checkpoint::sign(signer, channel, epoch, lo, hi, &entries).unwrap();
        let header = Header::new(
            SideClass::Stream,
            SideKind::Checkpoint,
            self.info.channel,
            self.send.key_epoch as u8,
            seq,
            0,
        )
        .unwrap();
        seal(&self.cipher, &header, &record).unwrap()
    }

    /// bob's checkpoint of `frames` over `[lo, hi)`.
    pub(super) fn checkpoint(&self, seq: u64, lo: u64, hi: u64, frames: &[&Bytes]) -> Bytes {
        self.signed(
            &*self.rig.nodes[1].inner.signer,
            self.send.key_epoch,
            self.info.channel,
            seq,
            lo,
            hi,
            frames,
        )
    }

    pub(super) async fn deliver(&self, frame: &Bytes, ingress: u64, now: Instant) -> Delivery {
        self.carol()
            .inner
            .chan_deliver(frame.clone(), ingress, now)
            .await
    }

    /// What the `Items` hold now, as `(path, payload)`.
    pub(super) fn got(&mut self) -> Vec<(Name, Vec<u8>)> {
        let mut buf: Vec<Got> = Vec::new();
        self.items.next_batch(&mut buf);
        buf.into_iter()
            .map(|g| (g.path, g.bytes.to_vec()))
            .collect()
    }

    /// The next notice of the `Items`, if one is queued.
    pub(super) fn notice(&mut self) -> Option<GetNotice> {
        match self.items.next().now_or_never() {
            Some(Some(Err(notice))) => Some(notice),
            Some(Some(Ok(got))) => panic!("an item where a notice was expected: {got:?}"),
            _ => None,
        }
    }

    /// The alerts Carol's space raised so far.
    pub(super) fn alerts(&mut self) -> Vec<Alert> {
        let mut out = Vec::new();
        while let Some(Some(Ok(change))) = self.changes.next().now_or_never() {
            if let Change::Alert(alert) = change {
                out.push(alert);
            }
        }
        out
    }

    pub(super) fn evidence(&self) -> Vec<ChannelEvidence> {
        self.carol().channel_evidence()
    }

    pub(super) fn bars(&self) -> Vec<u64> {
        self.bars.0.lock().clone()
    }

    /// Whether Carol still holds the session.
    pub(super) fn session_held(&self) -> bool {
        self.carol()
            .inner
            .chan
            .sessions
            .get(self.info.channel)
            .is_some_and(|s| s.ended().is_none())
    }
}

impl Ck {
    /// The 32 octets of bob's key as Carol verifies checkpoints under.
    pub(super) fn public(&self) -> [u8; 32] {
        self.carol()
            .inner
            .chan
            .sessions
            .get(self.info.channel)
            .unwrap()
            .signer_public()
            .expect("carol found bob's certificate")
    }

    /// The record a checkpoint frame carries, opened as a holder of the key opens it.
    pub(super) fn record_of(&self, frame: &Bytes) -> Record {
        let opened = open(&self.cipher, frame.clone(), 1 << 20).expect("a frame under the key");
        Record::decode(opened.plaintext()).expect("a checkpoint")
    }

    /// Hand over a frame the test expects to be taken as data.
    pub(super) async fn data_in(&self, frame: &Bytes, ingress: u64, ms: u64) {
        let got = self.deliver(frame, ingress, self.at(ms)).await;
        assert!(
            matches!(got, Delivery::Delivered { .. }),
            "a data frame was expected to be delivered, got {got:?}"
        );
    }

    /// Hand over a checkpoint the test expects to be read.
    pub(super) async fn checkpoint_in(&self, frame: &Bytes, ingress: u64, ms: u64) {
        let got = self.deliver(frame, ingress, self.at(ms)).await;
        assert_eq!(
            got,
            Delivery::Checkpoint,
            "a checkpoint was expected to be read"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forgery_by_a_key_holder_is_exposed_by_the_next_checkpoint_with_evidence_against_its_link()
 {
    let mut ck = ck(ChannelMode::Latest, latest(), LinkConfig::default()).await;
    ck.pause_tick();
    let s = ck.start();
    let g0 = ck.data(s, 0, b"one");
    let g1 = ck.data(s + 1, 1, b"two");
    let forged = ck.data(s + 2, 2, b"forged");
    ck.data_in(&g0, HONEST, 1).await;
    ck.data_in(&g1, HONEST, 2).await;
    ck.data_in(&forged, HOLDER, 3).await;

    // Inside the window all three are delivered, as the sender's: that is the stated trade.
    let delivered = ck.got();
    assert_eq!(
        delivered,
        vec![
            (path(0), b"one".to_vec()),
            (path(1), b"two".to_vec()),
            (path(2), b"forged".to_vec())
        ]
    );
    assert!(ck.evidence().is_empty() && ck.bars().is_empty() && ck.alerts().is_empty());

    // The next checkpoint lists what bob sent: the first two.
    let cp = ck.checkpoint(s + 3, s, s + 3, &[&g0, &g1]);
    let before = ck.carol().now();
    ck.checkpoint_in(&cp, HONEST, 22).await;
    let after = ck.carol().now();

    let evidence = ck.evidence();
    assert_eq!(evidence.len(), 1, "one frame is contradicted: {evidence:?}");
    let e = &evidence[0];
    assert_eq!(e.kind, EvidenceKind::Mismatch);
    assert_eq!(e.channel, ck.info.channel);
    assert_eq!(e.sender, *ck.bob().name());
    assert_eq!(e.key_epoch, ck.send.key_epoch);
    assert_eq!(e.seq0, s + 2);
    assert_eq!(e.frame, forged, "the octets accepted, as they came");
    assert_eq!(e.proof, cp, "the signed checkpoint that contradicts them");
    assert_eq!(
        e.ingress,
        FaceId(HOLDER),
        "the link the forgery came over, not the honest one"
    );
    assert!(
        before <= e.when && e.when <= after,
        "made when the checkpoint was read"
    );
    // A third party that holds the key can check the proof by the sender's key alone.
    let record = ck.record_of(&e.proof);
    assert!(record.verify(e.channel, e.key_epoch, &ck.public()));
    assert!(
        record.listed(e.seq0).next().is_none() && Header::decode(&e.frame).unwrap().seq0 == e.seq0,
        "the signed list holds no frame at the forged sequence"
    );

    assert_eq!(ck.bars(), vec![HOLDER], "only the forger's link is barred");
    assert_eq!(
        ck.alerts(),
        vec![Alert::ChannelForgery {
            writer: ck.bob().name().clone(),
            channel: ck.info.channel,
            key_epoch: ck.send.key_epoch,
            seq: s + 2,
            via: FaceId(HOLDER),
        }]
    );
    assert_eq!(
        ck.notice(),
        Some(GetNotice::Retracted {
            writer: ck.bob().name().clone(),
            from: s + 2,
            to: s + 2,
        })
    );
    assert_eq!(ck.stats().mismatches.get(), 1);
    assert!(
        ck.session_held(),
        "a forged frame does not end the session: the sender's stands"
    );

    // The layout round-trips, so evidence can be kept and shown.
    let octets = e.encode();
    assert_eq!(octets[0], 1, "version 1");
    assert_eq!(octets[1], 1, "kind Mismatch");
    assert_eq!(&octets[2..10], &ck.info.channel.to_be_bytes());
    assert_eq!(&octets[10..14], &ck.send.key_epoch.to_be_bytes());
    assert_eq!(&octets[14..22], &(s + 2).to_be_bytes());
    assert_eq!(&octets[22..30], &HOLDER.to_be_bytes());
    assert_eq!(&octets[30..38], &e.when.0.to_be_bytes());
    assert_eq!(ChannelEvidence::decode(&octets).unwrap(), *e);
    let mut cut = octets.to_vec();
    cut.pop();
    assert!(
        ChannelEvidence::decode(&cut).is_err(),
        "a truncated record is refused"
    );
    let mut longer = octets.to_vec();
    longer.push(0);
    assert!(
        ChannelEvidence::decode(&longer).is_err(),
        "octets left over are refused"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_keeps_the_last_64_pieces_of_evidence() {
    let ck = ck(ChannelMode::Latest, latest(), LinkConfig::default()).await;
    ck.pause_tick();
    let s = ck.start();
    // 70 forged frames, each contradicted by its own checkpoint.
    for i in 0..70u64 {
        let forged = ck.data(s + 2 * i, 0, &i.to_le_bytes());
        ck.data_in(&forged, HOLDER, 1 + i).await;
        let cp = ck.checkpoint(s + 2 * i + 1, s + 2 * i, s + 2 * i + 1, &[]);
        ck.checkpoint_in(&cp, HONEST, 1 + i).await;
    }
    let evidence = ck.evidence();
    assert_eq!(evidence.len(), 64);
    assert_eq!(evidence[0].seq0, s + 12, "the oldest six are gone");
    assert_eq!(evidence[63].seq0, s + 138, "the newest is last");
    assert!(
        evidence.windows(2).all(|w| w[0].seq0 < w[1].seq0),
        "oldest first"
    );
}

/// Let every task that can run, run.
pub(super) async fn settle() {
    for _ in 0..30 {
        tokio::task::yield_now().await;
    }
}

/// Whether `frame` is a checkpoint.
pub(super) fn is_checkpoint(frame: &Bytes) -> bool {
    Header::decode(frame).is_ok_and(|h| h.kind == SideKind::Checkpoint)
}

/// What an `Items` yielded, in order: items as `(path, payload)`, notices as they are.
type Event = Result<(Name, Vec<u8>), GetNotice>;

impl Ck {
    /// A data frame whose message names its id only (the name was bound earlier).
    pub(super) fn bare(&self, seq0: u64, letter: u8, payload: &[u8]) -> Bytes {
        let mut w = MessageWriter::new(
            self.class(),
            self.info.channel,
            self.send.key_epoch as u8,
            seq0,
            1_200,
            1_200,
            MESSAGE_DEFAULT,
        )
        .unwrap();
        w.push(&OutMessage::new(u64::from(letter) + 1, payload))
            .unwrap();
        w.seal(&self.cipher).unwrap()
    }

    /// Everything the `Items` hold, in order, items and notices alike.
    pub(super) fn events(&mut self) -> Vec<Event> {
        let mut out = Vec::new();
        while let Some(Some(item)) = self.items.next().now_or_never() {
            out.push(item.map(|g| (g.path, g.bytes.to_vec())));
        }
        out
    }

    /// Bob emits `payload` at `/<letter>` in the channel's mode, and the tasks run.
    pub(super) async fn emit(&self, i: u8, payload: &[u8]) {
        let opts = if self.mode == ChannelMode::Latest {
            EmitOptions::latest()
        } else {
            EmitOptions::reliable()
        };
        self.bob()
            .space(&space())
            .expect("bob holds the space")
            .emit(&path(i), Bytes::copy_from_slice(payload), opts)
            .await
            .expect("bob emits");
        settle().await;
    }

    /// Move the paused clock on by `ms` and let the tasks that woke run.
    pub(super) async fn advance(&self, ms: u64) {
        tokio::time::advance(Duration::from_millis(ms)).await;
        settle().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_relaying_another_senders_frames_alters_one_and_is_exposed_by_the_next_checkpoint()
{
    for holder_first in [true, false] {
        let mut ck = ck(ChannelMode::Latest, latest(), LinkConfig::default()).await;
        ck.pause_tick();
        let s = ck.start();
        let genuine = [
            ck.data(s, 0, b"one"),
            ck.data(s + 1, 1, b"two"),
            ck.data(s + 2, 2, b"three"),
        ];
        let altered = ck.data(s + 1, 1, b"altered");
        // The holder relays bob's frames over its link and replaces the second with its own.
        let relayed = [genuine[0].clone(), altered.clone(), genuine[2].clone()];
        let mut conflicts = 0;
        let order: [(&[Bytes; 3], u64); 2] = if holder_first {
            [(&relayed, HOLDER), (&genuine, HONEST)]
        } else {
            [(&genuine, HONEST), (&relayed, HOLDER)]
        };
        for (frames, ingress) in order {
            for frame in frames {
                if ck.deliver(frame, ingress, ck.at(5)).await == Delivery::Conflict {
                    conflicts += 1;
                }
            }
        }
        assert_eq!(
            conflicts, 1,
            "the altered frame (or the genuine one it replaced) is a conflict"
        );
        // What was delivered is whichever of the two came first.
        let second = if holder_first { "altered" } else { "two" };
        assert_eq!(
            ck.got(),
            vec![
                (path(0), b"one".to_vec()),
                (path(1), second.as_bytes().to_vec()),
                (path(2), b"three".to_vec())
            ]
        );
        // Before a checkpoint nothing says which of the two is the sender's: no link is barred,
        // no link is accused.
        let early = ck.evidence();
        assert_eq!(early.len(), 1, "{early:?}");
        assert_eq!(early[0].kind, EvidenceKind::Conflict);
        assert!(
            ck.bars().is_empty(),
            "no link is barred on a conflict alone"
        );
        assert!(
            ck.alerts().is_empty(),
            "no alert names a link before a checkpoint says whose frame is the forgery"
        );

        let cp = ck.checkpoint(s + 3, s, s + 3, &[&genuine[0], &genuine[1], &genuine[2]]);
        ck.checkpoint_in(&cp, HONEST, 25).await;

        let evidence = ck.evidence();
        let mismatch = evidence
            .iter()
            .find(|e| e.kind == EvidenceKind::Mismatch)
            .expect("the checkpoint contradicts the altered frame");
        assert_eq!(evidence.len(), 2);
        assert_eq!(mismatch.seq0, s + 1);
        assert_eq!(mismatch.frame, altered);
        assert_eq!(mismatch.proof, cp);
        assert_eq!(mismatch.ingress, FaceId(HOLDER));
        assert_eq!(
            ck.bars(),
            vec![HOLDER],
            "only the holder's link is barred, never the honest one"
        );
        assert_eq!(
            ck.alerts(),
            vec![Alert::ChannelForgery {
                writer: ck.bob().name().clone(),
                channel: ck.info.channel,
                key_epoch: ck.send.key_epoch,
                seq: s + 1,
                via: FaceId(HOLDER),
            }]
        );
        let notice = ck.notice();
        if holder_first {
            assert_eq!(
                notice,
                Some(GetNotice::Retracted {
                    writer: ck.bob().name().clone(),
                    from: s + 1,
                    // The altered frame carries its own names, so it may have changed how what
                    // followed was read: the retraction runs to the highest sequence taken.
                    to: s + 2,
                }),
                "the altered item was delivered: it is retracted, what came before stays"
            );
        } else {
            assert_eq!(
                notice, None,
                "the altered frame was never delivered: nothing to retract"
            );
        }
        assert!(ck.session_held());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lost_frame_is_not_a_forgery() {
    for mode in [ChannelMode::Latest, ChannelMode::Reliable] {
        let mut ck = ck(mode, latest(), LinkConfig::default()).await;
        ck.pause_tick();
        let s = ck.start();
        let frames: Vec<Bytes> = (0..4u8)
            .map(|i| ck.data(s + u64::from(i), i, &[i]))
            .collect();
        // The second frame is lost on the way; the fourth has not been covered by a checkpoint yet.
        for i in [0usize, 2, 3] {
            ck.data_in(&frames[i], HONEST, 1 + i as u64).await;
        }
        // The checkpoint covers three of the four and lists all of them.
        let cp = ck.checkpoint(s + 4, s, s + 3, &[&frames[0], &frames[1], &frames[2]]);
        ck.checkpoint_in(&cp, HONEST, 22).await;

        assert!(
            ck.evidence().is_empty(),
            "{mode:?}: a lost frame is not evidence"
        );
        assert!(ck.bars().is_empty() && ck.alerts().is_empty());
        assert_eq!(ck.stats().mismatches.get(), 0);
        let events = ck.events();
        assert!(
            events
                .iter()
                .all(|e| !matches!(e, Err(GetNotice::Retracted { .. }))),
            "{mode:?}: nothing is retracted: {events:?}"
        );
        if mode == ChannelMode::Reliable {
            assert!(
                events.contains(&Err(GetNotice::Lagged { missed: 1 })),
                "the loss is visible to a Reliable reader as a gap: {events:?}"
            );
        }

        // The frame the checkpoint did not cover is not a mismatch of the next one either: it
        // is listed there.
        let cp2 = ck.checkpoint(s + 5, s + 3, s + 4, &[&frames[3]]);
        ck.checkpoint_in(&cp2, HONEST, 44).await;
        assert!(ck.evidence().is_empty() && ck.bars().is_empty());
        assert_eq!(ck.stats().mismatches.get(), 0);
        assert!(ck.session_held());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_frame_accepted_ahead_of_a_checkpoints_range_is_not_judged_by_it() {
    let ck = ck(ChannelMode::Latest, latest(), LinkConfig::default()).await;
    ck.pause_tick();
    let s = ck.start();
    let near = ck.data(s, 0, b"near");
    let ahead = ck.data(s + 5, 1, b"ahead");
    ck.data_in(&near, HONEST, 1).await;
    ck.data_in(&ahead, HONEST, 2).await;
    // A checkpoint whose range ends before the second frame says nothing of it, listed or not.
    let cp = ck.checkpoint(s + 6, s, s + 3, &[&near]);
    ck.checkpoint_in(&cp, HONEST, 22).await;
    assert!(ck.evidence().is_empty() && ck.bars().is_empty());
    assert_eq!(ck.stats().mismatches.get(), 0);
    // The checkpoint whose range reaches it does judge it: here it lists nothing at that sequence.
    let cp2 = ck.checkpoint(s + 7, s + 3, s + 6, &[]);
    ck.checkpoint_in(&cp2, HONEST, 44).await;
    let evidence = ck.evidence();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].seq0, s + 5);
    assert_eq!(evidence[0].frame, ahead);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_accepted_frames_at_one_sequence_with_different_hashes_conflict_at_once() {
    let mut ck = ck(ChannelMode::Latest, latest(), LinkConfig::default()).await;
    ck.pause_tick();
    let s = ck.start();
    let first = ck.data(s, 0, b"first");
    let second = ck.data(s, 0, b"second");
    assert_ne!(frame_hash(&first), frame_hash(&second));
    ck.data_in(&first, HONEST, 1).await;

    // No checkpoint is awaited: the second authentic frame at the sequence is a conflict now.
    let attempts = ck.stats().aead_attempts.get();
    assert_eq!(
        ck.deliver(&second, HOLDER, ck.at(2)).await,
        Delivery::Conflict
    );
    assert_eq!(ck.stats().aead_attempts.get(), attempts + 1);
    assert_eq!(ck.stats().conflicts.get(), 1);
    assert_eq!(
        ck.got(),
        vec![(path(0), b"first".to_vec())],
        "the first accepted wins and the second is not delivered"
    );
    let evidence = ck.evidence();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].kind, EvidenceKind::Conflict);
    assert_eq!(evidence[0].seq0, s);
    assert_eq!(evidence[0].frame, second, "the second frame");
    assert_eq!(evidence[0].proof, first, "set against the first");
    assert_eq!(evidence[0].ingress, FaceId(HOLDER));
    assert!(
        ck.bars().is_empty(),
        "which of the two is the sender's is not known yet"
    );
    assert_eq!(ck.notice(), None);

    // The same second frame again is a copy; garbage at the sequence costs a bounded number of
    // AEAD attempts, then comparisons.
    assert_eq!(
        ck.deliver(&second, HOLDER, ck.at(3)).await,
        Delivery::Dropped(Dropped::Replayed)
    );
    let attempts = ck.stats().aead_attempts.get();
    for i in 0..20usize {
        let mut junk = second.to_vec();
        let at = 20 + i;
        junk[at] ^= 0xff;
        let got = ck.deliver(&Bytes::from(junk), HOLDER, ck.at(4)).await;
        assert!(matches!(got, Delivery::Dropped(_)), "{got:?}");
    }
    assert_eq!(
        ck.stats().aead_attempts.get() - attempts,
        u64::from(super::verify::ATTEMPTS_PER_SEQ - 1),
        "20 distinct junk frames at a seen sequence cost the attempts the sequence has left"
    );

    // The checkpoint says the second was the sender's: the first, which was delivered, is the
    // forgery, and the face it came over is the one barred.
    let cp = ck.checkpoint(s + 1, s, s + 1, &[&second]);
    ck.checkpoint_in(&cp, HONEST, 22).await;
    let evidence = ck.evidence();
    assert_eq!(evidence.len(), 2);
    assert_eq!(evidence[1].kind, EvidenceKind::Mismatch);
    assert_eq!(evidence[1].frame, first);
    assert_eq!(evidence[1].ingress, FaceId(HONEST));
    assert_eq!(ck.bars(), vec![HONEST]);
    assert_eq!(
        ck.notice(),
        Some(GetNotice::Retracted {
            writer: ck.bob().name().clone(),
            from: s,
            to: s,
        })
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_frame_at_a_sequence_a_checkpoint_listed_is_a_mismatch_at_once() {
    let mut ck = ck(ChannelMode::Latest, latest(), LinkConfig::default()).await;
    ck.pause_tick();
    let s = ck.start();
    let genuine = ck.data(s, 0, b"genuine");
    let forged = ck.data(s, 0, b"forged");
    ck.data_in(&genuine, HONEST, 1).await;
    let cp = ck.checkpoint(s + 1, s, s + 1, &[&genuine]);
    ck.checkpoint_in(&cp, HONEST, 22).await;
    assert!(ck.evidence().is_empty());
    // Now the sender's signature already vouches for the frame at `s`: no waiting is needed.
    assert_eq!(
        ck.deliver(&forged, HOLDER, ck.at(30)).await,
        Delivery::Conflict
    );
    let evidence = ck.evidence();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].kind, EvidenceKind::Mismatch);
    assert_eq!(evidence[0].frame, forged);
    assert_eq!(
        evidence[0].proof, cp,
        "the signed checkpoint that listed the genuine frame"
    );
    assert_eq!(ck.bars(), vec![HOLDER]);
    assert_eq!(
        ck.alerts(),
        vec![Alert::ChannelForgery {
            writer: ck.bob().name().clone(),
            channel: ck.info.channel,
            key_epoch: ck.send.key_epoch,
            seq: s,
            via: FaceId(HOLDER),
        }]
    );
    assert_eq!(
        ck.got(),
        vec![(path(0), b"genuine".to_vec())],
        "the forged copy is never delivered"
    );
    assert_eq!(ck.notice(), None, "nothing delivered is contradicted");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn withholding_and_replacing_a_frame_is_a_mismatch() {
    let mut ck = ck(ChannelMode::Reliable, latest(), LinkConfig::default()).await;
    ck.pause_tick();
    let s = ck.start();
    let g0 = ck.data(s, 0, b"zero");
    let g1 = ck.data(s + 1, 1, b"one");
    let g2 = ck.data(s + 2, 2, b"two");
    let replacement = ck.data(s + 1, 1, b"replaced");
    // The holder drops the genuine second frame and delivers its own at the same sequence.
    ck.data_in(&g0, HONEST, 1).await;
    ck.data_in(&replacement, HOLDER, 2).await;
    ck.data_in(&g2, HONEST, 3).await;
    assert_eq!(
        ck.events(),
        vec![
            Ok((path(0), b"zero".to_vec())),
            Ok((path(1), b"replaced".to_vec())),
            Ok((path(2), b"two".to_vec())),
        ],
        "nothing looks missing: the replacement fills the sequence"
    );
    let cp = ck.checkpoint(s + 3, s, s + 3, &[&g0, &g1, &g2]);
    ck.checkpoint_in(&cp, HONEST, 25).await;
    let evidence = ck.evidence();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].kind, EvidenceKind::Mismatch);
    assert_eq!(evidence[0].frame, replacement);
    assert_eq!(evidence[0].ingress, FaceId(HOLDER));
    let record = ck.record_of(&evidence[0].proof);
    let listed: Vec<_> = record.listed(s + 1).collect();
    assert_eq!(
        listed,
        vec![&frame_hash(&g1)],
        "the signature lists another hash at the sequence"
    );
    assert_ne!(frame_hash(&replacement), frame_hash(&g1));
    assert_eq!(ck.bars(), vec![HOLDER]);
    assert_eq!(
        ck.notice(),
        Some(GetNotice::Retracted {
            writer: ck.bob().name().clone(),
            from: s + 1,
            to: s + 2, // the replacement carries a name: see the retraction of a rebinding frame
        })
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_checkpoint_the_sender_did_not_sign_is_refused_and_ends_the_session() {
    let mut ck = ck(ChannelMode::Latest, latest(), LinkConfig::default()).await;
    ck.pause_tick();
    let s = ck.start();
    let g0 = ck.data(s, 0, b"one");
    ck.data_in(&g0, HONEST, 1).await;
    // A key holder seals a checkpoint under its own device key: it opens, and it is not bob's.
    let holder = Ed25519Signer::from_seed(&[9; 32], "/carol/tablet/KEY/1".parse::<Name>().unwrap());
    let cp = ck.signed(
        &holder,
        ck.send.key_epoch,
        ck.info.channel,
        s + 1,
        s,
        s + 1,
        &[&g0],
    );
    let got = ck.deliver(&cp, HOLDER, ck.at(22)).await;
    assert!(
        matches!(got, Delivery::Ended(EndReason::BadCheckpoint { .. })),
        "{got:?}"
    );
    assert_eq!(ck.stats().bad_checkpoints.get(), 1);
    let evidence = ck.evidence();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].kind, EvidenceKind::BadCheckpoint);
    assert_eq!(evidence[0].frame, cp);
    assert!(evidence[0].proof.is_empty());
    assert_eq!(evidence[0].ingress, FaceId(HOLDER));
    assert_eq!(
        ck.bars(),
        vec![HOLDER],
        "the link that carried it is barred"
    );
    assert_eq!(
        ck.alerts(),
        vec![Alert::ChannelCheckpoint {
            writer: ck.bob().name().clone(),
            channel: ck.info.channel,
            key_epoch: ck.send.key_epoch,
            via: FaceId(HOLDER),
        }]
    );
    assert!(!ck.session_held(), "the session is dropped");
    let events = ck.events();
    assert_eq!(
        events[0],
        Ok((path(0), b"one".to_vec())),
        "what was delivered stays"
    );
    assert!(
        matches!(
            events.last(),
            Some(Err(GetNotice::LiveEnded(LiveEnd::Ended {
                reason: EndReason::BadCheckpoint { .. },
                ..
            })))
        ),
        "the Items are told why: {events:?}"
    );
    // Nothing more is taken from the dropped session, genuine or not.
    let g1 = ck.data(s + 1, 1, b"two");
    assert!(matches!(
        ck.deliver(&g1, HONEST, ck.at(30)).await,
        Delivery::Dropped(_)
    ));
    assert!(ck.got().is_empty());
}

/// A checkpoint bob's key made for another channel, key epoch or range is no checkpoint of this
/// one: the signature binds all three.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_checkpoint_re_sealed_for_another_channel_key_epoch_or_range_fails() {
    for what in [
        "another channel id",
        "another key epoch",
        "another range",
        "a flipped signature",
    ] {
        let ck = ck(ChannelMode::Latest, latest(), LinkConfig::default()).await;
        ck.pause_tick();
        let s = ck.start();
        let g0 = ck.data(s, 0, b"one");
        ck.data_in(&g0, HONEST, 1).await;
        let bob = &*ck.bob().inner.signer;
        let (epoch, channel) = (ck.send.key_epoch, ck.info.channel);
        let cp = match what {
            "another channel id" => ck.signed(bob, epoch, channel ^ 1, s + 1, s, s + 1, &[&g0]),
            "another key epoch" => ck.signed(bob, epoch + 1, channel, s + 1, s, s + 1, &[&g0]),
            "another range" => {
                // bob's genuine signature over [s, s + 1), moved onto [s, s + 2).
                let genuine =
                    checkpoint::sign(bob, channel, epoch, s, s + 1, &[(s, frame_hash(&g0))])
                        .unwrap();
                let signature: [u8; 64] = genuine[genuine.len() - 64..].try_into().unwrap();
                let record = checkpoint::sign_with(
                    |_| Some(signature),
                    channel,
                    epoch,
                    s,
                    s + 2,
                    &[(s, frame_hash(&g0))],
                )
                .unwrap();
                let header = Header::new(
                    SideClass::Stream,
                    SideKind::Checkpoint,
                    channel,
                    epoch as u8,
                    s + 1,
                    0,
                )
                .unwrap();
                seal(&ck.cipher, &header, &record).unwrap()
            }
            _ => {
                let genuine = ck.checkpoint(s + 1, s, s + 1, &[&g0]);
                let opened = open(&ck.cipher, genuine, 1 << 20).unwrap();
                let mut record = opened.plaintext().to_vec();
                // The signature is the last 64 octets before the padding.
                let at = record.iter().rposition(|b| *b != 0).unwrap();
                record[at] ^= 1;
                let header = Header::new(
                    SideClass::Stream,
                    SideKind::Checkpoint,
                    channel,
                    epoch as u8,
                    s + 1,
                    0,
                )
                .unwrap();
                seal(&ck.cipher, &header, &record).unwrap()
            }
        };
        let got = ck.deliver(&cp, HOLDER, ck.at(22)).await;
        assert!(
            matches!(got, Delivery::Ended(EndReason::BadCheckpoint { .. })),
            "{what}: {got:?}"
        );
        assert!(!ck.session_held(), "{what}");
        assert_eq!(ck.bars(), vec![HOLDER], "{what}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replayed_checkpoint_changes_nothing() {
    let mut ck = ck(ChannelMode::Latest, latest(), LinkConfig::default()).await;
    ck.pause_tick();
    let s = ck.start();
    let g0 = ck.data(s, 0, b"one");
    let g1 = ck.data(s + 1, 1, b"two");
    ck.data_in(&g0, HONEST, 1).await;
    ck.data_in(&g1, HONEST, 2).await;
    let cp1 = ck.checkpoint(s + 2, s, s + 2, &[&g0, &g1]);
    ck.checkpoint_in(&cp1, HONEST, 22).await;
    ck.got();

    // The frame itself, again, from any link: dropped before the AEAD.
    let (attempts, verified) = (
        ck.stats().aead_attempts.get(),
        ck.stats().checkpoints_verified.get(),
    );
    assert_eq!(
        ck.deliver(&cp1, HOLDER, ck.at(30)).await,
        Delivery::Dropped(Dropped::Replayed)
    );
    assert_eq!(ck.stats().aead_attempts.get(), attempts);
    assert_eq!(ck.stats().checkpoints_verified.get(), verified);
    assert!(ck.evidence().is_empty() && ck.bars().is_empty() && ck.alerts().is_empty());

    // A holder seals the same signed record again at a new sequence: it verifies, and it must
    // change nothing that a checkpoint with nothing new to cover changes. In particular it is not
    // the checkpoint a receiver that holds delivery for want of one is waiting for.
    let g2 = ck.data(s + 3, 2, b"three");
    let g3 = ck.data(s + 4, 3, b"four");
    ck.data_in(&g2, HONEST, 40).await;
    // The silence rule: a frame older than max(4 periods, 100 ms) that no verified checkpoint
    // covers makes the receiver hold what follows.
    assert_eq!(
        ck.deliver(&g3, HONEST, ck.at(200)).await,
        Delivery::Deferred
    );
    assert!(
        ck.carol()
            .inner
            .chan
            .rx
            .channel(ck.info.channel)
            .unwrap()
            .holding()
    );
    let record = ck.record_of(&cp1);
    let resealed = {
        let header = Header::new(
            SideClass::Stream,
            SideKind::Checkpoint,
            ck.info.channel,
            ck.send.key_epoch as u8,
            s + 10,
            0,
        )
        .unwrap();
        let opened = open(&ck.cipher, cp1.clone(), 1 << 20).unwrap();
        assert_eq!(record.lo, s);
        seal(&ck.cipher, &header, opened.plaintext()).unwrap()
    };
    ck.checkpoint_in(&resealed, HOLDER, 210).await;
    assert!(
        ck.carol()
            .inner
            .chan
            .rx
            .channel(ck.info.channel)
            .unwrap()
            .holding(),
        "an old checkpoint, sealed again, does not lift the hold"
    );
    assert!(
        ck.got().iter().all(|(p, _)| *p != path(3)),
        "the held frame is still held"
    );
    assert!(ck.evidence().is_empty() && ck.bars().is_empty());

    // The checkpoint that covers the new frames lifts it.
    let cp2 = ck.checkpoint(s + 5, s + 2, s + 5, &[&g2, &g3]);
    ck.checkpoint_in(&cp2, HONEST, 220).await;
    assert!(
        !ck.carol()
            .inner
            .chan
            .rx
            .channel(ck.info.channel)
            .unwrap()
            .holding()
    );
    assert!(ck.got().iter().any(|(p, b)| *p == path(3) && b == b"four"));
    assert!(ck.evidence().is_empty());
}

// ---- the residuals of docs/specs/channel.md §13.12 ---------------------------------------------

/// Residual 1: a reader of a sealed space seals a `DATA` frame under the key: a `Prompt` receiver
/// takes it as the sender's until a checkpoint, a `Verified` one never does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reader_forging_a_data_frame_is_exposed_and_never_reaches_a_verified_reader() {
    let mut ck = ck(ChannelMode::Latest, latest(), LinkConfig::default()).await;
    ck.pause_tick();
    let mut verified_items = ck
        .carol()
        .space(&space())
        .unwrap()
        .live(Select::Prefix(Name::root()), verified())
        .expect("a verified reader of a channel with checkpoints");
    let s = ck.start();
    let genuine = ck.data(s, 0, b"genuine");
    let forged = ck.data(s + 1, 1, b"a reader wrote this");
    ck.data_in(&genuine, HONEST, 1).await;
    ck.data_in(&forged, HOLDER, 2).await;
    let mut now = vec![];
    verified_items.next_batch(&mut now);
    assert!(
        now.is_empty(),
        "a verified reader is given nothing before a checkpoint lists it"
    );
    assert_eq!(
        ck.got(),
        vec![
            (path(0), b"genuine".to_vec()),
            (path(1), b"a reader wrote this".to_vec())
        ],
        "a prompt reader takes both as the sender's: the stated window"
    );

    let cp = ck.checkpoint(s + 2, s, s + 2, &[&genuine]);
    ck.checkpoint_in(&cp, HONEST, 22).await;
    let mut then = vec![];
    verified_items.next_batch(&mut then);
    assert_eq!(
        then.iter().map(|g| g.bytes.to_vec()).collect::<Vec<_>>(),
        vec![b"genuine".to_vec()],
        "only what the sender's signature lists reaches a verified reader"
    );
    assert_eq!(ck.evidence().len(), 1);
    assert_eq!(ck.evidence()[0].frame, forged);
    assert_eq!(ck.bars(), vec![HOLDER]);
    assert_eq!(
        ck.notice(),
        Some(GetNotice::Retracted {
            writer: ck.bob().name().clone(),
            from: s + 1,
            to: s + 1,
        })
    );
    verified_items.next_batch(&mut then);
    assert_eq!(then.len(), 1, "the forged item never arrives later either");
}

/// Residual 2: captured plaintext sealed again under a new sequence is delivered as newer in
/// `Latest`; an exact repeat is not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn captured_content_sealed_again_at_a_new_sequence_is_exposed() {
    let mut ck = ck(ChannelMode::Latest, latest(), LinkConfig::default()).await;
    ck.pause_tick();
    let s = ck.start();
    let g0 = ck.data(s, 0, b"old value");
    let g1 = ck.data(s + 1, 1, b"other");
    ck.data_in(&g0, HONEST, 1).await;
    ck.data_in(&g1, HONEST, 2).await;
    ck.got();
    // The holder repeats the frame exactly: dropped before the AEAD.
    let attempts = ck.stats().aead_attempts.get();
    assert_eq!(
        ck.deliver(&g0, HOLDER, ck.at(3)).await,
        Delivery::Dropped(Dropped::Replayed)
    );
    assert_eq!(ck.stats().aead_attempts.get(), attempts);
    // It seals the same plaintext at a sequence the sender has not used.
    let again = ck.data(s + 4, 0, b"old value");
    ck.data_in(&again, HOLDER, 4).await;
    assert_eq!(
        ck.got(),
        vec![(path(0), b"old value".to_vec())],
        "old content, delivered as new: the window"
    );
    // The sender's frames are s, s + 1 and (not seen here) s + 2, s + 3; none at s + 4... whose
    // sequence the next checkpoint covers.
    let cp = ck.checkpoint(s + 6, s, s + 6, &[&g0, &g1]);
    ck.checkpoint_in(&cp, HONEST, 25).await;
    let evidence = ck.evidence();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].seq0, s + 4);
    assert_eq!(evidence[0].frame, again);
    assert_eq!(evidence[0].ingress, FaceId(HOLDER));
    assert_eq!(ck.bars(), vec![HOLDER]);
    assert_eq!(
        ck.notice(),
        Some(GetNotice::Retracted {
            writer: ck.bob().name().clone(),
            from: s + 4,
            to: s + 4,
        })
    );
}

/// Residual 3: a forged `END` ends nothing by itself; the sender's own is held until a checkpoint
/// lists it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_end_ends_the_session_only_once_a_checkpoint_lists_it() {
    let mut ck = ck(ChannelMode::Reliable, latest(), LinkConfig::default()).await;
    ck.pause_tick();
    let s = ck.start();
    let g0 = ck.data(s, 0, b"zero");
    let forged_end = ck.control(s + 1, Control::End);
    let g2 = ck.data(s + 2, 2, b"two");
    ck.data_in(&g0, HONEST, 1).await;
    assert_eq!(
        ck.deliver(&forged_end, HOLDER, ck.at(2)).await,
        Delivery::Control
    );
    assert!(
        ck.session_held(),
        "an END a key holder sealed does not end the session"
    );
    ck.data_in(&g2, HONEST, 3).await;
    assert_eq!(
        ck.events(),
        vec![
            Ok((path(0), b"zero".to_vec())),
            Ok((path(2), b"two".to_vec()))
        ],
        "the stream goes on after the forged END"
    );

    // The checkpoint lists the data and no END: the END is exposed.
    let cp = ck.checkpoint(s + 3, s, s + 3, &[&g0, &g2]);
    ck.checkpoint_in(&cp, HONEST, 25).await;
    assert!(ck.session_held());
    let evidence = ck.evidence();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].frame, forged_end);
    assert_eq!(evidence[0].ingress, FaceId(HOLDER));
    assert_eq!(ck.bars(), vec![HOLDER]);
    assert_eq!(
        ck.notice(),
        Some(GetNotice::Retracted {
            writer: ck.bob().name().clone(),
            from: s + 1,
            to: s + 2,
        }),
        "a contradicted record may have changed what followed it: the range runs to the highest sequence taken"
    );

    // The sender's own END is believed once its signature lists it.
    let end = ck.control(s + 4, Control::End);
    assert_eq!(ck.deliver(&end, HONEST, ck.at(30)).await, Delivery::Control);
    assert!(ck.session_held(), "held until a checkpoint lists it");
    assert_eq!(ck.notice(), None);
    let cp2 = ck.checkpoint(s + 5, s + 3, s + 5, &[&end]);
    assert_eq!(
        ck.deliver(&cp2, HONEST, ck.at(40)).await,
        Delivery::Ended(EndReason::Closed)
    );
    assert!(!ck.session_held());
    assert_eq!(
        ck.notice(),
        Some(GetNotice::LiveEnded(LiveEnd::Ended {
            writer: ck.bob().name().clone(),
            reason: EndReason::Closed,
        }))
    );
}

/// Residual 4: a holder drops frames of a `Reliable` channel. The gap is visible where it is, at
/// the next frame or at the checkpoint that follows (which takes a sequence too), and is not
/// forgery.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn withholding_frames_of_a_reliable_channel_shows_as_a_gap_not_as_forgery() {
    // A frame in the middle is dropped.
    let mut ck = ck(ChannelMode::Reliable, latest(), LinkConfig::default()).await;
    ck.pause_tick();
    let s = ck.start();
    let frames: Vec<Bytes> = (0..3u8)
        .map(|i| ck.data(s + u64::from(i), i, &[i]))
        .collect();
    ck.data_in(&frames[0], HONEST, 1).await;
    ck.data_in(&frames[2], HONEST, 3).await;
    let cp = ck.checkpoint(s + 3, s, s + 3, &[&frames[0], &frames[1], &frames[2]]);
    ck.checkpoint_in(&cp, HONEST, 25).await;
    assert_eq!(
        ck.events(),
        vec![
            Ok((path(0), vec![0])),
            Err(GetNotice::Lagged { missed: 1 }),
            Ok((path(2), vec![2])),
        ],
        "the missing frame is reported in its place"
    );
    assert!(ck.evidence().is_empty() && ck.bars().is_empty() && ck.alerts().is_empty());
    assert_eq!(ck.stats().mismatches.get(), 0);
    drop(ck);

    // The last frames are dropped: the checkpoint that follows shows where they were.
    let mut ck = ck_reliable().await;
    let s = ck.start();
    let frames: Vec<Bytes> = (0..3u8)
        .map(|i| ck.data(s + u64::from(i), i, &[i]))
        .collect();
    ck.data_in(&frames[0], HONEST, 1).await;
    let cp = ck.checkpoint(s + 3, s, s + 3, &[&frames[0], &frames[1], &frames[2]]);
    ck.checkpoint_in(&cp, HONEST, 25).await;
    assert_eq!(
        ck.events(),
        vec![Ok((path(0), vec![0])), Err(GetNotice::Lagged { missed: 2 })],
        "the checkpoint's own sequence shows that two frames before it never came"
    );
    assert!(ck.evidence().is_empty() && ck.bars().is_empty());
}

async fn ck_reliable() -> Ck {
    let ck = ck(ChannelMode::Reliable, latest(), LinkConfig::default()).await;
    ck.pause_tick();
    ck
}

/// Residual 5: a forged `BIND` or a forged `NAMED` message renames an id; a forged `UNBIND` drops
/// one. The checkpoint exposes the frame, and the table the receiver reads by goes back to what
/// the session said; the sender is asked again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forged_rename_is_exposed_and_the_name_table_resets_and_asks_again() {
    for what in ["BIND", "NAMED", "UNBIND"] {
        let mut ck = ck(ChannelMode::Latest, latest(), LinkConfig::default()).await;
        ck.pause_tick();
        let s = ck.start();
        // The sender names id 1 `/a`; a bare message of the id is `/a`'s.
        let bound = ck.data(s, 0, b"bound");
        ck.data_in(&bound, HONEST, 1).await;
        let bare = ck.bare(s + 1, 0, b"under /a");
        ck.data_in(&bare, HONEST, 2).await;
        assert_eq!(
            ck.got(),
            vec![(path(0), b"under /a".to_vec())],
            "Latest keeps the newest message of a name"
        );

        let forged = match what {
            "BIND" => ck.control(
                s + 2,
                Control::Bind {
                    id: 1,
                    name: Bytes::from(name(25)),
                },
            ),
            "NAMED" => {
                // The same id, named `/z` by a message of its own.
                let mut w = MessageWriter::new(
                    ck.class(),
                    ck.info.channel,
                    ck.send.key_epoch as u8,
                    s + 2,
                    1_200,
                    1_200,
                    MESSAGE_DEFAULT,
                )
                .unwrap();
                let octets = name(25);
                let mut m = OutMessage::new(1, b"renamed");
                m.name = Some(&octets);
                w.push(&m).unwrap();
                w.seal(&ck.cipher).unwrap()
            }
            _ => ck.control(s + 2, Control::Unbind { id: 1 }),
        };
        ck.deliver(&forged, HOLDER, ck.at(3)).await;
        let bare2 = ck.bare(s + 3, 0, b"after the forgery");
        ck.data_in(&bare2, HONEST, 4).await;
        let read = ck.got();
        match what {
            "UNBIND" => assert!(
                read.is_empty(),
                "{what}: the id is unbound for the receiver, the bare message waits for a bind: {read:?}"
            ),
            _ => assert!(
                read.iter().any(|(p, _)| *p == path(25)),
                "{what}: the forged name is read by: {read:?}"
            ),
        }

        // The checkpoint lists what the sender sent: not the forged frame.
        let cp = ck.checkpoint(s + 4, s, s + 4, &[&bound, &bare, &bare2]);
        let asks = ck.stats().epoch_asks.get();
        ck.checkpoint_in(&cp, HONEST, 25).await;
        let evidence = ck.evidence();
        assert_eq!(evidence.len(), 1, "{what}: {evidence:?}");
        assert_eq!(evidence[0].frame, forged);
        assert_eq!(evidence[0].ingress, FaceId(HOLDER));
        assert_eq!(ck.bars(), vec![HOLDER], "{what}");
        assert_eq!(
            ck.stats().resets.get(),
            1,
            "{what}: the name table went back to the session's"
        );
        eventually("the sender is asked again", || {
            ck.stats().epoch_asks.get() > asks
        })
        .await;
        let notice = ck.notice();
        assert!(
            matches!(&notice, Some(GetNotice::Retracted { from, .. }) if *from == s + 2),
            "{what}: {notice:?}"
        );
        // What the forged frame bound is gone: a bare message of the id is not the forged name's.
        let bare3 = ck.bare(s + 5, 0, b"later");
        ck.deliver(&bare3, HONEST, ck.at(30)).await;
        assert!(
            ck.got().iter().all(|(p, _)| *p != path(25)),
            "{what}: a bare message after the exposure was read under the forged name"
        );
    }
}

// ---- a real sender, a lossy carrier, and the clock -------------------------------------------

/// Checkpoints that are lost, duplicated and overtaken, and data frames that are lost, duplicated
/// and reordered, produce no evidence: neither loss nor repetition is forgery.
#[tokio::test(flavor = "current_thread")]
async fn checkpoints_under_loss_duplication_and_reorder() {
    let mut ck = ck(
        ChannelMode::Latest,
        latest(),
        LinkConfig {
            seed: 7,
            loss: 200,
            duplicate: 100,
            reorder: 300,
            ..LinkConfig::default()
        },
    )
    .await;
    ck.pause_tick();
    tokio::time::pause();
    let (mut seen, mut lost, mut overtaken, mut doubled) = (0u32, 0u32, 0u32, 0u32);
    let mut late: Option<Bytes> = None;
    let mut all = Vec::new();
    for round in 0..80u32 {
        for k in 0..6u32 {
            let n = round * 6 + k;
            ck.emit((n % 5) as u8, &n.to_le_bytes()).await;
        }
        ck.advance(25).await;
        let stream = ck.link.take_stream();
        for datagram in ck.link.take_datagrams() {
            ck.deliver(&datagram, HONEST, Instant::now()).await;
        }
        for frame in stream {
            if !is_checkpoint(&frame) {
                ck.deliver(&frame, HONEST, Instant::now()).await;
                continue;
            }
            seen += 1;
            match seen % 5 {
                0 => {
                    // Lost.
                    lost += 1;
                    continue;
                }
                2 => {
                    // Overtaken: it arrives after the next one.
                    overtaken += 1;
                    late = Some(frame);
                    continue;
                }
                _ => {}
            }
            assert_eq!(
                ck.deliver(&frame, HONEST, Instant::now()).await,
                Delivery::Checkpoint
            );
            // And again: a duplicate is dropped before the AEAD.
            doubled += 1;
            assert_eq!(
                ck.deliver(&frame, HONEST, Instant::now()).await,
                Delivery::Dropped(Dropped::Replayed)
            );
            if let Some(old) = late.take() {
                assert_eq!(
                    ck.deliver(&old, HONEST, Instant::now()).await,
                    Delivery::Checkpoint,
                    "an overtaken checkpoint is read, and harmless"
                );
            }
        }
        all.extend(ck.events());
    }

    let link = ck.link.stats();
    assert!(
        link.lost > 0 && link.duplicated > 0 && link.reordered > 0,
        "the link misbehaved: {link:?}"
    );
    assert!(
        lost > 3 && overtaken > 3 && doubled > 20,
        "{lost} {overtaken} {doubled}"
    );
    assert!(
        ck.stats().checkpoints_verified.get() > 30,
        "checkpoints were verified: {}",
        ck.stats().checkpoints_verified.get()
    );
    assert_eq!(ck.stats().mismatches.get(), 0, "no frame was contradicted");
    assert_eq!(ck.stats().conflicts.get(), 0);
    assert!(ck.evidence().is_empty(), "{:?}", ck.evidence());
    assert!(ck.bars().is_empty() && ck.alerts().is_empty());
    assert!(
        all.iter()
            .all(|e| !matches!(e, Err(GetNotice::Retracted { .. }))),
        "nothing was retracted"
    );
    assert!(
        all.iter().filter(|e| e.is_ok()).count() > 100,
        "data was delivered throughout"
    );
    assert!(ck.stats().replayed.get() > 0);
    assert!(ck.session_held());
}

/// What a forged frame costs between being delivered and being exposed, with the sender's real
/// loop and a stream that takes `DELAY_MS` to carry a checkpoint: it is exposed by the first
/// checkpoint written after it, at most `period + delay + epsilon` after the frame arrived.
async fn window(period_ms: u64) {
    const DELAY_MS: u64 = 1;
    let period = Duration::from_millis(period_ms);
    let mut ck = ck_with(ChannelMode::Latest, latest(), LinkConfig::default(), period).await;
    ck.pause_tick();
    tokio::time::pause();
    assert_eq!(
        ck.info.checkpoint,
        Some(period),
        "the session carries the period"
    );
    let stated = ck
        .info
        .detection_window(Duration::from_millis(DELAY_MS))
        .unwrap();
    assert_eq!(
        stated,
        period + Duration::from_millis(DELAY_MS) + super::config::VERIFY_EPSILON
    );

    // The records the setup sent armed the sender's timer: let that checkpoint go (not delivered:
    // what it covers is not this case) so the case starts with the sender quiet.
    ck.advance(period_ms + 5).await;
    ck.link.take_stream();
    ck.link.take_datagrams();
    let s = ck.start();
    // t = 0: bob sends his first message; it reaches Carol.
    ck.emit(0, b"first").await;
    for d in ck.link.take_datagrams() {
        ck.deliver(&d, HONEST, Instant::now()).await;
    }
    // t = 1 ms: bob sends his second; a holder withholds it and delivers its own at the same
    // sequence.
    ck.advance(1).await;
    ck.emit(1, b"second").await;
    let withheld = ck.link.take_datagrams();
    assert_eq!(withheld.len(), 1);
    // The first message of a name is preceded by the records that bind it: its sequence is not
    // `s + 1`.
    let seq1 = Header::decode(&withheld[0]).unwrap().seq0;
    let forged = ck.data(seq1, 1, b"forged");
    let taken = ck.deliver(&forged, HOLDER, Instant::now()).await;
    assert!(matches!(taken, Delivery::Delivered { .. }), "{taken:?}");
    let forged_at = 1u64;
    assert!(ck.evidence().is_empty());

    // Time passes one millisecond at a time; what bob's stream carries reaches Carol
    // `DELAY_MS` later.
    let mut in_flight: Vec<(u64, Bytes)> = Vec::new();
    let mut now = forged_at;
    let mut exposed = None;
    while now < forged_at + 4 * period_ms + 10 {
        ck.advance(1).await;
        now += 1;
        for frame in ck.link.take_stream() {
            in_flight.push((now + DELAY_MS, frame));
        }
        let (ready, waiting): (Vec<_>, Vec<_>) =
            in_flight.drain(..).partition(|(at, _)| *at <= now);
        in_flight = waiting;
        for (_, frame) in ready {
            ck.deliver(&frame, HONEST, Instant::now()).await;
        }
        if !ck.evidence().is_empty() {
            exposed = Some(now);
            break;
        }
    }
    let exposed = exposed.expect("the forgery was exposed");
    let waited = exposed - forged_at;
    let limit = stated.as_millis() as u64;
    assert!(
        waited <= limit,
        "period {period_ms} ms: exposed {waited} ms after the forged frame, the stated window is {limit} ms"
    );
    assert!(
        exposed >= period_ms,
        "period {period_ms} ms: the checkpoint is written one period after the first frame, not per frame (exposed at {exposed} ms)"
    );
    let evidence = ck.evidence();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].frame, forged);
    assert_eq!(evidence[0].ingress, FaceId(HOLDER));
    assert_eq!(ck.bars(), vec![HOLDER]);
}

#[tokio::test(flavor = "current_thread")]
async fn the_detection_window_is_the_stated_one() {
    window(20).await;
}

#[tokio::test(flavor = "current_thread")]
async fn the_detection_window_follows_a_configured_period_of_100_ms() {
    window(100).await;
}

#[tokio::test(flavor = "current_thread")]
async fn the_detection_window_follows_a_configured_period_of_1_ms() {
    window(1).await;
}

/// Under a flood of frames the sender signs at most once a period; each signature covers what was
/// sent since the last.
#[tokio::test(flavor = "current_thread")]
async fn a_flood_of_frames_costs_one_signature_per_period() {
    let mut ck = ck(ChannelMode::Latest, latest(), LinkConfig::default()).await;
    ck.pause_tick();
    tokio::time::pause();
    let signed = || ck.bob().inner.chan.tx.stats.checkpoints.get();
    let before = signed();
    let (mut written, mut frames) = (Vec::new(), 0usize);
    for ms in 0..600u64 {
        ck.emit((ms % 5) as u8, &ms.to_le_bytes()).await;
        ck.emit(((ms + 1) % 5) as u8, &ms.to_le_bytes()).await;
        ck.advance(1).await;
        frames += ck.link.take_datagrams().len();
        for frame in ck.link.take_stream() {
            if is_checkpoint(&frame) {
                written.push(ms);
            }
        }
    }
    assert!(frames > 500, "the flood was {frames} frames");
    assert!(
        written.windows(2).all(|w| w[1] - w[0] >= 20),
        "a checkpoint is written at most once a period: {written:?}"
    );
    assert!(
        (28..=31).contains(&written.len()),
        "600 ms at a 20 ms period is about 30 checkpoints, not one per frame: {}",
        written.len()
    );
    assert_eq!(
        signed() - before,
        written.len() as u64,
        "one signature for each checkpoint on the link"
    );
}

/// A channel that sends nothing says it is alive every 5 s, with an empty checkpoint, and no more.
#[tokio::test(flavor = "current_thread")]
async fn an_idle_channel_sends_one_empty_checkpoint_every_five_seconds() {
    let ck = ck(ChannelMode::Latest, latest(), LinkConfig::default()).await;
    ck.pause_tick();
    tokio::time::pause();
    let tx = &ck.bob().inner.chan.tx.stats;
    let (signed, empty) = (tx.checkpoints.get(), tx.empty_checkpoints.get());
    let mut at = Vec::new();
    let mut listing = Vec::new();
    let mut others = 0;
    for step in 0..(18_000 / 50u64) {
        ck.advance(50).await;
        for frame in ck.link.take_stream() {
            if is_checkpoint(&frame) {
                listing.push(!ck.record_of(&frame).entries.is_empty());
                at.push(step * 50);
            } else {
                others += 1;
            }
        }
        others += ck.link.take_datagrams().len();
    }
    assert_eq!(others, 0, "nothing but checkpoints is sent when idle");
    assert!(at.len() >= 3, "{at:?}");
    for pair in at.windows(2) {
        let gap = pair[1] - pair[0];
        assert!(
            (5_000..=5_000 + 250 + 50).contains(&gap),
            "empty checkpoints are 5 s apart (to the maintenance pass's 250 ms): {at:?}"
        );
    }
    // The first may list the frames the setup sent (the records that began the channel); every
    // one after it is empty.
    assert!(listing[1..].iter().all(|listed| !listed), "{listing:?}");
    let non_empty = u64::from(listing[0]);
    assert_eq!(tx.checkpoints.get() - signed, at.len() as u64);
    assert_eq!(
        tx.empty_checkpoints.get() - empty,
        at.len() as u64 - non_empty
    );
}

/// A receiver whose only reader is `Verified` delivers nothing as a frame is taken: the frame is
/// reported `Deferred`, and reaches the reader when a checkpoint lists it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_frame_taken_for_a_verified_only_reader_is_deferred_until_a_checkpoint_lists_it() {
    let mut ck = ck(ChannelMode::Latest, verified(), LinkConfig::default()).await;
    ck.pause_tick();
    let s = ck.start();
    let g0 = ck.data(s, 0, b"one");
    assert_eq!(ck.deliver(&g0, HONEST, ck.at(1)).await, Delivery::Deferred);
    assert!(ck.got().is_empty());
    let cp = ck.checkpoint(s + 1, s, s + 1, &[&g0]);
    ck.checkpoint_in(&cp, HONEST, 22).await;
    assert_eq!(ck.got(), vec![(path(0), b"one".to_vec())]);
}
