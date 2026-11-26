//! A compromised key holder, for tests (`adversary` feature; **never enable it in a product**).
//!
//! A channel's frames are sealed under a key every receiver holds, and the sender's signed
//! checkpoints are what tell a frame a holder made from one the sender sent (channel.md,
//! Checkpoints). The in-crate tests seal frames by hand to show that; a test outside this crate
//! (an end-to-end run on real processes) has no way to, because the key, the frame codec and the
//! seal are crate-private. These methods are that one seam: a node that holds a session of a
//! channel (it asked, and was answered) can seal a frame under that channel's key as any holder
//! could, sign a checkpoint with **its own** device key (a holder's, not the sender's, which
//! the receivers refuse), and answer an ask as the sender with a session signed by its own key
//! (which the asker refuses). They hand the bytes back; sending them, and where, is the caller's.
//!
//! The feature is off by default; `ndn-fwd` and `ndn-ext` never enable it. It adds no behaviour
//! to a node that does not call these methods.

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_packet::Interest;
use ndn_transport::{SideClass, SideKind};

use super::aead::FrameCipher;
use super::answer::session_data;
use super::checkpoint;
use super::frame::{Header, seal};
use super::limits::MESSAGE_DEFAULT;
use super::message::{MessageWriter, OutMessage};
use super::ring::frame_hash;
use super::table::name_octets;
use super::wire::{ChanAsk, ChannelMode, SessionRecord};
use crate::host::NodeHandle;

/// The largest frame the forged `DATA` frames are written to: a datagram a link takes at once.
const FORGED_FRAME_MAX: usize = 1_200;

impl NodeHandle {
    /// The sequence the sender's next message takes, as this node's session of `channel` last
    /// heard it (`S_SEQ` of the answer): where this node's own frames begin. `None` when this node
    /// holds no session of `channel`.
    pub fn adversary_next_seq(&self, channel: u64) -> Option<u64> {
        self.inner.chan.sessions.get(channel).map(|s| s.seq())
    }

    /// The answer a hostile holder of `channel`'s key gives to `ask` (a signed ask Interest, as
    /// it crossed the network) as if it were the sender: the session this node holds, its key
    /// wrapped to the recipient the ask names, named by the ask, and signed with **this node's**
    /// device key, which is not the sender's. A receiver must refuse it as not the sender's.
    /// `None` when this node holds no usable session of `channel`, `ask` is no ask, or the
    /// answer cannot be written.
    pub fn adversary_session_data(&self, channel: u64, ask: Bytes) -> Option<Bytes> {
        let session = self.inner.chan.sessions.get(channel)?;
        let (key, key_epoch) = session.current_key()?;
        let interest = Interest::decode(ask).ok()?;
        let ask = ChanAsk::decode(interest.app_parameters()?.clone()).ok()?;
        let terms = session.terms();
        let record = SessionRecord {
            id: channel,
            sender: session.sender().clone(),
            space: session.space().clone(),
            mode: session.mode(),
            key_epoch,
            key_id: key.id(),
            wrap: Bytes::new(),
            aead: terms.aead,
            carriers: terms.carriers,
            table: terms.table,
            ckpt_ms: terms.ckpt_ms,
            window: terms.window,
            lifetime: session.info().lifetime.as_secs(),
            audience_epoch: terms.audience,
            frame_max: terms.frame_max,
            seq: terms.seq,
            certs: self.inner.signer_chain(),
        };
        session_data(
            &*self.inner.signer,
            &interest.name,
            record,
            &key,
            &ask.recipient,
        )
        .ok()
    }

    /// A `DATA` frame of one message — `payload` at `path`, bound to name id `name_id` in the
    /// frame itself — sealed under the key of `channel` as this node holds it, with first
    /// sequence `seq0`: what a holder of the key makes. On the datagram class for a `Latest`
    /// channel, on the stream class otherwise. `None` when this node holds no usable session of
    /// `channel`, or the frame cannot be written.
    pub fn adversary_data_frame(
        &self,
        channel: u64,
        seq0: u64,
        name_id: u64,
        path: &Name,
        payload: &[u8],
    ) -> Option<Bytes> {
        let session = self.inner.chan.sessions.get(channel)?;
        let (key, epoch) = session.current_frame_key()?;
        let cipher = FrameCipher::new(&key, session.terms().aead);
        let class = match session.mode() {
            ChannelMode::Latest => SideClass::Datagram,
            _ => SideClass::Stream,
        };
        let mut writer = MessageWriter::new(
            class,
            channel,
            epoch as u8,
            seq0,
            FORGED_FRAME_MAX,
            FORGED_FRAME_MAX,
            MESSAGE_DEFAULT,
        )
        .ok()?;
        let octets = name_octets(path);
        let message = OutMessage {
            name_id,
            name: Some(&octets),
            stand_secs: None,
            origin: None,
            payload,
        };
        writer.push(&message).ok()?;
        writer.seal(&cipher).ok()
    }

    /// A checkpoint frame of `channel` at sequence `seq` over `[lo, hi)` listing `listed` (frames
    /// as they travelled), signed by **this node's** device key and sealed under the channel's
    /// key: what a holder that is not the sender can make, and what a receiver must refuse. `None`
    /// when this node holds no usable session of `channel`, or the record cannot be written.
    pub fn adversary_checkpoint_frame(
        &self,
        channel: u64,
        seq: u64,
        lo: u64,
        hi: u64,
        listed: &[Bytes],
    ) -> Option<Bytes> {
        let session = self.inner.chan.sessions.get(channel)?;
        let (key, epoch) = session.current_frame_key()?;
        let cipher = FrameCipher::new(&key, session.terms().aead);
        let mut entries = Vec::with_capacity(listed.len());
        for frame in listed {
            entries.push((Header::decode(frame).ok()?.seq0, frame_hash(frame)));
        }
        entries.sort_by_key(|(seq0, _)| *seq0);
        let record =
            checkpoint::sign(&*self.inner.signer, channel, epoch, lo, hi, &entries).ok()?;
        let header = Header::new(
            SideClass::Stream,
            SideKind::Checkpoint,
            channel,
            epoch as u8,
            seq,
            0,
        )
        .ok()?;
        seal(&cipher, &header, &record).ok()
    }

    /// What this node's receiver counted so far, as `(name, count)` (node-wide, every channel):
    /// how many frames it took, how many no checkpoint judged (`unchecked`: forgotten for the
    /// ring's bounds or below a range verified without them), the checkpoints it read and
    /// verified, the frames they contradicted. A test reads them to say whether a forged frame
    /// it made was accepted before the checkpoint that covers its sequence.
    pub fn adversary_rx_counters(&self) -> Vec<(&'static str, u64)> {
        let rx = &self.inner.chan.stats.rx;
        vec![
            ("frames", rx.frames.get()),
            ("accepted", rx.accepted.get()),
            ("replayed", rx.replayed.get()),
            ("too_old", rx.too_old.get()),
            ("sequence", rx.sequence.get()),
            ("too_far", rx.too_far.get()),
            ("unauthentic", rx.unauthentic.get()),
            ("unknown_epoch", rx.unknown_epoch.get()),
            ("unknown_channel", rx.unknown_channel.get()),
            ("unchecked", rx.unchecked.get()),
            ("checkpoints", rx.checkpoints.get()),
            ("checkpoints_verified", rx.checkpoints_verified.get()),
            ("checkpoints_over_rate", rx.checkpoints_over_rate.get()),
            (
                "unverifiable_checkpoints",
                rx.unverifiable_checkpoints.get(),
            ),
            ("bad_checkpoints", rx.bad_checkpoints.get()),
            ("mismatches", rx.mismatches.get()),
            ("conflicts", rx.conflicts.get()),
            ("held", rx.held.get()),
            ("held_dropped", rx.held_dropped.get()),
            ("unverifiable", rx.unverifiable.get()),
            ("ended", rx.ended.get()),
        ]
    }
}
